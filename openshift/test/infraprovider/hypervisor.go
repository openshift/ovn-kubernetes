package infraprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/command"
	"golang.org/x/crypto/ssh"
)

const (
	hypervisorUserName = "root"
)

// The hypervisor object must be created while initializing ocp provider
// It also implements infraprovider.CommandRunner interface which helps
// infra provider to perform container operations via SSH.
type hypervisor struct {
	command.Runner
	IP             string
	attachedIfaces map[string]*iface // host network name -> interface
	sshSigner      ssh.Signer
	sshClient      *ssh.Client
}

func loadHypervisorConfig() (*hypervisor, error) {
	sharedDir := os.Getenv("SHARED_DIR")
	if len(sharedDir) == 0 {
		return nil, fmt.Errorf("SHARED_DIR environment variable not set")
	}
	hypervisorIPFile := filepath.Join(sharedDir, "server-ip")
	if _, err := os.Stat(hypervisorIPFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("hypervisor ip config file not found")
	}

	data, err := os.ReadFile(hypervisorIPFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read hypervisor ip config file")
	}
	hypervisorIP := strings.TrimSpace(string(data))
	if hypervisorIP == "" {
		return nil, fmt.Errorf("hypervisor IP is empty in config file")
	}

	clusterProfileDir := os.Getenv("CLUSTER_PROFILE_DIR")
	if len(clusterProfileDir) == 0 {
		return nil, fmt.Errorf("CLUSTER_PROFILE_DIR environment variable not set")
	}
	sshKeyPath := filepath.Join(clusterProfileDir, "equinix-ssh-key")
	if _, err := os.Stat(sshKeyPath); os.IsNotExist(err) {
		sshKeyPath = filepath.Join(clusterProfileDir, "packet-ssh-key")
		if _, err := os.Stat(sshKeyPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("SSH key not found at equinix-ssh-key or packet-ssh-key in %s", clusterProfileDir)
		}
	}
	signerForHypervisor, err := makePrivateKeySignerFromFile(sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error getting hypervisor ssh signer: %w", err)
	}
	m := &hypervisor{IP: hypervisorIP,
		sshSigner:      signerForHypervisor,
		attachedIfaces: map[string]*iface{},
	}
	return m, nil
}

// getHypervisorClient returns the cached SSH client to the hypervisor, creating it if needed.
// If the existing connection is broken, it will be recreated.
func (h *hypervisor) getHypervisorClient() (*ssh.Client, error) {
	// If we already have a client, verify it's still alive
	if h.sshClient != nil {
		// Quick check: try to create a session
		session, err := h.sshClient.NewSession()
		if err == nil {
			session.Close()
			return h.sshClient, nil
		}
		// Connection is dead, close it and create a new one
		h.sshClient.Close()
		h.sshClient = nil
	}

	// Create new connection
	client, err := getSshClient(hypervisorUserName, fmt.Sprintf("%s:22", h.IP), h.sshSigner)
	if err != nil {
		return nil, fmt.Errorf("error getting ssh proxy client: %w", err)
	}

	h.sshClient = client
	return h.sshClient, nil
}

func (h *hypervisor) execCmd(cmd string) (result, error) {
	var r result
	hypervisorClient, err := h.getHypervisorClient()
	if err != nil {
		return r, err
	}
	r, err = runSSHCommand(hypervisorClient, cmd)
	if err != nil {
		return r, fmt.Errorf("failed to run SSH command for %s@%s, result: %v, err: %w", hypervisorUserName, h.IP, r, err)
	}
	return r, nil
}

type ipAddressInfo struct {
	Family string `json:"family"`
	Local  string `json:"local"`
}

type linkInfo struct {
	IfName   string          `json:"ifname"`
	Mac      string          `json:"address"`
	AddrInfo []ipAddressInfo `json:"addr_info"`
}

// findAndInitializeNetwork retrieves and caches the attached network information
// for the hypervisor.
func (h *hypervisor) findAndInitializeNetwork(name, v4Subnet, v6Subnet string) error {
	result, err := h.execCmd("ip -j addr")
	if err != nil {
		return fmt.Errorf("failed to retrieve network links: %w", err)
	}

	var links []linkInfo
	if err := json.Unmarshal([]byte(result.stdout), &links); err != nil {
		return fmt.Errorf("failed to parse network links: %w", err)
	}

	for _, link := range links {
		if netInfo := h.tryMatchLink(link, v4Subnet, v6Subnet); netInfo != nil {
			h.attachedIfaces[name] = netInfo
			return nil
		}
	}
	return fmt.Errorf("no network interface found matching subnets v4=%s v6=%s", v4Subnet, v6Subnet)
}

func (h *hypervisor) tryMatchLink(link linkInfo, v4Subnet, v6Subnet string) *iface {
	net := &iface{}

	for _, addr := range link.AddrInfo {
		// Check for IPv4 match
		if v4Subnet != "" {
			if ok, _ := ipInCIDR(addr.Local, v4Subnet); ok {
				net.v4 = addr.Local
				net.v4Subnet = v4Subnet
				ginkgo.GinkgoLogr.Info("found ip match", "ip4", net.v4, "v4subnet", v4Subnet)
			}
		}

		// Check for IPv6 match
		if v6Subnet != "" {
			if ok, _ := ipInCIDR(addr.Local, v6Subnet); ok {
				net.v6 = addr.Local
				net.v6Subnet = v6Subnet
				ginkgo.GinkgoLogr.Info("found ip match", "ip6", net.v6, "v6subnet", v6Subnet)
			}
		}
	}

	// Only consider this link a match if we found all requested IPs
	hasV4Match := v4Subnet == "" || net.v4 != ""
	hasV6Match := v6Subnet == "" || net.v6 != ""

	if hasV4Match && hasV6Match {
		net.ifName = link.IfName
		net.mac = link.Mac
		ginkgo.GinkgoLogr.Info("found link match", "iface", net.ifName, "v4subnet", v4Subnet, "v6subnet", v6Subnet)
		return net
	}

	// Not a complete match, return nil
	return nil
}

func (h *hypervisor) Run(args ...string) (string, error) {
	// Build the command string (e.g., "podman network inspect kind")
	var cmdParts []string
	cmdParts = append(cmdParts, "podman")
	cmdParts = append(cmdParts, args...)
	cmd := strings.Join(cmdParts, " ")

	// Add elevated privileges for podman commands
	cmd = addElevatedPrivileges(cmd)

	// Execute via SSH on the hypervisor
	result, err := h.execCmd(cmd)
	if err != nil {
		return "", fmt.Errorf("command failed: %w, output: %s", err, result.stdout)
	}
	return result.stdout, nil
}

func ipInCIDR(ipStr, cidrStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %q", ipStr)
	}
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, err
	}
	return ipNet.Contains(ip), nil
}

func addElevatedPrivileges(cmd string) string {
	return fmt.Sprintf("sudo %s", cmd)
}
