package infraprovider

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/containerengine"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"golang.org/x/crypto/ssh"
)

const (
	vmIPEnvKey              = "VM_IP"
	hypervisorIPEnvKey      = "HYPERVISOR_IP"
	hypervisorKeyPathEnvKey = "HYPERVISOR_SSH_KEY"
	vmKeyPathEnvKey         = "VM_SSH_KEY"
	hypervisorUserName      = "root"
	vmUserName              = "fedora"
)

// The vm object must be created while initializing ocp provider
// and methods are invoked after acquiring vm lock.
type vm struct {
	IP                  string                            // default IP address of the VM
	sshSigner           ssh.Signer                        // ssh signer to access the VM
	containers          map[string]*api.ExternalContainer // container name -> api.ExternalContainer object
	hypervisorIP        string                            // IP address of the hypervisor hosting VM
	hypervisorSshSigner ssh.Signer                        // ssh signer to access the hypervisor
	netLinks            []linkInfo                        // net links attached with the VM
	hypervisorClient    *ssh.Client                       // cached SSH connection to hypervisor (proxy)
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

func loadVMConfig() (*vm, error) {
	hypervisorIP := os.Getenv(hypervisorIPEnvKey)
	if len(hypervisorIP) == 0 {
		return nil, fmt.Errorf("no hypervisor found for test vm")
	}
	vmIP := os.Getenv(vmIPEnvKey)
	if len(vmIP) == 0 {
		return nil, fmt.Errorf("IP is not found for test vm")
	}
	signerForHypervisor, err := getSigner(hypervisorKeyPathEnvKey)
	if err != nil {
		return nil, fmt.Errorf("error getting ssh proxy signer: %w", err)
	}
	signerForVM, err := getSigner(vmKeyPathEnvKey)
	if err != nil {
		return nil, fmt.Errorf("error getting ssh vm signer: %w", err)
	}
	m := &vm{hypervisorIP: hypervisorIP,
		IP:                  vmIP,
		hypervisorSshSigner: signerForHypervisor,
		sshSigner:           signerForVM,
	}
	return m, nil
}

func (m *vm) addContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	nwIface, err := m.getNetwork(container)
	if err != nil {
		return container, err
	}
	container.IPv4 = nwIface.IPv4
	container.IPv6 = nwIface.IPv6
	cmd := buildDaemonContainerCmd(container)
	cmd = addElevatedPrivileges(cmd)
	if _, err := m.execCmd(cmd); err != nil {
		return container, fmt.Errorf("failed to execute command on VM: %w", err)
	}
	m.containers[container.Name] = &container
	return container, nil
}

func (m *vm) deleteContainer(container api.ExternalContainer) error {
	isRunning, err := m.isContainerRunning(container)
	if err != nil {
		return fmt.Errorf("failed to check if container is running: %w", err)
	}
	if !isRunning {
		return nil
	}
	// remove the container
	cmd := buildRemoveContainerCmd(container.Name)
	cmd = addElevatedPrivileges(cmd)
	if _, err := m.execCmd(cmd); err != nil {
		return fmt.Errorf("failed to execute command on VM: %w", err)
	}
	// Clean up tracking
	delete(m.containers, container.Name)
	return nil
}

func (m *vm) getContainerLogs(container api.ExternalContainer) (string, error) {
	isRunning, err := m.isContainerRunning(container)
	if err != nil {
		return "", fmt.Errorf("failed to check if container is running: %w", err)
	}
	if !isRunning {
		return "", fmt.Errorf("external container is not running on vm")
	}
	logsCmd := buildContainerLogsCmd(container.Name)
	logsCmd = addElevatedPrivileges(logsCmd)
	res, err := m.execCmd(logsCmd)
	if err != nil {
		return "", fmt.Errorf("failed to execute command (%s) within VM: %w", logsCmd, err)
	}
	return res.stdout, nil
}

// getHypervisorClient returns the cached SSH client to the hypervisor, creating it if needed.
// If the existing connection is broken, it will be recreated.
func (m *vm) getHypervisorClient() (*ssh.Client, error) {
	// If we already have a client, verify it's still alive
	if m.hypervisorClient != nil {
		// Quick check: try to create a session
		session, err := m.hypervisorClient.NewSession()
		if err == nil {
			session.Close()
			return m.hypervisorClient, nil
		}
		// Connection is dead, close it and create a new one
		m.hypervisorClient.Close()
		m.hypervisorClient = nil
	}

	// Create new connection
	client, err := getSshClient(hypervisorUserName, fmt.Sprintf("%s:22", m.hypervisorIP), m.hypervisorSshSigner)
	if err != nil {
		return nil, fmt.Errorf("error getting ssh proxy client: %w", err)
	}

	m.hypervisorClient = client
	return m.hypervisorClient, nil
}

func (m *vm) execCmd(cmd string) (result, error) {
	var r result
	hypervisorClient, err := m.getHypervisorClient()
	if err != nil {
		return r, err
	}
	r, err = runSSHCommand(vmUserName, cmd, hypervisorClient, fmt.Sprintf("%s:22", m.IP), m.sshSigner)
	if err != nil {
		return r, fmt.Errorf("failed to run SSH command for %s@%s: %w: %+v", vmUserName, m.IP, err, r)
	}
	return r, nil
}

func (m *vm) execContainerCmd(container api.ExternalContainer, cmd []string) (result, error) {
	containerCmd := buildContainerCmd(container.Name, cmd)
	containerCmd = addElevatedPrivileges(containerCmd)
	return m.execCmd(containerCmd)
}

func (m *vm) isContainerRunning(container api.ExternalContainer) (bool, error) {
	// check to see if the container is running before attempting to delete it
	isPresentCmd := buildContainerCheckCmd(container.Name)
	isPresentCmd = addElevatedPrivileges(isPresentCmd)
	r, err := m.execCmd(isPresentCmd)
	if err != nil {
		return false, fmt.Errorf("failed to execute command on VM: stdout=%s, stderr=%s",
			r.stdout, r.stderr)
	}
	if r.getStdOut() != "" {
		return true, nil
	}
	return false, nil
}

func (m *vm) getNetwork(container api.ExternalContainer) (api.NetworkInterface, error) {
	v4Subnet, v6Subnet, err := container.Network.IPv4IPv6Subnets()
	if err != nil {
		return api.NetworkInterface{}, err
	}

	// Find a link with IPs matching the requested subnet(s)
	for _, link := range m.netLinks {
		if iface := m.tryMatchLink(link, v4Subnet, v6Subnet); iface.InfName != "" {
			return iface, nil
		}
	}

	return api.NetworkInterface{}, fmt.Errorf("no network interface found matching network %s", container.Network.Name())
}

// tryMatchLink attempts to match IP addresses on a link to the given subnets.
// Returns a populated NetworkInterface if the link has IPs in the requested subnet(s).
func (m *vm) tryMatchLink(link linkInfo, v4Subnet, v6Subnet string) api.NetworkInterface {
	var iface api.NetworkInterface

	for _, addr := range link.AddrInfo {
		// Check for IPv4 match
		if v4Subnet != "" && iface.IPv4 == "" {
			if ok, _ := ipInCIDR(addr.Local, v4Subnet); ok {
				iface.IPv4 = addr.Local
				iface.IPv4Prefix = v4Subnet
			}
		}

		// Check for IPv6 match
		if v6Subnet != "" && iface.IPv6 == "" {
			if ok, _ := ipInCIDR(addr.Local, v6Subnet); ok {
				iface.IPv6 = addr.Local
				iface.IPv6Prefix = v6Subnet
			}
		}
	}

	// Only consider this link a match if we found all requested IPs
	hasV4Match := v4Subnet == "" || iface.IPv4 != ""
	hasV6Match := v6Subnet == "" || iface.IPv6 != ""

	if hasV4Match && hasV6Match {
		iface.InfName = link.IfName
		iface.MAC = link.Mac
		return iface
	}

	// Not a complete match, return empty interface
	return api.NetworkInterface{}
}

// initializeNetworkLinks retrieves and caches the network links information from the vm.
func (m *vm) initializeNetworkLinks() error {
	result, err := m.execCmd("ip -j addr")
	if err != nil {
		return fmt.Errorf("failed to retrieve network links: %w", err)
	}

	var links []linkInfo
	if err := json.Unmarshal([]byte(result.stdout), &links); err != nil {
		return fmt.Errorf("failed to parse network links: %w", err)
	}

	m.netLinks = links
	return nil
}

func addElevatedPrivileges(cmd string) string {
	return fmt.Sprintf("sudo %s", cmd)
}

// escapeShellArgument properly quotes a string for use as a single argument in a shell command.
// This is a simplified version and might not cover all edge cases for all shells.
// For robust shell escaping, consider using a dedicated library if available,
// or ensure your remote shell is predictable (e.g., always bash).
func escapeShellArgument(arg string) string {
	// Simple rule: if it contains spaces or special characters, single-quote it.
	// Within single quotes, single quotes themselves need to be handled: '\''
	if strings.ContainsAny(arg, " \t\n\r\"'\\`$!{}[]()<>*?~#&;|") {
		return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return arg
}

func buildContainerCmd(name string, cmd []string) string {
	var b strings.Builder
	b.WriteString(containerengine.Get().String())
	b.WriteString(" exec -t ")
	b.WriteString(escapeShellArgument(name))
	b.WriteString(" ") // Add space after container name

	for i, arg := range cmd {
		if i > 0 { // Add space before subsequent arguments
			b.WriteString(" ")
		}
		b.WriteString(escapeShellArgument(arg))
	}

	return b.String()
}

func buildDaemonContainerCmd(container api.ExternalContainer) string {
	var b strings.Builder
	b.WriteString(containerengine.Get().String())
	b.WriteString(" run -itd --privileged --name ")
	b.WriteString(escapeShellArgument(container.Name))
	b.WriteString(" --hostname ")
	b.WriteString(escapeShellArgument(container.Name))
	if container.Network != nil {
		b.WriteString(fmt.Sprintf(" --network %s", container.Network.Name()))
	} else {
		b.WriteString(" --network none")
	}
	b.WriteString(" ")
	b.WriteString(escapeShellArgument(container.Image))
	for _, arg := range container.CmdArgs {
		b.WriteString(" ")
		b.WriteString(escapeShellArgument(arg))
	}
	return b.String()
}

func buildContainerCheckCmd(name string) string {
	return fmt.Sprintf("%s ps -f name=%s -q", containerengine.Get(), escapeShellArgument(name))
}

func buildContainerLogsCmd(name string) string {
	return fmt.Sprintf("%s logs %s", containerengine.Get(), escapeShellArgument(name))
}

func buildRemoveContainerCmd(name string) string {
	return fmt.Sprintf("%s rm -f %s", containerengine.Get(), escapeShellArgument(name))
}

func buildOneShotContainerCmd(image string, cmd []string, runtimeArgs []string) string {
	var b strings.Builder
	b.WriteString(containerengine.Get().String())
	b.WriteString(" run --rm ")
	for _, arg := range runtimeArgs {
		b.WriteString(" ")
		b.WriteString(escapeShellArgument(arg))
	}
	b.WriteString(" ")
	b.WriteString(escapeShellArgument(image))
	for _, arg := range cmd {
		b.WriteString(" ")
		b.WriteString(escapeShellArgument(arg))
	}
	return b.String()
}
