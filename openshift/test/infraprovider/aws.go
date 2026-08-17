package infraprovider

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
)

const (
	bastionSSHPort        = "22"
	awsPrimaryNetworkName = "host"
)

func initializeAWSInfra() (*baseInfra, error) {
	sshRunner, err := bastionSshCmdRunner()
	if err != nil {
		return nil, err
	}
	if sshRunner == nil {
		return nil, nil
	}

	// Verify SSH connectivity works
	if _, err := sshRunner.Run("echo", "connection test"); err != nil {
		return nil, fmt.Errorf("failed connectivity check with bastion host: %w", err)
	}

	h := &baseInfra{
		runner:             sshRunner,
		externalContainers: make(map[string]api.ExternalContainer),
		engine:             container.NewEngine("podman", sshRunner),
		primaryNetworkName: awsPrimaryNetworkName,
	}

	// Discover bastion host's primary network interface by finding the
	// interface that carries the default route.
	h.hostNetworkInfo, err = findDefaultRouteInterface(sshRunner)
	if err != nil {
		return nil, fmt.Errorf("failed to discover bastion host network interface: %w", err)
	}

	// Build primary network from bastion's interface prefixes.
	machineNetwork := &network.ContainerEngineNetwork{NetName: awsPrimaryNetworkName}
	var cidrs []network.ContainerEngineNetworkConfig
	if h.hostNetworkInfo.IPv4Prefix != "" {
		cidrs = append(cidrs, network.ContainerEngineNetworkConfig{Subnet: h.hostNetworkInfo.IPv4Prefix})
	}
	if h.hostNetworkInfo.IPv6Prefix != "" {
		cidrs = append(cidrs, network.ContainerEngineNetworkConfig{Subnet: h.hostNetworkInfo.IPv6Prefix})
	}
	machineNetwork.Configs = cidrs
	h.machineNetwork = machineNetwork

	return h, nil
}

// findDefaultRouteInterface discovers the bastion's primary network interface
// by finding the interface that carries the default route.
func findDefaultRouteInterface(runner api.Runner) (*api.NetworkInterface, error) {
	// Try IPv4 default route first, fall back to IPv6.
	devName, err := findDefaultRouteDev(runner, "ip", "-j", "route", "show", "default")
	if err != nil {
		return nil, err
	}
	if devName == "" {
		devName, err = findDefaultRouteDev(runner, "ip", "-j", "-6", "route", "show", "default")
		if err != nil {
			return nil, err
		}
	}
	if devName == "" {
		return nil, fmt.Errorf("no default route found (tried IPv4 and IPv6)")
	}

	// Get address info for that interface.
	addrOut, err := runner.Run("ip", "-j", "addr", "show", "dev", devName)
	if err != nil {
		return nil, fmt.Errorf("failed to get address info for %s: %w", devName, err)
	}

	netInfo, err := parseInterfaceAddresses(devName, addrOut)
	if err != nil {
		return nil, err
	}
	return netInfo, nil
}

// findDefaultRouteDev runs an ip route command and extracts the device name
// from the route with the lowest metric. Returns ("", nil) when the command
// succeeds but no routes are present.
func findDefaultRouteDev(runner api.Runner, cmd string, args ...string) (string, error) {
	out, err := runner.Run(cmd, args...)
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %w", err)
	}
	return extractDevFromRouteJSON(strings.TrimSpace(out))
}

// extractDevFromRouteJSON extracts the device name from ip -j route output.
// Returns ("", nil) when no routes are present. Uses the first entry since
// the kernel returns routes sorted by priority (lowest metric first).
func extractDevFromRouteJSON(jsonStr string) (string, error) {
	type routeEntry struct {
		Dev string `json:"dev"`
	}
	var routes []routeEntry
	if err := json.Unmarshal([]byte(jsonStr), &routes); err != nil {
		return "", fmt.Errorf("failed to parse route JSON: %w", err)
	}
	if len(routes) == 0 {
		return "", nil
	}
	if routes[0].Dev == "" {
		return "", fmt.Errorf("default route has no device")
	}
	return routes[0].Dev, nil
}

// parseInterfaceAddresses parses ip -j addr show output for a single interface
// and returns its IPv4/IPv6 addresses.
func parseInterfaceAddresses(devName, jsonStr string) (*api.NetworkInterface, error) {
	var links []linkInfo
	if err := json.Unmarshal([]byte(jsonStr), &links); err != nil {
		return nil, fmt.Errorf("failed to parse address info for %s: %w", devName, err)
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("no address info found for interface %s", devName)
	}

	netInfo := &api.NetworkInterface{
		InfName: devName,
		MAC:     links[0].Mac,
	}
	for _, addr := range links[0].AddrInfo {
		switch addr.Family {
		case "inet":
			if netInfo.IPv4 == "" {
				netInfo.IPv4 = addr.Local
				netInfo.IPv4Prefix = fmt.Sprintf("%s/%d", addr.Local, addr.PrefixLen)
			}
		case "inet6":
			// Skip link-local addresses
			if netInfo.IPv6 == "" && !strings.HasPrefix(addr.Local, "fe80") {
				netInfo.IPv6 = addr.Local
				netInfo.IPv6Prefix = fmt.Sprintf("%s/%d", addr.Local, addr.PrefixLen)
			}
		}
	}
	return netInfo, nil
}

func bastionSshCmdRunner() (api.Runner, error) {
	// Read Bastion IP from shared directory
	ip, err := readSharedDirFile("bastion_public_address", "bastion ip")
	if err != nil {
		return nil, err
	}
	if ip == "" {
		return nil, nil
	}

	// Read SSH user for bastion host
	user, err := readSharedDirFile("bastion_ssh_user", "bastion ssh user")
	if err != nil {
		return nil, err
	}
	if user == "" {
		return nil, nil
	}

	// Find SSH key for bastion host access
	sshKeyPath, err := findClusterProfileFile("ssh-privatekey")
	if err != nil {
		return nil, err
	}
	if sshKeyPath == "" {
		return nil, nil
	}

	sshRunner, err := runner.NewSSHRunner(ip, user, bastionSSHPort, sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh runner for bastion host: %w", err)
	}

	return sshRunner, nil
}
