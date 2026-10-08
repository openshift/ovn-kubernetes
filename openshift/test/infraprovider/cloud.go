// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0
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
	// bastionPrimaryNetworkName is the primary network name for bastion-based
	// platforms (AWS, Azure, GCP) where containers use host networking.
	bastionPrimaryNetworkName = "host"
	bastionSSHPort            = "22"
)

// sudoRunner wraps a Runner and prepends "sudo" to every command.
// On bastion hosts (AWS, GCP, Azure) the SSH user is unprivileged (core),
// so rootless podman containers exit when the SSH session terminates.
// Running podman under sudo avoids this.
type sudoRunner struct {
	inner api.Runner
}

func (s *sudoRunner) Run(command string, args ...string) (string, error) {
	return s.inner.Run("sudo", append([]string{command}, args...)...)
}

// initializeCloudInfra sets up a baseInfra by connecting to a bastion host
// via SSH and discovering its primary network interface. Used by cloud platforms
// (AWS, Azure, GCP) that share the same bastion-based external container pattern.
func initializeCloudInfra() (*baseInfra, error) {
	primaryNetworkName := bastionPrimaryNetworkName
	sshRunner, err := bastionSshCmdRunner()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ssh runner for bastion host: %w", err)
	}
	// sshRunner is nil when bastion host ssh access configuration files are not present.
	if sshRunner == nil {
		return nil, nil
	}

	// Verify SSH connectivity works
	if _, err := sshRunner.Run("echo", "connection test"); err != nil {
		return nil, fmt.Errorf("failed connectivity check with bastion host: %w", err)
	}

	// Wrap runner with sudo: the bastion SSH user (core) is unprivileged,
	// and rootless podman containers exit when the SSH session ends.
	podmanRunner := &sudoRunner{inner: sshRunner}
	h := &baseInfra{
		runner:             podmanRunner,
		externalContainers: make(map[string]api.ExternalContainer),
		engine:             container.NewEngine("podman", podmanRunner),
		primaryNetworkName: primaryNetworkName,
	}

	// Discover bastion host's primary network interface by finding the
	// interface that carries the default route.
	h.hostNetworkInfo, err = findDefaultRouteInterface(sshRunner)
	if err != nil {
		return nil, fmt.Errorf("failed to discover bastion host network interface: %w", err)
	}

	// Build primary network from bastion's interface prefixes.
	h.machineNetwork, err = buildMachineNetwork(primaryNetworkName, h.hostNetworkInfo)
	if err != nil {
		return nil, err
	}

	return h, nil
}

// bastionSshCmdRunner creates an SSH runner for the bastion host.
// Returns (nil, nil) when bastion access is not configured, for example
// when SHARED_DIR is unset or the required files are absent. This is
// expected when ovn-kubernetes-tests-ext runs with the list option
// outside a CI environment.
func bastionSshCmdRunner() (api.Runner, error) {
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

// findDefaultRouteInterface discovers the bastion's primary network interface
// by finding the interface that carries the default route.
func findDefaultRouteInterface(r api.Runner) (*api.NetworkInterface, error) {
	// Try IPv4 default route first, fall back to IPv6.
	devName, err := findDefaultRouteDev(r, false)
	if err != nil {
		return nil, fmt.Errorf("failed to find IPv4 default route: %w", err)
	}
	if devName == "" {
		devName, err = findDefaultRouteDev(r, true)
		if err != nil {
			return nil, fmt.Errorf("failed to find IPv6 default route: %w", err)
		}
	}
	if devName == "" {
		return nil, fmt.Errorf("no default route found (tried IPv4 and IPv6)")
	}

	// Get address info for that interface.
	addrOut, err := r.Run("ip", "-j", "addr", "show", "dev", devName)
	if err != nil {
		return nil, fmt.Errorf("failed to get address info for %s: %w", devName, err)
	}

	netInfo, err := parseInterfaceAddresses(devName, addrOut)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip address from interface %s: %w", devName, err)
	}
	return netInfo, nil
}

// findDefaultRouteDev discovers the device carrying the default route.
// When ipv6 is true it queries the IPv6 routing table, otherwise IPv4.
// Returns ("", nil) when the command succeeds but no routes are present.
func findDefaultRouteDev(r api.Runner, ipv6 bool) (string, error) {
	args := []string{"-j"}
	if ipv6 {
		args = append(args, "-6")
	}
	args = append(args, "route", "show", "default")
	out, err := r.Run("ip", args...)
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %w", err)
	}
	return extractDevFromRouteJSON(strings.TrimSpace(out))
}

// extractDevFromRouteJSON extracts the device name from ip -j route output.
// Returns ("", nil) when no routes are present. Uses the first entry which
// is sufficient for discovering the bastion's primary network interface.
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

// buildMachineNetwork creates a ContainerEngineNetwork from interface prefixes.
func buildMachineNetwork(netName string, netInfo *api.NetworkInterface) (api.Network, error) {
	if netInfo == nil {
		return nil, fmt.Errorf("no network info available to build machine network")
	}
	machineNetwork := &network.ContainerEngineNetwork{NetName: netName}
	var cidrs []network.ContainerEngineNetworkConfig
	if netInfo.IPv4Prefix != "" {
		cidrs = append(cidrs, network.ContainerEngineNetworkConfig{Subnet: netInfo.IPv4Prefix})
	}
	if netInfo.IPv6Prefix != "" {
		cidrs = append(cidrs, network.ContainerEngineNetworkConfig{Subnet: netInfo.IPv6Prefix})
	}
	machineNetwork.Configs = cidrs
	return machineNetwork, nil
}

// linkInfo and ipAddressInfo are used for parsing ip -j addr output.
type linkInfo struct {
	IfName   string          `json:"ifname"`
	Mac      string          `json:"address"`
	AddrInfo []ipAddressInfo `json:"addr_info"`
}

type ipAddressInfo struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}
