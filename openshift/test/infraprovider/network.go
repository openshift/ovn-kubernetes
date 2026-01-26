package infraprovider

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	utilnet "k8s.io/utils/net"
)

const (
	defaultNetworkName = "ostestbm"
)

// hostNetwork implements the api.Network interface for OpenShift test provider.
// Contains the raw kcli network JSON fields from 'kcli show network' command.
type hostNetwork struct {
	Net    string `json:"-"`
	CIDR   string `json:"cidr"`
	Dhcp   bool   `json:"dhcp"`
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Mode   string `json:"mode"`
	Plan   string `json:"plan"`
}

func (n hostNetwork) Name() string {
	return n.Net
}

func (n hostNetwork) IPv4IPv6Subnets() (string, string, error) {
	if n.CIDR == "" {
		return "", "", fmt.Errorf("network %s has no CIDR configured", n.Name())
	}

	var v4, v6 string
	if utilnet.IsIPv4CIDRString(n.CIDR) {
		v4 = n.CIDR
	} else if utilnet.IsIPv6CIDRString(n.CIDR) {
		v6 = n.CIDR
	} else {
		return "", "", fmt.Errorf("network %s CIDR %s is neither valid IPv4 nor IPv6", n.Name(), n.CIDR)
	}
	return v4, v6, nil
}

func (n hostNetwork) Equal(candidate api.Network) bool {
	if n.Net != candidate.Name() {
		return false
	}
	return true
}

func (n hostNetwork) String() string {
	return n.Net
}

func listNetworks() (map[string]hostNetwork, error) {
	cmd := exec.Command("kcli", "list", "net", "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list networks, output: %s, err: %w", string(output), err)
	}
	var networks map[string]hostNetwork
	if err := json.Unmarshal(output, &networks); err != nil {
		return nil, fmt.Errorf("failed to parse networks, output: %s, err: %w", string(output), err)
	}
	for name, network := range networks {
		network.Net = name
		networks[name] = network
	}
	return networks, nil
}

func getNetwork(name string) (*hostNetwork, error) {
	cmd := exec.Command("kcli", "show", "network", name, "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve network %s, output: %s, err: %w", name, string(output), err)
	}

	network := &hostNetwork{Net: name}
	if err := json.Unmarshal(output, network); err != nil {
		return nil, fmt.Errorf("failed to unmarshal network %s output: %v, err: %w", name, string(output), err)
	}

	if network.CIDR == "" {
		return nil, fmt.Errorf("network %s has no CIDR configured", name)
	}

	if !utilnet.IsIPv4CIDRString(network.CIDR) && !utilnet.IsIPv6CIDRString(network.CIDR) {
		return nil, fmt.Errorf("network %s CIDR %s is neither valid IPv4 nor IPv6", name, network.CIDR)
	}

	return network, nil
}

func createNetwork(name, cidr string) (*hostNetwork, error) {
	cmd := exec.Command("kcli", "create", "network", name, "-c", cidr, "-i")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create network %s, output: %s, err: %w", name, string(output), err)
	}
	return getNetwork(name)
}

func deleteNetwork(name string) error {
	cmd := exec.Command("kcli", "remove", "network", name, "-y")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete network %s, output: %s, err: %w", name, string(output), err)
	}
	return nil
}
