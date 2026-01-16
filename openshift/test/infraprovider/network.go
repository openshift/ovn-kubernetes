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

// openshiftNetwork implements the api.Network interface for OpenShift test provider.
// Contains the raw kcli network JSON fields from 'kcli show network' command.
type openshiftNetwork struct {
	name string
	CIDR   string `json:"cidr"`
	Dhcp   bool   `json:"dhcp"`
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Mode   string `json:"mode"`
	Plan   string `json:"plan"`
}

func (n openshiftNetwork) Name() string {
	return n.name
}

func (n openshiftNetwork) IPv4IPv6Subnets() (string, string, error) {
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

func (n openshiftNetwork) Equal(candidate api.Network) bool {
	if n.name != candidate.Name() {
		return false
	}
	return true
}

func (n openshiftNetwork) String() string {
	return n.name
}

func getOpenshiftNetwork(networkName string) (openshiftNetwork, error) {
	cmd := exec.Command("kcli", "show", "network", networkName, "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return openshiftNetwork{}, fmt.Errorf("failed to retrieve network %s, output: %s, err: %w", networkName, string(output), err)
	}

	network := openshiftNetwork{name: networkName}
	if err := json.Unmarshal(output, &network); err != nil {
		return network, fmt.Errorf("failed to unmarshal network %s output: %v, err: %w", networkName, string(output), err)
	}

	if network.CIDR == "" {
		return network, fmt.Errorf("network %s has no CIDR configured", networkName)
	}

	if !utilnet.IsIPv4CIDRString(network.CIDR) && !utilnet.IsIPv6CIDRString(network.CIDR) {
		return network, fmt.Errorf("network %s CIDR %s is neither valid IPv4 nor IPv6", networkName, network.CIDR)
	}

	return network, nil
}
