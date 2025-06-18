package openshift

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
)

type baremetaldsNetwork struct {
	name string
	containerNetworkName
	ipv4 *baremetaldsNetworkConfig
	ipv6 *baremetaldsNetworkConfig
}

type baremetaldsNetworkConfig struct {
	Subnet  string `json:"Subnet"`
	Gateway string `json:"Gateway"`
}

func (n baremetaldsNetworkConfig) Name() string {
	return n.name
}

func (n baremetaldsNetworkConfig) IPv4IPv6Subnets() (string, string, error) {
	if n.ipv4 == nil && n.ipv6 == nil {
		return "", "", fmt.Errorf("failed to get IPV4/V6 because network doesnt contain configuration")
	}
	var v4, v6 string
	if n.ipv4 != nil {
		if n.ipv4.Subnet == "" {
			return "", "", fmt.Errorf("failed to get IPV4 because network %s contains a config with an empty subnet", n.Name())
		}
		v4 = n.ipv4.Subnet
	}
	if n.ipv6 != nil {
		if n.ipv6.Subnet == "" {
			return "", "", fmt.Errorf("failed to get IPV6 because network %s contains a config with an empty subnet", n.Name())
		}
		v6 = n.ipv6.Subnet
	}
	return v4, v6, nil
}

func (n baremetaldsNetworkConfig) Equal(candidate api.Network) bool {
	if n.name != candidate.Name() {
		return false
	}
	return true
}

func (n baremetaldsNetworkConfig) String() string {
	return n.name
}
