package infraprovider

import (
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	utilnet "k8s.io/utils/net"
)

const (
	defaultNetworkName = "default"
)

// hostNetwork implements the api.Network interface for OpenShift test provider.
// Contains the raw kcli network JSON fields from 'kcli show network' command.
type hostNetwork struct {
	name string
	cidr string
}

func (n hostNetwork) Name() string {
	return n.name
}

func (n hostNetwork) IPv4IPv6Subnets() (string, string, error) {
	if n.cidr == "" {
		return "", "", fmt.Errorf("network %s has no CIDR configured", n.Name())
	}

	var v4, v6 string
	if utilnet.IsIPv4CIDRString(n.cidr) {
		v4 = n.cidr
	} else if utilnet.IsIPv6CIDRString(n.cidr) {
		v6 = n.cidr
	} else {
		return "", "", fmt.Errorf("network %s CIDR %s is neither valid IPv4 nor IPv6", n.Name(), n.cidr)
	}
	return v4, v6, nil
}

func (n hostNetwork) Equal(candidate api.Network) bool {
	if n.name != candidate.Name() {
		return false
	}
	return true
}

func (n hostNetwork) String() string {
	return n.name
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
