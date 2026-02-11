package infraprovider

import (
	"fmt"
	"net"
	"sync/atomic"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	utilnet "k8s.io/utils/net"
)

const (
	primaryNetworkName = "primary"
)

var vniCurrentValue uint32 = 99

func NextVNI() uint32 {
	return atomic.AddUint32(&vniCurrentValue, 1)
}

// hostNetwork implements the api.Network interface for OpenShift test provider.
// Contains the raw kcli network JSON fields from 'kcli show network' command.
type hostNetwork struct {
	name   string
	ifName string
	cidrs  []string
}

func (n hostNetwork) Name() string {
	return n.name
}

func (n hostNetwork) IPv4IPv6Subnets() (string, string, error) {
	if len(n.cidrs) == 0 {
		return "", "", fmt.Errorf("network %s has no CIDR configured", n.Name())
	}

	var v4, v6 string
	for _, cidr := range n.cidrs {
		if utilnet.IsIPv4CIDRString(cidr) {
			v4 = cidr
		} else if utilnet.IsIPv6CIDRString(cidr) {
			v6 = cidr
		} else {
			return "", "", fmt.Errorf("network %s CIDR %s is neither valid IPv4 nor IPv6", n.Name(), cidr)
		}
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
