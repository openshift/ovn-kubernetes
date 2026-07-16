// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
)

const (
	// ARPProxyIPv4 is a randomly chosen IPv4 link-local address that KubeVirt
	// pods use as their default gateway.
	ARPProxyIPv4 = "169.254.1.1"

	// ARPProxyIPv6 is a randomly chosen IPv6 link-local address that KubeVirt
	// pods use as their default gateway.
	ARPProxyIPv6 = "fe80::1"

	// ARPProxyMAC is generated from ARPProxyIPv4 using util.IPAddrToHWAddr.
	ARPProxyMAC = "0a:58:a9:fe:01:01"
)

// ComposeARPProxyLSPOption returns the "arp_proxy" field needed on router-type
// LSPs to implement a stable default gateway for pod IP migration. It consists
// of a generated MAC address, link-local IPv4 and IPv6 addresses shared by all
// logical switches, and the cluster subnets that allow the migrated VM to ping
// pods in the same subnet.
// This is how it works step by step:
// For the default gateway:
//   - VM is configured with arp proxy IPv4/IPv6 as default gw
//   - when a VM accesses an address that does not belong to its subnet, it will
//     send an ARP asking for the default gw IP
//   - This will reach the OVN flows from arp_proxy and answer back with the
//     mac address here
//   - The VM will send the packet with that MAC address so OVN can route it.
//
// For a VM accessing pods in the same subnet after live migration:
//   - Since the dst address is in the same subnet, it will
//     not use default gw and will send an ARP for dst IP
//   - The logical switch does not have any LSP with that address since
//     the VM has been live migrated
//   - ovn will fallback to arp_proxy flows to resolve ARP (these flows have
//     lower priority than LSP flows, so they don't collide with them)
//   - The OVN flow for the cluster-wide CIDR will be hit and OVN will answer
//     back with arp_proxy mac
//   - VM will send the packet to that MAC and OVN will route it.
func ComposeARPProxyLSPOption() string {
	arpProxy := []string{ARPProxyMAC, ARPProxyIPv4, ARPProxyIPv6}
	for _, clusterSubnet := range config.Default.ClusterSubnets {
		arpProxy = append(arpProxy, clusterSubnet.CIDR.String())
	}
	return strings.Join(arpProxy, " ")
}
