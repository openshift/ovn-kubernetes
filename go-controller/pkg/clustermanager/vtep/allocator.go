// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package vtep

import (
	"fmt"
	"net"

	utilnet "k8s.io/utils/net"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/clustermanager/node"
	vtepv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/vtep/v1"
)

const (
	ipv4HostSubnetLen = 32
	ipv6HostSubnetLen = 128
)

// vtepIPAllocator allocates individual VTEP IPs from a set of CIDRs for
// managed-mode VTEPs. It wraps node.SubnetAllocator with /32 (IPv4) and
// /128 (IPv6) host subnet lengths, so each "subnet" allocation is exactly
// one IP address. Multiple CIDRs of the same family are supported with
// natural overflow: the first range is exhausted before the next is used.
type vtepIPAllocator struct {
	allocator node.SubnetAllocator
}

// newVTEPIPAllocator creates an allocator from the given VTEP CIDRs. Each
// CIDR is added as a network range with a single-IP host prefix (/32 or /128).
func newVTEPIPAllocator(cidrs []vtepv1.CIDR) (*vtepIPAllocator, error) {
	a := &vtepIPAllocator{
		allocator: node.NewSubnetAllocator(),
	}
	for _, cidr := range cidrs {
		if err := a.addCIDR(cidr); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *vtepIPAllocator) addCIDR(cidr vtepv1.CIDR) error {
	_, ipNet, err := net.ParseCIDR(string(cidr))
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	hostLen := ipv4HostSubnetLen
	if utilnet.IsIPv6CIDR(ipNet) {
		hostLen = ipv6HostSubnetLen
	}
	if err := a.allocator.AddNetworkRange(ipNet, hostLen); err != nil {
		return fmt.Errorf("failed to add CIDR %q to allocator: %w", cidr, err)
	}
	return nil
}

// allocateForNode allocates the next available IP per family for the given
// node. The underlying allocator is idempotent: if the node already has an
// allocation for a family it is returned as-is. Returns one /32 or /128
// net.IPNet per configured family (IPv4 first, then IPv6).
func (a *vtepIPAllocator) allocateForNode(nodeName string) ([]*net.IPNet, error) {
	return a.allocator.AllocateNetworks(nodeName)
}

// markAllocatedForNode reserves specific IPs for a node. Each IP is
// wrapped in a /32 or /128 net.IPNet before being passed to the
// underlying allocator. Used during initial sync to restore allocations
// from node annotations.
func (a *vtepIPAllocator) markAllocatedForNode(nodeName string, ips []net.IP) error {
	ipNets := make([]*net.IPNet, 0, len(ips))
	for _, ip := range ips {
		mask := net.CIDRMask(ipv4HostSubnetLen, ipv4HostSubnetLen)
		if utilnet.IsIPv6(ip) {
			mask = net.CIDRMask(ipv6HostSubnetLen, ipv6HostSubnetLen)
		}
		ipNets = append(ipNets, &net.IPNet{IP: ip, Mask: mask})
	}
	return a.allocator.MarkAllocatedNetworks(nodeName, ipNets...)
}

// replaceRange replaces an existing CIDR in the allocator with a wider one.
// The new CIDR must be a supernet of the old one (guaranteed by CEL validation
// in managed mode). Existing allocations from the old range are preserved.
func (a *vtepIPAllocator) replaceRange(oldCIDR, newCIDR vtepv1.CIDR) error {
	_, oldNet, err := net.ParseCIDR(string(oldCIDR))
	if err != nil {
		return fmt.Errorf("invalid old CIDR %q: %w", oldCIDR, err)
	}
	_, newNet, err := net.ParseCIDR(string(newCIDR))
	if err != nil {
		return fmt.Errorf("invalid new CIDR %q: %w", newCIDR, err)
	}
	hostLen := ipv4HostSubnetLen
	if utilnet.IsIPv6CIDR(newNet) {
		hostLen = ipv6HostSubnetLen
	}
	return a.allocator.ReplaceNetworkRange(oldNet, newNet, hostLen)
}

// releaseNode frees all allocations for the given node.
func (a *vtepIPAllocator) releaseNode(nodeName string) {
	a.allocator.ReleaseAllNetworks(nodeName)
}
