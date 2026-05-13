// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocators

import (
	"sync"

	"k8s.io/kubernetes/test/e2e/framework"

	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

const (
	bgpKey = "bgp"

	// VID valid range is 2-4094 (0, 1, 4095 are reserved)
	vidMin = 2
	vidMax = 4094

	// VNI valid range is 1-16777215 (24-bit)
	vniMax = 16777215
	// Even offset so MACVRF VNIs are always even and don't correlate with VIDs.
	vniOffset = vniMax/2 + 1
)

var (
	bgpOnce              sync.Once
	bgpPeerV4, bgpPeerV6 subnetSpec
	ipvrfV4, ipvrfV6     subnetSpec
	vtepV4, vtepV6       subnetSpec
)

type BGPAllocation struct {
	BGPPeerSubnet  string
	BGPPeerSubnet6 string
	IPVRFSubnet    string
	IPVRFSubnet6   string
	VTEPSubnet     string
	VTEPSubnet6    string
	MACVRFVNI      int
	MACVRFVID      int
	IPVRFVNI       int
	IPVRFVID       int
}

// AllocateBGP allocates non-overlapping BGP peering subnets, IP-VRF subnets,
// VTEP subnets, VNIs and VIDs for parallel test isolation. All resources are
// derived from a single integer allocated with AllocateInt. Deallocation is
// registered as a cleanup function.
func AllocateBGP(f *framework.Framework, cleanup infraapi.ContextCleanUp) (BGPAllocation, error) {
	bgpOnce.Do(func() {
		bgpPeerV4 = newSubnetSpec(bgpPeerSubnets, nil)
		bgpPeerV6 = newSubnetSpec(bgpPeerSubnets6, nil)
		ipvrfV4 = newSubnetSpec(ipvrfSubnets, nil)
		ipvrfV6 = newSubnetSpec(ipvrfSubnets6, nil)
		vtepV4 = newSubnetSpec(vtepSubnets, nil)
		vtepV6 = newSubnetSpec(vtepSubnets6, nil)
	})

	maxUsable := min(
		bgpPeerV4.usable(), bgpPeerV6.usable(),
		ipvrfV4.usable(), ipvrfV6.usable(),
		vtepV4.usable(), vtepV6.usable(),
		(vidMax-vidMin+1)/2,
		(vniMax-vniOffset+1)/2,
	)

	n, err := AllocateInt(f, bgpKey, maxUsable)
	if err != nil {
		return BGPAllocation{}, err
	}

	cleanup.AddCleanUpFn(func() error {
		return DeallocateInt(f, bgpKey, n)
	})

	bgpV4Idx := bgpPeerV4.nthFree(n)
	bgpV6Idx := bgpPeerV6.nthFree(n)
	ipvrfV4Idx := ipvrfV4.nthFree(n)
	ipvrfV6Idx := ipvrfV6.nthFree(n)
	vtepV4Idx := vtepV4.nthFree(n)
	vtepV6Idx := vtepV6.nthFree(n)

	// Each allocation consumes two VIDs (MACVRF + IPVRF). MACVRF gets even
	// VIDs and IPVRF gets odd VIDs so different allocations never collide.
	macvrfVID := (n-1)*2 + vidMin
	ipvrfVID := macvrfVID + 1
	// Same stride-by-2 scheme for VNIs: MACVRF gets even, IPVRF gets odd.
	macvrfVNI := (n-1)*2 + vniOffset
	ipvrfVNI := macvrfVNI + 1

	return BGPAllocation{
		BGPPeerSubnet:  bgpPeerV4.cidr(bgpV4Idx),
		BGPPeerSubnet6: bgpPeerV6.cidr(bgpV6Idx),
		IPVRFSubnet:    ipvrfV4.cidr(ipvrfV4Idx),
		IPVRFSubnet6:   ipvrfV6.cidr(ipvrfV6Idx),
		VTEPSubnet:     vtepV4.cidr(vtepV4Idx),
		VTEPSubnet6:    vtepV6.cidr(vtepV6Idx),
		MACVRFVNI:      macvrfVNI,
		MACVRFVID:      macvrfVID,
		IPVRFVNI:       ipvrfVNI,
		IPVRFVID:       ipvrfVID,
	}, nil
}
