// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocators

// These variables define subnets used for allocations in e2e tests.
// Exclusions are supported if needed, see newSubnetSpec
// TODO define these through DeploymentConfig

var (
	// UDN subnets, 1024 available
	// avoiding potential collisions with
    // - 10.88.0.0/16  (podman default network)
	// - 10.96.0.0/16  (Kubernetes services)
	// - 10.128.0.0/14 (cluster default network)
	// - 10.243.0.0/16 (cluster default network)
	// - 10.244.0.0/16 (cluster default network)
	udnSubnets  = "10.0.0.0/10/20"
	udnSubnets6 = "fd00::/42/52"

	// Note that all BGP/EVPN subnets are derived from a single allocation so it
	// does not make sense to have some subnets with broader range than others
	// and particularly the VID allocation range limit of 4096/2 (half range
	// since we allocate two VIDs for MACVRF and IPVRF).
	
	// BGP peering and EVPN IP-VRF subnets, 1024 available each
	// avoiding potential collisions with:
	// - 172.18.0.0/16 (KIND primary network)
	// - 172.19.0.0/16 (XGW network)
	// - 172.22.0.0/16 (MetalLB client network)
	// - 172.26.0.0/16 (BGP server network)
	bgpPeerSubnets  = "172.36.0.0/19/29"
	bgpPeerSubnets6 = "fc00::/102/112"
	ipvrfSubnets  = "172.27.0.0/19/29"
	ipvrfSubnets6 = "fd01::/102/112"

	// EVPN VTEP subnets, 1024 available
	// avoiding potential collisions with:
	// - 100.64.0.0/16 (default join subnet)
	// - 100.65.0.0/16 (UDN primary join subnet)
	vtepSubnets  = "100.66.0.0/14/24"
	vtepSubnets6 = "fd02:4200::/102/112"
)
