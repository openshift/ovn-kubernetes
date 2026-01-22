package e2e

import (
	"fmt"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/kubernetes/test/e2e/framework"
	utilnet "k8s.io/utils/net"
)

// =============================================================================
// EVPN E2E Test Infrastructure
// =============================================================================
//
// This file contains utilities and tests for EVPN (Ethernet VPN) functionality
// in OVN-Kubernetes.
//
// =============================================================================
// Test Infrastructure Overview (PS: the values are just for illustration purposes)
// =============================================================================
//
// EVPN Test Infrastructure:
//
// +---------------------------------------+                      +------------------+
// | KIND Cluster                          |    KIND Primary      | External FRR     |
// |                                       |    Network           | (reused from BGP)|
// | +-------------+ +-------------+       |    (BGP/EVPN)        |                  |
// | | Node 1      | | Node 2      |       |    172.18.0.0/16     | eth0 (primary)   |
// | | - FRR-K8s   | | - FRR-K8s   |       | <----------------->  | br0 (EVPN)       |
// | | - OVN VTEP  | | - OVN VTEP  |       |                      | vxlan0 (VTEP)    |
// | +-------------+ +-------------+       |                      +------------------+
// |                                       |                             |
// | +-------------+ +----------------+    |         +------------------+--------------------+
// | | Node 3      | | Pod (on CUDN)  |    |         |   CUDN-network   | agnhost-ipvrf-net  |
// | | - FRR-K8s   | | 10.100.0.0/16  |    |         |   10.100.0.0/16  | 172.27.102.0/24    |
// | | - OVN VTEP  | +----------------+    |         +--------|---------+---------|---------+
// | +-------------+                       |                  |                   |
// +---------------------------------------+                  v                   v
//                                                   +------------------+--------------------+
//                                                   | agnhost-macvrf   | agnhost-ipvrf      |
//                                                   | 10.100.0.250     | 172.27.102.2       |
//                                                   | VNI: 10100       | VNI: 20102         |
//                                                   +------------------+--------------------+
//
// EVPN tests depend on the RouteAdvertisements/BGP infrastructure being set up
// during KIND cluster installation. EVPN tests REUSE the existing FRR container
// created at install time rather than creating a new one.
// We extend its configuration to support EVPN by adding:
//   - a Linux bridge with vlan_filtering for EVPN (unique per test, e.g. brevpn<suffix>)
//   - a VXLAN device (VTEP) with vnifilter for SVD mode (unique per test, e.g. vxevpn<suffix>)
//   - VRF and SVI configuration for IP-VRF tests
//   - Access ports for MAC-VRF tests
//   - BGP EVPN address-family configuration
//
// See OKEP: https://github.com/ovn-org/ovn-kubernetes/blob/master/docs/okeps/okep-5088-evpn.md for more details.

// =============================================================================
// EVPN Utilities
// =============================================================================

const (
	// externalFRRContainerName is the name of the external FRR container
	// created during KIND cluster setup with BGP enabled (./contrib/kind.sh -rae)
	externalFRRContainerName = "frr"
)

// setupEVPNBridgeOnExternalFRR creates a Linux bridge and VXLAN device on the external FRR
// container. This is the foundation for both MAC-VRF and IP-VRF tests.
//
// Creates:
//   - bridgeName (e.g. "brevpn7a3f"): Linux bridge with vlan_filtering enabled, vlan_default_pvid 0
//   - vxlanName  (e.g. "vxevpn7a3f"): VXLAN device in SVD (Single VXLAN Device) mode with vnifilter
//
// The vxlanName device is configured with:
//   - dstport 4789: Standard VXLAN port
//   - local <frrVTEPIPAddress>: Local VTEP IP (FRR's IP on KIND network) - in future when VTEP CR is implemented, this will be the VTEP IP
//   - nolearning: Disable MAC learning (controlled by BGP EVPN)
//   - external: Allow external FDB programming
//   - vnifilter: Enable per-VLAN VNI mapping (SVD mode)
//
// Cleanup is automatically registered via ictx.AddCleanUpFn().
func setupEVPNBridgeOnExternalFRR(ictx infraapi.Context, frrVTEPIPAddress, bridgeName, vxlanName string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

	// Create bridge with VLAN filtering
	commands := [][]string{
		{"ip", "link", "add", bridgeName, "type", "bridge", "vlan_filtering", "1", "vlan_default_pvid", "0"},
		{"ip", "link", "set", bridgeName, "addrgenmode", "none"},
	}

	for _, cmd := range commands {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd)
		if err != nil {
			return fmt.Errorf("failed to execute %v: %w", cmd, err)
		}
	}

	// Create VXLAN device in SVD mode
	vxlanCmd := []string{
		"ip", "link", "add", vxlanName, "type", "vxlan",
		"dstport", "4789",
		"local", frrVTEPIPAddress,
		"nolearning",
		"external",
		"vnifilter",
	}
	_, err := infraprovider.Get().ExecExternalContainerCommand(frr, vxlanCmd)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", vxlanName, err)
	}

	// Configure VXLAN device
	commands = [][]string{
		{"ip", "link", "set", vxlanName, "addrgenmode", "none"},
		{"ip", "link", "set", vxlanName, "master", bridgeName},
	}

	for _, cmd := range commands {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd)
		if err != nil {
			return fmt.Errorf("failed to execute %v: %w", cmd, err)
		}
	}

	// Bring up interfaces
	commands = [][]string{
		{"ip", "link", "set", bridgeName, "up"},
		{"ip", "link", "set", vxlanName, "up"},
	}

	for _, cmd := range commands {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd)
		if err != nil {
			return fmt.Errorf("failed to execute %v: %w", cmd, err)
		}
	}

	// Configure VXLAN bridge options for EVPN
	bridgeCmd := []string{
		"bridge", "link", "set", "dev", vxlanName,
		"vlan_tunnel", "on",
		"neigh_suppress", "on",
		"learning", "off",
	}
	_, err = infraprovider.Get().ExecExternalContainerCommand(frr, bridgeCmd)
	if err != nil {
		return fmt.Errorf("failed to configure %s bridge options: %w", vxlanName, err)
	}

	// Register cleanup to remove bridge and VXLAN device.
	ictx.AddCleanUpFn(func() error {
		frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

		// Delete VXLAN device first (it's attached to the bridge)
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", vxlanName})
		if err != nil {
			return fmt.Errorf("failed to delete %s: %w", vxlanName, err)
		}

		// Delete bridge
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", bridgeName})
		if err != nil {
			return fmt.Errorf("failed to delete %s: %w", bridgeName, err)
		}

		framework.Logf("EVPN bridge cleanup complete on %s", externalFRRContainerName)
		return nil
	})

	framework.Logf("EVPN bridge setup complete on %s (%s + %s with local IP %s)", externalFRRContainerName, bridgeName, vxlanName, frrVTEPIPAddress)
	return nil
}

// setupMACVRFOnExternalFRR configures MAC-VRF (Layer 2 EVPN) on the external FRR container.
// This adds the VLAN/VNI mapping to extend the L2 domain via EVPN Type-2/Type-3 routes.
//
// Requires: setupEVPNBridgeOnExternalFRR must be called first to create bridgeName and vxlanName.
//
// No explicit cleanup is registered here: deleting the bridge (done by setupEVPNBridgeOnExternalFRR's
// cleanup) removes all associated bridge VLAN and VNI entries automatically.
//
// Parameters:
//   - vni: VXLAN Network Identifier (e.g., 10100)
//   - vid: VLAN ID for local bridging (e.g., 100)
//   - bridgeName: name of the bridge device (e.g., "brevpn7a3f")
//   - vxlanName: name of the VXLAN device (e.g., "vxevpn7a3f")
func setupMACVRFOnExternalFRR(vni, vid int, bridgeName, vxlanName string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	vidStr := fmt.Sprintf("%d", vid)
	vniStr := fmt.Sprintf("%d", vni)

	commands := [][]string{
		// Add VLAN to bridge
		{"bridge", "vlan", "add", "dev", bridgeName, "vid", vidStr, "self"},
		// Add VLAN to vxlan device
		{"bridge", "vlan", "add", "dev", vxlanName, "vid", vidStr},
		// Add VNI to vxlan device
		{"bridge", "vni", "add", "dev", vxlanName, "vni", vniStr},
		// Map VLAN to VNI (tunnel_info)
		{"bridge", "vlan", "add", "dev", vxlanName, "vid", vidStr, "tunnel_info", "id", vniStr},
	}
	for _, cmd := range commands {
		if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd); err != nil {
			return fmt.Errorf("failed to setup MAC-VRF (VNI %d, VID %d): %w", vni, vid, err)
		}
	}

	framework.Logf("MAC-VRF setup complete on %s (VNI %d, VID %d)", externalFRRContainerName, vni, vid)
	return nil
}

// setupIPVRFOnExternalFRR configures IP-VRF (Layer 3 EVPN) on the external FRR container.
// This creates a Linux VRF with SVI for L3 routing via EVPN Type-5 routes.
//
// Requires: setupEVPNBridgeOnExternalFRR must be called first to create bridgeName and vxlanName.
//
// Parameters:
//   - vrfName: Name of the Linux VRF (e.g., "vrf202")
//   - vni: VXLAN Network Identifier (e.g., 20102)
//   - vid: VLAN ID for the SVI (e.g., 202)
//   - bridgeName: name of the bridge device (e.g., "brevpn7a3f")
//   - vxlanName: name of the VXLAN device (e.g., "vxevpn7a3f")
//
// Cleanup is automatically registered via ictx.AddCleanUpFn().
// Note: VLAN/VNI mappings are cleaned up when bridgeName/vxlanName are deleted.
func setupIPVRFOnExternalFRR(ictx infraapi.Context, vrfName string, vni, vid int, bridgeName, vxlanName string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	vidStr := fmt.Sprintf("%d", vid)
	vniStr := fmt.Sprintf("%d", vni)

	// Create Linux VRF with routing table = VNI
	_, err := infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "add", vrfName, "type", "vrf", "table", vniStr})
	if err != nil {
		return fmt.Errorf("failed to create VRF %s: %w", vrfName, err)
	}

	// Bring up VRF
	_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "set", vrfName, "up"})
	if err != nil {
		return fmt.Errorf("failed to bring up VRF %s: %w", vrfName, err)
	}

	// Configure VLAN/VNI mapping (reuse MAC-VRF setup for this part)
	if err := setupMACVRFOnExternalFRR(vni, vid, bridgeName, vxlanName); err != nil {
		return fmt.Errorf("failed to configure VLAN/VNI mapping: %w", err)
	}

	// Create SVI (VLAN sub-interface on bridgeName)
	sviName := fmt.Sprintf("%s.%d", bridgeName, vid)
	_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "add", sviName, "link", bridgeName, "type", "vlan", "id", vidStr})
	if err != nil {
		return fmt.Errorf("failed to create SVI %s: %w", sviName, err)
	}

	// Bind SVI to VRF
	_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "set", sviName, "master", vrfName})
	if err != nil {
		return fmt.Errorf("failed to bind SVI %s to VRF %s: %w", sviName, vrfName, err)
	}

	// Bring up SVI
	_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "set", sviName, "up"})
	if err != nil {
		return fmt.Errorf("failed to bring up SVI %s: %w", sviName, err)
	}

	// Register cleanup to remove SVI, Linux VRF, and FRR VRF definition
	ictx.AddCleanUpFn(func() error {
		frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

		// Delete SVI
		sviName := fmt.Sprintf("%s.%d", bridgeName, vid)
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr,
			[]string{"ip", "link", "del", sviName})
		if err != nil {
			framework.Logf("Warning: failed to delete SVI %s: %v", sviName, err)
		}

		// Delete Linux VRF
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
			[]string{"ip", "link", "del", vrfName})
		if err != nil {
			framework.Logf("Warning: failed to delete Linux VRF %s: %v", vrfName, err)
		}

		// Delete FRR VRF definition (now that Linux VRF is gone, FRR should allow this)
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand(
			"configure terminal", fmt.Sprintf("no vrf %s", vrfName), "end",
		))
		if err != nil {
			framework.Logf("Warning: failed to delete FRR VRF definition %s: %v", vrfName, err)
		}

		framework.Logf("IP-VRF cleanup complete on %s (VRF %s, VID %d)", externalFRRContainerName, vrfName, vid)
		return nil
	})

	framework.Logf("IP-VRF setup complete on %s (VRF %s, VNI %d, VID %d)", externalFRRContainerName, vrfName, vni, vid)
	return nil
}

// vtyshCommand builds a shell command that invokes vtysh with single-quoted -c arguments.
// Using sh -c with single-quoted args ensures correct argument parsing regardless of
// how the infra provider executes the command (docker exec, podman exec, SSH, etc.).
func vtyshCommand(args ...string) []string {
	var parts []string
	for _, arg := range args {
		parts = append(parts, fmt.Sprintf("-c '%s'", arg))
	}
	return []string{"sh", "-c", "vtysh " + strings.Join(parts, " ")}
}

// setupEVPNBGPOnExternalFRR ensures the global BGP EVPN settings are present on the external FRR container.
// This is a redundancy check — the l2vpn evpn address-family, advertise-all-vni, and neighbor
// activations are configured at KIND cluster install time (deploy_frr_external_container in kind-common.sh
// when ENABLE_EVPN=true). Calling this here is idempotent and guards against clusters not set up
// with ENABLE_EVPN.
//
// Parameters:
//   - asn: BGP Autonomous System Number (e.g., 64512)
//   - neighborIPs: List of cluster node IPs to peer with
//
// No cleanup is registered: these are shared cluster-level settings that must persist
// across all parallel EVPN tests.
func setupEVPNBGPOnExternalFRR(ictx infraapi.Context, asn int, neighborIPs []string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

	args := []string{"configure terminal", fmt.Sprintf("router bgp %d", asn), "address-family l2vpn evpn", "advertise-all-vni"}
	for _, ip := range neighborIPs {
		args = append(args, fmt.Sprintf("neighbor %s activate", ip))
	}
	args = append(args, "exit-address-family", "end")

	_, err := infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand(args...))
	if err != nil {
		return fmt.Errorf("failed to configure EVPN BGP: %w", err)
	}

	// No per-test BGP cleanup needed on the external FRR:
	// - advertise-all-vni: global setting, shared across all parallel tests
	// - neighbor <nodeIP> activate: all tests peer with the same cluster nodes
	// Both are baseline infrastructure set up by the KIND cluster install (kind.sh -rae)
	// and must persist for the duration of the test suite.
	// IP-VRF per-VRF BGP config is cleaned up by setupIPVRFBGPOnExternalFRR.
	ictx.AddCleanUpFn(func() error {
		framework.Logf("EVPN BGP cleanup complete on %s (no-op: global BGP settings are shared infrastructure)", externalFRRContainerName)
		return nil
	})

	framework.Logf("EVPN BGP setup complete on %s (ASN %d, neighbors: %v)", externalFRRContainerName, asn, neighborIPs)
	return nil
}

// setupIPVRFBGPOnExternalFRR configures BGP for an IP-VRF on the external FRR container.
// This binds the VRF to a VNI and configures route-targets for Type-5 route exchange.
//
// Requires: setupEVPNBGPOnExternalFRR must be called first for global EVPN BGP config.
//
// Parameters:
//   - vrfName: Name of the Linux VRF (must match the VRF created by setupIPVRFOnExternalFRR)
//   - asn: BGP ASN (e.g., 64512). Must match the cluster's frr-k8s ASN and the global EVPN
//     BGP instance. Used for both the VRF BGP instance and the Route Distinguisher/Route Target.
//   - vni: VXLAN Network Identifier for route-target (e.g., 20102)
//   - ipFamilies: IP families to configure (e.g., sets.New(utilnet.IPv4) or sets.New(utilnet.IPv4, utilnet.IPv6))
//   - subnets: Subnets to advertise via BGP (e.g., []string{"172.27.102.0/24"} or {"172.27.102.0/24", "fd00:102::/64"})
//
// Cleanup is automatically registered via ictx.AddCleanUpFn().
func setupIPVRFBGPOnExternalFRR(ictx infraapi.Context, vrfName string, asn, vni int, ipFamilies sets.Set[utilnet.IPFamily], subnets []string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	rt := fmt.Sprintf("%d:%d", asn, vni)

	// Build vtysh args
	args := []string{
		"configure terminal",
		fmt.Sprintf("vrf %s", vrfName), fmt.Sprintf("vni %d", vni), "exit-vrf",
		fmt.Sprintf("router bgp %d vrf %s", asn, vrfName),
	}

	// Configure address-families with explicit network statements
	// (Using explicit 'network' statements instead of 'redistribute connected' to align
	// with how OVN-K advertises routes via RouteAdvertisements/FRRConfiguration Prefixes)
	if ipFamilies.Has(utilnet.IPv4) {
		args = append(args, "address-family ipv4 unicast")
		for _, subnet := range subnets {
			if !utilnet.IsIPv6CIDRString(subnet) {
				args = append(args, fmt.Sprintf("network %s", subnet))
			}
		}
		args = append(args, "exit-address-family")
	}
	if ipFamilies.Has(utilnet.IPv6) {
		args = append(args, "address-family ipv6 unicast")
		for _, subnet := range subnets {
			if utilnet.IsIPv6CIDRString(subnet) {
				args = append(args, fmt.Sprintf("network %s", subnet))
			}
		}
		args = append(args, "exit-address-family")
	}

	// l2vpn evpn - configure RD, RT, and advertise unicast routes
	args = append(args, "address-family l2vpn evpn", fmt.Sprintf("rd %s", rt), fmt.Sprintf("route-target import %s", rt), fmt.Sprintf("route-target export %s", rt))
	if ipFamilies.Has(utilnet.IPv4) {
		args = append(args, "advertise ipv4 unicast")
	}
	if ipFamilies.Has(utilnet.IPv6) {
		args = append(args, "advertise ipv6 unicast")
	}
	args = append(args, "exit-address-family", "end")

	_, err := infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand(args...))
	if err != nil {
		return fmt.Errorf("failed to configure IP-VRF BGP for %s: %w", vrfName, err)
	}

	// Register cleanup to remove BGP VRF instance and VRF-VNI binding
	// NOTE: This cleanup may run after setupIPVRFOnExternalFRR cleanup has already deleted
	// the Linux VRF device, which triggers FRR to auto-cleanup the VRF config. In that case,
	// these commands may fail - that's OK, we just log warnings and won't retry that.
	ictx.AddCleanUpFn(func() error {
		frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand(
			"configure terminal", fmt.Sprintf("vrf %s", vrfName), fmt.Sprintf("no vni %d", vni), "exit-vrf", "end",
		))
		if err != nil {
			framework.Logf("Warning: failed to remove VNI binding (may already be cleaned up): %v", err)
		}

		_, err = infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand(
			"configure terminal", fmt.Sprintf("no router bgp %d vrf %s", asn, vrfName), "end",
		))
		if err != nil {
			framework.Logf("Warning: failed to remove BGP VRF (may already be cleaned up): %v", err)
		}

		// NOTE: We intentionally do NOT run "no vrf" here.
		// FRR's VRF definition is tied to the Linux VRF and will auto-cleanup
		// when the Linux VRF is deleted by setupIPVRFOnExternalFRR's cleanup.
		// Trying to delete the FRR VRF while the Linux VRF still has interfaces
		// attached causes "Only inactive VRFs can be deleted" errors.

		framework.Logf("IP-VRF BGP cleanup complete on %s (VRF %s)", externalFRRContainerName, vrfName)
		return nil
	})

	framework.Logf("IP-VRF BGP setup complete on %s (VRF %s, ASN %d, VNI %d, RT %s, families %v)", externalFRRContainerName, vrfName, asn, vni, rt, ipFamilies.UnsortedList())
	return nil
}
