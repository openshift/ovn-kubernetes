package e2e

import (
	"fmt"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"k8s.io/kubernetes/test/e2e/framework"
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
		vtyshCmd := fmt.Sprintf("vtysh -c 'configure terminal' -c 'no vrf %s' -c 'end'", vrfName)
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr, []string{"sh", "-c", vtyshCmd})
		if err != nil {
			framework.Logf("Warning: failed to delete FRR VRF definition %s: %v", vrfName, err)
		}

		framework.Logf("IP-VRF cleanup complete on %s (VRF %s, VID %d)", externalFRRContainerName, vrfName, vid)
		return nil
	})

	framework.Logf("IP-VRF setup complete on %s (VRF %s, VNI %d, VID %d)", externalFRRContainerName, vrfName, vni, vid)
	return nil
}
