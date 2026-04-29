// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	udnv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	vtepv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/vtep/v1"
	vtepclientset "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/vtep/v1/apis/clientset/versioned"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
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
	// agnhostHTTPPort is the HTTP port for agnhost netexec
	agnhostHTTPPort = 8080
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

		// Delete VXLAN device first (it's attached to the bridge).
		// Tolerate "not found" / "does not exist" — device may have been
		// removed already by DestroyEVPNKernelStateOnFRR or a container restart.
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", vxlanName})
		if err != nil && !strings.Contains(err.Error(), "Cannot find device") && !strings.Contains(err.Error(), "does not exist") && !strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("failed to delete %s: %w", vxlanName, err)
		}

		// Delete bridge
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", bridgeName})
		if err != nil && !strings.Contains(err.Error(), "Cannot find device") && !strings.Contains(err.Error(), "does not exist") && !strings.Contains(err.Error(), "not found") {
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
		args = append(args, fmt.Sprintf("neighbor %s route-reflector-client", ip))
	}
	args = append(args, "exit-address-family", "end", "write memory")

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
	args = append(args, "exit-address-family", "end", "write memory")

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

		// Persist the cleaned-up config so that FRR container restarts (in disruptive tests)
		// don't re-load stale VRF BGP config from /etc/frr/frr.conf.
		if _, wmErr := infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand("write memory")); wmErr != nil {
			framework.Logf("Warning: failed to persist FRR config after IP-VRF BGP cleanup: %v", wmErr)
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

// =============================================================================
// EVPN Agnhost Utilities
// =============================================================================

// evpnAgnhostInfo holds the discovered network information for an EVPN agnhost container.
type evpnAgnhostInfo struct {
	agnhostIPs       []string
	agnhostInterface string
	frrIPs           []string
	frrInterface     string
}

// createEVPNAgnhost creates a Docker network with the given subnets, creates an agnhost
// container on it, attaches FRR to it, and discovers the assigned IPs and interface names.
//
// This is the shared foundation for both MAC-VRF and IP-VRF agnhost setups.
// The caller is responsible for configuring FRR's interface (e.g., adding it to bridgeName
// as an access port for MAC-VRF, or putting it in a VRF for IP-VRF).
//
// Parameters:
//   - networkName: Name for the Docker network (e.g., "macvrf-net-100", "ipvrf-net-202")
//   - containerName: Name for the agnhost container (e.g., "agnhost-macvrf-100")
//   - ipFamilies: Cluster IP family support, used to filter discovered IPs
//   - subnets: Subnets for the Docker network (e.g., "10.100.0.0/16" for IPv4, or both for dual-stack)
//   - ipv4: Optional IPv4 address to request for the agnhost container (empty = let IPAM decide)
//   - ipv6: Optional IPv6 address to request for the agnhost container (empty = let IPAM decide)
func createEVPNAgnhost(ictx infraapi.Context, networkName, containerName string, ipFamilies sets.Set[utilnet.IPFamily], subnets []string, ipv4, ipv6 string) (*evpnAgnhostInfo, error) {
	// Step 1: Create Docker network with specific subnet(s)
	network, err := ictx.CreateNetwork(networkName, subnets...)
	if err != nil {
		return nil, fmt.Errorf("failed to create network %s: %w", networkName, err)
	}

	// Step 2: Create agnhost container on that network
	agnhostContainer := infraapi.ExternalContainer{
		Name:        containerName,
		Image:       deploymentconfig.Get().GetAgnHostContainerImage(),
		Network:     network,
		IPv4:        ipv4,
		IPv6:        ipv6,
		CmdArgs:     []string{"netexec", fmt.Sprintf("--http-port=%d", agnhostHTTPPort)},
		RuntimeArgs: []string{"--cap-add=NET_ADMIN"},
	}
	_, err = ictx.CreateExternalContainer(agnhostContainer)
	if err != nil {
		return nil, fmt.Errorf("failed to create agnhost container %s: %w", containerName, err)
	}

	// Step 3: Connect FRR to the network
	_, err = ictx.AttachNetwork(network, externalFRRContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to connect FRR to network %s: %w", networkName, err)
	}

	// Step 4: Discover assigned IPs and interface names
	agnhostNetInf, err := infraprovider.Get().GetExternalContainerNetworkInterface(
		infraapi.ExternalContainer{Name: containerName}, network)
	if err != nil {
		return nil, fmt.Errorf("failed to get agnhost network interface: %w", err)
	}

	frrNetInf, err := infraprovider.Get().GetExternalContainerNetworkInterface(
		infraapi.ExternalContainer{Name: externalFRRContainerName}, network)
	if err != nil {
		return nil, fmt.Errorf("failed to get FRR network interface: %w", err)
	}

	frrInterface := frrNetInf.InfName
	if frrInterface == "" {
		return nil, fmt.Errorf("FRR interface name not found for network %s", networkName)
	}

	agnhostInterface := agnhostNetInf.InfName
	if agnhostInterface == "" {
		return nil, fmt.Errorf("agnhost interface name not found for network %s", networkName)
	}

	// Collect IPs only for cluster-supported address families.
	// Docker may assign IPs for families we didn't request (e.g., default IPv4 on IPv6-only networks),
	// so we filter based on what the cluster actually supports.
	var agnhostIPs, frrIPs []string
	if ipFamilies.Has(utilnet.IPv4) {
		if agnhostNetInf.IPv4 != "" {
			agnhostIPs = append(agnhostIPs, agnhostNetInf.IPv4)
		}
		if frrNetInf.IPv4 != "" {
			frrIPs = append(frrIPs, frrNetInf.IPv4)
		}
	}
	if ipFamilies.Has(utilnet.IPv6) {
		if agnhostNetInf.IPv6 != "" {
			agnhostIPs = append(agnhostIPs, agnhostNetInf.IPv6)
		}
		if frrNetInf.IPv6 != "" {
			frrIPs = append(frrIPs, frrNetInf.IPv6)
		}
	}

	framework.Logf("EVPN agnhost created: %s (agnhost IPs: %v, FRR IPs: %v, interface: %s, FRR interface: %s)", containerName, agnhostIPs, frrIPs, agnhostInterface, frrInterface)
	return &evpnAgnhostInfo{
		agnhostIPs:       agnhostIPs,
		agnhostInterface: agnhostInterface,
		frrIPs:           frrIPs,
		frrInterface:     frrInterface,
	}, nil
}

// =============================================================================
// MAC-VRF Agnhost Utilities
// =============================================================================

// secondToLastIP returns the second-to-last usable IP in the given subnet.
// Using the high end of the range avoids collisions with both OVN IPAM
// (which allocates from lower end onwards) and Docker IPAM (which allocates from lower end onwards).
// This assumes OVN-K CUDN IPAM won't allocate IPs from the top of the subnet range
// for pods in these e2e tests.
// Example: "10.100.0.0/24" -> 10.100.0.253, "fd00:100::/64" -> fd00:100::ffff:ffff:ffff:fffe
func secondToLastIP(ipNet *net.IPNet) net.IP {
	// Compute broadcast: network OR inverted mask
	broadcast := make(net.IP, len(ipNet.IP))
	for i := range ipNet.IP {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	// Subtract 2 from broadcast to get second-to-last usable IP
	result := make(net.IP, len(broadcast))
	copy(result, broadcast)
	borrow := byte(2)
	for i := len(result) - 1; i >= 0 && borrow > 0; i-- {
		diff := int(result[i]) - int(borrow)
		if diff < 0 {
			result[i] = byte(diff + 256)
			borrow = 1
		} else {
			result[i] = byte(diff)
			borrow = 0
		}
	}
	return result
}

// getMACVRFAgnhostIPsFromSubnets derives MAC-VRF agnhost IPs from CUDN subnets.
// For each subnet, it returns an IP with host portion set to the high end address.
// Example: "10.100.0.0/16" -> "10.100.0.253/16", "fd00:100::/64" -> "fd00:100::ffff:ffff:ffff:fffe"
func getMACVRFAgnhostIPsFromSubnets(subnets []string) ([]string, error) {
	var ips []string
	for _, subnet := range subnets {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, err
		}
		ips = append(ips, secondToLastIP(ipNet).String())
	}
	return ips, nil
}

// setupMACVRFAgnhost creates an agnhost container connected to the EVPN bridge
// for MAC-VRF (Layer 2) connectivity testing.
//
// This function:
//  1. Creates a Docker network with the CUDN subnet and an agnhost on it,
//     requesting the second-to-last IP of each subnet to avoid collisions
//     with OVN IPAM and Docker IPAM (both allocate from the low end)
//  2. Connects FRR to the network (Docker creates a veth pair automatically)
//  3. Moves FRR's interface to bridgeName as an access port for the MAC-VRF VLAN
//
// Requires: setupEVPNBridgeOnExternalFRR and setupMACVRFOnExternalFRR must be called first.
//
// The agnhost will be on the same L2 segment as pods on the CUDN, allowing
// direct Layer 2 communication via EVPN Type-2/Type-3 routes.
//
// Parameters:
//   - containerName: name of the agnhost container
//   - networkName: name of the agnhost network
//   - vid: VLAN ID for the access port on br0 (e.g., 100)
//   - ipFamilies: Cluster IP family support (e.g., sets.New(utilnet.IPv4, utilnet.IPv6))
//   - subnets: Subnets for the Docker network matching the CUDN (e.g., "10.100.0.0/16")
func setupMACVRFAgnhost(ictx infraapi.Context, containerName, networkName, bridgeName string, vid int, ipFamilies sets.Set[utilnet.IPFamily], subnets []string) error {
	// Derive agnhost IPs from CUDN subnets
	agnhostIPs, err := getMACVRFAgnhostIPsFromSubnets(subnets)
	if err != nil {
		return fmt.Errorf("Failed to derive MAC-VRF agnhost IPs from subnets: %w", err)
	}

	var ip4, ip6 string
	ips4, ips6 := splitIPStringsByIPFamily(agnhostIPs)
	if len(ips4) > 0 {
		ip4 = ips4[0]
	}
	if len(ips6) > 0 {
		ip6 = ips6[0]
	}

	info, err := createEVPNAgnhost(ictx, networkName, containerName, ipFamilies, subnets, ip4, ip6)
	if err != nil {
		return err
	}

	// Move FRR's interface to bridgeName and configure as access port
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	vidStr := fmt.Sprintf("%d", vid)
	frrCmds := [][]string{
		{"ip", "link", "set", info.frrInterface, "master", bridgeName},
		{"bridge", "vlan", "add", "dev", info.frrInterface, "vid", vidStr, "pvid", "untagged"},
	}
	for _, cmd := range frrCmds {
		if _, err = infraprovider.Get().ExecExternalContainerCommand(frr, cmd); err != nil {
			return fmt.Errorf("failed to configure %s as %s access port for VID %s: %w", info.frrInterface, bridgeName, vidStr, err)
		}
	}

	// Cleanup is handled automatically:
	// - ictx.CreateNetwork() registers network deletion
	// - ictx.CreateExternalContainer() registers container deletion
	// - ictx.AttachNetwork() registers network detachment

	framework.Logf("MAC-VRF agnhost setup complete: %s (IPs: %v, VID: %d, FRR interface: %s)", containerName, agnhostIPs, vid, info.frrInterface)
	return nil
}

// =============================================================================
// IP-VRF Agnhost Utilities
// =============================================================================

func getIPVRFAgnhostIPs(containerName, networkName string, ipFamilySet sets.Set[utilnet.IPFamily]) ([]string, error) {
	network, err := infraprovider.Get().GetNetwork(networkName)
	if err != nil {
		return nil, fmt.Errorf("failed to get network %s: %w", networkName, err)
	}

	agnhostNetInf, err := infraprovider.Get().GetExternalContainerNetworkInterface(
		infraapi.ExternalContainer{Name: containerName}, network)
	if err != nil {
		return nil, fmt.Errorf("failed to get agnhost network interface: %w", err)
	}

	ipVRFAgnhostIPs := matchIPStringsByIPFamilySet([]string{agnhostNetInf.IPv4, agnhostNetInf.IPv6}, ipFamilySet)
	return ipVRFAgnhostIPs, nil
}

// setupIPVRFAgnhost creates an agnhost container connected to the external FRR's VRF
// for IP-VRF (Layer 3) connectivity testing.
//
// This function:
//  1. Creates a Docker network with the specified subnet
//  2. Creates an agnhost container on that network
//  3. Connects FRR to the network
//  4. Discovers assigned IPs (Docker assigns them from subnet)
//  5. Puts FRR's interface for that network into the VRF
//  6. Sets agnhost's default route via FRR
//
// Requires: setupIPVRFOnExternalFRR must be called first to create the VRF.
//
// The agnhost will be on a separate routed subnet, reachable via EVPN Type-5 routes.
//
// Names are derived from VID to support multiple IP-VRF agnhosts:
//   - Network: ipvrf-net-<vid> (e.g., ipvrf-net-202)
//   - Container: agnhost-ipvrf-<vid> (e.g., agnhost-ipvrf-202)
//
// Parameters:
//   - containerName: name of the agnhost container
//   - networkName: name of the agnhost network
//   - vrfName: Name of the VRF to put FRR's interface in (must match setupIPVRFOnExternalFRR)
//   - ipFamilies: Cluster IP family support (e.g., sets.New(utilnet.IPv4, utilnet.IPv6))
//   - subnets: Subnets for the Docker network (e.g., "172.27.102.0/24" for IPv4, or both for dual-stack)
//
// Returns:
//   - Agnhost's IP addresses (IPv4 and/or IPv6 depending on cluster IP family support)
func setupIPVRFAgnhost(ictx infraapi.Context, containerName, networkName, vrfName string, vid int, ipFamilies sets.Set[utilnet.IPFamily], subnets ...string) error {
	info, err := createEVPNAgnhost(ictx, networkName, containerName, ipFamilies, subnets, "", "")
	if err != nil {
		return err
	}

	// Put FRR's interface in the VRF
	// NOTE: keep_addr_on_down=1 is set at FRR container startup (in deploy_frr_external_container)
	// to preserve IPv6 addresses during VRF assignment. See https://github.com/FRRouting/frr/issues/1666
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

	frrCmds := [][]string{
		{"ip", "link", "set", info.frrInterface, "master", vrfName},
		{"ip", "link", "set", info.frrInterface, "up"},
	}
	for _, cmd := range frrCmds {
		if _, err = infraprovider.Get().ExecExternalContainerCommand(frr, cmd); err != nil {
			return fmt.Errorf("failed to assign %s to VRF %s: %w", info.frrInterface, vrfName, err)
		}
	}

	// Set agnhost's default routes via FRR (for each address family)
	agnhost := infraapi.ExternalContainer{Name: containerName}

	var routeCmds [][]string
	for _, gwIP := range info.frrIPs {
		cmd := []string{"ip"}
		if utilnet.IsIPv6String(gwIP) {
			cmd = append(cmd, "-6")
		}
		cmd = append(cmd, "route", "replace", "default", "via", gwIP, "dev", info.agnhostInterface)
		routeCmds = append(routeCmds, cmd)
	}
	for _, cmd := range routeCmds {
		if _, err = infraprovider.Get().ExecExternalContainerCommand(agnhost, cmd); err != nil {
			return fmt.Errorf("failed to set default routes on agnhost: %w", err)
		}
	}

	// Cleanup is handled automatically:
	// - ictx.CreateNetwork() registers network deletion
	// - ictx.CreateExternalContainer() registers container deletion
	// - ictx.AttachNetwork() registers network detachment

	framework.Logf("IP-VRF agnhost setup complete: %s (IPs: %v, network: %s, VRF: %s)", containerName, info.agnhostIPs, networkName, vrfName)
	return nil
}

// =============================================================================
// VTEP Utilities
// =============================================================================

// createVTEP creates a VTEP (VXLAN Tunnel Endpoint) custom resource for EVPN.
// The VTEP CR defines the IP range from which VTEP IPs are allocated for EVPN VXLAN tunnels.
//
// Parameters:
//   - f: Test framework (used to get client config)
//   - ictx: Infrastructure context for cleanup registration
//   - name: Name of the VTEP CR
//   - cidrs: CIDR ranges for VTEP IP allocation (supports dual-stack with 2 CIDRs)
//   - mode: VTEP mode - "Managed" (OVN-K allocates IPs) or "Unmanaged" (external provider)
func createVTEP(f *framework.Framework, ictx infraapi.Context, name string, cidrs []string, mode vtepv1.VTEPMode) error {
	client, err := vtepclientset.NewForConfig(f.ClientConfig())
	if err != nil {
		return fmt.Errorf("failed to create VTEP client: %w", err)
	}

	// Convert string CIDRs to vtepv1.CIDR type
	vtepCIDRs := make([]vtepv1.CIDR, len(cidrs))
	for i, cidr := range cidrs {
		vtepCIDRs[i] = vtepv1.CIDR(cidr)
	}

	vtep := &vtepv1.VTEP{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: vtepv1.VTEPSpec{
			CIDRs: vtepCIDRs,
			Mode:  mode,
		},
	}

	_, err = client.K8sV1().VTEPs().Create(context.Background(), vtep, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create VTEP %s: %w", name, err)
	}

	// Register cleanup: delete VTEP and wait until it's fully removed
	ictx.AddCleanUpFn(func() error {
		err := client.K8sV1().VTEPs().Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			_, err := client.K8sV1().VTEPs().Get(ctx, name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		})
	})

	framework.Logf("VTEP created: %s (CIDRs: %v, Mode: %s)", name, cidrs, mode)
	return nil
}

// vtepLoopbackHostCIDR returns ip/prefix for loopback add/del and host-cidrs checks (/32 or /128).
func vtepLoopbackHostCIDR(ip net.IP) string {
	pl := 32
	if utilnet.IsIPv6(ip) {
		pl = 128
	}
	return fmt.Sprintf("%s/%d", ip.String(), pl)
}

// ensureVTEPLoopbackIPs seeds each node with a VTEP-reachable IP when the
// VTEP CIDRs are custom subnets that don't overlap with the node's existing
// InternalIPs. It allocates one IP per CIDR per node, adds it to the loopback
// interface, and waits for it to appear in host-cidrs. Once the VTEP CR is
// created the ovnkube-node EVPN controller picks these IPs up through the
// address manager and writes the k8s.ovn.org/vteps node annotation
// automatically; the caller should use waitForVTEPAccepted to confirm all
// nodes have been annotated.
//
// When node IPs already fall within the VTEP CIDRs (e.g. VTEP CIDRs match the
// node IP subnets) this is a no-op.
func ensureVTEPLoopbackIPs(
	f *framework.Framework,
	ictx infraapi.Context,
	vtepCIDRs []string,
) error {
	nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	if nodeIPsOverlapCIDRs(nodeList, vtepCIDRs) {
		return nil
	}

	var parsedCIDRs []*net.IPNet
	for _, cidr := range vtepCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse VTEP CIDR %q: %w", cidr, err)
		}
		parsedCIDRs = append(parsedCIDRs, ipNet)
	}

	for i, node := range nodeList.Items {
		for _, ipNet := range parsedCIDRs {
			ip := incrementIP(ipNet.IP, i+1)
			if !ipNet.Contains(ip) {
				return fmt.Errorf("ran out of IPs in CIDR %s for node %s", ipNet, node.Name)
			}
			hostCIDR := vtepLoopbackHostCIDR(ip)
			_, err := infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"ip", "addr", "add", hostCIDR, "dev", "lo"})
			if err != nil {
				if strings.Contains(err.Error(), "Address already assigned") || strings.Contains(err.Error(), "EEXIST") {
					framework.Logf("VTEP IP %s already present on node %s loopback, skipping", hostCIDR, node.Name)
				} else {
					return fmt.Errorf("failed to add VTEP IP %s to loopback on node %s: %w", ip, node.Name, err)
				}
			} else {
				framework.Logf("Added VTEP IP %s to loopback on node %s", hostCIDR, node.Name)
			}
		}
		nodeName := node.Name
		allocatedIPs := make([]string, 0, len(parsedCIDRs))
		for _, ipNet := range parsedCIDRs {
			allocatedIPs = append(allocatedIPs, incrementIP(ipNet.IP, i+1).String())
		}
		err := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			n, err := f.ClientSet.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			hostCIDRs, err := util.ParseNodeHostCIDRs(n)
			if err != nil {
				return false, nil
			}
			for _, ipStr := range allocatedIPs {
				parsed := net.ParseIP(ipStr)
				if parsed == nil {
					return false, fmt.Errorf("invalid allocated VTEP IP %q", ipStr)
				}
				if !hostCIDRs.Has(vtepLoopbackHostCIDR(parsed)) {
					return false, nil
				}
			}
			return true, nil
		})
		if err != nil {
			return fmt.Errorf("timed out waiting for VTEP IPs %v to appear in host-cidrs on node %s: %w", allocatedIPs, nodeName, err)
		}
		framework.Logf("VTEP IPs %v confirmed in host-cidrs on node %s", allocatedIPs, nodeName)
	}

	ictx.AddCleanUpFn(func() error {
		nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return err
		}
		for i, node := range nodeList.Items {
			for _, ipNet := range parsedCIDRs {
				ip := incrementIP(ipNet.IP, i+1)
				_, _ = infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"ip", "addr", "del", vtepLoopbackHostCIDR(ip), "dev", "lo"})
			}
		}
		return nil
	})

	return nil
}

// incrementIP returns a copy of ip with offset added. Works for both IPv4 and IPv6.
func incrementIP(baseIP net.IP, offset int) net.IP {
	ip := make(net.IP, len(baseIP))
	copy(ip, baseIP)
	for i := len(ip) - 1; i >= 0 && offset > 0; i-- {
		sum := int(ip[i]) + offset
		ip[i] = byte(sum % 256)
		offset = sum / 256
	}
	return ip
}

// nodeIPsOverlapCIDRs returns true if at least one node's InternalIP falls
// within one of the provided CIDRs.
func nodeIPsOverlapCIDRs(nodeList *corev1.NodeList, cidrStrings []string) bool {
	var cidrs []*net.IPNet
	for _, s := range cidrStrings {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		cidrs = append(cidrs, ipNet)
	}
	for _, node := range nodeList.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type != corev1.NodeInternalIP {
				continue
			}
			ip := net.ParseIP(addr.Address)
			if ip == nil {
				continue
			}
			for _, cidr := range cidrs {
				if cidr.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// waitForVTEPAccepted polls the VTEP status until the Accepted condition is
// True. When node IPs overlap with the VTEP CIDRs (KIND subnet case), parallel
// tests may cause transient CIDROverlap which is tolerated since it is expected
// when tests run in parallel specially for the nodeCIDR being the VTEP for unmanaged mode.
func waitForVTEPAccepted(f *framework.Framework, vtepName string, vtepCIDRs []string) error {
	client, err := vtepclientset.NewForConfig(f.ClientConfig())
	if err != nil {
		return fmt.Errorf("failed to create VTEP client: %w", err)
	}
	nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}
	tolerateCIDROverlap := nodeIPsOverlapCIDRs(nodeList, vtepCIDRs)

	return wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		vtep, err := client.K8sV1().VTEPs().Get(ctx, vtepName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		condition := meta.FindStatusCondition(vtep.Status.Conditions, "Accepted")
		if condition == nil {
			return false, nil
		}
		if condition.Status == metav1.ConditionTrue {
			framework.Logf("VTEP %s is healthy (Accepted=True)", vtepName)
			return true, nil
		}
		if tolerateCIDROverlap && condition.Reason == "CIDROverlap" {
			framework.Logf("VTEP %s Accepted=%s reason=%s (tolerated): %s", vtepName, condition.Status, condition.Reason, condition.Message)
			return true, nil
		}
		framework.Logf("VTEP %s Accepted=%s reason=%s: %s", vtepName, condition.Status, condition.Reason, condition.Message)
		return false, nil
	})
}

// =============================================================================
// EVPN VID Utilities
// =============================================================================

func randomN(n int) int {
	r, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand.Int failed: %v", err))
	}
	return int(r.Int64())
}

// randomVID generates a random VLAN ID in the valid range (2-4094).
// VIDs 0, 1, and 4095 are reserved and should not be used.
func randomVID() int {
	return randomN(4093) + 2 // 2-4094
}

// randomVNI generates a random VXLAN Network Identifier in the valid 24-bit range (1-16777215).
func randomVNI() int32 {
	return int32(randomN(16777215)) + 1
}

// randomCUDNSubnets generates random non-overlapping CUDN subnets for parallel test isolation.
// Uses /20 (4096 addresses) instead of /16 to allow randomizing both second and third octets,
// giving ~4016 possible subnets within 10.0.0.0/8 while avoiding collisions with:
//   - 10.88.0.0/16  (podman default network)
//   - 10.96.0.0/16  (Kubernetes services)
//   - 10.128.0.0/14 (default cluster network pod CIDRs)
//   - 10.132.0.0/16 (UDN perf tests)
//   - 10.243.0.0/16, 10.244.0.0/16 (pod CIDRs)
//
// Note: /20 supports up to 16 nodes with /24 per-node subnets for Layer3 topology.
// This is sufficient for KIND e2e clusters.
//
// Returns IPv4 (/20) and IPv6 (/52) subnets.
func randomCUDNSubnets() (ipv4, ipv6 string) {
	// 4096 possible /20 subnets in 10.0.0.0/8 (256 second octets * 16 /20-aligned third octets)
	// Exclude blocks overlapping known reservations (16 /20 blocks per second octet):
	//   10.88, 10.96, 10.128-131 (10.128.0.0/14), 10.132, 10.243, 10.244 = 112 excluded → ~3952 usable
	for {
		second := randomN(256)
		// 16 /20-aligned slots per second octet (256/16)
		third := randomN(16) * 16 // 0, 16, 32, ..., 240
		switch second {
		case 88, 96, 128, 129, 130, 131, 132, 243, 244:
			continue
		}
		n := second*16 + third/16
		return fmt.Sprintf("10.%d.%d.0/20", second, third), fmt.Sprintf("fd00:%x::/52", n)
	}
}

func randomL3CUDNSubnets() []udnv1.Layer3Subnet {
	cudnIPv4, cudnIPv6 := randomCUDNSubnets()
	return []udnv1.Layer3Subnet{{CIDR: udnv1.CIDR(cudnIPv4)}, {CIDR: udnv1.CIDR(cudnIPv6)}}
}

func randomL2CUDNSubnets() udnv1.DualStackCIDRs {
	cudnIPv4, cudnIPv6 := randomCUDNSubnets()
	return udnv1.DualStackCIDRs{udnv1.CIDR(cudnIPv4), udnv1.CIDR(cudnIPv6)}
}

// randomIPVRFAgnhostSubnets generates random IP-VRF agnhost subnets for parallel test isolation.
// Uses /29 (8 IPs, 6 usable) which is sufficient for provider gateway + agnhost + FRR,
// giving 8192 possible subnets within 172.27.0.0/16 to minimize collision probability.
// The 172.27.0.0/16 space avoids collisions with:
//   - 172.18.0.0/16 (KIND primary network)
//   - 172.19.0.0/16 (XGW network)
//   - 172.22.0.0/16 (MetalLB client network)
//   - 172.26.0.0/16 (BGP server network)
//
// Returns IPv4 (/29) and IPv6 (/112) subnets.
func randomIPVRFAgnhostSubnets() (ipv4, ipv6 string) {
	// 8192 possible /29 subnets in 172.27.0.0/16
	n := randomN(8192)
	// 32 /29-aligned slots per third octet (256/8), so divide to get octet pair
	third := n / 32
	fourth := (n % 32) * 8
	return fmt.Sprintf("172.27.%d.%d/29", third, fourth), fmt.Sprintf("fd01:%x::/112", n)
}

// randomVTEPSubnets generates random VTEP subnets for parallel test isolation.
// Uses /24 (254 usable IPs)
// Randomizes both second and third octets within RFC 6598 shared address space
// (100.64.0.0/10), giving 15,872 possible /24 subnets while avoiding:
//   - 100.64.0.0/16 (default join subnet)
//   - 100.65.0.0/16 (UDN primary join subnet)
//
// 100.88.0.0/16 (transit subnet) is NOT excluded because transit IPs are purely
// internal to OVN's logical network and never appear on physical interfaces.
// Safe second octets: 66-127 (62 values).
// Returns IPv4 (/24) and IPv6 (/112) subnets.
func randomVTEPSubnets() (ipv4, ipv6 string) {
	second := randomN(62) + 66 // 66-127
	third := randomN(256)      // 0-255
	return fmt.Sprintf("100.%d.%d.0/24", second, third), fmt.Sprintf("fd02:%x%02x::/112", second, third)
}

// =============================================================================
// FRRConfiguration Utilities
// =============================================================================

func getExternalFRRIP(ipFamilySet sets.Set[utilnet.IPFamily]) (string, error) {
	kindNetwork, err := infraprovider.Get().PrimaryNetwork()
	if err != nil {
		return "", err
	}
	frrNetIf, err := infraprovider.Get().GetExternalContainerNetworkInterface(infraapi.ExternalContainer{Name: externalFRRContainerName}, kindNetwork)
	if err != nil {
		return "", err
	}

	var externalFRRIP string
	switch {
	case ipFamilySet.Has(utilnet.IPv4) && frrNetIf.IPv4 != "":
		externalFRRIP = frrNetIf.IPv4
	case ipFamilySet.Has(utilnet.IPv6) && frrNetIf.IPv6 != "":
		externalFRRIP = frrNetIf.IPv6
	default:
		return "", fmt.Errorf("can't find external FRR IP on kind network")
	}
	return externalFRRIP, nil
}

// createFRRConfiguration creates an FRRConfiguration CR for BGP peering with the external FRR.
// This is used by RouteAdvertisements to determine which neighbors to advertise routes to.
//
// For EVPN L3 IP-VRF, we don't need toReceive because:
// - External routes come via EVPN Type-5 and are imported via route-target matching in the VRF
// - The FRRConfiguration just provides the BGP neighbor definition and label for RA selector
//
// Parameters:
//   - ictx: Infrastructure context for cleanup registration
//   - name: Name of the FRRConfiguration CR
//   - namespace: Namespace for the FRRConfiguration (typically frr-k8s-system)
//   - asn: BGP Autonomous System Number (e.g., 64512)
//   - neighborIP: IP address of the external FRR to peer with
//   - labels: Labels to apply to the FRRConfiguration (used by RouteAdvertisements selector)
func CreateFRRConfiguration(ictx infraapi.Context,
	name, namespace string,
	asn int,
	neighborIP string,
	labels map[string]string) error {

	// Build labels string for YAML
	labelsYAML := ""
	for k, v := range labels {
		labelsYAML += fmt.Sprintf("    %s: %s\n", k, v)
	}

	// Generate FRRConfiguration YAML
	// No toReceive needed - EVPN routes come via l2vpn evpn address-family
	// and are imported via route-target matching in the VRF
	yaml := fmt.Sprintf(`apiVersion: frrk8s.metallb.io/v1beta1
kind: FRRConfiguration
metadata:
  name: %s
  namespace: %s
  labels:
%sspec:
  bgp:
    routers:
    - asn: %d
      neighbors:
      - address: %s
        asn: %d
        disableMP: true
`, name, namespace, labelsYAML, asn, neighborIP, asn)

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "frrconfig-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(yaml); err != nil {
		return fmt.Errorf("failed to write FRRConfiguration YAML: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Apply via kubectl
	_, err = e2ekubectl.RunKubectl(namespace, "create", "-f", tmpFile.Name())
	if err != nil {
		return fmt.Errorf("failed to create FRRConfiguration: %w", err)
	}

	// Register cleanup
	ictx.AddCleanUpFn(func() error {
		_, err := e2ekubectl.RunKubectl(namespace, "delete", "frrconfiguration", name, "--ignore-not-found")
		if err != nil {
			return fmt.Errorf("failed to delete FRRConfiguration %s: %w", name, err)
		}
		framework.Logf("FRRConfiguration deleted: %s", name)
		return nil
	})

	framework.Logf("FRRConfiguration created: %s (neighbor: %s)", name, neighborIP)
	return nil
}

// =============================================================================
// EVPN Test Helpers
// =============================================================================

// EVPNExternalSetupIDs records VLAN IDs and IP-VRF subnets applied on the external FRR
// during runEVPNNetworkAndServers. Merge into EVPNDisruptiveState so
// DestroyEVPNKernelStateOnFRR deletes the correct IP-VRF SVI (bridgeName.IpVRFVID).
type EVPNExternalSetupIDs struct {
	MacVRFVID    int
	IpVRFVID     int
	IpVRFSubnets []string
}

func runEVPNNetworkAndServers(
	f *framework.Framework,
	ictx infraapi.Context,
	testName string,
	ipFamilySet sets.Set[utilnet.IPFamily],
	networkSpec *udnv1.NetworkSpec,
	ipVRFAgnhostSubnets []string,
	vtepSubnets []string,
	bgpASN int,
	macVRFAgnhostName string,
	macVRFNetworkName string,
	ipVRFAgnhostName string,
	ipVRFNetworkName string,
	// frrConfigName is the name (and label value) for the FRRConfiguration CR.
	// When empty (or omitted), defaults to testName — the upstream per-network default.
	// Pass a shared base name to have multiple networks share one FRRConfiguration.
	frrConfigName ...string,
) (EVPNExternalSetupIDs, error) {
	// Derive what to setup from networkSpec
	hasMACVRF := networkSpec.EVPN != nil && networkSpec.EVPN.MACVRF != nil
	hasIPVRF := networkSpec.EVPN != nil && networkSpec.EVPN.IPVRF != nil

	// Derive unique bridge/vxlan names from testBaseName for parallel isolation.
	// e.g. testBaseName="evpn7a3f" → bridgeName="brevpn7a3f", vxlanName="vxevpn7a3f"
	// keeping worst-case sviName ("brevpn9999.4094") at exactly 15 chars (Linux limit).
	bridgeName := "br" + testName
	vxlanName := "vx" + testName

	ipVRFAgnhostSubnets = matchCIDRStringsByIPFamilySet(ipVRFAgnhostSubnets, ipFamilySet)
	vtepSubnets = matchCIDRStringsByIPFamilySet(vtepSubnets, ipFamilySet)

	// Extract subnets from networkSpec for MAC-VRF agnhost IP derivation
	cudnSubnetsFromSpec := getNetworkSubnetsFromSpec(networkSpec)

	externalFRRIP, err := getExternalFRRIP(ipFamilySet)
	if err != nil {
		return EVPNExternalSetupIDs{}, err
	}

	// attach BGP peer network to all nodes
	nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return EVPNExternalSetupIDs{}, fmt.Errorf("failed to list nodes: %w", err)
	}
	nodeIPs := e2enode.CollectAddresses(nodeList, corev1.NodeInternalIP)

	framework.Logf("Setting up EVPN bridge on external FRR")
	err = setupEVPNBridgeOnExternalFRR(ictx, externalFRRIP, bridgeName, vxlanName)
	if err != nil {
		return EVPNExternalSetupIDs{}, err
	}

	var macVRFVID int
	var ipVRFVID int
	if hasMACVRF {
		macVRFVID = randomVID()
		framework.Logf("Generated random VIDs for external FRR: MAC-VRF VID=%d", macVRFVID)
		framework.Logf("Setting up MAC-VRF on external FRR")
		err = setupMACVRFOnExternalFRR(int(networkSpec.EVPN.MACVRF.VNI), macVRFVID, bridgeName, vxlanName)
		if err != nil {
			return EVPNExternalSetupIDs{}, err
		}

		framework.Logf("Creating MAC-VRF agnhost")
		err = setupMACVRFAgnhost(ictx, macVRFAgnhostName, macVRFNetworkName, bridgeName, macVRFVID, ipFamilySet, cudnSubnetsFromSpec)
		if err != nil {
			return EVPNExternalSetupIDs{}, err
		}
	}

	framework.Logf("Setting up EVPN BGP on external FRR")
	err = setupEVPNBGPOnExternalFRR(ictx, bgpASN, nodeIPs)
	if err != nil {
		return EVPNExternalSetupIDs{}, err
	}

	if hasIPVRF {
		// Derive VRF name from VNI (unique per IP-VRF)
		ipVRFName := fmt.Sprintf("vrf%d", networkSpec.EVPN.IPVRF.VNI)
		ipVRFVID = randomVID()
		for macVRFVID == ipVRFVID {
			ipVRFVID = randomVID()
		}
		framework.Logf("Generated random VIDs for external FRR: IP-VRF VID=%d", ipVRFVID)
		framework.Logf("Setting up IP-VRF on external FRR")
		err = setupIPVRFOnExternalFRR(ictx, ipVRFName, int(networkSpec.EVPN.IPVRF.VNI), ipVRFVID, bridgeName, vxlanName)
		if err != nil {
			return EVPNExternalSetupIDs{}, err
		}

		// Derive names from VID
		framework.Logf("Creating IP-VRF agnhost")
		err = setupIPVRFAgnhost(ictx, ipVRFAgnhostName, ipVRFNetworkName, ipVRFName, ipVRFVID, ipFamilySet, ipVRFAgnhostSubnets...)
		if err != nil {
			return EVPNExternalSetupIDs{}, err
		}

		// Configure BGP AFTER agnhost so FRR's interface is in the VRF
		// and has a connected route for the subnet we want to advertise
		framework.Logf("Setting up IP-VRF BGP on external FRR")
		err = setupIPVRFBGPOnExternalFRR(ictx, ipVRFName, bgpASN, int(networkSpec.EVPN.IPVRF.VNI), ipFamilySet, ipVRFAgnhostSubnets)
		if err != nil {
			return EVPNExternalSetupIDs{}, err
		}
	}

	framework.Logf("Ensuring VTEP loopback IPs on nodes")
	err = ensureVTEPLoopbackIPs(f, ictx, vtepSubnets)
	if err != nil {
		return EVPNExternalSetupIDs{}, err
	}

	testVTEPName := testName + "-vtep"
	framework.Logf("Creating VTEP CR with subnets %v", vtepSubnets)
	err = createVTEP(f, ictx, testVTEPName, vtepSubnets, vtepv1.VTEPModeUnmanaged)
	if err != nil {
		return EVPNExternalSetupIDs{}, err
	}

	framework.Logf("Waiting for VTEP %s to be accepted", testVTEPName)
	err = waitForVTEPAccepted(f, testVTEPName, vtepSubnets)
	if err != nil {
		return EVPNExternalSetupIDs{}, fmt.Errorf("VTEP %s did not become healthy: %w", testVTEPName, err)
	}

	// Update VTEP name in network spec
	networkSpec.EVPN.VTEP = testVTEPName

	// Resolve FRRConfig name: use the caller-supplied name if provided, else testName.
	// Pass "-" to skip FRRConfiguration creation entirely (caller manages it).
	fcName := testName
	if len(frrConfigName) > 0 && frrConfigName[0] != "" {
		fcName = frrConfigName[0]
	}
	if fcName != "-" {
		framework.Logf("Creating FRRConfiguration %q for EVPN", fcName)
		frrConfigLabels := map[string]string{"network": fcName}
		err = CreateFRRConfiguration(ictx, fcName, deploymentconfig.Get().FRRK8sNamespace(), bgpASN, externalFRRIP, frrConfigLabels)
		if err != nil {
			return EVPNExternalSetupIDs{}, err
		}
	} else {
		framework.Logf("Skipping FRRConfiguration creation (managed by caller)")
	}

	ids := EVPNExternalSetupIDs{}
	if hasMACVRF {
		ids.MacVRFVID = macVRFVID
	}
	if hasIPVRF {
		ids.IpVRFVID = ipVRFVID
		if len(ipVRFAgnhostSubnets) > 0 {
			ids.IpVRFSubnets = append([]string(nil), ipVRFAgnhostSubnets...)
		}
	}
	return ids, nil
}

// =============================================================================
// EVPN Disruptive Test Helpers
// =============================================================================

// EVPNDisruptiveState holds all state needed to verify and re-setup a single EVPN VPN
// after a disruptive action (FRR restart, node restart, OVN-K restart, FRR-K8s restart).
// It stores both the Kubernetes objects and the external FRR kernel parameters so that
// the FRR container's transient state can be re-applied without re-randomising VNI/VID.
// Exported so that OpenShift-specific test files can create and pass state objects.
type EVPNDisruptiveState struct {
	// Kubernetes objects
	Namespace   *corev1.Namespace
	TestPod     *corev1.Pod // pinned to a specific worker node
	NetworkName string
	NetworkSpec *udnv1.NetworkSpec

	// External server names — Docker/Podman containers outside the cluster created by
	// setupMACVRFAgnhost / setupIPVRFAgnhost. Used in connectivity and isolation checks.
	ExternalServers []string

	// Parameters for re-applying transient kernel state on the external FRR container
	// after a container restart (bridges and VXLANs are lost on stop/start).
	BridgeName   string
	VxlanName    string
	FrrVTEPIP    string // FRR's IP on the KIND primary network; used as VXLAN local IP
	MacVRFVNI    int
	MacVRFVID    int
	IpVRFName    string
	IpVRFVNI     int
	IpVRFVID     int
	IpVRFSubnets []string // subnets advertised by the IP-VRF agnhost
}

// restartExternalFRRDaemons force-kills the main FRR child processes inside the
// out-of-cluster FRR container (bgpd, zebra, staticd, bfdd, mgmtd) and leaves watchfrr
// and the container running. watchfrr then restarts the daemons, which reloads config
// from /etc/frr/frr.conf (kept in sync with "write memory" during test setup).
//
// This is not a docker/podman stop/start: the IP on the kind network, and any Linux
// network objects still present in the namespace, are not cleared by this call alone.
// The disruptive "spine" test first calls DestroyEVPNKernelStateOnFRR to clear bridges/
// VXLAN/VRF, then this function, then ReapplyEVPNKernelStateOnFRR to rebuild data plane.
func restartExternalFRRDaemons() error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

	framework.Logf("Restarting FRR daemons inside %q (keeping container alive)", externalFRRContainerName)

	// Kill only the child FRR daemons, NOT watchfrr (PID 1 / entrypoint).
	// Killing PID 1 would terminate the container entirely.
	// watchfrr monitors the other daemons and will automatically restart them.
	for _, proc := range []string{"bgpd", "zebra", "staticd", "bfdd", "mgmtd"} {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr,
			[]string{"killall", "-9", proc})
		if err != nil {
			framework.Logf("killall %s: %v (may already be stopped)", proc, err)
		}
	}

	// watchfrr detects the daemons are down and restarts them automatically.
	// Wait briefly for it to do its job.
	framework.Logf("Waiting for watchfrr to restart FRR daemons inside %q", externalFRRContainerName)
	return nil
}

// waitForExternalFRRProcessReady polls until the FRR process inside the external container
// responds to "vtysh -c 'show version'". Used right after restartExternalFRRDaemons to
// ensure FRR has fully started before attempting to re-apply kernel state or check BGP.
func waitForExternalFRRProcessReady(timeout time.Duration) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	return wait.PollImmediate(3*time.Second, timeout, func() (bool, error) {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand("show version"))
		if err != nil {
			framework.Logf("FRR process not ready yet: %v", err)
			return false, nil
		}
		return true, nil
	})
}

// destroyEVPNKernelStateOnFRR removes transient kernel objects (bridges, VXLANs, VRFs, SVIs)
// from the external FRR container, simulating the loss of that state on a full container stop
// or power cycle. Call before reapplyEVPNKernelStateOnFRR when a real `docker stop`/restart of
// the FRR container is not used. Per-link errors are only logged; missing devices are fine.
func destroyEVPNKernelStateOnFRR(states []EVPNDisruptiveState) {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

	for _, state := range states {
		hasIPVRF := state.NetworkSpec.EVPN != nil && state.NetworkSpec.EVPN.IPVRF != nil

		if hasIPVRF {
			vrfName := state.IpVRFName
			sviName := state.BridgeName + "." + fmt.Sprintf("%d", state.IpVRFVID)
			if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", sviName}); err != nil {
				framework.Logf("destroyEVPNKernelState: delete SVI %s: %v (may not exist)", sviName, err)
			}
			if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", vrfName}); err != nil {
				framework.Logf("destroyEVPNKernelState: delete VRF %s: %v (may not exist)", vrfName, err)
			}
		}

		if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", state.VxlanName}); err != nil {
			framework.Logf("destroyEVPNKernelState: delete VXLAN %s: %v (may not exist)", state.VxlanName, err)
		}
		if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", state.BridgeName}); err != nil {
			framework.Logf("destroyEVPNKernelState: delete bridge %s: %v (may not exist)", state.BridgeName, err)
		}

		framework.Logf("destroyEVPNKernelState: cleaned up kernel state for %q", state.NetworkName)
	}
}

// DestroyEVPNKernelStateOnFRR removes bridges, VXLANs, VRFs, and SVIs from the external FRR
// container; see destroyEVPNKernelStateOnFRR.
func DestroyEVPNKernelStateOnFRR(states []EVPNDisruptiveState) {
	destroyEVPNKernelStateOnFRR(states)
}

// reapplyEVPNKernelStateOnFRR re-creates all transient Linux kernel objects (bridge,
// VXLAN, VRF, MAC-VRF VLAN entries, IP-VRF SVI) on the external FRR container for
// every VPN in states.
//
// Background: docker restart destroys all kernel state inside the container's network
// namespace (bridges, VXLANs, VRFs). Docker does reconnect FRR to all its Docker
// networks on startup, so FRR's interfaces to the agnhost Docker networks are back
// automatically — but they are no longer attached to the bridge or VRF.
//
// FRR's BGP config is NOT re-applied here — it was persisted via "write memory" and
// is reloaded from /etc/frr/frr.conf on FRR startup.
//
// VIDs (VLAN IDs) are re-randomised on each re-apply. VID is a purely FRR-local tag;
// VXLAN encapsulation uses VNI (not VID), so a fresh VID is safe and correct.
func reapplyEVPNKernelStateOnFRR(ictx infraapi.Context, ipFamilySet sets.Set[utilnet.IPFamily], states []EVPNDisruptiveState) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

	for _, state := range states {
		hasMACVRF := state.NetworkSpec.EVPN != nil && state.NetworkSpec.EVPN.MACVRF != nil
		hasIPVRF := state.NetworkSpec.EVPN != nil && state.NetworkSpec.EVPN.IPVRF != nil

		framework.Logf("Re-applying EVPN bridge/VXLAN on external FRR for network %q", state.NetworkName)
		if err := setupEVPNBridgeOnExternalFRR(ictx, state.FrrVTEPIP, state.BridgeName, state.VxlanName); err != nil {
			return fmt.Errorf("failed to re-apply EVPN bridge for %q: %w", state.NetworkName, err)
		}

		if hasMACVRF {
			// MAC-VRF Docker network name follows the same convention used in
			// configureNetworkWithInfra: networkName + "-macvrf-agnhost".
			macVRFNetworkName := state.NetworkName + "-macvrf-agnhost"
			macVRFNet, err := infraprovider.Get().GetNetwork(macVRFNetworkName)
			if err != nil {
				return fmt.Errorf("failed to get MAC-VRF Docker network %q: %w", macVRFNetworkName, err)
			}
			frrMACNetInf, err := infraprovider.Get().GetExternalContainerNetworkInterface(frr, macVRFNet)
			if err != nil {
				return fmt.Errorf("failed to get FRR interface on MAC-VRF network %q: %w", macVRFNetworkName, err)
			}

			newMACVID := randomVID()
			framework.Logf("Re-applying MAC-VRF (VNI %d, new VID %d) on external FRR for %q", state.MacVRFVNI, newMACVID, state.NetworkName)
			if err := setupMACVRFOnExternalFRR(state.MacVRFVNI, newMACVID, state.BridgeName, state.VxlanName); err != nil {
				return fmt.Errorf("failed to re-apply MAC-VRF for %q: %w", state.NetworkName, err)
			}

			// Re-attach FRR's interface to the bridge as an access port with the new VID.
			// After docker restart, FRR is reconnected to the Docker network automatically,
			// but the interface is no longer enslaved to the bridge.
			vidStr := fmt.Sprintf("%d", newMACVID)
			frrCmds := [][]string{
				{"ip", "link", "set", frrMACNetInf.InfName, "master", state.BridgeName},
				{"bridge", "vlan", "add", "dev", frrMACNetInf.InfName, "vid", vidStr, "pvid", "untagged"},
				{"ip", "link", "set", frrMACNetInf.InfName, "up"},
			}
			for _, cmd := range frrCmds {
				if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd); err != nil {
					return fmt.Errorf("failed to re-attach FRR interface %q to MAC-VRF bridge: %w", frrMACNetInf.InfName, err)
				}
			}
		}

		if hasIPVRF {
			// IP-VRF Docker network name follows the same convention: networkName + "-ipvrf-agnhost".
			ipVRFNetworkName := state.NetworkName + "-ipvrf-agnhost"
			ipVRFNet, err := infraprovider.Get().GetNetwork(ipVRFNetworkName)
			if err != nil {
				return fmt.Errorf("failed to get IP-VRF Docker network %q: %w", ipVRFNetworkName, err)
			}
			frrIPNetInf, err := infraprovider.Get().GetExternalContainerNetworkInterface(frr, ipVRFNet)
			if err != nil {
				return fmt.Errorf("failed to get FRR interface on IP-VRF network %q: %w", ipVRFNetworkName, err)
			}

			newIPVID := randomVID()
			framework.Logf("Re-applying IP-VRF (VNI %d, new VID %d) on external FRR for %q", state.IpVRFVNI, newIPVID, state.NetworkName)
			if err := setupIPVRFOnExternalFRR(ictx, state.IpVRFName, state.IpVRFVNI, newIPVID, state.BridgeName, state.VxlanName); err != nil {
				return fmt.Errorf("failed to re-apply IP-VRF for %q: %w", state.NetworkName, err)
			}

			// Re-attach FRR's interface to the VRF.
			// Docker preserves the IP address assignment on the interface; moving it into
			// the VRF makes those IPs accessible in the VRF routing table.
			frrCmds := [][]string{
				{"ip", "link", "set", frrIPNetInf.InfName, "master", state.IpVRFName},
				{"ip", "link", "set", frrIPNetInf.InfName, "up"},
			}
			for _, cmd := range frrCmds {
				if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd); err != nil {
					return fmt.Errorf("failed to re-attach FRR interface %q to IP-VRF: %w", frrIPNetInf.InfName, err)
				}
			}
		}
	}
	return nil
}

// waitForExternalFRRBGPReady polls until at least expectedNeighborCount EVPN BGP neighbors
// on the external FRR container show state "Established". Used after any disruptive action
// that may drop BGP sessions.
func waitForExternalFRRBGPReady(expectedNeighborCount int, timeout time.Duration) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		out, err := infraprovider.Get().ExecExternalContainerCommand(frr,
			vtyshCommand("show bgp l2vpn evpn summary json"))
		if err != nil {
			framework.Logf("waitForExternalFRRBGPReady: vtysh error: %v", err)
			return false, nil
		}
		established := strings.Count(out, `"state":"Established"`)
		framework.Logf("waitForExternalFRRBGPReady: %d/%d neighbors Established", established, expectedNeighborCount)
		return established >= expectedNeighborCount, nil
	})
}

// restartFRRK8sPods deletes all pods in the frr-k8s-system namespace and waits for new
// pods to be Running and Ready. Follows the same pattern as restartOVNKubeNodePod.
func restartFRRK8sPods(clientset kubernetes.Interface, namespace string) error {
	ctx := context.TODO()
	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list FRR-K8s pods in %q: %w", namespace, err)
	}
	if len(podList.Items) == 0 {
		return fmt.Errorf("no FRR-K8s pods found in namespace %q", namespace)
	}
	expectedCount := len(podList.Items)

	framework.Logf("Deleting %d FRR-K8s pods in namespace %q", expectedCount, namespace)
	for i := range podList.Items {
		if err := deletePodWithWait(ctx, clientset, &podList.Items[i]); err != nil {
			return fmt.Errorf("failed to delete FRR-K8s pod %q: %w", podList.Items[i].Name, err)
		}
	}

	framework.Logf("Waiting for %d FRR-K8s pods to be Running/Ready in namespace %q", expectedCount, namespace)
	return wait.PollImmediate(5*time.Second, 3*time.Minute, func() (bool, error) {
		newList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, nil
		}
		if len(newList.Items) < expectedCount {
			framework.Logf("FRR-K8s pods: %d/%d present", len(newList.Items), expectedCount)
			return false, nil
		}
		for i := range newList.Items {
			pod := &newList.Items[i]
			if pod.Status.Phase != corev1.PodRunning {
				framework.Logf("FRR-K8s pod %q not Running yet (phase: %s)", pod.Name, pod.Status.Phase)
				return false, nil
			}
			for _, c := range pod.Status.ContainerStatuses {
				if !c.Ready {
					framework.Logf("FRR-K8s pod %q container %q not Ready yet", pod.Name, c.Name)
					return false, nil
				}
			}
		}
		framework.Logf("All %d FRR-K8s pods are Running/Ready", expectedCount)
		return true, nil
	})
}

// verifyEVPNVNIsActive checks that every expected VNI from the given states appears in
// the external FRR container's "show evpn vni json" output and that Zebra reports remote
// reachability for that VNI:
//   - L2 (MAC-VRF): require numRemoteVteps > 0 (remote VTEPs known from EVPN).
//   - L3 (IP-VRF):   FRR's summary JSON sets numRemoteVteps to the string "n/a" (see
//     zebra zl3vni_print_hash); we require numArpNd > 0 (next-hop / neighbor count in
//     the L3 VNI table) instead.
func verifyEVPNVNIsActive(states []EVPNDisruptiveState) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	out, err := infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand("show evpn vni json"))
	if err != nil {
		return fmt.Errorf("failed to run 'show evpn vni json': %w", err)
	}

	var table map[string]any
	if err := json.Unmarshal([]byte(out), &table); err != nil {
		return fmt.Errorf("parse 'show evpn vni json' output: %w; raw: %s", err, out)
	}

	for _, state := range states {
		if state.NetworkSpec.EVPN == nil {
			continue
		}
		for _, vni := range activeVNIsFromState(state) {
			key := strconv.Itoa(vni)
			raw, ok := table[key]
			if !ok {
				keys := make([]string, 0, len(table))
				for k := range table {
					keys = append(keys, k)
				}
				return fmt.Errorf("VNI %d for network %q not present in FRR EVPN VNI table (have keys %v); raw: %s",
					vni, state.NetworkName, keys, out)
			}
			m, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("VNI %d for network %q: expected JSON object, got %T %v", vni, state.NetworkName, raw, raw)
			}
			typ, _ := m["type"].(string)
			switch typ {
			case "L2":
				n := evpnJSONIntField(m, "numRemoteVteps")
				if n < 1 {
					return fmt.Errorf("VNI %d (L2) for network %q: want numRemoteVteps>=1, got %v (object=%v)",
						vni, state.NetworkName, m["numRemoteVteps"], m)
				}
				framework.Logf("verifyEVPNVNIsActive: VNI %d (L2) numRemoteVteps=%d", vni, n)
			case "L3":
				// L3 summary: numRemoteVteps is the string "n/a", not a count.
				n := evpnJSONIntField(m, "numArpNd")
				if n < 1 {
					return fmt.Errorf("VNI %d (L3) for network %q: want numArpNd>=1 (remote next-hops), got %v (object=%v)",
						vni, state.NetworkName, m["numArpNd"], m)
				}
				framework.Logf("verifyEVPNVNIsActive: VNI %d (L3) numArpNd=%d", vni, n)
			default:
				return fmt.Errorf("VNI %d for network %q: unknown or missing type %q in %v", vni, state.NetworkName, typ, m)
			}
		}
	}
	return nil
}

// evpnJSONIntField returns a non-negative int from a FRR JSON object field. FRR encodes
// small integers as JSON numbers (decoded as float64 in map[string]any).
func evpnJSONIntField(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case float64:
		if t < 0 {
			return 0
		}
		return int(t)
	case int:
		if t < 0 {
			return 0
		}
		return t
	case int64:
		if t < 0 {
			return 0
		}
		return int(t)
	case string:
		// e.g. numRemoteVteps "n/a" for L3 — not a count
		return 0
	default:
		return 0
	}
}

// waitForEVPNRouteConvergence polls the external FRR container until ALL Established
// BGP neighbors have received EVPN routes (PfxRcd > 0 in "show bgp l2vpn evpn
// summary json"). This ensures the EVPN data plane is fully converged before
// running connectivity checks, avoiding false failures after disruptive actions.
func waitForEVPNRouteConvergence(expectedNeighborCount int, timeout time.Duration) error {
	type bgpNeighbor struct {
		State  string `json:"state"`
		PfxRcd int    `json:"pfxRcd"`
		PfxSnt int    `json:"pfxSnt"`
	}
	type bgpSummary struct {
		Peers map[string]bgpNeighbor `json:"peers"`
	}

	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		out, err := infraprovider.Get().ExecExternalContainerCommand(frr,
			vtyshCommand("show bgp l2vpn evpn summary json"))
		if err != nil {
			framework.Logf("waitForEVPNRouteConvergence: vtysh error: %v", err)
			return false, nil
		}

		var summary bgpSummary
		if err := json.Unmarshal([]byte(out), &summary); err != nil {
			framework.Logf("waitForEVPNRouteConvergence: JSON parse error: %v", err)
			return false, nil
		}

		established := 0
		withRoutes := 0
		for ip, peer := range summary.Peers {
			if peer.State == "Established" {
				established++
				if peer.PfxRcd > 0 {
					withRoutes++
					framework.Logf("waitForEVPNRouteConvergence: neighbor %s Established pfxRcd=%d pfxSnt=%d", ip, peer.PfxRcd, peer.PfxSnt)
				} else {
					framework.Logf("waitForEVPNRouteConvergence: neighbor %s Established but pfxRcd=0 pfxSnt=%d (spine has not received routes FROM this node)", ip, peer.PfxSnt)
				}
			} else {
				framework.Logf("waitForEVPNRouteConvergence: neighbor %s state=%s (not Established)", ip, peer.State)
			}
		}

		framework.Logf("waitForEVPNRouteConvergence: %d/%d Established, %d/%d have sent EVPN routes to spine",
			established, expectedNeighborCount, withRoutes, established)
		return established >= expectedNeighborCount && withRoutes == established, nil
	})
}

// activeVNIsFromState returns all VNIs that should be active for the given state.
func activeVNIsFromState(state EVPNDisruptiveState) []int {
	var vnis []int
	if state.NetworkSpec.EVPN == nil {
		return vnis
	}
	if state.NetworkSpec.EVPN.MACVRF != nil {
		vnis = append(vnis, int(state.NetworkSpec.EVPN.MACVRF.VNI))
	}
	if state.NetworkSpec.EVPN.IPVRF != nil {
		vnis = append(vnis, int(state.NetworkSpec.EVPN.IPVRF.VNI))
	}
	return vnis
}

// =============================================================================
// Exported wrappers — used by openshift/test/evpn.go for the OpenShift-specific
// EVPN disruptive test. All symbols below are thin wrappers around the unexported
// implementations above so that the openshift package can call them.
// =============================================================================

// NewL3IPVRFNetworkSpec returns a new Layer3 CUDN EVPN IP-VRF network specification
// with randomly generated subnets and VNI, filtered to only include CIDRs for the
// IP families supported by the cluster. Used by the EVPN disruptive test setup.
func NewL3IPVRFNetworkSpec(ipFamilySet sets.Set[utilnet.IPFamily]) *udnv1.NetworkSpec {
	cudnIPv4, cudnIPv6 := randomCUDNSubnets()
	var subnets []udnv1.Layer3Subnet
	if ipFamilySet.Has(utilnet.IPv4) {
		subnets = append(subnets, udnv1.Layer3Subnet{CIDR: udnv1.CIDR(cudnIPv4)})
	}
	if ipFamilySet.Has(utilnet.IPv6) {
		subnets = append(subnets, udnv1.Layer3Subnet{CIDR: udnv1.CIDR(cudnIPv6)})
	}
	return &udnv1.NetworkSpec{
		Topology: udnv1.NetworkTopologyLayer3,
		Layer3: &udnv1.Layer3Config{
			Role:    udnv1.NetworkRolePrimary,
			Subnets: subnets,
		},
		Transport: udnv1.TransportOptionEVPN,
		EVPN: &udnv1.EVPNConfig{
			IPVRF: &udnv1.VRFConfig{
				VNI: randomVNI(),
			},
		},
	}
}

// NewL2MACVRFNetworkSpec returns a new Layer2 CUDN EVPN MAC-VRF network specification
// with randomly generated subnets and VNI, filtered to only include CIDRs for the
// IP families supported by the cluster. Used by the EVPN disruptive test setup.
func NewL2MACVRFNetworkSpec(ipFamilySet sets.Set[utilnet.IPFamily]) *udnv1.NetworkSpec {
	cudnIPv4, cudnIPv6 := randomCUDNSubnets()
	var subnets udnv1.DualStackCIDRs
	if ipFamilySet.Has(utilnet.IPv4) {
		subnets = append(subnets, udnv1.CIDR(cudnIPv4))
	}
	if ipFamilySet.Has(utilnet.IPv6) {
		subnets = append(subnets, udnv1.CIDR(cudnIPv6))
	}
	return &udnv1.NetworkSpec{
		Topology: udnv1.NetworkTopologyLayer2,
		Layer2: &udnv1.Layer2Config{
			Role:    udnv1.NetworkRolePrimary,
			Subnets: subnets,
		},
		Transport: udnv1.TransportOptionEVPN,
		EVPN: &udnv1.EVPNConfig{
			MACVRF: &udnv1.VRFConfig{
				VNI: randomVNI(),
			},
		},
	}
}

// SetupEVPNNetworkWithServers configures an EVPN network (external FRR + CUDN namespace)
// for the given networkSpec and returns the created namespace, external server names, and
// the external FRR VLAN IDs / IP-VRF subnets chosen during setup (for EVPNDisruptiveState).
// vtepSubnets is the list of CIDR subnets used for VTEP endpoint discovery; pass nil to
// auto-detect from the primary infra network.
// bgpASN is the BGP Autonomous System Number used by the external FRR router (e.g. 64512).
// frrConfigName optionally overrides the FRRConfiguration CR name. Pass "-" to skip
// FRRConfiguration creation entirely (caller is responsible for creating it beforehand).
func SetupEVPNNetworkWithServers(
	f *framework.Framework,
	ictx infraapi.Context,
	testName string,
	ipFamilySet sets.Set[utilnet.IPFamily],
	networkName string,
	networkSpec *udnv1.NetworkSpec,
	vtepSubnets []string,
	bgpASN int,
	frrConfigName ...string,
) (*corev1.Namespace, []string, EVPNExternalSetupIDs, error) {
	ipVRFAgnhostIPv4, ipVRFAgnhostIPv6 := randomIPVRFAgnhostSubnets()
	ipVRFAgnhostSubnets := []string{ipVRFAgnhostIPv4, ipVRFAgnhostIPv6}
	framework.Logf("Networks allocated for EVPN Agnhost servers: %v", ipVRFAgnhostSubnets)

	if len(vtepSubnets) == 0 {
		primaryNet, err := infraprovider.Get().PrimaryNetwork()
		if err != nil {
			return nil, nil, EVPNExternalSetupIDs{}, fmt.Errorf("failed to get primary network for VTEP subnets: %w", err)
		}
		v4Subnet, _, err := primaryNet.IPv4IPv6Subnets()
		if err != nil {
			return nil, nil, EVPNExternalSetupIDs{}, fmt.Errorf("failed to get primary network subnets: %w", err)
		}
		vtepSubnets = []string{v4Subnet}
	}
	framework.Logf("Networks used for EVPN VTEPs: %v", vtepSubnets)

	macVRFAgnhostName := networkName + "-macvrf-agnhost"
	macVRFNetworkName := macVRFAgnhostName
	ipVRFAgnhostName := networkName + "-ipvrf-agnhost"
	ipVRFNetworkName := ipVRFAgnhostName

	// Determine the FRRConfiguration name to pass through.
	// If caller provided an explicit name (including "-" to skip), use it;
	// otherwise default to testName for backward compatibility.
	fcName := testName
	if len(frrConfigName) > 0 && frrConfigName[0] != "" {
		fcName = frrConfigName[0]
	}
	extIDs, err := runEVPNNetworkAndServers(
		f, ictx, networkName, ipFamilySet, networkSpec,
		ipVRFAgnhostSubnets, vtepSubnets, bgpASN,
		macVRFAgnhostName, macVRFNetworkName, ipVRFAgnhostName, ipVRFNetworkName,
		fcName,
	)
	if err != nil {
		return nil, nil, EVPNExternalSetupIDs{}, fmt.Errorf("failed to run EVPN network and servers: %w", err)
	}

	var servers []string
	if networkSpec.EVPN.MACVRF != nil {
		servers = append(servers, macVRFAgnhostName)
	}
	if networkSpec.EVPN.IPVRF != nil {
		servers = append(servers, ipVRFAgnhostName)
	}

	// cudnAdvertisedEVPNShared: RA selector uses testName ({network: testName}) so both
	// L3 and L2 RouteAdvertisements point to the same shared FRRConfiguration.
	ns, err := createNamespaceWithPrimaryNetworkOfType(f, ictx, testName, networkName, cudnAdvertisedEVPNShared, networkSpec)
	if err != nil {
		return nil, nil, EVPNExternalSetupIDs{}, fmt.Errorf("failed to create namespace with EVPN network: %w", err)
	}
	return ns, servers, extIDs, nil
}

// GetExternalFRRIP returns the primary-network IP of the external FRR container,
// choosing IPv4 or IPv6 according to ipFamilySet. Used to set FrrVTEPIP in EVPNDisruptiveState.
func GetExternalFRRIP(ipFamilySet sets.Set[utilnet.IPFamily]) (string, error) {
	return getExternalFRRIP(ipFamilySet)
}

// RestartExternalFRRDaemons force-restarts the FRR routing daemons inside the external
// FRR container without stopping the container; see restartExternalFRRDaemons.
func RestartExternalFRRDaemons() error { return restartExternalFRRDaemons() }

// WaitForExternalFRRProcessReady polls until the FRR process inside the external container
// is ready to accept vtysh commands.
func WaitForExternalFRRProcessReady(timeout time.Duration) error {
	return waitForExternalFRRProcessReady(timeout)
}

// ReapplyEVPNKernelStateOnFRR re-creates transient Linux kernel objects on the external FRR
// container (bridges, VXLANs, VRFs) that are destroyed when the container is restarted.
func ReapplyEVPNKernelStateOnFRR(ictx infraapi.Context, ipFamilySet sets.Set[utilnet.IPFamily], states []EVPNDisruptiveState) error {
	return reapplyEVPNKernelStateOnFRR(ictx, ipFamilySet, states)
}

// WaitForExternalFRRBGPReady polls until at least expectedNeighborCount EVPN BGP
// neighbors are in "Established" state on the external FRR container.
func WaitForExternalFRRBGPReady(expectedNeighborCount int, timeout time.Duration) error {
	return waitForExternalFRRBGPReady(expectedNeighborCount, timeout)
}

// WaitForEVPNRouteConvergence polls until ALL expectedNeighborCount Established
// BGP neighbors have received EVPN routes from cluster nodes.
func WaitForEVPNRouteConvergence(expectedNeighborCount int, timeout time.Duration) error {
	return waitForEVPNRouteConvergence(expectedNeighborCount, timeout)
}

// RestartFRRK8sPods deletes all pods in the given namespace (typically frr-k8s-system)
// and waits for new pods to become Running and Ready.
func RestartFRRK8sPods(clientset kubernetes.Interface, namespace string) error {
	return restartFRRK8sPods(clientset, namespace)
}

// VerifyEVPNVNIsActive runs "show evpn vni json" on the external FRR and checks that each
// VNI from states is present. L2: numRemoteVteps >= 1. L3: numArpNd >= 1 (FRR L3 summary
// sets numRemoteVteps to the string "n/a", not a VTEP count). Call after BGP/EVPN convergence.
func VerifyEVPNVNIsActive(states []EVPNDisruptiveState) error {
	return verifyEVPNVNIsActive(states)
}

// RandomVTEPSubnets returns randomly generated VTEP CIDR subnets (IPv4 /24 and IPv6 /112)
// from the RFC 6598 shared address space, suitable for VTEP loopback IP allocation.
func RandomVTEPSubnets() (string, string) { return randomVTEPSubnets() }

// EnsureVTEPLoopbackIPs re-adds VTEP loopback IPs on all nodes for the given CIDRs.
// Idempotent: skips IPs that are already assigned. Use after a node reboot to restore
// the loopback IPs that are lost when the node restarts.
func EnsureVTEPLoopbackIPs(f *framework.Framework, ictx infraapi.Context, vtepCIDRs []string) error {
	return ensureVTEPLoopbackIPs(f, ictx, vtepCIDRs)
}

// NewL2MACVRFIPVRFNetworkSpec returns a new Layer2 CUDN EVPN network specification
// with both MAC-VRF and IP-VRF configured, using randomly generated subnets and VNIs,
// filtered to only include CIDRs for the IP families supported by the cluster.
func NewL2MACVRFIPVRFNetworkSpec(ipFamilySet sets.Set[utilnet.IPFamily]) *udnv1.NetworkSpec {
	cudnIPv4, cudnIPv6 := randomCUDNSubnets()
	var subnets udnv1.DualStackCIDRs
	if ipFamilySet.Has(utilnet.IPv4) {
		subnets = append(subnets, udnv1.CIDR(cudnIPv4))
	}
	if ipFamilySet.Has(utilnet.IPv6) {
		subnets = append(subnets, udnv1.CIDR(cudnIPv6))
	}
	return &udnv1.NetworkSpec{
		Topology: udnv1.NetworkTopologyLayer2,
		Layer2: &udnv1.Layer2Config{
			Role:    udnv1.NetworkRolePrimary,
			Subnets: subnets,
		},
		Transport: udnv1.TransportOptionEVPN,
		EVPN: &udnv1.EVPNConfig{
			MACVRF: &udnv1.VRFConfig{
				VNI: randomVNI(),
			},
			IPVRF: &udnv1.VRFConfig{
				VNI: randomVNI(),
			},
		},
	}
}

// WaitForDaemonSetReady polls until a DaemonSet has all pods updated, ready, and
// available. Used after restarting ovnkube-node or frr-k8s DaemonSet pods to
// confirm the DaemonSet controller considers the rollout complete.
func WaitForDaemonSetReady(clientset kubernetes.Interface, namespace, name string, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		ds, err := clientset.AppsV1().DaemonSets(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			framework.Logf("WaitForDaemonSetReady: error getting DaemonSet %s/%s: %v", namespace, name, err)
			return false, nil
		}
		ready := ds.Status.DesiredNumberScheduled > 0 &&
			ds.Status.DesiredNumberScheduled == ds.Status.NumberReady &&
			ds.Status.DesiredNumberScheduled == ds.Status.UpdatedNumberScheduled &&
			ds.Status.NumberUnavailable == 0
		if !ready {
			framework.Logf("DaemonSet %s/%s: desired=%d ready=%d updated=%d unavailable=%d",
				namespace, name,
				ds.Status.DesiredNumberScheduled, ds.Status.NumberReady,
				ds.Status.UpdatedNumberScheduled, ds.Status.NumberUnavailable)
		}
		return ready, nil
	})
}

// EVPNPodConnectsToHostname asserts that src can HTTP-reach dstIP and that the
// response hostname equals expect. Uses generous timeouts suitable for post-disruption checks.
func EVPNPodConnectsToHostname(src *corev1.Pod, dstIP, expect string) {
	const (
		evpnConnTimeout    = 240 * time.Second
		evpnConnPolling    = 1 * time.Second
		evpnCurlMaxTimeSec = 1
		evpnNetexecPort    = 8080
	)
	ginkgo.GinkgoHelper()
	hostname, err := e2epodoutput.RunHostCmdWithRetries(
		src.Namespace,
		src.Name,
		fmt.Sprintf("curl --max-time %d -g -q -s http://%s/hostname", evpnCurlMaxTimeSec, net.JoinHostPort(dstIP, fmt.Sprintf("%d", evpnNetexecPort))),
		evpnConnPolling,
		evpnConnTimeout,
	)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(hostname).To(gomega.Equal(expect))
}

// EVPNPodCannotConnect asserts that src consistently cannot HTTP-reach dstIP.
// Uses short timeouts to verify isolation without making the test too slow.
func EVPNPodCannotConnect(src *corev1.Pod, dstIP string) {
	const (
		evpnIsolTimeout    = 5 * time.Second
		evpnIsolPolling    = 2 * time.Second
		evpnCurlMaxTimeSec = 1
		evpnNetexecPort    = 8080
	)
	ginkgo.GinkgoHelper()
	gomega.Consistently(func(g gomega.Gomega) {
		_, err := e2epodoutput.RunHostCmd(
			src.Namespace,
			src.Name,
			fmt.Sprintf("curl --max-time %d -g -q -s http://%s/clientip", evpnCurlMaxTimeSec, net.JoinHostPort(dstIP, fmt.Sprintf("%d", evpnNetexecPort))),
		)
		g.Expect(err).To(gomega.HaveOccurred())
	}).WithTimeout(evpnIsolTimeout).WithPolling(evpnIsolPolling).Should(gomega.Succeed())
}
