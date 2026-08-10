// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package bridgeconfig

import (
	"fmt"
	"net"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	udngenerator "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/generator/udn"
	nodetypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

func TestArpFanoutFilterFlowsIncludeVLAN(t *testing.T) {
	if err := config.PrepareTestConfig(); err != nil {
		t.Fatalf("failed to prepare test config: %v", err)
	}
	t.Cleanup(func() {
		_ = config.PrepareTestConfig()
	})
	config.IPv4Mode = true
	config.IPv6Mode = true
	config.Gateway.Mode = config.GatewayModeShared
	config.Gateway.VLANID = 100
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableNetworkSegmentation = true

	bridgeMAC := mustParseMAC(t, "62:41:d0:54:3d:64")
	v4NodeIP := mustParseIPNet(t, "172.18.0.3/24")
	v6NodeIP := mustParseIPNet(t, "fd00::3/64")
	v4GatewayMasqIP := mustParseIPNet(t, "169.254.0.11/32")
	v4ManagementMasqIP := mustParseIPNet(t, "169.254.0.12/32")
	v6GatewayMasqIP := mustParseIPNet(t, "fd69::11/128")
	v6ManagementMasqIP := mustParseIPNet(t, "fd69::12/128")

	bridge := &BridgeConfiguration{
		ofPortPhys: "eth0",
		ofPortHost: nodetypes.OvsLocalPort,
		ips:        []*net.IPNet{v4NodeIP, v6NodeIP},
		macAddress: bridgeMAC,
		netConfig: map[string]*BridgeUDNConfiguration{
			types.DefaultNetworkName: {
				OfPortPatch: "patch-breth0_ov",
				MasqCTMark:  nodetypes.CtMarkOVN,
			},
			"bluenet": {
				OfPortPatch: "patch-breth0_bluenet",
				MasqCTMark:  "0x4",
				V4MasqIPs: &udngenerator.MasqueradeIPs{
					GatewayRouter:  v4GatewayMasqIP,
					ManagementPort: v4ManagementMasqIP,
				},
				V6MasqIPs: &udngenerator.MasqueradeIPs{
					GatewayRouter:  v6GatewayMasqIP,
					ManagementPort: v6ManagementMasqIP,
				},
			},
		},
	}

	flows, err := bridge.commonFlows(nil)
	if err != nil {
		t.Fatalf("failed to render bridge flows: %v", err)
	}

	expectedIPv4 := fmt.Sprintf("cookie=%s, priority=11, table=0, dl_vlan=100, arp, arp_op=1, arp_tpa=172.18.0.3, "+
		"actions=output:patch-breth0_ov,strip_vlan,output:LOCAL",
		nodetypes.DefaultOpenFlowCookie)
	expectedIPv6 := fmt.Sprintf("cookie=%s, priority=11, table=0, dl_vlan=100, icmp6, icmpv6_type=%d, nd_target=fd00::3, "+
		"actions=output:patch-breth0_ov,strip_vlan,output:LOCAL",
		nodetypes.DefaultOpenFlowCookie, types.NeighborSolicitationICMPType)

	expectFlow(t, flows, expectedIPv4)
	expectFlow(t, flows, expectedIPv6)
}

func mustParseMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("failed to parse MAC %q: %v", value, err)
	}
	return mac
}

func mustParseIPNet(t *testing.T, value string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatalf("failed to parse CIDR %q: %v", value, err)
	}
	ipNet.IP = ip
	return ipNet
}

func expectFlow(t *testing.T, flows []string, expected string) {
	t.Helper()
	for _, flow := range flows {
		if flow == expected {
			return
		}
	}
	t.Fatalf("expected flow not found:\n%s\n\nall flows:\n%v", expected, flows)
}
