// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux
// +build linux

package util

import (
	"errors"
	"fmt"
	"testing"

	"github.com/k8snetworkplumbingwg/sriovnet"
	"github.com/onsi/gomega"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	ovsops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	ovntest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	utilmocks "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util/mocks"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/vswitchd"
)

const (
	testHostPFMAC  = "00:73:58:6d:a1:b3"
	testHostVF0MAC = "00:07:3d:f2:76:4a"
)

// newVFBridgeHarness builds an OVS bridge holding a single host VF representor,
// which is the layout of an Uplink bridge on a BlueField style DPU.
func newVFBridgeHarness(t *testing.T) libovsdbclient.Client {
	t.Helper()
	g := gomega.NewWithT(t)

	ovsClient, testCtx, err := libovsdbtest.NewOVSTestHarness(libovsdbtest.TestSetup{
		OVSData: []libovsdbtest.TestData{
			&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"br-vm-uuid"}},
			&vswitchd.Bridge{UUID: "br-vm-uuid", Name: "br-vm", Ports: []string{"pf0vf0-port-uuid"}},
			&vswitchd.Port{UUID: "pf0vf0-port-uuid", Name: "pf0vf0", Interfaces: []string{"pf0vf0-iface-uuid"}},
			&vswitchd.Interface{UUID: "pf0vf0-iface-uuid", Name: "pf0vf0", Type: "system"},
		},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred(), "failed to build the OVS test harness for the VF bridge")
	t.Cleanup(testCtx.Cleanup)
	return ovsClient
}

func replaceSriovnetOps(t *testing.T) *utilmocks.SriovnetOps {
	t.Helper()
	sriovOps := utilmocks.NewSriovnetOps(t)
	orig := GetSriovnetOps()
	SetSriovnetOpsInst(sriovOps)
	t.Cleanup(func() {
		SetSriovnetOpsInst(orig)
	})
	return sriovOps
}

func mustGetBridge(t *testing.T, ovsClient libovsdbclient.Client, name string) *vswitchd.Bridge {
	t.Helper()
	g := gomega.NewWithT(t)
	bridge, err := ovsops.GetBridge(ovsClient, name)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "failed to get bridge %s from the test harness", name)
	return bridge
}

func TestSwitchdevFindHostRepresentorByPeerMACMatchesVF(t *testing.T) {
	g := gomega.NewWithT(t)
	ovsClient := newVFBridgeHarness(t)

	sriovOps := replaceSriovnetOps(t)
	sriovOps.On("GetRepresentorPortFlavour", "pf0vf0").
		Return(sriovnet.PortFlavour(sriovnet.PORT_FLAVOUR_PCI_VF), nil)
	sriovOps.On("GetDevlinkPortFunctionMacAddress", "pf0vf0").
		Return(ovntest.MustParseMAC(testHostVF0MAC), nil)

	rep, err := (&SwitchdevDPUOps{}).FindHostRepresentorByPeerMAC(
		ovsClient, mustGetBridge(t, ovsClient, "br-vm"), ovntest.MustParseMAC(testHostVF0MAC), "node-a")
	g.Expect(err).NotTo(gomega.HaveOccurred(), "looking up the VF representor by its host peer MAC must succeed")
	g.Expect(rep).To(gomega.Equal("pf0vf0"), "pf0vf0 is the VF representor peering with the host MAC")
}

func TestSwitchdevFindHostRepresentorByPeerMACMatchesSF(t *testing.T) {
	g := gomega.NewWithT(t)
	ovsClient := newVFBridgeHarness(t)

	sriovOps := replaceSriovnetOps(t)
	sriovOps.On("GetRepresentorPortFlavour", "pf0vf0").
		Return(sriovnet.PortFlavour(sriovnet.PORT_FLAVOUR_PCI_SF), nil)
	// SF representors resolve directly through devlink; there is no sriovnet
	// fallback to configure.
	sriovOps.On("GetDevlinkPortFunctionMacAddress", "pf0vf0").
		Return(ovntest.MustParseMAC(testHostVF0MAC), nil)

	rep, err := (&SwitchdevDPUOps{}).FindHostRepresentorByPeerMAC(
		ovsClient, mustGetBridge(t, ovsClient, "br-vm"), ovntest.MustParseMAC(testHostVF0MAC), "node-a")
	g.Expect(err).NotTo(gomega.HaveOccurred(), "looking up the SF representor by its host peer MAC must succeed")
	g.Expect(rep).To(gomega.Equal("pf0vf0"), "pf0vf0 is the SF representor peering with the host MAC")
}

func TestSwitchdevFindHostRepresentorByPeerMACRejectsZeroFallbackMAC(t *testing.T) {
	g := gomega.NewWithT(t)
	ovsClient := newVFBridgeHarness(t)

	sriovOps := replaceSriovnetOps(t)
	sriovOps.On("GetRepresentorPortFlavour", "pf0vf0").
		Return(sriovnet.PortFlavour(sriovnet.PORT_FLAVOUR_PCI_PF), nil)
	sriovOps.On("GetDevlinkPortFunctionMacAddress", "pf0vf0").
		Return(nil, fmt.Errorf("devlink unavailable"))
	// The sriovnet fallback can report an unset PF peer MAC as all zeroes with
	// a nil error; it must not be matched, even against a zero host MAC.
	sriovOps.On("GetRepresentorPeerMacAddress", "pf0vf0").
		Return(ovntest.MustParseMAC("00:00:00:00:00:00"), nil)

	_, err := (&SwitchdevDPUOps{}).FindHostRepresentorByPeerMAC(
		ovsClient, mustGetBridge(t, ovsClient, "br-vm"), ovntest.MustParseMAC("00:00:00:00:00:00"), "node-a")
	g.Expect(errors.Is(err, ErrHostRepresentorNotFound)).To(gomega.BeTrue(),
		"an all-zero fallback MAC must be treated as unset, not matched")
}

func TestSwitchdevFindHostRepresentorByPeerMACMissWrapsSentinel(t *testing.T) {
	g := gomega.NewWithT(t)
	ovsClient := newVFBridgeHarness(t)

	sriovOps := replaceSriovnetOps(t)
	sriovOps.On("GetRepresentorPortFlavour", "pf0vf0").
		Return(sriovnet.PortFlavour(sriovnet.PORT_FLAVOUR_PCI_VF), nil)
	sriovOps.On("GetDevlinkPortFunctionMacAddress", "pf0vf0").
		Return(ovntest.MustParseMAC(testHostVF0MAC), nil)

	_, err := (&SwitchdevDPUOps{}).FindHostRepresentorByPeerMAC(
		ovsClient, mustGetBridge(t, ovsClient, "br-vm"), ovntest.MustParseMAC(testHostPFMAC), "node-a")
	g.Expect(errors.Is(err, ErrHostRepresentorNotFound)).To(gomega.BeTrue(),
		"a clean miss must wrap ErrHostRepresentorNotFound so callers can keep searching")
}

func TestSwitchdevFindHostRepresentorByPeerMACSkipsUnreadableRepresentor(t *testing.T) {
	g := gomega.NewWithT(t)
	ovsClient, testCtx, err := libovsdbtest.NewOVSTestHarness(libovsdbtest.TestSetup{
		OVSData: []libovsdbtest.TestData{
			&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"br-vm-uuid"}},
			&vswitchd.Bridge{UUID: "br-vm-uuid", Name: "br-vm", Ports: []string{"pf0vf0-port-uuid", "pf0vf7-port-uuid"}},
			&vswitchd.Port{UUID: "pf0vf0-port-uuid", Name: "pf0vf0", Interfaces: []string{"pf0vf0-iface-uuid"}},
			&vswitchd.Interface{UUID: "pf0vf0-iface-uuid", Name: "pf0vf0", Type: "system"},
			&vswitchd.Port{UUID: "pf0vf7-port-uuid", Name: "pf0vf7", Interfaces: []string{"pf0vf7-iface-uuid"}},
			&vswitchd.Interface{UUID: "pf0vf7-iface-uuid", Name: "pf0vf7", Type: "system"},
		},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred(), "failed to build the OVS test harness for the two-representor bridge")
	t.Cleanup(testCtx.Cleanup)

	sriovOps := replaceSriovnetOps(t)
	// pf0vf0 is unreadable: a VF representor has no sriovnet fallback, so
	// its devlink failure must not abort the scan. The walk is in map order,
	// so when pf0vf7 happens to be visited first pf0vf0 is never probed;
	// hence the Maybe.
	sriovOps.On("GetRepresentorPortFlavour", "pf0vf0").
		Return(sriovnet.PortFlavour(sriovnet.PORT_FLAVOUR_PCI_VF), nil).
		Maybe()
	sriovOps.On("GetDevlinkPortFunctionMacAddress", "pf0vf0").
		Return(nil, fmt.Errorf("devlink unavailable")).
		Maybe()
	sriovOps.On("GetRepresentorPortFlavour", "pf0vf7").
		Return(sriovnet.PortFlavour(sriovnet.PORT_FLAVOUR_PCI_VF), nil)
	sriovOps.On("GetDevlinkPortFunctionMacAddress", "pf0vf7").
		Return(ovntest.MustParseMAC(testHostVF0MAC), nil)

	rep, err := (&SwitchdevDPUOps{}).FindHostRepresentorByPeerMAC(
		ovsClient, mustGetBridge(t, ovsClient, "br-vm"), ovntest.MustParseMAC(testHostVF0MAC), "node-a")
	g.Expect(err).NotTo(gomega.HaveOccurred(),
		"the unreadable representor must be skipped, not abort the scan")
	g.Expect(rep).To(gomega.Equal("pf0vf7"), "the matching representor after the unreadable one must be found")
}

// TestSwitchdevGetHostGatewayMACAddressStaysPFOnly guards the default gateway
// bridge path, which must keep resolving through the host PF representor only.
func TestSwitchdevGetHostGatewayMACAddressStaysPFOnly(t *testing.T) {
	g := gomega.NewWithT(t)
	ovsClient := newVFBridgeHarness(t)

	sriovOps := replaceSriovnetOps(t)
	sriovOps.On("GetRepresentorPortFlavour", "pf0vf0").
		Return(sriovnet.PortFlavour(sriovnet.PORT_FLAVOUR_PCI_VF), nil)

	_, err := (&SwitchdevDPUOps{}).GetHostGatewayMACAddress(ovsClient, "br-vm", "node-a")
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("dpu host interface was not found")))
}

func TestSimulatedFindHostRepresentorByPeerMAC(t *testing.T) {
	g := gomega.NewWithT(t)
	ovsClient, testCtx, err := libovsdbtest.NewOVSTestHarness(libovsdbtest.TestSetup{
		OVSData: []libovsdbtest.TestData{
			&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"br-vm-uuid"}},
			&vswitchd.Bridge{UUID: "br-vm-uuid", Name: "br-vm", Ports: []string{"rep-port-uuid"}},
			&vswitchd.Port{UUID: "rep-port-uuid", Name: "rep0-1", Interfaces: []string{"rep-iface-uuid"}},
			&vswitchd.Interface{UUID: "rep-iface-uuid", Name: "rep0-1"},
		},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred(), "failed to build the OVS test harness for the simulated bridge")
	t.Cleanup(testCtx.Cleanup)

	ops := &SimulatedDPUOps{}
	// The MAC the simulator derives for this bridge must be the same one the
	// reverse lookup accepts.
	hostMAC, err := ops.GetHostGatewayMACAddress(ovsClient, "br-vm", "node-a")
	g.Expect(err).NotTo(gomega.HaveOccurred(), "deriving the simulated host gateway MAC must succeed")

	rep, err := ops.FindHostRepresentorByPeerMAC(ovsClient, mustGetBridge(t, ovsClient, "br-vm"), hostMAC, "node-a")
	g.Expect(err).NotTo(gomega.HaveOccurred(), "the reverse lookup must accept the MAC the forward lookup derived")
	g.Expect(rep).To(gomega.Equal("rep0-1"), "rep0-1 is the only simulated representor on br-vm")

	// A different node derives a different MAC, so the lookup must miss.
	otherMAC, err := ops.GetHostGatewayMACAddress(ovsClient, "br-vm", "node-b")
	g.Expect(err).NotTo(gomega.HaveOccurred(), "deriving the simulated MAC for another node must succeed")
	_, err = ops.FindHostRepresentorByPeerMAC(ovsClient, mustGetBridge(t, ovsClient, "br-vm"), otherMAC, "node-a")
	g.Expect(errors.Is(err, ErrHostRepresentorNotFound)).To(gomega.BeTrue(),
		"a MAC derived for another node must be a clean miss")
}
