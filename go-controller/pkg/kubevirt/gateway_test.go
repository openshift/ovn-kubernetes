// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/stretchr/testify/require"
	kubevirtv1 "kubevirt.io/api/core/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	ovncnitypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	logicalswitchmanager "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func TestLiveMigrationStatusIsTarget(t *testing.T) {
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target", UID: "target-uid"}}
	status := LiveMigrationStatus{TargetPod: target}
	require.True(t, status.IsTarget(target.DeepCopy()))
	require.False(t, status.IsTarget(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "source", UID: "source-uid"}}))
	// A recreated pod with the same name is not the original migration target.
	require.False(t, status.IsTarget(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: target.Name, UID: "replacement-uid"}}))
}

func TestDefaultNetworkGatewayGARP(t *testing.T) {
	require.NoError(t, config.PrepareTestConfig())
	for _, tc := range []struct {
		name        string
		state       LiveMigrationState
		role        string
		gateways    []net.IP
		wantMAC     string
		invalid     bool
		sendFailed  bool
		notAllowed  bool
		hostNetwork bool
	}{
		{name: "ready target on any node", state: LiveMigrationTargetDomainReady, wantMAC: ARPProxyMAC},
		{name: "not ready", state: LiveMigrationInProgress},
		{name: "failed", state: LiveMigrationFailed},
		{name: "VM without bridge migration annotation", state: LiveMigrationTargetDomainReady, notAllowed: true},
		{name: "host network VM", state: LiveMigrationTargetDomainReady, hostNetwork: true},
		{name: "infrastructure network", state: LiveMigrationTargetDomainReady, role: types.NetworkRoleInfrastructure},
		{name: "IPv6 only", state: LiveMigrationTargetDomainReady, gateways: ovntest.MustParseIPs("fd00:1::1")},
		{name: "invalid annotation", state: LiveMigrationTargetDomainReady, invalid: true},
		{name: "retry send failure", state: LiveMigrationTargetDomainReady, wantMAC: ARPProxyMAC, sendFailed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateways := tc.gateways
			if gateways == nil {
				gateways = ovntest.MustParseIPs("10.244.1.1", "fd00:1::1")
			}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{kubevirtv1.AppLabel: "virt-launcher"}},
				Spec:       corev1.PodSpec{NodeName: "target", HostNetwork: tc.hostNetwork},
			}
			annotations, err := util.MarshalPodAnnotation(nil, &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets("10.244.1.8/24", "fd00:1::8/64"),
				MAC: ovntest.MustParseMAC("0a:58:0a:f4:01:08"), Gateways: gateways, Role: tc.role,
			}, types.DefaultNetworkName)
			require.NoError(t, err)
			pod.Annotations = annotations
			if tc.invalid {
				pod.Annotations = nil
			}
			if !tc.notAllowed {
				if pod.Annotations == nil {
					pod.Annotations = map[string]string{}
				}
				pod.Annotations[kubevirtv1.AllowPodBridgeNetworkLiveMigrationAnnotation] = ""
			}
			// No node lookup is needed, even when returning to the subnet owner.
			r := NewClusterDefaultNetworkGatewayAnnouncer(types.K8sMgmtIntfName)
			calls := 0
			sendErr := errors.New("send failed")
			r.unicastGARP = func(iface string, garp util.GARP, destinationMAC net.HardwareAddr) error {
				calls++
				require.Equal(t, "0a:58:0a:f4:01:08", destinationMAC.String())
				require.Equal(t, types.K8sMgmtIntfName, iface)
				require.Equal(t, "10.244.1.1", garp.IP().String())
				require.Equal(t, tc.wantMAC, garp.MAC().String())
				if tc.sendFailed && calls == 1 {
					return sendErr
				}
				return nil
			}
			status := &LiveMigrationStatus{TargetPod: pod, State: tc.state}
			err = r.AnnounceIPv4AfterLiveMigration(status)
			switch {
			case tc.invalid:
				require.Error(t, err)
			case tc.sendFailed:
				require.ErrorIs(t, err, sendErr)
				require.NoError(t, r.AnnounceIPv4AfterLiveMigration(status))
				require.Equal(t, 2, calls)
			default:
				require.NoError(t, err)
				if tc.wantMAC == "" {
					require.Zero(t, calls)
				} else {
					require.Equal(t, 1, calls)
				}
			}
		})
	}
}

func TestLayer2GatewayGARP(t *testing.T) {
	require.NoError(t, config.PrepareTestConfig())
	config.IPv4Mode, config.IPv6Mode = true, false
	config.OVNKubernetesFeature.EnableNetworkSegmentation = true
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	netInfo, err := util.NewNetInfo(&ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{Name: "blue"}, Topology: types.Layer2Topology,
		Role: types.NetworkRolePrimary, Subnets: "10.100.0.0/24", JoinSubnet: "100.65.0.0/16",
	})
	require.NoError(t, err)
	wf, err := factory.NewOVNKubeControllerWatchFactory(util.GetOVNClientset().GetOVNKubeControllerClientset())
	require.NoError(t, err)
	t.Cleanup(wf.Shutdown)
	require.NoError(t, wf.NodeCoreInformer().Informer().GetStore().Add(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Annotations: map[string]string{util.OvnNodeID: "4"}},
	}))
	mutableNetInfo := util.NewMutableNetInfo(netInfo)
	mutableNetInfo.SetNADs("ns/blue")
	r := NewLayer2GatewayAnnouncer(wf, mutableNetInfo, "ovn-k8s-mp1")
	calls := 0
	r.unicastGARP = func(iface string, garp util.GARP, destinationMAC net.HardwareAddr) error {
		calls++
		require.Equal(t, "0a:58:0a:f4:01:08", destinationMAC.String())
		require.Equal(t, "ovn-k8s-mp1", iface)
		require.Equal(t, "10.100.0.1", garp.IP().String())
		wantMAC := "0a:58:64:41:00:04"
		require.Equal(t, wantMAC, garp.MAC().String())
		return nil
	}
	// Layer2 VMs do not require the default-network bridge opt-in annotation.
	annotations, err := util.MarshalPodAnnotation(nil, &util.PodAnnotation{IPs: ovntest.MustParseIPNets("10.100.0.8/24"), MAC: ovntest.MustParseMAC("0a:58:0a:f4:01:08")}, "ns/blue")
	require.NoError(t, err)
	status := &LiveMigrationStatus{TargetPod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}, Spec: corev1.PodSpec{NodeName: "target"}}}
	for _, state := range []LiveMigrationState{LiveMigrationInProgress, LiveMigrationFailed} {
		status.State = state
		require.NoError(t, r.AnnounceIPv4AfterLiveMigration(status))
		require.Zero(t, calls)
	}
	status.State = LiveMigrationTargetDomainReady
	require.NoError(t, r.AnnounceIPv4AfterLiveMigration(status))
	require.Equal(t, 1, calls)
}

func TestLocalMigratablePodRoutingAndGateway(t *testing.T) {
	for _, tc := range []struct {
		name                                                        string
		home, notReady, source, ipv6Only, routeFailure, sendFailure bool
	}{
		{name: "foreign target"},
		{name: "return home", home: true},
		{name: "in progress", notReady: true},
		{name: "source pod", source: true},
		{name: "IPv6 only", ipv6Only: true},
		{name: "routing failure", routeFailure: true},
		{name: "GARP retry", sendFailure: true},
		{name: "GARP retry after return-home cleanup", home: true, sendFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, config.PrepareTestConfig())
			config.OVNKubernetesFeature.EnableInterconnect = true
			config.IPv4Mode, config.IPv6Mode = !tc.ipv6Only, tc.ipv6Only
			wf, err := factory.NewOVNKubeControllerWatchFactory(util.GetOVNClientset().GetOVNKubeControllerClientset())
			require.NoError(t, err)
			t.Cleanup(wf.Shutdown)
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "ns", UID: "target", CreationTimestamp: metav1.Now(),
					Labels:      map[string]string{kubevirtv1.AppLabel: "virt-launcher", kubevirtv1.VirtualMachineNameLabel: "vm"},
					Annotations: map[string]string{kubevirtv1.DomainAnnotation: "vm", kubevirtv1.AllowPodBridgeNetworkLiveMigrationAnnotation: ""}},
				Spec: corev1.PodSpec{NodeName: "target"}, Status: corev1.PodStatus{Phase: corev1.PodRunning},
			}
			if !tc.notReady {
				pod.Annotations[kubevirtv1.MigrationTargetReadyTimestamp] = "ready"
			}
			podIP, gateway, clusterCIDR := "10.244.1.8/24", "10.244.1.1", "10.244.0.0/16"
			if tc.ipv6Only {
				podIP, gateway, clusterCIDR = "fd00:1::8/64", "fd00:1::1", "fd00::/48"
			}
			pod.Annotations, err = util.MarshalPodAnnotation(pod.Annotations, &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets(podIP), MAC: ovntest.MustParseMAC("0a:58:0a:f4:01:08"), Gateways: ovntest.MustParseIPs(gateway),
			}, types.DefaultNetworkName)
			require.NoError(t, err)
			source := pod.DeepCopy()
			source.Name, source.UID, source.Spec.NodeName = "source", "source", "source"
			source.CreationTimestamp = metav1.NewTime(pod.CreationTimestamp.Add(-time.Minute))
			delete(source.Annotations, kubevirtv1.MigrationTargetReadyTimestamp)
			source.Labels[kubevirtv1.NodeNameLabel] = "source"
			for _, p := range []*corev1.Pod{source, pod} {
				require.NoError(t, wf.PodCoreInformer().Informer().GetStore().Add(p))
			}
			if !tc.routeFailure {
				require.NoError(t, wf.NodeCoreInformer().Informer().GetStore().Add(&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: "target", Annotations: map[string]string{util.OvnNodeID: "4"}},
				}))
			}
			staleRoute := &nbdb.LogicalRouterStaticRoute{UUID: "stale", IPPrefix: "10.244.1.8", Nexthop: "10.244.1.8",
				Policy: ptr.To(nbdb.LogicalRouterStaticRoutePolicyDstIP), ExternalIDs: map[string]string{
					VirtualMachineExternalIDsKey: "vm", NamespaceExternalIDsKey: "ns", OvnZoneExternalIDKey: OvnLocalZone,
				}}
			initial := []libovsdbtest.TestData{&nbdb.LogicalRouter{Name: types.OVNClusterRouter, UUID: "router"}}
			initial = append(initial, &nbdb.LogicalRouterPort{UUID: "lrp", Name: types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + "target", Networks: []string{"100.64.0.4/16", "fd98::4/64"}}, &nbdb.LogicalRouter{Name: types.GWRouterPrefix + "target", Ports: []string{"lrp"}})
			if tc.home {
				initial = []libovsdbtest.TestData{staleRoute, &nbdb.LogicalRouter{Name: types.OVNClusterRouter, UUID: "router", StaticRoutes: []string{"stale"}}}
			}
			nbClient, dbCtx, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{NBData: initial}, nil)
			require.NoError(t, err)
			t.Cleanup(dbCtx.Cleanup)
			lsManager := logicalswitchmanager.NewLogicalSwitchManager()
			if tc.home {
				require.NoError(t, lsManager.AddOrUpdateSwitch("target", ovntest.MustParseIPNets("10.244.1.0/24"), nil))
			}
			r := NewClusterDefaultNetworkGatewayAnnouncer(types.K8sMgmtIntfName)
			calls := 0
			sendErr := errors.New("send failed")
			r.unicastGARP = func(_ string, garp util.GARP, destinationMAC net.HardwareAddr) error {
				calls++
				require.Equal(t, "0a:58:0a:f4:01:08", destinationMAC.String())
				// Verify that routing has converged before notifying the guest.
				require.Eventually(t, func() bool {
					var routes []nbdb.LogicalRouterStaticRoute
					if err := nbClient.List(context.Background(), &routes); err != nil {
						return false
					}
					if tc.home {
						return len(routes) == 0
					}
					return len(routes) == 2
				}, time.Second, 10*time.Millisecond)
				require.Equal(t, ARPProxyMAC, garp.MAC().String())
				if tc.sendFailure && calls == 1 {
					return sendErr
				}
				return nil
			}
			if tc.source {
				pod = source
			}
			clusterSubnets := []config.CIDRNetworkEntry{{CIDR: ovntest.MustParseIPNet(clusterCIDR), HostSubnetLength: 24}}
			if tc.routeFailure || tc.ipv6Only {
				// Exercise the public coordinator: route failures and IPv6-only
				// configurations must not attempt to send a GARP.
				err = EnsureDefaultNetworkForLocalMigratablePod(wf, nbClient, lsManager, pod, clusterSubnets)
			} else {
				require.NoError(t, ensureLocalZonePodAddressesToNodeRoute(wf, nbClient, lsManager, pod, types.DefaultNetworkName, clusterSubnets))
				if tc.notReady || tc.source {
					err = reconcileIPv4GatewayForMigratablePod(wf, pod)
				} else {
					status, discoverErr := DiscoverLiveMigrationStatus(wf, pod)
					require.NoError(t, discoverErr)
					require.NotNil(t, status)
					err = r.AnnounceIPv4AfterLiveMigration(status)
				}
			}
			switch {
			case tc.routeFailure:
				require.Error(t, err)
				require.Zero(t, calls)
			case tc.sendFailure:
				require.ErrorIs(t, err, sendErr)
				require.NoError(t, ensureLocalZonePodAddressesToNodeRoute(wf, nbClient, lsManager, pod, types.DefaultNetworkName, clusterSubnets))
				status, discoverErr := DiscoverLiveMigrationStatus(wf, pod)
				require.NoError(t, discoverErr)
				require.NotNil(t, status)
				require.NoError(t, r.AnnounceIPv4AfterLiveMigration(status))
				require.Equal(t, 2, calls)
			default:
				require.NoError(t, err)
				if tc.notReady || tc.source || tc.ipv6Only {
					require.Zero(t, calls)
				} else {
					require.Equal(t, 1, calls)
				}
			}
		})
	}
}
