// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/util/sets"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"

	ovncnitypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

// recorder is a sink for the reconcile keys a controller.Reconciler receives, so
// tests can assert which follow-up work the controller enqueued.
type recorder struct {
	mu   sync.Mutex
	keys []string
}

func (r *recorder) record(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.keys))
	copy(out, r.keys)
	return out
}

// startRecorder builds a real controller.Reconciler whose only job is to record
// the keys it is handed (controller.Reconciler has unexported methods, so it
// cannot be faked outside the package). The caller must controller.Stop it.
func startRecorder(g gomega.Gomega, name string) (*recorder, controller.Reconciler) {
	rec := &recorder{}
	r := controller.NewReconciler(name, &controller.ReconcilerConfig{
		RateLimiter: controller.DefaultRateLimiter[string](),
		Reconcile:   func(key string) error { rec.record(key); return nil },
		Threadiness: 1,
		MaxAttempts: 1,
	})
	g.Expect(controller.Start(r)).To(gomega.Succeed())
	return rec, r
}

// cdnPortFor returns the CDN Gateway Router external port name for a node, the
// same way the controller derives it.
func cdnPortFor(node string) string {
	return types.GWRouterToExtSwitchPrefix + (&util.DefaultNetInfo{}).GetNetworkScopedGWRouterName(node)
}

// fakeUplinkSourceProvider provides the designated uplink sources without a real
// openflow manager. An empty map leaves only the default group (the getter adds
// the CDN source for the "" uplink itself).
type fakeUplinkSourceProvider struct {
	sources map[string]string
}

func (f *fakeUplinkSourceProvider) GetMacBindingSourceForUplinks() map[string]string {
	return f.sources
}

// newTestController builds a controller wired only with the fields the
// method-level tests exercise, bypassing NewMACBindingController (which needs a
// live networkManager and watchFactory).
func newTestController() *MACBindingController {
	return &MACBindingController{
		uplinkSourceProvider: &fakeUplinkSourceProvider{sources: map[string]string{}},
		nodeName:             "node1",
		ipv4Enabled:          true,
		followers:            map[string]sets.Set[string]{},
	}
}

func TestIPFamilyEnabled(t *testing.T) {
	g := gomega.NewWithT(t)
	c := &MACBindingController{ipv4Enabled: true, ipv6Enabled: false}
	g.Expect(c.ipFamilyEnabled("10.0.0.5")).To(gomega.BeTrue())
	g.Expect(c.ipFamilyEnabled("fd00::5")).To(gomega.BeFalse())

	c = &MACBindingController{ipv4Enabled: false, ipv6Enabled: true}
	g.Expect(c.ipFamilyEnabled("10.0.0.5")).To(gomega.BeFalse())
	g.Expect(c.ipFamilyEnabled("fd00::5")).To(gomega.BeTrue())
}

// TestReconcileMacBindingsForIPFromSource verifies the mirror read path: given a
// designated source MAC_Binding and a follower Gateway Router port,
// reconcileMacBindingsForIPFromSource resolves the follower datapath and mirrors
// the (ip, mac) pair onto it. A missing source binding is a no-op: followers are
// left to age out rather than being cleared.
func TestReconcileMacBindingsForIPFromSource(t *testing.T) {
	const (
		cdnPort    = "rtoe-GR_node1"
		targetPort = "rtoe-GR_udn_node1"
		srcIP      = "10.0.0.5"
		srcMAC     = "0a:00:00:00:00:05"
	)

	tests := []struct {
		name string
		// seedBinding, when true, seeds the source MAC_Binding row for srcIP.
		seedBinding bool
		reconcileIP string
		wantMirror  bool
	}{
		{
			name:        "mirrors an existing source binding onto the follower",
			seedBinding: true,
			reconcileIP: srcIP,
			wantMirror:  true,
		},
		{
			name:        "is a no-op when the source binding is missing",
			reconcileIP: "10.0.0.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			setup := libovsdbtest.TestSetup{
				IgnoreConstraints: true,
				SBData: []libovsdbtest.TestData{
					&sbdb.DatapathBinding{UUID: "src-dp"},
					&sbdb.DatapathBinding{UUID: "tgt-dp"},
					&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "src-dp"},
					&sbdb.PortBinding{UUID: "tgt-pb", LogicalPort: targetPort, Datapath: "tgt-dp"},
				},
			}
			if tt.seedBinding {
				setup.SBData = append(setup.SBData,
					&sbdb.MACBinding{UUID: "src-mb", LogicalPort: cdnPort, IP: srcIP, MAC: srcMAC, Datapath: "src-dp", Timestamp: 100})
			}
			sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanup.Cleanup()

			c := newTestController()
			c.sbClient = sbClient
			c.cdnGatewayPort = cdnPort
			c.followers[cdnPort] = sets.New(targetPort)

			tgtPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: targetPort})
			g.Expect(err).NotTo(gomega.HaveOccurred())

			// The write is synchronous: TransactAndCheck only returns once the
			// server has broadcast the update and the client has applied it to
			// its cache, so the cache read below needs no Eventually.
			g.Expect(c.reconcileMacBindingsForIPFromSource(tt.reconcileIP, cdnPort, updateWarnDelayThreshold)).To(gomega.Succeed())

			if !tt.wantMirror {
				g.Expect(macBindingsFor(g, sbClient, targetPort)).To(gomega.BeEmpty())
				return
			}

			// The (ip, mac) pair is mirrored onto the follower's datapath.
			mbs := macBindingsFor(g, sbClient, targetPort)
			g.Expect(mbs).To(gomega.HaveLen(1))
			g.Expect(mbs[0].IP).To(gomega.Equal(srcIP))
			g.Expect(mbs[0].MAC).To(gomega.Equal(srcMAC))
			g.Expect(mbs[0].Datapath).To(gomega.Equal(tgtPB.Datapath))
		})
	}
}

// TestReconcileMacBindingsForFollower verifies the follower catch-up path: a
// newly added follower gets every current source binding for an enabled IP
// family mirrored onto it, while bindings for a disabled family are skipped.
func TestReconcileMacBindingsForFollower(t *testing.T) {
	g := gomega.NewWithT(t)

	const (
		cdnPort    = "rtoe-GR_node1"
		targetPort = "rtoe-GR_udn_node1"
	)

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "src-dp"},
			&sbdb.DatapathBinding{UUID: "tgt-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "src-dp"},
			&sbdb.PortBinding{UUID: "tgt-pb", LogicalPort: targetPort, Datapath: "tgt-dp"},
			&sbdb.MACBinding{UUID: "mb1", LogicalPort: cdnPort, IP: "10.0.0.5", MAC: "0a:00:00:00:00:05", Datapath: "src-dp", Timestamp: 100},
			&sbdb.MACBinding{UUID: "mb2", LogicalPort: cdnPort, IP: "10.0.0.6", MAC: "0a:00:00:00:00:06", Datapath: "src-dp", Timestamp: 100},
			// IPv6 binding: ignored because the controller has IPv6 disabled.
			&sbdb.MACBinding{UUID: "mb3", LogicalPort: cdnPort, IP: "fd00::5", MAC: "0a:00:00:00:00:07", Datapath: "src-dp", Timestamp: 100},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	c := newTestController() // ipv4 enabled, ipv6 disabled
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.followers[cdnPort] = sets.New(targetPort)

	tgtPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: targetPort})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(c.reconcileMacBindingsForFollower(targetPort)).To(gomega.Succeed())

	// Only the enabled-family (IPv4) source bindings are mirrored onto the new
	// follower; the IPv6 binding is skipped.
	got := map[string]string{}
	for _, mb := range macBindingsFor(g, sbClient, targetPort) {
		got[mb.IP] = mb.MAC
		g.Expect(mb.Datapath).To(gomega.Equal(tgtPB.Datapath))
	}
	g.Expect(got).To(gomega.Equal(map[string]string{
		"10.0.0.5": "0a:00:00:00:00:05",
		"10.0.0.6": "0a:00:00:00:00:06",
	}))
}

// TestSetMacBindings verifies the actual SB write path: setMacBindings mirrors
// every (port, ip) pair in a single write, creating a row that does not exist,
// replacing one whose timestamp is older than the cooldown, and leaving one
// whose timestamp is still within the cooldown untouched.
func TestSetMacBindings(t *testing.T) {
	const (
		portA     = "rtoe-GR_udnA_node1"
		portB     = "rtoe-GR_udnB_node1"
		ip        = "10.0.0.7"
		otherIP   = "10.0.0.8"
		firstMAC  = "0a:00:00:00:00:07"
		otherMAC  = "0a:00:00:00:00:08"
		secondMAC = "0a:00:00:00:00:99"
	)

	// wantData holds the the mac and timstamp of a mac binding
	type wantData struct {
		mac       string
		timestamp int
	}

	tests := []struct {
		name string
		// initial mac bindings
		initial          map[string]string
		initialTimestamp int
		// mac bindings to set
		set          map[string]string
		setTimestamp int
		// ports to set the mac bings for
		targets []string
		// expect port->ip->mac,timestamp.
		want map[string]map[string]wantData
	}{
		{
			name:         "creates a row that does not yet exist",
			set:          map[string]string{ip: secondMAC},
			setTimestamp: 200,
			targets:      []string{portA},
			want:         map[string]map[string]wantData{portA: {ip: {secondMAC, 200}}},
		},
		{
			name:             "refreshes an unchanged row's timestamp once past the cooldown",
			initial:          map[string]string{ip: firstMAC},
			initialTimestamp: 200,
			set:              map[string]string{ip: firstMAC},
			setTimestamp:     200 + ovnk_cooldown_period_ms,
			targets:          []string{portA},
			want:             map[string]map[string]wantData{portA: {ip: {firstMAC, 200 + ovnk_cooldown_period_ms}}},
		},
		{
			name:             "skips a timestamp refresh still within the cooldown",
			initial:          map[string]string{ip: firstMAC},
			initialTimestamp: 200,
			set:              map[string]string{ip: firstMAC},
			setTimestamp:     200 + ovnk_cooldown_period_ms - 1,
			targets:          []string{portA},
			want:             map[string]map[string]wantData{portA: {ip: {firstMAC, 200}}},
		},
		{
			name:             "writes a changed MAC even within the cooldown",
			initial:          map[string]string{ip: firstMAC},
			initialTimestamp: 200,
			set:              map[string]string{ip: secondMAC},
			setTimestamp:     200 + ovnk_cooldown_period_ms - 1,
			targets:          []string{portA},
			want:             map[string]map[string]wantData{portA: {ip: {secondMAC, 200 + ovnk_cooldown_period_ms - 1}}},
		},
		{
			name:         "mirrors every ip onto every port in one write",
			set:          map[string]string{ip: firstMAC, otherIP: otherMAC},
			setTimestamp: 200,
			targets:      []string{portA, portB},
			want: map[string]map[string]wantData{
				portA: {ip: {firstMAC, 200}, otherIP: {otherMAC, 200}},
				portB: {ip: {firstMAC, 200}, otherIP: {otherMAC, 200}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			// Seed any pre-existing rows through SBData rather than via
			// setMacBindings, so the update/cooldown path is exercised against a
			// precondition established independently of the method under test.
			// The seeded Datapath is never asserted; it just references the shared
			// datapath so the rows are well-formed.
			setup := libovsdbtest.TestSetup{
				IgnoreConstraints: true,
				SBData: []libovsdbtest.TestData{
					&sbdb.DatapathBinding{UUID: "tgt-dp"},
				},
			}
			for _, port := range tt.targets {
				for ip, mac := range tt.initial {
					setup.SBData = append(setup.SBData, &sbdb.MACBinding{
						LogicalPort: port,
						IP:          ip,
						MAC:         mac,
						Datapath:    "tgt-dp",
						Timestamp:   tt.initialTimestamp,
					})
				}
			}
			sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanup.Cleanup()

			// The production SB client monitors the full MAC_Binding table, so
			// written rows reach the cache without the test installing its own
			// monitor (a second overlapping MAC_Binding monitor would make the
			// cache inconsistent).

			// Resolve the real datapath UUID assigned by the server; all ports
			// share it.
			var dps []*sbdb.DatapathBinding
			g.Expect(sbClient.List(context.Background(), &dps)).To(gomega.Succeed())
			g.Expect(dps).To(gomega.HaveLen(1))
			dpUUID := dps[0].UUID
			portToDatapath := map[string]string{}
			for _, port := range tt.targets {
				portToDatapath[port] = dpUUID
			}

			c := newTestController()
			c.sbClient = sbClient

			// setMacBindings is synchronous: on return the cache already reflects
			// the write (or, for the cooldown-skip case, the lack of one).
			g.Expect(c.setMacBindings(tt.set, tt.setTimestamp, portToDatapath)).To(gomega.Succeed())

			for port, want := range tt.want {
				got := map[string]wantData{}
				for _, mb := range macBindingsFor(g, sbClient, port) {
					got[mb.IP] = wantData{mb.MAC, mb.Timestamp}
				}
				g.Expect(got).To(gomega.Equal(want))
			}
		})
	}
}

// --- allocation engine ---------------------------------------------------

// primaryUDN builds a primary Layer2 UDN NetInfo for allocation tests. A
// non-empty uplink is reported by NetInfo.Uplink() only when the uplink feature
// is enabled (see enableUplinkFeature), so callers exercising uplink groups must
// enable it first.
func primaryUDN(g gomega.Gomega, name, nadKey, uplink string) util.NetInfo {
	ni, err := util.NewNetInfo(&ovncnitypes.NetConf{
		NetConf:  cnitypes.NetConf{Name: name, Type: "ovn-k8s-cni-overlay"},
		Role:     types.NetworkRolePrimary,
		Topology: types.Layer2Topology,
		NADName:  nadKey,
		Subnets:  "192.168.0.0/16",
		MTU:      1400,
		Uplink:   uplink,
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	return ni
}

// enableUplinkFeature turns on the feature flags that userDefinedNetInfo.Uplink()
// gates on, so a NetInfo built with a non-empty NetConf.Uplink actually reports
// it. config.PrepareTestConfig resets these between tests.
func enableUplinkFeature() {
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableNetworkSegmentation = true
	config.OVNKubernetesFeature.EnableUplink = true
}

// TestReconcileNetworks drives the whole network-reconcile stack through its real
// entry point, reconcileNetwork: the NAD-event dispatch (already-tracked no-op,
// and the unknown-source full-reconcile fan-out) and, via the "" key, the
// all-networks gather + source-resolution + port-validation pipeline that feeds
// the allocation engine. It asserts the observable outcomes — the resulting
// follower/port state and the keys enqueued on the mac-binding and network
// reconcilers. The allocation engine's own relocation scenarios are covered in
// isolation by TestUpdateFollowers.
func TestReconcileNetworks(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	enableUplinkFeature()

	cdnPort := cdnPortFor("node1")

	// Default-group primary UDN (shares breth0, Uplink() == "").
	udn := primaryUDN(g, "tenantred", "ns1/nad1", "")
	udnPort := util.GetNetworkScopedGWRouterExtPortName(udn.GetNetworkName(), "node1")
	// Two CUDNs sharing a dedicated uplink; cudnA is the designated source.
	cudnA := primaryUDN(g, "cudnA", "nsA/nadA", "uplinkA")
	cudnB := primaryUDN(g, "cudnB", "nsB/nadB", "uplinkA")
	portA := util.GetNetworkScopedGWRouterExtPortName(cudnA.GetNetworkName(), "node1")
	portB := util.GetNetworkScopedGWRouterExtPortName(cudnB.GetNetworkName(), "node1")

	tests := []struct {
		name string
		// primaryNetworks are the networks the fake network manager tracks
		// (namespace -> NetInfo); the CDN is always gathered implicitly.
		primaryNetworks map[string]util.NetInfo
		// nadNetworks are resolved by NAD key (nadKey -> NetInfo); needed when
		// reconcileKey is a NAD namespaced name (the dispatch path).
		nadNetworks map[string]util.NetInfo
		// uplinkSources is what the uplink source provider designates
		// (uplink -> source GR external port).
		uplinkSources map[string]string
		// sbPorts are the GR external ports that have a PortBinding in the SB DB.
		sbPorts []string
		// preFollowers pre-registers source -> followers as already known.
		preFollowers map[string][]string
		// reconcileKey is handed to reconcileNetwork: "" reconciles all networks,
		// a NAD namespaced name exercises the event-routing dispatch.
		reconcileKey string
		// wantMbEnqueued is the set of keys enqueued on the mac-binding reconciler
		// for a catch-up.
		wantMbEnqueued []string
		// wantNetEnqueued is the set of keys re-enqueued on the network reconciler
		// (the dispatch early-outs enqueue "" for a full reconcile).
		wantNetEnqueued []string
		// wantTrackedPorts is the full set of tracked ports (sources + followers)
		// after the reconcile; nil skips the assertion.
		wantTrackedPorts []string
		// wantFollowers is the expected source -> followers after the reconcile
		// (only sources with followers need to be listed).
		wantFollowers map[string][]string
		// dirtyUplinkSource leaves the uplink->source cache invalidated (nil)
		// going into the reconcile, as ReconcileUplinkSource leaves it after a
		// re-designation. By default the cache is warmed first, modelling steady
		// state where the designation is already computed.
		dirtyUplinkSource bool
	}{
		{
			name:             "NAD event for an already-tracked network is a no-op",
			primaryNetworks:  map[string]util.NetInfo{"ns1": udn},
			nadNetworks:      map[string]util.NetInfo{"ns1/nad1": udn},
			sbPorts:          []string{cdnPort, udnPort},
			preFollowers:     map[string][]string{cdnPort: {udnPort}},
			reconcileKey:     "ns1/nad1",
			wantTrackedPorts: []string{cdnPort, udnPort},
			wantFollowers:    map[string][]string{cdnPort: {udnPort}},
		},
		{
			name:            "NAD event while a follower's source is unknown triggers a full reconcile",
			nadNetworks:     map[string]util.NetInfo{"ns1/nad1": udn},
			preFollowers:    map[string][]string{"unknown": {"rtoe-GR_other_node1"}},
			reconcileKey:    "ns1/nad1",
			wantNetEnqueued: []string{""},
		},
		{
			name:             "full reconcile mirrors the CDN onto a primary UDN follower",
			primaryNetworks:  map[string]util.NetInfo{"ns1": udn},
			sbPorts:          []string{cdnPort, udnPort},
			reconcileKey:     "",
			wantMbEnqueued:   []string{udnPort},
			wantTrackedPorts: []string{cdnPort, udnPort},
			wantFollowers:    map[string][]string{cdnPort: {udnPort}},
		},
		{
			name:             "full reconcile mirrors the designated uplink source onto the other member",
			primaryNetworks:  map[string]util.NetInfo{"nsA": cudnA, "nsB": cudnB},
			uplinkSources:    map[string]string{"uplinkA": portA},
			sbPorts:          []string{cdnPort, portA, portB},
			reconcileKey:     "",
			wantMbEnqueued:   []string{portB},
			wantTrackedPorts: []string{cdnPort, portA, portB},
			wantFollowers:    map[string][]string{portA: {portB}},
		},
		{
			// The trickiest allocation branch driven through the real path: the
			// uplink's designated source changes from portA to portB. This is the
			// state ReconcileUplinkSource leaves behind — the CDN already tracked,
			// portA still the old source of portB, and the uplink->source cache
			// invalidated (dirtyUplinkSource) so hasUnknownSource trips the skip
			// guard even though there is no membership change. The old source is
			// relocated as a follower under the new one. TestUpdateFollowers covers
			// the engine branches exhaustively; this proves the branch is wired end
			// to end.
			name:              "full reconcile relocates followers when the uplink source is re-designated",
			primaryNetworks:   map[string]util.NetInfo{"nsA": cudnA, "nsB": cudnB},
			uplinkSources:     map[string]string{"uplinkA": portB}, // portB newly designated
			sbPorts:           []string{cdnPort, portA, portB},
			preFollowers:      map[string][]string{cdnPort: {}, portA: {portB}},
			reconcileKey:      "",
			dirtyUplinkSource: true,
			wantMbEnqueued:    []string{portA}, // old source becomes a follower under portB
			wantTrackedPorts:  []string{cdnPort, portA, portB},
			wantFollowers:     map[string][]string{portB: {portA}},
		},
		{
			name:             "full reconcile skips a network whose port is absent from the SB",
			primaryNetworks:  map[string]util.NetInfo{"ns1": udn},
			sbPorts:          []string{cdnPort}, // udnPort has no PortBinding
			reconcileKey:     "",
			wantTrackedPorts: []string{cdnPort}, // only the CDN is realized
		},
		{
			name:             "full reconcile is a no-op when every gathered port is already tracked",
			primaryNetworks:  map[string]util.NetInfo{"ns1": udn},
			sbPorts:          []string{cdnPort, udnPort},
			preFollowers:     map[string][]string{cdnPort: {udnPort}},
			reconcileKey:     "",
			wantTrackedPorts: []string{cdnPort, udnPort},
			wantFollowers:    map[string][]string{cdnPort: {udnPort}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			setup := libovsdbtest.TestSetup{IgnoreConstraints: true}
			for i, port := range tt.sbPorts {
				dp := fmt.Sprintf("dp-%d", i)
				setup.SBData = append(setup.SBData,
					&sbdb.DatapathBinding{UUID: dp},
					&sbdb.PortBinding{UUID: fmt.Sprintf("pb-%d", i), LogicalPort: port, Datapath: dp},
				)
			}
			sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanup.Cleanup()

			mbRec, mbR := startRecorder(g, "mb")
			defer controller.Stop(mbR)
			netRec, netR := startRecorder(g, "network")
			defer controller.Stop(netR)

			// A non-nil (possibly empty) sources map is required: a nil map makes
			// the provider skip the default "" -> CDN mapping.
			sources := maps.Clone(tt.uplinkSources)
			if sources == nil {
				sources = map[string]string{}
			}

			c := newTestController()
			c.sbClient = sbClient
			c.networkManager = &networkmanager.FakeNetworkManager{
				PrimaryNetworks: tt.primaryNetworks,
				NADNetworks:     tt.nadNetworks,
			}
			c.cdnGatewayPort = cdnPort
			c.macBindingReconciler = mbR
			c.networkReconciler = netR
			c.uplinkSourceProvider = &fakeUplinkSourceProvider{sources: sources}
			for source, followers := range tt.preFollowers {
				c.followers[source] = sets.New(followers...)
			}
			if !tt.dirtyUplinkSource {
				// Steady state: the uplink->source designation is already computed
				// (warm cache), so only real membership changes or a non-empty
				// "unknown" bucket drive a full reconcile — not the dirty-cache signal.
				c.getMacBindingSourceForUplinks()
			}

			g.Expect(c.reconcileNetwork(tt.reconcileKey)).To(gomega.Succeed())

			// Keys enqueued on the mac-binding reconciler for a catch-up.
			if len(tt.wantMbEnqueued) == 0 {
				g.Consistently(mbRec.got).Should(gomega.BeEmpty())
			} else {
				g.Eventually(mbRec.got).Should(gomega.ConsistOf(tt.wantMbEnqueued))
			}
			// Keys re-enqueued on the network reconciler (dispatch early-outs).
			if len(tt.wantNetEnqueued) == 0 {
				g.Consistently(netRec.got).Should(gomega.BeEmpty())
			} else {
				g.Eventually(netRec.got).Should(gomega.ConsistOf(tt.wantNetEnqueued))
			}

			// Resulting follower/port state.
			for source, followers := range tt.wantFollowers {
				g.Expect(c.getFollowers(source)).To(gomega.ConsistOf(followers))
			}
			if tt.wantTrackedPorts != nil {
				g.Expect(c.getAllPorts().UnsortedList()).To(gomega.ConsistOf(tt.wantTrackedPorts))
			}
		})
	}
}

// TestUpdateFollowers exercises the in-memory follower allocation engine
// directly: given a starting followers/ports state and a set of port additions,
// removals and the resolved uplink/source topology, it asserts the recomputed
// follower map and the set of ports that became new followers (which the caller
// enqueues for a mac binding catch-up).
func TestUpdateFollowers(t *testing.T) {
	cdnPort := cdnPortFor("node1")
	const (
		udnPort   = "rtoe-GR_tenantred_node1"
		oldSource = "rtoe-GR_cudnA_node1"
		newSource = "rtoe-GR_cudnB_node1"
	)

	tests := []struct {
		name string
		// starting controller state
		followers map[string][]string // source -> followers

		// updateFollowers arguments
		addPorts       []string
		removePorts    []string
		portToUplink   map[string]string
		uplinkToSource map[string]string

		// expectations
		wantNewFollowers []string
		wantFollowers    map[string][]string // source -> expected followers
		wantTrackedPorts []string            // ports expected to remain tracked
	}{
		{
			// A follower whose port disappeared is dropped, and its now-empty
			// source is removed.
			name:           "removes a dropped follower and prunes its empty source",
			followers:      map[string][]string{cdnPort: {udnPort}},
			removePorts:    []string{udnPort},
			portToUplink:   map[string]string{cdnPort: ""},
			uplinkToSource: map[string]string{"": cdnPort},
			wantFollowers:  map[string][]string{cdnPort: nil},
		},
		{
			// A port on an uplink with no known source is parked in the
			// "unknown" bucket rather than dropped, and is still tracked.
			name:             "parks a port with no known source as unknown",
			addPorts:         []string{udnPort},
			portToUplink:     map[string]string{udnPort: "uplinkA"}, // uplinkA has no source
			uplinkToSource:   map[string]string{"": cdnPort},        // only default group
			wantFollowers:    map[string][]string{"unknown": {udnPort}},
			wantTrackedPorts: []string{udnPort},
		},
		{
			// When the designated source of an uplink group changes, the old
			// source's followers are relocated under the new source and the old
			// source itself becomes a follower.
			name:             "relocates followers when the source is re-designated",
			followers:        map[string][]string{oldSource: {newSource}},
			portToUplink:     map[string]string{oldSource: "uplinkA", newSource: "uplinkA"},
			uplinkToSource:   map[string]string{"uplinkA": newSource, "": cdnPort},
			wantNewFollowers: []string{oldSource},
			wantFollowers: map[string][]string{
				newSource: {oldSource},
				oldSource: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			c := newTestController()
			c.cdnGatewayPort = cdnPort
			for source, followers := range tt.followers {
				c.followers[source] = sets.New(followers...)
			}

			newFollowers := c.updateFollowers(
				sets.New(tt.addPorts...),
				sets.New(tt.removePorts...),
				tt.portToUplink,
				tt.uplinkToSource,
			)

			g.Expect(newFollowers.UnsortedList()).To(gomega.ConsistOf(tt.wantNewFollowers))
			for source, want := range tt.wantFollowers {
				g.Expect(c.getFollowers(source)).To(gomega.ConsistOf(want))
			}

			for _, port := range tt.wantTrackedPorts {
				g.Expect(c.getAllPorts().Has(port)).To(gomega.BeTrue())
			}
		})
	}
}

// TestReconcileUplinkSource verifies how a re-designation notification is
// handled: when the notified network is not already a source with followers it
// invalidates the cached uplink->source designation — which both makes a full
// reconcile due (hasUnknownSource) and forces the next read to re-fetch — and
// enqueues the network so the group is recomputed; when it is already the
// designated source it is a no-op.
func TestReconcileUplinkSource(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

	const network = "tenantred"
	port := util.GetNetworkScopedGWRouterExtPortName(network, "node1")
	staleCache := map[string]string{"uplinkA": "rtoe-GR_stale_node1"}

	newController := func(netR controller.Reconciler) *MACBindingController {
		c := newTestController()
		c.cdnGatewayPort = cdnPortFor("node1")
		c.networkReconciler = netR
		c.uplinkSourceProvider = &fakeUplinkSourceProvider{sources: map[string]string{"uplinkB": "rtoe-GR_other_node1"}}
		// prime the cache with a stale designation so we can observe whether it
		// is reset.
		c.setMacBindingSourceForUplinks(maps.Clone(staleCache))
		return c
	}

	t.Run("re-designation invalidates the cache and enqueues a recompute", func(t *testing.T) {
		g := gomega.NewWithT(t)
		netRec, netR := startRecorder(g, "network")
		defer controller.Stop(netR)

		c := newController(netR)

		c.ReconcileUplinkSource(network)

		// The cache was invalidated, so a full reconcile is now due...
		g.Expect(c.hasUnknownSource()).To(gomega.BeTrue())
		// ...the network is enqueued for recompute...
		g.Eventually(netRec.got).Should(gomega.ConsistOf(network))
		// ...and the next read re-fetches the provider's current sources (with the
		// CDN injected) instead of the stale value.
		g.Expect(c.getMacBindingSourceForUplinks()).To(gomega.Equal(
			map[string]string{"uplinkB": "rtoe-GR_other_node1", "": cdnPortFor("node1")},
		))
	})

	t.Run("a network already designated as a source is a no-op", func(t *testing.T) {
		g := gomega.NewWithT(t)
		netRec, netR := startRecorder(g, "network")
		defer controller.Stop(netR)

		c := newController(netR)
		// the network's port is already the designated source of a follower.
		c.followers[port] = sets.New("rtoe-GR_follower_node1")

		c.ReconcileUplinkSource(network)

		// Nothing is enqueued and the cache is left intact: the next read still
		// returns the primed (stale) designation, not a re-fetch of the provider.
		g.Consistently(netRec.got, "200ms", "50ms").Should(gomega.BeEmpty())
		g.Expect(c.getMacBindingSourceForUplinks()).To(gomega.Equal(
			map[string]string{"uplinkA": "rtoe-GR_stale_node1", "": cdnPortFor("node1")},
		))
	})
}

// TestGetMacBindingSourceForUplinks verifies the memoized view of the provider's
// uplink sources: a cold cache fetches from the provider and injects the CDN
// source under the "" uplink; a warm cache is returned without re-consulting the
// provider; and invalidation (setMacBindingSourceForUplinks(nil)) forces the next
// read to re-fetch. It observes only through the getter and a mutable fake
// provider, so it does not depend on how the cache is stored.
func TestGetMacBindingSourceForUplinks(t *testing.T) {
	const cdn = "rtoe-GR_node1"

	newController := func() (*MACBindingController, *fakeUplinkSourceProvider) {
		c := newTestController()
		c.cdnGatewayPort = cdn
		fake := &fakeUplinkSourceProvider{sources: map[string]string{"uplinkA": "rtoe-GR_cudnA_node1"}}
		c.uplinkSourceProvider = fake
		return c, fake
	}
	// what the getter returns for the initial provider sources, with the CDN
	// injected under the default ("") uplink.
	withCDN := map[string]string{"uplinkA": "rtoe-GR_cudnA_node1", "": cdn}

	t.Run("cold cache fetches from the provider and injects the CDN source", func(t *testing.T) {
		g := gomega.NewWithT(t)
		c, _ := newController()

		g.Expect(c.getMacBindingSourceForUplinks()).To(gomega.Equal(withCDN))
	})

	t.Run("warm cache is returned without re-consulting the provider", func(t *testing.T) {
		g := gomega.NewWithT(t)
		c, fake := newController()

		// prime the cache, then change what the provider would return.
		_ = c.getMacBindingSourceForUplinks()
		fake.sources = map[string]string{"uplinkB": "rtoe-GR_cudnB_node1"}

		g.Expect(c.getMacBindingSourceForUplinks()).To(gomega.Equal(withCDN))
	})

	t.Run("invalidation forces the next read to re-fetch", func(t *testing.T) {
		g := gomega.NewWithT(t)
		c, fake := newController()

		// warm the cache, invalidate it, then change the provider's sources.
		_ = c.getMacBindingSourceForUplinks()
		c.setMacBindingSourceForUplinks(nil)
		fake.sources = map[string]string{"uplinkB": "rtoe-GR_cudnB_node1"}

		g.Expect(c.getMacBindingSourceForUplinks()).To(gomega.Equal(
			map[string]string{"uplinkB": "rtoe-GR_cudnB_node1", "": cdn},
		))
	})
}

// --- south-bound event handlers -----------------------------------------

// TestRegisterSouthBoundEventHandlers verifies the SB cache event handlers
// translate row changes into the right reconcile enqueues.
func TestRegisterSouthBoundEventHandlers(t *testing.T) {
	g := gomega.NewWithT(t)

	cdnPort := cdnPortFor("node1")
	udnPort := "rtoe-GR_tenantred_node1"

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "cdn-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "cdn-dp"},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	networkRec, networkR := startRecorder(g, "network")
	defer controller.Stop(networkR)
	mbRec, mbR := startRecorder(g, "mb")
	defer controller.Stop(mbR)
	refreshRec, refreshR := startRecorder(g, "refresh")
	defer controller.Stop(refreshR)
	c := newTestController()
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.networkReconciler = networkR
	c.macBindingReconciler = mbR
	c.macBindingRefreshReconciler = refreshR
	// track the CDN as a source so its MAC_Binding events are relevant.
	c.followers[cdnPort] = sets.New(udnPort)

	c.registerSouthBoundEventHandlers()

	// A PortBinding for a primary L2 GR external port enqueues its network.
	// ContainElement (not ConsistOf) because the seeded CDN gateway PortBinding's
	// own add event legitimately enqueues a full re-eval ("") via
	// enqueueAllNetworks, and that arrives asynchronously.
	createRow(g, sbClient, &sbdb.PortBinding{
		LogicalPort: udnPort,
		ExternalIDs: map[string]string{
			types.NetworkExternalID:  "tenantred",
			types.TopologyExternalID: types.Layer2Topology,
		},
	})
	g.Eventually(networkRec.got).Should(gomega.ContainElement("tenantred"))

	// A new MAC_Binding on the tracked CDN source enqueues designated|ip on the
	// mac-binding reconciler (a MAC not previously mirrored).
	createRow(g, sbClient, &sbdb.MACBinding{
		LogicalPort: cdnPort,
		IP:          "10.0.0.5",
		MAC:         "0a:00:00:00:00:05",
	})
	g.Eventually(mbRec.got).Should(gomega.ConsistOf(cdnPort + keySep + "10.0.0.5"))

	// Bumping only the timestamp (MAC unchanged) is a refresh: it enqueues
	// designated|ip on the refresh reconciler instead.
	mb := &sbdb.MACBinding{LogicalPort: cdnPort, IP: "10.0.0.5"}
	g.Expect(sbClient.Get(context.Background(), mb)).To(gomega.Succeed())
	mb.Timestamp = 100
	updOps, err := sbClient.Where(mb).Update(mb, &mb.Timestamp)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = ops.TransactAndCheck(sbClient, updOps)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Eventually(refreshRec.got).Should(gomega.ConsistOf(cdnPort + keySep + "10.0.0.5"))

	// A primary network's PortBinding delete re-enqueues its network so the
	// follower set is recomputed.
	pbDelOps, err := sbClient.WhereCache(func(pb *sbdb.PortBinding) bool {
		return pb.LogicalPort == udnPort
	}).Delete()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = ops.TransactAndCheck(sbClient, pbDelOps)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Eventually(func() int {
		n := 0
		for _, k := range networkRec.got() {
			if k == "tenantred" {
				n++
			}
		}
		return n
	}).Should(gomega.BeNumerically(">=", 2))
}

// TestRegisterSouthBoundEventHandlersIgnores verifies the event handlers filter
// out rows the controller does not care about: MAC bindings for a disabled IP
// family or an untracked source, and port bindings that are not tracked Gateway
// Router external ports.
func TestRegisterSouthBoundEventHandlersIgnores(t *testing.T) {
	g := gomega.NewWithT(t)

	const trackedSource = "rtoe-GR_tracked_node1"

	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(libovsdbtest.TestSetup{IgnoreConstraints: true}, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	networkRec, networkR := startRecorder(g, "network")
	defer controller.Stop(networkR)
	mbRec, mbR := startRecorder(g, "mb")
	defer controller.Stop(mbR)
	refreshRec, refreshR := startRecorder(g, "refresh")
	defer controller.Stop(refreshR)

	c := newTestController() // ipv4 enabled, ipv6 disabled
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPortFor("node1")
	c.networkReconciler = networkR
	c.macBindingReconciler = mbR
	c.macBindingRefreshReconciler = refreshR
	c.followers[trackedSource] = sets.New("rtoe-GR_follower_node1")

	c.registerSouthBoundEventHandlers()

	tests := []struct {
		name string
		row  model.Model
	}{
		{
			name: "MAC_Binding on an untracked source",
			row:  &sbdb.MACBinding{LogicalPort: "rtoe-GR_untracked_node1", IP: "10.0.0.5", MAC: "0a:00:00:00:00:05"},
		},
		{
			name: "MAC_Binding for a disabled IP family",
			row:  &sbdb.MACBinding{LogicalPort: trackedSource, IP: "fd00::5", MAC: "0a:00:00:00:00:06"},
		},
		{
			name: "PortBinding without the GR external port prefix",
			row: &sbdb.PortBinding{
				LogicalPort: "sw-port",
				TunnelKey:   1,
				ExternalIDs: map[string]string{
					types.NetworkExternalID:  "tenantred",
					types.TopologyExternalID: types.Layer2Topology,
				},
			},
		},
		{
			name: "PortBinding with a non-L2/L3 topology",
			row: &sbdb.PortBinding{
				LogicalPort: "rtoe-GR_localnet_node1",
				TunnelKey:   2,
				ExternalIDs: map[string]string{
					types.NetworkExternalID:  "localnetnet",
					types.TopologyExternalID: "localnet",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			createRow(g, sbClient, tt.row)
			// no reconcile of any kind is enqueued for an ignored row.
			g.Consistently(func(g gomega.Gomega) {
				g.Expect(networkRec.got()).To(gomega.BeEmpty())
				g.Expect(mbRec.got()).To(gomega.BeEmpty())
				g.Expect(refreshRec.got()).To(gomega.BeEmpty())
			}, "200ms", "50ms").Should(gomega.Succeed())
		})
	}
}

// --- small helpers -------------------------------------------------------

// macBindingsFor returns the MAC_Binding rows mirrored onto a logical port,
// read from the SB client cache.
func macBindingsFor(g gomega.Gomega, sbClient libovsdbclient.Client, port string) []*sbdb.MACBinding {
	var all []*sbdb.MACBinding
	g.Expect(sbClient.List(context.Background(), &all)).To(gomega.Succeed())
	var out []*sbdb.MACBinding
	for _, mb := range all {
		if mb.LogicalPort == port {
			out = append(out, mb)
		}
	}
	return out
}

// createRow inserts a single row into the SB database.
func createRow(g gomega.Gomega, sbClient libovsdbclient.Client, m model.Model) {
	createOps, err := sbClient.Create(m)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = ops.TransactAndCheck(sbClient, createOps)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
