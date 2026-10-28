// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package clustermanager

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	egressipv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipfake "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/kube"
)

// BenchmarkCheckEgressNodesReachabilityIterate isolates the per-tick CPU cost of
// the cluster-manager EgressIP health-check loop
// (checkEgressNodesReachabilityIterate), which runs every
// egressIPReachabilityCheckInterval (5s) in production.
//
// It exists to answer the OKEP-6800 scale question: with egressNodeSelector, the
// loop now compiles every EgressIP's selector (O(EIPs)) and matches every node
// against them (O(nodes*EIPs)) on each tick, on top of the reachability probe.
// The network probe dominates wall-clock on a real cluster and is unchanged for
// the default selector, so it is faked out here (fakeEgressIPHealthClient probes
// return instantly) to expose only the added selector-handling CPU and
// allocations.
//
// Run and compare master vs PR with benchstat:
//
//	go test ./pkg/clustermanager/ -run=NONE \
//	  -bench=BenchmarkCheckEgressNodesReachabilityIterate -benchmem -benchtime=200x
//
// On the master tree the function has no compile/match step, so the delta
// reported by benchstat is exactly the cost this feature adds per tick.
//
// Matrix mirrors the perf test plan (openshift/testplans): nodes {50,120,250}
// against EIP counts {0,10,50,100,250}, where 120 nodes / 250 EIP objects is the
// supported maximum. "custom" selectors are the worst case (non-matching nodes
// evaluate all selectors); "default" uses the legacy egress-assignable selector
// (probe set identical to master) for the backward-compatibility comparison.
func BenchmarkCheckEgressNodesReachabilityIterate(b *testing.B) {
	for _, useDefault := range []bool{false, true} {
		selKind := "custom"
		if useDefault {
			selKind = "default"
		}
		for _, nodes := range []int{50, 120, 250} {
			for _, eips := range []int{0, 10, 50, 100, 250} {
				b.Run(fmt.Sprintf("sel=%s/nodes=%d/eips=%d", selKind, nodes, eips), func(b *testing.B) {
					eIPC := newBenchController(b, nodes, eips, useDefault)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						checkEgressNodesReachabilityIterate(eIPC)
					}
				})
			}
		}
	}
}

// egressAssignableLabel is the legacy label the default egressNodeSelector matches.
const egressAssignableLabel = "k8s.ovn.org/egress-assignable"

// newBenchController builds a minimal egressIPClusterController wired for the
// health-check loop only: a fake EgressIP clientset holding numEIPs objects, and
// an allocator cache of numNodes nodes. A fixed fraction of nodes (capped at 50,
// matching the plan's egress-assignable node count) carry the labels that make
// them egress candidates; the rest are non-matching and exercise the
// worst-case "evaluate every selector then Disconnect" path.
//
// Health probes are faked (gRPC path with fakeEgressIPHealthClient), so each
// iteration measures selector compilation + matching + the no-op probe, not real
// network latency. No retry framework, watch factory, or metrics registry is
// needed because every node starts and stays reachable, so no reachability
// transition (and thus no deleteEgressNode / retry path) is triggered.
func newBenchController(b *testing.B, numNodes, numEIPs int, useDefaultSelector bool) *egressIPClusterController {
	b.Helper()

	// Route health checks through the in-package fakes (defined in
	// egressip_controller_test.go). These globals are only read by the loop; the
	// benchmark is the sole running goroutine touching them.
	hccAllocator = &fakeEgressIPHealthClientAllocator{}
	dialer = fakeEgressIPDialer{}

	const maxEgressNodes = 50
	numEgressNodes := min(numNodes, maxEgressNodes)

	// Build the EgressIP objects. With custom selectors each object matches on a
	// per-pool label so a non-matching node must test every selector before
	// giving up (the O(nodes*EIPs) worst case). With the default selector every
	// object matches the legacy egress-assignable label, reproducing today's
	// probe set.
	eipObjs := make([]runtimeEIP, 0, numEIPs)
	for i := range numEIPs {
		var sel *metav1.LabelSelector
		if useDefaultSelector {
			sel = defaultEgressNodeSelectorSpec
		} else {
			sel = &metav1.LabelSelector{MatchLabels: map[string]string{"egress-pool": fmt.Sprintf("pool-%d", i)}}
		}
		eipObjs = append(eipObjs, &egressipv1.EgressIP{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("eip-%d", i)},
			Spec:       egressipv1.EgressIPSpec{EgressNodeSelector: sel},
		})
	}

	eIPC := &egressIPClusterController{
		kube:                        &kube.KubeOVN{EIPClient: egressipfake.NewSimpleClientset(toObjects(eipObjs)...)},
		nodeAllocator:               nodeAllocator{&sync.Mutex{}, make(map[string]*egressNode, numNodes)},
		egressIPTotalTimeout:        1,
		egressIPNodeHealthCheckPort: 9107, // non-zero => gRPC path => uses the fake health client
		reachabilityCheckInterval:   time.Hour,
	}

	for i := range numNodes {
		name := fmt.Sprintf("node-%d", i)
		nodeLabels := labels.Set{}
		if i < numEgressNodes {
			nodeLabels[egressAssignableLabel] = ""
			// pool-0 so the first custom selector matches; matching nodes
			// short-circuit matchesAnyEgressIPSelector, as in production.
			nodeLabels["egress-pool"] = "pool-0"
		}
		eIPC.nodeAllocator.cache[name] = &egressNode{
			name:               name,
			mgmtIPs:            []net.IP{net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/256, i%256))},
			allocations:        map[string]string{},
			healthClient:       hccAllocator.allocate(name),
			labels:             nodeLabels,
			isReady:            true,
			isReachable:        true,
			isEgressAssignable: true,
		}
	}
	return eIPC
}

// runtimeEIP and toObjects adapt typed EgressIPs to the variadic runtime.Object
// slice NewSimpleClientset expects, keeping the construction above readable.
type runtimeEIP = *egressipv1.EgressIP

func toObjects(eips []runtimeEIP) []runtime.Object {
	objs := make([]runtime.Object, len(eips))
	for i := range eips {
		objs[i] = eips[i]
	}
	return objs
}
