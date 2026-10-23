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
	"k8s.io/apimachinery/pkg/runtime"

	egressipv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipfake "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/kube"
)

// BenchmarkCheckEgressNodesReachabilityIterate — MASTER BASELINE VARIANT.
//
// This is the master-API-compatible version of the benchmark introduced with the
// egressNodeSelector feature. On master the health-check loop
// (checkEgressNodesReachabilityIterate) is O(nodes): it probes every node with
// isEgressAssignable && isReady and does NOT list EgressIPs or match selectors.
// There is therefore no selector to sweep and no egressNodeSelector field; both the
// `sel` and `eips` dimensions below are no-ops for the loop and are retained ONLY so
// the sub-benchmark names match the feature-branch benchmark exactly, letting
// benchstat pair them. The flat cost across `eips` is itself the point: master's
// poll cost is independent of EgressIP count, whereas the feature adds an
// O(nodes*EIPs) term.
//
// Probes are faked (gRPC path with fakeEgressIPHealthClient), so ns/op is the
// loop's pure CPU cost. Run and diff against the feature branch with benchstat:
//
//	go test ./pkg/clustermanager/ -run=NONE \
//	  -bench=BenchmarkCheckEgressNodesReachabilityIterate -benchmem -benchtime=200x
func BenchmarkCheckEgressNodesReachabilityIterate(b *testing.B) {
	for _, useDefault := range []bool{false, true} {
		selKind := "custom"
		if useDefault {
			selKind = "default"
		}
		for _, nodes := range []int{50, 120, 250} {
			for _, eips := range []int{0, 10, 50, 100, 250} {
				b.Run(fmt.Sprintf("sel=%s/nodes=%d/eips=%d", selKind, nodes, eips), func(b *testing.B) {
					eIPC := newBenchController(b, nodes, eips)
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

// newBenchController builds a minimal egressIPClusterController wired for the
// health-check loop only. On master the loop gates purely on isEgressAssignable &&
// isReady, so the first numEgressNodes nodes (capped at 50, matching the feature
// benchmark's egress-assignable node count) are made assignable and the rest are
// not — giving master the same probe set the feature benchmark probes. The EgressIP
// objects are created (without any selector — master's EgressIPSpec has none) but are
// never read by the master loop; they exist only to keep setup symmetric.
//
// Health probes are faked, and every node starts and stays reachable, so no
// reachability transition (and thus no deleteEgressNode / retry path) is triggered —
// no retry framework, watch factory, or metrics registry is needed.
func newBenchController(b *testing.B, numNodes, numEIPs int) *egressIPClusterController {
	b.Helper()

	// Route health checks through the in-package fakes (egressip_controller_test.go).
	hccAllocator = &fakeEgressIPHealthClientAllocator{}
	dialer = fakeEgressIPDialer{}

	const maxEgressNodes = 50
	numEgressNodes := min(numNodes, maxEgressNodes)

	eipObjs := make([]runtimeEIP, 0, numEIPs)
	for i := range numEIPs {
		eipObjs = append(eipObjs, &egressipv1.EgressIP{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("eip-%d", i)},
			Spec:       egressipv1.EgressIPSpec{},
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
		eIPC.nodeAllocator.cache[name] = &egressNode{
			name:               name,
			mgmtIPs:            []net.IP{net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/256, i%256))},
			allocations:        map[string]string{},
			healthClient:       hccAllocator.allocate(name),
			isReady:            true,
			isReachable:        true,
			isEgressAssignable: i < numEgressNodes, // master probes assignable+ready nodes only
		}
	}
	return eIPC
}

// runtimeEIP and toObjects adapt typed EgressIPs to the variadic runtime.Object
// slice NewSimpleClientset expects.
type runtimeEIP = *egressipv1.EgressIP

func toObjects(eips []runtimeEIP) []runtime.Object {
	objs := make([]runtime.Object, len(eips))
	for i := range eips {
		objs[i] = eips[i]
	}
	return objs
}
