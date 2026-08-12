// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	egressfirewallapi "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallapply "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/applyconfiguration/egressfirewall/v1"
	egressfirewallfake "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
)

// TestCRDFakeClientSupportsServerSideApply verifies that the generated CRD fake
// clientset (NewClientset) performs real server-side apply.
// Using a random CRD (EgressFirewall) here and hoping all the other clients behave the same way.
func TestCRDFakeClientSupportsServerSideApply(t *testing.T) {
	ns, name := "ns1", "default"
	// Seed the object with an existing message (as if written by zone1).
	ef := &egressfirewallapi.EgressFirewall{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status:     egressfirewallapi.EgressFirewallStatus{Messages: []string{"zone1: ok"}},
	}
	// to manually check the difference, use NewSimpleClientset here and see the test failing.
	efClient := egressfirewallfake.NewClientset(ef).K8sV1().EgressFirewalls(ns)

	// zone2 applies only its own message; SSA must merge it into the listType=set
	// status.messages rather than replacing existing message.
	ac := egressfirewallapply.EgressFirewall(name, ns).
		WithStatus(egressfirewallapply.EgressFirewallStatus().WithMessages("zone2: ok"))
	var err error
	if ef, err = efClient.ApplyStatus(context.Background(), ac,
		metav1.ApplyOptions{FieldManager: "zone2", Force: true}); err != nil {
		t.Fatalf("ApplyStatus(zone2): %v", err)
	}

	if msgs := sets.New(ef.Status.Messages...); !msgs.Has("zone1: ok") || !msgs.Has("zone2: ok") {
		t.Fatalf("expected SSA to merge zone2's message with the existing one, got %v", msgs.UnsortedList())
	}
}
