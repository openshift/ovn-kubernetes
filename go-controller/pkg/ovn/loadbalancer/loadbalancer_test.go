package loadbalancer

import (
	"fmt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"testing"

	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
)

func TestEnsureLBs(t *testing.T) {
	nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{}, nil)
	if err != nil {
		t.Fatalf("Error creating NB: %v", err)
	}
	t.Cleanup(cleanup.Cleanup)
	lbCache, err := GetLBCache(nbClient)
	if err != nil {
		t.Fatalf("Error creating LB Cache: %v", err)
	}
	name := "foo"
	namespace := "testns"
	defaultExternalIDs := map[string]string{
		"k8s.ovn.org/kind":  "Service",
		"k8s.ovn.org/owner": fmt.Sprintf("%s/%s", namespace, name),
	}
	// put stale lb in the cache
	staleLBs := []LB{
		{
			Name:        "Service_testns/foo_TCP_node_router_node-a",
			ExternalIDs: defaultExternalIDs,
			Routers:     []string{"gr-node-a", "non-exisitng-router"},
			Switches:    []string{"non-exisitng-switch"},
			Groups:      []string{"non-existing-group"},
			Protocol:    "TCP",
			Rules: []LBRule{
				{
					Source:  Addr{"1.2.3.4", 80},
					Targets: []Addr{{"169.254.169.2", 8080}},
				},
			},
			UUID: libovsdbops.BuildNamedUUID(),
		},
	}
	lbCache.update(staleLBs, nil)
	// required lb doesn't have stale router, switch, and lb group reference.
	// "gr-node-a" is listed as applied in the cache, no update operation will be generated for it.
	LBs := []LB{
		{
			Name:        "Service_testns/foo_TCP_node_router_node-a",
			ExternalIDs: defaultExternalIDs,
			Routers:     []string{"gr-node-a"},
			Protocol:    "TCP",
			Rules: []LBRule{
				{
					Source:  Addr{"1.2.3.4", 80},
					Targets: []Addr{{"169.254.169.2", 8080}},
				},
			},
		},
	}

	err = EnsureLBs(nbClient, defaultExternalIDs, LBs)
	if err != nil {
		t.Fatalf("Error EnsureLBs: %v", err)
	}
}
