package libovsdbops

import (
	"context"
	"time"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

// CreateOrUpdateLoadBalancerGroup creates or updates the provided load balancer
// group
func CreateOrUpdateLoadBalancerGroup(nbClient libovsdbclient.Client, group *nbdb.LoadBalancerGroup) error {
	opModel := operationModel{
		Model:          group,
		OnModelUpdates: onModelUpdatesAll(),
		ErrNotFound:    false,
		BulkOp:         false,
	}

	m := newModelClient(nbClient)
	_, err := m.CreateOrUpdate(opModel)
	return err
}

// AddLoadBalancersToGroupOps adds the provided load balancers to the provided
// group and returns the corresponding ops
func AddLoadBalancersToGroupOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, group *nbdb.LoadBalancerGroup, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished AddLoadBalancersToGroupOps: %v", time.Since(startTime))
	}()
	originalLBs := group.LoadBalancer
	group.LoadBalancer = make([]string, 0, len(lbs))
	for _, lb := range lbs {
		group.LoadBalancer = append(group.LoadBalancer, lb.UUID)
	}
	opModel := operationModel{
		Model:            group,
		ModelPredicate:   func(item *nbdb.LoadBalancerGroup) bool { return item.Name == group.Name },
		OnModelMutations: []interface{}{&group.LoadBalancer},
		ErrNotFound:      true,
		BulkOp:           false,
	}

	m := newModelClient(nbClient)
	ops, err := m.CreateOrUpdateOps(ops, opModel)
	group.LoadBalancer = originalLBs
	return ops, err
}

// RemoveLoadBalancersFromGroupOps removes the provided load balancers from the
// provided group and returns the corresponding ops
func RemoveLoadBalancersFromGroupOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, group *nbdb.LoadBalancerGroup, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished RemoveLoadBalancersFromGroupOps: %v", time.Since(startTime))
	}()
	originalLBs := group.LoadBalancer
	group.LoadBalancer = make([]string, 0, len(lbs))
	for _, lb := range lbs {
		group.LoadBalancer = append(group.LoadBalancer, lb.UUID)
	}
	opModel := operationModel{
		Model:            group,
		ModelPredicate:   func(item *nbdb.LoadBalancerGroup) bool { return item.Name == group.Name },
		OnModelMutations: []interface{}{&group.LoadBalancer},
		ErrNotFound:      true,
		BulkOp:           false,
	}

	m := newModelClient(nbClient)
	ops, err := m.DeleteOps(ops, opModel)
	group.LoadBalancer = originalLBs
	return ops, err
}

type loadBalancerGroupPredicate func(*nbdb.LoadBalancerGroup) bool

// FindLoadBalancerGroupsWithPredicate looks up load balancer groups from the
// cache based on a given predicate
func FindLoadBalancerGroupsWithPredicate(nbClient libovsdbclient.Client, p loadBalancerGroupPredicate) ([]*nbdb.LoadBalancerGroup, error) {
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	groups := []*nbdb.LoadBalancerGroup{}
	err := nbClient.WhereCache(p).List(ctx, &groups)
	return groups, err
}
