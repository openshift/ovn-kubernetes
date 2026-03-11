package ovn

import nodecontroller "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/ovn/controller/node"

// NodeReconciler queues node keys for reconciliation.
// Used by UDN controllers to requeue node work without per-network node watchers.
type NodeReconciler interface {
	Reconcile(key string)
	RegisterNetworkController(handler nodecontroller.NodeHandler)
	DeregisterNetworkController(netName string)
}
