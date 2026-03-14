package clustermanager

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	sharednode "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/ovn/controller/node"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/syncmap"
)

type fakeClusterManagerNodeHandler struct {
	netName   string
	syncErr   error
	syncCalls int
}

func (f *fakeClusterManagerNodeHandler) GetNetworkName() string {
	return f.netName
}

func (f *fakeClusterManagerNodeHandler) ReconcileNode(_, _ *corev1.Node, _, _ *sharednode.NodeAnnotationState) error {
	return nil
}

func (f *fakeClusterManagerNodeHandler) SyncNodes(_ []*corev1.Node) error {
	f.syncCalls++
	return f.syncErr
}

func newClusterManagerNodeLister(t *testing.T, nodes ...*corev1.Node) corelisters.NodeLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, node := range nodes {
		if err := indexer.Add(node); err != nil {
			t.Fatalf("failed to add node to indexer: %v", err)
		}
	}
	return corelisters.NewNodeLister(indexer)
}

func newClusterManagerNodeControllerForTest(threadiness int) controller.Controller {
	return controller.NewController("clustermanager-node-test", &controller.ControllerConfig[corev1.Node]{
		RateLimiter: workqueue.DefaultTypedControllerRateLimiter[string](),
		Reconcile:   func(string) error { return nil },
		Threadiness: threadiness,
		Lister:      func(labels.Selector) ([]*corev1.Node, error) { return nil, nil },
		ObjNeedsUpdate: func(_, _ *corev1.Node) bool {
			return true
		},
	})
}

func TestRegisterNetworkControllerBootstrapFailureRollsBackHandler(t *testing.T) {
	handler := &fakeClusterManagerNodeHandler{
		netName: "net-a",
		syncErr: errors.New("sync failed"),
	}
	c := &clusterManagerNodeController{
		name:            "clustermanager-node-test",
		nodeController:  newClusterManagerNodeControllerForTest(1),
		nodeLister:      newClusterManagerNodeLister(t, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}),
		handlers:        syncmap.NewSyncMap[clusterManagerNodeHandler](),
		bootstrapNodes:  map[string]map[string]struct{}{},
		annotationCache: sharednode.NewNodeAnnotationCache(),
	}

	err := c.RegisterNetworkController(handler)
	if err == nil {
		t.Fatal("expected bootstrap failure to be returned")
	}
	if handler.syncCalls != 1 {
		t.Fatalf("expected one bootstrap attempt, got %d SyncNodes calls", handler.syncCalls)
	}
	if got, ok := c.handlers.Load(handler.netName); ok || got != nil {
		t.Fatalf("expected failed bootstrap to roll back handler registration for %q", handler.netName)
	}
}
