package clustermanager

import (
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/factory"
	sharednode "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/ovn/controller/node"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/syncmap"
	utilerrors "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util/errors"
)

type clusterManagerNodeHandler interface {
	GetNetworkName() string
	ReconcileNode(oldNode, newNode *corev1.Node, oldState, newState *sharednode.NodeAnnotationState) error
	SyncNodes(nodes []*corev1.Node) error
}

type clusterManagerNodeController struct {
	name string

	nodeController controller.Controller
	nodeLister     listers.NodeLister

	handlers *syncmap.SyncMap[clusterManagerNodeHandler]

	stateMu        sync.RWMutex
	bootstrapNodes map[string]map[string]struct{}

	nodeCache       clusterManagerNodeCache
	annotationCache *sharednode.NodeAnnotationCache

	startMu sync.Mutex
	started bool
}

const clusterManagerScopedNodeQueueKeySeparator = "|"

func newClusterManagerNodeController(wf *factory.WatchFactory) *clusterManagerNodeController {
	nodeInformer := wf.NodeCoreInformer()
	c := &clusterManagerNodeController{
		name:            "clustermanager-node",
		nodeLister:      nodeInformer.Lister(),
		handlers:        syncmap.NewSyncMap[clusterManagerNodeHandler](),
		bootstrapNodes:  map[string]map[string]struct{}{},
		nodeCache:       newClusterManagerNodeCache(),
		annotationCache: sharednode.NewNodeAnnotationCache(),
	}

	nodeControllerConfig := &controller.ControllerConfig[corev1.Node]{
		RateLimiter:    workqueue.NewTypedItemFastSlowRateLimiter[string](time.Second, 5*time.Second, 5),
		Informer:       nodeInformer.Informer(),
		Lister:         nodeInformer.Lister().List,
		MaxAttempts:    controller.InfiniteAttempts,
		ObjNeedsUpdate: func(_, _ *corev1.Node) bool { return true },
		Reconcile:      c.reconcileNode,
		Threadiness:    15,
	}
	c.nodeController = controller.NewController(c.name, nodeControllerConfig)

	return c
}

func (c *clusterManagerNodeController) Start() error {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	if c.started {
		return nil
	}

	if err := controller.Start(c.nodeController); err != nil {
		return err
	}

	c.started = true
	return nil
}

func (c *clusterManagerNodeController) Stop() {
	c.startMu.Lock()
	c.started = false
	c.startMu.Unlock()
	controller.Stop(c.nodeController)
}

func (c *clusterManagerNodeController) RegisterNetworkController(handler clusterManagerNodeHandler) error {
	netName := handler.GetNetworkName()
	return c.handlers.DoWithLock(netName, func(key string) error {
		if existing, ok := c.handlers.Load(key); ok && existing != nil {
			panic(fmt.Sprintf("%s: duplicate node handler registration for network %q", c.name, key))
		}
		c.handlers.Store(key, handler)
		if err := c.bootstrapNetwork(key, handler); err != nil {
			c.handlers.Delete(key)
			return fmt.Errorf("%s: failed to bootstrap network %s: %w", c.name, netName, err)
		}
		return nil
	})
}

func (c *clusterManagerNodeController) DeregisterNetworkController(netName string) {
	_ = c.handlers.DoWithLock(netName, func(key string) error {
		c.handlers.Delete(key)
		c.stateMu.Lock()
		delete(c.bootstrapNodes, key)
		c.stateMu.Unlock()
		return nil
	})
}

func (c *clusterManagerNodeController) reconcileNode(key string) error {
	nodeName, netName := parseClusterManagerScopedNodeQueueKey(key)
	node, err := c.nodeLister.Get(nodeName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return c.reconcileDelete(nodeName, netName)
		}
		return err
	}

	oldNode := c.nodeCache.get(nodeName)
	err = c.reconcileUpdate(oldNode, node, netName)
	if err == nil {
		c.nodeCache.set(node)
	}
	return err
}

func (c *clusterManagerNodeController) reconcileUpdate(oldNode, newNode *corev1.Node, netName string) error {
	handlerKeys := c.handlers.GetKeys()
	if netName != "" {
		handlerKeys = []string{netName}
	}
	if len(handlerKeys) == 0 {
		return nil
	}

	oldState := c.annotationCache.UpdateNodeAnnotationState(oldNode, false)
	newState := c.annotationCache.UpdateNodeAnnotationState(newNode, true)

	var errs []error
	for _, handlerKey := range handlerKeys {
		err := c.handlers.DoWithLock(handlerKey, func(key string) error {
			handler, ok := c.handlers.Load(key)
			if !ok || handler == nil {
				return nil
			}
			if c.nodeNeedsBootstrap(key, newNode.Name) {
				if err := handler.ReconcileNode(nil, newNode, nil, newState); err != nil {
					return err
				}
				c.markBootstrapNodeDone(key, newNode.Name)
				return nil
			}
			return handler.ReconcileNode(oldNode, newNode, oldState, newState)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("network %s: %w", handlerKey, err))
		}
	}

	return utilerrors.Join(errs...)
}

func (c *clusterManagerNodeController) reconcileDelete(nodeName, netName string) error {
	oldNode := c.nodeCache.get(nodeName)
	var oldState *sharednode.NodeAnnotationState
	if oldNode == nil {
		oldNode = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
		}
	} else {
		oldState = c.annotationCache.UpdateNodeAnnotationState(oldNode, false)
	}

	handlerKeys := c.handlers.GetKeys()
	if netName != "" {
		handlerKeys = []string{netName}
	}
	if len(handlerKeys) == 0 {
		return nil
	}

	var errs []error
	for _, handlerKey := range handlerKeys {
		err := c.handlers.DoWithLock(handlerKey, func(key string) error {
			handler, ok := c.handlers.Load(key)
			if !ok || handler == nil {
				return nil
			}
			if err := handler.ReconcileNode(oldNode, nil, oldState, nil); err != nil {
				return err
			}
			c.markBootstrapNodeDone(key, oldNode.Name)
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("network %s: %w", handlerKey, err))
		}
	}

	if len(errs) == 0 && netName == "" {
		c.nodeCache.delete(nodeName)
		c.annotationCache.DeleteNode(nodeName)
		c.deleteBootstrapNode(nodeName)
	}

	return utilerrors.Join(errs...)
}

func (c *clusterManagerNodeController) bootstrapNetwork(netName string, handler clusterManagerNodeHandler) error {
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}
	if err := handler.SyncNodes(nodes); err != nil {
		return err
	}

	c.setBootstrapNodes(netName, nodes)
	for _, node := range nodes {
		c.nodeController.Reconcile(scopedClusterManagerNodeQueueKey(node.Name, netName))
	}
	return nil
}

func (c *clusterManagerNodeController) setBootstrapNodes(netName string, nodes []*corev1.Node) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if len(nodes) == 0 {
		return
	}
	nodeSet := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		nodeSet[node.Name] = struct{}{}
	}
	c.bootstrapNodes[netName] = nodeSet
}

func (c *clusterManagerNodeController) nodeNeedsBootstrap(netName, nodeName string) bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	nodes := c.bootstrapNodes[netName]
	if len(nodes) == 0 {
		return false
	}
	_, ok := nodes[nodeName]
	return ok
}

func (c *clusterManagerNodeController) markBootstrapNodeDone(netName, nodeName string) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	nodes := c.bootstrapNodes[netName]
	if len(nodes) == 0 {
		return
	}
	delete(nodes, nodeName)
	if len(nodes) == 0 {
		delete(c.bootstrapNodes, netName)
	}
}

func (c *clusterManagerNodeController) deleteBootstrapNode(nodeName string) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	for netName, nodes := range c.bootstrapNodes {
		delete(nodes, nodeName)
		if len(nodes) == 0 {
			delete(c.bootstrapNodes, netName)
		}
	}
}

func scopedClusterManagerNodeQueueKey(nodeName, netName string) string {
	if netName == "" {
		return nodeName
	}
	return nodeName + clusterManagerScopedNodeQueueKeySeparator + netName
}

func parseClusterManagerScopedNodeQueueKey(key string) (nodeName, netName string) {
	parts := strings.SplitN(key, clusterManagerScopedNodeQueueKeySeparator, 2)
	if len(parts) != 2 {
		return key, ""
	}
	if parts[0] == "" || parts[1] == "" {
		return key, ""
	}
	return parts[0], parts[1]
}

type clusterManagerNodeCache struct {
	mu    sync.RWMutex
	nodes map[string]*corev1.Node
}

func newClusterManagerNodeCache() clusterManagerNodeCache {
	return clusterManagerNodeCache{nodes: map[string]*corev1.Node{}}
}

func (c *clusterManagerNodeCache) get(name string) *corev1.Node {
	c.mu.RLock()
	defer c.mu.RUnlock()
	node := c.nodes[name]
	if node == nil {
		return nil
	}
	return node.DeepCopy()
}

func (c *clusterManagerNodeCache) set(node *corev1.Node) {
	if node == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes[node.Name] = node.DeepCopy()
}

func (c *clusterManagerNodeCache) delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.nodes, name)
}
