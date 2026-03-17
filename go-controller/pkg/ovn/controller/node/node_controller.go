package node

import (
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/syncmap"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	utilerrors "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util/errors"
)

// NodeHandler handles node reconciliation for a single network.
type NodeHandler interface {
	// GetNetworkName returns the network this handler reconciles.
	GetNetworkName() string
	// ReconcileNode reconciles the network-specific state for a node. oldNode and
	// oldState may be nil when the node is first seen for the network or becomes
	// active again. newNode and newState describe the latest desired state; they
	// are nil when network-specific state for the node should be deleted.
	ReconcileNode(oldNode, newNode *corev1.Node, oldState, newState *NodeAnnotationState) error
	// SyncNodes performs the initial full-network sync before per-node
	// reconciliation is queued for the handler.
	SyncNodes(nodes []*corev1.Node) error
}

// NodeController reconciles node topology for all registered UDN networks.
type NodeController struct {
	name string

	nodeController controller.Controller
	networkManager networkmanager.Interface
	nodeLister     v1.NodeLister

	// handlers maps network name to node handler.
	handlers *syncmap.SyncMap[NodeHandler]

	// stateMu protects bootstrapNodes, nodeConfigured, and pendingDeletes.
	stateMu sync.RWMutex
	// bootstrapNodes tracks nodes that should be treated as "new" per network.
	// keyed by network -> nodes
	bootstrapNodes map[string]map[string]struct{}
	// nodeConfigured tracks whether the last successfully applied state for a
	// node/network was active/configured.
	// keyed by network -> nodes
	nodeConfigured map[string]map[string]bool
	// pendingDeletes tracks delete intent from HandleNetworkRefChange(active=false)
	// for a node/network. This preserves the old "inactive callback drives delete"
	// semantics until the next reconcile observes the latest desired state.
	// keyed by network -> nodes
	pendingDeletes map[string]map[string]bool

	nodeCache nodeCache
	// annotationCache stores parsed annotation maps keyed by node.
	annotationCache *NodeAnnotationCache

	startMu sync.Mutex
	started bool
}

type nodeNetworkReconcileAction int

const (
	nodeNetworkReconcileNoop nodeNetworkReconcileAction = iota
	nodeNetworkReconcileAdd
	nodeNetworkReconcileUpdate
	nodeNetworkReconcileDelete
)

const scopedNodeQueueKeySeparator = "|"

// NewNodeController builds a controller that handles node events for all UDNs.
func NewNodeController(wf *factory.WatchFactory, networkManager networkmanager.Interface) *NodeController {
	nodeInformer := wf.NodeCoreInformer()
	c := &NodeController{
		name:            "udn-node-topology",
		networkManager:  networkManager,
		nodeLister:      nodeInformer.Lister(),
		handlers:        syncmap.NewSyncMap[NodeHandler](),
		bootstrapNodes:  map[string]map[string]struct{}{},
		nodeConfigured:  map[string]map[string]bool{},
		pendingDeletes:  map[string]map[string]bool{},
		nodeCache:       newNodeCache(),
		annotationCache: NewNodeAnnotationCache(),
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
	c.nodeController = controller.NewController(c.name+"-node", nodeControllerConfig)

	return c
}

// Start starts the node worker.
func (c *NodeController) Start() error {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	if c.started {
		return nil
	}

	err := controller.Start(c.nodeController)
	if err != nil {
		return err
	}

	c.started = true
	return nil
}

// Stop stops the node worker.
func (c *NodeController) Stop() {
	c.startMu.Lock()
	c.started = false
	c.startMu.Unlock()
	controller.Stop(c.nodeController)
}

// ReconcileNetwork queues reconciliation for a single node/network pair.
func (c *NodeController) ReconcileNetwork(nodeName, netName string) {
	c.setNodeNetworkPendingDelete(netName, nodeName, false)
	c.nodeController.Reconcile(scopedNodeQueueKey(nodeName, netName))
}

// ReconcileNetworkDelete queues reconciliation for a single node/network pair
// with explicit delete intent.
func (c *NodeController) ReconcileNetworkDelete(nodeName, netName string) {
	c.setNodeNetworkPendingDelete(netName, nodeName, true)
	c.nodeController.Reconcile(scopedNodeQueueKey(nodeName, netName))
}

// AnnotationCache returns the cache used for parsed node annotations.
func (c *NodeController) AnnotationCache() *NodeAnnotationCache {
	return c.annotationCache
}

// RegisterNetworkController registers or replaces a per-network node handler.
// Registration is the activation signal for node handling.
func (c *NodeController) RegisterNetworkController(handler NodeHandler) error {
	if handler == nil {
		return fmt.Errorf("%s: nil node handler registration", c.name)
	}
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

// DeregisterNetworkController removes a per-network node handler and clears
// associated network state. Note, OVN cleanup for nodes will be executed by the handler.
func (c *NodeController) DeregisterNetworkController(netName string) {
	_ = c.handlers.DoWithLock(netName, func(key string) error {
		c.handlers.Delete(key)
		c.stateMu.Lock()
		delete(c.bootstrapNodes, key)
		delete(c.nodeConfigured, key)
		delete(c.pendingDeletes, key)
		c.stateMu.Unlock()
		return nil
	})
}

// reconcileNode handles node add/update/delete by comparing cached state.
func (c *NodeController) reconcileNode(key string) error {
	nodeName, netName := parseScopedNodeQueueKey(key)
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

// reconcileUpdate reconciles per-network node changes.
// oldNode is derived from this controller's internal cache.
// newNode is the latest state of the node from informer cache.
// Reconciliation is level-driven.
func (c *NodeController) reconcileUpdate(oldNode, newNode *corev1.Node, netName string) error {
	keys := c.handlers.GetKeys()
	if netName != "" {
		keys = []string{netName}
	}
	if len(keys) == 0 {
		return nil
	}

	oldState := c.annotationCache.updateNodeAnnotationState(oldNode, false)
	newState := c.annotationCache.updateNodeAnnotationState(newNode, true)

	var errs []error
	for _, netName := range keys {
		err := c.handlers.DoWithLock(netName, func(key string) error {
			handler, ok := c.handlers.Load(key)
			if !ok || handler == nil {
				return nil
			}
			nodeName := newNode.Name
			nodeNeedsBootstrap := c.nodeNeedsBootstrap(key, nodeName)
			// Dynamic UDN activity filtering only applies to remote-zone nodes for this controller.
			// The presence of the handler indicates the local node is active to us.
			needsDynamicFiltering := c.shouldFilterByRemoteNetworkActivity(newNode)
			desiredActive := c.nodeHasNetwork(nodeName, key)
			appliedActive := c.isNodeNetworkConfigured(key, nodeName)
			pendingDelete := c.isNodeNetworkPendingDelete(key, nodeName)

			switch determineNodeNetworkReconcileAction(pendingDelete, nodeNeedsBootstrap, needsDynamicFiltering, desiredActive, appliedActive) {
			case nodeNetworkReconcileNoop:
				if pendingDelete {
					c.setNodeNetworkPendingDelete(key, nodeName, false)
				}
				if nodeNeedsBootstrap {
					c.setNodeNetworkConfigured(key, nodeName, false)
					c.markBootstrapNodeDone(key, nodeName)
				}
			case nodeNetworkReconcileAdd:
				if pendingDelete {
					c.setNodeNetworkPendingDelete(key, nodeName, false)
				}
				if err := handler.ReconcileNode(nil, newNode, nil, newState); err != nil {
					return err
				}
				c.setNodeNetworkConfigured(key, nodeName, true)
				if nodeNeedsBootstrap {
					c.markBootstrapNodeDone(key, nodeName)
				}
			case nodeNetworkReconcileUpdate:
				if err := handler.ReconcileNode(oldNode, newNode, oldState, newState); err != nil {
					return err
				}
				c.setNodeNetworkConfigured(key, nodeName, true)
			case nodeNetworkReconcileDelete:
				deleteNode := oldNode
				deleteState := oldState
				if deleteNode == nil {
					deleteNode = newNode
					deleteState = newState
				}
				if err := handler.ReconcileNode(deleteNode, nil, deleteState, nil); err != nil {
					return err
				}
				c.setNodeNetworkConfigured(key, nodeName, false)
				if pendingDelete {
					c.setNodeNetworkPendingDelete(key, nodeName, false)
				}
				if nodeNeedsBootstrap {
					c.markBootstrapNodeDone(key, nodeName)
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("network %s: %w", netName, err))
			continue
		}
	}
	return utilerrors.Join(errs...)
}

func determineNodeNetworkReconcileAction(deleteRequested, bootstrapPending, needsDynamicFiltering, desiredActive, appliedActive bool) nodeNetworkReconcileAction {
	if deleteRequested {
		if !desiredActive {
			return nodeNetworkReconcileDelete
		}
	}

	if bootstrapPending {
		if needsDynamicFiltering && !desiredActive {
			return nodeNetworkReconcileNoop
		}
		return nodeNetworkReconcileAdd
	}

	if !needsDynamicFiltering {
		return nodeNetworkReconcileUpdate
	}

	switch {
	case desiredActive && appliedActive:
		return nodeNetworkReconcileUpdate
	case desiredActive:
		return nodeNetworkReconcileAdd
	case appliedActive:
		return nodeNetworkReconcileDelete
	default:
		return nodeNetworkReconcileNoop
	}
}

// reconcileDelete handles deletion using cached state.
func (c *NodeController) reconcileDelete(nodeName, netName string) error {
	oldNode := c.nodeCache.get(nodeName)
	if oldNode == nil {
		return nil
	}

	handlerKeys := c.handlers.GetKeys()
	// Normally we should not get a netName here when a controller is first starting to add all nodes.
	// However, it is possible that after queuing the key for a new controller, the node is deleted.
	// In that case we still try to delete the node, but we do not update global (network unaware) caches
	if netName != "" {
		handlerKeys = []string{netName}
	}
	if len(handlerKeys) == 0 {
		return nil
	}

	oldState := c.annotationCache.updateNodeAnnotationState(oldNode, true)

	var errs []error
	for _, netName := range handlerKeys {
		netName := netName
		err := c.handlers.DoWithLock(netName, func(handlerKey string) error {
			handler, ok := c.handlers.Load(handlerKey)
			if !ok || handler == nil {
				return nil
			}
			if c.shouldFilterByRemoteNetworkActivity(oldNode) &&
				!c.isNodeNetworkConfigured(handlerKey, oldNode.Name) &&
				!c.nodeNeedsBootstrap(handlerKey, oldNode.Name) {
				return nil
			}
			if err := handler.ReconcileNode(oldNode, nil, oldState, nil); err != nil {
				return err
			}
			c.setNodeNetworkConfigured(handlerKey, oldNode.Name, false)
			c.setNodeNetworkPendingDelete(handlerKey, oldNode.Name, false)
			c.markBootstrapNodeDone(handlerKey, oldNode.Name)
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("network %s: %w", netName, err))
		}
	}
	// Scoped delete reconciliations are best-effort cleanup for a single network.
	// Keep node cache/state for the regular node delete event to process all networks.
	if len(errs) == 0 && netName == "" {
		c.nodeCache.delete(nodeName)
		c.annotationCache.deleteNode(nodeName)
		c.deleteNodeNetworkState(nodeName)
	}
	return utilerrors.Join(errs...)
}

// bootstrapNetwork handles syncing, initializing bootstrap node cache, and queuing up nodes for reconciliation
func (c *NodeController) bootstrapNetwork(netName string, handler NodeHandler) error {
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}
	if err := handler.SyncNodes(nodes); err != nil {
		return err
	}

	c.setBootstrapNodes(netName, nodes)
	for _, node := range nodes {
		c.nodeController.Reconcile(scopedNodeQueueKey(node.Name, netName))
	}
	return nil
}

// setBootstrapNodes stores bootstrap node tracking for a network.
func (c *NodeController) setBootstrapNodes(netName string, nodes []*corev1.Node) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if len(nodes) != 0 {
		nodeSet := make(map[string]struct{}, len(nodes))
		for _, node := range nodes {
			nodeSet[node.Name] = struct{}{}
		}
		c.bootstrapNodes[netName] = nodeSet
	}
}

// nodeNeedsBootstrap returns true if a node should be treated as new for a network.
func (c *NodeController) nodeNeedsBootstrap(netName, nodeName string) bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	nodes := c.bootstrapNodes[netName]
	if len(nodes) == 0 {
		return false
	}
	_, ok := nodes[nodeName]
	return ok
}

// markBootstrapNodeDone clears bootstrap tracking for a node.
func (c *NodeController) markBootstrapNodeDone(netName, nodeName string) {
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

// isNodeNetworkConfigured returns whether the last successfully applied state
// for nodeName/netName was active/configured.
func (c *NodeController) isNodeNetworkConfigured(netName, nodeName string) bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	nodes := c.nodeConfigured[netName]
	if len(nodes) == 0 {
		return false
	}
	return nodes[nodeName]
}

// setNodeNetworkConfigured records whether the last successfully applied state
// for a node/network was active/configured.
func (c *NodeController) setNodeNetworkConfigured(netName, nodeName string, configured bool) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.setNodeNetworkConfiguredLocked(netName, nodeName, configured)
}

func (c *NodeController) setNodeNetworkConfiguredLocked(netName, nodeName string, configured bool) {
	if c.nodeConfigured == nil {
		c.nodeConfigured = map[string]map[string]bool{}
	}
	nodes := c.nodeConfigured[netName]
	if nodes == nil {
		nodes = map[string]bool{}
		c.nodeConfigured[netName] = nodes
	}
	nodes[nodeName] = configured
}

func (c *NodeController) isNodeNetworkPendingDelete(netName, nodeName string) bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	nodes := c.pendingDeletes[netName]
	if len(nodes) == 0 {
		return false
	}
	return nodes[nodeName]
}

func (c *NodeController) setNodeNetworkPendingDelete(netName, nodeName string, pendingDelete bool) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.pendingDeletes == nil {
		c.pendingDeletes = map[string]map[string]bool{}
	}
	if !pendingDelete {
		nodes := c.pendingDeletes[netName]
		if len(nodes) == 0 {
			return
		}
		delete(nodes, nodeName)
		if len(nodes) == 0 {
			delete(c.pendingDeletes, netName)
		}
		return
	}
	nodes := c.pendingDeletes[netName]
	if nodes == nil {
		nodes = map[string]bool{}
		c.pendingDeletes[netName] = nodes
	}
	nodes[nodeName] = true
}

// deleteNodeNetworkState removes configured-state tracking across all networks.
func (c *NodeController) deleteNodeNetworkState(nodeName string) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	for netName, nodes := range c.nodeConfigured {
		delete(nodes, nodeName)
		if len(nodes) == 0 {
			delete(c.nodeConfigured, netName)
		}
	}
	for netName, nodes := range c.pendingDeletes {
		delete(nodes, nodeName)
		if len(nodes) == 0 {
			delete(c.pendingDeletes, netName)
		}
	}
}

func (c *NodeController) nodeHasNetwork(nodeName, netName string) bool {
	return c.networkManager.NodeHasNetwork(nodeName, netName)
}

// shouldFilterByRemoteNetworkActivity returns true when dynamic UDN activity
// filtering should be applied for the node. This is limited to remote-zone
// nodes; local-zone nodes always run unfiltered reconciliation.
func (c *NodeController) shouldFilterByRemoteNetworkActivity(node *corev1.Node) bool {
	if node == nil || !config.OVNKubernetesFeature.EnableDynamicUDNAllocation {
		return false
	}
	localZone := config.Default.Zone
	if localZone == "" {
		localZone = types.OvnDefaultZone
	}
	return util.GetNodeZone(node) != localZone
}

// scopedNodeQueueKey allows us to queue keys with network references.
// This allows us to queue node updates for only specific networks.
// Useful for when networks first start up and register.
func scopedNodeQueueKey(nodeName, netName string) string {
	if netName == "" {
		return nodeName
	}
	return nodeName + scopedNodeQueueKeySeparator + netName
}

func parseScopedNodeQueueKey(key string) (nodeName, netName string) {
	parts := strings.SplitN(key, scopedNodeQueueKeySeparator, 2)
	if len(parts) != 2 {
		return key, ""
	}
	if parts[0] == "" || parts[1] == "" {
		return key, ""
	}
	return parts[0], parts[1]
}

type nodeCache struct {
	mu    sync.RWMutex
	nodes map[string]*corev1.Node
}

// newNodeCache returns an empty node cache.
func newNodeCache() nodeCache {
	return nodeCache{nodes: map[string]*corev1.Node{}}
}

// Get returns a deep copy of a cached node by name.
func (c *nodeCache) get(name string) *corev1.Node {
	c.mu.RLock()
	defer c.mu.RUnlock()
	node := c.nodes[name]
	if node == nil {
		return nil
	}
	return node.DeepCopy()
}

// Set stores a deep copy of a node.
func (c *nodeCache) set(node *corev1.Node) {
	if node == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes[node.Name] = node.DeepCopy()
}

// Delete removes a node from the cache.
func (c *nodeCache) delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.nodes, name)
}
