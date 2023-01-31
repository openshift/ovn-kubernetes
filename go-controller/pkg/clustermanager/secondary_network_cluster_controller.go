package clustermanager

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	cache "k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// secondaryNetworkClusterController is the object for managing the secondary
// layer3 networks for all the nodes. Listens to the node events.
type secondaryNetworkClusterController struct {
	networkClusterControllerBase
	nodeL3NetworkController *NodeNetworkController

	// per controller NAD/netconf name information
	util.NetInfo
	util.NetConfInfo

	// Node-specific sysnccaps used by node event handler
	addNodeFailed sync.Map
}

func newSecondaryNetworkClusterController(ovnClient *util.OVNClientset, wf *factory.WatchFactory, stopChan chan struct{},
	wg *sync.WaitGroup, nInfo util.NetInfo, netConfInfo util.NetConfInfo, networkName string) *secondaryNetworkClusterController {

	kube := &kube.Kube{
		KClient:              ovnClient.KubeClient,
		EIPClient:            ovnClient.EgressIPClient,
		EgressFirewallClient: ovnClient.EgressFirewallClient,
		CloudNetworkClient:   ovnClient.CloudNetworkClient,
	}

	sncc := &secondaryNetworkClusterController{
		networkClusterControllerBase: networkClusterControllerBase{
			kube:         kube,
			watchFactory: wf,
			stopChan:     stopChan,
			wg:           wg,
		},
		nodeL3NetworkController: newNodeNetworkController(kube, wf, networkName),
		NetInfo:                 nInfo,
		NetConfInfo:             netConfInfo,
		addNodeFailed:           sync.Map{},
	}

	sncc.initRetryFramework()
	return sncc
}

func (sncc *secondaryNetworkClusterController) initRetryFramework() {
	sncc.retryNodes = sncc.newRetryFramework(factory.NodeType)
}

// Start initializes the default network subnet allocator ranges
// and hybrid network subnet allocator ranges if hybrod overlay is enabled.
func (sncc *secondaryNetworkClusterController) Start(ctx context.Context) error {
	klog.Infof("Start secondary %s network cluster manager for network %s", sncc.TopologyType(), sncc.GetNetworkName())
	klog.Infof("Allocating subnets")
	layer3NetConfInfo := sncc.NetConfInfo.(*util.Layer3NetConfInfo)
	if err := sncc.nodeL3NetworkController.InitSubnetAllocatorRanges(layer3NetConfInfo.ClusterSubnets); err != nil {
		klog.Errorf("Failed to initialize host subnet allocator ranges: %v", err)
		return err
	}

	return sncc.Run()
}

// Stop gracefully stops the controller, and delete all logical entities for this network if requested
func (sncc *secondaryNetworkClusterController) Stop() {
	klog.Infof("Stop secondary %s network cluster manager for network %s", sncc.TopologyType(), sncc.GetNetworkName())
	close(sncc.stopChan)
	sncc.wg.Wait()

	if sncc.nodeHandler != nil {
		sncc.watchFactory.RemoveNodeHandler(sncc.nodeHandler)
	}
}

// Cleanup cleans up logical entities for the given network, called from net-attach-def routine
func (sncc *secondaryNetworkClusterController) Cleanup(netName string) error {
	return sncc.nodeL3NetworkController.cleanup(netName)
}

// Run starts the actual watching.
func (sncc *secondaryNetworkClusterController) Run() error {
	if err := sncc.WatchNodes(); err != nil {
		return err
	}

	return nil
}

// WatchNodes starts the watching of node resource and calls
// back the appropriate handler logic
func (sncc *secondaryNetworkClusterController) WatchNodes() error {
	if sncc.nodeHandler != nil {
		return nil
	}
	handler, err := sncc.retryNodes.WatchResource()
	if err == nil {
		sncc.nodeHandler = handler
	}
	return err
}

func (sncc *secondaryNetworkClusterController) addUpdateNodeEvent(node *kapi.Node, nSyncs *nodeSyncs) error {
	klog.Infof("Adding or Updating Node %q for network %s", node.Name, sncc.GetNetworkName())
	if nSyncs.syncNode {
		if err := sncc.addNode(node); err != nil {
			sncc.addNodeFailed.Store(node.Name, true)
			err = fmt.Errorf("nodeAdd: error adding node %q for network %s: %w", node.Name, sncc.GetNetworkName(), err)
			return err
		}
		sncc.addNodeFailed.Delete(node.Name)
	}

	return nil
}

func (sncc *secondaryNetworkClusterController) addNode(node *kapi.Node) error {
	return sncc.nodeL3NetworkController.addUpdateNode(node)
}

func (sncc *secondaryNetworkClusterController) deleteNodeEvent(node *kapi.Node) error {
	klog.V(5).Infof("Deleting Node %q for network %s. Removing the node from "+
		"various caches", node.Name, sncc.GetNetworkName())

	return sncc.nodeL3NetworkController.deleteNode(node)
}

func (sncc *secondaryNetworkClusterController) syncNodes(nodes []interface{}) error {
	return sncc.nodeL3NetworkController.syncNodes(nodes)
}

// newRetryFramework builds and returns a retry framework for the input resource type;
func (sncc *secondaryNetworkClusterController) newRetryFramework(
	objectType reflect.Type) *retry.RetryFramework {
	eventHandler := &secondaryNetworkClusterControllerEventHandler{
		objType:      objectType,
		watchFactory: sncc.watchFactory,
		sncc:         sncc,
		syncFunc:     nil,
	}
	resourceHandler := &retry.ResourceHandler{
		HasUpdateFunc:          true,
		NeedsUpdateDuringRetry: false,
		ObjType:                objectType,
		EventHandler:           eventHandler,
	}
	return retry.NewRetryFramework(
		sncc.stopChan,
		sncc.wg,
		sncc.watchFactory,
		resourceHandler,
	)
}

type nodeSyncs struct {
	syncNode bool
}

// secondaryNetworkClusterControllerEventHandler is the event handler for
// the events from retry framework.
type secondaryNetworkClusterControllerEventHandler struct {
	watchFactory *factory.WatchFactory
	objType      reflect.Type
	sncc         *secondaryNetworkClusterController
	syncFunc     func([]interface{}) error
}

func (h *secondaryNetworkClusterControllerEventHandler) AreResourcesEqual(obj1, obj2 interface{}) (bool, error) {
	node1, ok := obj1.(*kapi.Node)
	if !ok {
		return false, fmt.Errorf("could not cast obj1 of type %T to *kapi.Node", obj1)
	}
	node2, ok := obj2.(*kapi.Node)
	if !ok {
		return false, fmt.Errorf("could not cast obj2 of type %T to *kapi.Node", obj2)
	}

	// when shouldUpdateNode is false, the hostsubnet is not assigned by ovn-kubernetes
	shouldUpdate, err := util.ShouldUpdateNode(node2, node1)
	if err != nil {
		klog.Errorf(err.Error())
	}
	return !shouldUpdate, nil
}

// GetInternalCacheEntry returns the internal cache entry for this object, given an object and its type.
// This is now used only for pods, which will get their the logical port cache entry.
func (h *secondaryNetworkClusterControllerEventHandler) GetInternalCacheEntry(obj interface{}) interface{} {
	return nil
}

// GetResourceFromInformerCache returns the latest state of the object, given an object key and its type.
// from the informers cache.
func (h *secondaryNetworkClusterControllerEventHandler) GetResourceFromInformerCache(key string) (interface{}, error) {
	var obj interface{}
	var err error

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to split key %s: %v", key, err)
	}

	if h.objType == factory.NodeType {
		obj, err = h.watchFactory.GetNode(name)
	}
	return obj, err
}

// RecordAddEvent records the add event on this given object.
func (h *secondaryNetworkClusterControllerEventHandler) RecordAddEvent(obj interface{}) {
}

// RecordUpdateEvent records the udpate event on this given object.
func (h *secondaryNetworkClusterControllerEventHandler) RecordUpdateEvent(obj interface{}) {
}

// RecordDeleteEvent records the delete event on this given object.
func (h *secondaryNetworkClusterControllerEventHandler) RecordDeleteEvent(obj interface{}) {
}

// RecordSuccessEvent records the success event on this given object.
func (h *secondaryNetworkClusterControllerEventHandler) RecordSuccessEvent(obj interface{}) {
}

// RecordErrorEvent records the error event on this given object.
func (h *secondaryNetworkClusterControllerEventHandler) RecordErrorEvent(obj interface{}, reason string, err error) {
}

func (h *secondaryNetworkClusterControllerEventHandler) IsResourceScheduled(obj interface{}) bool {
	return true
}

// IsObjectInTerminalState returns true if the object is in a terminal state.
func (h *secondaryNetworkClusterControllerEventHandler) IsObjectInTerminalState(bj interface{}) bool {
	return false
}

// AddResource adds the specified object to the cluster according to its type and returns the error,
// if any, yielded during object creation.
// Given an object to add and a boolean specifying if the function was executed from iterateRetryResources
func (h *secondaryNetworkClusterControllerEventHandler) AddResource(obj interface{}, fromRetryLoop bool) error {
	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *kapi.Node", obj)
		}
		var nodeParams *nodeSyncs
		if fromRetryLoop {
			_, nodeSync := h.sncc.addNodeFailed.Load(node.Name)
			nodeParams = &nodeSyncs{syncNode: nodeSync}
		} else {
			nodeParams = &nodeSyncs{syncNode: true}
		}

		if err := h.sncc.addUpdateNodeEvent(node, nodeParams); err != nil {
			klog.Errorf("Node add failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	}
	return nil
}

// UpdateResource updates the specified object in the cluster to its version in newObj according to its
// type and returns the error, if any, yielded during the object update.
// Given an old and a new object; The inRetryCache boolean argument is to indicate if the given resource
// is in the retryCache or not.
func (h *secondaryNetworkClusterControllerEventHandler) UpdateResource(oldObj, newObj interface{}, inRetryCache bool) error {
	switch h.objType {
	case factory.NodeType:
		newNode, ok := newObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast newObj of type %T to *kapi.Node", newObj)
		}
		_, ok = oldObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast oldObj of type %T to *kapi.Node", oldObj)
		}
		// determine what actually changed in this update
		_, nodeSync := h.sncc.addNodeFailed.Load(newNode.Name)

		return h.sncc.addUpdateNodeEvent(newNode, &nodeSyncs{syncNode: nodeSync})
	}
	return nil
}

// DeleteResource deletes the object from the cluster according to the delete logic of its resource type.
// Given an object and optionally a cachedObj; cachedObj is the internal cache entry for this object,
// used for now for pods and network policies.
func (h *secondaryNetworkClusterControllerEventHandler) DeleteResource(obj, cachedObj interface{}) error {
	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast obj of type %T to *knet.Node", obj)
		}
		return h.sncc.deleteNodeEvent(node)

	}
	return nil
}

func (h *secondaryNetworkClusterControllerEventHandler) SyncFunc(objs []interface{}) error {
	switch h.objType {
	case factory.NodeType:
		return h.sncc.syncNodes(objs)

	default:
		return fmt.Errorf("no sync function for object type %s", h.objType)
	}
}
