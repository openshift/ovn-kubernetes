package clustermanager

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	cache "k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// secondaryNetworkClusterController is the object for managing the secondary
// layer3 networks for all the nodes. Listens to the node events.
type secondaryNetworkClusterController struct {
	networkClusterControllerBase
	nodeL3NetworkController *NodeNetworkController

	// per controller NAD/netconf name information
	util.NetInfo
	util.NetConfInfo

	// Record new nodes we failed to configure
	addNodeFailed sync.Map
}

func newSecondaryNetworkClusterController(ovnClient *util.OVNClusterManagerClientset, wf *factory.WatchFactory, stopChan chan struct{},
	wg *sync.WaitGroup, netInfo util.NetInfo, netConfInfo util.NetConfInfo, networkName string) *secondaryNetworkClusterController {

	kube := &kube.Kube{
		KClient: ovnClient.KubeClient,
	}

	sncc := &secondaryNetworkClusterController{
		networkClusterControllerBase: networkClusterControllerBase{
			kube:         kube,
			watchFactory: wf,
			stopChan:     stopChan,
			wg:           wg,
		},
		nodeL3NetworkController: newNodeNetworkController(kube, wf, networkName),
		NetInfo:                 netInfo,
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
// and hybrid network subnet allocator ranges if hybrid overlay is enabled.
func (sncc *secondaryNetworkClusterController) Start(ctx context.Context) error {
	klog.Infof("Start secondary %s network cluster manager for network %s", sncc.TopologyType(), sncc.GetNetworkName())
	layer3NetConfInfo := sncc.NetConfInfo.(*util.Layer3NetConfInfo)
	if err := sncc.nodeL3NetworkController.InitSubnetAllocatorRanges(layer3NetConfInfo.ClusterSubnets); err != nil {
		return fmt.Errorf("failed to initialize host subnet allocator ranges for secondary network %q: %w", sncc.GetNetworkName(), err)
	}

	// Start watching the nodes
	handler, err := sncc.retryNodes.WatchResource()
	if err != nil {
		return err
	}
	sncc.nodeHandler = handler
	return nil
}

// Stop gracefully stops the controller, and delete all logical entities for this network if requested
func (sncc *secondaryNetworkClusterController) Stop() {
	klog.Infof("Stopping secondary %s network cluster manager for network %q", sncc.TopologyType(), sncc.GetNetworkName())
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

func (sncc *secondaryNetworkClusterController) addUpdateNodeEvent(node *corev1.Node, syncNode bool) error {
	klog.V(5).Infof("Configuring secondary network %q after receiving add/update node event for node %s", sncc.GetNetworkName(), node.Name)
	if syncNode {
		if err := sncc.nodeL3NetworkController.addUpdateNode(node); err != nil {
			sncc.addNodeFailed.Store(node.Name, true)
			return fmt.Errorf("error configuring secondary network %q for node %s: %w", sncc.GetNetworkName(), node.Name, err)
		}
		sncc.addNodeFailed.Delete(node.Name)
	}

	return nil
}

func (sncc *secondaryNetworkClusterController) deleteNodeEvent(node *corev1.Node) error {
	klog.V(5).Infof("Configuring secondary network %q after receiving delete node event for node %s", sncc.GetNetworkName(), node.Name)
	return sncc.nodeL3NetworkController.deleteNode(node)
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

// secondaryNetworkClusterControllerEventHandler is the event handler for
// the events from retry framework.
type secondaryNetworkClusterControllerEventHandler struct {
	watchFactory *factory.WatchFactory
	objType      reflect.Type
	sncc         *secondaryNetworkClusterController
	syncFunc     func([]interface{}) error
}

func (h *secondaryNetworkClusterControllerEventHandler) AreResourcesEqual(obj1, obj2 interface{}) (bool, error) {
	node1, ok := obj1.(*corev1.Node)
	if !ok {
		return false, fmt.Errorf("could not cast obj1 of type %T to *corev1.Node", obj1)
	}
	node2, ok := obj2.(*corev1.Node)
	if !ok {
		return false, fmt.Errorf("could not cast obj2 of type %T to *corev1.Node", obj2)
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

// RecordAddEvent records the add event on this given object
func (h *secondaryNetworkClusterControllerEventHandler) RecordAddEvent(obj interface{}) {
}

// RecordUpdateEvent records the update event on this given object
func (h *secondaryNetworkClusterControllerEventHandler) RecordUpdateEvent(obj interface{}) {
}

// RecordDeleteEvent records the delete event on this given object
func (h *secondaryNetworkClusterControllerEventHandler) RecordDeleteEvent(obj interface{}) {
}

// RecordSuccessEvent records the success event on this given object
func (h *secondaryNetworkClusterControllerEventHandler) RecordSuccessEvent(obj interface{}) {
}

// RecordErrorEvent records the error event on this given object
func (h *secondaryNetworkClusterControllerEventHandler) RecordErrorEvent(obj interface{}, reason string, err error) {
}

// IsResourceScheduled returns true if the given object has been scheduled.
// Returns true as this is not relevant for secondary networks
func (h *secondaryNetworkClusterControllerEventHandler) IsResourceScheduled(obj interface{}) bool {
	return true
}

// IsObjectInTerminalState returns true if the object is in a terminal state
func (h *secondaryNetworkClusterControllerEventHandler) IsObjectInTerminalState(bj interface{}) bool {
	return false
}

// AddResource handles the add event for the 'Node' obj
func (h *secondaryNetworkClusterControllerEventHandler) AddResource(obj interface{}, fromRetryLoop bool) error {
	if h.objType == factory.NodeType {
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Node", obj)
		}
		syncNode := true
		if fromRetryLoop {
			_, syncNode = h.sncc.addNodeFailed.Load(node.Name)
		}

		return h.sncc.addUpdateNodeEvent(node, syncNode)
	}
	return nil
}

// UpdateResource handles the update event for the 'Node' obj. Given an old and a new object;
// The inRetryCache boolean argument is to indicate if the 'Node' object is in the retryCache or not.
func (h *secondaryNetworkClusterControllerEventHandler) UpdateResource(oldObj, newObj interface{}, inRetryCache bool) error {
	if h.objType == factory.NodeType {
		newNode, ok := newObj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast newObj of type %T to *corev1.Node", newObj)
		}
		_, ok = oldObj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast oldObj of type %T to *corev1.Node", oldObj)
		}
		// determine what actually changed in this update
		_, syncNode := h.sncc.addNodeFailed.Load(newNode.Name)

		return h.sncc.addUpdateNodeEvent(newNode, syncNode)
	}
	return nil
}

// DeleteResource handle the deletes event for the 'Node' obj
func (h *secondaryNetworkClusterControllerEventHandler) DeleteResource(obj, cachedObj interface{}) error {
	if h.objType == factory.NodeType {
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast obj of type %T to *knet.Node", obj)
		}
		return h.sncc.deleteNodeEvent(node)

	}
	return nil
}

// SyncFunc syncs the 'Node' objects.  Called in the beginning when the secondary network cluster
// controller is created for the secondary network.
func (h *secondaryNetworkClusterControllerEventHandler) SyncFunc(objs []interface{}) error {
	if h.objType == factory.NodeType {
		return h.sncc.nodeL3NetworkController.syncNodes(objs)
	}
	return fmt.Errorf("no sync function for object type %s", h.objType)
}
