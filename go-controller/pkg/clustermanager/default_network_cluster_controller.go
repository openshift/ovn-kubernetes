package clustermanager

import (
	"fmt"
	"net"
	"reflect"
	"sync"

	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/clustermanager/subnetallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	objretry "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	cache "k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type networkClusterControllerBase struct {
	kube         kube.Interface
	watchFactory *factory.WatchFactory
	stopChan     chan struct{}
	wg           *sync.WaitGroup

	// node events factory handler
	nodeHandler *factory.Handler

	// retry framework for nodes
	retryNodes *objretry.RetryFramework
}

// defaultNetworkClusterController is the cluster controller for the default network
// for all the nodes. Listens to the node events and allocates subnet from the
// default cluster subnet pool.
type defaultNetworkClusterController struct {
	networkClusterControllerBase
	defaultNetworkController *NodeNetworkController

	hybridOverlaySubnetAllocator *subnetallocator.HostSubnetAllocator
}

func newDefaultNetworkClusterController(ovnClient *util.OVNClientset, wf *factory.WatchFactory) *defaultNetworkClusterController {

	kube := &kube.Kube{
		KClient:              ovnClient.KubeClient,
		EIPClient:            ovnClient.EgressIPClient,
		EgressFirewallClient: ovnClient.EgressFirewallClient,
		CloudNetworkClient:   ovnClient.CloudNetworkClient,
	}

	stopChan := make(chan struct{})
	wg := &sync.WaitGroup{}

	var hybridOverlaySubnetAllocator *subnetallocator.HostSubnetAllocator
	if config.HybridOverlay.Enabled {
		hybridOverlaySubnetAllocator = subnetallocator.NewHostSubnetAllocator()
	}
	ncm := &defaultNetworkClusterController{
		networkClusterControllerBase: networkClusterControllerBase{
			kube:         kube,
			watchFactory: wf,
			stopChan:     stopChan,
			wg:           wg,
		},
		defaultNetworkController: newNodeNetworkController(kube, wf, types.DefaultNetworkName),

		hybridOverlaySubnetAllocator: hybridOverlaySubnetAllocator,
	}

	ncm.initRetryFramework()
	return ncm
}

func (ncm *defaultNetworkClusterController) initRetryFramework() {
	ncm.retryNodes = ncm.newRetryFramework(factory.NodeType)
}

// Start initializes the default network subnet allocator ranges
// and hybrid network subnet allocator ranges if hybrid overlay is enabled.
func (ncm *defaultNetworkClusterController) Start() error {
	if err := ncm.defaultNetworkController.InitSubnetAllocatorRanges(config.Default.ClusterSubnets); err != nil {
		klog.Errorf("Failed to initialize host subnet allocator ranges: %v", err)
		return err
	}

	if config.HybridOverlay.Enabled {
		if err := ncm.hybridOverlaySubnetAllocator.InitRanges(config.HybridOverlay.ClusterSubnets); err != nil {
			klog.Errorf("Failed to initialize hybrid overlay subnet allocator ranges: %v", err)
			return err
		}
	}

	return nil
}

func (ncm *defaultNetworkClusterController) Stop() {
	close(ncm.stopChan)
	ncm.wg.Wait()
}

// Run starts the actual watching.
func (ncm *defaultNetworkClusterController) Run() error {
	existingNodes, err := ncm.kube.GetNodes()
	if err != nil {
		klog.Errorf("Error in fetching nodes: %v", err)
		return err
	}
	klog.V(5).Infof("Existing number of nodes: %d", len(existingNodes.Items))

	if err := ncm.WatchNodes(); err != nil {
		return err
	}

	return nil
}

// WatchNodes starts the watching of node resource and calls
// back the appropriate handler logic
func (ncm *defaultNetworkClusterController) WatchNodes() error {
	if ncm.nodeHandler != nil {
		return nil
	}

	handler, err := ncm.retryNodes.WatchResource()
	if err == nil {
		ncm.nodeHandler = handler
	}
	return err
}

// defaultNetworkClusterControllerEventHandler object handles the events
// from retry framework.
type defaultNetworkClusterControllerEventHandler struct {
	objretry.EventHandler

	objType  reflect.Type
	ncm      *defaultNetworkClusterController
	syncFunc func([]interface{}) error
}

func (ncm *defaultNetworkClusterController) newRetryFramework(objectType reflect.Type) *objretry.RetryFramework {
	resourceHandler := &objretry.ResourceHandler{
		HasUpdateFunc:          hasResourceAnUpdateFunc(objectType),
		NeedsUpdateDuringRetry: false,
		ObjType:                objectType,
		EventHandler: &defaultNetworkClusterControllerEventHandler{
			objType:  objectType,
			ncm:      ncm,
			syncFunc: nil,
		},
	}
	r := objretry.NewRetryFramework(ncm.stopChan, ncm.wg, ncm.watchFactory, resourceHandler)
	return r
}

// hybridOverlayNodeEnsureSubnet allocates a subnet and sets the
// hybrid overlay subnet annotation. It returns any newly allocated subnet
// or an error. If an error occurs, the newly allocated subnet will be released.
func (ncm *defaultNetworkClusterController) hybridOverlayNodeEnsureSubnet(node *kapi.Node, annotator kube.Annotator) (*net.IPNet, error) {
	var existingSubnets []*net.IPNet
	// Do not allocate a subnet if the node already has one
	subnet, err := houtil.ParseHybridOverlayHostSubnet(node)
	if err != nil {
		// Log the error and try to allocate new subnets
		klog.Infof("Failed to get node %s hybrid overlay subnet annotation: %v", node.Name, err)
	} else if subnet != nil {
		existingSubnets = []*net.IPNet{subnet}
	}

	// Allocate a new host subnet for this node
	// FIXME: hybrid overlay is only IPv4 for now due to limitations on the Windows side
	hostSubnets, allocatedSubnets, err := ncm.hybridOverlaySubnetAllocator.AllocateNodeSubnets(node.Name, existingSubnets, true, false)
	if err != nil {
		return nil, fmt.Errorf("error allocating hybrid overlay HostSubnet for node %s: %v", node.Name, err)
	}

	if err := annotator.Set(hotypes.HybridOverlayNodeSubnet, hostSubnets[0].String()); err != nil {
		_ = ncm.hybridOverlaySubnetAllocator.ReleaseNodeSubnets(node.Name, allocatedSubnets...)
		return nil, err
	}

	return hostSubnets[0], nil
}

func (ncm *defaultNetworkClusterController) releaseHybridOverlayNodeSubnet(nodeName string) {
	ncm.hybridOverlaySubnetAllocator.ReleaseAllNodeSubnets(nodeName)
	klog.Infof("Deleted hybrid overlay HostSubnets for node %s", nodeName)
}

func (ncm *defaultNetworkClusterController) addUpdateNodeEvent(node *kapi.Node) error {
	if util.NoHostSubnet(node) {
		if config.HybridOverlay.Enabled && houtil.IsHybridOverlayNode(node) {
			annotator := kube.NewNodeAnnotator(ncm.kube, node.Name)
			allocatedSubnet, err := ncm.hybridOverlayNodeEnsureSubnet(node, annotator)
			if err != nil {
				return fmt.Errorf("failed to update node %s hybrid overlay subnet annotation: %v", node.Name, err)
			}
			if err := annotator.Run(); err != nil {
				// Release allocated subnet if any errors occurred
				if allocatedSubnet != nil {
					ncm.releaseHybridOverlayNodeSubnet(node.Name)
				}
				return fmt.Errorf("failed to set hybrid overlay annotations for node %s: %v", node.Name, err)
			}
		}
		return nil
	}

	return ncm.addNode(node)
}

func (ncm *defaultNetworkClusterController) addNode(node *kapi.Node) error {
	return ncm.defaultNetworkController.addUpdateNode(node)
}

func (ncm *defaultNetworkClusterController) deleteNode(node *kapi.Node) error {
	if config.HybridOverlay.Enabled {
		ncm.releaseHybridOverlayNodeSubnet(node.Name)
	}

	return ncm.defaultNetworkController.deleteNode(node)
}

func (ncm *defaultNetworkClusterController) syncNodes(nodes []interface{}) error {
	for _, tmp := range nodes {
		node, ok := tmp.(*kapi.Node)
		if !ok {
			return fmt.Errorf("spurious object in syncNodes: %v", tmp)
		}

		hostSubnets, _ := util.ParseNodeHostSubnetAnnotation(node, types.DefaultNetworkName)
		if config.HybridOverlay.Enabled && len(hostSubnets) == 0 && houtil.IsHybridOverlayNode(node) {
			// this is a hybrid overlay node so mark as allocated from the hybrid overlay subnet allocator
			hostSubnet, err := houtil.ParseHybridOverlayHostSubnet(node)
			if err != nil {
				klog.Warning(err.Error())
			} else if hostSubnet != nil {
				klog.V(5).Infof("Node %s contains subnets: %v", node.Name, hostSubnet)
				if err := ncm.hybridOverlaySubnetAllocator.MarkSubnetsAllocated(node.Name, hostSubnet); err != nil {
					utilruntime.HandleError(err)
				}
			}
			// there is nothing left to be done if this is a hybrid overlay node
			continue
		}
	}

	return ncm.defaultNetworkController.syncNodes(nodes)
}

func (h *defaultNetworkClusterControllerEventHandler) AreResourcesEqual(obj1, obj2 interface{}) (bool, error) {
	// switch based on type
	switch h.objType {
	case factory.NodeType:
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

	return false, nil
}

// Given an object and its type, GetInternalCacheEntry returns the internal cache entry for this object.
func (h *defaultNetworkClusterControllerEventHandler) GetInternalCacheEntry(obj interface{}) interface{} {
	return nil
}

// Given an object key and its type, getResourceFromInformerCache returns the latest state of the object
// from the informers cache.
func (h *defaultNetworkClusterControllerEventHandler) GetResourceFromInformerCache(key string) (interface{}, error) {
	var obj interface{}
	var name string
	var err error

	_, name, err = cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to split key %s: %v", key, err)
	}

	switch h.objType {
	case factory.NodeType,
		factory.EgressNodeType:
		obj, err = h.ncm.watchFactory.GetNode(name)

	default:
		err = fmt.Errorf("object type %s not supported, cannot retrieve it from informers cache",
			h.objType)
	}
	return obj, err
}

// Given an object and its type, RecordAddEvent records the add event on this object.
func (h *defaultNetworkClusterControllerEventHandler) RecordAddEvent(obj interface{}) {
}

// Given an object and its type, RecordUpdateEvent records the update event on this object.
func (h *defaultNetworkClusterControllerEventHandler) RecordUpdateEvent(obj interface{}) {
}

// Given an object and its type, RecordDeleteEvent records the delete event on this object. Only used for pods now.
func (h *defaultNetworkClusterControllerEventHandler) RecordDeleteEvent(obj interface{}) {
}

func (h *defaultNetworkClusterControllerEventHandler) RecordSuccessEvent(obj interface{}) {
}

// Given an object and its type, RecordErrorEvent records an error event on this object.
// Only used for pods now.
func (h *defaultNetworkClusterControllerEventHandler) RecordErrorEvent(obj interface{}, reason string, err error) {
}

// Given an object and its type, isResourceScheduled returns true if the object has been scheduled.
func (h *defaultNetworkClusterControllerEventHandler) IsResourceScheduled(obj interface{}) bool {
	return true
}

// Given an object and its type, IsObjectInTerminalState returns true if the object is a in terminal state.
func (h *defaultNetworkClusterControllerEventHandler) IsObjectInTerminalState(obj interface{}) bool {
	return false
}

// Given a *RetryFramework instance, an object to add and a boolean specifying if the function was executed from
// iterateRetryResources, AddResource adds the specified object to the cluster according to its type and
// returns the error, if any, yielded during object creation.
func (h *defaultNetworkClusterControllerEventHandler) AddResource(obj interface{}, fromRetryLoop bool) error {
	var err error

	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *kapi.Node", obj)
		}
		if err = h.ncm.addUpdateNodeEvent(node); err != nil {
			klog.Infof("Node add failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	default:
		return fmt.Errorf("no add function for object type %s", h.objType)
	}
	return nil
}

// Given a *RetryFramework instance, an old and a new object, UpdateResource updates the specified object in the cluster
// to its version in newObj according to its type and returns the error, if any, yielded during the object update.
// The inRetryCache boolean argument is to indicate if the given resource is in the retryCache or not.
func (h *defaultNetworkClusterControllerEventHandler) UpdateResource(oldObj, newObj interface{}, inRetryCache bool) error {
	var err error

	switch h.objType {
	case factory.NodeType:
		node, ok := newObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *kapi.Node", newObj)
		}
		if err = h.ncm.addUpdateNodeEvent(node); err != nil {
			klog.Infof("Node update failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	default:
		return fmt.Errorf("no update function for object type %s", h.objType)
	}
	return nil
}

// Given a *RetryFramework instance, an object and optionally a cachedObj, DeleteResource deletes the object from the cluster
// according to the delete logic of its resource type. cachedObj is the internal cache entry for this object,
// used for now for pods and network policies.
func (h *defaultNetworkClusterControllerEventHandler) DeleteResource(obj, cachedObj interface{}) error {
	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast obj of type %T to *knet.Node", obj)
		}
		return h.ncm.deleteNode(node)
	}
	return nil
}

func (h *defaultNetworkClusterControllerEventHandler) SyncFunc(objs []interface{}) error {
	var syncFunc func([]interface{}) error

	if h.syncFunc != nil {
		// syncFunc was provided explicitly
		syncFunc = h.syncFunc
	} else {
		switch h.objType {
		case factory.NodeType:
			syncFunc = h.ncm.syncNodes

		default:
			return fmt.Errorf("no sync function for object type %s", h.objType)
		}
	}
	if syncFunc == nil {
		return nil
	}
	return syncFunc(objs)
}
