package clustermanager

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	cache "k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/clustermanager/pod"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/clustermanager/subnetallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	objretry "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// networkClusterController is the cluster controller for the networks. An
// instance of this struct is expected to be created for each network. A network
// is identified by its name and its unique id. It handles events at a cluster
// level to support the necessary configuration for the cluster networks.
type networkClusterController struct {
	watchFactory *factory.WatchFactory
	stopChan     chan struct{}
	wg           *sync.WaitGroup

	// node events factory handler
	nodeHandler *factory.Handler

	// retry framework for nodes
	retryNodes *objretry.RetryFramework

	// retry framework for L2 pod ip allocation
	podHandler *factory.Handler
	retryPods  *objretry.RetryFramework

	// unique id of the network
	networkID int

	podIPAllocator      *pod.PodIPAllocator
	hostSubnetAllocator *subnetallocator.HostSubnetAllocator

	util.NetInfo
}

func newNetworkClusterController(networkID int, netInfo util.NetInfo, ovnClient *util.OVNClusterManagerClientset, wf *factory.WatchFactory) *networkClusterController {
	kube := &kube.Kube{
		KClient: ovnClient.KubeClient,
	}

	wg := &sync.WaitGroup{}

	ncc := &networkClusterController{
		NetInfo:      netInfo,
		watchFactory: wf,
		stopChan:     make(chan struct{}),
		wg:           wg,
		networkID:    networkID,
	}

	if ncc.hasNodeSubnetAllocation() {
		ncc.hostSubnetAllocator = subnetallocator.NewHostSubnetAllocator(networkID, netInfo, wf.NodeCoreInformer().Lister(), kube)
	}

	if ncc.hasPodIPAllocation() {
		ncc.podIPAllocator = pod.NewPodIPAllocator(netInfo, wf.PodCoreInformer().Lister(), kube)
	}

	ncc.initRetryFramework()
	return ncc
}

func (ncc *networkClusterController) hasPodIPAllocation() bool {
	// we only do pod IP allocation on L2 topologies with IPAM on interconnect
	switch ncc.TopologyType() {
	case types.Layer2Topology, types.LocalnetTopology:
		return config.OVNKubernetesFeature.EnableInterconnect && len(ncc.Subnets()) > 0
	}
	return false
}

func (ncc *networkClusterController) hasNodeSubnetAllocation() bool {
	// we only do node subnet allocation on L3 topologies or default network
	return ncc.TopologyType() == types.Layer3Topology || !ncc.IsSecondary()
}

func (ncc *networkClusterController) initRetryFramework() {
	if ncc.hasNodeSubnetAllocation() {
		ncc.retryNodes = ncc.newRetryFramework(factory.NodeType, true)
	}

	if ncc.hasPodIPAllocation() {
		ncc.retryPods = ncc.newRetryFramework(factory.PodType, true)
	}
}

// Start the network cluster controller. Depending on the cluster configuration
// and type of network, it does the following:
//   - initializes the host subnet allocator and starts listening to node events
//   - initializes the pod ip allocator and starts listening to pod events
func (ncc *networkClusterController) Start(ctx context.Context) error {
	if ncc.hasNodeSubnetAllocation() {
		err := ncc.hostSubnetAllocator.InitRanges()
		if err != nil {
			return fmt.Errorf("failed to initialize host subnet ip allocator: %w", err)
		}

		nodeHandler, err := ncc.retryNodes.WatchResource()
		if err != nil {
			return fmt.Errorf("unable to watch pods: %w", err)
		}
		ncc.nodeHandler = nodeHandler
	}

	if ncc.hasPodIPAllocation() {
		err := ncc.podIPAllocator.InitRanges()
		if err != nil {
			return fmt.Errorf("failed to initialize pod ip allocator: %w", err)
		}

		podHandler, err := ncc.retryPods.WatchResource()
		if err != nil {
			return fmt.Errorf("unable to watch pods: %w", err)
		}
		ncc.podHandler = podHandler
	}

	return nil
}

func (ncc *networkClusterController) Stop() {
	close(ncc.stopChan)
	ncc.wg.Wait()

	if ncc.nodeHandler != nil {
		ncc.watchFactory.RemoveNodeHandler(ncc.nodeHandler)
	}

	if ncc.podHandler != nil {
		ncc.watchFactory.RemovePodHandler(ncc.podHandler)
	}
}

func (ncc *networkClusterController) newRetryFramework(objectType reflect.Type, hasUpdateFunc bool) *objretry.RetryFramework {
	resourceHandler := &objretry.ResourceHandler{
		HasUpdateFunc:          hasUpdateFunc,
		NeedsUpdateDuringRetry: false,
		ObjType:                objectType,
		EventHandler: &networkClusterControllerEventHandler{
			objType:  objectType,
			ncc:      ncc,
			syncFunc: nil,
		},
	}
	return objretry.NewRetryFramework(ncc.stopChan, ncc.wg, ncc.watchFactory, resourceHandler)
}

// Cleanup the subnet annotations from the node for the secondary networks
func (ncc *networkClusterController) Cleanup(netName string) error {
	if !ncc.IsSecondary() {
		return fmt.Errorf("default network can't be cleaned up")
	}

	if ncc.hasNodeSubnetAllocation() {
		return ncc.hostSubnetAllocator.Cleanup(netName)
	}

	return nil
}

// networkClusterControllerEventHandler object handles the events
// from retry framework.
type networkClusterControllerEventHandler struct {
	objretry.EventHandler

	objType  reflect.Type
	ncc      *networkClusterController
	syncFunc func([]interface{}) error
}

// networkClusterControllerEventHandler functions

// AddResource adds the specified object to the cluster according to its type and
// returns the error, if any, yielded during object creation.
func (h *networkClusterControllerEventHandler) AddResource(obj interface{}, fromRetryLoop bool) error {
	var err error

	switch h.objType {
	case factory.PodType:
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Pod", obj)
		}
		err := h.ncc.podIPAllocator.Reconcile(nil, pod)
		if err != nil {
			klog.Infof("Pod add failed for %s/%s, will try again later: %v",
				pod.Namespace, pod.Name, err)
		}
	case factory.NodeType:
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Node", obj)
		}
		if err = h.ncc.hostSubnetAllocator.HandleAddUpdateNodeEvent(node); err != nil {
			klog.Infof("Node add failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	default:
		return fmt.Errorf("no add function for object type %s", h.objType)
	}
	return nil
}

// UpdateResource updates the specified object in the cluster to its version in newObj according
// to its type and returns the error, if any, yielded during the object update.
// The inRetryCache boolean argument is to indicate if the given resource is in the retryCache or not.
func (h *networkClusterControllerEventHandler) UpdateResource(oldObj, newObj interface{}, inRetryCache bool) error {
	var err error

	switch h.objType {
	case factory.PodType:
		old, ok := oldObj.(*corev1.Pod)
		if !ok {
			return fmt.Errorf("could not cast %T old object to *corev1.Pod", oldObj)
		}
		new, ok := newObj.(*corev1.Pod)
		if !ok {
			return fmt.Errorf("could not cast %T new object to *corev1.Pod", newObj)
		}
		err := h.ncc.podIPAllocator.Reconcile(old, new)
		if err != nil {
			klog.Infof("Pod update failed for %s/%s, will try again later: %v",
				new.Namespace, new.Name, err)
		}
	case factory.NodeType:
		node, ok := newObj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Node", newObj)
		}
		if err = h.ncc.hostSubnetAllocator.HandleAddUpdateNodeEvent(node); err != nil {
			klog.Infof("Node update failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	default:
		return fmt.Errorf("no update function for object type %s", h.objType)
	}
	return nil
}

// DeleteResource deletes the object from the cluster according to the delete logic of its resource type.
// cachedObj is the internal cache entry for this object, used for now for pods and network policies.
func (h *networkClusterControllerEventHandler) DeleteResource(obj, cachedObj interface{}) error {
	switch h.objType {
	case factory.PodType:
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Pod", obj)
		}
		err := h.ncc.podIPAllocator.Reconcile(pod, nil)
		if err != nil {
			klog.Infof("Pod delete failed for %s/%s, will try again later: %v",
				pod.Namespace, pod.Name, err)
		}
	case factory.NodeType:
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast obj of type %T to *knet.Node", obj)
		}
		return h.ncc.hostSubnetAllocator.HandleDeleteNode(node)
	}
	return nil
}

func (h *networkClusterControllerEventHandler) SyncFunc(objs []interface{}) error {
	var syncFunc func([]interface{}) error

	if h.syncFunc != nil {
		// syncFunc was provided explicitly
		syncFunc = h.syncFunc
	} else {
		switch h.objType {
		case factory.PodType:
			syncFunc = h.ncc.podIPAllocator.Sync
		case factory.NodeType:
			syncFunc = h.ncc.hostSubnetAllocator.Sync

		default:
			return fmt.Errorf("no sync function for object type %s", h.objType)
		}
	}
	if syncFunc == nil {
		return nil
	}
	return syncFunc(objs)
}

// RecordAddEvent records the add event on this object. Not used here.
func (h *networkClusterControllerEventHandler) RecordAddEvent(obj interface{}) {
}

// RecordUpdateEvent records the update event on this object. Not used here.
func (h *networkClusterControllerEventHandler) RecordUpdateEvent(obj interface{}) {
}

// RecordDeleteEvent records the delete event on this object. Not used here.
func (h *networkClusterControllerEventHandler) RecordDeleteEvent(obj interface{}) {
}

func (h *networkClusterControllerEventHandler) RecordSuccessEvent(obj interface{}) {
}

// RecordErrorEvent records an error event on this object. Not used here.
func (h *networkClusterControllerEventHandler) RecordErrorEvent(obj interface{}, reason string, err error) {
}

// isResourceScheduled returns true if the object has been scheduled.  Always returns true.
func (h *networkClusterControllerEventHandler) IsResourceScheduled(obj interface{}) bool {
	return true
}

// IsObjectInTerminalState returns true if the object is a in terminal state.  Always returns false.
func (h *networkClusterControllerEventHandler) IsObjectInTerminalState(obj interface{}) bool {
	// Note: the pod IP allocator needs to be aware when pods are deleted
	return false
}

func (h *networkClusterControllerEventHandler) AreResourcesEqual(obj1, obj2 interface{}) (bool, error) {
	// switch based on type
	if h.objType == factory.NodeType {
		node1, ok := obj1.(*corev1.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj1 of type %T to *corev1.Node", obj1)
		}
		node2, ok := obj2.(*corev1.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type %T to *corev1.Node", obj2)
		}

		// network cluster controller only updates the node/hybrid subnet annotations.
		// Check if the annotations have changed.
		return reflect.DeepEqual(node1.Annotations, node2.Annotations), nil
	}

	return false, nil
}

// GetInternalCacheEntry returns the internal cache entry for this object
func (h *networkClusterControllerEventHandler) GetInternalCacheEntry(obj interface{}) interface{} {
	return nil
}

// getResourceFromInformerCache returns the latest state of the object from the informers cache
// given an object key and its type
func (h *networkClusterControllerEventHandler) GetResourceFromInformerCache(key string) (interface{}, error) {
	var obj interface{}
	var namespace, name string
	var err error

	namespace, name, err = cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to split key %s: %v", key, err)
	}

	switch h.objType {
	case factory.NodeType:
		obj, err = h.ncc.watchFactory.GetNode(name)
	case factory.PodType:
		obj, err = h.ncc.watchFactory.GetPod(namespace, name)
	default:
		err = fmt.Errorf("object type %s not supported, cannot retrieve it from informers cache",
			h.objType)
	}
	return obj, err
}
