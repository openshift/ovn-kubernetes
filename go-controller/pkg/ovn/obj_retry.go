package ovn

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	kerrorsutil "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/cache"

	"k8s.io/klog/v2"

	factory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const retryObjInterval = 30 * time.Second

// retryObjEntry is a generic object caching with retry mechanism
//that resources can use to eventually complete their intended operations.
type retryObjEntry struct {
	// newObj holds k8s resource failed during add operation
	newObj interface{}
	// oldObj holds k8s resource failed during delete operation
	oldObj interface{}
	// config holds feature specific configuration
	// Note: currently used by network policy resource.
	config     interface{}
	timeStamp  time.Time
	backoffSec time.Duration
	// whether to include this object in the retry iterations
	ignore bool
}

type retryObjs struct {
	retryMutex sync.Mutex
	// cache to hold object needs retry to successfully complete processing
	entries map[string]*retryObjEntry
	// resource type for these objects
	oType reflect.Type
	// channel to indicate we need to retry objs immediately
	retryChan chan struct{}
	// namespace filter fed to the handler for this resource type
	namespaceForFilteredHandler string
	// label selector fed to the handler for this resource type
	labelSelectorForFilteredHandler labels.Selector
	// sync function for the handler
	syncFunc func([]interface{}) error
	// extra parameters needed by specific types, for now
	// in use by network policy dynamic handlers
	extraParameters interface{}
}

// NewRetryObjs returns a new retryObjs instance, packed with the desired input parameters.
// The returned struct is essential for watchResource and the whole retry logic.
func NewRetryObjs(
	objectType reflect.Type,
	namespaceForFilteredHandler string,
	labelSelectorForFilteredHandler labels.Selector,
	syncFunc func([]interface{}) error,
	extraParameters interface{}) *retryObjs {

	return &retryObjs{
		retryMutex:                      sync.Mutex{},
		entries:                         make(map[string]*retryObjEntry),
		retryChan:                       make(chan struct{}, 1),
		oType:                           objectType,
		namespaceForFilteredHandler:     namespaceForFilteredHandler,
		labelSelectorForFilteredHandler: labelSelectorForFilteredHandler,
		syncFunc:                        syncFunc,
		extraParameters:                 extraParameters,
	}
}

// addRetryObj adds an object to be retried later for an add event
func (r *retryObjs) addRetryObj(obj interface{}) {
	key, err := getResourceKey(r.oType, obj)
	if err != nil {
		klog.Errorf("Could not get the key of %v %v: %v", r.oType, obj, err)
		return
	}
	r.initRetryObjWithAdd(obj, key)
	r.unSkipRetryObj(key)
}

// initRetryObjWithAdd tracks an object that failed to be created to potentially retry later
// initially it is marked as skipped for retry loop (ignore = true)
func (r *retryObjs) initRetryObjWithAdd(obj interface{}, key string) {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	if entry, ok := r.entries[key]; ok {
		entry.timeStamp = time.Now()
		entry.newObj = obj
	} else {
		r.entries[key] = &retryObjEntry{newObj: obj,
			timeStamp: time.Now(), backoffSec: 1, ignore: true}
	}
}

// initRetryWithDelete tracks an object that failed to be deleted to potentially retry later
// initially it is marked as skipped for retry loop (ignore = true)
func (r *retryObjs) initRetryObjWithDelete(obj interface{}, key string, config interface{}) {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	if entry, ok := r.entries[key]; ok {
		entry.timeStamp = time.Now()
		entry.oldObj = obj
		if entry.config == nil {
			entry.config = config
		}
	} else {
		r.entries[key] = &retryObjEntry{oldObj: obj, config: config,
			timeStamp: time.Now(), backoffSec: 1, ignore: true}
	}
}

// addDeleteToRetryObj adds an old object that needs to be cleaned up to a retry object
// includes the config object as well in case the namespace is removed and the object is orphaned from
// the namespace
func (r *retryObjs) addDeleteToRetryObj(obj interface{}, key string, config interface{}) {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	if entry, ok := r.entries[key]; ok {
		entry.oldObj = obj
		entry.config = config
	}
}

// removeDeleteFromRetryObj removes any old object from a retry entry
func (r *retryObjs) removeDeleteFromRetryObj(key string) {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	if entry, ok := r.entries[key]; ok {
		entry.oldObj = nil
		entry.config = nil
	}
}

// unSkipRetryObj ensures an obj is no longer ignored for retry loop
func (r *retryObjs) unSkipRetryObj(key string) {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	if entry, ok := r.entries[key]; ok {
		entry.ignore = false
	}
}

// deleteRetryObj deletes a specific entry from the map
func (r *retryObjs) deleteRetryObj(key string, withLock bool) {
	if withLock {
		r.retryMutex.Lock()
		defer r.retryMutex.Unlock()
	}
	delete(r.entries, key)
}

// skipRetryObj sets a specific entry from the map to be ignored for subsequent retries
func (r *retryObjs) skipRetryObj(key string) {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	if entry, ok := r.entries[key]; ok {
		entry.ignore = true
	}
}

// checkRetryObj returns true if an entry with the given key exists, returns false otherwise.
func (r *retryObjs) checkRetryObj(key string) bool {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	_, ok := r.entries[key]
	return ok
}

// requestRetryObjs allows a caller to immediately request to iterate through all objects that
// are in the retry cache. This will ignore any outstanding time wait/backoff state
func (r *retryObjs) requestRetryObjs() {
	select {
	case r.retryChan <- struct{}{}:
		klog.V(5).Infof("Iterate retry objects requested (resource %v)", r.oType)
	default:
		klog.V(5).Infof("Iterate retry objects already requested (resource %v)", r.oType)
	}
}

//getObjRetryEntry returns a copy of an object  retry entry from the cache
func (r *retryObjs) getObjRetryEntry(key string) *retryObjEntry {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	if entry, ok := r.entries[key]; ok {
		x := *entry
		return &x
	}
	return nil
}

var sep = "/"

func splitNamespacedName(namespacedName string) (string, string) {
	if strings.Contains(namespacedName, sep) {
		s := strings.SplitN(namespacedName, sep, 2)
		if len(s) == 2 {
			return s[0], s[1]
		}
	}
	return namespacedName, ""
}

func getNamespacedName(namespace, name string) string {
	return namespace + sep + name
}

// hasResourceAnUpdateFunc returns true if the given resource type has a dedicated update function.
// It returns false if, upon an update event on this resource type, we instead need to first delete the old
// object and then add the new one.
func hasResourceAnUpdateFunc(objType reflect.Type) bool {
	switch objType {
	case factory.PodType,
		factory.NodeType,
		factory.PeerPodSelectorType,
		factory.PeerPodForNamespaceAndPodSelectorType,
		factory.LocalPodSelectorType:
		return true
	}
	return false
}

// areResourcesEqual returns true if, given two objects of a known resource type, the update logic for this resource
// type considers them equal and therefore no update is needed. It returns false when the two objects are not considered
// equal and an update needs be executed. This is regardless of how the update is carried out (whether with a dedicated update
// function or with a delete on the old obj followed by an add on the new obj).
func areResourcesEqual(objType reflect.Type, obj1, obj2 interface{}) (bool, error) {
	// switch based on type
	switch objType {
	case factory.PolicyType:
		np1, ok := obj1.(*knet.NetworkPolicy)
		if !ok {
			return false, fmt.Errorf("could not cast obj1 of type interface{} to *knet.NetworkPolicy")
		}
		np2, ok := obj2.(*knet.NetworkPolicy)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type interface{}  to *knet.NetworkPolicy")
		}
		return reflect.DeepEqual(np1, np2), nil

	case factory.NodeType:
		node1, ok := obj1.(*kapi.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj1 of type interface{} to *kapi.Node")
		}
		node2, ok := obj2.(*kapi.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type interface{} to *kapi.Node")
		}

		// when shouldUpdate is false, the hostsubnet is not assigned by ovn-kubernetes
		shouldUpdate, err := shouldUpdate(node2, node1)
		if err != nil {
			klog.Errorf(err.Error())
		}
		return !shouldUpdate, nil

	case factory.PeerServiceType:
		service1, ok := obj1.(*kapi.Service)
		if !ok {
			return false, fmt.Errorf("could not cast obj1 of type interface{} to *kapi.Service")
		}
		service2, ok := obj2.(*kapi.Service)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type interface{} to *kapi.Service")
		}
		areEqual := reflect.DeepEqual(service1.Spec.ExternalIPs, service2.Spec.ExternalIPs) &&
			reflect.DeepEqual(service1.Spec.ClusterIP, service2.Spec.ClusterIP) &&
			reflect.DeepEqual(service1.Spec.ClusterIPs, service2.Spec.ClusterIPs) &&
			reflect.DeepEqual(service1.Spec.Type, service2.Spec.Type) &&
			reflect.DeepEqual(service1.Status.LoadBalancer.Ingress, service2.Status.LoadBalancer.Ingress)
		return areEqual, nil

	case factory.PodType,
		factory.PeerPodSelectorType,
		factory.PeerPodForNamespaceAndPodSelectorType,
		factory.LocalPodSelectorType:
		// For these types, there was no old vs new obj comparison in the original update code,
		// so pretend they're always different so that the update code gets executed
		return false, nil

	case factory.PeerNamespaceSelectorType,
		factory.PeerNamespaceAndPodSelectorType:
		// For these types there is no update code, so pretend old and new
		// objs are always equivalent and stop processing the update event.
		return true, nil
	}

	return false, fmt.Errorf("no object comparison for type %v", objType)
}

// Given an object and its type, it returns the key for this object and an error if the key retrieval failed.
// For all namespaced resources, the key will be namespace/name. For resource types without a namespace,
// the key will be the object name itself.
func getResourceKey(objType reflect.Type, obj interface{}) (string, error) {
	switch objType {
	case factory.PolicyType:
		np, ok := obj.(*knet.NetworkPolicy)
		if !ok {
			return "", fmt.Errorf("could not cast interface{} object to *knet.NetworkPolicy")
		}
		return getPolicyNamespacedName(np), nil

	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return "", fmt.Errorf("could not cast interface{} object to *kapi.Node")
		}
		return node.Name, nil

	case factory.PeerServiceType:
		service, ok := obj.(*kapi.Service)
		if !ok {
			return "", fmt.Errorf("could not cast interface{} object to *kapi.Service")
		}
		return getNamespacedName(service.Namespace, service.Name), nil

	case factory.PodType,
		factory.PeerPodSelectorType,
		factory.PeerPodForNamespaceAndPodSelectorType,
		factory.LocalPodSelectorType:
		pod, ok := obj.(*kapi.Pod)
		if !ok {
			return "", fmt.Errorf("could not cast interface{} object to *kapi.Pod")
		}
		return getNamespacedName(pod.Namespace, pod.Name), nil

	case factory.PeerNamespaceAndPodSelectorType,
		factory.PeerNamespaceSelectorType:
		namespace, ok := obj.(*kapi.Namespace)
		if !ok {
			return "", fmt.Errorf("could not cast interface{} object to *kapi.Namespace")
		}
		return namespace.Name, nil
	}

	return "", fmt.Errorf("object type %v not supported", objType)
}

func (oc *Controller) getPortInfo(pod *kapi.Pod) *lpInfo {
	var portInfo *lpInfo
	key := util.GetLogicalPortName(pod.Namespace, pod.Name)
	if !util.PodWantsNetwork(pod) {
		// create dummy logicalPortInfo for host-networked pods
		mac, _ := net.ParseMAC("00:00:00:00:00:00")
		portInfo = &lpInfo{
			logicalSwitch: "host-networked",
			name:          key,
			uuid:          "host-networked",
			ips:           []*net.IPNet{},
			mac:           mac,
		}
	} else {
		portInfo, _ = oc.logicalPortCache.get(key)
	}
	return portInfo
}

// Given an object and its type, getInternalCacheEntry returns the internal cache entry for this object.
// This is now used only for pods, which will get their the logical port cache entry.
func (oc *Controller) getInternalCacheEntry(objType reflect.Type, obj interface{}) interface{} {
	switch objType {
	case factory.PodType:
		pod := obj.(*kapi.Pod)
		return oc.getPortInfo(pod)
	default:
		return nil
	}
}

// Given an object key and its type, getResourceFromInformerCache returns the latest state of the object
// from the informers cache.
func (oc *Controller) getResourceFromInformerCache(objType reflect.Type, key string) (interface{}, error) {
	var obj interface{}
	var err error

	switch objType {
	case factory.PolicyType:
		namespace, name := splitNamespacedName(key)
		obj, err = oc.watchFactory.GetNetworkPolicy(namespace, name)

	case factory.NodeType:
		obj, err = oc.watchFactory.GetNode(key)

	case factory.PeerServiceType:
		namespace, name := splitNamespacedName(key)
		obj, err = oc.watchFactory.GetService(namespace, name)

	case factory.PodType,
		factory.PeerPodSelectorType,
		factory.PeerPodForNamespaceAndPodSelectorType,
		factory.LocalPodSelectorType:
		namespace, name := splitNamespacedName(key)
		obj, err = oc.watchFactory.GetPod(namespace, name)

	case factory.PeerNamespaceAndPodSelectorType,
		factory.PeerNamespaceSelectorType:
		obj, err = oc.watchFactory.GetNamespace(key)

	default:
		err = fmt.Errorf("object type %v not supported, cannot retrieve it from informers cache",
			objType)
	}
	return obj, err
}

// Given an object and its type, recordAddEvent records the add event on this object. Only used for pods now.
func (oc *Controller) recordAddEvent(objType reflect.Type, obj interface{}) {
	switch objType {
	case factory.PodType:
		klog.V(5).Infof("Recording add event on pod")
		pod := obj.(*kapi.Pod)
		oc.metricsRecorder.AddPod(pod.UID)
	}
}

// Given an object and its type, recordDeleteEvent records the delete event on this object. Only used for pods now.
func (oc *Controller) recordDeleteEvent(objType reflect.Type, obj interface{}) {
	switch objType {
	case factory.PodType:
		klog.V(5).Infof("Recording add event on pod")
		pod := obj.(*kapi.Pod)
		oc.metricsRecorder.CleanPod(pod.UID)
	}
}

// Given an object and its type, recordErrorEvent records an error event on this object. Only used for pods now.
func (oc *Controller) recordErrorEvent(objType reflect.Type, obj interface{}, err error) {
	switch objType {
	case factory.PodType:
		klog.V(5).Infof("Recording error event on pod")
		pod := obj.(*kapi.Pod)
		oc.metricsRecorder.AddPod(pod.UID)
		oc.recordPodEvent(err, pod)
	}
}

// Given an object and its type, isResourceScheduled returns true if the object has been scheduled.
// Only applied to pods for now. Returns true for all other types.
func isResourceScheduled(objType reflect.Type, obj interface{}) bool {
	switch objType {
	case factory.PodType:
		pod := obj.(*kapi.Pod)
		return util.PodScheduled(pod)
	}
	return true
}

// Given a *retryObjs instance, an object to add and a boolean specifying if the function was executed from
// iterateRetryResources, addResource adds the specified object to the cluster according to its type and
// returns the error, if any, yielded during object creation.
func (oc *Controller) addResource(objectsToRetry *retryObjs, obj interface{}, fromRetryLoop bool) error {
	var err error

	switch objectsToRetry.oType {
	case factory.PodType:
		pod, ok := obj.(*kapi.Pod)
		if !ok {
			return fmt.Errorf("could not cast interface{} object to *knet.Pod")
		}
		return oc.ensurePod(nil, pod, true)

	case factory.PolicyType:
		np, ok := obj.(*knet.NetworkPolicy)
		if !ok {
			return fmt.Errorf("could not cast interface{} object to *knet.NetworkPolicy")
		}
		if err = oc.addNetworkPolicy(np); err != nil {
			klog.Infof("Network Policy retry delete failed for %s/%s, will try again later: %v",
				np.Namespace, np.Name, err)
			return err
		}

	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast interface{} object to *kapi.Node")
		}
		var nodeParams *nodeSyncs
		if fromRetryLoop {
			_, nodeSync := oc.addNodeFailed.Load(node.Name)
			_, clusterRtrSync := oc.nodeClusterRouterPortFailed.Load(node.Name)
			_, mgmtSync := oc.mgmtPortFailed.Load(node.Name)
			_, gwSync := oc.gatewaysFailed.Load(node.Name)
			nodeParams = &nodeSyncs{
				nodeSync,
				clusterRtrSync,
				mgmtSync,
				gwSync}
		} else {
			nodeParams = &nodeSyncs{true, true, true, true}
		}

		if err = oc.addUpdateNodeEvent(node, nodeParams); err != nil {
			klog.Infof("Node retry delete failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}

	case factory.PeerServiceType:
		service, ok := obj.(*kapi.Service)
		if !ok {
			return fmt.Errorf("could not cast peer service of type interface{} to *kapi.Service")
		}
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handlePeerServiceAdd(extraParameters.gp, service)

	case factory.PeerPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handlePeerPodSelectorAddUpdate(extraParameters.gp, obj)

	case factory.PeerNamespaceAndPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		namespace := obj.(*kapi.Namespace)
		extraParameters.np.RLock()
		alreadyDeleted := extraParameters.np.deleted
		extraParameters.np.RUnlock()
		if alreadyDeleted {
			return nil
		}

		// start watching pods in this namespace and selected by the label selector in extraParameters.podSelector
		retryPeerPods := NewRetryObjs(
			factory.PeerPodForNamespaceAndPodSelectorType,
			namespace.Name,
			extraParameters.podSelector,
			nil,
			&NetworkPolicyExtraParameters{gp: extraParameters.gp},
		)
		// The AddFilteredPodHandler call might call handlePeerPodSelectorAddUpdate
		// on existing pods so we can't be holding the lock at this point
		podHandler := oc.WatchResource(retryPeerPods)

		extraParameters.np.Lock()
		defer extraParameters.np.Unlock()
		if extraParameters.np.deleted {
			oc.watchFactory.RemovePodHandler(podHandler)
			return nil
		}
		extraParameters.np.podHandlerList = append(extraParameters.np.podHandlerList, podHandler)

	case factory.PeerPodForNamespaceAndPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handlePeerPodSelectorAddUpdate(extraParameters.gp, obj)

	case factory.PeerNamespaceSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		namespace := obj.(*kapi.Namespace)
		// Update the ACL ...
		return oc.handlePeerNamespaceSelectorOnUpdate(extraParameters.np, extraParameters.gp, func() bool {
			// ... on condition that the added address set was not already in the 'gress policy
			return extraParameters.gp.addNamespaceAddressSet(namespace.Name)
		})

	case factory.LocalPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handleLocalPodSelectorAddFunc(
			extraParameters.policy,
			extraParameters.np,
			extraParameters.portGroupIngressDenyName,
			extraParameters.portGroupEgressDenyName,
			obj)

	default:
		return fmt.Errorf("no add function for object type %v", objectsToRetry.oType)
	}

	return nil
}

// Given a *retryObjs instance, an old and a new object, updateResource updates the specified object in the cluster
// to its version in newObj according to its type and returns the error, if any, yielded during the object update.
func (oc *Controller) updateResource(objectsToRetry *retryObjs, oldObj, newObj interface{}) error {
	switch objectsToRetry.oType {
	case factory.PodType:
		oldPod := oldObj.(*kapi.Pod)
		newPod := newObj.(*kapi.Pod)
		newKey, err := getResourceKey(objectsToRetry.oType, newObj)
		if err != nil {
			return err
		}
		return oc.ensurePod(oldPod, newPod, objectsToRetry.checkRetryObj(newKey))

	case factory.NodeType:
		newNode, ok := newObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast newObj of type interface{} to *kapi.Node")
		}
		oldNode, ok := oldObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast oldObj of type interface{} to *kapi.Node")
		}
		// determine what actually changed in this update
		_, nodeSync := oc.addNodeFailed.Load(newNode.Name)
		_, failed := oc.nodeClusterRouterPortFailed.Load(newNode.Name)
		clusterRtrSync := failed || nodeChassisChanged(oldNode, newNode) || nodeSubnetChanged(oldNode, newNode)
		_, failed = oc.mgmtPortFailed.Load(newNode.Name)
		mgmtSync := failed || macAddressChanged(oldNode, newNode) || nodeSubnetChanged(oldNode, newNode)
		_, failed = oc.gatewaysFailed.Load(newNode.Name)
		gwSync := (failed || gatewayChanged(oldNode, newNode) ||
			nodeSubnetChanged(oldNode, newNode) || hostAddressesChanged(oldNode, newNode))

		return oc.addUpdateNodeEvent(newNode, &nodeSyncs{nodeSync, clusterRtrSync, mgmtSync, gwSync})

	case factory.PeerPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handlePeerPodSelectorAddUpdate(extraParameters.gp, newObj)

	case factory.PeerPodForNamespaceAndPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handlePeerPodSelectorAddUpdate(extraParameters.gp, newObj)

	case factory.LocalPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handleLocalPodSelectorAddFunc(
			extraParameters.policy,
			extraParameters.np,
			extraParameters.portGroupIngressDenyName,
			extraParameters.portGroupEgressDenyName,
			newObj)
	}

	return fmt.Errorf("no update function for object type %v", objectsToRetry.oType)
}

// Given a *retryObjs instance, an object and optionally a cachedObj, deleteResource deletes the object from the cluster
// according to the delete logic of its resource type. cachedObj is the internal cache entry for this object,
// used for now for pods and network policies.
func (oc *Controller) deleteResource(objectsToRetry *retryObjs, obj, cachedObj interface{}) error {
	switch objectsToRetry.oType {
	case factory.PodType:
		var portInfo *lpInfo
		pod := obj.(*kapi.Pod)
		if cachedObj != nil {
			portInfo = cachedObj.(*lpInfo)
		}
		oc.logicalPortCache.remove(util.GetLogicalPortName(pod.Namespace, pod.Name))
		return oc.removePod(pod, portInfo)

	case factory.PolicyType:
		var cachedNP *networkPolicy
		knp, ok := obj.(*knet.NetworkPolicy)
		if !ok {
			return fmt.Errorf("could not cast obj of type interface{} to *knet.NetworkPolicy")
		}
		if cachedObj != nil {
			if cachedNP, ok = cachedObj.(*networkPolicy); !ok {
				cachedNP = nil
			}
		}
		return oc.deleteNetworkPolicy(knp, cachedNP)

	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast obj of type interface{} to *knet.Node")
		}
		return oc.deleteNodeEvent(node)

	case factory.PeerServiceType:
		service, ok := obj.(*kapi.Service)
		if !ok {
			return fmt.Errorf("could not cast peer service of type interface{} to *kapi.Service")
		}
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handlePeerServiceDelete(extraParameters.gp, service)

	case factory.PeerPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handlePeerPodSelectorDelete(extraParameters.gp, obj)

	case factory.PeerNamespaceAndPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		// when the namespace labels no longer apply
		// remove the namespaces pods from the address_set
		var errs []error
		namespace := obj.(*kapi.Namespace)
		pods, _ := oc.watchFactory.GetPods(namespace.Name)

		for _, pod := range pods {
			if err := oc.handlePeerPodSelectorDelete(extraParameters.gp, pod); err != nil {
				errs = append(errs, err)
			}
		}
		return kerrorsutil.NewAggregate(errs)

	case factory.PeerPodForNamespaceAndPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handlePeerPodSelectorDelete(extraParameters.gp, obj)

	case factory.PeerNamespaceSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		namespace := obj.(*kapi.Namespace)
		// Remove namespace address set from the *gress policy in cache
		// (done in gress.delNamespaceAddressSet()), and then update ACLs
		return oc.handlePeerNamespaceSelectorOnUpdate(extraParameters.np, extraParameters.gp, func() bool {
			// ... on condition that the removed address set was in the 'gress policy
			return extraParameters.gp.delNamespaceAddressSet(namespace.Name)
		})

	case factory.PeerPodForNamespaceAndPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handleLocalPodSelectorDelFunc(
			extraParameters.policy,
			extraParameters.np,
			extraParameters.portGroupIngressDenyName,
			extraParameters.portGroupEgressDenyName,
			obj)

	case factory.LocalPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handleLocalPodSelectorDelFunc(
			extraParameters.policy,
			extraParameters.np,
			extraParameters.portGroupIngressDenyName,
			extraParameters.portGroupEgressDenyName,
			obj)

	default:
		return fmt.Errorf("object type %v not supported", objectsToRetry.oType)
	}
}

// iterateRetryResources checks if any outstanding resource objects exist and if so it tries to
// re-add them. updateAll forces all objects to be attempted to be retried regardless.
func (oc *Controller) iterateRetryResources(r *retryObjs, updateAll bool) {
	r.retryMutex.Lock()
	defer r.retryMutex.Unlock()
	now := time.Now()
	for objKey, entry := range r.entries {
		if entry.ignore {
			continue
		}
		// check if we need to create the resource object
		if entry.newObj != nil {
			// get the latest version of the resource object from the informer;
			// if it doesn't exist we are not going to create the new object.
			obj, err := oc.getResourceFromInformerCache(r.oType, objKey)
			if err != nil {
				if kerrors.IsNotFound(err) {
					klog.Infof("%v %s not found in the informers cache,"+
						" not going to retry object create", r.oType, objKey)
					entry.newObj = nil
				} else {
					klog.Errorf("Failed to look up %v %s in the informers cache,"+
						" will retry later: %v", r.oType, objKey, err)
					continue
				}
			} else {
				entry.newObj = obj
			}
		}

		entry.backoffSec = entry.backoffSec * 2
		if entry.backoffSec > 60 {
			entry.backoffSec = 60
		}
		backoff := (entry.backoffSec * time.Second) + (time.Duration(rand.Intn(500)) * time.Millisecond)
		objTimer := entry.timeStamp.Add(backoff)
		if !updateAll && now.Before(objTimer) {
			klog.V(5).Infof("%v retry %s not after timer yet, time: %s", r.oType, objKey, objTimer)
			continue
		}

		klog.Infof("%v %s: retry object setup", r.oType, objKey)

		// delete old object if needed
		if entry.oldObj != nil {
			klog.Infof("%v retry: removing old object for %s", r.oType, objKey)
			if !isResourceScheduled(r.oType, entry.oldObj) {
				klog.V(5).Infof("Retry: %s %s not scheduled", r.oType, objKey)
				continue
			}
			if err := oc.deleteResource(r, entry.oldObj, entry.config); err != nil {
				klog.Infof("%v retry delete failed for %s, will try again later: %v", r.oType, objKey, err)
				entry.timeStamp = time.Now()
				continue
			}
			// successfully cleaned up old object, remove it from the retry cache
			entry.oldObj = nil
		}

		// create new object if needed
		if entry.newObj != nil {
			klog.Infof("%v retry: creating object for %s", r.oType, objKey)
			if !isResourceScheduled(r.oType, entry.newObj) {
				klog.V(5).Infof("Retry: %s %s not scheduled", r.oType, objKey)
				continue
			}
			if err := oc.addResource(r, entry.newObj, true); err != nil {
				klog.Infof("%v retry create failed for %s, will try again later: %v", r.oType, objKey, err)
				entry.timeStamp = time.Now()
				continue
			}
			// successfully cleaned up old object, remove it from the retry cache
			entry.newObj = nil
		}

		klog.Infof("%v retry successful for %s", r.oType, objKey)
		r.deleteRetryObj(objKey, false)

	}
}

// periodicallyRetryResources tracks retryObjs and checks if any object needs to be retried for add or delete every
// retryObjInterval seconds or when requested through retryChan.
func (oc *Controller) periodicallyRetryResources(r *retryObjs) {
	for {
		select {
		case <-time.After(retryObjInterval):
			klog.V(5).Infof("%s s have elapsed, retrying failed objects of type %v", retryObjInterval, r.oType)
			oc.iterateRetryResources(r, false)

		case <-r.retryChan:
			klog.V(5).Infof("Retry channel got triggered: retrying failed objects of type %v", r.oType)
			oc.iterateRetryResources(r, true)

		case <-oc.stopChan:
			klog.V(5).Infof("Stop channel got triggered: will stop retrying failed objects of type %v", r.oType)
			return
		}
	}
}

// Given a *retryObjs instance, getSyncResourcesFunc retuns the sync function for a given resource type.
// This will be then called on all existing objects when a watcher is started.
func (oc *Controller) getSyncResourcesFunc(r *retryObjs) (func([]interface{}), error) {

	var syncRetriableFunc func([]interface{}) error
	var syncFunc func([]interface{})
	var name string

	// If a type needs a retriable sync funcion, it will set syncRetriableFunc
	// and will keep syncFunc=nil. For a non-retriable sync func,
	// it will directly set syncFunc.
	switch r.oType {
	case factory.PodType:
		name = "SyncPods"
		syncRetriableFunc = oc.syncPodsRetriable

	case factory.PolicyType:
		name = "syncNetworkPolicies"
		syncRetriableFunc = oc.syncNetworkPolicies

	case factory.NodeType:
		name = "syncNodes"
		syncRetriableFunc = oc.syncNodesRetriable

	case factory.PeerServiceType,
		factory.PeerNamespaceAndPodSelectorType:
		name = ""
		syncRetriableFunc = nil

	case factory.PeerPodSelectorType:
		name = "PeerPodSelector"
		extraParameters := r.extraParameters.(*NetworkPolicyExtraParameters)
		syncRetriableFunc = func(objs []interface{}) error {
			return oc.handlePeerPodSelectorAddUpdate(extraParameters.gp, objs...)
		}

	case factory.PeerPodForNamespaceAndPodSelectorType:
		name = "PeerPodForNamespaceAndPodSelector"
		extraParameters := r.extraParameters.(*NetworkPolicyExtraParameters)
		syncRetriableFunc = func(objs []interface{}) error {
			return oc.handlePeerPodSelectorAddUpdate(extraParameters.gp, objs...)
		}

	case factory.PeerNamespaceSelectorType:
		name = "PeerNamespaceSelector"
		extraParameters := r.extraParameters.(*NetworkPolicyExtraParameters)
		// the function below will never fail, so there's no point in making it retriable...
		syncFunc = func(i []interface{}) {
			// This needs to be a write lock because there's no locking around 'gress policies
			extraParameters.np.Lock()
			defer extraParameters.np.Unlock()
			// We load the existing address set into the 'gress policy.
			// Notice that this will make the AddFunc for this initial
			// address set a noop.
			// The ACL must be set explicitly after setting up this handler
			// for the address set to be considered.
			extraParameters.gp.addNamespaceAddressSets(i)
		}

	case factory.LocalPodSelectorType:
		name = "LocalPodSelectorType"
		syncRetriableFunc = r.syncFunc

	default:
		return nil, fmt.Errorf("no sync function for object type %v", r.oType)
	}

	if syncFunc == nil {
		syncFunc = func(objects []interface{}) {
			if syncRetriableFunc == nil {
				return
			}
			oc.syncWithRetry(name, func() error { return syncRetriableFunc(objects) })
		}
	}
	return syncFunc, nil
}

// Given an object and its type, isObjectInTerminalState returns true if the object is a in terminal state.
// This is used now for pods that are either in a PodSucceeded or in a PodFailed state.
func (oc *Controller) isObjectInTerminalState(objType reflect.Type, obj interface{}) bool {
	switch objType {
	case factory.PodType,
		factory.PeerPodSelectorType,
		factory.PeerPodForNamespaceAndPodSelectorType,
		factory.LocalPodSelectorType:
		pod := obj.(*kapi.Pod)
		return util.PodCompleted(pod)

	default:
		return false
	}
}

type resourceEvent string

var (
	resourceEventAdd    resourceEvent = "add"
	resourceEventUpdate resourceEvent = "update"
)

// processObjectInTerminalState is executed when an object has been added or updated and is actually in a terminal state
// already. The add or update event is not valid for such object, which we now remove from the cluster in order to
// free its resources. (for now, this applies to completed pods)
func (oc *Controller) processObjectInTerminalState(objectsToRetry *retryObjs, obj interface{}, key string, event resourceEvent) {
	// The object is in a terminal state: delete it from the cluster, delete its retry entry and return.
	klog.Infof("Detected object %s of type %v in terminal state (e.g. completed)"+
		" during %s event: will remove it", key, objectsToRetry.oType, event)

	internalCacheEntry := oc.getInternalCacheEntry(objectsToRetry.oType, obj)
	objectsToRetry.initRetryObjWithDelete(obj, key, internalCacheEntry) // set up the retry obj for deletion
	if retryEntry := objectsToRetry.getObjRetryEntry(key); retryEntry != nil {
		// retryEntry shouldn't be nil since we've just added the obj to objectsToRetry
		retryEntry.newObj = nil // will not be retried for addition
	}

	if err := oc.deleteResource(objectsToRetry, obj, internalCacheEntry); err != nil {
		klog.Errorf("Failed to delete object %s of type %v in terminal state, during %s event: %v",
			key, objectsToRetry.oType, event, err)
		oc.recordErrorEvent(objectsToRetry.oType, obj, err)
		objectsToRetry.unSkipRetryObj(key)
		return
	}
	objectsToRetry.removeDeleteFromRetryObj(key)
	objectsToRetry.deleteRetryObj(key, true)
}

// WatchResource starts the watching of a resource type, manages its retry entries and calls
// back the appropriate handler logic. It also starts a goroutine that goes over all retry objects
// periodically or when explicitly requested.
// Note: when applying WatchResource to a new resource type, the appropriate resource-specific logic must be added to the
// the different methods it calls.
func (oc *Controller) WatchResource(objectsToRetry *retryObjs) *factory.Handler {
	// track the retry entries and every 30 seconds (or upon explicit request) check if any objects
	// need to be retried
	go oc.periodicallyRetryResources(objectsToRetry)

	addHandlerFunc, err := oc.watchFactory.GetResourceHandlerFunc(objectsToRetry.oType)
	if err != nil {
		klog.Errorf("No resource handler function found for resource %v. "+
			"Cannot watch this resource.", objectsToRetry.oType)
		return nil
	}
	syncFunc, err := oc.getSyncResourcesFunc(objectsToRetry)
	if err != nil {
		klog.Errorf("No sync function found for resource %v. "+
			"Cannot watch this resource.", objectsToRetry.oType)
		return nil
	}

	// create the actual watcher
	handler := addHandlerFunc(
		objectsToRetry.namespaceForFilteredHandler,     // filter out objects not in this namespace
		objectsToRetry.labelSelectorForFilteredHandler, // filter out objects not matching these labels
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				oc.recordAddEvent(objectsToRetry.oType, obj)

				key, err := getResourceKey(objectsToRetry.oType, obj)
				if err != nil {
					klog.Errorf("Upon add event: %v", err)
					return
				}
				klog.V(5).Infof("Add event received for resource %v, key=%s", objectsToRetry.oType, key)

				objectsToRetry.initRetryObjWithAdd(obj, key)
				objectsToRetry.skipRetryObj(key)

				// This only applies to pod watchers (pods + dynamic network policy handlers watching pods):
				// if ovnkube-master is restarted, it will gets all the add events with completed pods
				if oc.isObjectInTerminalState(objectsToRetry.oType, obj) {
					oc.processObjectInTerminalState(objectsToRetry, obj, key, resourceEventAdd)
					return
				}

				// If there is a delete entry with the same key, we got an add event for an object
				// with the same name as a previous object that failed deletion.
				// Destroy the old object before we add the new one.
				if retryEntry := objectsToRetry.getObjRetryEntry(key); retryEntry != nil && retryEntry.oldObj != nil {
					klog.Infof("Detected stale object during new object"+
						" add of type %v with the same key: %s",
						objectsToRetry.oType, key)
					internalCacheEntry := oc.getInternalCacheEntry(objectsToRetry.oType, obj)
					if err := oc.deleteResource(objectsToRetry, obj, internalCacheEntry); err != nil {
						klog.Errorf("Failed to delete old object %s of type %v,"+
							" during add event: %v", key, objectsToRetry.oType, err)
						oc.recordErrorEvent(objectsToRetry.oType, obj, err)
						objectsToRetry.unSkipRetryObj(key)
						return
					}
					objectsToRetry.removeDeleteFromRetryObj(key)
				}
				start := time.Now()
				if err := oc.addResource(objectsToRetry, obj, false); err != nil {
					klog.Errorf("Failed to create %v object %s, error: %v",
						objectsToRetry.oType, key, err)
					oc.recordErrorEvent(objectsToRetry.oType, obj, err)
					objectsToRetry.unSkipRetryObj(key)
					return
				}
				klog.Infof("Creating %v %s took: %v", objectsToRetry.oType, key, time.Since(start))
				objectsToRetry.deleteRetryObj(key, true)
			},

			UpdateFunc: func(old, newer interface{}) {
				// skip the whole update if old and newer are equal
				areEqual, err := areResourcesEqual(objectsToRetry.oType, old, newer)
				if err != nil {
					klog.Errorf("Could not compare old and newer resource objects of type %v: %v",
						objectsToRetry.oType, err)
					return
				}
				klog.V(5).Infof("Update event received for resource %s, old object is equal to new: %v",
					objectsToRetry.oType, areEqual)
				if areEqual {
					return
				}

				// get the object keys for newer and old (expected to be the same)
				newKey, err := getResourceKey(objectsToRetry.oType, newer)
				if err != nil {
					klog.Errorf("Update of resource %v failed when looking up key of new obj: %v",
						objectsToRetry.oType, err)
					return
				}
				oldKey, err := getResourceKey(objectsToRetry.oType, old)
				if err != nil {
					klog.Errorf("Update of resource %v failed  when looking up key of old obj: %v",
						objectsToRetry.oType, err)
					return
				}

				// skip the whole update if the new object doesn't exist anymore in the API server
				newer, err = oc.getResourceFromInformerCache(objectsToRetry.oType, newKey)
				if err != nil {
					klog.Warningf("Unable to get %v %s from informer cache (perhaps it was already"+
						" deleted?), skipping update: %v", objectsToRetry.oType, newKey, err)
					return
				}

				klog.V(5).Infof("Update event received for resource %v, oldKey=%s, newKey=%s",
					objectsToRetry.oType, oldKey, newKey)

				objectsToRetry.skipRetryObj(newKey)
				hasUpdateFunc := hasResourceAnUpdateFunc(objectsToRetry.oType)

				// STEP 1:
				// Delete existing (old) object if:
				// a) it has a retry entry marked for deletion or
				// b) the resource is in terminal state (e.g. pod is completed) or
				// c) this resource type has no update function, so an update means delete old obj and add new one
				retryEntry := objectsToRetry.getObjRetryEntry(oldKey)
				if retryEntry != nil && retryEntry.oldObj != nil {
					// [step 1a] there is a retry entry marked for deletion
					klog.Infof("Found old retry object for %v %s: will delete it",
						objectsToRetry.oType, oldKey)
					if err := oc.deleteResource(objectsToRetry, retryEntry.oldObj,
						retryEntry.config); err != nil {
						klog.Errorf("Failed to delete stale object %s, during update: %v", oldKey, err)
						oc.recordErrorEvent(objectsToRetry.oType, retryEntry.oldObj, err)
						objectsToRetry.initRetryObjWithAdd(newer, newKey)
						objectsToRetry.unSkipRetryObj(oldKey)
						return
					}
					// remove the old object from retry entry since it was correctly deleted
					objectsToRetry.removeDeleteFromRetryObj(oldKey)

				} else if oc.isObjectInTerminalState(objectsToRetry.oType, newer) { // check the latest status on newer
					// [step 1b] The object is in a terminal state: delete it from the cluster,
					// delete its retry entry and return. This only applies to pod watchers
					// (pods + dynamic network policy handlers watching pods).
					oc.processObjectInTerminalState(objectsToRetry, old, oldKey, resourceEventUpdate)
					return

				} else if !hasUpdateFunc {
					// [step 1c] if this resource type has no update function,
					// delete old obj and in step 2 add the new one
					var existingCacheEntry interface{}
					if retryEntry != nil {
						existingCacheEntry = retryEntry.config
					}
					klog.Infof("Deleting old %s of type %s during update", oldKey, objectsToRetry.oType)
					if err := oc.deleteResource(objectsToRetry, old, existingCacheEntry); err != nil {
						klog.Errorf("Failed to delete %s %s, during update: %v",
							objectsToRetry.oType, oldKey, err)
						oc.recordErrorEvent(objectsToRetry.oType, old, err)
						objectsToRetry.initRetryObjWithDelete(old, oldKey, nil)
						objectsToRetry.initRetryObjWithAdd(newer, newKey)
						objectsToRetry.unSkipRetryObj(oldKey)
						return
					}
					// remove the old object from retry entry since it was correctly deleted
					objectsToRetry.removeDeleteFromRetryObj(oldKey)
				}

				// STEP 2:
				// Execute the update function for this resource type; resort to add if no update
				// function is available.
				if hasUpdateFunc {
					klog.Infof("Updating %s %s", objectsToRetry.oType, newKey)
					// if this resource type has an update func, just call the update function
					if err := oc.updateResource(objectsToRetry, old, newer); err != nil {
						klog.Errorf("Failed to update resource %v, old=%s, new=%s, error: %v",
							objectsToRetry.oType, oldKey, newKey, err)
						oc.recordErrorEvent(objectsToRetry.oType, newer, err)
						objectsToRetry.initRetryObjWithAdd(newer, newKey)
						objectsToRetry.unSkipRetryObj(newKey)
						return
					}
				} else { // we previously deleted old object, now let's add the new one
					klog.Infof("Adding new %s of type %s", newKey, objectsToRetry.oType)
					if err := oc.addResource(objectsToRetry, newer, false); err != nil {
						oc.recordErrorEvent(objectsToRetry.oType, newer, err)
						objectsToRetry.initRetryObjWithAdd(newer, newKey)
						objectsToRetry.unSkipRetryObj(newKey)
						klog.Errorf("Failed to add %s %s, during update: %v",
							objectsToRetry.oType, newKey, err)
						return
					}
				}

				objectsToRetry.deleteRetryObj(newKey, true)

			},
			DeleteFunc: func(obj interface{}) {
				oc.recordDeleteEvent(objectsToRetry.oType, obj)
				key, err := getResourceKey(objectsToRetry.oType, obj)
				if err != nil {
					klog.Errorf("Delete of resource %v failed: %v", objectsToRetry.oType, err)
					return
				}
				klog.V(5).Infof("Delete event received for resource %v %s", objectsToRetry.oType, key)
				// If object is in terminal state, we would have already deleted it during update.
				// No reason to attempt to delete it here again.
				if oc.isObjectInTerminalState(objectsToRetry.oType, obj) {
					klog.Infof("Ignoring delete event for completed resource %v %s", objectsToRetry.oType, key)
					return
				}
				objectsToRetry.skipRetryObj(key)
				internalCacheEntry := oc.getInternalCacheEntry(objectsToRetry.oType, obj)
				objectsToRetry.initRetryObjWithDelete(obj, key, internalCacheEntry) // set up the retry obj for deletion
				if err := oc.deleteResource(objectsToRetry, obj, internalCacheEntry); err != nil {
					objectsToRetry.unSkipRetryObj(key)
					klog.Errorf("Failed to delete resource object %s of type %v, error: %v",
						key, objectsToRetry.oType, err)
					return
				}
				objectsToRetry.deleteRetryObj(key, true)
			},
		},
		syncFunc) // adds all existing objects at startup

	return handler
}
