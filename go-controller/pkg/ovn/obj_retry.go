package ovn

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"

	ocpcloudnetworkapi "github.com/openshift/api/cloudnetwork/v1"

	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	kerrorsutil "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/cache"

	"k8s.io/klog/v2"

	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	factory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/syncmap"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const retryObjInterval = 30 * time.Second
const maxFailedAttempts = 15 // same value used for the services level-driven controller
const initialBackoff = 1
const noBackoff = 0

// retryObjEntry is a generic object caching with retry mechanism
// that resources can use to eventually complete their intended operations.
type retryObjEntry struct {
	// newObj holds k8s resource failed during add operation
	newObj interface{}
	// oldObj holds k8s resource failed during delete operation
	oldObj interface{}
	// config holds feature specific configuration,
	// currently used by network policies and pods.
	config     interface{}
	timeStamp  time.Time
	backoffSec time.Duration
	// number of times this object has been unsuccessfully added/updated/deleted
	failedAttempts uint8
}

type RetryObjs struct {
	// cache to hold object needs retry to successfully complete processing
	retryEntries *syncmap.SyncMap[*retryObjEntry]
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

// NewRetryObjs returns a new RetryObjs instance, packed with the desired input parameters.
// The returned struct is essential for watchResource and the whole retry logic.
func NewRetryObjs(
	objectType reflect.Type,
	namespaceForFilteredHandler string,
	labelSelectorForFilteredHandler labels.Selector,
	syncFunc func([]interface{}) error,
	extraParameters interface{}) *RetryObjs {

	return &RetryObjs{
		retryEntries:                    syncmap.NewSyncMap[*retryObjEntry](),
		retryChan:                       make(chan struct{}, 1),
		oType:                           objectType,
		namespaceForFilteredHandler:     namespaceForFilteredHandler,
		labelSelectorForFilteredHandler: labelSelectorForFilteredHandler,
		syncFunc:                        syncFunc,
		extraParameters:                 extraParameters,
	}
}

func (r *RetryObjs) DoWithLock(key string, f func(key string)) {
	r.retryEntries.LockKey(key)
	defer r.retryEntries.UnlockKey(key)
	f(key)
}

func (r *RetryObjs) initRetryObjWithAddBackoff(obj interface{}, lockedKey string, backoff time.Duration) *retryObjEntry {
	// even if the object was loaded and changed before with the same lock, LoadOrStore will return reference to the same object
	entry := r.retryEntries.LoadOrStore(lockedKey, &retryObjEntry{backoffSec: backoff})
	entry.timeStamp = time.Now()
	entry.newObj = obj
	entry.failedAttempts = 0
	entry.backoffSec = backoff
	return entry
}

// initRetryObjWithAdd creates a retry entry for an object that is being added,
// so that, if it fails, the add can be potentially retried later.
func (r *RetryObjs) initRetryObjWithAdd(obj interface{}, lockedKey string) *retryObjEntry {
	return r.initRetryObjWithAddBackoff(obj, lockedKey, initialBackoff)
}

// initRetryObjWithUpdate tracks objects that failed to be updated to potentially retry later
func (r *RetryObjs) initRetryObjWithUpdate(oldObj, newObj interface{}, lockedKey string) *retryObjEntry {
	entry := r.retryEntries.LoadOrStore(lockedKey, &retryObjEntry{config: oldObj, backoffSec: initialBackoff})
	// even if the object was loaded and changed before with the same lock, LoadOrStore will return reference to the same object
	entry.timeStamp = time.Now()
	entry.newObj = newObj
	entry.config = oldObj
	entry.failedAttempts = 0
	return entry
}

// initRetryObjWithDelete creates a retry entry for an object that is being deleted,
// so that, if it fails, the delete can be potentially retried later.
// When applied to pods, we include the config object as well in case the namespace is removed
// and the object is orphaned from the namespace. Similarly, when applied to network policies,
// we include in config the networkPolicy struct used internally, for the same scenario where
// a namespace is being deleted along with its network policies and, in case of a delete retry of
// one such network policy, we wouldn't be able to get to the networkPolicy struct from nsInfo.
//
// The noRetryAdd boolean argument is to indicate whether to retry for addition
func (r *RetryObjs) initRetryObjWithDelete(obj interface{}, lockedKey string, config interface{}, noRetryAdd bool) *retryObjEntry {
	// even if the object was loaded and changed before with the same lock, LoadOrStore will return reference to the same object
	entry := r.retryEntries.LoadOrStore(lockedKey, &retryObjEntry{config: config, backoffSec: initialBackoff})
	entry.timeStamp = time.Now()
	entry.oldObj = obj
	if entry.config == nil {
		entry.config = config
	}
	entry.failedAttempts = 0
	if noRetryAdd {
		// will not be retried for addition
		entry.newObj = nil
	}
	return entry
}

// AddRetryObjWithAddNoBackoff adds an object to be retried immediately for add.
// It will lock the key, create or update retryObject, and unlock the key
func (r *RetryObjs) AddRetryObjWithAddNoBackoff(obj interface{}) error {
	key, err := getResourceKey(r.oType, obj)
	if err != nil {
		return fmt.Errorf("could not get the key of %s %v: %v", r.oType, obj, err)
	}
	r.DoWithLock(key, func(key string) {
		r.initRetryObjWithAddBackoff(obj, key, noBackoff)
	})
	return nil
}

func (r *RetryObjs) getRetryObj(lockedKey string) (value *retryObjEntry, found bool) {
	return r.retryEntries.Load(lockedKey)
}

func (r *RetryObjs) deleteRetryObj(lockedKey string) {
	r.retryEntries.Delete(lockedKey)
}

// setRetryObjWithNoBackoff sets an object's backoff to be retried
// immediately during the next retry iteration
// Used only for testing right now
func (r *RetryObjs) setRetryObjWithNoBackoff(entry *retryObjEntry) {
	entry.backoffSec = noBackoff
}

// removeDeleteFromRetryObj removes any old object from a retry entry
func (r *RetryObjs) removeDeleteFromRetryObj(entry *retryObjEntry) {
	entry.oldObj = nil
	entry.config = nil
}

// increaseFailedAttemptsCounter increases by one the counter of failed add/update/delete attempts
// for the given key
func (r *RetryObjs) increaseFailedAttemptsCounter(entry *retryObjEntry) {
	entry.failedAttempts++
}

// RequestRetryObjs allows a caller to immediately request to iterate through all objects that
// are in the retry cache. This will ignore any outstanding time wait/backoff state
func (r *RetryObjs) RequestRetryObjs() {
	select {
	case r.retryChan <- struct{}{}:
		klog.V(5).Infof("Iterate retry objects requested (resource %s)", r.oType)
	default:
		klog.V(5).Infof("Iterate retry objects already requested (resource %s)", r.oType)
	}
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
		factory.EgressIPType,
		factory.EgressIPNamespaceType,
		factory.EgressIPPodType,
		factory.EgressNodeType,
		factory.CloudPrivateIPConfigType,
		factory.LocalPodSelectorType,
		factory.NamespaceType:
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
			return false, fmt.Errorf("could not cast obj1 of type %T to *knet.NetworkPolicy", obj1)
		}
		np2, ok := obj2.(*knet.NetworkPolicy)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type %T to *knet.NetworkPolicy", obj2)
		}
		return reflect.DeepEqual(np1, np2), nil

	case factory.NodeType:
		node1, ok := obj1.(*kapi.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj1 of type %T to *kapi.Node", obj1)
		}
		node2, ok := obj2.(*kapi.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type %T to *kapi.Node", obj2)
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
			return false, fmt.Errorf("could not cast obj1 of type %T to *kapi.Service", obj1)
		}
		service2, ok := obj2.(*kapi.Service)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type %T to *kapi.Service", obj2)
		}
		areEqual := reflect.DeepEqual(service1.Spec.ExternalIPs, service2.Spec.ExternalIPs) &&
			reflect.DeepEqual(service1.Spec.ClusterIP, service2.Spec.ClusterIP) &&
			reflect.DeepEqual(service1.Spec.ClusterIPs, service2.Spec.ClusterIPs) &&
			reflect.DeepEqual(service1.Spec.Type, service2.Spec.Type) &&
			reflect.DeepEqual(service1.Status.LoadBalancer.Ingress, service2.Status.LoadBalancer.Ingress)
		return areEqual, nil

	case factory.PodType,
		factory.EgressIPPodType,
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

	case factory.EgressFirewallType:
		oldEgressFirewall, ok := obj1.(*egressfirewall.EgressFirewall)
		if !ok {
			return false, fmt.Errorf("could not cast obj1 of type %T to *egressfirewall.EgressFirewall", obj1)
		}
		newEgressFirewall, ok := obj2.(*egressfirewall.EgressFirewall)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type %T to *egressfirewall.EgressFirewall", obj2)
		}
		return reflect.DeepEqual(oldEgressFirewall.Spec, newEgressFirewall.Spec), nil

	case factory.EgressIPType,
		factory.EgressIPNamespaceType,
		factory.EgressNodeType,
		factory.CloudPrivateIPConfigType:
		// force update path for EgressIP resource.
		return false, nil

	case factory.NamespaceType:
		// force update path for Namespace resource.
		return false, nil
	}

	return false, fmt.Errorf("no object comparison for type %s", objType)
}

// Given an object and its type, it returns the key for this object and an error if the key retrieval failed.
// For all namespaced resources, the key will be namespace/name. For resource types without a namespace,
// the key will be the object name itself.
func getResourceKey(objType reflect.Type, obj interface{}) (string, error) {
	switch objType {
	case factory.PolicyType:
		np, ok := obj.(*knet.NetworkPolicy)
		if !ok {
			return "", fmt.Errorf("could not cast %T object to *knet.NetworkPolicy", obj)
		}
		return getPolicyNamespacedName(np), nil

	case factory.NodeType,
		factory.EgressNodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return "", fmt.Errorf("could not cast %T object to *kapi.Node", obj)
		}
		return node.Name, nil

	case factory.PeerServiceType:
		service, ok := obj.(*kapi.Service)
		if !ok {
			return "", fmt.Errorf("could not cast %T object to *kapi.Service", obj)
		}
		return getNamespacedName(service.Namespace, service.Name), nil

	case factory.PodType,
		factory.PeerPodSelectorType,
		factory.PeerPodForNamespaceAndPodSelectorType,
		factory.LocalPodSelectorType,
		factory.EgressIPPodType:
		pod, ok := obj.(*kapi.Pod)
		if !ok {
			return "", fmt.Errorf("could not cast %T object to *kapi.Pod", obj)
		}
		return getNamespacedName(pod.Namespace, pod.Name), nil

	case factory.PeerNamespaceAndPodSelectorType,
		factory.PeerNamespaceSelectorType,
		factory.EgressIPNamespaceType,
		factory.NamespaceType:
		namespace, ok := obj.(*kapi.Namespace)
		if !ok {
			return "", fmt.Errorf("could not cast %T object to *kapi.Namespace", obj)
		}
		return namespace.Name, nil

	case factory.EgressFirewallType:
		egressFirewall, ok := obj.(*egressfirewall.EgressFirewall)
		if !ok {
			return "", fmt.Errorf("could not cast %T object to *egressfirewall.EgressFirewall", obj)
		}
		return getEgressFirewallNamespacedName(egressFirewall), nil

	case factory.EgressIPType:
		eIP, ok := obj.(*egressipv1.EgressIP)
		if !ok {
			return "", fmt.Errorf("could not cast %T object to *egressipv1.EgressIP", obj)
		}
		return eIP.Name, nil
	case factory.CloudPrivateIPConfigType:
		cloudPrivateIPConfig, ok := obj.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
		if !ok {
			return "", fmt.Errorf("could not cast %T object to *ocpcloudnetworkapi.CloudPrivateIPConfig", obj)
		}
		return cloudPrivateIPConfig.Name, nil
	}

	return "", fmt.Errorf("object type %s not supported", objType)
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

	case factory.NodeType,
		factory.EgressNodeType:
		obj, err = oc.watchFactory.GetNode(key)

	case factory.PeerServiceType:
		namespace, name := splitNamespacedName(key)
		obj, err = oc.watchFactory.GetService(namespace, name)

	case factory.PodType,
		factory.PeerPodSelectorType,
		factory.PeerPodForNamespaceAndPodSelectorType,
		factory.LocalPodSelectorType,
		factory.EgressIPPodType:
		namespace, name := splitNamespacedName(key)
		obj, err = oc.watchFactory.GetPod(namespace, name)

	case factory.PeerNamespaceAndPodSelectorType,
		factory.PeerNamespaceSelectorType,
		factory.EgressIPNamespaceType,
		factory.NamespaceType:
		obj, err = oc.watchFactory.GetNamespace(key)

	case factory.EgressFirewallType:
		namespace, name := splitNamespacedName(key)
		obj, err = oc.watchFactory.GetEgressFirewall(namespace, name)

	case factory.EgressIPType:
		obj, err = oc.watchFactory.GetEgressIP(key)

	case factory.CloudPrivateIPConfigType:
		obj, err = oc.watchFactory.GetCloudPrivateIPConfig(key)

	default:
		err = fmt.Errorf("object type %s not supported, cannot retrieve it from informers cache",
			objType)
	}
	return obj, err
}

// Given an object and its type, recordAddEvent records the add event on this object.
func (oc *Controller) recordAddEvent(objType reflect.Type, obj interface{}) {
	switch objType {
	case factory.PodType:
		klog.V(5).Infof("Recording add event on pod")
		pod := obj.(*kapi.Pod)
		oc.podRecorder.AddPod(pod.UID)
		metrics.GetConfigDurationRecorder().Start("pod", pod.Namespace, pod.Name)
	case factory.PolicyType:
		klog.V(5).Infof("Recording add event on network policy")
		np := obj.(*knet.NetworkPolicy)
		metrics.GetConfigDurationRecorder().Start("networkpolicy", np.Namespace, np.Name)
	}
}

// Given an object and its type, recordUpdateEvent records the update event on this object.
func (oc *Controller) recordUpdateEvent(objType reflect.Type, obj interface{}) {
	switch objType {
	case factory.PodType:
		klog.V(5).Infof("Recording update event on pod")
		pod := obj.(*kapi.Pod)
		metrics.GetConfigDurationRecorder().Start("pod", pod.Namespace, pod.Name)
	case factory.PolicyType:
		klog.V(5).Infof("Recording update event on network policy")
		np := obj.(*knet.NetworkPolicy)
		metrics.GetConfigDurationRecorder().Start("networkpolicy", np.Namespace, np.Name)
	}
}

// Given an object and its type, recordDeleteEvent records the delete event on this object. Only used for pods now.
func (oc *Controller) recordDeleteEvent(objType reflect.Type, obj interface{}) {
	switch objType {
	case factory.PodType:
		klog.V(5).Infof("Recording delete event on pod")
		pod := obj.(*kapi.Pod)
		oc.podRecorder.CleanPod(pod.UID)
		metrics.GetConfigDurationRecorder().Start("pod", pod.Namespace, pod.Name)
	case factory.PolicyType:
		klog.V(5).Infof("Recording delete event on network policy")
		np := obj.(*knet.NetworkPolicy)
		metrics.GetConfigDurationRecorder().Start("networkpolicy", np.Namespace, np.Name)
	}
}

func (oc *Controller) recordSuccessEvent(objType reflect.Type, obj interface{}) {
	switch objType {
	case factory.PodType:
		klog.V(5).Infof("Recording success event on pod")
		pod := obj.(*kapi.Pod)
		metrics.GetConfigDurationRecorder().End("pod", pod.Namespace, pod.Name)
	case factory.PolicyType:
		klog.V(5).Infof("Recording success event on network policy")
		np := obj.(*knet.NetworkPolicy)
		metrics.GetConfigDurationRecorder().End("networkpolicy", np.Namespace, np.Name)
	}
}

// Given an object and its type, recordErrorEvent records an error event on this object.
// Only used for pods now.
func (oc *Controller) recordErrorEvent(objType reflect.Type, obj interface{}, err error) {
	switch objType {
	case factory.PodType:
		klog.V(5).Infof("Recording error event on pod")
		pod := obj.(*kapi.Pod)
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

// Given an object type, resourceNeedsUpdate returns true if the object needs to invoke update during iterate retry.
func resourceNeedsUpdate(objType reflect.Type) bool {
	switch objType {
	case factory.EgressNodeType,
		factory.EgressIPType,
		factory.EgressIPPodType,
		factory.EgressIPNamespaceType,
		factory.CloudPrivateIPConfigType,
		factory.NamespaceType:
		return true
	}
	return false
}

// Given a *RetryObjs instance, an object to add and a boolean specifying if the function was executed from
// iterateRetryResources, addResource adds the specified object to the cluster according to its type and
// returns the error, if any, yielded during object creation.
func (oc *Controller) addResource(objectsToRetry *RetryObjs, obj interface{}, fromRetryLoop bool) error {
	var err error

	switch objectsToRetry.oType {
	case factory.PodType:
		pod, ok := obj.(*kapi.Pod)
		if !ok {
			return fmt.Errorf("could not cast %T object to *knet.Pod", obj)
		}
		if config.HybridOverlay.Enabled {
			if err := oc.addPodICNIv1(pod); err != nil {
				return err
			}
		}
		return oc.ensurePod(nil, pod, true)

	case factory.PolicyType:
		np, ok := obj.(*knet.NetworkPolicy)
		if !ok {
			return fmt.Errorf("could not cast %T object to *knet.NetworkPolicy", obj)
		}

		if err = oc.addNetworkPolicy(np); err != nil {
			klog.Infof("Network Policy add failed for %s/%s, will try again later: %v",
				np.Namespace, np.Name, err)
			return err
		}

	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *kapi.Node", obj)
		}
		var nodeParams *nodeSyncs
		if fromRetryLoop {
			_, nodeSync := oc.addNodeFailed.Load(node.Name)
			_, clusterRtrSync := oc.nodeClusterRouterPortFailed.Load(node.Name)
			_, mgmtSync := oc.mgmtPortFailed.Load(node.Name)
			_, gwSync := oc.gatewaysFailed.Load(node.Name)
			_, hoSync := oc.hybridOverlayFailed.Load(node.Name)
			nodeParams = &nodeSyncs{
				nodeSync,
				clusterRtrSync,
				mgmtSync,
				gwSync,
				hoSync}
		} else {
			nodeParams = &nodeSyncs{true, true, true, true, config.HybridOverlay.Enabled}
		}

		if err = oc.addUpdateNodeEvent(node, nodeParams); err != nil {
			klog.Infof("Node add failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}

	case factory.PeerServiceType:
		service, ok := obj.(*kapi.Service)
		if !ok {
			return fmt.Errorf("could not cast peer service of type %T to *kapi.Service", obj)
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
		syncFunc := func(objs []interface{}) error {
			return oc.handlePeerPodSelectorAddUpdate(extraParameters.gp, objs...)
		}
		retryPeerPods := NewRetryObjs(
			factory.PeerPodForNamespaceAndPodSelectorType,
			namespace.Name,
			extraParameters.podSelector,
			syncFunc,
			&NetworkPolicyExtraParameters{gp: extraParameters.gp},
		)
		// The AddFilteredPodHandler call might call handlePeerPodSelectorAddUpdate
		// on existing pods so we can't be holding the lock at this point
		podHandler, err := oc.WatchResource(retryPeerPods)
		if err != nil {
			klog.Errorf("Failed WatchResource for PeerNamespaceAndPodSelectorType: %v", err)
			return err
		}

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

	case factory.EgressFirewallType:
		var err error
		egressFirewall := obj.(*egressfirewall.EgressFirewall).DeepCopy()
		if err = oc.addEgressFirewall(egressFirewall); err != nil {
			egressFirewall.Status.Status = egressFirewallAddError
		} else {
			egressFirewall.Status.Status = egressFirewallAppliedCorrectly
			metrics.UpdateEgressFirewallRuleCount(float64(len(egressFirewall.Spec.Egress)))
			metrics.IncrementEgressFirewallCount()
		}
		if err := oc.updateEgressFirewallStatusWithRetry(egressFirewall); err != nil {
			klog.Errorf("Failed to update egress firewall status %s, error: %v", getEgressFirewallNamespacedName(egressFirewall), err)
		}
		return err

	case factory.EgressIPType:
		eIP := obj.(*egressipv1.EgressIP)
		return oc.reconcileEgressIP(nil, eIP)

	case factory.EgressIPNamespaceType:
		namespace := obj.(*kapi.Namespace)
		return oc.reconcileEgressIPNamespace(nil, namespace)

	case factory.EgressIPPodType:
		pod := obj.(*kapi.Pod)
		return oc.reconcileEgressIPPod(nil, pod)

	case factory.EgressNodeType:
		node := obj.(*kapi.Node)
		if err := oc.setupNodeForEgress(node); err != nil {
			return err
		}
		nodeEgressLabel := util.GetNodeEgressLabel()
		nodeLabels := node.GetLabels()
		_, hasEgressLabel := nodeLabels[nodeEgressLabel]
		if hasEgressLabel {
			oc.setNodeEgressAssignable(node.Name, true)
		}
		isReady := oc.isEgressNodeReady(node)
		if isReady {
			oc.setNodeEgressReady(node.Name, true)
		}
		isReachable := oc.isEgressNodeReachable(node)
		if isReachable {
			oc.setNodeEgressReachable(node.Name, true)
		}
		if hasEgressLabel && isReachable && isReady {
			if err := oc.addEgressNode(node.Name); err != nil {
				return err
			}
		}

	case factory.CloudPrivateIPConfigType:
		cloudPrivateIPConfig := obj.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
		return oc.reconcileCloudPrivateIPConfig(nil, cloudPrivateIPConfig)

	case factory.NamespaceType:
		ns, ok := obj.(*kapi.Namespace)
		if !ok {
			return fmt.Errorf("could not cast %T object to *kapi.Namespace", obj)
		}
		// OCP HACK -- required for hybrid overlay
		if config.HybridOverlay.Enabled && hasHybridAnnotation(ns.ObjectMeta) {
			if err := oc.addNamespaceICNIv1(ns); err != nil {
				klog.Errorf("Unable to handle legacy ICNIv1 check for namespace %q add, error: %v",
					ns.Name, err)
			}
		}
		// END OCP HACK
		return oc.AddNamespace(ns)

	default:
		return fmt.Errorf("no add function for object type %s", objectsToRetry.oType)
	}

	return nil
}

// Given a *RetryObjs instance, an old and a new object, updateResource updates the specified object in the cluster
// to its version in newObj according to its type and returns the error, if any, yielded during the object update.
// The inRetryCache boolean argument is to indicate if the given resource is in the retryCache or not.
func (oc *Controller) updateResource(objectsToRetry *RetryObjs, oldObj, newObj interface{}, inRetryCache bool) error {
	switch objectsToRetry.oType {
	case factory.PodType:
		oldPod := oldObj.(*kapi.Pod)
		newPod := newObj.(*kapi.Pod)
		if config.HybridOverlay.Enabled {
			if err := oc.addPodICNIv1(newPod); err != nil {
				return err
			}
		}
		return oc.ensurePod(oldPod, newPod, inRetryCache || util.PodScheduled(oldPod) != util.PodScheduled(newPod))

	case factory.NodeType:
		newNode, ok := newObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast newObj of type %T to *kapi.Node", newObj)
		}
		oldNode, ok := oldObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast oldObj of type %T to *kapi.Node", oldObj)
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
		_, hoSync := oc.hybridOverlayFailed.Load(newNode.Name)

		return oc.addUpdateNodeEvent(newNode, &nodeSyncs{nodeSync, clusterRtrSync, mgmtSync, gwSync, hoSync})

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

	case factory.EgressIPType:
		oldEIP := oldObj.(*egressipv1.EgressIP)
		newEIP := newObj.(*egressipv1.EgressIP)
		return oc.reconcileEgressIP(oldEIP, newEIP)

	case factory.EgressIPNamespaceType:
		oldNamespace := oldObj.(*kapi.Namespace)
		newNamespace := newObj.(*kapi.Namespace)
		return oc.reconcileEgressIPNamespace(oldNamespace, newNamespace)

	case factory.EgressIPPodType:
		oldPod := oldObj.(*kapi.Pod)
		newPod := newObj.(*kapi.Pod)
		return oc.reconcileEgressIPPod(oldPod, newPod)

	case factory.EgressNodeType:
		oldNode := oldObj.(*kapi.Node)
		newNode := newObj.(*kapi.Node)
		// Initialize the allocator on every update,
		// ovnkube-node/cloud-network-config-controller will make sure to
		// annotate the node with the egressIPConfig, but that might have
		// happened after we processed the ADD for that object, hence keep
		// retrying for all UPDATEs.
		if err := oc.initEgressIPAllocator(newNode); err != nil {
			klog.Warningf("Egress node initialization error: %v", err)
		}
		nodeEgressLabel := util.GetNodeEgressLabel()
		oldLabels := oldNode.GetLabels()
		newLabels := newNode.GetLabels()
		_, oldHadEgressLabel := oldLabels[nodeEgressLabel]
		_, newHasEgressLabel := newLabels[nodeEgressLabel]
		// If the node is not labeled for egress assignment, just return
		// directly, we don't really need to set the ready / reachable
		// status on this node if the user doesn't care about using it.
		if !oldHadEgressLabel && !newHasEgressLabel {
			return nil
		}
		if oldHadEgressLabel && !newHasEgressLabel {
			klog.Infof("Node: %s has been un-labeled, deleting it from egress assignment", newNode.Name)
			oc.setNodeEgressAssignable(oldNode.Name, false)
			return oc.deleteEgressNode(oldNode.Name)
		}
		isOldReady := oc.isEgressNodeReady(oldNode)
		isNewReady := oc.isEgressNodeReady(newNode)
		isNewReachable := oc.isEgressNodeReachable(newNode)
		oc.setNodeEgressReady(newNode.Name, isNewReady)
		oc.setNodeEgressReachable(newNode.Name, isNewReachable)
		if !oldHadEgressLabel && newHasEgressLabel {
			klog.Infof("Node: %s has been labeled, adding it for egress assignment", newNode.Name)
			oc.setNodeEgressAssignable(newNode.Name, true)
			if isNewReady && isNewReachable {
				if err := oc.addEgressNode(newNode.Name); err != nil {
					return err
				}
			} else {
				klog.Warningf("Node: %s has been labeled, but node is not ready and reachable, cannot use it for egress assignment", newNode.Name)
			}
			return nil
		}
		if isOldReady == isNewReady {
			return nil
		}
		if !isNewReady {
			klog.Warningf("Node: %s is not ready, deleting it from egress assignment", newNode.Name)
			if err := oc.deleteEgressNode(newNode.Name); err != nil {
				return err
			}
		} else if isNewReady && isNewReachable {
			klog.Infof("Node: %s is ready and reachable, adding it for egress assignment", newNode.Name)
			if err := oc.addEgressNode(newNode.Name); err != nil {
				return err
			}
		}
		return nil

	case factory.CloudPrivateIPConfigType:
		oldCloudPrivateIPConfig := oldObj.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
		newCloudPrivateIPConfig := newObj.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
		return oc.reconcileCloudPrivateIPConfig(oldCloudPrivateIPConfig, newCloudPrivateIPConfig)

	case factory.NamespaceType:
		oldNs, newNs := oldObj.(*kapi.Namespace), newObj.(*kapi.Namespace)
		// OCP HACK -- required for hybrid overlay
		if config.HybridOverlay.Enabled && nsHybridAnnotationChanged(oldNs, newNs) {
			if err := oc.addNamespaceICNIv1(newNs); err != nil {
				klog.Errorf("Unable to handle legacy ICNIv1 check for namespace %q during update, error: %v",
					newNs.Name, err)
			}
		}
		// END OCP HACK
		return oc.updateNamespace(oldNs, newNs)
	}

	return fmt.Errorf("no update function for object type %s", objectsToRetry.oType)
}

// Given a *RetryObjs instance, an object and optionally a cachedObj, deleteResource deletes the object from the cluster
// according to the delete logic of its resource type. cachedObj is the internal cache entry for this object,
// used for now for pods and network policies.
func (oc *Controller) deleteResource(objectsToRetry *RetryObjs, obj, cachedObj interface{}) error {
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
			return fmt.Errorf("could not cast obj of type %T to *knet.NetworkPolicy", obj)
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
			return fmt.Errorf("could not cast obj of type %T to *knet.Node", obj)
		}
		return oc.deleteNodeEvent(node)

	case factory.PeerServiceType:
		service, ok := obj.(*kapi.Service)
		if !ok {
			return fmt.Errorf("could not cast peer service of type %T to *kapi.Service", obj)
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

	case factory.LocalPodSelectorType:
		extraParameters := objectsToRetry.extraParameters.(*NetworkPolicyExtraParameters)
		return oc.handleLocalPodSelectorDelFunc(
			extraParameters.policy,
			extraParameters.np,
			extraParameters.portGroupIngressDenyName,
			extraParameters.portGroupEgressDenyName,
			obj)

	case factory.EgressFirewallType:
		egressFirewall := obj.(*egressfirewall.EgressFirewall)
		if err := oc.deleteEgressFirewall(egressFirewall); err != nil {
			return err
		}
		metrics.UpdateEgressFirewallRuleCount(float64(-len(egressFirewall.Spec.Egress)))
		metrics.DecrementEgressFirewallCount()
		return nil

	case factory.EgressIPType:
		eIP := obj.(*egressipv1.EgressIP)
		return oc.reconcileEgressIP(eIP, nil)

	case factory.EgressIPNamespaceType:
		namespace := obj.(*kapi.Namespace)
		return oc.reconcileEgressIPNamespace(namespace, nil)

	case factory.EgressIPPodType:
		pod := obj.(*kapi.Pod)
		return oc.reconcileEgressIPPod(pod, nil)

	case factory.EgressNodeType:
		node := obj.(*kapi.Node)
		if err := oc.deleteNodeForEgress(node); err != nil {
			return err
		}
		nodeEgressLabel := util.GetNodeEgressLabel()
		nodeLabels := node.GetLabels()
		if _, hasEgressLabel := nodeLabels[nodeEgressLabel]; hasEgressLabel {
			if err := oc.deleteEgressNode(node.Name); err != nil {
				return err
			}
		}
		return nil

	case factory.CloudPrivateIPConfigType:
		cloudPrivateIPConfig := obj.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
		return oc.reconcileCloudPrivateIPConfig(cloudPrivateIPConfig, nil)

	case factory.NamespaceType:
		ns := obj.(*kapi.Namespace)
		return oc.deleteNamespace(ns)

	default:
		return fmt.Errorf("object type %s not supported", objectsToRetry.oType)
	}
}

func (oc *Controller) resourceRetry(r *RetryObjs, objKey string, now time.Time) {
	r.DoWithLock(objKey, func(key string) {
		entry, loaded := r.getRetryObj(key)
		if !loaded {
			klog.V(5).Infof("%v resource %s was not found in the iterateRetryResources map while retrying resource setup", r.oType, objKey)
			return
		}

		if entry.failedAttempts >= maxFailedAttempts {
			klog.Warningf("Dropping retry entry for %s %s: exceeded number of failed attempts",
				r.oType, objKey)
			r.deleteRetryObj(key)
			return
		}
		forceRetry := false
		// check if immediate retry is requested
		if entry.backoffSec == noBackoff {
			entry.backoffSec = initialBackoff
			forceRetry = true
		}
		backoff := (entry.backoffSec * time.Second) + (time.Duration(rand.Intn(500)) * time.Millisecond)
		objTimer := entry.timeStamp.Add(backoff)
		if !forceRetry && now.Before(objTimer) {
			klog.V(5).Infof("Attempting retry of %s %s before timer (time: %s): skip", r.oType, objKey, objTimer)
			return
		}

		// update backoff for future attempts in case of failure
		entry.backoffSec = entry.backoffSec * 2
		if entry.backoffSec > 60 {
			entry.backoffSec = 60
		}

		// storing original obj for metrics
		var initObj interface{}
		if entry.newObj != nil {
			initObj = entry.newObj
		} else if entry.oldObj != nil {
			initObj = entry.oldObj
		}

		klog.Infof("Retry object setup: %s %s", r.oType, objKey)

		if entry.newObj != nil {
			// get the latest version of the object from the informer;
			// if it doesn't exist we are not going to create the new object.
			kObj, err := oc.getResourceFromInformerCache(r.oType, objKey)
			if err != nil {
				if kerrors.IsNotFound(err) {
					klog.Infof("%s %s not found in the informers cache,"+
						" not going to retry object create", r.oType, objKey)
					kObj = nil
				} else {
					klog.Errorf("Failed to look up %s %s in the informers cache,"+
						" will retry later: %v", r.oType, objKey, err)
					return
				}
			}
			entry.newObj = kObj
		}
		if resourceNeedsUpdate(r.oType) && entry.config != nil && entry.newObj != nil {
			klog.Infof("%v retry: updating object %s", r.oType, objKey)
			if err := oc.updateResource(r, entry.config, entry.newObj, true); err != nil {
				klog.Infof("%v retry update failed for %s, will try again later: %v", r.oType, objKey, err)
				entry.timeStamp = time.Now()
				entry.failedAttempts++
				return
			}
			// successfully cleaned up new and old object, remove it from the retry cache
			entry.newObj = nil
			entry.config = nil
		} else {
			// delete old object if needed
			if entry.oldObj != nil {
				klog.Infof("Removing old object: %s %s", r.oType, objKey)
				if !isResourceScheduled(r.oType, entry.oldObj) {
					klog.V(5).Infof("Retry: %s %s not scheduled", r.oType, objKey)
					entry.failedAttempts++
					return
				}
				if err := oc.deleteResource(r, entry.oldObj, entry.config); err != nil {
					klog.Infof("Retry delete failed for %s %s, will try again later: %v", r.oType, objKey, err)
					entry.timeStamp = time.Now()
					entry.failedAttempts++
					return
				}
				// successfully cleaned up old object, remove it from the retry cache
				entry.oldObj = nil
			}

			// create new object if needed
			if entry.newObj != nil {
				klog.Infof("Adding new object: %s %s", r.oType, objKey)
				if !isResourceScheduled(r.oType, entry.newObj) {
					klog.V(5).Infof("Retry: %s %s not scheduled", r.oType, objKey)
					entry.failedAttempts++
					return
				}
				if err := oc.addResource(r, entry.newObj, true); err != nil {
					klog.Infof("Retry add failed for %s %s, will try again later: %v", r.oType, objKey, err)
					entry.timeStamp = time.Now()
					entry.failedAttempts++
					return
				}
				// successfully cleaned up new object, remove it from the retry cache
				entry.newObj = nil
			}
		}

		klog.Infof("Retry successful for %s %s after %d failed attempt(s)", r.oType, objKey, entry.failedAttempts)
		if initObj != nil {
			oc.recordSuccessEvent(r.oType, initObj)
		}
		r.deleteRetryObj(key)
	})
}

// iterateRetryResources checks if any outstanding resource objects exist and if so it tries to
// re-add them. updateAll forces all objects to be attempted to be retried regardless.
// iterateRetryResources makes a snapshot of keys present in the r.retryEntries cache, and runs retry only
// for those keys. New changes may be applied to saved keys entries while iterateRetryResources is executed.
// Deleted entries will be ignored, and all the updates will be reflected with key Lock.
// Keys added after the snapshot was done won't be retried during this run.
func (oc *Controller) iterateRetryResources(r *RetryObjs) {
	now := time.Now()
	wg := &sync.WaitGroup{}

	entriesKeys := r.retryEntries.GetKeys()
	// Now process the above list of pods that need re-try by holding the lock for each one of them.
	klog.V(5).Infof("Going to retry %v resource setup for %d number of resources: %s", r.oType, len(entriesKeys), entriesKeys)

	for _, entryKey := range entriesKeys {
		wg.Add(1)
		go func(entryKey string) {
			defer wg.Done()
			oc.resourceRetry(r, entryKey, now)
		}(entryKey)
	}
	klog.V(5).Infof("Waiting for all the %s retry setup to complete in iterateRetryResources", r.oType)
	wg.Wait()
	klog.V(5).Infof("Function iterateRetryResources ended (in %v)", time.Since(now))
}

// periodicallyRetryResources tracks RetryObjs and checks if any object needs to be retried for add or delete every
// retryObjInterval seconds or when requested through retryChan.
func (oc *Controller) periodicallyRetryResources(r *RetryObjs) {
	timer := time.NewTicker(retryObjInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			oc.iterateRetryResources(r)

		case <-r.retryChan:
			klog.V(5).Infof("Retry channel got triggered: retrying failed objects of type %s", r.oType)
			oc.iterateRetryResources(r)
			timer.Reset(retryObjInterval)

		case <-oc.stopChan:
			klog.V(5).Infof("Stop channel got triggered: will stop retrying failed objects of type %s", r.oType)
			return
		}
	}
}

// Given a *RetryObjs instance, getSyncResourcesFunc retuns the sync function for a given resource type.
// This will be then called on all existing objects when a watcher is started.
func (oc *Controller) getSyncResourcesFunc(r *RetryObjs) (func([]interface{}) error, error) {

	var syncFunc func([]interface{}) error

	switch r.oType {
	case factory.PodType:
		syncFunc = oc.syncPods

	case factory.PolicyType:
		syncFunc = oc.syncNetworkPolicies

	case factory.NodeType:
		syncFunc = oc.syncNodes

	case factory.LocalPodSelectorType,
		factory.PeerServiceType,
		factory.PeerNamespaceAndPodSelectorType,
		factory.PeerPodSelectorType,
		factory.PeerPodForNamespaceAndPodSelectorType,
		factory.PeerNamespaceSelectorType:
		syncFunc = r.syncFunc

	case factory.EgressFirewallType:
		syncFunc = oc.syncEgressFirewall

	case factory.EgressIPNamespaceType:
		syncFunc = oc.syncEgressIPs

	case factory.EgressNodeType:
		syncFunc = oc.initClusterEgressPolicies

	case factory.EgressIPPodType,
		factory.EgressIPType,
		factory.CloudPrivateIPConfigType:
		syncFunc = nil

	case factory.NamespaceType:
		syncFunc = oc.syncNamespaces

	default:
		return nil, fmt.Errorf("no sync function for object type %s", r.oType)
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
		factory.LocalPodSelectorType,
		factory.EgressIPPodType:
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
// processObjectInTerminalState doesn't unlock key
func (oc *Controller) processObjectInTerminalState(objectsToRetry *RetryObjs, obj interface{}, lockedKey string, event resourceEvent) {
	// The object is in a terminal state: delete it from the cluster, delete its retry entry and return.
	klog.Infof("Detected object %s of type %s in terminal state (e.g. completed)"+
		" during %s event: will remove it", lockedKey, objectsToRetry.oType, event)

	internalCacheEntry := oc.getInternalCacheEntry(objectsToRetry.oType, obj)
	retryEntry := objectsToRetry.initRetryObjWithDelete(obj, lockedKey, internalCacheEntry, true) // set up the retry obj for deletion
	if err := oc.deleteResource(objectsToRetry, obj, internalCacheEntry); err != nil {
		klog.Errorf("Failed to delete object %s of type %s in terminal state, during %s event: %v",
			lockedKey, objectsToRetry.oType, event, err)
		oc.recordErrorEvent(objectsToRetry.oType, obj, err)
		objectsToRetry.increaseFailedAttemptsCounter(retryEntry)
		return
	}
	objectsToRetry.deleteRetryObj(lockedKey)
}

// WatchResource starts the watching of a resource type, manages its retry entries and calls
// back the appropriate handler logic. It also starts a goroutine that goes over all retry objects
// periodically or when explicitly requested.
// Note: when applying WatchResource to a new resource type, the appropriate resource-specific logic must be added to the
// the different methods it calls.
func (oc *Controller) WatchResource(objectsToRetry *RetryObjs) (*factory.Handler, error) {
	addHandlerFunc, err := oc.watchFactory.GetResourceHandlerFunc(objectsToRetry.oType)
	if err != nil {
		return nil, fmt.Errorf("no resource handler function found for resource %v. "+
			"Cannot watch this resource", objectsToRetry.oType)
	}
	syncFunc, err := oc.getSyncResourcesFunc(objectsToRetry)
	if err != nil {
		return nil, fmt.Errorf("no sync function found for resource %v. "+
			"Cannot watch this resource", objectsToRetry.oType)
	}

	// create the actual watcher
	handler, err := addHandlerFunc(
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
				klog.V(5).Infof("Add event received for %s, key=%s", objectsToRetry.oType, key)

				objectsToRetry.DoWithLock(key, func(key string) {
					// This only applies to pod watchers (pods + dynamic network policy handlers watching pods):
					// if ovnkube-master is restarted, it will get all the add events with completed pods
					if oc.isObjectInTerminalState(objectsToRetry.oType, obj) {
						oc.processObjectInTerminalState(objectsToRetry, obj, key, resourceEventAdd)
						return
					}

					retryObj := objectsToRetry.initRetryObjWithAdd(obj, key)
					// If there is a delete entry with the same key, we got an add event for an object
					// with the same name as a previous object that failed deletion.
					// Destroy the old object before we add the new one.
					if retryObj.oldObj != nil {
						klog.Infof("Detected stale object during new object"+
							" add of type %s with the same key: %s",
							objectsToRetry.oType, key)
						internalCacheEntry := oc.getInternalCacheEntry(objectsToRetry.oType, obj)
						if err := oc.deleteResource(objectsToRetry, retryObj.oldObj, internalCacheEntry); err != nil {
							klog.Errorf("Failed to delete old object %s of type %s,"+
								" during add event: %v", key, objectsToRetry.oType, err)
							oc.recordErrorEvent(objectsToRetry.oType, obj, err)
							objectsToRetry.increaseFailedAttemptsCounter(retryObj)
							return
						}
						objectsToRetry.removeDeleteFromRetryObj(retryObj)
					}
					start := time.Now()
					if err := oc.addResource(objectsToRetry, obj, false); err != nil {
						klog.Errorf("Failed to create %s %s, error: %v", objectsToRetry.oType, key, err)
						oc.recordErrorEvent(objectsToRetry.oType, obj, err)
						objectsToRetry.increaseFailedAttemptsCounter(retryObj)
						return
					}
					klog.Infof("Creating %s %s took: %v", objectsToRetry.oType, key, time.Since(start))
					// delete retryObj if handling was successful
					objectsToRetry.deleteRetryObj(key)
					oc.recordSuccessEvent(objectsToRetry.oType, obj)
				})
			},
			UpdateFunc: func(old, newer interface{}) {
				// skip the whole update if old and newer are equal
				areEqual, err := areResourcesEqual(objectsToRetry.oType, old, newer)
				if err != nil {
					klog.Errorf("Could not compare old and newer resource objects of type %s: %v",
						objectsToRetry.oType, err)
					return
				}
				klog.V(5).Infof("Update event received for resource %s, old object is equal to new: %t",
					objectsToRetry.oType, areEqual)
				if areEqual {
					return
				}
				oc.recordUpdateEvent(objectsToRetry.oType, newer)

				// get the object keys for newer and old (expected to be the same)
				newKey, err := getResourceKey(objectsToRetry.oType, newer)
				if err != nil {
					klog.Errorf("Update of %s failed when looking up key of new obj: %v",
						objectsToRetry.oType, err)
					return
				}
				oldKey, err := getResourceKey(objectsToRetry.oType, old)
				if err != nil {
					klog.Errorf("Update of %s failed when looking up key of old obj: %v",
						objectsToRetry.oType, err)
					return
				}
				if newKey != oldKey {
					klog.Errorf("Could not update resource object of type %s: the key was changed from %s to %s",
						objectsToRetry.oType, oldKey, newKey)
					return
				}

				// skip the whole update if the new object doesn't exist anymore in the API server
				latest, err := oc.getResourceFromInformerCache(objectsToRetry.oType, newKey)
				if err != nil {
					// When processing an object in terminal state there is a chance that it was already removed from
					//  the API server. Since delete events for objects in terminal state are skipped delete it here.
					// This only applies to pod watchers (pods + dynamic network policy handlers watching pods).
					if kerrors.IsNotFound(err) && oc.isObjectInTerminalState(objectsToRetry.oType, newer) {
						klog.Warningf("%s %s is in terminal state but no longer exists in informer cache, removing",
							objectsToRetry.oType, newKey)
						oc.processObjectInTerminalState(objectsToRetry, newer, newKey, resourceEventUpdate)
					} else {
						klog.Warningf("Unable to get %s %s from informer cache (perhaps it was already"+
							" deleted?), skipping update: %v", objectsToRetry.oType, newKey, err)
					}
					return
				}

				klog.V(5).Infof("Update event received for %s %s",
					objectsToRetry.oType, newKey)

				hasUpdateFunc := hasResourceAnUpdateFunc(objectsToRetry.oType)

				objectsToRetry.DoWithLock(newKey, func(key string) {
					// STEP 1:
					// Delete existing (old) object if:
					// a) it has a retry entry marked for deletion and doesn't use update or
					// b) the resource is in terminal state (e.g. pod is completed) or
					// c) this resource type has no update function, so an update means delete old obj and add new one
					//
					retryEntryOrNil, found := objectsToRetry.getRetryObj(key)
					// retryEntryOrNil may be nil if found=false

					if found && retryEntryOrNil.oldObj != nil {
						// [step 1a] there is a retry entry marked for deletion
						klog.Infof("Found retry entry for %s %s marked for deletion: will delete the object",
							objectsToRetry.oType, oldKey)
						if err := oc.deleteResource(objectsToRetry, retryEntryOrNil.oldObj,
							retryEntryOrNil.config); err != nil {
							klog.Errorf("Failed to delete stale object %s, during update: %v", oldKey, err)
							oc.recordErrorEvent(objectsToRetry.oType, retryEntryOrNil.oldObj, err)
							retryEntry := objectsToRetry.initRetryObjWithAdd(latest, key)
							objectsToRetry.increaseFailedAttemptsCounter(retryEntry)
							return
						}
						// remove the old object from retry entry since it was correctly deleted
						if found {
							objectsToRetry.removeDeleteFromRetryObj(retryEntryOrNil)
						}
					} else if oc.isObjectInTerminalState(objectsToRetry.oType, latest) { // check the latest status on newer
						// [step 1b] The object is in a terminal state: delete it from the cluster,
						// delete its retry entry and return. This only applies to pod watchers
						// (pods + dynamic network policy handlers watching pods).
						oc.processObjectInTerminalState(objectsToRetry, latest, key, resourceEventUpdate)
						return

					} else if !hasUpdateFunc {
						// [step 1c] if this resource type has no update function,
						// delete old obj and in step 2 add the new one
						var existingCacheEntry interface{}
						if found {
							existingCacheEntry = retryEntryOrNil.config
						}
						klog.Infof("Deleting old %s of type %s during update", oldKey, objectsToRetry.oType)
						if err := oc.deleteResource(objectsToRetry, old, existingCacheEntry); err != nil {
							klog.Errorf("Failed to delete %s %s, during update: %v",
								objectsToRetry.oType, oldKey, err)
							oc.recordErrorEvent(objectsToRetry.oType, old, err)
							retryEntry := objectsToRetry.initRetryObjWithDelete(old, key, nil, false)
							objectsToRetry.initRetryObjWithAdd(latest, key)
							objectsToRetry.increaseFailedAttemptsCounter(retryEntry)
							return
						}
						// remove the old object from retry entry since it was correctly deleted
						if found {
							objectsToRetry.removeDeleteFromRetryObj(retryEntryOrNil)
						}
					}
					// STEP 2:
					// Execute the update function for this resource type; resort to add if no update
					// function is available.
					if hasUpdateFunc {
						// if this resource type has an update func, just call the update function
						if err := oc.updateResource(objectsToRetry, old, latest, found); err != nil {
							klog.Errorf("Failed to update %s, old=%s, new=%s, error: %v",
								objectsToRetry.oType, oldKey, newKey, err)
							oc.recordErrorEvent(objectsToRetry.oType, latest, err)
							var retryEntry *retryObjEntry
							if resourceNeedsUpdate(objectsToRetry.oType) {
								retryEntry = objectsToRetry.initRetryObjWithUpdate(old, latest, key)
							} else {
								retryEntry = objectsToRetry.initRetryObjWithAdd(latest, key)
							}
							objectsToRetry.increaseFailedAttemptsCounter(retryEntry)
							return
						}
					} else { // we previously deleted old object, now let's add the new one
						if err := oc.addResource(objectsToRetry, latest, false); err != nil {
							oc.recordErrorEvent(objectsToRetry.oType, latest, err)
							retryEntry := objectsToRetry.initRetryObjWithAdd(latest, key)
							objectsToRetry.increaseFailedAttemptsCounter(retryEntry)
							klog.Errorf("Failed to add %s %s, during update: %v",
								objectsToRetry.oType, newKey, err)
							return
						}
					}
					objectsToRetry.deleteRetryObj(key)
					oc.recordSuccessEvent(objectsToRetry.oType, latest)
				})
			},
			DeleteFunc: func(obj interface{}) {
				oc.recordDeleteEvent(objectsToRetry.oType, obj)
				key, err := getResourceKey(objectsToRetry.oType, obj)
				if err != nil {
					klog.Errorf("Delete of %s failed: %v", objectsToRetry.oType, err)
					return
				}
				klog.V(5).Infof("Delete event received for %s %s", objectsToRetry.oType, key)
				// If object is in terminal state, we would have already deleted it during update.
				// No reason to attempt to delete it here again.
				if oc.isObjectInTerminalState(objectsToRetry.oType, obj) {
					klog.Infof("Ignoring delete event for resource in terminal state %s %s",
						objectsToRetry.oType, key)
					return
				}
				objectsToRetry.DoWithLock(key, func(key string) {
					internalCacheEntry := oc.getInternalCacheEntry(objectsToRetry.oType, obj)
					retryEntry := objectsToRetry.initRetryObjWithDelete(obj, key, internalCacheEntry, false) // set up the retry obj for deletion
					if err = oc.deleteResource(objectsToRetry, obj, internalCacheEntry); err != nil {
						retryEntry.failedAttempts++
						klog.Errorf("Failed to delete %s %s, error: %v", objectsToRetry.oType, key, err)
						return
					}
					objectsToRetry.deleteRetryObj(key)
					oc.recordSuccessEvent(objectsToRetry.oType, obj)
				})
			},
		},
		syncFunc) // adds all existing objects at startup

	if err != nil {
		return nil, fmt.Errorf("watchResource for resource %v. "+
			"Failed addHandlerFunc: %v", objectsToRetry.oType, err)
	}

	// track the retry entries and every 30 seconds (or upon explicit request) check if any objects
	// need to be retried
	go oc.periodicallyRetryResources(objectsToRetry)

	return handler, nil
}
