package factory

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/scheme"
	egressfirewallinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/informers/externalversions"

	egressipapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/scheme"
	egressipinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/informers/externalversions"
	egressiplister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/listers/egressip/v1"

	ocpcloudnetworkapi "github.com/openshift/api/cloudnetwork/v1"
	ocpcloudnetworkinformerfactory "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	ocpcloudnetworklister "github.com/openshift/client-go/cloudnetwork/listers/cloudnetwork/v1"

	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	informerfactory "k8s.io/client-go/informers"
	v1coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	netlisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// WatchFactory initializes and manages common kube watches
type WatchFactory struct {
	// Must be first member in the struct due to Golang ARM/x86 32-bit
	// requirements with atomic accesses
	handlerCounter uint64

	iFactory     informerfactory.SharedInformerFactory
	eipFactory   egressipinformerfactory.SharedInformerFactory
	efFactory    egressfirewallinformerfactory.SharedInformerFactory
	cpipcFactory ocpcloudnetworkinformerfactory.SharedInformerFactory
	informers    map[reflect.Type]*informer

	stopChan chan struct{}
}

// WatchFactory implements the ObjectCacheInterface interface.
var _ ObjectCacheInterface = &WatchFactory{}

const (
	// resync time is 0, none of the resources being watched in ovn-kubernetes have
	// any race condition where a resync may be required e.g. cni executable on node watching for
	// events on pods and assuming that an 'ADD' event will contain the annotations put in by
	// ovnkube master (currently, it is just a 'get' loop)
	// the downside of making it tight (like 10 minutes) is needless spinning on all resources
	// However, AddEventHandlerWithResyncPeriod can specify a per handler resync period
	resyncInterval        = 0
	handlerAlive   uint32 = 0
	handlerDead    uint32 = 1

	// namespace, node, and pod handlers
	defaultNumEventQueues uint32 = 15
)

// types for dynamic handlers created when adding a network policy
type peerService struct{}
type peerNamespaceAndPodSelector struct{}
type peerPodForNamespaceAndPodSelector struct{} // created during the add function of peerNamespaceAndPodSelectorType
type peerNamespaceSelector struct{}
type peerPodSelector struct{}
type localPodSelector struct{}

var (
	PodType                               reflect.Type = reflect.TypeOf(&kapi.Pod{})
	ServiceType                           reflect.Type = reflect.TypeOf(&kapi.Service{})
	EndpointsType                         reflect.Type = reflect.TypeOf(&kapi.Endpoints{})
	PolicyType                            reflect.Type = reflect.TypeOf(&knet.NetworkPolicy{})
	NamespaceType                         reflect.Type = reflect.TypeOf(&kapi.Namespace{})
	NodeType                              reflect.Type = reflect.TypeOf(&kapi.Node{})
	EgressFirewallType                    reflect.Type = reflect.TypeOf(&egressfirewallapi.EgressFirewall{})
	EgressIPType                          reflect.Type = reflect.TypeOf(&egressipapi.EgressIP{})
	CloudPrivateIPConfigType              reflect.Type = reflect.TypeOf(&ocpcloudnetworkapi.CloudPrivateIPConfig{})
	PeerServiceType                       reflect.Type = reflect.TypeOf(&peerService{})
	PeerNamespaceAndPodSelectorType       reflect.Type = reflect.TypeOf(&peerNamespaceAndPodSelector{})
	PeerPodForNamespaceAndPodSelectorType reflect.Type = reflect.TypeOf(&peerPodForNamespaceAndPodSelector{})
	PeerNamespaceSelectorType             reflect.Type = reflect.TypeOf(&peerNamespaceSelector{})
	PeerPodSelectorType                   reflect.Type = reflect.TypeOf(&peerPodSelector{})
	LocalPodSelectorType                  reflect.Type = reflect.TypeOf(&localPodSelector{})
)

// NewMasterWatchFactory initializes a new watch factory for the master or master+node processes.
func NewMasterWatchFactory(ovnClientset *util.OVNClientset) (*WatchFactory, error) {
	// resync time is 12 hours, none of the resources being watched in ovn-kubernetes have
	// any race condition where a resync may be required e.g. cni executable on node watching for
	// events on pods and assuming that an 'ADD' event will contain the annotations put in by
	// ovnkube master (currently, it is just a 'get' loop)
	// the downside of making it tight (like 10 minutes) is needless spinning on all resources
	// However, AddEventHandlerWithResyncPeriod can specify a per handler resync period
	wf := &WatchFactory{
		iFactory:     informerfactory.NewSharedInformerFactory(ovnClientset.KubeClient, resyncInterval),
		eipFactory:   egressipinformerfactory.NewSharedInformerFactory(ovnClientset.EgressIPClient, resyncInterval),
		efFactory:    egressfirewallinformerfactory.NewSharedInformerFactory(ovnClientset.EgressFirewallClient, resyncInterval),
		cpipcFactory: ocpcloudnetworkinformerfactory.NewSharedInformerFactory(ovnClientset.CloudNetworkClient, resyncInterval),
		informers:    make(map[reflect.Type]*informer),
		stopChan:     make(chan struct{}),
	}

	if err := egressipapi.AddToScheme(egressipscheme.Scheme); err != nil {
		return nil, err
	}
	if err := egressfirewallapi.AddToScheme(egressfirewallscheme.Scheme); err != nil {
		return nil, err
	}

	// For Services and Endpoints, pre-populate the shared Informer with one that
	// has a label selector excluding headless services.
	wf.iFactory.InformerFor(&kapi.Service{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredServiceInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noAlternateProxySelector())
	})

	wf.iFactory.InformerFor(&kapi.Endpoints{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredEndpointsInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noHeadlessServiceSelector())
	})

	var err error

	// Create our informer-wrapper informer (and underlying shared informer) for types we need
	wf.informers[PodType], err = newQueuedInformer(PodType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan,
		defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[ServiceType], err = newInformer(ServiceType, wf.iFactory.Core().V1().Services().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[EndpointsType], err = newInformer(EndpointsType, wf.iFactory.Core().V1().Endpoints().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[PolicyType], err = newInformer(PolicyType, wf.iFactory.Networking().V1().NetworkPolicies().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[NamespaceType], err = newQueuedInformer(NamespaceType, wf.iFactory.Core().V1().Namespaces().Informer(),
		wf.stopChan, defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[NodeType], err = newQueuedInformer(NodeType, wf.iFactory.Core().V1().Nodes().Informer(), wf.stopChan,
		defaultNumEventQueues)
	if err != nil {
		return nil, err
	}

	if config.OVNKubernetesFeature.EnableEgressIP {
		wf.informers[EgressIPType], err = newInformer(EgressIPType, wf.eipFactory.K8s().V1().EgressIPs().Informer())
		if err != nil {
			return nil, err
		}
	}
	if config.OVNKubernetesFeature.EnableEgressFirewall {
		wf.informers[EgressFirewallType], err = newInformer(EgressFirewallType, wf.efFactory.K8s().V1().EgressFirewalls().Informer())
		if err != nil {
			return nil, err
		}
	}
	if util.PlatformTypeIsEgressIPCloudProvider() {
		wf.informers[CloudPrivateIPConfigType], err = newInformer(CloudPrivateIPConfigType, wf.cpipcFactory.Cloud().V1().CloudPrivateIPConfigs().Informer())
		if err != nil {
			return nil, err
		}
	}
	return wf, nil
}

// Start starts the factory and begins processing events
func (wf *WatchFactory) Start() error {
	wf.iFactory.Start(wf.stopChan)
	for oType, synced := range wf.iFactory.WaitForCacheSync(wf.stopChan) {
		if !synced {
			return fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}
	if config.OVNKubernetesFeature.EnableEgressIP && wf.eipFactory != nil {
		wf.eipFactory.Start(wf.stopChan)
		for oType, synced := range wf.eipFactory.WaitForCacheSync(wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}
	if config.OVNKubernetesFeature.EnableEgressFirewall && wf.efFactory != nil {
		wf.efFactory.Start(wf.stopChan)
		for oType, synced := range wf.efFactory.WaitForCacheSync(wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}
	if util.PlatformTypeIsEgressIPCloudProvider() && wf.cpipcFactory != nil {
		wf.cpipcFactory.Start(wf.stopChan)
		for oType, synced := range wf.cpipcFactory.WaitForCacheSync(wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}
	return nil
}

// NewNodeWatchFactory initializes a watch factory with significantly fewer
// informers to save memory + bandwidth. It is to be used by the node-only process.
func NewNodeWatchFactory(ovnClientset *util.OVNClientset, nodeName string) (*WatchFactory, error) {
	wf := &WatchFactory{
		iFactory:  informerfactory.NewSharedInformerFactory(ovnClientset.KubeClient, resyncInterval),
		informers: make(map[reflect.Type]*informer),
		stopChan:  make(chan struct{}),
	}
	// For Services and Endpoints, pre-populate the shared Informer with one that
	// has a label selector excluding headless services.
	wf.iFactory.InformerFor(&kapi.Service{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredServiceInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noAlternateProxySelector())
	})

	wf.iFactory.InformerFor(&kapi.Endpoints{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredEndpointsInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noHeadlessServiceSelector())
	})

	// For Pods, only select pods scheduled to this node
	wf.iFactory.InformerFor(&kapi.Pod{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredPodInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(opts *metav1.ListOptions) {
				opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
			})
	})

	var err error
	wf.informers[PodType], err = newQueuedInformer(PodType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan,
		defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[ServiceType], err = newInformer(ServiceType, wf.iFactory.Core().V1().Services().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[EndpointsType], err = newInformer(EndpointsType, wf.iFactory.Core().V1().Endpoints().Informer())
	if err != nil {
		return nil, err
	}

	wf.informers[NodeType], err = newInformer(NodeType, wf.iFactory.Core().V1().Nodes().Informer())
	if err != nil {
		return nil, err
	}

	return wf, nil
}

func (wf *WatchFactory) Shutdown() {
	close(wf.stopChan)

	// Remove all informer handlers
	for _, inf := range wf.informers {
		inf.shutdown()
	}
}

func getObjectMeta(objType reflect.Type, obj interface{}) (*metav1.ObjectMeta, error) {
	switch objType {
	case PodType:
		if pod, ok := obj.(*kapi.Pod); ok {
			return &pod.ObjectMeta, nil
		}
	case ServiceType:
		if service, ok := obj.(*kapi.Service); ok {
			return &service.ObjectMeta, nil
		}
	case EndpointsType:
		if endpoints, ok := obj.(*kapi.Endpoints); ok {
			return &endpoints.ObjectMeta, nil
		}
	case PolicyType:
		if policy, ok := obj.(*knet.NetworkPolicy); ok {
			return &policy.ObjectMeta, nil
		}
	case NamespaceType:
		if namespace, ok := obj.(*kapi.Namespace); ok {
			return &namespace.ObjectMeta, nil
		}
	case NodeType:
		if node, ok := obj.(*kapi.Node); ok {
			return &node.ObjectMeta, nil
		}
	case EgressFirewallType:
		if egressFirewall, ok := obj.(*egressfirewallapi.EgressFirewall); ok {
			return &egressFirewall.ObjectMeta, nil
		}
	case EgressIPType:
		if egressIP, ok := obj.(*egressipapi.EgressIP); ok {
			return &egressIP.ObjectMeta, nil
		}
	case CloudPrivateIPConfigType:
		if cloudPrivateIPConfig, ok := obj.(*ocpcloudnetworkapi.CloudPrivateIPConfig); ok {
			return &cloudPrivateIPConfig.ObjectMeta, nil
		}
	}
	return nil, fmt.Errorf("cannot get ObjectMeta from type %v", objType)
}

type AddHandlerFuncType func(namespace string, sel labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler

func (wf *WatchFactory) GetResourceHandlerFunc(objType reflect.Type) (AddHandlerFuncType, error) {
	switch objType {
	case PolicyType:
		return func(namespace string, sel labels.Selector,
			funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
			return wf.AddPolicyHandler(funcs, processExisting)
		}, nil

	case NodeType:
		return func(namespace string, sel labels.Selector,
			funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
			return wf.AddNodeHandler(funcs, processExisting)
		}, nil

	case PeerServiceType:
		return func(namespace string, sel labels.Selector,
			funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
			return wf.AddFilteredServiceHandler(namespace, funcs, processExisting)
		}, nil

	case PeerPodSelectorType, LocalPodSelectorType, PodType:
		return func(namespace string, sel labels.Selector,
			funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
			return wf.AddFilteredPodHandler(namespace, sel, funcs, processExisting)
		}, nil

	case PeerNamespaceAndPodSelectorType, PeerNamespaceSelectorType:
		return func(namespace string, sel labels.Selector,
			funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
			return wf.AddFilteredNamespaceHandler(namespace, sel, funcs, processExisting)
		}, nil

	case PeerPodForNamespaceAndPodSelectorType:
		return func(namespace string, sel labels.Selector,
			funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
			return wf.AddFilteredPodHandler(namespace, sel, funcs, processExisting)
		}, nil
	}
	return nil, fmt.Errorf("cannot get ObjectMeta from type %v", objType)
}

func (wf *WatchFactory) addHandler(objType reflect.Type, namespace string, sel labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	inf, ok := wf.informers[objType]
	if !ok {
		klog.Fatalf("Tried to add handler of unknown object type %v", objType)
	}

	filterFunc := func(obj interface{}) bool {
		if namespace == "" && sel == nil {
			// Unfiltered handler
			return true
		}
		meta, err := getObjectMeta(objType, obj)
		if err != nil {
			klog.Errorf("Watch handler filter error: %v", err)
			return false
		}
		if namespace != "" && meta.Namespace != namespace {
			return false
		}
		if sel != nil && !sel.Matches(labels.Set(meta.Labels)) {
			return false
		}
		return true
	}

	inf.Lock()
	defer inf.Unlock()

	items := make([]interface{}, 0)
	for _, obj := range inf.inf.GetStore().List() {
		if filterFunc(obj) {
			items = append(items, obj)
		}
	}
	if processExisting != nil {
		// Process existing items as a set so the caller can clean up
		// after a restart or whatever
		processExisting(items)
	}

	handlerID := atomic.AddUint64(&wf.handlerCounter, 1)
	handler := inf.addHandler(handlerID, filterFunc, funcs, items)
	klog.V(5).Infof("Added %v event handler %d", objType, handler.id)
	return handler
}

func (wf *WatchFactory) removeHandler(objType reflect.Type, handler *Handler) {
	wf.informers[objType].removeHandler(handler)
}

// AddPodHandler adds a handler function that will be executed on Pod object changes
func (wf *WatchFactory) AddPodHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(PodType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredPodHandler adds a handler function that will be executed when Pod objects that match the given filters change
func (wf *WatchFactory) AddFilteredPodHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(PodType, namespace, sel, handlerFuncs, processExisting)
}

// RemovePodHandler removes a Pod object event handler function
func (wf *WatchFactory) RemovePodHandler(handler *Handler) {
	wf.removeHandler(PodType, handler)
}

// AddServiceHandler adds a handler function that will be executed on Service object changes
func (wf *WatchFactory) AddServiceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(ServiceType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredServiceHandler adds a handler function that will be executed on all Service object changes for a specific namespace
func (wf *WatchFactory) AddFilteredServiceHandler(namespace string, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(ServiceType, namespace, nil, handlerFuncs, processExisting)
}

// RemoveServiceHandler removes a Service object event handler function
func (wf *WatchFactory) RemoveServiceHandler(handler *Handler) {
	wf.removeHandler(ServiceType, handler)
}

// AddEndpointsHandler adds a handler function that will be executed on Endpoints object changes
func (wf *WatchFactory) AddEndpointsHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(EndpointsType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredEndpointsHandler adds a handler function that will be executed when Endpoint objects that match the given filters change
func (wf *WatchFactory) AddFilteredEndpointsHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(EndpointsType, namespace, sel, handlerFuncs, processExisting)
}

// RemoveEndpointsHandler removes a Endpoints object event handler function
func (wf *WatchFactory) RemoveEndpointsHandler(handler *Handler) {
	wf.removeHandler(EndpointsType, handler)
}

// AddPolicyHandler adds a handler function that will be executed on NetworkPolicy object changes
func (wf *WatchFactory) AddPolicyHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(PolicyType, "", nil, handlerFuncs, processExisting)
}

// RemovePolicyHandler removes a NetworkPolicy object event handler function
func (wf *WatchFactory) RemovePolicyHandler(handler *Handler) {
	wf.removeHandler(PolicyType, handler)
}

// AddEgressFirewallHandler adds a handler function that will be executed on EgressFirewall object changes
func (wf *WatchFactory) AddEgressFirewallHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(EgressFirewallType, "", nil, handlerFuncs, processExisting)
}

// RemoveEgressFirewallHandler removes an EgressFirewall object event handler function
func (wf *WatchFactory) RemoveEgressFirewallHandler(handler *Handler) {
	wf.removeHandler(EgressFirewallType, handler)
}

// AddEgressIPHandler adds a handler function that will be executed on EgressIP object changes
func (wf *WatchFactory) AddEgressIPHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(EgressIPType, "", nil, handlerFuncs, processExisting)
}

// RemoveEgressIPHandler removes an EgressIP object event handler function
func (wf *WatchFactory) RemoveEgressIPHandler(handler *Handler) {
	wf.removeHandler(EgressIPType, handler)
}

// AddCloudPrivateIPConfigHandler adds a handler function that will be executed on CloudPrivateIPConfig object changes
func (wf *WatchFactory) AddCloudPrivateIPConfigHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(CloudPrivateIPConfigType, "", nil, handlerFuncs, processExisting)
}

// RemoveCloudPrivateIPConfigHandler removes an CloudPrivateIPConfig object event handler function
func (wf *WatchFactory) RemoveCloudPrivateIPConfigHandler(handler *Handler) {
	wf.removeHandler(CloudPrivateIPConfigType, handler)
}

// AddNamespaceHandler adds a handler function that will be executed on Namespace object changes
func (wf *WatchFactory) AddNamespaceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(NamespaceType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredNamespaceHandler adds a handler function that will be executed when Namespace objects that match the given filters change
func (wf *WatchFactory) AddFilteredNamespaceHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(NamespaceType, namespace, sel, handlerFuncs, processExisting)
}

// RemoveNamespaceHandler removes a Namespace object event handler function
func (wf *WatchFactory) RemoveNamespaceHandler(handler *Handler) {
	wf.removeHandler(NamespaceType, handler)
}

// AddNodeHandler adds a handler function that will be executed on Node object changes
func (wf *WatchFactory) AddNodeHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(NodeType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredNodeHandler dds a handler function that will be executed when Node objects that match the given label selector
func (wf *WatchFactory) AddFilteredNodeHandler(sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(NodeType, "", sel, handlerFuncs, processExisting)
}

// RemoveNodeHandler removes a Node object event handler function
func (wf *WatchFactory) RemoveNodeHandler(handler *Handler) {
	wf.removeHandler(NodeType, handler)
}

// GetPod returns the pod spec given the namespace and pod name
func (wf *WatchFactory) GetPod(namespace, name string) (*kapi.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	return podLister.Pods(namespace).Get(name)
}

// GetAllPods returns all the pods in the cluster
func (wf *WatchFactory) GetAllPods() ([]*kapi.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	return podLister.List(labels.Everything())
}

// GetPods returns all the pods in a given namespace
func (wf *WatchFactory) GetPods(namespace string) ([]*kapi.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	return podLister.Pods(namespace).List(labels.Everything())
}

// GetPodsBySelector returns all the pods in a given namespace by the label selector
func (wf *WatchFactory) GetPodsBySelector(namespace string, labelSelector metav1.LabelSelector) ([]*kapi.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return nil, err
	}
	return podLister.Pods(namespace).List(selector)
}

// GetNodes returns the node specs of all the nodes
func (wf *WatchFactory) GetNodes() ([]*kapi.Node, error) {
	return wf.ListNodes(labels.Everything())
}

// ListNodes returns nodes that match a selector
func (wf *WatchFactory) ListNodes(selector labels.Selector) ([]*kapi.Node, error) {
	nodeLister := wf.informers[NodeType].lister.(listers.NodeLister)
	return nodeLister.List(selector)
}

// GetNode returns the node spec of a given node by name
func (wf *WatchFactory) GetNode(name string) (*kapi.Node, error) {
	nodeLister := wf.informers[NodeType].lister.(listers.NodeLister)
	return nodeLister.Get(name)
}

// GetService returns the service spec of a service in a given namespace
func (wf *WatchFactory) GetService(namespace, name string) (*kapi.Service, error) {
	serviceLister := wf.informers[ServiceType].lister.(listers.ServiceLister)
	return serviceLister.Services(namespace).Get(name)
}

// GetEndpoints returns the endpoints list in a given namespace
func (wf *WatchFactory) GetEndpoints(namespace string) ([]*kapi.Endpoints, error) {
	endpointsLister := wf.informers[EndpointsType].lister.(listers.EndpointsLister)
	return endpointsLister.Endpoints(namespace).List(labels.Everything())
}

// GetEndpoint returns a specific endpoint in a given namespace
func (wf *WatchFactory) GetEndpoint(namespace, name string) (*kapi.Endpoints, error) {
	endpointsLister := wf.informers[EndpointsType].lister.(listers.EndpointsLister)
	return endpointsLister.Endpoints(namespace).Get(name)
}

func (wf *WatchFactory) GetCloudPrivateIPConfig(name string) (*ocpcloudnetworkapi.CloudPrivateIPConfig, error) {
	cloudPrivateIPConfigLister := wf.informers[CloudPrivateIPConfigType].lister.(ocpcloudnetworklister.CloudPrivateIPConfigLister)
	return cloudPrivateIPConfigLister.Get(name)
}

func (wf *WatchFactory) GetEgressIP(name string) (*egressipapi.EgressIP, error) {
	egressIPLister := wf.informers[EgressIPType].lister.(egressiplister.EgressIPLister)
	return egressIPLister.Get(name)
}

func (wf *WatchFactory) GetEgressIPs() ([]*egressipapi.EgressIP, error) {
	egressIPLister := wf.informers[EgressIPType].lister.(egressiplister.EgressIPLister)
	return egressIPLister.List(labels.Everything())
}

// GetNamespace returns a specific namespace
func (wf *WatchFactory) GetNamespace(name string) (*kapi.Namespace, error) {
	namespaceLister := wf.informers[NamespaceType].lister.(listers.NamespaceLister)
	return namespaceLister.Get(name)
}

// GetNamespaces returns a list of namespaces in the cluster
func (wf *WatchFactory) GetNamespaces() ([]*kapi.Namespace, error) {
	namespaceLister := wf.informers[NamespaceType].lister.(listers.NamespaceLister)
	return namespaceLister.List(labels.Everything())
}

// GetNamespacesBySelector returns a list of namespaces in the cluster by the label selector
func (wf *WatchFactory) GetNamespacesBySelector(labelSelector metav1.LabelSelector) ([]*kapi.Namespace, error) {
	namespaceLister := wf.informers[NamespaceType].lister.(listers.NamespaceLister)
	selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return nil, err
	}
	return namespaceLister.List(selector)
}

// GetNetworkPolicy gets a specific network policy by the namespace/name
func (wf *WatchFactory) GetNetworkPolicy(namespace, name string) (*knet.NetworkPolicy, error) {
	networkPolicyLister := wf.informers[PolicyType].lister.(netlisters.NetworkPolicyLister)
	return networkPolicyLister.NetworkPolicies(namespace).Get(name)
}

func (wf *WatchFactory) NodeInformer() cache.SharedIndexInformer {
	return wf.informers[NodeType].inf
}

// LocalPodInformer returns a shared Informer that may or may not only
// return pods running on the local node.
func (wf *WatchFactory) LocalPodInformer() cache.SharedIndexInformer {
	return wf.informers[PodType].inf
}

func (wf *WatchFactory) PodInformer() cache.SharedIndexInformer {
	return wf.informers[PodType].inf
}

func (wf *WatchFactory) NamespaceInformer() cache.SharedIndexInformer {
	return wf.informers[NamespaceType].inf
}

func (wf *WatchFactory) ServiceInformer() cache.SharedIndexInformer {
	return wf.informers[ServiceType].inf
}

// noHeadlessServiceSelector is a LabelSelector added to the watch for
// Endpoints (and, eventually, EndpointSlices) that excludes endpoints
// for headless services.
// This matches the behavior of kube-proxy
func noHeadlessServiceSelector() func(options *metav1.ListOptions) {
	// if the service is headless, skip it
	noHeadlessEndpoints, err := labels.NewRequirement(kapi.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		// cannot occur
		panic(err)
	}

	labelSelector := labels.NewSelector().Add(*noHeadlessEndpoints)

	return func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}
}

// noAlternateProxySelector is a LabelSelector added to the watch for
// services that excludes services with a well-known label indicating
// proxying is via an alternate proxy.
// This matches the behavior of kube-proxy
func noAlternateProxySelector() func(options *metav1.ListOptions) {
	// if the proxy-name annotation is set, skip this service
	noProxyName, err := labels.NewRequirement("service.kubernetes.io/service-proxy-name", selection.DoesNotExist, nil)
	if err != nil {
		// cannot occur
		panic(err)
	}

	labelSelector := labels.NewSelector().Add(*noProxyName)

	return func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}
}
