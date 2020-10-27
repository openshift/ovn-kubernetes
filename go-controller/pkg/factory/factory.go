package factory

import (
	"fmt"
	"hash/fnv"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned"
	egressfirewallscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/scheme"
	egressfirewallinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/informers/externalversions"
	egressfirewalllister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/listers/egressfirewall/v1"

	egressipapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/scheme"
	egressipinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/informers/externalversions"
	egressiplister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/listers/egressip/v1"
	apiextensionsapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	apiextensionsinformerfactory "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions"
	apiextensionslister "k8s.io/apiextensions-apiserver/pkg/client/listers/apiextensions/v1beta1"

	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	informerfactory "k8s.io/client-go/informers"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

// Handler represents an event handler and is private to the factory module
type Handler struct {
	base cache.FilteringResourceEventHandler

	id uint64
	// tombstone is used to track the handler's lifetime. handlerAlive
	// indicates the handler can be called, while handlerDead indicates
	// it has been scheduled for removal and should not be called.
	// tombstone should only be set using atomic operations since it is
	// used from multiple goroutines.
	tombstone uint32
}

func (h *Handler) OnAdd(obj interface{}) {
	if atomic.LoadUint32(&h.tombstone) == handlerAlive {
		h.base.OnAdd(obj)
	}
}

func (h *Handler) OnUpdate(oldObj, newObj interface{}) {
	if atomic.LoadUint32(&h.tombstone) == handlerAlive {
		h.base.OnUpdate(oldObj, newObj)
	}
}

func (h *Handler) OnDelete(obj interface{}) {
	if atomic.LoadUint32(&h.tombstone) == handlerAlive {
		h.base.OnDelete(obj)
	}
}

func (h *Handler) kill() bool {
	return atomic.CompareAndSwapUint32(&h.tombstone, handlerAlive, handlerDead)
}

type event struct {
	obj     interface{}
	oldObj  interface{}
	process func(*event)
}

type listerInterface interface{}

type initialAddFn func(*Handler, []interface{})

type informer struct {
	sync.RWMutex
	oType    reflect.Type
	inf      cache.SharedIndexInformer
	handlers map[uint64]*Handler
	events   []chan *event
	lister   listerInterface
	// initialAddFunc will be called to deliver the initial list of objects
	// when a handler is added
	initialAddFunc initialAddFn
	shutdownWg     sync.WaitGroup
}

func (i *informer) forEachQueuedHandler(f func(h *Handler)) {
	i.RLock()
	curHandlers := make([]*Handler, 0, len(i.handlers))
	for _, handler := range i.handlers {
		curHandlers = append(curHandlers, handler)
	}
	i.RUnlock()

	for _, handler := range curHandlers {
		f(handler)
	}
}

func (i *informer) forEachHandler(obj interface{}, f func(h *Handler)) {
	i.RLock()
	defer i.RUnlock()

	objType := reflect.TypeOf(obj)
	if objType != i.oType {
		klog.Errorf("Object type %v did not match expected %v", objType, i.oType)
		return
	}

	for _, handler := range i.handlers {
		f(handler)
	}
}

func (i *informer) addHandler(id uint64, filterFunc func(obj interface{}) bool, funcs cache.ResourceEventHandler, existingItems []interface{}) *Handler {
	handler := &Handler{
		cache.FilteringResourceEventHandler{
			FilterFunc: filterFunc,
			Handler:    funcs,
		},
		id,
		handlerAlive,
	}

	// Send existing items to the handler's add function; informers usually
	// do this but since we share informers, it's long-since happened so
	// we must emulate that here
	i.initialAddFunc(handler, existingItems)

	i.handlers[id] = handler
	return handler
}

func (i *informer) removeHandler(handler *Handler) {
	if !handler.kill() {
		klog.Errorf("Removing already-removed %v event handler %d", i.oType, handler.id)
		return
	}

	klog.V(5).Infof("Sending %v event handler %d for removal", i.oType, handler.id)

	go func() {
		i.Lock()
		defer i.Unlock()
		if _, ok := i.handlers[handler.id]; ok {
			// Remove the handler
			delete(i.handlers, handler.id)
			klog.V(5).Infof("Removed %v event handler %d", i.oType, handler.id)
		} else {
			klog.Warningf("Tried to remove unknown object type %v event handler %d", i.oType, handler.id)
		}
	}()
}

func (i *informer) processEvents(events chan *event, stopChan <-chan struct{}) {
	defer i.shutdownWg.Done()
	for {
		select {
		case e, ok := <-events:
			if !ok {
				return
			}
			e.process(e)
		case <-stopChan:
			return
		}
	}
}

func getQueueNum(oType reflect.Type, obj interface{}) uint32 {
	meta, err := getObjectMeta(oType, obj)
	if err != nil {
		klog.Errorf("Object has no meta: %v", err)
		return 0
	}

	// Distribute the object to an event queue based on a hash of its
	// namespaced name, so that all events for a given object are
	// serialized in one queue.
	h := fnv.New32()
	if meta.Namespace != "" {
		_, _ = h.Write([]byte(meta.Namespace))
		_, _ = h.Write([]byte("/"))
	}
	_, _ = h.Write([]byte(meta.Name))
	return h.Sum32() % uint32(numEventQueues)
}

// enqueueEvent adds an event to the appropriate queue for the object
func (i *informer) enqueueEvent(oldObj, obj interface{}, processFunc func(*event)) {
	i.events[getQueueNum(i.oType, obj)] <- &event{
		obj:     obj,
		oldObj:  oldObj,
		process: processFunc,
	}
}

func ensureObjectOnDelete(obj interface{}, expectedType reflect.Type) (interface{}, error) {
	if expectedType == reflect.TypeOf(obj) {
		return obj, nil
	}
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("couldn't get object from tombstone: %+v", obj)
	}
	obj = tombstone.Obj
	objType := reflect.TypeOf(obj)
	if expectedType != objType {
		return nil, fmt.Errorf("expected tombstone object resource type %v but got %v", expectedType, objType)
	}
	return obj, nil
}

func (i *informer) newFederatedQueuedHandler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			i.enqueueEvent(nil, obj, func(e *event) {
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnAdd(e.obj)
				})
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			metrics.MetricResourceUpdateCount.WithLabelValues(i.oType.Elem().Name()).Inc()
			i.enqueueEvent(oldObj, newObj, func(e *event) {
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnUpdate(e.oldObj, e.obj)
				})
			})
		},
		DeleteFunc: func(obj interface{}) {
			realObj, err := ensureObjectOnDelete(obj, i.oType)
			if err != nil {
				klog.Errorf(err.Error())
				return
			}
			i.enqueueEvent(nil, realObj, func(e *event) {
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnDelete(e.obj)
				})
			})
		},
	}
}

func (i *informer) newFederatedHandler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			i.forEachHandler(obj, func(h *Handler) {
				h.OnAdd(obj)
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			name := i.oType.Elem().Name()
			metrics.MetricResourceUpdateCount.WithLabelValues(name).Inc()
			i.forEachHandler(newObj, func(h *Handler) {
				start := time.Now()
				h.OnUpdate(oldObj, newObj)
				metrics.MetricResourceUpdateLatency.WithLabelValues(name).Observe(time.Since(start).Seconds())
			})
		},
		DeleteFunc: func(obj interface{}) {
			realObj, err := ensureObjectOnDelete(obj, i.oType)
			if err != nil {
				klog.Errorf(err.Error())
				return
			}
			i.forEachHandler(realObj, func(h *Handler) {
				h.OnDelete(realObj)
			})
		},
	}
}

func (i *informer) removeAllHandlers() {
	i.Lock()
	defer i.Unlock()
	for _, handler := range i.handlers {
		i.removeHandler(handler)
	}
}

func (i *informer) shutdown() {
	i.removeAllHandlers()

	// Wait for all event processors to finish
	i.shutdownWg.Wait()
}

func newInformerLister(oType reflect.Type, sharedInformer cache.SharedIndexInformer) (listerInterface, error) {
	switch oType {
	case podType:
		return listers.NewPodLister(sharedInformer.GetIndexer()), nil
	case serviceType:
		return listers.NewServiceLister(sharedInformer.GetIndexer()), nil
	case endpointsType:
		return listers.NewEndpointsLister(sharedInformer.GetIndexer()), nil
	case namespaceType:
		return listers.NewNamespaceLister(sharedInformer.GetIndexer()), nil
	case nodeType:
		return listers.NewNodeLister(sharedInformer.GetIndexer()), nil
	case policyType:
		return nil, nil
	case egressFirewallType:
		return egressfirewalllister.NewEgressFirewallLister(sharedInformer.GetIndexer()), nil
	case crdType:
		return apiextensionslister.NewCustomResourceDefinitionLister(sharedInformer.GetIndexer()), nil
	case egressIPType:
		return egressiplister.NewEgressIPLister(sharedInformer.GetIndexer()), nil
	}

	return nil, fmt.Errorf("cannot create lister from type %v", oType)
}

func newBaseInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer) (*informer, error) {
	lister, err := newInformerLister(oType, sharedInformer)
	if err != nil {
		klog.Errorf(err.Error())
		return nil, err
	}

	return &informer{
		oType:      oType,
		inf:        sharedInformer,
		lister:     lister,
		handlers:   make(map[uint64]*Handler),
		shutdownWg: sync.WaitGroup{},
	}, nil
}

func newInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer) (*informer, error) {
	i, err := newBaseInformer(oType, sharedInformer)
	if err != nil {
		return nil, err
	}
	i.initialAddFunc = func(h *Handler, items []interface{}) {
		for _, item := range items {
			h.OnAdd(item)
		}
	}
	i.inf.AddEventHandler(i.newFederatedHandler())
	return i, nil
}

func newQueuedInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer, stopChan chan struct{}) (*informer, error) {
	i, err := newBaseInformer(oType, sharedInformer)
	if err != nil {
		return nil, err
	}
	i.events = make([]chan *event, numEventQueues)
	i.shutdownWg.Add(len(i.events))
	for j := range i.events {
		i.events[j] = make(chan *event, 10)
		go i.processEvents(i.events[j], stopChan)
	}
	i.initialAddFunc = func(h *Handler, items []interface{}) {
		// Make a handler-specific channel array across which the
		// initial add events will be distributed. When a new handler
		// is added, only that handler should receive events for all
		// existing objects.
		adds := make([]chan interface{}, numEventQueues)
		queueWg := &sync.WaitGroup{}
		queueWg.Add(len(adds))
		for j := range adds {
			adds[j] = make(chan interface{}, 10)
			go func(addChan chan interface{}) {
				defer queueWg.Done()
				for {
					obj, ok := <-addChan
					if !ok {
						return
					}
					h.OnAdd(obj)
				}
			}(adds[j])
		}
		// Distribute the existing items into the handler-specific
		// channel array.
		for _, obj := range items {
			queueIdx := getQueueNum(i.oType, obj)
			adds[queueIdx] <- obj
		}
		// Close all the channels
		for j := range adds {
			close(adds[j])
		}
		// Wait until all the object additions have been processed
		queueWg.Wait()
	}
	i.inf.AddEventHandler(i.newFederatedQueuedHandler())
	return i, nil
}

// WatchFactory initializes and manages common kube watches
type WatchFactory struct {
	// Must be first member in the struct due to Golang ARM/x86 32-bit
	// requirements with atomic accesses
	handlerCounter uint64

	iFactory    informerfactory.SharedInformerFactory
	eipFactory  egressipinformerfactory.SharedInformerFactory
	efFactory   egressfirewallinformerfactory.SharedInformerFactory
	efClientset egressfirewallclientset.Interface
	crdFactory  apiextensionsinformerfactory.SharedInformerFactory
	informers   map[reflect.Type]*informer

	stopChan               chan struct{}
	egressFirewallStopChan chan struct{}
}

// ObjectCacheInterface represents the exported methods for getting
// kubernetes resources from the informer cache

type ObjectCacheInterface interface {
	GetPod(namespace, name string) (*kapi.Pod, error)
	GetPods(namespace string) ([]*kapi.Pod, error)
	GetNodes() ([]*kapi.Node, error)
	GetNode(name string) (*kapi.Node, error)
	GetService(namespace, name string) (*kapi.Service, error)
	GetEndpoints(namespace string) ([]*kapi.Endpoints, error)
	GetEndpoint(namespace, name string) (*kapi.Endpoints, error)
	GetNamespace(name string) (*kapi.Namespace, error)
	GetNamespaces() ([]*kapi.Namespace, error)
}

// WatchFactory implements the ObjectCacheInterface interface.

var _ ObjectCacheInterface = &WatchFactory{}

const (
	resyncInterval        = 0
	handlerAlive   uint32 = 0
	handlerDead    uint32 = 1
	numEventQueues int    = 15
)

var (
	podType            reflect.Type = reflect.TypeOf(&kapi.Pod{})
	serviceType        reflect.Type = reflect.TypeOf(&kapi.Service{})
	endpointsType      reflect.Type = reflect.TypeOf(&kapi.Endpoints{})
	policyType         reflect.Type = reflect.TypeOf(&knet.NetworkPolicy{})
	namespaceType      reflect.Type = reflect.TypeOf(&kapi.Namespace{})
	nodeType           reflect.Type = reflect.TypeOf(&kapi.Node{})
	egressFirewallType reflect.Type = reflect.TypeOf(&egressfirewallapi.EgressFirewall{})
	crdType            reflect.Type = reflect.TypeOf(&apiextensionsapi.CustomResourceDefinition{})
	egressIPType       reflect.Type = reflect.TypeOf(&egressipapi.EgressIP{})
)

// NewWatchFactory initializes a new watch factory
func NewWatchFactory(ovnClientset *util.OVNClientset) (*WatchFactory, error) {
	// resync time is 12 hours, none of the resources being watched in ovn-kubernetes have
	// any race condition where a resync may be required e.g. cni executable on node watching for
	// events on pods and assuming that an 'ADD' event will contain the annotations put in by
	// ovnkube master (currently, it is just a 'get' loop)
	// the downside of making it tight (like 10 minutes) is needless spinning on all resources
	// However, AddEventHandlerWithResyncPeriod can specify a per handler resync period
	wf := &WatchFactory{
		iFactory:    informerfactory.NewSharedInformerFactory(ovnClientset.KubeClient, resyncInterval),
		eipFactory:  egressipinformerfactory.NewSharedInformerFactory(ovnClientset.EgressIPClient, resyncInterval),
		efClientset: ovnClientset.EgressFirewallClient,
		crdFactory:  apiextensionsinformerfactory.NewSharedInformerFactory(ovnClientset.APIExtensionsClient, resyncInterval),
		informers:   make(map[reflect.Type]*informer),
		stopChan:    make(chan struct{}),
	}
	var err error

	err = apiextensionsapi.AddToScheme(apiextensionsscheme.Scheme)
	if err != nil {
		return nil, err
	}
	err = egressipapi.AddToScheme(egressipscheme.Scheme)
	if err != nil {
		return nil, err
	}

	// Create shared informers we know we'll use
	wf.informers[podType], err = newQueuedInformer(podType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan)
	if err != nil {
		return nil, err
	}
	wf.informers[serviceType], err = newInformer(serviceType, wf.iFactory.Core().V1().Services().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[endpointsType], err = newInformer(endpointsType, wf.iFactory.Core().V1().Endpoints().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[policyType], err = newInformer(policyType, wf.iFactory.Networking().V1().NetworkPolicies().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[namespaceType], err = newInformer(namespaceType, wf.iFactory.Core().V1().Namespaces().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[crdType], err = newInformer(crdType, wf.crdFactory.Apiextensions().V1beta1().CustomResourceDefinitions().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[nodeType], err = newQueuedInformer(nodeType, wf.iFactory.Core().V1().Nodes().Informer(), wf.stopChan)
	if err != nil {
		return nil, err
	}

	wf.crdFactory.Start(wf.stopChan)
	for oType, synced := range wf.crdFactory.WaitForCacheSync(wf.stopChan) {
		if !synced {
			return nil, fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}
	wf.iFactory.Start(wf.stopChan)
	for oType, synced := range wf.iFactory.WaitForCacheSync(wf.stopChan) {
		if !synced {
			return nil, fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}
	if config.OVNKubernetesFeature.EnableEgressIP {
		wf.informers[egressIPType], err = newInformer(egressIPType, wf.eipFactory.K8s().V1().EgressIPs().Informer())
		if err != nil {
			return nil, err
		}
		wf.eipFactory.Start(wf.stopChan)
		for oType, synced := range wf.eipFactory.WaitForCacheSync(wf.stopChan) {
			if !synced {
				return nil, fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}
	return wf, nil
}

func (wf *WatchFactory) InitializeEgressFirewallWatchFactory() error {
	err := egressfirewallapi.AddToScheme(egressfirewallscheme.Scheme)
	if err != nil {
		return err
	}
	wf.efFactory = egressfirewallinformerfactory.NewSharedInformerFactory(wf.efClientset, resyncInterval)
	wf.informers[egressFirewallType], err = newInformer(egressFirewallType, wf.efFactory.K8s().V1().EgressFirewalls().Informer())
	if err != nil {
		return err
	}
	wf.egressFirewallStopChan = make(chan struct{})
	wf.efFactory.Start(wf.egressFirewallStopChan)
	for oType, synced := range wf.efFactory.WaitForCacheSync(wf.egressFirewallStopChan) {
		if !synced {
			return fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}
	return nil
}

func (wf *WatchFactory) ShutdownEgressFirewallWatchFactory() {
	close(wf.egressFirewallStopChan)
	wf.informers[egressFirewallType].shutdown()
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
	case podType:
		if pod, ok := obj.(*kapi.Pod); ok {
			return &pod.ObjectMeta, nil
		}
	case serviceType:
		if service, ok := obj.(*kapi.Service); ok {
			return &service.ObjectMeta, nil
		}
	case endpointsType:
		if endpoints, ok := obj.(*kapi.Endpoints); ok {
			return &endpoints.ObjectMeta, nil
		}
	case policyType:
		if policy, ok := obj.(*knet.NetworkPolicy); ok {
			return &policy.ObjectMeta, nil
		}
	case namespaceType:
		if namespace, ok := obj.(*kapi.Namespace); ok {
			return &namespace.ObjectMeta, nil
		}
	case nodeType:
		if node, ok := obj.(*kapi.Node); ok {
			return &node.ObjectMeta, nil
		}
	case egressFirewallType:
		if egressFirewall, ok := obj.(*egressfirewallapi.EgressFirewall); ok {
			return &egressFirewall.ObjectMeta, nil
		}
	case egressIPType:
		if egressIP, ok := obj.(*egressipapi.EgressIP); ok {
			return &egressIP.ObjectMeta, nil
		}
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
	return wf.addHandler(podType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredPodHandler adds a handler function that will be executed when Pod objects that match the given filters change
func (wf *WatchFactory) AddFilteredPodHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(podType, namespace, sel, handlerFuncs, processExisting)
}

// RemovePodHandler removes a Pod object event handler function
func (wf *WatchFactory) RemovePodHandler(handler *Handler) {
	wf.removeHandler(podType, handler)
}

// AddServiceHandler adds a handler function that will be executed on Service object changes
func (wf *WatchFactory) AddServiceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(serviceType, "", nil, handlerFuncs, processExisting)
}

// RemoveServiceHandler removes a Service object event handler function
func (wf *WatchFactory) RemoveServiceHandler(handler *Handler) {
	wf.removeHandler(serviceType, handler)
}

// AddEndpointsHandler adds a handler function that will be executed on Endpoints object changes
func (wf *WatchFactory) AddEndpointsHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(endpointsType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredEndpointsHandler adds a handler function that will be executed when Endpoint objects that match the given filters change
func (wf *WatchFactory) AddFilteredEndpointsHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(endpointsType, namespace, sel, handlerFuncs, processExisting)
}

// RemoveEndpointsHandler removes a Endpoints object event handler function
func (wf *WatchFactory) RemoveEndpointsHandler(handler *Handler) {
	wf.removeHandler(endpointsType, handler)
}

// AddPolicyHandler adds a handler function that will be executed on NetworkPolicy object changes
func (wf *WatchFactory) AddPolicyHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(policyType, "", nil, handlerFuncs, processExisting)
}

// RemovePolicyHandler removes a NetworkPolicy object event handler function
func (wf *WatchFactory) RemovePolicyHandler(handler *Handler) {
	wf.removeHandler(policyType, handler)
}

// AddEgressFirewallHandler adds a handler function that will be executed on EgressFirewall object changes
func (wf *WatchFactory) AddEgressFirewallHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(egressFirewallType, "", nil, handlerFuncs, processExisting)
}

// RemoveEgressFirewallHandler removes an EgressFirewall object event handler function
func (wf *WatchFactory) RemoveEgressFirewallHandler(handler *Handler) {
	wf.removeHandler(egressFirewallType, handler)
}

// AddCRDHandler adds a handler function that will be executed on CRD obje changes
func (wf *WatchFactory) AddCRDHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(crdType, "", nil, handlerFuncs, processExisting)
}

// RemoveCRDHandler removes a CRD object event handler function
func (wf *WatchFactory) RemoveCRDHandler(handler *Handler) {
	wf.removeHandler(crdType, handler)
}

// AddEgressIPHandler adds a handler function that will be executed on EgressIP object changes
func (wf *WatchFactory) AddEgressIPHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(egressIPType, "", nil, handlerFuncs, processExisting)
}

// RemoveEgressIPHandler removes an EgressIP object event handler function
func (wf *WatchFactory) RemoveEgressIPHandler(handler *Handler) {
	wf.removeHandler(egressIPType, handler)
}

// AddNamespaceHandler adds a handler function that will be executed on Namespace object changes
func (wf *WatchFactory) AddNamespaceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(namespaceType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredNamespaceHandler adds a handler function that will be executed when Namespace objects that match the given filters change
func (wf *WatchFactory) AddFilteredNamespaceHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(namespaceType, namespace, sel, handlerFuncs, processExisting)
}

// RemoveNamespaceHandler removes a Namespace object event handler function
func (wf *WatchFactory) RemoveNamespaceHandler(handler *Handler) {
	wf.removeHandler(namespaceType, handler)
}

// AddNodeHandler adds a handler function that will be executed on Node object changes
func (wf *WatchFactory) AddNodeHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(nodeType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredNodeHandler dds a handler function that will be executed when Node objects that match the given label selector
func (wf *WatchFactory) AddFilteredNodeHandler(sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(nodeType, "", sel, handlerFuncs, processExisting)
}

// RemoveNodeHandler removes a Node object event handler function
func (wf *WatchFactory) RemoveNodeHandler(handler *Handler) {
	wf.removeHandler(nodeType, handler)
}

// GetPod returns the pod spec given the namespace and pod name
func (wf *WatchFactory) GetPod(namespace, name string) (*kapi.Pod, error) {
	podLister := wf.informers[podType].lister.(listers.PodLister)
	return podLister.Pods(namespace).Get(name)
}

// GetPods returns all the pods in a given namespace
func (wf *WatchFactory) GetPods(namespace string) ([]*kapi.Pod, error) {
	podLister := wf.informers[podType].lister.(listers.PodLister)
	return podLister.Pods(namespace).List(labels.Everything())
}

// GetNodes returns the node specs of all the nodes
func (wf *WatchFactory) GetNodes() ([]*kapi.Node, error) {
	nodeLister := wf.informers[nodeType].lister.(listers.NodeLister)
	return nodeLister.List(labels.Everything())
}

// GetNode returns the node spec of a given node by name
func (wf *WatchFactory) GetNode(name string) (*kapi.Node, error) {
	nodeLister := wf.informers[nodeType].lister.(listers.NodeLister)
	return nodeLister.Get(name)
}

// GetService returns the service spec of a service in a given namespace
func (wf *WatchFactory) GetService(namespace, name string) (*kapi.Service, error) {
	serviceLister := wf.informers[serviceType].lister.(listers.ServiceLister)
	return serviceLister.Services(namespace).Get(name)
}

// GetEndpoints returns the endpoints list in a given namespace
func (wf *WatchFactory) GetEndpoints(namespace string) ([]*kapi.Endpoints, error) {
	endpointsLister := wf.informers[endpointsType].lister.(listers.EndpointsLister)
	return endpointsLister.Endpoints(namespace).List(labels.Everything())
}

// GetEndpoint returns a specific endpoint in a given namespace
func (wf *WatchFactory) GetEndpoint(namespace, name string) (*kapi.Endpoints, error) {
	endpointsLister := wf.informers[endpointsType].lister.(listers.EndpointsLister)
	return endpointsLister.Endpoints(namespace).Get(name)
}

// GetNamespace returns a specific namespace
func (wf *WatchFactory) GetNamespace(name string) (*kapi.Namespace, error) {
	namespaceLister := wf.informers[namespaceType].lister.(listers.NamespaceLister)
	return namespaceLister.Get(name)
}

// GetNamespaces returns a list of namespaces in the cluster
func (wf *WatchFactory) GetNamespaces() ([]*kapi.Namespace, error) {
	namespaceLister := wf.informers[namespaceType].lister.(listers.NamespaceLister)
	return namespaceLister.List(labels.Everything())
}

// GetFactory returns the underlying informer factory
func (wf *WatchFactory) GetFactory() informerfactory.SharedInformerFactory {
	return wf.iFactory
}
