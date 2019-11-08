package factory

import (
	"fmt"
	"hash/fnv"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	informerfactory "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Handler represents an event handler and is private to the factory module
type Handler struct {
	cache.FilteringResourceEventHandler

	id uint64
	// tombstone is used to track the handler's lifetime. handlerAlive
	// indicates the handler can be called, while handlerDead indicates
	// it has been scheduled for removal and should not be called.
	// tombstone should only be set using atomic operations since it is
	// used from multiple goroutines.
	tombstone uint32
}

type eventKind int

const (
	addEvent eventKind = iota
	updateEvent
	deleteEvent
)

type event struct {
	obj    interface{}
	oldObj interface{}
	kind   eventKind
}

type informer struct {
	sync.Mutex
	oType    reflect.Type
	inf      cache.SharedIndexInformer
	handlers map[uint64]*Handler
	events   []chan *event
	stopChan chan struct{}
}

func (i *informer) forEachHandler(obj interface{}, f func(h *Handler)) {
	i.Lock()
	defer i.Unlock()

	objType := reflect.TypeOf(obj)
	if objType != i.oType {
		logrus.Errorf("object type %v did not match expected %v", objType, i.oType)
		return
	}

	for _, handler := range i.handlers {
		// Only run alive handlers
		if !atomic.CompareAndSwapUint32(&handler.tombstone, handlerDead, handlerDead) {
			f(handler)
		}
	}
}

func (i *informer) processEvents(events chan *event, stopChan <-chan struct{}) {
	for {
		select {
		case e, ok := <-events:
			if !ok {
				return
			}
			switch e.kind {
			case addEvent:
				i.runAddHandlers(e.obj)
			case updateEvent:
				i.runUpdateHandlers(e.oldObj, e.obj)
			case deleteEvent:
				i.runDeleteHandlers(e.obj)
			}
		case <-stopChan:
			close(events)
			return
		}
	}
}

func (i *informer) enqueueEvent(oldObj, obj interface{}, kind eventKind) {
	meta, err := getObjectMeta(i.oType, obj)
	if err != nil {
		logrus.Errorf("object has no meta: %v", err)
		return
	}

	// Distribute the object to an event queue based on a hash of its
	// namespaced name, so that all events for a given object are
	// serialized in one queue.
	h := fnv.New32()
	_, _ = h.Write([]byte(meta.Namespace + "/" + meta.Name))
	queueIdx := h.Sum32() % uint32(numEventQueues)
	i.events[queueIdx] <- &event{
		obj:    obj,
		oldObj: oldObj,
		kind:   kind,
	}
}

func (i *informer) runAddHandlers(obj interface{}) {
	i.forEachHandler(obj, func(h *Handler) {
		h.OnAdd(obj)
	})
}

func (i *informer) runUpdateHandlers(oldObj, newObj interface{}) {
	i.forEachHandler(newObj, func(h *Handler) {
		h.OnUpdate(oldObj, newObj)
	})
}

func (i *informer) runDeleteHandlers(obj interface{}) {
	i.forEachHandler(obj, func(h *Handler) {
		h.OnDelete(obj)
	})
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
			logrus.Debugf("queueing %v ADD event", i.oType)
			i.enqueueEvent(nil, obj, addEvent)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			logrus.Debugf("queueing %v UPDATE event", i.oType)
			i.enqueueEvent(oldObj, newObj, updateEvent)
		},
		DeleteFunc: func(obj interface{}) {
			realObj, err := ensureObjectOnDelete(obj, i.oType)
			if err != nil {
				logrus.Errorf(err.Error())
				return
			}
			logrus.Debugf("queueing %v DELETE event", i.oType)
			i.enqueueEvent(nil, realObj, deleteEvent)
		},
	}
}

func (i *informer) newFederatedHandler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			i.runAddHandlers(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			i.runUpdateHandlers(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			realObj, err := ensureObjectOnDelete(obj, i.oType)
			if err != nil {
				logrus.Errorf(err.Error())
				return
			}
			i.runDeleteHandlers(realObj)
		},
	}
}

func newBaseInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer, stopChan chan struct{}) *informer {
	return &informer{
		oType:    oType,
		inf:      sharedInformer,
		handlers: make(map[uint64]*Handler),
		stopChan: stopChan,
	}
}

func newInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer, stopChan chan struct{}) *informer {
	i := newBaseInformer(oType, sharedInformer, stopChan)
	i.inf.AddEventHandler(i.newFederatedHandler())
	return i
}

func newQueuedInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer, stopChan chan struct{}) *informer {
	i := newBaseInformer(oType, sharedInformer, stopChan)
	i.events = make([]chan *event, numEventQueues)
	for j := 0; j < numEventQueues; j++ {
		i.events[j] = make(chan *event, 1)
		go i.processEvents(i.events[j], stopChan)
	}
	i.inf.AddEventHandler(i.newFederatedQueuedHandler())
	return i
}

// WatchFactory initializes and manages common kube watches
type WatchFactory struct {
	// Must be first member in the struct due to Golang ARM/x86 32-bit
	// requirements with atomic accesses
	handlerCounter uint64

	iFactory  informerfactory.SharedInformerFactory
	informers map[reflect.Type]*informer
	stopChan  chan struct{}
}

const (
	resyncInterval        = 12 * time.Hour
	handlerAlive   uint32 = 0
	handlerDead    uint32 = 1
	numEventQueues int    = 10
)

var (
	podType       reflect.Type = reflect.TypeOf(&kapi.Pod{})
	serviceType   reflect.Type = reflect.TypeOf(&kapi.Service{})
	endpointsType reflect.Type = reflect.TypeOf(&kapi.Endpoints{})
	policyType    reflect.Type = reflect.TypeOf(&knet.NetworkPolicy{})
	namespaceType reflect.Type = reflect.TypeOf(&kapi.Namespace{})
	nodeType      reflect.Type = reflect.TypeOf(&kapi.Node{})
)

// NewWatchFactory initializes a new watch factory
func NewWatchFactory(c kubernetes.Interface, stopChan chan struct{}) (*WatchFactory, error) {
	// resync time is 12 hours, none of the resources being watched in ovn-kubernetes have
	// any race condition where a resync may be required e.g. cni executable on node watching for
	// events on pods and assuming that an 'ADD' event will contain the annotations put in by
	// ovnkube master (currently, it is just a 'get' loop)
	// the downside of making it tight (like 10 minutes) is needless spinning on all resources
	wf := &WatchFactory{
		iFactory:  informerfactory.NewSharedInformerFactory(c, resyncInterval),
		informers: make(map[reflect.Type]*informer),
		stopChan:  make(chan struct{}),
	}

	// Create shared informers we know we'll use
	wf.informers[podType] = newQueuedInformer(podType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan)
	wf.informers[serviceType] = newInformer(serviceType, wf.iFactory.Core().V1().Services().Informer(), wf.stopChan)
	wf.informers[endpointsType] = newInformer(endpointsType, wf.iFactory.Core().V1().Endpoints().Informer(), wf.stopChan)
	wf.informers[policyType] = newInformer(policyType, wf.iFactory.Networking().V1().NetworkPolicies().Informer(), wf.stopChan)
	wf.informers[namespaceType] = newInformer(namespaceType, wf.iFactory.Core().V1().Namespaces().Informer(), wf.stopChan)
	wf.informers[nodeType] = newQueuedInformer(nodeType, wf.iFactory.Core().V1().Nodes().Informer(), wf.stopChan)

	wf.iFactory.Start(wf.stopChan)
	for oType, synced := range wf.iFactory.WaitForCacheSync(wf.stopChan) {
		if !synced {
			return nil, fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}

	go func() {
		<-stopChan
		wf.shutdown()
	}()

	return wf, nil
}

// Shutdown removes all handlers
func (wf *WatchFactory) shutdown() {
	for _, inf := range wf.informers {
		inf.Lock()
		defer inf.Unlock()
		for _, handler := range inf.handlers {
			if atomic.CompareAndSwapUint32(&handler.tombstone, handlerAlive, handlerDead) {
				delete(inf.handlers, handler.id)
			}
		}
	}
	close(wf.stopChan)
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
	}
	return nil, fmt.Errorf("cannot get ObjectMeta from type %v", objType)
}

func (wf *WatchFactory) addHandler(objType reflect.Type, namespace string, lsel *metav1.LabelSelector, funcs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	inf, ok := wf.informers[objType]
	if !ok {
		return nil, fmt.Errorf("unknown object type %v", objType)
	}

	sel, err := metav1.LabelSelectorAsSelector(lsel)
	if err != nil {
		return nil, fmt.Errorf("error creating label selector: %v", err)
	}

	filterFunc := func(obj interface{}) bool {
		if namespace == "" && lsel == nil {
			// Unfiltered handler
			return true
		}
		meta, err := getObjectMeta(objType, obj)
		if err != nil {
			logrus.Errorf("watch handler filter error: %v", err)
			return false
		}
		if namespace != "" && meta.Namespace != namespace {
			return false
		}
		if lsel != nil && !sel.Matches(labels.Set(meta.Labels)) {
			return false
		}
		return true
	}

	// Process existing items as a set so the caller can clean up
	// after a restart or whatever
	existingItems := inf.inf.GetStore().List()
	if processExisting != nil {
		items := make([]interface{}, 0)
		for _, obj := range existingItems {
			if filterFunc(obj) {
				items = append(items, obj)
			}
		}
		processExisting(items)
	}

	handlerID := atomic.AddUint64(&wf.handlerCounter, 1)

	inf.Lock()
	defer inf.Unlock()

	handler := &Handler{
		cache.FilteringResourceEventHandler{
			FilterFunc: filterFunc,
			Handler:    funcs,
		},
		handlerID,
		handlerAlive,
	}
	inf.handlers[handlerID] = handler
	logrus.Debugf("added %v event handler %d", objType, handlerID)

	// Send existing items to the handler's add function; informers usually
	// do this but since we share informers, it's long-since happened so
	// we must emulate that here
	for _, obj := range existingItems {
		inf.handlers[handlerID].OnAdd(obj)
	}

	return handler, nil
}

func (wf *WatchFactory) removeHandler(objType reflect.Type, handler *Handler) error {
	inf, ok := wf.informers[objType]
	if !ok {
		return fmt.Errorf("tried to remove unknown object type %v event handler", objType)
	}

	if !atomic.CompareAndSwapUint32(&handler.tombstone, handlerAlive, handlerDead) {
		// Already removed
		return fmt.Errorf("tried to remove already removed object type %v event handler %d", objType, handler.id)
	}

	logrus.Debugf("sending %v event handler %d for removal", objType, handler.id)

	go func() {
		inf.Lock()
		defer inf.Unlock()
		if _, ok := inf.handlers[handler.id]; ok {
			// Remove the handler
			delete(inf.handlers, handler.id)
			logrus.Debugf("removed %v event handler %d", objType, handler.id)
		} else {
			logrus.Warningf("tried to remove unknown object type %v event handler %d", objType, handler.id)
		}
	}()

	return nil
}

// AddPodHandler adds a handler function that will be executed on Pod object changes
func (wf *WatchFactory) AddPodHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(podType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredPodHandler adds a handler function that will be executed when Pod objects that match the given filters change
func (wf *WatchFactory) AddFilteredPodHandler(namespace string, lsel *metav1.LabelSelector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(podType, namespace, lsel, handlerFuncs, processExisting)
}

// RemovePodHandler removes a Pod object event handler function
func (wf *WatchFactory) RemovePodHandler(handler *Handler) error {
	return wf.removeHandler(podType, handler)
}

// AddServiceHandler adds a handler function that will be executed on Service object changes
func (wf *WatchFactory) AddServiceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(serviceType, "", nil, handlerFuncs, processExisting)
}

// RemoveServiceHandler removes a Service object event handler function
func (wf *WatchFactory) RemoveServiceHandler(handler *Handler) error {
	return wf.removeHandler(serviceType, handler)
}

// AddEndpointsHandler adds a handler function that will be executed on Endpoints object changes
func (wf *WatchFactory) AddEndpointsHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(endpointsType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredEndpointsHandler adds a handler function that will be executed when Endpoint objects that match the given filters change
func (wf *WatchFactory) AddFilteredEndpointsHandler(namespace string, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(endpointsType, namespace, nil, handlerFuncs, processExisting)
}

// RemoveEndpointsHandler removes a Endpoints object event handler function
func (wf *WatchFactory) RemoveEndpointsHandler(handler *Handler) error {
	return wf.removeHandler(endpointsType, handler)
}

// AddPolicyHandler adds a handler function that will be executed on NetworkPolicy object changes
func (wf *WatchFactory) AddPolicyHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(policyType, "", nil, handlerFuncs, processExisting)
}

// RemovePolicyHandler removes a NetworkPolicy object event handler function
func (wf *WatchFactory) RemovePolicyHandler(handler *Handler) error {
	return wf.removeHandler(policyType, handler)
}

// AddNamespaceHandler adds a handler function that will be executed on Namespace object changes
func (wf *WatchFactory) AddNamespaceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(namespaceType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredNamespaceHandler adds a handler function that will be executed when Namespace objects that match the given filters change
func (wf *WatchFactory) AddFilteredNamespaceHandler(namespace string, lsel *metav1.LabelSelector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(namespaceType, namespace, lsel, handlerFuncs, processExisting)
}

// RemoveNamespaceHandler removes a Namespace object event handler function
func (wf *WatchFactory) RemoveNamespaceHandler(handler *Handler) error {
	return wf.removeHandler(namespaceType, handler)
}

// AddNodeHandler adds a handler function that will be executed on Node object changes
func (wf *WatchFactory) AddNodeHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(nodeType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredNodeHandler adds a handler function that will be executed when Node objects that match the given filters change
func (wf *WatchFactory) AddFilteredNodeHandler(lsel *metav1.LabelSelector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) (*Handler, error) {
	return wf.addHandler(nodeType, "", lsel, handlerFuncs, processExisting)
}

// RemoveNodeHandler removes a Node object event handler function
func (wf *WatchFactory) RemoveNodeHandler(handler *Handler) error {
	return wf.removeHandler(nodeType, handler)
}
