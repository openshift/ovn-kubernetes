package factory

import (
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"

	egressfirewalllister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/listers/egressfirewall/v1"

	egressiplister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/listers/egressip/v1"

	kapi "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	v1coreinformers "k8s.io/client-go/informers/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

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

type queueMapEntry struct {
	queue    uint32
	refcount int32
}

type informer struct {
	sync.RWMutex
	oType    reflect.Type
	inf      cache.SharedIndexInformer
	handlers map[uint64]*Handler
	events   []chan *event
	count    uint32
	lister   listerInterface
	// initialAddFunc will be called to deliver the initial list of objects
	// when a handler is added
	initialAddFunc initialAddFn
	shutdownWg     sync.WaitGroup

	queueMap       map[ktypes.NamespacedName]*queueMapEntry
	queueMapLock   sync.Mutex
	queueIndex     uint32

	podsSynced cache.InformerSynced
	podsQueue  workqueue.RateLimitingInterface
	podsCache  sync.Map
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

func (i *informer) processEvents(events chan *event, stopChan <-chan struct{}, chanNum int32) {
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

func (i *informer) getNewQueueNum(numEventQueues uint32) uint32 {
	var j, startIdx, queueIdx uint32
	startIdx = uint32(rand.Intn(int(numEventQueues-1)))
	queueIdx = startIdx
	lowestNum := len(i.events[startIdx])
	for j = 0; j < numEventQueues; j++ {
		tryQueue := (startIdx + j) % numEventQueues
		num := len(i.events[tryQueue])
		if num < lowestNum {
			lowestNum = num
			queueIdx = tryQueue
		}
	}
	return queueIdx
}

func (i *informer) refQueueEntry(oType reflect.Type, obj interface{}, numEventQueues uint32, op string) (ktypes.NamespacedName, string, *queueMapEntry, uint32) {
	meta, err := getObjectMeta(oType, obj)
	if err != nil {
		klog.Errorf("Object has no meta: %v", err)
		return ktypes.NamespacedName{}, "", nil, 0
	}

	i.queueMapLock.Lock()
	defer i.queueMapLock.Unlock()

	namespacedName := ktypes.NamespacedName{Namespace: meta.Namespace, Name: meta.Name}
	entry, ok := i.queueMap[namespacedName]
	if ok {
		if atomic.AddInt32(&entry.refcount, 1) == 1 {
			// Entry was previously unused; assign new queue to ensure
			// better balance between handlers. Otherwise we would
			// use the same queue for all events of the entire lifetime
			// of objects like Namespaces.
//			entry.queue = atomic.AddUint32(&i.queueIndex, 1) % numEventQueues
			entry.queue = i.getNewQueueNum(numEventQueues)
		}
	} else {
		// no entry found, assign new queue
		entry = &queueMapEntry{
			refcount: 1,
//			queue:    atomic.AddUint32(&i.queueIndex, 1) % numEventQueues,
			queue:    i.getNewQueueNum(numEventQueues),
		}
		i.queueMap[namespacedName] = entry
	}
	return namespacedName, string(meta.UID), entry, entry.queue
}

func (i *informer) printQueues(numEventQueues uint32, detail string) {
	if atomic.AddUint32(&i.count, 1) % 10 == 0 {
		msg := fmt.Sprintf("#### %s queue depth ", detail)
		for j := 0; j < int(numEventQueues); j++ {
			msg = msg + fmt.Sprintf("%2d ", len(i.events[j]))
		}
		klog.Infof(msg)
	}
}

func (i *informer) unrefQueueEntry(key ktypes.NamespacedName, uid string, entry *queueMapEntry, del bool, op string) {
	if entry == nil {
		return
	}

	if !del {
		atomic.AddInt32(&entry.refcount, -1)
		return
	}

	i.queueMapLock.Lock()
	defer i.queueMapLock.Unlock()
	if atomic.AddInt32(&entry.refcount, -1) <= 0 {
		delete(i.queueMap, key)
	}
}

// enqueueEvent adds an event to the appropriate queue for the object
func (i *informer) enqueueEvent(oldObj, obj interface{}, queueNum uint32, processFunc func(*event)) {
	i.events[queueNum] <- &event{
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

func (i *informer) newFederatedQueuedHandler(numEventQueues uint32) cache.ResourceEventHandlerFuncs {
	name := i.oType.Elem().Name()
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			start2 := time.Now()
			key, uid, entry, queueNum := i.refQueueEntry(i.oType, obj, numEventQueues, "ADD")
			i.enqueueEvent(nil, obj, queueNum, func(e *event) {
				metrics.MetricResourceUpdateCount.WithLabelValues(name, "add").Inc()
				start := time.Now()
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnAdd(e.obj)
				})
				metrics.MetricResourceUpdateLatency.WithLabelValues(name, "add").Observe(time.Since(start).Seconds())
				i.unrefQueueEntry(key, uid, entry, false, "ADD")
			})
			i.printQueues(numEventQueues, name)
			metrics.MetricHandlerAddLatency.Observe(float64(time.Since(start2).Milliseconds()))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			start2 := time.Now()
			key, uid, entry, queueNum := i.refQueueEntry(i.oType, newObj, numEventQueues, "UPDATE")
			i.enqueueEvent(oldObj, newObj, queueNum, func(e *event) {
				metrics.MetricResourceUpdateCount.WithLabelValues(name, "update").Inc()
				start := time.Now()
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnUpdate(e.oldObj, e.obj)
				})
				metrics.MetricResourceUpdateLatency.WithLabelValues(name, "update").Observe(time.Since(start).Seconds())
				i.unrefQueueEntry(key, uid, entry, false, "UPDATE")
			})
			i.printQueues(numEventQueues, name)
			metrics.MetricHandlerUpdateLatency.Observe(float64(time.Since(start2).Milliseconds()))
		},
		DeleteFunc: func(obj interface{}) {
			realObj, err := ensureObjectOnDelete(obj, i.oType)
			if err != nil {
				klog.Errorf(err.Error())
				return
			}
			start2 := time.Now()
			key, uid, entry, queueNum := i.refQueueEntry(i.oType, obj, numEventQueues, "DEL")
			i.enqueueEvent(nil, realObj, queueNum, func(e *event) {
				metrics.MetricResourceUpdateCount.WithLabelValues(name, "delete").Inc()
				start := time.Now()
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnDelete(e.obj)
				})
				metrics.MetricResourceUpdateLatency.WithLabelValues(name, "delete").Observe(time.Since(start).Seconds())
				i.unrefQueueEntry(key, uid, entry, true, "DEL")
			})
			i.printQueues(numEventQueues, name)
			metrics.MetricHandlerDeleteLatency.Observe(float64(time.Since(start2).Milliseconds()))
		},
	}
}

func (i *informer) newFederatedHandler() cache.ResourceEventHandlerFuncs {
	name := i.oType.Elem().Name()
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			metrics.MetricResourceUpdateCount.WithLabelValues(name, "add").Inc()
			start := time.Now()
			i.forEachHandler(obj, func(h *Handler) {
				h.OnAdd(obj)
			})
			metrics.MetricResourceUpdateLatency.WithLabelValues(name, "add").Observe(time.Since(start).Seconds())
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			metrics.MetricResourceUpdateCount.WithLabelValues(name, "update").Inc()
			start := time.Now()
			i.forEachHandler(newObj, func(h *Handler) {
				h.OnUpdate(oldObj, newObj)
			})
			metrics.MetricResourceUpdateLatency.WithLabelValues(name, "update").Observe(time.Since(start).Seconds())
		},
		DeleteFunc: func(obj interface{}) {
			realObj, err := ensureObjectOnDelete(obj, i.oType)
			if err != nil {
				klog.Errorf(err.Error())
				return
			}
			metrics.MetricResourceUpdateCount.WithLabelValues(name, "delete").Inc()
			start := time.Now()
			i.forEachHandler(realObj, func(h *Handler) {
				h.OnDelete(realObj)
			})
			metrics.MetricResourceUpdateLatency.WithLabelValues(name, "delete").Observe(time.Since(start).Seconds())
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
		oType:    oType,
		inf:      sharedInformer,
		lister:   lister,
		handlers: make(map[uint64]*Handler),
		queueMap: make(map[ktypes.NamespacedName]*queueMapEntry),
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

func newQueuedInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer,
	stopChan chan struct{}, numEventQueues uint32) (*informer, error) {
	i, err := newBaseInformer(oType, sharedInformer)
	if err != nil {
		return nil, err
	}
	i.events = make([]chan *event, numEventQueues)
	i.shutdownWg.Add(len(i.events))
	for j := range i.events {
		i.events[j] = make(chan *event, 10)
		go i.processEvents(i.events[j], stopChan, int32(j))
	}
	i.initialAddFunc = func(h *Handler, items []interface{}) {
		// Make a handler-specific channel array across which the
		// initial add events will be distributed. When a new handler
		// is added, only that handler should receive events for all
		// existing objects.
		type initialAddEntry struct {
			obj      interface{}
			doneFunc func()
		}
		adds := make([]chan *initialAddEntry, numEventQueues)
		queueWg := &sync.WaitGroup{}
		queueWg.Add(len(adds))
		for j := range adds {
			adds[j] = make(chan *initialAddEntry, 10)
			go func(addChan chan *initialAddEntry) {
				defer queueWg.Done()
				for {
					entry, ok := <-addChan
					if !ok {
						return
					}
					h.OnAdd(entry.obj)
					entry.doneFunc()
				}
			}(adds[j])
		}
		// Distribute the existing items into the handler-specific
		// channel array.
		for _, obj := range items {
			key, uid, entry, queueNum := i.refQueueEntry(i.oType, obj, numEventQueues, "INIADD")
			adds[queueNum] <- &initialAddEntry{
				obj: obj,
				doneFunc: func() {
					i.unrefQueueEntry(key, uid, entry, false, "INIADD")
				},
			}
		}
		// Close all the channels
		for j := range adds {
			close(adds[j])
		}
		// Wait until all the object additions have been processed
		queueWg.Wait()
	}
	i.inf.AddEventHandler(i.newFederatedQueuedHandler(numEventQueues))
	return i, nil
}

func newPodsInformer(oType reflect.Type, pods v1coreinformers.PodInformer,
	stopChan chan struct{}, numEventQueues uint32) (*informer, error) {

	i, err := newBaseInformer(oType, pods.Informer())
	if err != nil {
		return nil, err
	}

	i.events = make([]chan *event, numEventQueues)
	i.podsSynced = pods.Informer().HasSynced
	i.podsQueue = workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(),
		"pods",
	)

	pods.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
klog.Infof("!!!! ADD %v", key)
				i.podsQueue.Add(key)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
klog.Infof("!!!! UPD %v", key)
				i.podsQueue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
klog.Infof("!!!! DEL %v", key)
				i.podsQueue.Add(key)
			}
		},
	})

	i.initialAddFunc = func(h *Handler, items []interface{}) {
		// Make a handler-specific channel array across which the
		// initial add events will be distributed. When a new handler
		// is added, only that handler should receive events for all
		// existing objects.
		type initialAddEntry struct {
			obj      interface{}
			doneFunc func()
		}
		adds := make([]chan *initialAddEntry, numEventQueues)
		queueWg := &sync.WaitGroup{}
		queueWg.Add(len(adds))
		for j := range adds {
			adds[j] = make(chan *initialAddEntry, 10)
			go func(addChan chan *initialAddEntry) {
				defer queueWg.Done()
				for {
					entry, ok := <-addChan
					if !ok {
						return
					}
					h.OnAdd(entry.obj)
					entry.doneFunc()
				}
			}(adds[j])
		}
		// Distribute the existing items into the handler-specific
		// channel array.
		for _, obj := range items {
			key, uid, entry, queueNum := i.refQueueEntry(i.oType, obj, numEventQueues, "INIADD")
			adds[queueNum] <- &initialAddEntry{
				obj: obj,
				doneFunc: func() {
					i.unrefQueueEntry(key, uid, entry, false, "INIADD")
				},
			}
		}
		// Close all the channels
		for j := range adds {
			close(adds[j])
		}
		// Wait until all the object additions have been processed
		queueWg.Wait()
	}
	return i, nil
}

func (i *informer) runPodInformer(threadiness int, stopCh <-chan struct{}) {
	// don't let panics crash the process
	defer utilruntime.HandleCrash()

	klog.Infof("Starting Pod Controller")

	// wait for your caches to fill before starting your work
	if !cache.WaitForCacheSync(stopCh, i.podsSynced) {
		return
	}

	i.shutdownWg.Add(1)
	defer i.shutdownWg.Done()

	// start up your worker threads based on threadiness.  Some controllers
	// have multiple kinds of workers
	wg := &sync.WaitGroup{}
	for j := 0; j < threadiness; j++ {
		wg.Add(1)
		// runWorker will loop until "something bad" happens.  The .Until will
		// then rekick the worker after one second
		go func() {
			defer wg.Done()
			wait.Until(func() {
				i.runPodWorker(wg)
			}, time.Second, stopCh)
		}()
	}

	// wait until we're told to stop
	<-stopCh

	klog.Infof("Shutting down Pod controller")
	// make sure the work queue is shutdown which will trigger workers to end
	i.podsQueue.ShutDown()
	// wait for workers to finish
	wg.Wait()
}

func (i *informer) runPodWorker(wg *sync.WaitGroup) {
	// hot loop until we're told to stop.  processNextWorkItem will
	// automatically wait until there's work available, so we don't worry
	// about secondary waits
	for i.processNextPodWorkItem(wg) {
	}
}

// sync pod handler brings the pod resource in sync
func (i *informer) syncPodHandler(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	pod, err := i.lister.(listers.PodLister).Pods(namespace).Get(name)
	if err != nil && !apierrors.IsNotFound(err) {
		// Very unlikely to see any error other than "not found" since
		// wer're pulling from the informer cache, but just try again
		return err
	}

	// Delete the pod if it was not found (already gone) or if it had a
	// deletion timestamp set (deleted but not yet finalized); if so
	if apierrors.IsNotFound(err) { // || time.Now().After(pod.GetDeletionTimestamp().Time) {
		if pod != nil {
			klog.Infof("!!!!!! [%s] deleting TS %s", key, pod.GetDeletionTimestamp())
		} else {
			klog.Infof("!!!!!! [%s] deleting (only not found)", key)
		}
		p, ok := i.podsCache.Load(key)
		if !ok {
			klog.Infof("Pod %s deleted before it could be handled", key)
			return nil
		}
		pod = p.(*kapi.Pod)

		metrics.MetricResourceUpdateCount.WithLabelValues(name, "delete").Inc()
		start := time.Now()
		i.forEachQueuedHandler(func(h *Handler) {
			h.OnDelete(pod)
		})
		metrics.MetricResourceUpdateLatency.WithLabelValues(name, "delete").Observe(time.Since(start).Seconds())

		i.podsCache.Delete(key)
		return nil
	}

	p, existed := i.podsCache.Load(key)
	if !existed {
		// ADD
		i.podsCache.Store(key, pod)

		metrics.MetricResourceUpdateCount.WithLabelValues(name, "add").Inc()
		start := time.Now()
		i.forEachQueuedHandler(func(h *Handler) {
			h.OnAdd(pod)
		})
		metrics.MetricResourceUpdateLatency.WithLabelValues(name, "add").Observe(time.Since(start).Seconds())

		return nil
	}

	// UPDATE
	oldPod := p.(*kapi.Pod)
	i.podsCache.Store(key, pod)

	metrics.MetricResourceUpdateCount.WithLabelValues(name, "update").Inc()
	start := time.Now()
	i.forEachQueuedHandler(func(h *Handler) {
		h.OnUpdate(oldPod, pod)
	})
	metrics.MetricResourceUpdateLatency.WithLabelValues(name, "update").Observe(time.Since(start).Seconds())

	return nil
}

const maxPodRetries = 5

// processNextPodWorkItem deals with one key off the queue.  It returns false
// when it's time to quit.
func (i *informer) processNextPodWorkItem(wg *sync.WaitGroup) bool {
	wg.Add(1)
	defer wg.Done()
	// pull the next work item from queue.  It should be a key we use to lookup
	// something in a cache
	key, quit := i.podsQueue.Get()
	if quit {
		return false
	}
	// you always have to indicate to the queue that you've completed a piece of
	// work
	defer i.podsQueue.Done(key)

	// do your work on the key.  This method will contains your "do stuff" logic
	err := i.syncPodHandler(key.(string))
	if err == nil {
		// if you had no error, tell the queue to stop tracking history for your
		// key. This will reset things like failure counts for per-item rate
		// limiting
		i.podsQueue.Forget(key)
		return true
	}

	// there was a failure so be sure to report it.  This method allows for
	// pluggable error handling which can be used for things like
	// cluster-monitoring
	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", key, err))

	// since we failed, we should requeue the item to work on later.
	// but only if we've not exceeded max retries. This method
	// will add a backoff to avoid hotlooping on particular items
	// (they're probably still not going to work right away) and overall
	// controller protection (everything I've done is broken, this controller
	// needs to calm down or it can starve other useful work) cases.
	if i.podsQueue.NumRequeues(key) < maxPodRetries {
		i.podsQueue.AddRateLimited(key)
		return true
	}

	// if we've exceeded MaxRetries, remove the item from the queue
	i.podsQueue.Forget(key)

	return true
}
