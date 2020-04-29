// Package informer provides a wrapper around a client-go SharedIndexInformer
// for event handling. It removes a lot of boilerplate code that would be required
// to use workqueues.
package informer

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

// EventHandler is an event handler that responds to
// Add/Delete events from the informer cache
type EventHandler interface {
	Run(threadiness int, stopChan <-chan struct{}) error
	GetIndexer() cache.Indexer
}

type eventHandler struct {
	name            string
	informer        cache.SharedIndexInformer
	deletedIndexer  cache.Indexer
	workqueue       workqueue.RateLimitingInterface
	add             func(obj interface{}) error
	delete          func(obj interface{}) error
	updatePredicate UpdatePredicateFunction
}

// UpdatePredicateFunction returns true if the update is interesting
type UpdatePredicateFunction func(old, new interface{}) bool

// DefaultUpdatePredicateFunction always returns true
func DefaultUpdatePredicateFunction(old, new interface{}) bool {
	return true
}

// NewDefaultEventHandler returns a default event handler
func NewDefaultEventHandler(
	name string,
	informer cache.SharedIndexInformer,
	addFunc, deleteFunc func(obj interface{}) error,
	updatePredicateFunc UpdatePredicateFunction,
) EventHandler {
	e := &eventHandler{
		name:            name,
		informer:        informer,
		deletedIndexer:  cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{}),
		workqueue:       workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		add:             addFunc,
		delete:          deleteFunc,
		updatePredicate: updatePredicateFunc,
	}
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.enqueue(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(metav1.Object)
			newObj := new.(metav1.Object)
			// Make sure object is not set for deletion and was actually changed
			if oldObj.GetDeletionTimestamp() == nil && oldObj.GetResourceVersion() != newObj.GetResourceVersion() {
				if e.updatePredicate(old, new) {
					e.enqueue(newObj)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			e.enqueueDelete(obj)
		},
	})
	return e
}

// GetIndexer returns the indexer that is associated with
// the SharedInformer
func (e *eventHandler) GetIndexer() cache.Indexer {
	return e.informer.GetIndexer()
}

// Run starts the cache and workqueues. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (e *eventHandler) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer e.workqueue.ShutDown()

	klog.Infof("Starting %s informer queue", e.name)

	klog.Infof("Waiting for %s informer caches to sync", e.name)
	if ok := cache.WaitForCacheSync(stopCh, e.informer.HasSynced); !ok {
		return fmt.Errorf("failed to wait for %s caches to sync", e.name)
	}

	klog.Infof("Starting %d %s queue workers", threadiness, e.name)
	// Launch two workers to process Node resources
	for j := 0; j < threadiness; j++ {
		go wait.Until(e.runWorker, time.Second, stopCh)
	}

	klog.Infof("Started %s queue workers", e.name)
	<-stopCh
	klog.Infof("Shutting down %s queue workers", e.name)

	return nil
}

func (e *eventHandler) enqueue(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	e.workqueue.Add(key)
}

func (e *eventHandler) enqueueDelete(obj interface{}) {
	var key string
	var err error
	if key, err = cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	err = e.deletedIndexer.Add(obj)
	if err != nil {
		utilruntime.HandleError(err)
	}
	e.workqueue.Add(key)
}

func (e *eventHandler) runWorker() {
	for e.processNextWorkItem() {
	}
}

func (e *eventHandler) processNextWorkItem() bool {
	obj, shutdown := e.workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer e.workqueue.Done(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			e.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		// Run the syncHandler, passing it the namespace/name string of the
		// resource to be synced.
		if err := e.syncHandler(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			e.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		e.workqueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)

		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
	}
	return true
}

func (e *eventHandler) syncHandler(key string) error {
	obj, exists, err := e.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("Error fetching object with key %s from store: %v", key, err)
	}
	if !exists {
		obj, exists, err := e.deletedIndexer.GetByKey(key)
		if err != nil {
			return fmt.Errorf("Error getting object with key %s from deletedIndexer: %v", key, err)
		}
		if !exists {
			return fmt.Errorf("Key %s doesn't exist in deletedIndexer: %v", key, err)
		}
		if err := e.delete(obj); err != nil {
			return err
		}
		return e.deletedIndexer.Delete(obj)
	}
	return e.add(obj)
}
