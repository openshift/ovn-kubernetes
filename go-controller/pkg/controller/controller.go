package controller

import (
	"fmt"
	"golang.org/x/sync/errgroup"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const maxRetries = 15

// Controller is a level-driven controller that is shut down after Stop() call.
type Controller interface {
	ReconcileAll()
	addHandler() error
	startWorkers() error
	stop()
}

type Config[T any] struct {
	RateLimiter workqueue.RateLimiter
	Informer    cache.SharedIndexInformer
	Lister      func(selector labels.Selector) (ret []*T, err error)
	// ObjNeedsUpdate tells if object should be reconciled.
	// May be called with oldObj = nil on Add, won't be called on Delete.
	ObjNeedsUpdate func(oldObj, newObj *T) bool
	Reconcile      func(key string) error
	// How many workers should be started for this controller.
	Threadiness int
}

// controller has the basic functionality, and may have some wrappers to provide different Start() method options.
type controller[T any] struct {
	name         string
	config       *Config[T]
	eventHandler cache.ResourceEventHandlerRegistration

	queue    workqueue.RateLimitingInterface
	stopChan chan struct{}
	wg       *sync.WaitGroup
}

// NewController creates a new level-driven controller.
// It should be started and stopped using StartControllers and StopControllers functions.
func NewController[T any](name string, config *Config[T]) Controller {
	return &controller[T]{
		name:   name,
		config: config,
		queue: workqueue.NewRateLimitingQueueWithConfig(
			config.RateLimiter,
			workqueue.RateLimitingQueueConfig{
				Name: name,
			},
		),
		stopChan: make(chan struct{}),
		wg:       &sync.WaitGroup{},
	}
}

func (c *controller[T]) addHandler() error {
	klog.Infof("Adding controller %v event handlers", c.name)

	var err error
	c.eventHandler, err = c.config.Informer.AddEventHandler(
		factory.WithUpdateHandlingForObjReplace(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.onAdd,
			UpdateFunc: c.onUpdate,
			DeleteFunc: c.onDelete,
		}))
	if err != nil {
		return fmt.Errorf("failed to add event handler: %w", err)
	}

	if !util.WaitForInformerCacheSyncWithTimeout(c.name, c.stopChan, c.config.Informer.HasSynced) {
		return fmt.Errorf("timed out waiting for %s informer cache to sync", c.name)
	}
	return nil
}

func (c *controller[T]) startWorkers() error {
	if c.config.Threadiness < 1 {
		return fmt.Errorf("failed to start controller %s: threadiness should be > 0", c.name)
	}

	klog.Infof("Starting controller %v with %v workers", c.name, c.config.Threadiness)

	for i := 0; i < c.config.Threadiness; i++ {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			// this loop will exit once the queue is shut down, because processNextQueueItem will return false
			for c.processNextQueueItem() {
			}
		}()
	}
	return nil
}

func (c *controller[T]) stop() {
	close(c.stopChan)
	c.cleanup()
	c.wg.Wait()
}

func (c *controller[T]) cleanup() {
	c.queue.ShutDown()
	if c.eventHandler != nil {
		if err := c.config.Informer.RemoveEventHandler(c.eventHandler); err != nil {
			klog.Errorf("Failed to remove event handler for controller %s: %w", c.name, err)
		}
	}
}

func (c *controller[T]) onAdd(objInterface interface{}) {
	newObj, ok := objInterface.(*T)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("controller %s: expecting %T but received %T", c.name, *new(T), newObj))
		return
	}
	if !c.config.ObjNeedsUpdate(nil, newObj) {
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("controller %s: couldn't get key for object %+v: %v", c.name, newObj, err))
		return
	}
	c.queue.Add(key)
}

func (c *controller[T]) onUpdate(oldObjInterface, newObjInterface interface{}) {
	oldObj, ok := oldObjInterface.(*T)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("controller %s: expecting %T but received %T", c.name, *new(T), oldObj))
		return
	}
	newObj, ok := newObjInterface.(*T)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("controller %s: expecting %T but received %T", c.name, *new(T), newObj))
		return
	}

	if !c.config.ObjNeedsUpdate(oldObj, newObj) {
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("controller %s: couldn't get key for object %+v: %v", c.name, newObj, err))
		return
	}
	c.queue.Add(key)
}

func (c *controller[T]) onDelete(objInterface interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(objInterface)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("controller %s: couldn't get key for object %+v: %v", c.name, objInterface, err))
		return
	}
	c.queue.Add(key)
}

// processNextQueueItem returns false when the queue is shutdown and the handling should be stopped.
// Otherwise, it handles the next item from the queue and always returns true.
func (c *controller[T]) processNextQueueItem() bool {
	key, shutdown := c.queue.Get()

	if shutdown {
		return false
	}

	defer c.queue.Done(key)

	err := c.config.Reconcile(key.(string))
	if err != nil {
		if c.queue.NumRequeues(key) < maxRetries {
			klog.Infof("Controller %s: error found while processing %s: %v", c.name, key.(string), err)
			c.queue.AddRateLimited(key)
			return true
		}
		klog.Warningf("Controller %s: dropping %s out of the queue: %v", c.name, key.(string), err)
		utilruntime.HandleError(err)
	}
	c.queue.Forget(key)
	return true
}

func (c *controller[T]) ReconcileAll() {
	klog.Infof("Controller %s: full reconcile", c.name)
	objs, err := c.config.Lister(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("controller %s: couldn't list objects of type %T on ReconcileAll: %v", c.name, *new(T), err))
		return
	}
	for _, obj := range objs {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("controller %s: couldn't get key for object %+v: %v", c.name, obj, err))
			return
		}
		c.queue.Add(key)
	}
}

// StartControllers starts one or multiple controllers. If initial sync is required, use StartControllersWithInitialSync
func StartControllers(controllers ...Controller) (err error) {
	return StartControllersWithInitialSync(nil, controllers...)
}

// StartControllersWithInitialSync starts one or multiple controllers that share initialSync function.
// initialSync will be called after all event handlers for given controllers were added, but before queue handlers are started.
// It ensures no events will be missed.
// A user of this package that manages multiple controllers would most likely do a single call to this function
// if it needs to use this sync to take an initial action (i.e. building up its own cache) correlating the information
// from all the initialized informers.
// If initial sync is not required, use StartControllers.
func StartControllersWithInitialSync(initialSync func() error, controllers ...Controller) (err error) {
	defer func() {
		if err != nil {
			StopControllers(controllers...)
		}
	}()

	g := new(errgroup.Group)
	for _, controller := range controllers {
		controller := controller
		g.Go(func() error {
			return controller.addHandler()
		})
	}
	if err = g.Wait(); err != nil {
		return err
	}

	// now we have already started receiving events and putting keys in the queue.
	// If initial sync is needed, we can do it now, by listing all existing objects.
	// Since we are receiving all events already, we know every change that happens after the following
	// List call, will be handled.
	if initialSync != nil {
		if err = initialSync(); err != nil {
			return fmt.Errorf("initial sync failed: %w", err)
		}
	}
	for _, controller := range controllers {
		if err = controller.startWorkers(); err != nil {
			return err
		}
	}
	return nil
}

func StopControllers(controllers ...Controller) {
	for _, subcontroller := range controllers {
		subcontroller.stop()
	}
}
