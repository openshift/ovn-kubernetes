package egressip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	eipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/informers/externalversions/egressip/v1"
	egressiplisters "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/listers/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/iprulemanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/iptables"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/linkmanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/routemanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/syncmap"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	utilnet "k8s.io/utils/net"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ktypes "k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"

	"github.com/gaissmai/cidrtree"
	"github.com/vishvananda/netlink"
)

const (
	rulePriority        = 6000 // the priority of the ip routing rules created by the controller. Egress Service priority is 5000.
	routingTableIDStart = 1000
	chainName           = "OVN-KUBE-EGRESS-IP-MULTI-NIC"
	iptChainName        = utiliptables.Chain(chainName)
	maxRetries          = 15
)

var (
	_, defaultV4AnyCIDR, _ = net.ParseCIDR("0.0.0.0/0")
	_, defaultV6AnyCIDR, _ = net.ParseCIDR("0:0:0:0:0:0:0:0")
	iptJumpRule            = []iptables.RuleArg{{Args: []string{"-j", chainName}}}
)

// eIPConfig represents exactly one EgressIP IP. It contains non-pod related EIP configuration information only.
type eIPConfig struct {
	// EgressIP name
	name string
	// EgressIP IP
	ip        *netlink.Addr
	routeLink *routemanager.RoutesPerLink
}

func newEIPConfig() *eIPConfig {
	return &eIPConfig{}
}

// state contains current state for an EgressIP as it was applied.
type state struct {
	// namespaceName -> pod ns/name -> pod IP configuration
	namespacesWithPodIPConfigs map[string]map[ktypes.NamespacedName]*podIPConfigList
	// eIPConfig IP contains all applied configuration for a given EgressIP IP. It does not contain any pod specific config
	eIPConfig *eIPConfig
}

func newState() *state {
	return &state{
		namespacesWithPodIPConfigs: map[string]map[ktypes.NamespacedName]*podIPConfigList{},
		eIPConfig:                  newEIPConfig(),
	}
}

// config is used to update an EIP to the latest state, it stores all required information for an
// update.
type config struct {
	// namespacesWithPods[namespaceName[podNamespacedName] = Pod
	namespacesWithPods map[string]map[ktypes.NamespacedName]*corev1.Pod
	eIPConfig          *eIPConfig
	podIPConfigs       *podIPConfigList
}

// referencedObjects is used by pod and namespace handlers to find what is selected for an EgressIP
type referencedObjects struct {
	eIPNamespaces sets.Set[string]
	eIPPods       sets.Set[ktypes.NamespacedName]
}

// Controller implement Egress IP for non-OVN managed networks
type Controller struct {
	eIPLister         egressiplisters.EgressIPLister
	eIPInformer       cache.SharedIndexInformer
	eIPQueue          workqueue.RateLimitingInterface
	nodeLister        corelisters.NodeLister
	namespaceLister   corelisters.NamespaceLister
	namespaceInformer cache.SharedIndexInformer
	namespaceQueue    workqueue.RateLimitingInterface

	podLister   corelisters.PodLister
	podInformer cache.SharedIndexInformer
	podQueue    workqueue.RateLimitingInterface

	// cache is a cache of configuration states for EIPs, key is EgressIP Name.
	cache *syncmap.SyncMap[*state]

	// referencedObjects should only be accessed with referencedObjectsLock
	referencedObjectsLock sync.RWMutex
	// referencedObjects is a cache of objects that every EIP has selected for its config.
	// With this cache namespace and pod handlers may fetch affected EIP config.
	// key is EIP name.
	referencedObjects map[string]*referencedObjects

	routeManager    *routemanager.Controller
	linkManager     *linkmanager.Controller
	ruleManager     *iprulemanager.Controller
	iptablesManager *iptables.Controller

	nodeName string
	v4       bool
	v6       bool
}

func NewController(eIPInformer egressipinformer.EgressIPInformer, nodeInformer cache.SharedIndexInformer,
	namespaceInformer coreinformers.NamespaceInformer, podInformer coreinformers.PodInformer,
	routeManager *routemanager.Controller, v4, v6 bool, nodeName string, linkManager *linkmanager.Controller) (*Controller, error) {

	c := &Controller{
		eIPLister:   eIPInformer.Lister(),
		eIPInformer: eIPInformer.Informer(),
		eIPQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.NewItemFastSlowRateLimiter(time.Second, 5*time.Second, 5),
			"eipeip",
		),
		nodeLister:        corelisters.NewNodeLister(nodeInformer.GetIndexer()),
		namespaceLister:   namespaceInformer.Lister(),
		namespaceInformer: namespaceInformer.Informer(),
		namespaceQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.NewItemFastSlowRateLimiter(time.Second, 5*time.Second, 5),
			"eipnamespace",
		),
		podLister:   podInformer.Lister(),
		podInformer: podInformer.Informer(),
		podQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.NewItemFastSlowRateLimiter(time.Second, 5*time.Second, 5),
			"eippods",
		),
		cache:                 syncmap.NewSyncMap[*state](),
		referencedObjectsLock: sync.RWMutex{},
		referencedObjects:     map[string]*referencedObjects{},
		routeManager:          routeManager,
		linkManager:           linkManager,
		ruleManager:           iprulemanager.NewController(v4, v6),
		iptablesManager:       iptables.NewController(),
		nodeName:              nodeName,
		v4:                    v4,
		v6:                    v6,
	}
	return c, nil
}

// Run starts the Egress IP that is hosted in non-OVN managed networks. Changes to this function
// need to be mirrored in test function setupFakeTestNode
func (c *Controller) Run(stopCh <-chan struct{}, wg *sync.WaitGroup, threads int) error {
	klog.Info("Starting Egress IP Controller")

	_, err := c.namespaceInformer.AddEventHandler(
		factory.WithUpdateHandlingForObjReplace(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.onNamespaceAdd,
			UpdateFunc: c.onNamespaceUpdate,
			DeleteFunc: c.onNamespaceDelete,
		}))
	if err != nil {
		return err
	}
	_, err = c.podInformer.AddEventHandler(
		factory.WithUpdateHandlingForObjReplace(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.onPodAdd,
			UpdateFunc: c.onPodUpdate,
			DeleteFunc: c.onPodDelete,
		}))
	if err != nil {
		return err
	}
	_, err = c.eIPInformer.AddEventHandler(
		factory.WithUpdateHandlingForObjReplace(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.onEIPAdd,
			UpdateFunc: c.onEIPUpdate,
			DeleteFunc: c.onEIPDelete,
		}))
	if err != nil {
		return err
	}

	syncWg := &sync.WaitGroup{}
	var syncErrs []error
	for _, se := range []struct {
		resourceName string
		syncFn       cache.InformerSynced
	}{
		{"eipeip", c.eIPInformer.HasSynced},
		{"eipnamespace", c.namespaceInformer.HasSynced},
		{"eippod", c.podInformer.HasSynced},
	} {
		syncWg.Add(1)
		go func(resourceName string, syncFn cache.InformerSynced) {
			defer syncWg.Done()
			if !util.WaitForInformerCacheSyncWithTimeout(resourceName, stopCh, syncFn) {
				syncErrs = append(syncErrs, fmt.Errorf("timed out waiting for %q caches to sync", resourceName))
			}
		}(se.resourceName, se.syncFn)
	}
	syncWg.Wait()
	if len(syncErrs) != 0 {
		return kerrors.NewAggregate(syncErrs)
	}
	// Tell rule manager and IPTable manager that we want to fully own all rules at a particular priority/table.
	// Any rules created with this priority or in that particular IPTables chain, that we do not recognize it, will be
	// removed by relevant manager.
	if err := c.ruleManager.OwnPriority(rulePriority); err != nil {
		return fmt.Errorf("failed to own priority %d for IP rules: %v", rulePriority, err)
	}
	if c.v4 {
		if err := c.iptablesManager.OwnChain(utiliptables.TableNAT, iptChainName, utiliptables.ProtocolIPv4); err != nil {
			return fmt.Errorf("unable to own chain %s: %v", iptChainName, err)
		}
		if err = c.iptablesManager.EnsureRules(utiliptables.TableNAT, utiliptables.ChainPostrouting, utiliptables.ProtocolIPv4, iptJumpRule); err != nil {
			return fmt.Errorf("failed to create rule in chain %s to jump to chain %s: %v", utiliptables.ChainPostrouting, iptChainName, err)
		}
	}
	if c.v6 {
		if err := c.iptablesManager.OwnChain(utiliptables.TableNAT, iptChainName, utiliptables.ProtocolIPv6); err != nil {
			return fmt.Errorf("unable to own chain %s: %v", iptChainName, err)
		}
		if err = c.iptablesManager.EnsureRules(utiliptables.TableNAT, utiliptables.ChainPostrouting, utiliptables.ProtocolIPv6, iptJumpRule); err != nil {
			return fmt.Errorf("unable to ensure iptables rules for jump rule: %v", err)
		}
	}

	err = wait.PollUntilContextTimeout(wait.ContextForChannel(stopCh), 1*time.Second, 10*time.Second, true,
		func(ctx context.Context) (done bool, err error) {
			if err := c.RepairNode(); err != nil {
				klog.Errorf("Failed to repair node: '%v' - Retrying", err)
				return false, nil
			}
			return true, nil
		})
	if err != nil {
		return fmt.Errorf("failed to run EgressIP controller because repairing node failed: %v", err)
	}

	for i := 0; i < threads; i++ {
		for _, workerFn := range []func(*sync.WaitGroup){
			c.runEIPWorker,
			c.runPodWorker,
			c.runNamespaceWorker,
		} {
			wg.Add(1)
			go func(fn func(*sync.WaitGroup)) {
				defer wg.Done()
				wait.Until(func() {
					fn(wg)
				}, time.Second, stopCh)
			}(workerFn)
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// wait until we're told to stop
		<-stopCh
		c.eIPQueue.ShutDown()
		c.podQueue.ShutDown()
		c.namespaceQueue.ShutDown()
	}()
	wg.Add(1)
	go func() {
		c.iptablesManager.Run(stopCh, 6*time.Minute)
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		c.ruleManager.Run(stopCh, 5*time.Minute)
		wg.Done()
	}()
	return nil
}

func (c *Controller) onEIPAdd(obj interface{}) {
	_, ok := obj.(*eipv1.EgressIP)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expecting %T but received %T", &eipv1.EgressIP{}, obj))
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	klog.V(4).Infof("Adding Egress IP %s", key)
	c.eIPQueue.Add(key)
}

func (c *Controller) onEIPUpdate(oldObj, newObj interface{}) {
	oldEIP, ok := oldObj.(*eipv1.EgressIP)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expecting %T but received %T", &eipv1.EgressIP{}, oldObj))
		return
	}
	newEIP, ok := newObj.(*eipv1.EgressIP)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expecting %T but received %T", &eipv1.EgressIP{}, newObj))
		return
	}
	if oldEIP == nil || newEIP == nil {
		utilruntime.HandleError(errors.New("invalid Egress IP policy to onEIPUpdate()"))
		return
	}
	if oldEIP.Generation == newEIP.Generation ||
		!newEIP.GetDeletionTimestamp().IsZero() {
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", newObj, err))
	}
	c.eIPQueue.Add(key)
}

func (c *Controller) onEIPDelete(obj interface{}) {
	_, ok := obj.(*eipv1.EgressIP)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tomstone %#v", obj))
			return
		}
		_, ok = tombstone.Obj.(*eipv1.EgressIP)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not an Egress IP object %#v", tombstone.Obj))
			return
		}
	}
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	c.eIPQueue.Add(key)
}

func (c *Controller) runEIPWorker(wg *sync.WaitGroup) {
	for c.processNextEIPWorkItem(wg) {
	}
}

func (c *Controller) processNextEIPWorkItem(wg *sync.WaitGroup) bool {
	wg.Add(1)
	defer wg.Done()
	key, shutdown := c.eIPQueue.Get()
	if shutdown {
		return false
	}
	defer c.eIPQueue.Done(key)
	klog.V(4).Infof("Processing Egress IP %s", key)
	if err := c.syncEIP(key.(string)); err != nil {
		if c.eIPQueue.NumRequeues(key) < maxRetries {
			klog.V(4).Infof("Error found while processing Egress IP %s: %w", key, err)
			c.eIPQueue.AddRateLimited(key)
			return true
		}
		klog.Errorf("Dropping Egress IP %q out of the queue: %w", key, err)
		utilruntime.HandleError(err)
	}
	c.eIPQueue.Forget(key)
	return true
}

func (c *Controller) syncEIP(eIPName string) error {
	// 1. Lock on the existing 'state', as we are going to use it for cleanup and update.
	// 2. Build latest 'config'. This includes listing referenced namespaces and pods.
	// To make sure there is no race with pod and namespace handlers, referencedObjects is acquired
	// before listing objects, and released when the 'config' is built. At this point namespace and pod
	// handler can use referencedObjects to see which objects were considered as related by the handler last time.
	// 3. With existing state and newly generated config, we can clean up and apply.
	return c.cache.DoWithLock(eIPName, func(eIPName string) error {
		informerEIP, err := c.eIPLister.Get(eIPName)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get Egress IP before sync: %w", err)
		}
		var update *config
		// get updated policy and update policy refs
		if apierrors.IsNotFound(err) || (informerEIP != nil && !informerEIP.DeletionTimestamp.IsZero()) {
			// EIP deleted
			update = nil
			c.deleteRefObjects(eIPName)
		} else {
			update, err = c.getConfigAndUpdateRefs(informerEIP, true)
			if err != nil {
				return fmt.Errorf("failed to get config and update references for Egress IP %s: %w", eIPName, err)
			}
		}
		existing, found := c.cache.Load(eIPName)
		if !found {
			if update == nil {
				// nothing to do
				return nil
			}
			existing = newState()
			c.cache.Store(eIPName, existing)
		}
		if err = c.updateEIP(existing, update); err != nil {
			return fmt.Errorf("failed to update policy from %+v to %+v: %w", existing, update, err)
		}
		if update == nil {
			c.cache.Delete(eIPName)
		}
		return nil
	})
}

// getConfigAndUpdateRefs lists and updates all referenced objects for a given EIP and returns
// config to perform an update.
// This function should be the only one that lists referenced objects, and updates referencedObjects atomically.
func (c *Controller) getConfigAndUpdateRefs(eIP *eipv1.EgressIP, updateRefs bool) (*config, error) {
	c.referencedObjectsLock.Lock()
	defer c.referencedObjectsLock.Unlock()
	eIPConfig, podIPConfigs, selectedNamespaces, selectedPods, namespacePods, err := c.processEIP(eIP)
	if err != nil {
		return nil, err
	}
	if updateRefs {
		refObjs := &referencedObjects{
			eIPNamespaces: selectedNamespaces,
			eIPPods:       selectedPods,
		}
		c.referencedObjects[eIP.Name] = refObjs
	}
	if eIPConfig == nil || podIPConfigs == nil {
		return nil, nil
	}
	return &config{
		namespacesWithPods: namespacePods,
		eIPConfig:          eIPConfig,
		podIPConfigs:       podIPConfigs,
	}, nil

}

// processEIP attempts to find namespaces and pods that match the EIP selectors and then attempts to find a network
// that can host one of the EIP IPs returning egress IP configuration, selected namespaces and pods
func (c *Controller) processEIP(eip *eipv1.EgressIP) (*eIPConfig, *podIPConfigList, sets.Set[string], sets.Set[ktypes.NamespacedName],
	map[string]map[ktypes.NamespacedName]*corev1.Pod, error) {
	selectedNamespaces := sets.Set[string]{}
	selectedPods := sets.Set[ktypes.NamespacedName]{}
	selectedPodIPs := make(map[ktypes.NamespacedName][]net.IP)
	selectedNamespacesPods := map[string]map[ktypes.NamespacedName]*corev1.Pod{}

	// namespace selector is mandatory for EIP
	namespaces, err := c.listNamespacesBySelector(&eip.Spec.NamespaceSelector)
	if err != nil {
		return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods, fmt.Errorf("failed to list namespaces: %w", err)
	}
	for _, namespace := range namespaces {
		pods, err := c.listPodsByNamespaceAndSelector(namespace.Name, &eip.Spec.PodSelector)
		if err != nil {
			return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods, fmt.Errorf("failed to list pods in namespace %s: %w",
				namespace.Name, err)
		}
		podsNsName := map[ktypes.NamespacedName]*corev1.Pod{}
		for _, pod := range pods {
			// Ignore completed pods, host networked pods, pods not scheduled
			if util.PodWantsHostNetwork(pod) || util.PodCompleted(pod) || !util.PodScheduled(pod) {
				continue
			}
			ips, err := util.DefaultNetworkPodIPs(pod)
			if err != nil {
				return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods, fmt.Errorf("failed to get pod ips: %w", err)
			}
			if len(ips) == 0 {
				continue
			}
			key := ktypes.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
			selectedPods.Insert(key)
			selectedPodIPs[key] = ips
			podsNsName[key] = pod
		}
		selectedNamespacesPods[namespace.Name] = podsNsName
		selectedNamespaces.Insert(namespace.Name)
	}
	if selectedPods.Len() == 0 {
		return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods, nil
	}
	node, err := c.nodeLister.Get(c.nodeName)
	if err != nil {
		return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods,
			fmt.Errorf("failed to find this node %q kubernetes Node object: %v", c.nodeName, err)
	}
	parsedNodeEIPConfig, err := util.GetNodeEIPConfig(node)
	if err != nil {
		return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods,
			fmt.Errorf("failed to determine egress IP config for node %s: %w", node.Name, err)
	}
	// max of 1 EIP IP is selected. Return when 1 is found.
	for _, status := range eip.Status.Items {
		if isValid := isEIPStatusItemValid(status, c.nodeName); !isValid {
			continue
		}
		eIPNet, err := util.GetIPNetFullMask(status.EgressIP)
		if err != nil {
			return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods,
				fmt.Errorf("failed to generate mask for EgressIP %s IP %s: %v", eip.Name, status.EgressIP, err)
		}
		if util.IsOVNManagedNetwork(parsedNodeEIPConfig, eIPNet.IP) {
			continue
		}
		isEIPV6 := utilnet.IsIPv6(eIPNet.IP)
		found, link, err := findLinkOnSameNetworkAsIP(eIPNet.IP, c.v4, c.v6)
		if err != nil {
			return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods,
				fmt.Errorf("failed to find a network to host EgressIP %s IP %s: %v", eip.Name, status.EgressIP, err)
		}
		if !found {
			continue
		}
		klog.Infof("Generating config for EgressIP %s IP %s which is hosted by a non-OVN managed interface (name %s)",
			eip.Name, status.EgressIP, link.Attrs().Name)
		// go through all selected pods and build a config per pod IP. We know there are at least one pod and these the
		// pod(s) have IP(s).
		eIPConfig, podIPConfigs := generateEIPConfigForPods(selectedPodIPs, link, eIPNet, isEIPV6)
		// ignore other EIP IPs. Multiple EIP IPs cannot be assigned to the same node
		return eIPConfig, podIPConfigs, selectedNamespaces, selectedPods, selectedNamespacesPods, nil
	}
	return nil, nil, selectedNamespaces, selectedPods, selectedNamespacesPods, nil
}

func generateEIPConfigForPods(pods map[ktypes.NamespacedName][]net.IP, link netlink.Link, eIPNet *net.IPNet, isEIPV6 bool) (*eIPConfig, *podIPConfigList) {
	eipConfig := newEIPConfig()
	newPodIPConfigs := newPodIPConfigList()
	eipConfig.routeLink = getDefaultRouteForLink(link, isEIPV6)
	eipConfig.ip = getNetlinkAddressWithLabel(eIPNet, link.Attrs().Index, link.Attrs().Name)
	for _, podIPs := range pods {
		for _, podIP := range podIPs {
			isPodIPv6 := utilnet.IsIPv6(podIP)
			if isPodIPv6 != isEIPV6 {
				continue
			}
			ipConfig := newPodIPConfig()
			ipConfig.ipTableRule = generateIPTablesSNATRuleArg(podIP, isPodIPv6, link.Attrs().Name, eIPNet.IP.String())
			ipConfig.ipRule = generateIPRule(podIP, isPodIPv6, link.Attrs().Index)
			ipConfig.v6 = isPodIPv6
			newPodIPConfigs.elems = append(newPodIPConfigs.elems, ipConfig)
		}
	}
	return eipConfig, newPodIPConfigs
}

func (c *Controller) deleteRefObjects(name string) {
	c.referencedObjectsLock.Lock()
	delete(c.referencedObjects, name)
	c.referencedObjectsLock.Unlock()
}

// updateEIP reconciles existing state towards update config. If update is nil, delete existing state.
func (c *Controller) updateEIP(existing *state, update *config) error {
	// cleanup first
	// cleanup pod specific configuration - aka ip rules and iptables
	if len(existing.namespacesWithPodIPConfigs) > 0 {
		// track which namespaces should be removed from targetNamespaces
		var namespacesToDelete []string
		for targetNamespace, targetPods := range existing.namespacesWithPodIPConfigs {
			// track which pods should be removed from targetPods
			var podsToDelete []ktypes.NamespacedName
			for podNamespacedName, existingPodConfig := range targetPods {
				podIPConfigsToDelete := newPodIPConfigList()
				// each pod IP will have its own configuration that needs to be tracked and possibly removed
				for _, existingPodIPConfig := range existingPodConfig.elems {
					// delete EIP config if:
					// 1. EIP deleted or no EIP found
					// 3. Is not present in update
					// 3. Target pod is not listed in update.targetNamespaces
					// 4. Pod IP config has changed
					if update == nil || !update.podIPConfigs.has(existingPodIPConfig) ||
						update.namespacesWithPods[targetNamespace][podNamespacedName] == nil {
						podIPConfigsToDelete.Insert(*existingPodIPConfig)
					}
				}
				if podIPConfigsToDelete.Len() > 0 {
					for _, podIPConfigToDelete := range podIPConfigsToDelete.elems {
						if err := c.deleteIPConfig(podIPConfigToDelete); err != nil {
							existingPodConfig.InsertOverwriteFailed(*podIPConfigToDelete)
							return err
						}
						existingPodConfig.Delete(*podIPConfigToDelete)
					}
				}
				if update == nil || update.namespacesWithPods[targetNamespace][podNamespacedName] == nil {
					podsToDelete = append(podsToDelete, podNamespacedName)
				}
			}
			for _, podToDelete := range podsToDelete {
				delete(targetPods, podToDelete)
			}
			if update == nil || update.namespacesWithPods[targetNamespace] == nil {
				namespacesToDelete = append(namespacesToDelete, targetNamespace)
			}
		}
		for _, nsToDelete := range namespacesToDelete {
			delete(existing.namespacesWithPodIPConfigs, nsToDelete)
		}
	}
	// clean up pod independent configuration first
	// if EIP IP has changed and therefore could be hosted by a different interface, remove old EIP
	// Delete addresses and routes under the following conditions
	// 1. existing contains a non nil IP and update is nil
	// 2. existing contains an ip and update contains an ip and update contains an ip different to existing
	if (update == nil && existing.eIPConfig != nil && existing.eIPConfig.ip != nil) ||
		(update != nil && update.eIPConfig != nil && update.eIPConfig.ip != nil &&
			existing.eIPConfig != nil && existing.eIPConfig.ip != nil && !existing.eIPConfig.ip.Equal(*update.eIPConfig.ip)) {

		if err := c.linkManager.DelAddress(*existing.eIPConfig.ip); err != nil {
			// TODO(mk): if we fail to delete address, handle it
			return fmt.Errorf("failed to delete egress IP address %s: %w", existing.eIPConfig.ip, err)
		}
	}
	if (update == nil && existing.eIPConfig != nil && existing.eIPConfig.routeLink != nil) ||
		(update != nil && update.eIPConfig != nil && update.eIPConfig.routeLink != nil &&
			existing.eIPConfig != nil && existing.eIPConfig.routeLink != nil &&
			!existing.eIPConfig.routeLink.Equal(*update.eIPConfig.routeLink)) {
		// route manager takes care of retry
		c.routeManager.Del(*existing.eIPConfig.routeLink)
	}

	// apply new changes
	if update != nil && update.eIPConfig != nil && update.eIPConfig.ip != nil && update.eIPConfig.routeLink != nil {
		for updatedTargetNS, updatedTargetPod := range update.namespacesWithPods {
			existingNs, found := existing.namespacesWithPodIPConfigs[updatedTargetNS]
			if !found {
				existingNs = map[ktypes.NamespacedName]*podIPConfigList{}
				existing.namespacesWithPodIPConfigs[updatedTargetNS] = existingNs
			}
			for updatedPodNamespacedName, updatedPod := range updatedTargetPod {
				existingTargetPodConfig, found := existingNs[updatedPodNamespacedName]
				if !found {
					existingTargetPodConfig = newPodIPConfigList()
					existingNs[updatedPodNamespacedName] = existingTargetPodConfig
				}
				// applyPodConfig will apply pod specific configuration - ip rules and iptables rules
				err := c.applyPodConfig(existingTargetPodConfig, update)
				if err != nil {
					return fmt.Errorf("failed to apply pod %s/%s configuration for EgressIP %s IP %s: %v",
						updatedPod.Namespace, updatedPod.Name, update.eIPConfig.name, update.eIPConfig.ip.String(), err)
				}
			}
		}
		// TODO(mk): only apply the follow when its new config or when it failed to apply
		// Ok to repeat requests to route manager and link manager
		if err := c.linkManager.AddAddress(*update.eIPConfig.ip); err != nil {
			return fmt.Errorf("failed to add address EgressIP %s IP %s to link manager: %v", update.eIPConfig.name,
				update.eIPConfig.ip.String(), err)
		}
		existing.eIPConfig.ip = update.eIPConfig.ip
		// route manager manages retry
		c.routeManager.Add(*update.eIPConfig.routeLink)
		existing.eIPConfig.routeLink = update.eIPConfig.routeLink
	}
	return nil
}

func (c *Controller) deleteIPConfig(podIPConfigToDelete *podIPConfig) error {
	if err := c.ruleManager.Delete(podIPConfigToDelete.ipRule); err != nil {
		return err
	}
	if podIPConfigToDelete.v6 {
		if err := c.iptablesManager.DeleteRule(utiliptables.TableNAT, iptChainName, utiliptables.ProtocolIPv6,
			podIPConfigToDelete.ipTableRule); err != nil {
			return err
		}
	} else {
		if err := c.iptablesManager.DeleteRule(utiliptables.TableNAT, iptChainName, utiliptables.ProtocolIPv4,
			podIPConfigToDelete.ipTableRule); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) applyPodConfig(existingConfig *podIPConfigList, updatedPolicy *config) error {
	configToAdd := newPodIPConfigList()
	for _, newConfig := range updatedPolicy.podIPConfigs.elems {
		if !existingConfig.hasWithoutError(newConfig) {
			configToAdd.Insert(*newConfig)
		}
	}
	for _, newConfig := range configToAdd.elems {
		if err := c.ruleManager.Add(newConfig.ipRule); err != nil {
			existingConfig.InsertOverwriteFailed(*newConfig)
			return err
		}
		// v4
		if newConfig.v6 {
			if err := c.iptablesManager.EnsureRules(utiliptables.TableNAT, iptChainName, utiliptables.ProtocolIPv6, []iptables.RuleArg{newConfig.ipTableRule}); err != nil {
				existingConfig.InsertOverwriteFailed(*newConfig)
				return fmt.Errorf("unable to ensure iptables rules: %v", err)
			}
		} else {
			if err := c.iptablesManager.EnsureRules(utiliptables.TableNAT, iptChainName, utiliptables.ProtocolIPv4, []iptables.RuleArg{newConfig.ipTableRule}); err != nil {
				existingConfig.InsertOverwriteFailed(*newConfig)
				return fmt.Errorf("failed to ensure rules (%+v) in chain %s: %v", newConfig.ipTableRule, iptChainName, err)
			}
		}
		existingConfig.insertOverwrite(*newConfig)
	}
	return nil
}

func (c *Controller) getAllEIPs() ([]*eipv1.EgressIP, error) {
	eips, err := c.eIPLister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list EgressIPs: %v", err)
	}
	return eips, nil
}

// RepairNode generates whats expected and what is seen on the node and removes any stale configuration. This should be
// called at Controller startup.
func (c *Controller) RepairNode() error {
	links, err := util.GetNetLinkOps().LinkList()
	if err != nil {
		return fmt.Errorf("failed to ensure IP is correctly configured becase we could not list links: %v", err)
	}
	// get address map for each interface -> addresses/mask
	// also map address/mask -> interface name
	assignedAddr := sets.New[string]()
	assignedAddrStrToAddrs := make(map[string]netlink.Addr)
	assignedIPRoutes := sets.New[string]()
	assignedIPRouteStrToRoutes := make(map[string]routemanager.RoutesPerLink)
	assignedIPRules := sets.New[string]()
	assignedIPRulesStrToRules := make(map[string]netlink.Rule)
	assignedIPTableV4Rules := sets.New[string]()
	assignedIPTableV6Rules := sets.New[string]()
	assignedIPTablesV4StrToRules := make(map[string]iptables.RuleArg)
	assignedIPTablesV6StrToRules := make(map[string]iptables.RuleArg)

	for _, link := range links {
		link := link
		linkName := link.Attrs().Name
		linkIdx := link.Attrs().Index
		addresses, err := linkmanager.GetExternallyAvailableAddresses(link, c.v4, c.v6)
		if err != nil {
			return fmt.Errorf("unable to get link addresses for link %s: %v", linkName, err)
		}
		var assignedAddrFound bool
		for _, address := range addresses {
			if address.Label == linkmanager.GetAssignedAddressLabel(linkName) {
				assignedAddrFound = true
				addressStr := address.String()
				assignedAddr.Insert(addressStr)
				assignedAddrStrToAddrs[addressStr] = address
			}
		}
		if !assignedAddrFound {
			continue
		}
		filter, mask := filterRouteByLinkTable(linkIdx, getRouteTableID(linkIdx))
		existingRoutes, err := util.GetNetLinkOps().RouteListFiltered(netlink.FAMILY_ALL, filter, mask)
		if err != nil {
			return fmt.Errorf("unable to get route list using filter (%s): %v", filter.String(), err)
		}
		for _, existingRoute := range existingRoutes {
			route := routemanager.ConvertNetlinkRouteToRoute(existingRoute)
			routeStr := route.String()
			assignedIPRoutes.Insert(routeStr)
			assignedIPRouteStrToRoutes[routeStr] = routemanager.RoutesPerLink{Link: link,
				Routes: []routemanager.Route{route}}
		}
	}
	filter, mask := filterRuleByPriority(rulePriority)
	existingRules, err := util.GetNetLinkOps().RuleListFiltered(netlink.FAMILY_ALL, filter, mask)
	if err != nil {
		return fmt.Errorf("failed to list IP rules: %v", err)
	}
	for _, existingRule := range existingRules {
		ruleStr := existingRule.String()
		assignedIPRules.Insert(ruleStr)
		assignedIPRulesStrToRules[ruleStr] = existingRule
	}
	// gather IPv4 and IPv6 IPTable rules and ignore what IP family we currently support because we may have converted from
	// dual to single or vice versa
	ipTableV4Rules, err := c.iptablesManager.GetIPv4ChainRuleArgs(utiliptables.TableNAT, chainName)
	if err != nil {
		return fmt.Errorf("failed to list IPTable IPv4 rules: %v", err)
	}
	for _, rule := range ipTableV4Rules {
		ruleStr := strings.Join(rule.Args, " ")
		assignedIPTableV4Rules.Insert(ruleStr)
		assignedIPTablesV4StrToRules[ruleStr] = rule
	}
	ipTableV6Rules, err := c.iptablesManager.GetIPv6ChainRuleArgs(utiliptables.TableNAT, chainName)
	if err != nil {
		return fmt.Errorf("failed to list IPTable IPv4 rules: %v", err)
	}
	for _, rule := range ipTableV6Rules {
		ruleStr := strings.Join(rule.Args, " ")
		assignedIPTableV6Rules.Insert(ruleStr)
		assignedIPTablesV6StrToRules[ruleStr] = rule
	}

	expectedAddrs := sets.New[string]()
	expectedIPRoutes := sets.New[string]()
	expectedIPRules := sets.New[string]()
	expectedIPTableV4Rules := sets.New[string]()
	expectedIPTableV6Rules := sets.New[string]()
	egressIPs, err := c.getAllEIPs()
	if err != nil {
		return err
	}
	node, err := c.nodeLister.Get(c.nodeName)
	if err != nil {
		return err
	}
	parsedNodeEIPConfig, err := util.GetNodeEIPConfig(node)
	if err != nil {
		return err
	}
	for _, egressIP := range egressIPs {
		if len(egressIP.Status.Items) == 0 {
			continue
		}
		for _, status := range egressIP.Status.Items {
			if isValid := isEIPStatusItemValid(status, c.nodeName); !isValid {
				continue
			}
			eIPNet, err := util.GetIPNetFullMask(status.EgressIP)
			if err != nil {
				return err
			}
			if util.IsOVNManagedNetwork(parsedNodeEIPConfig, eIPNet.IP) {
				continue
			}
			isEIPV6 := utilnet.IsIPv6(eIPNet.IP)
			found, link, err := findLinkOnSameNetworkAsIP(eIPNet.IP, c.v4, c.v6)
			if err != nil {
				return fmt.Errorf("failed to find a network to host EgressIP %s IP %s: %v", egressIP.Name,
					eIPNet.IP.String(), err)
			}
			if !found {
				continue
			}
			linkIdx := link.Attrs().Index
			linkName := link.Attrs().Name
			expectedIPRoutes.Insert(getDefaultRoute(linkIdx, isEIPV6).String())
			expectedAddrs.Insert(getNetlinkAddressWithLabel(eIPNet, linkIdx, linkName).String())
			namespaceSelector, err := metav1.LabelSelectorAsSelector(&egressIP.Spec.NamespaceSelector)
			if err != nil {
				return fmt.Errorf("invalid namespaceSelector for egress IP %s: %v", egressIP.Name, err)
			}
			podSelector, err := metav1.LabelSelectorAsSelector(&egressIP.Spec.PodSelector)
			if err != nil {
				return fmt.Errorf("invalid podSelector for egress IP %s: %v", egressIP.Name, err)
			}
			namespaces, err := c.namespaceLister.List(namespaceSelector)
			if err != nil {
				return fmt.Errorf("failed to list namespaces using selector %s to configure egress IP %s: %v",
					namespaceSelector.String(), egressIP.Name, err)
			}
			for _, namespace := range namespaces {
				namespaceLabels := labels.Set(namespace.Labels)
				if namespaceSelector.Matches(namespaceLabels) {
					pods, err := c.podLister.Pods(namespace.Name).List(podSelector)
					if err != nil {
						return fmt.Errorf("failed to list pods using selector %s to configure egress IP %s: %v",
							podSelector.String(), egressIP.Name, err)
					}
					for _, pod := range pods {
						if util.PodCompleted(pod) || util.PodWantsHostNetwork(pod) || len(pod.Status.PodIPs) == 0 {
							continue
						}
						podIPs, err := util.DefaultNetworkPodIPs(pod)
						if err != nil {
							return err
						}
						for _, podIP := range podIPs {
							isPodIPV6 := utilnet.IsIPv6(podIP)
							if isPodIPV6 != isEIPV6 {
								continue
							}
							if !c.isIPSupported(isPodIPV6) {
								continue
							}
							ipTableRule := strings.Join(generateIPTablesSNATRuleArg(podIP, isPodIPV6, linkName, status.EgressIP).Args, " ")
							if isPodIPV6 {
								expectedIPTableV6Rules.Insert(ipTableRule)
							} else {
								expectedIPTableV4Rules.Insert(ipTableRule)
							}
							expectedIPRules.Insert(generateIPRule(podIP, isPodIPV6, link.Attrs().Index).String())
						}
					}
				}
			}
		}
	}
	staleAddresses := assignedAddr.Difference(expectedAddrs)
	if err := c.removeStaleAddresses(staleAddresses, assignedAddrStrToAddrs); err != nil {
		return fmt.Errorf("failed to remove stale Egress IP addresse(s) (%+v): %v", staleAddresses, err)
	}
	staleIPRoutes := assignedIPRoutes.Difference(expectedIPRoutes)
	if err := c.removeStaleIPRoutes(staleIPRoutes, assignedIPRouteStrToRoutes); err != nil {
		return fmt.Errorf("failed to remove stale IP route(s) (%+v): %v", staleIPRoutes, err)
	}
	staleIPRules := assignedIPRules.Difference(expectedIPRules)
	if err := c.removeStaleIPRules(staleIPRules, assignedIPRulesStrToRules); err != nil {
		return fmt.Errorf("failed to remove stale IP rule(s) (%+v): %v", staleIPRules, err)
	}
	staleIPTableV4Rules := assignedIPTableV4Rules.Difference(expectedIPTableV4Rules)
	if err := c.removeStaleIPTableV4Rules(staleIPTableV4Rules, assignedIPTablesV4StrToRules); err != nil {
		return fmt.Errorf("failed to remove stale IPTable V4 rule(s) (%+v): %v", staleIPTableV4Rules, err)
	}
	staleIPTableV6Rules := assignedIPTableV6Rules.Difference(expectedIPTableV6Rules)
	if err := c.removeStaleIPTableV6Rules(staleIPTableV6Rules, assignedIPTablesV6StrToRules); err != nil {
		return fmt.Errorf("failed to remove stale IPTable V4 rule(s) (%+v): %v", staleIPTableV6Rules, err)
	}
	return nil
}

func isEIPStatusItemValid(status eipv1.EgressIPStatusItem, nodeName string) bool {
	if status.Node != nodeName {
		return false
	}
	if status.EgressIP == "" {
		return false
	}
	return true
}

func (c *Controller) removeStaleAddresses(staleAddresses sets.Set[string], addrStrToNetlinkAddr map[string]netlink.Addr) error {
	for _, address := range staleAddresses.UnsortedList() {
		nlAddr, ok := addrStrToNetlinkAddr[address]
		if !ok {
			return fmt.Errorf("expected to find address %q in map: %+v", address, addrStrToNetlinkAddr)
		}
		if err := c.linkManager.DelAddress(nlAddr); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) removeStaleIPRoutes(staleIPRoutes sets.Set[string], routeStrToNetlinkRoute map[string]routemanager.RoutesPerLink) error {
	for _, ipRoute := range staleIPRoutes.UnsortedList() {
		route, ok := routeStrToNetlinkRoute[ipRoute]
		if !ok {
			return fmt.Errorf("expected to find route %q in map: %+v", ipRoute, routeStrToNetlinkRoute)
		}
		c.routeManager.Del(route)
	}
	return nil
}

func (c *Controller) removeStaleIPRules(staleIPRules sets.Set[string], ruleStrToNetlinkRule map[string]netlink.Rule) error {
	for _, ipRule := range staleIPRules.UnsortedList() {
		rule, ok := ruleStrToNetlinkRule[ipRule]
		if !ok {
			return fmt.Errorf("expected to find route %q in map: %+v", ipRule, ruleStrToNetlinkRule)
		}
		if err := c.ruleManager.Delete(rule); err != nil {
			return fmt.Errorf("failed to delete IP rule (%s): %v", rule.String(), err)
		}
	}
	return nil
}

func (c *Controller) removeStaleIPTableV4Rules(staleRules sets.Set[string], ruleStrToRule map[string]iptables.RuleArg) error {
	return c.removeStaleIPTableRules(utiliptables.ProtocolIPv4, staleRules, ruleStrToRule)
}

func (c *Controller) removeStaleIPTableV6Rules(staleRules sets.Set[string], ruleStrToRule map[string]iptables.RuleArg) error {
	return c.removeStaleIPTableRules(utiliptables.ProtocolIPv6, staleRules, ruleStrToRule)
}

func (c *Controller) removeStaleIPTableRules(proto utiliptables.Protocol, staleRules sets.Set[string], ruleStrToRule map[string]iptables.RuleArg) error {
	for _, rule := range staleRules.UnsortedList() {
		ruleArg, ok := ruleStrToRule[rule]
		if !ok {
			return fmt.Errorf("expected to find route %q in map: %+v", rule, ruleStrToRule)
		}
		if err := c.iptablesManager.DeleteRule(utiliptables.TableNAT, iptChainName, proto, ruleArg); err != nil {
			return fmt.Errorf("failed to delete IP rule (%s): %v", rule, err)
		}
	}
	return nil
}

func (c *Controller) isIPSupported(isIPV6 bool) bool {
	if !isIPV6 && c.v4 {
		return true
	}
	if isIPV6 && c.v6 {
		return true
	}
	return false
}

func getRouteTableID(ifIndex int) int {
	return ifIndex + routingTableIDStart
}

func findLinkOnSameNetworkAsIP(ip net.IP, v4, v6 bool) (bool, netlink.Link, error) {
	found, link, err := findLinkOnSameNetworkAsIPUsingLPM(ip, v4, v6)
	if err != nil {
		return false, nil, fmt.Errorf("failed to find network to host IP %s: %v", ip.String(), err)
	}
	return found, link, nil

}

// findLinkOnSameNetworkAsIPUsingLPM iterates through all links found locally building a map of addresses associated with
// each link and attempts to find a network that will host the func parameter IP address using longest-prefix-match.
func findLinkOnSameNetworkAsIPUsingLPM(ip net.IP, v4, v6 bool) (bool, netlink.Link, error) {
	prefixLinks := map[string]netlink.Link{} // key is network CIDR
	prefixes := make([]netip.Prefix, 0)
	links, err := util.GetNetLinkOps().LinkList()
	if err != nil {
		return false, nil, fmt.Errorf("failed to list links: %v", err)
	}
	for _, link := range links {
		link := link
		linkPrefixes, err := linkmanager.GetExternallyAvailablePrefixesExcludeAssigned(link, v4, v6)
		if err != nil {
			klog.Errorf("Failed to get address from link %s: %v", link.Attrs().Name, err)
			continue
		}
		prefixes = append(prefixes, linkPrefixes...)
		// create lookup table for later retrieval
		for _, prefixFound := range linkPrefixes {
			_, ipNet, err := net.ParseCIDR(prefixFound.String())
			if err != nil {
				klog.Errorf("Egress IP: skipping prefix %q due to parsing CIDR error: %v", prefixFound.String(), err)
				continue
			}
			prefixLinks[ipNet.String()] = link
		}
	}
	lpmTree := cidrtree.New(prefixes...)
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false, nil, fmt.Errorf("failed to convert IP %s to netip addr: %v", ip.String(), err)
	}
	network, found := lpmTree.Lookup(addr)
	if !found {
		return false, nil, nil
	}
	link, ok := prefixLinks[network.String()]
	if !ok {
		return false, nil, nil
	}
	return true, link, nil
}

func getNetlinkAddressWithLabel(addr *net.IPNet, ifindex int, linkName string) *netlink.Addr {
	return &netlink.Addr{
		IPNet:     addr,
		Scope:     int(netlink.SCOPE_UNIVERSE),
		LinkIndex: ifindex,
		Label:     linkmanager.GetAssignedAddressLabel(linkName),
	}
}

func getDefaultRouteForLink(link netlink.Link, v6 bool) *routemanager.RoutesPerLink {
	return &routemanager.RoutesPerLink{Link: link,
		Routes: []routemanager.Route{
			getDefaultRoute(link.Attrs().Index, v6),
		},
	}
}

func getDefaultRoute(linkIdx int, v6 bool) routemanager.Route {
	anyCIDR := defaultV4AnyCIDR
	if v6 {
		anyCIDR = defaultV6AnyCIDR
	}
	return routemanager.Route{
		Table:  getRouteTableID(linkIdx),
		Subnet: anyCIDR,
	}
}

// generateIPRules generates IP rules at a predefined priority for each pod IP with a custom routing table based
// from the links 'ifindex'
func generateIPRule(srcIP net.IP, isIPv6 bool, ifIndex int) netlink.Rule {
	r := *netlink.NewRule()
	r.Table = getRouteTableID(ifIndex)
	r.Priority = rulePriority
	var ipFullMask string
	if isIPv6 {
		ipFullMask = fmt.Sprintf("%s/128", srcIP.String())
		r.Family = netlink.FAMILY_V6
	} else {
		ipFullMask = fmt.Sprintf("%s/32", srcIP.String())
		r.Family = netlink.FAMILY_V4
	}
	_, ipNet, _ := net.ParseCIDR(ipFullMask)
	r.Src = ipNet
	return r
}

func filterRouteByLinkTable(linkIndex, tableID int) (*netlink.Route, uint64) {
	return &netlink.Route{
			LinkIndex: linkIndex,
			Table:     tableID,
		},
		netlink.RT_FILTER_OIF | netlink.RT_FILTER_TABLE
}

func filterRuleByPriority(priority int) (*netlink.Rule, uint64) {
	return &netlink.Rule{
			Priority: priority,
		},
		netlink.RT_FILTER_PRIORITY
}

func getPodNamespacedName(pod *corev1.Pod) ktypes.NamespacedName {
	return ktypes.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
}

func generateIPTablesSNATRuleArg(srcIP net.IP, isIPv6 bool, infName, snatIP string) iptables.RuleArg {
	var srcIPFullMask string
	if isIPv6 {
		srcIPFullMask = fmt.Sprintf("%s/128", srcIP.String())
	} else {
		srcIPFullMask = fmt.Sprintf("%s/32", srcIP.String())
	}
	return iptables.RuleArg{Args: []string{"-s", srcIPFullMask, "-o", infName, "-j", "SNAT", "--to-source", snatIP}}
}
