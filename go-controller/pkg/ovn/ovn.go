package ovn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	goovn "github.com/ebay/go-ovn"
	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	hocontroller "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	svccontroller "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/services"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/unidling"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	lsm "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/subnetallocator"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"

	utilnet "k8s.io/utils/net"

	kapi "k8s.io/api/core/v1"
	kapisnetworking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	ref "k8s.io/client-go/tools/reference"
	"k8s.io/klog/v2"
)

const (
	clusterPortGroupName             string        = "clusterPortGroup"
	clusterRtrPortGroupName          string        = "clusterRtrPortGroup"
	egressFirewallDNSDefaultDuration time.Duration = 30 * time.Minute
)

// ACL logging severity levels
type ACLLoggingLevels struct {
	Allow string `json:"allow,omitempty"`
	Deny  string `json:"deny,omitempty"`
}

// namespaceInfo contains information related to a Namespace. Use oc.getNamespaceLocked()
// or oc.waitForNamespaceLocked() to get a locked namespaceInfo for a Namespace, and call
// nsInfo.Unlock() on it when you are done with it. (No code outside of the code that
// manages the oc.namespaces map is ever allowed to hold an unlocked namespaceInfo.)
type namespaceInfo struct {
	sync.RWMutex

	// addressSet is an address set object that holds the IP addresses
	// of all pods in the namespace.
	addressSet addressset.AddressSet

	// map from NetworkPolicy name to networkPolicy. You must hold the
	// namespaceInfo's mutex to add/delete/lookup policies, but must hold the
	// networkPolicy's mutex (and not necessarily the namespaceInfo's) to work with
	// the policy itself.
	networkPolicies map[string]*networkPolicy

	hybridOverlayExternalGW net.IP
	hybridOverlayVTEP       net.IP

	// routingExternalGWs is a slice of net.IP containing the values parsed from
	// annotation k8s.ovn.org/routing-external-gws
	routingExternalGWs gatewayInfo
	// podExternalRoutes is a cache keeping the LR routes added to the GRs when
	// the k8s.ovn.org/routing-external-gws annotation is used. The first map key
	// is the podIP, the second the GW and the third the GR
	podExternalRoutes map[string]map[string]string

	// routingExternalPodGWs contains a map of all pods serving as exgws as well as their
	// exgw IPs
	routingExternalPodGWs map[string]gatewayInfo

	// The UUID of the namespace-wide port group that contains all the pods in the namespace.
	portGroupUUID string

	multicastEnabled bool

	// If not empty, then it has to be set to a logging a severity level, e.g. "notice", "alert", etc
	aclLogging ACLLoggingLevels

	// Per-namespace port group default deny UUIDs
	portGroupIngressDenyUUID string // Port group UUID for ingress deny rule
	portGroupIngressDenyName string // Port group Name for ingress deny rule
	portGroupEgressDenyUUID  string // Port group UUID for egress deny rule
	portGroupEgressDenyName  string // Port group Name for egress deny rule
}

// Controller structure is the object which holds the controls for starting
// and reacting upon the watched resources (e.g. pods, endpoints)
type Controller struct {
	client                clientset.Interface
	kube                  kube.Interface
	watchFactory          *factory.WatchFactory
	egressFirewallHandler *factory.Handler
	stopChan              <-chan struct{}

	// FIXME DUAL-STACK -  Make IP Allocators more dual-stack friendly
	masterSubnetAllocator     *subnetallocator.SubnetAllocator
	nodeLocalNatIPv4Allocator *ipallocator.Range
	nodeLocalNatIPv6Allocator *ipallocator.Range

	hoMaster *hocontroller.MasterController

	SCTPSupport bool

	// For TCP, UDP, and SCTP type traffic, cache OVN load-balancers used for the
	// cluster's east-west traffic.
	loadbalancerClusterCache map[kapi.Protocol]string

	// A cache of all logical switches seen by the watcher and their subnets
	lsManager *lsm.LogicalSwitchManager

	// A cache of all logical ports known to the controller
	logicalPortCache *portCache

	// Info about known namespaces. You must use oc.getNamespaceLocked() or
	// oc.waitForNamespaceLocked() to read this map, and oc.createNamespaceLocked()
	// or oc.deleteNamespaceLocked() to modify it. namespacesMutex is only held
	// from inside those functions.
	namespaces      map[string]*namespaceInfo
	namespacesMutex sync.Mutex

	// egressFirewalls is a map of namespaces and the egressFirewall attached to it
	egressFirewalls sync.Map

	// An address set factory that creates address sets
	addressSetFactory addressset.AddressSetFactory

	// Port group for all cluster logical switch ports
	clusterPortGroupUUID string

	// Port group for all node logical switch ports connected to the cluster
	// logical router
	clusterRtrPortGroupUUID string

	// For each logical port, the number of network policies that want
	// to add a ingress deny rule.
	lspIngressDenyCache map[string]int

	// For each logical port, the number of network policies that want
	// to add a egress deny rule.
	lspEgressDenyCache map[string]int

	// A mutex for lspIngressDenyCache and lspEgressDenyCache
	lspMutex *sync.Mutex

	// Supports multicast?
	multicastSupport bool

	// Controller used for programming OVN for egress IP
	eIPC egressIPController

	// Controller used to handle services
	svcController *svccontroller.Controller

	egressFirewallDNS *EgressDNS

	// Is ACL logging enabled while configuring meters?
	aclLoggingEnabled bool

	joinSwIPManager *lsm.JoinSwitchIPManager

	// event recorder used to post events to k8s
	recorder record.EventRecorder

	// go-ovn northbound client interface
	ovnNBClient goovn.Client

	// go-ovn southbound client interface
	ovnSBClient goovn.Client

	// libovsdb northbound client interface
	nbClient libovsdbclient.Client

	// libovsdb southbound client interface
	sbClient libovsdbclient.Client

	// v4HostSubnetsUsed keeps track of number of v4 subnets currently assigned to nodes
	v4HostSubnetsUsed float64

	// v6HostSubnetsUsed keeps track of number of v6 subnets currently assigned to nodes
	v6HostSubnetsUsed float64

	// Map of pods that need to be retried, and the timestamp of when they last failed
	retryPods     map[types.UID]*retryEntry
	retryPodsLock sync.Mutex

	// channel to indicate we need to retry pods immediately
	retryPodsChan chan struct{}
}

type retryEntry struct {
	pod       *kapi.Pod
	timeStamp time.Time
	// whether to include this pod in retry iterations
	ignore bool
}

const (
	// TCP is the constant string for the string "TCP"
	TCP = "TCP"

	// UDP is the constant string for the string "UDP"
	UDP = "UDP"

	// SCTP is the constant string for the string "SCTP"
	SCTP = "SCTP"
)

func GetIPFullMask(ip string) string {
	const (
		// IPv4FullMask is the maximum prefix mask for an IPv4 address
		IPv4FullMask = "/32"
		// IPv6FullMask is the maxiumum prefix mask for an IPv6 address
		IPv6FullMask = "/128"
	)

	if utilnet.IsIPv6(net.ParseIP(ip)) {
		return IPv6FullMask
	}
	return IPv4FullMask
}

// NewOvnController creates a new OVN controller for creating logical network
// infrastructure and policy
func NewOvnController(ovnClient *util.OVNClientset, wf *factory.WatchFactory, stopChan <-chan struct{}, addressSetFactory addressset.AddressSetFactory,
	ovnNBClient goovn.Client, ovnSBClient goovn.Client, libovsdbOvnNBClient libovsdbclient.Client, libovsdbOvnSBClient libovsdbclient.Client,
	recorder record.EventRecorder) *Controller {
	if addressSetFactory == nil {
		addressSetFactory = addressset.NewOvnAddressSetFactory(ovnNBClient)
	}
	return &Controller{
		client: ovnClient.KubeClient,
		kube: &kube.Kube{
			KClient:              ovnClient.KubeClient,
			EIPClient:            ovnClient.EgressIPClient,
			EgressFirewallClient: ovnClient.EgressFirewallClient,
		},
		watchFactory:              wf,
		stopChan:                  stopChan,
		masterSubnetAllocator:     subnetallocator.NewSubnetAllocator(),
		nodeLocalNatIPv4Allocator: &ipallocator.Range{},
		nodeLocalNatIPv6Allocator: &ipallocator.Range{},
		lsManager:                 lsm.NewLogicalSwitchManager(),
		logicalPortCache:          newPortCache(stopChan),
		namespaces:                make(map[string]*namespaceInfo),
		namespacesMutex:           sync.Mutex{},
		addressSetFactory:         addressSetFactory,
		lspIngressDenyCache:       make(map[string]int),
		lspEgressDenyCache:        make(map[string]int),
		lspMutex:                  &sync.Mutex{},
		eIPC: egressIPController{
			assignmentRetryMutex:  &sync.Mutex{},
			assignmentRetry:       make(map[string]bool),
			namespaceHandlerMutex: &sync.Mutex{},
			namespaceHandlerCache: make(map[string]factory.Handler),
			podHandlerMutex:       &sync.Mutex{},
			podHandlerCache:       make(map[string]factory.Handler),
			allocatorMutex:        &sync.Mutex{},
			allocator:             make(map[string]*egressNode),
			nbClient:              libovsdbOvnNBClient,
		},
		loadbalancerClusterCache: make(map[kapi.Protocol]string),
		multicastSupport:         config.EnableMulticast,
		aclLoggingEnabled:        true,
		joinSwIPManager:          nil,
		retryPods:                make(map[types.UID]*retryEntry),
		retryPodsChan:            make(chan struct{}, 1),
		recorder:                 recorder,
		ovnNBClient:              ovnNBClient,
		ovnSBClient:              ovnSBClient,
		nbClient:                 libovsdbOvnNBClient,
		sbClient:                 libovsdbOvnSBClient,
		svcController:            newServiceController(ovnClient.KubeClient, libovsdbOvnNBClient, stopChan),
	}
}

// Run starts the actual watching.
func (oc *Controller) Run(wg *sync.WaitGroup, nodeName string) error {
	oc.syncPeriodic()
	klog.Infof("Starting all the Watchers...")
	start := time.Now()

	// Sync external gateway routes. External gateway may be set in namespaces
	// or via pods. So execute an individual sync method at startup
	oc.cleanExGwECMPRoutes()

	// WatchNamespaces() should be started first because it has no other
	// dependencies, and WatchNodes() depends on it
	oc.WatchNamespaces()

	// WatchNodes must be started next because it creates the node switch
	// which most other watches depend on.
	// https://github.com/ovn-org/ovn-kubernetes/pull/859
	oc.WatchNodes()

	// Services should be started after nodes to prevent LB churn
	if err := oc.StartServiceController(wg, true); err != nil {
		return err
	}

	oc.WatchPods()

	// WatchNetworkPolicy depends on WatchPods and WatchNamespaces
	oc.WatchNetworkPolicy()

	if config.OVNKubernetesFeature.EnableEgressIP {
		oc.WatchEgressNodes()
		oc.WatchEgressIP()
	}

	if config.OVNKubernetesFeature.EnableEgressFirewall {
		var err error
		oc.egressFirewallDNS, err = NewEgressDNS(oc.addressSetFactory, oc.stopChan)
		if err != nil {
			return err
		}
		oc.egressFirewallDNS.Run(egressFirewallDNSDefaultDuration)
		oc.egressFirewallHandler = oc.WatchEgressFirewall()

	}

	klog.Infof("Completing all the Watchers took %v", time.Since(start))

	if config.Kubernetes.OVNEmptyLbEvents {
		klog.Infof("Starting unidling controller")
		unidlingController := unidling.NewController(
			oc.recorder,
			oc.watchFactory.ServiceInformer(),
			oc.sbClient,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			unidlingController.Run(oc.stopChan)
		}()
	}

	if oc.hoMaster != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.hoMaster.Run(oc.stopChan)
		}()
	}

	// Final step to cleanup after resource handlers have synced
	err := oc.ovnTopologyCleanup()
	if err != nil {
		klog.Errorf("Failed to cleanup OVN topology to version %d: %v", ovntypes.OvnCurrentTopologyVersion, err)
		return err
	}

	// Master is fully running and resource handlers have synced, update Topology version in OVN
	stdout, stderr, err := util.RunOVNNbctl("set", "logical_router", ovntypes.OVNClusterRouter,
		fmt.Sprintf("external_ids:k8s-ovn-topo-version=%d", ovntypes.OvnCurrentTopologyVersion))
	if err != nil {
		klog.Errorf("Failed to set topology version in OVN, "+
			"stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	// Update topology version on node
	node, err := oc.kube.GetNode(nodeName)
	if err != nil {
		return fmt.Errorf("unable to get node: %s", nodeName)
	}
	err = oc.kube.SetAnnotationsOnNode(node, map[string]interface{}{ovntypes.OvnK8sTopoAnno: strconv.Itoa(ovntypes.OvnCurrentTopologyVersion)})
	if err != nil {
		return fmt.Errorf("failed to set topology annotation for node %s", node.Name)
	}

	return nil
}

func (oc *Controller) ovnTopologyCleanup() error {
	ver, err := util.DetermineOVNTopoVersionFromOVN()
	if err != nil {
		return err
	}

	// Cleanup address sets in non dual stack formats in all versions known to possibly exist.
	if ver <= ovntypes.OvnPortBindingTopoVersion {
		err = addressset.NonDualStackAddressSetCleanup(oc.ovnNBClient)
	}
	return err
}

// syncPeriodic adds a goroutine that periodically does some work
// right now there is only one ticker registered
// for syncNodesPeriodic which deletes chassis records from the sbdb
// every 5 minutes
func (oc *Controller) syncPeriodic() {
	go func() {
		nodeSyncTicker := time.NewTicker(5 * time.Minute)
		for {
			select {
			case <-nodeSyncTicker.C:
				oc.syncNodesPeriodic()
			case <-oc.stopChan:
				return
			}
		}
	}()
}

func (oc *Controller) recordPodEvent(addErr error, pod *kapi.Pod) {
	podRef, err := ref.GetReference(scheme.Scheme, pod)
	if err != nil {
		klog.Errorf("Couldn't get a reference to pod %s/%s to post an event: '%v'",
			pod.Namespace, pod.Name, err)
	} else {
		klog.V(5).Infof("Posting a %s event for Pod %s/%s", kapi.EventTypeWarning, pod.Namespace, pod.Name)
		oc.recorder.Eventf(podRef, kapi.EventTypeWarning, "ErrorAddingLogicalPort", addErr.Error())
	}
}

// iterateRetryPods checks if any outstanding pods have been waiting for 60 seconds of last known failure
// then tries to re-add them if so
// updateAll forces all pods to be attempted to be retried regardless of the 1 minute delay
func (oc *Controller) iterateRetryPods(updateAll bool) {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	now := time.Now()
	for uid, podEntry := range oc.retryPods {
		if podEntry.ignore {
			continue
		}

		pod := podEntry.pod
		podDesc := fmt.Sprintf("[%s/%s/%s]", pod.UID, pod.Namespace, pod.Name)
		// it could be that the Pod got deleted, but Pod's DeleteFunc has not been called yet, so don't retry
		kPod, err := oc.watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil && errors.IsNotFound(err) {
			klog.Infof("%s pod not found in the informers cache, not going to retry pod setup", podDesc)
			delete(oc.retryPods, uid)
			continue
		}

		if !util.PodScheduled(kPod) {
			klog.V(5).Infof("retry: %s not scheduled", podDesc)
			continue
		}
		podTimer := podEntry.timeStamp.Add(time.Minute)
		if updateAll || now.After(podTimer) {
			klog.Infof("%s retry pod setup", podDesc)

			if oc.ensurePod(nil, kPod, true) {
				klog.Infof("%s pod setup successful", podDesc)
				delete(oc.retryPods, uid)
			} else {
				klog.Infof("%s setup retry failed; will try again later", podDesc)
				oc.retryPods[uid] = &retryEntry{pod, time.Now(), false}
			}
		} else {
			klog.V(5).Infof("%s retry pod not after timer yet, time: %s", podDesc, podTimer)
		}
	}
}

// checkAndDeleteRetryPod deletes a specific entry from the map, if it existed, returns true
func (oc *Controller) checkAndDeleteRetryPod(uid types.UID) bool {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	if _, ok := oc.retryPods[uid]; ok {
		delete(oc.retryPods, uid)
		return true
	}
	return false
}

// checkAndSkipRetryPod sets a specific entry from the map to be ignored for subsequent retries
// if it existed, returns true
func (oc *Controller) checkAndSkipRetryPod(uid types.UID) bool {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	if entry, ok := oc.retryPods[uid]; ok {
		entry.ignore = true
		return true
	}
	return false
}

// unSkipRetryPod ensures a pod is no longer ignored for retry loop
func (oc *Controller) unSkipRetryPod(pod *kapi.Pod) {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	if entry, ok := oc.retryPods[pod.UID]; ok {
		entry.ignore = false
	}
}

// initRetryPod tracks a failed pod to potentially retry later
// initially it is marked as skipped for retry loop (ignore = true)
func (oc *Controller) initRetryPod(pod *kapi.Pod) {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	if entry, ok := oc.retryPods[pod.UID]; ok {
		entry.timeStamp = time.Now()
	} else {
		oc.retryPods[pod.UID] = &retryEntry{pod, time.Now(), true}
	}
}

// addRetryPods adds multiple pods to retry later
func (oc *Controller) addRetryPods(pods []kapi.Pod) {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	for _, pod := range pods {
		if entry, ok := oc.retryPods[pod.UID]; ok {
			entry.timeStamp = time.Now()
		} else {
			oc.retryPods[pod.UID] = &retryEntry{&pod, time.Now(), false}
		}
	}
}

func exGatewayAnnotationsChanged(oldPod, newPod *kapi.Pod) bool {
	return oldPod.Annotations[routingNamespaceAnnotation] != newPod.Annotations[routingNamespaceAnnotation] ||
		oldPod.Annotations[routingNetworkAnnotation] != newPod.Annotations[routingNetworkAnnotation] ||
		oldPod.Annotations[bfdAnnotation] != newPod.Annotations[bfdAnnotation]
}

func networkStatusAnnotationsChanged(oldPod, newPod *kapi.Pod) bool {
	return oldPod.Annotations[nettypes.NetworkStatusAnnot] != newPod.Annotations[nettypes.NetworkStatusAnnot]
}

// ensurePod tries to set up a pod. It returns success or failure; failure
// indicates the pod should be retried later.
func (oc *Controller) ensurePod(oldPod, pod *kapi.Pod, addPort bool) bool {
	// Try unscheduled pods later
	if !util.PodScheduled(pod) {
		return false
	}

	if oldPod != nil && (exGatewayAnnotationsChanged(oldPod, pod) || networkStatusAnnotationsChanged(oldPod, pod)) {
		// No matter if a pod is ovn networked, or host networked, we still need to check for exgw
		// annotations. If the pod is ovn networked and is in update reschedule, addLogicalPort will take
		// care of updating the exgw updates
		oc.deletePodExternalGW(oldPod)
	}

	if util.PodWantsNetwork(pod) && addPort {
		if err := oc.addLogicalPort(pod); err != nil {
			klog.Errorf(err.Error())
			oc.recordPodEvent(err, pod)
			return false
		}
	} else {
		// either pod is host-networked or its an update for a normal pod (addPort=false case)
		if oldPod == nil || exGatewayAnnotationsChanged(oldPod, pod) || networkStatusAnnotationsChanged(oldPod, pod) {
			if err := oc.addPodExternalGW(pod); err != nil {
				klog.Errorf(err.Error())
				oc.recordPodEvent(err, pod)
				return false
			}
		}
	}

	return true
}

func (oc *Controller) requestRetryPods() {
	select {
	case oc.retryPodsChan <- struct{}{}:
		klog.V(5).Infof("Iterate retry pods requested")
	default:
		klog.V(5).Infof("Iterate retry pods already requested")
	}
}

// WatchPods starts the watching of Pod resource and calls back the appropriate handler logic
func (oc *Controller) WatchPods() {
	go func() {
		// track the retryPods map and every 30 seconds check if any pods need to be retried
		for {
			select {
			case <-time.After(30 * time.Second):
				oc.iterateRetryPods(false)
			case <-oc.retryPodsChan:
				oc.iterateRetryPods(true)
			case <-oc.stopChan:
				return
			}
		}
	}()

	start := time.Now()
	oc.watchFactory.AddPodHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			oc.initRetryPod(pod)
			if !oc.ensurePod(nil, pod, true) {
				oc.unSkipRetryPod(pod)
				return
			}
			oc.checkAndDeleteRetryPod(pod.UID)
		},
		UpdateFunc: func(old, newer interface{}) {
			oldPod := old.(*kapi.Pod)
			pod := newer.(*kapi.Pod)
			// there may be a situation where this update event is not the latest
			// and we rely on annotations to determine the pod mac/ifaddr
			// this would create a situation where
			// 1. addLogicalPort is executing with an older pod annotation, skips setting a new annotation
			// 2. creates OVN logical port with old pod annotation value
			// 3. CNI flows check fails and pod annotation does not match what is in OVN
			// Therefore we need to get the latest version of this pod to attempt to addLogicalPort with
			podName := pod.Name
			podNs := pod.Namespace
			pod, err := oc.watchFactory.GetPod(podNs, podName)
			if err != nil {
				klog.Warningf("Unable to get pod %s/%s for pod update, most likely it was already deleted",
					podNs, podName)
				return
			}
			if !oc.ensurePod(oldPod, pod, oc.checkAndSkipRetryPod(pod.UID)) {
				// unskip failed pod for next retry iteration
				oc.unSkipRetryPod(pod)
				return
			}
			oc.checkAndDeleteRetryPod(pod.UID)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			oc.checkAndDeleteRetryPod(pod.UID)
			if !util.PodWantsNetwork(pod) {
				oc.deletePodExternalGW(pod)
				return
			}
			// deleteLogicalPort will take care of removing exgw for ovn networked pods
			oc.deleteLogicalPort(pod)
		},
	}, oc.syncPods)
	klog.Infof("Bootstrapping existing pods and cleaning stale pods took %v", time.Since(start))
}

// WatchNetworkPolicy starts the watching of network policy resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNetworkPolicy() {
	start := time.Now()
	oc.watchFactory.AddPolicyHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			oc.addNetworkPolicy(policy)
		},
		UpdateFunc: func(old, newer interface{}) {
			oldPolicy := old.(*kapisnetworking.NetworkPolicy)
			newPolicy := newer.(*kapisnetworking.NetworkPolicy)
			if !reflect.DeepEqual(oldPolicy, newPolicy) {
				oc.deleteNetworkPolicy(oldPolicy)
				oc.addNetworkPolicy(newPolicy)
			}
		},
		DeleteFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			oc.deleteNetworkPolicy(policy)
		},
	}, oc.syncNetworkPolicies)
	klog.Infof("Bootstrapping existing policies and cleaning stale policies took %v", time.Since(start))
}

// WatchEgressFirewall starts the watching of egressfirewall resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchEgressFirewall() *factory.Handler {
	return oc.watchFactory.AddEgressFirewallHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			egressFirewall := obj.(*egressfirewall.EgressFirewall).DeepCopy()
			txn := util.NewNBTxn()
			addErrors := oc.addEgressFirewall(egressFirewall, txn)
			if addErrors != nil {
				klog.Error(addErrors)
				egressFirewall.Status.Status = egressFirewallAddError
			} else {
				_, stderr, err := txn.Commit()
				if err != nil {
					klog.Errorf("Failed to commit db changes for egressFirewall in namespace %s stderr: %q, err: %+v", egressFirewall.Namespace, stderr, err)
					egressFirewall.Status.Status = egressFirewallAddError
				} else {
					egressFirewall.Status.Status = egressFirewallAppliedCorrectly
				}
			}

			err := oc.updateEgressFirewallWithRetry(egressFirewall)
			if err != nil {
				klog.Error(err)
			}
		},
		UpdateFunc: func(old, newer interface{}) {
			newEgressFirewall := newer.(*egressfirewall.EgressFirewall).DeepCopy()
			oldEgressFirewall := old.(*egressfirewall.EgressFirewall)
			if !reflect.DeepEqual(oldEgressFirewall.Spec, newEgressFirewall.Spec) {
				txn := util.NewNBTxn()
				errList := oc.updateEgressFirewall(oldEgressFirewall, newEgressFirewall, txn)
				if errList != nil {
					newEgressFirewall.Status.Status = egressFirewallUpdateError
					klog.Error(errList)
				} else {
					_, stderr, err := txn.Commit()
					if err != nil {
						klog.Errorf("Failed to commit db changes for egressFirewall in namespace %s stderr: %q, err: %+v", newEgressFirewall.Namespace, stderr, err)
						newEgressFirewall.Status.Status = egressFirewallUpdateError

					} else {
						newEgressFirewall.Status.Status = egressFirewallAppliedCorrectly
					}
				}
				err := oc.updateEgressFirewallWithRetry(newEgressFirewall)
				if err != nil {
					klog.Error(err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			egressFirewall := obj.(*egressfirewall.EgressFirewall)
			txn := util.NewNBTxn()
			deleteErrors := oc.deleteEgressFirewall(egressFirewall, txn)
			if deleteErrors != nil {
				klog.Error(deleteErrors)
				return
			}
			stdout, stderr, err := txn.Commit()
			if err != nil {
				klog.Errorf("Failed to commit db changes for egressFirewall in namespace %s stdout: %q, stderr: %q, err: %+v", egressFirewall.Namespace, stdout, stderr, err)
			}
		},
	}, oc.syncEgressFirewall)
}

// WatchEgressNodes starts the watching of egress assignable nodes and calls
// back the appropriate handler logic.
func (oc *Controller) WatchEgressNodes() {
	nodeEgressLabel := util.GetNodeEgressLabel()
	oc.watchFactory.AddNodeHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			if err := oc.addNodeForEgress(node); err != nil {
				klog.Error(err)
			}
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
				if err := oc.addEgressNode(node); err != nil {
					klog.Error(err)
				}
			}
		},
		UpdateFunc: func(old, new interface{}) {
			oldNode := old.(*kapi.Node)
			newNode := new.(*kapi.Node)
			if err := oc.initEgressIPAllocator(newNode); err != nil {
				klog.Error(err)
			}
			oldLabels := oldNode.GetLabels()
			newLabels := newNode.GetLabels()
			_, oldHadEgressLabel := oldLabels[nodeEgressLabel]
			_, newHasEgressLabel := newLabels[nodeEgressLabel]
			if !oldHadEgressLabel && !newHasEgressLabel {
				return
			}
			if oldHadEgressLabel && !newHasEgressLabel {
				klog.Infof("Node: %s has been un-labelled, deleting it from egress assignment", newNode.Name)
				oc.setNodeEgressAssignable(oldNode.Name, false)
				if err := oc.deleteEgressNode(oldNode); err != nil {
					klog.Error(err)
				}
				return
			}
			isOldReady := oc.isEgressNodeReady(oldNode)
			isNewReady := oc.isEgressNodeReady(newNode)
			isNewReachable := oc.isEgressNodeReachable(newNode)
			oc.setNodeEgressReady(newNode.Name, isNewReady)
			oc.setNodeEgressReachable(newNode.Name, isNewReachable)
			if !oldHadEgressLabel && newHasEgressLabel {
				klog.Infof("Node: %s has been labelled, adding it for egress assignment", newNode.Name)
				oc.setNodeEgressAssignable(newNode.Name, true)
				if isNewReady && isNewReachable {
					if err := oc.addEgressNode(newNode); err != nil {
						klog.Error(err)
					}
				} else {
					klog.Warningf("Node: %s has been labelled, but node is not ready and reachable, cannot use it for egress assignment", newNode.Name)
				}
				return
			}
			if isOldReady == isNewReady {
				return
			}
			if !isNewReady {
				klog.Warningf("Node: %s is not ready, deleting it from egress assignment", newNode.Name)
				if err := oc.deleteEgressNode(newNode); err != nil {
					klog.Error(err)
				}
			} else if isNewReady && isNewReachable {
				klog.Infof("Node: %s is ready and reachable, adding it for egress assignment", newNode.Name)
				if err := oc.addEgressNode(newNode); err != nil {
					klog.Error(err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			if err := oc.deleteNodeForEgress(node); err != nil {
				klog.Error(err)
			}
			nodeLabels := node.GetLabels()
			if _, hasEgressLabel := nodeLabels[nodeEgressLabel]; hasEgressLabel {
				if err := oc.deleteEgressNode(node); err != nil {
					klog.Error(err)
				}
			}
		},
	}, oc.initClusterEgressPolicies)
}

// WatchEgressIP starts the watching of egressip resource and calls
// back the appropriate handler logic.
func (oc *Controller) WatchEgressIP() {
	oc.watchFactory.AddEgressIPHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			eIP := obj.(*egressipv1.EgressIP).DeepCopy()
			oc.eIPC.assignmentRetryMutex.Lock()
			defer oc.eIPC.assignmentRetryMutex.Unlock()
			if err := oc.addEgressIP(eIP); err != nil {
				klog.Error(err)
			}
			if err := oc.updateEgressIPWithRetry(eIP); err != nil {
				klog.Error(err)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			oldEIP := old.(*egressipv1.EgressIP)
			newEIP := new.(*egressipv1.EgressIP).DeepCopy()
			if !reflect.DeepEqual(oldEIP.Spec, newEIP.Spec) {
				if err := oc.deleteEgressIP(oldEIP); err != nil {
					klog.Error(err)
				}
				newEIP.Status = egressipv1.EgressIPStatus{
					Items: []egressipv1.EgressIPStatusItem{},
				}
				oc.eIPC.assignmentRetryMutex.Lock()
				defer oc.eIPC.assignmentRetryMutex.Unlock()
				if err := oc.addEgressIP(newEIP); err != nil {
					klog.Error(err)
				}
				if err := oc.updateEgressIPWithRetry(newEIP); err != nil {
					klog.Error(err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			eIP := obj.(*egressipv1.EgressIP)
			if err := oc.deleteEgressIP(eIP); err != nil {
				klog.Error(err)
			}
		},
	}, oc.syncEgressIPs)
}

// WatchNamespaces starts the watching of namespace resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNamespaces() {
	start := time.Now()
	oc.watchFactory.AddNamespaceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns := obj.(*kapi.Namespace)
			oc.AddNamespace(ns)
		},
		UpdateFunc: func(old, newer interface{}) {
			oldNs, newNs := old.(*kapi.Namespace), newer.(*kapi.Namespace)
			oc.updateNamespace(oldNs, newNs)
		},
		DeleteFunc: func(obj interface{}) {
			ns := obj.(*kapi.Namespace)
			oc.deleteNamespace(ns)
		},
	}, oc.syncNamespaces)
	klog.Infof("Bootstrapping existing namespaces and cleaning stale namespaces took %v", time.Since(start))
}

// syncNodeGateway ensures a node's gateway router is configured
func (oc *Controller) syncNodeGateway(node *kapi.Node, hostSubnets []*net.IPNet) error {
	l3GatewayConfig, err := util.ParseNodeL3GatewayAnnotation(node)
	if err != nil {
		return err
	}

	if hostSubnets == nil {
		hostSubnets, _ = util.ParseNodeHostSubnetAnnotation(node)
	}

	if l3GatewayConfig.Mode == config.GatewayModeDisabled {
		if err := gatewayCleanup(node.Name); err != nil {
			return fmt.Errorf("error cleaning up gateway for node %s: %v", node.Name, err)
		}
		if err := oc.joinSwIPManager.ReleaseJoinLRPIPs(node.Name); err != nil {
			return err
		}
	} else if hostSubnets != nil {
		var hostAddrs sets.String
		if config.Gateway.Mode == config.GatewayModeShared {
			hostAddrs, err = util.ParseNodeHostAddresses(node)
			if err != nil {
				return fmt.Errorf("failed to get host addresses for node: %s: %v", node.Name, err)
			}
		}
		if err := oc.syncGatewayLogicalNetwork(node, l3GatewayConfig, hostSubnets, hostAddrs); err != nil {
			return fmt.Errorf("error creating gateway for node %s: %v", node.Name, err)
		}
	}
	return nil
}

// WatchNodes starts the watching of node resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNodes() {
	var gatewaysFailed sync.Map
	var mgmtPortFailed sync.Map
	var addNodeFailed sync.Map
	var nodeClusterRouterPortFailed sync.Map

	start := time.Now()
	oc.watchFactory.AddNodeHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			if noHostSubnet := noHostSubnet(node); noHostSubnet {
				err := oc.lsManager.AddNoHostSubnetNode(node.Name)
				if err != nil {
					klog.Errorf("Error creating logical switch cache for node %s: %v", node.Name, err)
				}
				return
			}

			klog.V(5).Infof("Added event for Node %q", node.Name)
			hostSubnets, err := oc.addNode(node)
			if err != nil {
				klog.Errorf("NodeAdd: error creating subnet for node %s: %v", node.Name, err)
				addNodeFailed.Store(node.Name, true)
				mgmtPortFailed.Store(node.Name, true)
				gatewaysFailed.Store(node.Name, true)
				return
			}

			if err = oc.syncNodeClusterRouterPort(node, hostSubnets); err != nil {
				if !util.IsAnnotationNotSetError(err) {
					klog.Warningf(err.Error())
				}
				nodeClusterRouterPortFailed.Store(node.Name, true)
			}

			err = oc.syncNodeManagementPort(node, hostSubnets)
			if err != nil {
				if !util.IsAnnotationNotSetError(err) {
					klog.Warningf("Error creating management port for node %s: %v", node.Name, err)
				}
				mgmtPortFailed.Store(node.Name, true)
			}

			if err := oc.syncNodeGateway(node, hostSubnets); err != nil {
				if !util.IsAnnotationNotSetError(err) {
					klog.Warningf(err.Error())
				}
				gatewaysFailed.Store(node.Name, true)
			}

			// ensure pods that already exist on this node have their logical ports created
			options := metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("spec.nodeName", node.Name).String()}
			pods, err := oc.client.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), options)
			if err != nil {
				klog.Errorf("Unable to list existing pods on node: %s, existing pods on this node may not function")
			} else {
				oc.addRetryPods(pods.Items)
				oc.requestRetryPods()
			}

		},
		UpdateFunc: func(old, new interface{}) {
			oldNode := old.(*kapi.Node)
			node := new.(*kapi.Node)

			shouldUpdate, err := shouldUpdate(node, oldNode)
			if err != nil {
				klog.Errorf(err.Error())
			}
			if !shouldUpdate {
				// the hostsubnet is not assigned by ovn-kubernetes
				return
			}

			var hostSubnets []*net.IPNet
			_, failed := addNodeFailed.Load(node.Name)
			if failed {
				hostSubnets, err = oc.addNode(node)
				if err != nil {
					klog.Errorf("NodeUpdate: error creating subnet for node %s: %v", node.Name, err)
					return
				}
				addNodeFailed.Delete(node.Name)
			}

			_, failed = nodeClusterRouterPortFailed.Load(node.Name)
			if failed || nodeChassisChanged(oldNode, node) || nodeSubnetChanged(oldNode, node) {
				if err = oc.syncNodeClusterRouterPort(node, nil); err != nil {
					if !util.IsAnnotationNotSetError(err) {
						klog.Warningf(err.Error())
					}
					nodeClusterRouterPortFailed.Store(node.Name, true)
				} else {
					nodeClusterRouterPortFailed.Delete(node.Name)
				}
			}

			_, failed = mgmtPortFailed.Load(node.Name)
			if failed || macAddressChanged(oldNode, node) || nodeSubnetChanged(oldNode, node) {
				err := oc.syncNodeManagementPort(node, hostSubnets)
				if err != nil {
					if !util.IsAnnotationNotSetError(err) {
						klog.Errorf("Error updating management port for node %s: %v", node.Name, err)
					}
					mgmtPortFailed.Store(node.Name, true)
				} else {
					mgmtPortFailed.Delete(node.Name)
				}
			}

			if nodeChassisChanged(oldNode, node) {
				// delete stale chassis in SBDB if any
				oc.deleteStaleNodeChassis(node)
			}

			oc.clearInitialNodeNetworkUnavailableCondition(oldNode, node)

			_, failed = gatewaysFailed.Load(node.Name)
			if failed || gatewayChanged(oldNode, node) || nodeSubnetChanged(oldNode, node) || hostAddressesChanged(oldNode, node) {
				err := oc.syncNodeGateway(node, nil)
				if err != nil {
					if !util.IsAnnotationNotSetError(err) {
						klog.Errorf(err.Error())
					}
					gatewaysFailed.Store(node.Name, true)
				} else {
					gatewaysFailed.Delete(node.Name)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			klog.V(5).Infof("Delete event for Node %q. Removing the node from "+
				"various caches", node.Name)

			nodeSubnets, _ := util.ParseNodeHostSubnetAnnotation(node)
			dnatSnatIPs, _ := util.ParseNodeLocalNatIPAnnotation(node)
			oc.deleteNode(node.Name, nodeSubnets, dnatSnatIPs)
			oc.lsManager.DeleteNode(node.Name)
			addNodeFailed.Delete(node.Name)
			mgmtPortFailed.Delete(node.Name)
			gatewaysFailed.Delete(node.Name)
			nodeClusterRouterPortFailed.Delete(node.Name)
		},
	}, oc.syncNodes)
	klog.Infof("Bootstrapping existing nodes and cleaning stale nodes took %v", time.Since(start))
}

// GetNetworkPolicyACLLogging retrieves ACL deny policy logging setting for the Namespace
func (oc *Controller) GetNetworkPolicyACLLogging(ns string) *ACLLoggingLevels {
	nsInfo, nsUnlock := oc.getNamespaceLocked(ns, true)
	if nsInfo == nil {
		return &ACLLoggingLevels{
			Allow: "",
			Deny:  "",
		}
	}
	defer nsUnlock()
	return &nsInfo.aclLogging
}

// Verify if controller can support ACL logging and validate annotation
func (oc *Controller) aclLoggingCanEnable(annotation string, nsInfo *namespaceInfo) bool {
	if !oc.aclLoggingEnabled || annotation == "" {
		nsInfo.aclLogging.Deny = ""
		nsInfo.aclLogging.Allow = ""
		return false
	}
	var aclLevels ACLLoggingLevels
	err := json.Unmarshal([]byte(annotation), &aclLevels)
	if err != nil {
		return false
	}
	okCnt := 0
	for _, s := range []string{"alert", "warning", "notice", "info", "debug"} {
		if aclLevels.Deny != "" && s == aclLevels.Deny {
			nsInfo.aclLogging.Deny = aclLevels.Deny
			okCnt++
		}
		if aclLevels.Allow != "" && s == aclLevels.Allow {
			nsInfo.aclLogging.Allow = aclLevels.Allow
			okCnt++
		}
	}
	return okCnt > 0
}

// gatewayChanged() compares old annotations to new and returns true if something has changed.
func gatewayChanged(oldNode, newNode *kapi.Node) bool {
	oldL3GatewayConfig, _ := util.ParseNodeL3GatewayAnnotation(oldNode)
	l3GatewayConfig, _ := util.ParseNodeL3GatewayAnnotation(newNode)
	return !reflect.DeepEqual(oldL3GatewayConfig, l3GatewayConfig)
}

// hostAddressesChanged compares old annotations to new and returns true if the something has changed.
func hostAddressesChanged(oldNode, newNode *kapi.Node) bool {
	oldAddrs, _ := util.ParseNodeHostAddresses(oldNode)
	Addrs, _ := util.ParseNodeHostAddresses(newNode)
	return !oldAddrs.Equal(Addrs)
}

// macAddressChanged() compares old annotations to new and returns true if something has changed.
func macAddressChanged(oldNode, node *kapi.Node) bool {
	oldMacAddress, _ := util.ParseNodeManagementPortMACAddress(oldNode)
	macAddress, _ := util.ParseNodeManagementPortMACAddress(node)
	return !bytes.Equal(oldMacAddress, macAddress)
}

func nodeSubnetChanged(oldNode, node *kapi.Node) bool {
	oldSubnets, _ := util.ParseNodeHostSubnetAnnotation(oldNode)
	newSubnets, _ := util.ParseNodeHostSubnetAnnotation(node)
	return !reflect.DeepEqual(oldSubnets, newSubnets)
}

func nodeChassisChanged(oldNode, node *kapi.Node) bool {
	oldChassis, _ := util.ParseNodeChassisIDAnnotation(oldNode)
	newChassis, _ := util.ParseNodeChassisIDAnnotation(node)
	return oldChassis != newChassis
}

// noHostSubnet() compares the no-hostsubenet-nodes flag with node labels to see if the node is manageing its
// own network.
func noHostSubnet(node *kapi.Node) bool {
	if config.Kubernetes.NoHostSubnetNodes == nil {
		return false
	}

	nodeSelector, _ := metav1.LabelSelectorAsSelector(config.Kubernetes.NoHostSubnetNodes)
	return nodeSelector.Matches(labels.Set(node.Labels))
}

// shouldUpdate() determines if the ovn-kubernetes plugin should update the state of the node.
// ovn-kube should not perform an update if it does not assign a hostsubnet, or if you want to change
// whether or not ovn-kubernetes assigns a hostsubnet
func shouldUpdate(node, oldNode *kapi.Node) (bool, error) {
	newNoHostSubnet := noHostSubnet(node)
	oldNoHostSubnet := noHostSubnet(oldNode)

	if oldNoHostSubnet && newNoHostSubnet {
		return false, nil
	} else if oldNoHostSubnet && !newNoHostSubnet {
		return false, fmt.Errorf("error updating node %s, cannot remove assigned hostsubnet, please delete node and recreate.", node.Name)
	} else if !oldNoHostSubnet && newNoHostSubnet {
		return false, fmt.Errorf("error updating node %s, cannot assign a hostsubnet to already created node, please delete node and recreate.", node.Name)
	}

	return true, nil
}

func newServiceController(client clientset.Interface, nbClient libovsdbclient.Client, stopChan <-chan struct{}) *svccontroller.Controller {
	// Create our own informers to start compartmentalizing the code
	// filter server side the things we don't care about
	noProxyName, err := labels.NewRequirement("service.kubernetes.io/service-proxy-name", selection.DoesNotExist, nil)
	if err != nil {
		panic(err)
	}

	noHeadlessEndpoints, err := labels.NewRequirement(kapi.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		panic(err)
	}

	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*noProxyName, *noHeadlessEndpoints)

	svcFactory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = labelSelector.String()
		}))

	controller := svccontroller.NewController(
		client,
		nbClient,
		svcFactory.Core().V1().Services(),
		svcFactory.Discovery().V1beta1().EndpointSlices(),
		svcFactory.Core().V1().Nodes(),
	)

	svcFactory.Start(stopChan)

	return controller
}

func (oc *Controller) StartServiceController(wg *sync.WaitGroup, runRepair bool) error {
	klog.Infof("Starting OVN Service Controller: Using Endpoint Slices")
	wg.Add(1)
	go func() {
		defer wg.Done()
		// use 5 workers like most of the kubernetes controllers in the
		// kubernetes controller-manager
		err := oc.svcController.Run(5, oc.stopChan, runRepair, oc.clusterPortGroupUUID)
		if err != nil {
			klog.Errorf("Error running OVN Kubernetes Services controller: %v", err)
		}
	}()
	return nil
}
