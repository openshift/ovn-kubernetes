package ovn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	ocpcloudnetworkapi "github.com/openshift/api/cloudnetwork/v1"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	hocontroller "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	svccontroller "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/services"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/unidling"

	lsm "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/subnetallocator"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"

	utilnet "k8s.io/utils/net"

	kapi "k8s.io/api/core/v1"
	kapisnetworking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	ktypes "k8s.io/apimachinery/pkg/types"
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

	// routingExternalPodGWs contains a map of all pods serving as exgws as well as their
	// exgw IPs
	// key is <namespace>_<pod name>
	routingExternalPodGWs map[string]gatewayInfo

	multicastEnabled bool

	// If not empty, then it has to be set to a logging a severity level, e.g. "notice", "alert", etc
	aclLogging ACLLoggingLevels

	// Per-namespace port group default deny UUIDs
	portGroupIngressDenyName string // Port group Name for ingress deny rule
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
	masterSubnetAllocator *subnetallocator.SubnetAllocator

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

	externalGWCache map[ktypes.NamespacedName]*externalRouteInfo
	exGWCacheMutex  sync.RWMutex

	// egressFirewalls is a map of namespaces and the egressFirewall attached to it
	egressFirewalls sync.Map

	// An address set factory that creates address sets
	addressSetFactory addressset.AddressSetFactory

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

	// Cluster wide Load_Balancer_Group UUID.
	loadBalancerGroupUUID string

	// Cluster-wide gateway router default Control Plane Protection (COPP) UUID
	defaultGatewayCOPPUUID string

	// Controller used for programming OVN for egress IP
	eIPC egressIPController

	// Controller used to handle services
	svcController *svccontroller.Controller
	// svcFactory used to handle service related events
	svcFactory informers.SharedInformerFactory

	egressFirewallDNS *EgressDNS

	// Is ACL logging enabled while configuring meters?
	aclLoggingEnabled bool

	joinSwIPManager *lsm.JoinSwitchIPManager

	// event recorder used to post events to k8s
	recorder record.EventRecorder

	// libovsdb northbound client interface
	nbClient libovsdbclient.Client

	// libovsdb southbound client interface
	sbClient libovsdbclient.Client

	// v4HostSubnetsUsed keeps track of number of v4 subnets currently assigned to nodes
	v4HostSubnetsUsed float64

	// v6HostSubnetsUsed keeps track of number of v6 subnets currently assigned to nodes
	v6HostSubnetsUsed float64

	// Map of pods that need to be retried, and the timestamp of when they last failed
	// The key is a string which holds "namespace_podName"
	retryPods     map[string]*retryEntry
	retryPodsLock sync.Mutex

	// channel to indicate we need to retry pods immediately
	retryPodsChan chan struct{}

	// Objects for network policies that need to be retried
	retryNetPolices *retryObjs

	// Objects for node that need to be retried
	retryNodes *retryObjs
	// Node's specific syncMap used by WatchNode event handler
	gatewaysFailed              sync.Map
	mgmtPortFailed              sync.Map
	addNodeFailed               sync.Map
	nodeClusterRouterPortFailed sync.Map

	metricsRecorder *metrics.ControlPlaneRecorder
}

type retryEntry struct {
	pod        *kapi.Pod
	timeStamp  time.Time
	backoffSec time.Duration
	// whether to include this pod in retry iterations
	ignore bool
	// used to indicate if add events need to be retried
	needsAdd bool
	// used to indicate if delete event needs to be retried;
	// this will hold a copy of its value from the oc.logicalSwitchPort cache
	needsDel *lpInfo
}

type retryObjs struct {
	retryMutex sync.Mutex
	// cache to hold object needs retry to successfully complete processing
	entries map[string]*retryObjEntry
	// channel to indicate we need to retry objs immediately
	retryChan chan struct{}
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
	libovsdbOvnNBClient libovsdbclient.Client, libovsdbOvnSBClient libovsdbclient.Client,
	recorder record.EventRecorder) *Controller {
	if addressSetFactory == nil {
		addressSetFactory = addressset.NewOvnAddressSetFactory(libovsdbOvnNBClient)
	}
	svcController, svcFactory := newServiceController(ovnClient.KubeClient, libovsdbOvnNBClient)
	return &Controller{
		client: ovnClient.KubeClient,
		kube: &kube.Kube{
			KClient:              ovnClient.KubeClient,
			EIPClient:            ovnClient.EgressIPClient,
			EgressFirewallClient: ovnClient.EgressFirewallClient,
			CloudNetworkClient:   ovnClient.CloudNetworkClient,
		},
		watchFactory:          wf,
		stopChan:              stopChan,
		masterSubnetAllocator: subnetallocator.NewSubnetAllocator(),
		lsManager:             lsm.NewLogicalSwitchManager(),
		logicalPortCache:      newPortCache(stopChan),
		namespaces:            make(map[string]*namespaceInfo),
		namespacesMutex:       sync.Mutex{},
		externalGWCache:       make(map[ktypes.NamespacedName]*externalRouteInfo),
		exGWCacheMutex:        sync.RWMutex{},
		addressSetFactory:     addressSetFactory,
		lspIngressDenyCache:   make(map[string]int),
		lspEgressDenyCache:    make(map[string]int),
		lspMutex:              &sync.Mutex{},
		eIPC: egressIPController{
			egressIPAssignmentMutex:           &sync.Mutex{},
			podAssignmentMutex:                &sync.Mutex{},
			podAssignment:                     make(map[string]*podAssignmentState),
			pendingCloudPrivateIPConfigsMutex: &sync.Mutex{},
			pendingCloudPrivateIPConfigsOps:   make(map[string]map[string]*cloudPrivateIPConfigOp),
			allocator:                         allocator{&sync.Mutex{}, make(map[string]*egressNode)},
			nbClient:                          libovsdbOvnNBClient,
			watchFactory:                      wf,
		},
		loadbalancerClusterCache: make(map[kapi.Protocol]string),
		multicastSupport:         config.EnableMulticast,
		loadBalancerGroupUUID:    "",
		aclLoggingEnabled:        true,
		joinSwIPManager:          nil,
		retryPods:                make(map[string]*retryEntry),
		retryPodsChan:            make(chan struct{}, 1),
		retryNetPolices: &retryObjs{
			retryMutex: sync.Mutex{},
			entries:    make(map[string]*retryObjEntry),
			retryChan:  make(chan struct{}, 1),
		},
		retryNodes: &retryObjs{
			retryMutex: sync.Mutex{},
			entries:    make(map[string]*retryObjEntry),
			retryChan:  make(chan struct{}, 1),
		},
		recorder:        recorder,
		nbClient:        libovsdbOvnNBClient,
		sbClient:        libovsdbOvnSBClient,
		svcController:   svcController,
		svcFactory:      svcFactory,
		metricsRecorder: metrics.NewControlPlaneRecorder(),
	}
}

// Run starts the actual watching.
func (oc *Controller) Run(ctx context.Context, wg *sync.WaitGroup) error {
	// Start and sync the watch factory to begin listening for events
	if err := oc.watchFactory.Start(); err != nil {
		return err
	}

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

	// Start service watch factory and sync services
	oc.svcFactory.Start(oc.stopChan)

	// Services should be started after nodes to prevent LB churn
	if err := oc.StartServiceController(wg, true); err != nil {
		return err
	}

	oc.WatchPods()

	// WatchNetworkPolicy depends on WatchPods and WatchNamespaces
	oc.WatchNetworkPolicy()

	if config.OVNKubernetesFeature.EnableEgressIP {
		// This is probably the best starting order for all egress IP handlers.
		// WatchEgressIPNamespaces and WatchEgressIPPods only use the informer
		// cache to retrieve the egress IPs when determining if namespace/pods
		// match. It is thus better if we initialize them first and allow
		// WatchEgressNodes / WatchEgressIP to initialize after. Those handlers
		// might change the assignments of the existing objects. If we do the
		// inverse and start WatchEgressIPNamespaces / WatchEgressIPPod last, we
		// risk performing a bunch of modifications on the EgressIP objects when
		// we restart and then have these handlers act on stale data when they
		// sync.
		oc.WatchEgressIPNamespaces()
		oc.WatchEgressIPPods()
		oc.WatchEgressNodes()
		oc.WatchEgressIP()
		if util.PlatformTypeIsEgressIPCloudProvider() {
			oc.WatchCloudPrivateIPConfig()
		}
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
		unidlingController, err := unidling.NewController(
			oc.recorder,
			oc.watchFactory.ServiceInformer(),
			oc.sbClient,
		)
		if err != nil {
			return err
		}
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

	// Master is fully running and resource handlers have synced, update Topology version in OVN and the ConfigMap
	if err := oc.reportTopologyVersion(ctx); err != nil {
		klog.Errorf("Failed to report topology version: %v", err)
		return err
	}

	return nil
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

func exGatewayAnnotationsChanged(oldPod, newPod *kapi.Pod) bool {
	return oldPod.Annotations[routingNamespaceAnnotation] != newPod.Annotations[routingNamespaceAnnotation] ||
		oldPod.Annotations[routingNetworkAnnotation] != newPod.Annotations[routingNetworkAnnotation] ||
		oldPod.Annotations[bfdAnnotation] != newPod.Annotations[bfdAnnotation]
}

func networkStatusAnnotationsChanged(oldPod, newPod *kapi.Pod) bool {
	return oldPod.Annotations[nettypes.NetworkStatusAnnot] != newPod.Annotations[nettypes.NetworkStatusAnnot]
}

// ensurePod tries to set up a pod. It returns nil on success and error on failure; failure
// indicates the pod set up should be retried later.
func (oc *Controller) ensurePod(oldPod, pod *kapi.Pod, addPort bool) error {
	// Try unscheduled pods later
	if !util.PodScheduled(pod) {
		return fmt.Errorf("failed to ensurePod %s/%s since it is not yet scheduled", pod.Namespace, pod.Name)
	}

	if oldPod != nil && (exGatewayAnnotationsChanged(oldPod, pod) || networkStatusAnnotationsChanged(oldPod, pod)) {
		// No matter if a pod is ovn networked, or host networked, we still need to check for exgw
		// annotations. If the pod is ovn networked and is in update reschedule, addLogicalPort will take
		// care of updating the exgw updates
		if err := oc.deletePodExternalGW(oldPod); err != nil {
			return fmt.Errorf("ensurePod failed %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}

	if util.PodWantsNetwork(pod) && addPort {
		if err := oc.addLogicalPort(pod); err != nil {
			return fmt.Errorf("addLogicalPort failed for %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	} else {
		// either pod is host-networked or its an update for a normal pod (addPort=false case)
		if oldPod == nil || exGatewayAnnotationsChanged(oldPod, pod) || networkStatusAnnotationsChanged(oldPod, pod) {
			if err := oc.addPodExternalGW(pod); err != nil {
				return fmt.Errorf("addPodExternalGW failed for %s/%s: %w", pod.Namespace, pod.Name, err)
			}
		}
	}

	return nil
}

// removePod tried to tear down a pod. It returns nil on success and error on failure;
// failure indicates the pod tear down should be retried later.
func (oc *Controller) removePod(pod *kapi.Pod, portInfo *lpInfo) error {
	if !util.PodWantsNetwork(pod) {
		if err := oc.deletePodExternalGW(pod); err != nil {
			return fmt.Errorf("unable to delete external gateway routes for pod %s: %w",
				getPodNamespacedName(pod), err)
		}
		return nil
	}
	if err := oc.deleteLogicalPort(pod, portInfo); err != nil {
		return fmt.Errorf("deleteLogicalPort failed for pod %s: %w",
			getPodNamespacedName(pod), err)
	}
	return nil
}

// WatchPods starts the watching of Pod resource and calls back the appropriate handler logic
func (oc *Controller) WatchPods() {
	oc.triggerRetryObjs(oc.retryPodsChan, oc.iterateRetryPods)

	start := time.Now()

	oc.watchFactory.AddPodHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			oc.metricsRecorder.AddPod(pod.UID)
			oc.checkAndSkipRetryPod(pod)
			// in case ovnkube-master is restarted and gets all the add events with completed pods
			if util.PodCompleted(pod) {
				// pod is in completed state, remove it
				klog.Infof("Detected completed pod: %s. Will remove.", getPodNamespacedName(pod))
				oc.initRetryDelPod(pod)
				oc.removeAddRetry(pod)
				oc.logicalPortCache.remove(util.GetLogicalPortName(pod.Namespace, pod.Name))
				retryEntry := oc.getPodRetryEntry(pod)
				var portInfo *lpInfo
				if retryEntry != nil {
					// retryEntry shouldn't be nil since we usually add the pod to retryCache above
					portInfo = retryEntry.needsDel
				}
				if err := oc.removePod(pod, portInfo); err != nil {
					oc.recordPodEvent(err, pod)
					klog.Errorf("Failed to delete completed pod %s, error: %v",
						getPodNamespacedName(pod), err)
					oc.unSkipRetryPod(pod)
					return
				}
				oc.checkAndDeleteRetryPod(pod)
				return
			}
			// need to add new pod
			oc.initRetryAddPod(pod)
			if retryEntry := oc.getPodRetryEntry(pod); retryEntry != nil && retryEntry.needsDel != nil {
				klog.Infof("Detected leftover old pod during new pod add with the same name: %s. "+
					"Attempting deletion of leftover old...", getPodNamespacedName(pod))
				if err := oc.removePod(pod, retryEntry.needsDel); err != nil {
					oc.recordPodEvent(err, pod)
					klog.Errorf("Failed to delete pod %s, error: %v",
						getPodNamespacedName(pod), err)
					oc.unSkipRetryPod(pod)
					return
				}
				// deletion was a success; remove delete retry entry
				oc.removeDeleteRetry(pod)
			}
			if err := oc.ensurePod(nil, pod, true); err != nil {
				oc.recordPodEvent(err, pod)
				klog.Errorf("Failed to add pod %s, error: %v",
					getPodNamespacedName(pod), err)
				oc.unSkipRetryPod(pod)
				return
			}
			oc.checkAndDeleteRetryPod(pod)
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
			oc.checkAndSkipRetryPod(pod)
			if retryEntry := oc.getPodRetryEntry(pod); retryEntry != nil && retryEntry.needsDel != nil {
				klog.Infof("Detected leftover old pod during new pod add with the same name: %s. "+
					"Attempting deletion of leftover old...", getPodNamespacedName(pod))
				if err := oc.removePod(pod, retryEntry.needsDel); err != nil {
					oc.recordPodEvent(err, pod)
					klog.Errorf("Failed to delete pod %s, error: %v",
						getPodNamespacedName(pod), err)
					oc.unSkipRetryPod(pod)
					return
				}
				// deletion was a success; remove delete retry entry
				oc.removeDeleteRetry(pod)
			} else if util.PodCompleted(pod) {
				// pod is in completed state, remove it
				klog.Infof("Detected completed pod: %s. Will remove.", getPodNamespacedName(pod))
				oc.initRetryDelPod(pod)
				oc.removeAddRetry(pod)
				oc.logicalPortCache.remove(util.GetLogicalPortName(pod.Namespace, pod.Name))
				retryEntry := oc.getPodRetryEntry(pod)
				var portInfo *lpInfo
				if retryEntry != nil {
					// retryEntry shouldn't be nil since we usually add the pod to retryCache above
					portInfo = retryEntry.needsDel
				}
				if err := oc.removePod(pod, portInfo); err != nil {
					oc.recordPodEvent(err, pod)
					klog.Errorf("Failed to delete completed pod %s, error: %v",
						getPodNamespacedName(pod), err)
					oc.unSkipRetryPod(pod)
					return
				}
				oc.checkAndDeleteRetryPod(pod)
				return
			}

			if err := oc.ensurePod(oldPod, pod, oc.checkAndSkipRetryPod(pod)); err != nil {
				oc.recordPodEvent(err, pod)
				klog.Errorf("Failed to update pod %s, error: %v",
					getPodNamespacedName(pod), err)
				oc.initRetryAddPod(pod)
				// unskip failed pod for next retry iteration
				oc.unSkipRetryPod(pod)
				return
			}
			oc.checkAndDeleteRetryPod(pod)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			oc.metricsRecorder.CleanPod(pod.UID)
			oc.initRetryDelPod(pod)
			// we have a copy of portInfo in the retry cache now, we can remove it from
			// logicalPortCache so that we don't race with a new add pod that comes with
			// the same name.
			oc.logicalPortCache.remove(util.GetLogicalPortName(pod.Namespace, pod.Name))
			retryEntry := oc.getPodRetryEntry(pod)
			var portInfo *lpInfo
			if retryEntry != nil {
				// retryEntry shouldn't be nil since we usually add the pod to retryCache above
				portInfo = retryEntry.needsDel
			}
			if err := oc.removePod(pod, portInfo); err != nil {
				oc.recordPodEvent(err, pod)
				klog.Errorf("Failed to delete pod %s, error: %v",
					getPodNamespacedName(pod), err)
				oc.unSkipRetryPod(pod)
				return
			}
			oc.checkAndDeleteRetryPod(pod)
		},
	}, oc.syncPods)
	klog.Infof("Bootstrapping existing pods and cleaning stale pods took %v", time.Since(start))
}

// WatchNetworkPolicy starts the watching of network policy resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNetworkPolicy() {
	oc.triggerRetryObjs(oc.retryNetPolices.retryChan, oc.iterateRetryNetworkPolicies)
	start := time.Now()
	oc.watchFactory.AddPolicyHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			key := getPolicyNamespacedName(policy)
			oc.retryNetPolices.initRetryObjWithAdd(policy, key)
			oc.retryNetPolices.skipRetryObj(key)
			// If there is a delete entry this is a network policy being added
			// with the same name as a previous network policy that failed deletion.
			// Destroy it first before we add the new policy.
			if retryEntry := oc.retryNetPolices.getObjRetryEntry(key); retryEntry != nil && retryEntry.oldObj != nil {
				klog.Infof("Detected stale policy during new policy add with the same name: %s/%s",
					policy.Namespace, policy.Name)
				knp := retryEntry.oldObj.(*kapisnetworking.NetworkPolicy)
				if err := oc.deleteNetworkPolicy(knp, nil); err != nil {
					oc.retryNetPolices.unSkipRetryObj(key)
					klog.Errorf("Failed to delete stale network policy %s, during add: %v",
						key, err)
					return
				}
				oc.retryNetPolices.removeDeleteFromRetryObj(key)
			}
			start := time.Now()
			if err := oc.addNetworkPolicy(policy); err != nil {
				klog.Errorf("Failed to create network policy %s, error: %v",
					getPolicyNamespacedName(policy), err)
				oc.retryNetPolices.unSkipRetryObj(key)
				return
			}
			klog.Infof("Created Network Policy: %s took: %v", key, time.Since(start))
			oc.retryNetPolices.deleteRetryObj(key, true)
		},
		UpdateFunc: func(old, newer interface{}) {
			oldPolicy := old.(*kapisnetworking.NetworkPolicy)
			newPolicy := newer.(*kapisnetworking.NetworkPolicy)
			if !reflect.DeepEqual(oldPolicy, newPolicy) {
				newKey := getPolicyNamespacedName(newPolicy)
				oldKey := getPolicyNamespacedName(oldPolicy)
				oc.retryNetPolices.skipRetryObj(oldKey)
				// check if there was already a retry entry with an old policy
				// else just look to delete the old policy in the update
				if retryEntry := oc.retryNetPolices.getObjRetryEntry(oldKey); retryEntry != nil && retryEntry.oldObj != nil {
					knp := retryEntry.oldObj.(*kapisnetworking.NetworkPolicy)
					if err := oc.deleteNetworkPolicy(knp, nil); err != nil {
						oc.retryNetPolices.initRetryObjWithAdd(newPolicy, newKey)
						oc.retryNetPolices.unSkipRetryObj(oldKey)
						klog.Errorf("Failed to delete stale network policy %s, during update: %v",
							oldKey, err)
						return
					}
				} else if err := oc.deleteNetworkPolicy(oldPolicy, nil); err != nil {
					oc.retryNetPolices.initRetryObjWithDelete(oldPolicy, oldKey, nil)
					oc.retryNetPolices.initRetryObjWithAdd(newPolicy, newKey)
					oc.retryNetPolices.unSkipRetryObj(oldKey)
					klog.Errorf("Failed to delete network policy %s, during update: %v",
						oldKey, err)
					return
				}
				// remove the old policy from retry entry since it was correctly deleted
				oc.retryNetPolices.removeDeleteFromRetryObj(oldKey)
				if err := oc.addNetworkPolicy(newPolicy); err != nil {
					oc.retryNetPolices.initRetryObjWithAdd(newPolicy, newKey)
					oc.retryNetPolices.unSkipRetryObj(newKey)
					klog.Errorf("Failed to create network policy %s, during update: %v",
						newKey, err)
					return
				}
				oc.retryNetPolices.deleteRetryObj(newKey, true)
			}
		},
		DeleteFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			key := getPolicyNamespacedName(policy)
			oc.retryNetPolices.skipRetryObj(key)
			oc.retryNetPolices.initRetryObjWithDelete(policy, key, nil)
			if err := oc.deleteNetworkPolicy(policy, nil); err != nil {
				oc.retryNetPolices.unSkipRetryObj(key)
				klog.Errorf("Failed to delete network policy %s, error: %v", getPolicyNamespacedName(policy), err)
				return
			}
			oc.retryNetPolices.deleteRetryObj(key, true)
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
			addErrors := oc.addEgressFirewall(egressFirewall)
			if addErrors != nil {
				klog.Error(addErrors)
				egressFirewall.Status.Status = egressFirewallAddError
			} else {
				egressFirewall.Status.Status = egressFirewallAppliedCorrectly
			}

			err := oc.updateEgressFirewallWithRetry(egressFirewall)
			if err != nil {
				klog.Error(err)
			}
			metrics.UpdateEgressFirewallRuleCount(float64(len(egressFirewall.Spec.Egress)))
			metrics.IncrementEgressFirewallCount()
		},
		UpdateFunc: func(old, newer interface{}) {
			newEgressFirewall := newer.(*egressfirewall.EgressFirewall).DeepCopy()
			oldEgressFirewall := old.(*egressfirewall.EgressFirewall)
			if !reflect.DeepEqual(oldEgressFirewall.Spec, newEgressFirewall.Spec) {
				errList := oc.updateEgressFirewall(oldEgressFirewall, newEgressFirewall)
				if errList != nil {
					newEgressFirewall.Status.Status = egressFirewallUpdateError
					klog.Error(errList)
				} else {
					newEgressFirewall.Status.Status = egressFirewallAppliedCorrectly
				}

				err := oc.updateEgressFirewallWithRetry(newEgressFirewall)
				if err != nil {
					klog.Error(err)
				}
				metrics.UpdateEgressFirewallRuleCount(float64(len(newEgressFirewall.Spec.Egress) - len(oldEgressFirewall.Spec.Egress)))
			}
		},
		DeleteFunc: func(obj interface{}) {
			egressFirewall := obj.(*egressfirewall.EgressFirewall)
			deleteErrors := oc.deleteEgressFirewall(egressFirewall)
			if deleteErrors != nil {
				klog.Error(deleteErrors)
				return
			}

			metrics.UpdateEgressFirewallRuleCount(float64(-len(egressFirewall.Spec.Egress)))
			metrics.DecrementEgressFirewallCount()
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
			// Initialize the allocator on every update,
			// ovnkube-node/cloud-network-config-controller will make sure to
			// annotate the node with the egressIPConfig, but that might have
			// happened after we processed the ADD for that object, hence keep
			// retrying for all UPDATEs.
			if err := oc.initEgressIPAllocator(newNode); err != nil {
				klog.V(5).Infof("Egress node initialization error: %v", err)
			}
			oldLabels := oldNode.GetLabels()
			newLabels := newNode.GetLabels()
			_, oldHadEgressLabel := oldLabels[nodeEgressLabel]
			_, newHasEgressLabel := newLabels[nodeEgressLabel]
			// If the node is not labelled for egress assignment, just return
			// directly, we don't really need to set the ready / reachable
			// status on this node if the user doesn't care about using it.
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

// WatchCloudPrivateIPConfig starts the watching of cloudprivateipconfigs
// resource and calls back the appropriate handler logic.
func (oc *Controller) WatchCloudPrivateIPConfig() {
	oc.watchFactory.AddCloudPrivateIPConfigHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cloudPrivateIPConfig := obj.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
			if err := oc.reconcileCloudPrivateIPConfig(nil, cloudPrivateIPConfig); err != nil {
				klog.Errorf("Unable to add CloudPrivateIPConfig: %s, err: %v", cloudPrivateIPConfig.Name, err)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			oldCloudPrivateIPConfig := old.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
			newCloudPrivateIPConfig := new.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
			if err := oc.reconcileCloudPrivateIPConfig(oldCloudPrivateIPConfig, newCloudPrivateIPConfig); err != nil {
				klog.Errorf("Unable to update CloudPrivateIPConfig: %s, err: %v", newCloudPrivateIPConfig.Name, err)
			}
		},
		DeleteFunc: func(obj interface{}) {
			cloudPrivateIPConfig := obj.(*ocpcloudnetworkapi.CloudPrivateIPConfig)
			if err := oc.reconcileCloudPrivateIPConfig(cloudPrivateIPConfig, nil); err != nil {
				klog.Errorf("Unable to delete CloudPrivateIPConfig: %s, err: %v", cloudPrivateIPConfig.Name, err)
			}
		},
	}, nil)
}

// WatchEgressIP starts the watching of egressip resource and calls back the
// appropriate handler logic. It also initiates the other dedicated resource
// handlers for egress IP setup: namespaces, pods.
func (oc *Controller) WatchEgressIP() {
	oc.watchFactory.AddEgressIPHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			eIP := obj.(*egressipv1.EgressIP)
			if err := oc.reconcileEgressIP(nil, eIP); err != nil {
				klog.Errorf("Unable to add EgressIP: %s, err: %v", eIP.Name, err)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			oldEIP := old.(*egressipv1.EgressIP)
			newEIP := new.(*egressipv1.EgressIP)
			if err := oc.reconcileEgressIP(oldEIP, newEIP); err != nil {
				klog.Errorf("Unable to update EgressIP: %s, err: %v", newEIP.Name, err)
			}
		},
		DeleteFunc: func(obj interface{}) {
			eIP := obj.(*egressipv1.EgressIP)
			if err := oc.reconcileEgressIP(eIP, nil); err != nil {
				klog.Errorf("Unable to delete EgressIP: %s, err: %v", eIP.Name, err)
			}
		},
	}, oc.syncEgressIPs)
}

func (oc *Controller) WatchEgressIPNamespaces() {
	oc.watchFactory.AddNamespaceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			namespace := obj.(*kapi.Namespace)
			if err := oc.reconcileEgressIPNamespace(nil, namespace); err != nil {
				klog.Errorf("Unable to add egress IP matching namespace: %s, err: %v", namespace.Name, err)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNamespace := oldObj.(*kapi.Namespace)
			newNamespace := newObj.(*kapi.Namespace)
			if err := oc.reconcileEgressIPNamespace(oldNamespace, newNamespace); err != nil {
				klog.Errorf("Unable to update egress IP matching namespace: %s, err: %v", newNamespace.Name, err)
			}
		},
		DeleteFunc: func(obj interface{}) {
			namespace := obj.(*kapi.Namespace)
			if err := oc.reconcileEgressIPNamespace(namespace, nil); err != nil {
				klog.Errorf("Unable to delete egress IP matching namespace: %s, err: %v", namespace.Name, err)
			}
		},
	}, nil)
}

func (oc *Controller) WatchEgressIPPods() {
	oc.watchFactory.AddPodHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			if err := oc.reconcileEgressIPPod(nil, pod); err != nil {
				klog.Errorf("Unable to add egress IP matching pod: %s/%s, err: %v", pod.Name, pod.Namespace, err)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod := oldObj.(*kapi.Pod)
			newPod := newObj.(*kapi.Pod)
			if util.PodCompleted(newPod) {
				if err := oc.reconcileEgressIPPod(oldPod, nil); err != nil {
					klog.Errorf("Unable to delete egress IP matching completed pod: %s/%s, err: %v",
						oldPod.Name, oldPod.Namespace, err)
				}
			} else {
				if err := oc.reconcileEgressIPPod(oldPod, newPod); err != nil {
					klog.Errorf("Unable to update egress IP matching pod: %s/%s, err: %v", newPod.Name, newPod.Namespace, err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			if err := oc.reconcileEgressIPPod(pod, nil); err != nil {
				klog.Errorf("Unable to delete egress IP matching pod: %s/%s, err: %v", pod.Name, pod.Namespace, err)
			}
		},
	}, nil)
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
		hostSubnets, err = util.ParseNodeHostSubnetAnnotation(node)
		if err != nil {
			return err
		}
	}

	if l3GatewayConfig.Mode == config.GatewayModeDisabled {
		if err := oc.gatewayCleanup(node.Name); err != nil {
			return fmt.Errorf("error cleaning up gateway for node %s: %v", node.Name, err)
		}
		if err := oc.joinSwIPManager.ReleaseJoinLRPIPs(node.Name); err != nil {
			return err
		}
	} else if hostSubnets != nil {
		var hostAddrs sets.String
		if config.Gateway.Mode == config.GatewayModeShared {
			hostAddrs, err = util.ParseNodeHostAddresses(node)
			if err != nil && !util.IsAnnotationNotSetError(err) {
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
	oc.triggerRetryObjs(oc.retryNodes.retryChan, oc.iterateRetryNodes)
	start := time.Now()
	oc.watchFactory.AddNodeHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			oc.retryNodes.initRetryObjWithAdd(node, node.Name)
			oc.retryNodes.skipRetryObj(node.Name)
			if retryEntry := oc.retryNodes.getObjRetryEntry(node.Name); retryEntry != nil && retryEntry.oldObj != nil {
				klog.Infof("Detected leftover old node during new node add  %s.", node.Name)
				if err := oc.deleteNodeEvent(node); err != nil {
					oc.retryNodes.unSkipRetryObj(node.Name)
					klog.Errorf("Failed to delete node %s, error: %v",
						node.Name, err)
					return
				}
				oc.retryNodes.removeDeleteFromRetryObj(node.Name)
			}
			start := time.Now()
			if err := oc.addUpdateNodeEvent(node,
				&nodeSyncs{true, true, true, true}); err != nil {
				klog.Errorf("Failed to create node %s, error: %v",
					node.Name, err)
				oc.retryNodes.unSkipRetryObj(node.Name)
				return
			}
			klog.Infof("Created Node: %s took: %v", node.Name, time.Since(start))
			oc.retryNodes.deleteRetryObj(node.Name, true)
		},
		UpdateFunc: func(old, new interface{}) {
			oldNode := old.(*kapi.Node)
			newNode := new.(*kapi.Node)

			shouldUpdate, err := shouldUpdate(newNode, oldNode)
			if err != nil {
				klog.Errorf(err.Error())
			}
			if !shouldUpdate {
				// the hostsubnet is not assigned by ovn-kubernetes
				return
			}

			oc.retryNodes.skipRetryObj(oldNode.Name)
			if retryEntry := oc.retryNodes.getObjRetryEntry(oldNode.Name); retryEntry != nil && retryEntry.oldObj != nil {
				klog.Infof("Detected leftover old node during node update  %s.", newNode.Name)
				if err := oc.deleteNodeEvent(oldNode); err != nil {
					oc.retryNodes.initRetryObjWithAdd(newNode, newNode.Name)
					oc.retryNodes.unSkipRetryObj(oldNode.Name)
					klog.Errorf("Failed to delete stale node %s, during update: %v",
						oldNode.Name, err)
					return
				}
			}
			// remove the old node from retry entry since it was correctly deleted
			oc.retryNodes.removeDeleteFromRetryObj(oldNode.Name)

			// determine what actually changed in this update
			_, nodeSync := oc.addNodeFailed.Load(newNode.Name)
			_, failed := oc.nodeClusterRouterPortFailed.Load(newNode.Name)
			clusterRtrSync := failed || nodeChassisChanged(oldNode, newNode) || nodeSubnetChanged(oldNode, newNode)
			_, failed = oc.mgmtPortFailed.Load(newNode.Name)
			mgmtSync := failed || macAddressChanged(oldNode, newNode) || nodeSubnetChanged(oldNode, newNode)
			_, failed = oc.gatewaysFailed.Load(newNode.Name)
			gwSync := failed || gatewayChanged(oldNode, newNode) || nodeSubnetChanged(oldNode, newNode) || hostAddressesChanged(oldNode, newNode)

			if err := oc.addUpdateNodeEvent(newNode,
				&nodeSyncs{nodeSync, clusterRtrSync, mgmtSync, gwSync}); err != nil {
				klog.Errorf("Failed to update node %s, error: %v", newNode.Name, err)
				oc.retryNodes.initRetryObjWithAdd(newNode, newNode.Name)
				oc.retryNodes.unSkipRetryObj(newNode.Name)
				return
			}
			oc.retryNodes.deleteRetryObj(newNode.Name, true)
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			oc.retryNodes.skipRetryObj(node.Name)
			oc.retryNodes.initRetryObjWithDelete(node, node.Name, nil)
			if err := oc.deleteNodeEvent(node); err != nil {
				oc.retryNodes.unSkipRetryObj(node.Name)
				klog.Errorf("Failed to delete node %s, error: %v", node.Name, err)
				return
			}
			oc.retryNodes.deleteRetryObj(node.Name, true)
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

func newServiceController(client clientset.Interface, nbClient libovsdbclient.Client) (*svccontroller.Controller, informers.SharedInformerFactory) {
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

	return controller, svcFactory
}

func (oc *Controller) StartServiceController(wg *sync.WaitGroup, runRepair bool) error {
	klog.Infof("Starting OVN Service Controller: Using Endpoint Slices")
	wg.Add(1)
	go func() {
		defer wg.Done()
		useLBGroups := oc.loadBalancerGroupUUID != ""
		// use 5 workers like most of the kubernetes controllers in the
		// kubernetes controller-manager
		err := oc.svcController.Run(5, oc.stopChan, runRepair, useLBGroups)
		if err != nil {
			klog.Errorf("Error running OVN Kubernetes Services controller: %v", err)
		}
	}()
	return nil
}
