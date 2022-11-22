package ovn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"reflect"
	"strconv"
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
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	svccontroller "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/services"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/unidling"

	lsm "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/subnetallocator"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"

	kapi "k8s.io/api/core/v1"
	kapisnetworking "k8s.io/api/networking/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
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

	modelClient libovsdbops.ModelClient

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

	// Map of network policies that need to be retried, and the timestamp of when they last failed
	// keyed by namespace/name
	retryNetPolices map[string]*retryNetPolEntry
	retryNetPolLock sync.Mutex

	// channel to indicate we need to retry policy immediately
	retryPolicyChan chan struct{}

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

type retryNetPolEntry struct {
	newPolicy  *kapisnetworking.NetworkPolicy
	oldPolicy  *kapisnetworking.NetworkPolicy
	np         *networkPolicy
	timeStamp  time.Time
	backoffSec time.Duration
	// whether to include this NP in retry iterations
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

var NetPolObjects sync.Map

// NewOvnController creates a new OVN controller for creating logical network
// infrastructure and policy
func NewOvnController(ovnClient *util.OVNClientset, wf *factory.WatchFactory, stopChan <-chan struct{}, addressSetFactory addressset.AddressSetFactory,
	libovsdbOvnNBClient libovsdbclient.Client, libovsdbOvnSBClient libovsdbclient.Client,
	recorder record.EventRecorder) *Controller {
	if addressSetFactory == nil {
		addressSetFactory = addressset.NewOvnAddressSetFactory(libovsdbOvnNBClient)
	}
	modelClient := libovsdbops.NewModelClient(libovsdbOvnNBClient)
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
			egressIPAssignmentMutex: &sync.Mutex{},
			podAssignmentMutex:      &sync.Mutex{},
			podAssignment:           make(map[string]*podAssignmentState),
			allocator:               allocator{&sync.Mutex{}, make(map[string]*egressNode)},
			nbClient:                libovsdbOvnNBClient,
			modelClient:             modelClient,
			watchFactory:            wf,
		},
		loadbalancerClusterCache: make(map[kapi.Protocol]string),
		multicastSupport:         config.EnableMulticast,
		loadBalancerGroupUUID:    "",
		aclLoggingEnabled:        true,
		joinSwIPManager:          nil,
		retryPods:                make(map[string]*retryEntry),
		retryPodsChan:            make(chan struct{}, 1),
		retryNetPolices:          make(map[string]*retryNetPolEntry),
		retryPolicyChan:          make(chan struct{}, 1),
		recorder:                 recorder,
		nbClient:                 libovsdbOvnNBClient,
		sbClient:                 libovsdbOvnSBClient,
		svcController:            svcController,
		svcFactory:               svcFactory,
		modelClient:              modelClient,
		metricsRecorder:          metrics.NewControlPlaneRecorder(),
	}
}

// Run starts the actual watching.
func (oc *Controller) Run(wg *sync.WaitGroup, nodeName string) error {
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

	// Master is fully running and resource handlers have synced, update Topology version in OVN
	currentTopologyVersion := strconv.Itoa(ovntypes.OvnCurrentTopologyVersion)
	logicalRouterRes := []nbdb.LogicalRouter{}
	ctx, cancel := context.WithTimeout(context.Background(), ovntypes.OVSDBTimeout)
	defer cancel()
	if err := oc.nbClient.WhereCache(func(lr *nbdb.LogicalRouter) bool {
		return lr.Name == ovntypes.OVNClusterRouter
	}).List(ctx, &logicalRouterRes); err != nil {
		return fmt.Errorf("failed in retrieving %s, error: %v", ovntypes.OVNClusterRouter, err)
	}
	// Update topology version on distributed cluster router
	logicalRouterRes[0].ExternalIDs["k8s-ovn-topo-version"] = currentTopologyVersion
	logicalRouter := nbdb.LogicalRouter{
		Name:        ovntypes.OVNClusterRouter,
		ExternalIDs: logicalRouterRes[0].ExternalIDs,
	}
	opModel := libovsdbops.OperationModel{
		Model:          &logicalRouter,
		ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == ovntypes.OVNClusterRouter },
		OnModelUpdates: []interface{}{
			&logicalRouter.ExternalIDs,
		},
		ErrNotFound: true,
	}
	if _, err := oc.modelClient.CreateOrUpdate(opModel); err != nil {
		return fmt.Errorf("failed to generate set topology version in OVN, err: %v", err)
	}

	// Update topology version on node
	node, err := oc.kube.GetNode(nodeName)
	if err != nil {
		return fmt.Errorf("unable to get node: %s", nodeName)
	}
	err = oc.kube.SetAnnotationsOnNode(node.Name, map[string]interface{}{ovntypes.OvnK8sTopoAnno: strconv.Itoa(ovntypes.OvnCurrentTopologyVersion)})
	if err != nil {
		return fmt.Errorf("failed to set topology annotation for node %s", node.Name)
	}

	return nil
}

func (oc *Controller) ovnTopologyCleanup() error {
	ver, err := oc.determineOVNTopoVersionFromOVN()
	if err != nil {
		return err
	}

	// Cleanup address sets in non dual stack formats in all versions known to possibly exist.
	if ver <= ovntypes.OvnPortBindingTopoVersion {
		err = addressset.NonDualStackAddressSetCleanup(oc.nbClient)
	}
	return err
}

// determineOVNTopoVersionFromOVN determines what OVN Topology version is being used
// If "k8s-ovn-topo-version" key in external_ids column does not exist, it is prior to OVN topology versioning
// and therefore set version number to OvnCurrentTopologyVersion
func (oc *Controller) determineOVNTopoVersionFromOVN() (int, error) {
	ver := 0
	logicalRouterRes := []nbdb.LogicalRouter{}
	ctx, cancel := context.WithTimeout(context.Background(), ovntypes.OVSDBTimeout)
	defer cancel()
	if err := oc.nbClient.WhereCache(func(lr *nbdb.LogicalRouter) bool {
		return lr.Name == ovntypes.OVNClusterRouter
	}).List(ctx, &logicalRouterRes); err != nil {
		return ver, fmt.Errorf("failed in retrieving %s to determine the current version of OVN logical topology: "+
			"error: %v", ovntypes.OVNClusterRouter, err)
	}
	if len(logicalRouterRes) == 0 {
		// no OVNClusterRouter exists, DB is empty, nothing to upgrade
		return math.MaxInt32, nil
	}
	v, exists := logicalRouterRes[0].ExternalIDs["k8s-ovn-topo-version"]
	if !exists {
		klog.Infof("No version string found. The OVN topology is before versioning is introduced. Upgrade needed")
		return ver, nil
	}
	ver, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid OVN topology version string for the cluster, err: %v", err)
	}
	return ver, nil
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
	return oldPod.Annotations[util.RoutingNamespaceAnnotation] != newPod.Annotations[util.RoutingNamespaceAnnotation] ||
		oldPod.Annotations[util.RoutingNetworkAnnotation] != newPod.Annotations[util.RoutingNetworkAnnotation] ||
		oldPod.Annotations[util.BfdAnnotation] != newPod.Annotations[util.BfdAnnotation]
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

// processPodInTerminalState is executed when a pod has been added or updated and is actually in a terminal state
// already. The add or update event is not valid for such object, which we now remove from the cluster in order to
// free its resources. (for now, this applies to completed pods)
func (oc *Controller) processPodInTerminalState(pod *kapi.Pod) {
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
}

// WatchPods starts the watching of Pod resource and calls back the appropriate handler logic
func (oc *Controller) WatchPods() {
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
			newerPod := newer.(*kapi.Pod)
			// there may be a situation where this update event is not the latest
			// and we rely on annotations to determine the pod mac/ifaddr
			// this would create a situation where
			// 1. addLogicalPort is executing with an older pod annotation, skips setting a new annotation
			// 2. creates OVN logical port with old pod annotation value
			// 3. CNI flows check fails and pod annotation does not match what is in OVN
			// Therefore we need to get the latest version of this pod to attempt to addLogicalPort with
			podName := newerPod.Name
			podNs := newerPod.Namespace
			pod, err := oc.watchFactory.GetPod(podNs, podName)
			if err != nil {
				// When processing an object in terminal state there is a chance that it was already removed from
				// the API server. Since delete events for objects in terminal state are skipped delete it here.
				if kerrors.IsNotFound(err) && util.PodCompleted(newerPod) {
					klog.Warningf("Pod %s/%s is in terminal state but no longer exists in informer cache, removing",
						podNs, podName)
					oc.processPodInTerminalState(newerPod)
				} else {
					klog.Warningf("Unable to get pod %s/%s for pod update, most likely it was already deleted",
						podNs, podName)
				}
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
				oc.processPodInTerminalState(pod)
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
			// If object is in terminal state, we would have already deleted it during update.
			// No reason to attempt to delete it here again.
			if util.PodCompleted(pod) {
				klog.Infof("Ignoring delete event for completed pod %s/%s", pod.Namespace, pod.Name)
				return
			}
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
	}, oc.syncPods, oc.watchFactory.GetHandlerPriority(""))

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

	klog.Infof("Bootstrapping existing pods and cleaning stale pods took %v", time.Since(start))
}

// WatchNetworkPolicy starts the watching of network policy resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNetworkPolicy() {
	go func() {
		// track the retryNetworkPolicies map and every 30 seconds check if any pods need to be retried
		for {
			select {
			case <-time.After(30 * time.Second):
				oc.iterateRetryNetworkPolicies(false)
			case <-oc.retryPolicyChan:
				oc.iterateRetryNetworkPolicies(true)
			case <-oc.stopChan:
				return
			}
		}
	}()

	start := time.Now()
	oc.watchFactory.AddPolicyHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			oc.initRetryPolicy(policy)
			oc.checkAndSkipRetryPolicy(policy)
			// If there is a delete entry this is a network policy being added
			// with the same name as a previous network policy that failed deletion.
			// Destroy it first before we add the new policy.
			if retryEntry := oc.getPolicyRetryEntry(policy); retryEntry != nil && retryEntry.oldPolicy != nil {
				klog.Infof("Detected stale policy during new policy add with the same name: %s/%s",
					policy.Namespace, policy.Name)
				if err := oc.deleteNetworkPolicy(retryEntry.oldPolicy, nil); err != nil {
					oc.unSkipRetryPolicy(policy)
					klog.Errorf("Failed to delete stale network policy %s, during add: %v",
						getPolicyNamespacedName(policy), err)
					return
				}
				oc.removeDeleteFromRetryPolicy(policy)
			}
			start := time.Now()
			if err := oc.addNetworkPolicy(policy); err != nil {
				klog.Errorf("Failed to create network policy %s, error: %v",
					getPolicyNamespacedName(policy), err)
				oc.unSkipRetryPolicy(policy)
				return
			}
			klog.Infof("Created Network Policy: %s took: %v", getPolicyNamespacedName(policy), time.Since(start))
			oc.checkAndDeleteRetryPolicy(policy)
		},
		UpdateFunc: func(old, newer interface{}) {
			oldPolicy := old.(*kapisnetworking.NetworkPolicy)
			newPolicy := newer.(*kapisnetworking.NetworkPolicy)
			if !reflect.DeepEqual(oldPolicy, newPolicy) {
				oc.checkAndSkipRetryPolicy(oldPolicy)
				// check if there was already a retry entry with an old policy
				// else just look to delete the old policy in the update
				if retryEntry := oc.getPolicyRetryEntry(oldPolicy); retryEntry != nil && retryEntry.oldPolicy != nil {
					if err := oc.deleteNetworkPolicy(retryEntry.oldPolicy, nil); err != nil {
						oc.initRetryPolicy(newPolicy)
						oc.unSkipRetryPolicy(oldPolicy)
						klog.Errorf("Failed to delete stale network policy %s, during update: %v",
							getPolicyNamespacedName(oldPolicy), err)
						return
					}
				} else if err := oc.deleteNetworkPolicy(oldPolicy, nil); err != nil {
					oc.initRetryPolicyWithDelete(oldPolicy, nil)
					oc.initRetryPolicy(newPolicy)
					oc.unSkipRetryPolicy(oldPolicy)
					klog.Errorf("Failed to delete network policy %s, during update: %v",
						getPolicyNamespacedName(oldPolicy), err)
					return
				}
				// remove the old policy from retry entry since it was correctly deleted
				oc.removeDeleteFromRetryPolicy(oldPolicy)
				if err := oc.addNetworkPolicy(newPolicy); err != nil {
					oc.initRetryPolicy(newPolicy)
					oc.unSkipRetryPolicy(newPolicy)
					klog.Errorf("Failed to create network policy %s, during update: %v",
						getPolicyNamespacedName(newPolicy), err)
					return
				}
				oc.checkAndDeleteRetryPolicy(newPolicy)
			}
		},
		DeleteFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			oc.checkAndSkipRetryPolicy(policy)
			oc.initRetryPolicyWithDelete(policy, nil)
			if err := oc.deleteNetworkPolicy(policy, nil); err != nil {
				oc.unSkipRetryPolicy(policy)
				klog.Errorf("Failed to delete network policy %s, error: %v", getPolicyNamespacedName(policy), err)
				return
			}
			oc.checkAndDeleteRetryPolicy(policy)
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
				if err := oc.addEgressNode(node.Name); err != nil {
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
				if err := oc.deleteEgressNode(oldNode.Name); err != nil {
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
					if err := oc.addEgressNode(newNode.Name); err != nil {
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
				if err := oc.deleteEgressNode(newNode.Name); err != nil {
					klog.Error(err)
				}
			} else if isNewReady && isNewReachable {
				klog.Infof("Node: %s is ready and reachable, adding it for egress assignment", newNode.Name)
				if err := oc.addEgressNode(newNode.Name); err != nil {
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
				if err := oc.deleteEgressNode(node.Name); err != nil {
					klog.Error(err)
				}
			}
		},
	}, oc.initClusterEgressPolicies, oc.watchFactory.GetHandlerPriority("EgressNodeType"))
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
	}, nil)
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
	}, oc.syncEgressIPs, oc.watchFactory.GetHandlerPriority("EgressIPNamespaceType"))
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
	}, nil, oc.watchFactory.GetHandlerPriority("EgressIPPodType"))
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
	}, oc.syncNamespaces, oc.watchFactory.GetHandlerPriority(""))
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
					return
				}
				oc.clearInitialNodeNetworkUnavailableCondition(node, nil)
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
				filteredPods := make([]kapi.Pod, 0)
				for _, pod := range pods.Items {
					pod := pod
					if util.PodCompleted(&pod) {
						continue
					}
					filteredPods = append(filteredPods, pod)
				}
				if len(filteredPods) > 0 {
					oc.addRetryPods(filteredPods)
					oc.requestRetryPods()
				}
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
			oc.deleteNode(node.Name, nodeSubnets)
			oc.lsManager.DeleteNode(node.Name)
			addNodeFailed.Delete(node.Name)
			mgmtPortFailed.Delete(node.Name)
			gatewaysFailed.Delete(node.Name)
			nodeClusterRouterPortFailed.Delete(node.Name)
		},
	}, oc.syncNodes, oc.watchFactory.GetHandlerPriority(""))
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
