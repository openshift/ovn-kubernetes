package factory

import (
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"sync/atomic"
	"time"

	ipamclaimsapi "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1"
	ipamclaimsscheme "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1/apis/clientset/versioned/scheme"
	ipamclaimsfactory "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1/apis/informers/externalversions"
	ipamclaimsinformer "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1/apis/informers/externalversions/ipamclaims/v1alpha1"
	ipamclaimslister "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1/apis/listers/ipamclaims/v1alpha1"
	mnpapi "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	mnpscheme "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned/scheme"
	mnpinformerfactory "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/informers/externalversions"
	mnplister "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/listers/k8s.cni.cncf.io/v1beta1"
	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	nadscheme "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/scheme"
	nadinformerfactory "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions"
	nadinformer "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions/k8s.cni.cncf.io/v1"
	nadlister "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/listers/k8s.cni.cncf.io/v1"
	frrapi "github.com/metallb/frr-k8s/api/v1beta1"
	frrscheme "github.com/metallb/frr-k8s/pkg/client/clientset/versioned/scheme"
	frrinformerfactory "github.com/metallb/frr-k8s/pkg/client/informers/externalversions"
	frrinformer "github.com/metallb/frr-k8s/pkg/client/informers/externalversions/api/v1beta1"
	ocpcloudnetworkapi "github.com/openshift/api/cloudnetwork/v1"
	ocpnetworkapiv1alpha1 "github.com/openshift/api/network/v1alpha1"
	ocpcloudnetworkinformerfactory "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	ocpcloudnetworklister "github.com/openshift/client-go/cloudnetwork/listers/cloudnetwork/v1"
	ocpnetworkscheme "github.com/openshift/client-go/network/clientset/versioned/scheme"
	ocpnetworkinformerfactory "github.com/openshift/client-go/network/informers/externalversions"
	ocpnetworkinformerv1alpha1 "github.com/openshift/client-go/network/informers/externalversions/network/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	knet "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	informerfactory "k8s.io/client-go/informers"
	certificatesinformers "k8s.io/client-go/informers/certificates/v1"
	v1coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	netlisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	anpapi "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	anpscheme "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/scheme"
	anpinformerfactory "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
	anpinformer "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	adminbasedpolicyapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1"
	adminbasedpolicyscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1/apis/clientset/versioned/scheme"
	adminbasedpolicyinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1/apis/informers/externalversions"
	adminpolicybasedrouteinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1/apis/informers/externalversions/adminpolicybasedroute/v1"
	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/scheme"
	egressfirewallinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/informers/externalversions"
	egressfirewallinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/informers/externalversions/egressfirewall/v1"
	egressfirewalllister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/listers/egressfirewall/v1"
	egressipapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/scheme"
	egressipinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/informers/externalversions"
	egressipinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/informers/externalversions/egressip/v1"
	egressiplister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/listers/egressip/v1"
	egressqosapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressqos/v1"
	egressqosscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressqos/v1/apis/clientset/versioned/scheme"
	egressqosinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressqos/v1/apis/informers/externalversions"
	egressqosinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressqos/v1/apis/informers/externalversions/egressqos/v1"
	egressserviceapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressservice/v1"
	egressservicescheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressservice/v1/apis/clientset/versioned/scheme"
	egressserviceinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressservice/v1/apis/informers/externalversions"
	egressserviceinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressservice/v1/apis/informers/externalversions/egressservice/v1"
	networkqosapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1alpha1"
	networkqosscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1alpha1/apis/clientset/versioned/scheme"
	networkqosinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1alpha1/apis/informers/externalversions"
	networkqosinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1alpha1/apis/informers/externalversions/networkqos/v1alpha1"
	networkqoslister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/networkqos/v1alpha1/apis/listers/networkqos/v1alpha1"
	routeadvertisementsapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1"
	routeadvertisementsscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/clientset/versioned/scheme"
	routeadvertisementsinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/informers/externalversions"
	routeadvertisementsinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/informers/externalversions/routeadvertisements/v1"
	userdefinednetworkapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	userdefinednetworkscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/clientset/versioned/scheme"
	userdefinednetworkapiinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/informers/externalversions"
	userdefinednetworkinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/informers/externalversions/userdefinednetwork/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type handlerCounter struct {
	// Must be first member in the struct due to Golang ARM/x86 32-bit
	// requirements with atomic accesses
	counter uint64
}

// WatchFactory initializes and manages common kube watches
type WatchFactory struct {
	handlerCounter *handlerCounter

	iFactory             informerfactory.SharedInformerFactory
	anpFactory           anpinformerfactory.SharedInformerFactory
	eipFactory           egressipinformerfactory.SharedInformerFactory
	efFactory            egressfirewallinformerfactory.SharedInformerFactory
	dnsFactory           ocpnetworkinformerfactory.SharedInformerFactory
	cpipcFactory         ocpcloudnetworkinformerfactory.SharedInformerFactory
	egressQoSFactory     egressqosinformerfactory.SharedInformerFactory
	mnpFactory           mnpinformerfactory.SharedInformerFactory
	egressServiceFactory egressserviceinformerfactory.SharedInformerFactory
	apbRouteFactory      adminbasedpolicyinformerfactory.SharedInformerFactory
	ipamClaimsFactory    ipamclaimsfactory.SharedInformerFactory
	nadFactory           nadinformerfactory.SharedInformerFactory
	udnFactory           userdefinednetworkapiinformerfactory.SharedInformerFactory
	raFactory            routeadvertisementsinformerfactory.SharedInformerFactory
	frrFactory           frrinformerfactory.SharedInformerFactory
	networkQoSFactory    networkqosinformerfactory.SharedInformerFactory
	informers            map[reflect.Type]*informer

	stopChan chan struct{}

	// Shallow watch factory clones potentially use different internal
	// informers (to allow multiplexing and load sharing).
	internalInformerIndex int
}

func (wf *WatchFactory) ShallowClone() *WatchFactory {
	return &WatchFactory{
		handlerCounter:       wf.handlerCounter,
		iFactory:             wf.iFactory,
		anpFactory:           wf.anpFactory,
		eipFactory:           wf.eipFactory,
		efFactory:            wf.efFactory,
		dnsFactory:           wf.dnsFactory,
		cpipcFactory:         wf.cpipcFactory,
		egressQoSFactory:     wf.egressQoSFactory,
		mnpFactory:           wf.mnpFactory,
		egressServiceFactory: wf.egressServiceFactory,
		apbRouteFactory:      wf.apbRouteFactory,
		ipamClaimsFactory:    wf.ipamClaimsFactory,
		nadFactory:           wf.nadFactory,
		udnFactory:           wf.udnFactory,
		raFactory:            wf.raFactory,
		frrFactory:           wf.frrFactory,
		networkQoSFactory:    wf.networkQoSFactory,
		informers:            wf.informers,
		stopChan:             wf.stopChan,

		// Choose a random internalInformer to use for this clone of the
		// factory.  Reserve index 0 for default network handlers.
		internalInformerIndex: rand.IntN(internalInformerPoolSize-1) + 1,
	}
}

// WatchFactory implements the ObjectCacheInterface interface.
var _ ObjectCacheInterface = &WatchFactory{handlerCounter: &handlerCounter{}}

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
	// rest of handlers
	minNumEventQueues = 1

	// default priorities for various handlers (also the highest priority)
	defaultHandlerPriority int = 0
	// lowest priority among various handlers (See GetHandlerPriority for more information)
	minHandlerPriority int = 4

	// used to determine if an internal informer has handlers attached to it or not
	hasNoHandler uint32 = 0
	hasHandler   uint32 = 1
)

var (
	// Use a larger queue for incoming events to avoid bottlenecks
	// due to handlers being slow.
	eventQueueSize uint32 = 100
)

// Override default event queue configuration.  Used only for tests.
func SetEventQueueSize(newEventQueueSize uint32) {
	eventQueueSize = newEventQueueSize
}

// types for dynamic handlers created when adding a network policy
type addressSetNamespaceAndPodSelector struct{}
type peerNamespaceSelector struct{}
type addressSetPodSelector struct{}
type localPodSelector struct{}

// types for handlers related to egress IP
type egressIPPod struct{}
type egressIPNamespace struct{}
type egressNode struct{}

// types for handlers in use by ovn-k node
type namespaceExGw struct{}
type endpointSliceForStaleConntrackRemoval struct{}
type serviceForGateway struct{}
type endpointSliceForGateway struct{}
type serviceForFakeNodePortWatcher struct{} // only for unit tests

var (
	// Resource types used in ovnk master
	PodType                               reflect.Type = reflect.TypeOf(&corev1.Pod{})
	ServiceType                           reflect.Type = reflect.TypeOf(&corev1.Service{})
	EndpointSliceType                     reflect.Type = reflect.TypeOf(&discovery.EndpointSlice{})
	PolicyType                            reflect.Type = reflect.TypeOf(&knet.NetworkPolicy{})
	NamespaceType                         reflect.Type = reflect.TypeOf(&corev1.Namespace{})
	NodeType                              reflect.Type = reflect.TypeOf(&corev1.Node{})
	EgressFirewallType                    reflect.Type = reflect.TypeOf(&egressfirewallapi.EgressFirewall{})
	EgressIPType                          reflect.Type = reflect.TypeOf(&egressipapi.EgressIP{})
	EgressIPNamespaceType                 reflect.Type = reflect.TypeOf(&egressIPNamespace{})
	EgressIPPodType                       reflect.Type = reflect.TypeOf(&egressIPPod{})
	EgressNodeType                        reflect.Type = reflect.TypeOf(&egressNode{})
	CloudPrivateIPConfigType              reflect.Type = reflect.TypeOf(&ocpcloudnetworkapi.CloudPrivateIPConfig{})
	EgressQoSType                         reflect.Type = reflect.TypeOf(&egressqosapi.EgressQoS{})
	EgressServiceType                     reflect.Type = reflect.TypeOf(&egressserviceapi.EgressService{})
	AdminNetworkPolicyType                reflect.Type = reflect.TypeOf(&anpapi.AdminNetworkPolicy{})
	BaselineAdminNetworkPolicyType        reflect.Type = reflect.TypeOf(&anpapi.BaselineAdminNetworkPolicy{})
	AddressSetNamespaceAndPodSelectorType reflect.Type = reflect.TypeOf(&addressSetNamespaceAndPodSelector{})
	PeerNamespaceSelectorType             reflect.Type = reflect.TypeOf(&peerNamespaceSelector{})
	AddressSetPodSelectorType             reflect.Type = reflect.TypeOf(&addressSetPodSelector{})
	LocalPodSelectorType                  reflect.Type = reflect.TypeOf(&localPodSelector{})
	NetworkAttachmentDefinitionType       reflect.Type = reflect.TypeOf(&nadapi.NetworkAttachmentDefinition{})
	MultiNetworkPolicyType                reflect.Type = reflect.TypeOf(&mnpapi.MultiNetworkPolicy{})
	IPAMClaimsType                        reflect.Type = reflect.TypeOf(&ipamclaimsapi.IPAMClaim{})
	UserDefinedNetworkType                reflect.Type = reflect.TypeOf(&userdefinednetworkapi.UserDefinedNetwork{})
	ClusterUserDefinedNetworkType         reflect.Type = reflect.TypeOf(&userdefinednetworkapi.ClusterUserDefinedNetwork{})
	NetworkQoSType                        reflect.Type = reflect.TypeOf(&networkqosapi.NetworkQoS{})

	// Resource types used in ovnk node
	NamespaceExGwType                         reflect.Type = reflect.TypeOf(&namespaceExGw{})
	EndpointSliceForStaleConntrackRemovalType reflect.Type = reflect.TypeOf(&endpointSliceForStaleConntrackRemoval{})
	ServiceForGatewayType                     reflect.Type = reflect.TypeOf(&serviceForGateway{})
	EndpointSliceForGatewayType               reflect.Type = reflect.TypeOf(&endpointSliceForGateway{})
	ServiceForFakeNodePortWatcherType         reflect.Type = reflect.TypeOf(&serviceForFakeNodePortWatcher{}) // only for unit tests
)

// NewMasterWatchFactory initializes a new watch factory for:
// a) ovnkube controller + cluster manager or
// b) ovnkube controller + node
// c) all-in-one a.k.a ovnkube controller + cluster-manager + node
// processes.
func NewMasterWatchFactory(ovnClientset *util.OVNMasterClientset) (*WatchFactory, error) {
	wf, err := NewOVNKubeControllerWatchFactory(ovnClientset.GetOVNKubeControllerClientset())
	if err != nil {
		return nil, err
	}
	wf.cpipcFactory = ocpcloudnetworkinformerfactory.NewSharedInformerFactory(ovnClientset.CloudNetworkClient, resyncInterval)
	if util.PlatformTypeIsEgressIPCloudProvider() {
		wf.informers[CloudPrivateIPConfigType], err = newQueuedInformer(eventQueueSize, CloudPrivateIPConfigType,
			wf.cpipcFactory.Cloud().V1().CloudPrivateIPConfigs().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	return wf, nil
}

// Informer transform to trim object fields for memory efficiency.
func informerObjectTrim(obj interface{}) (interface{}, error) {
	if accessor, err := meta.Accessor(obj); err == nil {
		accessor.SetManagedFields(nil)
	}
	if pod, ok := obj.(*corev1.Pod); ok {
		pod.Spec.Volumes = []corev1.Volume{}
		for i := range pod.Spec.Containers {
			pod.Spec.Containers[i].Command = nil
			pod.Spec.Containers[i].Args = nil
			pod.Spec.Containers[i].Env = nil
			pod.Spec.Containers[i].VolumeMounts = nil
		}
	}
	return obj, nil
}

// NewOVNKubeControllerWatchFactory initializes a new watch factory for the ovnkube controller process
func NewOVNKubeControllerWatchFactory(ovnClientset *util.OVNKubeControllerClientset) (*WatchFactory, error) {
	// resync time is 12 hours, none of the resources being watched in ovn-kubernetes have
	// any race condition where a resync may be required e.g. cni executable on node watching for
	// events on pods and assuming that an 'ADD' event will contain the annotations put in by
	// ovnkube master (currently, it is just a 'get' loop)
	// the downside of making it tight (like 10 minutes) is needless spinning on all resources
	// However, AddEventHandlerWithResyncPeriod can specify a per handler resync period
	wf := &WatchFactory{
		handlerCounter:       &handlerCounter{},
		iFactory:             informerfactory.NewSharedInformerFactoryWithOptions(ovnClientset.KubeClient, resyncInterval, informerfactory.WithTransform(informerObjectTrim)),
		anpFactory:           anpinformerfactory.NewSharedInformerFactory(ovnClientset.ANPClient, resyncInterval),
		eipFactory:           egressipinformerfactory.NewSharedInformerFactory(ovnClientset.EgressIPClient, resyncInterval),
		efFactory:            egressfirewallinformerfactory.NewSharedInformerFactory(ovnClientset.EgressFirewallClient, resyncInterval),
		dnsFactory:           ocpnetworkinformerfactory.NewSharedInformerFactoryWithOptions(ovnClientset.OCPNetworkClient, resyncInterval, ocpnetworkinformerfactory.WithNamespace(config.Kubernetes.OVNConfigNamespace)),
		egressQoSFactory:     egressqosinformerfactory.NewSharedInformerFactory(ovnClientset.EgressQoSClient, resyncInterval),
		mnpFactory:           mnpinformerfactory.NewSharedInformerFactory(ovnClientset.MultiNetworkPolicyClient, resyncInterval),
		egressServiceFactory: egressserviceinformerfactory.NewSharedInformerFactory(ovnClientset.EgressServiceClient, resyncInterval),
		apbRouteFactory:      adminbasedpolicyinformerfactory.NewSharedInformerFactory(ovnClientset.AdminPolicyRouteClient, resyncInterval),
		networkQoSFactory:    networkqosinformerfactory.NewSharedInformerFactory(ovnClientset.NetworkQoSClient, resyncInterval),
		informers:            make(map[reflect.Type]*informer),
		stopChan:             make(chan struct{}),
	}

	if err := anpapi.AddToScheme(anpscheme.Scheme); err != nil {
		return nil, err
	}

	if err := egressipapi.AddToScheme(egressipscheme.Scheme); err != nil {
		return nil, err
	}
	if err := egressfirewallapi.AddToScheme(egressfirewallscheme.Scheme); err != nil {
		return nil, err
	}
	if err := ocpnetworkapiv1alpha1.Install(ocpnetworkscheme.Scheme); err != nil {
		return nil, err
	}
	if err := egressqosapi.AddToScheme(egressqosscheme.Scheme); err != nil {
		return nil, err
	}
	if err := egressserviceapi.AddToScheme(egressservicescheme.Scheme); err != nil {
		return nil, err
	}
	if err := adminbasedpolicyapi.AddToScheme(adminbasedpolicyscheme.Scheme); err != nil {
		return nil, err
	}
	if err := routeadvertisementsapi.AddToScheme(routeadvertisementsscheme.Scheme); err != nil {
		return nil, err
	}

	if err := nadapi.AddToScheme(nadscheme.Scheme); err != nil {
		return nil, err
	}

	if err := mnpapi.AddToScheme(mnpscheme.Scheme); err != nil {
		return nil, err
	}

	if err := ipamclaimsapi.AddToScheme(ipamclaimsscheme.Scheme); err != nil {
		return nil, err
	}
	if err := userdefinednetworkapi.AddToScheme(userdefinednetworkscheme.Scheme); err != nil {
		return nil, err
	}

	if err := networkqosapi.AddToScheme(networkqosscheme.Scheme); err != nil {
		return nil, err
	}

	// For Services and Endpoints, pre-populate the shared Informer with one that
	// has a label selector excluding headless services.
	wf.iFactory.InformerFor(&corev1.Service{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredServiceInformer(
			c,
			corev1.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noAlternateProxySelector())
	})

	wf.iFactory.InformerFor(&discovery.EndpointSlice{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return discoveryinformers.NewFilteredEndpointSliceInformer(
			c,
			corev1.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			getEndpointSliceSelector())
	})

	var err error
	// Create our informer-wrapper informer (and underlying shared informer) for types we need
	wf.informers[PodType], err = newQueuedInformer(eventQueueSize, PodType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan,
		defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[ServiceType], err = newQueuedInformer(eventQueueSize, ServiceType, wf.iFactory.Core().V1().Services().Informer(),
		wf.stopChan, minNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[PolicyType], err = newQueuedInformer(eventQueueSize, PolicyType, wf.iFactory.Networking().V1().NetworkPolicies().Informer(),
		wf.stopChan, minNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[NamespaceType], err = newQueuedInformer(eventQueueSize, NamespaceType, wf.iFactory.Core().V1().Namespaces().Informer(),
		wf.stopChan, defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[NodeType], err = newQueuedInformer(eventQueueSize, NodeType, wf.iFactory.Core().V1().Nodes().Informer(), wf.stopChan,
		defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[EndpointSliceType], err = newQueuedInformer(eventQueueSize, EndpointSliceType, wf.iFactory.Discovery().V1().EndpointSlices().Informer(),
		wf.stopChan, minNumEventQueues)
	if err != nil {
		return nil, err
	}
	if config.OVNKubernetesFeature.EnableAdminNetworkPolicy {
		wf.informers[AdminNetworkPolicyType], err = newQueuedInformer(eventQueueSize, AdminNetworkPolicyType,
			wf.anpFactory.Policy().V1alpha1().AdminNetworkPolicies().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
		wf.informers[BaselineAdminNetworkPolicyType], err = newQueuedInformer(eventQueueSize, BaselineAdminNetworkPolicyType,
			wf.anpFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}
	if config.OVNKubernetesFeature.EnableEgressIP {
		wf.informers[EgressIPType], err = newQueuedInformer(eventQueueSize, EgressIPType, wf.eipFactory.K8s().V1().EgressIPs().Informer(), wf.stopChan,
			minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}
	if config.OVNKubernetesFeature.EnableEgressFirewall {
		wf.informers[EgressFirewallType], err = newQueuedInformer(eventQueueSize, EgressFirewallType, wf.efFactory.K8s().V1().EgressFirewalls().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}

		if config.OVNKubernetesFeature.EnableDNSNameResolver {
			// make sure shared informer is created for a factory, so on wf.dnsFactory.Start() it is initialized and caches are synced.
			wf.dnsFactory.Network().V1alpha1().DNSNameResolvers().Informer()
		}
	}
	if config.OVNKubernetesFeature.EnableEgressQoS {
		wf.informers[EgressQoSType], err = newQueuedInformer(eventQueueSize, EgressQoSType, wf.egressQoSFactory.K8s().V1().EgressQoSes().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}
	if config.OVNKubernetesFeature.EnableEgressService {
		wf.informers[EgressServiceType], err = newQueuedInformer(eventQueueSize, EgressServiceType,
			wf.egressServiceFactory.K8s().V1().EgressServices().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	if config.OVNKubernetesFeature.EnableMultiNetwork {
		wf.nadFactory = nadinformerfactory.NewSharedInformerFactory(ovnClientset.NetworkAttchDefClient, resyncInterval)
		wf.informers[NetworkAttachmentDefinitionType], err = newQueuedInformer(eventQueueSize, NetworkAttachmentDefinitionType,
			wf.nadFactory.K8sCniCncfIo().V1().NetworkAttachmentDefinitions().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}

		if config.OVNKubernetesFeature.EnablePersistentIPs && !config.OVNKubernetesFeature.EnableInterconnect {
			wf.ipamClaimsFactory = ipamclaimsfactory.NewSharedInformerFactory(ovnClientset.IPAMClaimsClient, resyncInterval)
			wf.informers[IPAMClaimsType], err = newQueuedInformer(eventQueueSize, IPAMClaimsType,
				wf.ipamClaimsFactory.K8s().V1alpha1().IPAMClaims().Informer(), wf.stopChan, minNumEventQueues)
			if err != nil {
				return nil, err
			}
		}
	}

	if util.IsNetworkSegmentationSupportEnabled() {
		wf.udnFactory = userdefinednetworkapiinformerfactory.NewSharedInformerFactory(ovnClientset.UserDefinedNetworkClient, resyncInterval)
		wf.informers[UserDefinedNetworkType], err = newQueuedInformer(eventQueueSize, UserDefinedNetworkType,
			wf.udnFactory.K8s().V1().UserDefinedNetworks().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}

		wf.informers[ClusterUserDefinedNetworkType], err = newQueuedInformer(eventQueueSize, ClusterUserDefinedNetworkType,
			wf.udnFactory.K8s().V1().ClusterUserDefinedNetworks().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	if util.IsMultiNetworkPoliciesSupportEnabled() {
		wf.informers[MultiNetworkPolicyType], err = newQueuedInformer(eventQueueSize, MultiNetworkPolicyType,
			wf.mnpFactory.K8sCniCncfIo().V1beta1().MultiNetworkPolicies().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	if config.OVNKubernetesFeature.EnableMultiExternalGateway {
		// make sure shared informer is created for a factory, so on wf.apbRouteFactory.Start() it is initialized and caches are synced.
		wf.apbRouteFactory.K8s().V1().AdminPolicyBasedExternalRoutes().Informer()
	}

	if util.IsRouteAdvertisementsEnabled() {
		wf.raFactory = routeadvertisementsinformerfactory.NewSharedInformerFactory(ovnClientset.RouteAdvertisementsClient, resyncInterval)
		// make sure shared informer is created for a factory, so on wf.raFactory.Start() it is initialized and caches are synced.
		wf.raFactory.K8s().V1().RouteAdvertisements().Informer()
	}

	if config.OVNKubernetesFeature.EnableNetworkQoS {
		wf.informers[NetworkQoSType], err = newQueuedInformer(eventQueueSize, NetworkQoSType,
			wf.networkQoSFactory.K8s().V1alpha1().NetworkQoSes().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	return wf, nil
}

// Start starts the factory and begins processing events
func (wf *WatchFactory) Start() error {
	klog.Info("Starting watch factory")
	wf.iFactory.Start(wf.stopChan)
	for oType, synced := range waitForCacheSyncWithTimeout(wf.iFactory, wf.stopChan) {
		if !synced {
			return fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}
	if config.OVNKubernetesFeature.EnableAdminNetworkPolicy && wf.anpFactory != nil {
		wf.anpFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.anpFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}
	if config.OVNKubernetesFeature.EnableEgressIP && wf.eipFactory != nil {
		wf.eipFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.eipFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}
	if config.OVNKubernetesFeature.EnableEgressFirewall && wf.efFactory != nil {
		wf.efFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.efFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}

		if config.OVNKubernetesFeature.EnableDNSNameResolver && wf.dnsFactory != nil {
			wf.dnsFactory.Start(wf.stopChan)
			for oType, synced := range waitForCacheSyncWithTimeout(wf.dnsFactory, wf.stopChan) {
				if !synced {
					return fmt.Errorf("error in syncing cache for %v informer", oType)
				}
			}
		}
	}
	if util.PlatformTypeIsEgressIPCloudProvider() && wf.cpipcFactory != nil {
		wf.cpipcFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.cpipcFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}
	if config.OVNKubernetesFeature.EnableEgressQoS && wf.egressQoSFactory != nil {
		wf.egressQoSFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.egressQoSFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if util.IsMultiNetworkPoliciesSupportEnabled() && wf.mnpFactory != nil {
		wf.mnpFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.mnpFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if config.OVNKubernetesFeature.EnableEgressService && wf.egressServiceFactory != nil {
		wf.egressServiceFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.egressServiceFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if config.OVNKubernetesFeature.EnableMultiExternalGateway && wf.apbRouteFactory != nil {
		wf.apbRouteFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.apbRouteFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if wf.ipamClaimsFactory != nil {
		wf.ipamClaimsFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.ipamClaimsFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if wf.nadFactory != nil {
		wf.nadFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.nadFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if config.OVNKubernetesFeature.EnableNetworkQoS && wf.networkQoSFactory != nil {
		wf.networkQoSFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.networkQoSFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if util.IsNetworkSegmentationSupportEnabled() && wf.udnFactory != nil {
		wf.udnFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.udnFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if wf.raFactory != nil {
		wf.raFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.raFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if wf.frrFactory != nil {
		wf.frrFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.frrFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	if config.OVNKubernetesFeature.EnableNetworkQoS && wf.networkQoSFactory != nil {
		wf.networkQoSFactory.Start(wf.stopChan)
		for oType, synced := range waitForCacheSyncWithTimeout(wf.networkQoSFactory, wf.stopChan) {
			if !synced {
				return fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}

	return nil
}

// Stop stops the factory informers, and waits for their handlers to stop
func (wf *WatchFactory) Stop() {
	klog.Info("Stopping watch factory")
	wf.iFactory.Shutdown()
	if wf.anpFactory != nil {
		wf.anpFactory.Shutdown()
	}
	if wf.eipFactory != nil {
		wf.eipFactory.Shutdown()
	}
	if wf.efFactory != nil {
		wf.efFactory.Shutdown()
	}
	if wf.dnsFactory != nil {
		wf.dnsFactory.Shutdown()
	}
	if wf.cpipcFactory != nil {
		wf.cpipcFactory.Shutdown()
	}
	if wf.egressQoSFactory != nil {
		wf.egressQoSFactory.Shutdown()
	}
	// FIXME(trozet) when https://github.com/k8snetworkplumbingwg/multi-networkpolicy/issues/22 is resolved
	// wf.mnpFactory.Shutdown()
	// wf.nadFactory.Shutdown()
	if wf.egressServiceFactory != nil {
		wf.egressServiceFactory.Shutdown()
	}
	if wf.apbRouteFactory != nil {
		wf.apbRouteFactory.Shutdown()
	}
	if wf.ipamClaimsFactory != nil {
		wf.ipamClaimsFactory.Shutdown()
	}

	if wf.udnFactory != nil {
		wf.udnFactory.Shutdown()
	}

	if wf.raFactory != nil {
		wf.raFactory.Shutdown()
	}

	if wf.frrFactory != nil {
		wf.frrFactory.Shutdown()
	}

	if wf.networkQoSFactory != nil {
		wf.networkQoSFactory.Shutdown()
	}
}

// NewNodeWatchFactory initializes a watch factory with significantly fewer
// informers to save memory + bandwidth. It is to be used by the node-only process.
//
// TODO(jtanenba) originally the pod selector was only supposed to select pods local to the node
// commit 91046e889... changed that and pod selector selects all pods in the cluster fix the naming
// of the localPodSelector or figure out how to deal with selecting all pods everywhere.
func NewNodeWatchFactory(ovnClientset *util.OVNNodeClientset, nodeName string) (*WatchFactory, error) {
	wf := &WatchFactory{
		handlerCounter:       &handlerCounter{},
		iFactory:             informerfactory.NewSharedInformerFactoryWithOptions(ovnClientset.KubeClient, resyncInterval, informerfactory.WithTransform(informerObjectTrim)),
		egressServiceFactory: egressserviceinformerfactory.NewSharedInformerFactory(ovnClientset.EgressServiceClient, resyncInterval),
		eipFactory:           egressipinformerfactory.NewSharedInformerFactory(ovnClientset.EgressIPClient, resyncInterval),
		apbRouteFactory:      adminbasedpolicyinformerfactory.NewSharedInformerFactory(ovnClientset.AdminPolicyRouteClient, resyncInterval),
		informers:            make(map[reflect.Type]*informer),
		stopChan:             make(chan struct{}),
	}

	if err := egressserviceapi.AddToScheme(egressservicescheme.Scheme); err != nil {
		return nil, err
	}
	if err := egressipapi.AddToScheme(egressipscheme.Scheme); err != nil {
		return nil, err
	}
	if err := adminbasedpolicyapi.AddToScheme(adminbasedpolicyscheme.Scheme); err != nil {
		return nil, err
	}
	if err := nadapi.AddToScheme(nadscheme.Scheme); err != nil {
		return nil, err
	}
	if err := routeadvertisementsapi.AddToScheme(routeadvertisementsscheme.Scheme); err != nil {
		return nil, err
	}

	var err error
	wf.informers[PodType], err = newQueuedInformer(eventQueueSize, PodType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan,
		defaultNumEventQueues)
	if err != nil {
		return nil, err
	}

	// For Services and Endpoints, pre-populate the shared Informer with one that
	// has a label selector excluding headless services.
	wf.iFactory.InformerFor(&corev1.Service{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredServiceInformer(
			c,
			corev1.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noAlternateProxySelector())
	})

	// For Pods, only select pods scheduled to this node
	wf.iFactory.InformerFor(&corev1.Pod{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredPodInformer(
			c,
			corev1.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(opts *metav1.ListOptions) {
				opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
			})
	})

	// For namespaces
	wf.iFactory.InformerFor(&corev1.Namespace{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewNamespaceInformer(
			c,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	})

	wf.iFactory.InformerFor(&discovery.EndpointSlice{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return discoveryinformers.NewFilteredEndpointSliceInformer(
			c,
			corev1.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			getEndpointSliceSelector())
	})

	wf.informers[NamespaceType], err = newQueuedInformer(eventQueueSize, NamespaceType, wf.iFactory.Core().V1().Namespaces().Informer(),
		wf.stopChan, defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[PodType], err = newQueuedInformer(eventQueueSize, PodType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan,
		defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[ServiceType], err = newQueuedInformer(
		eventQueueSize,
		ServiceType,
		wf.iFactory.Core().V1().Services().Informer(), wf.stopChan, minNumEventQueues)
	if err != nil {
		return nil, err
	}
	wf.informers[EndpointSliceType], err = newQueuedInformer(
		eventQueueSize,
		EndpointSliceType,
		wf.iFactory.Discovery().V1().EndpointSlices().Informer(), wf.stopChan, minNumEventQueues)
	if err != nil {
		return nil, err
	}

	wf.informers[NodeType], err = newQueuedInformer(eventQueueSize, NodeType, wf.iFactory.Core().V1().Nodes().Informer(), wf.stopChan,
		defaultNumEventQueues)
	if err != nil {
		return nil, err
	}

	if config.OVNKubernetesFeature.EnableEgressService {
		wf.informers[EgressServiceType], err = newQueuedInformer(eventQueueSize, EgressServiceType,
			wf.egressServiceFactory.K8s().V1().EgressServices().Informer(), wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}
	if config.OVNKubernetesFeature.EnableEgressIP {
		wf.informers[EgressIPType], err = newQueuedInformer(eventQueueSize, EgressIPType, wf.eipFactory.K8s().V1().EgressIPs().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	if config.OVNKubernetesFeature.EnableMultiExternalGateway {
		// make sure shared informer is created for a factory, so on wf.apbRouteFactory.Start() it is initialized and caches are synced.
		wf.apbRouteFactory.K8s().V1().AdminPolicyBasedExternalRoutes().Informer()
	}

	if util.IsRouteAdvertisementsEnabled() {
		wf.raFactory = routeadvertisementsinformerfactory.NewSharedInformerFactory(ovnClientset.RouteAdvertisementsClient, resyncInterval)
		// make sure shared informer is created for a factory, so on wf.raFactory.Start() it is initialized and caches are synced.
		wf.raFactory.K8s().V1().RouteAdvertisements().Informer()
	}

	// need to configure OVS interfaces for Pods on secondary networks in the DPU mode
	// need to know what is the primary network for a namespace on the CNI side, which
	// needs the NAD factory whenever the UDN feature is used.
	if config.OVNKubernetesFeature.EnableMultiNetwork && (config.OVNKubernetesFeature.EnableNetworkSegmentation || config.OvnKubeNode.Mode == types.NodeModeDPU) {
		wf.nadFactory = nadinformerfactory.NewSharedInformerFactory(ovnClientset.NetworkAttchDefClient, resyncInterval)
		wf.informers[NetworkAttachmentDefinitionType], err = newQueuedInformer(eventQueueSize,
			NetworkAttachmentDefinitionType, wf.nadFactory.K8sCniCncfIo().V1().NetworkAttachmentDefinitions().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	if util.IsNetworkSegmentationSupportEnabled() {
		wf.udnFactory = userdefinednetworkapiinformerfactory.NewSharedInformerFactory(ovnClientset.UserDefinedNetworkClient, resyncInterval)
		wf.informers[UserDefinedNetworkType], err = newQueuedInformer(eventQueueSize,
			UserDefinedNetworkType, wf.udnFactory.K8s().V1().UserDefinedNetworks().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}

		wf.informers[ClusterUserDefinedNetworkType], err = newQueuedInformer(eventQueueSize,
			ClusterUserDefinedNetworkType, wf.udnFactory.K8s().V1().ClusterUserDefinedNetworks().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	return wf, nil
}

// NewClusterManagerWatchFactory initializes a watch factory with significantly fewer
// informers to save memory + bandwidth. It is to be used by the cluster manager only
// mode process.
func NewClusterManagerWatchFactory(ovnClientset *util.OVNClusterManagerClientset) (*WatchFactory, error) {
	wf := &WatchFactory{
		handlerCounter:       &handlerCounter{},
		iFactory:             informerfactory.NewSharedInformerFactoryWithOptions(ovnClientset.KubeClient, resyncInterval, informerfactory.WithTransform(informerObjectTrim)),
		efFactory:            egressfirewallinformerfactory.NewSharedInformerFactory(ovnClientset.EgressFirewallClient, resyncInterval),
		eipFactory:           egressipinformerfactory.NewSharedInformerFactory(ovnClientset.EgressIPClient, resyncInterval),
		cpipcFactory:         ocpcloudnetworkinformerfactory.NewSharedInformerFactory(ovnClientset.CloudNetworkClient, resyncInterval),
		egressServiceFactory: egressserviceinformerfactory.NewSharedInformerFactoryWithOptions(ovnClientset.EgressServiceClient, resyncInterval),
		dnsFactory:           ocpnetworkinformerfactory.NewSharedInformerFactoryWithOptions(ovnClientset.OCPNetworkClient, resyncInterval, ocpnetworkinformerfactory.WithNamespace(config.Kubernetes.OVNConfigNamespace)),
		apbRouteFactory:      adminbasedpolicyinformerfactory.NewSharedInformerFactory(ovnClientset.AdminPolicyRouteClient, resyncInterval),
		egressQoSFactory:     egressqosinformerfactory.NewSharedInformerFactory(ovnClientset.EgressQoSClient, resyncInterval),
		networkQoSFactory:    networkqosinformerfactory.NewSharedInformerFactory(ovnClientset.NetworkQoSClient, resyncInterval),
		informers:            make(map[reflect.Type]*informer),
		stopChan:             make(chan struct{}),
	}

	if err := egressipapi.AddToScheme(egressipscheme.Scheme); err != nil {
		return nil, err
	}

	if err := egressserviceapi.AddToScheme(egressservicescheme.Scheme); err != nil {
		return nil, err
	}
	if err := ipamclaimsapi.AddToScheme(ipamclaimsscheme.Scheme); err != nil {
		return nil, err
	}
	if err := nadapi.AddToScheme(nadscheme.Scheme); err != nil {
		return nil, err
	}
	if err := egressfirewallapi.AddToScheme(egressfirewallscheme.Scheme); err != nil {
		return nil, err
	}
	if err := ocpnetworkapiv1alpha1.Install(ocpnetworkscheme.Scheme); err != nil {
		return nil, err
	}
	if err := userdefinednetworkapi.AddToScheme(userdefinednetworkscheme.Scheme); err != nil {
		return nil, err
	}
	if err := routeadvertisementsapi.AddToScheme(routeadvertisementsscheme.Scheme); err != nil {
		return nil, err
	}
	if err := frrapi.AddToScheme(frrscheme.Scheme); err != nil {
		return nil, err
	}

	// For Services and Endpoints, pre-populate the shared Informer with one that
	// has a label selector excluding headless services.
	wf.iFactory.InformerFor(&corev1.Service{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredServiceInformer(
			c,
			corev1.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noAlternateProxySelector())
	})

	wf.iFactory.InformerFor(&discovery.EndpointSlice{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return discoveryinformers.NewFilteredEndpointSliceInformer(
			c,
			corev1.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			getEndpointSliceSelector())
	})

	var err error
	// Create our informer-wrapper informer (and underlying shared informer) for types we need
	wf.informers[ServiceType], err = newQueuedInformer(eventQueueSize, ServiceType,
		wf.iFactory.Core().V1().Services().Informer(), wf.stopChan, minNumEventQueues)
	if err != nil {
		return nil, err
	}

	wf.informers[EndpointSliceType], err = newQueuedInformer(
		eventQueueSize,
		EndpointSliceType,
		wf.iFactory.Discovery().V1().EndpointSlices().Informer(), wf.stopChan, minNumEventQueues)
	if err != nil {
		return nil, err
	}

	wf.informers[NodeType], err = newQueuedInformer(eventQueueSize,
		NodeType, wf.iFactory.Core().V1().Nodes().Informer(),
		wf.stopChan, defaultNumEventQueues)
	if err != nil {
		return nil, err
	}
	if config.OVNKubernetesFeature.EnableEgressIP {
		wf.informers[EgressIPType], err = newQueuedInformer(eventQueueSize,
			EgressIPType,
			wf.eipFactory.K8s().V1().EgressIPs().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}
	if util.PlatformTypeIsEgressIPCloudProvider() {
		wf.informers[CloudPrivateIPConfigType], err = newQueuedInformer(eventQueueSize,
			CloudPrivateIPConfigType,
			wf.cpipcFactory.Cloud().V1().CloudPrivateIPConfigs().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	if config.OVNKubernetesFeature.EnableEgressService {
		wf.informers[EgressServiceType], err = newQueuedInformer(eventQueueSize,
			EgressServiceType,
			wf.egressServiceFactory.K8s().V1().EgressServices().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
	}

	if config.OVNKubernetesFeature.EnableMultiNetwork {
		wf.nadFactory = nadinformerfactory.NewSharedInformerFactory(ovnClientset.NetworkAttchDefClient, resyncInterval)
		wf.informers[NetworkAttachmentDefinitionType], err = newQueuedInformer(eventQueueSize,
			NetworkAttachmentDefinitionType,
			wf.nadFactory.K8sCniCncfIo().V1().NetworkAttachmentDefinitions().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}

		if config.OVNKubernetesFeature.EnableInterconnect {
			wf.informers[PodType], err = newQueuedInformer(eventQueueSize,
				PodType, wf.iFactory.Core().V1().Pods().Informer(),
				wf.stopChan, defaultNumEventQueues)
			if err != nil {
				return nil, err
			}

			if config.OVNKubernetesFeature.EnablePersistentIPs {
				wf.ipamClaimsFactory = ipamclaimsfactory.NewSharedInformerFactory(ovnClientset.IPAMClaimsClient, resyncInterval)
				wf.informers[IPAMClaimsType], err = newQueuedInformer(eventQueueSize,
					IPAMClaimsType,
					wf.ipamClaimsFactory.K8s().V1alpha1().IPAMClaims().Informer(),
					wf.stopChan, minNumEventQueues)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if config.OVNKubernetesFeature.EnableMultiExternalGateway {
		// make sure shared informer is created for a factory, so on wf.apbRouteFactory.Start() it is initialized and caches are synced.
		wf.apbRouteFactory.K8s().V1().AdminPolicyBasedExternalRoutes().Informer()
	}

	if config.OVNKubernetesFeature.EnableEgressFirewall {
		// make sure shared informer is created for a factory, so on wf.efFactory.Start() it is initialized and caches are synced.
		wf.efFactory.K8s().V1().EgressFirewalls().Informer()

		if config.OVNKubernetesFeature.EnableDNSNameResolver {
			// make sure shared informer is created for a factory, so on wf.dnsFactory.Start() it is initialized and caches are synced.
			wf.dnsFactory.Network().V1alpha1().DNSNameResolvers().Informer()
		}
	}

	if util.IsNetworkSegmentationSupportEnabled() {
		wf.udnFactory = userdefinednetworkapiinformerfactory.NewSharedInformerFactory(ovnClientset.UserDefinedNetworkClient, resyncInterval)
		wf.informers[UserDefinedNetworkType], err = newQueuedInformer(eventQueueSize,
			UserDefinedNetworkType,
			wf.udnFactory.K8s().V1().UserDefinedNetworks().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}
		wf.informers[ClusterUserDefinedNetworkType], err = newQueuedInformer(eventQueueSize,
			ClusterUserDefinedNetworkType,
			wf.udnFactory.K8s().V1().ClusterUserDefinedNetworks().Informer(),
			wf.stopChan, minNumEventQueues)
		if err != nil {
			return nil, err
		}

		// make sure namespace informer cache is initialized and synced on Start().
		wf.iFactory.Core().V1().Namespaces().Informer()

		// make sure pod informer cache is initialized and synced when on Start().
		wf.iFactory.Core().V1().Pods().Informer()
	}

	if util.IsRouteAdvertisementsEnabled() {
		wf.informers[NamespaceType], err = newQueuedInformer(eventQueueSize, NamespaceType, wf.iFactory.Core().V1().Namespaces().Informer(),
			wf.stopChan, defaultNumEventQueues)
		if err != nil {
			return nil, err
		}

		wf.raFactory = routeadvertisementsinformerfactory.NewSharedInformerFactory(ovnClientset.RouteAdvertisementsClient, resyncInterval)
		// make sure shared informer is created for a factory, so on wf.raFactory.Start() it is initialized and caches are synced.
		wf.raFactory.K8s().V1().RouteAdvertisements().Informer()

		wf.frrFactory = frrinformerfactory.NewSharedInformerFactory(ovnClientset.FRRClient, resyncInterval)
		// make sure shared informer is created for a factory, so on wf.frrFactory.Start() it is initialized and caches are synced.
		wf.frrFactory.Api().V1beta1().FRRConfigurations().Informer()
	}

	return wf, nil
}

func (wf *WatchFactory) Shutdown() {
	close(wf.stopChan)

	// Remove all informer handlers and wait for them to terminate before continuing
	for _, inf := range wf.informers {
		inf.shutdown()
	}
	// Stop all non-custom informers and wait (closing the above channel will not wait)
	wf.Stop()
}

func getObjectMeta(objType reflect.Type, obj interface{}) (*metav1.ObjectMeta, error) {
	switch objType {
	case PodType:
		if pod, ok := obj.(*corev1.Pod); ok {
			return &pod.ObjectMeta, nil
		}
	case ServiceType:
		if service, ok := obj.(*corev1.Service); ok {
			return &service.ObjectMeta, nil
		}
	case PolicyType:
		if policy, ok := obj.(*knet.NetworkPolicy); ok {
			return &policy.ObjectMeta, nil
		}
	case AdminNetworkPolicyType:
		if adminNetworkPolicy, ok := obj.(*anpapi.AdminNetworkPolicy); ok {
			return &adminNetworkPolicy.ObjectMeta, nil
		}
	case BaselineAdminNetworkPolicyType:
		if baselineAdminNetworkPolicy, ok := obj.(*anpapi.BaselineAdminNetworkPolicy); ok {
			return &baselineAdminNetworkPolicy.ObjectMeta, nil
		}
	case NamespaceType:
		if namespace, ok := obj.(*corev1.Namespace); ok {
			return &namespace.ObjectMeta, nil
		}
	case NodeType:
		if node, ok := obj.(*corev1.Node); ok {
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
	case EndpointSliceType:
		if endpointSlice, ok := obj.(*discovery.EndpointSlice); ok {
			return &endpointSlice.ObjectMeta, nil
		}
	case NetworkAttachmentDefinitionType:
		if networkAttachmentDefinition, ok := obj.(*nadapi.NetworkAttachmentDefinition); ok {
			return &networkAttachmentDefinition.ObjectMeta, nil
		}
	case MultiNetworkPolicyType:
		if multinetworkpolicy, ok := obj.(*mnpapi.MultiNetworkPolicy); ok {
			return &multinetworkpolicy.ObjectMeta, nil
		}
	case IPAMClaimsType:
		if persistentips, ok := obj.(*ipamclaimsapi.IPAMClaim); ok {
			return &persistentips.ObjectMeta, nil
		}
	case EgressQoSType:
		if egressQoS, ok := obj.(*egressqosapi.EgressQoS); ok {
			return &egressQoS.ObjectMeta, nil
		}
	case EgressServiceType:
		if egressService, ok := obj.(*egressserviceapi.EgressService); ok {
			return &egressService.ObjectMeta, nil
		}
	case UserDefinedNetworkType:
		if udn, ok := obj.(*userdefinednetworkapi.UserDefinedNetwork); ok {
			return &udn.ObjectMeta, nil
		}
	case ClusterUserDefinedNetworkType:
		if cudn, ok := obj.(*userdefinednetworkapi.ClusterUserDefinedNetwork); ok {
			return &cudn.ObjectMeta, nil
		}
	case NetworkQoSType:
		if networkQoS, ok := obj.(*networkqosapi.NetworkQoS); ok {
			return &networkQoS.ObjectMeta, nil
		}
	}

	return nil, fmt.Errorf("cannot get ObjectMeta from type %v", objType)
}

type AddHandlerFuncType func(namespace string, sel labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error)

// GetHandlerPriority returns the priority of each objType's handler
// Priority of the handler is what determine which handler would get an event first
// This is relevant only for handlers that are sharing the same resources:
// Pods: shared by PodType (0), EgressIPPodType (1), AddressSetPodSelectorType (2), LocalPodSelectorType (3)
// Namespaces: shared by NamespaceType (0), EgressIPNamespaceType (1), PeerNamespaceSelectorType (3), AddressSetNamespaceAndPodSelectorType (4)
// Nodes: shared by NodeType (0), EgressNodeType (1)
// By default handlers get the defaultHandlerPriority which is 0 (highest priority). Higher the number, lower the priority to get an event.
// Example: EgressIPPodType will always get the pod event after PodType and AddressSetPodSelectorType will always get the event after PodType and EgressIPPodType
// NOTE: If you are touching this function to add a new object type that uses shared objects, please make sure to update `minHandlerPriority` if needed
func (wf *WatchFactory) GetHandlerPriority(objType reflect.Type) (priority int) {
	switch objType {
	case EgressIPPodType:
		return 1
	case AddressSetPodSelectorType:
		return 2
	case LocalPodSelectorType:
		return 3
	case EgressIPNamespaceType:
		return 1
	case PeerNamespaceSelectorType:
		return 2
	case AddressSetNamespaceAndPodSelectorType:
		return 3
	case EgressNodeType:
		return 1
	default:
		return defaultHandlerPriority
	}
}

func (wf *WatchFactory) GetResourceHandlerFunc(objType reflect.Type) (AddHandlerFuncType, error) {
	priority := wf.GetHandlerPriority(objType)
	switch objType {
	case NamespaceType, NamespaceExGwType:
		return func(_ string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddNamespaceHandler(funcs, processExisting)
		}, nil

	case PolicyType:
		return func(_ string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddPolicyHandler(funcs, processExisting)
		}, nil

	case MultiNetworkPolicyType:
		return func(_ string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddMultiNetworkPolicyHandler(funcs, processExisting)
		}, nil

	case NodeType, EgressNodeType:
		return func(_ string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddNodeHandler(funcs, processExisting, priority)
		}, nil

	case ServiceForGatewayType, ServiceForFakeNodePortWatcherType:
		return func(namespace string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddFilteredServiceHandler(namespace, funcs, processExisting)
		}, nil

	case AddressSetPodSelectorType, LocalPodSelectorType, PodType, EgressIPPodType:
		return func(namespace string, sel labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddFilteredPodHandler(namespace, sel, funcs, processExisting, priority)
		}, nil

	case AddressSetNamespaceAndPodSelectorType, PeerNamespaceSelectorType, EgressIPNamespaceType:
		return func(namespace string, sel labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddFilteredNamespaceHandler(namespace, sel, funcs, processExisting, priority)
		}, nil

	case EgressFirewallType:
		return func(_ string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddEgressFirewallHandler(funcs, processExisting)
		}, nil

	case EgressIPType:
		return func(_ string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddEgressIPHandler(funcs, processExisting)
		}, nil

	case CloudPrivateIPConfigType:
		return func(_ string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddCloudPrivateIPConfigHandler(funcs, processExisting)
		}, nil

	case EndpointSliceForStaleConntrackRemovalType, EndpointSliceForGatewayType:
		return func(namespace string, sel labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddFilteredEndpointSliceHandler(namespace, sel, funcs, processExisting)
		}, nil

	case IPAMClaimsType:
		return func(_ string, _ labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
			return wf.AddIPAMClaimsHandler(funcs, processExisting)
		}, nil
	}
	return nil, fmt.Errorf("cannot get ObjectMeta from type %v", objType)
}

func (wf *WatchFactory) addHandler(objType reflect.Type, namespace string, sel labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{}) error, priority int) (*Handler, error) {
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

	intInf := inf.internalInformers[wf.internalInformerIndex]

	intInf.Lock()
	defer intInf.Unlock()

	// we are going to add a handler, we need to update the atomic signal that handlers exist now
	// so that we do not miss events after we list current items.
	// We need to do this after we get internal informer lock, to preserve that we can be the only one updating
	// the atomic and preserve known state of the atomic while the handler is going to be added in the future
	hadZeroHandlers := atomic.CompareAndSwapUint32(&intInf.hasHandlers, hasNoHandler, hasHandler)

	items := make([]interface{}, 0)
	for _, obj := range inf.inf.GetStore().List() {
		if filterFunc(obj) {
			items = append(items, obj)
		}
	}
	if processExisting != nil {
		// Process existing items as a set so the caller can clean up
		// after a restart or whatever. We will wrap it with retries to ensure it succeeds.
		// Being so, processExisting is expected to be idem-potent!
		err := utilwait.PollUntilContextTimeout(context.Background(), 500*time.Millisecond, 60*time.Second, true, func(_ context.Context) (bool, error) {
			if err := processExisting(items); err != nil {
				klog.Errorf("Failed (will retry) while processing existing %v items: %v", objType, err)
				return false, nil
			}
			return true, nil
		})
		if err != nil {
			// handler is not going to be added, restore previous value if needed
			if hadZeroHandlers {
				atomic.StoreUint32(&intInf.hasHandlers, hasNoHandler)
			}
			return nil, err
		}
	}

	handlerID := atomic.AddUint64(&wf.handlerCounter.counter, 1)
	handler := inf.addHandler(wf.internalInformerIndex, handlerID, priority, filterFunc, funcs, items)
	klog.V(5).Infof("Added %v event handler %d", objType, handler.id)
	return handler, nil
}

func (wf *WatchFactory) removeHandler(objType reflect.Type, handler *Handler) {
	wf.informers[objType].removeHandler(handler)
}

// AddPodHandler adds a handler function that will be executed on Pod object changes
func (wf *WatchFactory) AddPodHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(PodType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// AddFilteredPodHandler adds a handler function that will be executed when Pod objects that match the given filters change
func (wf *WatchFactory) AddFilteredPodHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error, priority int) (*Handler, error) {
	return wf.addHandler(PodType, namespace, sel, handlerFuncs, processExisting, priority)
}

// RemovePodHandler removes a Pod object event handler function
func (wf *WatchFactory) RemovePodHandler(handler *Handler) {
	wf.removeHandler(PodType, handler)
}

// RemoveIPAMClaimsHandler removes a PersistentIPs object event handler function
func (wf *WatchFactory) RemoveIPAMClaimsHandler(handler *Handler) {
	wf.removeHandler(IPAMClaimsType, handler)
}

// AddIPAMClaimsHandler adds a handler function that will be executed on AddPersistentIPsobject changes
func (wf *WatchFactory) AddIPAMClaimsHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(IPAMClaimsType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// AddServiceHandler adds a handler function that will be executed on Service object changes
func (wf *WatchFactory) AddServiceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(ServiceType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// AddFilteredServiceHandler adds a handler function that will be executed on all Service object changes for a specific namespace
func (wf *WatchFactory) AddFilteredServiceHandler(namespace string, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(ServiceType, namespace, nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemoveServiceHandler removes a Service object event handler function
func (wf *WatchFactory) RemoveServiceHandler(handler *Handler) {
	wf.removeHandler(ServiceType, handler)
}

// AddFilteredEndpointSliceHandler adds a handler function that will be executed on EndpointSlice object changes
func (wf *WatchFactory) AddFilteredEndpointSliceHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(EndpointSliceType, namespace, sel, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemoveEndpointSliceHandler removes a EndpointSlice object event handler function
func (wf *WatchFactory) RemoveEndpointSliceHandler(handler *Handler) {
	wf.removeHandler(EndpointSliceType, handler)
}

// AddPolicyHandler adds a handler function that will be executed on NetworkPolicy object changes
func (wf *WatchFactory) AddPolicyHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(PolicyType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemovePolicyHandler removes a NetworkPolicy object event handler function
func (wf *WatchFactory) RemovePolicyHandler(handler *Handler) {
	wf.removeHandler(PolicyType, handler)
}

// AddEgressFirewallHandler adds a handler function that will be executed on EgressFirewall object changes
func (wf *WatchFactory) AddEgressFirewallHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(EgressFirewallType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemoveEgressFirewallHandler removes an EgressFirewall object event handler function
func (wf *WatchFactory) RemoveEgressFirewallHandler(handler *Handler) {
	wf.removeHandler(EgressFirewallType, handler)
}

// RemoveEgressQoSHandler removes an EgressQoS object event handler function
func (wf *WatchFactory) RemoveEgressQoSHandler(handler *Handler) {
	wf.removeHandler(EgressQoSType, handler)
}

func (wf *WatchFactory) RemoveEgressServiceHandler(handler *Handler) {
	wf.removeHandler(EgressServiceType, handler)
}

// RemoveAdminNetworkPolicyHandler removes an AdminNetworkPolicy object event handler function
// used only in unit tests
func (wf *WatchFactory) RemoveAdminNetworkPolicyHandler(handler *Handler) {
	wf.removeHandler(AdminNetworkPolicyType, handler)
}

// RemoveBaselineAdminNetworkPolicyHandler removes a BaselineAdminNetworkPolicy object event handler function
// used only in unit tests
func (wf *WatchFactory) RemoveBaselineAdminNetworkPolicyHandler(handler *Handler) {
	wf.removeHandler(BaselineAdminNetworkPolicyType, handler)
}

// RemoveNetworkQoSHandler removes an NetworkQoS object event handler function
func (wf *WatchFactory) RemoveNetworkQoSHandler(handler *Handler) {
	wf.removeHandler(NetworkQoSType, handler)
}

// AddNetworkAttachmentDefinitionHandler adds a handler function that will be executed on NetworkAttachmentDefinition object changes
func (wf *WatchFactory) AddNetworkAttachmentDefinitionHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(NetworkAttachmentDefinitionType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemoveNetworkAttachmentDefinitionHandler removes an NetworkAttachmentDefinition object event handler function
func (wf *WatchFactory) RemoveNetworkAttachmentDefinitionHandler(handler *Handler) {
	wf.removeHandler(NetworkAttachmentDefinitionType, handler)
}

// AddEgressIPHandler adds a handler function that will be executed on EgressIP object changes
func (wf *WatchFactory) AddEgressIPHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(EgressIPType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemoveEgressIPHandler removes an EgressIP object event handler function
func (wf *WatchFactory) RemoveEgressIPHandler(handler *Handler) {
	wf.removeHandler(EgressIPType, handler)
}

// AddCloudPrivateIPConfigHandler adds a handler function that will be executed on CloudPrivateIPConfig object changes
func (wf *WatchFactory) AddCloudPrivateIPConfigHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(CloudPrivateIPConfigType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemoveCloudPrivateIPConfigHandler removes an CloudPrivateIPConfig object event handler function
func (wf *WatchFactory) RemoveCloudPrivateIPConfigHandler(handler *Handler) {
	wf.removeHandler(CloudPrivateIPConfigType, handler)
}

// AddMultiNetworkPolicyHandler adds a handler function that will be executed on MultiNetworkPolicy object changes
func (wf *WatchFactory) AddMultiNetworkPolicyHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(MultiNetworkPolicyType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemoveMultiNetworkPolicyHandler removes an MultiNetworkPolicy object event handler function
func (wf *WatchFactory) RemoveMultiNetworkPolicyHandler(handler *Handler) {
	wf.removeHandler(MultiNetworkPolicyType, handler)
}

// AddNamespaceHandler adds a handler function that will be executed on Namespace object changes
func (wf *WatchFactory) AddNamespaceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(NamespaceType, "", nil, handlerFuncs, processExisting, defaultHandlerPriority)
}

// AddFilteredNamespaceHandler adds a handler function that will be executed when Namespace objects that match the given filters change
func (wf *WatchFactory) AddFilteredNamespaceHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error, priority int) (*Handler, error) {
	return wf.addHandler(NamespaceType, namespace, sel, handlerFuncs, processExisting, priority)
}

// RemoveNamespaceHandler removes a Namespace object event handler function
func (wf *WatchFactory) RemoveNamespaceHandler(handler *Handler) {
	wf.removeHandler(NamespaceType, handler)
}

// AddNodeHandler adds a handler function that will be executed on Node object changes
func (wf *WatchFactory) AddNodeHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error, priority int) (*Handler, error) {
	return wf.addHandler(NodeType, "", nil, handlerFuncs, processExisting, priority)
}

// AddFilteredNodeHandler dds a handler function that will be executed when Node objects that match the given label selector
func (wf *WatchFactory) AddFilteredNodeHandler(sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{}) error) (*Handler, error) {
	return wf.addHandler(NodeType, "", sel, handlerFuncs, processExisting, defaultHandlerPriority)
}

// RemoveNodeHandler removes a Node object event handler function
func (wf *WatchFactory) RemoveNodeHandler(handler *Handler) {
	wf.removeHandler(NodeType, handler)
}

// GetPod returns the pod spec given the namespace and pod name
func (wf *WatchFactory) GetPod(namespace, name string) (*corev1.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	return podLister.Pods(namespace).Get(name)
}

// GetAllPods returns all the pods in the cluster
func (wf *WatchFactory) GetAllPods() ([]*corev1.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	return podLister.List(labels.Everything())
}

// GetPods returns all the pods in a given namespace
func (wf *WatchFactory) GetPods(namespace string) ([]*corev1.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	return podLister.Pods(namespace).List(labels.Everything())
}

// GetPodsBySelector returns all the pods in a given namespace by the label selector
func (wf *WatchFactory) GetPodsBySelector(namespace string, labelSelector metav1.LabelSelector) ([]*corev1.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return nil, err
	}
	return podLister.Pods(namespace).List(selector)
}

// GetAllPodsBySelector returns all the pods in all namespace by the label selector
func (wf *WatchFactory) GetAllPodsBySelector(labelSelector metav1.LabelSelector) ([]*corev1.Pod, error) {
	podLister := wf.informers[PodType].lister.(listers.PodLister)
	selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return nil, err
	}
	return podLister.List(selector)
}

// GetNodes returns the node specs of all the nodes
func (wf *WatchFactory) GetNodes() ([]*corev1.Node, error) {
	return wf.ListNodes(labels.Everything())
}

// ListNodes returns nodes that match a selector
func (wf *WatchFactory) ListNodes(selector labels.Selector) ([]*corev1.Node, error) {
	nodeLister := wf.informers[NodeType].lister.(listers.NodeLister)
	return nodeLister.List(selector)
}

// GetNode returns the node spec of a given node by name
func (wf *WatchFactory) GetNode(name string) (*corev1.Node, error) {
	nodeLister := wf.informers[NodeType].lister.(listers.NodeLister)
	return nodeLister.Get(name)
}

// GetNodesByLabelSelector returns all the nodes selected by the label selector
func (wf *WatchFactory) GetNodesByLabelSelector(labelSelector metav1.LabelSelector) ([]*corev1.Node, error) {
	selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return nil, err
	}
	return wf.GetNodesBySelector(selector)
}

// GetNodesBySelector returns all the nodes selected by the selector
func (wf *WatchFactory) GetNodesBySelector(selector labels.Selector) ([]*corev1.Node, error) {
	return wf.ListNodes(selector)
}

// GetService returns the service spec of a service in a given namespace
func (wf *WatchFactory) GetService(namespace, name string) (*corev1.Service, error) {
	serviceLister := wf.informers[ServiceType].lister.(listers.ServiceLister)
	return serviceLister.Services(namespace).Get(name)
}

// GetServices returns all services
func (wf *WatchFactory) GetServices() ([]*corev1.Service, error) {
	serviceLister := wf.informers[ServiceType].lister.(listers.ServiceLister)
	return serviceLister.List(labels.Everything())
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
func (wf *WatchFactory) GetNamespace(name string) (*corev1.Namespace, error) {
	namespaceLister := wf.informers[NamespaceType].lister.(listers.NamespaceLister)
	return namespaceLister.Get(name)
}

// GetEndpointSlice returns the endpointSlice indexed by the given namespace and name
func (wf *WatchFactory) GetEndpointSlice(namespace, name string) (*discovery.EndpointSlice, error) {
	endpointSliceLister := wf.informers[EndpointSliceType].lister.(discoverylisters.EndpointSliceLister)
	return endpointSliceLister.EndpointSlices(namespace).Get(name)
}

// GetEndpointSlicesBySelector returns a list of EndpointSlices in a given namespace by the label selector
func (wf *WatchFactory) GetEndpointSlicesBySelector(namespace string, labelSelector metav1.LabelSelector) ([]*discovery.EndpointSlice, error) {
	return util.GetEndpointSlicesBySelector(namespace, labelSelector, wf.informers[EndpointSliceType].lister.(discoverylisters.EndpointSliceLister))
}

// GetServiceEndpointSlices returns the endpointSlices associated with a service for the specified network
// if network is DefaultNetworkName the default endpointSlices are returned, otherwise the function looks for mirror endpointslices
// for the specified network.
func (wf *WatchFactory) GetServiceEndpointSlices(namespace, svcName, network string) ([]*discovery.EndpointSlice, error) {
	return util.GetServiceEndpointSlices(namespace, svcName, network, wf.informers[EndpointSliceType].lister.(discoverylisters.EndpointSliceLister))
}

// GetNamespaces returns a list of namespaces in the cluster
func (wf *WatchFactory) GetNamespaces() ([]*corev1.Namespace, error) {
	namespaceLister := wf.informers[NamespaceType].lister.(listers.NamespaceLister)
	return namespaceLister.List(labels.Everything())
}

// GetNamespacesBySelector returns a list of namespaces in the cluster by the label selector
func (wf *WatchFactory) GetNamespacesBySelector(labelSelector metav1.LabelSelector) ([]*corev1.Namespace, error) {
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

// GetMultinetworkPolicy gets a specific multinetwork policy by the namespace/name
func (wf *WatchFactory) GetMultiNetworkPolicy(namespace, name string) (*mnpapi.MultiNetworkPolicy, error) {
	multinetworkPolicyLister := wf.informers[MultiNetworkPolicyType].lister.(mnplister.MultiNetworkPolicyLister)
	return multinetworkPolicyLister.MultiNetworkPolicies(namespace).Get(name)
}

func (wf *WatchFactory) GetEgressFirewall(namespace, name string) (*egressfirewallapi.EgressFirewall, error) {
	egressFirewallLister := wf.informers[EgressFirewallType].lister.(egressfirewalllister.EgressFirewallLister)
	return egressFirewallLister.EgressFirewalls(namespace).Get(name)
}

func (wf *WatchFactory) GetNetworkQoSes() ([]*networkqosapi.NetworkQoS, error) {
	networkQosLister := wf.informers[NetworkQoSType].lister.(networkqoslister.NetworkQoSLister)
	return networkQosLister.List(labels.Everything())
}

func (wf *WatchFactory) CertificateSigningRequestInformer() certificatesinformers.CertificateSigningRequestInformer {
	return wf.iFactory.Certificates().V1().CertificateSigningRequests()
}

// GetIPAMClaim gets a specific IPAMClaim by the namespace/name
func (wf *WatchFactory) GetIPAMClaim(namespace, name string) (*ipamclaimsapi.IPAMClaim, error) {
	ipamClaimsLister := wf.informers[IPAMClaimsType].lister.(ipamclaimslister.IPAMClaimLister)
	return ipamClaimsLister.IPAMClaims(namespace).Get(name)
}

// GetNAD gets a specific NAD by the namespace/name
func (wf *WatchFactory) GetNAD(namespace, name string) (*nadapi.NetworkAttachmentDefinition, error) {
	nadLister := wf.informers[NetworkAttachmentDefinitionType].lister.(nadlister.NetworkAttachmentDefinitionLister)
	return nadLister.NetworkAttachmentDefinitions(namespace).Get(name)
}

// GetNAD gets all NADs by the namespace
func (wf *WatchFactory) GetNADs(namespace string) ([]*nadapi.NetworkAttachmentDefinition, error) {
	nadLister := wf.informers[NetworkAttachmentDefinitionType].lister.(nadlister.NetworkAttachmentDefinitionLister)
	return nadLister.NetworkAttachmentDefinitions(namespace).List(labels.Everything())
}

func (wf *WatchFactory) NodeInformer() cache.SharedIndexInformer {
	return wf.informers[NodeType].inf
}

func (wf *WatchFactory) NodeCoreInformer() v1coreinformers.NodeInformer {
	return wf.iFactory.Core().V1().Nodes()
}

// LocalPodInformer returns a shared Informer that may or may not only
// return pods running on the local node.
func (wf *WatchFactory) LocalPodInformer() cache.SharedIndexInformer {
	return wf.informers[PodType].inf
}

func (wf *WatchFactory) PodInformer() cache.SharedIndexInformer {
	return wf.informers[PodType].inf
}

func (wf *WatchFactory) PodCoreInformer() v1coreinformers.PodInformer {
	return wf.iFactory.Core().V1().Pods()
}

func (wf *WatchFactory) NamespaceInformer() v1coreinformers.NamespaceInformer {
	return wf.iFactory.Core().V1().Namespaces()
}

func (wf *WatchFactory) NamespaceCoreInformer() v1coreinformers.NamespaceInformer {
	return wf.iFactory.Core().V1().Namespaces()
}

func (wf *WatchFactory) ServiceInformer() cache.SharedIndexInformer {
	return wf.informers[ServiceType].inf
}

func (wf *WatchFactory) ServiceCoreInformer() v1coreinformers.ServiceInformer {
	return wf.iFactory.Core().V1().Services()
}

func (wf *WatchFactory) EndpointSliceInformer() cache.SharedIndexInformer {
	return wf.informers[EndpointSliceType].inf
}

func (wf *WatchFactory) EndpointSliceCoreInformer() discoveryinformers.EndpointSliceInformer {
	return wf.iFactory.Discovery().V1().EndpointSlices()
}

func (wf *WatchFactory) EgressQoSInformer() egressqosinformer.EgressQoSInformer {
	return wf.egressQoSFactory.K8s().V1().EgressQoSes()
}

func (wf *WatchFactory) EgressServiceInformer() egressserviceinformer.EgressServiceInformer {
	return wf.egressServiceFactory.K8s().V1().EgressServices()
}

func (wf *WatchFactory) APBRouteInformer() adminpolicybasedrouteinformer.AdminPolicyBasedExternalRouteInformer {
	return wf.apbRouteFactory.K8s().V1().AdminPolicyBasedExternalRoutes()
}

func (wf *WatchFactory) ANPInformer() anpinformer.AdminNetworkPolicyInformer {
	return wf.anpFactory.Policy().V1alpha1().AdminNetworkPolicies()
}

func (wf *WatchFactory) BANPInformer() anpinformer.BaselineAdminNetworkPolicyInformer {
	return wf.anpFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies()
}

func (wf *WatchFactory) EgressIPInformer() egressipinformer.EgressIPInformer {
	return wf.eipFactory.K8s().V1().EgressIPs()
}

func (wf *WatchFactory) EgressFirewallInformer() egressfirewallinformer.EgressFirewallInformer {
	return wf.efFactory.K8s().V1().EgressFirewalls()
}

func (wf *WatchFactory) IPAMClaimsInformer() ipamclaimsinformer.IPAMClaimInformer {
	return wf.ipamClaimsFactory.K8s().V1alpha1().IPAMClaims()
}

func (wf *WatchFactory) NADInformer() nadinformer.NetworkAttachmentDefinitionInformer {
	return wf.nadFactory.K8sCniCncfIo().V1().NetworkAttachmentDefinitions()
}

func (wf *WatchFactory) UserDefinedNetworkInformer() userdefinednetworkinformer.UserDefinedNetworkInformer {
	return wf.udnFactory.K8s().V1().UserDefinedNetworks()
}

func (wf *WatchFactory) ClusterUserDefinedNetworkInformer() userdefinednetworkinformer.ClusterUserDefinedNetworkInformer {
	return wf.udnFactory.K8s().V1().ClusterUserDefinedNetworks()
}

func (wf *WatchFactory) DNSNameResolverInformer() ocpnetworkinformerv1alpha1.DNSNameResolverInformer {
	return wf.dnsFactory.Network().V1alpha1().DNSNameResolvers()
}

func (wf *WatchFactory) RouteAdvertisementsInformer() routeadvertisementsinformer.RouteAdvertisementsInformer {
	return wf.raFactory.K8s().V1().RouteAdvertisements()
}

func (wf *WatchFactory) FRRConfigurationsInformer() frrinformer.FRRConfigurationInformer {
	return wf.frrFactory.Api().V1beta1().FRRConfigurations()
}

func (wf *WatchFactory) NetworkQoSInformer() networkqosinformer.NetworkQoSInformer {
	return wf.networkQoSFactory.K8s().V1alpha1().NetworkQoSes()
}

// withServiceNameAndNoHeadlessServiceSelector returns a LabelSelector (added to the
// watcher for EndpointSlices) that will only choose EndpointSlices with a non-empty
// "kubernetes.io/service-name" label and without "service.kubernetes.io/headless"
// label.
func withServiceNameAndNoHeadlessServiceSelector() func(options *metav1.ListOptions) {
	// LabelServiceName must exist
	svcNameLabel, err := labels.NewRequirement(discovery.LabelServiceName, selection.Exists, nil)
	if err != nil {
		// cannot occur
		panic(err)
	}
	// LabelServiceName value must be non-empty
	notEmptySvcName, err := labels.NewRequirement(discovery.LabelServiceName, selection.NotEquals, []string{""})
	if err != nil {
		// cannot occur
		panic(err)
	}
	// headless service label must not be there
	noHeadlessService, err := labels.NewRequirement(corev1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		// cannot occur
		panic(err)
	}

	selector := labels.NewSelector().Add(*svcNameLabel, *notEmptySvcName, *noHeadlessService)

	return func(options *metav1.ListOptions) {
		options.LabelSelector = selector.String()
	}
}

// noHeadlessServiceSelector returns a LabelSelector (added to the
// watcher for EndpointSlices) that will only choose EndpointSlices without "service.kubernetes.io/headless"
// label.
func noHeadlessServiceSelector() func(options *metav1.ListOptions) {
	// headless service label must not be there
	noHeadlessService, err := labels.NewRequirement(corev1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		// cannot occur
		panic(err)
	}

	return func(options *metav1.ListOptions) {
		options.LabelSelector = noHeadlessService.String()
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

// WithUpdateHandlingForObjReplace decorates given cache.ResourceEventHandler with checking object
// replace case in the update event. when old and new object have different UIDs, then consider it
// as a replace and invoke delete handler for old object followed by add handler for new object.
func WithUpdateHandlingForObjReplace(funcs cache.ResourceEventHandler) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			funcs.OnAdd(obj, false)
		},
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(metav1.Object)
			newObj := new.(metav1.Object)
			if oldObj.GetUID() == newObj.GetUID() {
				funcs.OnUpdate(old, new)
				return
			}
			// This occurs not so often, so log this occurance.
			klog.Infof("Object %s/%s is replaced, invoking delete followed by add handler", newObj.GetNamespace(), newObj.GetName())
			funcs.OnDelete(old)
			funcs.OnAdd(new, false)
		},
		DeleteFunc: func(obj interface{}) {
			funcs.OnDelete(obj)
		},
	}
}

type waitForCacheSyncer interface {
	WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool
}

func waitForCacheSyncWithTimeout(factory waitForCacheSyncer, stopCh <-chan struct{}) map[reflect.Type]bool {
	// Give some small time for sync. It helps significantly reduce unit tests time
	time.Sleep(5 * time.Millisecond)
	return factory.WaitForCacheSync(util.GetChildStopChanWithTimeout(stopCh, types.InformerSyncTimeout))
}

// getEndpointSliceSelector returns an EndpointSlice selector function used in watchers.
// When network segmentation is enabled it returns a selector that ignores EndpointSlices for headless services.
// Otherwise, it returns a selector that excludes EndpointSlices a with missing default service name too.
func getEndpointSliceSelector() func(options *metav1.ListOptions) {
	endpointSliceSelector := withServiceNameAndNoHeadlessServiceSelector()
	if util.IsNetworkSegmentationSupportEnabled() {
		// When network segmentation is enabled we need to watch for mirrored EndpointSlices that do not contain the
		// default service name.
		endpointSliceSelector = noHeadlessServiceSelector()
	}
	return endpointSliceSelector
}
