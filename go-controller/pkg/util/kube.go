package util

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	kapi "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	egressfirewallclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned"
	egressipclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	ocpcloudnetworkclientset "github.com/openshift/client-go/cloudnetwork/clientset/versioned"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

// OVNClientset is a wrapper around all clientsets used by OVN-Kubernetes
type OVNClientset struct {
	KubeClient           kubernetes.Interface
	EgressIPClient       egressipclientset.Interface
	EgressFirewallClient egressfirewallclientset.Interface
	CloudNetworkClient   ocpcloudnetworkclientset.Interface
}

func adjustCommit() string {
	if len(config.Commit) < 12 {
		return "unknown"
	}
	return config.Commit[:12]
}

func adjustNodeName() string {
	hostName, err := os.Hostname()
	if err != nil {
		hostName = "unknown"
	}
	return hostName
}

// newKubernetesRestConfig create a Kubernetes rest config from either a kubeconfig,
// TLS properties, or an apiserver URL. If the CA certificate data is passed in the
// CAData in the KubernetesConfig, the CACert path is ignored.
func newKubernetesRestConfig(conf *config.KubernetesConfig) (*rest.Config, error) {
	var kconfig *rest.Config
	var err error

	if conf.Kubeconfig != "" {
		// uses the current context in kubeconfig
		kconfig, err = clientcmd.BuildConfigFromFlags("", conf.Kubeconfig)
	} else if strings.HasPrefix(conf.APIServer, "https") {
		if conf.Token == "" || len(conf.CAData) == 0 {
			return nil, fmt.Errorf("TLS-secured apiservers require token and CA certificate")
		}
		if _, err := cert.NewPoolFromBytes(conf.CAData); err != nil {
			return nil, err
		}
		kconfig = &rest.Config{
			Host:            conf.APIServer,
			BearerToken:     conf.Token,
			BearerTokenFile: conf.TokenFile,
			TLSClientConfig: rest.TLSClientConfig{CAData: conf.CAData},
		}
	} else if strings.HasPrefix(conf.APIServer, "http") {
		kconfig, err = clientcmd.BuildConfigFromFlags(conf.APIServer, "")
	} else {
		// Assume we are running from a container managed by kubernetes
		// and read the apiserver address and tokens from the
		// container's environment.
		kconfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	kconfig.QPS = 50
	kconfig.Burst = 50
	// if all the clients are behind HA-Proxy, then on the K8s API server side we only
	// see the HAProxy's IP and we can't tell the actual client making the request.
	kconfig.UserAgent = fmt.Sprintf("%s/%s@%s (%s/%s) kubernetes/%s",
		adjustNodeName(), filepath.Base(os.Args[0]), adjustCommit(), runtime.GOOS, runtime.GOARCH,
		version.Get().GitVersion)
	return kconfig, nil
}

// NewKubernetesClientset creates a Kubernetes clientset from a KubernetesConfig
func NewKubernetesClientset(conf *config.KubernetesConfig) (*kubernetes.Clientset, error) {
	kconfig, err := newKubernetesRestConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes rest config, err: %v", err)
	}
	kconfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	kconfig.ContentType = "application/vnd.kubernetes.protobuf"
	clientset, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

// NewOVNClientset creates a OVNClientset from a KubernetesConfig
func NewOVNClientset(conf *config.KubernetesConfig) (*OVNClientset, error) {
	kclientset, err := NewKubernetesClientset(conf)
	if err != nil {
		return nil, err
	}
	kconfig, err := newKubernetesRestConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes rest config, err: %v", err)
	}
	egressFirewallClientset, err := egressfirewallclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	egressIPClientset, err := egressipclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	cloudNetworkClientset, err := ocpcloudnetworkclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	return &OVNClientset{
		KubeClient:           kclientset,
		EgressIPClient:       egressIPClientset,
		EgressFirewallClient: egressFirewallClientset,
		CloudNetworkClient:   cloudNetworkClientset,
	}, nil
}

// IsClusterIPSet checks if the service is an headless service or not
func IsClusterIPSet(service *kapi.Service) bool {
	return service.Spec.ClusterIP != kapi.ClusterIPNone && service.Spec.ClusterIP != ""
}

// GetClusterIPs return an array with the ClusterIPs present in the service
// for backward compatibility with versions < 1.20
// we need to handle the case where only ClusterIP exist
func GetClusterIPs(service *kapi.Service) []string {
	if len(service.Spec.ClusterIPs) > 0 {
		return service.Spec.ClusterIPs
	}
	if len(service.Spec.ClusterIP) > 0 && service.Spec.ClusterIP != kapi.ClusterIPNone {
		return []string{service.Spec.ClusterIP}
	}
	return []string{}
}

// GetExternalAndLBIPs returns an array with the ExternalIPs and LoadBalancer IPs present in the service
func GetExternalAndLBIPs(service *kapi.Service) []string {
	svcVIPs := []string{}
	svcVIPs = append(svcVIPs, service.Spec.ExternalIPs...)
	if ServiceTypeHasLoadBalancer(service) {
		for _, ingressVIP := range service.Status.LoadBalancer.Ingress {
			if len(ingressVIP.IP) > 0 {
				svcVIPs = append(svcVIPs, ingressVIP.IP)
			}
		}
	}
	return svcVIPs
}

// ValidatePort checks if the port is non-zero and port protocol is valid
func ValidatePort(proto kapi.Protocol, port int32) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port number: %v", port)
	}
	return ValidateProtocol(proto)
}

// ValidateProtocol checks if the protocol is a valid kapi.Protocol type (TCP, UDP, or SCTP) or returns an error
func ValidateProtocol(proto kapi.Protocol) error {
	if proto == kapi.ProtocolTCP || proto == kapi.ProtocolUDP || proto == kapi.ProtocolSCTP {
		return nil
	}
	return fmt.Errorf("protocol %s is not a valid protocol", proto)
}

// ServiceTypeHasClusterIP checks if the service has an associated ClusterIP or not
func ServiceTypeHasClusterIP(service *kapi.Service) bool {
	return service.Spec.Type == kapi.ServiceTypeClusterIP || service.Spec.Type == kapi.ServiceTypeNodePort || service.Spec.Type == kapi.ServiceTypeLoadBalancer
}

// ServiceTypeHasNodePort checks if the service has an associated NodePort or not
func ServiceTypeHasNodePort(service *kapi.Service) bool {
	return service.Spec.Type == kapi.ServiceTypeNodePort || service.Spec.Type == kapi.ServiceTypeLoadBalancer
}

// ServiceTypeHasLoadBalancer checks if the service has an associated LoadBalancer or not
func ServiceTypeHasLoadBalancer(service *kapi.Service) bool {
	return service.Spec.Type == kapi.ServiceTypeLoadBalancer
}

func ServiceExternalTrafficPolicyLocal(service *kapi.Service) bool {
	return service.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeLocal
}

func ServiceInternalTrafficPolicyLocal(service *kapi.Service) bool {
	return service.Spec.InternalTrafficPolicy != nil && *service.Spec.InternalTrafficPolicy == kapi.ServiceInternalTrafficPolicyLocal
}

// GetNodePrimaryIP extracts the primary IP address from the node status in the  API
func GetNodePrimaryIP(node *kapi.Node) (string, error) {
	if node == nil {
		return "", fmt.Errorf("invalid node object")
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == kapi.NodeInternalIP {
			return addr.Address, nil
		}
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == kapi.NodeExternalIP {
			return addr.Address, nil
		}
	}
	return "", fmt.Errorf("%s doesn't have an address with type %s or %s", node.GetName(),
		kapi.NodeInternalIP, kapi.NodeExternalIP)
}

// PodWantsNetwork returns if the given pod is hostNetworked or not to determine if networking
// needs to be setup
func PodWantsNetwork(pod *kapi.Pod) bool {
	return !pod.Spec.HostNetwork
}

// PodCompleted checks if the pod is marked as completed (in a terminal state)
func PodCompleted(pod *kapi.Pod) bool {
	return pod.Status.Phase == kapi.PodSucceeded || pod.Status.Phase == kapi.PodFailed
}

// PodScheduled returns if the given pod is scheduled
func PodScheduled(pod *kapi.Pod) bool {
	return pod.Spec.NodeName != ""
}

// EventRecorder returns an EventRecorder type that can be
// used to post Events to different object's lifecycles.
func EventRecorder(kubeClient kubernetes.Interface) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(
		&typedcorev1.EventSinkImpl{
			Interface: kubeClient.CoreV1().Events(""),
		})
	recorder := eventBroadcaster.NewRecorder(
		scheme.Scheme,
		kapi.EventSource{Component: "controlplane"})
	return recorder
}

// UseEndpointSlices detect if Endpoints Slices are enabled in the cluster
func UseEndpointSlices(kubeClient kubernetes.Interface) bool {
	if _, err := kubeClient.Discovery().ServerResourcesForGroupVersion(discovery.SchemeGroupVersion.String()); err == nil {
		klog.V(2).Infof("Kubernetes Endpoint Slices enabled on the cluster: %s", discovery.SchemeGroupVersion.String())
		return true
	}
	return false
}

type LbEndpoints struct {
	V4IPs []string
	V6IPs []string
	Port  int32
}

// GetLbEndpoints return the endpoints that belong to the IPFamily as a slice of IPs
func GetLbEndpoints(slices []*discovery.EndpointSlice, svcPort kapi.ServicePort) LbEndpoints {
	v4ips := sets.NewString()
	v6ips := sets.NewString()

	out := LbEndpoints{}
	// return an empty object so the caller don't have to check for nil and can use it as an iterator
	if len(slices) == 0 {
		return out
	}

	for _, slice := range slices {
		klog.V(4).Infof("Getting endpoints for slice %s/%s", slice.Namespace, slice.Name)

		// build the list of endpoints in the slice
		for _, port := range slice.Ports {
			// If Service port name set it must match the name field in the endpoint
			// If Service port name is not set we just use the endpoint port
			if svcPort.Name != "" && svcPort.Name != *port.Name {
				klog.V(5).Infof("Slice %s with different Port name, requested: %s received: %s",
					slice.Name, svcPort.Name, *port.Name)
				continue
			}

			// Skip ports that doesn't match the protocol
			if *port.Protocol != svcPort.Protocol {
				klog.V(5).Infof("Slice %s with different Port protocol, requested: %s received: %s",
					slice.Name, svcPort.Protocol, *port.Protocol)
				continue
			}

			out.Port = *port.Port
			for _, endpoint := range slice.Endpoints {
				// Skip endpoints that are not ready
				if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
					klog.V(4).Infof("Slice endpoints Not Ready")
					continue
				}
				for _, ip := range endpoint.Addresses {
					klog.V(4).Infof("Adding slice %s endpoints: %v, port: %d", slice.Name, endpoint.Addresses, *port.Port)
					switch slice.AddressType {
					case discovery.AddressTypeIPv4:
						v4ips.Insert(ip)
					case discovery.AddressTypeIPv6:
						v6ips.Insert(ip)
					default:
						klog.V(5).Infof("Skipping FQDN slice %s/%s", slice.Namespace, slice.Name)
					}
				}
			}
		}
	}

	out.V4IPs = v4ips.List()
	out.V6IPs = v6ips.List()
	klog.V(4).Infof("LB Endpoints for %s/%s are: %v / %v on port: %d",
		slices[0].Namespace, slices[0].Labels[discovery.LabelServiceName],
		out.V4IPs, out.V6IPs, out.Port)
	return out
}

type K8sObject interface {
	metav1.Object
	k8sruntime.Object
}

func ExternalIDsForObject(obj K8sObject) map[string]string {
	gk := obj.GetObjectKind().GroupVersionKind().GroupKind()
	nsn := k8stypes.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}

	if gk.String() == "" {
		kinds, _, err := scheme.Scheme.ObjectKinds(obj)
		if err != nil || len(kinds) == 0 || len(kinds) > 1 {
			klog.Warningf("BUG: object has no / ambiguous GVK: %#v, err", obj, err)
		}
		gk = kinds[0].GroupKind()
	}

	return map[string]string{
		types.OvnK8sPrefix + "/owner": nsn.String(),
		types.OvnK8sPrefix + "/kind":  gk.String(),
	}
}
