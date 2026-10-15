package infraprovider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ovnkconfig "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/portalloc"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
)

// Names of the OpenShift cluster feature gates the e2e suites depend on.
const (
	evpnFeatureGateName = "EVPN"
	// NoOverlayMode gates both the default network transport field and the
	// per-network no-overlay configuration on (C)UDNs.
	noOverlayFeatureGateName = "NoOverlayMode"
)

type OpenshiftInfraProvider struct {
	clusterFeatureGate      *configv1.FeatureGate
	operNetwork             *operv1.Network
	hasFRRExternalContainer bool
	hostPort                *portalloc.PortAllocator
	clusterInfra            *baremetalInfra
}

func New(config *rest.Config) (*OpenshiftInfraProvider, error) {
	ovnkconfig.Kubernetes.DNSServiceNamespace = "openshift-dns"
	ovnkconfig.Kubernetes.DNSServiceName = "dns-default"
	clusterInfra, err := initializeClusterInfra(config)
	if err != nil {
		return nil, err
	}
	o := &OpenshiftInfraProvider{
		hostPort:     portalloc.New(30000, 32767),
		clusterInfra: clusterInfra,
	}
	if err = o.initClusterObjects(config); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *OpenshiftInfraProvider) initClusterObjects(config *rest.Config) error {
	configClient, err := configclient.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to retrieve config client: %w", err)
	}
	operatorClient, err := operatorv1client.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to retrieve operator client: %w", err)
	}
	o.operNetwork, err = operatorClient.OperatorV1().Networks().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to retrieve network operator cluster object: %w", err)
		}
		o.operNetwork = nil
	}
	o.clusterFeatureGate, err = configClient.ConfigV1().FeatureGates().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to retrieve cluster feature gate: %w", err)
		}
		o.clusterFeatureGate = nil
	}
	// check ovn gateway mode and export required env variable
	o.configureOVNGatewayMode()
	if o.clusterInfra != nil {
		// check for frr external container availability
		frrContainer := api.ExternalContainer{Name: externalFRRContainerName}
		output, _ := o.clusterInfra.ExecExternalContainerCommand(frrContainer, []string{"hostname"})
		o.hasFRRExternalContainer = output != ""
	}
	return nil
}

// configureOVNGatewayMode detects and configures the OVN gateway mode for tests
func (o *OpenshiftInfraProvider) configureOVNGatewayMode() {
	if o.operNetwork == nil || o.operNetwork.Spec.DefaultNetwork.OVNKubernetesConfig == nil {
		return
	}

	if o.operNetwork.Spec.DefaultNetwork.OVNKubernetesConfig.GatewayConfig != nil &&
		o.operNetwork.Spec.DefaultNetwork.OVNKubernetesConfig.GatewayConfig.RoutingViaHost {
		// The E2E utility method isLocalGWModeEnabled depends on the
		// OVN_GATEWAY_MODE environment variable. All EVPN tests must
		// satisfy this condition; otherwise, they will be skipped.
		_ = os.Setenv("OVN_GATEWAY_MODE", "local")
	}
}

// CheckForEVPN checks all EVPN prerequisites
func (o *OpenshiftInfraProvider) CheckForEVPN() bool {
	if o.operNetwork == nil {
		return false
	}
	return hasFeatureGate(o.clusterFeatureGate, evpnFeatureGateName) &&
		hasFRRRouteProvider(o.operNetwork) &&
		isLocalGatewayMode(o.operNetwork) &&
		o.hasFRRExternalContainer
}

// CheckForRouteAdvertisements checks the prerequisites shared by every BGP e2e:
// the cluster must advertise routes through FRR and an external FRR router must
// be reachable to inspect the advertised routes with.
func (o *OpenshiftInfraProvider) CheckForRouteAdvertisements() bool {
	if o.operNetwork == nil {
		return false
	}
	return hasFRRRouteProvider(o.operNetwork) &&
		hasRouteAdvertisementsEnabled(o.operNetwork) &&
		o.hasFRRExternalContainer
}

// CheckForNoOverlay reports whether the cluster can run no-overlay specs. These
// configure no-overlay per network (for example on a CUDN), which needs the
// NoOverlayMode feature gate and route advertisements through FRR.
//
// Deliberately not CheckForRouteAdvertisements: that one also demands an
// external FRR router, and no-overlay with managed routing peers the nodes with
// each other only, so it needs no router outside the cluster. Specs that do
// inspect the external router carry Feature:RouteAdvertisements and are gated on
// it separately.
//
// Specs exercising no-overlay on the cluster default network additionally need
// IsDefaultNetworkNoOverlay, and specs using managed routing need HasManagedBGP.
func (o *OpenshiftInfraProvider) CheckForNoOverlay() bool {
	if o.operNetwork == nil {
		return false
	}
	return hasFeatureGate(o.clusterFeatureGate, noOverlayFeatureGateName) &&
		hasFRRRouteProvider(o.operNetwork) &&
		hasRouteAdvertisementsEnabled(o.operNetwork)
}

// HasManagedBGP reports whether the cluster is configured with the internal BGP
// fabric that no-overlay networks with managed routing peer over. ovn-kubernetes
// requires a topology to be set before it will run its managed BGP controller
// (see ManagedBGPConfig.Topology, "Required when transport=no-overlay and
// routing=managed"), and on OpenShift that is rendered from bgpManagedConfig.
//
// Note that a cluster can have managed CUDNs without the cluster default network
// itself being managed, so this is independent of IsDefaultNetworkNoOverlay.
func (o *OpenshiftInfraProvider) HasManagedBGP() bool {
	if o.operNetwork == nil || o.operNetwork.Spec.DefaultNetwork.OVNKubernetesConfig == nil {
		return false
	}
	return o.operNetwork.Spec.DefaultNetwork.OVNKubernetesConfig.BGPManagedConfig.BGPTopology != ""
}

// IsDefaultNetworkNoOverlay reports whether the cluster default network itself
// runs unencapsulated. Transport is immutable after installation, so this is a
// property of how the cluster was installed, not something a test can turn on.
func (o *OpenshiftInfraProvider) IsDefaultNetworkNoOverlay() bool {
	if o.operNetwork == nil || o.operNetwork.Spec.DefaultNetwork.OVNKubernetesConfig == nil {
		return false
	}
	return o.operNetwork.Spec.DefaultNetwork.OVNKubernetesConfig.Transport == operv1.TransportOptionNoOverlay
}

// hasFeatureGate checks if the named feature gate is enabled in the cluster
func hasFeatureGate(clusterFeatureGate *configv1.FeatureGate, name string) bool {
	if clusterFeatureGate == nil {
		return false
	}
	for _, featureGate := range clusterFeatureGate.Status.FeatureGates {
		for _, feature := range featureGate.Enabled {
			if string(feature.Name) == name {
				return true
			}
		}
	}
	return false
}

// hasRouteAdvertisementsEnabled checks if the cluster advertises its network
// routes through a dynamic routing protocol.
func hasRouteAdvertisementsEnabled(network *operv1.Network) bool {
	if network.Spec.DefaultNetwork.OVNKubernetesConfig == nil {
		return false
	}
	return network.Spec.DefaultNetwork.OVNKubernetesConfig.RouteAdvertisements == operv1.RouteAdvertisementsEnabled
}

// hasFRRRouteProvider checks if FRR is configured as a routing capability provider.
func hasFRRRouteProvider(network *operv1.Network) bool {
	if network.Spec.AdditionalRoutingCapabilities == nil {
		return false
	}

	for _, raProvider := range network.Spec.AdditionalRoutingCapabilities.Providers {
		if raProvider == operv1.RoutingCapabilitiesProviderFRR {
			return true
		}
	}
	return false
}

// isLocalGatewayMode checks if OVN is configured with local gateway mode (routing via host).
func isLocalGatewayMode(network *operv1.Network) bool {
	if network.Spec.DefaultNetwork.OVNKubernetesConfig == nil {
		return false
	}

	return network.Spec.DefaultNetwork.OVNKubernetesConfig.GatewayConfig != nil &&
		network.Spec.DefaultNetwork.OVNKubernetesConfig.GatewayConfig.RoutingViaHost
}

func (o *OpenshiftInfraProvider) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	if o.clusterInfra == nil {
		panic("not implemented")
	}
	return o.clusterInfra.GetExternalContainerNetworkInterface(container, network)
}

func (o *OpenshiftInfraProvider) ShutdownNode(nodeName string) error {
	panic("not implemented")
}

func (o *OpenshiftInfraProvider) StartNode(nodeName string) error {
	panic("not implemented")
}

func (o *OpenshiftInfraProvider) GetDefaultTimeoutContext() *framework.TimeoutContext {
	timeouts := framework.NewTimeoutContext()
	timeouts.PodStart = 10 * time.Minute
	return timeouts
}

func (o OpenshiftInfraProvider) PreloadImages(images []string) {
	// no-op: OpenShift clusters pull images at runtime
}

func (o *OpenshiftInfraProvider) Name() string {
	return "openshift"
}

func (o *OpenshiftInfraProvider) PrimaryNetwork() (api.Network, error) {
	if o.clusterInfra == nil {
		panic("not implemented")
	}
	return o.clusterInfra.GetNetwork(primaryNetworkName)
}

func (o *OpenshiftInfraProvider) GetNetwork(name string) (api.Network, error) {
	if o.clusterInfra == nil {
		panic("not implemented")
	}
	return o.clusterInfra.GetNetwork(name)

}

func (o *OpenshiftInfraProvider) GetK8HostPort() uint16 {
	return o.hostPort.Allocate()
}

func (o *OpenshiftInfraProvider) GetK8NodeNetworkInterface(instance string, network api.Network) (api.NetworkInterface, error) {
	panic("not implemented")
}

func (o *OpenshiftInfraProvider) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("insufficient command arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd = append([]string{"debug", fmt.Sprintf("node/%s", nodeName), "--to-namespace=default",
		"--", "chroot", "/host"}, cmd...)
	ocDebugCmd := exec.CommandContext(ctx, "oc", cmd...)
	var stdout, stderr bytes.Buffer
	ocDebugCmd.Stdout = &stdout
	ocDebugCmd.Stderr = &stderr

	if err := ocDebugCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to run command %q on node %s: %v, stdout: %s, stderr: %s", ocDebugCmd.String(), nodeName, err, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

func (o *OpenshiftInfraProvider) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	if o.clusterInfra == nil {
		panic("not implemented")
	}
	return o.clusterInfra.ExecExternalContainerCommand(container, cmd)
}

func (o *OpenshiftInfraProvider) ExternalContainerPrimaryInterfaceName() string {
	if o.clusterInfra == nil {
		panic("not implemented")
	}
	return o.clusterInfra.ExternalContainerPrimaryInterfaceName()
}

func (o *OpenshiftInfraProvider) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	if o.clusterInfra == nil {
		panic("not implemented")
	}
	return o.clusterInfra.GetExternalContainerLogs(container)
}

func (o *OpenshiftInfraProvider) GetExternalContainerPort() uint16 {
	if o.clusterInfra == nil {
		panic("not implemented")
	}
	return o.clusterInfra.GetExternalContainerPort()
}

func (o *OpenshiftInfraProvider) ListNetworks() ([]string, error) {
	if o.clusterInfra == nil {
		panic("not implemented")
	}
	return o.clusterInfra.ListNetworks()
}

func (o *OpenshiftInfraProvider) NewTestContext() api.Context {
	context := &testcontext.TestContext{}
	ginkgo.DeferCleanup(context.CleanUp)
	co := &contextOpenshift{
		TestContext: context,
	}
	if o.clusterInfra != nil {
		co.externalContainerContextProvider = o.clusterInfra.GetExternalContainerContextProvider(context)
	}
	return co
}

type contextOpenshift struct {
	*testcontext.TestContext
	externalContainerContextProvider api.ExternalContainerContextProvider
}

func (o *contextOpenshift) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	if o.externalContainerContextProvider == nil {
		panic("not implemented")
	}
	return o.externalContainerContextProvider.CreateExternalContainer(container)
}

func (o *contextOpenshift) DeleteExternalContainer(container api.ExternalContainer) error {
	if o.externalContainerContextProvider == nil {
		panic("not implemented")
	}
	return o.externalContainerContextProvider.DeleteExternalContainer(container)
}

func (o *contextOpenshift) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	if o.externalContainerContextProvider == nil {
		panic("not implemented")
	}
	return o.externalContainerContextProvider.CreateNetwork(name, subnets...)
}

func (o *contextOpenshift) AttachNetwork(network api.Network, container string) (api.NetworkInterface, error) {
	if o.externalContainerContextProvider == nil {
		panic("not implemented")
	}
	return o.externalContainerContextProvider.AttachNetwork(network, container)
}

func (o *contextOpenshift) DetachNetwork(network api.Network, container string) error {
	if o.externalContainerContextProvider == nil {
		panic("not implemented")
	}
	return o.externalContainerContextProvider.DetachNetwork(network, container)
}

func (o *contextOpenshift) DeleteNetwork(network api.Network) error {
	if o.externalContainerContextProvider == nil {
		panic("not implemented")
	}
	return o.externalContainerContextProvider.DeleteNetwork(network)
}

func (o *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	panic("not implemented")
}
