package infraprovider

import (
	"bytes"
	"context"
	"fmt"
	"net"
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
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	deploymentconfigapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/portalloc"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
)

type OpenshiftInfraProvider struct {
	restConfig              *rest.Config
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
		restConfig:   config,
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
	// export a subnet-exhaustion CIDR that does not overlap the cluster network
	o.configureKubevirtSubnetExhaustionCIDR()
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
	// Add the agnhost image to the required images
	deploymentconfig.Get().AddImage(images.Agnhost)
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

// kubevirtSubnetExhaustionCIDRIPv4Env is the environment variable the upstream
// kubevirt "ipv4 subnet exhaustion" test reads to override its default IPv4
// CUDN subnet. Must stay in sync with test/e2e/kubevirt.go.
const kubevirtSubnetExhaustionCIDRIPv4Env = "OVN_TEST_KV_SUBNET_EXHAUSTION_CIDR_IPV4"

// configureKubevirtSubnetExhaustionCIDR points the kubevirt subnet-exhaustion
// test at a /30 that does not overlap the cluster default network. The upstream
// default (10.130.0.0/30) overlaps OpenShift's default cluster network
// (10.128.0.0/14), which makes CUDN creation fail upfront with a
// NetworkAttachmentDefinitionSyncError before the allocation path under test is
// reached. A /30 has no usable host IPs once the gateway and broadcast/network
// addresses are reserved, so it still forces exhaustion.
func (o *OpenshiftInfraProvider) configureKubevirtSubnetExhaustionCIDR() {
	const candidate = "192.168.222.0/30"
	if o.clusterNetworkOverlaps(candidate) {
		// Extremely unlikely for the cluster network to use this RFC1918 /24;
		// leave the upstream default in place rather than guessing further.
		return
	}
	_ = os.Setenv(kubevirtSubnetExhaustionCIDRIPv4Env, candidate)
}

// clusterNetworkOverlaps reports whether cidr overlaps any configured cluster
// network entry. On any parsing problem it conservatively returns true so the
// caller keeps the upstream default.
func (o *OpenshiftInfraProvider) clusterNetworkOverlaps(cidr string) bool {
	_, candidate, err := net.ParseCIDR(cidr)
	if err != nil {
		return true
	}
	if o.operNetwork == nil {
		return false
	}
	for _, entry := range o.operNetwork.Spec.ClusterNetwork {
		_, clusterNet, err := net.ParseCIDR(entry.CIDR)
		if err != nil {
			return true
		}
		if clusterNet.Contains(candidate.IP) || candidate.Contains(clusterNet.IP) {
			return true
		}
	}
	return false
}

// CheckForEVPN checks all EVPN prerequisites
func (o *OpenshiftInfraProvider) CheckForEVPN() bool {
	if o.operNetwork == nil {
		return false
	}
	return hasEVPNFeatureGate(o.clusterFeatureGate) &&
		hasFRRRouteProvider(o.operNetwork) &&
		isLocalGatewayMode(o.operNetwork) &&
		o.hasFRRExternalContainer
}

// hasEVPNFeatureGate checks if the EVPN feature gate is enabled in the cluster
func hasEVPNFeatureGate(clusterFeatureGate *configv1.FeatureGate) bool {
	if clusterFeatureGate == nil {
		return false
	}
	for _, featureGate := range clusterFeatureGate.Status.FeatureGates {
		for _, feature := range featureGate.Enabled {
			if feature.Name == "EVPN" {
				return true
			}
		}
	}
	return false
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

func (o OpenshiftInfraProvider) ShouldPruneKubeVirtImages() bool {
	return false
}

func (o OpenshiftInfraProvider) PreloadImages(images []deploymentconfigapi.ImageConfig) {
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
