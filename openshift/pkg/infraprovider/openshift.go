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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	ovnkconfig "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/portalloc"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
)

type OpenshiftInfraProvider struct {
	clusterFeatureGate      *configv1.FeatureGate
	operNetwork             *operv1.Network
	hasFRRExternalContainer bool
	hostPort                *portalloc.PortAllocator
	clusterInfra            *baremetalInfra
	kubeClient              kubernetes.Interface
}

func New(config *rest.Config) (*OpenshiftInfraProvider, error) {
	ovnkconfig.Kubernetes.DNSServiceNamespace = "openshift-dns"
	ovnkconfig.Kubernetes.DNSServiceName = "dns-default"
	clusterInfra, err := initializeClusterInfra(config)
	if err != nil {
		return nil, err
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	o := &OpenshiftInfraProvider{
		hostPort:     portalloc.New(30000, 32767),
		clusterInfra: clusterInfra,
		kubeClient:   kubeClient,
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
		os.Setenv("OVN_GATEWAY_MODE", "local")
	}
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

const (
	nodeRebootNotReadyTimeout = 5 * time.Minute
	nodeRebootReadyTimeout    = 10 * time.Minute
	nodeRebootPollInterval    = 10 * time.Second
)

// RebootNode restarts the OpenShift node via `oc debug node/<name> -- chroot /host systemctl reboot`
// and blocks until the node returns to Ready.
//
// The Kubernetes API is used to confirm the node is Ready before issuing the reboot,
// then to wait for it to go NotReady (reboot in progress) and come back Ready.
// systemctl reboot kills the oc debug session immediately, so the command always
// returns a non-zero exit; that error is logged but not returned.
func (o *OpenshiftInfraProvider) RebootNode(nodeName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	node, err := o.kubeClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get node %q before reboot: %w", nodeName, err)
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status != corev1.ConditionTrue {
			return fmt.Errorf("node %q is not Ready (status: %s), refusing to reboot", nodeName, condition.Status)
		}
	}
	// systemctl reboot tears down the node immediately, killing the oc debug session,
	// so ExecK8NodeCommand will always return an error here — log it, don't fail on it.
	if _, err := o.ExecK8NodeCommand(nodeName, []string{"systemctl", "reboot"}); err != nil {
		framework.Logf("reboot command for node %q returned (expected due to session teardown): %v", nodeName, err)
	}
	framework.Logf("waiting for node %q to go NotReady", nodeName)
	if err := o.waitForNodeReadyState(nodeName, false, nodeRebootNotReadyTimeout); err != nil {
		return fmt.Errorf("node %q did not go NotReady within %s after reboot: %w", nodeName, nodeRebootNotReadyTimeout, err)
	}
	framework.Logf("waiting for node %q to return to Ready", nodeName)
	if err := o.waitForNodeReadyState(nodeName, true, nodeRebootReadyTimeout); err != nil {
		return fmt.Errorf("node %q did not return to Ready within %s after reboot: %w", nodeName, nodeRebootReadyTimeout, err)
	}
	return nil
}

// waitForNodeReadyState polls the Kubernetes API until the node reaches the desired Ready condition.
func (o *OpenshiftInfraProvider) waitForNodeReadyState(nodeName string, desiredReady bool, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(context.Background(), nodeRebootPollInterval, timeout, true,
		func(ctx context.Context) (bool, error) {
			node, err := o.kubeClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				framework.Logf("error getting node %q: %v", nodeName, err)
				return false, nil
			}
			for _, condition := range node.Status.Conditions {
				if condition.Type == corev1.NodeReady {
					return (condition.Status == corev1.ConditionTrue) == desiredReady, nil
				}
			}
			return false, nil
		},
	)
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
