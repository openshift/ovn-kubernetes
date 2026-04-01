package infraprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ovnkconfig "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/portalloc"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	// use network name created for attaching frr container with
	// cluster primary network as per changes in the link:
	// https://github.com/openshift/release/blob/db6697de61f4ae7e05c5a2db782a87c459e849bf/ci-operator/step-registry/baremetalds/e2e/ovn/bgp/pre/baremetalds-e2e-ovn-bgp-pre-commands.sh#L123-L124
	primaryNetworkName         = "ostestbm_net"
	frrContainerPrimaryNetIPv4 = "192.168.111.3"
	frrContainerPrimaryNetIPv6 = "fd2e:6f44:5dd8:c956::3"
	externalFRRContainerName   = "frr"

	// Environment variable names for test configuration
	// These are set during infra provider initialization and consumed by test selection logic
	EnvVarOVNGatewayMode     = "OVN_GATEWAY_MODE"
	EnvVarEVPNFeatureEnabled = "EVPN_FEATURE_ENABLED"
	EnvVarNoOverlayEnabled   = "NO_OVERLAY_ENABLED"
)

// Provider extends the base api.Provider interface with OpenShift-specific
// initialization that uses lazy loading to optimize performance for non-test commands.
//
// The initialization is split into two phases:
//  1. New() and LoadTestConfigs() performs lightweight initialization - loads cluster
//     capabilities (EVPN, gateway mode) needed for test filtering in 'list' command.
//     This phase MUST avoid verbose logging (e.g., from RunHostCmd/builder.go)
//     to keep metadata commands clean and user-friendly.
//  2. InitProvider() performs heavyweight initialization - discovers nodes,
//     network interfaces, and external container setup. This should only be called
//     before tests execute (e.g., in a BeforeAll hook) to avoid expensive operations
//     and verbose logging during metadata-only commands like 'list', 'info', or 'images'
type Provider interface {
	api.Provider
	LoadTestConfigs() error
	InitProvider() error
}

type openshift struct {
	config                     *rest.Config
	externalContainerPortAlloc *portalloc.PortAllocator
	hostPortAlloc              *portalloc.PortAllocator
	kubeClient                 *kubernetes.Clientset
}

func IsProvider(config *rest.Config) (bool, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	// Check for OpenShift-specific API groups
	groups, err := kubeClient.Discovery().ServerGroups()
	if err != nil {
		return false, fmt.Errorf("failed to get server groups: %w", err)
	}
	for _, group := range groups.Groups {
		if strings.HasSuffix(group.Name, ".openshift.io") {
			return true, nil
		}
	}
	return false, nil
}

func New(config *rest.Config) (Provider, error) {
	ovnkconfig.Kubernetes.DNSServiceNamespace = "openshift-dns"
	ovnkconfig.Kubernetes.DNSServiceName = "dns-default"
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
	}
	return &openshift{
		config:                     config,
		externalContainerPortAlloc: portalloc.New(30000, 32767),
		hostPortAlloc:              portalloc.New(30000, 32767),
		kubeClient:                 kubeClient,
	}, nil
}

func (o *openshift) LoadTestConfigs() error {
	// Fetch cluster configs once and reuse for all checks.
	// This optimization makes it easy to add more feature gate or network config checks
	// in the future without additional API calls.
	operatorClient, err := operatorv1client.NewForConfig(o.config)
	if err != nil {
		return fmt.Errorf("failed to retrieve operator client: %w", err)
	}

	configClient, err := configclient.NewForConfig(o.config)
	if err != nil {
		return fmt.Errorf("failed to retrieve config client: %w", err)
	}

	network, err := operatorClient.OperatorV1().Networks().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to retrieve network operator cluster object: %w", err)
	}

	clusterFeatureGate, err := configClient.ConfigV1().FeatureGates().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to retrieve cluster feature gate: %w", err)
	}

	// Configure test environment based on cluster configuration
	o.configureOVNGatewayMode(network)
	err = o.detectEVPNCapability(network, clusterFeatureGate)
	if err != nil {
		return fmt.Errorf("failed to check EVPN capability with the cluster: %w", err)
	}
	o.detectNoOverlayCapability(network)
	// Future feature detection can be added here, reusing network and clusterFeatureGate

	return nil
}

func (o *openshift) InitProvider() error {
	return nil
}

// configureOVNGatewayMode detects and configures the OVN gateway mode for tests
func (o *openshift) configureOVNGatewayMode(network *operv1.Network) {
	if network.Spec.DefaultNetwork.OVNKubernetesConfig == nil {
		return
	}

	if network.Spec.DefaultNetwork.OVNKubernetesConfig.GatewayConfig != nil &&
		network.Spec.DefaultNetwork.OVNKubernetesConfig.GatewayConfig.RoutingViaHost {
		os.Setenv(EnvVarOVNGatewayMode, "local")
	}
}

// detectEVPNCapability checks all EVPN prerequisites and enables EVPN tests if available
func (o *openshift) detectEVPNCapability(network *operv1.Network, featureGate *configv1.FeatureGate) error {
	if !hasEVPNFeatureGate(featureGate) {
		return nil
	}
	if !hasFRRRouteProvider(network) {
		return nil
	}
	if !isLocalGatewayMode(network) {
		return nil
	}
	exists, err := o.hasFRRExternalContainer()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	// All prerequisites met - enable EVPN tests
	os.Setenv(EnvVarEVPNFeatureEnabled, "true")
	return nil
}

// hasEVPNFeatureGate checks if the EVPN feature gate is enabled in the cluster
func hasEVPNFeatureGate(clusterFeatureGate *configv1.FeatureGate) bool {
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

// detectNoOverlayCapability checks if no-overlay mode is enabled and sets the env var
func (o *openshift) detectNoOverlayCapability(network *operv1.Network) {
	if network.Spec.DefaultNetwork.OVNKubernetesConfig == nil {
		return
	}
	if network.Spec.DefaultNetwork.OVNKubernetesConfig.Transport == operv1.TransportOptionNoOverlay {
		os.Setenv(EnvVarNoOverlayEnabled, "true")
	}
}

// hasFRRExternalContainer checks if the FRR external container is available.
// Returns false when the container engine is not configured (e.g., non-baremetal clusters).
func (o *openshift) hasFRRExternalContainer() (bool, error) {
	return false, nil
}

func (o *openshift) ShutdownNode(nodeName string) error {
	return fmt.Errorf("ShutdownNode not implemented for OpenShift provider")
}

func (o *openshift) StartNode(nodeName string) error {
	return fmt.Errorf("StartNode not implemented for OpenShift provider")
}

func (o *openshift) GetDefaultTimeoutContext() *framework.TimeoutContext {
	timeouts := framework.NewTimeoutContext()
	timeouts.PodStart = 10 * time.Minute
	return timeouts
}

func (o *openshift) PreloadImages(images []string) {
	// no-op: OpenShift clusters pull images at runtime
}

func (o *openshift) Name() string {
	return "openshift"
}

func (o *openshift) PrimaryNetwork() (api.Network, error) {
	panic("not implemented")
}

func (o *openshift) ExternalContainerPrimaryInterfaceName() string {
	panic("not implemented")
}

func (o *openshift) GetNetwork(name string) (api.Network, error) {
	panic("not implemented")
}

func (o *openshift) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	panic("not implemented")
}

func (o *openshift) GetK8NodeNetworkInterface(instance string, network api.Network) (api.NetworkInterface, error) {
	panic("not implemented")
}

func (o *openshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	panic("not implemented")
}

func (o *openshift) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
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

func (o *openshift) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	panic("not implemented")
}

func (o *openshift) GetExternalContainerPort() uint16 {
	return o.externalContainerPortAlloc.Allocate()
}

func (o *openshift) GetK8HostPort() uint16 {
	return o.hostPortAlloc.Allocate()
}

func (o *openshift) NewTestContext() api.Context {
	co := &contextOpenshift{make([]func() error, 0)}
	ginkgo.DeferCleanup(co.CleanUp)
	return co
}

func (o *openshift) ListNetworks() ([]string, error) {
	panic("not implemented")
}

type contextOpenshift struct {
	cleanUpFns []func() error
}

func (c *contextOpenshift) GetAllowedExternalContainerPort() int {
	panic("not implemented")
}

func (c *contextOpenshift) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	panic("not implemented")
}

func (c *contextOpenshift) DeleteExternalContainer(container api.ExternalContainer) error {
	panic("not implemented")
}

func (c *contextOpenshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	panic("not implemented")
}

func (c contextOpenshift) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	panic("not implemented")
}

func (c contextOpenshift) DeleteNetwork(network api.Network) error {
	panic("not implemented")
}

func (c *contextOpenshift) GetAttachedNetworks() (api.Networks, error) {
	panic("not implemented")
}

func (c *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	panic("not implemented")
}

func (c contextOpenshift) AttachNetwork(network api.Network, instance string) (api.NetworkInterface, error) {
	panic("not implemented")
}

func (c contextOpenshift) DetachNetwork(network api.Network, instance string) error {
	panic("not implemented")
}

func (c *contextOpenshift) AddCleanUpFn(cleanUpFn func() error) {
	c.cleanUpFns = append(c.cleanUpFns, cleanUpFn)
}

func (c *contextOpenshift) CleanUp() error {
	ginkgo.By("Cleaning up openshift test context")
	var errs []error
	for i := len(c.cleanUpFns) - 1; i >= 0; i-- {
		if err := c.cleanUpFns[i](); err != nil {
			errs = append(errs, err)
		}
	}
	c.cleanUpFns = nil
	return condenseErrors(errs)
}

func condenseErrors(errs []error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}
	err := errs[0]
	for _, e := range errs[1:] {
		err = errors.Join(err, e)
	}
	return err
}
