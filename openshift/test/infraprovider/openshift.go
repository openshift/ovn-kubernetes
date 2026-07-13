package infraprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
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
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/portalloc"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"

	"github.com/onsi/ginkgo/v2"
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
	debugNamespaceOnce      sync.Once
	debugNamespace          string
	debugNamespaceErr       error
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
		return nil, fmt.Errorf("failed to create kube client: %w", err)
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

// nodeDebugNamespace lazily creates a dedicated privileged namespace for the
// `oc debug node/...` helper pods. Using a dedicated namespace instead of
// "default" avoids tripping CI monitor tests (KubePodNotReady alerts and
// force-deleted platform pod invariants) with the short-lived debug pods.
func (o *OpenshiftInfraProvider) nodeDebugNamespace() (string, error) {
	o.debugNamespaceOnce.Do(func() {
		const name = "ovn-kubernetes-e2e-node-debug"
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce":             "privileged",
					"pod-security.kubernetes.io/audit":               "privileged",
					"pod-security.kubernetes.io/warn":                "privileged",
					"security.openshift.io/scc.podSecurityLabelSync": "false",
				},
			},
		}
		_, err := o.kubeClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			o.debugNamespaceErr = fmt.Errorf("failed to create node debug namespace: %w", err)
			return
		}
		o.debugNamespace = name
	})
	return o.debugNamespace, o.debugNamespaceErr
}

func (o *OpenshiftInfraProvider) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("insufficient command arguments")
	}

	namespace, err := o.nodeDebugNamespace()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd = append([]string{"debug", fmt.Sprintf("node/%s", nodeName), fmt.Sprintf("--to-namespace=%s", namespace),
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
		provider:    o,
	}
	if o.clusterInfra != nil {
		co.externalContainerContextProvider = o.clusterInfra.GetExternalContainerContextProvider(context)
	}
	return co
}

type contextOpenshift struct {
	*testcontext.TestContext
	externalContainerContextProvider api.ExternalContainerContextProvider
	provider                         *OpenshiftInfraProvider
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

// underlaySetupScript adds a bridge-mapping for the logical network, creating
// an OVS bridge attached to an underlay NIC first when a dedicated underlay is
// requested (bridge != br-ex). By default the logical network is mapped on
// br-ex: the machine network is a shared L2 segment on the metal CI jobs, so
// no dedicated bridge or spare NIC is needed. The script is idempotent and
// appends only its own bridge-mappings entry so that concurrent/serial tests
// sharing a bridge do not clobber each other. Arguments: $1=bridge $2=iface
// $3=vlanID $4=logicalNetworkName.
const underlaySetupScript = `
set -e
bridge="$1"
iface="$2"
vlan="$3"
net="$4"
if [ "$bridge" != "br-ex" ]; then
	ovs-vsctl --may-exist add-br "$bridge"
	ovs-vsctl --may-exist add-port "$bridge" "$iface"
	if [ "$vlan" -gt 0 ]; then
		ovs-vsctl set port "$iface" tag="$vlan"
	fi
fi
mappings="$(ovs-vsctl --if-exists get open . external-ids:ovn-bridge-mappings | tr -d '"')"
entry="$net:$bridge"
case ",$mappings," in
*",$entry,"*) ;;
*) ovs-vsctl set open . external-ids:ovn-bridge-mappings="${mappings:+$mappings,}$entry" ;;
esac
echo "underlay-bridge=$bridge underlay-iface=$iface"
`

// underlayCleanupScript removes only the bridge-mappings entry owned by the
// test. The OVS bridge (and its port) is left in place on purpose: it is
// harmless, idempotently reused by the next test and removing it while another
// test still references it would break that test.
const underlayCleanupScript = `
set -e
net="$1"
mappings="$(ovs-vsctl --if-exists get open . external-ids:ovn-bridge-mappings | tr -d '"')"
new=""
old_ifs="$IFS"
IFS=','
for m in $mappings; do
	case "$m" in
	"$net":*) continue ;;
	esac
	new="${new:+$new,}$m"
done
IFS="$old_ifs"
if [ -n "$new" ]; then
	ovs-vsctl set open . external-ids:ovn-bridge-mappings="$new"
else
	ovs-vsctl remove open . external-ids ovn-bridge-mappings
fi
`

const underlayDefaultBridge = "ovsbr1"

func (o *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	if underlay.LogicalNetworkName == "" {
		return fmt.Errorf("underlay logical network name must be set")
	}
	// By default the logical network is mapped on br-ex (the machine network
	// is a shared L2 segment on the metal CI jobs, no dedicated bridge or
	// spare NIC needed). Setting UNDERLAY_INTERFACE opts into a dedicated OVS
	// bridge attached to that NIC on every node.
	iface := os.Getenv("UNDERLAY_INTERFACE")
	if iface != "" {
		if underlay.BridgeName == "" {
			underlay.BridgeName = underlayDefaultBridge
		}
	} else {
		underlay.BridgeName = deploymentconfig.Get().ExternalBridgeName()
	}

	nodes, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes during underlay setup: %w", err)
	}

	o.AddCleanUpFn(func() error {
		var errs []error
		for _, node := range nodes.Items {
			if _, err := o.provider.ExecK8NodeCommand(node.Name, []string{
				"sh", "-c", underlayCleanupScript, "underlay-cleanup", underlay.LogicalNetworkName,
			}); err != nil {
				errs = append(errs, fmt.Errorf("node %s: %w", node.Name, err))
			}
		}
		return errors.Join(errs...)
	})

	for _, node := range nodes.Items {
		output, err := o.provider.ExecK8NodeCommand(node.Name, []string{
			"sh", "-c", underlaySetupScript, "underlay-setup",
			underlay.BridgeName, iface, fmt.Sprintf("%d", underlay.VlanID), underlay.LogicalNetworkName,
		})
		if err != nil {
			return fmt.Errorf("failed to setup underlay on node %s: %w", node.Name, err)
		}
		framework.Logf("SetupUnderlay node %s: %s", node.Name, output)
	}
	return nil
}
