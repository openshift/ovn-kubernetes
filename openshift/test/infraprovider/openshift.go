package infraprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ovnkconfig "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/portalloc"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

const (
	ovnAnnotationNodeIfAddr = "k8s.ovn.org/node-primary-ifaddr"
	ovnpodNamespace         = "openshift-ovn-kubernetes"
	// use network name created for attaching frr container with
	// cluster priamary network as per changes in the link:
	// https://github.com/openshift/release/blob/db6697de61f4ae7e05c5a2db782a87c459e849bf/ci-operator/step-registry/baremetalds/e2e/ovn/bgp/pre/baremetalds-e2e-ovn-bgp-pre-commands.sh#L123-L124
	primaryNetworkName         = "ostestbm_net"
	frrContainerPrimaryNetIPv4 = "192.168.111.3"
	frrContainerPrimaryNetIPv6 = "fd2e:6f44:5dd8:c956::3"
	externalFRRContainerName   = "frr"

	// Environment variable names for test configuration
	// These are set during infra provider initialization and consumed by test selection logic
	EnvVarOVNGatewayMode     = "OVN_GATEWAY_MODE"
	EnvVarEVPNFeatureEnabled = "EVPN_FEATURE_ENABLED"
)

type openshift struct {
	container.Provider
	config       *rest.Config
	nodes        map[string]*ocpNode
	host         *hypervisor
	hostNetworks map[string]*container.ContainerEngineNetwork
	kubeClient   *kubernetes.Clientset
}

type ocpNode struct {
	attachedIfaces map[string]*iface
}

type iface struct {
	ifName   string
	mac      string
	v4       string
	v4Subnet string
	v6       string
	v6Subnet string
}

func New(config *rest.Config) (api.Provider, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
	}
	infraNodes, primaryNet, err := loadKubeNodes(kubeClient)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize kube nodes: %w", err)
	}
	v4, v6, err := primaryNet.IPv4IPv6Subnets()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve primary network subnets: %w", err)
	}
	o := &openshift{
		Provider: container.Provider{
			ExternalContainerPort: portalloc.New(30000, 32767),
			HostPort:              portalloc.New(30000, 32767)},
		config:       config,
		kubeClient:   kubeClient,
		nodes:        infraNodes,
		hostNetworks: map[string]*container.ContainerEngineNetwork{primaryNetworkName: primaryNet}}
	// Try to set up external container support (optional, may not be available)
	host, err := loadHypervisorConfig()
	if err != nil {
		ginkgo.GinkgoLogr.Info("External container support not available, skipping hypervisor setup", "error", err.Error())
	} else {
		// Verify SSH connectivity works
		echoCmd := []string{"echo", "connection test"}
		if _, err := host.execCmd(echoCmd); err != nil {
			ginkgo.GinkgoLogr.Info("Failed to verify SSH connectivity to hypervisor, external container support disabled", "error", err.Error())
			host = nil
		} else {
			// Initialize primary network for Hypervisor instance
			if err := host.findAndInitializeNetwork(primaryNetworkName, v4, v6); err != nil {
				ginkgo.GinkgoLogr.Info("Failed to initialize network links, external container support disabled", "error", err.Error())
				host = nil
			} else {
				// Initialize command runner for executing podman commands on hypervisor
				o.ContainerOps = &container.ContainerOps{CmdRunner: host}
				o.host = host
				ginkgo.GinkgoLogr.Info("External container support enabled")
			}
		}
	}
	o.loadTestConfigs()
	return o, nil
}

func loadKubeNodes(kubeClient *kubernetes.Clientset) (map[string]*ocpNode, *container.ContainerEngineNetwork, error) {
	nodeMap := map[string]*ocpNode{}
	nodeList, err := kubeClient.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve nodes from the cluster: %w", err)
	}
	primaryNet := &container.ContainerEngineNetwork{NetName: primaryNetworkName}
	for _, node := range nodeList.Items {
		nodeIfAddrAnno, ok := node.Annotations[ovnAnnotationNodeIfAddr]
		if !ok {
			ginkgo.GinkgoLogr.Info("The annotation k8s.ovn.org/node-primary-ifaddr not found from node", "node", node.Name)
			continue
		}
		nodeIfAddr := make(map[string]string)
		if err := json.Unmarshal([]byte(nodeIfAddrAnno), &nodeIfAddr); err != nil {
			return nil, nil, fmt.Errorf("failed to parse node annotation %s: %w", ovnAnnotationNodeIfAddr, err)
		}
		nodeNetInfo := &iface{}
		kubeNode := &ocpNode{attachedIfaces: map[string]*iface{primaryNetworkName: nodeNetInfo}}
		var cidrs []container.ContainerEngineNetworkConfig
		if ip4, ok := nodeIfAddr["ipv4"]; ok {
			v4, cidr, err := net.ParseCIDR(ip4)
			if err != nil {
				return nil, nil, fmt.Errorf("unexpected error: node annotation ip %s entry is not a valid CIDR", ip4)
			}
			nodeNetInfo.v4 = v4.String()
			nodeNetInfo.v4Subnet = cidr.String()
			cidrs = append(cidrs, container.ContainerEngineNetworkConfig{Subnet: nodeNetInfo.v4Subnet})
		}
		if ip6, ok := nodeIfAddr["ipv6"]; ok {
			v6, cidr, err := net.ParseCIDR(ip6)
			if err != nil {
				return nil, nil, fmt.Errorf("unexpected error: node annotation ip %s entry is not a valid CIDR", ip6)
			}
			nodeNetInfo.v6 = v6.String()
			nodeNetInfo.v6Subnet = cidr.String()
			cidrs = append(cidrs, container.ContainerEngineNetworkConfig{Subnet: nodeNetInfo.v6Subnet})
		}
		if len(primaryNet.Configs) == 0 {
			// all nodes share same cidr, so assign first matching one.
			primaryNet.Configs = cidrs
		}
		ifName, err := findPrimaryInterface(kubeClient, node.Name)
		if err != nil {
			return nil, nil, err
		}
		nodeNetInfo.ifName = ifName
		nodeMap[node.Name] = kubeNode
	}
	return nodeMap, primaryNet, nil
}

func findPrimaryInterface(kubeClient *kubernetes.Clientset, nodeName string) (string, error) {
	ovnkubeNodePods, err := kubeClient.CoreV1().Pods(ovnpodNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=ovnkube-node",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return "", err
	}
	if len(ovnkubeNodePods.Items) != 1 {
		return "", fmt.Errorf("failed to find ovnkube-node pod for node instance %s", nodeName)
	}
	ovnKubeNodePodName := ovnkubeNodePods.Items[0].Name
	ports, err := e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, "ovs-vsctl list-ports br-ex")
	if err != nil {
		return "", err
	}
	if ports == "" {
		return "", fmt.Errorf("no ports found on br-ex for node %s", nodeName)
	}
	for _, port := range strings.Split(ports, "\n") {
		if port == "" {
			continue
		}
		out, err := e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ovs-vsctl get Port %s Interfaces", port))
		if err != nil {
			return "", err
		}
		// remove brackets on list of interfaces
		ifaces := strings.Trim(strings.TrimSpace(out), "[]")
		for _, iface := range strings.Split(ifaces, ",") {
			out, err := e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ovs-vsctl get Interface %s Type", strings.TrimSpace(iface)))
			if err != nil {
				return "", err

			}
			// If system Type we know this is the OVS port is the NIC
			if strings.TrimSpace(out) == "system" {
				return port, nil
			}
		}
	}
	return "", fmt.Errorf("failed to find network interface from ovnkube-node pod %s", ovnKubeNodePodName)
}

func (o *openshift) loadTestConfigs() {
	// Fetch cluster configs once and reuse for all checks.
	// This optimization makes it easy to add more feature gate or network config checks
	// in the future without additional API calls.
	operatorClient, err := operatorv1client.NewForConfig(o.config)
	if err != nil {
		ginkgo.GinkgoLogr.Info("Skipping test config detection", "error", err)
		return
	}

	configClient, err := configclient.NewForConfig(o.config)
	if err != nil {
		ginkgo.GinkgoLogr.Info("Skipping test config detection", "error", err)
		return
	}

	network, err := operatorClient.OperatorV1().Networks().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		ginkgo.GinkgoLogr.Info("Skipping network config detection", "error", err)
		return
	}

	clusterFeatureGate, err := configClient.ConfigV1().FeatureGates().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		ginkgo.GinkgoLogr.Info("Skipping feature gate detection", "error", err)
		return
	}

	// Configure test environment based on cluster configuration
	o.configureOVNGatewayMode(network)
	o.detectEVPNCapability(network, clusterFeatureGate)
	// Future feature detection can be added here, reusing network and clusterFeatureGate
}

// configureOVNGatewayMode detects and configures the OVN gateway mode for tests
func (o *openshift) configureOVNGatewayMode(network *operv1.Network) {
	if network.Spec.DefaultNetwork.OVNKubernetesConfig == nil {
		return
	}

	if network.Spec.DefaultNetwork.OVNKubernetesConfig.GatewayConfig != nil &&
		network.Spec.DefaultNetwork.OVNKubernetesConfig.GatewayConfig.RoutingViaHost {
		os.Setenv(EnvVarOVNGatewayMode, "local")
		ginkgo.GinkgoLogr.Info("OVN gateway mode configured", "mode", "local")
	}
}

// detectEVPNCapability checks all EVPN prerequisites and enables EVPN tests if available
func (o *openshift) detectEVPNCapability(network *operv1.Network, featureGate *configv1.FeatureGate) {
	if !hasEVPNFeatureGate(featureGate) {
		ginkgo.GinkgoLogr.Info("EVPN tests disabled: feature gate not enabled")
		return
	}
	if !hasFRRRouteProvider(network) {
		ginkgo.GinkgoLogr.Info("EVPN tests disabled: FRR route provider not configured")
		return
	}
	if !isLocalGatewayMode(network) {
		ginkgo.GinkgoLogr.Info("EVPN tests disabled: local gateway mode not enabled")
		return
	}
	if !o.hasFRRExternalContainer() {
		ginkgo.GinkgoLogr.Info("EVPN tests disabled: FRR external container not available")
		return
	}

	// All prerequisites met - enable EVPN tests
	os.Setenv(EnvVarEVPNFeatureEnabled, "true")
	ginkgo.GinkgoLogr.Info("EVPN capability detected, enabling EVPN tests")
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

// hasFRRExternalContainer checks if the FRR external container is available
func (o *openshift) hasFRRExternalContainer() bool {
	if o.ContainerOps == nil {
		return false
	}

	_, err := o.ContainerOps.GetContainerState(externalFRRContainerName)
	if err != nil {
		ginkgo.GinkgoLogr.Info("FRR container not available", "name", externalFRRContainerName, "error", err)
		return false
	}
	return true
}

func (o *openshift) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	if container.Name == "frr" && network.Name() == primaryNetworkName {
		// frr container uses static ip configuration for ostestbm_net,
		// querying it with podman inspect returns empty values, so build
		// it explicitly.
		if o.host == nil {
			return api.NetworkInterface{}, fmt.Errorf("can not find gateway node for frr container")
		}
		gwIface, ok := o.host.attachedIfaces[primaryNetworkName]
		if !ok {
			return api.NetworkInterface{}, fmt.Errorf("can not find primary network gateway node for frr container")
		}
		return api.NetworkInterface{
			IPv4: frrContainerPrimaryNetIPv4, IPv6: frrContainerPrimaryNetIPv6,
			IPv4Gateway: gwIface.v4, IPv6Gateway: gwIface.v6,
			InfName:    "eth0",
			IPv4Prefix: gwIface.v4Subnet, IPv6Prefix: gwIface.v6Subnet}, nil
	}
	return o.GetNetworkInterface(container.Name, network.Name())
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
}

func New(config *rest.Config) (api.Provider, error) {
	ovnkconfig.Kubernetes.DNSServiceNamespace = "openshift-dns"
	ovnkconfig.Kubernetes.DNSServiceName = "dns-default"
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
	}
	return &openshift{
		externalContainerPortAlloc: portalloc.New(30000, 32767),
		hostPortAlloc:              portalloc.New(30000, 32767),
		kubeClient:                 kubeClient,
	}, nil
}

func (o *openshift) Name() string {
	return "openshift"
}

func (o *openshift) PrimaryNetwork() (api.Network, error) {
	return o.getNetwork(primaryNetworkName)
}

func (o *openshift) GetNetwork(name string) (api.Network, error) {
	// Override "kind" network queries with the actual primary network name
	if name == "kind" {
		framework.Logf("overriding kind network with actual primary network name %s for the query", primaryNetworkName)
		name = primaryNetworkName
	}
	return o.getNetwork(name)

}

func (o *openshift) getNetwork(name string) (api.Network, error) {
	// check host networks first
	if network, ok := o.hostNetworks[name]; ok {
		return network, nil
	}
	// fall back into checking container networks.
	return o.ContainerOps.GetNetwork(name)
}

func (o *openshift) GetK8NodeNetworkInterface(instance string, network api.Network) (api.NetworkInterface, error) {
	if node, ok := o.nodes[instance]; ok {
		if network, ok := node.attachedIfaces[network.Name()]; ok {
			return api.NetworkInterface{InfName: network.ifName, IPv4: network.v4,
				IPv6: network.v6, IPv4Prefix: network.v4Subnet,
				IPv6Prefix: network.v6Subnet}, nil
		}
	}
	return api.NetworkInterface{}, fmt.Errorf("network interface not found on instance %s for network %s", instance, network.Name())
}

func (o *openshift) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("insufficient command arguments")
	}
	cmd = append([]string{"debug", fmt.Sprintf("node/%s", nodeName), "--to-namespace=default",
		"--", "chroot", "/host"}, cmd...)
	ocDebugCmd := exec.Command("oc", cmd...)
	var stdout, stderr bytes.Buffer
	ocDebugCmd.Stdout = &stdout
	ocDebugCmd.Stderr = &stderr

	if err := ocDebugCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to run command %q on node %s: %v, stdout: %s, stderr: %s", ocDebugCmd.String(), nodeName, err, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

func (o *openshift) NewTestContext() api.Context {
	co := &contextOpenshift{
		TestContext: container.TestContext{
			Mutex:        sync.Mutex{},
			ContainerOps: o.ContainerOps,
		},
	}
	ginkgo.DeferCleanup(co.CleanUp)
	return co
}

type contextOpenshift struct {
	container.TestContext
}

func (c *contextOpenshift) GetExternalContainerImage() string {
	// use downloadable image for external container.
	// ref: https://github.com/openshift/release/blob/db6697de61f4ae7e05c5a2db782a87c459e849bf/ci-operator/step-registry/baremetalds/e2e/ovn/bgp/pre/baremetalds-e2e-ovn-bgp-pre-commands.sh#L197
	return "registry.k8s.io/e2e-test-images/agnhost:2.40"
}

func (c *contextOpenshift) GetAttachedNetworks() (api.Networks, error) {
	c.Lock()
	defer c.Unlock()
	return c.getAttachedNetworks()
}

func (c *contextOpenshift) getAttachedNetworks() (api.Networks, error) {
	attachedNetworks := api.Networks{}
	for _, attachment := range c.CleanUpNetworkAttachments.List {
		attachedNetworks.InsertNoDupe(attachment.Network)
	}
	return attachedNetworks, nil
}

func (c *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	return fmt.Errorf("SetupUnderlay is not supported")
}
