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

	v1 "github.com/openshift/api/operator/v1"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
)

type openshift struct {
	container.Provider
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
	operatorClient, err := operatorv1client.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create operator client: %w", err)
	}
	network, err := operatorClient.OperatorV1().Networks().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve networks operator config: %w", err)
	}
	err = loadOvnConfig(network.Spec.DefaultNetwork.OVNKubernetesConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to load ovn configuration: %w", err)
	}
	infraNodes, primaryNet, err := loadKubeNodes(kubeClient)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize kube nodes: %w", err)
	}
	v4, v6, err := primaryNet.IPv4IPv6Subnets()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve primary network subnets: %w", err)
	}
	o := openshift{
		Provider: container.Provider{
			ExternalContainerPort: portalloc.New(30000, 32767),
			HostPort:              portalloc.New(30000, 32767)},
		kubeClient:   kubeClient,
		nodes:        infraNodes,
		hostNetworks: map[string]*container.ContainerEngineNetwork{primaryNetworkName: primaryNet}}
	// Try to set up external container support (optional, may not be available)
	host, err := loadHypervisorConfig()
	if err != nil {
		ginkgo.GinkgoLogr.Info("External container support not available, skipping hypervisor setup", "error", err.Error())
	} else {
		// Verify SSH connectivity works
		if _, err := host.execCmd("echo 'connection test'"); err != nil {
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
				err = o.setupExternalFRRContainer()
				if err != nil {
					ginkgo.GinkgoLogr.Info("Failed to configure external frr container", "error", err)
				}
				ginkgo.GinkgoLogr.Info("External container support enabled")
			}
		}
	}
	return &o, nil
}

func loadOvnConfig(conf *v1.OVNKubernetesConfig) error {
	if conf == nil {
		return fmt.Errorf("no ovn configuration found")
	}
	if conf.GatewayConfig == nil {
		return fmt.Errorf("ovn gateway config not found")
	}
	if conf.GatewayConfig.RoutingViaHost {
		os.Setenv("OVN_GATEWAY_MODE", "local")
	}
	return nil
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

func (o *openshift) setupExternalFRRContainer() error {
	frr := api.ExternalContainer{Name: externalFRRContainerName}
	// Enable keep_addr_on_down to preserve IPv6 addresses during VRF enslavement.
	// Without this, IPv6 global addresses are removed when interfaces are moved to a VRF,
	// causing FRR/zebra to fail creating FIB nexthop groups ("no fib nhg" bug).
	// See: https://docs.kernel.org/networking/vrf.html (section 4: Enslave L3 interfaces)
	//     https://github.com/FRRouting/frr/issues/1666
	_, err := o.ExecExternalContainerCommand(frr, []string{"sysctl", "-w", "net.ipv6.conf.all.keep_addr_on_down=1"})
	if err != nil {
		return fmt.Errorf("failed to configure %s container: %w", externalFRRContainerName, err)
	}
	return nil
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
