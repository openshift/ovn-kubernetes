package infraprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/containerengine"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/portalloc"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

const (
	ovnAnnotationNodeIfAddr = "k8s.ovn.org/node-primary-ifaddr"
	ovnpodNamespace         = "openshift-ovn-kubernetes"
)

type openshift struct {
	nodes                      map[string]*ocpNode
	networks                   map[string]*hostNetwork
	vm                         *vm
	mutex                      *sync.Mutex
	externalContainerPortAlloc *portalloc.PortAllocator
	hostPortAlloc              *portalloc.PortAllocator
	kubeClient                 *kubernetes.Clientset
}

type ocpNode struct {
	attachedNetworks map[string]*netInfo
}

type netInfo struct {
	id       uint32
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
	// Try to set up external container support (optional, may not be available)
	var m *vm
	m, err = loadVMConfig()
	if err != nil {
		ginkgo.GinkgoLogr.Info("External container support not available, skipping vm setup", "error", err.Error())
	} else {
		// Verify SSH connectivity works
		if _, err := m.execCmd("echo 'connection test'"); err != nil {
			ginkgo.GinkgoLogr.Info("Failed to verify SSH connectivity to test vm, external container support disabled", "error", err.Error())
			m = nil
		} else {
			// Initialize primary network for VM instance
			if err := m.findAndInitializeNetwork(primaryNetworkName, v4, v6); err != nil {
				ginkgo.GinkgoLogr.Info("Failed to initialize network links, external container support disabled", "error", err.Error())
				m = nil
			} else {
				m.containers = map[string]*api.ExternalContainer{}
				ginkgo.GinkgoLogr.Info("External container support enabled")
			}
		}
	}

	o := openshift{externalContainerPortAlloc: portalloc.New(30000, 32767), hostPortAlloc: portalloc.New(30000, 32767),
		kubeClient: kubeClient, mutex: &sync.Mutex{}, vm: m, nodes: infraNodes,
		networks: map[string]*hostNetwork{primaryNetworkName: primaryNet}}
	return o, nil
}

func loadKubeNodes(kubeClient *kubernetes.Clientset) (map[string]*ocpNode, *hostNetwork, error) {
	nodeMap := map[string]*ocpNode{}
	nodeList, err := kubeClient.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve nodes from the cluster: %w", err)
	}
	primaryNet := &hostNetwork{name: primaryNetworkName}
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
		nodeNetInfo := &netInfo{}
		kubeNode := &ocpNode{attachedNetworks: map[string]*netInfo{primaryNetworkName: nodeNetInfo}}
		var cidrs []string
		if ip4, ok := nodeIfAddr["ipv4"]; ok {
			v4, cidr, err := net.ParseCIDR(ip4)
			if err != nil {
				return nil, nil, fmt.Errorf("unexpected error: node annotation ip %s entry is not a valid CIDR", ip4)
			}
			nodeNetInfo.v4 = v4.String()
			nodeNetInfo.v4Subnet = cidr.String()
			cidrs = append(cidrs, nodeNetInfo.v4Subnet)
		}
		if ip6, ok := nodeIfAddr["ipv6"]; ok {
			v6, cidr, err := net.ParseCIDR(ip6)
			if err != nil {
				return nil, nil, fmt.Errorf("unexpected error: node annotation ip %s entry is not a valid CIDR", ip6)
			}
			nodeNetInfo.v6 = v6.String()
			nodeNetInfo.v6Subnet = cidr.String()
			cidrs = append(cidrs, nodeNetInfo.v6Subnet)
		}
		if len(primaryNet.cidrs) == 0 {
			primaryNet.cidrs = cidrs
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
	ovnkubeNodePods, err := kubeClient.CoreV1().Pods(ovnpodNamespace).List(context.TODO(), metav1.ListOptions{
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
	for _, port := range strings.Split(ports, "\n") {
		out, err := e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ovs-vsctl get Port %s Interfaces", port))
		if err != nil {
			return "", err
		}
		// remove brackets on list of interfaces
		ifaces := strings.TrimPrefix(strings.TrimSuffix(out, "]"), "[")
		for _, iface := range strings.Split(ifaces, ",") {
			out, err := e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ovs-vsctl get Interface %s Type", strings.TrimSpace(iface)))
			if err != nil {
				return "", err

			}
			// If system Type we know this is the OVS port is the NIC
			if out == "system" {
				return port, nil
			}
		}
	}
	return "", fmt.Errorf("failed to find network interface from ovnkube-node pod %s", ovnKubeNodePodName)
}

func (o openshift) ShutdownNode(nodeName string) error {
	return fmt.Errorf("ShutdownNode not implemented for OpenShift provider")
}

func (o openshift) StartNode(nodeName string) error {
	return fmt.Errorf("StartNode not implemented for OpenShift provider")
}

func (o openshift) GetDefaultTimeoutContext() *framework.TimeoutContext {
	timeouts := framework.NewTimeoutContext()
	timeouts.PodStart = 10 * time.Minute
	return timeouts
}

func (o openshift) Name() string {
	return "openshift"
}

func (o openshift) PrimaryNetwork() (api.Network, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.getNetwork(primaryNetworkName)
}

func (o openshift) ExternalContainerPrimaryInterfaceName() string {
	return "eth0"
}

func (o openshift) GetNetwork(name string) (api.Network, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.getNetwork(name)
}

func (o openshift) getNetwork(name string) (api.Network, error) {
	if network, ok := o.networks[name]; ok {
		return network, nil
	}
	return nil, fmt.Errorf("network %s not found", name)
}

func (o openshift) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	panic("not implemented")
}

func (o openshift) GetK8NodeNetworkInterface(instance string, network api.Network) (api.NetworkInterface, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	if node, ok := o.nodes[instance]; ok {
		if network, ok := node.attachedNetworks[network.Name()]; ok {
			return api.NetworkInterface{InfName: network.ifName, IPv4: network.v4,
				IPv6: network.v6, IPv4Prefix: network.v4Subnet,
				IPv6Prefix: network.v6Subnet}, nil
		}
	}
	return api.NetworkInterface{}, fmt.Errorf("network interface not found on instance %s for network %s", instance, network.Name())
}

func (o openshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	if !container.IsIPv6() && !container.IsIPv4() {
		return "", fmt.Errorf("expected either IPv4 or IPv6 address to be set")
	}
	return o.execContainer(container, []string{containerengine.Get().String(), "logs", container.Name})
}

func (o openshift) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
	if len(cmd) == 0 {
		panic("ExecK8NodeCommand(): insufficient command arguments")
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

func (o openshift) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	if len(cmd) == 0 {
		panic("ExecExternalContainerCommand(): insufficient command arguments")
	}
	if !container.IsIPv6() && !container.IsIPv4() {
		return "", fmt.Errorf("expected either IPv4 or IPv6 address to be set")
	}
	return o.execContainer(container, cmd)
}

func (o openshift) GetExternalContainerPort() uint16 {
	return o.externalContainerPortAlloc.Allocate()
}

func (o openshift) GetK8HostPort() uint16 {
	return o.hostPortAlloc.Allocate()
}

// GetExternalContainerPID implements api.Provider.
func (o openshift) GetExternalContainerPID(containerName string) (int, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.vm.getContainerPID(containerName)
}

// RunOneShotContainer implements api.Provider.
func (o openshift) RunOneShotContainer(image string, cmd []string, runtimeArgs []string) (string, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	oneShotCmd := buildOneShotContainerCmd(image, cmd, runtimeArgs)
	oneShotCmd = addElevatedPrivileges(oneShotCmd)
	r, err := o.vm.execCmd(oneShotCmd)
	if err != nil {
		return "", fmt.Errorf("failed to run one-shot container %s, stdout=%s, stderr=%s, err: %v",
			oneShotCmd, r.stdout, r.stderr, err)
	}
	return r.getStdOut(), nil
}

func (o openshift) NewTestContext() api.Context {
	co := &contextOpenshift{32700, o.kubeClient, o.nodes, o.networks, o.vm, o.mutex,
		make([]api.ExternalContainer, 0), make([]func() error, 0)}
	ginkgo.DeferCleanup(co.CleanUp)
	return co
}

func (o openshift) execContainer(container api.ExternalContainer, cmd []string) (string, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	if o.vm == nil {
		return "", fmt.Errorf("external container support is not available (test vm not configured)")
	}
	r, err := o.vm.execContainerCmd(container, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to execute command on remote container within vm: %v - stdout=%s, stderr=%s",
			err, r.stdout, r.stderr)
	}
	return r.getStdOut(), nil
}

type contextOpenshift struct {
	containerPort     int
	kubeClient        *kubernetes.Clientset
	nodes             map[string]*ocpNode
	networks          map[string]*hostNetwork
	vm                *vm
	mutex             *sync.Mutex
	cleanUpContainers []api.ExternalContainer
	cleanUpFns        []func() error
}

func (c *contextOpenshift) GetAllowedExternalContainerPort() int {
	port := c.containerPort
	c.containerPort += 1
	return port
}

func (c *contextOpenshift) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	if valid, err := container.IsValidPreCreateContainer(); !valid {
		return container, fmt.Errorf("failed to create external container: %w", err)
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.vm == nil {
		return container, fmt.Errorf("external container support is not available (test vm not configured)")
	}

	if _, exists := c.vm.containers[container.Name]; exists {
		return container, fmt.Errorf("container %s already exists", container.Name)
	}
	container, err := c.vm.addContainer(container)
	if err != nil {
		return container, fmt.Errorf("failed to add container to vm: %w", err)
	}
	c.cleanUpContainers = append(c.cleanUpContainers, container)
	if valid, err := container.IsValidPostCreate(); !valid {
		return container, fmt.Errorf("failed to validate external container post creation: %w", err)
	}
	return container, nil
}

func (c *contextOpenshift) DeleteExternalContainer(container api.ExternalContainer) error {
	if valid, err := container.IsValidPreDelete(); !valid {
		return fmt.Errorf("external container is invalid: %w", err)
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.vm == nil {
		return fmt.Errorf("external container support is not available (test vm not configured)")
	}
	return c.vm.deleteContainer(container)
}

func (c *contextOpenshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.vm == nil {
		return "", fmt.Errorf("external container support is not available (test vm not configured)")
	}
	return c.vm.getContainerLogs(container)
}

// CreateNetwork creates a VXLAN overlay network with a unique VNI, sets up VXLAN interfaces on all nodes
// and the VM, uses primary network IPs as VTEP endpoints and configures static L2 FDB entries for all-to-all
// connectivity
func (c contextOpenshift) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.vm == nil {
		return nil, fmt.Errorf("create network is not supported because vm not found from infra provider")
	}
	if _, exists := c.networks[name]; exists {
		return nil, fmt.Errorf("network %s already exists", name)
	}
	networkID := NextVNI()
	networkIfName := fmt.Sprintf("net%d", networkID)
	network := &hostNetwork{name: name, ifName: networkIfName, cidrs: subnets}
	for nodeName, node := range c.nodes {
		ovnkubeNodePods, err := c.kubeClient.CoreV1().Pods(ovnpodNamespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=ovnkube-node",
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err != nil {
			return nil, err
		}
		if len(ovnkubeNodePods.Items) != 1 {
			return nil, fmt.Errorf("failed to find ovnkube-node pod for node instance %s", nodeName)
		}
		ovnKubeNodePodName := ovnkubeNodePods.Items[0].Name
		primaryNetworkInfo, ok := node.attachedNetworks[primaryNetworkName]
		if !ok {
			return nil, fmt.Errorf("failed to find underlay network for node instance %s", nodeName)
		}
		localVtepIP := primaryNetworkInfo.v4
		if localVtepIP == "" {
			localVtepIP = primaryNetworkInfo.v6
		}
		_, err = e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ip link add %s type vxlan id %d local %s dstport 5789 dev %s",
			networkIfName, networkID, localVtepIP, primaryNetworkInfo.ifName))
		if err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				_, err = e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ip link delete %s", networkIfName))
			}
		}()
		_, err = e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ip link set %s up", networkIfName))
		if err != nil {
			return nil, err
		}
		for peerNodeName, peerNode := range c.nodes {
			if peerNodeName == nodeName {
				continue
			}
			primaryNetworkInfo, ok := peerNode.attachedNetworks[primaryNetworkName]
			if !ok {
				return nil, fmt.Errorf("failed to find primary network for peer node instance %s", peerNodeName)
			}
			remoteVtepIP := primaryNetworkInfo.v4
			if remoteVtepIP == "" {
				remoteVtepIP = primaryNetworkInfo.v6
			}
			_, err = e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("bridge fdb append 00:00:00:00:00:00 dev %s dst %s",
				networkIfName, remoteVtepIP))
			if err != nil {
				return nil, fmt.Errorf("failed to add network %s fdb entry on node %s for the peer node %s: %w", name, nodeName, peerNodeName, err)
			}
		}
		primaryNetworkInfo, ok = c.vm.attachedNetworks[primaryNetworkName]
		if !ok {
			return nil, fmt.Errorf("failed to find primary network for vm")
		}
		remoteVtepIP := primaryNetworkInfo.v4
		if remoteVtepIP == "" {
			remoteVtepIP = primaryNetworkInfo.v6
		}
		_, err = e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("bridge fdb append 00:00:00:00:00:00 dev %s dst %s",
			networkIfName, remoteVtepIP))
		if err != nil {
			return nil, fmt.Errorf("failed to add network %s fdb entry on node %s for the vm: %w", name, nodeName, err)
		}
	}
	primaryNetworkInfo, ok := c.vm.attachedNetworks[primaryNetworkName]
	if !ok {
		return nil, fmt.Errorf("failed to find primary network for vm")
	}
	localVtepIP := primaryNetworkInfo.v4
	if localVtepIP == "" {
		localVtepIP = primaryNetworkInfo.v6
	}
	result, err := c.vm.execCmd(fmt.Sprintf("sudo ip link add %s type vxlan id %d local %s dstport 5789 dev %s", networkIfName, networkID, localVtepIP, primaryNetworkInfo.ifName))
	if err != nil {
		return nil, fmt.Errorf("failed to plump network %s into the vm, stderr: %s, err: %w", name, result.stderr, err)
	}
	defer func() {
		if err != nil {
			result, err := c.vm.execCmd(fmt.Sprintf("sudo ip link delete %s", networkIfName))
			if err != nil {
				ginkgo.GinkgoLogr.Info("Failed to cleanup network interface upon failure", "network", name, "stderr", result.stderr, "error", err.Error())
			}
		}
	}()
	result, err = c.vm.execCmd(fmt.Sprintf("sudo ip link set %s up", networkIfName))
	if err != nil {
		return nil, fmt.Errorf("failed to plump network %s into the vm, stderr: %s, err: %w", name, result.stderr, err)
	}
	for peerNodeName, peerNode := range c.nodes {
		primaryNetworkInfo, ok := peerNode.attachedNetworks[primaryNetworkName]
		if !ok {
			return nil, fmt.Errorf("failed to find primary network for peer node instance %s", peerNodeName)
		}
		remoteVtepIP := primaryNetworkInfo.v4
		if remoteVtepIP == "" {
			remoteVtepIP = primaryNetworkInfo.v6
		}
		_, err = c.vm.execCmd(fmt.Sprintf("bridge fdb append 00:00:00:00:00:00 dev %s dst %s", networkIfName, remoteVtepIP))
		if err != nil {
			return nil, fmt.Errorf("failed to add network %s fdb entry on vm for the peer node %s: %w", name, peerNodeName, err)
		}
	}
	c.networks[name] = network
	return network, nil
}

// DeleteNetwork Cleans up VXLAN interfaces from nodes and VM.
func (c contextOpenshift) DeleteNetwork(network api.Network) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	name := network.Name()
	if name == primaryNetworkName {
		return fmt.Errorf("cannot delete primary network")
	}
	hostNetwork, ok := c.networks[name]
	if !ok {
		return fmt.Errorf("network %s is not found", name)
	}
	for nodeName := range c.nodes {
		ovnkubeNodePods, err := c.kubeClient.CoreV1().Pods(ovnpodNamespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=ovnkube-node",
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err != nil {
			return err
		}
		if len(ovnkubeNodePods.Items) != 1 {
			return fmt.Errorf("failed to find ovnkube-node pod for node instance %s", nodeName)
		}
		ovnKubeNodePodName := ovnkubeNodePods.Items[0].Name
		_, err = e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ip link delete %s", hostNetwork.ifName))
		if err != nil {
			return fmt.Errorf("failed to delete network %s interface for node %s: %w", name, nodeName, err)
		}
	}
	result, err := c.vm.execCmd(fmt.Sprintf("sudo ip link delete %s", hostNetwork.ifName))
	if err != nil {
		return fmt.Errorf("failed to delete network %s interface from vm, stderr: %s, err: %w", name, result.stderr, err)
	}
	delete(c.networks, name)
	return nil
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

	// Clean up external containers
	for i := len(c.cleanUpContainers) - 1; i >= 0; i-- {
		if err := c.DeleteExternalContainer(c.cleanUpContainers[i]); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete external container %s: %w", c.cleanUpContainers[i].Name, err))
		}
	}
	c.cleanUpContainers = nil

	// Generic cleanup activities
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
