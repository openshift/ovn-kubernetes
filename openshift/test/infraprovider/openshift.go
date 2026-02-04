package infraprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ovnkconfig "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/containerengine"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/portalloc"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	hypervisorUserName      = "root"
	machineUserName         = "fedora"
	ovnAnnotationNodeIfAddr = "k8s.ovn.org/node-primary-ifaddr"
)

// machine maps 1-1 with OpenShift machine and therefore represents either a VM or BM host
type machine struct {
	name             string
	proxyIP          string                            // IP address of the hypervisor hosting VM
	proxySshSigner   ssh.Signer                        // proxy signer for accessing machine via ssh
	defaultIP        string                            // default IP address of the machine
	sshSigner        ssh.Signer                        // ssh signer to access the machine
	links            []linkInfo                        // net links attached with the machine
	containers       map[string]*api.ExternalContainer // container name -> api.ExternalContainer object
	hypervisorClient *ssh.Client                       // cached SSH connection to hypervisor (proxy)
}

type ipAddressInfo struct {
	Family string `json:"family"`
	Local  string `json:"local"`
}

type linkInfo struct {
	IfName   string          `json:"ifname"`
	Mac      string          `json:"address"`
	AddrInfo []ipAddressInfo `json:"addr_info"`
}

func (m *machine) addContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	nwIface, err := m.getNetwork(container)
	if err != nil {
		return container, err
	}
	container.IPv4 = nwIface.IPv4
	container.IPv6 = nwIface.IPv6
	cmd := buildDaemonContainerCmd(container.Name, container.Image, container.CmdArgs)
	cmd = addElevatedPrivileges(cmd)
	if _, err := m.execCmd(cmd); err != nil {
		return container, fmt.Errorf("failed to execute command on machine %s: %w", m.name, err)
	}
	m.containers[container.Name] = &container
	return container, nil
}

func (m *machine) deleteContainer(container api.ExternalContainer) error {
	isRunning, err := m.isContainerRunning(container)
	if err != nil {
		return fmt.Errorf("failed to check if container is running: %w", err)
	}
	if !isRunning {
		return nil
	}
	// remove the container
	cmd := buildRemoveContainerCmd(container.Name)
	cmd = addElevatedPrivileges(cmd)
	if _, err := m.execCmd(cmd); err != nil {
		return fmt.Errorf("failed to execute command on machine %s: %w", m.name, err)
	}
	// Clean up tracking
	delete(m.containers, container.Name)
	return nil
}

func (m *machine) getContainerLogs(container api.ExternalContainer) (string, error) {
	isRunning, err := m.isContainerRunning(container)
	if err != nil {
		return "", fmt.Errorf("failed to check if container is running: %w", err)
	}
	if !isRunning {
		return "", fmt.Errorf("external container is not running on machine")
	}
	logsCmd := buildContainerLogsCmd(container.Name)
	logsCmd = addElevatedPrivileges(logsCmd)
	res, err := m.execCmd(logsCmd)
	if err != nil {
		return "", fmt.Errorf("failed to execute command (%s) within machine %s: %w", logsCmd, m.name, err)
	}
	return res.stdout, nil
}

// getHypervisorClient returns the cached SSH client to the hypervisor, creating it if needed.
// If the existing connection is broken, it will be recreated.
func (m *machine) getHypervisorClient() (*ssh.Client, error) {
	// If we already have a client, verify it's still alive
	if m.hypervisorClient != nil {
		// Quick check: try to create a session
		session, err := m.hypervisorClient.NewSession()
		if err == nil {
			session.Close()
			return m.hypervisorClient, nil
		}
		// Connection is dead, close it and create a new one
		m.hypervisorClient.Close()
		m.hypervisorClient = nil
	}

	// Create new connection
	client, err := getSshClient(hypervisorUserName, fmt.Sprintf("%s:22", m.proxyIP), m.proxySshSigner)
	if err != nil {
		return nil, fmt.Errorf("error getting ssh proxy client: %w", err)
	}

	m.hypervisorClient = client
	return m.hypervisorClient, nil
}

// Close closes the cached SSH connection to the hypervisor.
func (m *machine) Close() error {
	if m.hypervisorClient != nil {
		err := m.hypervisorClient.Close()
		m.hypervisorClient = nil
		return err
	}
	return nil
}

func (m *machine) execCmd(cmd string) (result, error) {
	var r result
	hypervisorClient, err := m.getHypervisorClient()
	if err != nil {
		return r, err
	}
	r, err = runSSHCommand(machineUserName, cmd, hypervisorClient, fmt.Sprintf("%s:22", m.defaultIP), m.sshSigner)
	if err != nil {
		return r, fmt.Errorf("failed to run SSH command for %s@%s: %w: %+v", machineUserName, m.defaultIP, err, r)
	}
	return r, nil
}

func (m *machine) execContainerCmd(container api.ExternalContainer, cmd []string) (result, error) {
	containerCmd := buildContainerCmd(container.Name, cmd)
	containerCmd = addElevatedPrivileges(containerCmd)
	return m.execCmd(containerCmd)
}

func (m *machine) isContainerRunning(container api.ExternalContainer) (bool, error) {
	// check to see if the container is running before attempting to delete it
	isPresentCmd := buildContainerCheckCmd(container.Name)
	isPresentCmd = addElevatedPrivileges(isPresentCmd)
	r, err := m.execCmd(isPresentCmd)
	if err != nil {
		return false, fmt.Errorf("failed to execute command on machine %s: stdout=%s, stderr=%s",
			m.name, r.stdout, r.stderr)
	}
	if r.getStdOut() != "" {
		return true, nil
	}
	return false, nil
}

func (m *machine) getNetwork(container api.ExternalContainer) (api.NetworkInterface, error) {
	v4Subnet, v6Subnet, err := container.Network.IPv4IPv6Subnets()
	if err != nil {
		return api.NetworkInterface{}, err
	}

	// Find a link with IPs matching the requested subnet(s)
	for _, link := range m.links {
		if iface := m.tryMatchLink(link, v4Subnet, v6Subnet); iface.InfName != "" {
			return iface, nil
		}
	}

	return api.NetworkInterface{}, fmt.Errorf("no network interface found matching network %s", container.Network.Name())
}

// tryMatchLink attempts to match IP addresses on a link to the given subnets.
// Returns a populated NetworkInterface if the link has IPs in the requested subnet(s).
func (m *machine) tryMatchLink(link linkInfo, v4Subnet, v6Subnet string) api.NetworkInterface {
	var iface api.NetworkInterface

	for _, addr := range link.AddrInfo {
		// Check for IPv4 match
		if v4Subnet != "" && iface.IPv4 == "" {
			if ok, _ := ipInCIDR(addr.Local, v4Subnet); ok {
				iface.IPv4 = addr.Local
				iface.IPv4Prefix = v4Subnet
			}
		}

		// Check for IPv6 match
		if v6Subnet != "" && iface.IPv6 == "" {
			if ok, _ := ipInCIDR(addr.Local, v6Subnet); ok {
				iface.IPv6 = addr.Local
				iface.IPv6Prefix = v6Subnet
			}
		}
	}

	// Only consider this link a match if we found all requested IPs
	hasV4Match := v4Subnet == "" || iface.IPv4 != ""
	hasV6Match := v6Subnet == "" || iface.IPv6 != ""

	if hasV4Match && hasV6Match {
		iface.InfName = link.IfName
		iface.MAC = link.Mac
		return iface
	}

	// Not a complete match, return empty interface
	return api.NetworkInterface{}
}

// initializeNetworkLinks retrieves and caches the network links information from the machine.
func (m *machine) initializeNetworkLinks() error {
	result, err := m.execCmd("ip -j addr")
	if err != nil {
		return fmt.Errorf("failed to retrieve network links: %w", err)
	}

	var links []linkInfo
	if err := json.Unmarshal([]byte(result.stdout), &links); err != nil {
		return fmt.Errorf("failed to parse network links: %w", err)
	}

	m.links = links
	return nil
}

type openshift struct {
	externalContainerPortAlloc *portalloc.PortAllocator
	hostPortAlloc              *portalloc.PortAllocator
	kubeClient                 *kubernetes.Clientset
	platform                   configv1.PlatformType
	mu                         *sync.Mutex
	sharedMachine              *machine
}

func (o openshift) ShutdownNode(nodeName string) error {
	return fmt.Errorf("ShutdownNode not implemented for OpenShift provider")
}

func (o openshift) StartNode(nodeName string) error {
	return fmt.Errorf("StartNode not implemented for OpenShift provider")
}

func (m openshift) GetDefaultTimeoutContext() *framework.TimeoutContext {
	timeouts := framework.NewTimeoutContext()
	timeouts.PodStart = 10 * time.Minute
	return timeouts
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

func New(config *rest.Config) (api.Provider, error) {
	ovnkconfig.Kubernetes.DNSServiceNamespace = "openshift-dns"
	ovnkconfig.Kubernetes.DNSServiceName = "dns-default"
	configClient, err := configclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create config client: %w", err)
	}
	infra, err := configClient.ConfigV1().Infrastructures().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get cluster infrastructure: %w", err)
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
	}
	// Try to set up external container support (optional, may not be available)
	var m *machine
	m, err = ensureTestMachine()
	if err != nil {
		ginkgo.GinkgoLogr.Info("External container support not available, skipping machine setup", "error", err.Error())
	} else {
		// Verify SSH connectivity works
		if _, err := m.execCmd("echo 'connection test'"); err != nil {
			ginkgo.GinkgoLogr.Info("Failed to verify SSH connectivity to test machine, external container support disabled", "machine", testMachineName, "error", err.Error())
			m = nil
		} else {
			// Initialize network links information
			if err := m.initializeNetworkLinks(); err != nil {
				ginkgo.GinkgoLogr.Info("Failed to initialize network links, external container support disabled", "machine", testMachineName, "error", err.Error())
				m = nil
			} else {
				m.containers = map[string]*api.ExternalContainer{}
				ginkgo.GinkgoLogr.Info("External container support enabled", "machine", testMachineName)
			}
		}
	}
	o := openshift{externalContainerPortAlloc: portalloc.New(30000, 32767), hostPortAlloc: portalloc.New(30000, 32767),
		kubeClient: kubeClient, platform: infra.Spec.PlatformSpec.Type, mu: &sync.Mutex{}, sharedMachine: m}
	return o, nil
}

func (o openshift) Name() string {
	return "openshift"
}

func (o openshift) PrimaryNetwork() (api.Network, error) {
	if o.platform != configv1.BareMetalPlatformType {
		return nil, fmt.Errorf("external container provider is only supported on BareMetalPlatformType, current platform: %s", o.platform)
	}

	networkName := os.Getenv("BAREMETAL_NETWORK_NAME")
	if networkName == "" {
		ginkgo.GinkgoLogr.Info("Network name env is not set for baremetal cluster, using default network name")
		networkName = defaultNetworkName
	}
	nodeList, err := o.kubeClient.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve nodes from the cluster: %w", err)
	}
	var (
		nodeIfAddrAnno string
		ok             bool
	)
	for _, node := range nodeList.Items {
		if nodeIfAddrAnno, ok = node.Annotations[ovnAnnotationNodeIfAddr]; ok {
			break
		}
	}
	if nodeIfAddrAnno == "" {
		return nil, fmt.Errorf("no nodes found with annotation %s", ovnAnnotationNodeIfAddr)
	}
	nodeIfAddr := make(map[string]string)
	if err := json.Unmarshal([]byte(nodeIfAddrAnno), &nodeIfAddr); err != nil {
		return nil, fmt.Errorf("failed to parse node annotation %s: %w", ovnAnnotationNodeIfAddr, err)
	}
	address, ok := nodeIfAddr["ipv4"]
	if !ok {
		address, ok = nodeIfAddr["ipv6"]
	}
	if !ok {
		return nil, fmt.Errorf("failed to find node annotation %s in any of the cluster nodes", ovnAnnotationNodeIfAddr)
	}
	_, cidr, err := net.ParseCIDR(address)
	if err != nil {
		return nil, fmt.Errorf("unexpected error: node annotation ip %s entry is not a valid CIDR", address)
	}
	return hostNetwork{name: networkName, cidr: cidr.String()}, nil
}

func (o openshift) ExternalContainerPrimaryInterfaceName() string {
	return "eth0"
}

func (o openshift) GetNetwork(name string) (api.Network, error) {
	panic("not implemented")
}

func (o openshift) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	panic("not implemented")
}

func (o openshift) GetK8NodeNetworkInterface(instance string, network api.Network) (api.NetworkInterface, error) {
	panic("not implemented")
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

func (o openshift) NewTestContext() api.Context {
	co := &contextOpenshift{32700, o.kubeClient, o.platform, o.sharedMachine, o.mu,
		make([]api.ExternalContainer, 0), make([]func() error, 0)}
	ginkgo.DeferCleanup(co.CleanUp)
	return co
}

func (o *openshift) execContainer(container api.ExternalContainer, cmd []string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sharedMachine == nil {
		return "", fmt.Errorf("external container support is not available (test machine not configured)")
	}
	r, err := o.sharedMachine.execContainerCmd(container, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to execute command on remote container within machine: %v - stdout=%s, stderr=%s",
			err, r.stdout, r.stderr)
	}
	return r.getStdOut(), nil
}

type contextOpenshift struct {
	containerPort     int
	kubeClient        *kubernetes.Clientset
	platform          configv1.PlatformType
	sharedMachine     *machine
	machineLock       *sync.Mutex
	cleanUpContainers []api.ExternalContainer
	cleanUpFns        []func() error
}

func (c *contextOpenshift) GetAllowedExternalContainerPort() int {
	c.machineLock.Lock()
	defer c.machineLock.Unlock()
	port := c.containerPort
	c.containerPort += 1
	return port
}

func (c *contextOpenshift) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	if valid, err := container.IsValidPreCreateContainer(); !valid {
		return container, fmt.Errorf("failed to create external container: %w", err)
	}
	c.machineLock.Lock()
	defer c.machineLock.Unlock()

	if c.sharedMachine == nil {
		return container, fmt.Errorf("external container support is not available (test machine not configured)")
	}

	if _, exists := c.sharedMachine.containers[container.Name]; exists {
		return container, fmt.Errorf("container %s already exists", container.Name)
	}
	container, err := c.sharedMachine.addContainer(container)
	if err != nil {
		return container, fmt.Errorf("failed to add container to machine %s: %w", c.sharedMachine.name, err)
	}
	if valid, err := container.IsValidPostCreate(); !valid {
		return container, fmt.Errorf("failed to validate external container post creation: %w", err)
	}
	c.cleanUpContainers = append(c.cleanUpContainers, container)
	return container, nil
}

func (c *contextOpenshift) DeleteExternalContainer(container api.ExternalContainer) error {
	if valid, err := container.IsValidPreDelete(); !valid {
		return fmt.Errorf("external container is invalid: %w", err)
	}
	c.machineLock.Lock()
	defer c.machineLock.Unlock()
	if c.sharedMachine == nil {
		return fmt.Errorf("external container support is not available (test machine not configured)")
	}
	return c.sharedMachine.deleteContainer(container)
}

func (c *contextOpenshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	c.machineLock.Lock()
	defer c.machineLock.Unlock()
	if c.sharedMachine == nil {
		return "", fmt.Errorf("external container support is not available (test machine not configured)")
	}
	return c.sharedMachine.getContainerLogs(container)
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

	// Close the shared machine SSH connection (idempotent, safe to call multiple times)
	if c.sharedMachine != nil {
		if err := c.sharedMachine.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close machine SSH connection: %w", err))
		}
	}

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

func addElevatedPrivileges(cmd string) string {
	return fmt.Sprintf("sudo %s", cmd)
}

// escapeShellArgument properly quotes a string for use as a single argument in a shell command.
// This is a simplified version and might not cover all edge cases for all shells.
// For robust shell escaping, consider using a dedicated library if available,
// or ensure your remote shell is predictable (e.g., always bash).
func escapeShellArgument(arg string) string {
	// Simple rule: if it contains spaces or special characters, single-quote it.
	// Within single quotes, single quotes themselves need to be handled: '\''
	if strings.ContainsAny(arg, " \t\n\r\"'\\`$!{}[]()<>*?~#&;|") {
		return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return arg
}

func buildContainerCmd(name string, cmd []string) string {
	var b strings.Builder
	b.WriteString(containerengine.Get().String())
	b.WriteString(" exec -t ")
	b.WriteString(escapeShellArgument(name))
	b.WriteString(" ") // Add space after container name

	for i, arg := range cmd {
		if i > 0 { // Add space before subsequent arguments
			b.WriteString(" ")
		}
		b.WriteString(escapeShellArgument(arg))
	}

	return b.String()
}

func buildDaemonContainerCmd(name, image string, cmd []string) string {
	var b strings.Builder
	b.WriteString(containerengine.Get().String())
	b.WriteString(" run -itd --privileged --name ")
	b.WriteString(escapeShellArgument(name))
	b.WriteString(" --network host --hostname ")
	b.WriteString(escapeShellArgument(name))
	b.WriteString(" ")
	b.WriteString(escapeShellArgument(image))
	for _, arg := range cmd {
		b.WriteString(" ")
		b.WriteString(escapeShellArgument(arg))
	}
	return b.String()
}

func buildContainerCheckCmd(name string) string {
	return fmt.Sprintf("%s ps -f name=%s -q", containerengine.Get(), escapeShellArgument(name))
}

func buildContainerLogsCmd(name string) string {
	return fmt.Sprintf("%s logs %s", containerengine.Get(), escapeShellArgument(name))
}

func buildRemoveContainerCmd(name string) string {
	return fmt.Sprintf("%s rm -f %s", containerengine.Get(), escapeShellArgument(name))
}
