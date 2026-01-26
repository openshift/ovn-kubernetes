package infraprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ovnkconfig "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/containerengine"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/portalloc"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
	utilnet "k8s.io/utils/net"
)

const (
	machineUserName = "fedora"
)

// machine maps 1-1 with OpenShift machine and therefore represents either a VM or BM host
type machine struct {
	name                 string
	ipv4Addresses        map[string]string                 // network name -> IPv4
	ipv6Addresses        map[string]string                 // network name -> IPv6
	containers           map[string]*api.ExternalContainer // container name -> api.ExternalContainer object
	networksForContainer map[string]map[string]any         // container name -> set of network names
}

func (m *machine) hasNetwork(name string) bool {
	_, ok4 := m.ipv4Addresses[name]
	_, ok6 := m.ipv6Addresses[name]
	return ok4 || ok6
}

func (m *machine) getIP() (string, error) {
	for _, ipv4 := range m.ipv4Addresses {
		return ipv4, nil
	}
	for _, ipv6 := range m.ipv6Addresses {
		return ipv6, nil
	}
	return "", fmt.Errorf("no ip address found in the machine %s", m.name)
}

func (m *machine) isNetworkUsedByAnyContainer(networkName string) bool {
	for _, networks := range m.networksForContainer {
		if _, exists := networks[networkName]; exists {
			return true
		}
	}
	return false
}

func (m *machine) addContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	network := container.Network.Name()
	var (
		nwIface api.NetworkInterface
		err     error
	)
	if nwIface, err = m.attachNetwork(network); err != nil {
		return container, err
	}
	container.IPv4 = nwIface.IPv4
	container.IPv6 = nwIface.IPv6
	cmd := buildDaemonContainerCmd(container.Name, container.Image, container.CmdArgs)
	cmd = addElevatedPrivileges(cmd)
	if _, err := m.execCmd(cmd); err != nil {
		// Rollback: detach the network if container startup failed
		_ = m.detachNetworkIfUnused(network)
		return container, fmt.Errorf("failed to execute command on machine %s: %w", m.name, err)
	}
	m.containers[container.Name] = &container
	// Track that this container uses this network
	if m.networksForContainer[container.Name] == nil {
		m.networksForContainer[container.Name] = make(map[string]any)
	}
	m.networksForContainer[container.Name][network] = nil
	return container, nil
}

func (m *machine) attachNetwork(name string) (api.NetworkInterface, error) {
	nwIface := api.NetworkInterface{}
	// Check if network is already attached to the VM
	if m.hasNetwork(name) {
		// Network already attached, reuse it
		nwIface.IPv4 = m.ipv4Addresses[name]
		nwIface.IPv6 = m.ipv6Addresses[name]

		// Get MAC and device info
		testMachine, err := showMachine(m.name)
		if err != nil {
			return nwIface, fmt.Errorf("failed retrieving test machine: %w", err)
		}
		for _, net := range testMachine.Nets {
			if net.Net == name {
				nwIface.MAC = net.Mac
				nwIface.InfName = net.Device
				break
			}
		}
		if nwIface.MAC == "" || nwIface.InfName == "" {
			return nwIface, fmt.Errorf("network %s marked as attached but not found in VM network interfaces", name)
		}
		return nwIface, nil
	}
	// Network not attached yet, proceed with physical attachment
	testMachine, err := showMachine(m.name)
	if err != nil {
		return nwIface, fmt.Errorf("failed retrieving test machine: %w", err)
	}
	if err := testMachine.attachNetwork(name); err != nil {
		return nwIface, fmt.Errorf("failed attaching network %q to machine %q: %w", name, testMachine.Name, err)
	}
	network, err := getNetwork(name)
	if err != nil {
		// Rollback: detach the network
		if updated, showErr := showMachine(m.name); showErr == nil {
			for _, net := range updated.Nets {
				if net.Net == name {
					_ = updated.detachNetwork(name, net.Device) // Best effort cleanup
					break
				}
			}
		}
		return nwIface, fmt.Errorf("failed to retrieve network %s, err: %w", name, err)
	}

	// Poll for IPs with timeout - wait for machine to get IPs in the container network
	err = wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		updatedMachine, err := showMachine(m.name)
		if err != nil {
			ginkgo.GinkgoLogr.Info("Failed to retrieve machine, retrying", "machine", m.name, "error", err)
			return false, nil
		}

		// Find and assign MAC, Device and IPs from the container network
		for _, net := range updatedMachine.Nets {
			if net.Net == name {
				nwIface.MAC = net.Mac
				nwIface.InfName = net.Device
				break
			}
		}
		foundIP := false
		for _, ip := range updatedMachine.IPs {
			in, err := ipInCIDR(ip, network.CIDR)
			if err != nil {
				ginkgo.GinkgoLogr.Info("Error checking IP against CIDR, retrying", "ip", ip, "cidr", network.CIDR, "error", err)
				return false, nil
			}
			if in && utilnet.IsIPv4String(ip) {
				m.ipv4Addresses[name] = ip
				nwIface.IPv4 = ip
				foundIP = true
			} else if in {
				m.ipv6Addresses[name] = ip
				nwIface.IPv6 = ip
				foundIP = true
			}
		}
		if !foundIP || nwIface.MAC == "" || nwIface.InfName == "" {
			ginkgo.GinkgoLogr.Info("Machine IPs, MAC and Device not yet populated in network, retrying", "machine", m.name, "network", name)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		// Rollback: detach the network
		if updated, showErr := showMachine(m.name); showErr == nil {
			for _, net := range updated.Nets {
				if net.Net == name {
					_ = updated.detachNetwork(name, net.Device) // Best effort cleanup
					break
				}
			}
		}
		return nwIface, fmt.Errorf("timeout waiting for machine %s to get IPs in network %s: %w", m.name, name, err)
	}
	return nwIface, nil
}

func (m *machine) detachNetwork(name string) error {
	testMachine, err := showMachine(m.name)
	if err != nil {
		return fmt.Errorf("failed retrieving test machine: %w", err)
	}
	var interfaceName string
	for _, net := range testMachine.Nets {
		if net.Net == name {
			interfaceName = net.Device
			break
		}
	}
	if interfaceName == "" {
		return fmt.Errorf("failed to find interface from machine %s for network %s", m.name, name)
	}
	if err := testMachine.detachNetwork(name, interfaceName); err != nil {
		return err
	}
	// Clean up IP addresses after successful detach
	delete(m.ipv4Addresses, name)
	delete(m.ipv6Addresses, name)
	return nil
}

func (m *machine) detachNetworkIfUnused(networkName string) error {
	// Check if any container still uses this network
	if m.isNetworkUsedByAnyContainer(networkName) {
		return nil // Network still in use, don't detach
	}

	// No container uses this network, safe to detach
	return m.detachNetwork(networkName)
}

func (m *machine) deleteContainer(container api.ExternalContainer) error {
	isRunning, err := m.isContainerRunning(container)
	if err != nil {
		return fmt.Errorf("failed to check if container is running: %v", err)
	}
	// Get networks used by this container before cleanup
	containerNetworks := m.networksForContainer[container.Name]

	if !isRunning {
		// Container already stopped, just clean up state
		delete(m.containers, container.Name)
		delete(m.networksForContainer, container.Name)
		// Detach networks that are no longer used by any container
		for networkName := range containerNetworks {
			_ = m.detachNetworkIfUnused(networkName) // Best effort
		}
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
	delete(m.networksForContainer, container.Name)

	// Detach networks that are no longer used by any container
	for networkName := range containerNetworks {
		if err := m.detachNetworkIfUnused(networkName); err != nil {
			return fmt.Errorf("failed to detach unused network %s: %w", networkName, err)
		}
	}

	return nil
}

func (m *machine) getContainerLogs(container api.ExternalContainer) (string, error) {
	isRunning, err := m.isContainerRunning(container)
	if err != nil {
		return "", fmt.Errorf("failed to check if container is running: %v", err)
	}
	if !isRunning {
		return "", fmt.Errorf("external container is not running on machine")
	}
	logsCmd := buildContainerLogsCmd(container.Name)
	logsCmd = addElevatedPrivileges(logsCmd)
	res, err := m.execCmd(logsCmd)
	if err != nil {
		return "", fmt.Errorf("failed to execute command (%s) within machine %s: err: %v", logsCmd, m.name, err)
	}
	return res.stdout, nil
}

func (m *machine) execCmd(cmd string) (result, error) {
	ginkgo.By("Running command on test machine: " + cmd)
	var r result
	signer, err := getSigner()
	if err != nil {
		return r, fmt.Errorf("error getting signer: %w", err)
	}
	var ip string
	// When network string is empty, then retrieve any available IP address
	// from the machine.
	ip, err = m.getIP()
	if err != nil {
		return r, fmt.Errorf("failed to get valid IP: %w", err)
	}
	r, err = runSSHCommand(cmd, ip+":22", signer)
	if err != nil {
		return r, fmt.Errorf("failed to run SSH command for %s@%s: %w: %+v", machineUserName, ip, err, r)
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
	m, err := ensureTestMachine(testMachineName)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure %s machine to host the container: %v", testMachineName, err)
	}
	m.containers = map[string]*api.ExternalContainer{}
	m.networksForContainer = map[string]map[string]any{}
	o := openshift{externalContainerPortAlloc: portalloc.New(30000, 32767), hostPortAlloc: portalloc.New(30000, 32767),
		kubeClient: kubeClient, platform: infra.Spec.PlatformSpec.Type, mu: &sync.Mutex{}, sharedMachine: m}
	return o, nil
}

func (o openshift) Name() string {
	return "openshift"
}

func (o openshift) PrimaryNetwork() (api.Network, error) {
	var networkName string
	if o.platform == configv1.BareMetalPlatformType {
		networkName = os.Getenv("BAREMETAL_NETWORK_NAME")
		if networkName == "" {
			ginkgo.GinkgoLogr.Info("Network name env is not set for baremetal cluster, using default network name")
			networkName = defaultNetworkName
		}
	}
	if networkName == "" {
		return nil, fmt.Errorf("failed to find primary network for the cluster")
	}
	return getNetwork(networkName)
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
	if !isKcliInstalled() {
		ginkgo.Skip("kcli is not installed, so creation of external container is unsupported with this cluster")
	}
	if valid, err := container.IsValidPreCreateContainer(); !valid {
		return container, fmt.Errorf("failed to create external container: %w", err)
	}
	c.machineLock.Lock()
	defer c.machineLock.Unlock()

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
		return fmt.Errorf("external container is invalid: %v", err)
	}
	c.machineLock.Lock()
	defer c.machineLock.Unlock()
	return c.sharedMachine.deleteContainer(container)
}

func (c *contextOpenshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	c.machineLock.Lock()
	defer c.machineLock.Unlock()
	return c.sharedMachine.getContainerLogs(container)
}

func (c contextOpenshift) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	if len(subnets) != 1 {
		return nil, fmt.Errorf("network must be provided with one subnet")
	}
	c.machineLock.Lock()
	defer c.machineLock.Unlock()
	networks, err := listNetworks()
	if err != nil {
		return nil, err
	}
	if net, ok := networks[name]; ok {
		return &net, nil
	}
	return createNetwork(name, subnets[0])
}

func (c contextOpenshift) DeleteNetwork(network api.Network) error {
	name := network.Name()
	_, err := getNetwork(name)
	if err != nil {
		return err
	}
	c.machineLock.Lock()
	defer c.machineLock.Unlock()
	if c.sharedMachine.isNetworkUsedByAnyContainer(name) {
		return fmt.Errorf("container is still attached with network %s, can't delete it", name)
	}
	return deleteNetwork(name)
}

func (c *contextOpenshift) GetAttachedNetworks() (api.Networks, error) {
	panic("not implemented")
}

func (c *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	panic("not implemented")
}

func (c contextOpenshift) AttachNetwork(network api.Network, instance string) (api.NetworkInterface, error) {
	name := network.Name()
	_, err := getNetwork(name)
	if err != nil {
		return api.NetworkInterface{}, err
	}

	c.machineLock.Lock()
	defer c.machineLock.Unlock()

	if _, ok := c.sharedMachine.containers[instance]; !ok {
		return api.NetworkInterface{}, fmt.Errorf("container %s not found", instance)
	}

	nwIface, err := c.sharedMachine.attachNetwork(name)
	if err != nil {
		return api.NetworkInterface{}, err
	}

	// Track that this container now uses this network
	if c.sharedMachine.networksForContainer[instance] == nil {
		c.sharedMachine.networksForContainer[instance] = map[string]any{}
	}
	c.sharedMachine.networksForContainer[instance][name] = nil

	return nwIface, nil
}

func (c contextOpenshift) DetachNetwork(network api.Network, instance string) error {
	name := network.Name()
	_, err := getNetwork(name)
	if err != nil {
		return err
	}

	c.machineLock.Lock()
	defer c.machineLock.Unlock()
	// Check if container actually has this network
	if networks, exists := c.sharedMachine.networksForContainer[instance]; exists {
		if _, hasNet := networks[name]; !hasNet {
			return fmt.Errorf("network %s is not attached to container %s", name, instance)
		}
	} else {
		return fmt.Errorf("container %s not found in network tracking", instance)
	}

	// Remove network from container's tracking
	delete(c.sharedMachine.networksForContainer[instance], name)

	// Clean up empty map if no networks remain
	if len(c.sharedMachine.networksForContainer[instance]) == 0 {
		delete(c.sharedMachine.networksForContainer, instance)
	}

	// Detach network from VM only if no other container uses it
	return c.sharedMachine.detachNetworkIfUnused(name)
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
