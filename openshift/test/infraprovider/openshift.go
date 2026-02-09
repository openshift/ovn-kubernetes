package infraprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
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
)

const (
	ovnAnnotationNodeIfAddr = "k8s.ovn.org/node-primary-ifaddr"
)

type openshift struct {
	vm                         *vm
	vmLock                     *sync.Mutex
	externalContainerPortAlloc *portalloc.PortAllocator
	hostPortAlloc              *portalloc.PortAllocator
	kubeClient                 *kubernetes.Clientset
}

func New(config *rest.Config) (api.Provider, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
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
			// Initialize network links information
			if err := m.initializeNetworkLinks(); err != nil {
				ginkgo.GinkgoLogr.Info("Failed to initialize network links, external container support disabled", "error", err.Error())
				m = nil
			} else {
				m.containers = map[string]*api.ExternalContainer{}
				ginkgo.GinkgoLogr.Info("External container support enabled")
			}
		}
	}
	o := openshift{externalContainerPortAlloc: portalloc.New(30000, 32767), hostPortAlloc: portalloc.New(30000, 32767),
		kubeClient: kubeClient, vmLock: &sync.Mutex{}, vm: m}
	return o, nil
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
	return hostNetwork{name: defaultNetworkName, cidr: cidr.String()}, nil
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

// GetExternalContainerPID implements api.Provider.
func (o openshift) GetExternalContainerPID(containerName string) (int, error) {
	panic("unimplemented")
}

// RunOneShotContainer implements api.Provider.
func (o openshift) RunOneShotContainer(image string, cmd []string, runtimeArgs []string) (string, error) {
	panic("unimplemented")
}

func (o openshift) NewTestContext() api.Context {
	co := &contextOpenshift{32700, o.kubeClient, o.vm, o.vmLock,
		make([]api.ExternalContainer, 0), make([]func() error, 0)}
	ginkgo.DeferCleanup(co.CleanUp)
	return co
}

func (o openshift) execContainer(container api.ExternalContainer, cmd []string) (string, error) {
	o.vmLock.Lock()
	defer o.vmLock.Unlock()
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
	vm                *vm
	vmLock            *sync.Mutex
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
	c.vmLock.Lock()
	defer c.vmLock.Unlock()

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
	c.vmLock.Lock()
	defer c.vmLock.Unlock()
	if c.vm == nil {
		return fmt.Errorf("external container support is not available (test vm not configured)")
	}
	return c.vm.deleteContainer(container)
}

func (c *contextOpenshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	c.vmLock.Lock()
	defer c.vmLock.Unlock()
	if c.vm == nil {
		return "", fmt.Errorf("external container support is not available (test vm not configured)")
	}
	return c.vm.getContainerLogs(container)
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
