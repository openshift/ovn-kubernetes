package infraprovider

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	ovnkconfig "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/portalloc"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
)

type openshift struct {
	externalContainerPortAlloc *portalloc.PortAllocator
	hostPortAlloc              *portalloc.PortAllocator
	kubeClient                 *kubernetes.Clientset
}

func (o openshift) ShutdownNode(nodeName string) error {
	panic("not implemented")
}

func (o openshift) StartNode(nodeName string) error {
	panic("not implemented")
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
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
	}
	return openshift{
		externalContainerPortAlloc: portalloc.New(30000, 32767),
		hostPortAlloc:              portalloc.New(30000, 32767),
		kubeClient:                 kubeClient,
	}, nil
}

func (o openshift) Name() string {
	return "openshift"
}

func (o openshift) PrimaryNetwork() (api.Network, error) {
	panic("not implemented")
}

func (o openshift) ExternalContainerPrimaryInterfaceName() string {
	panic("not implemented")
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
	panic("not implemented")
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
	panic("not implemented")
}

func (o openshift) GetExternalContainerPort() uint16 {
	return o.externalContainerPortAlloc.Allocate()
}

func (o openshift) GetK8HostPort() uint16 {
	return o.hostPortAlloc.Allocate()
}

func (o openshift) NewTestContext() api.Context {
	co := &contextOpenshift{make([]func() error, 0)}
	ginkgo.DeferCleanup(co.CleanUp)
	return co
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
	// generic cleanup activities
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
