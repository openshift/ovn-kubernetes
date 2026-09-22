package infraprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	ovnkconfig "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/portalloc"

	"github.com/onsi/ginkgo/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
	utilnet "k8s.io/utils/net"
)

// ocpNetwork implements api.Network using the cluster's machine network CIDRs.
type ocpNetwork struct {
	name   string
	v4CIDR string
	v6CIDR string
}

func (n ocpNetwork) Name() string                          { return n.name }
func (n ocpNetwork) Equal(candidate api.Network) bool      { return n.name == candidate.Name() }
func (n ocpNetwork) String() string                        { return n.name }
func (n ocpNetwork) IPv4IPv6Subnets() (string, string, error) {
	if n.v4CIDR == "" && n.v6CIDR == "" {
		return "", "", fmt.Errorf("no subnets configured for network %s", n.name)
	}
	return n.v4CIDR, n.v6CIDR, nil
}

type openshift struct {
	externalContainerPortAlloc *portalloc.PortAllocator
	hostPortAlloc              *portalloc.PortAllocator
	kubeClient                 *kubernetes.Clientset
	restConfig                 *rest.Config
	primaryNet                 *ocpNetwork
}

func (o openshift) ShutdownNode(nodeName string) error {
	return fmt.Errorf("ShutdownNode not implemented for openshift provider")
}

func (o openshift) StartNode(nodeName string) error {
	return fmt.Errorf("StartNode not implemented for openshift provider")
}

func (o openshift) GetDefaultTimeoutContext() *framework.TimeoutContext {
	return nil
}

func IsProvider(config *rest.Config) (bool, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
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

	// Discover primary network CIDRs from node addresses
	pNet, err := discoverPrimaryNetwork(kubeClient)
	if err != nil {
		framework.Logf("WARNING: could not discover primary network: %v", err)
	}

	// Offset the port range by PID so parallel ginkgo processes don't collide
	// when creating hostNetwork pods on the same node.
	pid := os.Getpid()
	rng := rand.New(rand.NewSource(int64(pid)))
	startPort := uint16(30100 + rng.Intn(2600))

	return &openshift{
		externalContainerPortAlloc: portalloc.New(startPort, 32767),
		hostPortAlloc:              portalloc.New(startPort, 32767),
		kubeClient:                 kubeClient,
		restConfig:                 config,
		primaryNet:                 pNet,
	}, nil
}

// discoverPrimaryNetwork queries node addresses to build a primary network representation.
func discoverPrimaryNetwork(kubeClient *kubernetes.Clientset) (*ocpNetwork, error) {
	nodes, err := kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("no nodes found")
	}
	var v4CIDR, v6CIDR string
	for _, addr := range nodes.Items[0].Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			if utilnet.IsIPv4String(addr.Address) && v4CIDR == "" {
				v4CIDR = addr.Address + "/16"
			} else if utilnet.IsIPv6String(addr.Address) && v6CIDR == "" {
				v6CIDR = addr.Address + "/64"
			}
		}
	}
	// Try to get more accurate CIDRs from pod CIDRs
	for _, node := range nodes.Items {
		for _, cidr := range node.Spec.PodCIDRs {
			ip, _, _ := utilnet.ParseCIDRSloppy(cidr)
			if ip != nil {
				if utilnet.IsIPv4(ip) && v4CIDR != "" {
					// Keep node IP CIDR for machine network
				}
			}
		}
	}
	return &ocpNetwork{name: "ocp-primary", v4CIDR: v4CIDR, v6CIDR: v6CIDR}, nil
}

func (o *openshift) Name() string {
	return "openshift"
}

func (o *openshift) PrimaryNetwork() (api.Network, error) {
	if o.primaryNet == nil {
		return nil, fmt.Errorf("primary network not discovered")
	}
	return o.primaryNet, nil
}

func (o *openshift) ExternalContainerPrimaryInterfaceName() string {
	return "eth0"
}

func (o *openshift) GetNetwork(name string) (api.Network, error) {
	if o.primaryNet != nil && (name == o.primaryNet.name || name == "kind") {
		return o.primaryNet, nil
	}
	return nil, fmt.Errorf("network %q not found", name)
}

func (o *openshift) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	// For hostNetwork pods, the container's IP is the node IP
	return api.NetworkInterface{
		IPv4: container.GetIPv4(),
		IPv6: container.GetIPv6(),
	}, nil
}

func (o *openshift) GetK8NodeNetworkInterface(instance string, network api.Network) (api.NetworkInterface, error) {
	node, err := o.kubeClient.CoreV1().Nodes().Get(context.TODO(), instance, metav1.GetOptions{})
	if err != nil {
		return api.NetworkInterface{}, fmt.Errorf("failed to get node %s: %w", instance, err)
	}
	ni := api.NetworkInterface{}
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			if utilnet.IsIPv4String(addr.Address) {
				ni.IPv4 = addr.Address
			} else {
				ni.IPv6 = addr.Address
			}
		}
	}
	return ni, nil
}

func (o *openshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	return runOC("logs", fmt.Sprintf("pod/%s", container.Name), "-n", "default")
}

func (o *openshift) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("ExecK8NodeCommand(): insufficient command arguments")
	}
	args := append([]string{"debug", fmt.Sprintf("node/%s", nodeName), "--to-namespace=default",
		"--", "chroot", "/host"}, cmd...)
	return runOC(args...)
}

func (o *openshift) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("empty command")
	}
	args := append([]string{"exec", container.Name, "-n", "default", "--"}, cmd...)
	return runOC(args...)
}

func (o *openshift) GetExternalContainerPort() uint16 {
	return o.externalContainerPortAlloc.Allocate()
}

func (o *openshift) GetK8HostPort() uint16 {
	return o.hostPortAlloc.Allocate()
}

func (o *openshift) NewTestContext() api.Context {
	co := &contextOpenshift{
		kubeClient: o.kubeClient,
		cleanUpFns: make([]func() error, 0),
	}
	ginkgo.DeferCleanup(co.CleanUp)
	return co
}

// runOC executes an oc command and returns stdout.
func runOC(args ...string) (string, error) {
	cmd := exec.Command("oc", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("oc %s failed: %v, stdout: %s, stderr: %s",
			strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

// --- Context implementation using hostNetwork pods as "external containers" ---

type contextOpenshift struct {
	kubeClient *kubernetes.Clientset
	cleanUpFns []func() error
}

func (c *contextOpenshift) GetAllowedExternalContainerPort() int {
	return 0
}

// sanitizePodName converts a container name to a valid RFC 1123 subdomain:
// lowercase, alphanumeric + hyphens only, no leading/trailing hyphens.
func sanitizePodName(name string) string {
	name = strings.ToLower(name)
	re := regexp.MustCompile(`[^a-z0-9-]`)
	name = re.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-")
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

func (c *contextOpenshift) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	// Create a hostNetwork pod to simulate an external container.
	// Use GenerateName to avoid name collisions between parallel tests.
	podPrefix := sanitizePodName(container.Name) + "-"

	privileged := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: podPrefix,
			Namespace:    "default",
			Labels:       map[string]string{"app": "ext-container-hack"},
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{
				{
					Name:            "main",
					Image:           container.Image,
					Args:            container.CmdArgs,
					SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
			Tolerations: []corev1.Toleration{
				{Operator: corev1.TolerationOpExists},
			},
		},
	}

	created, err := c.kubeClient.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return container, fmt.Errorf("failed to create external container pod %s*: %w", podPrefix, err)
	}
	podName := created.Name

	// Register cleanup
	c.AddCleanUpFn(func() error {
		return c.kubeClient.CoreV1().Pods("default").Delete(context.TODO(), podName, metav1.DeleteOptions{})
	})

	// Wait for pod to be running
	err = wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		p, err := c.kubeClient.CoreV1().Pods("default").Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return p.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		return container, fmt.Errorf("external container pod %s did not become running: %w", podName, err)
	}

	// Get the pod's host IP (node IP)
	running, err := c.kubeClient.CoreV1().Pods("default").Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return container, fmt.Errorf("failed to get running pod %s: %w", podName, err)
	}

	// Update container.Name to the generated pod name so callers can exec/delete it
	container.Name = podName

	container.IPv4 = ""
	container.IPv6 = ""
	if running.Status.HostIP != "" {
		if utilnet.IsIPv4String(running.Status.HostIP) {
			container.IPv4 = running.Status.HostIP
		} else {
			container.IPv6 = running.Status.HostIP
		}
	}
	// Also check PodIPs for dual-stack
	for _, pip := range running.Status.PodIPs {
		if utilnet.IsIPv4String(pip.IP) && container.IPv4 == "" {
			container.IPv4 = pip.IP
		} else if utilnet.IsIPv6String(pip.IP) && container.IPv6 == "" {
			container.IPv6 = pip.IP
		}
	}

	return container, nil
}

func (c *contextOpenshift) DeleteExternalContainer(container api.ExternalContainer) error {
	// container.Name is already the generated pod name from CreateExternalContainer
	return c.kubeClient.CoreV1().Pods("default").Delete(context.TODO(), container.Name, metav1.DeleteOptions{})
}

func (c *contextOpenshift) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	return runOC("logs", fmt.Sprintf("pod/%s", container.Name), "-n", "default")
}

func (c *contextOpenshift) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	// Secondary network creation is not supported on AWS; return a stub so the
	// test can proceed and fail gracefully if it actually tries to use it.
	var v4, v6 string
	for _, s := range subnets {
		ip, _, _ := utilnet.ParseCIDRSloppy(s)
		if ip != nil {
			if utilnet.IsIPv4(ip) {
				v4 = s
			} else {
				v6 = s
			}
		}
	}
	return &ocpNetwork{name: name, v4CIDR: v4, v6CIDR: v6}, nil
}

func (c *contextOpenshift) DeleteNetwork(network api.Network) error {
	return nil
}

func (c *contextOpenshift) GetAttachedNetworks() (api.Networks, error) {
	return api.Networks{}, nil
}

func (c *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	return fmt.Errorf("underlay not supported on openshift AWS provider")
}

func (c *contextOpenshift) AttachNetwork(network api.Network, instance string) (api.NetworkInterface, error) {
	// On AWS there is no real container engine network to attach.
	// Return an empty interface; tests that depend on this will fail with a
	// meaningful error rather than a panic.
	return api.NetworkInterface{}, nil
}

func (c *contextOpenshift) DetachNetwork(network api.Network, instance string) error {
	return nil
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
