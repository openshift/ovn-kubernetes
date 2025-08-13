package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/containerengine"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/images"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider"
	infraapi "github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"

	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	e2edeployment "k8s.io/kubernetes/test/e2e/framework/deployment"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
	testutils "k8s.io/kubernetes/test/utils"
	kexec "k8s.io/utils/exec"
	utilnet "k8s.io/utils/net"
)

const (
	podNetworkAnnotation = "k8s.ovn.org/pod-networks"
	retryInterval        = 1 * time.Second  // polling interval timer
	retryTimeout         = 40 * time.Second // polling timeout
	rolloutTimeout       = 10 * time.Minute
	redirectIP           = "123.123.123.123"
	redirectPort         = "13337"
	defaultPodInterface  = "eth0"
	udnPodInterface      = "ovn-udn1"
)

type podCondition = func(pod *v1.Pod) (bool, error)

// setupHostRedirectPod
func setupHostRedirectPod(f *framework.Framework, externalContainer infraapi.ExternalContainer, nodeName, nodeIP string, isIPv6 bool) error {
	mask := 32
	ipCmd := []string{"ip"}
	if isIPv6 {
		mask = 128
		ipCmd = []string{"ip", "-6"}
	}
	cmd := []string{}
	cmd = append(cmd, ipCmd...)
	cmd = append(cmd, "route", "add", fmt.Sprintf("%s/%d", redirectIP, mask), "via", nodeIP)
	_, err := infraprovider.Get().ExecExternalContainerCommand(externalContainer, cmd) // cleanup not needed because containers persist for a single tests lifetime
	if err != nil {
		return err
	}

	// setup redirect iptables rule in node
	ipTablesArgs := []string{"PREROUTING", "-t", "nat", "--dst", redirectIP, "-j", "REDIRECT"}
	updateIPTablesRulesForNode("insert", nodeName, ipTablesArgs, isIPv6)

	command := []string{
		"bash", "-c",
		fmt.Sprintf("set -xe; while true; do nc -l -p %s; done",
			redirectPort),
	}
	tcpServer := "tcp-continuous-server"
	// setup host networked pod to act as server
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: tcpServer,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    tcpServer,
					Image:   images.AgnHost(),
					Command: command,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
			HostNetwork:   true,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err = podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	err = e2epod.WaitForPodNotPending(context.TODO(), f.ClientSet, f.Namespace.Name, tcpServer)
	return err
}

// checkContinuousConnectivity creates a pod and checks that it can connect to the given host over tries*2 seconds.
// The created pod object is sent to the podChan while any errors along the way are sent to the errChan.
// Callers are expected to read the errChan and verify that they received a nil before fetching
// the pod from the podChan to be sure that the pod was created successfully.
// TODO: this approach with the channels is a bit ugly, it might be worth to refactor this and the other
// functions that use it similarly in this file.
func checkContinuousConnectivity(f *framework.Framework, nodeName, podName, host string, port, tries, timeout int, podChan chan *v1.Pod, errChan chan error) {
	contName := fmt.Sprintf("%s-container", podName)

	command := []string{
		"bash", "-c",
		fmt.Sprintf("set -xe; for i in {1..%d}; do nc -vz -w %d %s %d ; sleep 2; done",
			tries, timeout, host, port),
	}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    contName,
					Image:   images.AgnHost(),
					Command: command,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		errChan <- err
		return
	}

	// Wait for pod network setup to be almost ready
	err = wait.PollImmediate(1*time.Second, 30*time.Second, func() (bool, error) {
		pod, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		_, ok := pod.Annotations[podNetworkAnnotation]
		return ok, nil
	})
	if err != nil {
		errChan <- err
		return
	}

	err = e2epod.WaitForPodNotPending(context.TODO(), f.ClientSet, f.Namespace.Name, podName)
	if err != nil {
		errChan <- err
		return
	}

	podGet, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		errChan <- err
		return
	}

	errChan <- nil
	podChan <- podGet

	err = e2epod.WaitForPodSuccessInNamespace(context.TODO(), f.ClientSet, podName, f.Namespace.Name)

	if err != nil {
		logs, logErr := e2epod.GetPodLogs(context.TODO(), f.ClientSet, f.Namespace.Name, pod.Name, contName)
		if logErr != nil {
			framework.Logf("Warning: Failed to get logs from pod %q: %v", pod.Name, logErr)
		} else {
			framework.Logf("pod %s/%s logs:\n%s", f.Namespace.Name, pod.Name, logs)
		}
	}

	errChan <- err
}

// pingCommand is the type to hold ping command.
type pingCommand string

const (
	// ipv4PingCommand is a ping command for IPv4.
	ipv4PingCommand pingCommand = "ping"
	// ipv6PingCommand is a ping command for IPv6.
	ipv6PingCommand pingCommand = "ping6"
)

// Place the workload on the specified node to test external connectivity
func checkConnectivityPingToHost(f *framework.Framework, nodeName, podName, host string, pingCmd pingCommand, timeout int) error {
	contName := fmt.Sprintf("%s-container", podName)
	// Ping options are:
	// -c sends 3 pings
	// -W wait at most 2 seconds for a reply
	// -w timeout
	command := []string{"/bin/sh", "-c"}
	args := []string{fmt.Sprintf("sleep 20; %s -c 3 -W 2 -w %s %s", string(pingCmd), strconv.Itoa(timeout), host)}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    contName,
					Image:   images.AgnHost(),
					Command: command,
					Args:    args,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	// Wait for pod network setup to be almost ready
	err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
		pod, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		_, ok := pod.Annotations[podNetworkAnnotation]
		return ok, nil
	})
	// Fail the test if no pod annotation is retrieved
	if err != nil {
		framework.Failf("Error trying to get the pod annotation")
	}

	err = e2epod.WaitForPodSuccessInNamespace(context.TODO(), f.ClientSet, podName, f.Namespace.Name)

	if err != nil {
		logs, logErr := e2epod.GetPodLogs(context.TODO(), f.ClientSet, f.Namespace.Name, pod.Name, contName)
		if logErr != nil {
			framework.Logf("Warning: Failed to get logs from pod %q: %v", pod.Name, logErr)
		} else {
			framework.Logf("pod %s/%s logs:\n%s", f.Namespace.Name, pod.Name, logs)
		}
	}

	return err
}

// Place the workload on the specified node and return pod gw route
func getPodGWRoute(f *framework.Framework, nodeName string, podName string) net.IP {
	command := []string{"bash", "-c", "sleep 20000"}
	contName := fmt.Sprintf("%s-container", podName)
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    contName,
					Image:   images.AgnHost(),
					Command: command,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		framework.Failf("Error trying to create pod")
	}

	// Wait for pod network setup to be almost ready
	wait.PollImmediate(1*time.Second, 30*time.Second, func() (bool, error) {
		podGet, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if podGet.Annotations != nil && podGet.Annotations[podNetworkAnnotation] != "" {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		framework.Failf("Error trying to get the pod annotations")
	}

	podGet, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		framework.Failf("Error trying to get the pod object")
	}
	annotation, err := unmarshalPodAnnotation(podGet.Annotations, "default")
	if err != nil {
		framework.Failf("Error trying to unmarshal pod annotations")
	}

	return annotation.Gateways[0]
}

// Create a pod on the specified node using the agnostic host image
func createGenericPod(f *framework.Framework, podName, nodeSelector, namespace string, command []string) (*v1.Pod, error) {
	return createPod(f, podName, nodeSelector, namespace, command, nil)
}

// Create a pod on the specified node using the agnostic host image
func createGenericPodWithLabel(f *framework.Framework, podName, nodeSelector, namespace string, command []string, labels map[string]string, options ...func(*v1.Pod)) (*v1.Pod, error) {
	return createPod(f, podName, nodeSelector, namespace, command, labels, options...)
}

func createServiceForPodsWithLabel(f *framework.Framework, namespace string, servicePort, targetPort uint16, serviceType string, labels map[string]string) (string, error) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-for-pods",
			Namespace: namespace,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Protocol:   v1.ProtocolTCP,
					TargetPort: intstr.FromInt(int(targetPort)),
					Port:       int32(servicePort),
				},
			},
			Type:     v1.ServiceType(serviceType),
			Selector: labels,
		},
	}
	serviceClient := f.ClientSet.CoreV1().Services(namespace)
	res, err := serviceClient.Create(context.Background(), service, metav1.CreateOptions{})
	if err != nil {
		return "", errors.Wrapf(err, "Failed to create service %s %s", service.Name, namespace)
	}
	err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
		res, err = serviceClient.Get(context.Background(), service.Name, metav1.GetOptions{})
		return res.Spec.ClusterIP != "", err
	})
	if err != nil {
		return "", errors.Wrapf(err, "Failed to get service %s %s", service.Name, namespace)
	}
	return res.Spec.ClusterIP, nil
}

// HACK: 'container runtime' is statically set to docker. For EIP multi network scenario, we require ip6tables support to
// allow isolated ipv6 networks and prevent the bridges from forwarding to each other.
// Docker ipv6+ip6tables support is currently experimental (11/23) [1], and enabling this requires altering the
// container runtime config. To avoid altering the runtime config, add ip6table rules to prevent the bridges talking
// to each other. Not required to remove the iptables, because when we delete the network, the iptable rules will be removed.
// Remove when this func when it is no longer experimental.
// [1] https://docs.docker.com/config/daemon/ipv6/
func isolateKinDIPv6Networks(networkA, networkB string) error {
	if infraprovider.Get().Name() != "kind" {
		// nothing to do
		return nil
	}
	if containerengine.Get() != containerengine.Docker {
		panic("unsupported container runtime")
	}
	var bridgeInfNames []string
	// docker creates bridges by appending 12 chars from network ID to 'br-'
	bridgeIDLimit := 12
	exec := kexec.New()
	for _, network := range []string{networkA, networkB} {
		// output will be wrapped in single quotes
		idByte, err := exec.Command("docker", "inspect", network, "--format", "'{{.Id}}'").CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to inspect network %s: %v", network, err)
		}
		id := string(idByte)
		if len(id) <= bridgeIDLimit+1 {
			return fmt.Errorf("invalid bridge ID %q", id)
		}
		bridgeInfName := fmt.Sprintf("br-%s", id[1:bridgeIDLimit+1])
		// validate bridge exists
		_, err = exec.Command("ip", "link", "show", bridgeInfName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("bridge %q doesnt exist: %v", bridgeInfName, err)
		}
		bridgeInfNames = append(bridgeInfNames, bridgeInfName)
	}
	if len(bridgeInfNames) != 2 {
		return fmt.Errorf("expected two bridge names but found %d", len(bridgeInfNames))
	}
	_, err := exec.Command("sudo", "ip6tables", "-t", "filter", "-A", "FORWARD", "-i", bridgeInfNames[0], "-o", bridgeInfNames[1], "-j", "DROP").CombinedOutput()
	if err != nil {
		return err
	}
	_, err = exec.Command("sudo", "ip6tables", "-t", "filter", "-A", "FORWARD", "-i", bridgeInfNames[1], "-o", bridgeInfNames[0], "-j", "DROP").CombinedOutput()
	return err
}

// forwardIPWithIPTables inserts an iptables rule to always accept source and destination of arg ip
func forwardIPWithIPTables(ip string) (func() error, error) {
	isIPv6 := utilnet.IsIPv6String(ip)
	ipTablesBin := "iptables"
	if isIPv6 {
		ipTablesBin = "ip6tables"
	}
	mask := "/32"
	if isIPv6 {
		mask = "/128"
	}

	var cleanUpFns []func() error
	cleanUp := func() error {
		var errs []error
		for _, cleanUpFn := range cleanUpFns {
			if err := cleanUpFn(); err != nil {
				errs = append(errs, err)
			}
		}
		return utilerrors.AggregateGoroutines(cleanUpFns...)
	}
	exec := kexec.New()
	_, err := exec.Command("sudo", ipTablesBin, "-I", "FORWARD", "-s", ip+mask, "-j", "ACCEPT").CombinedOutput()
	if err != nil {
		return cleanUp, fmt.Errorf("failed to insert rule to forward IP %q: %w", ip+mask, err)
	}
	cleanUpFns = append(cleanUpFns, func() error {
		exec.Command("sudo", ipTablesBin, "-D", "FORWARD", "-s", ip+mask, "-j", "ACCEPT").CombinedOutput()
		return nil
	})
	_, err = exec.Command("sudo", ipTablesBin, "-I", "FORWARD", "-d", ip+mask, "-j", "ACCEPT").CombinedOutput()
	if err != nil {
		return cleanUp, fmt.Errorf("failed to insert rule to forward IP %q: %w", ip+mask, err)
	}
	cleanUpFns = append(cleanUpFns, func() error {
		exec.Command("sudo", ipTablesBin, "-D", "FORWARD", "-d", ip+mask, "-j", "ACCEPT").CombinedOutput()
		return nil
	})
	return cleanUp, nil
}

// updatesNamespace labels while preserving the required UDN label
func updateNamespaceLabels(f *framework.Framework, namespace *v1.Namespace, labels map[string]string) {
	// should never be nil
	n := *namespace
	for k, v := range labels {
		n.Labels[k] = v
	}
	if _, ok := namespace.Labels[RequiredUDNNamespaceLabel]; ok {
		n.Labels[RequiredUDNNamespaceLabel] = ""
	}
	_, err := f.ClientSet.CoreV1().Namespaces().Update(context.Background(), &n, metav1.UpdateOptions{})
	framework.ExpectNoError(err, fmt.Sprintf("unable to update namespace: %s, err: %v", namespace.Name, err))
}
func getNamespace(f *framework.Framework, name string) *v1.Namespace {
	ns, err := f.ClientSet.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
	framework.ExpectNoError(err, fmt.Sprintf("unable to get namespace: %s, err: %v", name, err))
	return ns
}

func updatePod(f *framework.Framework, pod *v1.Pod) {
	_, err := f.ClientSet.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
	framework.ExpectNoError(err, fmt.Sprintf("unable to update pod: %s, err: %v", pod.Name, err))
}
func getPod(f *framework.Framework, podName string) *v1.Pod {
	pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(context.Background(), podName, metav1.GetOptions{})
	framework.ExpectNoError(err, fmt.Sprintf("unable to get pod: %s, err: %v", podName, err))
	return pod
}

// Create a pod on the specified node using the agnostic host image
func createPod(f *framework.Framework, podName, nodeSelector, namespace string, command []string, labels map[string]string, options ...func(*v1.Pod)) (*v1.Pod, error) {

	contName := fmt.Sprintf("%s-container", podName)

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podName,
			Labels: labels,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    contName,
					Image:   images.AgnHost(),
					Command: command,
				},
			},
			NodeName:      nodeSelector,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}

	for _, o := range options {
		o(pod)
	}

	podClient := f.ClientSet.CoreV1().Pods(namespace)
	res, err := podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		framework.Logf("Warning: Failed to create pod %s %v", pod.Name, err)
		return nil, errors.Wrapf(err, "Failed to create pod %s %s", pod.Name, namespace)
	}

	err = e2epod.WaitForPodRunningInNamespace(context.TODO(), f.ClientSet, res)

	if err != nil {
		res, err = podClient.Get(context.Background(), pod.Name, metav1.GetOptions{})
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to get pod %s %s", pod.Name, namespace)
		}
		framework.Logf("Warning: Failed to get pod running %v: %v", *res, err)
		logs, logErr := e2epod.GetPodLogs(context.TODO(), f.ClientSet, namespace, pod.Name, contName)
		if logErr != nil {
			framework.Logf("Warning: Failed to get logs from pod %q: %v", pod.Name, logErr)
		} else {
			framework.Logf("pod %s/%s logs:\n%s", namespace, pod.Name, logs)
		}
	}
	// Need to get it again to ensure the ip addresses are filled
	res, err = podClient.Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get pod %s %s", pod.Name, namespace)
	}
	return res, nil
}

// Get the IP address of a pod in the specified namespace
func getPodAddress(podName, namespace string) string {
	podIP, err := e2ekubectl.RunKubectl(namespace, "get", "pods", podName, "--template={{.status.podIP}}")
	if err != nil {
		framework.Failf("Unable to retrieve the IP for pod %s %v", podName, err)
	}
	return podIP
}

// Get the IP address of the API server
func getApiAddress() string {
	apiServerIP, err := e2ekubectl.RunKubectl("default", "get", "svc", "kubernetes", "-o", "jsonpath='{.spec.clusterIP}'")
	apiServerIP = strings.Trim(apiServerIP, "'")
	if err != nil {
		framework.Failf("Error: unable to get API-server IP address, err:  %v", err)
	}
	apiServer := net.ParseIP(apiServerIP)
	if apiServer == nil {
		framework.Failf("Error: unable to parse API-server IP address:  %s", apiServerIP)
	}
	return apiServer.String()
}

// IsGatewayModeLocal returns true if the gateway mode is local
func IsGatewayModeLocal(cs kubernetes.Interface) bool {
	ginkgo.GinkgoHelper()
	node, err := e2enode.GetRandomReadySchedulableNode(context.TODO(), cs)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	l3Config, err := util.ParseNodeL3GatewayAnnotation(node)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "must get node l3 gateway annotation")
	return l3Config.Mode == config.GatewayModeLocal
}

// restartOVNKubeNodePod restarts the ovnkube-node pod from namespace, running on nodeName
func restartOVNKubeNodePod(clientset kubernetes.Interface, namespace string, nodeName string) error {
	ovnKubeNodePods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "name=ovnkube-node",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return fmt.Errorf("could not get ovnkube-node pods: %w", err)
	}

	if len(ovnKubeNodePods.Items) <= 0 {
		return fmt.Errorf("could not find ovnkube-node pod running on node %s", nodeName)
	}
	for _, pod := range ovnKubeNodePods.Items {
		if err := deletePodWithWait(context.TODO(), clientset, &pod); err != nil {
			return fmt.Errorf("could not delete ovnkube-node pod on node %s: %w", nodeName, err)
		}
	}

	framework.Logf("waiting for node %s to have running ovnkube-node pod", nodeName)
	err = wait.Poll(2*time.Second, 3*time.Minute, func() (bool, error) {
		ovnKubeNodePods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "name=ovnkube-node",
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err != nil {
			return false, fmt.Errorf("could not get ovnkube-node pods: %w", err)
		}

		if len(ovnKubeNodePods.Items) <= 0 {
			framework.Logf("Node %s has no ovnkube-node pod yet", nodeName)
			return false, nil
		}
		for _, pod := range ovnKubeNodePods.Items {
			if ready, err := testutils.PodRunningReady(&pod); !ready {
				framework.Logf("%v", err)
				return false, nil
			}
		}
		return true, nil
	})

	return err
}

// restartOVNKubeNodePodsInParallel restarts multiple ovnkube-node pods in parallel. See `restartOVNKubeNodePod`
func restartOVNKubeNodePodsInParallel(clientset kubernetes.Interface, namespace string, nodeNames ...string) error {
	framework.Logf("restarting ovnkube-node for %v", nodeNames)

	restartFuncs := make([]func() error, 0, len(nodeNames))
	for _, n := range nodeNames {
		nodeName := n
		restartFuncs = append(restartFuncs, func() error {
			return restartOVNKubeNodePod(clientset, namespace, nodeName)
		})
	}

	return utilerrors.AggregateGoroutines(restartFuncs...)
}

// getOVNKubePodLogsFiltered retrieves logs from ovnkube-node pods and filters logs lines according to filteringRegexp
func getOVNKubePodLogsFiltered(clientset kubernetes.Interface, namespace, nodeName, filteringRegexp string) (string, error) {
	ovnKubeNodePods, err := clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "name=ovnkube-node",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return "", fmt.Errorf("getOVNKubePodLogsFiltered: error while getting ovnkube-node pods: %w", err)
	}

	logs, err := e2epod.GetPodLogs(context.TODO(), clientset, namespace, ovnKubeNodePods.Items[0].Name, getNodeContainerName())
	if err != nil {
		return "", fmt.Errorf("getOVNKubePodLogsFiltered: error while getting ovnkube-node [%s/%s] logs: %w",
			namespace, ovnKubeNodePods.Items[0].Name, err)
	}

	scanner := bufio.NewScanner(strings.NewReader(logs))
	filteredLogs := ""
	re := regexp.MustCompile(filteringRegexp)
	for scanner.Scan() {
		line := scanner.Text()
		if re.MatchString(line) {
			filteredLogs += line + "\n"
		}
	}

	err = scanner.Err()
	if err != nil {
		return "", fmt.Errorf("getOVNKubePodLogsFiltered: error while scanning ovnkube-node logs: %w", err)
	}

	return filteredLogs, nil
}

func findOvnKubeControlPlaneNode(namespace, controlPlanePodName, leaseName string) (string, error) {

	ovnkubeControlPlaneNode, err := e2ekubectl.RunKubectl(namespace, "get", "leases", leaseName,
		"-o", "jsonpath='{.spec.holderIdentity}'")

	framework.ExpectNoError(err, fmt.Sprintf("Unable to retrieve leases (%s)"+
		"from %s %v", leaseName, namespace, err))

	framework.Logf("master instance of %s is running on node %s", controlPlanePodName, ovnkubeControlPlaneNode)
	// Strip leading and trailing quotes if present
	if ovnkubeControlPlaneNode[0] == '\'' || ovnkubeControlPlaneNode[0] == '"' {
		ovnkubeControlPlaneNode = ovnkubeControlPlaneNode[1 : len(ovnkubeControlPlaneNode)-1]
	}

	return ovnkubeControlPlaneNode, nil
}

var _ = ginkgo.Describe("e2e control plane", func() {
	var svcname = "nettest"

	f := wrappedTestFramework(svcname)

	var (
		extDNSIP                   string
		numControlPlanePods        int
		controlPlanePodName        string
		controlPlaneLeaseName      string
		providerCtx                infraapi.Context
		secondaryProviderNetwork   infraapi.Network
		secondaryExternalContainer infraapi.ExternalContainer
	)

	ginkgo.BeforeEach(func() {
		var err error
		providerCtx = infraprovider.Get().NewTestContext()
		secondaryProviderNetwork, err = providerCtx.CreateNetwork(secondaryNetworkName, secondaryIPV4Subnet)
		framework.ExpectNoError(err, "must get secondary network")
		ginkgo.DeferCleanup(func() error {
			return providerCtx.DeleteNetwork(secondaryProviderNetwork)
		})
		nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		framework.ExpectNoError(err, "must list all Nodes")
		ginkgo.By("attach secondary proivider network to all Nodes")
		for _, node := range nodeList.Items {
			_, err = providerCtx.AttachNetwork(secondaryProviderNetwork, node.Name)
			framework.ExpectNoError(err, "network %s must attach to node %s", secondaryProviderNetwork.Name(), node.Name)
		}
		secondaryExternalContainerPort := infraprovider.Get().GetExternalContainerPort()
		secondaryExternalContainerSpec := infraapi.ExternalContainer{Name: "e2e-ovn-k", Image: images.AgnHost(),
			Network: secondaryProviderNetwork, CmdArgs: getAgnHostHTTPPortBindCMDArgs(secondaryExternalContainerPort), ExtPort: secondaryExternalContainerPort}
		ginkgo.By("creating container on secondary provider network")
		secondaryExternalContainer, err = providerCtx.CreateExternalContainer(secondaryExternalContainerSpec)
		framework.ExpectNoError(err, "failed to create external container")
		// Assert basic external connectivity.
		// Since this is not really a test of kubernetes in any way, we
		// leave it as a pre-test assertion, rather than a Ginko test.
		ginkgo.By("Executing a successful http request from the external internet")
		_, err = http.Get("http://google.com")
		if err != nil {
			framework.Failf("Unable to connect/talk to the internet: %v", err)
		}

		if isInterconnectEnabled() {
			controlPlanePodName = "ovnkube-control-plane"
			// in "one node per zone" config, ovnkube-controller doesn't create leader election lease
			if !singleNodePerZone() {
				controlPlaneLeaseName = "ovn-kubernetes-master-ovn-control-plane"
			} else {
				controlPlaneLeaseName = "ovn-kubernetes-master"
			}
		} else {
			controlPlanePodName = "ovnkube-master"
			controlPlaneLeaseName = "ovn-kubernetes-master"
		}

		controlPlanePods, err := f.ClientSet.CoreV1().Pods(deploymentconfig.Get().OVNKubernetesNamespace()).List(context.Background(), metav1.ListOptions{
			LabelSelector: "name=" + controlPlanePodName,
		})
		framework.ExpectNoError(err)
		numControlPlanePods = len(controlPlanePods.Items)
		extDNSIP = "8.8.8.8"
		if IsIPv6Cluster(f.ClientSet) {
			extDNSIP = "2001:4860:4860::8888"
		}
	})

	ginkgo.It("should provide Internet connection continuously when ovnkube-node pod is killed", func() {
		ginkgo.By(fmt.Sprintf("Running container which tries to connect to %s in a loop", extDNSIP))

		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go func() {
			defer ginkgo.GinkgoRecover()
			checkContinuousConnectivity(f, "", "connectivity-test-continuous", extDNSIP, 53, 30, 30, podChan, errChan)
		}()

		err := <-errChan
		framework.ExpectNoError(err)

		testPod := <-podChan
		targetNodeName := testPod.Spec.NodeName
		targetNodeInterface, err := infraprovider.Get().GetK8NodeNetworkInterface(targetNodeName, secondaryProviderNetwork)
		framework.ExpectNoError(err, "must get Node %s address for network %s", targetNodeName, secondaryProviderNetwork.Name())
		targetNodeIP := targetNodeInterface.IPv4
		if IsIPv6Cluster(f.ClientSet) {
			targetNodeIP = targetNodeInterface.IPv6
		}
		gomega.Expect(targetNodeIP).NotTo(gomega.BeEmpty(), "unable to find Node IP for secondary network")
		framework.Logf("Target node is %q and IP is %q", targetNodeName, targetNodeIP)
		err = setupHostRedirectPod(f, secondaryExternalContainer, targetNodeName, targetNodeIP, IsIPv6Cluster(f.ClientSet))
		framework.ExpectNoError(err)

		cleanUp, err := forwardIPWithIPTables(redirectIP)
		ginkgo.DeferCleanup(cleanUp)

		// start TCP client
		go func() {
			defer ginkgo.GinkgoRecover()
			out, err := infraprovider.Get().ExecExternalContainerCommand(secondaryExternalContainer, []string{"nc", redirectIP, redirectPort})
			if err != nil {
				framework.Logf("external container %s exited with error: %q, stdout: %q", secondaryExternalContainer.Name, err, out)
			}
			if out != "" {
				framework.Logf("external container %s exisited with stdout: %q", secondaryExternalContainer.Name, out)
			}
			framework.Logf("external container with TCP client exited")
		}()

		ginkgo.By("Checking that TCP redirect connection entry in conntrack before ovnkube-node restart")
		gomega.Eventually(func() int {
			return pokeConntrackEntries(targetNodeName, redirectIP, "tcp", nil)
		}, "10s", "1s").ShouldNot(gomega.Equal(0))

		ginkgo.By("Deleting ovn-kube pod on node " + targetNodeName)
		err = restartOVNKubeNodePod(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), targetNodeName)
		framework.ExpectNoError(err)

		ginkgo.By("Ensuring there were no connectivity errors")
		framework.ExpectNoError(<-errChan)

		err = waitClusterHealthy(f, numControlPlanePods, controlPlanePodName)
		framework.ExpectNoError(err, "one or more nodes failed to go back ready, schedulable, and untainted")

		ginkgo.By("Checking that TCP redirect connection entry in conntrack remained after ovnkube-node restart")
		gomega.Consistently(func() int {
			return pokeConntrackEntries(targetNodeName, redirectIP, "tcp", nil)
		}, "5s", "500ms").ShouldNot(gomega.Equal(0))
	})

	ginkgo.It("should provide Internet connection continuously when pod running master instance of ovnkube-control-plane is killed", func() {
		ginkgo.By(fmt.Sprintf("Running container which tries to connect to %s in a loop", extDNSIP))

		ovnKubeControlPlaneNode, err := findOvnKubeControlPlaneNode(deploymentconfig.Get().OVNKubernetesNamespace(), controlPlanePodName, controlPlaneLeaseName)
		framework.ExpectNoError(err, fmt.Sprintf("unable to find current master of %s cluster %v", controlPlanePodName, err))
		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go func() {
			defer ginkgo.GinkgoRecover()
			checkContinuousConnectivity(f, "", "connectivity-test-continuous", extDNSIP, 53, 30, 30, podChan, errChan)
		}()

		err = <-errChan
		framework.ExpectNoError(err)

		testPod := <-podChan
		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)

		time.Sleep(5 * time.Second)
		ovnKubeNamespace := deploymentconfig.Get().OVNKubernetesNamespace()
		podClient := f.ClientSet.CoreV1().Pods(ovnKubeNamespace)

		podList, err := podClient.List(context.Background(), metav1.ListOptions{
			LabelSelector: "name=" + controlPlanePodName,
		})
		framework.ExpectNoError(err)

		podName := ""
		for _, pod := range podList.Items {
			if strings.HasPrefix(pod.Name, controlPlanePodName) && pod.Spec.NodeName == ovnKubeControlPlaneNode {
				podName = pod.Name
				break
			}
		}

		ginkgo.By("Deleting ovnkube control plane pod " + podName)
		e2epod.DeletePodWithWaitByName(context.TODO(), f.ClientSet, podName, ovnKubeNamespace)
		framework.Logf("Deleted ovnkube control plane pod %q", podName)

		ginkgo.By("Ensuring there were no connectivity errors")
		framework.ExpectNoError(<-errChan)

		err = waitClusterHealthy(f, numControlPlanePods, controlPlanePodName)
		framework.ExpectNoError(err, "one or more nodes failed to go back ready, schedulable, and untainted")
	})

	ginkgo.It("should provide Internet connection continuously when all pods are killed on node running master instance of ovnkube-control-plane", func() {
		ginkgo.By(fmt.Sprintf("Running container which tries to connect to %s in a loop", extDNSIP))
		ovnKubeNamespace := deploymentconfig.Get().OVNKubernetesNamespace()
		ovnKubeControlPlaneNode, err := findOvnKubeControlPlaneNode(ovnKubeNamespace, controlPlanePodName, controlPlaneLeaseName)
		framework.ExpectNoError(err, fmt.Sprintf("unable to find current master of %s cluster %v", controlPlanePodName, err))

		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go func() {
			defer ginkgo.GinkgoRecover()
			checkContinuousConnectivity(f, "", "connectivity-test-continuous", extDNSIP, 53, 30, 30, podChan, errChan)
		}()

		err = <-errChan
		framework.ExpectNoError(err)

		testPod := <-podChan
		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)

		time.Sleep(5 * time.Second)

		podClient := f.ClientSet.CoreV1().Pods("")

		podList, _ := podClient.List(context.Background(), metav1.ListOptions{})
		for _, pod := range podList.Items {
			// deleting the ovs-node pod tears down all the node networking and the restarting pod
			// does not rebuild it, effectively breaking that node entirely. Therefore, we cannot delete it
			// for this test case. The same reasoning applies to ovnkube-identity: webhook calls for pod updates
			// may fail if the webhook itself is deleted, potentially leaving ovnkube-identity stuck in a
			// terminated state. This can result in no new pods being scheduled or running. In a real-world
			// scenario, this limitation is mitigated by deploying multiple API server replicas, which is not
			// the case for the basic kind cluster deployment.
			if pod.Spec.NodeName == ovnKubeControlPlaneNode && pod.Name != "connectivity-test-continuous" &&
				pod.Name != "etcd-ovn-control-plane" &&
				!strings.HasPrefix(pod.Name, "ovnkube-identity") &&
				!strings.HasPrefix(pod.Name, "ovs-node") {
				framework.Logf("%q", pod.Namespace)
				deletePodWithWaitByName(context.Background(), f.ClientSet, pod.GetName(), ovnKubeNamespace)
				framework.Logf("Deleted control plane pod %q", pod.Name)
			}
		}

		framework.Logf("Killed all pods running on node %s", ovnKubeControlPlaneNode)

		framework.ExpectNoError(<-errChan)
	})

	ginkgo.It("should provide Internet connection continuously when all ovnkube-control-plane pods are killed", func() {
		ginkgo.By(fmt.Sprintf("Running container which tries to connect to %s in a loop", extDNSIP))

		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go func() {
			defer ginkgo.GinkgoRecover()
			checkContinuousConnectivity(f, "", "connectivity-test-continuous", extDNSIP, 53, 30, 30, podChan, errChan)
		}()

		err := <-errChan
		framework.ExpectNoError(err)

		testPod := <-podChan
		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)

		time.Sleep(5 * time.Second)

		podClient := f.ClientSet.CoreV1().Pods("")

		podList, _ := podClient.List(context.Background(), metav1.ListOptions{})
		for _, pod := range podList.Items {
			if strings.HasPrefix(pod.Name, controlPlanePodName) && !strings.HasPrefix(pod.Name, "ovs-node") {
				framework.Logf("%q", pod.Namespace)
				err = deletePodWithWaitByName(context.TODO(), f.ClientSet, pod.Name, deploymentconfig.Get().OVNKubernetesNamespace())
				framework.ExpectNoError(err, fmt.Sprintf("failed to delete pod %s", pod.Name))
				framework.Logf("Deleted control plane pod %q", pod.Name)
			}
		}

		framework.Logf("Killed all the %s pods.", controlPlanePodName)

		framework.ExpectNoError(<-errChan)
	})

	ginkgo.It("should provide connection to external host by DNS name from a pod", func() {
		ginkgo.By("Running container which tries to connect to www.google.com. in a loop")

		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go func() {
			defer ginkgo.GinkgoRecover()
			checkContinuousConnectivity(f, "", "connectivity-test-continuous", "www.google.com.", 443, 10, 30, podChan, errChan)
		}()

		err := <-errChan
		framework.ExpectNoError(err)

		testPod := <-podChan
		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)

		time.Sleep(10 * time.Second)

		framework.ExpectNoError(<-errChan)
	})

	ginkgo.Describe("test node readiness according to its defaults interface MTU size", func() {
		var testNodeName string
		var originalMTU int

		ginkgo.BeforeEach(func() {
			node, err := e2enode.GetRandomReadySchedulableNode(context.Background(), f.ClientSet)
			framework.ExpectNoError(err, "must get a schedulable Node")
			testNodeName = node.GetName()
			// get the interface current mtu and store it as original value to be able to reset it after the test
			res, err := infraprovider.Get().ExecK8NodeCommand(testNodeName, []string{"cat", fmt.Sprintf("/sys/class/net/%s/mtu", deploymentconfig.Get().ExternalBridgeName())})
			if err != nil {
				framework.Failf("could not get MTU of interface: %s", err)
			}

			res = strings.ReplaceAll(res, "\n", "")
			originalMTU, err = strconv.Atoi(res)
			if err != nil {
				framework.Failf("could not convert MTU to integer: %s", err)
			}
		})

		ginkgo.AfterEach(func() {
			// reset MTU to original value
			_, err := infraprovider.Get().ExecK8NodeCommand(testNodeName, []string{"ip", "link", "set", deploymentconfig.Get().ExternalBridgeName(), "mtu", fmt.Sprintf("%d", originalMTU)})
			if err != nil {
				framework.Failf("could not reset MTU of interface: %s", err)
			}

			// restart ovnkube-node pod
			if err := restartOVNKubeNodePod(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), testNodeName); err != nil {
				framework.Failf("could not restart ovnkube-node pod: %s", err)
			}

			err = waitClusterHealthy(f, numControlPlanePods, controlPlanePodName)
			framework.ExpectNoError(err, "one or more nodes failed to go back ready, schedulable, and untainted")
		})

		ginkgo.It("should get node not ready with a too small MTU", func() {
			// set the defaults interface MTU very low
			_, err := infraprovider.Get().ExecK8NodeCommand(testNodeName, []string{"ip", "link", "set", deploymentconfig.Get().ExternalBridgeName(), "mtu", "1000"})
			if err != nil {
				framework.Failf("could not set MTU of interface: %s", err)
			}

			// restart ovnkube-node pod to trigger mtu validation
			if err := restartOVNKubeNodePod(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), testNodeName); err == nil || err != wait.ErrWaitTimeout {
				if err == nil {
					framework.Failf("ovnkube-node pod restarted correctly, but wasn't supposed to: %s", err)
				}
				framework.Failf("could not restart ovnkube-node pod: %s", err)
			}

			gomega.Eventually(func() bool {
				node, err := f.ClientSet.CoreV1().Nodes().Get(context.TODO(), testNodeName, metav1.GetOptions{ResourceVersion: "0"})
				if err != nil {
					framework.Failf("could not find node resource: %s", err)
				}
				return e2enode.IsNodeReady(node)
			}, 30*time.Second).Should(gomega.BeFalse())
		})

		ginkgo.It("should get node ready with a big enough MTU", func() {
			// set the defaults interface MTU big enough
			_, err := infraprovider.Get().ExecK8NodeCommand(testNodeName, []string{"ip", "link", "set", deploymentconfig.Get().ExternalBridgeName(), "mtu", "2000"})
			if err != nil {
				framework.Failf("could not set MTU of interface: %s", err)
			}

			// restart ovnkube-node pod to trigger mtu validation
			if err := restartOVNKubeNodePod(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), testNodeName); err != nil {
				framework.Failf("could not restart ovnkube-node pod: %s", err)
			}

			// validate that node is in Ready state
			gomega.Eventually(func() bool {
				node, err := f.ClientSet.CoreV1().Nodes().Get(context.TODO(), testNodeName, metav1.GetOptions{ResourceVersion: "0"})
				if err != nil {
					framework.Failf("could not find node resource: %s", err)
				}
				return e2enode.IsNodeReady(node)
			}, 30*time.Second).Should(gomega.BeTrue())
		})
	})
})

// Test pod connectivity to other host IP addresses
var _ = ginkgo.Describe("test e2e pod connectivity to host addresses", func() {
	const svcname string = "node-e2e-to-host"

	var (
		targetIP       string
		singleIPMask   string
		workerNodeName string
	)

	f := wrappedTestFramework(svcname)

	ginkgo.BeforeEach(func() {
		targetIP = "123.123.123.123"
		singleIPMask = "32"
		if IsIPv6Cluster(f.ClientSet) {
			targetIP = "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF"
			singleIPMask = "128"
		}
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(context.TODO(), f.ClientSet, 1)
		framework.ExpectNoError(err)
		if len(nodes.Items) < 1 {
			framework.Failf("Test requires >= 1 Ready nodes, but there are only %v nodes", len(nodes.Items))
		}
		workerNodeName = nodes.Items[0].Name
		// Add another IP address to the worker
		_, err = infraprovider.Get().ExecK8NodeCommand(workerNodeName, []string{"ip", "a", "add",
			fmt.Sprintf("%s/%s", targetIP, singleIPMask), "dev", deploymentconfig.Get().ExternalBridgeName()})
		framework.ExpectNoError(err, "failed to add IP to %s", workerNodeName)
	})

	ginkgo.AfterEach(func() {
		_, err := infraprovider.Get().ExecK8NodeCommand(workerNodeName, []string{"ip", "a", "del",
			fmt.Sprintf("%s/%s", targetIP, singleIPMask), "dev", deploymentconfig.Get().ExternalBridgeName()})
		framework.ExpectNoError(err, "failed to remove IP from %s", workerNodeName)
	})

	ginkgo.It("Should validate connectivity from a pod to a non-node host address on same node", func() {
		// Spin up another pod that attempts to reach the previously started pod on separate nodes
		framework.ExpectNoError(
			checkConnectivityPingToHost(f, workerNodeName, "e2e-src-ping-pod", targetIP, ipv4PingCommand, 30))
	})
})

// Test e2e inter-node connectivity over br-int
var _ = ginkgo.Describe("test e2e inter-node connectivity between worker nodes", func() {
	const (
		svcname       string = "inter-node-e2e"
		getPodIPRetry int    = 20
	)

	f := wrappedTestFramework(svcname)

	ginkgo.It("Should validate connectivity within a namespace of pods on separate nodes", func() {
		var validIP net.IP
		var pingTarget string
		var ciWorkerNodeSrc string
		var ciWorkerNodeDst string
		dstPingPodName := "e2e-dst-ping-pod"
		command := []string{"bash", "-c", "sleep 20000"}
		// non-ha ci mode runs a named set of nodes with a prefix of ovn-worker
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(context.TODO(), f.ClientSet, 2)
		framework.ExpectNoError(err)
		if len(nodes.Items) < 2 {
			framework.Failf("Test requires >= 2 Ready nodes, but there are only %v nodes", len(nodes.Items))
		}
		ciWorkerNodeSrc = nodes.Items[0].Name
		ciWorkerNodeDst = nodes.Items[1].Name

		ginkgo.By(fmt.Sprintf("Creating a container on node %s and verifying connectivity to a pod on node %s", ciWorkerNodeSrc, ciWorkerNodeDst))

		// Create the pod that will be used as the destination for the connectivity test
		createGenericPod(f, dstPingPodName, ciWorkerNodeDst, f.Namespace.Name, command)

		// There is a condition somewhere with e2e WaitForPodNotPending that returns ready
		// before calling for the IP address will succeed. This simply adds some retries.
		for i := 1; i < getPodIPRetry; i++ {
			pingTarget = getPodAddress(dstPingPodName, f.Namespace.Name)
			validIP = net.ParseIP(pingTarget)
			if validIP != nil {
				framework.Logf("Destination ping target for %s is %s", dstPingPodName, pingTarget)
				break
			}
			time.Sleep(time.Second * 4)
			framework.Logf("Retry attempt %d to get pod IP from initializing pod %s", i, dstPingPodName)
		}
		// Fail the test if no address is ever retrieved
		if validIP == nil {
			framework.Failf("Warning: Failed to get an IP for target pod %s, test will fail", dstPingPodName)
		}
		// Spin up another pod that attempts to reach the previously started pod on separate nodes
		framework.ExpectNoError(
			checkConnectivityPingToHost(f, ciWorkerNodeSrc, "e2e-src-ping-pod", pingTarget, ipv4PingCommand, 30))
	})
})

func createSrcPod(podName, nodeName string, ipCheckInterval, ipCheckTimeout time.Duration, f *framework.Framework) {
	_, err := createGenericPod(f, podName, nodeName, f.Namespace.Name,
		[]string{"bash", "-c", "sleep 20000"})
	if err != nil {
		framework.Failf("Failed to create src pod %s: %v", podName, err)
	}
	// Wait for pod setup to be almost ready
	err = wait.PollImmediate(ipCheckInterval, ipCheckTimeout, func() (bool, error) {
		kubectlOut := getPodAddress(podName, f.Namespace.Name)
		validIP := net.ParseIP(kubectlOut)
		if validIP == nil {
			return false, nil
		}
		return true, nil
	})
	// Fail the test if no address is ever retrieved
	if err != nil {
		framework.Failf("Error trying to get the pod IP address %v", err)
	}
}

var _ = ginkgo.Describe("e2e network policy hairpinning validation", func() {
	const (
		svcName          string = "network-policy"
		serviceHTTPPort  uint16 = 6666
		endpointHTTPPort uint16 = 80
	)

	f := wrappedTestFramework(svcName)
	hairpinPodSel := map[string]string{"hairpinbackend": "true"}

	ginkgo.It("Should validate the hairpinned traffic is always allowed", func() {
		namespaceName := f.Namespace.Name

		ginkgo.By("creating a \"default deny\" network policy")
		_, err := makeDenyAllPolicy(f, namespaceName, "deny-all")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.By("creating pods")
		cmd := getAgnHostHTTPPortBindFullCMD(endpointHTTPPort)
		// pod1 is a client and a service backend for hairpinned traffic
		pod1 := newAgnhostPod(namespaceName, "pod1", cmd...)
		pod1.Labels = hairpinPodSel
		pod1 = e2epod.NewPodClient(f).CreateSync(context.TODO(), pod1)
		// pod2 is another pod in the same namespace, that should be denied
		pod2 := newAgnhostPod(namespaceName, "pod2", cmd...)
		pod2 = e2epod.NewPodClient(f).CreateSync(context.TODO(), pod2)

		ginkgo.By("creating a service with a single backend")
		svcIP, err := createServiceForPodsWithLabel(f, namespaceName, serviceHTTPPort, endpointHTTPPort, "ClusterIP", hairpinPodSel)
		framework.ExpectNoError(err, fmt.Sprintf("unable to create ClusterIP svc: %v", err))

		err = framework.WaitForServiceEndpointsNum(context.TODO(), f.ClientSet, namespaceName, "service-for-pods", 1, time.Second, wait.ForeverTestTimeout)
		framework.ExpectNoError(err, fmt.Sprintf("ClusterIP svc never had an endpoint, expected 1: %v", err))

		ginkgo.By("verify hairpinned connection from a pod to its own service is allowed")
		hostname := pokeEndpointViaPod(f, namespaceName, pod1.Name, svcIP, serviceHTTPPort, "hostname")
		gomega.Expect(hostname).To(gomega.Equal(pod1.Name), fmt.Sprintf("returned client: %v was not correct", hostname))

		ginkgo.By("verify connection to another pod is denied")
		err = pokePod(f, pod1.Name, pod2.Status.PodIP)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("Connection timed out"))
	})
})

var _ = ginkgo.Describe("e2e ingress traffic validation", func() {
	const (
		endpointHTTPPort = 80
		endpointUDPPort  = 90
		clusterHTTPPort  = 81
		clusterHTTPPort2 = 82
		clusterUDPPort   = 91
		clusterUDPPort2  = 92
	)

	f := wrappedTestFramework("nodeport-ingress-test")
	endpointsSelector := map[string]string{"servicebackend": "true"}

	var endPoints []*v1.Pod
	var nodesHostnames sets.String
	var maxTries int
	var nodes *v1.NodeList
	var newNodeAddresses []string
	var providerCtx infraapi.Context
	var isDualStack bool

	ginkgo.BeforeEach(func() {
		providerCtx = infraprovider.Get().NewTestContext()
	})

	ginkgo.Context("Validating ingress traffic", func() {
		var externalContainer infraapi.ExternalContainer

		ginkgo.BeforeEach(func() {
			endPoints = make([]*v1.Pod, 0)
			nodesHostnames = sets.NewString()

			var err error
			nodes, err = e2enode.GetBoundedReadySchedulableNodes(context.TODO(), f.ClientSet, 3)
			framework.ExpectNoError(err)

			if len(nodes.Items) < 3 {
				framework.Failf(
					"Test requires >= 3 Ready nodes, but there are only %v nodes",
					len(nodes.Items))
			}

			isDualStack = isDualStackCluster(nodes)

			ginkgo.By("Creating the endpoints pod, one for each worker")
			for _, node := range nodes.Items {
				// this create a udp / http netexec listener which is able to receive the "hostname"
				// command. We use this to validate that each endpoint is received at least once
				args := []string{
					"netexec",
					fmt.Sprintf("--http-port=%d", endpointHTTPPort),
					fmt.Sprintf("--udp-port=%d", endpointUDPPort),
				}
				pod, err := createPod(f, node.Name+"-ep", node.Name, f.Namespace.Name, []string{}, endpointsSelector, func(p *v1.Pod) {
					p.Spec.Containers[0].Args = args
				})
				framework.ExpectNoError(err)
				endPoints = append(endPoints, pod)
				nodesHostnames.Insert(pod.Name)

				// this is arbitrary and mutuated from k8s network e2e tests. We aim to hit all the endpoints at least once
				maxTries = len(endPoints)*len(endPoints) + 30
			}

			ginkgo.By("Creating an external container to send the traffic from")
			// the client uses the netexec command from the agnhost image, which is able to receive commands for poking other
			// addresses.
			// CAP NET_ADMIN is needed to remove neighbor entries for ARP/NS flap tests
			primaryProviderNetwork, err := infraprovider.Get().PrimaryNetwork()
			framework.ExpectNoError(err, "failed to get primary network")
			externalContainerPort := infraprovider.Get().GetExternalContainerPort()
			externalContainer = infraapi.ExternalContainer{Name: "e2e-ingress", Image: images.AgnHost(), Network: primaryProviderNetwork,
				CmdArgs: getAgnHostHTTPPortBindCMDArgs(externalContainerPort), ExtPort: externalContainerPort}
			externalContainer, err = providerCtx.CreateExternalContainer(externalContainer)
			framework.ExpectNoError(err, "failed to create external service", externalContainer.String())
		})

		// This test validates ingress traffic to nodeports.
		// It creates a nodeport service on both udp and tcp, and creates a backend pod on each node.
		// The backend pods are using the agnhost - netexec command which replies to commands
		// with different protocols. We use the "hostname" command to have each backend pod to reply
		// with its hostname.
		// We use an external container to poke the service exposed on the node and we iterate until
		// all the hostnames are returned.
		// In case of dual stack enabled cluster, we iterate over all the nodes ips and try to hit the
		// endpoints from both each node's ips.
		ginkgo.It("Should be allowed by nodeport services", func() {
			serviceName := "nodeportsvc"
			ginkgo.By("Creating the nodeport service")
			npSpec := nodePortServiceSpecFrom(serviceName, v1.IPFamilyPolicyPreferDualStack, endpointHTTPPort, endpointUDPPort, clusterHTTPPort, clusterUDPPort, endpointsSelector, v1.ServiceExternalTrafficPolicyTypeCluster)
			np, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), npSpec, metav1.CreateOptions{})
			nodeTCPPort, nodeUDPPort := nodePortsFromService(np)
			framework.ExpectNoError(err)

			ginkgo.By("Waiting for the endpoints to pop up")
			expectedEndpointsNum :=  len(endPoints)
			if isDualStack {
				expectedEndpointsNum = expectedEndpointsNum * 2
			}
			err = framework.WaitForServiceEndpointsNum(context.TODO(), f.ClientSet, f.Namespace.Name, serviceName, expectedEndpointsNum, time.Second, wait.ForeverTestTimeout)
			framework.ExpectNoError(err, "failed to validate endpoints for service %s in namespace: %s", serviceName, f.Namespace.Name)

			for _, protocol := range []string{"http", "udp"} {
				for _, node := range nodes.Items {
					for _, nodeAddress := range node.Status.Addresses {
						// skipping hostnames
						if !addressIsIP(nodeAddress) {
							continue
						}

						responses := sets.NewString()
						valid := false
						nodePort := nodeTCPPort
						if protocol == "udp" {
							nodePort = nodeUDPPort
						}

						ginkgo.By("Hitting the nodeport on " + node.Name + " and reaching all the endpoints " + protocol)
						for i := 0; i < maxTries; i++ {
							epHostname := pokeEndpointViaExternalContainer(externalContainer, protocol, nodeAddress.Address, nodePort, "hostname")
							responses.Insert(epHostname)

							// each endpoint returns its hostname. By doing this, we validate that each ep was reached at least once.
							if responses.Equal(nodesHostnames) {
								framework.Logf("Validated node %s on address %s after %d tries", node.Name, nodeAddress.Address, i)
								valid = true
								break
							}
						}
						gomega.Expect(valid).To(gomega.Equal(true), fmt.Sprintf("Validation failed for node %s. Expected Responses=%v, Actual Responses=%v", node.Name, nodesHostnames, responses))
					}
				}
			}
		})

		// This test validates ingress traffic to NodePorts in a dual stack cluster after a Service upgrade from single stack to dual stack.
		// After an upgrade to DualStack cluster, 2 tests must be run:
		// a) Test from outside the cluster towards the NodePort - this test would fail in earlier versions of ovn-kubernetes
		// b) Test from the node itself towards its own NodePort - this test would fail in more recent versions of ovn-kubernetes even though a) would pass.
		//
		// This test tests a)
		// For test b), see test: "Should be allowed to node local host-networked endpoints by nodeport services with externalTrafficPolicy=local after upgrade to DualStack"
		//
		// In order to test this, this test does the following:
		// It creates a SingleStack nodeport service on both udp and tcp, and creates a backend pod on each node.
		// It then updates the nodeport service to PreferDualStack
		// It then waits for the service to get 2 ClusterIPs.
		// The backend pods are using the agnhost - netexec command which replies to commands
		// with different protocols. We use the "hostname" command to have each backend pod to reply
		// with its hostname.
		//
		// To test a) We use an external container to poke the service exposed on the node and we iterate until
		// all the hostnames are returned.
		// In case of dual stack enabled cluster, we iterate over all the nodes ips and try to hit the
		// endpoints from both each node's ips.
		//
		// This test will be skipped if the cluster is not in DualStack mode.
		ginkgo.It("Should be allowed by nodeport services after upgrade to DualStack", func() {
			if !isDualStack {
				ginkgo.Skip("Skipping as this is not a DualStack cluster")
			}
			serviceName := "nodeportsvc"

			ginkgo.By("Creating the nodeport service")
			npSpec := nodePortServiceSpecFrom(serviceName, v1.IPFamilyPolicySingleStack, endpointHTTPPort, endpointUDPPort, clusterHTTPPort, clusterUDPPort, endpointsSelector, v1.ServiceExternalTrafficPolicyTypeCluster)
			np, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), npSpec, metav1.CreateOptions{})
			nodeTCPPort, nodeUDPPort := nodePortsFromService(np)
			protocolPorts := map[string]int32{
				"http": nodeTCPPort,
				"udp":  nodeUDPPort,
			}
			framework.ExpectNoError(err)

			ginkgo.By("Waiting for the endpoints to pop up")
			err = framework.WaitForServiceEndpointsNum(context.TODO(), f.ClientSet, f.Namespace.Name, serviceName, len(endPoints), time.Second, wait.ForeverTestTimeout)
			framework.ExpectNoError(err, "failed to validate endpoints for service %s in namespace: %s", serviceName, f.Namespace.Name)

			ginkgo.By("Collecting IPv4 and IPv6 node addresses")
			// Mapping of nodeName to all node IPv4 addresses and
			// mapping of nodeName to all node IPv6 addresses.
			ipv4Addresses := make(map[string][]string)
			ipv6Addresses := make(map[string][]string)
			var n string
			for _, node := range nodes.Items {
				n = node.Name
				ipv4Addresses[n] = []string{}
				ipv6Addresses[n] = []string{}
				for _, nodeAddress := range node.Status.Addresses {
					if addressIsIPv6(nodeAddress) {
						ipv6Addresses[n] = append(ipv6Addresses[n], nodeAddress.Address)
					} else if addressIsIPv4(nodeAddress) {
						ipv4Addresses[n] = append(ipv4Addresses[n], nodeAddress.Address)
					}
				}
			}
			// Mapping IPv4 -> nodeNames -> IP addreses.
			// Mapping IPv6 -> nodeNames -> IP addreses.
			ipAddressFamilyTargets := map[string]map[string][]string{
				"IPv4": ipv4Addresses,
				"IPv6": ipv6Addresses,
			}

			// First, upgrade to PreferDualStack and test endpoints.
			// Then, downgrade back to SingleStack and test endpoints.
			for _, ipFamilyPolicy := range []string{"PreferDualStack", "SingleStack"} {
				ginkgo.By(fmt.Sprintf("Changing the nodeport service to %s", ipFamilyPolicy))
				err = patchServiceStringValue(f.ClientSet, np.Name, np.Namespace, "/spec/ipFamilyPolicy", ipFamilyPolicy)
				framework.ExpectNoError(err)

				// It is expected that endpoints take a bit of time to come up after conversion. We remove all iptables rules and all breth0 flows.
				// Therefore, test IPv4 endpoints until they are stable, only then proceed to the actual test.
				// To be removed once https://github.com/ovn-org/ovn-kubernetes/issues/2933 is fixed.
				framework.Logf("Monitoring endpoints for up to 60 seconds for IPv4 to give them time to come up (issue 2933)")
				gomega.Eventually(func() (r bool) {
					// Sleep for 5 seconds before proceeding.
					framework.Logf("Sleeping for 5 seconds")
					time.Sleep(5 * time.Second)

					// Test all node IPv4 addresses http and return true if all of them come back with a valid answer.
					for _, ipAddresses := range ipv4Addresses {
						for _, targetHost := range ipAddresses {
							hostname := pokeEndpointViaExternalContainer(externalContainer, "http", targetHost, protocolPorts["http"], "hostname")
							if hostname == "" {
								framework.Logf("Failed, could get hostname")
								return false
							}
						}
					}
					return true
				}, 60*time.Second, 10*time.Second).Should(gomega.BeTrue())

				// Test in the following order:
				// for IPv4, then IPv6:
				//   for each node:
				//      for all node IP addresses that belong to that node:
				//        probe http service port
				//          make sure that all endpoints can be reached
				//        probe udp service port
				//          make sure that all endpoints can be reached
				// Hit the exact same IP address family, IP address, protocol and port for maxTries times until we get back all endpoint hostnames for that
				// tuple.
				ipFamiliesToTest := []string{"IPv4"}
				if ipFamilyPolicy == "PreferDualStack" {
					ipFamiliesToTest = append(ipFamiliesToTest, "IPv6")
				}
				for _, ipAddressFamily := range ipFamiliesToTest {
					ginkgo.By(fmt.Sprintf("Testing %s services", ipAddressFamily))
					nodeToAddressesMapping := ipAddressFamilyTargets[ipAddressFamily]
					for nodeName, ipAddresses := range nodeToAddressesMapping {
						for _, address := range ipAddresses {
							// Use a slice for stable order, always tests http first and udp second due to
							// https://github.com/ovn-org/ovn-kubernetes/issues/2913.
							for _, protocol := range []string{"http", "udp"} {
								port := protocolPorts[protocol]
								ginkgo.By(fmt.Sprintf("Hitting nodeport %s/%d on %s with IP %s and reaching all the endpoints ", protocol, port, nodeName, address))
								responses := sets.NewString()
								valid := false
								for i := 0; i < maxTries; i++ {
									epHostname := pokeEndpointViaExternalContainer(externalContainer, protocol, address, port, "hostname")
									responses.Insert(epHostname)

									// each endpoint returns its hostname. By doing this, we validate that each ep was reached at least once.
									if responses.Equal(nodesHostnames) {
										framework.Logf("Validated node %s on address %s after %d tries", nodeName, address, i)
										valid = true
										break
									}
								}
								gomega.Expect(valid).To(gomega.Equal(true), fmt.Sprintf("Validation failed for node %s. Expected Responses=%v, Actual Responses=%v", nodeName, nodesHostnames, responses))
							}
						}
					}
				}
			}
		})

		// This test validates ingress traffic to nodeports with externalTrafficPolicy Set to local.
		// It creates a nodeport service on both udp and tcp, and creates a backend pod on each node.
		// The backend pod is using the agnhost - netexec command which replies to commands
		// with different protocols. We use the "hostname" and "clientip" commands to have each backend
		// pod to reply with its hostname and the request packet's srcIP.
		// We use an external container to poke the service exposed on the node and ensure that only the
		// nodeport on the node with the backend actually receives traffic and that the packet is not
		// SNATed.
		// In case of dual stack enabled cluster, we iterate over all the nodes ips and try to hit the
		// endpoints from both each node's ips.
		ginkgo.It("Should be allowed to node local cluster-networked endpoints by nodeport services with externalTrafficPolicy=local", func() {
			serviceName := "nodeportsvclocal"
			ginkgo.By("Creating the nodeport service with externalTrafficPolicy=local")
			npSpec := nodePortServiceSpecFrom(serviceName, v1.IPFamilyPolicyPreferDualStack, endpointHTTPPort, endpointUDPPort, clusterHTTPPort, clusterUDPPort, endpointsSelector, v1.ServiceExternalTrafficPolicyTypeLocal)
			np, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), npSpec, metav1.CreateOptions{})
			nodeTCPPort, nodeUDPPort := nodePortsFromService(np)
			framework.ExpectNoError(err)

			ginkgo.By("Waiting for the endpoints to pop up")
			expectedEndpointsNum :=  len(endPoints)
			if isDualStack {
				expectedEndpointsNum = expectedEndpointsNum * 2
			}
			err = framework.WaitForServiceEndpointsNum(context.TODO(), f.ClientSet, f.Namespace.Name, serviceName, expectedEndpointsNum, time.Second, wait.ForeverTestTimeout)
			framework.ExpectNoError(err, "failed to validate endpoints for service %s in namespace: %s", serviceName, f.Namespace.Name)

			for _, protocol := range []string{"http", "udp"} {
				for _, node := range nodes.Items {
					for _, nodeAddress := range node.Status.Addresses {
						// skipping hostnames
						if !addressIsIP(nodeAddress) {
							continue
						}

						responses := sets.NewString()
						// Fill expected responses, it should hit the nodeLocal endpoints and not SNAT packet IP
						expectedResponses := sets.NewString()

						if utilnet.IsIPv6String(nodeAddress.Address) {
							expectedResponses.Insert(node.Name+"-ep", externalContainer.GetIPv6())
						} else {
							expectedResponses.Insert(node.Name+"-ep", externalContainer.GetIPv4())
						}

						valid := false
						nodePort := nodeTCPPort
						if protocol == "udp" {
							nodePort = nodeUDPPort
						}

						ginkgo.By("Hitting the nodeport on " + node.Name + " and trying to reach only the local endpoint with protocol " + protocol)

						for i := 0; i < maxTries; i++ {
							epHostname := pokeEndpointViaExternalContainer(externalContainer, protocol, nodeAddress.Address, nodePort, "hostname")
							epClientIP := pokeEndpointViaExternalContainer(externalContainer, protocol, nodeAddress.Address, nodePort, "clientip")
							epClientIP, _, err = net.SplitHostPort(epClientIP)
							framework.ExpectNoError(err, "failed to parse client ip:port")
							responses.Insert(epHostname, epClientIP)

							if responses.Equal(expectedResponses) {
								framework.Logf("Validated local endpoint on node %s with address %s, and packet src IP %s", node.Name, nodeAddress.Address, epClientIP)
								valid = true
								break
							}

						}
						gomega.Expect(valid).To(gomega.Equal(true), fmt.Sprintf("Validation failed for node %s. Expected Responses=%v, Actual Responses=%v", node.Name, expectedResponses, responses))
					}
				}
			}
		})
		// This test validates ingress traffic to externalservices.
		// It creates a service on both udp and tcp and assignes all the first node's addresses as
		// external addresses. Then, creates a backend pod on each node.
		// The backend pods are using the agnhost - netexec command which replies to commands
		// with different protocols. We use the "hostname" command to have each backend pod to reply
		// with its hostname.
		// We use an external container to poke the service exposed on the node and we iterate until
		// all the hostnames are returned.
		// In case of dual stack enabled cluster, we iterate over all the node's addresses and try to hit the
		// endpoints from both each node's ips.
		ginkgo.It("Should be allowed by externalip services", func() {
			serviceName := "externalipsvc"
			serviceName2 := "externalipsvc2"

			// collecting all the first node's addresses
			addresses := []string{}
			for _, a := range nodes.Items[0].Status.Addresses {
				if addressIsIP(a) {
					addresses = append(addresses, a.Address)
				}
			}

			// We will create 2 services, test the first, then delete the first service
			// Deleting the first externalip service should not affect the ARP/NS redirect rule pushed into OVS breth0 and the second service should still behave
			// correctly after deletion of the first service
			ginkgo.By("Creating the first externalip service")
			externalIPsvcSpec := externalIPServiceSpecFrom(serviceName, endpointHTTPPort, endpointUDPPort, clusterHTTPPort, clusterUDPPort, endpointsSelector, addresses)
			_, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), externalIPsvcSpec, metav1.CreateOptions{})
			framework.ExpectNoError(err)

			ginkgo.By("Creating the second externalip service on the same VIP")
			externalIPsvcSpec2 := externalIPServiceSpecFrom(serviceName2, endpointHTTPPort, endpointUDPPort, clusterHTTPPort2, clusterUDPPort2, endpointsSelector, addresses)
			_, err = f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), externalIPsvcSpec2, metav1.CreateOptions{})
			framework.ExpectNoError(err)

			ginkgo.By("Waiting for the endpoints to pop up")
			expectedEndpointsNum :=  len(endPoints)
			if isDualStack {
				expectedEndpointsNum = expectedEndpointsNum * 2
			}
			err = framework.WaitForServiceEndpointsNum(context.TODO(), f.ClientSet, f.Namespace.Name, serviceName, expectedEndpointsNum, time.Second, wait.ForeverTestTimeout)
			framework.ExpectNoError(err, "failed to validate endpoints for service %s in namespace: %s", serviceName, f.Namespace.Name)

			for _, externalAddress := range addresses {
				ginkgo.By(fmt.Sprintf("Making sure that the neighbor entry is stable for endpoint IP %s", externalAddress))
				valid := isNeighborEntryStable(externalContainer, externalAddress, 10)
				gomega.Expect(valid).Should(gomega.BeTrue(), "Validation failed for neighbor entry of external address: %s", externalAddress)

				for _, protocol := range []string{"http", "udp"} {
					externalPort := int32(clusterHTTPPort)
					if protocol == "udp" {
						externalPort = int32(clusterUDPPort)
					}
					ginkgo.By(
						fmt.Sprintf("Hitting the external service on IP %s, protocol %s, port %d and reaching all the endpoints",
							externalAddress,
							protocol,
							externalPort))
					valid = pokeExternalIpService(externalContainer, protocol, externalAddress, externalPort, maxTries, nodesHostnames)
					gomega.Expect(valid).Should(gomega.BeTrue(), "Validation failed for external address: %s", externalAddress)
				}
			}

			// Deleting the first externalip service should not affect the ARP/NS redirect rules
			ginkgo.By("Deleting the first externalip service")
			err = f.ClientSet.CoreV1().Services(f.Namespace.Name).Delete(context.Background(), serviceName, metav1.DeleteOptions{})
			framework.ExpectNoError(err, "failed to delete the first external IP service for service %s in namespace: %s", serviceName, f.Namespace.Name)

			for _, externalAddress := range addresses {
				ginkgo.By(fmt.Sprintf("Making sure that the neighbor entry is stable for endpoint IP %s", externalAddress))
				valid := isNeighborEntryStable(externalContainer, externalAddress, 10)
				gomega.Expect(valid).Should(gomega.BeTrue(), "Validation failed for neighbor entry of external address: %s", externalAddress)

				for _, protocol := range []string{"http", "udp"} {
					externalPort := int32(clusterHTTPPort2)
					if protocol == "udp" {
						externalPort = int32(clusterUDPPort2)
					}
					ginkgo.By(
						fmt.Sprintf("Hitting the external service on IP %s, protocol %s, port %d and reaching all the endpoints",
							externalAddress,
							protocol,
							externalPort))
					valid = pokeExternalIpService(externalContainer, protocol, externalAddress, externalPort, maxTries, nodesHostnames)
					gomega.Expect(valid).Should(gomega.BeTrue(), "Validation failed for external address: %s", externalAddress)
				}
			}
		})
	})

	ginkgo.Context("Validating ingress traffic to manually added node IPs", func() {
		var externalContainer infraapi.ExternalContainer

		ginkgo.BeforeEach(func() {
			endPoints = make([]*v1.Pod, 0)
			nodesHostnames = sets.NewString()

			var err error
			nodes, err = e2enode.GetBoundedReadySchedulableNodes(context.TODO(), f.ClientSet, 3)
			framework.ExpectNoError(err)

			if len(nodes.Items) < 3 {
				framework.Failf(
					"Test requires >= 3 Ready nodes, but there are only %v nodes",
					len(nodes.Items))
			}

			ginkgo.By("Creating the endpoints pod, one for each worker")
			for _, node := range nodes.Items {
				// this create a udp / http netexec listener which is able to receive the "hostname"
				// command. We use this to validate that each endpoint is received at least once
				args := []string{
					"netexec",
					fmt.Sprintf("--http-port=%d", endpointHTTPPort),
					fmt.Sprintf("--udp-port=%d", endpointUDPPort),
				}
				pod, err := createPod(f, node.Name+"-ep", node.Name, f.Namespace.Name, []string{}, endpointsSelector, func(p *v1.Pod) {
					p.Spec.Containers[0].Args = args
				})
				framework.ExpectNoError(err)
				endPoints = append(endPoints, pod)
				nodesHostnames.Insert(pod.Name)

				// this is arbitrary and mutuated from k8s network e2e tests. We aim to hit all the endpoints at least once
				maxTries = len(endPoints)*len(endPoints) + 30
			}

			ginkgo.By("Creating an external container to send the traffic from")
			// the client uses the netexec command from the agnhost image, which is able to receive commands for poking other
			// addresses.
			primaryProviderNetwork, err := infraprovider.Get().PrimaryNetwork()
			framework.ExpectNoError(err, "failed to get primary network")
			externalContainerPort := infraprovider.Get().GetExternalContainerPort()
			externalContainer = infraapi.ExternalContainer{Name: "e2e-ingress-add-more", Image: images.AgnHost(), Network: primaryProviderNetwork,
				CmdArgs: getAgnHostHTTPPortBindCMDArgs(externalContainerPort), ExtPort: externalContainerPort}
			externalContainer, err = providerCtx.CreateExternalContainer(externalContainer)
			framework.ExpectNoError(err, "external container %s must be created successfully", externalContainer.Name)

			// If `xgw` exists, connect client container to it
			exGwNetwork, err := infraprovider.Get().GetNetwork("xgw")
			if err == nil {
				_, _ = providerCtx.AttachNetwork(exGwNetwork, externalContainer.Name)
			}
			ginkgo.By("Adding ip addresses to each node")
			// add new secondary IP from node subnet to all nodes, if the cluster is v6 add an ipv6 address
			var newIP string
			newNodeAddresses = make([]string, 0)
			for i, node := range nodes.Items {
				if utilnet.IsIPv6String(e2enode.GetAddresses(&node, v1.NodeInternalIP)[0]) {
					newIP = "fc00:f853:ccd:e794::" + strconv.Itoa(i)
				} else {
					newIP = "172.18.1." + strconv.Itoa(i+1)
				}
				// manually add the a secondary IP to each node
				_, err := infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"ip", "addr", "add", newIP, "dev", deploymentconfig.Get().ExternalBridgeName()})
				if err != nil {
					framework.Failf("failed to add new Addresses to node %s: %v", node.Name, err)
				}
				providerCtx.AddCleanUpFn(func() error {
					_, err := infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"ip", "addr", "del", newIP, "dev", deploymentconfig.Get().ExternalBridgeName()})
					if err != nil {
						framework.Logf("failed to add new Addresses to node %s: %v", node.Name, err)
					}
					return nil
				})

				newNodeAddresses = append(newNodeAddresses, newIP)
			}
		})

		// This test validates ingress traffic to externalservices after a new node Ip is added.
		// It creates a service on both udp and tcp and assigns the new node IPs as
		// external Addresses. Then, creates a backend pod on each node.
		// The backend pods are using the agnhost - netexec command which replies to commands
		// with different protocols. We use the "hostname" command to have each backend pod to reply
		// with its hostname.
		// We use an external container to poke the service exposed on the node and we iterate until
		// all the hostnames are returned.
		ginkgo.It("Should be allowed by externalip services to a new node ip", func() {
			serviceName := "externalipsvc"

			ginkgo.By("Creating the externalip service")
			externalIPsvcSpec := externalIPServiceSpecFrom(serviceName, endpointHTTPPort, endpointUDPPort, clusterHTTPPort, clusterUDPPort, endpointsSelector, newNodeAddresses)
			_, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), externalIPsvcSpec, metav1.CreateOptions{})
			framework.ExpectNoError(err)

			ginkgo.By("Waiting for the endpoints to pop up")
			expectedEndpointsNum :=  len(endPoints)
			if isDualStack {
				expectedEndpointsNum = expectedEndpointsNum * 2
			}
			err = framework.WaitForServiceEndpointsNum(context.TODO(), f.ClientSet, f.Namespace.Name, serviceName, expectedEndpointsNum, time.Second, wait.ForeverTestTimeout)
			framework.ExpectNoError(err, "failed to validate endpoints for service %s in namespace: %s", serviceName, f.Namespace.Name)

			for _, protocol := range []string{"http", "udp"} {
				for _, externalAddress := range newNodeAddresses {
					responses := sets.NewString()
					valid := false
					externalPort := int32(clusterHTTPPort)
					if protocol == "udp" {
						externalPort = int32(clusterUDPPort)
					}

					ginkgo.By("Hitting the external service on " + externalAddress + " and reaching all the endpoints " + protocol)
					for i := 0; i < maxTries; i++ {
						epHostname := pokeEndpointViaExternalContainer(externalContainer, protocol, externalAddress, externalPort, "hostname")
						responses.Insert(epHostname)

						// each endpoint returns its hostname. By doing this, we validate that each ep was reached at least once.
						if responses.Equal(nodesHostnames) {
							framework.Logf("Validated external address %s after %d tries", externalAddress, i)
							valid = true
							break
						}
					}
					gomega.Expect(valid).To(gomega.Equal(true), "Validation failed for external address: %s", externalAddress)
				}
			}
		})
	})
})

var _ = ginkgo.Describe("e2e ingress to host-networked pods traffic validation", func() {
	const (
		endpointHTTPPort = 8085
		endpointUDPPort  = 9095
		clusterHTTPPort  = 81
		clusterUDPPort   = 91

		clientContainerName = "npclient"
	)

	f := wrappedTestFramework("nodeport-ingress-test")
	hostNetEndpointsSelector := map[string]string{"hostNetservicebackend": "true"}
	var endPoints []*v1.Pod
	var nodesHostnames sets.String
	maxTries := 0
	var nodes *v1.NodeList
	var providerCtx infraapi.Context
	var isDualStack bool

	ginkgo.BeforeEach(func() {
		providerCtx = infraprovider.Get().NewTestContext()
	})

	// This test validates ingress traffic to nodeports with externalTrafficPolicy Set to local.
	// It creates a nodeport service on both udp and tcp, and creates a host networked
	// backend pod on each node. The backend pod is using the agnhost - netexec command which
	// replies to commands with different protocols. We use the "hostname" and "clientip" commands
	// to have each backend pod to reply with its hostname and the request packet's srcIP.
	// We use an external container to poke the service exposed on the node and ensure that only the
	// nodeport on the node with the backend actually receives traffic and that the packet is not
	// SNATed.
	ginkgo.Context("Validating ingress traffic to Host Networked pods with externalTrafficPolicy=local", func() {
		var externalContainer infraapi.ExternalContainer

		ginkgo.BeforeEach(func() {
			endPoints = make([]*v1.Pod, 0)
			nodesHostnames = sets.NewString()

			var err error
			nodes, err = e2enode.GetBoundedReadySchedulableNodes(context.TODO(), f.ClientSet, 3)
			framework.ExpectNoError(err)

			if len(nodes.Items) < 3 {
				framework.Failf(
					"Test requires >= 3 Ready nodes, but there are only %v nodes",
					len(nodes.Items))
			}

			isDualStack = isDualStackCluster(nodes)

			ginkgo.By("Creating the endpoints pod, one for each worker")
			for _, node := range nodes.Items {
				// this create a udp / http netexec listener which is able to receive the "hostname"
				// command. We use this to validate that each endpoint is received at least once
				args := []string{
					"netexec",
					fmt.Sprintf("--http-port=%d", endpointHTTPPort),
					fmt.Sprintf("--udp-port=%d", endpointUDPPort),
				}

				// create hostNeworkedPods
				hostNetPod, err := createPod(f, node.Name+"-hostnet-ep", node.Name, f.Namespace.Name, []string{}, hostNetEndpointsSelector, func(p *v1.Pod) {
					p.Spec.Containers[0].Args = args
					p.Spec.HostNetwork = true
				})

				framework.ExpectNoError(err)
				endPoints = append(endPoints, hostNetPod)
				nodesHostnames.Insert(hostNetPod.Name)

				// this is arbitrary and mutuated from k8s network e2e tests. We aim to hit all the endpoints at least once
				maxTries = len(endPoints)*len(endPoints) + 30
			}

			ginkgo.By("Creating an external container to send the traffic from")
			// the client uses the netexec command from the agnhost image, which is able to receive commands for poking other
			// addresses.
			primaryProviderNetwork, err := infraprovider.Get().PrimaryNetwork()
			framework.ExpectNoError(err, "failed to get primary network")
			externalContainerPort := infraprovider.Get().GetExternalContainerPort()
			externalContainer = infraapi.ExternalContainer{Name: clientContainerName, Image: images.AgnHost(), Network: primaryProviderNetwork,
				CmdArgs: getAgnHostHTTPPortBindCMDArgs(externalContainerPort), ExtPort: externalContainerPort}
			externalContainer, err = providerCtx.CreateExternalContainer(externalContainer)
			framework.ExpectNoError(err, "external container %s must be created successfully", externalContainer.Name)
		})

		ginkgo.AfterEach(func() {
			// f.Delete will delete the namespace and run WaitForNamespacesDeleted
			// This is inside the Context and will happen before the framework's teardown inside the Describe
			f.DeleteNamespace(context.TODO(), f.Namespace.Name)
		})

		// Make sure ingress traffic can reach host pod backends for a service without SNAT when externalTrafficPolicy is set to local
		ginkgo.It("Should be allowed to node local host-networked endpoints by nodeport services", func() {
			serviceName := "nodeportsvclocalhostnet"
			ginkgo.By("Creating the nodeport service")
			npSpec := nodePortServiceSpecFrom(serviceName, v1.IPFamilyPolicyPreferDualStack, endpointHTTPPort, endpointUDPPort, clusterHTTPPort, clusterUDPPort, hostNetEndpointsSelector, v1.ServiceExternalTrafficPolicyTypeLocal)
			np, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), npSpec, metav1.CreateOptions{})
			framework.ExpectNoError(err)
			nodeTCPPort, nodeUDPPort := nodePortsFromService(np)

			ginkgo.By("Waiting for the endpoints to pop up")
			expectedEndpointsNum :=  len(endPoints)
			if isDualStack {
				expectedEndpointsNum = expectedEndpointsNum * 2
			}
			err = framework.WaitForServiceEndpointsNum(context.TODO(), f.ClientSet, f.Namespace.Name, serviceName, expectedEndpointsNum, time.Second, wait.ForeverTestTimeout)
			framework.ExpectNoError(err, "failed to validate endpoints for service %s in namespace: %s", serviceName, f.Namespace.Name)

			for _, protocol := range []string{"http", "udp"} {
				for _, node := range nodes.Items {
					for _, nodeAddress := range node.Status.Addresses {
						// skipping hostnames
						if !addressIsIP(nodeAddress) {
							continue
						}

						responses := sets.NewString()
						// Fill expected responses, it should hit the nodeLocal endpoints and not SNAT packet IP
						expectedResponses := sets.NewString()

						if utilnet.IsIPv6String(nodeAddress.Address) {
							expectedResponses.Insert(node.Name, externalContainer.GetIPv6())
						} else {
							expectedResponses.Insert(node.Name, externalContainer.GetIPv4())
						}

						valid := false
						nodePort := nodeTCPPort
						if protocol == "udp" {
							nodePort = nodeUDPPort
						}

						ginkgo.By("Hitting the nodeport on " + node.Name + " and trying to reach only the local endpoint with protocol " + protocol)
						for i := 0; i < maxTries; i++ {
							epHostname := pokeEndpointViaExternalContainer(externalContainer, protocol, nodeAddress.Address, nodePort, "hostname")
							epClientIP := pokeEndpointViaExternalContainer(externalContainer, protocol, nodeAddress.Address, nodePort, "clientip")
							epClientIP, _, err = net.SplitHostPort(epClientIP)
							framework.ExpectNoError(err, "failed to parse client ip:port")
							responses.Insert(epHostname, epClientIP)

							if responses.Equal(expectedResponses) {
								framework.Logf("Validated local endpoint on node %s with address %s, and packet src IP %s ", node.Name, nodeAddress.Address, epClientIP)
								valid = true
								break
							}

						}
						gomega.Expect(valid).To(gomega.Equal(true),
							fmt.Sprintf("Validation failed for node %s. Expected Responses=%v, Actual Responses=%v", node.Name, expectedResponses, responses))
					}
				}
			}
		})
	})
})

// This test validates that OVS exports flow monitoring data from br-int to an external collector
var _ = ginkgo.Describe("e2e br-int flow monitoring export validation", func() {
	type flowMonitoringProtocol string

	const (
		netflow_v5 flowMonitoringProtocol = "netflow"
		ipfix      flowMonitoringProtocol = "ipfix"
		sflow      flowMonitoringProtocol = "sflow"

		svcname                    string = "netflow-test"
		collectorContainerTemplate string = "netflow-collector%d"
	)

	getContainerName := func(port uint16) string {
		return fmt.Sprintf(collectorContainerTemplate, port)
	}

	keywordInLogs := map[flowMonitoringProtocol]string{
		netflow_v5: "NETFLOW_V5", ipfix: "IPFIX", sflow: "SFLOW_5"}

	f := wrappedTestFramework(svcname)
	var providerCtx infraapi.Context

	ginkgo.BeforeEach(func() {
		providerCtx = infraprovider.Get().NewTestContext()
	})

	ginkgo.DescribeTable("Should validate flow data of br-int is sent to an external gateway",
		func(protocol flowMonitoringProtocol, collectorPort uint16) {
			protocolStr := string(protocol)
			isIpv6 := IsIPv6Cluster(f.ClientSet)
			ovnKubeNamespace := deploymentconfig.Get().OVNKubernetesNamespace()

			ginkgo.By("Starting a flow collector container")
			primaryProviderNetwork, err := infraprovider.Get().PrimaryNetwork()
			framework.ExpectNoError(err, "failed to get primary network")
			collectorExternalContainer := infraapi.ExternalContainer{Name: getContainerName(collectorPort), Image: "cloudflare/goflow",
				Network: primaryProviderNetwork, CmdArgs: []string{"-kafka=false"}, ExtPort: collectorPort}
			collectorExternalContainer, err = providerCtx.CreateExternalContainer(collectorExternalContainer)
			if err != nil {
				framework.Failf("failed to start flow collector container %s: %v", getContainerName(collectorPort), err)
			}
			ovnEnvVar := fmt.Sprintf("OVN_%s_TARGETS", strings.ToUpper(protocolStr))
			// retrieve the ip of the collector container
			collectorIP := collectorExternalContainer.GetIPv4()
			if isIpv6 {
				collectorIP = collectorExternalContainer.GetIPv6()
			}

			addressAndPort := net.JoinHostPort(collectorIP, strconv.Itoa(int(collectorExternalContainer.ExtPort)))

			ginkgo.By(fmt.Sprintf("Configuring ovnkube-node to use the new %s collector target", protocolStr))
			setEnv := map[string]string{ovnEnvVar: addressAndPort}
			setUnsetTemplateContainerEnv(f.ClientSet, ovnKubeNamespace, "daemonset/ovnkube-node", getNodeContainerName(), setEnv)

			ginkgo.By(fmt.Sprintf("Checking that the collector container received %s data", protocolStr))
			keyword := keywordInLogs[protocol]
			collectorContainerLogsTest := func() wait.ConditionFunc {
				return func() (bool, error) {
					collectorContainerLogs, err := infraprovider.Get().GetExternalContainerLogs(collectorExternalContainer)
					if err != nil {
						framework.Logf("failed to inspect logs in test container: %v", err)
						return false, nil
					}
					collectorContainerLogs = strings.TrimSuffix(collectorContainerLogs, "\n")
					logLines := strings.Split(collectorContainerLogs, "\n")
					lastLine := logLines[len(logLines)-1]
					// check that flow monitoring traffic has been logged
					if strings.Contains(lastLine, keyword) {
						framework.Logf("Successfully found string %s in last log line of"+
							" the collector: %s", keyword, lastLine)
						return true, nil
					}
					framework.Logf("%s not found in last log line: %s", keyword, lastLine)
					return false, nil
				}
			}
			err = wait.PollImmediate(retryInterval, retryTimeout, collectorContainerLogsTest())
			framework.ExpectNoError(err, fmt.Sprintf("failed to verify that collector container "+
				"received %s data from br-int: string %s not found in logs",
				protocolStr, keyword))

			ginkgo.By(fmt.Sprintf("Unsetting %s variable in ovnkube-node daemonset", ovnEnvVar))
			setUnsetTemplateContainerEnv(f.ClientSet, ovnKubeNamespace, "daemonset/ovnkube-node", getNodeContainerName(), nil, ovnEnvVar)

			ovnKubeNodePods, err := f.ClientSet.CoreV1().Pods(ovnKubeNamespace).List(context.TODO(), metav1.ListOptions{
				LabelSelector: "name=ovnkube-node",
			})
			if err != nil {
				framework.Failf("could not get ovnkube-node pods: %v", err)
			}

			for _, ovnKubeNodePod := range ovnKubeNodePods.Items {

				execOptions := e2epod.ExecOptions{
					Command:       []string{"ovs-vsctl", "find", strings.ToLower(protocolStr)},
					Namespace:     ovnKubeNamespace,
					PodName:       ovnKubeNodePod.Name,
					ContainerName: getNodeContainerName(),
					CaptureStdout: true,
					CaptureStderr: true,
				}

				targets, stderr, _ := e2epod.ExecWithOptions(f, execOptions)
				framework.Logf("execOptions are %v", execOptions)
				if err != nil {
					framework.Failf("could not lookup ovs %s targets: %v", protocolStr, stderr)
				}
				gomega.Expect(targets).To(gomega.BeEmpty())
			}
		},
		// This is a long test (~5 minutes per run), so let's just validate netflow v5
		// in an IPv4 cluster and sflow in IPv6 cluster
		ginkgo.Entry("with netflow v5", netflow_v5, uint16(2056)),
		// goflow doesn't currently support OVS ipfix:
		// https://github.com/cloudflare/goflow/issues/99
		// ginkgo.Entry("ipfix", ipfix, uint16(2055)),
		ginkgo.Entry("with sflow", sflow, uint16(6343)),
	)

})

func getNodePodCIDRs(nodeName string) (string, string, error) {
	// retrieve the pod cidr for the worker node
	jsonFlag := "jsonpath='{.metadata.annotations.k8s\\.ovn\\.org/node-subnets}'"
	kubectlOut, err := e2ekubectl.RunKubectl("default", "get", "node", nodeName, "-o", jsonFlag)
	if err != nil {
		return "", "", err
	}
	// strip the apostrophe from stdout and parse the pod cidr
	annotation := strings.Replace(kubectlOut, "'", "", -1)

	var ipv4CIDR, ipv6CIDR string

	ssSubnets := make(map[string]string)
	if err := json.Unmarshal([]byte(annotation), &ssSubnets); err == nil {
		// If only one subnet, determine if it's v4 or v6
		if subnet, ok := ssSubnets["default"]; ok {
			if strings.Contains(subnet, ":") {
				ipv6CIDR = subnet
			} else {
				ipv4CIDR = subnet
			}
			return ipv4CIDR, ipv6CIDR, nil
		}
	}

	dsSubnets := make(map[string][]string)
	if err := json.Unmarshal([]byte(annotation), &dsSubnets); err == nil {
		if subnets, ok := dsSubnets["default"]; ok && len(subnets) > 0 {
			// Classify each subnet as IPv4 or IPv6
			for _, subnet := range subnets {
				if strings.Contains(subnet, ":") {
					ipv6CIDR = subnet
				} else {
					ipv4CIDR = subnet
				}
			}
			return ipv4CIDR, ipv6CIDR, nil
		}
	}

	return "", "", fmt.Errorf("could not parse annotation %q", annotation)
}

var _ = ginkgo.Describe("e2e delete databases", func() {
	const (
		svcname           string = "delete-db"
		databasePodPrefix string = "ovnkube-db"
		northDBFileName   string = "ovnnb_db.db"
		southDBFileName   string = "ovnsb_db.db"
		dirDB             string = "/etc/ovn"
		haModeMinDb       int    = 0
		haModeMaxDb       int    = 2
	)
	var allDBFiles = []string{path.Join(dirDB, northDBFileName), path.Join(dirDB, southDBFileName)}

	f := wrappedTestFramework(svcname)

	// WaitForPodConditionAllowNotFoundError is a wrapper for WaitForPodCondition that allows at most 6 times for the pod not to be found.
	WaitForPodConditionAllowNotFoundErrors := func(f *framework.Framework, ns, podName, desc string, timeout time.Duration, condition podCondition) error {
		max_tries := 6               // 6 tries to waiting for the pod to restart
		cooldown := 10 * time.Second // 10 sec to cooldown between each try
		for i := 0; i < max_tries; i++ {
			err := e2epod.WaitForPodCondition(context.TODO(), f.ClientSet, ns, podName, desc, 5*time.Minute, condition)
			if apierrors.IsNotFound(err) {
				// pod not found,try again after cooldown
				time.Sleep(cooldown)
				continue
			}
			if err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("gave up after waiting %v for pod %q to be %q: pod is not found", timeout, podName, desc)
	}

	// waitForPodToFinishFullRestart waits for a the pod to finish its reset cycle and returns.
	waitForPodToFinishFullRestart := func(f *framework.Framework, pod *v1.Pod) {
		podClient := f.ClientSet.CoreV1().Pods(pod.Namespace)
		// loop until pod with new UID exists
		err := wait.PollImmediate(retryInterval, 5*time.Minute, func() (bool, error) {
			newPod, err := podClient.Get(context.Background(), pod.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			} else if err != nil {
				return false, err
			}

			return pod.UID != newPod.UID, nil
		})
		framework.ExpectNoError(err)

		// during this stage on the restarting process we can encounter "pod not found" errors.
		// these types of errors are valid because the pod is restarting so there will be a period of time it is unavailable
		// so we will use "WaitForPodConditionAllowNotFoundErrors" in order to handle properly those errors.
		err = WaitForPodConditionAllowNotFoundErrors(f, pod.Namespace, pod.Name, "running and ready", 5*time.Minute, testutils.PodRunningReady)
		if err != nil {
			framework.Failf("pod %v did not reach running and ready state: %v", pod.Name, err)
		}
	}

	deletePod := func(f *framework.Framework, namespace string, podName string) {
		podClient := f.ClientSet.CoreV1().Pods(namespace)
		_, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}

		err = podClient.Delete(context.Background(), podName, metav1.DeleteOptions{})
		framework.ExpectNoError(err, "failed to delete pod "+podName)
	}

	fileExistsOnPod := func(f *framework.Framework, namespace string, pod *v1.Pod, file string) bool {
		containerFlag := fmt.Sprintf("-c=%s", pod.Spec.Containers[0].Name)
		_, err := e2ekubectl.RunKubectl(namespace, "exec", pod.Name, containerFlag, "--", "ls", file)
		if err == nil {
			return true
		}
		if strings.Contains(err.Error(), fmt.Sprintf("ls: cannot access '%s': No such file or directory", file)) {
			return false
		}
		framework.Failf("failed to check if file %s exists on pod: %s, err: %v", file, pod.Name, err)
		return false
	}

	getDeployment := func(f *framework.Framework, namespace string, deploymentName string) *appsv1.Deployment {
		deploymentClient := f.ClientSet.AppsV1().Deployments(namespace)
		deployment, err := deploymentClient.Get(context.TODO(), deploymentName, metav1.GetOptions{})
		framework.ExpectNoError(err, "should get %s deployment", deploymentName)

		return deployment
	}

	allFilesExistOnPod := func(f *framework.Framework, namespace string, pod *v1.Pod, files []string) bool {
		for _, file := range files {
			if !fileExistsOnPod(f, namespace, pod, file) {
				framework.Logf("file %s not exists", file)
				return false
			}
			framework.Logf("file %s exists", file)
		}
		return true
	}

	deleteFileFromPod := func(f *framework.Framework, namespace string, pod *v1.Pod, file string) {
		containerFlag := fmt.Sprintf("-c=%s", pod.Spec.Containers[0].Name)
		e2ekubectl.RunKubectl(namespace, "exec", pod.Name, containerFlag, "--", "rm", file)
		if fileExistsOnPod(f, namespace, pod, file) {
			framework.Failf("Error: failed to delete file %s", file)
		}
		framework.Logf("file %s deleted ", file)
	}

	singlePodConnectivityTest := func(f *framework.Framework, podName string) {
		framework.Logf("Running container which tries to connect to API server in a loop")

		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go func() {
			defer ginkgo.GinkgoRecover()
			checkContinuousConnectivity(f, "", podName, getApiAddress(), 443, 10, 30, podChan, errChan)
		}()

		err := <-errChan
		framework.ExpectNoError(err)

		testPod := <-podChan

		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)
		framework.ExpectNoError(<-errChan)
	}

	twoPodsContinuousConnectivityTest := func(f *framework.Framework, node1Name string, node2Name string, syncChan chan string, errChan chan error) {
		const (
			pod1Name                  string        = "connectivity-test-pod1"
			pod2Name                  string        = "connectivity-test-pod2"
			podPort                   uint16        = 8080
			timeIntervalBetweenChecks time.Duration = 2 * time.Second
		)

		_, err := createGenericPod(f, pod1Name, node1Name, f.Namespace.Name, getAgnHostHTTPPortBindFullCMD(podPort))
		framework.ExpectNoError(err, "failed to create pod %s/%s", f.Namespace.Name, pod1Name)
		_, err = createGenericPod(f, pod2Name, node2Name, f.Namespace.Name, getAgnHostHTTPPortBindFullCMD(podPort))
		framework.ExpectNoError(err, "failed to create pod %s/%s", f.Namespace.Name, pod2Name)

		pod2IP := getPodAddress(pod2Name, f.Namespace.Name)

		ginkgo.By("Checking initial connectivity from one pod to the other and verifying that the connection is achieved")

		stdout, err := e2ekubectl.RunKubectl(f.Namespace.Name, "exec", pod1Name, "--", "curl", fmt.Sprintf("%s/hostname",
			net.JoinHostPort(pod2IP, fmt.Sprintf("%d", podPort))))

		if err != nil || stdout != pod2Name {
			errChan <- fmt.Errorf("Error: attempted connection to pod %s found err:  %v", pod2Name, err)
		}

		syncChan <- "connectivity test pods are ready"

	L:
		for {
			select {
			case msg := <-syncChan:
				framework.Logf("%s: finish connectivity test.", msg)
				break L
			default:
				stdout, err := e2ekubectl.RunKubectl(f.Namespace.Name, "exec", pod1Name, "--", "curl", fmt.Sprintf("%s/hostname",
					net.JoinHostPort(pod2IP, fmt.Sprintf("%d", podPort))))
				if err != nil || stdout != pod2Name {
					errChan <- err
					framework.Failf("Error: attempted connection to pod %s found err:  %v", pod2Name, err)
				}
				time.Sleep(timeIntervalBetweenChecks)
			}
		}

		errChan <- nil
	}

	ginkgo.DescribeTable("recovering from deleting db files while maintaining connectivity",
		func(db_pod_num int, DBFileNamesToDelete []string) {
			var (
				db_pod_name = fmt.Sprintf("%s-%d", databasePodPrefix, db_pod_num)
			)
			if db_pod_num < haModeMinDb || db_pod_num > haModeMaxDb {
				framework.Failf("invalid db_pod_num.")
				return
			}

			// Adding db file path
			for i, file := range DBFileNamesToDelete {
				DBFileNamesToDelete[i] = path.Join(dirDB, file)
			}

			nodes, err := e2enode.GetBoundedReadySchedulableNodes(context.TODO(), f.ClientSet, 2)
			framework.ExpectNoError(err)
			if len(nodes.Items) < 2 {
				ginkgo.Skip("Test requires >= 2 Ready nodes, but there are only %v nodes", len(nodes.Items))
			}
			framework.Logf("connectivity test before deleting db files")
			framework.Logf("test simple connectivity from new pod to API server, before deleting db files")
			singlePodConnectivityTest(f, "before-delete-db-files")
			framework.Logf("setup two pods for continuous connectivity test")
			syncChan, errChan := make(chan string), make(chan error)
			node1Name, node2Name := nodes.Items[0].GetName(), nodes.Items[1].GetName()
			go func() {
				defer ginkgo.GinkgoRecover()
				twoPodsContinuousConnectivityTest(f, node1Name, node2Name, syncChan, errChan)
			}()

			select {
			case msg := <-syncChan:
				// wait for the connectivity test pods to be ready
				framework.Logf("%s: delete and restart db pods.", msg)
			case err := <-errChan:
				// fail if error is returned before test pods are ready
				framework.Fail(err.Error())
			}

			// Start the db disruption - delete the db files and delete the db-pod in order to emulate the cluster/pod restart

			// Retrieve the DB pod
			ovnKubeNamespace := deploymentconfig.Get().OVNKubernetesNamespace()
			dbPod, err := f.ClientSet.CoreV1().Pods(ovnKubeNamespace).Get(context.Background(), db_pod_name, metav1.GetOptions{})
			framework.ExpectNoError(err, fmt.Sprintf("unable to get pod: %s, err: %v", db_pod_name, err))

			// Check that all files are on the db pod
			framework.Logf("make sure that all the db files are on db pod %s", dbPod.Name)
			if !allFilesExistOnPod(f, ovnKubeNamespace, dbPod, allDBFiles) {
				framework.Failf("Error: db files not found")
			}
			// Delete the db files from the db-pod
			framework.Logf("deleting db files from db pod")
			for _, db_file := range DBFileNamesToDelete {
				deleteFileFromPod(f, ovnKubeNamespace, dbPod, db_file)
			}
			// Delete the db-pod in order to emulate the cluster/pod restart
			framework.Logf("deleting db pod %s", dbPod.Name)
			deletePod(f, ovnKubeNamespace, dbPod.Name)

			framework.Logf("wait for db pod to finish full restart")
			waitForPodToFinishFullRestart(f, dbPod)

			// Check db files existence
			// Check that all files are on pod
			framework.Logf("make sure that all the db files are on db pod %s", dbPod.Name)
			if !allFilesExistOnPod(f, ovnKubeNamespace, dbPod, allDBFiles) {
				framework.Failf("Error: db files not found")
			}

			// disruption over.
			syncChan <- "disruption over"
			framework.ExpectNoError(<-errChan)

			framework.Logf("test simple connectivity from new pod to API server, after recovery")
			singlePodConnectivityTest(f, "after-delete-db-files")
		},

		// One can choose to delete only specific db file (uncomment the requested lines)

		// db pod 0
		ginkgo.Entry("when deleting both db files on ovnkube-db-0", 0, []string{northDBFileName, southDBFileName}),
		// ginkgo.Entry("when delete north db on ovnkube-db-0", 0, []string{northDBFileName}),
		// ginkgo.Entry("when delete south db on ovnkube-db-0", 0, []string{southDBFileName}),

		// db pod 1
		ginkgo.Entry("when deleting both db files on ovnkube-db-1", 1, []string{northDBFileName, southDBFileName}),
		// ginkgo.Entry("when delete north db on ovnkube-db-1", 1, []string{northDBFileName}),
		// ginkgo.Entry("when delete south db on ovnkube-db-1", 1, []string{southDBFileName}),

		// db pod 2
		ginkgo.Entry("when deleting both db files on ovnkube-db-2", 2, []string{northDBFileName, southDBFileName}),
		// ginkgo.Entry("when delete north db on ovnkube-db-2", 2, []string{northDBFileName}),
		// ginkgo.Entry("when delete south db on ovnkube-db-2", 2, []string{southDBFileName}),
	)

	ginkgo.It("Should validate connectivity before and after deleting all the db-pods at once in Non-HA mode", func() {
		if isInterconnectEnabled() {
			e2eskipper.Skipf(
				"No separate db pods in muliple zones interconnect deployment",
			)
		}
		ovnKubeNamespace := deploymentconfig.Get().OVNKubernetesNamespace()
		dbDeployment := getDeployment(f, ovnKubeNamespace, "ovnkube-db")
		dbPods, err := e2edeployment.GetPodsForDeployment(context.TODO(), f.ClientSet, dbDeployment)
		if err != nil {
			framework.Failf("Error: Failed to get pods, err: %v", err)
		}
		if dbPods.Size() == 0 {
			framework.Failf("Error: db pods not found")
		}

		framework.Logf("test simple connectivity from new pod to API server,before deleting db pods")
		singlePodConnectivityTest(f, "before-delete-db-pods")

		framework.Logf("deleting all the db pods")

		for _, dbPod := range dbPods.Items {
			dbPodName := dbPod.Name
			framework.Logf("deleting db pod: %v", dbPodName)
			// Delete the db-pod in order to emulate the pod restart
			dbPod.Status.Message = "check"
			deletePod(f, ovnKubeNamespace, dbPodName)
		}

		framework.Logf("wait for all the Deployment to become ready again after pod deletion")
		err = e2edeployment.WaitForDeploymentComplete(f.ClientSet, dbDeployment)
		framework.ExpectNoError(err, "failed to wait for DB deployment to complete")

		framework.Logf("all the pods finish full restart")

		framework.Logf("test simple connectivity from new pod to API server,after recovery")
		singlePodConnectivityTest(f, "after-delete-db-pods")
	})

	ginkgo.It("Should validate connectivity before and after deleting all the db-pods at once in HA mode", func() {
		ovnKubeNamespace := deploymentconfig.Get().OVNKubernetesNamespace()
		dbPods, err := e2epod.GetPods(context.TODO(), f.ClientSet, ovnKubeNamespace, map[string]string{"name": databasePodPrefix})
		if err != nil {
			framework.Failf("Error: Failed to get pods, err: %v", err)
		}
		if len(dbPods) == 0 {
			framework.Failf("Error: db pods not found")
		}

		framework.Logf("test simple connectivity from new pod to API server,before deleting db pods")
		singlePodConnectivityTest(f, "before-delete-db-pods")

		framework.Logf("deleting all the db pods")
		for _, dbPod := range dbPods {
			dbPodName := dbPod.Name
			framework.Logf("deleting db pod: %v", dbPodName)
			// Delete the db-pod in order to emulate the pod restart
			dbPod.Status.Message = "check"
			deletePod(f, ovnKubeNamespace, dbPodName)
		}

		framework.Logf("wait for all the pods to finish full restart")
		var wg sync.WaitGroup
		for _, pod := range dbPods {
			wg.Add(1)
			go func(pod v1.Pod) {
				defer ginkgo.GinkgoRecover()
				defer wg.Done()
				waitForPodToFinishFullRestart(f, &pod)
			}(pod)
		}
		wg.Wait()
		framework.Logf("all the pods finish full restart")

		framework.Logf("test simple connectivity from new pod to API server,after recovery")
		singlePodConnectivityTest(f, "after-delete-db-pods")
	})
})
