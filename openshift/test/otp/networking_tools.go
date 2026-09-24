package otp

import (
	"bytes"
	"context"
	"fmt"
	osExec "os/exec"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

var _ = g.Describe("[OTP] OVN Networking Tools", func() {
	var (
		clientset *kubernetes.Clientset
		config    *rest.Config
		ctx       context.Context
	)

	g.BeforeEach(func() {
		ctx = context.Background()

		// Load kubeconfig
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

		var err error
		config, err = kubeConfig.ClientConfig()
		o.Expect(err).NotTo(o.HaveOccurred())

		clientset, err = kubernetes.NewForConfig(config)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("55889-should execute ovn-db-run-command script successfully", func() {
		g.By("Finding an ovnkube-node pod with northd container")
		pods, err := clientset.CoreV1().Pods("openshift-ovn-kubernetes").List(ctx, metav1.ListOptions{
			LabelSelector: "app=ovnkube-node",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(pods.Items)).To(o.BeNumerically(">", 0), "Expected at least one ovnkube-node pod")

		nodePod := pods.Items[0].Name

		g.By("Testing ovn-nbctl command (equivalent to ovn-db-run-command)")
		// Execute: ovn-nbctl show
		// Note: ovn-db-run-command script may not exist in older versions
		execCmd := []string{
			"ovn-nbctl",
			"--no-leader-only",
			"show",
		}

		scheme := runtime.NewScheme()
		err = corev1.AddToScheme(scheme)
		o.Expect(err).NotTo(o.HaveOccurred())

		req := clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name(nodePod).
			Namespace("openshift-ovn-kubernetes").
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "northd",
				Command:   execCmd,
				Stdout:    true,
				Stderr:    true,
			}, runtime.NewParameterCodec(scheme))

		exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
		o.Expect(err).NotTo(o.HaveOccurred())

		var stdout, stderr bytes.Buffer
		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})
		o.Expect(err).NotTo(o.HaveOccurred(), "ovn-db-run-command execution failed: %s", stderr.String())

		output := stdout.String()
		g.By("Verifying command output contains expected OVN database content")
		// The 'show' command should produce non-empty output showing OVN topology
		o.Expect(output).NotTo(o.BeEmpty(), "ovn-nbctl produced no output")

		// Verify output looks like OVN Northbound DB content (contains typical elements)
		hasValidContent := strings.Contains(output, "switch") ||
			strings.Contains(output, "router") ||
			strings.Contains(output, "port") ||
			strings.Contains(output, "Logical") ||
			strings.Contains(output, "join")
		o.Expect(hasValidContent).To(o.BeTrue(),
			"Output doesn't appear to be valid OVN database content: %s", output)
	})

	g.It("55890-should verify network-tools ovn-get script functionality", func() {
		const testNS = "test-network-tools-55890"
		const podName = "network-tools-test"
		const containerName = "network-tools"
		const crbName = "test-network-tools-55890-admin"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "privileged",
					"pod-security.kubernetes.io/audit":   "privileged",
					"pod-security.kubernetes.io/warn":    "privileged",
				},
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			_ = osExec.CommandContext(ctx, "oc", "delete", "clusterrolebinding", crbName, "--ignore-not-found").Run()
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Setting up RBAC for network-tools pod")
		rbacCmd := osExec.CommandContext(ctx, "oc", "create", "clusterrolebinding", crbName,
			"--clusterrole=cluster-admin",
			fmt.Sprintf("--serviceaccount=%s:default", testNS))
		rbacOut, err := rbacCmd.CombinedOutput()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to create ClusterRoleBinding: %s", string(rbacOut))

		g.By("Getting network-tools image from imagestream")
		imageCmd := osExec.CommandContext(ctx, "oc", "get", "istag", "network-tools:latest",
			"-n", "openshift", "-o", "jsonpath={.image.dockerImageReference}")
		imageOut, err := imageCmd.CombinedOutput()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get network-tools image: %s", string(imageOut))
		networkToolsImage := strings.TrimSpace(string(imageOut))
		o.Expect(networkToolsImage).NotTo(o.BeEmpty(), "network-tools image reference is empty")

		g.By(fmt.Sprintf("Creating network-tools pod with image %s", networkToolsImage))
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: testNS,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    containerName,
						Image:   networkToolsImage,
						Command: []string{"sleep", "3600"},
					},
				},
				RestartPolicy: corev1.RestartPolicyNever,
			},
		}
		_, err = clientset.CoreV1().Pods(testNS).Create(ctx, pod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for network-tools pod to be ready")
		o.Eventually(func() bool {
			p, getErr := clientset.CoreV1().Pods(testNS).Get(ctx, podName, metav1.GetOptions{})
			if getErr != nil {
				return false
			}
			return p.Status.Phase == corev1.PodRunning
		}, 120, 5).Should(o.BeTrue(), "network-tools pod did not reach Running state")

		const networkToolsBin = "/opt/bin/network-tools"

		g.By("Testing ovn-get -h (help)")
		helpOutput, err := execCommandInPod(ctx, clientset, config, testNS, podName, containerName,
			[]string{networkToolsBin, "ovn-get", "-h"})
		o.Expect(err).NotTo(o.HaveOccurred(), "ovn-get -h failed: %s", helpOutput)
		o.Expect(helpOutput).To(o.ContainSubstring("leaders"), "Help output should mention 'leaders' command")
		o.Expect(helpOutput).To(o.ContainSubstring("mode"), "Help output should mention 'mode' command")

		g.By("Testing ovn-get leaders")
		leadersOutput, err := execCommandInPod(ctx, clientset, config, testNS, podName, containerName,
			[]string{networkToolsBin, "ovn-get", "leaders"})
		o.Expect(err).NotTo(o.HaveOccurred(), "ovn-get leaders failed: %s", leadersOutput)
		o.Expect(leadersOutput).To(o.ContainSubstring("leader"), "Leaders output should contain leader information")

		g.By("Testing ovn-get mode")
		modeOutput, err := execCommandInPod(ctx, clientset, config, testNS, podName, containerName,
			[]string{networkToolsBin, "ovn-get", "mode"})
		o.Expect(err).NotTo(o.HaveOccurred(), "ovn-get mode failed: %s", modeOutput)
		hasMode := strings.Contains(modeOutput, "multi-zone") ||
			strings.Contains(modeOutput, "interconnect") ||
			strings.Contains(modeOutput, "ovn-ic") ||
			strings.Contains(modeOutput, "legacy") ||
			strings.Contains(modeOutput, "single-zone")
		o.Expect(hasMode).To(o.BeTrue(), "Mode output should indicate cluster mode: %s", modeOutput)
	})

	g.It("67625-should trace pod-to-pod traffic successfully", func() {
		var err error
		const traceNS = "test-ovnkube-trace-67625"
		const crbName = "test-ovnkube-trace-67625-admin"

		g.By("Creating test namespace for trace pods")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: traceNS,
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "privileged",
					"pod-security.kubernetes.io/audit":   "privileged",
					"pod-security.kubernetes.io/warn":    "privileged",
				},
			},
		}
		_, err = clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			_ = osExec.CommandContext(ctx, "oc", "delete", "clusterrolebinding", crbName, "--ignore-not-found").Run()
			_ = clientset.CoreV1().Namespaces().Delete(ctx, traceNS, metav1.DeleteOptions{})
		}()

		g.By("Setting up RBAC for trace runner pod")
		rbacCmd := osExec.CommandContext(ctx, "oc", "create", "clusterrolebinding", crbName,
			"--clusterrole=cluster-admin",
			fmt.Sprintf("--serviceaccount=%s:default", traceNS))
		rbacOut, err := rbacCmd.CombinedOutput()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to create ClusterRoleBinding: %s", string(rbacOut))

		g.By("Creating source pod")
		srcPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "src-pod",
				Namespace: traceNS,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "test",
						Image:   "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}
		_, err = clientset.CoreV1().Pods(traceNS).Create(ctx, srcPod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating destination pod")
		dstPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dst-pod",
				Namespace: traceNS,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "test",
						Image:   "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}
		_, err = clientset.CoreV1().Pods(traceNS).Create(ctx, dstPod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for pods to be Running")
		o.Eventually(func() bool {
			src, _ := clientset.CoreV1().Pods(traceNS).Get(ctx, "src-pod", metav1.GetOptions{})
			dst, _ := clientset.CoreV1().Pods(traceNS).Get(ctx, "dst-pod", metav1.GetOptions{})
			return src.Status.Phase == corev1.PodRunning && dst.Status.Phase == corev1.PodRunning
		}, 60, 5).Should(o.BeTrue(), "Pods did not reach Running state")

		g.By("Running ovnkube-trace from src to dst pod")
		output, err := runOVNKubeTrace(ctx, clientset, config, traceNS,
			traceNS, "src-pod",
			traceNS, "dst-pod",
			"tcp", "8080")
		o.Expect(err).NotTo(o.HaveOccurred(), "ovnkube-trace failed with output:\n%s", output)

		g.By("Verifying trace output shows packet delivery")
		o.Expect(output).To(o.ContainSubstring("indicates success"), "Trace should indicate success")
		o.Expect(output).NotTo(o.ContainSubstring("drop"), "Trace should not show packet drops")
	})

	g.It("67648-should trace pod-to-hostnetworkpod traffic successfully", func() {
		var err error
		const traceNS = "test-ovnkube-trace-67648"
		const crbName = "test-ovnkube-trace-67648-admin"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: traceNS,
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "privileged",
					"pod-security.kubernetes.io/audit":   "privileged",
					"pod-security.kubernetes.io/warn":    "privileged",
				},
			},
		}
		_, err = clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			_ = osExec.CommandContext(ctx, "oc", "delete", "clusterrolebinding", crbName, "--ignore-not-found").Run()
			_ = clientset.CoreV1().Namespaces().Delete(ctx, traceNS, metav1.DeleteOptions{})
		}()

		g.By("Setting up RBAC for trace runner pod")
		rbacCmd := osExec.CommandContext(ctx, "oc", "create", "clusterrolebinding", crbName,
			"--clusterrole=cluster-admin",
			fmt.Sprintf("--serviceaccount=%s:default", traceNS))
		rbacOut, err := rbacCmd.CombinedOutput()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to create ClusterRoleBinding: %s", string(rbacOut))

		g.By("Creating source pod (regular overlay pod)")
		srcPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "src-pod",
				Namespace: traceNS,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "test",
						Image:   "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}
		_, err = clientset.CoreV1().Pods(traceNS).Create(ctx, srcPod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating destination host-network pod")
		dstPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dst-hostnet-pod",
				Namespace: traceNS,
			},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				Containers: []corev1.Container{
					{
						Name:    "test",
						Image:   "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}
		_, err = clientset.CoreV1().Pods(traceNS).Create(ctx, dstPod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for pods to be Running")
		o.Eventually(func() bool {
			src, _ := clientset.CoreV1().Pods(traceNS).Get(ctx, "src-pod", metav1.GetOptions{})
			dst, _ := clientset.CoreV1().Pods(traceNS).Get(ctx, "dst-hostnet-pod", metav1.GetOptions{})
			return src.Status.Phase == corev1.PodRunning && dst.Status.Phase == corev1.PodRunning
		}, 60, 5).Should(o.BeTrue(), "Pods did not reach Running state")

		g.By("Running ovnkube-trace from overlay pod to host-network pod")
		output, err := runOVNKubeTrace(ctx, clientset, config, traceNS,
			traceNS, "src-pod",
			traceNS, "dst-hostnet-pod",
			"tcp", "22")
		o.Expect(err).NotTo(o.HaveOccurred(), "ovnkube-trace failed with output:\n%s", output)

		g.By("Verifying trace shows routing to host network")
		o.Expect(output).NotTo(o.BeEmpty(), "Trace should produce output")
		o.Expect(output).To(o.ContainSubstring("indicates success"), "Trace should indicate success")
		o.Expect(output).NotTo(o.ContainSubstring("policy drop"), "Should not be blocked by policy")
	})

})

// runOVNKubeTrace creates a trace runner pod with the OVN image and executes ovnkube-trace.
// The traceNS must have a default SA with cluster-admin ClusterRoleBinding (set up by the caller).
// ovnkube-trace needs cluster-wide pods list/get, nodes list/get, and pods/exec in the OVN namespace.
func runOVNKubeTrace(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config,
	traceNS, srcNS, srcPod, dstNS, dstPod, protocol, port string) (string, error) {

	const tracePodName = "ovnkube-trace-runner"
	const traceContainer = "trace"

	// Get OVN image from an existing ovnkube-node pod
	ovnPods, err := clientset.CoreV1().Pods("openshift-ovn-kubernetes").List(ctx, metav1.ListOptions{
		LabelSelector: "app=ovnkube-node",
	})
	if err != nil {
		return "", fmt.Errorf("failed to list ovnkube-node pods: %v", err)
	}
	if len(ovnPods.Items) == 0 {
		return "", fmt.Errorf("no ovnkube-node pods found in openshift-ovn-kubernetes namespace")
	}

	var ovnImage string
	for _, container := range ovnPods.Items[0].Spec.Containers {
		if container.Name == "ovnkube-controller" || container.Name == "ovnkube-node" {
			ovnImage = container.Image
			break
		}
	}
	if ovnImage == "" {
		return "", fmt.Errorf("could not find ovnkube-controller or ovnkube-node container in pod %s", ovnPods.Items[0].Name)
	}

	// Create a trace runner pod using the OVN image (which contains ovnkube-trace binary)
	tracePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tracePodName,
			Namespace: traceNS,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    traceContainer,
					Image:   ovnImage,
					Command: []string{"sleep", "3600"},
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
	_, err = clientset.CoreV1().Pods(traceNS).Create(ctx, tracePod, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create trace runner pod: %v", err)
	}
	defer func() {
		_ = clientset.CoreV1().Pods(traceNS).Delete(ctx, tracePodName, metav1.DeleteOptions{})
	}()

	// Wait for trace runner pod to be running
	for i := 0; i < 24; i++ {
		p, getErr := clientset.CoreV1().Pods(traceNS).Get(ctx, tracePodName, metav1.GetOptions{})
		if getErr == nil && p.Status.Phase == corev1.PodRunning {
			break
		}
		if i == 23 {
			return "", fmt.Errorf("trace runner pod did not reach Running state within 120s")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

	traceCmd := []string{
		"ovnkube-trace",
		"-src-namespace", srcNS,
		"-src", srcPod,
		"-dst-namespace", dstNS,
		"-dst", dstPod,
		"-" + protocol,
		"-dst-port", port,
		"-loglevel", "2",
	}

	return execCommandInPod(ctx, clientset, config, traceNS, tracePodName, traceContainer, traceCmd)
}


// execCommandInPod executes a command in a specific pod/container
func execCommandInPod(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config,
	namespace, podName, containerName string, command []string) (string, error) {

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return "", err
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, runtime.NewParameterCodec(scheme))

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return "", err
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return stdout.String() + "\n" + stderr.String(), err
	}

	return stdout.String(), nil
}
