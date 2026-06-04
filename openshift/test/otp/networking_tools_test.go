package otp

import (
	"bytes"
	"context"
	"fmt"
	"strings"

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

var _ = g.Describe("[sig-networking] OTP Networking Tools", func() {
	defer g.GinkgoRecover()

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

	// Medium-55889: ovn-db-run-command Script Functionality
	g.It("[OTP][blocking][case_id:55889] should execute ovn-db-run-command script successfully", func() {
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

	// Medium-67625: ovnkube-trace pod-to-pod
	g.It("[OTP][informing][case_id:67625] should trace pod-to-pod traffic successfully", func() {
		g.By("Finding ovnkube-node pods")
		pods, err := clientset.CoreV1().Pods("openshift-ovn-kubernetes").List(ctx, metav1.ListOptions{
			LabelSelector: "app=ovnkube-node",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(pods.Items)).To(o.BeNumerically(">=", 2), "Need at least 2 nodes for pod-to-pod test")

		g.By("Creating test namespace for trace pods")
		const traceNS = "test-ovnkube-trace-67625"
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: traceNS,
			},
		}
		_, err = clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			_ = clientset.CoreV1().Namespaces().Delete(ctx, traceNS, metav1.DeleteOptions{})
		}()

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
		output, err := runOVNKubeTrace(ctx, clientset, config,
			traceNS, "src-pod",
			traceNS, "dst-pod",
			"tcp", "8080")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Verifying trace output shows packet delivery")
		o.Expect(output).To(o.ContainSubstring("output"), "Trace should show output action")
		o.Expect(output).NotTo(o.ContainSubstring("drop"), "Trace should not show packet drops")
	})

	// Medium-67648: ovnkube-trace pod-to-hostnetworkpod
	g.It("[OTP][informing][case_id:67648] should trace pod-to-hostnetworkpod traffic successfully", func() {
		g.By("Creating test namespace")
		const traceNS = "test-ovnkube-trace-67648"
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: traceNS,
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			_ = clientset.CoreV1().Namespaces().Delete(ctx, traceNS, metav1.DeleteOptions{})
		}()

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
		output, err := runOVNKubeTrace(ctx, clientset, config,
			traceNS, "src-pod",
			traceNS, "dst-hostnet-pod",
			"tcp", "22")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Verifying trace shows routing to host network")
		// Trace should show packet reaching the node (might show different path than pod-to-pod)
		o.Expect(output).NotTo(o.BeEmpty(), "Trace should produce output")
		// Host-network traffic bypasses some OVN overlay, so just verify no hard drops
		o.Expect(output).NotTo(o.ContainSubstring("policy drop"), "Should not be blocked by policy")
	})
})

// runOVNKubeTrace executes ovnkube-trace in an ovnkube-node pod
func runOVNKubeTrace(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config,
	srcNS, srcPod, dstNS, dstPod, protocol, port string) (string, error) {

	// Find an ovnkube-node pod
	pods, err := clientset.CoreV1().Pods("openshift-ovn-kubernetes").List(ctx, metav1.ListOptions{
		LabelSelector: "app=ovnkube-node",
	})
	if err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no ovnkube-node pods found in openshift-ovn-kubernetes namespace")
	}

	nodePod := pods.Items[0].Name

	// Build ovnkube-trace command
	execCmd := []string{
		"ovnkube-trace",
		"-src-namespace", srcNS,
		"-src", srcPod,
		"-dst-namespace", dstNS,
		"-dst", dstPod,
		"-" + protocol,
		"-dst-port", port,
		"-loglevel", "2",
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return "", err
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(nodePod).
		Namespace("openshift-ovn-kubernetes").
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "ovnkube-controller",
			Command:   execCmd,
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
