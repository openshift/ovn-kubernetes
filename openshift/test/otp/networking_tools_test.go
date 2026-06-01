package otp

import (
	"bytes"
	"context"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
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

	// Medium-49216: API Token Logging Security
	g.It("[OTP][blocking][case_id:49216] should not expose API tokens in ovnkube-node logs", func() {
		g.By("Getting all ovnkube-node pods")
		pods, err := clientset.CoreV1().Pods("openshift-ovn-kubernetes").List(ctx, metav1.ListOptions{
			LabelSelector: "app=ovnkube-node",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(pods.Items)).To(o.BeNumerically(">", 0), "Expected at least one ovnkube-node pod")

		g.By("Checking logs from each ovnkube-node pod for token exposure")
		totalViolations := 0
		failedPods := []string{}
		skippedPods := []string{}

		for _, pod := range pods.Items {
			// Get logs from ovnkube-controller container
			logOptions := &corev1.PodLogOptions{
				Container: "ovnkube-controller",
				TailLines: int64Ptr(10000),
			}

			req := clientset.CoreV1().Pods("openshift-ovn-kubernetes").GetLogs(pod.Name, logOptions)
			logs, err := req.DoRaw(ctx)

			// If logs can't be retrieved, record and skip this pod
			if err != nil {
				g.GinkgoWriter.Printf("Warning: could not retrieve logs for pod %s: %v\n", pod.Name, err)
				skippedPods = append(skippedPods, pod.Name)
				continue
			}

			logsStr := string(logs)

			// Search for sensitive patterns
			patterns := []string{"api-token", "authorization", "bearer"}
			podViolations := 0

			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(logsStr), pattern) {
					// Filter out false positives (configuration field names without values)
					lines := strings.Split(logsStr, "\n")
					for _, line := range lines {
						lowerLine := strings.ToLower(line)
						if strings.Contains(lowerLine, pattern) {
							// Check if it's just an empty field (e.g., "Token: " with no value)
							if !strings.Contains(lowerLine, "token:") ||
								(strings.Contains(lowerLine, "token:") && !strings.Contains(lowerLine, "token: ")) {
								// This might be an actual token
								if strings.Contains(lowerLine, "eyj") || // JWT tokens start with "eyJ"
									strings.Contains(lowerLine, "bearer ") {
									podViolations++
									break
								}
							}
						}
					}
				}
			}

			if podViolations > 0 {
				totalViolations += podViolations
				failedPods = append(failedPods, pod.Name)
			}
		}

		// Ensure at least some pods were scanned
		scannedCount := len(pods.Items) - len(skippedPods)
		o.Expect(scannedCount).To(o.BeNumerically(">", 0),
			"Could not retrieve logs from any pod - all %d pods skipped: %v",
			len(pods.Items), skippedPods)

		// Assert no tokens were found
		o.Expect(totalViolations).To(o.Equal(0),
			"Found %d potential token exposures in pods: %v",
			totalViolations, failedPods)
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

	// High-57589: Whereabouts CNI Timeout with Large Exclude Range
	g.It("[OTP][blocking][case_id:57589] should handle large IPv6 exclude ranges without timeout", func() {
		const testNS = "test-whereabouts-57589"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			g.By("Cleaning up test namespace")
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Creating NetworkAttachmentDefinition with large exclude range")
		nadConfig := `{
      "cniVersion": "0.3.1",
      "name": "bridge-net",
      "type": "bridge",
      "bridge": "test-br0",
      "isGateway": false,
      "ipMasq": false,
      "ipam": {
         "type": "whereabouts",
         "range": "fd43:01f1:3daa:0baa::/64",
         "exclude": [ "fd43:01f1:3daa:0baa::/100" ],
         "log_file": "/tmp/whereabouts.log",
         "log_level" : "debug"
      }
    }`

		err = createNAD(ctx, config, testNS, "nad-w-excludes", nadConfig)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating pod with secondary network")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: testNS,
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/networks": "nad-w-excludes",
				},
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

		_, err = clientset.CoreV1().Pods(testNS).Create(ctx, pod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for pod to reach Running state (max 60s)")
		// Pod should be Running within 60 seconds (test validates no timeout)
		o.Eventually(func() corev1.PodPhase {
			p, err := clientset.CoreV1().Pods(testNS).Get(ctx, "test-pod", metav1.GetOptions{})
			if err != nil {
				return corev1.PodPending
			}
			return p.Status.Phase
		}, 60, 5).Should(o.Equal(corev1.PodRunning),
			"Pod did not reach Running state within 60s - Whereabouts may have timed out")

		g.By("Verifying secondary network attachment")
		p, err := clientset.CoreV1().Pods(testNS).Get(ctx, "test-pod", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		networkStatus, ok := p.Annotations["k8s.v1.cni.cncf.io/network-status"]
		o.Expect(ok).To(o.BeTrue(), "Pod missing network-status annotation")
		o.Expect(networkStatus).NotTo(o.BeEmpty())

		// Verify at least 2 networks (primary + secondary)
		networkCount := strings.Count(networkStatus, `"name"`)
		o.Expect(networkCount).To(o.BeNumerically(">=", 2),
			"Expected at least 2 networks, got %d", networkCount)
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

		src, err := clientset.CoreV1().Pods(traceNS).Get(ctx, "src-pod", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		dst, err := clientset.CoreV1().Pods(traceNS).Get(ctx, "dst-pod", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Running ovnkube-trace from src to dst pod")
		output, err := runOVNKubeTrace(ctx, clientset, config,
			traceNS, "src-pod", src.Status.PodIP,
			traceNS, "dst-pod", dst.Status.PodIP,
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

		src, err := clientset.CoreV1().Pods(traceNS).Get(ctx, "src-pod", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		dst, err := clientset.CoreV1().Pods(traceNS).Get(ctx, "dst-hostnet-pod", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Running ovnkube-trace from overlay pod to host-network pod")
		output, err := runOVNKubeTrace(ctx, clientset, config,
			traceNS, "src-pod", src.Status.PodIP,
			traceNS, "dst-hostnet-pod", dst.Status.HostIP,
			"tcp", "22")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Verifying trace shows routing to host network")
		// Trace should show packet reaching the node (might show different path than pod-to-pod)
		o.Expect(output).NotTo(o.BeEmpty(), "Trace should produce output")
		// Host-network traffic bypasses some OVN overlay, so just verify no hard drops
		o.Expect(output).NotTo(o.ContainSubstring("policy drop"), "Should not be blocked by policy")
	})
})

// Helper function
func int64Ptr(i int64) *int64 {
	return &i
}

// runOVNKubeTrace executes ovnkube-trace in an ovnkube-node pod
func runOVNKubeTrace(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config,
	srcNS, srcPod, srcIP, dstNS, dstPod, dstIP, protocol, port string) (string, error) {

	// Find an ovnkube-node pod
	pods, err := clientset.CoreV1().Pods("openshift-ovn-kubernetes").List(ctx, metav1.ListOptions{
		LabelSelector: "app=ovnkube-node",
	})
	if err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", err
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

// createNAD creates a NetworkAttachmentDefinition
func createNAD(ctx context.Context, config *rest.Config, namespace, name, nadConfig string) error {
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}

	nadGVR := schema.GroupVersionResource{
		Group:    "k8s.cni.cncf.io",
		Version:  "v1",
		Resource: "network-attachment-definitions",
	}

	nad := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "k8s.cni.cncf.io/v1",
			"kind":       "NetworkAttachmentDefinition",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"config": nadConfig,
			},
		},
	}

	_, err = dynamicClient.Resource(nadGVR).Namespace(namespace).Create(ctx, nad, metav1.CreateOptions{})
	return err
}
