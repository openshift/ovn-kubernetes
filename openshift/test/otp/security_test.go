package otp

import (
	"bytes"
	"context"
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

var _ = g.Describe("[sig-networking] OTP Security", func() {
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

	// Medium-77102: CIS File Permissions for CNI Config
	g.It("[OTP][blocking][case_id:77102] should have secure permissions on CNI configuration files", func() {
		g.By("Checking multus config permissions via multus pods")
		multusPods, err := clientset.CoreV1().Pods("openshift-multus").List(ctx, metav1.ListOptions{
			LabelSelector: "app=multus",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(multusPods.Items)).To(o.BeNumerically(">", 0), "Expected at least one multus pod")

		// Check first multus pod for config file permissions
		multusPod := multusPods.Items[0].Name
		output, err := execInPod(ctx, clientset, config, "openshift-multus", multusPod, "kube-multus",
			[]string{"/bin/bash", "-c", "stat -c '%a %n' /host/etc/cni/net.d/*.conf"})
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to check multus config permissions")

		g.By("Verifying multus config has 600 permissions")
		lines := strings.Split(strings.TrimSpace(output), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			o.Expect(len(parts)).To(o.BeNumerically(">=", 2), "Invalid stat output: %s", line)
			perms := parts[0]
			filename := parts[1]
			o.Expect(perms).To(o.Equal("600"),
				"CIS violation: %s has insecure permissions %s (expected 600)", filename, perms)
		}

		g.By("Checking whereabouts config permissions")
		// Get a worker node
		nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{
			LabelSelector: "node-role.kubernetes.io/worker",
		})
		o.Expect(err).NotTo(o.HaveOccurred())

		if len(nodes.Items) == 0 {
			// Fall back to any node if no workers labeled
			nodes, err = clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		o.Expect(len(nodes.Items)).To(o.BeNumerically(">", 0), "Expected at least one node")

		nodeName := nodes.Items[0].Name

		// Create debug pod on node
		debugPodName := "cis-perms-check-77102"
		debugPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      debugPodName,
				Namespace: "openshift-ovn-kubernetes",
			},
			Spec: corev1.PodSpec{
				NodeName:    nodeName,
				HostNetwork: true,
				HostPID:     true,
				Containers: []corev1.Container{
					{
						Name:  "debug",
						Image: "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"sleep", "300"},
						SecurityContext: &corev1.SecurityContext{
							Privileged: boolPtr(true),
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "host",
								MountPath: "/host",
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "host",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/",
							},
						},
					},
				},
				RestartPolicy: corev1.RestartPolicyNever,
			},
		}

		_, err = clientset.CoreV1().Pods("openshift-ovn-kubernetes").Create(ctx, debugPod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			_ = clientset.CoreV1().Pods("openshift-ovn-kubernetes").Delete(ctx, debugPodName, metav1.DeleteOptions{})
		}()

		// Wait for debug pod to be running
		o.Eventually(func() corev1.PodPhase {
			p, _ := clientset.CoreV1().Pods("openshift-ovn-kubernetes").Get(ctx, debugPodName, metav1.GetOptions{})
			return p.Status.Phase
		}, 60, 5).Should(o.Equal(corev1.PodRunning), "Debug pod did not reach Running state")

		// Check whereabouts config file permissions
		output, err = execInPod(ctx, clientset, config, "openshift-ovn-kubernetes", debugPodName, "debug",
			[]string{"/bin/bash", "-c", "stat -c '%a %n' /host/etc/kubernetes/cni/net.d/whereabouts.d/*.conf /host/etc/kubernetes/cni/net.d/whereabouts.d/*.kubeconfig 2>/dev/null || true"})
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to check whereabouts config permissions")

		g.By("Verifying whereabouts configs have 600 permissions")
		if strings.TrimSpace(output) != "" {
			lines = strings.Split(strings.TrimSpace(output), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				parts := strings.Fields(line)
				o.Expect(len(parts)).To(o.BeNumerically(">=", 2), "Invalid stat output: %s", line)
				perms := parts[0]
				filename := parts[1]
				o.Expect(perms).To(o.Equal("600"),
					"CIS violation: %s has insecure permissions %s (expected 600)", filename, perms)
			}
		}
	})
})

// Helper functions
func int64Ptr(i int64) *int64 {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

// execInPod executes a command in a pod and returns the output
func execInPod(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config,
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
