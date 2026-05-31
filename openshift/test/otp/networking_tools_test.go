package otp

import (
	"context"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var _ = g.Describe("[sig-networking] OTP Networking Tools", func() {
	defer g.GinkgoRecover()

	var (
		clientset *kubernetes.Clientset
		ctx       context.Context
	)

	g.BeforeEach(func() {
		ctx = context.Background()

		// Load kubeconfig
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

		config, err := kubeConfig.ClientConfig()
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

		for _, pod := range pods.Items {
			// Get logs from ovnkube-controller container
			logOptions := &corev1.PodLogOptions{
				Container: "ovnkube-controller",
				TailLines: int64Ptr(10000),
			}

			req := clientset.CoreV1().Pods("openshift-ovn-kubernetes").GetLogs(pod.Name, logOptions)
			logs, err := req.DoRaw(ctx)

			// If logs can't be retrieved, skip this pod
			if err != nil {
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
								if strings.Contains(lowerLine, "ey") || // JWT tokens start with "ey"
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

		// Assert no tokens were found
		o.Expect(totalViolations).To(o.Equal(0),
			"Found %d potential token exposures in pods: %v",
			totalViolations, failedPods)
	})
})

// Helper function
func int64Ptr(i int64) *int64 {
	return &i
}
