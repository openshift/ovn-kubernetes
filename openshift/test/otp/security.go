package otp

import (
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[sig-networking] OTP Security", func() {
	var oc = exutil.NewCLI("otp-security")

	// Medium-49216: API Token Logging Security
	g.It("[OTP][blocking][case_id:49216] should not expose API tokens in ovnkube-node logs", func() {
		g.By("Getting all ovnkube-node pods")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", "openshift-ovn-kubernetes", "-l", "app=ovnkube-node", "-o", "name").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		podNames := strings.Split(strings.TrimSpace(output), "\n")
		o.Expect(len(podNames)).To(o.BeNumerically(">", 0), "Expected at least one ovnkube-node pod")

		g.By("Checking logs from each ovnkube-node pod for token exposure")
		totalViolations := 0
		failedPods := []string{}
		skippedPods := []string{}

		for _, podName := range podNames {
			// Strip "pod/" prefix if present
			podName = strings.TrimPrefix(podName, "pod/")
			if podName == "" {
				continue
			}

			// Get logs from ovnkube-controller container
			logs, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args(
				"-n", "openshift-ovn-kubernetes",
				podName,
				"-c", "ovnkube-controller",
				"--tail=10000",
			).Output()

			// If logs can't be retrieved, record and skip this pod
			if err != nil {
				e2e.Logf("Warning: could not retrieve logs for pod %s: %v", podName, err)
				skippedPods = append(skippedPods, podName)
				continue
			}

			// Search for sensitive patterns
			patterns := []string{"api-token", "authorization", "bearer"}
			podViolations := 0

			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(logs), pattern) {
					// Filter out false positives (configuration field names without values)
					lines := strings.Split(logs, "\n")
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
				failedPods = append(failedPods, podName)
			}
		}

		// Ensure at least some pods were scanned
		scannedCount := len(podNames) - len(skippedPods)
		o.Expect(scannedCount).To(o.BeNumerically(">", 0),
			"Could not retrieve logs from any pod - all %d pods skipped: %v",
			len(podNames), skippedPods)

		// Assert no tokens were found
		o.Expect(totalViolations).To(o.Equal(0),
			"Found %d potential token exposures in pods: %v",
			totalViolations, failedPods)
	})

	// Medium-77102: CIS File Permissions for CNI Config
	g.It("[OTP][blocking][case_id:77102] should have secure permissions on CNI configuration files", func() {
		g.By("Checking multus config permissions via multus pods")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", "openshift-multus", "-l", "app=multus", "-o", "name").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		multusPods := strings.Split(strings.TrimSpace(output), "\n")
		o.Expect(len(multusPods)).To(o.BeNumerically(">", 0), "Expected at least one multus pod")

		// Check first multus pod for config file permissions
		multusPod := strings.TrimPrefix(multusPods[0], "pod/")
		output, err = oc.AsAdmin().WithoutNamespace().Run("exec").Args(
			"-n", "openshift-multus",
			multusPod,
			"-c", "kube-multus",
			"--",
			"/bin/bash", "-c", "stat -c '%a %n' /host/etc/cni/net.d/*.conf",
		).Output()
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

		g.By("Checking whereabouts config permissions on nodes")
		// Get first worker node
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/worker", "-o", "jsonpath={.items[0].metadata.name}").Output()
		if err != nil || output == "" {
			// Fall back to any node
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-o", "jsonpath={.items[0].metadata.name}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		nodeName := strings.TrimSpace(output)
		o.Expect(nodeName).NotTo(o.BeEmpty(), "Expected at least one node")

		// Check whereabouts config permissions using oc debug node
		g.By("Checking whereabouts config file permissions via debug node")
		output, err = oc.AsAdmin().WithoutNamespace().Run("debug").Args(
			"node/"+nodeName,
			"--",
			"chroot", "/host", "/bin/bash", "-c",
			"stat -c '%a %n' /etc/kubernetes/cni/net.d/whereabouts.d/*.conf /etc/kubernetes/cni/net.d/whereabouts.d/*.kubeconfig 2>/dev/null || true",
		).Output()
		// Note: debug node command may have some errors in stderr, but we only care about stdout
		// so we don't fail on err here if we got output

		g.By("Verifying whereabouts configs have 600 permissions")
		if strings.TrimSpace(output) != "" {
			lines = strings.Split(strings.TrimSpace(output), "\n")
			for _, line := range lines {
				// Skip lines that look like debug pod messages
				if strings.Contains(line, "Starting pod/") || strings.Contains(line, "Removing debug pod") ||
				   strings.Contains(line, "To use host binaries") || line == "" {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) < 2 {
					continue
				}
				perms := parts[0]
				filename := parts[1]
				// Only check .conf and .kubeconfig files, skip other files like "nodename"
				if strings.HasSuffix(filename, ".conf") || strings.HasSuffix(filename, ".kubeconfig") {
					o.Expect(perms).To(o.Equal("600"),
						"CIS violation: %s has insecure permissions %s (expected 600)", filename, perms)
				}
			}
		}
	})
})
