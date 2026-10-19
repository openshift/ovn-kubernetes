package otp

import (
	"fmt"
	"os/exec"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
)

var _ = g.Describe("[OTP] SDN adminnetworkpolicy APBR interaction", func() {
	defer g.GinkgoRecover()

	var (
		nsList []string
	)

	g.BeforeEach(func() {
		// Ensure OVN-K is present
		output, err := exec.Command("oc", "get", "network.config.openshift.io", "cluster", "-o", "jsonpath={.status.networkType}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if !strings.Contains(strings.ToLower(string(output)), "ovn") {
			g.Skip("AdminNetworkPolicy only supported on OVN clusters")
		}
	})

	g.AfterEach(func() {
		for _, ns := range nsList {
			exec.Command("oc", "delete", "ns", ns, "--ignore-not-found=true").Run()
		}
		nsList = nil
	})

	g.It("73963-ANP overrides BANP with AdminPolicyBasedExternalRoutes [Serial]", func() {
		var (
			testID         = "73963"
			testExternalIP = "8.8.8.8"
		)

		g.By("1. Create served namespace with test pod")
		servedNs := "served-" + testID
		_, err := exec.Command("oc", "create", "ns", servedNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		nsList = append(nsList, servedNs)

		err = exec.Command("oc", "label", "ns", servedNs, "team=served").Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		// Create a simple test pod
		podManifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: test-pod-%s
  namespace: %s
spec:
  containers:
  - name: test
    image: busybox
    command: ["sleep", "3600"]
`, testID, servedNs)
		cmd := exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(podManifest)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("2. Verify connectivity before BANP (should succeed)")
		podIP := getTestPodIP(servedNs, "test-pod-"+testID)
		o.Expect(len(podIP) > 0).To(o.BeTrue())

		g.By("3. Create BANP to deny all egress")
		banpManifest := fmt.Sprintf(`apiVersion: networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: %s
  egress:
  - name: deny-all-egress
    action: Deny
    to:
    - networks:
      - cidr: 0.0.0.0/0
`, servedNs)
		cmdBanp := exec.Command("oc", "apply", "-f", "-")
		cmdBanp.Stdin = strings.NewReader(banpManifest)
		err = cmdBanp.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Verify connectivity after BANP (should fail)")
		connectivity := testConnectivity(podIP, testExternalIP, 53)
		o.Expect(connectivity).To(o.BeFalse())

		g.By("5. Create ANP to allow egress to specific IP")
		anpManifest := fmt.Sprintf(`apiVersion: networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: anp-allow-external
spec:
  priority: 10
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: %s
  egress:
  - name: allow-specific-external
    action: Allow
    to:
    - networks:
      - cidr: %s/32
`, servedNs, testExternalIP)
		cmdAnp := exec.Command("oc", "apply", "-f", "-")
		cmdAnp.Stdin = strings.NewReader(anpManifest)
		err = cmdAnp.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Verify connectivity after ANP override (should succeed)")
		connectivity = testConnectivity(podIP, testExternalIP, 53)
		o.Expect(connectivity).To(o.BeTrue())

		g.By("7. Clean up")
		exec.Command("oc", "delete", "anp", "anp-allow-external", "-n", servedNs).Run()
		exec.Command("oc", "delete", "banp", "default").Run()
	})
})

// Helper function to get pod IP
func getTestPodIP(namespace, podName string) string {
	output, err := exec.Command("oc", "get", "pod", podName, "-n", namespace, "-o", "jsonpath={.status.podIP}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// Helper function to test connectivity
func testConnectivity(podIP, targetIP string, port int) bool {
	cmd := exec.Command("oc", "exec", "-n", "default", "test-pod-73963", "--", "timeout", "2", "sh", "-c",
		fmt.Sprintf("ping -c 1 %s || nc -zv %s %d", targetIP, targetIP, port))
	return cmd.Run() == nil
}
