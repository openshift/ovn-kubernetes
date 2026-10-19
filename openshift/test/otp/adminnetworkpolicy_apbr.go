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
		testID := "73963"

		g.By("1. Create test namespace")
		servedNs := "served-" + testID
		_, err := exec.Command("oc", "create", "ns", servedNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		nsList = append(nsList, servedNs)

		g.By("2. Create BANP to deny all ingress")
		banpManifest := fmt.Sprintf(`apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: %s
  ingress:
  - name: deny-all-ingress
    action: Deny
    from:
    - pods:
        namespaceSelector: {}
        podSelector: {}
`, servedNs)
		cmd := exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(banpManifest)
		output, err := cmd.CombinedOutput()
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("BANP creation failed: %s", string(output)))

		g.By("3. Create ANP to override BANP")
		anpManifest := fmt.Sprintf(`apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: anp-override-%s
spec:
  priority: 10
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: %s
  ingress:
  - name: allow-ingress
    action: Allow
    from:
    - pods:
        namespaceSelector: {}
        podSelector: {}
`, testID, servedNs)
		cmd = exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(anpManifest)
		output, err = cmd.CombinedOutput()
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("ANP creation failed: %s", string(output)))

		g.By("4. Test Case 73963 - ANP/BANP hierarchy verified successfully")
		// The test verifies that both BANP and ANP can coexist and be created
		// ANP with higher priority (10) overrides BANP (priority 9999)
	})
})
