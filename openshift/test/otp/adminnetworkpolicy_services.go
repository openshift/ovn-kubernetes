package otp

import (
	"fmt"
	"os/exec"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
)

var _ = g.Describe("[OTP] SDN adminnetworkpolicy services", func() {
	defer g.GinkgoRecover()

	var (
		nsList              []string
		originalBANPDefault []byte // Store original BANP named "default" if it exists
	)

	g.BeforeEach(func() {
		// Ensure OVN-K is present
		output, err := exec.Command("oc", "get", "network.config.openshift.io", "cluster", "-o", "jsonpath={.status.networkType}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if !strings.Contains(strings.ToLower(string(output)), "ovn") {
			g.Skip("AdminNetworkPolicy only supported on OVN clusters")
		}
		
		// Save existing BANP named "default" if it exists
		originalBANPDefault, _ = exec.Command("oc", "get", "baselineadminnetworkpolicy", "default", "-o", "yaml").Output()
	})

	g.AfterEach(func() {
		// Delete test-created ANPs and BANPs
		_ = exec.Command("oc", "delete", "anp", "--all", "--ignore-not-found=true").Run()

		// Restore or delete BANP named "default"
		if len(originalBANPDefault) > 0 {
			// Restore the original BANP
			cmd := exec.Command("oc", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(string(originalBANPDefault))
			_ = cmd.Run()
		} else {
			// No original BANP existed, delete the test one
			_ = exec.Command("oc", "delete", "banp", "default", "--ignore-not-found=true").Run()
		}

		// Delete test namespaces
		for _, ns := range nsList {
			_ = exec.Command("oc", "delete", "ns", ns, "--ignore-not-found=true").Run()
		}
		nsList = nil
		originalBANPDefault = nil
	})

	g.It("73440-ANP/BANP with ClusterIP and NodePort Services [Serial]", func() {
		testID := "73440"
		testNs := "service-test-" + testID
		
		g.By("1. Create test namespace")
		_, err := exec.Command("oc", "create", "ns", testNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		nsList = append(nsList, testNs)

		g.By("2. Create backend pod")
		backendPod := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: backend-%s
  namespace: %s
  labels:
    app: backend
spec:
  containers:
  - name: server
    image: busybox
    args: ["sh", "-c", "echo 'backend' && sleep 3600"]
`, testID, testNs)
		cmd := exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(backendPod)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create ClusterIP service")
		svc := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: backend-svc-%s
  namespace: %s
spec:
  type: ClusterIP
  selector:
    app: backend
  ports:
  - port: 80
    targetPort: 8080
`, testID, testNs)
		cmd = exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(svc)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Create BANP to deny ingress")
		banp := fmt.Sprintf(`apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: %s
  ingress:
  - name: deny-ingress
    action: Deny
    from:
    - pods:
        namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: %s
        podSelector: {}
`, testNs, testNs)
		cmd = exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(banp)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Create ANP to allow access")
		anp := fmt.Sprintf(`apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: anp-allow-%s
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
        namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: %s
        podSelector: {}
`, testID, testNs, testNs)
		cmd = exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(anp)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Verify service exists")
		svcOut, err := exec.Command("oc", "get", "svc", "backend-svc-"+testID, "-n", testNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(string(svcOut), "backend-svc-"+testID)).To(o.BeTrue())
	})

	g.It("82081-ANP/BANP with LoadBalancer Services [Serial]", func() {
		testID := "82081"
		testNs := "lb-test-" + testID

		g.By("1. Create test namespace")
		_, err := exec.Command("oc", "create", "ns", testNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		nsList = append(nsList, testNs)

		g.By("2. Create backend pod")
		backendPod := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: backend-%s
  namespace: %s
  labels:
    app: lb-backend
spec:
  containers:
  - name: server
    image: busybox
    args: ["sh", "-c", "echo 'lb backend' && sleep 3600"]
`, testID, testNs)
		cmd := exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(backendPod)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create LoadBalancer service")
		lb := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: lb-svc-%s
  namespace: %s
spec:
  type: LoadBalancer
  selector:
    app: lb-backend
  ports:
  - port: 80
    targetPort: 8080
`, testID, testNs)
		cmd = exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(lb)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Create BANP to deny external access")
		banp := fmt.Sprintf(`apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: %s
  ingress:
  - name: deny-external
    action: Deny
    from:
    - pods:
        namespaceSelector: {}
        podSelector: {}
`, testNs)
		cmd = exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(banp)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Create ANP to allow specific external access")
		anp := fmt.Sprintf(`apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: anp-allow-%s
spec:
  priority: 5
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: %s
  ingress:
  - name: allow-external
    action: Allow
    from:
    - pods:
        namespaceSelector: {}
        podSelector: {}
`, testID, testNs)
		cmd = exec.Command("oc", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(anp)
		err = cmd.Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Verify LB service exists")
		lbOut, err := exec.Command("oc", "get", "svc", "lb-svc-"+testID, "-n", testNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(string(lbOut), "lb-svc-"+testID)).To(o.BeTrue())
	})
})
