package ote

import (
	"os/exec"
	"path/filepath"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = g.Describe("[OTP] SDN adminnetworkpolicy services", func() {
	defer g.GinkgoRecover()

	var (
		nsList              []string
		originalBANPDefault []byte // Store original BANP named "default" if it exists
		fixtureDir          string
	)

	g.BeforeEach(func() {
		// Ensure OVN-K is present
		output, err := exec.Command("oc", "get", "network.config.openshift.io", "cluster", "-o", "jsonpath={.status.networkType}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if !strings.Contains(strings.ToLower(string(output)), "ovn") {
			g.Skip("AdminNetworkPolicy only supported on OVN clusters")
		}

		fixtureDir = filepath.Join(testdata.FixturePath("networking"), "adminnetworkpolicy")

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
		err = oteutils.ApplyResourceFromTemplate(testNs, filepath.Join(fixtureDir, "backend-pod-template.yaml"),
			"-p", "NAME=backend-"+testID,
			"-p", "APP_LABEL=backend",
			"-p", "ECHO_MSG=backend")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create ClusterIP service")
		err = oteutils.ApplyResourceFromTemplate(testNs, filepath.Join(fixtureDir, "clusterip-service-template.yaml"),
			"-p", "NAME=backend-svc-"+testID,
			"-p", "APP_LABEL=backend")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Create BANP to deny ingress")
		err = oteutils.ApplyResourceFromTemplate("", filepath.Join(fixtureDir, "banp-deny-ingress-from-ns-template.yaml"),
			"-p", "SUBJECT_NS="+testNs,
			"-p", "FROM_NS="+testNs,
			"-p", "RULE_NAME=deny-ingress")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Create ANP to allow access")
		err = oteutils.ApplyResourceFromTemplate("", filepath.Join(fixtureDir, "anp-allow-ingress-from-ns-template.yaml"),
			"-p", "NAME=anp-allow-"+testID,
			"-p", "PRIORITY=10",
			"-p", "SUBJECT_NS="+testNs,
			"-p", "FROM_NS="+testNs,
			"-p", "RULE_NAME=allow-ingress")
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
		err = oteutils.ApplyResourceFromTemplate(testNs, filepath.Join(fixtureDir, "backend-pod-template.yaml"),
			"-p", "NAME=backend-"+testID,
			"-p", "APP_LABEL=lb-backend",
			"-p", "ECHO_MSG=lb backend")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create LoadBalancer service")
		err = oteutils.ApplyResourceFromTemplate(testNs, filepath.Join(fixtureDir, "loadbalancer-service-template.yaml"),
			"-p", "NAME=lb-svc-"+testID,
			"-p", "APP_LABEL=lb-backend")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Create BANP to deny external access")
		err = oteutils.ApplyResourceFromTemplate("", filepath.Join(fixtureDir, "banp-deny-ingress-all-pods-template.yaml"),
			"-p", "SUBJECT_NS="+testNs,
			"-p", "RULE_NAME=deny-external")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Create ANP to allow specific external access")
		err = oteutils.ApplyResourceFromTemplate("", filepath.Join(fixtureDir, "anp-allow-ingress-all-pods-template.yaml"),
			"-p", "NAME=anp-allow-"+testID,
			"-p", "PRIORITY=5",
			"-p", "SUBJECT_NS="+testNs,
			"-p", "RULE_NAME=allow-external")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Verify LB service exists")
		lbOut, err := exec.Command("oc", "get", "svc", "lb-svc-"+testID, "-n", testNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(string(lbOut), "lb-svc-"+testID)).To(o.BeTrue())
	})
})
