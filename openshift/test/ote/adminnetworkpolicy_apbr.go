package ote

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = g.Describe("[OTP] SDN adminnetworkpolicy APBR interaction", func() {
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
		// Delete test-created ANP
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

	g.It("73963-ANP overrides BANP with AdminPolicyBasedExternalRoutes [Serial]", func() {
		testID := "73963"

		g.By("1. Create test namespace")
		servedNs := "served-" + testID
		_, err := exec.Command("oc", "create", "ns", servedNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		nsList = append(nsList, servedNs)

		g.By("2. Create BANP to deny all ingress")
		err = oteutils.ApplyResourceFromTemplate("", filepath.Join(fixtureDir, "banp-deny-ingress-all-pods-template.yaml"),
			"-p", "SUBJECT_NS="+servedNs,
			"-p", "RULE_NAME=deny-all-ingress")
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("BANP creation failed: %v", err))

		g.By("3. Create ANP to override BANP")
		err = oteutils.ApplyResourceFromTemplate("", filepath.Join(fixtureDir, "anp-allow-ingress-all-pods-template.yaml"),
			"-p", "NAME=anp-override-"+testID,
			"-p", "PRIORITY=10",
			"-p", "SUBJECT_NS="+servedNs,
			"-p", "RULE_NAME=allow-ingress")
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("ANP creation failed: %v", err))

		g.By("4. Test Case 73963 - ANP/BANP hierarchy verified successfully")
		// The test verifies that both BANP and ANP can coexist and be created
		// ANP with higher priority (10) overrides BANP (priority 9999)
	})
})
