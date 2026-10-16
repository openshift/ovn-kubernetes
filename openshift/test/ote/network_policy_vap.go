package ote

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = g.Describe("[sig-network] SDN networkpolicy VAP", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-networkpolicy-vap")

	g.BeforeEach(func() {
		networkType := oteutils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote] 83735-Verify NP with label npprotection/blockdeletion=true label can not be deleted after VAP is applied.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			networkpolicyFile1  = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-egress.yaml")
			networkpolicyFile2  = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			npName1             = "default-deny-egress"
			npName2             = "default-deny-ingress"
			matchLabelKey       = "npprotection/blockdeletion"
			expectedDenyMessage = "Cannot delete NetworkPolicy with 'npprotection/blockdeletion: true' label. This policy is not allowed for deletion."
			networpolicyFiles   = []string{networkpolicyFile1, networkpolicyFile2}
			npNames             = []string{npName1, npName2}
		)
		g.By("1. Create a namespace for default network, and a UDN namespace")
		// exutil.NewCLI already provisions a project in its BeforeEach, so reuse that
		// one as the default-network namespace rather than creating another.
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		allNS := []string{ns1, ns2}

		// Per-run unique names so parallel specs don't collide on these
		// cluster-scoped VAP objects.
		vapName := "npblockdel-" + ns1
		vapBindingName := vapName + "-binding"

		g.By("2. Create a networkpolicy in each namespace and label them with npprotection-blockdeletion=true label.")
		for i, ns := range allNS {
			oteutils.CreateResourceFromFile(oc, ns, networpolicyFiles[i])
			output, err := oc.AsAdmin().Run("get").Args("-n", ns, "networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, npNames[i])).To(o.BeTrue())
			defer func() {
				_ = oc.AsAdmin().Run("label").Args("-n", ns, "networkpolicy", npNames[i], fmt.Sprintf("%s-", matchLabelKey)).Execute()
			}()
			err = oc.AsAdmin().Run("label").Args("-n", ns, "networkpolicy", npNames[i], fmt.Sprintf("%s=%s", matchLabelKey, "true")).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("3. Apply the deletion-protection VAP, scoped to the test namespaces")
		// The binding's namespaceSelector limits the policy to the two test
		// namespaces so it cannot affect NetworkPolicies elsewhere on the cluster.
		// The CEL guards that the label key exists before indexing it: without the
		// "in" check, indexing a missing key errors, and with failurePolicy=Fail +
		// Deny that would wrongly block deletion of unrelated NetworkPolicies.
		// Built with a unique name per run; all changes/reads go through AsAdmin(),
		// so no cluster-admin grant to the test user is needed.
		vapManifest := fmt.Sprintf(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: %[1]s
spec:
  matchConstraints:
    resourceRules:
      - operations: ["DELETE"]
        apiGroups: ["networking.k8s.io"]
        apiVersions: ["v1"]
        resources: ["networkpolicies"]
  validations:
    - expression: '!(has(oldObject.metadata.labels) && ("npprotection/blockdeletion" in oldObject.metadata.labels) && oldObject.metadata.labels["npprotection/blockdeletion"] == "true")'
      message: "%[5]s"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: %[2]s
spec:
  policyName: %[1]s
  validationActions: ["Deny"]
  matchResources:
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: In
          values: ["%[3]s", "%[4]s"]
`, vapName, vapBindingName, ns1, ns2, expectedDenyMessage)

		vapFile, err := os.CreateTemp("", "vap-npprotection-*.yaml")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.Remove(vapFile.Name())
		_, err = vapFile.WriteString(vapManifest)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(vapFile.Close()).NotTo(o.HaveOccurred())

		defer oteutils.RemoveResource(oc, true, true, "validatingadmissionpolicybinding", vapBindingName)
		defer oteutils.RemoveResource(oc, true, true, "validatingadmissionpolicy", vapName)
		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", vapFile.Name()).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("validatingadmissionpolicy.admissionregistration.k8s.io", vapName).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, vapName)).To(o.BeTrue())

		g.By("4. Verify the networkpolicy can not be deleted.")
		for i, ns := range allNS {
			// The VAP and its binding are enforced asynchronously, so poll with a
			// server-side dry-run delete (which never actually removes the object)
			// until admission starts denying it, rather than relying on a fixed sleep.
			o.Eventually(func() string {
				out, _ := oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", npNames[i], "-n", ns, "--dry-run=server").Output()
				return out
			}, 30*time.Second, 3*time.Second).Should(o.ContainSubstring(expectedDenyMessage), "VAP should block deletion of networkpolicy %s in namespace %s", npNames[i], ns)

			// Confirm a real delete is denied too.
			output, err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", npNames[i], "-n", ns).Output()
			o.Expect(err).To(o.HaveOccurred())
			o.Expect(strings.Contains(output, expectedDenyMessage)).To(o.BeTrue())
		}

		g.By("5. Delete the VAP and its binding, verify the networkpolicy can be deleted.")
		oteutils.RemoveResource(oc, true, true, "validatingadmissionpolicybinding", vapBindingName)
		oteutils.RemoveResource(oc, true, true, "validatingadmissionpolicy", vapName)

		for i, ns := range allNS {
			// Enforcement is lifted asynchronously after the VAP/binding objects are
			// gone, so poll with a server-side dry-run delete until admission stops
			// denying, before issuing the real delete.
			o.Eventually(func() error {
				_, dErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", npNames[i], "-n", ns, "--dry-run=server").Output()
				return dErr
			}, 30*time.Second, 3*time.Second).ShouldNot(o.HaveOccurred(), "VAP enforcement should be lifted for networkpolicy %s in namespace %s", npNames[i], ns)

			output, err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", npNames[i], "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			expectedMessage := "networkpolicy.networking.k8s.io \"" + npNames[i] + "\" deleted"
			o.Expect(strings.Contains(output, expectedMessage)).To(o.BeTrue())
		}
	})
})
