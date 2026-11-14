package ote

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote] NetworkPolicy VAP deletion protection test", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			protectedNPFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/np-blockdeletion.yaml")
			protectedNPName     = "protected-np"
			denyMessage         = "Cannot delete NetworkPolicy with 'npprotection/blockdeletion: true' label. This policy is not allowed for deletion."
		)

		oc.SetupProject()
		ns := oc.Namespace()

		// Per-run unique names so parallel specs never collide on these
		// cluster-scoped VAP objects.
		vapName := "npblockdel-" + ns
		vapBindingName := vapName + "-binding"

		g.By("Create a NetworkPolicy labeled for deletion protection")
		oteutils.CreateResourceFromFile(oc, ns, protectedNPFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(protectedNPName))

		g.By("Create the ValidatingAdmissionPolicy that blocks deletion of protected NetworkPolicies")
		// The binding's namespaceSelector limits the policy to this test's namespace
		// so it cannot affect NetworkPolicies in other (parallel) specs. The CEL
		// guards that the label key exists before indexing it: without the "in"
		// check, indexing a missing key errors, and with the default failurePolicy
		// of Fail plus a Deny action that would wrongly block deletion of unrelated
		// NetworkPolicies.
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
      message: "%[3]s"
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
          values: ["%[4]s"]
`, vapName, vapBindingName, denyMessage, ns)

		vapFile, err := os.CreateTemp("", "vap-npprotection-*.yaml")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() { _ = os.Remove(vapFile.Name()) }()
		_, err = vapFile.WriteString(vapManifest)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(vapFile.Close()).NotTo(o.HaveOccurred())

		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", vapFile.Name()).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		// The VAP is cluster-scoped; remove it before the namespace is torn down so
		// namespace cleanup (which deletes the protected NetworkPolicy) is not blocked.
		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", vapFile.Name(), "--ignore-not-found").Execute()
		}()

		g.By("Deleting the protected NetworkPolicy should be denied by the VAP")
		// VAP enforcement becomes active asynchronously after the binding is created,
		// so poll with a server-side dry-run delete (which runs admission but never
		// actually removes the object) until admission starts denying it. A real
		// delete here would succeed on the first poll before enforcement is active,
		// deleting the fixture and making every later poll fail with NotFound.
		o.Eventually(func() string {
			out, delErr := oc.AsAdmin().Run("delete").Args("networkpolicy", protectedNPName, "-n", ns, "--dry-run=server").Output()
			if delErr != nil {
				return delErr.Error()
			}
			return out
		}, "60s", "5s").Should(o.ContainSubstring("not allowed for deletion"), "deletion of the protected NetworkPolicy should be denied by the VAP")

		g.By("Removing the VAP should allow the NetworkPolicy to be deleted again")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", vapFile.Name(), "--ignore-not-found").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		// Enforcement is lifted asynchronously after the VAP/binding are gone, so poll
		// with a server-side dry-run delete until admission stops denying, then issue
		// the real delete.
		o.Eventually(func() error {
			_, dErr := oc.AsAdmin().Run("delete").Args("networkpolicy", protectedNPName, "-n", ns, "--dry-run=server").Output()
			return dErr
		}, "60s", "5s").ShouldNot(o.HaveOccurred(), "deletion should be allowed once the VAP is removed")
		o.Expect(oc.AsAdmin().Run("delete").Args("networkpolicy", protectedNPName, "-n", ns).Execute()).NotTo(o.HaveOccurred())
	})
})
