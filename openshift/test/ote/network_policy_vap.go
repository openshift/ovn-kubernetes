package ote

import (
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
			vapFile             = filepath.Join(buildPruningBaseDir, "networkpolicy/vap-npprotection-blockdeletion.yaml")
			protectedNPFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/np-blockdeletion.yaml")
			protectedNPName     = "protected-np"
		)

		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create a NetworkPolicy labeled for deletion protection")
		oteutils.CreateResourceFromFile(oc, ns, protectedNPFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(protectedNPName))

		g.By("Create the ValidatingAdmissionPolicy that blocks deletion of protected NetworkPolicies")
		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", vapFile).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		// The VAP is cluster-scoped; remove it before the namespace is torn down so
		// namespace cleanup (which deletes the protected NetworkPolicy) is not blocked.
		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", vapFile, "--ignore-not-found").Execute()
		}()

		g.By("Deleting the protected NetworkPolicy should be denied by the VAP")
		// VAP enforcement can take a moment to become active after creation.
		o.Eventually(func() string {
			_, delErr := oc.AsAdmin().Run("delete").Args("networkpolicy", protectedNPName, "-n", ns).Output()
			if delErr != nil {
				return delErr.Error()
			}
			return ""
		}, "60s", "5s").Should(o.ContainSubstring("not allowed for deletion"), "deletion of the protected NetworkPolicy should be denied by the VAP")

		g.By("Removing the VAP should allow the NetworkPolicy to be deleted again")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", vapFile, "--ignore-not-found").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Eventually(func() error {
			return oc.AsAdmin().Run("delete").Args("networkpolicy", protectedNPName, "-n", ns).Execute()
		}, "60s", "5s").ShouldNot(o.HaveOccurred(), "deletion should succeed once the VAP is removed")
	})
})
