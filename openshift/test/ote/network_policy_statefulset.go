package ote

import (
	"path/filepath"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = g.Describe("[sig-network] SDN networkpolicy statefulset", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-networkpolicy-statefulset")

	g.BeforeEach(func() {
		networkType := oteutils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote] NetworkPolicy egress with statefulset test", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			statefulsetFile     = filepath.Join(buildPruningBaseDir, "statefulset-hello.yaml")
			egressFile          = filepath.Join(buildPruningBaseDir, "networkpolicy/egress-allow-all.yaml")
		)

		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create a statefulset")
		oteutils.CreateResourceFromFile(oc, ns, statefulsetFile)
		err := oteutils.WaitForPodWithLabelReady(oc, ns, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "statefulset pod with label name=test-pods not ready")

		g.By("Create egress networkpolicy")
		oteutils.CreateResourceFromFile(oc, ns, egressFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-egress"))

		g.By("Verify the statefulset pod can still resolve DNS (egress) after applying the egress networkpolicy")
		statefulsetPods := oteutils.GetPodName(oc, ns, "name=test-pods")
		o.Expect(statefulsetPods).NotTo(o.BeEmpty(), "expected at least one statefulset pod")
		digOutput, err := e2eoutput.RunHostCmd(ns, statefulsetPods[0], "dig +search kubernetes.default")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("status: NOERROR"), "DNS query for kubernetes.default should resolve successfully (NOERROR) from the statefulset pod")
		o.Expect(digOutput).Should(o.ContainSubstring("ANSWER SECTION"), "DNS query for kubernetes.default should return an address record")
	})
})
