package ote

import (
	"net"
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

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs] 49186-Networkpolicy egress rule should work for statefulset pods.", func() {
		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			testPodFile          = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			helloStatefulsetFile = filepath.Join(buildPruningBaseDir, "statefulset-hello.yaml")
			egressTypeFile       = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-egress-red.yaml")
		)
		g.By("1. Create first namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("2. Create a statefulset pod in first namespace.")
		oteutils.CreateResourceFromFile(oc, ns1, helloStatefulsetFile)
		err := oteutils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label app=hello not ready")
		helloPodName := oteutils.GetPodName(oc, ns1, "app=hello")

		g.By("3. Create networkpolicy with egress rule in first namespace.")
		oteutils.CreateResourceFromFile(oc, ns1, egressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-egress-to-red"))

		g.By("4. Create second namespace.")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("5. Create test pods in second namespace.")
		oteutils.CreateResourceFromFile(oc, ns2, testPodFile)
		err = oteutils.WaitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")

		g.By("6. Add label to first test pod in second namespace.")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "team=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		testPodName := oteutils.GetPodName(oc, ns2, "name=test-pods")
		err = oteutils.LabelPod(oc, ns2, testPodName[0], "type=red")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Get IPs of the test pods in second namespace.")
		allowedPodIPs := oteutils.GetPodIPs(oc, ns2, testPodName[0])
		blockedPodIPs := oteutils.GetPodIPs(oc, ns2, testPodName[1])

		// checkNPWorks asserts the egress policy for every pod IP family (both on a
		// dual-stack cluster): traffic to the allowed type=red peer succeeds and
		// traffic to the other peer is blocked.
		checkNPWorks := func() {
			for _, ip := range allowedPodIPs {
				output, err = e2eoutput.RunHostCmd(ns1, helloPodName[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(ip, "8080"))
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(output).Should(o.ContainSubstring("Hello OpenShift"))
			}
			for _, ip := range blockedPodIPs {
				_, err = e2eoutput.RunHostCmd(ns1, helloPodName[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(ip, "8080"))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))
			}
		}

		g.By("7. Check networkpolicy works.")
		checkNPWorks()

		g.By("8. Delete statefulset pod for a couple of times.")
		for i := 0; i < 5; i++ {
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", helloPodName[0], "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err := oteutils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
			o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label app=hello not ready")
		}

		g.By("9. Again checking networkpolicy works.")
		checkNPWorks()
	})
})
