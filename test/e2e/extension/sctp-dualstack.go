package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN sctp", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-sctp", compat_otp.KubeConfigPath())

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-Medium-28757-Establish pod to pod SCTP connections. ", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking/sctp")
			sctpClientPod       = filepath.Join(buildPruningBaseDir, "sctpclient.yaml")
			sctpServerPod       = filepath.Join(buildPruningBaseDir, "sctpserver.yaml")
			sctpModule          = filepath.Join(buildPruningBaseDir, "load-sctp-module.yaml")
			sctpServerPodName   = "sctpserver"
			sctpClientPodname   = "sctpclient"
		)

		g.By("install load-sctp-module in all workers")
		prepareSCTPModule(oc, sctpModule)

		g.By("create new namespace")
		oc.SetupProject()
		defer compat_otp.RecoverNamespaceRestricted(oc, oc.Namespace())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())

		g.By("create sctpClientPod")
		createResourceFromFile(oc, oc.Namespace(), sctpClientPod)
		err1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=sctpclient")
		compat_otp.AssertWaitPollNoErr(err1, "sctpClientPod is not running")

		g.By("create sctpServerPod")
		createResourceFromFile(oc, oc.Namespace(), sctpServerPod)
		err2 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=sctpserver")
		compat_otp.AssertWaitPollNoErr(err2, "sctpServerPod is not running")

		ipStackType := checkIPStackType(oc)

		g.By("test ipv4 in ipv4 cluster or dualstack cluster")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			g.By("get ipv4 address from the sctpServerPod")
			sctpServerPodIP := getPodIPv4(oc, oc.Namespace(), sctpServerPodName)

			g.By("sctpserver pod start to wait for sctp traffic")
			_, _, _, err := oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			o.Expect(err).NotTo(o.HaveOccurred())
			time.Sleep(5 * time.Second)

			g.By("check sctp process enabled in the sctp server pod")
			msg, err := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

			g.By("sctpclient pod start to send sctp traffic")
			_, err1 := e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")
			o.Expect(err1).NotTo(o.HaveOccurred())

			g.By("server sctp process will end after get sctp traffic from sctp client")
			time.Sleep(5 * time.Second)
			msg1, err1 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err1).NotTo(o.HaveOccurred())
			o.Expect(msg1).NotTo(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"))
		}

		g.By("test ipv6 in ipv6 cluster or dualstack cluster")
		if ipStackType == "ipv6single" || ipStackType == "dualstack" {
			g.By("get ipv6 address from the sctpServerPod")
			sctpServerPodIP := getPodIPv6(oc, oc.Namespace(), sctpServerPodName, ipStackType)

			g.By("sctpserver pod start to wait for sctp traffic")
			oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			time.Sleep(5 * time.Second)

			g.By("check sctp process enabled in the sctp server pod")
			msg, err := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

			g.By("sctpclient pod start to send sctp traffic")
			e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")

			g.By("server sctp process will end after get sctp traffic from sctp client")
			time.Sleep(5 * time.Second)
			msg1, err1 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err1).NotTo(o.HaveOccurred())
			o.Expect(msg1).NotTo(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"))
		}
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-ROSA-OSD_CCS-NonHyperShiftHOST-NonPreRelease-Medium-28758-Expose SCTP ClusterIP Services. ", func() {
		var (
			buildPruningBaseDir  = testdata.FixturePath("networking/sctp")
			sctpClientPod        = filepath.Join(buildPruningBaseDir, "sctpclient.yaml")
			sctpServerPod        = filepath.Join(buildPruningBaseDir, "sctpserver.yaml")
			sctpModule           = filepath.Join(buildPruningBaseDir, "load-sctp-module.yaml")
			sctpServerPodName    = "sctpserver"
			sctpClientPodname    = "sctpclient"
			sctpServicev4        = filepath.Join(buildPruningBaseDir, "sctpservicev4.yaml")
			sctpServicev6        = filepath.Join(buildPruningBaseDir, "sctpservicev6.yaml")
			sctpServiceDualstack = filepath.Join(buildPruningBaseDir, "sctpservicedualstack.yaml")
		)

		g.By("install load-sctp-module in all workers")
		prepareSCTPModule(oc, sctpModule)

		g.By("create new namespace")
		oc.SetupProject()
		defer compat_otp.RecoverNamespaceRestricted(oc, oc.Namespace())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())

		g.By("create sctpClientPod")
		createResourceFromFile(oc, oc.Namespace(), sctpClientPod)
		err1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=sctpclient")
		compat_otp.AssertWaitPollNoErr(err1, "sctpClientPod is not running")

		g.By("create sctpServerPod")
		createResourceFromFile(oc, oc.Namespace(), sctpServerPod)
		err2 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=sctpserver")
		compat_otp.AssertWaitPollNoErr(err2, "sctpServerPod is not running")

		ipStackType := checkIPStackType(oc)

		if ipStackType == "ipv4single" {
			g.By("test ipv4 singlestack cluster")
			g.By("create sctpServiceIPv4")
			createResourceFromFile(oc, oc.Namespace(), sctpServicev4)
			output, err := oc.WithoutNamespace().Run("get").Args("service").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("sctpservice-v4"))

			g.By("get service ipv4 address")
			sctpServiceIPv4 := getSvcIPv4(oc, oc.Namespace(), "sctpservice-v4")

			g.By("sctpserver pod start to wait for sctp traffic")
			_, _, _, err1 := oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			o.Expect(err1).NotTo(o.HaveOccurred())
			time.Sleep(5 * time.Second)

			g.By("check sctp process enabled in the sctp server pod")
			msg, err2 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err2).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

			g.By("sctpclient pod start to send sctp traffic")
			_, err3 := e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServiceIPv4+" 30102 --sctp; }")
			o.Expect(err3).NotTo(o.HaveOccurred())

			g.By("server sctp process will end after get sctp traffic from sctp client")
			time.Sleep(5 * time.Second)
			msg1, err4 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err4).NotTo(o.HaveOccurred())
			o.Expect(msg1).NotTo(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"))
		}

		if ipStackType == "ipv6single" {
			g.By("test ipv6 singlestack cluster")
			g.By("create sctpServiceIPv4")
			createResourceFromFile(oc, oc.Namespace(), sctpServicev6)
			output, err := oc.WithoutNamespace().Run("get").Args("service").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("sctpservice-v6"))

			g.By("get service ipv6 address")
			sctpServiceIPv6, _ := getSvcIP(oc, oc.Namespace(), "sctpservice-v6")

			g.By("sctpserver pod start to wait for sctp traffic")
			_, _, _, err1 := oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			o.Expect(err1).NotTo(o.HaveOccurred())
			time.Sleep(5 * time.Second)

			g.By("check sctp process enabled in the sctp server pod")
			msg, err2 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err2).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

			g.By("sctpclient pod start to send sctp traffic")
			_, err3 := e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServiceIPv6+" 30102 --sctp; }")
			o.Expect(err3).NotTo(o.HaveOccurred())

			g.By("server sctp process will end after get sctp traffic from sctp client")
			time.Sleep(5 * time.Second)
			msg1, err4 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err4).NotTo(o.HaveOccurred())
			o.Expect(msg1).NotTo(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"))
		}

		if ipStackType == "dualstack" {
			g.By("test ip dualstack cluster")
			g.By("create sctpservicedualstack")
			createResourceFromFile(oc, oc.Namespace(), sctpServiceDualstack)
			output, err := oc.WithoutNamespace().Run("get").Args("service").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("sctpservice-dualstack"))

			g.By("get service ipv4 and ipv6 address")
			sctpServiceIPv4, sctpServiceIPv6 := getSvcIPdualstack(oc, oc.Namespace(), "sctpservice-dualstack")

			g.By("test ipv4 in dualstack cluster")
			g.By("sctpserver pod start to wait for sctp traffic")
			_, _, _, err1 := oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			o.Expect(err1).NotTo(o.HaveOccurred())
			time.Sleep(5 * time.Second)

			g.By("check sctp process enabled in the sctp server pod")
			msg, err2 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err2).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

			g.By("sctpclient pod start to send sctp traffic")
			_, err3 := e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServiceIPv4+" 30102 --sctp; }")
			o.Expect(err3).NotTo(o.HaveOccurred())

			g.By("server sctp process will end after get sctp traffic from sctp client")
			time.Sleep(5 * time.Second)
			msg1, err4 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err4).NotTo(o.HaveOccurred())
			o.Expect(msg1).NotTo(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"))

			g.By("test ipv6 in dualstack cluster")
			g.By("sctpserver pod start to wait for sctp traffic")
			oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			time.Sleep(5 * time.Second)

			g.By("check sctp process enabled in the sctp server pod")
			msg, err5 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err5).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

			g.By("sctpclient pod start to send sctp traffic")
			e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServiceIPv6+" 30102 --sctp; }")

			g.By("server sctp process will end after get sctp traffic from sctp client")
			time.Sleep(5 * time.Second)
			msg1, err6 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
			o.Expect(err6).NotTo(o.HaveOccurred())
			o.Expect(msg1).NotTo(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"))
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonPreRelease-NonHyperShiftHOST-PreChkUpgrade-Medium-44765-Check the sctp works well after upgrade.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking/sctp")
			sctpClientPod       = filepath.Join(buildPruningBaseDir, "sctpclient-upgrade.yaml")
			sctpServerPod       = filepath.Join(buildPruningBaseDir, "sctpserver-upgrade.yaml")
			sctpModule          = filepath.Join(buildPruningBaseDir, "load-sctp-module.yaml")
			ns                  = "44765-upgrade-ns"
		)

		g.By("Enable sctp module in all workers")
		prepareSCTPModule(oc, sctpModule)

		g.By("create new namespace")
		err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("create sctpClientPod")
		createResourceFromFile(oc, ns, sctpClientPod)
		err1 := waitForPodWithLabelReady(oc, ns, "name=sctpclient")
		compat_otp.AssertWaitPollNoErr(err1, "sctpClientPod is not running")
		sctpClientPodname := getPodName(oc, ns, "name=sctpclient")[0]

		g.By("create sctpServerPod")
		createResourceFromFile(oc, ns, sctpServerPod)
		err2 := waitForPodWithLabelReady(oc, ns, "name=sctpserver")
		compat_otp.AssertWaitPollNoErr(err2, "sctpServerPod is not running")
		sctpServerPodName := getPodName(oc, ns, "name=sctpserver")[0]

		ipStackType := checkIPStackType(oc)

		g.By("test ipv4 in ipv4 cluster or dualstack cluster")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			g.By("get ipv4 address from the sctpServerPod")
			sctpServerPodIP := getPodIPv4(oc, ns, sctpServerPodName)

			g.By("sctpserver pod start to wait for sctp traffic")
			cmdNcat, _, _, err := oc.AsAdmin().Run("exec").Args("-n", ns, sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			defer cmdNcat.Process.Kill()
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("check sctp process enabled in the sctp server pod")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(ns, sctpServerPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").Should(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "No sctp process running on sctp server pod")

			g.By("sctpclient pod start to send sctp traffic")
			_, err1 := e2eoutput.RunHostCmd(ns, sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")
			o.Expect(err1).NotTo(o.HaveOccurred())

			g.By("server sctp process will end after get sctp traffic from sctp client")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(ns, sctpServerPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").ShouldNot(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "Sctp process didn't end after get sctp traffic from sctp client")
		}

		g.By("test ipv6 in ipv6 cluster or dualstack cluster")
		if ipStackType == "ipv6single" || ipStackType == "dualstack" {
			g.By("get ipv6 address from the sctpServerPod")
			sctpServerPodIP := getPodIPv6(oc, ns, sctpServerPodName, ipStackType)

			g.By("sctpserver pod start to wait for sctp traffic")
			cmdNcat, _, _, err := oc.AsAdmin().Run("exec").Args("-n", ns, sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			defer cmdNcat.Process.Kill()
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("check sctp process enabled in the sctp server pod")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(ns, sctpServerPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").Should(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "No sctp process running on sctp server pod")

			g.By("sctpclient pod start to send sctp traffic")
			_, err1 := e2eoutput.RunHostCmd(ns, sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")
			o.Expect(err1).NotTo(o.HaveOccurred())

			g.By("server sctp process will end after get sctp traffic from sctp client")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(ns, sctpServerPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").ShouldNot(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "Sctp process didn't end after get sctp traffic from sctp client")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonPreRelease-NonHyperShiftHOST-PstChkUpgrade-Medium-44765-Check the sctp works well after upgrade. ", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking/sctp")
			sctpModule          = filepath.Join(buildPruningBaseDir, "load-sctp-module.yaml")
			ns                  = "44765-upgrade-ns"
		)

		g.By("Check if sctp upgrade namespace existed")
		//Skip if no 44765-upgrade-ns which means no prepare before upgrade or parepare failed
		nsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("namespace", ns).Execute()
		if nsErr != nil {
			g.Skip("Skip for no namespace 44765-upgrade-ns in post upgrade.")
		}

		g.By("Get sctp upgrade setup info")
		e2e.Logf("The sctp upgrade namespace is %s ", ns)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("namespace", ns, "--ignore-not-found").Execute()
		err1 := waitForPodWithLabelReady(oc, ns, "name=sctpclient")
		compat_otp.AssertWaitPollNoErr(err1, "sctpClientPod is not running")
		sctpClientPodname := getPodName(oc, ns, "name=sctpclient")[0]
		err2 := waitForPodWithLabelReady(oc, ns, "name=sctpserver")
		compat_otp.AssertWaitPollNoErr(err2, "sctpServerPod is not running")
		sctpServerPodName := getPodName(oc, ns, "name=sctpserver")[0]

		g.By("Enable sctp module on all workers")
		prepareSCTPModule(oc, sctpModule)

		ipStackType := checkIPStackType(oc)

		g.By("test ipv4 in ipv4 cluster or dualstack cluster")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			g.By("get ipv4 address from the sctpServerPod")
			sctpServerPodIP := getPodIPv4(oc, ns, sctpServerPodName)

			g.By("sctpserver pod start to wait for sctp traffic")
			cmdNcat, _, _, err := oc.AsAdmin().Run("exec").Args("-n", ns, sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			defer cmdNcat.Process.Kill()
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("check sctp process enabled in the sctp server pod")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(ns, sctpServerPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").Should(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "No sctp process running on sctp server pod")

			g.By("sctpclient pod start to send sctp traffic")
			_, err1 := e2eoutput.RunHostCmd(ns, sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")
			o.Expect(err1).NotTo(o.HaveOccurred())

			g.By("server sctp process will end after get sctp traffic from sctp client")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(ns, sctpServerPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").ShouldNot(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "Sctp process didn't end after get sctp traffic from sctp client")
		}

		g.By("test ipv6 in ipv6 cluster or dualstack cluster")
		if ipStackType == "ipv6single" || ipStackType == "dualstack" {
			g.By("get ipv6 address from the sctpServerPod")
			sctpServerPodIP := getPodIPv6(oc, ns, sctpServerPodName, ipStackType)

			g.By("sctpserver pod start to wait for sctp traffic")
			cmdNcat, _, _, err := oc.AsAdmin().Run("exec").Args("-n", ns, sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
			defer cmdNcat.Process.Kill()
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("check sctp process enabled in the sctp server pod")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(ns, sctpServerPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").Should(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "No sctp process running on sctp server pod")

			g.By("sctpclient pod start to send sctp traffic")
			_, err1 := e2eoutput.RunHostCmd(ns, sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")
			o.Expect(err1).NotTo(o.HaveOccurred())

			g.By("server sctp process will end after get sctp traffic from sctp client")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(ns, sctpServerPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").ShouldNot(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "Sctp process didn't end after get sctp traffic from sctp client")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-ROSA-OSD_CCS-NonHyperShiftHOST-NonPreRelease-Medium-28759-Expose SCTP NodePort Services. [Disruptive]", func() {
		var (
			buildPruningBaseDir  = testdata.FixturePath("networking/sctp")
			sctpClientPod        = filepath.Join(buildPruningBaseDir, "sctpclient.yaml")
			sctpServerPod        = filepath.Join(buildPruningBaseDir, "sctpserver.yaml")
			sctpModule           = filepath.Join(buildPruningBaseDir, "load-sctp-module.yaml")
			sctpServerPodName    = "sctpserver"
			sctpClientPodname    = "sctpclient"
			sctpServicev4        = filepath.Join(buildPruningBaseDir, "sctpservicev4.yaml")
			sctpServicev6        = filepath.Join(buildPruningBaseDir, "sctpservicev6.yaml")
			sctpServiceDualstack = filepath.Join(buildPruningBaseDir, "sctpservicedualstack.yaml")
		)

		compat_otp.By("install load-sctp-module in all workers")
		prepareSCTPModule(oc, sctpModule)

		compat_otp.By("create new namespace")
		oc.SetupProject()
		ns := oc.Namespace()
		defer compat_otp.RecoverNamespaceRestricted(oc, ns)
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("create sctpClientPod")
		createResourceFromFile(oc, ns, sctpClientPod)
		err1 := waitForPodWithLabelReady(oc, ns, "name=sctpclient")
		compat_otp.AssertWaitPollNoErr(err1, "sctpClientPod is not running")

		compat_otp.By("create sctpServerPod")
		createResourceFromFile(oc, ns, sctpServerPod)
		err2 := waitForPodWithLabelReady(oc, ns, "name=sctpserver")
		compat_otp.AssertWaitPollNoErr(err2, "sctpServerPod is not running")

		compat_otp.By("Get sctpServerPod node ")
		nodeName, err3 := compat_otp.GetPodNodeName(oc, ns, "sctpserver")
		compat_otp.AssertWaitPollNoErr(err3, "Cannot get sctpSeverpod node name")

		ipStackType := checkIPStackType(oc)
		var sctpService string
		var expectedSctpService string
		switch ipStackType {
		case "ipv4single":
			sctpService = sctpServicev4
			expectedSctpService = "sctpservice-v4"
		case "ipv6single":
			sctpService = sctpServicev6
			expectedSctpService = "sctpservice-v6"
		case "dualstack":
			sctpService = sctpServiceDualstack
			expectedSctpService = "sctpservice-dualstack"
		}

		compat_otp.By("create sctp service")
		createResourceFromFile(oc, oc.Namespace(), sctpService)
		output, err := oc.WithoutNamespace().Run("get").Args("service").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(expectedSctpService))

		compat_otp.By("get node port and node ip")
		sctpNodePort := getLoadBalancerSvcNodePort(oc, oc.Namespace(), expectedSctpService)
		nodeIP1, nodeIP2 := getNodeIP(oc, nodeName)

		compat_otp.By("Verify sctp nodeport service can be accessed")
		checkSCTPResultPASS(oc, ns, sctpServerPodName, sctpClientPodname, nodeIP2, sctpNodePort)

		if ipStackType == "dualstack" {
			compat_otp.By("Verify sctp nodeport service can be accessed on IPv6")
			checkSCTPResultPASS(oc, ns, sctpServerPodName, sctpClientPodname, nodeIP1, sctpNodePort)
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-NonPreRelease-ConnectedOnly-Medium-29645-Networkpolicy allow SCTP Client. ", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			sctpClientPod       = filepath.Join(buildPruningBaseDir, "sctp/sctpclient.yaml")
			sctpServerPod       = filepath.Join(buildPruningBaseDir, "sctp/sctpserver.yaml")
			sctpModule          = filepath.Join(buildPruningBaseDir, "sctp/load-sctp-module.yaml")
			defaultDenyPolicy   = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			allowSCTPPolicy     = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-sctpclient.yaml")
			sctpServerPodName   = "sctpserver"
			sctpClientPodname   = "sctpclient"
		)
		compat_otp.By("Preparing the nodes for SCTP")
		prepareSCTPModule(oc, sctpModule)

		compat_otp.By("Setting privileges on the namespace")
		ns := oc.Namespace()
		defer compat_otp.RecoverNamespaceRestricted(oc, ns)
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("create sctpClientPod")
		createResourceFromFile(oc, ns, sctpClientPod)
		err1 := waitForPodWithLabelReady(oc, ns, "name=sctpclient")
		compat_otp.AssertWaitPollNoErr(err1, "sctpClientPod is not running")

		compat_otp.By("create sctpServerPod")
		createResourceFromFile(oc, ns, sctpServerPod)
		err2 := waitForPodWithLabelReady(oc, ns, "name=sctpserver")
		compat_otp.AssertWaitPollNoErr(err2, "sctpServerPod is not running")

		ipStackType := checkIPStackType(oc)
		compat_otp.By("Verify sctp server pod can be accessed")
		var sctpServerIPv6, sctpServerIPv4, sctpServerIP string
		if ipStackType == "dualstack" {
			sctpServerIPv6, sctpServerIPv4 = getPodIP(oc, ns, sctpServerPodName)
			verifySctpConnPod2IP(oc, ns, sctpServerIPv4, sctpServerPodName, sctpClientPodname, true)
			verifySctpConnPod2IP(oc, ns, sctpServerIPv6, sctpServerPodName, sctpClientPodname, true)
		} else {
			sctpServerIP, _ = getPodIP(oc, ns, sctpServerPodName)
			verifySctpConnPod2IP(oc, ns, sctpServerIP, sctpServerPodName, sctpClientPodname, true)
		}

		compat_otp.By("create default deny ingress type networkpolicy")
		createResourceFromFile(oc, ns, defaultDenyPolicy)
		output, err := oc.Run("get").Args("networkpolicy", "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-ingress"))

		compat_otp.By("Verify sctp server pod was blocked")
		if ipStackType == "dualstack" {
			verifySctpConnPod2IP(oc, ns, sctpServerIPv4, sctpServerPodName, sctpClientPodname, false)
			verifySctpConnPod2IP(oc, ns, sctpServerIPv6, sctpServerPodName, sctpClientPodname, false)
		} else {
			verifySctpConnPod2IP(oc, ns, sctpServerIP, sctpServerPodName, sctpClientPodname, false)
		}

		compat_otp.By("Create allow deny sctp client networkpolicy")
		createResourceFromFile(oc, ns, allowSCTPPolicy)
		output, err = oc.Run("get").Args("networkpolicy", "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allowsctpclient"))

		compat_otp.By("Verify sctp server pod can be accessed again")
		if ipStackType == "dualstack" {
			verifySctpConnPod2IP(oc, ns, sctpServerIPv4, sctpServerPodName, sctpClientPodname, true)
			verifySctpConnPod2IP(oc, ns, sctpServerIPv6, sctpServerPodName, sctpClientPodname, true)
		} else {
			verifySctpConnPod2IP(oc, ns, sctpServerIP, sctpServerPodName, sctpClientPodname, true)
		}

	})
})
