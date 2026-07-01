package otp

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"

	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/utils"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[sig-network] SDN networkpolicy", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-networkpolicy")

	g.BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 49076-service domain can be resolved when egress type is enabled", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			helloSdnFile        = filepath.Join(buildPruningBaseDir, "hellosdn.yaml")
			egressTypeFile      = filepath.Join(buildPruningBaseDir, "networkpolicy/egress-allow-all.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/ingress-allow-all.yaml")
		)
		g.By("create new namespace")
		oc.SetupProject()

		g.By("create test pods")
		otputils.CreateResourceFromFile(oc, oc.Namespace(), testPodFile)
		otputils.CreateResourceFromFile(oc, oc.Namespace(), helloSdnFile)
		err := otputils.WaitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		err = otputils.WaitForPodWithLabelReady(oc, oc.Namespace(), "name=hellosdn")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=hellosdn not ready")

		g.By("create egress and ingress type networkpolicy")
		otputils.CreateResourceFromFile(oc, oc.Namespace(), egressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-egress"))
		otputils.CreateResourceFromFile(oc, oc.Namespace(), ingressTypeFile)
		output, err = oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-ingress"))

		g.By("check hellosdn pods can reolsve the dns after apply the networkplicy")
		helloSdnName := otputils.GetPodName(oc, oc.Namespace(), "name=hellosdn")
		digOutput, err := e2eoutput.RunHostCmd(oc.Namespace(), helloSdnName[0], "dig kubernetes.default")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("connection timed out"))

		g.By("check test-pods can reolsve the dns after apply the networkplicy")
		testPodName := otputils.GetPodName(oc, oc.Namespace(), "name=test-pods")
		digOutput, err = e2eoutput.RunHostCmd(oc.Namespace(), testPodName[0], "dig kubernetes.default")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("connection timed out"))

	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 49186-Networkpolicy egress rule should work for statefulset pods.", func() {
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
		otputils.CreateResourceFromFile(oc, ns1, helloStatefulsetFile)
		err := otputils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label app=hello not ready")
		helloPodName := otputils.GetPodName(oc, ns1, "app=hello")

		g.By("3. Create networkpolicy with egress rule in first namespace.")
		otputils.CreateResourceFromFile(oc, ns1, egressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-egress-to-red"))

		g.By("4. Create second namespace.")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("5. Create test pods in second namespace.")
		otputils.CreateResourceFromFile(oc, ns2, testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")

		g.By("6. Add label to first test pod in second namespace.")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "team=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		testPodName := otputils.GetPodName(oc, ns2, "name=test-pods")
		err = otputils.LabelPod(oc, ns2, testPodName[0], "type=red")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Get IP of the test pods in second namespace.")
		testPodIP1 := otputils.GetPodIPv4(oc, ns2, testPodName[0])
		testPodIP2 := otputils.GetPodIPv4(oc, ns2, testPodName[1])

		g.By("7. Check networkpolicy works.")
		output, err = e2eoutput.RunHostCmd(ns1, helloPodName[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(testPodIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("Hello OpenShift"))
		_, err = e2eoutput.RunHostCmd(ns1, helloPodName[0], "curl --connect-timeout 5  -s "+net.JoinHostPort(testPodIP2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))

		g.By("8. Delete statefulset pod for a couple of times.")
		for i := 0; i < 5; i++ {
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", helloPodName[0], "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err := otputils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
			o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label app=hello not ready")
		}

		g.By("9. Again checking networkpolicy works.")
		output, err = e2eoutput.RunHostCmd(ns1, helloPodName[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(testPodIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("Hello OpenShift"))
		_, err = e2eoutput.RunHostCmd(ns1, helloPodName[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(testPodIP2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))

	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 49437-Ingress network policy shouldn't be overruled by egress network policy on another pod", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressTypeFile      = filepath.Join(buildPruningBaseDir, "networkpolicy/default-allow-egress.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)
		g.By("Create first namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("create a hello pod in first namespace")
		podns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		podns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, podns1.Namespace, podns1.Name)

		g.By("create default allow egress type networkpolicy in first namespace")
		otputils.CreateResourceFromFile(oc, ns1, egressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-allow-egress"))

		g.By("Create Second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()
		g.By("create a hello-pod on 2nd namesapce on same node as first namespace")
		pod1Ns2 := otputils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns2,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1Ns2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1Ns2.Namespace, pod1Ns2.Name)

		g.By("create another hello-pod on 2nd namesapce but on different node")
		pod2Ns2 := otputils.PingPodResourceNode{
			Name:      "hello-pod-other-node",
			Namespace: ns2,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod2Ns2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2Ns2.Namespace, pod2Ns2.Name)

		helloPodNameNs2 := otputils.GetPodName(oc, ns2, "name=hello-pod")

		g.By("create default deny ingress type networkpolicy in 2nd namespace")
		otputils.CreateResourceFromFile(oc, ns2, ingressTypeFile)
		output, err = oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-ingress"))

		g.By("3. Get IP of the test pods in second namespace.")
		hellopodIP1Ns2 := otputils.GetPodIPv4(oc, ns2, helloPodNameNs2[0])
		hellopodIP2Ns2 := otputils.GetPodIPv4(oc, ns2, helloPodNameNs2[1])

		g.By("4. Curl both ns2 pods from ns1.")
		_, err = e2eoutput.RunHostCmd(ns1, podns1.Name, "curl --connect-timeout 5  -s "+net.JoinHostPort(hellopodIP1Ns2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))
		_, err = e2eoutput.RunHostCmd(ns1, podns1.Name, "curl --connect-timeout 5  -s "+net.JoinHostPort(hellopodIP2Ns2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))
	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 49686-network policy with ingress rule with ipBlock", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking")
			ipBlockIngressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-dual-CIDRs-template.yaml")
			ipBlockIngressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-single-CIDR-template.yaml")
			pingPodNodeTemplate          = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("Create first namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("create 1st hello pod in ns1")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod2ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)

		g.By("create 3rd hello pod in ns1")
		pod3ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod3",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod3ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod3ns1.Namespace, pod3ns1.Name)

		helloPod1ns1IPv6, helloPod1ns1IPv4 := otputils.GetPodIP(oc, ns1, pod1ns1.Name)
		helloPod1ns1IPv4WithCidr := helloPod1ns1IPv4 + "/32"
		helloPod1ns1IPv6WithCidr := helloPod1ns1IPv6 + "/128"

		if ipStackType == "dualstack" {
			g.By("create ipBlock Ingress Dual CIDRs Policy in ns1")
			npIPBlockNS1 := otputils.IpBlockCIDRsDual{
				Name:      "ipblock-dual-cidrs-ingress",
				Template:  ipBlockIngressTemplateDual,
				CidrIpv4:  helloPod1ns1IPv4WithCidr,
				CidrIpv6:  helloPod1ns1IPv6WithCidr,
				Namespace: ns1,
			}
			npIPBlockNS1.CreateipBlockCIDRObjectDual(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-dual-cidrs-ingress"))
		} else {
			// For singlestack getPodIP returns second parameter empty therefore use helloPod1ns1IPv6 variable but append it
			// with CIDR based on stack.
			var helloPod1ns1IPWithCidr string
			if ipStackType == "ipv6single" {
				helloPod1ns1IPWithCidr = helloPod1ns1IPv6WithCidr
			} else {
				helloPod1ns1IPWithCidr = helloPod1ns1IPv6 + "/32"
			}

			npIPBlockNS1 := otputils.IpBlockCIDRsSingle{
				Name:      "ipblock-single-cidr-ingress",
				Template:  ipBlockIngressTemplateSingle,
				Cidr:      helloPod1ns1IPWithCidr,
				Namespace: ns1,
			}
			npIPBlockNS1.CreateipBlockCIDRObjectSingle(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-ingress"))
		}
		g.By("Checking connectivity from pod1 to pod3")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod1", ns1, "hello-pod3")

		g.By("Checking connectivity from pod2 to pod3")
		otputils.CurlPod2PodFail(oc, ns1, "hello-pod2", ns1, "hello-pod3")

		g.By("Create 2nd namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("create 1st hello pod in ns2")
		pod1ns2 := otputils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns2,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1ns2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns2.Namespace, pod1ns2.Name)

		g.By("create 2nd hello pod in ns2")
		pod2ns2 := otputils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns2,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod2ns2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns2.Namespace, pod2ns2.Name)

		g.By("Checking connectivity from pod1ns2 to pod3ns1")
		otputils.CurlPod2PodFail(oc, ns2, "hello-pod1", ns1, "hello-pod3")

		g.By("Checking connectivity from pod2ns2 to pod1ns1")
		otputils.CurlPod2PodFail(oc, ns2, "hello-pod2", ns1, "hello-pod1")

		if ipStackType == "dualstack" {
			g.By("Delete networkpolicy from ns1")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-dual-cidrs-ingress", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			g.By("Delete networkpolicy from ns1")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-single-cidr-ingress", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		helloPod2ns2IPv6, helloPod2ns2IPv4 := otputils.GetPodIP(oc, ns2, pod2ns2.Name)
		helloPod2ns2IPv4WithCidr := helloPod2ns2IPv4 + "/32"
		helloPod2ns2IPv6WithCidr := helloPod2ns2IPv6 + "/128"

		if ipStackType == "dualstack" {
			g.By("create ipBlock Ingress Dual CIDRs Policy in ns1 again but with ipblock for pod2 ns2")
			npIPBlockNS1New := otputils.IpBlockCIDRsDual{
				Name:      "ipblock-dual-cidrs-ingress",
				Template:  ipBlockIngressTemplateDual,
				CidrIpv4:  helloPod2ns2IPv4WithCidr,
				CidrIpv6:  helloPod2ns2IPv6WithCidr,
				Namespace: ns1,
			}
			npIPBlockNS1New.CreateipBlockCIDRObjectDual(oc)
		} else {
			// For singlestack getPodIP returns second parameter empty therefore use helloPod2ns2IPv6 variable but append it
			// with CIDR based on stack.
			var helloPod2ns2IPWithCidr string
			if ipStackType == "ipv6single" {
				helloPod2ns2IPWithCidr = helloPod2ns2IPv6WithCidr
			} else {
				helloPod2ns2IPWithCidr = helloPod2ns2IPv6 + "/32"
			}

			npIPBlockNS1New := otputils.IpBlockCIDRsSingle{
				Name:      "ipblock-single-cidr-ingress",
				Template:  ipBlockIngressTemplateSingle,
				Cidr:      helloPod2ns2IPWithCidr,
				Namespace: ns1,
			}
			npIPBlockNS1New.CreateipBlockCIDRObjectSingle(oc)
		}
		g.By("Checking connectivity from pod2 ns2 to pod3 ns1")
		otputils.CurlPod2PodPass(oc, ns2, "hello-pod2", ns1, "hello-pod3")

		g.By("Checking connectivity from pod1 ns2 to pod3 ns1")
		otputils.CurlPod2PodFail(oc, ns2, "hello-pod1", ns1, "hello-pod3")

		if ipStackType == "dualstack" {
			g.By("Delete networkpolicy from ns1 again so no networkpolicy in namespace")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-dual-cidrs-ingress", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			g.By("Delete networkpolicy from ns1 again so no networkpolicy in namespace")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-single-cidr-ingress", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("Check connectivity works fine across all failed ones above to make sure all policy flows are cleared properly")

		g.By("Checking connectivity from pod2ns1 to pod3ns1")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod3")

		g.By("Checking connectivity from pod1ns2 to pod3ns1")
		otputils.CurlPod2PodPass(oc, ns2, "hello-pod1", ns1, "hello-pod3")

		g.By("Checking connectivity from pod2ns2 to pod1ns1 on IPv4 interface")
		otputils.CurlPod2PodPass(oc, ns2, "hello-pod2", ns1, "hello-pod1")

	})

	g.It("[JIRA:Networking][OTP][LEVEL0][FdpOvnOvs] 49696-mixed ingress and egress policies can work well", g.Label("Level0"), func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			helloSdnFile        = filepath.Join(buildPruningBaseDir, "hellosdn.yaml")
			egressTypeFile      = filepath.Join(buildPruningBaseDir, "networkpolicy/egress_49696.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/ingress_49696.yaml")
		)
		g.By("create one namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("create test pods")
		otputils.CreateResourceFromFile(oc, ns1, testPodFile)
		otputils.CreateResourceFromFile(oc, ns1, helloSdnFile)
		err := otputils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		err = otputils.WaitForPodWithLabelReady(oc, ns1, "name=hellosdn")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=hellosdn not ready")
		hellosdnPodNameNs1 := otputils.GetPodName(oc, ns1, "name=hellosdn")

		g.By("create egress type networkpolicy in ns1")
		otputils.CreateResourceFromFile(oc, ns1, egressTypeFile)

		g.By("create ingress type networkpolicy in ns1")
		otputils.CreateResourceFromFile(oc, ns1, ingressTypeFile)

		g.By("create second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("create test pods in second namespace")
		otputils.CreateResourceFromFile(oc, ns2, helloSdnFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns2, "name=hellosdn")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=hellosdn not ready")

		g.By("Get IP of the test pods in second namespace.")
		hellosdnPodNameNs2 := otputils.GetPodName(oc, ns2, "name=hellosdn")
		hellosdnPodIP1Ns2 := otputils.GetPodIPv4(oc, ns2, hellosdnPodNameNs2[0])

		g.By("curl from ns1 hellosdn pod to ns2 pod")
		_, err = e2eoutput.RunHostCmd(ns1, hellosdnPodNameNs1[0], "curl --connect-timeout 5  -s "+net.JoinHostPort(hellosdnPodIP1Ns2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))

	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 46246-Network Policies should work with OVNKubernetes when traffic hairpins back to the same source through a service", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			allowfromsameNS        = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-same-namespace.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("Create a namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("create 1st hello pod in ns1")

		pod1 := otputils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, ns, pod1.Name)

		g.By("create 2nd hello pod in same namespace but on different node")

		pod2 := otputils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, ns, pod2.Name)

		g.By("Create a test service backing up both the above pods")
		svc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        "",
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "", //This no value parameter will be ignored
			Template:              genericServiceTemplate,
		}
		svc.IpFamilyPolicy = "SingleStack"
		svc.CreateServiceFromParams(oc)

		g.By("create allow-from-same-namespace ingress networkpolicy in ns")
		otputils.CreateResourceFromFile(oc, ns, allowfromsameNS)

		g.By("curl from hello-pod1 to hello-pod2")
		otputils.CurlPod2PodPass(oc, ns, "hello-pod1", ns, "hello-pod2")

		g.By("curl from hello-pod2 to hello-pod1")
		otputils.CurlPod2PodPass(oc, ns, "hello-pod2", ns, "hello-pod1")

		for i := 0; i < 5; i++ {

			g.By("curl from hello-pod1 to service:port")
			otputils.CurlPod2SvcPass(oc, ns, ns, "hello-pod1", "test-service")

			g.By("curl from hello-pod2 to service:port")
			otputils.CurlPod2SvcPass(oc, ns, ns, "hello-pod2", "test-service")
		}

		g.By("Make sure pods are curl'able from respective nodes")
		otputils.CurlNode2PodPass(oc, pod1.Nodename, ns, "hello-pod1")
		otputils.CurlNode2PodPass(oc, pod2.Nodename, ns, "hello-pod2")

		ipStackType := otputils.CheckIPStackType(oc)

		if ipStackType == "dualstack" {
			g.By("Delete testservice from ns")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", "test-service", "-n", ns).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			g.By("Checking pod to svc:port behavior now on with PreferDualStack Service")
			svc.IpFamilyPolicy = "PreferDualStack"
			svc.CreateServiceFromParams(oc)
			for i := 0; i < 5; i++ {
				g.By("curl from hello-pod1 to service:port")
				otputils.CurlPod2SvcPass(oc, ns, ns, "hello-pod1", "test-service")

				g.By("curl from hello-pod2 to service:port")
				otputils.CurlPod2SvcPass(oc, ns, ns, "hello-pod2", "test-service")
			}
		}
	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 41879-ipBlock should not ignore all other cidr's apart from the last one specified", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking")
			ipBlockIngressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-dual-multiple-CIDRs-template.yaml")
			ipBlockIngressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-single-multiple-CIDRs-template.yaml")
			testPodFile                  = filepath.Join(buildPruningBaseDir, "testpod.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.Skip("This case requires dualstack or Single Stack IPv6 cluster")
		}

		g.By("Create a namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("create test pods in ns1")
		otputils.CreateResourceFromFile(oc, ns1, testPodFile)
		err := otputils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")

		g.By("Scale test pods to 5")
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=5", "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = otputils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")

		g.By("Get 3 test pods's podname and IPs")
		testPodName := otputils.GetPodName(oc, ns1, "name=test-pods")
		testPod1IPv6, testPod1IPv4 := otputils.GetPodIP(oc, ns1, testPodName[0])
		testPod1IPv4WithCidr := testPod1IPv4 + "/32"
		testPod1IPv6WithCidr := testPod1IPv6 + "/128"
		testPod2IPv6, testPod2IPv4 := otputils.GetPodIP(oc, ns1, testPodName[1])
		testPod2IPv4WithCidr := testPod2IPv4 + "/32"
		testPod2IPv6WithCidr := testPod2IPv6 + "/128"
		testPod3IPv6, testPod3IPv4 := otputils.GetPodIP(oc, ns1, testPodName[2])
		testPod3IPv4WithCidr := testPod3IPv4 + "/32"
		testPod3IPv6WithCidr := testPod3IPv6 + "/128"

		if ipStackType == "dualstack" {
			g.By("create ipBlock Ingress Dual CIDRs Policy in ns1")

			npIPBlockNS1 := otputils.IpBlockCIDRsDual{
				Name:      "ipblock-dual-cidrs-ingress-41879",
				Template:  ipBlockIngressTemplateDual,
				CidrIpv4:  testPod1IPv4WithCidr,
				CidrIpv6:  testPod1IPv6WithCidr,
				Cidr2Ipv4: testPod2IPv4WithCidr,
				Cidr2Ipv6: testPod2IPv6WithCidr,
				Cidr3Ipv4: testPod3IPv4WithCidr,
				Cidr3Ipv6: testPod3IPv6WithCidr,
				Namespace: ns1,
			}
			npIPBlockNS1.CreateIPBlockMultipleCIDRsObjectDual(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-dual-cidrs-ingress-41879"))
		} else {

			npIPBlockNS1 := otputils.IpBlockCIDRsSingle{
				Name:      "ipblock-single-cidr-ingress-41879",
				Template:  ipBlockIngressTemplateSingle,
				Cidr:      testPod1IPv6WithCidr,
				Cidr2:     testPod2IPv6WithCidr,
				Cidr3:     testPod3IPv6WithCidr,
				Namespace: ns1,
			}
			npIPBlockNS1.CreateIPBlockMultipleCIDRsObjectSingle(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-ingress-41879"))
		}

		g.By("Checking connectivity from pod1 to pod5")
		otputils.CurlPod2PodPass(oc, ns1, testPodName[0], ns1, testPodName[4])

		g.By("Checking connectivity from pod2 to pod5")
		otputils.CurlPod2PodPass(oc, ns1, testPodName[1], ns1, testPodName[4])

		g.By("Checking connectivity from pod3 to pod5")
		otputils.CurlPod2PodPass(oc, ns1, testPodName[2], ns1, testPodName[4])

		g.By("Checking connectivity from pod4 to pod5")
		otputils.CurlPod2PodFail(oc, ns1, testPodName[3], ns1, testPodName[4])

	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 46807-network policy with egress rule with ipBlock", func() {
		var (
			buildPruningBaseDir         = testdata.FixturePath("networking")
			ipBlockEgressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-dual-CIDRs-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-single-CIDR-template.yaml")
			pingPodNodeTemplate         = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("Obtain the namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("create 1st hello pod in ns1")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod2ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)

		g.By("create 3rd hello pod in ns1")
		pod3ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod3",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod3ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod3ns1.Namespace, pod3ns1.Name)

		helloPod1ns1IP1, helloPod1ns1IP2 := otputils.GetPodIP(oc, ns1, pod1ns1.Name)

		if ipStackType == "dualstack" {
			helloPod1ns1IPv6WithCidr := helloPod1ns1IP1 + "/128"
			helloPod1ns1IPv4WithCidr := helloPod1ns1IP2 + "/32"
			g.By("create ipBlock Egress Dual CIDRs Policy in ns1")
			npIPBlockNS1 := otputils.IpBlockCIDRsDual{
				Name:      "ipblock-dual-cidrs-egress",
				Template:  ipBlockEgressTemplateDual,
				CidrIpv4:  helloPod1ns1IPv4WithCidr,
				CidrIpv6:  helloPod1ns1IPv6WithCidr,
				Namespace: ns1,
			}
			npIPBlockNS1.CreateipBlockCIDRObjectDual(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-dual-cidrs-egress"))

		} else {
			if ipStackType == "ipv6single" {
				helloPod1ns1IPv6WithCidr := helloPod1ns1IP1 + "/128"
				npIPBlockNS1 := otputils.IpBlockCIDRsSingle{
					Name:      "ipblock-single-cidr-egress",
					Template:  ipBlockEgressTemplateSingle,
					Cidr:      helloPod1ns1IPv6WithCidr,
					Namespace: ns1,
				}
				npIPBlockNS1.CreateipBlockCIDRObjectSingle(oc)
			} else {
				helloPod1ns1IPv4WithCidr := helloPod1ns1IP1 + "/32"
				npIPBlockNS1 := otputils.IpBlockCIDRsSingle{
					Name:      "ipblock-single-cidr-egress",
					Template:  ipBlockEgressTemplateSingle,
					Cidr:      helloPod1ns1IPv4WithCidr,
					Namespace: ns1,
				}
				npIPBlockNS1.CreateipBlockCIDRObjectSingle(oc)
			}

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress"))
		}
		g.By("Checking connectivity from pod2 to pod1")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		g.By("Checking connectivity from pod2 to pod3")
		otputils.CurlPod2PodFail(oc, ns1, "hello-pod2", ns1, "hello-pod3")

		if ipStackType == "dualstack" {
			g.By("Delete networkpolicy from ns1 so no networkpolicy in namespace")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-dual-cidrs-egress", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			g.By("Delete networkpolicy from ns1 so no networkpolicy in namespace")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-single-cidr-egress", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("Check connectivity works fine across all failed ones above to make sure all policy flows are cleared properly")

		g.By("Checking connectivity from pod2 to pod1")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		g.By("Checking connectivity from pod2 to pod3")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod3")

	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 46808-network policy with egress rule with ipBlock and except", func() {
		var (
			buildPruningBaseDir         = testdata.FixturePath("networking")
			ipBlockEgressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-except-dual-CIDRs-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-except-single-CIDR-template.yaml")
			pingPodNodeTemplate         = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("Obtain the namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("create 1st hello pod in ns1 on node[0]")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("create 2nd hello pod in ns1 on node[0]")
		pod2ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod2ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)

		g.By("create 3rd hello pod in ns1 on node[1]")
		pod3ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod3",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod3ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod3ns1.Namespace, pod3ns1.Name)

		g.By("create 4th hello pod in ns1 on node[1]")
		pod4ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod4",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod4ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod4ns1.Namespace, pod4ns1.Name)

		helloPod2ns1IP1, helloPod2ns1IP2 := otputils.GetPodIP(oc, ns1, pod2ns1.Name)
		if ipStackType == "dualstack" {
			hostSubnetCIDRIPv4, hostSubnetCIDRIPv6 := otputils.GetNodeSubnetDualStack(oc, nodeList.Items[0].Name, "default")
			o.Expect(hostSubnetCIDRIPv6).NotTo(o.BeEmpty())
			o.Expect(hostSubnetCIDRIPv4).NotTo(o.BeEmpty())
			helloPod2ns1IPv6WithCidr := helloPod2ns1IP1 + "/128"
			helloPod2ns1IPv4WithCidr := helloPod2ns1IP2 + "/32"
			g.By("create ipBlock Egress CIDRs with except rule Policy in ns1 on dualstack")
			npIPBlockNS1 := otputils.IpBlockCIDRsExceptDual{
				Name:           "ipblock-dual-cidrs-egress-except",
				Template:       ipBlockEgressTemplateDual,
				CidrIpv4:       hostSubnetCIDRIPv4,
				CidrIpv4Except: helloPod2ns1IPv4WithCidr,
				CidrIpv6:       hostSubnetCIDRIPv6,
				CidrIpv6Except: helloPod2ns1IPv6WithCidr,
				Namespace:      ns1,
			}
			npIPBlockNS1.CreateipBlockExceptObjectDual(oc)
			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-dual-cidrs-egress-except"))
		} else {
			if ipStackType == "ipv6single" {
				hostSubnetCIDRIPv6 := otputils.GetNodeSubnet(oc, nodeList.Items[0].Name, "default")
				o.Expect(hostSubnetCIDRIPv6).NotTo(o.BeEmpty())
				helloPod2ns1IPv6WithCidr := helloPod2ns1IP1 + "/128"
				g.By("create ipBlock Egress CIDRs with except rule Policy in ns1 on IPv6 singlestack")
				npIPBlockNS1 := otputils.IpBlockCIDRsExceptSingle{
					Name:      "ipblock-single-cidr-egress-except",
					Template:  ipBlockEgressTemplateSingle,
					Cidr:      hostSubnetCIDRIPv6,
					Except:    helloPod2ns1IPv6WithCidr,
					Namespace: ns1,
				}
				npIPBlockNS1.CreateipBlockExceptObjectSingle(oc, true)
			} else {
				hostSubnetCIDRIPv4 := otputils.GetNodeSubnet(oc, nodeList.Items[0].Name, "default")
				o.Expect(hostSubnetCIDRIPv4).NotTo(o.BeEmpty())
				helloPod2ns1IPv4WithCidr := helloPod2ns1IP1 + "/32"
				g.By("create ipBlock Egress CIDRs with except rule Policy in ns1 on IPv4 singlestack")
				npIPBlockNS1 := otputils.IpBlockCIDRsExceptSingle{
					Name:      "ipblock-single-cidr-egress-except",
					Template:  ipBlockEgressTemplateSingle,
					Cidr:      hostSubnetCIDRIPv4,
					Except:    helloPod2ns1IPv4WithCidr,
					Namespace: ns1,
				}
				npIPBlockNS1.CreateipBlockExceptObjectSingle(oc, true)
			}
			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress-except"))
		}
		g.By("Checking connectivity from pod3 to pod1")
		o.Eventually(func() error {
			podIP1, podIP2 := otputils.GetPodIP(oc, ns1, "hello-pod1")
			if _, err := e2eoutput.RunHostCmd(ns1, "hello-pod3", "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080")); err != nil {
				return err
			}
			if podIP2 != "" {
				if _, err := e2eoutput.RunHostCmd(ns1, "hello-pod3", "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP2, "8080")); err != nil {
					return err
				}
			}
			return nil
		}, "30s", "5s").Should(o.Succeed(), "pod3 should reach pod1 after network policy propagation")

		g.By("Checking connectivity from pod3 to pod2")
		otputils.CurlPod2PodFail(oc, ns1, "hello-pod3", ns1, "hello-pod2")

		g.By("Checking connectivity from pod3 to pod4")
		otputils.CurlPod2PodFail(oc, ns1, "hello-pod3", ns1, "hello-pod4")
		if ipStackType == "dualstack" {
			g.By("Delete networkpolicy from ns1 so no networkpolicy in namespace")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-dual-cidrs-egress-except", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			g.By("Delete networkpolicy from ns1 so no networkpolicy in namespace")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-single-cidr-egress-except", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("Check connectivity works fine across all failed ones above to make sure all policy flows are cleared properly")

		g.By("Checking connectivity from pod3 to pod1")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod3", ns1, "hello-pod1")

		g.By("Checking connectivity from pod3 to pod2")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod3", ns1, "hello-pod2")

		g.By("Checking connectivity from pod3 to pod4")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod3", ns1, "hello-pod4")

	})

	g.It("[JIRA:Networking][OTP] 41082-Check ACL audit logs can be extracted", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			allowFromSameNS     = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-same-namespace.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Obtain the namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("Enable ACL looging on the namespace ns1")
		aclSettings := otputils.AclSettings{DenySetting: "alert", AllowSetting: "alert"}
		err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", ns1, aclSettings.GetJSONString()).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())

		g.By("create default deny ingress networkpolicy in ns1")
		otputils.CreateResourceFromFile(oc, ns1, ingressTypeFile)

		g.By("create allow same namespace networkpolicy in ns1")
		otputils.CreateResourceFromFile(oc, ns1, allowFromSameNS)

		g.By("create 1st hello pod in ns1")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}

		pod2ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)

		g.By("Checking connectivity from pod2 to pod1 to generate messages")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		output, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "verdict=allow")).To(o.BeTrue())

	})
	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 41407-Check networkpolicy ACL audit message is logged with correct policy name", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			allowFromSameNS     = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-same-namespace.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		var namespaces [2]string
		policyList := [2]string{"default-deny-ingress", "allow-from-same-namespace"}
		for i := 0; i < 2; i++ {
		oc.SetupProject()
			namespaces[i] = oc.Namespace()
			g.By(fmt.Sprintf("Enable ACL looging on the namespace %s", namespaces[i]))
			aclSettings := otputils.AclSettings{DenySetting: "alert", AllowSetting: "warning"}
			err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", namespaces[i], aclSettings.GetJSONString()).Execute()
			o.Expect(err1).NotTo(o.HaveOccurred())

			g.By(fmt.Sprintf("Create default deny ingress networkpolicy in %s", namespaces[i]))
			otputils.CreateResourceFromFile(oc, namespaces[i], ingressTypeFile)
			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(policyList[0]))

			g.By(fmt.Sprintf("Create allow same namespace networkpolicy in %s", namespaces[i]))
			otputils.CreateResourceFromFile(oc, namespaces[i], allowFromSameNS)
			output, err = oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(policyList[1]))

			pod := otputils.PingPodResourceNode{
				Name:      "",
				Namespace: namespaces[i],
				Nodename:  "",
				Template:  pingPodNodeTemplate,
			}
			for j := 0; j < 2; j++ {
				g.By(fmt.Sprintf("Create hello pod in %s", namespaces[i]))
				pod.Name = "hello-pod" + strconv.Itoa(j)
				pod.Nodename = nodeList.Items[j].Name
				pod.CreatePingPodNode(oc)
				otputils.WaitPodReady(oc, pod.Namespace, pod.Name)
			}
			g.By(fmt.Sprintf("Checking connectivity from second pod to  first pod to generate messages in %s", namespaces[i]))
			otputils.CurlPod2PodPass(oc, namespaces[i], "hello-pod1", namespaces[i], "hello-pod0")
			oc.SetupProject()
		}

		output, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ACL logs for allow-from-same-namespace policy \n %s", output)
		// policy name truncated to allow-from-same-name in ACL log message
		for i := 0; i < len(namespaces); i++ {
			searchString := fmt.Sprintf("name=\"NP:%s:allow-from-same-name\", verdict=allow, severity=warning", namespaces[i])
			o.Expect(strings.Contains(output, searchString)).To(o.BeTrue())
			otputils.RemoveResource(oc, true, true, "networkpolicy", policyList[1], "-n", namespaces[i])
			otputils.CurlPod2PodFail(oc, namespaces[i], "hello-pod0", namespaces[i], "hello-pod1")
		}
		output, err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[1].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ACL logs for default-deny-ingress policy \n %s", output)
		for i := 0; i < len(namespaces); i++ {
			searchString := fmt.Sprintf("name=\"NP:%s:Ingress\", verdict=drop, severity=alert", namespaces[i])
			o.Expect(strings.Contains(output, searchString)).To(o.BeTrue())
		}

	})
	g.It("[JIRA:Networking][OTP][WRS][V-BR.33][Serial] 41080-Check network policy ACL audit messages are logged to journald", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			allowFromSameNS     = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-same-namespace.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Configure audit message logging destination to journald")
		patchSResource := "networks.operator.openshift.io/cluster"
		patchInfo := `{"spec":{"defaultNetwork":{"ovnKubernetesConfig":{"policyAuditConfig": {"destination": "libc"}}}}}`
		undoPatchInfo := `{"spec":{"defaultNetwork":{"ovnKubernetesConfig":{"policyAuditConfig": {"destination": ""}}}}}`
		defer func() {
			_, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args(patchSResource, "-p", undoPatchInfo, "--type=merge").Output()
			o.Expect(patchErr).NotTo(o.HaveOccurred())
			otputils.WaitForNetworkOperatorState(oc, 100, 15, "True.*False.*False")
		}()
		_, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args(patchSResource, "-p", patchInfo, "--type=merge").Output()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		//Network operator needs to recreate the pods on a merge request, therefore give it enough time.
		otputils.WaitForNetworkOperatorState(oc, 100, 15, "True.*False.*False")

		g.By("Obtain the namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()
		otputils.SetNamespacePrivileged(oc, ns1)

		g.By("Enable ACL looging on the namespace ns1")
		aclSettings := otputils.AclSettings{DenySetting: "alert", AllowSetting: "alert"}
		err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", ns1, aclSettings.GetJSONString()).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())

		g.By("create default deny ingress networkpolicy in ns1")
		otputils.CreateResourceFromFile(oc, ns1, ingressTypeFile)

		g.By("create allow same namespace networkpolicy in ns1")
		otputils.CreateResourceFromFile(oc, ns1, allowFromSameNS)

		g.By("create 1st hello pod in ns1")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}

		pod2ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)

		g.By("Checking connectivity from pod2 to pod1 to generate messages")
		otputils.CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		g.By("Checking messages are logged to journald")
		cmd := fmt.Sprintf("journalctl -t ovn-controller --since '1min ago'| grep 'verdict=allow'")
		output, journalctlErr := otputils.DebugNodeWithOptionsAndChroot(oc, nodeList.Items[0].Name, []string{"-q"}, "bin/sh", "-c", cmd)
		e2e.Logf("Output %s", output)
		o.Expect(journalctlErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "verdict=allow")).To(o.BeTrue())

	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 55287-Default network policy ACLs to a namespace should not be present with arp but arp||nd for ARPAllowPolicies", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
		)
		g.By("This is for BZ 2095852")

		g.By("create new namespace")
		oc.SetupProject()

		g.By("create test pods")
		otputils.CreateResourceFromFile(oc, oc.Namespace(), testPodFile)
		err := otputils.WaitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")

		g.By("create ingress default-deny type networkpolicy")
		otputils.CreateResourceFromFile(oc, oc.Namespace(), ingressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny"))

		ovnMasterPodName := otputils.GetOVNKMasterOVNkubeNode(oc)
		o.Expect(ovnMasterPodName).NotTo(o.BeEmpty())
		g.By("get ACLs related to ns")
		//list ACLs only related namespace in test
		listACLCmd := "ovn-nbctl list ACL | grep -C 5 " + "NP:" + oc.Namespace() + " | grep -C 5 type=arpAllow"
		listOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnMasterPodName, "ovnkube-controller", listACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		e2e.Logf("Output %s", listOutput)
		o.Expect(listOutput).To(o.ContainSubstring("&& (arp || nd)"))
		o.Expect(listOutput).ShouldNot(o.ContainSubstring("&& arp"))
	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 62524-OVN address_set referenced in acl should not miss when networkpolicy name includes dot.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			networkPolicyFile   = filepath.Join(buildPruningBaseDir, "networkpolicy/egress-ingress-62524.yaml")
		)
		g.By("Check cluster network type")

		g.By("Get namespace")
		oc.SetupProject()
		ns := oc.Namespace()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "team-").Execute()
			}
		}()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "team=openshift-networking").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("create test pods")
		otputils.CreateResourceFromFile(oc, ns, testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPod := otputils.GetPodName(oc, ns, "name=test-pods")

		g.By("Create a pod ")
		pod1 := otputils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod1.CreatePingPod(oc)
		otputils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("create egress-ingress type networkpolicy")
		otputils.CreateResourceFromFile(oc, ns, networkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("egress-ingress-62524.test"))

		ovnMasterPodName := otputils.GetOVNKMasterOVNkubeNode(oc)
		o.Expect(ovnMasterPodName).NotTo(o.BeEmpty())
		g.By("Verify the address_set exists for the specific acl")
		//list ACLs related to the networkpolicy name
		listACLCmd := "ovn-nbctl --data=bare --no-heading --format=table find acl | grep  egress-ingress-62524.test"
		listOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnMasterPodName, "ovnkube-controller", listACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listOutput).NotTo(o.BeEmpty())

		// Get the address set name from the acls
		regex := `\{\$(\w+)\}`
		re := regexp.MustCompile(regex)
		matches := re.FindAllStringSubmatch(listOutput, -1)
		if len(matches) == 0 {
			e2e.Fail("No matched address_set name found")
		}
		var result []string
		for _, match := range matches {
			if len(match) == 2 { // Check if a match was found
				result = append(result, match[1]) // Append the captured group to the result slice
			}
		}
		if len(result) == 0 {
			e2e.Fail("No matched address_set name found")
		}

		//Check adress_set can be found when ovn-nbctl list address_set
		for _, addrSetName := range result {
			listAddressSetCmd := "ovn-nbctl --no-leader-only list address_set | grep " + addrSetName
			listAddrOutput, listAddrErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnMasterPodName, "ovnkube-controller", listAddressSetCmd)
			o.Expect(listAddrErr).NotTo(o.HaveOccurred())
			o.Expect(listAddrOutput).NotTo(o.BeEmpty())
		}

		g.By("Checking pods connectivity")
		otputils.CurlPod2PodPass(oc, ns, testPod[0], ns, pod1.Name)
		otputils.CurlPod2PodFail(oc, ns, testPod[0], ns, testPod[1])

	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs][Serial] 65901-Duplicate transactions should not be executed for network policy for every pod update.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			networkPolicyFile   = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-ingress-red.yaml")
			testPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)

		g.By("Obtain the namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create a pod in namespace")
		pod := otputils.PingPodResource{
			Name:      "test-pod",
			Namespace: ns,
			Template:  testPodTemplate,
		}
		pod.CreatePingPod(oc)
		otputils.WaitPodReady(oc, pod.Namespace, pod.Name)
		_, labelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", pod.Namespace, "pod", pod.Name, "type=red").Output()
		o.Expect(labelErr).NotTo(o.HaveOccurred())

		g.By("Create a network policy")
		otputils.CreateResourceFromFile(oc, ns, networkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-ingress-to-red"))

		g.By("Obtain the transaction count to be 1")
		podIP1, _ := otputils.GetPodIP(oc, ns, pod.Name)

		podNodeName, podNodenameErr := otputils.GetPodNodeName(oc, ns, pod.Name)
		o.Expect(podNodeName).NotTo(o.BeEmpty())
		o.Expect(podNodenameErr).NotTo(o.HaveOccurred())
		e2e.Logf("Node on which pod %s is running %s", pod.Name, podNodeName)
		ovnKNodePod, ovnkNodePodErr := otputils.GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", podNodeName)
		o.Expect(ovnKNodePod).NotTo(o.BeEmpty())
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, podNodeName)

		getCmd := fmt.Sprintf("cat /var/log/ovnkube/libovsdb.log | grep 'transacting operations' | grep '%s' ", podIP1)
		// Wait for in-flight transactions from network policy creation to settle before capturing baseline
		time.Sleep(10 * time.Second)
		logContents, logErr1 := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", getCmd)
		o.Expect(logErr1).NotTo(o.HaveOccurred())
		e2e.Logf(fmt.Sprintf("Log content before label update \n %s", logContents))
		logLinesCount := len(strings.Split(logContents, "\n")) - 1

		g.By("Label the pods to see transaction count is unchanged")
		_, reLabelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", pod.Namespace, "--overwrite", "pod", pod.Name, "type=blue").Output()
		o.Expect(reLabelErr).NotTo(o.HaveOccurred())

		time.Sleep(5 * time.Second)
		newLogContents, logErr2 := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", getCmd)
		o.Expect(logErr2).NotTo(o.HaveOccurred())
		e2e.Logf(fmt.Sprintf("Log content after label update \n %s", newLogContents))
		newLogLinesCount := len(strings.Split(newLogContents, "\n")) - 1
		o.Expect(logLinesCount).To(o.Equal(newLogLinesCount))

	})
	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 66085-Creating egress network policies for allowing to same namespace and openshift dns in namespace prevents the pod from reaching its own service", func() {
		var (
			buildPruningBaseDir        = testdata.FixturePath("networking")
			pingPodTemplate            = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			genericServiceTemplate     = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			allowToNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-to-same-namespace.yaml")
			allowToDNSNPolicyFile      = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-to-openshift-dns.yaml")
			podsInProject              = []string{"hello-pod-1", "other-pod"}
			svcURL                     string
		)

		g.By("Get first namespace and create another")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create set of pods with different labels")
		for _, podItem := range podsInProject {
			pod1 := otputils.PingPodResource{
				Name:      podItem,
				Namespace: ns,
				Template:  pingPodTemplate,
			}
			pod1.CreatePingPod(oc)
			otputils.WaitPodReady(oc, ns, pod1.Name)
		}
		g.By("Label the pods to ensure the pod does not serve the service")
		_, reLabelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns, "--overwrite", "pod", podsInProject[1], "name=other-pod").Output()
		o.Expect(reLabelErr).NotTo(o.HaveOccurred())

		g.By("Create a service for one of the pods")
		svc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        "SingleStack",
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "", //This no value parameter will be ignored
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)
		g.By("Check service status")
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.Servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.Servicename))

		g.By("Obtain the service URL")
		svcURL = fmt.Sprintf("http://%s.%s.svc:27017", svc.Servicename, svc.Namespace)
		e2e.Logf("Service URL %s", svcURL)
		g.By("Check the connectivity to service from the pods in the namespace")
		for _, podItem := range podsInProject {
			output, err := e2eoutput.RunHostCmd(ns, podItem, "curl --connect-timeout 5 -s "+svcURL)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("Hello OpenShift!"))
		}

		g.By("Create the network policies in the namespace")
		g.By("Create the allow to same namespace policy in the namespace")
		otputils.CreateResourceFromFile(oc, ns, allowToNSNetworkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-same-namespace"))
		g.By("Create the allow to DNS policy in the namespace")
		otputils.CreateResourceFromFile(oc, ns, allowToDNSNPolicyFile)
		output, err = oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-openshift-dns"))

		g.By("Create another pod to serve the service")
		anotherPod := otputils.PingPodResource{
			Name:      "hello-pod-2",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		anotherPod.CreatePingPod(oc)
		otputils.WaitPodReady(oc, ns, anotherPod.Name)
		podsInProject = append(podsInProject, anotherPod.Name)

		g.By("Check the connectivity to service again from the pods in the namespace")
		for _, eachPod := range podsInProject {
			output, err := e2eoutput.RunHostCmd(ns, eachPod, "curl --connect-timeout 5 -s "+svcURL)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("Hello OpenShift!"))
		}
	})
	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 64787-Network policy with duplicate egress rules (same CIDR block) fails to be recreated", g.Label("Disruptive"), func() {
		var (
			buildPruningBaseDir         = testdata.FixturePath("networking")
			ipBlockEgressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-dual-multiple-CIDRs-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-single-multiple-CIDRs-template.yaml")
			pingPodNodeTemplate         = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("Obtain the namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("create a hello pod in namspace")
		podns := otputils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		podns.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, podns.Namespace, podns.Name)

		helloPodnsIP1, helloPodnsIP2 := otputils.GetPodIP(oc, ns, podns.Name)
		var policyName string
		if ipStackType == "dualstack" {
			helloPodnsIPv6WithCidr := helloPodnsIP1 + "/128"
			helloPodnsIPv4WithCidr := helloPodnsIP2 + "/32"
			g.By("Create ipBlock Egress Dual with multiple CIDRs Policy in namespace")
			npIPBlockNS := otputils.IpBlockCIDRsDual{
				Name:      "ipblock-dual-multiple-cidrs-egress",
				Template:  ipBlockEgressTemplateDual,
				CidrIpv4:  helloPodnsIPv4WithCidr,
				CidrIpv6:  helloPodnsIPv6WithCidr,
				Cidr2Ipv4: helloPodnsIPv4WithCidr,
				Cidr2Ipv6: helloPodnsIPv6WithCidr,
				Cidr3Ipv4: helloPodnsIPv4WithCidr,
				Cidr3Ipv6: helloPodnsIPv6WithCidr,
				Namespace: ns,
			}
			npIPBlockNS.CreateIPBlockMultipleCIDRsObjectDual(oc)
			output, err := oc.Run("get").Args("networkpolicy", "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(npIPBlockNS.Name))
			policyName = npIPBlockNS.Name

		} else {
			var npIPBlockNS otputils.IpBlockCIDRsSingle
			if ipStackType == "ipv6single" {
				helloPodnsIPv6WithCidr := helloPodnsIP1 + "/128"
				npIPBlockNS = otputils.IpBlockCIDRsSingle{
					Name:      "ipblock-single-multiple-cidr-egress",
					Template:  ipBlockEgressTemplateSingle,
					Cidr:      helloPodnsIPv6WithCidr,
					Cidr2:     helloPodnsIPv6WithCidr,
					Cidr3:     helloPodnsIPv6WithCidr,
					Namespace: ns,
				}
			} else {
				helloPodnsIPv4WithCidr := helloPodnsIP1 + "/32"
				npIPBlockNS = otputils.IpBlockCIDRsSingle{
					Name:      "ipblock-single-multiple-cidr-egress",
					Template:  ipBlockEgressTemplateSingle,
					Cidr:      helloPodnsIPv4WithCidr,
					Cidr2:     helloPodnsIPv4WithCidr,
					Cidr3:     helloPodnsIPv4WithCidr,
					Namespace: ns,
				}
			}
			npIPBlockNS.CreateIPBlockMultipleCIDRsObjectSingle(oc)
			output, err := oc.Run("get").Args("networkpolicy", "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(npIPBlockNS.Name))
			policyName = npIPBlockNS.Name
		}
		g.By("Delete the ovnkube node pod on the node")
		ovnKNodePod, ovnkNodePodErr := otputils.GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, nodeList.Items[0].Name)
		defer otputils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnKNodePod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Wait for new ovnkube-node pod recreated on the node")
		otputils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		ovnKNodePod, ovnkNodePodErr = otputils.GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))

		g.By("Check for error message related network policy")
		e2e.Logf("ovnkube-node new podname %s running on node %s", ovnKNodePod, nodeList.Items[0].Name)
		filterString := fmt.Sprintf(" %s/%s ", ns, policyName)
		e2e.Logf("Filter String %s", filterString)
		logContents, logErr := otputils.GetSpecificPodLogs(oc, "openshift-ovn-kubernetes", "ovnkube-controller", ovnKNodePod, filterString)
		o.Expect(logErr).NotTo(o.HaveOccurred())
		e2e.Logf("Log contents \n%s", logContents)
		o.Expect(strings.Contains(logContents, "failed")).To(o.BeFalse())

	})
	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 64786-Network policy in namespace that has long name fails to be recreated as the ACLs are considered duplicate", g.Label("Disruptive"), func() {
		var (
			testNs                     = "test-64786networkpolicy-with-a-62chars-62chars-long-namespace62"
			buildPruningBaseDir        = testdata.FixturePath("networking")
			allowToNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-to-same-namespace.yaml")
			pingPodTemplate            = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items) == 0).NotTo(o.BeTrue())

		g.By("Create a namespace with a long name")
		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		origContxt = strings.TrimSpace(origContxt)
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().Run("delete").Args("project", testNs, "--ignore-not-found").Execute()
			}
		}()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
				o.Expect(useContxtErr).NotTo(o.HaveOccurred())
			}
		}()
		nsCreateErr := oc.WithoutNamespace().Run("new-project").Args(testNs).Execute()
		o.Expect(nsCreateErr).NotTo(o.HaveOccurred())

		g.By("Create a hello pod in namspace")
		podns := otputils.PingPodResource{
			Name:      "hello-pod",
			Namespace: testNs,
			Template:  pingPodTemplate,
		}
		podns.CreatePingPod(oc)
		otputils.WaitPodReady(oc, podns.Namespace, podns.Name)

		g.By("Create a network policy in namespace")
		otputils.CreateResourceFromFile(oc, testNs, allowToNSNetworkPolicyFile)
		checkErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			output, err := oc.WithoutNamespace().Run("get").Args("networkpolicy", "-n", testNs).Output()
			if err != nil {
				e2e.Logf("%v,Waiting for policy to be created, try again ...,", err)
				return false, nil
			}
			// Check network policy
			if strings.Contains(output, "allow-to-same-namespace") {
				e2e.Logf("Network policy created")
				return true, nil
			}
			return false, nil
		})
		o.Expect(checkErr).NotTo(o.HaveOccurred(), "Network policy could not be created")

		g.By("Delete the ovnkube node pod on the node")
		ovnKNodePod, ovnkNodePodErr := otputils.GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, nodeList.Items[0].Name)
		defer otputils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnKNodePod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Wait for new ovnkube-node pod recreated on the node")
		otputils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		ovnKNodePod, ovnkNodePodErr = otputils.GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))

		g.By("Check for error message related network policy")
		e2e.Logf("ovnkube-node new podname %s running on node %s", ovnKNodePod, nodeList.Items[0].Name)
		filterString := fmt.Sprintf(" %s/%s ", testNs, "allow-to-same-namespace")
		e2e.Logf("Filter String %s", filterString)
		logContents, logErr := otputils.GetSpecificPodLogs(oc, "openshift-ovn-kubernetes", "ovnkube-controller", ovnKNodePod, filterString)
		o.Expect(logErr).NotTo(o.HaveOccurred())
		e2e.Logf("Log contents \n%s", logContents)
		o.Expect(strings.Contains(logContents, "failed")).To(o.BeFalse())

	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 64788-Same network policies across multiple namespaces fail to be recreated.", g.Label("Disruptive"), func() {
		var (
			buildPruningBaseDir     = testdata.FixturePath("networking")
			testPodFile             = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			networkPolicyFileSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-single-CIDR-template.yaml")
			networkPolicyFileDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-dual-CIDRs-template.yaml")
			policyName              = "ipblock-64788"
		)

		ipStackType := otputils.CheckIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		g.By("Get namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create a test pods")
		otputils.CreateResourceFromFile(oc, ns, testPodFile)
		err := otputils.WaitForPodWithLabelReady(oc, ns, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "The pod with label name=test-pods is not ready")
		testPod := otputils.GetPodName(oc, ns, "name=test-pods")
		nodeName, err := otputils.GetPodNodeName(oc, ns, testPod[0])
		o.Expect(err).NotTo(o.HaveOccurred())

		helloPod1ns1IPv6, helloPod1ns1IPv4 := otputils.GetPodIP(oc, ns, testPod[0])
		helloPod1ns1IPv4WithCidr := helloPod1ns1IPv4 + "/32"
		helloPod1ns1IPv6WithCidr := helloPod1ns1IPv6 + "/128"
		g.By("Create ipBlock Ingress CIDRs Policy in namespace")
		if ipStackType == "dualstack" {
			npIPBlockNS1 := otputils.IpBlockCIDRsDual{
				Name:      policyName,
				Template:  networkPolicyFileDual,
				CidrIpv4:  helloPod1ns1IPv4WithCidr,
				CidrIpv6:  helloPod1ns1IPv6WithCidr,
				Namespace: ns,
			}
			npIPBlockNS1.CreateipBlockCIDRObjectDual(oc)
		} else {
			// For singlestack getPodIP returns second parameter empty therefore use helloPod1ns1IPv6 variable but append it
			// with CIDR based on stack.
			var helloPod1ns1IPWithCidr string
			if ipStackType == "ipv6single" {
				helloPod1ns1IPWithCidr = helloPod1ns1IPv6WithCidr
			} else {
				helloPod1ns1IPWithCidr = helloPod1ns1IPv6 + "/32"
			}

			npIPBlockNS1 := otputils.IpBlockCIDRsSingle{
				Name:      policyName,
				Template:  networkPolicyFileSingle,
				Cidr:      helloPod1ns1IPWithCidr,
				Namespace: ns,
			}
			npIPBlockNS1.CreateipBlockCIDRObjectSingle(oc)
		}

		g.By("Check the policy has been created")
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(policyName))

		ovnKNodePod, ovnkNodePodErr := otputils.GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, nodeName)

		g.By("Get the ACL for the created policy")
		//list ACLs related to the networkpolicy name
		aclName := fmt.Sprintf("'NP:%s:%s:Ingres'", ns, policyName)
		listACLCmd := fmt.Sprintf("ovn-nbctl find acl name='NP\\:%s\\:%s\\:Ingres'", ns, policyName)
		listAclOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAclOutput).NotTo(o.BeEmpty())
		e2e.Logf(listAclOutput)
		var aclMap map[string]string
		var listPGCmd string
		//Dual stack has two ACLs for policy and uuid of both are needed to get port group
		if ipStackType == "dualstack" {
			listAcls := strings.Split(listAclOutput, "\n\n")
			aclMap = otputils.NbContructToMap(listAcls[0])
			o.Expect(len(aclMap)).NotTo(o.Equal(0))
			aclMap1 := otputils.NbContructToMap(listAcls[1])
			o.Expect(len(aclMap1)).NotTo(o.Equal(0))
			listPGCmd = fmt.Sprintf("ovn-nbctl find port-group acls='[%s, %s]'", aclMap["_uuid"], aclMap1["_uuid"])
		} else {
			aclMap = otputils.NbContructToMap(listAclOutput)
			o.Expect(len(aclMap)).NotTo(o.Equal(0))
			listPGCmd = fmt.Sprintf("ovn-nbctl find port-group acls='[%s]'", aclMap["_uuid"])
		}
		aclMap["name"] = aclName

		g.By("Get the port group for the created policy")
		listPGOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listPGCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listPGOutput).NotTo(o.BeEmpty())
		e2e.Logf(listPGOutput)
		pgMap := otputils.NbContructToMap(listPGOutput)
		o.Expect(len(pgMap)).NotTo(o.Equal(0))

		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", policyName, "-n", ns).Execute()
			}
		}()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("Create a duplicate ACL")
		createAclCmd := fmt.Sprintf("ovn-nbctl --id=@copyacl create acl name=copyacl direction=%s action=%s -- add port_group %s acl @copyacl", aclMap["direction"], aclMap["action"], pgMap["_uuid"])
		idOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", createAclCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(idOutput).NotTo(o.BeEmpty())
		e2e.Logf(idOutput)
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", policyName, "-n", ns).Execute()
			}
		}()
		g.By("Set properties of duplicate ACL")
		setAclPropertiesCmd := fmt.Sprintf("ovn-nbctl set acl %s  match='%s' priority=%s meter=%s", idOutput, aclMap["match"], aclMap["priority"], aclMap["meter"])
		_, listErr = otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", setAclPropertiesCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", policyName, "-n", ns).Execute()
			}
		}()
		g.By("Set name of duplicate ACL")
		dupAclName := fmt.Sprintf("'NP\\:%s\\:%s\\:Ingre0'", ns, policyName)
		setAclNameCmd := fmt.Sprintf("ovn-nbctl set acl %s name=%s", idOutput, dupAclName)
		_, listErr = otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", setAclNameCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())

		g.By("Check duplicate ACL is created successfully")
		listDupACLCmd := fmt.Sprintf("ovn-nbctl find acl name='NP\\:%s\\:%s\\:Ingre0'", ns, policyName)
		listDupAclOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listDupACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listDupAclOutput).NotTo(o.BeEmpty())
		e2e.Logf(listDupAclOutput)

		g.By("Delete the ovnkube node pod on the node")
		ovnKNodePod, ovnkNodePodErr = otputils.GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, nodeName)
		defer otputils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnKNodePod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Wait for new ovnkube-node pod to be recreated on the node")
		otputils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		ovnKNodePod, ovnkNodePodErr = otputils.GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))

		g.By("Check the duplicate ACL is removed")
		listAclOutput, listErr = otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAclOutput).NotTo(o.BeEmpty(), listAclOutput)

		listDupAclOutput, listErr = otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listDupACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listDupAclOutput).To(o.BeEmpty())
	})

	g.It("[JIRA:Networking][OTP][FdpOvnOvs] 68660-Exposed route of the service should be accessible when allowing inbound traffic from any namespace network policy is created.", func() {
		var (
			buildPruningBaseDir             = testdata.FixturePath("networking")
			allowFromAllNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-all-namespaces.yaml")
			pingPodTemplate                 = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			genericServiceTemplate          = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			serviceName                     = "test-service-68660"
		)

		g.By("Get namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create a hello pod in namspace")
		podns := otputils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		podns.CreatePingPod(oc)
		otputils.WaitPodReady(oc, podns.Namespace, podns.Name)
		g.By("Create a test service which is in front of the above pod")
		svc := otputils.GenericServiceResource{
			Servicename:           serviceName,
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        "PreferDualStack",
			InternalTrafficPolicy: "Local",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)

		g.By("Expose the service through a route")
		err := oc.AsAdmin().WithoutNamespace().Run("expose").Args("svc", serviceName, "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		svcRoute, routeErr := oc.AsAdmin().Run("get").Args("route", serviceName, "-n", ns, "-o=jsonpath={.spec.host}").Output()
		o.Expect(routeErr).NotTo(o.HaveOccurred())
		o.Expect(svcRoute).ShouldNot(o.Equal(""))

		g.By("Access the route before network policy creation")
		var svcErr error
		var routeCurlOutput []byte
		o.Eventually(func() string {
			routeCurlOutput, svcErr = exec.Command("bash", "-c", "curl -sI "+svcRoute).Output()
			if svcErr != nil {
				e2e.Logf("Wait for service to be accessible through route, %v", svcErr)
			}
			return string(routeCurlOutput)
		}, "15s", "5s").Should(o.ContainSubstring("200 OK"), fmt.Sprintf("Service inaccessible through route %s", string(routeCurlOutput)))

		g.By("Create a network policy in namespace")
		otputils.CreateResourceFromFile(oc, ns, allowFromAllNSNetworkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-from-all-namespaces"))

		g.By("Access the route after network policy creation")
		routeCurlOutput, svcErr = exec.Command("bash", "-c", "curl -sI "+svcRoute).Output()
		o.Expect(svcErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(string(routeCurlOutput), "200 OK")).To(o.BeTrue())

	})

	g.It("[JIRA:Networking][OTP] 75540-Network Policy Validation", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			networkPolicyFile   = filepath.Join(buildPruningBaseDir, "networkpolicy/netpol-30920-75540.yaml")
		)
		g.By("Verify the network policy is not created with invalid value")
		oc.SetupProject()
		ns := oc.Namespace()
		o.Expect(otputils.CreateResourceFromFileWithError(oc, ns, networkPolicyFile)).To(o.HaveOccurred())
	})

	g.It("[JIRA:Networking][OTP] 70009-Pod IP is missing from OVN DB AddressSet when using allow-namespace-only network policy", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking")
			allowSameNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-same-namespace.yaml")
			pingPodNodeTemplate          = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("This case requires 1 nodes, but the cluster has none")
		}

		g.By("1. Get namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("2. Create a network policy in namespace")
		otputils.CreateResourceFromFile(oc, ns, allowSameNSNetworkPolicyFile)
		output, err := oc.AsAdmin().Run("get").Args("networkpolicy", "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-same-namespace"))

		ovnNodePod := otputils.OvnkubeNodePod(oc, nodeList.Items[0].Name)
		o.Expect(ovnNodePod).NotTo(o.BeEmpty())

		g.By("3. Check the acl from the port-group from the OVNK leader ovnkube-node")
		listPGCmd := fmt.Sprintf("ovn-nbctl find port-group | grep -C 2 '%s\\:allow-same-namespace'", ns)
		listPGCOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnNodePod, "ovnkube-controller", listPGCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listPGCOutput).NotTo(o.BeEmpty())
		e2e.Logf("Output %s", listPGCOutput)

		g.By("4. Check the addresses in ACL's address-set is empty")
		var PGCMap map[string]string
		PGCMap = otputils.NbContructToMap(listPGCOutput)
		acls := strings.Split(strings.Trim(PGCMap["acls"], "[]"), ", ")
		o.Expect(len(acls)).To(o.Equal(2))

		listAclCmd := fmt.Sprintf("ovn-nbctl list acl %s", strings.Join(acls, " "))
		listAclOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnNodePod, "ovnkube-controller", listAclCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAclOutput).NotTo(o.BeEmpty())

		regex := `\{\$(\w+)\}`
		re := regexp.MustCompile(regex)
		addrSetNames := re.FindAllString(listAclOutput, -1)
		if len(addrSetNames) == 0 {
			e2e.Fail("No matched address_set name found")
		}

		var trimmedAddrSetNames []string
		for _, rawName := range addrSetNames {
			trimmedAddrSetNames = append(trimmedAddrSetNames, strings.Trim(rawName, "{$}"))
		}

		for _, addrSetName := range trimmedAddrSetNames {
			o.Expect(addrSetName).NotTo(o.BeEmpty())
			listAddressSetCmd := fmt.Sprintf("ovn-nbctl list address_set %s", addrSetName)
			listAddrOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnNodePod, "ovnkube-controller", listAddressSetCmd)
			o.Expect(listErr).NotTo(o.HaveOccurred())
			o.Expect(listAddrOutput).NotTo(o.BeEmpty())
			AddrMap := otputils.NbContructToMap(listAddrOutput)
			addrs := strings.Trim(AddrMap["addresses"], "[]")
			o.Expect(addrs).To(o.BeEmpty())
		}

		g.By("5. Create a hello pod on non existent node")
		nonexistNodeName := "doesnotexist-" + otputils.GetRandomString()
		pod1 := otputils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns,
			Nodename:  nonexistNodeName,
			Template:  pingPodNodeTemplate,
		}
		pod1.CreatePingPodNode(oc)

		g.By("6. Verify address is not added to address-set")
		ovnNodePod = otputils.OvnkubeNodePod(oc, nodeList.Items[0].Name)
		for _, addrSetName := range trimmedAddrSetNames {
			listAddressSetCmd := fmt.Sprintf("ovn-nbctl list address_set %s", addrSetName)
			listAddrOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnNodePod, "ovnkube-controller", listAddressSetCmd)
			o.Expect(listErr).NotTo(o.HaveOccurred())
			o.Expect(listAddrOutput).NotTo(o.BeEmpty())
			AddrMap := otputils.NbContructToMap(listAddrOutput)
			addrs := strings.Trim(AddrMap["addresses"], "[]")
			o.Expect(addrs).To(o.BeEmpty())
		}

		g.By("7. Delete the pods that did not reach running state and create it with valid node name")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1.Name, "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		pod1.Nodename = nodeList.Items[0].Name
		pod1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("8. Verify address is added to address-set")
		ipStack := otputils.CheckIPStackType(oc)
		Pod1IP, Pod1IPv4 := otputils.GetPodIP(oc, ns, pod1.Name)
		ovnNodePod = otputils.OvnkubeNodePod(oc, nodeList.Items[0].Name)
		for _, addrSetName := range trimmedAddrSetNames {
			listAddressSetCmd := fmt.Sprintf("ovn-nbctl list address_set %s", addrSetName)
			listAddrOutput, listErr := otputils.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnNodePod, "ovnkube-controller", listAddressSetCmd)
			o.Expect(listErr).NotTo(o.HaveOccurred())
			o.Expect(listAddrOutput).NotTo(o.BeEmpty())
			AddrMap := otputils.NbContructToMap(listAddrOutput)
			addrs := strings.Trim(AddrMap["addresses"], "[\"]")
			o.Expect(addrs).NotTo(o.BeEmpty())

			if ipStack == "ipv6single" || ipStack == "ipv4single" {
				o.Expect(addrs == Pod1IP).To(o.BeTrue())
			} else if strings.Contains(addrSetName, "_v4") {
				o.Expect(addrs == Pod1IPv4).To(o.BeTrue())
			} else {
				o.Expect(addrs == Pod1IP).To(o.BeTrue())
			}
		}
	})

	g.It("[JIRA:Networking][OTP] 83735-Verify NP with label npprotection/blockdeletion=true label can not be deleted after VAP is applied.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			networkpolicyFile1  = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-egress.yaml")
			networkpolicyFile2  = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			vapFile             = filepath.Join(buildPruningBaseDir, "networkpolicy/vap-npprotection-blockdeletion.yaml")
			vapName             = "fine-grained-network-policy-protection"
			npName1             = "default-deny-egress"
			npName2             = "default-deny-ingress"
			matchLabelKey       = "npprotection/blockdeletion"
			expectedDenyMessage = "Cannot delete NetworkPolicy with 'npprotection/blockdeletion: true' label. This policy is not allowed for deletion."
			networpolicyFiles   = []string{networkpolicyFile1, networkpolicyFile2}
			npNames             = []string{npName1, npName2}
		)
		g.By("1. Create a namespace for default network, and a UDN namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		allNS := []string{ns1, ns2}

		g.By("2. Create a networkpolicy in each namespace and label them with npprotection-blockdeletion=true label.")
		for i, ns := range allNS {
			otputils.CreateResourceFromFile(oc, ns, networpolicyFiles[i])
			output, err := oc.AsAdmin().Run("get").Args("-n", ns, "networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, npNames[i])).To(o.BeTrue())
			defer oc.AsAdmin().Run("label").Args("-n", ns, "networkpolicy", npNames[i], fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err = oc.AsAdmin().Run("label").Args("-n", ns, "networkpolicy", npNames[i], fmt.Sprintf("%s=%s", matchLabelKey, "true")).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("3. Apply VAP with npprotection-blockdeletion")
		defer oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "remove-cluster-role-from-user", "cluster-admin", oc.Username()).Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-cluster-role-to-user", "cluster-admin", oc.Username()).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		defer otputils.RemoveResource(oc, true, true, "validatingadmissionpolicy", vapName)
		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", vapFile).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err := oc.Run("get").Args("validatingadmissionpolicy.admissionregistration.k8s.io").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, vapName)).To(o.BeTrue())

		// wait a little to let VAP take effect
		time.Sleep(3 * time.Second)

		g.By("4. Verify the networkpolicy can not be deleted.")
		for i, ns := range allNS {
			output, err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", npNames[i], "-n", ns).Output()
			o.Expect(err).To(o.HaveOccurred())
			o.Expect(strings.Contains(output, expectedDenyMessage)).To(o.BeTrue())
		}

		g.By("5. Delete the VAP, verify the networkpolicy can be deleted.")
		otputils.RemoveResource(oc, true, true, "validatingadmissionpolicy", "fine-grained-network-policy-protection")

		for i, ns := range allNS {
			output, err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", npNames[i], "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			expectedMessage := "networkpolicy.networking.k8s.io \"" + npNames[i] + "\" deleted"
			o.Expect(strings.Contains(output, expectedMessage)).To(o.BeTrue())
		}
	})

})

var _ = g.Describe("[sig-network] SDN networkpolicy", func() {
	//This case will only be run in perf stress ci which can be deployed for stress testing.
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-networkpolicy-stress")

	g.BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP] 69234-high memory usage on ovnkube-master leader pods on some clusters when a network policy is deleted.", g.Serial, func() {
		var (
			buildPruningBaseDir           = testdata.FixturePath("networking")
			ingressNPPolicyTemplate       = filepath.Join(buildPruningBaseDir, "networkpolicy/generic-networkpolicy-template.yaml")
			matchLabelKey                 = "kubernetes.io/metadata.Name"
			master_port             int32 = 8100
		)

		g.By("0. Get namespace.\n")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("1. Get port from ovnk-master leader pod.\n")
		ovnMasterPodName := otputils.GetOVNKMasterPod(oc)
		ovnMasterPodNames := otputils.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-control-plane")
		var port string
		for _, ovnPod := range ovnMasterPodNames {
			if ovnPod == ovnMasterPodName {
				port = strconv.Itoa(int(master_port))
				break
			}
			master_port++
		}

		g.By("2. Get initial pprof goroutine value from ovnk-master leader after enabling forwarding.\n")
		cmd, _, _, err := oc.AsAdmin().WithoutNamespace().Run("port-forward").Args("-n", "openshift-ovn-kubernetes", ovnMasterPodName, port+":29103", "--request-timeout=40s").Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer cmd.Process.Kill()
		output, err := exec.Command("bash", "-c", "ps -ef | grep 29103").Output()
		e2e.Logf("output is: %s", output)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring(ovnMasterPodName))

		// wait port start listening
		checkErr := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 100*time.Second, false, func(cxt context.Context) (bool, error) {
			checkOutput, _ := exec.Command("bash", "-c", "lsof -iTCP:"+port+" -sTCP:LISTEN").Output()
			// no need to check error since some system output stderr for valid result
			if len(checkOutput) != 0 {
				return true, nil
			}
			e2e.Logf("Port is not listening, trying again...")
			return false, nil
		})
		o.Expect(checkErr).NotTo(o.HaveOccurred(), "Port cannot listen")

		getGoroutineOut := "curl -ks --noproxy localhost http://localhost:" + port + "/debug/pprof/goroutine\\?debug\\=1 | grep -C 1 'periodicallyRetryResources' | awk 'NR==1{print $1}'"
		PreGoroutineOut, err := exec.Command("bash", "-c", getGoroutineOut).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(PreGoroutineOut).NotTo(o.BeEmpty())
		e2e.Logf("PreGoroutineOut is: %s", PreGoroutineOut)

		g.By("3. Get initial ovnk-master pod memory usage.\n")
		checkMemoryCmd := fmt.Sprintf(`oc -n openshift-ovn-kubernetes adm top pod | awk '$1=="%s" {print $1,$3}'`, ovnMasterPodName)
		checkMemory1, err := exec.Command("bash", "-c", checkMemoryCmd).CombinedOutput()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Repeat creating, deleting then recreating same network policy 15 times.\n")
		networkPolicyResource := otputils.NetworkPolicyResource{
			Name:             "ingress-networkpolicy",
			Namespace:        ns,
			Policy:           "ingress",
			PolicyType:       "Ingress",
			Direction1:       "from",
			NamespaceSel1:    "matchLabels",
			NamespaceSelKey1: matchLabelKey,
			NamespaceSelVal1: ns,
			Template:         ingressNPPolicyTemplate,
		}
		for i := 0; i < 15; i++ {
			// Create network policy
			networkPolicyResource.CreateNetworkPolicy(oc)
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, networkPolicyResource.Name)).To(o.BeTrue())

			// Delete network policy
			otputils.RemoveResource(oc, true, true, "networkpolicy", networkPolicyResource.Name, "-n", ns)
		}

		g.By("5. Compare the goroutine call value between pre and post output.\n")
		PostGoroutineOut, err := exec.Command("bash", "-c", getGoroutineOut).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(PostGoroutineOut).NotTo(o.BeEmpty())
		e2e.Logf("PostGoroutineOut is: %s", PostGoroutineOut)
		o.Expect(string(PreGoroutineOut) == string(PostGoroutineOut)).To(o.BeTrue())

		g.By("6. Verify ovnk-master pod memory usage should be the same as previous.\n")
		// wait for ovnk-master leader pod to be stable
		checkErr = wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
			checkMemory2, err := exec.Command("bash", "-c", checkMemoryCmd).CombinedOutput()
			o.Expect(err).NotTo(o.HaveOccurred())
			if string(checkMemory2) == string(checkMemory1) {
				e2e.Logf("Memory usage is the same as previous.")
				return true, nil
			}
			e2e.Logf("%v,Waiting for ovnk-master pod stable, try again ...,", err)
			return false, nil
		})
		o.Expect(checkErr).NotTo(o.HaveOccurred(), "Check the memory usage timeout.")
	})
})
