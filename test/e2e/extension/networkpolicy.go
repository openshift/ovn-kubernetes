package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
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

	"github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN networkpolicy", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-networkpolicy", compat_otp.KubeConfigPath())

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	// author: zzhao@redhat.com
	g.It("Author:zzhao-Critical-49076-[FdpOvnOvs]-service domain can be resolved when egress type is enabled", func() {
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
		createResourceFromFile(oc, oc.Namespace(), testPodFile)
		createResourceFromFile(oc, oc.Namespace(), helloSdnFile)
		err := waitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		err = waitForPodWithLabelReady(oc, oc.Namespace(), "name=hellosdn")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=hellosdn not ready")

		g.By("create egress and ingress type networkpolicy")
		createResourceFromFile(oc, oc.Namespace(), egressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-egress"))
		createResourceFromFile(oc, oc.Namespace(), ingressTypeFile)
		output, err = oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-ingress"))

		g.By("check hellosdn pods can reolsve the dns after apply the networkplicy")
		helloSdnName := getPodName(oc, oc.Namespace(), "name=hellosdn")
		digOutput, err := e2eoutput.RunHostCmd(oc.Namespace(), helloSdnName[0], "dig kubernetes.default")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("connection timed out"))

		g.By("check test-pods can reolsve the dns after apply the networkplicy")
		testPodName := getPodName(oc, oc.Namespace(), "name=test-pods")
		digOutput, err = e2eoutput.RunHostCmd(oc.Namespace(), testPodName[0], "dig kubernetes.default")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("connection timed out"))

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-Critical-49186-[FdpOvnOvs] [Bug 2035336] Networkpolicy egress rule should work for statefulset pods.", func() {
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
		createResourceFromFile(oc, ns1, helloStatefulsetFile)
		err := waitForPodWithLabelReady(oc, ns1, "app=hello")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label app=hello not ready")
		helloPodName := getPodName(oc, ns1, "app=hello")

		g.By("3. Create networkpolicy with egress rule in first namespace.")
		createResourceFromFile(oc, ns1, egressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-egress-to-red"))

		g.By("4. Create second namespace.")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("5. Create test pods in second namespace.")
		createResourceFromFile(oc, ns2, testPodFile)
		err = waitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		g.By("6. Add label to first test pod in second namespace.")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "team=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		testPodName := getPodName(oc, ns2, "name=test-pods")
		err = compat_otp.LabelPod(oc, ns2, testPodName[0], "type=red")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Get IP of the test pods in second namespace.")
		testPodIP1 := getPodIPv4(oc, ns2, testPodName[0])
		testPodIP2 := getPodIPv4(oc, ns2, testPodName[1])

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
			err := waitForPodWithLabelReady(oc, ns1, "app=hello")
			compat_otp.AssertWaitPollNoErr(err, "this pod with label app=hello not ready")
		}

		g.By("9. Again checking networkpolicy works.")
		output, err = e2eoutput.RunHostCmd(ns1, helloPodName[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(testPodIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("Hello OpenShift"))
		_, err = e2eoutput.RunHostCmd(ns1, helloPodName[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(testPodIP2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))

	})

	// author: anusaxen@redhat.com
	g.It("Author:anusaxen-High-49437-[FdpOvnOvs] [BZ 2037647] Ingress network policy shouldn't be overruled by egress network policy on another pod", func() {
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
		podns1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		podns1.createPingPodNode(oc)
		waitPodReady(oc, podns1.namespace, podns1.name)

		g.By("create default allow egress type networkpolicy in first namespace")
		createResourceFromFile(oc, ns1, egressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-allow-egress"))

		g.By("Create Second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()
		g.By("create a hello-pod on 2nd namesapce on same node as first namespace")
		pod1Ns2 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns2,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1Ns2.createPingPodNode(oc)
		waitPodReady(oc, pod1Ns2.namespace, pod1Ns2.name)

		g.By("create another hello-pod on 2nd namesapce but on different node")
		pod2Ns2 := pingPodResourceNode{
			name:      "hello-pod-other-node",
			namespace: ns2,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod2Ns2.createPingPodNode(oc)
		waitPodReady(oc, pod2Ns2.namespace, pod2Ns2.name)

		helloPodNameNs2 := getPodName(oc, ns2, "name=hello-pod")

		g.By("create default deny ingress type networkpolicy in 2nd namespace")
		createResourceFromFile(oc, ns2, ingressTypeFile)
		output, err = oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-ingress"))

		g.By("3. Get IP of the test pods in second namespace.")
		hellopodIP1Ns2 := getPodIPv4(oc, ns2, helloPodNameNs2[0])
		hellopodIP2Ns2 := getPodIPv4(oc, ns2, helloPodNameNs2[1])

		g.By("4. Curl both ns2 pods from ns1.")
		_, err = e2eoutput.RunHostCmd(ns1, podns1.name, "curl --connect-timeout 5  -s "+net.JoinHostPort(hellopodIP1Ns2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))
		_, err = e2eoutput.RunHostCmd(ns1, podns1.name, "curl --connect-timeout 5  -s "+net.JoinHostPort(hellopodIP2Ns2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))
	})

	// author: anusaxen@redhat.com
	// modified by: asood@redhat.com
	g.It("NonHyperShiftHOST-Author:anusaxen-Medium-49686-[FdpOvnOvs] network policy with ingress rule with ipBlock", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking")
			ipBlockIngressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-dual-CIDRs-template.yaml")
			ipBlockIngressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-single-CIDR-template.yaml")
			pingPodNodeTemplate          = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := checkIPStackType(oc)
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
		pod1ns1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1ns1.createPingPodNode(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod2ns1.createPingPodNode(oc)
		waitPodReady(oc, pod2ns1.namespace, pod2ns1.name)

		g.By("create 3rd hello pod in ns1")
		pod3ns1 := pingPodResourceNode{
			name:      "hello-pod3",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod3ns1.createPingPodNode(oc)
		waitPodReady(oc, pod3ns1.namespace, pod3ns1.name)

		helloPod1ns1IPv6, helloPod1ns1IPv4 := getPodIP(oc, ns1, pod1ns1.name)
		helloPod1ns1IPv4WithCidr := helloPod1ns1IPv4 + "/32"
		helloPod1ns1IPv6WithCidr := helloPod1ns1IPv6 + "/128"

		if ipStackType == "dualstack" {
			g.By("create ipBlock Ingress Dual CIDRs Policy in ns1")
			npIPBlockNS1 := ipBlockCIDRsDual{
				name:      "ipblock-dual-cidrs-ingress",
				template:  ipBlockIngressTemplateDual,
				cidrIpv4:  helloPod1ns1IPv4WithCidr,
				cidrIpv6:  helloPod1ns1IPv6WithCidr,
				namespace: ns1,
			}
			npIPBlockNS1.createipBlockCIDRObjectDual(oc)

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

			npIPBlockNS1 := ipBlockCIDRsSingle{
				name:      "ipblock-single-cidr-ingress",
				template:  ipBlockIngressTemplateSingle,
				cidr:      helloPod1ns1IPWithCidr,
				namespace: ns1,
			}
			npIPBlockNS1.createipBlockCIDRObjectSingle(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-ingress"))
		}
		g.By("Checking connectivity from pod1 to pod3")
		CurlPod2PodPass(oc, ns1, "hello-pod1", ns1, "hello-pod3")

		g.By("Checking connectivity from pod2 to pod3")
		CurlPod2PodFail(oc, ns1, "hello-pod2", ns1, "hello-pod3")

		g.By("Create 2nd namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("create 1st hello pod in ns2")
		pod1ns2 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns2,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod1ns2.createPingPodNode(oc)
		waitPodReady(oc, pod1ns2.namespace, pod1ns2.name)

		g.By("create 2nd hello pod in ns2")
		pod2ns2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns2,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod2ns2.createPingPodNode(oc)
		waitPodReady(oc, pod2ns2.namespace, pod2ns2.name)

		g.By("Checking connectivity from pod1ns2 to pod3ns1")
		CurlPod2PodFail(oc, ns2, "hello-pod1", ns1, "hello-pod3")

		g.By("Checking connectivity from pod2ns2 to pod1ns1")
		CurlPod2PodFail(oc, ns2, "hello-pod2", ns1, "hello-pod1")

		if ipStackType == "dualstack" {
			g.By("Delete networkpolicy from ns1")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-dual-cidrs-ingress", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			g.By("Delete networkpolicy from ns1")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", "ipblock-single-cidr-ingress", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		helloPod2ns2IPv6, helloPod2ns2IPv4 := getPodIP(oc, ns2, pod2ns2.name)
		helloPod2ns2IPv4WithCidr := helloPod2ns2IPv4 + "/32"
		helloPod2ns2IPv6WithCidr := helloPod2ns2IPv6 + "/128"

		if ipStackType == "dualstack" {
			g.By("create ipBlock Ingress Dual CIDRs Policy in ns1 again but with ipblock for pod2 ns2")
			npIPBlockNS1New := ipBlockCIDRsDual{
				name:      "ipblock-dual-cidrs-ingress",
				template:  ipBlockIngressTemplateDual,
				cidrIpv4:  helloPod2ns2IPv4WithCidr,
				cidrIpv6:  helloPod2ns2IPv6WithCidr,
				namespace: ns1,
			}
			npIPBlockNS1New.createipBlockCIDRObjectDual(oc)
		} else {
			// For singlestack getPodIP returns second parameter empty therefore use helloPod2ns2IPv6 variable but append it
			// with CIDR based on stack.
			var helloPod2ns2IPWithCidr string
			if ipStackType == "ipv6single" {
				helloPod2ns2IPWithCidr = helloPod2ns2IPv6WithCidr
			} else {
				helloPod2ns2IPWithCidr = helloPod2ns2IPv6 + "/32"
			}

			npIPBlockNS1New := ipBlockCIDRsSingle{
				name:      "ipblock-single-cidr-ingress",
				template:  ipBlockIngressTemplateSingle,
				cidr:      helloPod2ns2IPWithCidr,
				namespace: ns1,
			}
			npIPBlockNS1New.createipBlockCIDRObjectSingle(oc)
		}
		g.By("Checking connectivity from pod2 ns2 to pod3 ns1")
		CurlPod2PodPass(oc, ns2, "hello-pod2", ns1, "hello-pod3")

		g.By("Checking connectivity from pod1 ns2 to pod3 ns1")
		CurlPod2PodFail(oc, ns2, "hello-pod1", ns1, "hello-pod3")

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
		CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod3")

		g.By("Checking connectivity from pod1ns2 to pod3ns1")
		CurlPod2PodPass(oc, ns2, "hello-pod1", ns1, "hello-pod3")

		g.By("Checking connectivity from pod2ns2 to pod1ns1 on IPv4 interface")
		CurlPod2PodPass(oc, ns2, "hello-pod2", ns1, "hello-pod1")

	})

	// author: zzhao@redhat.com
	g.It("[Level0] Author:zzhao-Critical-49696-[FdpOvnOvs] mixed ingress and egress policies can work well", func() {
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
		createResourceFromFile(oc, ns1, testPodFile)
		createResourceFromFile(oc, ns1, helloSdnFile)
		err := waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		err = waitForPodWithLabelReady(oc, ns1, "name=hellosdn")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=hellosdn not ready")
		hellosdnPodNameNs1 := getPodName(oc, ns1, "name=hellosdn")

		g.By("create egress type networkpolicy in ns1")
		createResourceFromFile(oc, ns1, egressTypeFile)

		g.By("create ingress type networkpolicy in ns1")
		createResourceFromFile(oc, ns1, ingressTypeFile)

		g.By("create second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("create test pods in second namespace")
		createResourceFromFile(oc, ns2, helloSdnFile)
		err = waitForPodWithLabelReady(oc, ns2, "name=hellosdn")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=hellosdn not ready")

		g.By("Get IP of the test pods in second namespace.")
		hellosdnPodNameNs2 := getPodName(oc, ns2, "name=hellosdn")
		hellosdnPodIP1Ns2 := getPodIPv4(oc, ns2, hellosdnPodNameNs2[0])

		g.By("curl from ns1 hellosdn pod to ns2 pod")
		_, err = e2eoutput.RunHostCmd(ns1, hellosdnPodNameNs1[0], "curl --connect-timeout 5  -s "+net.JoinHostPort(hellosdnPodIP1Ns2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(err.Error()).Should(o.ContainSubstring("exit status 28"))

	})

	// author: anusaxen@redhat.com
	g.It("Author:anusaxen-High-46246-[FdpOvnOvs] Network Policies should work with OVNKubernetes when traffic hairpins back to the same source through a service", func() {
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

		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns, pod1.name)

		g.By("create 2nd hello pod in same namespace but on different node")

		pod2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, ns, pod2.name)

		g.By("Create a test service backing up both the above pods")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "", //This no value parameter will be ignored
			template:              genericServiceTemplate,
		}
		svc.ipFamilyPolicy = "SingleStack"
		svc.createServiceFromParams(oc)

		g.By("create allow-from-same-namespace ingress networkpolicy in ns")
		createResourceFromFile(oc, ns, allowfromsameNS)

		g.By("curl from hello-pod1 to hello-pod2")
		CurlPod2PodPass(oc, ns, "hello-pod1", ns, "hello-pod2")

		g.By("curl from hello-pod2 to hello-pod1")
		CurlPod2PodPass(oc, ns, "hello-pod2", ns, "hello-pod1")

		for i := 0; i < 5; i++ {

			g.By("curl from hello-pod1 to service:port")
			CurlPod2SvcPass(oc, ns, ns, "hello-pod1", "test-service")

			g.By("curl from hello-pod2 to service:port")
			CurlPod2SvcPass(oc, ns, ns, "hello-pod2", "test-service")
		}

		g.By("Make sure pods are curl'able from respective nodes")
		CurlNode2PodPass(oc, pod1.nodename, ns, "hello-pod1")
		CurlNode2PodPass(oc, pod2.nodename, ns, "hello-pod2")

		ipStackType := checkIPStackType(oc)

		if ipStackType == "dualstack" {
			g.By("Delete testservice from ns")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", "test-service", "-n", ns).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			g.By("Checking pod to svc:port behavior now on with PreferDualStack Service")
			svc.ipFamilyPolicy = "PreferDualStack"
			svc.createServiceFromParams(oc)
			for i := 0; i < 5; i++ {
				g.By("curl from hello-pod1 to service:port")
				CurlPod2SvcPass(oc, ns, ns, "hello-pod1", "test-service")

				g.By("curl from hello-pod2 to service:port")
				CurlPod2SvcPass(oc, ns, ns, "hello-pod2", "test-service")
			}
		}
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Author:huirwang-High-41879-[FdpOvnOvs] ipBlock should not ignore all other cidr's apart from the last one specified	", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking")
			ipBlockIngressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-dual-multiple-CIDRs-template.yaml")
			ipBlockIngressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-single-multiple-CIDRs-template.yaml")
			testPodFile                  = filepath.Join(buildPruningBaseDir, "testpod.yaml")
		)

		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.Skip("This case requires dualstack or Single Stack IPv6 cluster")
		}

		g.By("Create a namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("create test pods in ns1")
		createResourceFromFile(oc, ns1, testPodFile)
		err := waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		g.By("Scale test pods to 5")
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=5", "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		g.By("Get 3 test pods's podname and IPs")
		testPodName := getPodName(oc, ns1, "name=test-pods")
		testPod1IPv6, testPod1IPv4 := getPodIP(oc, ns1, testPodName[0])
		testPod1IPv4WithCidr := testPod1IPv4 + "/32"
		testPod1IPv6WithCidr := testPod1IPv6 + "/128"
		testPod2IPv6, testPod2IPv4 := getPodIP(oc, ns1, testPodName[1])
		testPod2IPv4WithCidr := testPod2IPv4 + "/32"
		testPod2IPv6WithCidr := testPod2IPv6 + "/128"
		testPod3IPv6, testPod3IPv4 := getPodIP(oc, ns1, testPodName[2])
		testPod3IPv4WithCidr := testPod3IPv4 + "/32"
		testPod3IPv6WithCidr := testPod3IPv6 + "/128"

		if ipStackType == "dualstack" {
			g.By("create ipBlock Ingress Dual CIDRs Policy in ns1")

			npIPBlockNS1 := ipBlockCIDRsDual{
				name:      "ipblock-dual-cidrs-ingress-41879",
				template:  ipBlockIngressTemplateDual,
				cidrIpv4:  testPod1IPv4WithCidr,
				cidrIpv6:  testPod1IPv6WithCidr,
				cidr2Ipv4: testPod2IPv4WithCidr,
				cidr2Ipv6: testPod2IPv6WithCidr,
				cidr3Ipv4: testPod3IPv4WithCidr,
				cidr3Ipv6: testPod3IPv6WithCidr,
				namespace: ns1,
			}
			npIPBlockNS1.createIPBlockMultipleCIDRsObjectDual(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-dual-cidrs-ingress-41879"))
		} else {

			npIPBlockNS1 := ipBlockCIDRsSingle{
				name:      "ipblock-single-cidr-ingress-41879",
				template:  ipBlockIngressTemplateSingle,
				cidr:      testPod1IPv6WithCidr,
				cidr2:     testPod2IPv6WithCidr,
				cidr3:     testPod3IPv6WithCidr,
				namespace: ns1,
			}
			npIPBlockNS1.createIPBlockMultipleCIDRsObjectSingle(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-ingress-41879"))
		}

		g.By("Checking connectivity from pod1 to pod5")
		CurlPod2PodPass(oc, ns1, testPodName[0], ns1, testPodName[4])

		g.By("Checking connectivity from pod2 to pod5")
		CurlPod2PodPass(oc, ns1, testPodName[1], ns1, testPodName[4])

		g.By("Checking connectivity from pod3 to pod5")
		CurlPod2PodPass(oc, ns1, testPodName[2], ns1, testPodName[4])

		g.By("Checking connectivity from pod4 to pod5")
		CurlPod2PodFail(oc, ns1, testPodName[3], ns1, testPodName[4])

	})

	// author: asood@redhat.com
	g.It("Author:asood-Medium-46807-[FdpOvnOvs] network policy with egress rule with ipBlock", func() {
		var (
			buildPruningBaseDir         = testdata.FixturePath("networking")
			ipBlockEgressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-dual-CIDRs-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-single-CIDR-template.yaml")
			pingPodNodeTemplate         = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("Obtain the namespace")
		ns1 := oc.Namespace()

		g.By("create 1st hello pod in ns1")
		pod1ns1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1ns1.createPingPodNode(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod2ns1.createPingPodNode(oc)
		waitPodReady(oc, pod2ns1.namespace, pod2ns1.name)

		g.By("create 3rd hello pod in ns1")
		pod3ns1 := pingPodResourceNode{
			name:      "hello-pod3",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod3ns1.createPingPodNode(oc)
		waitPodReady(oc, pod3ns1.namespace, pod3ns1.name)

		helloPod1ns1IP1, helloPod1ns1IP2 := getPodIP(oc, ns1, pod1ns1.name)

		if ipStackType == "dualstack" {
			helloPod1ns1IPv6WithCidr := helloPod1ns1IP1 + "/128"
			helloPod1ns1IPv4WithCidr := helloPod1ns1IP2 + "/32"
			g.By("create ipBlock Egress Dual CIDRs Policy in ns1")
			npIPBlockNS1 := ipBlockCIDRsDual{
				name:      "ipblock-dual-cidrs-egress",
				template:  ipBlockEgressTemplateDual,
				cidrIpv4:  helloPod1ns1IPv4WithCidr,
				cidrIpv6:  helloPod1ns1IPv6WithCidr,
				namespace: ns1,
			}
			npIPBlockNS1.createipBlockCIDRObjectDual(oc)

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-dual-cidrs-egress"))

		} else {
			if ipStackType == "ipv6single" {
				helloPod1ns1IPv6WithCidr := helloPod1ns1IP1 + "/128"
				npIPBlockNS1 := ipBlockCIDRsSingle{
					name:      "ipblock-single-cidr-egress",
					template:  ipBlockEgressTemplateSingle,
					cidr:      helloPod1ns1IPv6WithCidr,
					namespace: ns1,
				}
				npIPBlockNS1.createipBlockCIDRObjectSingle(oc)
			} else {
				helloPod1ns1IPv4WithCidr := helloPod1ns1IP1 + "/32"
				npIPBlockNS1 := ipBlockCIDRsSingle{
					name:      "ipblock-single-cidr-egress",
					template:  ipBlockEgressTemplateSingle,
					cidr:      helloPod1ns1IPv4WithCidr,
					namespace: ns1,
				}
				npIPBlockNS1.createipBlockCIDRObjectSingle(oc)
			}

			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress"))
		}
		g.By("Checking connectivity from pod2 to pod1")
		CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		g.By("Checking connectivity from pod2 to pod3")
		CurlPod2PodFail(oc, ns1, "hello-pod2", ns1, "hello-pod3")

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
		CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		g.By("Checking connectivity from pod2 to pod3")
		CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod3")

	})

	// author: asood@redhat.com
	g.It("Author:asood-Medium-46808-[FdpOvnOvs] network policy with egress rule with ipBlock and except", func() {
		var (
			buildPruningBaseDir         = testdata.FixturePath("networking")
			ipBlockEgressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-except-dual-CIDRs-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-except-single-CIDR-template.yaml")
			pingPodNodeTemplate         = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("Obtain the namespace")
		ns1 := oc.Namespace()

		g.By("create 1st hello pod in ns1 on node[0]")
		pod1ns1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1ns1.createPingPodNode(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		g.By("create 2nd hello pod in ns1 on node[0]")
		pod2ns1 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod2ns1.createPingPodNode(oc)
		waitPodReady(oc, pod2ns1.namespace, pod2ns1.name)

		g.By("create 3rd hello pod in ns1 on node[1]")
		pod3ns1 := pingPodResourceNode{
			name:      "hello-pod3",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod3ns1.createPingPodNode(oc)
		waitPodReady(oc, pod3ns1.namespace, pod3ns1.name)

		g.By("create 4th hello pod in ns1 on node[1]")
		pod4ns1 := pingPodResourceNode{
			name:      "hello-pod4",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod4ns1.createPingPodNode(oc)
		waitPodReady(oc, pod4ns1.namespace, pod4ns1.name)

		helloPod2ns1IP1, helloPod2ns1IP2 := getPodIP(oc, ns1, pod2ns1.name)
		if ipStackType == "dualstack" {
			hostSubnetCIDRIPv4, hostSubnetCIDRIPv6 := getNodeSubnetDualStack(oc, nodeList.Items[0].Name, "default")
			o.Expect(hostSubnetCIDRIPv6).NotTo(o.BeEmpty())
			o.Expect(hostSubnetCIDRIPv4).NotTo(o.BeEmpty())
			helloPod2ns1IPv6WithCidr := helloPod2ns1IP1 + "/128"
			helloPod2ns1IPv4WithCidr := helloPod2ns1IP2 + "/32"
			g.By("create ipBlock Egress CIDRs with except rule Policy in ns1 on dualstack")
			npIPBlockNS1 := ipBlockCIDRsExceptDual{
				name:           "ipblock-dual-cidrs-egress-except",
				template:       ipBlockEgressTemplateDual,
				cidrIpv4:       hostSubnetCIDRIPv4,
				cidrIpv4Except: helloPod2ns1IPv4WithCidr,
				cidrIpv6:       hostSubnetCIDRIPv6,
				cidrIpv6Except: helloPod2ns1IPv6WithCidr,
				namespace:      ns1,
			}
			npIPBlockNS1.createipBlockExceptObjectDual(oc)
			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-dual-cidrs-egress-except"))
		} else {
			if ipStackType == "ipv6single" {
				hostSubnetCIDRIPv6 := getNodeSubnet(oc, nodeList.Items[0].Name, "default")
				o.Expect(hostSubnetCIDRIPv6).NotTo(o.BeEmpty())
				helloPod2ns1IPv6WithCidr := helloPod2ns1IP1 + "/128"
				g.By("create ipBlock Egress CIDRs with except rule Policy in ns1 on IPv6 singlestack")
				npIPBlockNS1 := ipBlockCIDRsExceptSingle{
					name:      "ipblock-single-cidr-egress-except",
					template:  ipBlockEgressTemplateSingle,
					cidr:      hostSubnetCIDRIPv6,
					except:    helloPod2ns1IPv6WithCidr,
					namespace: ns1,
				}
				npIPBlockNS1.createipBlockExceptObjectSingle(oc, true)
			} else {
				hostSubnetCIDRIPv4 := getNodeSubnet(oc, nodeList.Items[0].Name, "default")
				o.Expect(hostSubnetCIDRIPv4).NotTo(o.BeEmpty())
				helloPod2ns1IPv4WithCidr := helloPod2ns1IP1 + "/32"
				g.By("create ipBlock Egress CIDRs with except rule Policy in ns1 on IPv4 singlestack")
				npIPBlockNS1 := ipBlockCIDRsExceptSingle{
					name:      "ipblock-single-cidr-egress-except",
					template:  ipBlockEgressTemplateSingle,
					cidr:      hostSubnetCIDRIPv4,
					except:    helloPod2ns1IPv4WithCidr,
					namespace: ns1,
				}
				npIPBlockNS1.createipBlockExceptObjectSingle(oc, true)
			}
			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress-except"))
		}
		g.By("Checking connectivity from pod3 to pod1")
		CurlPod2PodPass(oc, ns1, "hello-pod3", ns1, "hello-pod1")

		g.By("Checking connectivity from pod3 to pod2")
		CurlPod2PodFail(oc, ns1, "hello-pod3", ns1, "hello-pod2")

		g.By("Checking connectivity from pod3 to pod4")
		CurlPod2PodFail(oc, ns1, "hello-pod3", ns1, "hello-pod4")
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
		CurlPod2PodPass(oc, ns1, "hello-pod3", ns1, "hello-pod1")

		g.By("Checking connectivity from pod3 to pod2")
		CurlPod2PodPass(oc, ns1, "hello-pod3", ns1, "hello-pod2")

		g.By("Checking connectivity from pod3 to pod4")
		CurlPod2PodPass(oc, ns1, "hello-pod3", ns1, "hello-pod4")

	})

	// author: asood@redhat.com
	g.It("Author:asood-Medium-41082-Check ACL audit logs can be extracted", func() {
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
		ns1 := oc.Namespace()

		g.By("Enable ACL looging on the namespace ns1")
		aclSettings := aclSettings{DenySetting: "alert", AllowSetting: "alert"}
		err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", ns1, aclSettings.getJSONString()).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())

		g.By("create default deny ingress networkpolicy in ns1")
		createResourceFromFile(oc, ns1, ingressTypeFile)

		g.By("create allow same namespace networkpolicy in ns1")
		createResourceFromFile(oc, ns1, allowFromSameNS)

		g.By("create 1st hello pod in ns1")
		pod1ns1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1ns1.createPingPodNode(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}

		pod2ns1.createPingPodNode(oc)
		waitPodReady(oc, pod2ns1.namespace, pod2ns1.name)

		g.By("Checking connectivity from pod2 to pod1 to generate messages")
		CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		output, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "verdict=allow")).To(o.BeTrue())

	})
	// author: asood@redhat.com
	g.It("Author:asood-Medium-41407-[FdpOvnOvs] Check networkpolicy ACL audit message is logged with correct policy name", func() {
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
			namespaces[i] = oc.Namespace()
			compat_otp.By(fmt.Sprintf("Enable ACL looging on the namespace %s", namespaces[i]))
			aclSettings := aclSettings{DenySetting: "alert", AllowSetting: "warning"}
			err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", namespaces[i], aclSettings.getJSONString()).Execute()
			o.Expect(err1).NotTo(o.HaveOccurred())

			compat_otp.By(fmt.Sprintf("Create default deny ingress networkpolicy in %s", namespaces[i]))
			createResourceFromFile(oc, namespaces[i], ingressTypeFile)
			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(policyList[0]))

			compat_otp.By(fmt.Sprintf("Create allow same namespace networkpolicy in %s", namespaces[i]))
			createResourceFromFile(oc, namespaces[i], allowFromSameNS)
			output, err = oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(policyList[1]))

			pod := pingPodResourceNode{
				name:      "",
				namespace: namespaces[i],
				nodename:  "",
				template:  pingPodNodeTemplate,
			}
			for j := 0; j < 2; j++ {
				compat_otp.By(fmt.Sprintf("Create hello pod in %s", namespaces[i]))
				pod.name = "hello-pod" + strconv.Itoa(j)
				pod.nodename = nodeList.Items[j].Name
				pod.createPingPodNode(oc)
				waitPodReady(oc, pod.namespace, pod.name)
			}
			compat_otp.By(fmt.Sprintf("Checking connectivity from second pod to  first pod to generate messages in %s", namespaces[i]))
			CurlPod2PodPass(oc, namespaces[i], "hello-pod1", namespaces[i], "hello-pod0")
			oc.SetupProject()
		}

		output, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ACL logs for allow-from-same-namespace policy \n %s", output)
		// policy name truncated to allow-from-same-name in ACL log message
		for i := 0; i < len(namespaces); i++ {
			searchString := fmt.Sprintf("name=\"NP:%s:allow-from-same-name\", verdict=allow, severity=warning", namespaces[i])
			o.Expect(strings.Contains(output, searchString)).To(o.BeTrue())
			removeResource(oc, true, true, "networkpolicy", policyList[1], "-n", namespaces[i])
			CurlPod2PodFail(oc, namespaces[i], "hello-pod0", namespaces[i], "hello-pod1")
		}
		output, err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[1].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ACL logs for default-deny-ingress policy \n %s", output)
		for i := 0; i < len(namespaces); i++ {
			searchString := fmt.Sprintf("name=\"NP:%s:Ingress\", verdict=drop, severity=alert", namespaces[i])
			o.Expect(strings.Contains(output, searchString)).To(o.BeTrue())
		}

	})
	// author: asood@redhat.com
	g.It("Author:asood-NonPreRelease-Longduration-WRS-Medium-41080-V-BR.33-Check network policy ACL audit messages are logged to journald", func() {
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
			waitForNetworkOperatorState(oc, 100, 15, "True.*False.*False")
		}()
		_, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args(patchSResource, "-p", patchInfo, "--type=merge").Output()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		//Network operator needs to recreate the pods on a merge request, therefore give it enough time.
		waitForNetworkOperatorState(oc, 100, 15, "True.*False.*False")

		g.By("Obtain the namespace")
		ns1 := oc.Namespace()

		g.By("Enable ACL looging on the namespace ns1")
		aclSettings := aclSettings{DenySetting: "alert", AllowSetting: "alert"}
		err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", ns1, aclSettings.getJSONString()).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())

		g.By("create default deny ingress networkpolicy in ns1")
		createResourceFromFile(oc, ns1, ingressTypeFile)

		g.By("create allow same namespace networkpolicy in ns1")
		createResourceFromFile(oc, ns1, allowFromSameNS)

		g.By("create 1st hello pod in ns1")
		pod1ns1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1ns1.createPingPodNode(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns1,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}

		pod2ns1.createPingPodNode(oc)
		waitPodReady(oc, pod2ns1.namespace, pod2ns1.name)

		g.By("Checking connectivity from pod2 to pod1 to generate messages")
		CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		g.By("Checking messages are logged to journald")
		cmd := fmt.Sprintf("journalctl -t ovn-controller --since '1min ago'| grep 'verdict=allow'")
		output, journalctlErr := compat_otp.DebugNodeWithOptionsAndChroot(oc, nodeList.Items[0].Name, []string{"-q"}, "bin/sh", "-c", cmd)
		e2e.Logf("Output %s", output)
		o.Expect(journalctlErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "verdict=allow")).To(o.BeTrue())

	})

	// author: anusaxen@redhat.com
	g.It("NonHyperShiftHOST-Author:anusaxen-Medium-55287-[FdpOvnOvs] Default network policy ACLs to a namespace should not be present with arp but arp||nd for ARPAllowPolicies", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
		)
		g.By("This is for BZ 2095852")

		g.By("create new namespace")
		oc.SetupProject()

		g.By("create test pods")
		createResourceFromFile(oc, oc.Namespace(), testPodFile)
		err := waitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		g.By("create ingress default-deny type networkpolicy")
		createResourceFromFile(oc, oc.Namespace(), ingressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny"))

		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		o.Expect(ovnMasterPodName).NotTo(o.BeEmpty())
		g.By("get ACLs related to ns")
		//list ACLs only related namespace in test
		listACLCmd := "ovn-nbctl list ACL | grep -C 5 " + "NP:" + oc.Namespace() + " | grep -C 5 type=arpAllow"
		listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		e2e.Logf("Output %s", listOutput)
		o.Expect(listOutput).To(o.ContainSubstring("&& (arp || nd)"))
		o.Expect(listOutput).ShouldNot(o.ContainSubstring("&& arp"))
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-High-62524-[FdpOvnOvs] [NETWORKCUSIM] OVN address_set referenced in acl should not miss when networkpolicy name includes dot.", func() {
		// This is for customer bug https://issues.redhat.com/browse/OCPBUGS-4085
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			networkPolicyFile   = filepath.Join(buildPruningBaseDir, "networkpolicy/egress-ingress-62524.yaml")
		)
		g.By("Check cluster network type")

		g.By("Get namespace")
		ns := oc.Namespace()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "team-").Execute()
			}
		}()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "team=openshift-networking").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("create test pods")
		createResourceFromFile(oc, ns, testPodFile)
		err = waitForPodWithLabelReady(oc, ns, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPod := getPodName(oc, ns, "name=test-pods")

		g.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		g.By("create egress-ingress type networkpolicy")
		createResourceFromFile(oc, ns, networkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("egress-ingress-62524.test"))

		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		o.Expect(ovnMasterPodName).NotTo(o.BeEmpty())
		g.By("Verify the address_set exists for the specific acl")
		//list ACLs related to the networkpolicy name
		listACLCmd := "ovn-nbctl --data=bare --no-heading --format=table find acl | grep  egress-ingress-62524.test"
		listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listACLCmd)
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
			listAddrOutput, listAddrErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listAddressSetCmd)
			o.Expect(listAddrErr).NotTo(o.HaveOccurred())
			o.Expect(listAddrOutput).NotTo(o.BeEmpty())
		}

		g.By("Checking pods connectivity")
		CurlPod2PodPass(oc, ns, testPod[0], ns, pod1.name)
		CurlPod2PodFail(oc, ns, testPod[0], ns, testPod[1])

	})

	// author: asood@redhat.com
	g.It("Author:asood-NonHyperShiftHOST-Critical-65901-[FdpOvnOvs] [NETWORKCUSIM] Duplicate transactions should not be executed for network policy for every pod update.", func() {
		// Customer https://issues.redhat.com/browse/OCPBUGS-4659
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			networkPolicyFile   = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-ingress-red.yaml")
			testPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)

		compat_otp.By("Obtain the namespace")
		ns := oc.Namespace()

		compat_otp.By("Create a pod in namespace")
		pod := pingPodResource{
			name:      "test-pod",
			namespace: ns,
			template:  testPodTemplate,
		}
		pod.createPingPod(oc)
		waitPodReady(oc, pod.namespace, pod.name)
		_, labelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", pod.namespace, "pod", pod.name, "type=red").Output()
		o.Expect(labelErr).NotTo(o.HaveOccurred())

		compat_otp.By("Create a network policy")
		createResourceFromFile(oc, ns, networkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-ingress-to-red"))

		compat_otp.By("Obtain the transaction count to be 1")
		podIP1, _ := getPodIP(oc, ns, pod.name)

		podNodeName, podNodenameErr := compat_otp.GetPodNodeName(oc, ns, pod.name)
		o.Expect(podNodeName).NotTo(o.BeEmpty())
		o.Expect(podNodenameErr).NotTo(o.HaveOccurred())
		e2e.Logf("Node on which pod %s is running %s", pod.name, podNodeName)
		ovnKNodePod, ovnkNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", podNodeName)
		o.Expect(ovnKNodePod).NotTo(o.BeEmpty())
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, podNodeName)

		getCmd := fmt.Sprintf("cat /var/log/ovnkube/libovsdb.log | grep 'transacting operations' | grep '%s' ", podIP1)
		logContents, logErr1 := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", getCmd)
		o.Expect(logErr1).NotTo(o.HaveOccurred())
		e2e.Logf(fmt.Sprintf("Log content before label update \n %s", logContents))
		logLinesCount := len(strings.Split(logContents, "\n")) - 1

		compat_otp.By("Label the pods to see transaction count is unchanged")
		_, reLabelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", pod.namespace, "--overwrite", "pod", pod.name, "type=blue").Output()
		o.Expect(reLabelErr).NotTo(o.HaveOccurred())

		newLogContents, logErr2 := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", getCmd)
		o.Expect(logErr2).NotTo(o.HaveOccurred())
		e2e.Logf(fmt.Sprintf("Log content after label update \n %s", newLogContents))
		newLogLinesCount := len(strings.Split(newLogContents, "\n")) - 1
		o.Expect(logLinesCount).To(o.Equal(newLogLinesCount))

	})
	g.It("Author:asood-High-66085-[FdpOvnOvs] [NETWORKCUSIM] Creating egress network policies for allowing to same namespace and openshift dns in namespace prevents the pod from reaching its own service", func() {
		// https://issues.redhat.com/browse/OCPBUGS-4909
		var (
			buildPruningBaseDir        = testdata.FixturePath("networking")
			pingPodTemplate            = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			genericServiceTemplate     = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			allowToNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-to-same-namespace.yaml")
			allowToDNSNPolicyFile      = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-to-openshift-dns.yaml")
			podsInProject              = []string{"hello-pod-1", "other-pod"}
			svcURL                     string
		)

		compat_otp.By("Get first namespace and create another")
		ns := oc.Namespace()

		compat_otp.By("Create set of pods with different labels")
		for _, podItem := range podsInProject {
			pod1 := pingPodResource{
				name:      podItem,
				namespace: ns,
				template:  pingPodTemplate,
			}
			pod1.createPingPod(oc)
			waitPodReady(oc, ns, pod1.name)
		}
		compat_otp.By("Label the pods to ensure the pod does not serve the service")
		_, reLabelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns, "--overwrite", "pod", podsInProject[1], "name=other-pod").Output()
		o.Expect(reLabelErr).NotTo(o.HaveOccurred())

		compat_otp.By("Create a service for one of the pods")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "SingleStack",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "", //This no value parameter will be ignored
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		compat_otp.By("Check service status")
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("Obtain the service URL")
		svcURL = fmt.Sprintf("http://%s.%s.svc:27017", svc.servicename, svc.namespace)
		e2e.Logf("Service URL %s", svcURL)
		compat_otp.By("Check the connectivity to service from the pods in the namespace")
		for _, podItem := range podsInProject {
			output, err := e2eoutput.RunHostCmd(ns, podItem, "curl --connect-timeout 5 -s "+svcURL)
			o.Expect(strings.Contains(output, "Hello OpenShift!")).To(o.BeTrue())
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Create the network policies in the namespace")
		compat_otp.By("Create the allow to same namespace policy in the namespace")
		createResourceFromFile(oc, ns, allowToNSNetworkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-same-namespace"))
		compat_otp.By("Create the allow to DNS policy in the namespace")
		createResourceFromFile(oc, ns, allowToDNSNPolicyFile)
		output, err = oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-openshift-dns"))

		compat_otp.By("Create another pod to serve the service")
		anotherPod := pingPodResource{
			name:      "hello-pod-2",
			namespace: ns,
			template:  pingPodTemplate,
		}
		anotherPod.createPingPod(oc)
		waitPodReady(oc, ns, anotherPod.name)
		podsInProject = append(podsInProject, anotherPod.name)

		compat_otp.By("Check the connectivity to service again from the pods in the namespace")
		for _, eachPod := range podsInProject {
			output, err := e2eoutput.RunHostCmd(ns, eachPod, "curl --connect-timeout 5 -s "+svcURL)
			o.Expect(strings.Contains(output, "Hello OpenShift!")).To(o.BeTrue())
			o.Expect(err).NotTo(o.HaveOccurred())
		}
	})
	g.It("Author:asood-Medium-64787-[FdpOvnOvs] [NETWORKCUSIM] Network policy with duplicate egress rules (same CIDR block) fails to be recreated [Disruptive]", func() {
		// https://issues.redhat.com/browse/OCPBUGS-5835
		var (
			buildPruningBaseDir         = testdata.FixturePath("networking")
			ipBlockEgressTemplateDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-dual-multiple-CIDRs-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-egress-single-multiple-CIDRs-template.yaml")
			pingPodNodeTemplate         = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Obtain the namespace")
		ns := oc.Namespace()

		compat_otp.By("create a hello pod in namspace")
		podns := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		podns.createPingPodNode(oc)
		waitPodReady(oc, podns.namespace, podns.name)

		helloPodnsIP1, helloPodnsIP2 := getPodIP(oc, ns, podns.name)
		var policyName string
		if ipStackType == "dualstack" {
			helloPodnsIPv6WithCidr := helloPodnsIP1 + "/128"
			helloPodnsIPv4WithCidr := helloPodnsIP2 + "/32"
			compat_otp.By("Create ipBlock Egress Dual with multiple CIDRs Policy in namespace")
			npIPBlockNS := ipBlockCIDRsDual{
				name:      "ipblock-dual-multiple-cidrs-egress",
				template:  ipBlockEgressTemplateDual,
				cidrIpv4:  helloPodnsIPv4WithCidr,
				cidrIpv6:  helloPodnsIPv6WithCidr,
				cidr2Ipv4: helloPodnsIPv4WithCidr,
				cidr2Ipv6: helloPodnsIPv6WithCidr,
				cidr3Ipv4: helloPodnsIPv4WithCidr,
				cidr3Ipv6: helloPodnsIPv6WithCidr,
				namespace: ns,
			}
			npIPBlockNS.createIPBlockMultipleCIDRsObjectDual(oc)
			output, err := oc.Run("get").Args("networkpolicy", "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(npIPBlockNS.name))
			policyName = npIPBlockNS.name

		} else {
			var npIPBlockNS ipBlockCIDRsSingle
			if ipStackType == "ipv6single" {
				helloPodnsIPv6WithCidr := helloPodnsIP1 + "/128"
				npIPBlockNS = ipBlockCIDRsSingle{
					name:      "ipblock-single-multiple-cidr-egress",
					template:  ipBlockEgressTemplateSingle,
					cidr:      helloPodnsIPv6WithCidr,
					cidr2:     helloPodnsIPv6WithCidr,
					cidr3:     helloPodnsIPv6WithCidr,
					namespace: ns,
				}
			} else {
				helloPodnsIPv4WithCidr := helloPodnsIP1 + "/32"
				npIPBlockNS = ipBlockCIDRsSingle{
					name:      "ipblock-single-multiple-cidr-egress",
					template:  ipBlockEgressTemplateSingle,
					cidr:      helloPodnsIPv4WithCidr,
					cidr2:     helloPodnsIPv4WithCidr,
					cidr3:     helloPodnsIPv4WithCidr,
					namespace: ns,
				}
			}
			npIPBlockNS.createIPBlockMultipleCIDRsObjectSingle(oc)
			output, err := oc.Run("get").Args("networkpolicy", "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(npIPBlockNS.name))
			policyName = npIPBlockNS.name
		}
		compat_otp.By("Delete the ovnkube node pod on the node")
		ovnKNodePod, ovnkNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, nodeList.Items[0].Name)
		defer waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnKNodePod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Wait for new ovnkube-node pod recreated on the node")
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		ovnKNodePod, ovnkNodePodErr = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))

		compat_otp.By("Check for error message related network policy")
		e2e.Logf("ovnkube-node new podname %s running on node %s", ovnKNodePod, nodeList.Items[0].Name)
		filterString := fmt.Sprintf(" %s/%s ", ns, policyName)
		e2e.Logf("Filter String %s", filterString)
		logContents, logErr := compat_otp.GetSpecificPodLogs(oc, "openshift-ovn-kubernetes", "ovnkube-controller", ovnKNodePod, filterString)
		o.Expect(logErr).NotTo(o.HaveOccurred())
		e2e.Logf("Log contents \n%s", logContents)
		o.Expect(strings.Contains(logContents, "failed")).To(o.BeFalse())

	})
	g.It("Author:asood-Critical-64786-[FdpOvnOvs] Network policy in namespace that has long name fails to be recreated as the ACLs are considered duplicate [Disruptive]", func() {
		// https://issues.redhat.com/browse/OCPBUGS-15371
		var (
			testNs                     = "test-64786networkpolicy-with-a-62chars-62chars-long-namespace62"
			buildPruningBaseDir        = testdata.FixturePath("networking")
			allowToNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-to-same-namespace.yaml")
			pingPodTemplate            = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items) == 0).NotTo(o.BeTrue())

		compat_otp.By("Create a namespace with a long name")
		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
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

		compat_otp.By("Create a hello pod in namspace")
		podns := pingPodResource{
			name:      "hello-pod",
			namespace: testNs,
			template:  pingPodTemplate,
		}
		podns.createPingPod(oc)
		waitPodReady(oc, podns.namespace, podns.name)

		compat_otp.By("Create a network policy in namespace")
		createResourceFromFile(oc, testNs, allowToNSNetworkPolicyFile)
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
		compat_otp.AssertWaitPollNoErr(checkErr, "Network policy could not be created")

		compat_otp.By("Delete the ovnkube node pod on the node")
		ovnKNodePod, ovnkNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, nodeList.Items[0].Name)
		defer waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnKNodePod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Wait for new ovnkube-node pod recreated on the node")
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		ovnKNodePod, ovnkNodePodErr = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))

		compat_otp.By("Check for error message related network policy")
		e2e.Logf("ovnkube-node new podname %s running on node %s", ovnKNodePod, nodeList.Items[0].Name)
		filterString := fmt.Sprintf(" %s/%s ", testNs, "allow-to-same-namespace")
		e2e.Logf("Filter String %s", filterString)
		logContents, logErr := compat_otp.GetSpecificPodLogs(oc, "openshift-ovn-kubernetes", "ovnkube-controller", ovnKNodePod, filterString)
		o.Expect(logErr).NotTo(o.HaveOccurred())
		e2e.Logf("Log contents \n%s", logContents)
		o.Expect(strings.Contains(logContents, "failed")).To(o.BeFalse())

	})

	// author: asood@redhat.com
	g.It("Author:asood-NonHyperShiftHOST-High-64788-[FdpOvnOvs] [NETWORKCUSIM] Same network policies across multiple namespaces fail to be recreated [Disruptive].", func() {
		// This is for customer bug https://issues.redhat.com/browse/OCPBUGS-11447
		var (
			buildPruningBaseDir     = testdata.FixturePath("networking")
			testPodFile             = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			networkPolicyFileSingle = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-single-CIDR-template.yaml")
			networkPolicyFileDual   = filepath.Join(buildPruningBaseDir, "networkpolicy/ipblock/ipBlock-ingress-dual-CIDRs-template.yaml")
			policyName              = "ipblock-64788"
		)

		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		compat_otp.By("Get namespace")
		ns := oc.Namespace()

		compat_otp.By("Create a test pods")
		createResourceFromFile(oc, ns, testPodFile)
		err := waitForPodWithLabelReady(oc, ns, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "The pod with label name=test-pods is not ready")
		testPod := getPodName(oc, ns, "name=test-pods")
		nodeName, err := compat_otp.GetPodNodeName(oc, ns, testPod[0])
		o.Expect(err).NotTo(o.HaveOccurred())

		helloPod1ns1IPv6, helloPod1ns1IPv4 := getPodIP(oc, ns, testPod[0])
		helloPod1ns1IPv4WithCidr := helloPod1ns1IPv4 + "/32"
		helloPod1ns1IPv6WithCidr := helloPod1ns1IPv6 + "/128"
		compat_otp.By("Create ipBlock Ingress CIDRs Policy in namespace")
		if ipStackType == "dualstack" {
			npIPBlockNS1 := ipBlockCIDRsDual{
				name:      policyName,
				template:  networkPolicyFileDual,
				cidrIpv4:  helloPod1ns1IPv4WithCidr,
				cidrIpv6:  helloPod1ns1IPv6WithCidr,
				namespace: ns,
			}
			npIPBlockNS1.createipBlockCIDRObjectDual(oc)
		} else {
			// For singlestack getPodIP returns second parameter empty therefore use helloPod1ns1IPv6 variable but append it
			// with CIDR based on stack.
			var helloPod1ns1IPWithCidr string
			if ipStackType == "ipv6single" {
				helloPod1ns1IPWithCidr = helloPod1ns1IPv6WithCidr
			} else {
				helloPod1ns1IPWithCidr = helloPod1ns1IPv6 + "/32"
			}

			npIPBlockNS1 := ipBlockCIDRsSingle{
				name:      policyName,
				template:  networkPolicyFileSingle,
				cidr:      helloPod1ns1IPWithCidr,
				namespace: ns,
			}
			npIPBlockNS1.createipBlockCIDRObjectSingle(oc)
		}

		compat_otp.By("Check the policy has been created")
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(policyName))

		ovnKNodePod, ovnkNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, nodeName)

		compat_otp.By("Get the ACL for the created policy")
		//list ACLs related to the networkpolicy name
		aclName := fmt.Sprintf("'NP:%s:%s:Ingres'", ns, policyName)
		listACLCmd := fmt.Sprintf("ovn-nbctl find acl name='NP\\:%s\\:%s\\:Ingres'", ns, policyName)
		listAclOutput, listErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAclOutput).NotTo(o.BeEmpty())
		e2e.Logf(listAclOutput)
		var aclMap map[string]string
		var listPGCmd string
		//Dual stack has two ACLs for policy and uuid of both are needed to get port group
		if ipStackType == "dualstack" {
			listAcls := strings.Split(listAclOutput, "\n\n")
			aclMap = nbContructToMap(listAcls[0])
			o.Expect(len(aclMap)).NotTo(o.Equal(0))
			aclMap1 := nbContructToMap(listAcls[1])
			o.Expect(len(aclMap1)).NotTo(o.Equal(0))
			listPGCmd = fmt.Sprintf("ovn-nbctl find port-group acls='[%s, %s]'", aclMap["_uuid"], aclMap1["_uuid"])
		} else {
			aclMap = nbContructToMap(listAclOutput)
			o.Expect(len(aclMap)).NotTo(o.Equal(0))
			listPGCmd = fmt.Sprintf("ovn-nbctl find port-group acls='[%s]'", aclMap["_uuid"])
		}
		aclMap["name"] = aclName

		compat_otp.By("Get the port group for the created policy")
		listPGOutput, listErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listPGCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listPGOutput).NotTo(o.BeEmpty())
		e2e.Logf(listPGOutput)
		pgMap := nbContructToMap(listPGOutput)
		o.Expect(len(pgMap)).NotTo(o.Equal(0))

		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", policyName, "-n", ns).Execute()
			}
		}()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Create a duplicate ACL")
		createAclCmd := fmt.Sprintf("ovn-nbctl --id=@copyacl create acl name=copyacl direction=%s action=%s -- add port_group %s acl @copyacl", aclMap["direction"], aclMap["action"], pgMap["_uuid"])
		idOutput, listErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", createAclCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(idOutput).NotTo(o.BeEmpty())
		e2e.Logf(idOutput)
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", policyName, "-n", ns).Execute()
			}
		}()
		compat_otp.By("Set properties of duplicate ACL")
		setAclPropertiesCmd := fmt.Sprintf("ovn-nbctl set acl %s  match='%s' priority=%s meter=%s", idOutput, aclMap["match"], aclMap["priority"], aclMap["meter"])
		_, listErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", setAclPropertiesCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", policyName, "-n", ns).Execute()
			}
		}()
		compat_otp.By("Set name of duplicate ACL")
		dupAclName := fmt.Sprintf("'NP\\:%s\\:%s\\:Ingre0'", ns, policyName)
		setAclNameCmd := fmt.Sprintf("ovn-nbctl set acl %s name=%s", idOutput, dupAclName)
		_, listErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", setAclNameCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())

		compat_otp.By("Check duplicate ACL is created successfully")
		listDupACLCmd := fmt.Sprintf("ovn-nbctl find acl name='NP\\:%s\\:%s\\:Ingre0'", ns, policyName)
		listDupAclOutput, listErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listDupACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listDupAclOutput).NotTo(o.BeEmpty())
		e2e.Logf(listDupAclOutput)

		compat_otp.By("Delete the ovnkube node pod on the node")
		ovnKNodePod, ovnkNodePodErr = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		e2e.Logf("ovnkube-node podname %s running on node %s", ovnKNodePod, nodeName)
		defer waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnKNodePod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Wait for new ovnkube-node pod to be recreated on the node")
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		ovnKNodePod, ovnkNodePodErr = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))

		compat_otp.By("Check the duplicate ACL is removed")
		listAclOutput, listErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAclOutput).NotTo(o.BeEmpty(), listAclOutput)

		listDupAclOutput, listErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", listDupACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listDupAclOutput).To(o.BeEmpty())
	})

	// author: asood@redhat.com
	g.It("Author:asood-Medium-68660-[FdpOvnOvs] [NETWORKCUSIM] Exposed route of the service should be accessible when allowing inbound traffic from any namespace network policy is created.", func() {
		// https://issues.redhat.com/browse/OCPBUGS-14632
		var (
			buildPruningBaseDir             = testdata.FixturePath("networking")
			allowFromAllNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-all-namespaces.yaml")
			pingPodTemplate                 = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			genericServiceTemplate          = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			serviceName                     = "test-service-68660"
		)

		compat_otp.By("Get namespace")
		ns := oc.Namespace()

		compat_otp.By("Create a hello pod in namspace")
		podns := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		podns.createPingPod(oc)
		waitPodReady(oc, podns.namespace, podns.name)
		compat_otp.By("Create a test service which is in front of the above pod")
		svc := genericServiceResource{
			servicename:           serviceName,
			namespace:             ns,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "PreferDualStack",
			internalTrafficPolicy: "Local",
			externalTrafficPolicy: "",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)

		compat_otp.By("Expose the service through a route")
		err := oc.AsAdmin().WithoutNamespace().Run("expose").Args("svc", serviceName, "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		svcRoute, routeErr := oc.AsAdmin().Run("get").Args("route", serviceName, "-n", ns, "-o=jsonpath={.spec.host}").Output()
		o.Expect(routeErr).NotTo(o.HaveOccurred())
		o.Expect(svcRoute).ShouldNot(o.Equal(""))

		compat_otp.By("Access the route before network policy creation")
		var svcErr error
		var routeCurlOutput []byte
		o.Eventually(func() string {
			routeCurlOutput, svcErr = exec.Command("bash", "-c", "curl -sI "+svcRoute).Output()
			if svcErr != nil {
				e2e.Logf("Wait for service to be accessible through route, %v", svcErr)
			}
			return string(routeCurlOutput)
		}, "15s", "5s").Should(o.ContainSubstring("200 OK"), fmt.Sprintf("Service inaccessible through route %s", string(routeCurlOutput)))

		compat_otp.By("Create a network policy in namespace")
		createResourceFromFile(oc, ns, allowFromAllNSNetworkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-from-all-namespaces"))

		compat_otp.By("Access the route after network policy creation")
		routeCurlOutput, svcErr = exec.Command("bash", "-c", "curl -sI "+svcRoute).Output()
		o.Expect(svcErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(string(routeCurlOutput), "200 OK")).To(o.BeTrue())

	})

	// author: asood@redhat.com
	g.It("Author:asood-NonPreRelease-PreChkUpgrade-Critical-69236-[NETWORKCUSIM] Network policy in namespace that has long name is created successfully post upgrade", func() {
		var (
			testNs                       = "test-the-networkpolicy-with-a-62chars-62chars-long-namespace62"
			buildPruningBaseDir          = testdata.FixturePath("networking")
			allowSameNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-same-namespace.yaml")
			pingPodTemplate              = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			helloStatefulsetFile         = filepath.Join(buildPruningBaseDir, "statefulset-hello.yaml")
		)
		compat_otp.By("Get namespace")
		ns := oc.Namespace()

		compat_otp.By("Create a hello pod in the namespace")
		podns := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		podns.createPingPod(oc)
		waitPodReady(oc, podns.namespace, podns.name)

		compat_otp.By("Create a namespace with a long name")
		oc.CreateSpecifiedNamespaceAsAdmin(testNs)

		compat_otp.By("Create a hello pod in namespace that has long name")
		createResourceFromFile(oc, testNs, helloStatefulsetFile)
		podErr := waitForPodWithLabelReady(oc, testNs, "app=hello")
		compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
		helloPodName := getPodName(oc, testNs, "app=hello")[0]

		compat_otp.By("Create a network policy in namespace")
		createResourceFromFile(oc, testNs, allowSameNSNetworkPolicyFile)
		output, err := oc.AsAdmin().Run("get").Args("networkpolicy", "-n", testNs).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-same-namespace"))

		compat_otp.By("Verify the network policy in namespace with long name pre upgrade is functional ")
		CurlPod2PodFail(oc, ns, "hello-pod", testNs, helloPodName)

	})
	g.It("NonPreRelease-PstChkUpgrade-Author:asood-Critical-69236-Network policy in namespace that has long name is created successfully post upgrade", func() {
		var (
			testNs              = "test-the-networkpolicy-with-a-62chars-62chars-long-namespace62"
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)
		nsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", testNs).Execute()
		if nsErr != nil {
			g.Skip("Skip the PstChkUpgrade test as test-the-networkpolicy-with-a-62chars-62chars-long-namespace62 namespace does not exist, PreChkUpgrade test did not run")
		}
		defer oc.DeleteSpecifiedNamespaceAsAdmin(testNs)
		compat_otp.By("Get namespace")
		ns := oc.Namespace()

		compat_otp.By("Create a hello pod in the namespace")
		podns := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		podns.createPingPod(oc)
		waitPodReady(oc, podns.namespace, podns.name)

		compat_otp.By("Verify the network policy in namespace with long name post upgrade is functional ")
		podErr := waitForPodWithLabelReady(oc, testNs, "app=hello")
		compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
		helloPodName := getPodName(oc, testNs, "app=hello")[0]
		CurlPod2PodFail(oc, ns, "hello-pod", testNs, helloPodName)

	})
	g.It("Author:asood-Low-75540-[NETWORKCUSIM] Network Policy Validation", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			networkPolicyFile   = filepath.Join(buildPruningBaseDir, "networkpolicy/netpol-30920-75540.yaml")
		)
		compat_otp.By("OCPBUGS-30920 Verify the network policy is not created with invalid value")
		ns := oc.Namespace()
		o.Expect(createResourceFromFileWithError(oc, ns, networkPolicyFile)).To(o.HaveOccurred())
	})

	// author: meinli@redhat.com
	g.It("Author:meinli-High-70009-Pod IP is missing from OVN DB AddressSet when using allow-namespace-only network policy", func() {
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

		compat_otp.By("1. Get namespace")
		ns := oc.Namespace()

		compat_otp.By("2. Create a network policy in namespace")
		createResourceFromFile(oc, ns, allowSameNSNetworkPolicyFile)
		output, err := oc.AsAdmin().Run("get").Args("networkpolicy", "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-same-namespace"))

		ovnNodePod := ovnkubeNodePod(oc, nodeList.Items[0].Name)
		o.Expect(ovnNodePod).NotTo(o.BeEmpty())

		compat_otp.By("3. Check the acl from the port-group from the OVNK leader ovnkube-node")
		listPGCmd := fmt.Sprintf("ovn-nbctl find port-group | grep -C 2 '%s\\:allow-same-namespace'", ns)
		listPGCOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnNodePod, listPGCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listPGCOutput).NotTo(o.BeEmpty())
		e2e.Logf("Output %s", listPGCOutput)

		compat_otp.By("4. Check the addresses in ACL's address-set is empty")
		var PGCMap map[string]string
		PGCMap = nbContructToMap(listPGCOutput)
		acls := strings.Split(strings.Trim(PGCMap["acls"], "[]"), ", ")
		o.Expect(len(acls)).To(o.Equal(2))

		listAclCmd := fmt.Sprintf("ovn-nbctl list acl %s", strings.Join(acls, " "))
		listAclOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnNodePod, listAclCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAclOutput).NotTo(o.BeEmpty())

		regex := `\{\$(\w+)\}`
		re := regexp.MustCompile(regex)
		addrSetNames := re.FindAllString(listAclOutput, -1)
		if len(addrSetNames) == 0 {
			e2e.Fail("No matched address_set name found")
		}
		addrSetName := strings.Trim(addrSetNames[0], "{$}")
		o.Expect(addrSetName).NotTo(o.BeEmpty())

		listAddressSetCmd := fmt.Sprintf("ovn-nbctl list address_set %s", addrSetName)
		listAddrOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnNodePod, listAddressSetCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAddrOutput).NotTo(o.BeEmpty())
		var AddrMap map[string]string
		AddrMap = nbContructToMap(listAddrOutput)
		addrs := strings.Trim(AddrMap["addresses"], "[]")
		o.Expect(addrs).To(o.BeEmpty())

		compat_otp.By("5. Create a hello pod on non existent node")
		nonexistNodeName := "doesnotexist-" + getRandomString()
		pod1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns,
			nodename:  nonexistNodeName,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)

		compat_otp.By("6. Verify address is not added to address-set")
		listAddrOutput, listErr = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnNodePod, listAddressSetCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAddrOutput).NotTo(o.BeEmpty())
		AddrMap = nbContructToMap(listAddrOutput)
		addrs = strings.Trim(AddrMap["addresses"], "[]")
		o.Expect(addrs).To(o.BeEmpty())

		compat_otp.By("7. Delete the pods that did not reach running state and create it with valid node name")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1.name, "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		pod1.nodename = nodeList.Items[0].Name
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("8. Verify address is added to address-set")
		listAddrOutput, listErr = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnNodePod, listAddressSetCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		o.Expect(listAddrOutput).NotTo(o.BeEmpty())
		AddrMap = nbContructToMap(listAddrOutput)
		addrs = strings.Trim(AddrMap["addresses"], "[\"]")
		o.Expect(addrs).NotTo(o.BeEmpty())

		ipStack := checkIPStackType(oc)
		if (ipStack == "ipv6single") || (ipStack == "ipv4single") {
			Pod1IP, _ := getPodIP(oc, ns, pod1.name)
			o.Expect(addrs == Pod1IP).To(o.BeTrue())
		} else {
			_, Pod1IPv4 := getPodIP(oc, ns, pod1.name)
			o.Expect(addrs == Pod1IPv4).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-Medium-83735-Verify NP with label npprotection/blockdeletion=true label can not be deleted after VAP is applied.", func() {
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
		compat_otp.By("1. Create a namespace for default network, and a UDN namespace")
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		allNS := []string{ns1, ns2}

		compat_otp.By("2. Create a networkpolicy in each namespace and label them with npprotection-blockdeletion=true label.")
		for i, ns := range allNS {
			createResourceFromFile(oc, ns, networpolicyFiles[i])
			output, err := oc.AsAdmin().Run("get").Args("-n", ns, "networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, npNames[i])).To(o.BeTrue())
			defer oc.AsAdmin().Run("label").Args("-n", ns, "networkpolicy", npNames[i], fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err = oc.AsAdmin().Run("label").Args("-n", ns, "networkpolicy", npNames[i], fmt.Sprintf("%s=%s", matchLabelKey, "true")).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3. Apply VAP with npprotection-blockdeletion")
		defer oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "remove-cluster-role-from-user", "cluster-admin", oc.Username()).Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-cluster-role-to-user", "cluster-admin", oc.Username()).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		defer removeResource(oc, true, true, "validatingadmissionpolicy", vapName)
		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", vapFile).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err := oc.Run("get").Args("validatingadmissionpolicy.admissionregistration.k8s.io").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, vapName)).To(o.BeTrue())

		// wait a little to let VAP take effect
		time.Sleep(3 * time.Second)

		compat_otp.By("4. Verify the networkpolicy can not be deleted.")
		for i, ns := range allNS {
			output, err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", npNames[i], "-n", ns).Output()
			o.Expect(err).To(o.HaveOccurred())
			o.Expect(strings.Contains(output, expectedDenyMessage)).To(o.BeTrue())
		}

		compat_otp.By("5. Delete the VAP, verify the networkpolicy can be deleted.")
		removeResource(oc, true, true, "validatingadmissionpolicy", "fine-grained-network-policy-protection")

		for i, ns := range allNS {
			output, err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("networkpolicy", npNames[i], "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			expectedMessage := "networkpolicy.networking.k8s.io \"" + npNames[i] + "\" deleted"
			o.Expect(strings.Contains(output, expectedMessage)).To(o.BeTrue())
		}
	})

})

var _ = g.Describe("[OTP][sig-networking] SDN networkpolicy StressTest", func() {
	//This case will only be run in perf stress ci which can be deployed for stress testing.
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-networkpolicy-stress", compat_otp.KubeConfigPath())

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	//author: meinli@redhat.com
	g.It("Author:meinli-High-69234-high memory usage on ovnkube-master leader pods on some clusters when a network policy is deleted. [Serial]", func() {
		var (
			buildPruningBaseDir           = testdata.FixturePath("networking")
			ingressNPPolicyTemplate       = filepath.Join(buildPruningBaseDir, "networkpolicy/generic-networkpolicy-template.yaml")
			matchLabelKey                 = "kubernetes.io/metadata.name"
			master_port             int32 = 8100
		)

		compat_otp.By("0. Get namespace.\n")
		ns := oc.Namespace()

		compat_otp.By("1. Get port from ovnk-master leader pod.\n")
		ovnMasterPodName := getOVNKMasterPod(oc)
		ovnMasterPodNames := getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-control-plane")
		var port string
		var flag int
		for i, ovnPod := range ovnMasterPodNames {
			if ovnPod == ovnMasterPodName {
				port = strconv.Itoa(int(master_port))
				flag = i + 1
				break
			}
			master_port++
		}

		compat_otp.By("2. Get initial pprof goroutine value from ovnk-master leader after enabling forwarding.\n")
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
		compat_otp.AssertWaitPollNoErr(checkErr, "Port cannot listen")

		getGoroutineOut := "curl -ks --noproxy localhost http://localhost:" + port + "/debug/pprof/goroutine\\?debug\\=1 | grep -C 1 'periodicallyRetryResources' | awk 'NR==1{print $1}'"
		PreGoroutineOut, err := exec.Command("bash", "-c", getGoroutineOut).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(PreGoroutineOut).NotTo(o.BeEmpty())
		e2e.Logf("PreGoroutineOut is: %s", PreGoroutineOut)

		compat_otp.By("3. Get initial ovnk-master pod memory usage.\n")
		checkMemoryCmd := fmt.Sprintf("oc -n openshift-ovn-kubernetes adm top pod | sed '1d' | awk 'NR==%d{print $1,$3}'", flag)
		checkMemory1, err := exec.Command("bash", "-c", checkMemoryCmd).CombinedOutput()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Repeat creating, deleting then recreating same network policy 15 times.\n")
		networkPolicyResource := networkPolicyResource{
			name:             "ingress-networkpolicy",
			namespace:        ns,
			policy:           "ingress",
			policyType:       "Ingress",
			direction1:       "from",
			namespaceSel1:    "matchLabels",
			namespaceSelKey1: matchLabelKey,
			namespaceSelVal1: ns,
			template:         ingressNPPolicyTemplate,
		}
		for i := 0; i < 15; i++ {
			// Create network policy
			networkPolicyResource.createNetworkPolicy(oc)
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, networkPolicyResource.name)).To(o.BeTrue())

			// Delete network policy
			removeResource(oc, true, true, "networkpolicy", networkPolicyResource.name, "-n", ns)
		}

		compat_otp.By("5. Compare the goroutine call value between pre and post output.\n")
		PostGoroutineOut, err := exec.Command("bash", "-c", getGoroutineOut).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(PostGoroutineOut).NotTo(o.BeEmpty())
		e2e.Logf("PostGoroutineOut is: %s", PostGoroutineOut)
		o.Expect(string(PreGoroutineOut) == string(PostGoroutineOut)).To(o.BeTrue())

		compat_otp.By("6. Verify ovnk-master pod memory usage should be the same as previous.\n")
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
		compat_otp.AssertWaitPollNoErr(checkErr, "Check the memory usage timeout.")
	})
})
