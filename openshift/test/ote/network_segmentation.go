package ote

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = g.Describe("[sig-network] SDN network segmentation", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("otp-network-segmentation")

	g.BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:NetworkSegmentation] 77542-Check default network ports can be exposed on UDN pods layer3", g.Serial, func() {
		var (
			testDataDir         = testdata.FixturePath("networking")
			netsegDir           = testdata.FixturePath("networking/network_segmentation")
			sctpModule          = filepath.Join(netsegDir, "sctp/load-sctp-module.yaml")
			statefulSetHelloPod = filepath.Join(testDataDir, "statefulset-hello.yaml")
			tcpPort             = 8080
			udpPort             = 6000
			sctpPort            = 30102
		)

		g.By("Preparing the nodes for SCTP")
		otputils.PrepareSCTPModule(oc, sctpModule)

		g.By("1. Create the UDN namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()

		g.By("2. Create CRD for UDN in ns2")
		err := otputils.ApplyL3UDNtoNamespace(oc, ns2, 0)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create a udn hello pod in ns2 and get the node name")
		otputils.CreateResourceFromFile(oc, ns2, statefulSetHelloPod)
		pod2Err := otputils.WaitForPodWithLabelReady(oc, ns2, "app=hello")
		o.Expect(pod2Err).NotTo(o.HaveOccurred(), "The statefulSet pod is not ready")
		pod2Name := otputils.GetPodName(oc, ns2, "app=hello")[0]

		podNodeName, podNodeNameErr := otputils.GetPodNodeName(oc, ns2, pod2Name)
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())

		g.By("4. Create the non UDN namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("5. Create a hello pod in ns1")
		otputils.CreateResourceFromFile(oc, ns1, statefulSetHelloPod)
		pod1Err := otputils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
		o.Expect(pod1Err).NotTo(o.HaveOccurred(), "The statefulSet pod is not ready")
		pod1Name := otputils.GetPodName(oc, ns1, "app=hello")[0]

		g.By("6. Check host isolation from node to UDN pod's IP on default network on TCP/ICMP, should not be able to access")
		otputils.CurlNode2PodFail(oc, podNodeName, ns2, pod2Name)
		otputils.PingNode2PodFail(oc, podNodeName, ns2, pod2Name)

		g.By("7. Check ICMP/TCP/UDP/SCTP traffic between pods in ns1 and ns2, should not be able to access")
		otputils.PingPod2PodFail(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.CurlPod2PodFail(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "UDP", udpPort, false)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "SCTP", sctpPort, false)

		g.By("8. Add annotation to expose default network port on udn pod")
		annotationConf := `k8s.ovn.org/open-default-ports=[{"protocol":"icmp"}, {"protocol":"tcp","port":` + strconv.Itoa(tcpPort) + `}, {"protocol":"udp","port":` + strconv.Itoa(udpPort) + `}, {"protocol":"sctp","port":` + strconv.Itoa(sctpPort) + `}]`
		err = oc.AsAdmin().WithoutNamespace().Run("annotate").Args("pod", pod2Name, "-n", ns2, "--overwrite", annotationConf).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		time.Sleep(10 * time.Second)

		g.By("9. Check ICMP/TCP/UDP/SCTP traffic between pods in ns1 and ns2, should be able to access")
		otputils.PingPod2PodPass(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.CurlPod2PodPass(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "UDP", udpPort, true)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "SCTP", sctpPort, true)

		g.By("10. Check host isolation from node to UDN pod's IP on default network on TCP and ICMP, should be able to access")
		otputils.CurlNode2PodPass(oc, podNodeName, ns2, pod2Name)
		otputils.PingNode2PodPass(oc, podNodeName, ns2, pod2Name)
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:NetworkSegmentation] 77742-Check default network ports can be exposed on UDN pods layer2", g.Serial, func() {
		var (
			testDataDir         = testdata.FixturePath("networking")
			netsegDir           = testdata.FixturePath("networking/network_segmentation")
			sctpModule          = filepath.Join(netsegDir, "sctp/load-sctp-module.yaml")
			udnCRDdualStack     = filepath.Join(netsegDir, "udn/udn_crd_layer2_dualstack_template.yaml")
			udnCRDSingleStack   = filepath.Join(netsegDir, "udn/udn_crd_layer2_singlestack_template.yaml")
			statefulSetHelloPod = filepath.Join(testDataDir, "statefulset-hello.yaml")
			tcpPort             = 8080
			udpPort             = 6000
			sctpPort            = 30102
		)

		g.By("Preparing the nodes for SCTP")
		otputils.PrepareSCTPModule(oc, sctpModule)

		g.By("1. Create UDN namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()

		g.By("2. Create CRD for UDN in ns2")
		var cidr, ipv4cidr, ipv6cidr string
		ipStackType := otputils.CheckIPStackType(oc)
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::0/48"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::0/48"
			}
		}
		udncrd := otputils.UdnCRDResource{
			Crdname:   "udn-l2-network-77742",
			Namespace: ns2,
			Role:      "Primary",
		}
		if ipStackType == "dualstack" {
			udncrd.IPv4cidr = ipv4cidr
			udncrd.IPv6cidr = ipv6cidr
			udncrd.Template = udnCRDdualStack
			udncrd.CreateLayer2DualStackUDNCRD(oc)
		} else {
			udncrd.Cidr = cidr
			udncrd.Template = udnCRDSingleStack
			udncrd.CreateLayer2SingleStackUDNCRD(oc)
		}
		err := otputils.WaitUDNCRDApplied(oc, ns2, udncrd.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create a udn hello pod in ns2 and get node name")
		otputils.CreateResourceFromFile(oc, ns2, statefulSetHelloPod)
		pod2Err := otputils.WaitForPodWithLabelReady(oc, ns2, "app=hello")
		o.Expect(pod2Err).NotTo(o.HaveOccurred(), "The statefulSet pod is not ready")
		pod2Name := otputils.GetPodName(oc, ns2, "app=hello")[0]

		podNodeName, podNodeNameErr := otputils.GetPodNodeName(oc, ns2, pod2Name)
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())

		g.By("4. Create non UDN namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("5. Create a hello pod in ns1")
		otputils.CreateResourceFromFile(oc, ns1, statefulSetHelloPod)
		pod1Err := otputils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
		o.Expect(pod1Err).NotTo(o.HaveOccurred(), "The statefulSet pod is not ready")
		pod1Name := otputils.GetPodName(oc, ns1, "app=hello")[0]

		g.By("6. Check host isolation from node to UDN pod's IP on default network on TCP/ICMP, should not be able to access")
		otputils.CurlNode2PodFail(oc, podNodeName, ns2, pod2Name)
		otputils.PingNode2PodFail(oc, podNodeName, ns2, pod2Name)

		g.By("7. Check ICMP/TCP/UDP/SCTP traffic between pods in ns1 and ns2, should not be able to access")
		otputils.PingPod2PodFail(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.CurlPod2PodFail(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "UDP", udpPort, false)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "SCTP", sctpPort, false)

		g.By("8. Add annotation to expose default network port on udn pod")
		annotationConf := `k8s.ovn.org/open-default-ports=[{"protocol":"icmp"}, {"protocol":"tcp","port":` + strconv.Itoa(tcpPort) + `}, {"protocol":"udp","port":` + strconv.Itoa(udpPort) + `}, {"protocol":"sctp","port":` + strconv.Itoa(sctpPort) + `}]`
		err = oc.AsAdmin().WithoutNamespace().Run("annotate").Args("pod", pod2Name, "-n", ns2, "--overwrite", annotationConf).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		time.Sleep(10 * time.Second)

		g.By("9. Check ICMP/TCP/UDP/SCTP traffic between pods in ns1 and ns2, should be able to access")
		otputils.PingPod2PodPass(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.CurlPod2PodPass(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "UDP", udpPort, true)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "SCTP", sctpPort, true)

		g.By("10. Check host isolation from node to UDN pod's IP on default network on TCP/ICMP, should be able to access")
		otputils.CurlNode2PodPass(oc, podNodeName, ns2, pod2Name)
		otputils.PingNode2PodPass(oc, podNodeName, ns2, pod2Name)
	})

})
