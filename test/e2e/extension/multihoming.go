package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

var _ = g.Describe("[OTP][sig-networking] SDN multihoming", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-multihoming", compat_otp.KubeConfigPath())

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-Author:weliang-Medium-60505-Multihoming Verify the ip4 connectivity between multihoming pods", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
		)

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Create a test namespace")
		ns1 := oc.Namespace()

		nadName := "layer2ipv4network60505"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			g.By("Create a custom resource network-attach-defintion in tested namespace")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "192.168.100.0/24",
				nswithnadname:  nsWithnad,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			g.By("Check if the network-attach-defintion is created")
			if checkNAD(oc, ns1, nadName) {
				e2e.Logf("The correct network-attach-defintion: %v is created!", nadName)
			} else {
				e2e.Failf("The correct network-attach-defintion: %v is not created!", nadName)
			}

			g.By("Check if the new OVN switch is created")
			ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
			o.Expect(ovnMasterPodName).ShouldNot(o.Equal(""))
			o.Eventually(func() bool {
				return checkOVNSwitch(oc, nadName, ovnMasterPodName)
			}, 20*time.Second, 5*time.Second).Should(o.BeTrue(), "The correct OVN switch is not created")

			g.By("Create 1st pod consuming above network-attach-defintion in ns1")
			pod1 := testMultihomingPod{
				name:       "multihoming-pod-1",
				namespace:  ns1,
				podlabel:   "multihoming-pod1",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-1",
				template:   multihomingPodTemplate,
			}
			pod1.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

			g.By("Create 2nd pod consuming above network-attach-defintion in ns1")
			pod2 := testMultihomingPod{
				name:       "multihoming-pod-2",
				namespace:  ns1,
				podlabel:   "multihoming-pod2",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-2",
				template:   multihomingPodTemplate,
			}
			pod2.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())

			g.By("Create 3rd pod consuming above network-attach-defintion in ns1")
			pod3 := testMultihomingPod{
				name:       "multihoming-pod-3",
				namespace:  ns1,
				podlabel:   "multihoming-pod3",
				nadname:    nadName,
				nodename:   nodeList.Items[1].Name,
				podenvname: "Hello multihoming-pod-3",
				template:   multihomingPodTemplate,
			}
			pod3.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod3")).NotTo(o.HaveOccurred())

			g.By("Get IPs from the pod1's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1IPv4, _ := getPodMultiNetwork(ns1, pod1Name[0])
			e2e.Logf("The v4 address of pod1 is: %v", pod1IPv4)

			g.By("Get IPs from the pod2's secondary interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2IPv4, _ := getPodMultiNetwork(ns1, pod2Name[0])
			e2e.Logf("The v4 address of pod2 is: %v", pod2IPv4)

			g.By("Get IPs from the pod3's secondary interface")
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			pod3IPv4, _ := getPodMultiNetwork(ns1, pod3Name[0])
			e2e.Logf("The v4 address of pod3 is: %v", pod3IPv4)

			g.By("Check if the new OVN switch ports is created")
			listSWCmd := "ovn-nbctl show | grep port | grep " + nadName + " "
			podname := []string{pod1Name[0], pod2Name[0], pod3Name[0]}
			o.Eventually(func() bool {
				listOutput, _ := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listSWCmd)
				return checkOVNswitchPorts(podname, listOutput)
			}, 20*time.Second, 5*time.Second).Should(o.BeTrue(), "The correct OVN switch ports are not created")

			g.By("Checking connectivity from pod1 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2IPv4, "net1", pod2.podenvname)

			g.By("Checking connectivity from pod1 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3IPv4, "net1", pod3.podenvname)

			g.By("Checking connectivity from pod2 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1IPv4, "net1", pod1.podenvname)

			g.By("Checking connectivity from pod2 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3IPv4, "net1", pod3.podenvname)

			g.By("Checking connectivity from pod3 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1IPv4, "net1", pod1.podenvname)

			g.By("Checking connectivity from pod3 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2IPv4, "net1", pod2.podenvname)

			g.By("Check if the new OVN switch ports are deleted after deleting the pods")
			o.Expect(oc.AsAdmin().WithoutNamespace().Run("delete").Args("all", "--all", "-n", ns1).Execute()).NotTo(o.HaveOccurred())
			//After deleting pods, it will take several seconds to delete the switch ports
			o.Eventually(func() bool {
				listOutput, _ := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listSWCmd)
				return checkOVNswitchPorts(podname, listOutput)
			}, 20*time.Second, 5*time.Second).ShouldNot(o.BeTrue(), "The correct OVN switch ports are not deleted")

			g.By("Check if the network-attach-defintion is deleted")
			o.Expect(oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()).NotTo(o.HaveOccurred())
			if !checkNAD(oc, ns1, nadName) {
				e2e.Logf("The correct network-attach-defintion: %v is deleted!", nadName)
			} else {
				e2e.Failf("The correct network-attach-defintion: %v is not deleted!", nadName)
			}

			g.By("Check if the new created OVN switch is deleted")
			o.Eventually(func() bool {
				return checkOVNSwitch(oc, nadName, ovnMasterPodName)
			}, 20*time.Second, 5*time.Second).ShouldNot(o.BeTrue(), "The correct OVN switch is not deleted")
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-Author:weliang-Medium-60506-Multihoming Verify the ipv6 connectivity between multihoming pods", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
		)

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Create a test namespace")
		ns1 := oc.Namespace()

		nadName := "layer2ipv6network60506"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			g.By("Create a custom resource network-attach-defintion in tested namespace")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "fd00:dead:beef::0/64",
				nswithnadname:  nsWithnad,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			g.By("Create 1st pod consuming above network-attach-defintion in ns1")
			pod1 := testMultihomingPod{
				name:       "multihoming-pod-1",
				namespace:  ns1,
				podlabel:   "multihoming-pod1",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-1",
				template:   multihomingPodTemplate,
			}
			pod1.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

			g.By("Create 2nd pod consuming above network-attach-defintion in ns1")
			pod2 := testMultihomingPod{
				name:       "multihoming-pod-2",
				namespace:  ns1,
				podlabel:   "multihoming-pod2",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-2",
				template:   multihomingPodTemplate,
			}
			pod2.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())

			g.By("Create 3rd pod consuming above network-attach-defintion in ns1")
			pod3 := testMultihomingPod{
				name:       "multihoming-pod-3",
				namespace:  ns1,
				podlabel:   "multihoming-pod3",
				nadname:    nadName,
				nodename:   nodeList.Items[1].Name,
				podenvname: "Hello multihoming-pod-3",
				template:   multihomingPodTemplate,
			}
			pod3.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod3")).NotTo(o.HaveOccurred())

			g.By("Get IPs from the pod1's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1IPv6 := getPodMultiNetworkIPv6(oc, ns1, pod1Name[0])
			e2e.Logf("The v6 address of pod1 is: %v", pod1IPv6)

			g.By("Get IPs from the pod2's secondary interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2IPv6 := getPodMultiNetworkIPv6(oc, ns1, pod2Name[0])
			e2e.Logf("The v6 address of pod2 is: %v", pod2IPv6)

			g.By("Get IPs from the pod3's secondary interface")
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			pod3IPv6 := getPodMultiNetworkIPv6(oc, ns1, pod3Name[0])
			e2e.Logf("The v6 address of pod3 is: %v", pod3IPv6)

			g.By("Checking connectivity from pod1 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2IPv6, "net1", pod2.podenvname)

			g.By("Checking connectivity from pod1 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3IPv6, "net1", pod3.podenvname)

			g.By("Checking connectivity from pod2 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1IPv6, "net1", pod1.podenvname)

			g.By("Checking connectivity from pod2 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3IPv6, "net1", pod3.podenvname)

			g.By("Checking connectivity from pod3 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1IPv6, "net1", pod1.podenvname)

			g.By("Checking connectivity from pod3 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2IPv6, "net1", pod2.podenvname)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("[Level0] Author:weliang-NonHyperShiftHOST-Medium-60507-Multihoming Verify the dualstack connectivity between multihoming pods", func() {
		var podName, podEnvName, podIPv4, podIPv6 []string
		var ovnMasterPodName, ns, nadName string
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns).Execute()
			podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns, nadName = multihomingBeforeCheck(oc, value)
			multihomingAfterCheck(oc, podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns, nadName)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-Author:weliang-Medium-60508-Multihoming Verify ipv4 address excludeSubnets for multihoming pods", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
		)

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Create a test namespace")
		ns1 := oc.Namespace()

		nadName := "layer2excludeipv4network60508"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			g.By("Create a custom resource network-attach-defintion in tested namespace")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "192.168.10.0/29",
				nswithnadname:  nsWithnad,
				excludeSubnets: "192.168.10.0/30,192.168.10.6/32",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			g.By("Create 1st pod consuming above network-attach-defintion in ns1")
			pod1 := testMultihomingPod{
				name:       "multihoming-pod-1",
				namespace:  ns1,
				podlabel:   "multihoming-pod1",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-1",
				template:   multihomingPodTemplate,
			}
			pod1.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

			g.By("Create 2nd pod consuming above network-attach-defintion in ns1")
			pod2 := testMultihomingPod{
				name:       "multihoming-pod-2",
				namespace:  ns1,
				podlabel:   "multihoming-pod2",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-2",
				template:   multihomingPodTemplate,
			}
			pod2.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())

			g.By("Create 3rd pod consuming above network-attach-defintion in ns1")
			pod3 := testMultihomingPod{
				name:       "multihoming-pod-3",
				namespace:  ns1,
				podlabel:   "multihoming-pod3",
				nadname:    nadName,
				nodename:   nodeList.Items[1].Name,
				podenvname: "Hello multihoming-pod-3",
				template:   multihomingPodTemplate,
			}
			pod3.createTestMultihomingPod(oc)
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			o.Eventually(func() string {
				podStatus, _ := getPodStatus(oc, ns1, pod3Name[0])
				return podStatus
			}, 20*time.Second, 5*time.Second).Should(o.Equal("Pending"), fmt.Sprintf("Pod: %s should not be in Running state", pod3Name[0]))

			g.By("Get IPs from the pod1's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1IPv4, _ := getPodMultiNetwork(ns1, pod1Name[0])
			e2e.Logf("The v4 address of pod1 is: %v", pod1IPv4)
			if strings.Contains(pod1IPv4, "192.168.10.1") || strings.Contains(pod1IPv4, "192.168.10.2") || strings.Contains(pod1IPv4, "192.168.10.3") || strings.Contains(pod1IPv4, "192.168.10.6") {
				e2e.Failf("Pod: %s get a wrong excluded ipv4 address", pod1Name[0])
			}

			g.By("Get IPs from the pod2's secondary interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2IPv4, _ := getPodMultiNetwork(ns1, pod2Name[0])
			e2e.Logf("The v4 address of pod2 is: %v", pod2IPv4)
			if strings.Contains(pod2IPv4, "192.168.10.1") || strings.Contains(pod2IPv4, "192.168.10.2") || strings.Contains(pod2IPv4, "192.168.10.3") || strings.Contains(pod2IPv4, "192.168.10.6") {
				e2e.Failf("Pod: %s get a wrong excluded ipv4 address", pod2Name[0])
			}

			g.By("Checking connectivity from pod1 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2IPv4, "net1", pod2.podenvname)

			g.By("Checking connectivity from pod2 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1IPv4, "net1", pod1.podenvname)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-Author:weliang-Medium-60509-Multihoming Verify ipv6 address excludeSubnets for multihoming pods", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
		)

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Create a test namespace")
		ns1 := oc.Namespace()

		nadName := "layer2excludeipv6network60509"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			g.By("Create a custom resource network-attach-defintion in tested namespace")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "fd00:dead:beef:1::0/126",
				nswithnadname:  nsWithnad,
				excludeSubnets: "fd00:dead:beef:1::0/127",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			g.By("Create 1st pod consuming above network-attach-defintion in ns1")
			pod1 := testMultihomingPod{
				name:       "multihoming-pod-1",
				namespace:  ns1,
				podlabel:   "multihoming-pod1",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-1",
				template:   multihomingPodTemplate,
			}
			pod1.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

			g.By("Create 2nd pod consuming above network-attach-defintion in ns1")
			pod2 := testMultihomingPod{
				name:       "multihoming-pod-2",
				namespace:  ns1,
				podlabel:   "multihoming-pod2",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-2",
				template:   multihomingPodTemplate,
			}
			pod2.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())

			g.By("Create 3rd pod consuming above network-attach-defintion in ns1")
			pod3 := testMultihomingPod{
				name:       "multihoming-pod-3",
				namespace:  ns1,
				podlabel:   "multihoming-pod3",
				nadname:    nadName,
				nodename:   nodeList.Items[1].Name,
				podenvname: "Hello multihoming-pod-3",
				template:   multihomingPodTemplate,
			}
			pod3.createTestMultihomingPod(oc)
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			o.Eventually(func() string {
				podStatus, _ := getPodStatus(oc, ns1, pod3Name[0])
				return podStatus
			}, 20*time.Second, 5*time.Second).Should(o.Equal("Pending"), fmt.Sprintf("Pod: %s should not be in Running state", pod3Name[0]))

			g.By("Get IPs from the pod1's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1IPv6 := getPodMultiNetworkIPv6(oc, ns1, pod1Name[0])
			e2e.Logf("The v6 address of pod1 is: %v", pod1IPv6)
			if !strings.Contains(pod1IPv6, "fd00:dead:beef:1::2") && !strings.Contains(pod1IPv6, "fd00:dead:beef:1::3") {
				e2e.Failf("Pod: %s does not get correct ipv6 address", pod1Name[0])
			}

			g.By("Get IPs from the pod2's secondary interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2IPv6 := getPodMultiNetworkIPv6(oc, ns1, pod2Name[0])
			e2e.Logf("The v6 address of pod2 is: %v", pod2IPv6)
			if !strings.Contains(pod1IPv6, "fd00:dead:beef:1::2") && !strings.Contains(pod1IPv6, "fd00:dead:beef:1::3") {
				e2e.Failf("Pod: %s does not get correct ipv6 address", pod2Name[0])
			}

			g.By("Checking connectivity from pod1 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2IPv6, "net1", pod2.podenvname)

			g.By("Checking connectivity from pod2 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1IPv6, "net1", pod1.podenvname)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-Author:weliang-Medium-62548-Multihoming Verify multihoming pods with multiple attachments to the different OVN-K networks", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
		)

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Create a test namespace")
		ns1 := oc.Namespace()

		nadName1 := "layer2dualstacknetwork1"
		nsWithnad1 := ns1 + "/" + nadName1
		nadName2 := "layer2dualstacknetwork2"
		nsWithnad2 := ns1 + "/" + nadName2
		nadName3 := nadName1 + "," + nadName2
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			g.By("Create two custom resource network-attach-defintions in tested namespace")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName1, "-n", ns1).Execute()
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName1,
				subnets:        "192.168.100.0/24,fd00:dead:beef::0/64",
				nswithnadname:  nsWithnad1,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName2, "-n", ns1).Execute()
			nad1ns2 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName2,
				subnets:        "192.168.110.0/24,fd00:dead:beee::0/64",
				nswithnadname:  nsWithnad2,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns2.createMultihomingNAD(oc)

			g.By("Create 1st pod consuming above network-attach-defintions in ns1")
			pod1 := testMultihomingPod{
				name:       "multihoming-pod-1",
				namespace:  ns1,
				podlabel:   "multihoming-pod1",
				nadname:    nadName3,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-1",
				template:   multihomingPodTemplate,
			}
			pod1.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

			g.By("Create 2nd pod consuming above network-attach-defintions in ns1")
			pod2 := testMultihomingPod{
				name:       "multihoming-pod-2",
				namespace:  ns1,
				podlabel:   "multihoming-pod2",
				nadname:    nadName3,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-2",
				template:   multihomingPodTemplate,
			}
			pod2.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())

			g.By("Create 3rd pod consuming above network-attach-defintions in ns1")
			pod3 := testMultihomingPod{
				name:       "multihoming-pod-3",
				namespace:  ns1,
				podlabel:   "multihoming-pod3",
				nadname:    nadName3,
				nodename:   nodeList.Items[1].Name,
				podenvname: "Hello multihoming-pod-3",
				template:   multihomingPodTemplate,
			}
			pod3.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod3")).NotTo(o.HaveOccurred())

			g.By("Get IPs from the pod1's net1 interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1Net1IPv4, pod1Net1IPv6 := getPodMultiNetworks(oc, ns1, pod1Name[0], "net1")
			e2e.Logf("The v4 address of pod1's net1 is: %v", pod1Net1IPv4)
			e2e.Logf("The v6 address of pod1's net1 is: %v", pod1Net1IPv6)

			g.By("Get IPs from the pod2's net1 interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2Net1IPv4, pod2Net1IPv6 := getPodMultiNetworks(oc, ns1, pod2Name[0], "net1")
			e2e.Logf("The v4 address of pod2's net1 is: %v", pod2Net1IPv4)
			e2e.Logf("The v6 address of pod2's net1 is: %v", pod2Net1IPv6)

			g.By("Get IPs from the pod3's net1 interface")
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			pod3Net1IPv4, pod3Net1IPv6 := getPodMultiNetworks(oc, ns1, pod3Name[0], "net1")
			e2e.Logf("The v4 address of pod3's net1 is: %v", pod3Net1IPv4)
			e2e.Logf("The v6 address of pod3's net1 is: %v", pod3Net1IPv6)

			g.By("Checking net1 connectivity from pod1 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2Net1IPv4, "net1", pod2.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2Net1IPv6, "net1", pod2.podenvname)

			g.By("Checking net1 connectivity from pod1 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3Net1IPv4, "net1", pod3.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3Net1IPv6, "net1", pod3.podenvname)

			g.By("Checking net1 connectivity from pod2 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1Net1IPv4, "net1", pod1.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1Net1IPv6, "net1", pod1.podenvname)

			g.By("Checking net1 connectivity from pod2 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3Net1IPv4, "net1", pod3.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3Net1IPv6, "net1", pod3.podenvname)

			g.By("Checking net1 connectivity from pod3 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1Net1IPv4, "net1", pod1.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1Net1IPv6, "net1", pod1.podenvname)

			g.By("Checking net1 connectivity from pod3 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2Net1IPv4, "net1", pod2.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2Net1IPv6, "net1", pod2.podenvname)

			g.By("Get IPs from the pod1's net2 interface")
			pod1Net2IPv4, pod1Net2IPv6 := getPodMultiNetworks(oc, ns1, pod1Name[0], "net2")
			e2e.Logf("The v4 address of pod1's net2 is: %v", pod1Net2IPv4, pod1.podenvname)
			e2e.Logf("The v6 address of pod1's net2 is: %v", pod1Net2IPv6, pod1.podenvname)

			g.By("Get IPs from the pod2's net2 interface")
			pod2Net2IPv4, pod2Net2IPv6 := getPodMultiNetworks(oc, ns1, pod2Name[0], "net2")
			e2e.Logf("The v4 address of pod2's net2 is: %v", pod2Net2IPv4, pod2.podenvname)
			e2e.Logf("The v6 address of pod2's net2 is: %v", pod2Net2IPv6, pod2.podenvname)

			g.By("Get IPs from the pod3's net2 interface")
			pod3Net2IPv4, pod3Net2IPv6 := getPodMultiNetworks(oc, ns1, pod3Name[0], "net2")
			e2e.Logf("The v4 address of pod3's net2 is: %v", pod3Net2IPv4)
			e2e.Logf("The v6 address of pod3's net2 is: %v", pod3Net2IPv6)

			g.By("Checking net2 connectivity from pod1 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2Net2IPv4, "net2", pod2.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2Net2IPv6, "net2", pod2.podenvname)

			g.By("Checking net2 connectivity from pod1 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3Net2IPv4, "net2", pod3.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3Net2IPv6, "net2", pod3.podenvname)

			g.By("Checking net2 connectivity from pod2 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1Net2IPv4, "net2", pod1.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1Net2IPv6, "net2", pod1.podenvname)

			g.By("Checking net2 connectivity from pod2 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3Net2IPv4, "net2", pod3.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3Net2IPv6, "net2", pod3.podenvname)

			g.By("Checking net2 connectivity from pod3 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1Net2IPv4, "net2", pod1.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1Net2IPv6, "net2", pod1.podenvname)

			g.By("Checking net2 connectivity from pod3 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2Net2IPv4, "net2", pod2.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2Net2IPv6, "net2", pod2.podenvname)

			//Check no pods connectivity cross two OVN-K networks in layer2 topology
			CurlMultusPod2PodFail(oc, ns1, pod1Name[0], pod2Net1IPv4, "net2", pod2.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod1Name[0], pod2Net1IPv6, "net2", pod2.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod1Name[0], pod2Net2IPv4, "net1", pod2.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod1Name[0], pod2Net2IPv6, "net1", pod2.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod1Name[0], pod3Net1IPv4, "net2", pod3.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod1Name[0], pod3Net1IPv6, "net2", pod3.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod1Name[0], pod3Net2IPv4, "net1", pod3.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod1Name[0], pod3Net2IPv6, "net1", pod3.podenvname)

			CurlMultusPod2PodFail(oc, ns1, pod2Name[0], pod1Net1IPv4, "net2", pod1.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod2Name[0], pod1Net1IPv6, "net2", pod1.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod2Name[0], pod1Net2IPv4, "net1", pod1.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod2Name[0], pod1Net2IPv6, "net1", pod1.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod2Name[0], pod3Net1IPv4, "net2", pod3.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod2Name[0], pod3Net1IPv6, "net2", pod3.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod2Name[0], pod3Net2IPv4, "net1", pod3.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod2Name[0], pod3Net2IPv6, "net1", pod3.podenvname)

			CurlMultusPod2PodFail(oc, ns1, pod3Name[0], pod2Net1IPv4, "net2", pod2.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod3Name[0], pod2Net1IPv6, "net2", pod2.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod3Name[0], pod2Net2IPv4, "net1", pod2.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod3Name[0], pod2Net2IPv6, "net1", pod2.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod3Name[0], pod1Net1IPv4, "net2", pod1.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod3Name[0], pod1Net1IPv6, "net2", pod1.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod3Name[0], pod1Net2IPv4, "net1", pod1.podenvname)
			CurlMultusPod2PodFail(oc, ns1, pod3Name[0], pod1Net2IPv6, "net1", pod1.podenvname)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("Longduration-NonPreRelease-NonHyperShiftHOST-Author:weliang-Medium-60511-Multihoming Verify the dualstack connectivity between multihoming pods after deleting ovn-northbound-leader pod. [Disruptive]", func() {
		var podName, podEnvName, podIPv4, podIPv6 []string
		var ovnMasterPodName, ns, nadName string
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns).Execute()
			podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns, nadName = multihomingBeforeCheck(oc, value)

			g.By("Delete ovn-northbound-leader pod")
			o.Expect(oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnMasterPodName, "-n", "openshift-ovn-kubernetes").Execute()).NotTo(o.HaveOccurred())

			multihomingAfterCheck(oc, podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns, nadName)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("Longduration-NonPreRelease-NonHyperShiftHOST-Author:weliang-Medium-60512-Multihoming Verify the dualstack connectivity between multihoming pods after deleting all ovnkube-master pods. [Disruptive]", func() {
		var podName, podEnvName, podIPv4, podIPv6 []string
		var ovnMasterPodName, ns, nadName string
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns).Execute()
			podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns, nadName = multihomingBeforeCheck(oc, value)

			g.By("Delete all ovnkube-control-plane pods")
			ovnMasterPodNames := getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-control-plane")
			for _, ovnPod := range ovnMasterPodNames {
				o.Expect(oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnPod, "-n", "openshift-ovn-kubernetes").Execute()).NotTo(o.HaveOccurred())
			}

			multihomingAfterCheck(oc, podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns, nadName)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("Longduration-NonPreRelease-NonHyperShiftHOST-Author:weliang-Medium-60516-Multihoming Verify the dualstack connectivity between multihoming pods after deleting all ovnkube-node pods. [Disruptive]", func() {
		var podName, podEnvName, podIPv4, podIPv6 []string
		var ovnMasterPodName, ns, nadName string
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns).Execute()
			podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns, nadName = multihomingBeforeCheck(oc, value)

			g.By("Delete all ovnkube-node pods")
			ovnNodePodNames := getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
			for _, ovnPod := range ovnNodePodNames {
				o.Expect(oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnPod, "-n", "openshift-ovn-kubernetes").Execute()).NotTo(o.HaveOccurred())
			}

			multihomingAfterCheck(oc, podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns, nadName)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-Author:weliang-Medium-60564-Multihoming Verify the connectivity between multihoming pods without setting subnets", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
		)

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())

		g.By("Create a test namespace")
		ns1 := oc.Namespace()

		nadName := "layer2ipv4network60564"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			g.By("Create a custom resource network-attach-defintion in tested namespace")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "",
				nswithnadname:  nsWithnad,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			g.By("Create a pod consuming above network-attach-defintion in ns1")
			pod1 := testMultihomingPod{
				name:       "multihoming-pod-1",
				namespace:  ns1,
				podlabel:   "multihoming-pod1",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-1",
				template:   multihomingPodTemplate,
			}
			pod1.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

			g.By("Verify the pod will fail to get IP from it's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			getPodMultiNetworkFail(oc, ns1, pod1Name[0])
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-Author:weliang-Medium-63186-Multihoming Verify the connectivity between multihoming pods with static IP", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate       = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingStaticPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-staticpod-template.yaml")
		)

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Create a test namespace")
		ns1 := oc.Namespace()

		nadName := "layer2ipv4network63186"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			g.By("Create a custom resource network-attach-defintion in tested namespace")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "",
				nswithnadname:  nsWithnad,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			g.By("Create 1st pod consuming above network-attach-defintion in ns1")
			ip1 := "192.168.10.10" + "/" + "24"
			pod1 := testMultihomingStaticPod{
				name:       "multihoming-pod-1",
				namespace:  ns1,
				podlabel:   "multihoming-pod1",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-1",
				macaddress: "02:03:04:05:06:01",
				ipaddress:  ip1,
				template:   multihomingStaticPodTemplate,
			}
			pod1.createTestMultihomingStaticPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

			g.By("Create 2nd pod consuming above network-attach-defintion in ns1")
			ip2 := "192.168.10.20" + "/" + "24"
			pod2 := testMultihomingStaticPod{
				name:       "multihoming-pod-2",
				namespace:  ns1,
				podlabel:   "multihoming-pod2",
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-2",
				macaddress: "02:03:04:05:06:02",
				ipaddress:  ip2,
				template:   multihomingStaticPodTemplate,
			}
			pod2.createTestMultihomingStaticPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())

			g.By("Create 3rd pod consuming above network-attach-defintion in ns1")
			ip3 := "192.168.10.30" + "/" + "24"
			pod3 := testMultihomingStaticPod{
				name:       "multihoming-pod-3",
				namespace:  ns1,
				podlabel:   "multihoming-pod3",
				nadname:    nadName,
				nodename:   nodeList.Items[1].Name,
				podenvname: "Hello multihoming-pod-3",
				macaddress: "02:03:04:05:06:03",
				ipaddress:  ip3,
				template:   multihomingStaticPodTemplate,
			}
			pod3.createTestMultihomingStaticPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())
			g.By("Get IPs from the pod1's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1IPv4, _ := getPodMultiNetwork(ns1, pod1Name[0])
			e2e.Logf("The v4 address of pod1 is: %v", pod1IPv4)

			g.By("Get IPs from the pod2's secondary interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2IPv4, _ := getPodMultiNetwork(ns1, pod2Name[0])
			e2e.Logf("The v4 address of pod2 is: %v", pod2IPv4)

			g.By("Get IPs from the pod3's secondary interface")
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			pod3IPv4, _ := getPodMultiNetwork(ns1, pod3Name[0])
			e2e.Logf("The v4 address of pod3 is: %v", pod3IPv4)

			g.By("Checking connectivity from pod1 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2IPv4, "net1", pod2.podenvname)

			g.By("Checking connectivity from pod1 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3IPv4, "net1", pod3.podenvname)

			g.By("Checking connectivity from pod2 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1IPv4, "net1", pod1.podenvname)

			g.By("Checking connectivity from pod2 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3IPv4, "net1", pod3.podenvname)

			g.By("Checking connectivity from pod3 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1IPv4, "net1", pod1.podenvname)

			g.By("Checking connectivity from pod3 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2IPv4, "net1", pod2.podenvname)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-Author:weliang-Medium-60510-Multihoming Verify multihoming pods with multiple attachments to the same OVN-K networks", func() {
		var (
			buildPruningBaseDir            = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate         = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingSharenetNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-sharenet-NAD-template.yaml")
			multihomingPodTemplate         = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
		)

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Create a test namespace")
		ns1 := oc.Namespace()

		nadName1 := "layer2dualstacknetwork1"
		nsWithnad1 := ns1 + "/" + nadName1
		nadName2 := "layer2dualstacknetwork2"
		nsWithnad2 := ns1 + "/" + nadName2
		sharenet := "192.168.100.0/24,fd00:dead:beef::0/64"
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			g.By("Create two custom resource network-attach-defintions in tested namespace")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName1, "-n", ns1).Execute()
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName1,
				subnets:        sharenet,
				nswithnadname:  nsWithnad1,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName2, "-n", ns1).Execute()
			nad1ns2 := multihomingSharenetNAD{
				namespace:      ns1,
				nadname:        nadName2,
				subnets:        sharenet,
				nswithnadname:  nsWithnad2,
				excludeSubnets: "",
				topology:       value,
				sharenetname:   nadName1,
				template:       multihomingSharenetNADTemplate,
			}
			nad1ns2.createMultihomingSharenetNAD(oc)

			g.By("Create 1st pod consuming first network-attach-defintion in ns1")
			pod1 := testMultihomingPod{
				name:       "multihoming-pod-1",
				namespace:  ns1,
				podlabel:   "multihoming-pod1",
				nadname:    nadName1,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-1",
				template:   multihomingPodTemplate,
			}
			pod1.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

			g.By("Create 2nd pod consuming second network-attach-defintion in ns1")
			pod2 := testMultihomingPod{
				name:       "multihoming-pod-2",
				namespace:  ns1,
				podlabel:   "multihoming-pod2",
				nadname:    nadName2,
				nodename:   nodeList.Items[0].Name,
				podenvname: "Hello multihoming-pod-2",
				template:   multihomingPodTemplate,
			}
			pod2.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())

			g.By("Create 3rd pod consuming second network-attach-defintion in ns1")
			pod3 := testMultihomingPod{
				name:       "multihoming-pod-3",
				namespace:  ns1,
				podlabel:   "multihoming-pod3",
				nadname:    nadName2,
				nodename:   nodeList.Items[1].Name,
				podenvname: "Hello multihoming-pod-3",
				template:   multihomingPodTemplate,
			}
			pod3.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod3")).NotTo(o.HaveOccurred())

			g.By("Get IPs from the pod1's net1 interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1Net1IPv4, pod1Net1IPv6 := getPodMultiNetworks(oc, ns1, pod1Name[0], "net1")
			e2e.Logf("The v4 address of pod1 is: %v", pod1Net1IPv4)
			e2e.Logf("The v6 address of pod1 is: %v", pod1Net1IPv6)

			g.By("Get IPs from the pod2's net1 interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2Net1IPv4, pod2Net1IPv6 := getPodMultiNetworks(oc, ns1, pod2Name[0], "net1")
			e2e.Logf("The v4 address of pod2 is: %v", pod2Net1IPv4)
			e2e.Logf("The v6 address of pod2 is: %v", pod2Net1IPv6)

			g.By("Get IPs from the pod3's net1 interface")
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			pod3Net1IPv4, pod3Net1IPv6 := getPodMultiNetworks(oc, ns1, pod3Name[0], "net1")
			e2e.Logf("The v4 address of pod3 is: %v", pod3Net1IPv4)
			e2e.Logf("The v6 address of pod3 is: %v", pod3Net1IPv6)

			g.By("Checking net1 connectivity from pod1 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2Net1IPv4, "net1", pod2.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2Net1IPv6, "net1", pod2.podenvname)

			g.By("Checking net1 connectivity from pod1 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3Net1IPv4, "net1", pod3.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3Net1IPv6, "net1", pod3.podenvname)

			g.By("Checking net1 connectivity from pod2 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1Net1IPv4, "net1", pod1.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1Net1IPv6, "net1", pod1.podenvname)

			g.By("Checking net1 connectivity from pod2 to pod3")
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3Net1IPv4, "net1", pod3.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3Net1IPv6, "net1", pod3.podenvname)

			g.By("Checking net1 connectivity from pod3 to pod1")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1Net1IPv4, "net1", pod1.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1Net1IPv6, "net1", pod1.podenvname)

			g.By("Checking net1 connectivity from pod3 to pod2")
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2Net1IPv4, "net1", pod2.podenvname)
			CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2Net1IPv6, "net1", pod2.podenvname)
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("[Level0] Author:weliang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-64810-Multihoming verify ingress-ipblock policy. [Disruptive]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
			ipBlockIngressTemplate = filepath.Join(buildPruningBaseDir, "ipBlock-ingress-template.yaml")
			ipv4Cidr               = "192.168.100.0/30"
			patchSResource         = "networks.operator.openshift.io/cluster"
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		compat_otp.By("Enable useMultiNetworkPolicy in the cluster")
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			reloadState := "True.*True.*False"
			waitForNetworkOperatorState(oc, 10, 15, reloadState)
			normalState := "True.*False.*False"
			waitForNetworkOperatorState(oc, 10, 15, normalState)
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfoTrue)

		compat_otp.By("NetworkOperatorStatus should back to normal after enable useMultiNetworkPolicy")
		reloadState := "True.*True.*False"
		waitForNetworkOperatorState(oc, 10, 15, reloadState)
		normalState := "True.*False.*False"
		waitForNetworkOperatorState(oc, 10, 15, normalState)

		compat_otp.By("Create a test namespace")
		ns1 := oc.Namespace()
		nadName := "ipblockingress64810"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			compat_otp.By("Create a custom resource network-attach-defintion in tested namespace")
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "192.168.100.0/29",
				nswithnadname:  nsWithnad,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			compat_otp.By("Create six testing pods consuming above network-attach-defintion in ns1")
			var podName, podLabel, podenvName, nodeLocation string
			pod := []testMultihomingPod{}
			for i := 1; i < 7; i++ {
				podName = "multihoming-pod-" + strconv.Itoa(i)
				podLabel = "multihoming-pod" + strconv.Itoa(i)
				podenvName = "Hello multihoming-pod-" + strconv.Itoa(i)
				//Create the pods in different nodes.
				if i < 4 {
					nodeLocation = nodeList.Items[0].Name
				} else {
					nodeLocation = nodeList.Items[1].Name
				}
				p := testMultihomingPod{
					name:       podName,
					namespace:  ns1,
					podlabel:   podLabel,
					nadname:    nadName,
					nodename:   nodeLocation,
					podenvname: podenvName,
					template:   multihomingPodTemplate,
				}
				pod = append(pod, p)
				p.createTestMultihomingPod(oc)
				o.Expect(waitForPodWithLabelReady(oc, ns1, "name="+podLabel)).NotTo(o.HaveOccurred())
			}

			compat_otp.By("Get IPs from the pod1's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1IPv4, _ := getPodMultiNetwork(ns1, pod1Name[0])
			e2e.Logf("The v4 address of pod1 is: %v", pod1IPv4)

			compat_otp.By("Get IPs from the pod2's secondary interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2IPv4, _ := getPodMultiNetwork(ns1, pod2Name[0])
			e2e.Logf("The v4 address of pod2 is: %v", pod2IPv4)

			compat_otp.By("Get IPs from the pod3's secondary interface")
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			pod3IPv4, _ := getPodMultiNetwork(ns1, pod3Name[0])
			e2e.Logf("The v4 address of pod3 is: %v", pod3IPv4)

			compat_otp.By("Get IPs from the pod4's secondary interface")
			pod4Name := getPodName(oc, ns1, "name=multihoming-pod4")
			pod4IPv4, _ := getPodMultiNetwork(ns1, pod4Name[0])
			e2e.Logf("The v4 address of pod4 is: %v", pod4IPv4)

			compat_otp.By("Get IPs from the pod5's secondary interface")
			pod5Name := getPodName(oc, ns1, "name=multihoming-pod5")
			pod5IPv4, _ := getPodMultiNetwork(ns1, pod5Name[0])
			e2e.Logf("The v4 address of pod5 is: %v", pod5IPv4)

			compat_otp.By("Get IPs from the pod6's secondary interface")
			pod6Name := getPodName(oc, ns1, "name=multihoming-pod6")
			pod6IPv4, _ := getPodMultiNetwork(ns1, pod6Name[0])
			e2e.Logf("The v4 address of pod6 is: %v", pod6IPv4)

			// Not like multus/whereabouts, six pods will not always get ip addresses in the order of IP's address, need to reroder the
			// existing pods' name to the new testpods names by the order of IP's addresses
			type podInfor struct {
				podName    string
				podenvName string
			}

			podData := map[string]podInfor{
				pod1IPv4: {podName: pod1Name[0], podenvName: pod[0].podenvname},
				pod2IPv4: {podName: pod2Name[0], podenvName: pod[1].podenvname},
				pod3IPv4: {podName: pod3Name[0], podenvName: pod[2].podenvname},
				pod4IPv4: {podName: pod4Name[0], podenvName: pod[3].podenvname},
				pod5IPv4: {podName: pod5Name[0], podenvName: pod[4].podenvname},
				pod6IPv4: {podName: pod6Name[0], podenvName: pod[5].podenvname},
			}

			testpod1IP := "192.168.100.1"
			testpod1Name := podData[testpod1IP].podName
			testpod1envName := podData[testpod1IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod1 are: %v, %v, %v", testpod1IP, testpod1Name, testpod1envName)

			testpod2IP := "192.168.100.2"
			testpod2Name := podData[testpod2IP].podName
			testpod2envName := podData[testpod2IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod2 are: %v, %v, %v", testpod2IP, testpod2Name, testpod2envName)

			testpod3IP := "192.168.100.3"
			testpod3Name := podData[testpod3IP].podName
			testpod3envName := podData[testpod3IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod3 are: %v, %v, %v", testpod3IP, testpod3Name, testpod3envName)

			testpod4IP := "192.168.100.4"
			testpod4Name := podData[testpod4IP].podName
			testpod4envName := podData[testpod4IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod4 are: %v, %v, %v", testpod4IP, testpod4Name, testpod4envName)

			testpod5IP := "192.168.100.5"
			testpod5Name := podData[testpod5IP].podName
			testpod5envName := podData[testpod5IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod5 are: %v, %v, %v", testpod5IP, testpod5Name, testpod5envName)

			testpod6IP := "192.168.100.6"
			testpod6Name := podData[testpod6IP].podName
			testpod6envName := podData[testpod6IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod6 are: %v, %v, %v", testpod6IP, testpod6Name, testpod6envName)

			compat_otp.By("All curls should pass before applying policy")
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodPass(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod6Name, testpod5IP, "net1", testpod5envName)

			compat_otp.By("Create ingress ipblock to block the traffic from the pods in the range of 192.168.100.4 to 192.168.100.6")
			ipIngressBlock := multihomingIPBlock{
				name:      "ipblock-ingress",
				template:  ipBlockIngressTemplate,
				cidr:      ipv4Cidr,
				namespace: ns1,
				policyfor: nsWithnad,
			}
			ipIngressBlock.createMultihomingipBlockIngressObject(oc)
			policyoutput, policyerr := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
			o.Expect(policyerr).NotTo(o.HaveOccurred())
			o.Expect(policyoutput).To(o.ContainSubstring("ipblock-ingress"))

			compat_otp.By("Check a ACL rule is created for 192.168.100.0/30")
			ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
			listACLCmd := "ovn-nbctl --format=table --no-heading --columns=action,priority,match find acl"
			o.Eventually(func() string {
				listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listACLCmd)
				if listErr != nil {
					e2e.Logf("Wait for policy ACL applied, %v", listErr)
				}
				return listOutput
			}, "60s", "10s").Should(o.ContainSubstring("ip4.src == 192.168.100.0/30"), fmt.Sprintf("Failed to apply policy on the cluster"))

			compat_otp.By("Check only the pods which get 192.168.100.4 to 192.168.100.6 can not communicate to others after applying policy")
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodPass(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodFail(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodFail(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodFail(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodFail(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodFail(oc, ns1, testpod6Name, testpod5IP, "net1", testpod5envName)

			compat_otp.By("All curl should pass again after deleting policy")
			_, policydelerr := oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ipblock-ingress", "-n", ns1).Output()
			o.Expect(policydelerr).NotTo(o.HaveOccurred())

			ovnMasterPodNewName := getOVNKMasterOVNkubeNode(oc)
			o.Eventually(func() string {
				listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodNewName, listACLCmd)
				if listErr != nil {
					e2e.Logf("Wait for policy ACL deleted, %v", listErr)
				}
				return listOutput
			}, "60s", "10s").ShouldNot(o.ContainSubstring("ip4.src == 192.168.100.0/30"), fmt.Sprintf("Failed to delete policy on the cluster"))

			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodPass(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod6Name, testpod5IP, "net1", testpod5envName)
			e2e.Logf("Delete all the pods and NAD for topology: %v ----------------------------", value)
			_, delPodErr := oc.AsAdmin().Run("delete").Args("pod", "--all", "-n", ns1).Output()
			o.Expect(delPodErr).NotTo(o.HaveOccurred())
			_, delNADErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Output()
			o.Expect(delNADErr).NotTo(o.HaveOccurred())
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-NonPreRelease-Longduration-Author:weliang-Medium-64811-Multihoming verify egress-ipblock policy. [Disruptive]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
			ipBlockEgressTemplate  = filepath.Join(buildPruningBaseDir, "ipBlock-egress-template.yaml")
			ipv4Cidr               = "192.168.100.0/30"
			patchSResource         = "networks.operator.openshift.io/cluster"
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		compat_otp.By("Enable useMultiNetworkPolicy in the cluster")
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			reloadState := "True.*True.*False"
			waitForNetworkOperatorState(oc, 10, 15, reloadState)
			normalState := "True.*False.*False"
			waitForNetworkOperatorState(oc, 10, 15, normalState)
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfoTrue)

		compat_otp.By("NetworkOperatorStatus should back to normal after enable useMultiNetworkPolicy")
		reloadState := "True.*True.*False"
		waitForNetworkOperatorState(oc, 10, 15, reloadState)
		normalState := "True.*False.*False"
		waitForNetworkOperatorState(oc, 10, 15, normalState)

		compat_otp.By("Create a test namespace")
		ns1 := oc.Namespace()
		nadName := "ipblockingress64811"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			compat_otp.By("Create a custom resource network-attach-defintion in tested namespace")
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "192.168.100.0/29",
				nswithnadname:  nsWithnad,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			compat_otp.By("Create six testing pods consuming above network-attach-defintion in ns1")
			var podName, podLabel, podenvName, nodeLocation string
			pod := []testMultihomingPod{}
			for i := 1; i < 7; i++ {
				podName = "multihoming-pod-" + strconv.Itoa(i)
				podLabel = "multihoming-pod" + strconv.Itoa(i)
				podenvName = "Hello multihoming-pod-" + strconv.Itoa(i)
				//Create the pods in different nodes.
				if i < 4 {
					nodeLocation = nodeList.Items[0].Name
				} else {
					nodeLocation = nodeList.Items[1].Name
				}
				p := testMultihomingPod{
					name:       podName,
					namespace:  ns1,
					podlabel:   podLabel,
					nadname:    nadName,
					nodename:   nodeLocation,
					podenvname: podenvName,
					template:   multihomingPodTemplate,
				}
				pod = append(pod, p)
				p.createTestMultihomingPod(oc)
				o.Expect(waitForPodWithLabelReady(oc, ns1, "name="+podLabel)).NotTo(o.HaveOccurred())
			}

			compat_otp.By("Get IPs from the pod1's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1IPv4, _ := getPodMultiNetwork(ns1, pod1Name[0])
			e2e.Logf("The v4 address of pod1 is: %v", pod1IPv4)

			compat_otp.By("Get IPs from the pod2's secondary interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2IPv4, _ := getPodMultiNetwork(ns1, pod2Name[0])
			e2e.Logf("The v4 address of pod2 is: %v", pod2IPv4)

			compat_otp.By("Get IPs from the pod3's secondary interface")
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			pod3IPv4, _ := getPodMultiNetwork(ns1, pod3Name[0])
			e2e.Logf("The v4 address of pod3 is: %v", pod3IPv4)

			compat_otp.By("Get IPs from the pod4's secondary interface")
			pod4Name := getPodName(oc, ns1, "name=multihoming-pod4")
			pod4IPv4, _ := getPodMultiNetwork(ns1, pod4Name[0])
			e2e.Logf("The v4 address of pod4 is: %v", pod4IPv4)

			compat_otp.By("Get IPs from the pod5's secondary interface")
			pod5Name := getPodName(oc, ns1, "name=multihoming-pod5")
			pod5IPv4, _ := getPodMultiNetwork(ns1, pod5Name[0])
			e2e.Logf("The v4 address of pod5 is: %v", pod5IPv4)

			compat_otp.By("Get IPs from the pod6's secondary interface")
			pod6Name := getPodName(oc, ns1, "name=multihoming-pod6")
			pod6IPv4, _ := getPodMultiNetwork(ns1, pod6Name[0])
			e2e.Logf("The v4 address of pod6 is: %v", pod6IPv4)

			// Not like multus/whereabouts, six pods will not always get ip addresses in the order of IP's address, need to reroder the
			// existing pods' name to the new testpods names by the order of IP's addresses
			type podInfor struct {
				podName    string
				podenvName string
			}

			podData := map[string]podInfor{
				pod1IPv4: {podName: pod1Name[0], podenvName: pod[0].podenvname},
				pod2IPv4: {podName: pod2Name[0], podenvName: pod[1].podenvname},
				pod3IPv4: {podName: pod3Name[0], podenvName: pod[2].podenvname},
				pod4IPv4: {podName: pod4Name[0], podenvName: pod[3].podenvname},
				pod5IPv4: {podName: pod5Name[0], podenvName: pod[4].podenvname},
				pod6IPv4: {podName: pod6Name[0], podenvName: pod[5].podenvname},
			}

			testpod1IP := "192.168.100.1"
			testpod1Name := podData[testpod1IP].podName
			testpod1envName := podData[testpod1IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod1 are: %v, %v, %v", testpod1IP, testpod1Name, testpod1envName)

			testpod2IP := "192.168.100.2"
			testpod2Name := podData[testpod2IP].podName
			testpod2envName := podData[testpod2IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod2 are: %v, %v, %v", testpod2IP, testpod2Name, testpod2envName)

			testpod3IP := "192.168.100.3"
			testpod3Name := podData[testpod3IP].podName
			testpod3envName := podData[testpod3IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod3 are: %v, %v, %v", testpod3IP, testpod3Name, testpod3envName)

			testpod4IP := "192.168.100.4"
			testpod4Name := podData[testpod4IP].podName
			testpod4envName := podData[testpod4IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod4 are: %v, %v, %v", testpod4IP, testpod4Name, testpod4envName)

			testpod5IP := "192.168.100.5"
			testpod5Name := podData[testpod5IP].podName
			testpod5envName := podData[testpod5IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod5 are: %v, %v, %v", testpod5IP, testpod5Name, testpod5envName)

			testpod6IP := "192.168.100.6"
			testpod6Name := podData[testpod6IP].podName
			testpod6envName := podData[testpod6IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod6 are: %v, %v, %v", testpod6IP, testpod6Name, testpod6envName)

			compat_otp.By("All curls should pass before applying policy")
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodPass(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod6Name, testpod5IP, "net1", testpod5envName)

			compat_otp.By("Create a egress ipblock to block the traffic to the pods in the range of 192.168.100.4 to 192.168.100.6")
			ipEgressBlock := multihomingIPBlock{
				name:      "ipblock-egress",
				template:  ipBlockEgressTemplate,
				cidr:      ipv4Cidr,
				namespace: ns1,
				policyfor: nsWithnad,
			}
			defer oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ipblock-egress", "-n", ns1).Execute()
			ipEgressBlock.createMultihomingipBlockIngressObject(oc)
			policyoutput, policyerr := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
			o.Expect(policyerr).NotTo(o.HaveOccurred())
			o.Expect(policyoutput).To(o.ContainSubstring("ipblock-egress"))

			compat_otp.By("Check a ACL rule is created for 192.168.100.0/30")
			ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
			listACLCmd := "ovn-nbctl --format=table --no-heading --columns=action,priority,match find acl"
			o.Eventually(func() string {
				listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listACLCmd)
				if listErr != nil {
					e2e.Logf("Wait for policy ACL applied, %v", listErr)
				}
				return listOutput
			}, "60s", "10s").Should(o.ContainSubstring("ip4.dst == 192.168.100.0/30"), fmt.Sprintf("Failed to apply policy on the cluster"))

			compat_otp.By("Check all pods can communicate to 192.168.100.1-3 but can not communicate to 192.168.100.4-6 after applying policy")
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodFail(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodFail(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodFail(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodFail(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodFail(oc, ns1, testpod6Name, testpod5IP, "net1", testpod5envName)

			compat_otp.By("All curl should pass again after deleting policy")
			_, policydelerr := oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ipblock-egress", "-n", ns1).Output()
			o.Expect(policydelerr).NotTo(o.HaveOccurred())

			ovnMasterPodNewName := getOVNKMasterOVNkubeNode(oc)
			o.Eventually(func() string {
				listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodNewName, listACLCmd)
				if listErr != nil {
					e2e.Logf("Wait for policy ACL deleted, %v", listErr)
				}
				return listOutput
			}, "60s", "10s").ShouldNot(o.ContainSubstring("ip4.dst == 192.168.100.0/30"), fmt.Sprintf("Failed to delete policy on the cluster"))

			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodPass(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod6Name, testpod5IP, "net1", testpod5envName)
			e2e.Logf("Delete all the pods and NAD for topology: %v ----------------------------", value)
			_, delPodErr := oc.AsAdmin().Run("delete").Args("pod", "--all", "-n", ns1).Output()
			o.Expect(delPodErr).NotTo(o.HaveOccurred())
			_, delNADErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Output()
			o.Expect(delNADErr).NotTo(o.HaveOccurred())
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-NonPreRelease-Longduration-Author:weliang-Medium-64812-Multihoming verify ingressandegress-ipblock policy. [Disruptive]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
			ipBlockTemplate        = filepath.Join(buildPruningBaseDir, "ipBlock-ingressandegress-template.yaml")
			ipv4Cidr               = "192.168.100.6/32"
			patchSResource         = "networks.operator.openshift.io/cluster"
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		compat_otp.By("Enable useMultiNetworkPolicy in the cluster")
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			reloadState := "True.*True.*False"
			waitForNetworkOperatorState(oc, 10, 15, reloadState)
			normalState := "True.*False.*False"
			waitForNetworkOperatorState(oc, 10, 15, normalState)
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfoTrue)

		compat_otp.By("NetworkOperatorStatus should back to normal after enable useMultiNetworkPolicy")
		reloadState := "True.*True.*False"
		waitForNetworkOperatorState(oc, 10, 15, reloadState)
		normalState := "True.*False.*False"
		waitForNetworkOperatorState(oc, 10, 15, normalState)

		compat_otp.By("Create a test namespace")
		ns1 := oc.Namespace()
		nadName := "ingressandegress"
		nsWithnad := ns1 + "/" + nadName
		topology := []string{"layer2"}

		for _, value := range topology {
			e2e.Logf("Start testing the network topology: %v ----------------------------", value)
			compat_otp.By("Create a custom resource network-attach-defintion in tested namespace")
			nad1ns1 := multihomingNAD{
				namespace:      ns1,
				nadname:        nadName,
				subnets:        "192.168.100.0/29",
				nswithnadname:  nsWithnad,
				excludeSubnets: "",
				topology:       value,
				template:       multihomingNADTemplate,
			}
			nad1ns1.createMultihomingNAD(oc)

			compat_otp.By("Create six testing pods consuming above network-attach-defintion in ns1")
			var podName, podLabel, podenvName, nodeLocation string
			pod := []testMultihomingPod{}
			for i := 1; i < 7; i++ {
				podName = "multihoming-pod-" + strconv.Itoa(i)
				podLabel = "multihoming-pod" + strconv.Itoa(i)
				podenvName = "Hello multihoming-pod-" + strconv.Itoa(i)
				//Create the pods in different nodes.
				if i < 4 {
					nodeLocation = nodeList.Items[0].Name
				} else {
					nodeLocation = nodeList.Items[1].Name
				}
				p := testMultihomingPod{
					name:       podName,
					namespace:  ns1,
					podlabel:   podLabel,
					nadname:    nadName,
					nodename:   nodeLocation,
					podenvname: podenvName,
					template:   multihomingPodTemplate,
				}
				pod = append(pod, p)
				p.createTestMultihomingPod(oc)
				o.Expect(waitForPodWithLabelReady(oc, ns1, "name="+podLabel)).NotTo(o.HaveOccurred())
			}

			compat_otp.By("Get IPs from the pod1's secondary interface")
			pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
			pod1IPv4, _ := getPodMultiNetwork(ns1, pod1Name[0])
			e2e.Logf("The v4 address of pod1 is: %v", pod1IPv4)

			compat_otp.By("Get IPs from the pod2's secondary interface")
			pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
			pod2IPv4, _ := getPodMultiNetwork(ns1, pod2Name[0])
			e2e.Logf("The v4 address of pod2 is: %v", pod2IPv4)

			compat_otp.By("Get IPs from the pod3's secondary interface")
			pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
			pod3IPv4, _ := getPodMultiNetwork(ns1, pod3Name[0])
			e2e.Logf("The v4 address of pod3 is: %v", pod3IPv4)

			compat_otp.By("Get IPs from the pod4's secondary interface")
			pod4Name := getPodName(oc, ns1, "name=multihoming-pod4")
			pod4IPv4, _ := getPodMultiNetwork(ns1, pod4Name[0])
			e2e.Logf("The v4 address of pod4 is: %v", pod4IPv4)

			compat_otp.By("Get IPs from the pod5's secondary interface")
			pod5Name := getPodName(oc, ns1, "name=multihoming-pod5")
			pod5IPv4, _ := getPodMultiNetwork(ns1, pod5Name[0])
			e2e.Logf("The v4 address of pod5 is: %v", pod5IPv4)

			compat_otp.By("Get IPs from the pod6's secondary interface")
			pod6Name := getPodName(oc, ns1, "name=multihoming-pod6")
			pod6IPv4, _ := getPodMultiNetwork(ns1, pod6Name[0])
			e2e.Logf("The v4 address of pod6 is: %v", pod6IPv4)

			// Not like multus/whereabouts, six pods will not always get ip addresses in the order of IP's address, need to reroder the
			// existing pods' name to the new testpods names by the order of IP's addresses
			type podInfor struct {
				podName    string
				podenvName string
			}

			podData := map[string]podInfor{
				pod1IPv4: {podName: pod1Name[0], podenvName: pod[0].podenvname},
				pod2IPv4: {podName: pod2Name[0], podenvName: pod[1].podenvname},
				pod3IPv4: {podName: pod3Name[0], podenvName: pod[2].podenvname},
				pod4IPv4: {podName: pod4Name[0], podenvName: pod[3].podenvname},
				pod5IPv4: {podName: pod5Name[0], podenvName: pod[4].podenvname},
				pod6IPv4: {podName: pod6Name[0], podenvName: pod[5].podenvname},
			}

			testpod1IP := "192.168.100.1"
			testpod1Name := podData[testpod1IP].podName
			testpod1envName := podData[testpod1IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod1 are: %v, %v, %v", testpod1IP, testpod1Name, testpod1envName)

			testpod2IP := "192.168.100.2"
			testpod2Name := podData[testpod2IP].podName
			testpod2envName := podData[testpod2IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod2 are: %v, %v, %v", testpod2IP, testpod2Name, testpod2envName)

			testpod3IP := "192.168.100.3"
			testpod3Name := podData[testpod3IP].podName
			testpod3envName := podData[testpod3IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod3 are: %v, %v, %v", testpod3IP, testpod3Name, testpod3envName)

			testpod4IP := "192.168.100.4"
			testpod4Name := podData[testpod4IP].podName
			testpod4envName := podData[testpod4IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod4 are: %v, %v, %v", testpod4IP, testpod4Name, testpod4envName)

			testpod5IP := "192.168.100.5"
			testpod5Name := podData[testpod5IP].podName
			testpod5envName := podData[testpod5IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod5 are: %v, %v, %v", testpod5IP, testpod5Name, testpod5envName)

			testpod6IP := "192.168.100.6"
			testpod6Name := podData[testpod6IP].podName
			testpod6envName := podData[testpod6IP].podenvName
			e2e.Logf("The podIP, podName and podenvName of testpod6 are: %v, %v, %v", testpod6IP, testpod6Name, testpod6envName)

			compat_otp.By("All curls should pass before applying policy")
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodPass(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod6IP, "net1", testpod6envName)

			compat_otp.By("Create a egress ipblock to allow only ip4.src == 192.168.100.5 to ip4.dst == 192.168.100.6")
			ingressandegress := multihomingIPBlock{
				name:      "ingressandegress",
				template:  ipBlockTemplate,
				cidr:      ipv4Cidr,
				namespace: ns1,
				policyfor: nsWithnad,
			}
			defer oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ingressandegress", "-n", ns1).Execute()
			ingressandegress.createMultihomingipBlockIngressObject(oc)
			policyoutput, policyerr := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
			o.Expect(policyerr).NotTo(o.HaveOccurred())
			o.Expect(policyoutput).To(o.ContainSubstring("ingressandegress"))

			compat_otp.By("Check a ACL rule is created for ip4.src == 192.168.100.5/32")
			ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
			listACLCmd := "ovn-nbctl --format=table --no-heading --columns=action,priority,match find acl"
			o.Eventually(func() string {
				listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listACLCmd)
				if listErr != nil {
					e2e.Logf("Wait for policy ACL applied, %v", listErr)
				}
				return listOutput
			}, "60s", "10s").Should(o.ContainSubstring("ip4.src == 192.168.100.5/32"), fmt.Sprintf("Failed to apply policy on the cluster"))
			compat_otp.By("Check a ACL rule is created for ip4.dst == 192.168.100.6/32")
			o.Eventually(func() string {
				listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listACLCmd)
				if listErr != nil {
					e2e.Logf("Wait for policy ACL applied, %v", listErr)
				}
				return listOutput
			}, "60s", "10s").Should(o.ContainSubstring("ip4.dst == 192.168.100.6/32"), fmt.Sprintf("Failed to apply policy on the cluster"))

			compat_otp.By("Check only ip4.src == 192.168.100.5 to ip4.dst == 192.168.100.6 will be allowed after applying policy")
			CurlMultusPod2PodFail(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodFail(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodFail(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodFail(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodFail(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodFail(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodFail(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodFail(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodFail(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod6IP, "net1", testpod6envName)

			compat_otp.By("All curl should pass again after deleting policy")
			_, policydelerr := oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ingressandegress", "-n", ns1).Output()
			o.Expect(policydelerr).NotTo(o.HaveOccurred())

			ovnMasterPodNewName := getOVNKMasterOVNkubeNode(oc)
			o.Eventually(func() string {
				listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodNewName, listACLCmd)
				if listErr != nil {
					e2e.Logf("Wait for policy ACL deleted, %v", listErr)
				}
				return listOutput
			}, "60s", "10s").ShouldNot(o.ContainSubstring("ip4.src == 192.168.100.5/32"), fmt.Sprintf("Failed to delete policy on the cluster"))
			o.Eventually(func() string {
				listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodNewName, listACLCmd)
				if listErr != nil {
					e2e.Logf("Wait for policy ACL deleted, %v", listErr)
				}
				return listOutput
			}, "60s", "10s").ShouldNot(o.ContainSubstring("ip4.dst == 192.168.100.6/32"), fmt.Sprintf("Failed to delete policy on the cluster"))

			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod1Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod2Name, testpod5IP, "net1", testpod5envName)
			CurlMultusPod2PodPass(oc, ns1, testpod3Name, testpod6IP, "net1", testpod6envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod1IP, "net1", testpod1envName)
			CurlMultusPod2PodPass(oc, ns1, testpod4Name, testpod2IP, "net1", testpod2envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod3IP, "net1", testpod3envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod4IP, "net1", testpod4envName)
			CurlMultusPod2PodPass(oc, ns1, testpod5Name, testpod6IP, "net1", testpod6envName)

			e2e.Logf("Delete all the pods and NAD for topology: %v ----------------------------", value)
			_, delPodErr := oc.AsAdmin().Run("delete").Args("pod", "--all", "-n", ns1).Output()
			o.Expect(delPodErr).NotTo(o.HaveOccurred())
			_, delNADErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Output()
			o.Expect(delNADErr).NotTo(o.HaveOccurred())
			e2e.Logf("End testing the network topology: %v ----------------------------", value)
		}
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-NonPreRelease-Longduration-Author:weliang-Medium-65002-Multihoming verify ingress-ipblock policy with static IP. [Disruptive]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-staticpod-template.yaml")
			ipBlockIngressTemplate = filepath.Join(buildPruningBaseDir, "ipBlock-ingress-template.yaml")
			ipv4Cidr               = "192.168.100.0/30"
			patchSResource         = "networks.operator.openshift.io/cluster"
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has fewer than two nodes")
		}

		compat_otp.By("Enable useMultiNetworkPolicy in the cluster")
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")
		reloadState := "True.*True.*False"
		normalState := "True.*False.*False"
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 15, reloadState)
			waitForNetworkOperatorState(oc, 10, 15, normalState)
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfoTrue)

		compat_otp.By("NetworkOperatorStatus should back to normal after enable useMultiNetworkPolicy")
		waitForNetworkOperatorState(oc, 10, 15, reloadState)
		waitForNetworkOperatorState(oc, 10, 15, normalState)

		compat_otp.By("Get the name of testing namespace")
		ns1 := oc.Namespace()
		nadName := "ipblockingress65002"
		nsWithnad := ns1 + "/" + nadName
		topology := "layer2"

		compat_otp.By("Create a custom resource network-attach-defintion in tested namespace")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
		nad1ns1 := multihomingNAD{
			namespace:      ns1,
			nadname:        nadName,
			subnets:        "",
			nswithnadname:  nsWithnad,
			excludeSubnets: "",
			topology:       topology,
			template:       multihomingNADTemplate,
		}
		nad1ns1.createMultihomingNAD(oc)

		compat_otp.By("Create six testing pods consuming above network-attach-defintion in ns1")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "--all", "-n", ns1).Execute()
		var podName, podLabel, podenvName, nodeLocation, macAddress, ipAddress string
		pod := []testMultihomingStaticPod{}
		for i := 1; i < 7; i++ {
			podName = "multihoming-pod-" + strconv.Itoa(i)
			podLabel = "multihoming-pod" + strconv.Itoa(i)
			podenvName = "Hello multihoming-pod-" + strconv.Itoa(i)
			macAddress = "02:03:04:05:06:0" + strconv.Itoa(i)
			ipAddress = "192.168.100." + strconv.Itoa(i) + "/" + "29"
			//Create the pods in different nodes.
			if i < 4 {
				nodeLocation = nodeList.Items[0].Name
			} else {
				nodeLocation = nodeList.Items[1].Name
			}
			p := testMultihomingStaticPod{
				name:       podName,
				namespace:  ns1,
				podlabel:   podLabel,
				nadname:    nadName,
				nodename:   nodeLocation,
				podenvname: podenvName,
				macaddress: macAddress,
				ipaddress:  ipAddress,
				template:   multihomingPodTemplate,
			}
			pod = append(pod, p)
			p.createTestMultihomingStaticPod(oc)
		}

		compat_otp.By("Check all pods are online")
		for i := 1; i < 7; i++ {
			podLabel = "multihoming-pod" + strconv.Itoa(i)
			compat_otp.AssertWaitPollNoErr(waitForPodWithLabelReady(oc, ns1, "name="+podLabel), fmt.Sprintf("Waiting for pod with label name=%s become ready timeout", podLabel))
		}

		compat_otp.By("Get pod's name from each pod")
		pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
		pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
		pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
		pod4Name := getPodName(oc, ns1, "name=multihoming-pod4")
		pod5Name := getPodName(oc, ns1, "name=multihoming-pod5")
		pod6Name := getPodName(oc, ns1, "name=multihoming-pod6")

		compat_otp.By("All curls should pass before applying policy")
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.5", "net1", pod[4].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod3Name[0], "192.168.100.6", "net1", pod[5].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.1", "net1", pod[0].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod6Name[0], "192.168.100.5", "net1", pod[4].podenvname)

		compat_otp.By("Create ingress ipblock to block the traffic from the pods in the range of 192.168.100.4 to 192.168.100.6")
		defer oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ipblock-ingress", "-n", ns1).Output()
		ipIngressBlock := multihomingIPBlock{
			name:      "ipblock-ingress",
			template:  ipBlockIngressTemplate,
			cidr:      ipv4Cidr,
			namespace: ns1,
			policyfor: nsWithnad,
		}
		ipIngressBlock.createMultihomingipBlockIngressObject(oc)
		policyoutput, policyerr := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(policyerr).NotTo(o.HaveOccurred())
		o.Expect(policyoutput).To(o.ContainSubstring("ipblock-ingress"))

		compat_otp.By("Check a ACL rule is created for 192.168.100.0/30")
		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		listACLCmd := "ovn-nbctl --format=table --no-heading --columns=action,priority,match find acl"
		o.Eventually(func() string {
			listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listACLCmd)
			if listErr != nil {
				e2e.Logf("Wait for policy ACL applied, %v", listErr)
			}
			return listOutput
		}, "60s", "10s").Should(o.ContainSubstring("ip4.src == 192.168.100.0/30"), fmt.Sprintf("Failed to apply policy on the cluster"))

		compat_otp.By("Check all pods can communicate to 192.168.100.1-3 but can not communicate to 192.168.100.4-6 after applying policy")
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.5", "net1", pod[4].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod3Name[0], "192.168.100.6", "net1", pod[5].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod4Name[0], "192.168.100.1", "net1", pod[0].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod4Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod5Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod5Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod6Name[0], "192.168.100.5", "net1", pod[4].podenvname)

		compat_otp.By("All curl should pass again after deleting policy")
		_, policydelerr := oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ipblock-ingress", "-n", ns1).Output()
		o.Expect(policydelerr).NotTo(o.HaveOccurred())

		ovnMasterPodNewName := getOVNKMasterOVNkubeNode(oc)
		o.Eventually(func() string {
			listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodNewName, listACLCmd)
			if listErr != nil {
				e2e.Logf("Wait for policy ACL deleted, %v", listErr)
			}
			return listOutput
		}, "60s", "10s").ShouldNot(o.ContainSubstring("ip4.src == 192.168.100.0/30"), fmt.Sprintf("Failed to delete policy on the cluster"))

		compat_otp.By("All curl should pass again after deleting policy")
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.5", "net1", pod[4].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod3Name[0], "192.168.100.6", "net1", pod[5].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.1", "net1", pod[0].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod6Name[0], "192.168.100.5", "net1", pod[4].podenvname)
	})

	// author: weliang@redhat.com
	g.It("NonHyperShiftHOST-NonPreRelease-Longduration-Author:weliang-Medium-65003-Multihoming verify egress-ipblock policy with static IP. [Disruptive]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
			multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-staticpod-template.yaml")
			ipBlockEgressTemplate  = filepath.Join(buildPruningBaseDir, "ipBlock-egress-template.yaml")
			ipv4Cidr               = "192.168.100.0/30"
			patchSResource         = "networks.operator.openshift.io/cluster"
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has fewer than two nodes")
		}

		compat_otp.By("Enable useMultiNetworkPolicy in the cluster")
		patchInfoTrue := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":true}}")
		patchInfoFalse := fmt.Sprintf("{\"spec\":{\"useMultiNetworkPolicy\":false}}")
		reloadState := "True.*True.*False"
		normalState := "True.*False.*False"
		defer func() {
			patchResourceAsAdmin(oc, patchSResource, patchInfoFalse)
			compat_otp.By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			waitForNetworkOperatorState(oc, 10, 15, reloadState)
			waitForNetworkOperatorState(oc, 10, 15, normalState)
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfoTrue)

		compat_otp.By("NetworkOperatorStatus should back to normal after enable useMultiNetworkPolicy")
		waitForNetworkOperatorState(oc, 10, 15, reloadState)
		waitForNetworkOperatorState(oc, 10, 15, normalState)

		compat_otp.By("Get the name of a namespace")
		ns1 := oc.Namespace()
		nadName := "ipblockegress65003"
		nsWithnad := ns1 + "/" + nadName
		topology := "layer2"

		compat_otp.By("Create a custom resource network-attach-defintion in tested namespace")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
		nad1ns1 := multihomingNAD{
			namespace:      ns1,
			nadname:        nadName,
			subnets:        "",
			nswithnadname:  nsWithnad,
			excludeSubnets: "",
			topology:       topology,
			template:       multihomingNADTemplate,
		}
		nad1ns1.createMultihomingNAD(oc)

		compat_otp.By("Create six testing pods consuming above network-attach-defintion in ns1")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "--all", "-n", ns1).Execute()
		var podName, podLabel, podenvName, nodeLocation, macAddress, ipAddress string
		pod := []testMultihomingStaticPod{}
		for i := 1; i < 7; i++ {
			podName = "multihoming-pod-" + strconv.Itoa(i)
			podLabel = "multihoming-pod" + strconv.Itoa(i)
			podenvName = "Hello multihoming-pod-" + strconv.Itoa(i)
			macAddress = "02:03:04:05:06:0" + strconv.Itoa(i)
			ipAddress = "192.168.100." + strconv.Itoa(i) + "/" + "29"
			//Create the pods in different nodes.
			if i < 4 {
				nodeLocation = nodeList.Items[0].Name
			} else {
				nodeLocation = nodeList.Items[1].Name
			}
			p := testMultihomingStaticPod{
				name:       podName,
				namespace:  ns1,
				podlabel:   podLabel,
				nadname:    nadName,
				nodename:   nodeLocation,
				podenvname: podenvName,
				macaddress: macAddress,
				ipaddress:  ipAddress,
				template:   multihomingPodTemplate,
			}
			pod = append(pod, p)
			p.createTestMultihomingStaticPod(oc)
		}

		compat_otp.By("Check all pods are online")
		for i := 1; i < 7; i++ {
			podLabel = "multihoming-pod" + strconv.Itoa(i)
			compat_otp.AssertWaitPollNoErr(waitForPodWithLabelReady(oc, ns1, "name="+podLabel), fmt.Sprintf("Waiting for pod with label name=%s become ready timeout", podLabel))
		}

		compat_otp.By("Get pod's name from each pod")
		pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
		pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
		pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
		pod4Name := getPodName(oc, ns1, "name=multihoming-pod4")
		pod5Name := getPodName(oc, ns1, "name=multihoming-pod5")
		pod6Name := getPodName(oc, ns1, "name=multihoming-pod6")

		compat_otp.By("All curls should pass before applying policy")
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.5", "net1", pod[4].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod3Name[0], "192.168.100.6", "net1", pod[5].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.1", "net1", pod[0].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod6Name[0], "192.168.100.5", "net1", pod[4].podenvname)

		compat_otp.By("Create a egress ipblock to block the traffic to the pods in the range of 192.168.100.4 to 192.168.100.6")
		defer oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ipblock-egress", "-n", ns1).Execute()
		ipEgressBlock := multihomingIPBlock{
			name:      "ipblock-egress",
			template:  ipBlockEgressTemplate,
			cidr:      ipv4Cidr,
			namespace: ns1,
			policyfor: nsWithnad,
		}
		ipEgressBlock.createMultihomingipBlockIngressObject(oc)
		policyoutput, policyerr := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(policyerr).NotTo(o.HaveOccurred())
		o.Expect(policyoutput).To(o.ContainSubstring("ipblock-egress"))

		compat_otp.By("Check a ACL rule is created for 192.168.100.0/30")
		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		listACLCmd := "ovn-nbctl --format=table --no-heading --columns=action,priority,match find acl"
		o.Eventually(func() string {
			listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, listACLCmd)
			if listErr != nil {
				e2e.Logf("Wait for policy ACL applied, %v", listErr)
			}
			return listOutput
		}, "60s", "10s").Should(o.ContainSubstring("ip4.dst == 192.168.100.0/30"), fmt.Sprintf("Failed to apply policy on the cluster"))

		compat_otp.By("Check all pods can communicate to 192.168.100.1-3 but can not communicate to 192.168.100.4-6 after applying policy")
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod2Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod2Name[0], "192.168.100.5", "net1", pod[4].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod3Name[0], "192.168.100.6", "net1", pod[5].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.1", "net1", pod[0].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod5Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodFail(oc, ns1, pod6Name[0], "192.168.100.5", "net1", pod[4].podenvname)

		compat_otp.By("All curl should pass again after deleting policy")
		_, policydelerr := oc.AsAdmin().Run("delete").Args("multi-networkpolicy", "ipblock-egress", "-n", ns1).Output()
		o.Expect(policydelerr).NotTo(o.HaveOccurred())

		ovnMasterPodNewName := getOVNKMasterOVNkubeNode(oc)
		o.Eventually(func() string {
			listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodNewName, listACLCmd)
			if listErr != nil {
				e2e.Logf("Wait for policy ACL deleted, %v", listErr)
			}
			return listOutput
		}, "60s", "10s").ShouldNot(o.ContainSubstring("ip4.dst == 192.168.100.0/30"), fmt.Sprintf("Failed to delete policy on the cluster"))

		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod1Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod2Name[0], "192.168.100.5", "net1", pod[4].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod3Name[0], "192.168.100.6", "net1", pod[5].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.1", "net1", pod[0].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod4Name[0], "192.168.100.2", "net1", pod[1].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.3", "net1", pod[2].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod5Name[0], "192.168.100.4", "net1", pod[3].podenvname)
		CurlMultusPod2PodPass(oc, ns1, pod6Name[0], "192.168.100.5", "net1", pod[4].podenvname)
	})
})
