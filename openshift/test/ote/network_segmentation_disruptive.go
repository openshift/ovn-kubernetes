// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ote

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = Describe("[sig-network] SDN network segmentation disruptive", func() {
	defer GinkgoRecover()

	var oc = exutil.NewCLI("networking-udn")

	BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:NetworkSegmentation] 75984-Check udn pods isolation on user defined networks post OVN gateway migration", Label("Disruptive"), func() {
		var (
			testDataDirUDN = testdata.FixturePath("networking/network_segmentation/udn")
			udnNadtemplate = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			udnPodTemplate = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)

		By("1. Create first namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		By("2. Create 2nd namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		By("3. Create 3rd namespace")
		oc.CreateNamespaceUDN()
		ns3 := oc.Namespace()

		By("4. Create 4th namespace")
		oc.CreateNamespaceUDN()
		ns4 := oc.Namespace()

		nadResourcename := []string{"l3-network-" + ns1, "l3-network-" + ns2, "l2-network-" + ns3, "l2-network-" + ns4}
		nadNS := []string{ns1, ns2, ns3, ns4}
		topo := []string{"layer3", "layer3", "layer2", "layer2"}

		var subnet []string
		if ipStackType == "ipv4single" {
			subnet = []string{"10.150.0.0/16/24", "10.151.0.0/16/24", "10.152.0.0/16", "10.153.0.0/16"}
		} else {
			if ipStackType == "ipv6single" {
				subnet = []string{"2010:100:200::0/60", "2011:100:200::0/60", "2012:100:200::0/60", "2013:100:200::0/60"}
			} else {
				subnet = []string{"10.150.0.0/16/24,2010:100:200::0/60", "10.151.0.0/16/24,2011:100:200::0/60", "10.152.0.0/16,2012:100:200::0/60", "10.153.0.0/16,2013:100:200::0/60"}
			}
		}

		nad := make([]otputils.UdnNetDefResource, 4)
		for i := 0; i < 4; i++ {
			By(fmt.Sprintf("create NAD %s in namespace %s", nadResourcename[i], nadNS[i]))
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadResourcename[i],
				Namespace:        nadNS[i],
				NadNetworkName:   nadResourcename[i],
				Topology:         topo[i],
				Subnet:           subnet[i],
				NetAttachDefName: nadNS[i] + "/" + nadResourcename[i],
				Role:             "primary",
				Template:         udnNadtemplate,
			}
			nad[i].CreateUdnNad(oc)
		}

		pod := make([]otputils.UdnPodResource, 4)
		for i := 0; i < 4; i++ {
			By("create a udn hello pods in ns1 ns2 ns3 and ns4")
			pod[i] = otputils.UdnPodResource{
				Name:      "hello-pod",
				Namespace: nadNS[i],
				Label:     "hello-pod",
				Template:  udnPodTemplate,
			}
			pod[i].CreateUdnPod(oc)
			otputils.WaitPodReady(oc, pod[i].Namespace, pod[i].Name)
		}

		By("create another udn hello pod in ns1 to ensure layer3 connectivity post migration among them")
		podNs1 := otputils.UdnPodResource{
			Name:      "hello-pod-ns1",
			Namespace: nadNS[0],
			Label:     "hello-pod",
			Template:  udnPodTemplate,
		}
		podNs1.CreateUdnPod(oc)
		otputils.WaitPodReady(oc, podNs1.Namespace, podNs1.Name)

		By("create another udn hello pod in ns3 to ensure layer2 connectivity post migration among them")
		podNs3 := otputils.UdnPodResource{
			Name:      "hello-pod-ns3",
			Namespace: nadNS[2],
			Label:     "hello-pod",
			Template:  udnPodTemplate,
		}
		podNs3.CreateUdnPod(oc)
		otputils.WaitPodReady(oc, podNs3.Namespace, podNs3.Name)

		// need to find out original mode cluster is on so that we can revert back to same post test
		var desiredMode string
		origMode := otputils.GetOVNGatewayMode(oc)
		if origMode == "local" {
			desiredMode = "shared"
		} else {
			desiredMode = "local"
		}
		e2e.Logf("Cluster is currently on gateway mode %s", origMode)
		e2e.Logf("Desired mode is %s", desiredMode)

		defer otputils.SwitchOVNGatewayMode(oc, origMode)
		otputils.SwitchOVNGatewayMode(oc, desiredMode)

		// udn network connectivity for layer3 should be isolated
		otputils.CurlPod2PodFailUDN(oc, ns1, pod[0].Name, ns2, pod[1].Name)
		// default network connectivity for layer3 should also be isolated
		otputils.CurlPod2PodFail(oc, ns1, pod[0].Name, ns2, pod[1].Name)

		// udn network connectivity for layer2 should be isolated
		otputils.CurlPod2PodFailUDN(oc, ns3, pod[2].Name, ns4, pod[3].Name)
		// default network connectivity for layer2 should also be isolated
		otputils.CurlPod2PodFail(oc, ns3, pod[2].Name, ns4, pod[3].Name)

		// ensure udn network connectivity for layer3 should be there
		otputils.CurlPod2PodPassUDN(oc, ns1, pod[0].Name, ns1, podNs1.Name)
		// ensure udn network connectivity for layer2 should be there
		otputils.CurlPod2PodPassUDN(oc, ns3, pod[2].Name, ns3, podNs3.Name)
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:NetworkSegmentation] 76939-Check udn pods isolation on a scaled node", Label("Disruptive"), func() {
		var (
			testDataDirUDN     = testdata.FixturePath("networking/network_segmentation/udn")
			udnPodTemplate     = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			udnPodTemplateNode = filepath.Join(testDataDirUDN, "udn_test_pod_template_node.yaml")
			udnCRDSingleStack  = filepath.Join(testDataDirUDN, "udn_crd_singlestack_template.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())
		if ipStackType != "ipv4single" {
			Skip("This case requires IPv4 single stack cluster")
		}
		platform := otputils.CheckPlatform(oc)
		supportedPlatforms := []string{"aws", "azure", "gcp", "vsphere", "ibmcloud", "openstack"}
		platformSupported := false
		for _, p := range supportedPlatforms {
			if platform == p {
				platformSupported = true
				break
			}
		}
		if !platformSupported {
			Skip(fmt.Sprintf("Skipping test: platform %s is not supported for this test case", platform))
		}

		By("1. Create first namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		By("2. Create 2nd namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()

		udnResourcename := []string{"l3-network-" + ns1, "l3-network-" + ns2}
		udnNS := []string{ns1, ns2}
		var cidr []string
		var prefix int32

		cidr = []string{"10.150.0.0/16", "10.151.0.0/16"}
		prefix = 24

		udncrd := make([]otputils.UdnCRDResource, 2)
		for i := 0; i < 2; i++ {
			udncrd[i] = otputils.UdnCRDResource{
				Crdname:   udnResourcename[i],
				Namespace: udnNS[i],
				Role:      "Primary",
				Cidr:      cidr[i],
				Prefix:    prefix,
				Template:  udnCRDSingleStack,
			}
			udncrd[i].CreateUdnCRDSingleStack(oc)
			err := otputils.WaitUDNCRDApplied(oc, udnNS[i], udncrd[i].Crdname)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		By("create a udn hello pod in ns1")
		pod1 := otputils.UdnPodResource{
			Name:      "hello-pod-ns1",
			Namespace: ns1,
			Label:     "hello-pod",
			Template:  udnPodTemplate,
		}
		pod1.CreateUdnPod(oc)
		otputils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		// Scale up a new node on the cluster using a new machineset
		By("3. Scale an existing machineset to add a node")
		existingMS, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("machineset", "-n", "openshift-machine-api", "-o=jsonpath={.items[0].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(existingMS).NotTo(o.BeEmpty())

		// Get all worker nodes before scaling
		nodesBefore, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/worker", "-o=jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		nodesBeforeList := strings.Fields(nodesBefore)

		// Scale existing machineset
		existingReplicas, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("machineset", existingMS, "-n", "openshift-machine-api", "-o=jsonpath={.spec.replicas}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		origReplicas, _ := strconv.Atoi(existingReplicas)
		newReplicas := origReplicas + 1

		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("scale").Args("machineset", existingMS, "-n", "openshift-machine-api", fmt.Sprintf("--replicas=%d", origReplicas)).Execute()
			e2e.Logf("Waiting for scaled node to be removed")
			_ = wait.PollUntilContextTimeout(context.TODO(), 30*time.Second, 15*time.Minute, true, func(_ context.Context) (bool, error) {
				currentNodes, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/worker", "-o=jsonpath={.items[*].metadata.name}").Output()
				return len(strings.Fields(currentNodes)) <= len(nodesBeforeList), nil
			})
		}()

		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("machineset", existingMS, "-n", "openshift-machine-api", fmt.Sprintf("--replicas=%d", newReplicas)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		// Wait for new node to appear and become Ready
		var nodeName string
		err = wait.PollUntilContextTimeout(context.TODO(), 30*time.Second, 15*time.Minute, true, func(_ context.Context) (bool, error) {
			nodesAfter, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/worker", "-o=jsonpath={.items[*].metadata.name}").Output()
			if err != nil {
				return false, nil
			}
			nodesAfterList := strings.Fields(nodesAfter)
			for _, n := range nodesAfterList {
				found := false
				for _, ob := range nodesBeforeList {
					if n == ob {
						found = true
						break
					}
				}
				if !found {
					nodeName = n
					return true, nil
				}
			}
			return false, nil
		})
		o.Expect(err).NotTo(o.HaveOccurred(), "New node did not appear after scaling")
		e2e.Logf("Get nodeName: %v", nodeName)

		otputils.CheckNodeStatus(oc, nodeName, "Ready")

		By("create a udn hello pod in ns2")
		pod2 := otputils.UdnPodResourceNode{
			Name:      "hello-pod-ns2",
			Namespace: ns2,
			Label:     "hello-pod",
			Nodename:  nodeName,
			Template:  udnPodTemplateNode,
		}

		pod2.CreateUdnPodNode(oc)
		otputils.WaitPodReady(oc, pod2.Namespace, pod2.Name)

		// udn network connectivity should be isolated
		otputils.CurlPod2PodFailUDN(oc, ns1, pod1.Name, ns2, pod2.Name)
		// default network connectivity should also be isolated
		otputils.CurlPod2PodFail(oc, ns1, pod1.Name, ns2, pod2.Name)
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:NetworkSegmentation] 75624-Feature integration UDN with multinetworkpolicy [Disruptive]", Label("Disruptive"), func() {
		var (
			testDataDirUDN         = testdata.FixturePath("networking/network_segmentation/udn")
			testDataDirMultus      = testdata.FixturePath("networking/multus")
			testDataDirMultihoming = testdata.FixturePath("networking/multihoming")
			udnNADTemplate         = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			dualstackNADTemplate   = filepath.Join(testDataDirMultus, "dualstack-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(testDataDirMultihoming, "multihoming-pod-template.yaml")
			policyFile             = filepath.Join(testDataDirUDN, "udn_with_multiplenetworkpolicy.yaml")
			patchSResource         = "networks.operator.openshift.io/cluster"
		)

		By("Getting the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			Skip("The cluster has no ready node for the testing")
		}

		By("Enabling useMultiNetworkPolicy in the cluster")
		patchTrue := `{"spec":{"useMultiNetworkPolicy":true}}`
		patchFalse := `{"spec":{"useMultiNetworkPolicy":false}}`
		defer func() {
			otputils.PatchResourceAsAdmin(oc, patchSResource, patchFalse)
			By("NetworkOperatorStatus should back to normal after disable useMultiNetworkPolicy")
			otputils.WaitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")
		}()
		otputils.PatchResourceAsAdmin(oc, patchSResource, patchTrue)
		otputils.WaitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")

		By("Creating a new namespace for this MultiNetworkPolicy testing")
		ns1 := "project75624"
		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("namespace", ns1, "--ignore-not-found").Execute()
		}()
		oc.CreateSpecificNamespaceUDN(ns1)
		rbacErr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-role-to-user", "admin", oc.Username(), "-n", ns1).Execute()
		o.Expect(rbacErr).NotTo(o.HaveOccurred())
		origNs, origNsErr := oc.Run("config").Args("view", "--minify", "-o", "jsonpath={.contexts[0].context.namespace}").Output()
		o.Expect(origNsErr).NotTo(o.HaveOccurred())
		defer func() {
			_ = oc.Run("config").Args("set-context", "--current", "--namespace="+origNs).Execute()
		}()
		ctxErr := oc.Run("config").Args("set-context", "--current", "--namespace="+ns1).Execute()
		o.Expect(ctxErr).NotTo(o.HaveOccurred())
		_, proerr1 := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "user="+ns1).Output()
		o.Expect(proerr1).NotTo(o.HaveOccurred())

		By("Creating primary UDN NAD for ns1")
		nad1 := otputils.UdnNetDefResource{
			Nadname:          "udn-primary-net",
			Namespace:        ns1,
			NadNetworkName:   "udn-primary-net",
			Topology:         "layer3",
			Subnet:           "10.100.0.0/16/24",
			NetAttachDefName: ns1 + "/" + "udn-primary-net",
			Role:             "primary",
			Template:         udnNADTemplate,
		}
		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nad1.Nadname, "-n", ns1).Execute()
		}()
		nad1.CreateUdnNad(oc)

		By("Verifying the primary NAD is created")
		nadOutput, nadErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("net-attach-def", nad1.Nadname, "-n", ns1).Output()
		o.Expect(nadErr).NotTo(o.HaveOccurred())
		o.Expect(nadOutput).To(o.ContainSubstring(nad1.Nadname))

		By("Creating secondary dualstack macvlan NAD for ns1")
		nad2 := otputils.DualstackNAD{
			Nadname:        "dualstack",
			Namespace:      ns1,
			Plugintype:     "macvlan",
			Mode:           "bridge",
			Ipamtype:       "whereabouts",
			Ipv4range:      "192.168.10.0/24",
			Ipv6range:      "fd00:dead:beef:10::/64",
			Ipv4rangestart: "",
			Ipv4rangeend:   "",
			Ipv6rangestart: "",
			Ipv6rangeend:   "",
			Template:       dualstackNADTemplate,
		}
		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nad2.Nadname, "-n", ns1).Execute()
		}()
		nad2.CreateDualstackNAD(oc)

		By("Verifying the secondary NAD is created")
		nadOutput, nadErr = oc.AsAdmin().WithoutNamespace().Run("get").Args("net-attach-def", nad2.Nadname, "-n", ns1).Output()
		o.Expect(nadErr).NotTo(o.HaveOccurred())
		o.Expect(nadOutput).To(o.ContainSubstring(nad2.Nadname))

		nadName := "dualstack"
		nsWithNAD := ns1 + "/" + nadName

		By("Creating blue-pod-1 with secondary network")
		pod1 := otputils.TestMultihomingPod{
			Name:       "blue-pod-1",
			Namespace:  ns1,
			Podlabel:   "blue-pod",
			Nadname:    nsWithNAD,
			Nodename:   nodeList.Items[0].Name,
			Podenvname: "",
			Template:   multihomingPodTemplate,
		}
		pod1.CreateTestMultihomingPod(oc)

		By("Creating blue-pod-2 with secondary network")
		pod2 := otputils.TestMultihomingPod{
			Name:       "blue-pod-2",
			Namespace:  ns1,
			Podlabel:   "blue-pod",
			Nadname:    nsWithNAD,
			Nodename:   nodeList.Items[0].Name,
			Podenvname: "",
			Template:   multihomingPodTemplate,
		}
		pod2.CreateTestMultihomingPod(oc)

		By("Verifying blue pods are ready")
		o.Expect(otputils.WaitForPodWithLabelReady(oc, ns1, "name=blue-pod")).NotTo(o.HaveOccurred())

		By("Creating red-pod-1 with secondary network")
		pod3 := otputils.TestMultihomingPod{
			Name:       "red-pod-1",
			Namespace:  ns1,
			Podlabel:   "red-pod",
			Nadname:    nsWithNAD,
			Nodename:   nodeList.Items[0].Name,
			Podenvname: "",
			Template:   multihomingPodTemplate,
		}
		pod3.CreateTestMultihomingPod(oc)

		By("Creating red-pod-2 with secondary network")
		pod4 := otputils.TestMultihomingPod{
			Name:       "red-pod-2",
			Namespace:  ns1,
			Podlabel:   "red-pod",
			Nadname:    nsWithNAD,
			Nodename:   nodeList.Items[0].Name,
			Podenvname: "",
			Template:   multihomingPodTemplate,
		}
		pod4.CreateTestMultihomingPod(oc)

		By("Verifying red pods are ready")
		o.Expect(otputils.WaitForPodWithLabelReady(oc, ns1, "name=red-pod")).NotTo(o.HaveOccurred())

		By("Getting deployed pod names")
		podList, podListErr := otputils.GetAllPodsWithLabel(oc, ns1, "")
		o.Expect(podListErr).NotTo(o.HaveOccurred())
		o.Expect(len(podList)).To(o.BeNumerically(">=", 4))

		By("Getting secondary network IPs for all pods")
		pod1v4, pod1v6 := otputils.GetPodMultiNetwork(ns1, podList[0])
		pod2v4, pod2v6 := otputils.GetPodMultiNetwork(ns1, podList[1])
		pod3v4, pod3v6 := otputils.GetPodMultiNetwork(ns1, podList[2])
		pod4v4, pod4v6 := otputils.GetPodMultiNetwork(ns1, podList[3])

		By("Verifying curl should pass before applying multinetworkpolicy")
		otputils.CurlPod2PodMultiNetworkPass(ns1, podList[2], pod1v4, pod1v6)
		otputils.CurlPod2PodMultiNetworkPass(ns1, podList[2], pod2v4, pod2v6)
		otputils.CurlPod2PodMultiNetworkPass(ns1, podList[3], pod1v4, pod1v6)
		otputils.CurlPod2PodMultiNetworkPass(ns1, podList[3], pod2v4, pod2v6)
		otputils.CurlPod2PodMultiNetworkPass(ns1, podList[2], pod4v4, pod4v6)
		otputils.CurlPod2PodMultiNetworkPass(ns1, podList[3], pod3v4, pod3v6)

		By("Creating the ingress-allow-same-podSelector-with-same-namespaceSelector MultiNetworkPolicy in ns1")
		defer otputils.RemoveResource(oc, true, true, "multi-networkpolicy", "ingress-allow-same-podselector-with-same-namespaceselector", "-n", ns1)
		err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", policyFile, "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err := oc.AsAdmin().Run("get").Args("multi-networkpolicy", "-n", ns1).Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		By("Verifying the MultiNetworkPolicy is created")
		o.Expect(output).To(o.ContainSubstring("ingress-allow-same-podselector-with-same-namespaceselector"))

		By("Verifying multinetworkpolicy denies red->blue and allows blue->blue traffic")
		otputils.CurlPod2PodMultiNetworkFail(ns1, podList[2], pod1v4, pod1v6)
		otputils.CurlPod2PodMultiNetworkFail(ns1, podList[2], pod2v4, pod2v6)
		otputils.CurlPod2PodMultiNetworkFail(ns1, podList[3], pod1v4, pod1v6)
		otputils.CurlPod2PodMultiNetworkFail(ns1, podList[3], pod2v4, pod2v6)
		otputils.CurlPod2PodMultiNetworkPass(ns1, podList[2], pod4v4, pod4v6)
		otputils.CurlPod2PodMultiNetworkPass(ns1, podList[3], pod3v4, pod3v6)
	})
})
