package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	netutils "k8s.io/utils/net"
)

var _ = g.Describe("[OTP][sig-networking] SDN bgp egressIP", func() {
	defer g.GinkgoRecover()

	var (
		oc                  = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		host                = ""
		externalFRRIP1      string
		externalFRRIP2      string
		allNodes            []string
		podNetwork1Map      = make(map[string]string)
		podNetwork2Map      = make(map[string]string)
		nodesIP1Map         = make(map[string]string)
		nodesIP2Map         = make(map[string]string)
		allNodesIP2         []string
		allNodesIP1         []string
		frrNamespace        = "openshift-frr-k8s"
		externalServiceipv4 = "172.20.0.100"
		externalServiceipv6 = "2001:db8:2::100"
		advertiseType       = "EgressIP"
	)

	g.JustBeforeEach(func() {
		var (
			nodeErr error
		)

		host = os.Getenv("QE_HYPERVISOR_PUBLIC_ADDRESS")
		if host == "" {
			g.Skip("hypervisorHost is nil, please set env QE_HYPERVISOR_PUBLIC_ADDRESS first!!!")
		}

		if !IsFrrRouteAdvertisementEnabled(oc) || !areFRRPodsReady(oc, frrNamespace) {
			g.Skip("FRR routeAdvertisement is still not enabled on the cluster, or FRR pods are not ready, skip the test!!!")
		}

		raErr := checkRAStatus(oc, "default", "Accepted")
		if raErr != nil {
			g.Skip(("default ra is not accepted. pleaes check the default ra is ready before run the automation"))
		}

		compat_otp.By("Get IPs of all cluster nodes, and IP map of all nodes")
		allNodes, nodeErr = compat_otp.GetAllNodes(oc)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(len(allNodes)).NotTo(o.BeEquivalentTo(0))
		nodesIP2Map, nodesIP1Map, allNodesIP2, allNodesIP1 = getNodeIPMAP(oc, allNodes)
		o.Expect(len(nodesIP2Map)).NotTo(o.BeEquivalentTo(0))
		o.Expect(len(nodesIP1Map)).NotTo(o.BeEquivalentTo(0))
		o.Expect(len(allNodesIP2)).NotTo(o.BeEquivalentTo(0))
		o.Expect(len(allNodesIP1)).NotTo(o.BeEquivalentTo(0))

		compat_otp.By("Get external FRR IP, create external FRR container on the host with external FRR IP and cluster nodes' IPs")
		externalFRRIP2, externalFRRIP1 = getExternalFRRIP(oc, allNodesIP2, allNodesIP1, host)
		e2e.Logf("\n externalFRRIP1: %s, externalFRRIP2:%s \n", externalFRRIP1, externalFRRIP2)

		compat_otp.By("Get default podNetworks of all cluster nodes")
		podNetwork2Map, podNetwork1Map = getHostPodNetwork(oc, allNodes, "default")
		o.Expect(len(podNetwork2Map)).NotTo(o.BeEquivalentTo(0))
		o.Expect(len(podNetwork1Map)).NotTo(o.BeEquivalentTo(0))

		compat_otp.By("Verify default network is advertised")
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "30s", "5s").Should(o.BeTrue(), "BGP route advertisement of default network did not succeed!!")
		e2e.Logf("SUCCESS - BGP enabled, default network is advertised!!!")

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-79089-egressIP without nodeSelector on default network can be advertised correctly and egressIP functions well (singlestack) [Serial]", func() {

		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_defaultnetwork_template.yaml")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressNodeLabel     = "k8s.ovn.org/egress-assignable"
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		ipStackType := checkIPStackType(oc)
		// If cluster is dualstack, it will be used as singlev4 cluster in this case,
		// A full daulstack scenario will be covered in a separate test case because each dualstack egressIP uses two nodes, will need total of 4 nodes for egressIP failover
		if len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		var nonEgressNode string
		for _, node := range nodeList.Items {
			if node.Name != egressNodes[0] && node.Name != egressNodes[1] {
				nonEgressNode = node.Name
				break
			}
		}
		o.Expect(nonEgressNode).NotTo(o.Equal(""))

		// Under assumption that default RA that is already on BGP enabled cluster has only podNetwork under spec.advertisements
		compat_otp.By("0. Apply a routeAdvertisement with EgressIP in spec.advertisements")
		raname := "ra-with-egressip"
		params := []string{"-f", raTemplate, "-p", "NAME=" + raname, "ADVERTISETYPE=" + advertiseType}
		defer removeResource(oc, true, true, "ra", raname)
		compat_otp.ApplyNsResourceFromTemplate(oc, oc.Namespace(), params...)
		raErr := checkRAStatus(oc, raname, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - UDN routeAdvertisement applied is accepted")

		compat_otp.By("1. Label an egressNode, get a namespace, label the namespace with org=qe to match namespaceSelector of egressIP object that will be created in step 2")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")

		ns1 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2. Create an egressip object with an usused IP from same subnet of egress node, verify egressIP is assigned to egress node")
		e2e.Logf("get freeIP from node: %s", egressNodes[0])
		var freeIPs []string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			freeIPs = findFreeIPs(oc, egressNodes[0], 1)
		}
		if ipStackType == "ipv6single" {
			freeIPs = findFreeIPv6s(oc, egressNodes[0], 1)
		}
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip1 := egressIPResource1{
			name:          "egressip-79089",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNodes[0]))

		compat_otp.By("3.1 Verify egressIP address is advertised to external frr router")
		var nodeIPEgressNode string
		// since we treat dualstack cluster as singlev4 cluster in this case, only get egress node's IPv4 address even for dualstack cluster.
		// There is separate case for BGP egressIP cases on dualstack
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			nodeIPEgressNode = getNodeIPv4(oc, "default", egressIPMaps1[0]["node"])
		}
		if ipStackType == "ipv6single" {
			_, nodeIPEgressNode = getNodeIP(oc, egressIPMaps1[0]["node"])
		}
		o.Expect(nodeIPEgressNode).NotTo(o.BeEmpty())
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, egressIPMaps1[0]["egressIP"], nodeIPEgressNode, true)
			return result
		}, "90s", "15s").Should(o.BeTrue(), "egressIP on default network with random unused IP was not advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("3.2. Verify egressIP address is advertised to all other cluster nodes")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, egressIPMaps1[0]["node"], allNodes, egressIPMaps1[0]["egressIP"], nodeIPEgressNode, true)
		// 	return result
		// }, "90s", "5s").Should(o.BeTrue(), "egressIP on default network with random unused IP was not advertised to all other cluster nodes!!")

		compat_otp.By("4.1 Create two test pods, add to them with label color=pink to match podSelector of egressIP, one local and another remote to the egress node")
		var podNodes []string
		podNodes = append(podNodes, egressNodes[0])
		podNodes = append(podNodes, nonEgressNode)
		EIPPods := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			EIPPods[i] = pingPodResourceNode{
				name:      "hello-pod" + strconv.Itoa(i) + "-eip-" + ns1,
				namespace: ns1,
				nodename:  podNodes[i],
				template:  pingPodNodeTemplate,
			}
			EIPPods[i].createPingPodNode(oc)
			waitPodReady(oc, ns1, EIPPods[i].name)
			defer compat_otp.LabelPod(oc, ns1, EIPPods[i].name, "color-")
			err = compat_otp.LabelPod(oc, ns1, EIPPods[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("4.2. Verify egressIP works from local or remote pod to egress node")
		e2e.Logf("Trying to get physical interface on the egressNode: %s", egressNodes[0])
		primaryInf, infErr := getSnifPhyInf(oc, egressNodes[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		var tcpdumpCmd, cmdOnPod string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
			cmdOnPod = "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
		}
		if ipStackType == "ipv6single" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
			cmdOnPod = "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
		}

		for i := 0; i < len(EIPPods); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, ns1, EIPPods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("5.1. Create a 3rd test pod on egress node but do not label it so this pod will not use egressIP")
		nonEIPPod := pingPodResourceNode{
			name:      "hello-pod" + "-non-eip-" + ns1,
			namespace: ns1,
			nodename:  egressNodes[0],
			template:  pingPodNodeTemplate,
		}
		nonEIPPod.createPingPodNode(oc)
		waitPodReady(oc, ns1, nonEIPPod.name)

		_, nonEIPPodIP1 := getPodIP(oc, ns1, nonEIPPod.name)

		compat_otp.By("5.2. Verify the non-EIP pod does not use EIP as source IP in its egressing packets, it directly uses its own podIP as sourceIP")
		tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, ns1, nonEIPPod.name, cmdOnPod)
		o.Expect(strings.Contains(tcpdumOutput, nonEIPPodIP1)).To(o.BeTrue(), "Pod that unqualified to use egressIP did not use its podIP as sourceIP!!!")
		o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeFalse(), "Pod that unqualified to use egressIP should not see egressIP as sourceIP in its egress packets!!!")

		compat_otp.By("6. Label the second node with egressNodeLabel, unlabel the first node, verify the new egress node is updated in the egressip object.\n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")

		egressipErr := wait.PollUntilContextTimeout(context.Background(), 20*time.Second, 360*time.Second, false, func(cxt context.Context) (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 1 || egressIPMaps1[0]["node"] == egressNodes[0] {
				e2e.Logf("Wait for egressIP being applied to new egress node,try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to update egress node:%s", egressipErr))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNodes[1]))

		compat_otp.By("7.1. Verify advertised egressIP route is updated with correct nexthop IP after failover")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			nodeIPEgressNode = getNodeIPv4(oc, "default", egressNodes[1])
		}
		if ipStackType == "ipv6single" {
			_, nodeIPEgressNode = getNodeIP(oc, egressNodes[1])
		}
		o.Expect(nodeIPEgressNode).NotTo(o.BeEmpty())
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, egressIPMaps1[0]["egressIP"], nodeIPEgressNode, true)
			return result
		}, "90s", "15s").Should(o.BeTrue(), "egressIP on default network with random unused IP was not advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("7.2. Verify advertised egressIP route to all other cluster nodes is updated with correct nexthop IP after failover")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, egressIPMaps1[0]["node"], allNodes, egressIPMaps1[0]["egressIP"], nodeIPEgressNode, true)
		// 	return result
		// }, "90s", "5s").Should(o.BeTrue(), "egressIP on default network was not advertised to all other cluster nodes!!")

		compat_otp.By("8. From local and remote EIP pods, validate egressIP on new egressNode after egressIP failover \n")
		primaryInf, infErr = getSnifPhyInf(oc, egressNodes[1])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		if ipStackType == "ipv4single" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
		}
		if ipStackType == "ipv6single" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
		}
		for i := 0; i < len(EIPPods); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[1], tcpdumpCmd, ns1, EIPPods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("9. Verify that after egressIP failover, the non-EIP pod still just uses its own podIP as sourceIP")
		primaryInf, infErr = getSnifPhyInf(oc, egressNodes[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
		}
		if ipStackType == "ipv6single" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
		}
		tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, ns1, nonEIPPod.name, cmdOnPod)
		o.Expect(strings.Contains(tcpdumOutput, nonEIPPodIP1)).To(o.BeTrue(), "After failover, pod that unqualified to use egressIP did not use its podIP as sourceIP!!!")
		o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeFalse(), "After failover, pod that unqualified to use egressIP should not see egressIP as sourceIP in its egress packets!!!")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-79715-egressIP without nodeSelector on CUDN can be advertised correctly and egressIP functions well (singlestack) [Serial]", func() {

		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			raTemplate           = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			egressIP2Template    = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate  = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressNodeLabel      = "k8s.ovn.org/egress-assignable"
			networkselectorkey   = "app"
			networkselectorvalue = "udn"
			cudnName             = "cudn-network-79715"
			matchLabelKey        = "cudn-bgp"
			matchValue           = "cudn-network-" + getRandomString()
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		ipStackType := checkIPStackType(oc)
		// If cluster is dualstack, it will be used as singlev4 cluster in this case,
		// A full daulstack scenario will be covered in a separate test case because each dualstack egressIP uses two nodes, will need total of 4 nodes for egressIP failover
		if len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		var nonEgressNode string
		for _, node := range nodeList.Items {
			if node.Name != egressNodes[0] && node.Name != egressNodes[1] {
				nonEgressNode = node.Name
				break
			}
		}
		o.Expect(nonEgressNode).NotTo(o.Equal(""))

		compat_otp.By("1. Create a UDN namespace, create a layer3 CUDN in the UDN namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create CRD for layer3 CUDN")
		var cidr, ipv4cidr, ipv6cidr string
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::/48"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::/48"
			}
		}

		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, cudnName, ipv4cidr, ipv6cidr, cidr, "layer3")
		o.Expect(err).NotTo(o.HaveOccurred())

		//label the CUDN with label app=udn that matches the networkSelector of CUDN RA
		compat_otp.By("2. Label the CUDN with label that matches networkSelector in routeAdvertisement")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns1, "clusteruserdefinednetwork", cudnName, networkselectorkey+"-").Execute()
		setUDNLabel(oc, cudnName, networkselectorkey+"="+networkselectorvalue)

		compat_otp.By("3. Apply a routeAdvertisement that has egressIP in spec.advertisements and has matching networkSelector to select CUDN created above")
		raname := "ra-cudn"
		params := []string{"-f", raTemplate, "-p", "NAME=" + raname, "NETWORKSELECTORKEY=" + networkselectorkey, "NETWORKSELECTORVALUE=" + networkselectorvalue, "ADVERTISETYPE=" + advertiseType}
		defer removeResource(oc, true, true, "ra", raname)
		compat_otp.ApplyNsResourceFromTemplate(oc, oc.Namespace(), params...)
		raErr := checkRAStatus(oc, raname, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		patchchange := `[{"op": "add", "path": "/spec/advertisements/-", "value": "PodNetwork"}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("routeadvertisements/"+raname, "--type=json", "-p", patchchange).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		e2e.Logf("SUCCESS - UDN routeAdvertisement applied is accepted")

		compat_otp.By("4.1  Verify layer3 CUDN network is advertised to external frr")
		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnName)
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - BGP UDN network %s for namespace %s advertised to external !!!", cudnName, ns1)

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("4.2  Verify UDN network is advertised to other cluster nodes")
		// for _, node := range allNodes {
		// 	result := verifyBGPRoutesOnClusterNode(oc, node, externalFRRIP2, externalFRRIP1, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
		// 	o.Expect(result).To(o.BeTrue(), fmt.Sprintf("ip routing table of node %s did not have all bgp routes as expected", node))
		// }
		// e2e.Logf("SUCCESS - BGP UDN network %s for namespace %s advertised to other cluster nodes !!!", cudnName, ns1)

		compat_otp.By("5. Label an egressNode, get a namespace, label the namespace with org=qe to match namespaceSelector of egressIP object that will be created in next step")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6. Create an egressip object with an unused IP from same subnet of egress node, verify egressIP is assigned to egress node")
		var freeIPs []string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			freeIPs = findFreeIPs(oc, egressNodes[0], 1)
		}
		if ipStackType == "ipv6single" {
			freeIPs = findFreeIPv6s(oc, egressNodes[0], 1)
		}
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip1 := egressIPResource1{
			name:          "egressip-79715",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNodes[0]))

		compat_otp.By("7.1 Verify egressIP address is advertised to external frr router")
		var nodeIPEgressNode string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			nodeIPEgressNode = getNodeIPv4(oc, "default", egressNodes[0])
		}
		if ipStackType == "ipv6single" {
			_, nodeIPEgressNode = getNodeIP(oc, egressNodes[0])
		}
		o.Expect(nodeIPEgressNode).NotTo(o.BeEmpty())

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, egressIPMaps1[0]["egressIP"], nodeIPEgressNode, true)
			return result
		}, "90s", "15s").Should(o.BeTrue(), "egressIP was not advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("7.2. Verify egressIP address is advertised to all other cluster nodes")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, egressIPMaps1[0]["node"], allNodes, egressIPMaps1[0]["egressIP"], nodeIPEgressNode, true)
		// 	return result
		// }, "90s", "5s").Should(o.BeTrue(), "egressIP on default network with random unused IP was not advertised to all other cluster nodes!!")

		compat_otp.By("8.1 Create two test pods, add to them with label color=pink to match podSelector of egressIP, one local and another remote to the egress node")
		podNodes := []string{egressNodes[0], nonEgressNode}
		EIPPods := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			EIPPods[i] = pingPodResourceNode{
				name:      "hello-pod" + strconv.Itoa(i) + "-eip-" + ns1,
				namespace: ns1,
				nodename:  podNodes[i],
				template:  pingPodNodeTemplate,
			}
			defer removeResource(oc, true, true, "pod", EIPPods[i].name, "-n", EIPPods[i].namespace)
			EIPPods[i].createPingPodNode(oc)
			waitPodReady(oc, ns1, EIPPods[i].name)
			defer compat_otp.LabelPod(oc, ns1, EIPPods[i].name, "color-")
			err = compat_otp.LabelPod(oc, ns1, EIPPods[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("8.2. Verify egressIP works from local or remote pod to egress node")
		e2e.Logf("Trying to get physical interface on the egressNode: %s", egressNodes[0])
		primaryInf, infErr := getSnifPhyInf(oc, egressNodes[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		var tcpdumpCmd, cmdOnPod string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
			cmdOnPod = "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
		}
		if ipStackType == "ipv6single" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
			cmdOnPod = "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
		}

		for i := 0; i < len(EIPPods); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, ns1, EIPPods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("9.1. Create a 3rd test pod on egress node but do not label it so this pod will not use egressIP")
		nonEIPPod := pingPodResourceNode{
			name:      "hello-pod" + "-non-eip-" + ns1,
			namespace: ns1,
			nodename:  egressNodes[0],
			template:  pingPodNodeTemplate,
		}
		defer removeResource(oc, true, true, "pod", nonEIPPod.name, "-n", nonEIPPod.namespace)
		nonEIPPod.createPingPodNode(oc)
		waitPodReady(oc, ns1, nonEIPPod.name)

		nonEIPPodIP2, nonEIPPodIP1 := getPodIPUDN(oc, ns1, nonEIPPod.name, "ovn-udn1")

		// Add iptables rules to assist the test for traffic forwarding between nonEIP pod and external
		defer restoreIptablesRules(host)
		err = addIPtablesRules(host, allNodesIP1[1], nonEIPPodIP2, nonEIPPodIP1)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("9.2. Verify the non-EIP pod does not use EIP as source IP in its egressing packets, it directly uses its own UDN podIP as sourceIP")
		tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, ns1, nonEIPPod.name, cmdOnPod)
		o.Expect(strings.Contains(tcpdumOutput, nonEIPPodIP1)).To(o.BeTrue(), "Pod that unqualified to use egressIP did not use its UDN podIP as sourceIP!!!")
		o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeFalse(), "Pod that unqualified to use egressIP should not see egressIP as sourceIP in its egress packets!!!")

		compat_otp.By("10. Label the second node with egressNodeLabel, unlabel the first node, verify the new egress node is updated in the egressip object.\n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")

		egressipErr := wait.PollUntilContextTimeout(context.Background(), 20*time.Second, 360*time.Second, false, func(cxt context.Context) (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 1 || egressIPMaps1[0]["node"] == egressNodes[0] {
				e2e.Logf("Wait for egressIP being applied to new egress node,try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to update egress node:%s", egressipErr))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNodes[1]))

		compat_otp.By("11.1. Verify advertised egressIP route is updated with correct nexthop IP after failover")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			nodeIPEgressNode = getNodeIPv4(oc, "default", egressNodes[1])
		}
		if ipStackType == "ipv6single" {
			_, nodeIPEgressNode = getNodeIP(oc, egressNodes[1])
		}
		o.Expect(nodeIPEgressNode).NotTo(o.BeEmpty())
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, egressIPMaps1[0]["egressIP"], nodeIPEgressNode, true)
			return result
		}, "90s", "15s").Should(o.BeTrue(), "egressIP on default network with random unused IP was not advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("11.2. Verify advertised egressIP route to all other cluster nodes is updated with correct nexthop IP after failover")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, egressIPMaps1[0]["node"], allNodes, egressIPMaps1[0]["egressIP"], nodeIPEgressNode, true)
		// 	return result
		// }, "90s", "5s").Should(o.BeTrue(), "egressIP on default network with random unused IP was not advertised to all other cluster nodes!!")

		compat_otp.By("12.1 From local and remote EIP pods, validate egressIP on new egressNode after egressIP failover \n")
		primaryInf, infErr = getSnifPhyInf(oc, egressNodes[1])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		if ipStackType == "ipv4single" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
		}
		if ipStackType == "ipv6single" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
		}
		for i := 0; i < len(EIPPods); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[1], tcpdumpCmd, ns1, EIPPods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("12.2 Verify that after egressIP failover, the non-EIP pod still just uses its own UDN podIP as sourceIP")
		primaryInf, infErr = getSnifPhyInf(oc, egressNodes[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
		}
		if ipStackType == "ipv6single" {
			tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
		}

		tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, ns1, nonEIPPod.name, cmdOnPod)
		o.Expect(strings.Contains(tcpdumOutput, nonEIPPodIP1)).To(o.BeTrue(), "After failover, pod that unqualified to use egressIP did not use its UDN podIP as sourceIP!!!")
		o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeFalse(), "After failover, pod that unqualified to use egressIP should not see egressIP as sourceIP in its egress packets!!!")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-79766-On default network, only egressIP on the egressNode that has label matching EIP nodeSelector will be advertised (singlestack) [Serial]", func() {

		var (
			buildPruningBaseDir       = testdata.FixturePath("networking")
			egressIP2Template         = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodTemplate           = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			raEipNodeSelectorTemplate = filepath.Join(buildPruningBaseDir, "bgp/ra_defaultnetwork_template.yaml")
			egressNodeLabel           = "k8s.ovn.org/egress-assignable"
			nodeSelectorKey           = "node"
			nodeSelectorValue         = "A"
			podLabelKey               = "color"
			podLabelValues            = []string{"pink", "blue"}
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		ipStackType := checkIPStackType(oc)
		// If cluster is dualstack, it will be used as singlev4 cluster in this case,
		// A full daulstack scenario will be covered in a separate test case because each dualstack egressIP uses two nodes
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1. Get a namespace, label the namespace with org=qe to match namespaceSelector of egressIP object that will be created in step 4")
		ns1 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2. Label two nodes to be egress nodes with egress-assignable=true, but only label first egress node with node=A to match egressIP's nodeSelector in RA")
		for _, egressNode := range egressNodes {
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		}
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], nodeSelectorKey)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], nodeSelectorKey, nodeSelectorValue)

		compat_otp.By("3.1 Apply a new RA with egressIP in spec.advertisements on default network")
		raName := "ra-eip-nodeselector"
		defer removeResource(oc, true, true, "ra", raName)
		params := []string{"-f", raEipNodeSelectorTemplate, "-p", "NAME=" + raName, "ADVERTISETYPE=" + advertiseType}
		compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
		raErr := checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement with egressIP does not have the right condition status")
		e2e.Logf("SUCCESS - routeAdvertisement with egressIP applied is accepted")

		compat_otp.By("3.2 Patch add a nodeSelector node=A to be used by EgressIP advertisement")
		patchChange2 := `{"spec":{"nodeSelector":{"matchLabels":{"node":"A"}}}}`
		patchResourceAsAdmin(oc, "RouteAdvertisements/"+raName, patchChange2)

		raErr = checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - Updated 2nd RA is still in Accepted state after patch changes")

		compat_otp.By("4. Create two egressip objects, each with an usused IP from same subnet of egress node, verify both egressIPs are assigned to egress node")
		e2e.Logf("get freeIP from node: %s", egressNodes[0])
		var freeIPs []string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			freeIPs = findFreeIPs(oc, egressNodes[0], 2)
		}
		if ipStackType == "ipv6single" {
			freeIPs = findFreeIPv6s(oc, egressNodes[0], 2)
		}
		o.Expect(len(freeIPs)).Should(o.Equal(2))

		var expectedAdvertisedEIPMap1, expectedAdvertisedEIPMap2, expectedAdvertisedEIPMaps []map[string]string
		egressip1s := make([]egressIPResource1, 2)
		for i := 0; i < 2; i++ {
			egressip1s[i] = egressIPResource1{
				name:          "egressip-79766-" + strconv.Itoa(i),
				template:      egressIP2Template,
				egressIP1:     freeIPs[i],
				nsLabelKey:    "org",
				nsLabelValue:  "qe",
				podLabelKey:   podLabelKey,
				podLabelValue: podLabelValues[i],
			}
			defer egressip1s[i].deleteEgressIPObject1(oc)
			egressip1s[i].createEgressIPObject2(oc)
			egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1s[i].name)
			e2e.Logf("\negressIPMaps1: %v", egressIPMaps1)
			o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
			o.Expect(egressIPMaps1[0]["node"]).NotTo(o.Equal(""))
			expectedAdvertisedEIPMaps = append(expectedAdvertisedEIPMaps, egressIPMaps1[0])
			if egressIPMaps1[0]["node"] == egressNodes[0] {
				expectedAdvertisedEIPMap1 = egressIPMaps1
			}
			if egressIPMaps1[0]["node"] == egressNodes[1] {
				expectedAdvertisedEIPMap2 = egressIPMaps1
			}
		}
		e2e.Logf("\ncurrent expectedAdvertisedEIPMap: %v", expectedAdvertisedEIPMap1)

		compat_otp.By("5.1 Verify selected egress node has its assigned egressIP address be advertised to external frr router")
		var nodeIPEgressNode1, nodeIPEgressNode2 string
		// since we treat dualstack cluster as singlev4 cluster in this case, only get egress node's IPv4 address even for dualstack cluster.
		// There is separate case for BGP egressIP cases on dualstack
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			nodeIPEgressNode1 = getNodeIPv4(oc, "default", egressNodes[0])
			nodeIPEgressNode2 = getNodeIPv4(oc, "default", egressNodes[1])
		}
		if ipStackType == "ipv6single" {
			_, nodeIPEgressNode1 = getNodeIP(oc, egressNodes[0])
			_, nodeIPEgressNode2 = getNodeIP(oc, egressNodes[1])
		}
		o.Expect(nodeIPEgressNode1).NotTo(o.BeEmpty())
		o.Expect(nodeIPEgressNode2).NotTo(o.BeEmpty())
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, expectedAdvertisedEIPMap1[0]["egressIP"], nodeIPEgressNode1, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL - The first selected egressNode has its egressIP on default network not advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("5.2 Verify selected egress node has its assigned egressIP address be advertised to other cluster nods")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, expectedAdvertisedEIPMap1[0]["node"], allNodes, expectedAdvertisedEIPMap1[0]["egressIP"], nodeIPEgressNode1, true)
		// 	return result
		// }, "60s", "5s").Should(o.BeTrue(), "FAIL-The first selected egressNode has its egressIP on default network not advertised to all other cluster nodes!!")

		compat_otp.By("5.3 Verify second egressIP on the second egress node is not showing up in BGP routing table of external frr because it does not have matching nodeSelector")
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, expectedAdvertisedEIPMap2[0]["egressIP"], nodeIPEgressNode2, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL - The second egress node should not have its egressIP on default network advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("5.4 Verify second egressIP on the second egress node is not showing up in BGP routing table of cluster nodes because it does not have matching nodeSelector")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, expectedAdvertisedEIPMap2[0]["node"], allNodes, expectedAdvertisedEIPMap2[0]["egressIP"], nodeIPEgressNode2, false)
		// 	return result
		// }, "60s", "5s").Should(o.BeTrue(), "FAIL-The second egress node should not have its egressIP on default network advertised to all other cluster nodes!!")

		compat_otp.By("6. Label the second egress node with node=A to match egressIP's nodeSelector in RA")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], nodeSelectorKey)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], nodeSelectorKey, nodeSelectorValue)

		compat_otp.By("7.1 Verify the second selected egress node has its assigned egressIP address be advertised to external frr router as well")
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, expectedAdvertisedEIPMap2[0]["egressIP"], nodeIPEgressNode2, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL - The second selected egressNode has egressIP on default network not advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("7.2 Verify the second selected egress node has its assigned egressIP address be advertised to other cluster nods as well")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, expectedAdvertisedEIPMap2[0]["node"], allNodes, expectedAdvertisedEIPMap2[0]["egressIP"], nodeIPEgressNode2, true)
		// 	return result
		// }, "60s", "5s").Should(o.BeTrue(), "FAIL - The second selected egressNode has egressIP on default network not advertised to all other cluster nodes!!")

		compat_otp.By("8.1 Create two pods without specifying which node they are on, give them different podLabels so they are associated with different egressIPs")
		EIPPods := make([]pingPodResource, 2)
		for i := 0; i < 2; i++ {
			EIPPods[i] = pingPodResource{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: ns1,
				template:  pingPodTemplate,
			}
			EIPPods[i].createPingPod(oc)
			waitPodReady(oc, EIPPods[i].namespace, EIPPods[i].name)
			defer compat_otp.LabelPod(oc, ns1, EIPPods[i].name, podLabelKey+"-")
			err = compat_otp.LabelPod(oc, ns1, EIPPods[i].name, podLabelKey+"="+podLabelValues[i])
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("8.2. Verify egressIP works from each egressIP pod")
		for i := 0; i < len(EIPPods); i++ {
			e2e.Logf("Trying to get physical interface of egressNode %s that is associated with EIPPod: %s", expectedAdvertisedEIPMaps[i]["node"], EIPPods[i].name)
			primaryInf, infErr := getSnifPhyInf(oc, expectedAdvertisedEIPMaps[i]["node"])
			o.Expect(infErr).NotTo(o.HaveOccurred())

			var tcpdumpCmd, cmdOnPod string
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
				cmdOnPod = "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
			}
			if ipStackType == "ipv6single" {
				tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
				cmdOnPod = "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
			}
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, expectedAdvertisedEIPMaps[i]["node"], tcpdumpCmd, ns1, EIPPods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[i])).To(o.BeTrue())
		}

		compat_otp.By("9.1 Unlabel the first egress node with node-, verify the first egress node's assigned egressIP will change to not be advertised ")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], nodeSelectorKey)

		compat_otp.By("9.2 egressIP on unselected first egress node should be de-advertised from external frr")
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, expectedAdvertisedEIPMap1[0]["egressIP"], nodeIPEgressNode1, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-Un-selected egressNode has its assigned egressIP on default network still advertised to external frr incorrectly!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("9.3 egressIP on unselected first egress node should be de-advertised from all other cluster nodes")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, expectedAdvertisedEIPMap1[0]["node"], allNodes, expectedAdvertisedEIPMap1[0]["egressIP"], nodeIPEgressNode1, false)
		// 	return result
		// }, "60s", "5s").Should(o.BeTrue(), "FAIL-Un-selected egressNode has its assigned egressIP on default network still advertised to all other cluster nodes incorrectly!!")

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-79767-On CUDN, only egressIP on the egressNode that has label matching EIP nodeSelector will be advertised (singlestack) [Serial]", func() {

		var (
			buildPruningBaseDir       = testdata.FixturePath("networking")
			egressIP2Template         = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodTemplate           = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			raEipNodeSelectorTemplate = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			egressNodeLabel           = "k8s.ovn.org/egress-assignable"
			nodeSelectorKey           = "node"
			nodeSelectorValue         = "A"
			networkSelectorKey        = "app"
			networkSelectorValue      = "udn"
			cudnName                  = "cudn-network-79767"
			matchLabelKey             = "cudn-bgp"
			matchValue                = "cudn-network-" + getRandomString()
			podLabelKey               = "color"
			podLabelValues            = []string{"pink", "blue"}
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		ipStackType := checkIPStackType(oc)
		// If cluster is dualstack, it will be used as singlev4 cluster in this case,
		// A full daulstack scenario will be covered in a separate test case because each dualstack egressIP uses two nodes
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1. Create a UDN namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("1.2 Create CUDN in the UDN namespace, label the namespace with org=qe to match namespaceSelector of egressIP objects that will be created in step 5")
		var cidr, ipv4cidr, ipv6cidr string
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::/48"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::/48"
			}
		}

		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, cudnName, ipv4cidr, ipv6cidr, cidr, "layer3")
		o.Expect(err).NotTo(o.HaveOccurred())

		//label the CUDN with label app=udn that matches the networkSelector of UDN RA
		compat_otp.By("2. Label the CUDN with label that matches networkSelector in egressIP RA")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns1, "clusteruserdefinednetwork", cudnName, networkSelectorKey+"-").Execute()
		setUDNLabel(oc, cudnName, networkSelectorKey+"="+networkSelectorValue)

		compat_otp.By("3. Label two nodes to be egress nodes with egress-assignable=true, but only label first egress node with node=A to match egressIP's nodeSelector in RA")
		for _, egressNode := range egressNodes {
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		}
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], nodeSelectorKey)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], nodeSelectorKey, nodeSelectorValue)

		compat_otp.By("4.1 Apply a new RA to select CUDN, since the new RA has both PodNetwork and EgressIP in its spec.advertisements, remove PodNetwork in next step")
		raName := "ra-cudn-eip-nodeselector"
		defer removeResource(oc, true, true, "ra", raName)
		params := []string{"-f", raEipNodeSelectorTemplate, "-p", "NAME=" + raName, "NETWORKSELECTORKEY=" + networkSelectorKey, "NETWORKSELECTORVALUE=" + networkSelectorValue, "ADVERTISETYPE=" + advertiseType}
		compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
		raErr := checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement with egressIP nodeSelector applied does not have the right condition status")
		e2e.Logf("SUCCESS - routeAdvertisement applied is accepted")

		compat_otp.By("4.3 Patch add a nodeSelector node=A to be used by EgressIP advertisement")
		patchChange2 := `{"spec":{"nodeSelector":{"matchLabels":{"node":"A"}}}}`
		patchResourceAsAdmin(oc, "RouteAdvertisements/"+raName, patchChange2)

		raErr = checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - Updated 2nd RA is still in Accepted state after patch changes")

		compat_otp.By("5. Create two egressip objects, each with an usused IP from same subnet of egress node, verify both egressIPs are assigned to egress node")
		e2e.Logf("get freeIP from node: %s", egressNodes[0])
		var freeIPs []string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			freeIPs = findFreeIPs(oc, egressNodes[0], 2)
		}
		if ipStackType == "ipv6single" {
			freeIPs = findFreeIPv6s(oc, egressNodes[0], 2)
		}
		o.Expect(len(freeIPs)).Should(o.Equal(2))

		var expectedAdvertisedEIPMap1, expectedAdvertisedEIPMap2, expectedAdvertisedEIPMaps []map[string]string
		egressip1s := make([]egressIPResource1, 2)
		for i := 0; i < 2; i++ {
			egressip1s[i] = egressIPResource1{
				name:          "egressip-79767-" + strconv.Itoa(i),
				template:      egressIP2Template,
				egressIP1:     freeIPs[i],
				nsLabelKey:    "org",
				nsLabelValue:  "qe",
				podLabelKey:   podLabelKey,
				podLabelValue: podLabelValues[i],
			}
			defer egressip1s[i].deleteEgressIPObject1(oc)
			egressip1s[i].createEgressIPObject2(oc)
			egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1s[i].name)
			e2e.Logf("\negressIPMaps1: %v", egressIPMaps1)
			o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
			o.Expect(egressIPMaps1[0]["node"]).NotTo(o.Equal(""))
			expectedAdvertisedEIPMaps = append(expectedAdvertisedEIPMaps, egressIPMaps1[0])
			if egressIPMaps1[0]["node"] == egressNodes[0] {
				expectedAdvertisedEIPMap1 = egressIPMaps1
			}
			if egressIPMaps1[0]["node"] == egressNodes[1] {
				expectedAdvertisedEIPMap2 = egressIPMaps1
			}
		}
		e2e.Logf("\n current expectedAdvertisedEIPMap: %v", expectedAdvertisedEIPMap1)

		compat_otp.By("6.1 Verify selected egress node has its assigned egressIP advertised to external frr router")
		var nodeIPEgressNode1, nodeIPEgressNode2 string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			nodeIPEgressNode1 = getNodeIPv4(oc, "default", egressNodes[0])
			nodeIPEgressNode2 = getNodeIPv4(oc, "default", egressNodes[1])
		}
		if ipStackType == "ipv6single" {
			_, nodeIPEgressNode1 = getNodeIP(oc, egressNodes[0])
			_, nodeIPEgressNode2 = getNodeIP(oc, egressNodes[1])
		}
		o.Expect(nodeIPEgressNode1).NotTo(o.BeEmpty())
		o.Expect(nodeIPEgressNode2).NotTo(o.BeEmpty())
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, expectedAdvertisedEIPMap1[0]["egressIP"], nodeIPEgressNode1, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-The first selected egressNode has its assigned egressIP on CUDN not advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("6.2 Verify selected egress node has its assigned egressIP advertised to other cluster nods")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, expectedAdvertisedEIPMap1[0]["node"], allNodes, expectedAdvertisedEIPMap1[0]["egressIP"], nodeIPEgressNode1, true)
		// 	return result
		// }, "60s", "5s").Should(o.BeTrue(), "FAIL-The first selected egressNode has its assigned egressIP on CUDN not advertised to all other cluster nodes!!")

		compat_otp.By("6.3 Verify second egressIP on the second egress node is not showing up in BGP routing table of external frr because it does not have matching nodeSelector")
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, expectedAdvertisedEIPMap2[0]["egressIP"], nodeIPEgressNode2, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL - The second egress node should not have its egressIP on CUDN advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("6.4 Verify second egressIP on the second egress node is not showing up in BGP routing of cluster nodes because it does not have matching nodeSelector")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, expectedAdvertisedEIPMap2[0]["node"], allNodes, expectedAdvertisedEIPMap2[0]["egressIP"], nodeIPEgressNode2, false)
		// 	return result
		// }, "60s", "5s").Should(o.BeTrue(), "FAIL-The second egress node should not have its egressIP on CUDN advertised to all other cluster nodes!!")

		compat_otp.By("7. Label the second egress node with node=A to match egressIP's nodeSelector in RA")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], nodeSelectorKey)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], nodeSelectorKey, nodeSelectorValue)

		compat_otp.By("8.1 Verify the second selected egress node has its assigned egressIP advertised to external frr router as well")
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, expectedAdvertisedEIPMap2[0]["egressIP"], nodeIPEgressNode2, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-The second selected egressNode has its assigned egressIP on CUDN not advertised to external frr!!")

		// Comment out checking advertisement on cluster nodes for now
		// compat_otp.By("8.2 Verify the second selected egress node has its assigned egressIP advertised to other cluster nods as well")
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, expectedAdvertisedEIPMap2[0]["node"], allNodes, expectedAdvertisedEIPMap2[0]["egressIP"], nodeIPEgressNode2, true)
		// 	return result
		// }, "60s", "5s").Should(o.BeTrue(), "FAIL-The second selected egressNode has its assigned egressIP on CUDN not advertised to all other cluster nodes!!")

		compat_otp.By("9.1 Create two pods without specifying which nodes they are on, give them different podLabels so they are associated with different egressIPs")
		EIPPods := make([]pingPodResource, 2)
		for i := 0; i < 2; i++ {
			EIPPods[i] = pingPodResource{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: ns1,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", EIPPods[i].name, "-n", EIPPods[i].namespace)
			EIPPods[i].createPingPod(oc)
			waitPodReady(oc, EIPPods[i].namespace, EIPPods[i].name)
			defer compat_otp.LabelPod(oc, ns1, EIPPods[i].name, podLabelKey+"-")
			err = compat_otp.LabelPod(oc, ns1, EIPPods[i].name, podLabelKey+"="+podLabelValues[i])
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("9.2. Verify egressIP works from each egressIP pod")
		for i := 0; i < len(EIPPods); i++ {
			e2e.Logf("Trying to get physical interface of egressNode %s that is associated with EIPPod: %s", expectedAdvertisedEIPMaps[i]["node"], EIPPods[i].name)
			primaryInf, infErr := getSnifPhyInf(oc, expectedAdvertisedEIPMaps[i]["node"])
			o.Expect(infErr).NotTo(o.HaveOccurred())

			var tcpdumpCmd, cmdOnPod string
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
				cmdOnPod = "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
			}
			if ipStackType == "ipv6single" {
				tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
				cmdOnPod = "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
			}
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, expectedAdvertisedEIPMaps[i]["node"], tcpdumpCmd, ns1, EIPPods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[i])).To(o.BeTrue())
		}

		compat_otp.By("10. Unlabel the first egress node with node-, verify the first egress node's assigned egressIP will change to not be advertised ")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], nodeSelectorKey)

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, expectedAdvertisedEIPMap1[0]["egressIP"], nodeIPEgressNode1, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-Un-selected egressNode has its assigned egressIP on CUDN still advertised to external frr incorrectly!!")

		// Comment out checking advertisement on cluster nodes for now
		// o.Eventually(func() bool {
		// 	result := verifySingleBGPRouteOnClusterNode(oc, expectedAdvertisedEIPMap1[0]["node"], allNodes, expectedAdvertisedEIPMap1[0]["egressIP"], nodeIPEgressNode1, false)
		// 	return result
		// }, "60s", "5s").Should(o.BeTrue(), "FAIL-Un-selected egressNode has its assigned egressIP on CUDN still advertised to all other cluster nodes incorrectly!!")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-80047-Configuring egressIP advertisement on L2 CUDN is rejected (singlestack)", func() {

		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			raTemplate           = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			networkselectorkey   = "app"
			networkselectorvalue = "udn"
			cudnName             = "cudn-network-80047"
			matchLabelKey        = "cudn-bgp"
			matchValue           = "cudn-network-" + getRandomString()
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		ipStackType := checkIPStackType(oc)
		// If cluster is dualstack, it will be used as singlev4 cluster in this case,
		// A full daulstack scenario will be covered in a separate test case because each dualstack egressIP uses two nodes, will need total of 4 nodes for egressIP failover
		if len(nodeList.Items) < 2 {
			g.Skip("Need minimal 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1.1 Create a UDN namespace, label the UDN namespace with CUDN namespaceSelector")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("1.2 Label the UDN namespace to match namespaceSelector of egressIP object that will be created in step 5")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2.1 Create L2 CUDN in the UDN namespace")
		var cidr, ipv4cidr, ipv6cidr string
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::/48"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::/48"
			}
		}

		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, cudnName, ipv4cidr, ipv6cidr, cidr, "layer2")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2.2 Label the CUDN with label that matches networkSelector in routeAdvertisement")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns1, "clusteruserdefinednetwork", cudnName, networkselectorkey+"-").Execute()
		setUDNLabel(oc, cudnName, networkselectorkey+"="+networkselectorvalue)

		compat_otp.By("3.1 Apply a second RA that has egressIP in spec.advertisements but does not have nodeSelector,  and it has matching networkSelector to select UDN created above")
		raname := "ra-udn-eip"
		params := []string{"-f", raTemplate, "-p", "NAME=" + raname, "NETWORKSELECTORKEY=" + networkselectorkey, "NETWORKSELECTORVALUE=" + networkselectorvalue, "ADVERTISETYPE=" + advertiseType}
		defer removeResource(oc, true, true, "ra", raname)
		compat_otp.ApplyNsResourceFromTemplate(oc, oc.Namespace(), params...)
		status, err1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("ra", raname, "-ojsonpath={.status.conditions[0].status}").Output()
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(status, "False")).To(o.BeTrue())
		reason, err2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("ra", raname, "-ojsonpath={.status.conditions[0].reason}").Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(reason, "ConfigurationError")).To(o.BeTrue())
		message, err3 := oc.AsAdmin().WithoutNamespace().Run("get").Args("ra", raname, "-ojsonpath={.status.conditions[0].message}").Output()
		o.Expect(err3).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(message, "EgressIP advertisement is currently not supported for Layer2 networks, network: cluster_udn_"+cudnName)).To(o.BeTrue())

	})

	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-80048-egressIP without or with nodeSelector on  default network can be advertised correctly and egressIP functions well (dualstack) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_defaultnetwork_template.yaml")
			egressIP1Template   = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			egressNodeLabel     = "k8s.ovn.org/egress-assignable"
			nodeSelectorKey     = "node"
			nodeSelectorValue   = "A"
		)
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		ipStackType := checkIPStackType(oc)
		if ipStackType != "dualstack" {
			g.Skip("This case only test egressIP dualstack scenario, skip on singlestack cluster!!!")
		}
		// since BGP only run on RDU, all worker nodes have same subnet, skip check the subnet.
		if len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test, the prerequirement was not fullfilled, skip the case!!!")
		}

		compat_otp.By("1. Apply a new RA that select default network, patch change its spec.advertisements so that only egressIP is in its spec.advertisements")
		raName := "ra-eip-nodeselector"
		defer removeResource(oc, true, true, "ra", raName)
		params := []string{"-f", raTemplate, "-p", "NAME=" + raName, "ADVERTISETYPE=" + advertiseType}
		compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
		raErr := checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement with egressIP does not have the right condition status")
		e2e.Logf("SUCCESS - routeAdvertisement with egressIP applied is accepted")

		// no need to defer restore its original value as the RA will be defer deleted
		patchChange1 := `[{"op": "replace", "path": "/spec/advertisements", "value":["EgressIP"]}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("routeadvertisements/"+raName, "--type=json", "-p", patchChange1).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		raErr = checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement updated with only egressIP does not have the right condition status")
		e2e.Logf("SUCCESS - RA is still in Accepted state after it is updated to only have egressIP advertisement")

		compat_otp.By("2. Label two egressNodes")
		egressNode := []string{nodeList.Items[0].Name, nodeList.Items[1].Name}
		for i := 0; i < len(egressNode); i++ {
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode[i], egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode[i], egressNodeLabel, "true")
		}

		compat_otp.By("3. Get namespace for default network, label the namespace with name=test to match namespaceSelector of egressIP object")
		ns := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Create a dualstack egressip object, verify v4 and v6 egressIP addresses are assigned to an egress node separately")
		freeIPv4 := findFreeIPs(oc, egressNode[0], 1)
		o.Expect(len(freeIPv4)).Should(o.Equal(1))
		freeIPv6 := findFreeIPv6s(oc, egressNode[1], 1)
		o.Expect(len(freeIPv6)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:      "egressip-80048",
			template:  egressIP1Template,
			egressIP1: freeIPv4[0],
			egressIP2: freeIPv6[0],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)

		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
		var assignedEIPNodev4, assignedEIPNodev6 string
		for _, eipMap := range egressIPMaps1 {
			if netutils.IsIPv4String(eipMap["egressIP"]) {
				assignedEIPNodev4 = eipMap["node"]
			}
			if netutils.IsIPv6String(eipMap["egressIP"]) {
				assignedEIPNodev6 = eipMap["node"]
			}
		}
		o.Expect(assignedEIPNodev4).NotTo(o.Equal(""))
		o.Expect(assignedEIPNodev6).NotTo(o.Equal(""))
		e2e.Logf("For the dualstack EIP,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)

		compat_otp.By("5. Create a pod without specifying which node it is created on")
		EIPPod := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", EIPPod.name, "-n", EIPPod.namespace)
		EIPPod.createPingPod(oc)
		waitPodReady(oc, EIPPod.namespace, EIPPod.name)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6. verify egressIP has been advertised to external frr")
		// Verify v4 egressIP advertisement
		nodeIPEgressNodev4 := getNodeIPv4(oc, "default", assignedEIPNodev4)
		e2e.Logf("Got v4 nodeIP for assigned v4 egressNode %s: %s", assignedEIPNodev4, nodeIPEgressNodev4)
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv4[0], nodeIPEgressNodev4, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr!!")

		// Verify v6 egressIP advertisement
		nodeIPEgressNodev6, _ := getNodeIP(oc, assignedEIPNodev6)
		e2e.Logf("Got v6 nodeIP for assigned v6 egressNode %s: %s", assignedEIPNodev6, nodeIPEgressNodev6)
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv6[0], nodeIPEgressNodev6, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr!!")

		compat_otp.By("7. Verify egressIP works from the egressIP pod")
		//Verify from v4 perspective
		primaryInfv4, infErr := getSnifPhyInf(oc, assignedEIPNodev4)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv4 := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInfv4, externalServiceipv4)
		cmdOnPodv4 := "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns, EIPPod.name, cmdOnPodv4)
		o.Expect(strings.Contains(tcpdumOutputv4, freeIPv4[0])).To(o.BeTrue())

		//Verify from v6 perspective
		primaryInfv6, infErr := getSnifPhyInf(oc, assignedEIPNodev6)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv6 := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInfv6, externalServiceipv6)
		cmdOnPodv6 := "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv6 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns, EIPPod.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, freeIPv6[0])).To(o.BeTrue())

		compat_otp.By("8. Validate egressIP after egressIP failover")
		compat_otp.By("8.1 Label a third node to be egress-assignable node, make v4 egressIP failover to it, free up the previous assigned v4 egressNode")
		candidateEIPNode := nodeList.Items[2].Name
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev4, egressNodeLabel)

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, candidateEIPNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, candidateEIPNode, egressNodeLabel, "true")

		egressipErr := wait.Poll(10*time.Second, 350*time.Second, func() (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 2 || egressIPMaps1[0]["node"] == assignedEIPNodev4 || egressIPMaps1[1]["node"] == assignedEIPNodev4 {
				e2e.Logf("Wait for v4 egressIP fail over to new egress node,try next round...")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("v4 egeressIP failed to fail over to new egress node, got err:%s", egressipErr))

		o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
		freedUpNode := assignedEIPNodev4
		assignedEIPNodev4 = candidateEIPNode

		compat_otp.By("8.2 Label the freed up node again, and make v6 egressIP failover to it")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev6, egressNodeLabel)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, freedUpNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, freedUpNode, egressNodeLabel, "true")

		egressipErr = wait.Poll(10*time.Second, 350*time.Second, func() (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 2 || egressIPMaps1[0]["node"] == assignedEIPNodev6 || egressIPMaps1[1]["node"] == assignedEIPNodev6 {
				e2e.Logf("Wait for v6 egressIP fail over to the freed up egress node,try next round...")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("v6 egeressIP failed to new egress node:%s", egressipErr))

		o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
		assignedEIPNodev6 = freedUpNode

		e2e.Logf("SUCCESS - v4 and v6 egressIP failover succeeded")
		e2e.Logf("after egressIP failover,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)

		compat_otp.By("9. verify advertisement has changed after EIP failover")
		// Verify v4 egressIP advertisement after failover
		nodeIPEgressNodev4 = getNodeIPv4(oc, "default", assignedEIPNodev4)
		e2e.Logf("Got v4 nodeIP for assigned v4 egressNode %s: %s", assignedEIPNodev4, nodeIPEgressNodev4)
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv4[0], nodeIPEgressNodev4, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr!!")

		// Verify v6 egressIP advertisement after failover
		nodeIPEgressNodev6, _ = getNodeIP(oc, assignedEIPNodev6)
		e2e.Logf("Got v6 nodeIP for assigned v6 egressNode %s: %s", assignedEIPNodev6, nodeIPEgressNodev6)
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv6[0], nodeIPEgressNodev6, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr!!")

		compat_otp.By("10. Verify v4 and v6 egressIP still work after failover")
		primaryInfv4, infErr = getSnifPhyInf(oc, assignedEIPNodev4)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv4 = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInfv4, externalServiceipv4)
		cmdOnPodv4 = "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns, EIPPod.name, cmdOnPodv4)
		o.Expect(strings.Contains(tcpdumOutputv4, freeIPv4[0])).To(o.BeTrue())

		primaryInfv6, infErr = getSnifPhyInf(oc, assignedEIPNodev6)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv6 = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInfv6, externalServiceipv6)
		cmdOnPodv6 = "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns, EIPPod.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, freeIPv6[0])).To(o.BeTrue())

		compat_otp.By("11.1 Label the v4 egressNode with a label that matches nodeSelector of EgressIP advertisement in the RA")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev4, nodeSelectorKey)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, assignedEIPNodev4, nodeSelectorKey, nodeSelectorValue)

		compat_otp.By("11.2 Patch to add a nodeSelector node=A to be used by EgressIP advertisement in the RA")
		// no need to defer restore its original value as the RA will be defer deleted
		patchChange3 := `{"spec":{"nodeSelector":{"matchLabels":{"node":"A"}}}}`
		patchResourceAsAdmin(oc, "RouteAdvertisements/"+raName, patchChange3)

		raErr = checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - default RA is still in Accepted state after patch add non-empty nodeSelector for egressIP advertisement")

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv4[0], nodeIPEgressNodev4, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr while the egess node has label matching nodeSelector!!")

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv6[0], nodeIPEgressNodev6, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v6 egressIP should not be advertised as its egress node does not have a label matching nodeSelector!!")

		compat_otp.By("11.2 Unlabel v4 egressNode, label v6 egressNode with a label that matches nodeSelector of EgressIP advertisement in default RA")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev4, nodeSelectorKey)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev6, nodeSelectorKey)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, assignedEIPNodev6, nodeSelectorKey, nodeSelectorValue)

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv4[0], nodeIPEgressNodev4, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP should not be advertised as its egress node does not have a label matching nodeSelector!!")

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv6[0], nodeIPEgressNodev6, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v6 egressIP should be  advertised as its egress node has a label matching nodeSelector!!")

		compat_otp.By("11.3 Verify v4 and v6 egressIP still work regardless egressIP is advertised by nodeSelector or not")
		tcpdumpCmdv4 = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInfv4, externalServiceipv4)
		cmdOnPodv4 = "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns, EIPPod.name, cmdOnPodv4)
		o.Expect(strings.Contains(tcpdumOutputv4, freeIPv4[0])).To(o.BeTrue())

		tcpdumpCmdv6 = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInfv6, externalServiceipv6)
		cmdOnPodv6 = "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns, EIPPod.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, freeIPv6[0])).To(o.BeTrue())

	})

	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-80049-egressIP without or with nodeSelector on L3 CUDN can be advertised correctly and egressIP functions well (dualstack) [Serial]", func() {
		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			raCUDNTemplate       = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			egressIP1Template    = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			pingPodTemplate      = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			egressNodeLabel      = "k8s.ovn.org/egress-assignable"
			networkSelectorKey   = "app"
			networkSelectorValue = "udn"
			nodeSelectorKey      = "node"
			nodeSelectorValue    = "A"
			cudnName             = "cudn-l3-network-80049"
			matchLabelKey        = "cudn-bgp"
			matchValue           = "cudn-network-" + getRandomString()
		)
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		ipStackType := checkIPStackType(oc)
		if ipStackType != "dualstack" {
			g.Skip("This case only test egressIP dualstack scenario, skip on singlestack cluster!!!")
		}
		// since BGP only run on RDU, all worker nodes have same subnet, skip check the subnet.
		if len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test, the prerequirement was not fullfilled, skip the case!!!")
		}

		compat_otp.By("1. Label two egressNodes")
		egressNode := []string{nodeList.Items[0].Name, nodeList.Items[1].Name}
		for i := 0; i < len(egressNode); i++ {
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode[i], egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode[i], egressNodeLabel, "true")
		}

		compat_otp.By("2. Create an UDN namespace, label the namespace to match L3 CUDN created next, and label it with name=test to match namespaceSelector of egressIP object")
		oc.CreateNamespaceUDN()
		cudnNS := oc.Namespace()

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		var cidr, ipv4cidr, ipv6cidr string
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

		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, cudnName, ipv4cidr, ipv6cidr, cidr, "layer3")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3. Label the CUDN with label that matches networkSelector in egressIP RA")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", cudnNS, "clusteruserdefinednetwork", cudnName, networkSelectorKey+"-").Execute()
		setUDNLabel(oc, cudnName, networkSelectorKey+"="+networkSelectorValue)

		compat_otp.By("4.1 Apply a new RA to select CUDN, since the new RA has both PodNetwork and EgressIP in its spec.advertisements, remove PodNetwork in next step")
		raName := "ra-cudn-eip-nodeselector"
		defer removeResource(oc, true, true, "ra", raName)
		params := []string{"-f", raCUDNTemplate, "-p", "NAME=" + raName, "NETWORKSELECTORKEY=" + networkSelectorKey, "NETWORKSELECTORVALUE=" + networkSelectorValue, "ADVERTISETYPE=" + advertiseType}
		compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
		raErr := checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement with egressIP nodeSelector applied does not have the right condition status")
		e2e.Logf("SUCCESS - routeAdvertisement applied is accepted")

		compat_otp.By("4.2 Patch remove PodNetwork from the new RA's spec.advertisements so only EgressIP remains in spec.advertisements, this is to prepare for using non-empty nodeSelector for EgressIP")
		// no need to defer restore patch change because the ra-eip-nodeselector will be defer deleted
		patchChange := `[{"op": "replace", "path": "/spec/advertisements", "value":["EgressIP"]}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("routeadvertisements/"+raName, "--type=json", "-p", patchChange).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		compat_otp.By("5. Create a dualstack egressip object, verify v4 and v6 egressIP addresses are assigned to an egress node separately")
		freeIPv4 := findFreeIPs(oc, egressNode[0], 1)
		o.Expect(len(freeIPv4)).Should(o.Equal(1))
		freeIPv6 := findFreeIPv6s(oc, egressNode[1], 1)
		o.Expect(len(freeIPv6)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:      "egressip-80049",
			template:  egressIP1Template,
			egressIP1: freeIPv4[0],
			egressIP2: freeIPv6[0],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)

		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
		var assignedEIPNodev4, assignedEIPNodev6 string
		for _, eipMap := range egressIPMaps1 {
			if netutils.IsIPv4String(eipMap["egressIP"]) {
				assignedEIPNodev4 = eipMap["node"]
			}
			if netutils.IsIPv6String(eipMap["egressIP"]) {
				assignedEIPNodev6 = eipMap["node"]
			}
		}
		o.Expect(assignedEIPNodev4).NotTo(o.Equal(""))
		o.Expect(assignedEIPNodev6).NotTo(o.Equal(""))
		e2e.Logf("For the dualstack EIP,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)

		compat_otp.By("6. Create a pod without specifying which node it is created on")
		EIPPod := pingPodResource{
			name:      "hello-pod",
			namespace: cudnNS,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", EIPPod.name, "-n", EIPPod.namespace)
		EIPPod.createPingPod(oc)
		waitPodReady(oc, EIPPod.namespace, EIPPod.name)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6. verify egressIP has been advertised to external frr")
		// Verify v4 egressIP advertisement
		nodeIPEgressNodev4 := getNodeIPv4(oc, "default", assignedEIPNodev4)
		e2e.Logf("Got v4 nodeIP for assigned v4 egressNode %s: %s", assignedEIPNodev4, nodeIPEgressNodev4)
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv4[0], nodeIPEgressNodev4, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr!!")

		// Verify v6 egressIP advertisement
		nodeIPEgressNodev6, _ := getNodeIP(oc, assignedEIPNodev6)
		e2e.Logf("Got v6 nodeIP for assigned v6 egressNode %s: %s", assignedEIPNodev6, nodeIPEgressNodev6)
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv6[0], nodeIPEgressNodev6, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr!!")

		compat_otp.By("7. Verify both v4 and v6 egressIP work from the egressIP pod")
		//Verify from v4 perspective
		primaryInfv4, infErr := getSnifPhyInf(oc, assignedEIPNodev4)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv4 := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInfv4, externalServiceipv4)
		cmdOnPodv4 := "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, cudnNS, EIPPod.name, cmdOnPodv4)
		o.Expect(strings.Contains(tcpdumOutputv4, freeIPv4[0])).To(o.BeTrue())

		//Verify from v6 perspective
		primaryInfv6, infErr := getSnifPhyInf(oc, assignedEIPNodev6)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv6 := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInfv6, externalServiceipv6)
		cmdOnPodv6 := "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv6 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, cudnNS, EIPPod.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, freeIPv6[0])).To(o.BeTrue())

		compat_otp.By("8. Validate egressIP after egressIP failover")
		compat_otp.By("8.1 Label a third node to be egress-assignable node, make v4 egressIP failover to it, free up the previous assigned v4 egressNode")
		candidateEIPNode := nodeList.Items[2].Name
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev4, egressNodeLabel)

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, candidateEIPNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, candidateEIPNode, egressNodeLabel, "true")

		egressipErr := wait.Poll(10*time.Second, 350*time.Second, func() (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 2 || egressIPMaps1[0]["node"] == assignedEIPNodev4 || egressIPMaps1[1]["node"] == assignedEIPNodev4 {
				e2e.Logf("Wait for v4 egressIP fail over to new egress node,try next round...")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("v4 egeressIP failed to fail over to new egress node, got err:%s", egressipErr))

		o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
		freedUpNode := assignedEIPNodev4
		assignedEIPNodev4 = candidateEIPNode

		compat_otp.By("8.2 Label the freed up node again, and make v6 egressIP failover to it")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev6, egressNodeLabel)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, freedUpNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, freedUpNode, egressNodeLabel, "true")

		egressipErr = wait.Poll(10*time.Second, 350*time.Second, func() (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 2 || egressIPMaps1[0]["node"] == assignedEIPNodev6 || egressIPMaps1[1]["node"] == assignedEIPNodev6 {
				e2e.Logf("Wait for v6 egressIP fail over to the freed up egress node,try next round...")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("v6 egeressIP failed to new egress node:%s", egressipErr))

		o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
		assignedEIPNodev6 = freedUpNode

		e2e.Logf("SUCCESS - v4 and v6 egressIP failover succeeded")
		e2e.Logf("After egressIP failover,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)

		compat_otp.By("9. verify advertisement has changed after EIP failover")
		// Verify v4 egressIP advertisement after failover
		nodeIPEgressNodev4 = getNodeIPv4(oc, "default", assignedEIPNodev4)
		e2e.Logf("Got v4 nodeIP for assigned v4 egressNode %s: %s", assignedEIPNodev4, nodeIPEgressNodev4)
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv4[0], nodeIPEgressNodev4, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr!!")

		// Verify v6 egressIP advertisement after failover
		nodeIPEgressNodev6, _ = getNodeIP(oc, assignedEIPNodev6)
		e2e.Logf("Got v6 nodeIP for assigned v6 egressNode %s: %s", assignedEIPNodev6, nodeIPEgressNodev6)
		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv6[0], nodeIPEgressNodev6, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr!!")

		compat_otp.By("10. Verify v4 and v6 egressIP both work after failover")
		primaryInfv4, infErr = getSnifPhyInf(oc, assignedEIPNodev4)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv4 = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInfv4, externalServiceipv4)
		cmdOnPodv4 = "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, cudnNS, EIPPod.name, cmdOnPodv4)
		o.Expect(strings.Contains(tcpdumOutputv4, freeIPv4[0])).To(o.BeTrue())

		primaryInfv6, infErr = getSnifPhyInf(oc, assignedEIPNodev6)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv6 = fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInfv6, externalServiceipv6)
		cmdOnPodv6 = "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, cudnNS, EIPPod.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, freeIPv6[0])).To(o.BeTrue())

		compat_otp.By("11.1 Label the v4 egressNode with a label that matches nodeSelector of EgressIP advertisement in the RA")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev4, nodeSelectorKey)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, assignedEIPNodev4, nodeSelectorKey, nodeSelectorValue)

		compat_otp.By("11.2 Patch to add a nodeSelector node=A to be used by EgressIP advertisement in the RA")
		// no need to defer restore patch change because the ra-eip-nodeselector will be defer deleted
		patchChange3 := `{"spec":{"nodeSelector":{"matchLabels":{"node":"A"}}}}`
		patchResourceAsAdmin(oc, "RouteAdvertisements/"+raName, patchChange3)

		raErr = checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - default RA is still in Accepted state after patch add non-empty nodeSelector for egressIP advertisement")

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv4[0], nodeIPEgressNodev4, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP was not advertised to external frr while the egess node has label matching nodeSelector!!")

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv6[0], nodeIPEgressNodev6, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v6 egressIP should not be advertised as its egress node does not have a label matching nodeSelector!!")

		compat_otp.By("11.2 Unlabel v4 egressNode, label v6 egressNode with a label that matches nodeSelector of EgressIP advertisement in default RA")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev4, nodeSelectorKey)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, assignedEIPNodev6, nodeSelectorKey)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, assignedEIPNodev6, nodeSelectorKey, nodeSelectorValue)

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv4[0], nodeIPEgressNodev4, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v4 egressIP should not be advertised as its egress node does not have a label matching nodeSelector!!")

		o.Eventually(func() bool {
			result := verifySingleBGPRouteOnExternalFrr(host, freeIPv6[0], nodeIPEgressNodev6, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "FAIL-v6 egressIP should be  advertised as its egress node has a label matching nodeSelector!!")

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-80054-Validate EgressIP advertisement and load-balancing functionality with multiple egressIPs (each with multiple egressIPs) on default network and L3 UDNs (singlestack) .[Serial]", func() {
		var (
			buildPruningBaseDir   = testdata.FixturePath("networking")
			pingPodTemplate       = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			egressIPTemplate      = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			raDefaultEIPTemplate  = filepath.Join(buildPruningBaseDir, "bgp/ra_defaultnetwork_template.yaml")
			raUDNEIPTemplate      = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			egressNodeLabel       = "k8s.ovn.org/egress-assignable"
			matchLabelKey         = "cudn-bgp-1"
			matchValue            = "cudn-network-80054-1"
			cudnName              = "cudn-network-80054-1"
			layerSelection        = "layer3"
			networkSelectorKey2   = "app"
			networkSelectorValue2 = "udn"
		)

		compat_otp.By("1. Get two worker nodes that are in same subnet, they will be used as egress-assignable nodes, apply EgressLabel Key to them\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)

		compat_otp.By("2.1 Apply two RAs for egressIP in default network, first one to select default network, second one to select CUDN")
		raname1 := "ra-defaultnw-eip"
		params := []string{"-f", raDefaultEIPTemplate, "-p", "NAME=" + raname1, "ADVERTISETYPE=" + advertiseType}
		defer removeResource(oc, true, true, "ra", raname1)
		compat_otp.ApplyNsResourceFromTemplate(oc, oc.Namespace(), params...)

		compat_otp.By("2.2 Apply another RA for egressIP in CUDN with matching networkSelector to select CUDN")
		raname2 := "ra-udn-eip"
		params = []string{"-f", raUDNEIPTemplate, "-p", "NAME=" + raname2, "NETWORKSELECTORKEY=" + networkSelectorKey2, "NETWORKSELECTORVALUE=" + networkSelectorValue2, "ADVERTISETYPE=" + advertiseType}
		defer removeResource(oc, true, true, "ra", raname2)
		compat_otp.ApplyNsResourceFromTemplate(oc, oc.Namespace(), params...)

		compat_otp.By("3.1 Obtain first namespace for default network, create ns2 for L3 CUDN")
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		allNS := []string{ns1, ns2}

		compat_otp.By("3.2 Label CUDN namespace separately with matching label with its CUDN that will be created in step 3.4")
		compat_otp.By("3.3 Label each namespace with matching namespaceSelector with the egressIP in each that will be created in step 5")
		for i := 0; i < len(allNS); i++ {
			if i != 0 {
				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", allNS[i], fmt.Sprintf("%s-", matchLabelKey)).Execute()
				err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", allNS[i], fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			}
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", allNS[i], "name-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", allNS[i], "name="+"test"+strconv.Itoa(i)).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3.4 Create L3 CUDN in ns2")
		ipStackType := checkIPStackType(oc)
		ipv4cidr := "10.150.0.0/16"
		ipv6cidr := "2010:100:200::/48"
		cidr := "10.150.0.0/16"
		if ipStackType == "ipv6single" {
			cidr = "2010:100:200::/48"
		}

		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, cudnName, ipv4cidr, ipv6cidr, cidr, layerSelection)
		o.Expect(err).NotTo(o.HaveOccurred())

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns2, "clusteruserdefinednetwork", cudnName, networkSelectorKey2+"-").Execute()
		setUDNLabel(oc, cudnName, networkSelectorKey2+"="+networkSelectorValue2)

		compat_otp.By("4.1 Verify both RA are in Accepted state")
		raErr := checkRAStatus(oc, raname1, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - %s routeAdvertisement applied is accepted", raname1)

		raErr = checkRAStatus(oc, raname2, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - %s routeAdvertisement applied is accepted", raname2)

		compat_otp.By("5. Find total of 4 freeIPs from node subnet, use two free IP addresses to create an egressip object in each namespace\n")
		var freeIPs []string
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			freeIPs = findFreeIPs(oc, egressNodes[0], 4)
		}
		if ipStackType == "ipv6single" {
			freeIPs = findFreeIPv6s(oc, egressNodes[0], 4)
		}
		o.Expect(len(freeIPs)).Should(o.Equal(4))
		var egressIPMaps1 []map[string]string
		egressip1s := make([]egressIPResource1, 2)
		var expectedAdvertisedEIPMaps []map[string]string
		for i := 0; i < 2; i++ {
			egressip1s[i] = egressIPResource1{
				name:      "egressip-80054-" + strconv.Itoa(i),
				template:  egressIPTemplate,
				egressIP1: freeIPs[i*2+0],
				egressIP2: freeIPs[i*2+1],
			}
			egressip1s[i].createEgressIPObject1(oc)
			defer egressip1s[i].deleteEgressIPObject1(oc)
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1s[i].name)
			o.Expect(len(egressIPMaps1)).Should(o.Equal(2))
			o.Expect(egressIPMaps1[0]["node"]).NotTo(o.Equal(""))
			o.Expect(egressIPMaps1[1]["node"]).NotTo(o.Equal(""))
			expectedAdvertisedEIPMaps = append(expectedAdvertisedEIPMaps, egressIPMaps1[0])
			expectedAdvertisedEIPMaps = append(expectedAdvertisedEIPMaps, egressIPMaps1[1])

			//Patch change namespaceSelector of the egressIP object so it matches the label of its own namespace
			namespaceSelectorValue := "test" + strconv.Itoa(i)
			e2e.Logf("for egressIP %s, change its namespaceSelectorValue to: %s", egressip1s[i].name, namespaceSelectorValue)
			patchChange := fmt.Sprintf("[{\"op\": \"replace\", \"path\": \"/spec/namespaceSelector/matchLabels/name\", \"value\": \"%s\"}]", namespaceSelectorValue)
			patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/"+egressip1s[i].name, "--type=json", "-p", patchChange).Execute()
			o.Expect(patchErr).NotTo(o.HaveOccurred())
		}

		e2e.Logf("\nexpectedAdvertisedEIPMaps: %v", expectedAdvertisedEIPMaps)

		compat_otp.By("6. Verify each egressIP is advertised to external frr")
		for _, EIPMap := range expectedAdvertisedEIPMaps {
			var nodeIPEgressNode string
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				nodeIPEgressNode = getNodeIPv4(oc, "default", EIPMap["node"])
			}
			if ipStackType == "ipv6single" {
				_, nodeIPEgressNode = getNodeIP(oc, EIPMap["node"])
			}
			o.Expect(nodeIPEgressNode).NotTo(o.BeEmpty())
			o.Eventually(func() bool {
				result := verifySingleBGPRouteOnExternalFrr(host, EIPMap["egressIP"], nodeIPEgressNode, true)
				return result
			}, "60s", "5s").Should(o.BeTrue(), fmt.Sprintf("FAIL - egressIP %s was not advertised to external frr as expected !!!", EIPMap["egressIP"]))
		}

		compat_otp.By("7. Create a pod that is associated with each egressIP in its corresponding namespace ")
		EIPPods := make([]pingPodResource, 2)
		for i := 0; i < 2; i++ {
			EIPPods[i] = pingPodResource{
				name:      "eip-hello-pod" + strconv.Itoa(i) + "-" + allNS[i],
				namespace: allNS[i],
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", EIPPods[i].name, "-n", EIPPods[i].namespace)
			EIPPods[i].createPingPod(oc)
			waitPodReady(oc, EIPPods[i].namespace, EIPPods[i].name)

		}

		compat_otp.By("8. Verify egressIP pod can access external service, both egressIP addresses of each egressIP object are used as sourceIP in egressing packets from its egressIP pod")
		externalServiceIP := externalServiceipv4
		if ipStackType == "ipv6single" {
			externalServiceIP = externalServiceipv6
		}

		for i := 0; i < 2; i++ {
			var foundFirstEIP, foundSecondEIP bool = false, false
			for j := 0; j < 10; j++ {
				stdout, err := e2eoutput.RunHostCmd(EIPPods[i].namespace, EIPPods[i].name, fmt.Sprintf("curl --max-time 30 -g -q -s http://%s/clientip", net.JoinHostPort(externalServiceIP, "8000")))
				o.Expect(err).NotTo(o.HaveOccurred())

				if strings.Contains(stdout, expectedAdvertisedEIPMaps[i*2]["egressIP"]) {
					foundFirstEIP = true
				}
				if strings.Contains(stdout, expectedAdvertisedEIPMaps[i*2+1]["egressIP"]) {
					foundSecondEIP = true
				}

				if foundFirstEIP && foundSecondEIP {
					e2e.Logf("Both egressIP %s and %s are used, egressIP load-balancing functionality works correctly from pod %s", expectedAdvertisedEIPMaps[i*2]["egressIP"], expectedAdvertisedEIPMaps[i*2+1]["egressIP"], EIPPods[i].name)
					break
				}
			}
			o.Expect(foundFirstEIP).To(o.BeTrue(), fmt.Sprintf("Expected egressIP %s not found in stdout", expectedAdvertisedEIPMaps[i*2]["egressIP"]))
			o.Expect(foundSecondEIP).To(o.BeTrue(), fmt.Sprintf("Expected egressIP %s not found in stdout", expectedAdvertisedEIPMaps[i*2+1]["egressIP"]))
		}

	})

})
