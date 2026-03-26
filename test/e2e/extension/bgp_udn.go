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
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN ovn-kubernetes ibgp-cudn", func() {
	defer g.GinkgoRecover()

	var (
		oc                  = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		host                = ""
		allNodes            []string
		podNetwork1Map      = make(map[string]string)
		podNetwork2Map      = make(map[string]string)
		nodesIP1Map         = make(map[string]string)
		nodesIP2Map         = make(map[string]string)
		allNodesIP2         []string
		allNodesIP1         []string
		frrNamespace        = "openshift-frr-k8s"
		advertiseType       = "PodNetwork"
		externalServiceipv4 = "172.20.0.100"
		externalServiceipv6 = "2001:db8:2::100"
		frrContainerIPv4    = "192.168.111.3"
		frrContainerIPv6    = "fd2e:6f44:5dd8:c956::3"
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
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-78339-High-78348-route advertisement for UDN networks through VRF-default and route filtering with networkSelector [Serial]", func() {

		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			raTemplate           = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			pingPodTemplate      = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			networkselectorkey   = "app"
			networkselectorvalue = "udn"
			matchLabelKey        = []string{"cudn-bgp", "cudn-bgp2", "cudn-bgp3"}
			matchValue           = []string{"cudn-network1-" + getRandomString(), "cudn-network2-" + getRandomString(), "cudn-network3-" + getRandomString()}
			udnNames             = []string{"layer3-udn-78339-1", "layer3-udn-78339-2", "layer3-udn-78339-3"}
			udnNS                []string
		)

		compat_otp.By("1. Create two UDN namespaces, create a layer3 UDN in each UDN namespace, the two UDNs should NOT be overlapping")
		ipStackType := checkIPStackType(oc)
		var cidr, ipv4cidr, ipv6cidr []string
		ipv4cidr = []string{"10.150.0.0/16", "20.150.0.0/16", "30.150.0.0/16"}
		ipv6cidr = []string{"2010:100:200::/48", "2011:100:200::/48", "2012:100:200::/48"}
		cidr = []string{"10.150.0.0/16", "20.150.0.0/16", "30.150.0.0/16"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/48", "2011:100:200::/48", "2012:100:200::/48"}
		}

		for i := 0; i < 3; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey[i], matchValue[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			udnNS = append(udnNS, ns)
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", udnNames[i])
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey[i], matchValue[i], udnNames[i], ipv4cidr[i], ipv6cidr[i], cidr[i], "layer3")
			o.Expect(err).NotTo(o.HaveOccurred())
			//label clusteruserdefinednetwork with label app=udn for frist two CUDN that matches networkSelector in routeAdvertisement
			if i != 2 {
				setUDNLabel(oc, udnNames[i], "app=udn")
			}
		}

		compat_otp.By("3. Apply a routeAdvertisement with matching networkSelector")
		raname := "ra-udn"
		params := []string{"-f", raTemplate, "-p", "NAME=" + raname, "NETWORKSELECTORKEY=" + networkselectorkey, "NETWORKSELECTORVALUE=" + networkselectorvalue, "ADVERTISETYPE=" + advertiseType}
		defer removeResource(oc, true, true, "ra", raname)
		compat_otp.ApplyNsResourceFromTemplate(oc, oc.Namespace(), params...)
		raErr := checkRAStatus(oc, raname, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - UDN routeAdvertisement applied is accepted")

		compat_otp.By("4. Verify the first two UDNs with matching networkSelector are advertised")
		var UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 map[string]string
		for i := 0; i < 2; i++ {
			UDNnetwork_ipv6_ns, UDNnetwork_ipv4_ns := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+udnNames[i])

			// save pod nework info of first UDN, it will be be used in step 8
			if i == 0 {
				UDNnetwork_ipv6_ns1 = UDNnetwork_ipv6_ns
				UDNnetwork_ipv4_ns1 = UDNnetwork_ipv4_ns
			}
			o.Eventually(func() bool {
				result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns, UDNnetwork_ipv6_ns, nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "10s").Should(o.BeTrue(), "UDN with matching networkSelector was not advertised as expected!!")
		}

		compat_otp.By("5. Verify the third UDN without matching networkSelector is NOT advertised")
		UDNnetwork_ipv6_ns3, UDNnetwork_ipv4_ns3 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+udnNames[2])
		result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns3, UDNnetwork_ipv6_ns3, nodesIP1Map, nodesIP2Map, false)
		o.Expect(result).To(o.BeTrue(), "Unlablled UDN should not be advertised, but their routes are in routing table")

		compat_otp.By("6.1 Create a UDN pod in each UDN namespace associating with its UDN")
		testpods := make([]pingPodResource, len(udnNS))
		for i := 0; i < len(udnNS); i++ {
			testpods[i] = pingPodResource{
				name:      "hello-pod" + udnNS[i],
				namespace: udnNS[i],
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", testpods[i].name, "-n", udnNS[i])
			testpods[i].createPingPod(oc)
			waitPodReady(oc, testpods[i].namespace, testpods[i].name)
		}

		compat_otp.By("6.2 Verify UDN pod in first two UDN namespaces can be accessed from external but the UDN pod in 3rd UDN namespace is not accessible as its UDN was not advertised")
		Curlexternal2UDNPodPass(oc, host, udnNS[0], testpods[0].name)
		Curlexternal2UDNPodPass(oc, host, udnNS[1], testpods[1].name)
		Curlexternal2UDNPodFail(oc, host, udnNS[2], testpods[2].name)

		// comment out the rest of test steps due to https://issues.redhat.com/browse/OCPBUGS-51142, will add it back after the bug is fixed
		// compat_otp.By("7.1 Unlabel the second UDN, verify the second UDN is not longer advertised")
		// err := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", udnNS[1], "userdefinednetwork", udnNames[1], networkselectorkey+"-").Execute()
		// o.Expect(err).NotTo(o.HaveOccurred())
		// UDNnetwork_ipv6_ns2, UDNnetwork_ipv4_ns2 := getHostPodNetwork(oc, allNodes, udnNS[1]+"_"+udnNames[1])
		// o.Eventually(func() bool {
		// 	result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns2, UDNnetwork_ipv6_ns2, nodesIP1Map, nodesIP2Map, false)
		// 	return result
		// }, "60s", "10s").Should(o.BeTrue(), "advertised routes for unlabelled UDN were not cleaned up as expected!!")

		// compat_otp.By("7.2 UDN pod in second UDN should not be accessible from external any more")
		// time.Sleep(60 * time.Second)
		// Curlexternal2UDNPodFail(oc, host, udnNS[1], testpods[1].name)

		compat_otp.By("8. Delete the UDN pod of first UDN, then delete the first UDN, verify the first UDN is not longer advertised")
		removeResource(oc, true, true, "pod", testpods[0].name, "-n", testpods[0].namespace)
		removeResource(oc, true, true, "clusteruserdefinednetwork", udnNames[0])

		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, false)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "advertised routes for deleted UDN were not cleaned up as expected!!")

		e2e.Logf("SUCCESS - UDN route advertisement through VRF-default and route filtering through networkSelector work correctly!!!")
	})

	g.It("Author:zzhao-NonHyperShiftHOST-ConnectedOnly-Critical-78809-UDN pod should be able to access host service on different node but not on same node when BGP is advertise in LGW and SGW mode [Serial]", func() {

		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			hostNetworkPodTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-hostnetwork-specific-node-template.yaml")
			raTemplate             = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			matchLabelKey          = "cudn-bgp"
			matchValue             = "cudn-network-" + getRandomString()
			cudnName               = "cudn-network-78809"
		)
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled. ")
		}
		ipStackType := checkIPStackType(oc)

		compat_otp.By("Create hostnetwork pod in ns")
		ns_hostnetwork := oc.Namespace()
		err := compat_otp.SetNamespacePrivileged(oc, ns_hostnetwork)
		o.Expect(err).NotTo(o.HaveOccurred())

		hostpod := pingPodResourceNode{
			name:      "hostnetwork-pod",
			namespace: ns_hostnetwork,
			nodename:  nodeList.Items[0].Name,
			template:  hostNetworkPodTemplate,
		}
		hostpod.createPingPodNode(oc)
		waitPodReady(oc, ns_hostnetwork, hostpod.name)
		compat_otp.By("Create namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create CRD for UDN")
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

		//label userdefinednetwork with label app=udn
		setUDNLabel(oc, cudnName, "app=udn")

		compat_otp.By("Create RA to advertise the UDN network")

		ra := routeAdvertisement{
			name:              "udn",
			networkLabelKey:   "app",
			networkLabelVaule: "udn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("Check the UDN network was advertised to external router")

		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnName)
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")

		e2e.Logf("SUCCESS - BGP UDN network %s for namespace %s advertise!!!", cudnName, ns1)

		compat_otp.By("Create test pods in ns1")
		pods := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			pods[i] = pingPodResourceNode{
				name:      "hello-pod-" + strconv.Itoa(i),
				namespace: ns1,
				nodename:  nodeList.Items[i].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", pods[i].name, "-n", ns1)
			pods[i].createPingPodNode(oc)
			waitPodReady(oc, pods[i].namespace, pods[i].name)
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns1, "pod", pods[i].name, "name=hello-pod-"+strconv.Itoa(i), "--overwrite=true").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		nodeIPv6, nodeIPv4 := getNodeIP(oc, hostpod.nodename)
		compat_otp.By("check from the UDN pod can access same/different host service")

		//comment due to https://issues.redhat.com/browse/OCPBUGS-55914
		compat_otp.By("udn cannot access host serivce in same node after RA")
		CurlUDNPod2hostServiceFail(oc, ns1, pods[0].name, nodeIPv4, nodeIPv6, "8080")

		compat_otp.By("udn should be able to access host serivce in different node after RA")
		CurlUDNPod2hostServicePASS(oc, ns1, pods[1].name, nodeIPv4, nodeIPv6, "8080")

		compat_otp.By("Delete the RA for the udn and check the traffic again, which should be failed as UDN host isolation")
		ra.deleteRA(oc)

		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not be removed!!")

		compat_otp.By("udn cannot access host serivce in same node after removing RA")
		CurlUDNPod2hostServiceFail(oc, ns1, pods[0].name, nodeIPv4, nodeIPv6, "8080")

		compat_otp.By("udn should be able to access host serivce on different node after removing RA")
		CurlUDNPod2hostServicePASS(oc, ns1, pods[1].name, nodeIPv4, nodeIPv6, "8080")

	})

	g.It("Author:zzhao-NonHyperShiftHOST-ConnectedOnly-Critical-78810-Same host and different host cannot access the UDN pod when BGP route is advertised on both SGW and LGW [Serial]", func() {

		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			matchLabelKey       = "cudn-bgp"
			matchValue          = "cudn-network-" + getRandomString()
			cudnName            = "udn-network-78810"
		)
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled. ")
		}
		ipStackType := checkIPStackType(oc)
		compat_otp.By("Create namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create CRD for CUDN")
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
		//label userdefinednetwork with label app=udn
		setUDNLabel(oc, cudnName, "app=udn")

		compat_otp.By("Create RA to advertise the CUDN network")

		ra := routeAdvertisement{
			name:              "udn",
			networkLabelKey:   "app",
			networkLabelVaule: "udn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("Check the UDN network was advertised on worker node")

		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnName)
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")

		e2e.Logf("SUCCESS - BGP UDN network %s for namespace %s advertise!!!", cudnName, ns1)

		compat_otp.By("Create replica pods in ns1")
		defer removeResource(oc, true, true, "rc", "test-rc", "-n", ns1)
		createResourceFromFile(oc, ns1, testPodFile)
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testpodNS1Names := getPodName(oc, ns1, "name=test-pods")

		compat_otp.By("Get the pod located node name")
		nodeName, nodeNameErr := compat_otp.GetPodNodeName(oc, ns1, testpodNS1Names[1])
		o.Expect(nodeNameErr).NotTo(o.HaveOccurred())

		compat_otp.By("Validate pod to pod on different workers")
		CurlPod2PodPassUDN(oc, ns1, testpodNS1Names[0], ns1, testpodNS1Names[1])

		compat_otp.By("check from same host to access udn pod")
		// comment this due to bug https://issues.redhat.com/browse/OCPBUGS-51165
		CurlNode2PodFailUDN(oc, nodeName, ns1, testpodNS1Names[1])

		compat_otp.By("check from the UDN pod can access different host service")
		differentHostName := nodeList.Items[0].Name
		if differentHostName == nodeName {
			differentHostName = nodeList.Items[1].Name
		}
		// comment this due to bug https://issues.redhat.com/browse/OCPBUGS-51165
		CurlNode2PodFailUDN(oc, differentHostName, ns1, testpodNS1Names[1])

		compat_otp.By("Delete the RA for the udn and check the traffic again, host to UDN should be isolation")
		ra.deleteRA(oc)

		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, false)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not be removed!!")
		CurlNode2PodFailUDN(oc, nodeName, ns1, testpodNS1Names[1])
		CurlNode2PodFailUDN(oc, differentHostName, ns1, testpodNS1Names[1])

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-Longduration-NonPreRelease-High-78342-route advertisement recovery for default network, L3 UDN and L2 UDN if applicable after node reboot [Disruptive]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			matchLabelKey       = "cudn-bgp"
			matchValues         = []string{"cudn-network-l3" + getRandomString(), "cudn-network-l2" + getRandomString()}
			cudnNames           = []string{"l3-udn-network-78342", "l2-udn-network-78342"}
			ipStackType         = checkIPStackType(oc)
		)

		compat_otp.By("1. Get worker nodes")
		workerNodes, err := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerNodes) < 1 {
			g.Skip("Need at least 1 worker node, not enough worker node, skip the case!!")
		}

		compat_otp.By("3.1 Get first namespace for default network, create an UDN namespace and label it with cudn selector")
		ns1 := oc.Namespace()

		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[0])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		allNS := []string{ns1, ns2}

		var cidr, ipv4cidr, ipv6cidr []string
		ipv4cidr = []string{"10.150.0.0/16", "20.150.0.0/16"}
		ipv6cidr = []string{"2010:100:200::/48", "2011:100:200::/48"}
		cidr = []string{"10.150.0.0/16", "20.150.0.0/16"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/48", "2011:100:200::/48"}
		}

		compat_otp.By("3.2. Create L3 CUDN, and label the L3 CUDN to match networkSelector of RA")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[0])
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[0], cudnNames[0], ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		o.Expect(err).NotTo(o.HaveOccurred())
		//label userdefinednetwork with label app=udn
		setUDNLabel(oc, cudnNames[0], "app=udn")

		var ns3 string
		compat_otp.By("3.3. create another UDN namespace for L2 CUDN, and label it with cudn selector")
		oc.CreateNamespaceUDN()
		ns3 = oc.Namespace()
		allNS = append(allNS, ns3)
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns3, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns3, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[1])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3.4 create L2 CUDN L2 in ns3, and label the L2 CUDN to match networkSelector of RA")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[1])
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[1], cudnNames[1], ipv4cidr[1], ipv6cidr[1], cidr[1], "layer2")
		o.Expect(err).NotTo(o.HaveOccurred())

		// label CUDN L2 to match networkSelector of RA
		setUDNLabel(oc, cudnNames[1], "app=udn")

		compat_otp.By("4. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "udn",
			networkLabelKey:   "app",
			networkLabelVaule: "udn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("5.  Verify L3 CUDN network is advertised to external and other cluster nodes")
		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[0])
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L3 UDN network %s for namespace %s advertised to external !!!", cudnNames[0], ns2)

		compat_otp.By("5.2. verify CUDN L2 is advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is advertised to external !!!", cudnNames[1], ns3)

		compat_otp.By("6. Create a test pod in each namespace, verify each pod can be accessed from external because their default network and UDN are advertised")
		testpods := make([]pingPodResource, len(allNS))
		for i := 0; i < len(allNS); i++ {
			testpods[i] = pingPodResource{
				name:      "hello-pod-" + allNS[i],
				namespace: allNS[i],
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", testpods[i].name, "-n", allNS[i])
			testpods[i].createPingPod(oc)
			waitPodReady(oc, testpods[i].namespace, testpods[i].name)
		}
		Curlexternal2PodPass(oc, host, testpods[0].namespace, testpods[0].name)
		Curlexternal2UDNPodPass(oc, host, testpods[1].namespace, testpods[1].name)
		Curlexternal2UDNPodPass(oc, host, testpods[2].namespace, testpods[2].name)

		compat_otp.By("7. Reboot one worker node.\n")
		defer checkNodeStatus(oc, workerNodes[0], "Ready")
		rebootNode(oc, workerNodes[0])
		checkNodeStatus(oc, workerNodes[0], "NotReady")
		checkNodeStatus(oc, workerNodes[0], "Ready")

		compat_otp.By("8.  Verify default network and UDN advertisements after node reboot")
		compat_otp.By("8.1.  Verify from external frr container")
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "120s", "5s").Should(o.BeTrue(), "Not all podNetwork are advertised to external frr router after rebooting a node")
		e2e.Logf("SUCCESS - BGP default network is still correctly advertised to external after node reboot !!!")

		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L3 UDN network %s for namespace %s is still correctly advertised to external after node reboot !!!", cudnNames[0], ns2)

		compat_otp.By("5.2. verify CUDN L2 is advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is still correctly advertised to external after node reboot !!!", cudnNames[1], ns3)

		compat_otp.By("9. Verify each pod can still be accessed from external after node reboot because their default network and UDN remain advertised")
		Curlexternal2PodPass(oc, host, allNS[0], testpods[0].name)
		Curlexternal2UDNPodPass(oc, host, allNS[1], testpods[1].name)
		Curlexternal2UDNPodPass(oc, host, testpods[2].namespace, testpods[2].name)

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-Longduration-High-78343-route advertisement recovery for default network, L3 UDN and L2 UDN if applicable after OVNK restart [Disruptive]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			matchLabelKey       = "cudn-bgp"
			matchValues         = []string{"cudn-network-l3" + getRandomString(), "cudn-network-l2" + getRandomString()}
			cudnNames           = []string{"l3-udn-network-78343", "l2-udn-network-78343"}
			ipStackType         = checkIPStackType(oc)
		)
		compat_otp.By("2.1 Get first namespace for default network, create an UDN namespace and label it with cudn selector")
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[0])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		allNS := []string{ns1, ns2}

		compat_otp.By("2.2. Create L3 CUDN, and label the L3 CUDN to match networkSelector of RA")
		var cidr, ipv4cidr, ipv6cidr []string
		ipv4cidr = []string{"10.150.0.0/16", "20.150.0.0/16"}
		ipv6cidr = []string{"2010:100:200::/48", "2011:100:200::/48"}
		cidr = []string{"10.150.0.0/16", "20.150.0.0/16"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/48", "2011:100:200::/48"}
		}

		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[0])
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[0], cudnNames[0], ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		o.Expect(err).NotTo(o.HaveOccurred())
		//label userdefinednetwork with label app=udn
		setUDNLabel(oc, cudnNames[0], "app=udn")

		var ns3 string
		compat_otp.By("2.3. create another UDN namespace for L2 CUDN, and label it with cudn selector")
		oc.CreateNamespaceUDN()
		ns3 = oc.Namespace()
		allNS = append(allNS, ns3)
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns3, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns3, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[1])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2.4 create L2 CUDN L2 in ns3, and label the L2 CUDN to match networkSelector of RA")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[1])
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[1], cudnNames[1], ipv4cidr[1], ipv6cidr[1], cidr[1], "layer2")
		o.Expect(err).NotTo(o.HaveOccurred())

		setUDNLabel(oc, cudnNames[1], "app=udn")

		compat_otp.By("3. Create RA to advertise the UDN network")

		ra := routeAdvertisement{
			name:              "udn",
			networkLabelKey:   "app",
			networkLabelVaule: "udn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("4.  Verify  UDN network is advertised to external and other cluster nodes")
		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[0])
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L3 UDN network %s for namespace %s advertised to external !!!", cudnNames[0], ns2)

		compat_otp.By("4.2. verify CUDN L2 is advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is advertised to external !!!", cudnNames[1], ns3)

		compat_otp.By("5. Create a test pod in each namespace, verify each pod can be accessed from external because their default network and UDN are advertised")
		testpods := make([]pingPodResource, len(allNS))
		for i := 0; i < len(allNS); i++ {
			testpods[i] = pingPodResource{
				name:      "hello-pod-" + allNS[i],
				namespace: allNS[i],
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", testpods[i].name, "-n", allNS[i])
			testpods[i].createPingPod(oc)
			waitPodReady(oc, testpods[i].namespace, testpods[i].name)
		}
		Curlexternal2PodPass(oc, host, testpods[0].namespace, testpods[0].name)
		Curlexternal2UDNPodPass(oc, host, testpods[1].namespace, testpods[1].name)
		Curlexternal2UDNPodPass(oc, host, testpods[2].namespace, testpods[2].name)

		compat_otp.By("6. Restart OVNK.\n")
		defer waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		delPodErr := oc.AsAdmin().Run("delete").Args("pod", "-l", "app=ovnkube-node", "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		waitForNetworkOperatorState(oc, 20, 18, "True.*False.*False")

		compat_otp.By("7.  Verify default network and UDN advertisements after OVNK restart")
		compat_otp.By("7.1.  Verify from external frr container")
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "120s", "5s").Should(o.BeTrue(), "Not all podNetwork are advertised to external frr router after OVNK restart")
		e2e.Logf("SUCCESS - BGP default network is still correctly advertised to external after OVNK restart !!!")

		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L3 UDN network %s for namespace %s is still correctly advertised to external after OVNK restart !!!", cudnNames[0], ns2)

		compat_otp.By("5.2. verify CUDN L2 is advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is still correctly advertised to external after OVNK restart !!!", cudnNames[1], ns3)

		compat_otp.By("8. Verify each pod can still be accessed from external after OVNK restart because their default network and UDN remain advertised")
		Curlexternal2PodPass(oc, host, allNS[0], testpods[0].name)
		Curlexternal2UDNPodPass(oc, host, allNS[1], testpods[1].name)
		Curlexternal2UDNPodPass(oc, host, testpods[2].namespace, testpods[2].name)

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-Longduration-High-78344-route advertisement recovery for default network, L3 UDN and L2 UDN if applicable after frr-k8s pods restart [Disruptive]", func() {

		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			statefulSetHelloPod = filepath.Join(buildPruningBaseDir, "statefulset-hello.yaml")
			matchLabelKey       = "cudn-bgp"
			matchValues         = []string{"cudn-network-l3" + getRandomString(), "cudn-network-l2" + getRandomString()}
			cudnNames           = []string{"l3-udn-network-78344", "l2-udn-network-78344"}
			ipStackType         = checkIPStackType(oc)
		)

		compat_otp.By("2.1 Get first namespace for default network, create an UDN namespace and label it with cudn selector")
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[0])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		allNS := []string{ns1, ns2}

		compat_otp.By("2.2. Create L3 CUDN, and label the L3 CUDN to match networkSelector of RA")
		var cidr, ipv4cidr, ipv6cidr []string
		ipv4cidr = []string{"10.150.0.0/16", "20.150.0.0/16"}
		ipv6cidr = []string{"2010:100:200::/48", "2011:100:200::/48"}
		cidr = []string{"10.150.0.0/16", "20.150.0.0/16"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/48", "2011:100:200::/48"}
		}

		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[0])
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[0], cudnNames[0], ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		o.Expect(err).NotTo(o.HaveOccurred())
		//label userdefinednetwork with label app=udn
		setUDNLabel(oc, cudnNames[0], "app=udn")

		var ns3 string
		compat_otp.By("2.3. create another UDN namespace for L2 CUDN, and label it with cudn selector")
		oc.CreateNamespaceUDN()
		ns3 = oc.Namespace()
		allNS = append(allNS, ns3)
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns3, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns3, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[1])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2.4 create L2 CUDN L2 in ns3, and label the L2 CUDN to match networkSelector of RA")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[1])
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[1], cudnNames[1], ipv4cidr[1], ipv6cidr[1], cidr[1], "layer2")
		o.Expect(err).NotTo(o.HaveOccurred())

		// label CUDN L2 to match networkSelector of RA
		setUDNLabel(oc, cudnNames[1], "app=udn")

		compat_otp.By("3. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "udn",
			networkLabelKey:   "app",
			networkLabelVaule: "udn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("4.  Verify  UDN network is advertised to external and other cluster nodes")
		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[0])
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L3 UDN network %s for namespace %s advertised to external !!!", cudnNames[0], ns2)

		compat_otp.By("4.2. verify CUDN L2 is advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is advertised to external !!!", cudnNames[1], ns3)

		compat_otp.By("5. Create a test pod in each namespace, verify each pod can be accessed from external because their default network and UDN are advertised")
		var testpods []string
		for _, ns := range allNS {
			defer removeResource(oc, true, true, "StatefulSet", "hello", "-n", ns)
			createResourceFromFile(oc, ns, statefulSetHelloPod)
			podErr := waitForPodWithLabelReady(oc, ns, "app=hello")
			compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
			helloPodname := getPodName(oc, ns, "app=hello")
			o.Expect(len(helloPodname)).Should(o.Equal(1))
			testpods = append(testpods, helloPodname[0])
		}
		Curlexternal2PodPass(oc, host, allNS[0], testpods[0])
		Curlexternal2UDNPodPass(oc, host, allNS[1], testpods[1])
		Curlexternal2UDNPodPass(oc, host, allNS[2], testpods[2])

		compat_otp.By("6. Restart frr-k8s pods.\n")
		defer waitForPodWithLabelReady(oc, frrNamespace, "app=frr-k8s")
		defer waitForPodWithLabelReady(oc, frrNamespace, "component=frr-k8s-webhook-server")
		delPodErr := oc.AsAdmin().Run("delete").Args("pod", "-l", "app=frr-k8s", "-n", frrNamespace).Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())
		delPodErr = oc.AsAdmin().Run("delete").Args("pod", "-l", "component=frr-k8s-webhook-server", "-n", frrNamespace).Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())

		result := areFRRPodsReady(oc, frrNamespace)
		o.Expect(result).To(o.BeTrue(), "Not all frr-k8s pods fully recovered from restart")

		// Make sure frr-k8s ds successfully rolled out after restart
		status, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", frrNamespace, "ds", "frr-k8s", "--timeout", "5m").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(status, "successfully rolled out")).To(o.BeTrue(), "frr-k8s ds did not successfully roll out")

		// wait for routs to be re-advertised
		time.Sleep(60 * time.Second)

		compat_otp.By("7.  Verify default network and UDN advertisements after frr-k8s pods restart")
		compat_otp.By("7.1.  Verify from external frr container")
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "120s", "5s").Should(o.BeTrue(), "Not all podNetwork are advertised to external frr router after frr-k8s pods restart")
		e2e.Logf("SUCCESS - BGP default network is still correctly advertised to external after frr-k8s pods restart !!!")

		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L3 UDN network %s for namespace %s is still correctly advertised to external after frr-k8s pods restart !!!", cudnNames[0], ns2)

		compat_otp.By("5.2. verify CUDN L2 is advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is still correctly advertised to external after frr-k8s pods restart !!!", cudnNames[1], ns3)

		compat_otp.By("8. Verify each pod can still be accessed from external after frr-k8s pods restart because their default network and UDN remain advertised")
		// If stateful test pod(s) happen to be on rebooted node, pods would be recreated, wait for pods to be ready
		var testpods2 []string
		for _, ns := range allNS {
			podErr := waitForPodWithLabelReady(oc, ns, "app=hello")
			compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
			helloPodname := getPodName(oc, ns, "app=hello")
			testpods2 = append(testpods2, helloPodname[0])
		}
		Curlexternal2PodPass(oc, host, allNS[0], testpods2[0])
		Curlexternal2UDNPodPass(oc, host, allNS[1], testpods2[1])
		Curlexternal2UDNPodPass(oc, host, allNS[2], testpods[2])
	})

	g.It("Author:zzhao-NonPreRelease-Critical-79214-UDN to default network pods with NodePort and externalTrafficPolicy is Local/cluster service when BGP is advertise in LGW and SGW mode (UDN layer3)[Serial]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			raTemplate             = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			ipFamilyPolicy         = "SingleStack"
			matchLabelKey          = "cudn-bgp"
			matchValue             = "cudn-network-" + getRandomString()
			cudnName               = "udn-79214-l3"
		)

		compat_otp.By("0. Get three worker nodes")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This case requires 3 nodes, but the cluster has less than three nodes")
		}

		compat_otp.By("1. Create two namespaces, first one is for default network and second is for UDN and then label namespaces")
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		ns := []string{ns1, ns2}
		for _, namespace := range ns {
			err = compat_otp.SetNamespacePrivileged(oc, namespace)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("2. Create UDN CRD in ns2")
		var cidr, ipv4cidr, ipv6cidr string
		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::/48"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::/48"
				ipFamilyPolicy = "PreferDualStack"
			}
		}
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, cudnName, ipv4cidr, ipv6cidr, cidr, "layer3")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create RA to advertise the UDN")

		setUDNLabel(oc, cudnName, "app=udn")
		ra := routeAdvertisement{
			name:              "udn",
			networkLabelKey:   "app",
			networkLabelVaule: "udn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("Check the UDN network was advertised on worker node")

		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnName)
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")

		e2e.Logf("SUCCESS - BGP UDN network %s for namespace %s advertise!!!", cudnName, ns2)
		compat_otp.By("3. Create two pods and nodeport service with externalTrafficPolicy=Local in ns1 and ns2")
		nodeportsLocal := []string{}
		pods := make([]pingPodResourceNode, 2)
		svcs := make([]genericServiceResource, 2)
		for i := 0; i < 2; i++ {
			compat_otp.By(fmt.Sprintf("3.%d Create pod and nodeport service with externalTrafficPolicy=Local in %s", i, ns[i]))
			for j := 0; j < 2; j++ {
				pods[j] = pingPodResourceNode{
					name:      "hello-pod" + strconv.Itoa(j),
					namespace: ns[i],
					nodename:  nodeList.Items[j].Name,
					template:  pingPodNodeTemplate,
				}
				defer removeResource(oc, true, true, "pod", pods[j].name, "-n", ns[i])
				pods[j].createPingPodNode(oc)
				waitPodReady(oc, ns[i], pods[j].name)
			}
			svcs[i] = genericServiceResource{
				servicename:           "test-service" + strconv.Itoa(i),
				namespace:             ns[i],
				protocol:              "TCP",
				selector:              "hello-pod",
				serviceType:           "NodePort",
				ipFamilyPolicy:        ipFamilyPolicy,
				internalTrafficPolicy: "Cluster",
				externalTrafficPolicy: "Local",
				template:              genericServiceTemplate,
			}
			svcs[i].createServiceFromParams(oc)
			nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns[i], svcs[i].servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			nodeportsLocal = append(nodeportsLocal, nodePort)
		}

		compat_otp.By("4. Validate pod/host to nodeport service with externalTrafficPolicy=Local traffic")
		for i := 0; i < 2; i++ {
			compat_otp.By(fmt.Sprintf("4.1.%d Validate pod to nodeport service with externalTrafficPolicy=Local traffic in %s", i, ns[i]))
			//comment due to bug https://issues.redhat.com/browse/OCPBUGS-50636
			//CurlPod2NodePortPass(oc, ns[i], pods[i].name, nodeList.Items[0].Name, nodeportsLocal[i])
			//CurlPod2NodePortPass(oc, ns[i], pods[i].name, nodeList.Items[1].Name, nodeportsLocal[i])
			//CurlPod2NodePortFail(oc, ns[i], pods[i].name, nodeList.Items[2].Name, nodeportsLocal[i])
		}
		compat_otp.By("4.2 Validate host to nodeport service with externalTrafficPolicy=Local traffic on default network")
		CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[0].Name, nodeportsLocal[0])
		CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[1].Name, nodeportsLocal[0])
		compat_otp.By("4.3 [same node]Validate UDN pod to default network nodeport service with externalTrafficPolicy=Local traffic")
		//comment due to bug: https://issues.redhat.com/browse/OCPBUGS-52453
		CurlPod2NodePortFail(oc, ns[1], pods[0].name, nodeList.Items[0].Name, nodeportsLocal[0])

		compat_otp.By("4.3 [different node]Validate UDN pod to default network nodeport service with externalTrafficPolicy=Local traffic")
		//comment due to bug: https://issues.redhat.com/browse/OCPBUGS-50636
		CurlPod2NodePortPass(oc, ns[1], pods[0].name, nodeList.Items[1].Name, nodeportsLocal[0])

		compat_otp.By("4.3 [different node without backend]Validate UDN pod to default network nodeport service with externalTrafficPolicy=Local traffic")
		CurlPod2NodePortFail(oc, ns[1], pods[0].name, nodeList.Items[2].Name, nodeportsLocal[0])

		compat_otp.By("[same node]Validate default network pod to UDN nodeport service with externalTrafficPolicy=Local traffic")

		CurlPod2NodePortFail(oc, ns[0], pods[0].name, nodeList.Items[0].Name, nodeportsLocal[1])

		compat_otp.By("[different node]Validate default network pod to UDN nodeport service with externalTrafficPolicy=Local traffic")

		//comment due to bug: https://issues.redhat.com/browse/OCPBUGS-50636
		//CurlPod2NodePortPass(oc, ns[0], pods[0].name, nodeList.Items[1].Name, nodeportsLocal[1])

		compat_otp.By("[different node without backend]Validate default network pod to UDN nodeport service with externalTrafficPolicy=Local traffic")

		CurlPod2NodePortFail(oc, ns[0], pods[0].name, nodeList.Items[2].Name, nodeportsLocal[1])

		compat_otp.By("4.4 Validate host to nodeport service with externalTrafficPolicy=Local traffic on UDN network")
		//comment it as it failed on LGW
		//CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[0].Name, nodeportsLocal[1])
		//CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[1].Name, nodeportsLocal[1])

		compat_otp.By("5. Create nodeport service with externalTrafficPolicy=Cluster in ns1 and ns2")
		nodeportsCluster := []string{}
		for i := 0; i < 2; i++ {
			compat_otp.By(fmt.Sprintf("5.%d Create pod and nodeport service with externalTrafficPolicy=Cluster in %s", i, ns[i]))
			removeResource(oc, true, true, "svc", "test-service"+strconv.Itoa(i), "-n", ns[i])
			svcs[i].externalTrafficPolicy = "Cluster"
			svcs[i].createServiceFromParams(oc)
			nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns[i], svcs[i].servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			nodeportsCluster = append(nodeportsCluster, nodePort)
		}
		gwMode := getOVNGatewayMode(oc)
		compat_otp.By("6. Validate pod/host to nodeport service with externalTrafficPolicy=Cluster traffic")
		for i := 0; i < 2; i++ {
			compat_otp.By(fmt.Sprintf("6.1.%d Validate pod to nodeport service with externalTrafficPolicy=Cluster traffic in %s", i, ns[i]))
			if gwMode == "shared" {
				// there is bug for LGW mode https://issues.redhat.com/browse/OCPBUGS-55366
				CurlPod2NodePortPass(oc, ns[i], pods[i].name, nodeList.Items[0].Name, nodeportsCluster[i])
				CurlPod2NodePortPass(oc, ns[i], pods[i].name, nodeList.Items[1].Name, nodeportsCluster[i])
				CurlPod2NodePortPass(oc, ns[i], pods[i].name, nodeList.Items[2].Name, nodeportsCluster[i])
			}
		}
		compat_otp.By("6.2 Validate host to nodeport service with externalTrafficPolicy=Cluster traffic on default network")
		CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[0].Name, nodeportsCluster[0])
		CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[1].Name, nodeportsCluster[0])
		compat_otp.By("6.3 [same node]Validate UDN pod to default network nodeport service with externalTrafficPolicy=Cluster traffic")

		//comment due to host isolation bug https://issues.redhat.com/browse/OCPBUGS-51165
		CurlPod2NodePortFail(oc, ns[1], pods[0].name, nodeList.Items[0].Name, nodeportsCluster[0])

		compat_otp.By("[different node with backend]Validate UDN pod to default network nodeport service with externalTrafficPolicy=Cluster traffic")

		CurlPod2NodePortPass(oc, ns[1], pods[0].name, nodeList.Items[1].Name, nodeportsCluster[0])

		compat_otp.By("[different node without backend]Validate UDN pod to default network nodeport service with externalTrafficPolicy=Cluster traffic")

		CurlPod2NodePortPass(oc, ns[1], pods[0].name, nodeList.Items[2].Name, nodeportsCluster[0])

		compat_otp.By("6.4 [same node]Validate default network pod to UDN network nodeport service with externalTrafficPolicy=Cluster traffic")
		CurlPod2NodePortFail(oc, ns[0], pods[0].name, nodeList.Items[0].Name, nodeportsCluster[1])

		// there is bug for LGW mode https://issues.redhat.com/browse/OCPBUGS-55366
		if gwMode == "shared" {

			compat_otp.By("[different node with backend]Validate default network pod to UDN network nodeport service with externalTrafficPolicy=Cluster traffic")

			//ipv6 is not working due to https://issues.redhat.com/browse/OCPBUGS-55112
			CurlPod2NodePortPass(oc, ns[0], pods[0].name, nodeList.Items[1].Name, nodeportsCluster[1])

			compat_otp.By("[different node without backend]Validate default network pod to UDN network nodeport service with externalTrafficPolicy=Cluster traffic")

			//ipv6 is not working due to https://issues.redhat.com/browse/OCPBUGS-55112

			CurlPod2NodePortPass(oc, ns[0], pods[0].name, nodeList.Items[2].Name, nodeportsCluster[1])
		}
	})

	g.It("Author:meinli-NonPreRelease-Critical-79212-Validate pod2Service by BGP UDN in LGW and SGW (Layer3)[Serial]", func() {

		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			testPodFile            = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			raTemplate             = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			matchLabelKey          = []string{"cudn-bgp", "cudn-bgp2"}
			matchValue             = []string{"cudn-network1-" + getRandomString(), "cudn-network2-" + getRandomString()}
			cudnNames              = []string{"udn-network-ns1", "udn-network-ns2"}
			ipFamilyPolicy         = "SingleStack"
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled.")
		}

		compat_otp.By("1. Obtain three namespaces, first and second for UDN, third for default network")
		oc.CreateNamespaceUDN()
		udnNS := []string{oc.Namespace()}
		oc.CreateNamespaceUDN()
		udnNS = append(udnNS, oc.Namespace())
		oc.SetupProject()
		ns3 := oc.Namespace()

		compat_otp.By("2. Create UDN CRD in udnNS")
		ipStackType := checkIPStackType(oc)
		var cidr, ipv4cidr, ipv6cidr []string
		cidr = []string{"10.150.0.0/16", "10.160.0.0/16"}
		ipv4cidr = []string{"10.150.0.0/16", "10.160.0.0/16"}
		ipv6cidr = []string{"2010:100:200::/48", "2010:200:200::/48"}
		if ipStackType == "dualstack" {
			ipFamilyPolicy = "PreferDualStack"
		}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/48", "2010:200:200::/48"}
		}

		for i := 0; i < 2; i++ {
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", udnNS[i], fmt.Sprintf("%s=%s", matchLabelKey[i], matchValue[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[i])
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey[i], matchValue[i], cudnNames[i], ipv4cidr[i], ipv6cidr[i], cidr[i], "layer3")
			o.Expect(err).NotTo(o.HaveOccurred())
			//label userdefinednetwork with label app=udn
			setUDNLabel(oc, cudnNames[i], "app=udn")
		}

		compat_otp.By("3. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "udn",
			networkLabelKey:   "app",
			networkLabelVaule: "udn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("4. Verify two UDNs with matching networkSelector are advertised")
		for i := 0; i < 2; i++ {
			UDNnetwork_ipv6_ns, UDNnetwork_ipv4_ns := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[i])
			o.Eventually(func() bool {
				result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns, UDNnetwork_ipv6_ns, nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "10s").Should(o.BeTrue(), "UDN with matching networkSelector was not advertised as expected!!")
		}

		compat_otp.By("5. Create three pods: one as a backend pod and the other two as client pods on the same/different nodes in ns1.")
		pod1ns1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: udnNS[0],
			nodename:  nodeList.Items[0].Name,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", pod1ns1.name, "-n", udnNS[0])
		pod1ns1.createPingPodNode(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		pods := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			pods[i] = pingPodResourceNode{
				name:      "hello-pod-" + strconv.Itoa(i),
				namespace: udnNS[0],
				nodename:  nodeList.Items[i].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", pods[i].name, "-n", udnNS[0])
			pods[i].createPingPodNode(oc)
			waitPodReady(oc, pods[i].namespace, pods[i].name)
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", udnNS[0], "pod", pods[i].name, "name=hello-pod-"+strconv.Itoa(i), "--overwrite=true").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("6. create a ClusterIP service in ns1")
		svc := genericServiceResource{
			servicename:           "test-service-udn",
			namespace:             udnNS[0],
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        ipFamilyPolicy,
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", udnNS[0], svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("7. Verify ClusterIP service can be accessed from pods on same/different nodes in ns1.")
		for _, pod := range pods {
			CurlPod2SvcPass(oc, udnNS[0], udnNS[0], pod.name, svc.servicename)
		}

		compat_otp.By("8. Create udn pods in ns2")
		defer removeResource(oc, true, true, "rc", "test-rc", "-n", udnNS[1])
		createResourceFromFile(oc, udnNS[1], testPodFile)
		err = waitForPodWithLabelReady(oc, udnNS[1], "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodNameNS2 := getPodName(oc, udnNS[1], "name=test-pods")

		compat_otp.By("9. Validate same/different host to pod")
		CurlNode2PodFailUDN(oc, nodeList.Items[0].Name, udnNS[0], pods[0].name)
		CurlNode2PodFailUDN(oc, nodeList.Items[1].Name, udnNS[0], pods[0].name)

		compat_otp.By("10. Validate pod was isolated with different udn network")
		CurlPod2PodFailUDN(oc, udnNS[1], testPodNameNS2[0], udnNS[0], pods[0].name)

		compat_otp.By("11. Verify different udn network, service was isolated")
		CurlPod2SvcFail(oc, udnNS[1], udnNS[0], testPodNameNS2[0], svc.servicename)

		compat_otp.By("12. Create service and pods on default network")
		createResourceFromFile(oc, ns3, testPodFile)
		err = waitForPodWithLabelReady(oc, ns3, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodNameNS3 := getPodName(oc, ns3, "name=test-pods")

		compat_otp.By("13. validate external network to pod and pod to external network traffic on BGP")
		// verify external network to pod
		Curlexternal2PodPass(oc, host, ns3, testPodNameNS3[0])

		compat_otp.By("checking the imported route from external router can be worked")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			_, err := e2eoutput.RunHostCmd(ns3, testPodNameNS3[0], "curl "+net.JoinHostPort(externalServiceipv4, "8000")+" --connect-timeout 2 -I")
			o.Expect(err).NotTo(o.HaveOccurred())

		}
		if ipStackType == "ipv6single" || ipStackType == "dualstack" {
			_, err := e2eoutput.RunHostCmd(ns3, testPodNameNS3[0], "curl "+net.JoinHostPort(externalServiceipv6, "8000")+" --connect-timeout 2 -I")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("14. Not be able to access udn service from default network.")
		CurlPod2SvcFail(oc, ns3, udnNS[0], testPodNameNS3[0], svc.servicename)
		compat_otp.By("15. Not be able to access default network service from udn network.")
		CurlPod2SvcFail(oc, udnNS[0], ns3, pods[0].name, "test-service")
		compat_otp.By("16. Validate that the default network pod is isolated from the UDN network pod.")
		CurlPod2PodFail(oc, udnNS[0], pods[0].name, ns3, testPodNameNS3[0])
		compat_otp.By("16.1. Validate that the UDN pod is isolated from the default network pod.")
		CurlPod2PodFail(oc, ns3, testPodNameNS3[0], udnNS[0], pods[0].name)

		compat_otp.By("17. Update internalTrafficPolicy as Local for udn service in ns1.")
		patch := `[{"op": "replace", "path": "/spec/internalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service", svc.servicename, "-n", udnNS[0], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("17.1. Verify ClusterIP service can be accessed from pods[0] which is deployed on same node as service back-end pod.")
		CurlPod2SvcPass(oc, udnNS[0], udnNS[0], pods[0].name, svc.servicename)
		compat_otp.By("17.2. Verify ClusterIP service can NOT be accessed from pods[1] which is deployed on different node as service back-end pod.")
		CurlPod2SvcFail(oc, udnNS[0], udnNS[0], pods[1].name, svc.servicename)
	})

	g.It("Author:meinli-NonHyperShiftHOST-ConnectedOnly-Critical-78806-Critical-79993-Critical-80050-Pod to external BGP server and pod to another node when CUDN L2/L3 network is advertised and toggled to non-advertised [Disruptive]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			cudnNames           = []string{"l3-78806", "l2-80050"}
			topology            = []string{"layer3", "layer2"}
			matchLabelKey       = "test.io"
			matchValue          = []string{"cudn-network-l3", "cudn-network-l2"}
		)

		gwMode := getOVNGatewayMode(oc)
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled.")
		}

		compat_otp.By("1. get two CUDN namespaces and label with cudn selector")
		defaultNS := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Pods")
		compat_otp.SetNamespacePrivileged(oc, defaultNS)
		var allNS []string
		for i := 0; i < 2; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValue[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			allNS = append(allNS, ns)
		}

		compat_otp.By("2. create CUDN L3 and L2 in allNS")
		ipStackType := checkIPStackType(oc)
		cidr := []string{"10.152.0.0/16", "10.153.0.0/16"}
		ipv4cidr := []string{"10.152.0.0/16", "10.153.0.0/16"}
		ipv6cidr := []string{"2011:100:200::/60", "2012:100:200::/60"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2011:100:200::/60", "2012:100:200::/60"}
		}
		for i, cudnName := range cudnNames {
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
			_, err := applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue[i], cudnName, ipv4cidr[i], ipv6cidr[i], cidr[i], topology[i])
			o.Expect(err).NotTo(o.HaveOccurred())
			setUDNLabel(oc, cudnName, "app=cudn")
		}

		compat_otp.By("3. create a CUDN L2 test pod and hostnetwork pod with different nodes")
		var podNames []string
		for _, ns := range allNS {
			pod := pingPodResourceNode{
				name:      "hello-pod",
				namespace: ns,
				nodename:  nodeList.Items[0].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", pod.name, "-n", ns)
			pod.createPingPodNode(oc)
			waitPodReady(oc, pod.namespace, pod.name)
			podNames = append(podNames, pod.name)
		}
		hostpodName := "hostnetworkpod"
		overrides := fmt.Sprintf(`{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "%s"
  },
  "spec": {
    "hostNetwork": true,
    "nodeName": "%s",
    "containers": [
      {
        "name": "agnhost",
        "image": "registry.k8s.io/e2e-test-images/agnhost:2.53",
        "args": ["netexec", "--http-port=8080"]
      }
    ]
  }
}`, hostpodName, nodeList.Items[1].Name)
		_, err := oc.Run("run").Args(hostpodName, "-n", defaultNS, "--image=registry.k8s.io/e2e-test-images/agnhost:2.53", "--overrides="+overrides).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitPodReady(oc, defaultNS, hostpodName)

		compat_otp.By("4. verify pod to external BGP server and pod to another node's srcIP before advertisement")
		nodeIP2, nodeIP1 := getNodeIP(oc, nodeList.Items[0].Name)
		hostpodIP2, hostpodIP1 := getPodIP(oc, defaultNS, hostpodName)
		for i, ns := range allNS {
			if gwMode == "shared" {
				compat_otp.By("In SGW mode, add routes to external BGP server network into node's gateway router")
				defer deleteRoutesFromGatewayRouter(oc, nodeList.Items[0].Name, cudnNames[i], externalServiceipv4, externalServiceipv6)
				addRoutesToGatewayRouter(oc, nodeList.Items[0].Name, cudnNames[i], externalServiceipv4, externalServiceipv6, frrContainerIPv4, frrContainerIPv6)
			} else {
				compat_otp.By("In LGW mode, add routes to external BGP server network into CUDN's vrf table")
				defer deleteRoutesFromVrfTable(oc, nodeList.Items[0].Name, cudnNames[i], externalServiceipv4, externalServiceipv6)
				addRoutesToVrfTable(oc, nodeList.Items[0].Name, cudnNames[i], externalServiceipv4, externalServiceipv6, frrContainerIPv4, frrContainerIPv6)
			}

			compat_otp.By("verify pod to external BGP server's srcip is nodeIP before advertisement")
			switch ipStackType {
			case "ipv6single":
				verifyPodToServerSrcIP([]string{externalServiceipv6, ""}, []string{nodeIP1, ""}, "8000", ns, podNames[i])
			case "ipv4single":
				verifyPodToServerSrcIP([]string{externalServiceipv4, ""}, []string{nodeIP1, ""}, "8000", ns, podNames[i])
			case "dualstack":
				verifyPodToServerSrcIP([]string{externalServiceipv6, externalServiceipv4}, []string{nodeIP2, nodeIP1}, "8000", ns, podNames[i])
			}

			compat_otp.By("verify pod to another node's srcip is nodeIP before advertisement")
			switch ipStackType {
			case "dualstack":
				verifyPodToServerSrcIP([]string{hostpodIP2, hostpodIP1}, []string{nodeIP2, nodeIP1}, "8080", ns, podNames[i])
			default:
				verifyPodToServerSrcIP([]string{hostpodIP1, hostpodIP2}, []string{nodeIP2, nodeIP1}, "8080", ns, podNames[i])
			}
			if gwMode == "shared" {
				compat_otp.By("Delete routes to external BGP server network from node's Gateway Router in SGW")
				deleteRoutesFromGatewayRouter(oc, nodeList.Items[0].Name, cudnNames[i], externalServiceipv4, externalServiceipv6)
			} else {
				compat_otp.By("Delete routes to external BGP server network from CUDN vrf table in LGW")
				deleteRoutesFromVrfTable(oc, nodeList.Items[0].Name, cudnNames[i], externalServiceipv4, externalServiceipv6)
			}
		}

		compat_otp.By("5. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "80050-cudn-ra",
			networkLabelKey:   "app",
			networkLabelVaule: "cudn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("6. verify pod to external BGP server and pod to another node's srcip with CUDN advertisement")
		for i, ns := range allNS {
			switch i {
			case 0:
				UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[0])
				o.Eventually(func() bool {
					result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
					return result
				}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
				e2e.Logf("SUCCESS - BGP CUDN network %s for namespace %s advertise!!!", cudnNames[0], ns)
			case 1:
				o.Eventually(func() bool {
					result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[i], ipv6cidr[i], nodesIP1Map, nodesIP2Map, true)
					return result
				}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
				e2e.Logf("SUCCESS - BGP UDN L2 network %s for namespace %s advertised to external !!!", cudnNames[1], ns)
			}
			compat_otp.By("verify external to pod can access after BGP enabled")
			Curlexternal2UDNPodPass(oc, host, ns, podNames[i])

			podIP2, podIP1 := getPodIPUDN(oc, ns, podNames[i], "ovn-udn1")
			compat_otp.By("verify pod to external BGP server's srcip is podIP with CUDN advertisement")
			switch ipStackType {
			case "ipv6single":
				verifyPodToServerSrcIP([]string{externalServiceipv6, ""}, []string{podIP2, ""}, "8000", ns, podNames[i])
			case "ipv4single":
				verifyPodToServerSrcIP([]string{externalServiceipv4, ""}, []string{podIP2, ""}, "8000", ns, podNames[i])
			case "dualstack":
				verifyPodToServerSrcIP([]string{externalServiceipv6, externalServiceipv4}, []string{podIP2, podIP1}, "8000", ns, podNames[i])
			}
			compat_otp.By("verify pod to another node's srcip is nodeIP with CUDN advertisement")
			switch ipStackType {
			case "dualstack":
				verifyPodToServerSrcIP([]string{hostpodIP2, hostpodIP1}, []string{nodeIP2, nodeIP1}, "8080", ns, podNames[i])
			default:
				verifyPodToServerSrcIP([]string{hostpodIP1, hostpodIP2}, []string{nodeIP2, nodeIP1}, "8080", ns, podNames[i])
			}
		}

		compat_otp.By("7. verify pod to external BGP server and pod to another node's srcip after delete RA")
		ra.deleteRA(oc)
		for i, ns := range allNS {
			switch i {
			case 0:
				UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[0])
				o.Eventually(func() bool {
					result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, false)
					return result
				}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not be removed!!")
				e2e.Logf("SUCCESS - BGP UDN L3 network %s for namespace %s was successfully removed!!!", cudnNames[0], ns)
			case 1:
				o.Eventually(func() bool {
					result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[i], ipv6cidr[i], nodesIP1Map, nodesIP2Map, false)
					return result
				}, "60s", "10s").Should(o.BeTrue(), "BGP UDN L2 route advertisement did not be removed")
				e2e.Logf("SUCCESS - BGP UDN L2 network %s for namespace %s was successfully removed!!!", cudnNames[1], ns)
			}

			if gwMode == "shared" {
				compat_otp.By("In SGW mode, add routes to external BGP server network into node's gateway router")
				addRoutesToGatewayRouter(oc, nodeList.Items[0].Name, cudnNames[i], externalServiceipv4, externalServiceipv6, frrContainerIPv4, frrContainerIPv6)
			} else {
				compat_otp.By("In LGW mode, add routes to external BGP server network into CUDN's vrf table")
				addRoutesToVrfTable(oc, nodeList.Items[0].Name, cudnNames[i], externalServiceipv4, externalServiceipv6, frrContainerIPv4, frrContainerIPv6)
			}

			compat_otp.By("verify pod to external BGP server's srcip is nodeIP after delete RA")
			switch ipStackType {
			case "ipv6single":
				verifyPodToServerSrcIP([]string{externalServiceipv6, ""}, []string{nodeIP1, ""}, "8000", ns, podNames[i])
			case "ipv4single":
				verifyPodToServerSrcIP([]string{externalServiceipv4, ""}, []string{nodeIP1, ""}, "8000", ns, podNames[i])
			case "dualstack":
				verifyPodToServerSrcIP([]string{externalServiceipv6, externalServiceipv4}, []string{nodeIP2, nodeIP1}, "8000", ns, podNames[i])
			}

			compat_otp.By("verify pod to another node's srcip is nodeIP after delete RA")
			switch ipStackType {
			case "dualstack":
				verifyPodToServerSrcIP([]string{hostpodIP2, hostpodIP1}, []string{nodeIP2, nodeIP1}, "8080", ns, podNames[i])
			default:
				verifyPodToServerSrcIP([]string{hostpodIP1, hostpodIP2}, []string{nodeIP2, nodeIP1}, "8080", ns, podNames[i])
			}
		}
	})

	g.It("Author:meinli-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-Critical-80051-Validate pod to pod connection across two CUDN Layer2 (CUDN Layer2) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			matchLabelKey       = "test.io"
			matchValues         = []string{"cudn-network1-" + getRandomString(), "cudn-network2-" + getRandomString()}
			cudnNames           = []string{"cudn-network1-80051", "cudn-network2-80051"}
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1. create three CUDN namespaces and label them as cudn selector: the first two for first CUDN and the third for second CUDN")
		var allNS []string
		for i := 0; i < 3; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			if i < 2 {
				err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[0])).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[1])).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			}
			allNS = append(allNS, ns)
		}

		compat_otp.By("2. create two CUDN Layer2 with non-overlap subnets")
		ipStackType := checkIPStackType(oc)
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::/60", "2011:100:200::/60"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/60", "2011:100:200::/60"}
		}
		for i, cudnName := range cudnNames {
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnName, ipv4cidr[i], ipv6cidr[i], cidr[i], "layer2")
			o.Expect(err).NotTo(o.HaveOccurred())

			// label CUDN L2 with app=cudn-l2
			setUDNLabel(oc, cudnName, "app=cudn-l2-80051")
		}

		compat_otp.By("3. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "cudn-l2-80051",
			networkLabelKey:   "app",
			networkLabelVaule: "cudn-l2-80051",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By("4. Verify both L2 CUDN are advertised to external")
		for i, cudnName := range cudnNames {
			o.Eventually(func() bool {
				result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[i], ipv6cidr[i], nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
			e2e.Logf("SUCCESS - BGP CUDN L2 network %s advertised to external !!!", cudnName)
		}

		compat_otp.By("5. Create two pods on different nodes across different namespaces")
		testpodCUDN1 := make([]pingPodResourceNode, 2)
		for i, ns := range allNS[:2] {
			testpodCUDN1[i] = pingPodResourceNode{
				name:      "hello-pod-" + strconv.Itoa(i),
				namespace: ns,
				nodename:  nodeList.Items[i].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", testpodCUDN1[i].name, "-n", testpodCUDN1[i].namespace)
			testpodCUDN1[i].createPingPodNode(oc)
			waitPodReady(oc, testpodCUDN1[i].namespace, testpodCUDN1[i].name)
		}
		testpodCUDN2 := pingPodResourceNode{
			name:      "hello-pod-2",
			namespace: allNS[2],
			nodename:  nodeList.Items[0].Name,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", testpodCUDN2.name, "-n", testpodCUDN2.namespace)
		testpodCUDN2.createPingPodNode(oc)
		waitPodReady(oc, testpodCUDN2.namespace, testpodCUDN2.name)

		compat_otp.By("6. validate connection among the same CUDN pods")
		CurlPod2PodPassUDN(oc, testpodCUDN1[0].namespace, testpodCUDN1[0].name, testpodCUDN1[1].namespace, testpodCUDN1[1].name)

		compat_otp.By("7. validate isolation among the different CUDNs pods")
		for i := 0; i < 2; i++ {
			CurlPod2PodFailUDN(oc, testpodCUDN1[i].namespace, testpodCUDN1[i].name, testpodCUDN2.namespace, testpodCUDN2.name)
		}

		compat_otp.By("8. Validate same/different host to pod")
		CurlNode2PodFailUDN(oc, nodeList.Items[0].Name, allNS[0], testpodCUDN1[0].name)
		CurlNode2PodFailUDN(oc, nodeList.Items[1].Name, allNS[0], testpodCUDN1[0].name)
	})

	g.It("Author: meinli-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-81496-Validate pod2pod / pod2service from CUDN L2 to CUDN l3 [Serial]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			raTemplate             = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			matchLabelKey          = "test.io"
			matchValues            = []string{"cudn-l2-" + getRandomString(), "cudn-l3-" + getRandomString()}
			cudnNames              = []string{"cudn-l2-81496", "cudn-l3-81496"}
			ipFamilyPolicy         = "SingleStack"
		)

		gwMode := getOVNGatewayMode(oc)
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1. create two namespaces: first one for L2, second one for L3")
		var allNS []string
		for i := 0; i < 2; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			allNS = append(allNS, ns)
		}

		compat_otp.By("2. create two CUDNs: first one is L2, second one is L3")
		ipStackType := checkIPStackType(oc)
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::/60", "2011:100:200::/60"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/60", "2011:100:200::/60"}
		}
		for i, cudnName := range cudnNames {
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
			if i == 0 {
				_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnName, ipv4cidr[i], ipv6cidr[i], cidr[i], "layer2")
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnName, ipv4cidr[i], ipv6cidr[i], cidr[i], "layer3")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
			setUDNLabel(oc, cudnName, "app=cudn-e2e-81496")
		}

		compat_otp.By("3. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "cudn-e2e-81496",
			networkLabelKey:   "app",
			networkLabelVaule: "cudn-e2e-81496",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer ra.deleteRA(oc)
		ra.createRA(oc)

		compat_otp.By("4. Verify L2 and L3 network are advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[0], ipv6cidr[0], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - BGP CUDN L2 network %s advertised to external !!!", cudnNames[0])

		UDNL3_ipv6_ns2, UDNL3_ipv4_ns2 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[1])
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNL3_ipv4_ns2, UDNL3_ipv6_ns2, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - BGP CUDN L3 network %s advertised to external !!!", cudnNames[1])

		compat_otp.By("5. Create two pods in L2 namespace")
		testpodsL2 := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			testpodsL2[i] = pingPodResourceNode{
				name:      "client-pod-" + strconv.Itoa(i),
				namespace: allNS[0],
				nodename:  nodeList.Items[i].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", testpodsL2[i].name, "-n", testpodsL2[i].namespace)
			testpodsL2[i].createPingPodNode(oc)
			waitPodReady(oc, testpodsL2[i].namespace, testpodsL2[i].name)
		}

		compat_otp.By("6. create one pods as backend-pod for service in L3 namespace")
		testpodL3 := pingPodResourceNode{
			name:      "backend-pod-1",
			namespace: allNS[1],
			nodename:  nodeList.Items[0].Name,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", testpodL3.name, "-n", testpodL3.namespace)
		testpodL3.createPingPodNode(oc)
		waitPodReady(oc, testpodL3.namespace, testpodL3.name)

		compat_otp.By("7. Validate L2 pod to L3 pod on the same/different node")
		CurlPod2PodFailUDN(oc, allNS[0], testpodsL2[0].name, allNS[1], testpodL3.name)
		CurlPod2PodFailUDN(oc, allNS[0], testpodsL2[1].name, allNS[1], testpodL3.name)

		compat_otp.By("8. Validate L2 pod to L3 ClusterIP service traffic")
		compat_otp.By("8.1 create ClusterIP service in L3 namespace")
		if ipStackType == "dualstack" {
			ipFamilyPolicy = "PreferDualStack"
		}
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             allNS[1],
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        ipFamilyPolicy,
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[1], svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))
		CurlPod2SvcFail(oc, allNS[0], allNS[1], testpodsL2[0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[0], allNS[1], testpodsL2[1].name, svc.servicename)

		compat_otp.By("8.2 patch L3 ClusterIP service to Local")
		patch := `[{"op": "replace", "path": "/spec/internalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", allNS[1], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		CurlPod2SvcFail(oc, allNS[0], allNS[1], testpodsL2[0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[0], allNS[1], testpodsL2[1].name, svc.servicename)

		compat_otp.By("9. Validate L2 pod to L3 NodePort traffic when ETP=Cluster")
		compat_otp.By("9.1 Delete ClusterIP service in L3 namespace")
		removeResource(oc, true, true, "svc", svc.servicename, "-n", allNS[1])
		compat_otp.By("9.2 Create NodePort service in L3 namespace")
		svc.serviceType = "NodePort"
		svc.externalTrafficPolicy = "Cluster"
		svc.createServiceFromParams(oc)
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[1], svc.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("9.3 Validate L2 pod to L3 NodePort traffic when ETP=Cluster")
		CurlPod2NodePortFail(oc, allNS[0], testpodsL2[0].name, nodeList.Items[0].Name, nodePort)
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		CurlPod2NodePortPass(oc, allNS[0], testpodsL2[0].name, nodeList.Items[1].Name, nodePort)

		compat_otp.By("10. Validate L2 pod to L3 NodePort traffic when ETP=Local")
		compat_otp.By("10.1 create another back-end pod in nodeList[1]")
		testpod2L3 := pingPodResourceNode{
			name:      "backend-pod-2",
			namespace: allNS[1],
			nodename:  nodeList.Items[1].Name,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", testpod2L3.name, "-n", testpod2L3.namespace)
		testpod2L3.createPingPodNode(oc)
		waitPodReady(oc, testpod2L3.namespace, testpod2L3.name)
		compat_otp.By("10.2 patch L3 NodePort to ETP=Local")
		patch = `[{"op": "replace", "path": "/spec/externalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", allNS[1], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("10.3 Validate L2 pod to L3 NodePort traffic when ETP=Local")
		CurlPod2NodePortFail(oc, allNS[0], testpodsL2[0].name, nodeList.Items[0].Name, nodePort)
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		if gwMode == "shared" {
			// Failed in LGW mode
			CurlPod2NodePortPass(oc, allNS[0], testpodsL2[0].name, nodeList.Items[1].Name, nodePort)
		}
		CurlPod2NodePortFail(oc, allNS[0], testpodsL2[0].name, nodeList.Items[2].Name, nodePort)
	})

	g.It("Author:meinli-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-81497-Validate pod2pod / pod2service from CUDN L3 to CUDN l2. [Serial]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			raTemplate             = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			matchLabelKey          = "test.io"
			matchValues            = []string{"cudn-l3-" + getRandomString(), "cudn-l2-" + getRandomString()}
			cudnNames              = []string{"cudn-l3-81497", "cudn-l2-81497"}
			ipFamilyPolicy         = "SingleStack"
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1. create two namespaces: first one for L3, second one for L2")
		var allNS []string
		for i := 0; i < 2; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			allNS = append(allNS, ns)
		}

		compat_otp.By("2. create two CUDNs: first one is L3, second one is L2")
		ipStackType := checkIPStackType(oc)
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::/60", "2011:100:200::/60"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/60", "2011:100:200::/60"}
		}
		for i, cudnName := range cudnNames {
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
			if i == 0 {
				_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnName, ipv4cidr[i], ipv6cidr[i], cidr[i], "layer3")
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnName, ipv4cidr[i], ipv6cidr[i], cidr[i], "layer2")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
			setUDNLabel(oc, cudnName, "app=cudn-e2e-81497")
		}

		compat_otp.By("3. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "cudn-e2e-81497",
			networkLabelKey:   "app",
			networkLabelVaule: "cudn-e2e-81497",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer ra.deleteRA(oc)
		ra.createRA(oc)

		compat_otp.By("4. Verify L2 and L3 network are advertised to external")
		UDNL3_ipv6_ns1, UDNL3_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[0])
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNL3_ipv4_ns1, UDNL3_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - BGP CUDN L3 network %s advertised to external !!!", cudnNames[0])

		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - BGP CUDN L2 network %s advertised to external !!!", cudnNames[1])

		compat_otp.By("5. Create two pods in L3 namespace")
		testpodsL3 := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			testpodsL3[i] = pingPodResourceNode{
				name:      "client-pod-" + strconv.Itoa(i),
				namespace: allNS[0],
				nodename:  nodeList.Items[i].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", testpodsL3[i].name, "-n", testpodsL3[i].namespace)
			testpodsL3[i].createPingPodNode(oc)
			waitPodReady(oc, testpodsL3[i].namespace, testpodsL3[i].name)
		}

		compat_otp.By("6. create one pods as backend-pod for service in L2 namespace")
		testpodL2 := pingPodResourceNode{
			name:      "backend-pod-1",
			namespace: allNS[1],
			nodename:  nodeList.Items[0].Name,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", testpodL2.name, "-n", testpodL2.namespace)
		testpodL2.createPingPodNode(oc)
		waitPodReady(oc, testpodL2.namespace, testpodL2.name)

		compat_otp.By("7. Validate L3 pod to L2 pod on the same/different node")
		CurlPod2PodFailUDN(oc, allNS[0], testpodsL3[0].name, allNS[1], testpodL2.name)
		CurlPod2PodFailUDN(oc, allNS[0], testpodsL3[1].name, allNS[1], testpodL2.name)

		compat_otp.By("8. Validate L3 pod to L2 ClusterIP service traffic")
		compat_otp.By("8.1 create ClusterIP service in L2 namespace")
		if ipStackType == "dualstack" {
			ipFamilyPolicy = "PreferDualStack"
		}
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             allNS[1],
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        ipFamilyPolicy,
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[1], svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))
		CurlPod2SvcFail(oc, allNS[0], allNS[1], testpodsL3[0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[0], allNS[1], testpodsL3[1].name, svc.servicename)

		compat_otp.By("8.2 patch L2 ClusterIP service to Local")
		patch := `[{"op": "replace", "path": "/spec/internalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", allNS[1], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		CurlPod2SvcFail(oc, allNS[0], allNS[1], testpodsL3[0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[0], allNS[1], testpodsL3[1].name, svc.servicename)

		compat_otp.By("9. Validate L3 pod to L2 NodePort traffic when ETP=Cluster")
		compat_otp.By("9.1 Delete ClusterIP service in L3 namespace")
		removeResource(oc, true, true, "svc", svc.servicename, "-n", allNS[1])
		compat_otp.By("9.2 Create NodePort service in L2 namespace")
		svc.serviceType = "NodePort"
		svc.externalTrafficPolicy = "Cluster"
		svc.createServiceFromParams(oc)
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[1], svc.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("9.3 Validate L3 pod to L2 NodePort traffic when ETP=Cluster")
		CurlPod2NodePortFail(oc, allNS[0], testpodsL3[0].name, nodeList.Items[0].Name, nodePort)
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		CurlPod2NodePortPass(oc, allNS[0], testpodsL3[0].name, nodeList.Items[1].Name, nodePort)

		compat_otp.By("10. Validate L3 pod to L2 NodePort traffic when ETP=Local")
		compat_otp.By("10.1 create another back-end pod in nodeList[1]")
		testpod2L2 := pingPodResourceNode{
			name:      "backend-pod-2",
			namespace: allNS[1],
			nodename:  nodeList.Items[1].Name,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", testpod2L2.name, "-n", testpod2L2.namespace)
		testpod2L2.createPingPodNode(oc)
		waitPodReady(oc, testpod2L2.namespace, testpod2L2.name)
		compat_otp.By("10.2 patch L2 NodePort to ETP=Local")
		patch = `[{"op": "replace", "path": "/spec/externalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", allNS[1], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("10.3 Validate L3 pod to L2 NodePort traffic when ETP=Local")
		CurlPod2NodePortFail(oc, allNS[0], testpodsL3[0].name, nodeList.Items[0].Name, nodePort)
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		CurlPod2NodePortPass(oc, allNS[0], testpodsL3[0].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortFail(oc, allNS[0], testpodsL3[0].name, nodeList.Items[2].Name, nodePort)
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-78347-route advertisement through VRF-default and route filtering with networkSelector for L2 CUDN [Serial]", func() {
		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			raTemplate           = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			pingPodTemplate      = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			networkselectorkey   = "app"
			networkselectorvalue = "udn"
			matchLabelKey        = []string{"cudn-bgp", "cudn-bgp2", "cudn-bgp3"}
			matchValue           = []string{"cudn-network1-" + getRandomString(), "cudn-network2-" + getRandomString(), "cudn-network3-" + getRandomString()}
			cudnNames            = []string{"layer2-udn-78339-1", "layer2-udn-78339-2", "layer2-udn-78339-3"}
			udnNS                []string
			externalServiceipv4  = "172.20.0.100"
			externalServiceipv6  = "2001:db8:2::100"
		)

		compat_otp.By("1. Create three UDN namespaces, create a layer2 UDN in each UDN namespace, the two UDNs should NOT be overlapping")
		ipStackType := checkIPStackType(oc)
		var cidr, ipv4cidr, ipv6cidr []string
		ipv4cidr = []string{"10.150.0.0/16", "20.150.0.0/16", "30.150.0.0/16"}
		ipv6cidr = []string{"2010:100:200::/48", "2011:100:200::/48", "2012:100:200::/48"}
		cidr = []string{"10.150.0.0/16", "20.150.0.0/16", "30.150.0.0/16"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/48", "2011:100:200::/48", "2012:100:200::/48"}
		}

		for i := 0; i < 3; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey[i], matchValue[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			udnNS = append(udnNS, ns)
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[i])
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey[i], matchValue[i], cudnNames[i], ipv4cidr[i], ipv6cidr[i], cidr[i], "layer2")
			o.Expect(err).NotTo(o.HaveOccurred())
			//label clusteruserdefinednetwork with label app=udn for frist two CUDN that matches networkSelector in routeAdvertisement
			if i != 2 {
				setUDNLabel(oc, cudnNames[i], "app=udn")
			}
		}

		compat_otp.By("3. Apply a routeAdvertisement with matching networkSelector")
		raname := "ra-udn"
		params := []string{"-f", raTemplate, "-p", "NAME=" + raname, "NETWORKSELECTORKEY=" + networkselectorkey, "NETWORKSELECTORVALUE=" + networkselectorvalue, "ADVERTISETYPE=" + advertiseType}
		defer removeResource(oc, true, true, "ra", raname)
		compat_otp.ApplyNsResourceFromTemplate(oc, oc.Namespace(), params...)
		raErr := checkRAStatus(oc, raname, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - UDN routeAdvertisement applied is accepted")

		compat_otp.By("4. Verify the first two L2 CUDNs with matching networkSelector are advertised")
		for i := 0; i < 2; i++ {
			o.Eventually(func() bool {
				result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[i], ipv6cidr[i], nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "5s").Should(o.BeTrue(), "BGP L2 UDN route advertisement did not succeed!!")
			e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is advertised to external !!!", cudnNames[1], udnNS[i])
		}

		compat_otp.By("5. Verify the third L2 CUDN without matching networkSelector is NOT advertised")
		result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[2], ipv6cidr[2], nodesIP1Map, nodesIP2Map, false)
		o.Expect(result).To(o.BeTrue(), "Unlablled UDN should not be advertised, but their routes are in routing table")

		compat_otp.By("6.1 Create a UDN pod in each UDN namespace associating with its L2 CUDN")
		testpods := make([]pingPodResource, len(udnNS))
		for i := 0; i < len(udnNS); i++ {
			testpods[i] = pingPodResource{
				name:      "hello-pod-" + udnNS[i],
				namespace: udnNS[i],
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", testpods[i].name, "-n", udnNS[i])
			testpods[i].createPingPod(oc)
			waitPodReady(oc, testpods[i].namespace, testpods[i].name)
		}

		compat_otp.By("6.2 Verify traffic between UDN pod in first two UDN namespaces and external should work, but traffic between the UDN pod in 3rd UDN namespace and external should not work as its CUDN was not advertised")
		Curlexternal2UDNPodPass(oc, host, udnNS[0], testpods[0].name)
		Curlexternal2UDNPodPass(oc, host, udnNS[1], testpods[1].name)
		Curlexternal2UDNPodFail(oc, host, udnNS[2], testpods[2].name)
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			_, err := e2eoutput.RunHostCmd(udnNS[0], testpods[0].name, "curl "+net.JoinHostPort(externalServiceipv4, "8000")+" --connect-timeout 2 -I")
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = e2eoutput.RunHostCmd(udnNS[1], testpods[1].name, "curl "+net.JoinHostPort(externalServiceipv4, "8000")+" --connect-timeout 2 -I")
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = e2eoutput.RunHostCmd(udnNS[2], testpods[2].name, "curl "+net.JoinHostPort(externalServiceipv4, "8000")+" --connect-timeout 2 -I")
			o.Expect(err).To(o.HaveOccurred())
		}
		if ipStackType == "ipv6single" || ipStackType == "dualstack" {
			_, err := e2eoutput.RunHostCmd(udnNS[0], testpods[0].name, "curl "+net.JoinHostPort(externalServiceipv6, "8000")+" --connect-timeout 2 -I")
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = e2eoutput.RunHostCmd(udnNS[1], testpods[1].name, "curl "+net.JoinHostPort(externalServiceipv6, "8000")+" --connect-timeout 2 -I")
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = e2eoutput.RunHostCmd(udnNS[2], testpods[2].name, "curl "+net.JoinHostPort(externalServiceipv6, "8000")+" --connect-timeout 2 -I")
			o.Expect(err).To(o.HaveOccurred())
		}

		// comment out the rest of test steps due to https://issues.redhat.com/browse/OCPBUGS-51142, will add it back after the bug is fixed
		// compat_otp.By("7.1 Unlabel the second L2 CUDN, verify the second UDN is not longer advertised")
		// err := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", udnNS[1], "clusteruserdefinednetwork", cudnNames[1], networkselectorkey+"-").Execute()
		// o.Expect(err).NotTo(o.HaveOccurred())

		// o.Eventually(func() bool {
		// 	result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, false)
		// 	return result
		// }, "60s", "10s").Should(o.BeTrue(), "advertised routes for unlabelled L2 CUDN were not cleaned up as expected!!")

		// compat_otp.By("7.2 UDN pod in second L2 CUDN should not be accessible to/from external any more")
		// time.Sleep(60 * time.Second)
		// Curlexternal2UDNPodFail(oc, host, udnNS[1], testpods[1].name)
		// if ipStackType == "ipv4single" || ipStackType == "dualstack" {
		// 	_, err = e2eoutput.RunHostCmd(udnNS[1], testpods[1].name, "curl "+net.JoinHostPort(externalServiceipv4, "8000")+" --connect-timeout 2 -I")
		// 	o.Expect(err).To(o.HaveOccurred())

		// }
		// if ipStackType == "ipv6single" || ipStackType == "dualstack" {
		// 	_, err = e2eoutput.RunHostCmd(udnNS[1], testpods[1].name, "curl "+net.JoinHostPort(externalServiceipv6, "8000")+" --connect-timeout 2 -I")
		// 	o.Expect(err).To(o.HaveOccurred())
		// }

		compat_otp.By("8. Delete the UDN pod of first L2 CUDN, then delete the first L2 CUDN, verify the first L2 CUDN is not longer advertised")
		removeResource(oc, true, true, "pod", testpods[0].name, "-n", testpods[0].namespace)
		removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[0])

		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[0], ipv6cidr[0], nodesIP1Map, nodesIP2Map, false)
			return result
		}, "120s", "10s").Should(o.BeTrue(), "advertised routes for deleted L2 CUDN were not cleaned up as expected!!")

		e2e.Logf("SUCCESS - L2 CUDN route advertisement through VRF-default and route filtering through networkSelector work correctly!!!")
	})

	g.It("Author:meinli-NonHyperShiftHOST-ConnectedOnly-Longduration-NonPreRelease-High-80052-Validate pod to ClusterIP Service across CUDN Layer2 and default network in SGW and LGW [Serial]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			raTemplate             = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			matchLabelKey          = "test.io"
			matchValues            = []string{"cudn-network1-" + getRandomString(), "cudn-network2-" + getRandomString()}
			cudnNames              = []string{"cudn-network1-80052", "cudn-network2-80052"}
			ipFamilyPolicy         = "SingleStack"
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1. create three namespaces")
		// create default network ns
		defaultNS := oc.Namespace()
		compat_otp.By("1.1 create two CUDN namespace and label them as cudnselector: the first one is for CUDN network1 and the second one is for CUDN network2")
		allNS := []string{}
		for i := 0; i < 2; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			allNS = append(allNS, ns)
		}
		compat_otp.By("1.2 create one namespace for default network")
		allNS = append(allNS, defaultNS)

		compat_otp.By("2. create two CUDN Layer2 with non-overlap subnets")
		ipStackType := checkIPStackType(oc)
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::/60", "2011:100:200::/60"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/60", "2011:100:200::/60"}
		}
		for i, cudnName := range cudnNames {
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnName, ipv4cidr[i], ipv6cidr[i], cidr[i], "layer2")
			o.Expect(err).NotTo(o.HaveOccurred())

			// label CUDN L2 with app=cudn-l2
			setUDNLabel(oc, cudnName, "app=cudn-l2-80052")
		}

		compat_otp.By("3. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "cudn-l2-80052",
			networkLabelKey:   "app",
			networkLabelVaule: "cudn-l2-80052",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer ra.deleteRA(oc)
		ra.createRA(oc)

		compat_otp.By("4. verify UDN L2 is advertised to external and other cluster nodes")
		for i, cudnName := range cudnNames {
			o.Eventually(func() bool {
				result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[i], ipv6cidr[i], nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
			e2e.Logf("SUCCESS - BGP CUDN L2 network %s advertised to external !!!", cudnName)
		}

		compat_otp.By("5. Create a pod deployed on node0 as backend pod for service.")
		backendPodNS1 := pingPodResourceNode{
			name:      "hello-pod-1",
			namespace: allNS[0],
			nodename:  nodeList.Items[0].Name,
			template:  pingPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", backendPodNS1.name, "-n", backendPodNS1.namespace)
		backendPodNS1.createPingPodNode(oc)
		waitPodReady(oc, backendPodNS1.namespace, backendPodNS1.name)

		compat_otp.By("6. create two client pods on the same and different nodes in both CUDN and default network namespaces")
		clientPodsNS := make([][]pingPodResourceNode, 3)
		for nsIdx := 0; nsIdx < 3; nsIdx++ {
			clientPodsNS[nsIdx] = make([]pingPodResourceNode, 2)
			for podIdx := 0; podIdx < 2; podIdx++ {
				podName := fmt.Sprintf("hellopod-ns%d-%d", nsIdx+1, podIdx)
				labelName := fmt.Sprintf("hellopod-ns%d-%d", nsIdx+1, podIdx)
				clientPodsNS[nsIdx][podIdx] = pingPodResourceNode{
					name:      podName,
					namespace: allNS[nsIdx],
					nodename:  nodeList.Items[podIdx].Name,
					template:  pingPodTemplate,
				}
				defer removeResource(oc, true, true, "pod", podName, "-n", allNS[nsIdx])
				clientPodsNS[nsIdx][podIdx].createPingPodNode(oc)
				waitPodReady(oc, allNS[nsIdx], podName)
				// Update label for pod to a different one
				err = oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", allNS[nsIdx], "pod", podName, "name="+labelName, "--overwrite=true").Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}

		compat_otp.By("7. validate pod2pod traffic between CUDN L2 and default network")
		CurlPod2PodFail(oc, allNS[0], clientPodsNS[0][0].name, allNS[2], clientPodsNS[2][0].name)
		CurlPod2PodFail(oc, allNS[0], clientPodsNS[0][0].name, allNS[2], clientPodsNS[2][1].name)
		CurlPod2PodFailUDN(oc, allNS[2], clientPodsNS[2][0].name, allNS[0], clientPodsNS[0][0].name)
		CurlPod2PodFailUDN(oc, allNS[2], clientPodsNS[2][0].name, allNS[0], clientPodsNS[0][1].name)

		compat_otp.By("8. create a ClusterIP service in ns1")
		if ipStackType == "dualstack" {
			ipFamilyPolicy = "PreferDualStack"
		}
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             allNS[0],
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        ipFamilyPolicy,
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[0], svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("9. Verify CUDN and default network pods to ClusterIP service traffic on CUDN")
		// cudn pods to clusterIP with the same CUDN network
		CurlPod2SvcPass(oc, allNS[0], allNS[0], clientPodsNS[0][0].name, svc.servicename)
		CurlPod2SvcPass(oc, allNS[0], allNS[0], clientPodsNS[0][1].name, svc.servicename)
		// cudn pods to clusterIP with the different CUDN networks
		CurlPod2SvcFail(oc, allNS[1], allNS[0], clientPodsNS[1][0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[1], allNS[0], clientPodsNS[1][1].name, svc.servicename)
		// default network pods to clusterIP service on CUDN L2
		CurlPod2SvcFail(oc, allNS[2], allNS[0], clientPodsNS[2][0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[2], allNS[0], clientPodsNS[2][1].name, svc.servicename)

		compat_otp.By("10. Update internalTrafficPolicy as Local for cudn service in ns1.")
		patch := `[{"op": "replace", "path": "/spec/internalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", allNS[0], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("10.1 Verify CUDN and default network pods to ClusterIP service traffic on CUDN")
		// cudn pods to clusterIP with the same CUDN network
		CurlPod2SvcPass(oc, allNS[0], allNS[0], clientPodsNS[0][0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[0], allNS[0], clientPodsNS[0][1].name, svc.servicename)
		// cudn pods to clusterIP with the different CUDN networks
		CurlPod2SvcFail(oc, allNS[1], allNS[0], clientPodsNS[1][0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[1], allNS[0], clientPodsNS[1][1].name, svc.servicename)
		// default network pods to clusterIP service on CUDN L2
		CurlPod2SvcFail(oc, allNS[2], allNS[0], clientPodsNS[2][0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[2], allNS[0], clientPodsNS[2][1].name, svc.servicename)

		compat_otp.By("11. validate CUDN L2 pods to ClusterIP service on default network")
		compat_otp.By("11.1 delete clusterIP service in cudnNS[0] and create service on default network ns")
		removeResource(oc, true, true, "svc", svc.servicename, "-n", allNS[0])
		backendPodNS3 := backendPodNS1
		backendPodNS3.namespace = allNS[2]
		defer removeResource(oc, true, true, "pod", backendPodNS3.name, "-n", backendPodNS3.namespace)
		backendPodNS3.createPingPodNode(oc)
		waitPodReady(oc, backendPodNS3.namespace, backendPodNS3.name)
		svc.namespace = allNS[2]
		svc.createServiceFromParams(oc)
		svcOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[2], svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("11.2 validate CUDN L2 pods to clusterIP service on default network")
		CurlPod2SvcFail(oc, allNS[1], allNS[2], clientPodsNS[1][0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[1], allNS[2], clientPodsNS[1][0].name, svc.servicename)

		compat_otp.By("11.3 Update internalTrafficPolicy as Local for default network service")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", allNS[2], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		CurlPod2SvcFail(oc, allNS[1], allNS[2], clientPodsNS[1][0].name, svc.servicename)
		CurlPod2SvcFail(oc, allNS[1], allNS[2], clientPodsNS[1][0].name, svc.servicename)
	})

	g.It("Author:meinli-NonHyperShiftHOST-ConnectedOnly-Longduration-NonPreRelease-High-80053-Validate pod to nodePort service across CUDN Layer2 and default network in SGW and LGW [Serial]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			raTemplate             = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			matchLabelKey          = "test.io"
			matchValues            = []string{"cudn-network1-80053", "cudn-network2-80053"}
			cudnNames              = []string{"cudn-network1-80053", "cudn-network2-80053"}
			ipFamilyPolicy         = "SingleStack"
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This case requires 3 nodes, but the cluster has less than three nodes. skip it!!!")
		}
		compat_otp.By("1. create three namespaces")
		// create default network ns
		defaultNS := oc.Namespace()
		compat_otp.By("1.1 create two CUDN namespace and label them as cudnselector: the first one is for CUDN network1 and the second one is for CUDN network2")
		allNS := []string{}
		for i := 0; i < 2; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			allNS = append(allNS, ns)
		}
		compat_otp.By("1.2 create one namespace for default network")
		allNS = append(allNS, defaultNS)

		compat_otp.By("2. create CUDN layer2 in cudnNS")
		ipStackType := checkIPStackType(oc)
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::/60", "2011:100:200::/60"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/60", "2011:100:200::/60"}
		}
		for i, cudnName := range cudnNames {
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnName)
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnName, ipv4cidr[i], ipv6cidr[i], cidr[i], "layer2")
			o.Expect(err).NotTo(o.HaveOccurred())

			// label CUDN L2 with app=cudn-l2
			setUDNLabel(oc, cudnName, "app=cudn-l2-80053")
		}

		compat_otp.By("3. Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "cudn-l2-80053",
			networkLabelKey:   "app",
			networkLabelVaule: "cudn-l2-80053",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer ra.deleteRA(oc)
		ra.createRA(oc)

		compat_otp.By("4. verify CUDN L2 is advertised to external and other cluster nodes")
		for i, cudnName := range cudnNames {
			o.Eventually(func() bool {
				result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[i], ipv6cidr[i], nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
			e2e.Logf("SUCCESS - BGP CUDN L2 network %s advertised to external !!!", cudnName)
		}

		compat_otp.By("5. create two pods as service backend pods on different nodes in the first cudnNS")
		backendpodsNS1 := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			backendpodsNS1[i] = pingPodResourceNode{
				name:      "hello-pod-" + strconv.Itoa(i),
				namespace: allNS[0],
				nodename:  nodeList.Items[i].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", backendpodsNS1[i].name, "-n", backendpodsNS1[i].namespace)
			backendpodsNS1[i].createPingPodNode(oc)
			waitPodReady(oc, backendpodsNS1[i].namespace, backendpodsNS1[i].name)
		}

		compat_otp.By("6. Create three client pods on the first node, one in each of two CUDN and default network namespaces")
		clientpods := make([]pingPodResourceNode, 3)
		for i := 0; i < 3; i++ {
			clientpods[i] = pingPodResourceNode{
				name:      "client-pod",
				namespace: allNS[i],
				nodename:  nodeList.Items[0].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", clientpods[i].name, "-n", clientpods[i].namespace)
			clientpods[i].createPingPodNode(oc)
			waitPodReady(oc, clientpods[i].namespace, clientpods[i].name)
			// Update label for pod2 to a different one
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", allNS[i], "pod", clientpods[i].name, "name=client-pod", "--overwrite=true").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("7. create nodeport Service with ETP=cluster in first CUDN network")
		svc := genericServiceResource{
			servicename:           "test-service-cudn",
			namespace:             allNS[0],
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "NodePort",
			ipFamilyPolicy:        ipFamilyPolicy,
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "Cluster",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[0], svc.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("8 Validate CUDN and default network pods to nodePort service on CUDN when ETP=Cluster")
		compat_otp.By("8.1 validate cudn pod to nodePort service within the same CUDN network")
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		CurlPod2NodePortPass(oc, allNS[0], clientpods[0].name, nodeList.Items[0].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[0], clientpods[0].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[0], clientpods[0].name, nodeList.Items[2].Name, nodePort)
		compat_otp.By("8.2 validate cudn pod to nodePort service with the different CUDN networks")
		CurlPod2NodePortFail(oc, allNS[1], clientpods[1].name, nodeList.Items[0].Name, nodePort)
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		CurlPod2NodePortPass(oc, allNS[1], clientpods[1].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[1], clientpods[1].name, nodeList.Items[2].Name, nodePort)
		compat_otp.By("8.3 validate default network pod to nodePort service on CUDN network")
		// connection refused on ipv6
		CurlPod2NodePortFail(oc, allNS[2], clientpods[2].name, nodeList.Items[0].Name, nodePort)
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		CurlPod2NodePortPass(oc, allNS[2], clientpods[2].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[2], clientpods[2].name, nodeList.Items[2].Name, nodePort)

		compat_otp.By("9. Validate CUDN and default network pods to nodePort service on CUDN when ETP=Local")
		compat_otp.By("9.1 update NodePort service with ETP=Local in ns1")
		patch := `[{"op": "replace", "path": "/spec/externalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service-cudn", "-n", allNS[0], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("9.2 validate CUDN and default network pods to nodePort service on CUDN")
		compat_otp.By("9.2.1 validate cudn pod to nodePort service within the same CUDN network")
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		CurlPod2NodePortPass(oc, allNS[0], clientpods[0].name, nodeList.Items[0].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[0], clientpods[0].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortFail(oc, allNS[0], clientpods[0].name, nodeList.Items[2].Name, nodePort)
		compat_otp.By("9.2.2 validate cudn pod to nodePort service with the different CUDN networks")
		CurlPod2NodePortFail(oc, allNS[1], clientpods[1].name, nodeList.Items[0].Name, nodePort)
		// ipv6 nodeport doesn't work, https://issues.redhat.com/browse/OCPBUGS-55112
		CurlPod2NodePortPass(oc, allNS[1], clientpods[1].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortFail(oc, allNS[1], clientpods[1].name, nodeList.Items[2].Name, nodePort)
		compat_otp.By("9.2.3 validate default network pod to nodePort service on CUDN network")
		// connection refused on ipv6
		CurlPod2NodePortFail(oc, allNS[2], clientpods[2].name, nodeList.Items[0].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[2], clientpods[2].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortFail(oc, allNS[2], clientpods[2].name, nodeList.Items[2].Name, nodePort)

		compat_otp.By("10. validate CUDN L2 pod to nodePort service traffic on default network")
		compat_otp.By("10.1 delete nodePort service on CUDN l2 and create nodePort service on default network")
		removeResource(oc, true, true, "svc", svc.servicename, "-n", allNS[0])
		// create two backend pods on default network ns
		backendpodsNS2 := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			backendpodsNS2[i] = pingPodResourceNode{
				name:      "hello-pod-" + strconv.Itoa(i),
				namespace: allNS[2],
				nodename:  nodeList.Items[i].Name,
				template:  pingPodTemplate,
			}
			defer removeResource(oc, true, true, "pod", backendpodsNS2[i].name, "-n", backendpodsNS2[i].namespace)
			backendpodsNS2[i].createPingPodNode(oc)
			waitPodReady(oc, backendpodsNS2[i].namespace, backendpodsNS2[i].name)
		}

		svc.servicename = "test-service"
		svc.namespace = allNS[2]
		svc.createServiceFromParams(oc)
		nodePort, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[2], svc.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("10.2 validate CUDN l2 pod to nodePort service on default network")
		CurlPod2NodePortFail(oc, allNS[1], clientpods[1].name, nodeList.Items[0].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[1], clientpods[1].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[1], clientpods[1].name, nodeList.Items[2].Name, nodePort)

		compat_otp.By("10.3 update nodePort service ETP=Local")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", allNS[2], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		CurlPod2NodePortFail(oc, allNS[1], clientpods[1].name, nodeList.Items[0].Name, nodePort)
		CurlPod2NodePortPass(oc, allNS[1], clientpods[1].name, nodeList.Items[1].Name, nodePort)
		CurlPod2NodePortFail(oc, allNS[1], clientpods[1].name, nodeList.Items[2].Name, nodePort)
	})
	g.It("Author:zzhao-NonHyperShiftHOST-ConnectedOnly-Longduration-NonPreRelease-Medium-81698-check the connection/isoation still can be worked after node reboot [Disruptive]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			raTemplate             = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			helloDaemonset         = filepath.Join(buildPruningBaseDir, "hello-pod-daemonset.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			matchLabelKey          = "cudn-bgp"
			matchValues            = []string{"cudn-network-blue" + getRandomString(), "cudn-network-red" + getRandomString(), "cudn-network-l2" + getRandomString()}
			cudnNames              = []string{"l3-blue-network-81698", "l3-red-network-81698", "l2-udn-network-81698"}
			ipStackType            = checkIPStackType(oc)
			ipFamilyPolicy         = "SingleStack"
			allNS                  []string
		)

		compat_otp.By("Get worker nodes")
		workerNodes, err := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerNodes) < 2 {
			g.Skip("Need at least 2 worker node, not enough worker node, skip the case!!")
		}

		compat_otp.By("Get first namespace for default network, create an UDN namespace and label it with cudn selector")
		ns1 := oc.Namespace()
		allNS = append(allNS, ns1)

		compat_otp.By("create two UDN namespace and label it with cudn selector and apply CUDN resource")
		var cidr, ipv4cidr, ipv6cidr []string
		ipv4cidr = []string{"10.150.0.0/16", "20.150.0.0/16", "30.150.0.0/16"}
		ipv6cidr = []string{"2010:100:200::0/48", "2011:100:200::0/48", "2012:100:200::/48"}
		cidr = []string{"10.150.0.0/16", "20.150.0.0/16", "30.150.0.0/16"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::0/48", "2011:100:200::0/48", "2012:100:200::/48"}
		}
		for i := 0; i < 2; i++ {

			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			allNS = append(allNS, ns)

			compat_otp.By("Create L3 CUDN, and label the L3 CUDN to match networkSelector of RA")
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[i])
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnNames[i], ipv4cidr[i], ipv6cidr[i], cidr[i], "layer3")
			o.Expect(err).NotTo(o.HaveOccurred())
			//label userdefinednetwork with label app=udn
			setUDNLabel(oc, cudnNames[i], "app=udn")
		}

		var ns4 string
		compat_otp.By("create another UDN namespace for L2 CUDN, and label it with cudn selector")
		oc.CreateNamespaceUDN()
		ns4 = oc.Namespace()
		allNS = append(allNS, ns4)
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns4, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns4, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[2])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("create L2 CUDN L2 in ns4, and label the L2 CUDN to match networkSelector of RA")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[2])
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[2], cudnNames[2], ipv4cidr[2], ipv6cidr[2], cidr[2], "layer2")
		o.Expect(err).NotTo(o.HaveOccurred())

		// label CUDN L2 to match networkSelector of RA
		setUDNLabel(oc, cudnNames[2], "app=udn")

		compat_otp.By("Create RA to advertise the UDN network")
		ra := routeAdvertisement{
			name:              "udn",
			networkLabelKey:   "app",
			networkLabelVaule: "udn",
			advertiseType:     advertiseType,
			template:          raTemplate,
		}
		defer func() {
			ra.deleteRA(oc)
		}()
		ra.createRA(oc)

		compat_otp.By(" Verify L3 CUDN network is advertised to external router")
		for i := 0; i < 2; i++ {
			UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[i])
			o.Eventually(func() bool {
				result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
			e2e.Logf("SUCCESS - L3 UDN network %s advertised to external !!!", cudnNames[i])
		}

		compat_otp.By("verify CUDN L2 is advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[2], ipv6cidr[2], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is advertised to external !!!", cudnNames[2], ns4)

		compat_otp.By("Create a test pod and service in each namespace")

		for i := 0; i < len(allNS); i++ {

			compat_otp.By(fmt.Sprintf("Create hello-pod-daemonset in namespace %s", allNS[i]))
			defer removeResource(oc, true, true, "daemonset", "hello-daemonset", "-n", allNS[i])
			createResourceFromFile(oc, allNS[i], helloDaemonset)
			err = waitForPodWithLabelReady(oc, allNS[i], "name=hello-pod")
			compat_otp.AssertWaitPollNoErr(err, "hello pods are not ready!")

			compat_otp.By("Create svc for each namespace.")

			if ipStackType == "dualstack" {
				ipFamilyPolicy = "PreferDualStack"
			}
			svc := genericServiceResource{
				servicename:           "test-service",
				namespace:             allNS[i],
				protocol:              "TCP",
				selector:              "hello-pod",
				serviceType:           "ClusterIP",
				ipFamilyPolicy:        ipFamilyPolicy,
				internalTrafficPolicy: "Cluster",
				externalTrafficPolicy: "",
				template:              genericServiceTemplate,
			}
			svc.createServiceFromParams(oc)
			svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[i], svc.servicename).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))
		}

		compat_otp.By("7. Reboot two worker node.\n")
		defer checkNodeStatus(oc, workerNodes[0], "Ready")
		defer checkNodeStatus(oc, workerNodes[1], "Ready")

		rebootNode(oc, workerNodes[0])
		rebootNode(oc, workerNodes[1])

		checkNodeStatus(oc, workerNodes[0], "NotReady")
		checkNodeStatus(oc, workerNodes[1], "NotReady")

		checkNodeStatus(oc, workerNodes[0], "Ready")
		checkNodeStatus(oc, workerNodes[1], "Ready")

		compat_otp.By(" Verify L3 CUDN network is advertised to external and other cluster nodes")
		for i := 0; i < 2; i++ {
			UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[i])
			o.Eventually(func() bool {
				result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
			e2e.Logf("SUCCESS - L3 UDN network %s advertised to external !!!", cudnNames[i])
		}

		compat_otp.By("verify CUDN L2 is advertised to external")
		o.Eventually(func() bool {
			result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[2], ipv6cidr[2], nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L2 UDN network %s for namespace %s is advertised to external !!!", cudnNames[2], ns4)

		testpodNS0Name, _ := compat_otp.GetPodName(oc, allNS[0], "name=hello-pod", workerNodes[0])
		testpodNS1Name0, _ := compat_otp.GetPodName(oc, allNS[1], "name=hello-pod", workerNodes[0])
		testpodNS1Name1, _ := compat_otp.GetPodName(oc, allNS[1], "name=hello-pod", workerNodes[1])
		testpodNS2Name0, _ := compat_otp.GetPodName(oc, allNS[2], "name=hello-pod", workerNodes[0])
		testpodNS2Name1, _ := compat_otp.GetPodName(oc, allNS[2], "name=hello-pod", workerNodes[1])

		compat_otp.By("verified UDN L3 network pod cannot be accessed from same host worker")
		CurlNode2PodFailUDN(oc, workerNodes[0], allNS[1], testpodNS1Name0)

		//comment this due to bug https://issues.redhat.com/browse/OCPBUGS-51165
		compat_otp.By("verified UDN L3 network pod cannot be accessed from different host worker")
		CurlNode2PodFailUDN(oc, workerNodes[1], allNS[1], testpodNS1Name0)

		compat_otp.By("verified UDN L3 network pod cannot access to default network service")
		CurlPod2SvcFail(oc, allNS[1], allNS[0], testpodNS1Name0, "test-service")

		compat_otp.By("verified UDN L3 network pod cannot access to another UDN l3 service")
		CurlPod2SvcFail(oc, allNS[1], allNS[2], testpodNS1Name0, "test-service")

		compat_otp.By("verified default network pod cannot access to UDN l3 service")
		CurlPod2SvcFail(oc, allNS[0], allNS[2], testpodNS0Name, "test-service")

		compat_otp.By("verified UDN L3 network pod cannot access to another UDN pod")
		CurlPod2PodFailUDN(oc, allNS[1], testpodNS1Name1, allNS[2], testpodNS2Name0)
		CurlPod2PodFailUDN(oc, allNS[1], testpodNS1Name1, allNS[2], testpodNS2Name1)

		compat_otp.By("verified default network pod cannot access to UDN pod")
		CurlPod2PodFailUDN(oc, allNS[0], testpodNS0Name, allNS[2], testpodNS2Name0)
		CurlPod2PodFailUDN(oc, allNS[0], testpodNS0Name, allNS[2], testpodNS2Name1)

		compat_otp.By("verified defaunt network can be accessed from it's owned network")
		CurlPod2SvcPass(oc, allNS[0], allNS[0], testpodNS0Name, "test-service")

		compat_otp.By("verified UDN L3 network can be accessed from it's owned network")
		CurlPod2SvcPass(oc, allNS[1], allNS[1], testpodNS1Name0, "test-service")

		compat_otp.By("verified UDN L3 network can be accessed from it's owned network by podip")
		CurlPod2PodPassUDN(oc, allNS[1], testpodNS1Name1, allNS[1], testpodNS1Name0)

		compat_otp.By("verified L2 network pod can be accessed from external router")
		testpodNS3Name, _ := compat_otp.GetPodName(oc, allNS[3], "name=hello-pod", workerNodes[0])
		Curlexternal2UDNPodPass(oc, host, allNS[3], testpodNS3Name)

		compat_otp.By("verified UDN L2 network pod cannot be accessed from same host worker")
		CurlNode2PodFailUDN(oc, workerNodes[0], allNS[3], testpodNS3Name)
		compat_otp.By("verified UDN L2 network pod cannot be accessed from different host worker")
		CurlNode2PodFailUDN(oc, workerNodes[1], allNS[3], testpodNS3Name)

		compat_otp.By("verified UDN L3 network pod cannot access to L2 network service")
		CurlPod2SvcFail(oc, allNS[1], allNS[3], testpodNS1Name0, "test-service")

		compat_otp.By("verified UDN L2 network pod cannot be accessed from L3 network")
		CurlPod2PodFailUDN(oc, allNS[2], testpodNS2Name1, allNS[3], testpodNS3Name)

		compat_otp.By("verified UDN L2 network pod cannot access to another UDN l3 service")
		CurlPod2SvcFail(oc, allNS[3], allNS[2], testpodNS3Name, "test-service")

		compat_otp.By("verified UDN L2 network pod cannot access to defaunt network service")
		CurlPod2SvcFail(oc, allNS[3], allNS[0], testpodNS3Name, "test-service")

		compat_otp.By("verified default network pod cannot access to UDN l2 service")
		CurlPod2SvcFail(oc, allNS[0], allNS[3], testpodNS0Name, "test-service")

		compat_otp.By("verified default network pod cannot access to UDN l2 pod")
		CurlPod2PodFailUDN(oc, allNS[0], testpodNS0Name, allNS[3], testpodNS3Name)

		compat_otp.By("verified l2 network can be accessed to it's owned network")
		CurlPod2SvcPass(oc, allNS[3], allNS[3], testpodNS3Name, "test-service")

	})

	g.It("Author:meinli-High-82297-verify RA status when switch between SGW and LGW. [Disruptive]", func() {
		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			raTemplate           = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			cudnNames            = []string{"cudn-l3-82297", "cudn-l2-82297"}
			raName               = "cudn-82297"
			cudnTypes            = []string{"layer3", "layer2"}
			matchLabelKey        = "cudn-bgp"
			matchValues          = []string{"cudn-network-l3" + getRandomString(), "cudn-network-l2" + getRandomString()}
			networkSelectorKey   = "app"
			networkSelectorValue = "cudn-82297"
		)
		compat_otp.By("1. create CUDN L3 and L2")
		origMode := getOVNGatewayMode(oc)
		ipStackType := checkIPStackType(oc)
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::/60", "2011:100:200::/60"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/60", "2011:100:200::/60"}
		}
		var raErr error
		for i := 0; i < 2; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[i])
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[i], cudnNames[i], ipv4cidr[i], ipv6cidr[i], cidr[i], cudnTypes[i])
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		// label first CUDN
		setUDNLabel(oc, cudnNames[0], networkSelectorKey+"="+networkSelectorValue)

		// create RA to advertise CUDN network
		defer removeResource(oc, true, true, "ra", raName)
		params := []string{"-f", raTemplate, "-p", "NAME=" + raName, "NETWORKSELECTORKEY=" + networkSelectorKey, "NETWORKSELECTORVALUE=" + networkSelectorValue, "ADVERTISETYPE=" + advertiseType}
		compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)

		// label second CUDN
		setUDNLabel(oc, cudnNames[1], networkSelectorKey+"="+networkSelectorValue)

		raErr = checkRAStatus(oc, raName, "Accepted")
		o.Expect(raErr).NotTo(o.HaveOccurred())

		// check default network RA status
		raErr = checkRAStatus(oc, "default", "Accepted")
		o.Expect(raErr).NotTo(o.HaveOccurred())

		compat_otp.By("2. Switch gateway mode")
		var desiredMode string
		if origMode == "local" {
			desiredMode = "shared"
		} else {
			desiredMode = "local"
		}
		e2e.Logf("Cluster is currently on gateway mode %s", origMode)
		e2e.Logf("Desired mode is %s", desiredMode)
		defer switchOVNGatewayMode(oc, origMode)
		switchOVNGatewayMode(oc, desiredMode)

		compat_otp.By("3. check RA status after switch gateway mode")
		raErr = checkRAStatus(oc, raName, "Accepted")
		o.Expect(raErr).NotTo(o.HaveOccurred())

		// check default network RA status
		raErr = checkRAStatus(oc, "default", "Accepted")
		o.Expect(raErr).NotTo(o.HaveOccurred())

		compat_otp.By("4. check OVNK health")
		waitForNetworkOperatorState(oc, 100, 15, "True.*False.*False")
	})

	g.It("Author:meinli-NonHyperShiftHOST-ConnectedOnly-Longduration-NonPreRelease-High-83249-verify BGP loose isolation mode on CUDN. [Disruptive]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			matchLabelKey       = "cudn-bgp"
			networkSelectorKey  = "app"
			configName          = "ovn-kubernetes-config-overrides"
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1. create L3 and L2 CUDN, and create cudn pods respectively")
		type CUDNConfig struct {
			Name       string
			cidr       string
			ipv4cidr   string
			ipv6cidr   string
			Type       string
			MatchValue string
			RAName     string
		}

		cudnConfigs := []CUDNConfig{
			{
				Name: "l3-net-1", cidr: "10.150.0.0/16", ipv4cidr: "10.150.0.0/16", ipv6cidr: "2010:100:200::/60", Type: "layer3",
				MatchValue: "83249-l3-1", RAName: "ra-l3-1",
			},
			{
				Name: "l3-net-2", cidr: "10.151.0.0/16", ipv4cidr: "10.151.0.0/16", ipv6cidr: "2011:100:200::/60", Type: "layer3",
				MatchValue: "83249-l3-2", RAName: "ra-l3-2",
			},
			{
				Name: "l2-net-1", cidr: "10.152.0.0/16", ipv4cidr: "10.152.0.0/16", ipv6cidr: "2012:100:200::/60", Type: "layer2",
				MatchValue: "83249-l2-1", RAName: "ra-l2-1",
			},
			{
				Name: "l2-net-2", cidr: "10.153.0.0/16", ipv4cidr: "10.153.0.0/16", ipv6cidr: "2013:100:200::/60", Type: "layer2",
				MatchValue: "83249-l2-2", RAName: "ra-l2-2",
			},
		}

		ipStackType := checkIPStackType(oc)
		var allNS []string
		cudnpods := make([][]pingPodResourceNode, 4)
		for i, cudn := range cudnConfigs {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, cudn.MatchValue)).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			allNS = append(allNS, ns)

			// create CUDN
			if ipStackType == "ipv6single" {
				cudn.cidr = cudn.ipv6cidr
			}
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudn.Name)
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, cudn.MatchValue, cudn.Name, cudn.ipv4cidr, cudn.ipv6cidr, cudn.cidr, cudn.Type)
			o.Expect(err).NotTo(o.HaveOccurred())
			// label CUDN
			setUDNLabel(oc, cudn.Name, networkSelectorKey+"="+cudn.MatchValue)

			// create RA to advertise CUDN network
			defer removeResource(oc, true, true, "ra", cudn.RAName)
			params := []string{"-f", raTemplate, "-p", "NAME=" + cudn.RAName, "NETWORKSELECTORKEY=" + networkSelectorKey, "NETWORKSELECTORVALUE=" + cudn.MatchValue, "ADVERTISETYPE=" + advertiseType}
			compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
			raErr := checkRAStatus(oc, cudn.RAName, "Accepted")
			o.Expect(raErr).NotTo(o.HaveOccurred())

			// create CUDN pod
			cudnpods[i] = make([]pingPodResourceNode, 2)
			for podIdx := 0; podIdx < 2; podIdx++ {
				podName := fmt.Sprintf("hellopod-ns%d-%d", i+1, podIdx)
				cudnpods[i][podIdx] = pingPodResourceNode{
					name:      podName,
					namespace: ns,
					nodename:  nodeList.Items[podIdx].Name,
					template:  pingPodTemplate,
				}
				defer removeResource(oc, true, true, "pod", podName, "-n", ns)
				cudnpods[i][podIdx].createPingPodNode(oc)
				waitPodReady(oc, ns, podName)

				// add cudn pod routes in the default gateway router
				udnIp1, udnIp2 := getPodIPUDN(oc, ns, podName, "ovn-udn1")
				defer restoreIptablesRules(host)
				err = addIPtablesRules(host, allNodesIP1[1], udnIp1, udnIp2)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}

		compat_otp.By("2. update cluster to loose isolation mode")
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("configmap", configName, "-n", "openshift-network-operator").Output()
		if err != nil || msg == "" {
			// create loose mode configmap
			defer func() {
				removeResource(oc, true, true, "configmap", configName, "-n", "openshift-network-operator")
				checkOVNKState(oc)
			}()
			err := oc.AsAdmin().WithoutNamespace().Run("create").Args("configmap", configName, "-n", "openshift-network-operator", "--from-literal=advertised-udn-isolation-mode=loose").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err = checkConfigMap(oc, "openshift-network-operator", configName)
			compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("cm %v not found", configName))

			// wait for ovnkube pods rollout
			err = checkOVNKState(oc)
			compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("OVNkube didn't rolled out successfully after applying loose isolation mode"))
		}

		compat_otp.By("3. verify loose isolation mode between different CUDN networks")
		// validate L3
		CurlPod2PodPassUDN(oc, allNS[0], cudnpods[0][0].name, allNS[0], cudnpods[0][1].name)
		CurlPod2PodPassUDN(oc, allNS[0], cudnpods[0][0].name, allNS[1], cudnpods[1][0].name)
		CurlPod2PodPassUDN(oc, allNS[0], cudnpods[0][0].name, allNS[1], cudnpods[1][1].name)

		// validate L2
		CurlPod2PodPassUDN(oc, allNS[2], cudnpods[2][0].name, allNS[2], cudnpods[2][1].name)
		CurlPod2PodPassUDN(oc, allNS[2], cudnpods[2][0].name, allNS[3], cudnpods[3][0].name)
		CurlPod2PodPassUDN(oc, allNS[2], cudnpods[2][0].name, allNS[3], cudnpods[3][1].name)

		compat_otp.By("4. verify CUDN isolation mode after delete configmap")
		removeResource(oc, true, true, "configmap", configName, "-n", "openshift-network-operator")
		// wait for ovnkube pods rollout
		err = checkOVNKState(oc)
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("OVNkube didn't rolled out successfully after delete loose isolation mode"))
		// validate L3
		CurlPod2PodFailUDN(oc, allNS[0], cudnpods[0][0].name, allNS[1], cudnpods[1][0].name)
		CurlPod2PodFailUDN(oc, allNS[0], cudnpods[0][0].name, allNS[1], cudnpods[1][1].name)
		// validate L2
		CurlPod2PodFailUDN(oc, allNS[2], cudnpods[2][0].name, allNS[3], cudnpods[3][0].name)
		CurlPod2PodFailUDN(oc, allNS[2], cudnpods[2][0].name, allNS[3], cudnpods[3][1].name)
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-80056-Pod to node and pod to external traffic test with advertised v/s unadvertised default network toggled [Disruptive]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			raDefaultNWTemplate    = filepath.Join(buildPruningBaseDir, "bgp/ra_defaultnetwork_template.yaml")
			ipStackType            = checkIPStackType(oc)
			ipFamilyPolicy         = "SingleStack"
		)

		if ipStackType == "dualstack" {
			ipFamilyPolicy = "PreferDualStack"
		}

		compat_otp.By("0. Get worker nodes")
		workerNodes, err := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerNodes) < 2 {
			g.Skip("Need at least 2 worker nodes, not enough worker nodes, skip the case!!")
		}

		compat_otp.By("1.1 Get first namespace for default network, create a test pod in the namespace")
		ns1 := oc.Namespace()

		testPod := pingPodResourceNode{
			name:      "hello-pod-" + ns1,
			namespace: ns1,
			nodename:  workerNodes[0],
			template:  pingPodNodeTemplate,
		}
		testPod.createPingPodNode(oc)
		waitPodReady(oc, ns1, testPod.name)

		compat_otp.By("1.2 Create a second namespace for default network, create nodeport service with backend pod on the second worker node")
		oc.SetupProject()
		ns2 := oc.Namespace()

		nodePortPod := pingPodResourceNode{
			name:      "nodeport-pod-" + ns2,
			namespace: ns2,
			nodename:  workerNodes[1],
			template:  pingPodNodeTemplate,
		}
		defer removeResource(oc, true, true, "pod", nodePortPod.name, "-n", ns2)
		nodePortPod.createPingPodNode(oc)
		waitPodReady(oc, ns2, nodePortPod.name)

		svcs := genericServiceResource{
			servicename:           "test-service" + ns2,
			namespace:             ns2,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "NodePort",
			ipFamilyPolicy:        ipFamilyPolicy,
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "Local",
			template:              genericServiceTemplate,
		}
		svcs.createServiceFromParams(oc)
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns2, svcs.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("1.3. Verify egressing packets from testpod to external are SNATed to the test pod's podIP")
		testPodIP1, testPodIP2 := getPodIP(oc, ns1, testPod.name)
		e2e.Logf("testPodIP1: %s;   testPodIP2: %s", testPodIP1, testPodIP2)

		primaryInf, infErr := getSnifPhyInf(oc, workerNodes[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmdv4 := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, externalServiceipv4)
		curlExternalFromtestPodv4 := "curl " + net.JoinHostPort(externalServiceipv4, "8000") + " --connect-timeout 2 -I"
		tcpdumpCmdv6 := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, externalServiceipv6)
		curlExternalFromtestPodv6 := "curl " + net.JoinHostPort(externalServiceipv6, "8000") + " --connect-timeout 2 -I"

		if ipStackType == "ipv4single" {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmdv4, ns1, testPod.name, curlExternalFromtestPodv4)
			o.Expect(strings.Contains(tcpdumOutput, testPodIP1)).To(o.BeTrue())
		}
		if ipStackType == "ipv6single" {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmdv6, ns1, testPod.name, curlExternalFromtestPodv6)
			o.Expect(strings.Contains(tcpdumOutput, testPodIP1)).To(o.BeTrue())
		}
		if ipStackType == "dualstack" {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmdv4, ns1, testPod.name, curlExternalFromtestPodv4)
			o.Expect(strings.Contains(tcpdumOutput, testPodIP2)).To(o.BeTrue())
			tcpdumOutput2 := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmdv6, ns1, testPod.name, curlExternalFromtestPodv6)
			o.Expect(strings.Contains(tcpdumOutput2, testPodIP1)).To(o.BeTrue())
		}

		compat_otp.By("1.4. Verify packets from test pod to another cluster node are SNATed to nodeIP of the test pod's host")
		destNodeIP2, destNodeIP1 := getNodeIP(oc, workerNodes[1])
		podNodeIP2, podNodeIP1 := getNodeIP(oc, workerNodes[0])
		e2e.Logf("pod's host nodeIP,  podNodeIP1: %s;   podNodeIP2: %s", podNodeIP1, podNodeIP2)

		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			curlNodeFromPod1 := "curl " + net.JoinHostPort(destNodeIP1, nodePort) + " --connect-timeout 5"
			tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, destNodeIP1)
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmd, ns1, testPod.name, curlNodeFromPod1)
			o.Expect(strings.Contains(tcpdumOutput, podNodeIP1)).To(o.BeTrue())
		}

		if ipStackType == "ipv6single" {
			curlNodeFromPod1 := "curl " + net.JoinHostPort(destNodeIP1, nodePort) + " --connect-timeout 5"
			tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, destNodeIP1)
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmd, ns1, testPod.name, curlNodeFromPod1)
			o.Expect(strings.Contains(tcpdumOutput, podNodeIP1)).To(o.BeTrue())
		}

		if ipStackType == "dualstack" {
			curlNodeFromPod2 := "curl " + net.JoinHostPort(destNodeIP2, nodePort) + " --connect-timeout 5"
			tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, destNodeIP2)
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmd, ns1, testPod.name, curlNodeFromPod2)
			o.Expect(strings.Contains(tcpdumOutput, podNodeIP2)).To(o.BeTrue())
		}

		compat_otp.By("2.1. Remove the default network RA")

		// defer restore test environment with default network RA
		defer func() {
			raName := "default"
			params := []string{"-f", raDefaultNWTemplate, "-p", "NAME=" + raName, "ADVERTISETYPE=" + advertiseType}
			compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
			raErr := checkRAStatus(oc, raName, "Accepted")
			compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
			e2e.Logf("SUCCESS - routeAdvertisement applied is accepted")

			compat_otp.By("Verify default network is advertised")
			o.Eventually(func() bool {
				result := verifyIPRoutesOnExternalFrr(host, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map, true)
				return result
			}, "30s", "5s").Should(o.BeTrue(), "BGP route advertisement of default network did not succeed!!")
			e2e.Logf("SUCCESS - BGP is enabled again, default network is advertised again!!!")
		}()

		removeResource(oc, true, true, "ra", "default")

		// // wait a little time for default network routes to be removed
		// time.Sleep(30 * time.Second)

		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map, false)
			e2e.Logf("result after removing RA: %v", result)
			return result
		}, "30s", "5s").Should(o.BeTrue(), "BGP route advertisement of default network was not removed!!")
		e2e.Logf("SUCCESS - default network is not advertised anymore!!!")

		compat_otp.By("2.2. Without default network being advertised, verify egressing packets from pod to external are fallback to SNATing to nodeIP of the test pod's host")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmdv4, ns1, testPod.name, curlExternalFromtestPodv4)
			o.Expect(strings.Contains(tcpdumOutput, podNodeIP1)).To(o.BeTrue())
		}
		if ipStackType == "ipv6single" {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmdv6, ns1, testPod.name, curlExternalFromtestPodv6)
			o.Expect(strings.Contains(tcpdumOutput, podNodeIP1)).To(o.BeTrue())
		}
		if ipStackType == "dualstack" {
			tcpdumOutput2 := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmdv6, ns1, testPod.name, curlExternalFromtestPodv6)
			o.Expect(strings.Contains(tcpdumOutput2, podNodeIP2)).To(o.BeTrue())
		}
		compat_otp.By("2.3. Without default network being advertised, verify packets from pod to another cluster node are still SNATed to nodeIP of the test pod's host")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			curlNodeFromPod1 := "curl " + net.JoinHostPort(destNodeIP1, nodePort) + " --connect-timeout 5"
			tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s host %s", primaryInf, destNodeIP1)
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmd, ns1, testPod.name, curlNodeFromPod1)
			o.Expect(strings.Contains(tcpdumOutput, podNodeIP1)).To(o.BeTrue())
		}

		if ipStackType == "ipv6single" {
			curlNodeFromPod1 := "curl " + net.JoinHostPort(destNodeIP1, nodePort) + " --connect-timeout 5"
			tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, destNodeIP1)
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmd, ns1, testPod.name, curlNodeFromPod1)
			o.Expect(strings.Contains(tcpdumOutput, podNodeIP1)).To(o.BeTrue())
		}

		if ipStackType == "dualstack" {
			curlNodeFromPod2 := "curl " + net.JoinHostPort(destNodeIP2, nodePort) + " --connect-timeout 5"
			tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s ip6 host %s", primaryInf, destNodeIP2)
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, workerNodes[0], tcpdumpCmd, ns1, testPod.name, curlNodeFromPod2)
			o.Expect(strings.Contains(tcpdumOutput, podNodeIP2)).To(o.BeTrue())
		}

	})

})
