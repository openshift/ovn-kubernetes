package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

var _ = g.Describe("[OTP][sig-networking] SDN OVN ibgp", func() {
	defer g.GinkgoRecover()

	var (
		oc                   = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		ipStackType          string
		host                 = ""
		externalFRRIP1       string
		externalFRRIP2       string
		frrContainerID       string
		allNodes             []string
		podNetwork1Map       = make(map[string]string)
		podNetwork2Map       = make(map[string]string)
		nodesIP1Map          = make(map[string]string)
		nodesIP2Map          = make(map[string]string)
		allNodesIP2          []string
		allNodesIP1          []string
		frrNamespace         = "openshift-frr-k8s"
		raName               string
		frrConfigurationName string
		asn                  = 64512
		advertiseType        = "PodNetwork"
	)

	g.JustBeforeEach(func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			receiveTemplate     = filepath.Join(buildPruningBaseDir, "bgp/receive_all_template.yaml")
			receiveDSTemplate   = filepath.Join(buildPruningBaseDir, "bgp/receive_all_dualstack_template.yaml")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_defaultnetwork_template.yaml")

			nodeErr error
		)

		host = os.Getenv("QE_HYPERVISOR_PUBLIC_ADDRESS")
		if host == "" {
			g.Skip("hypervisorHost is nil, please set env QE_HYPERVISOR_PUBLIC_ADDRESS first!!!")
		}

		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}

		SkipIfExternalFRRExists(host)

		ipStackType = checkIPStackType(oc)

		compat_otp.By("check if FRR routeAdvertisements is enabled")
		if !IsFrrRouteAdvertisementEnabled(oc) {
			enableFRRRouteAdvertisement(oc)
			if !IsFrrRouteAdvertisementEnabled(oc) || !areFRRPodsReady(oc, frrNamespace) {
				g.Skip("FRR routeAdvertisement is still not enabled on the cluster, or FRR pods are not ready, skip the test!!!")
			}
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
		o.Expect(externalFRRIP1).NotTo(o.BeEmpty())
		if ipStackType == "dualstack" {
			o.Expect(externalFRRIP2).NotTo(o.BeEmpty())
		}

		emptyArray := []string{}
		if ipStackType == "dualstack" {
			frrContainerID = createExternalFrrRouter(host, "", allNodesIP1, allNodesIP2, emptyArray, emptyArray)
		} else if ipStackType == "ipv4single" {
			frrContainerID = createExternalFrrRouter(host, "", allNodesIP1, emptyArray, emptyArray, emptyArray)
		} else if ipStackType == "ipv6single" {
			frrContainerID = createExternalFrrRouter(host, "", emptyArray, allNodesIP1, emptyArray, emptyArray)
		}

		compat_otp.By("Get default podNetworks of all cluster nodes")
		podNetwork2Map, podNetwork1Map = getHostPodNetwork(oc, allNodes, "default")
		o.Expect(len(podNetwork2Map)).NotTo(o.BeEquivalentTo(0))
		o.Expect(len(podNetwork1Map)).NotTo(o.BeEquivalentTo(0))

		compat_otp.By("Apply receive_all frrconfiguration and routeAdvertisements yamls to cluster")
		frrConfigurationName = "receive-all"
		switch ipStackType {
		case "ipv4single":
			frrconfigration1 := frrconfigurationResource{
				name:           frrConfigurationName,
				namespace:      frrNamespace,
				asnLocal:       asn,
				asnRemote:      asn,
				externalFRRIP1: externalFRRIP1,
				template:       receiveTemplate,
			}
			frrconfigration1.createFRRconfigration(oc)
			output, frrConfigErr := oc.AsAdmin().Run("get").Args("frrconfiguration", "-n", frrNamespace).Output()
			o.Expect(frrConfigErr).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, frrconfigration1.name)).To(o.BeTrue())
		case "dualstack":
			frrconfigrationDS := frrconfigurationResourceDS{
				name:           frrConfigurationName,
				namespace:      frrNamespace,
				asnLocal:       asn,
				asnRemote:      asn,
				externalFRRIP1: externalFRRIP1,
				externalFRRIP2: externalFRRIP2,
				template:       receiveDSTemplate,
			}
			frrconfigrationDS.createFRRconfigrationDS(oc)
			output, frrConfigErr := oc.AsAdmin().Run("get").Args("frrconfiguration", "-n", frrNamespace).Output()
			o.Expect(frrConfigErr).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, frrconfigrationDS.name)).To(o.BeTrue())
		default:
			e2e.Logf("Other ipstack type (i.e singlev6) is currently not supported due to bug in frr.")
			g.Skip("Skip other unsupported ipstack type for now.")
		}

		raName = "default"
		params := []string{"-f", raTemplate, "-p", "NAME=" + raName, "ADVERTISETYPE=" + advertiseType}
		compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
		raErr := checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - routeAdvertisement applied is accepted")

		compat_otp.By("Verify default network is advertised")
		o.Eventually(func() bool {
			result := verifyRouteAdvertisement(oc, host, externalFRRIP2, externalFRRIP1, frrContainerID, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map)
			return result
		}, "120s", "15s").Should(o.BeTrue(), "BGP route advertisement of default network did not succeed!!")
		e2e.Logf("SUCCESS - BGP enabled, default network is advertised!!!")

	})

	g.JustAfterEach(func() {
		removeResource(oc, true, true, "ra", raName)
		removeResource(oc, true, true, "frrconfiguration", frrConfigurationName, "-n", frrNamespace)
		sshRunCmd(host, "root", "sudo podman rm -f "+frrContainerID)
		sshRunCmd(host, "root", "rm -rf "+"/tmp/bgp-test-frr")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-78338-Medium-78341-route advertisement and route leaking through VRF-default on default network, and dynamically update with route change [Serial]", func() {

		compat_otp.By("1. From IP routing table, verify cluster default podnetwork routes are advertised to external frr router")
		result := verifyIPRoutesOnExternalFrr(host, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map, true)
		o.Expect(result).To(o.BeTrue(), "Not all podNetwork are advertised to external frr router")

		compat_otp.By("2. From IP routing table, verify external routes and other cluster nodes' default podnetwork are learned to each cluster node")
		for _, node := range allNodes {
			result := verifyIPRoutesOnClusterNode(oc, node, externalFRRIP1, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map, true)
			o.Expect(result).To(o.BeTrue(), fmt.Sprintf("ip routing table of node %s did not have all bgp routes as expected", node))
		}

		compat_otp.By("3. Add a new route externally to external frr")
		newV4Network := "192.169.1.0/24"
		newV6Network := "fd12:3456:789a::/64"
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			vtyshCmds := []string{"configure terminal", "router bgp " + strconv.Itoa(asn), "network " + newV4Network, "end", "write"}
			var addCmdString string
			for _, cmd := range vtyshCmds {
				addCmdString = addCmdString + " -c \"" + cmd + "\""
			}

			externalFrrAddCmd := "sudo podman exec -it " + frrContainerID + " vtysh " + addCmdString
			err := sshRunCmd(host, "root", externalFrrAddCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		if ipStackType == "ipv6single" || ipStackType == "dualstack" {
			vtyshCmds := []string{"configure terminal", "router bgp " + strconv.Itoa(asn) + newV6Network, "end", "write"}
			var addCmdString string
			for _, cmd := range vtyshCmds {
				addCmdString = addCmdString + " -c \"" + cmd + "\""
			}

			externalFrrAddCmd := "sudo podman exec -it " + frrContainerID + " vtysh " + addCmdString
			err := sshRunCmd(host, "root", externalFrrAddCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		output, err := sshRunCmdOutPut(host, "root", "sudo podman exec -it "+frrContainerID+" vtysh -c \" show running-conf \"")
		o.Expect(err).NotTo(o.HaveOccurred())
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			o.Expect(strings.Contains(output, "network "+newV4Network)).To(o.BeTrue())
		}
		if ipStackType == "ipv6single" || ipStackType == "dualstack" {
			o.Expect(strings.Contains(output, "network "+newV6Network)).To(o.BeTrue())
		}

		compat_otp.By("4. Verify new route is imported to each node's ovnk router")
		for _, node := range allNodes {
			nodeLogicalRouterName := "GR_" + node
			ovnKubePod, ovnkNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", node)
			o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
			o.Expect(ovnKubePod).ShouldNot(o.Equal(""))
			cmd := "ovn-nbctl lr-route-list " + nodeLogicalRouterName
			output, cmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubePod, "northd", cmd)
			o.Expect(cmdErr).NotTo(o.HaveOccurred())
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				expectedRoutePattern := fmt.Sprintf(`%s\s+%s\s+dst-ip\s+%s`, regexp.QuoteMeta(newV4Network), regexp.QuoteMeta(externalFRRIP1), regexp.QuoteMeta("rtoe-"+nodeLogicalRouterName))
				e2e.Logf("expectedRoutePattern: %s\n", expectedRoutePattern)
				matched, err := regexp.MatchString(expectedRoutePattern, output)
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(matched).Should(o.BeTrue())
			}

			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				expectedRoutePattern := fmt.Sprintf(`%s\s+%s\s+dst-ip\s+%s`, regexp.QuoteMeta(newV6Network), regexp.QuoteMeta(externalFRRIP2), regexp.QuoteMeta("rtoe-"+nodeLogicalRouterName))
				e2e.Logf("expectedRoutePattern: %s\n", expectedRoutePattern)
				matched, err := regexp.MatchString(expectedRoutePattern, output)
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(matched).Should(o.BeTrue())
			}

		}

		compat_otp.By("5. Delete the route from external frr")
		if ipStackType == "ipv4single" || ipStackType == "dualstack" {
			vtyshCmds := []string{"configure terminal", "router bgp " + strconv.Itoa(asn), " no network " + newV4Network, "end", "write"}
			var delCmdString string
			for _, cmd := range vtyshCmds {
				delCmdString = delCmdString + " -c \"" + cmd + "\""
			}
			externalFrrDelCmd := "sudo podman exec -it " + frrContainerID + " vtysh " + delCmdString
			err := sshRunCmd(host, "root", externalFrrDelCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		if ipStackType == "ipv6single" || ipStackType == "dualstack" {
			vtyshCmds := []string{"configure terminal", "router bgp " + strconv.Itoa(asn), "no network " + newV6Network, "end", "write"}
			var delCmdString string
			for _, cmd := range vtyshCmds {
				delCmdString = delCmdString + " -c \"" + cmd + "\""
			}
			externalFrrDelCmd := "sudo podman exec -it " + frrContainerID + " vtysh " + delCmdString
			err := sshRunCmd(host, "root", externalFrrDelCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("6. Verify new route is removed from each node's ovnk router")
		for _, node := range allNodes {
			nodeLogicalRouterName := "GR_" + node
			ovnKubePod, ovnkNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", node)
			o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
			o.Expect(ovnKubePod).ShouldNot(o.Equal(""))
			cmd := "ovn-nbctl lr-route-list " + nodeLogicalRouterName
			output, cmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubePod, "northd", cmd)
			o.Expect(cmdErr).NotTo(o.HaveOccurred())
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				expectedRoutePattern := fmt.Sprintf(`%s\s+%s\s+dst-ip\s+%s`, regexp.QuoteMeta(newV4Network), regexp.QuoteMeta(externalFRRIP1), regexp.QuoteMeta("rtoe-"+nodeLogicalRouterName))
				e2e.Logf("expectedRoutePattern: %s\n", expectedRoutePattern)
				matched, err := regexp.MatchString(expectedRoutePattern, output)
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(matched).Should(o.BeFalse())
			}

			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				expectedRoutePattern := fmt.Sprintf(`%s\s+%s\s+dst-ip\s+%s`, regexp.QuoteMeta(newV6Network), regexp.QuoteMeta(externalFRRIP2), regexp.QuoteMeta("rtoe-"+nodeLogicalRouterName))
				e2e.Logf("expectedRoutePattern: %s\n", expectedRoutePattern)
				matched, err := regexp.MatchString(expectedRoutePattern, output)
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(matched).Should(o.BeFalse())
			}
		}
	})

})

var _ = g.Describe("[OTP][sig-networking] SDN bgp ebgp", func() {
	defer g.GinkgoRecover()

	var (
		oc                   = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		ipStackType          string
		host                 = ""
		externalFRRIP1       string
		externalFRRIP2       string
		frrContainerID       string
		allNodes             []string
		podNetwork1Map       = make(map[string]string)
		podNetwork2Map       = make(map[string]string)
		nodesIP1Map          = make(map[string]string)
		nodesIP2Map          = make(map[string]string)
		allNodesIP2          []string
		allNodesIP1          []string
		frrNamespace         = "openshift-frr-k8s"
		raName               string
		frrConfigurationName string
		advertiseType        = "PodNetwork"
	)

	g.JustBeforeEach(func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			receiveTemplate     = filepath.Join(buildPruningBaseDir, "bgp/receive_all_template.yaml")
			receiveDSTemplate   = filepath.Join(buildPruningBaseDir, "bgp/receive_all_dualstack_template.yaml")
			raTemplate          = filepath.Join(buildPruningBaseDir, "bgp/ra_defaultnetwork_template.yaml")
			localASN            = 64512
			externalASN         = 64515
			nodeErr             error
		)

		host = os.Getenv("QE_HYPERVISOR_PUBLIC_ADDRESS")
		if host == "" {
			g.Skip("hypervisorHost is nil, please set env QE_HYPERVISOR_PUBLIC_ADDRESS first!!!")
		}

		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}

		SkipIfExternalFRRExists(host)

		ipStackType = checkIPStackType(oc)

		compat_otp.By("check if FRR routeAdvertisements is enabled")
		if !IsFrrRouteAdvertisementEnabled(oc) {
			enableFRRRouteAdvertisement(oc)
			if !IsFrrRouteAdvertisementEnabled(oc) || !areFRRPodsReady(oc, frrNamespace) {
				g.Skip("FRR routeAdvertisement is still not enabled on the cluster, or FRR pods are not ready, skip the test!!!")
			}
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
		o.Expect(externalFRRIP1).NotTo(o.BeEmpty())
		if ipStackType == "dualstack" {
			o.Expect(externalFRRIP2).NotTo(o.BeEmpty())
		}

		emptyArray := []string{}
		if ipStackType == "dualstack" {
			frrContainerID = createExternalFrrRouterEBGP(host, "", allNodesIP1, allNodesIP2, emptyArray, emptyArray)
		} else if ipStackType == "ipv4single" {
			frrContainerID = createExternalFrrRouterEBGP(host, "", allNodesIP1, emptyArray, emptyArray, emptyArray)
		} else if ipStackType == "ipv6single" {
			frrContainerID = createExternalFrrRouterEBGP(host, "", emptyArray, allNodesIP1, emptyArray, emptyArray)
		}

		compat_otp.By("Get default podNetworks of all cluster nodes")
		podNetwork2Map, podNetwork1Map = getHostPodNetwork(oc, allNodes, "default")
		o.Expect(len(podNetwork2Map)).NotTo(o.BeEquivalentTo(0))
		o.Expect(len(podNetwork1Map)).NotTo(o.BeEquivalentTo(0))

		compat_otp.By("Apply receive_all frrconfiguration and routeAdvertisements yamls to cluster")
		frrConfigurationName = "receive-all"
		switch ipStackType {
		case "ipv4single":
			frrconfigration1 := frrconfigurationResource{
				name:           frrConfigurationName,
				namespace:      frrNamespace,
				asnLocal:       localASN,
				asnRemote:      externalASN,
				externalFRRIP1: externalFRRIP1,
				template:       receiveTemplate,
			}
			frrconfigration1.createFRRconfigration(oc)
			output, frrConfigErr := oc.AsAdmin().Run("get").Args("frrconfiguration", "-n", frrNamespace).Output()
			o.Expect(frrConfigErr).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, frrconfigration1.name)).To(o.BeTrue())
		case "dualstack":
			frrconfigrationDS := frrconfigurationResourceDS{
				name:           frrConfigurationName,
				namespace:      frrNamespace,
				asnLocal:       localASN,
				asnRemote:      externalASN,
				externalFRRIP1: externalFRRIP1,
				externalFRRIP2: externalFRRIP2,
				template:       receiveDSTemplate,
			}
			frrconfigrationDS.createFRRconfigrationDS(oc)
			output, frrConfigErr := oc.AsAdmin().Run("get").Args("frrconfiguration", "-n", frrNamespace).Output()
			o.Expect(frrConfigErr).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, frrconfigrationDS.name)).To(o.BeTrue())
		default:
			e2e.Logf("Other ipstack type (i.e singlev6) is currently not supported due to bug in frr.")
			g.Skip("Skip other unsupported ipstack type for now.")
		}

		raName = "default"
		params := []string{"-f", raTemplate, "-p", "NAME=" + raName, "ADVERTISETYPE=" + advertiseType}
		compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
		raErr := checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - routeAdvertisement applied is accepted")

		// wait some time for routeAdvertisement to occur
		time.Sleep(60 * time.Second)
		compat_otp.By("Verify default network is advertised")
		o.Eventually(func() bool {
			result := verifyRouteAdvertisementEBGP(oc, host, externalFRRIP2, externalFRRIP1, frrContainerID, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map)
			return result
		}, "90s", "5s").Should(o.BeTrue(), "BGP route advertisement of default network did not succeed!!")
		e2e.Logf("SUCCESS - BGP enabled, default network is advertised!!!")

	})

	g.JustAfterEach(func() {
		removeResource(oc, true, true, "ra", raName)
		removeResource(oc, true, true, "frrconfiguration", frrConfigurationName, "-n", frrNamespace)
		sshRunCmd(host, "root", "sudo podman rm -f "+frrContainerID)
		sshRunCmd(host, "root", "rm -rf "+"/tmp/bgp-test-frr")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-Longduration-NonPreRelease-High-78349-route advertisement on default network for eBGP scenrio [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)
		compat_otp.By("1. Get first namespace for default network")
		ns1 := oc.Namespace()

		compat_otp.By("2. Create a test pod in each namespace, verify each pod can be accessed from external because their default network")
		testpod := pingPodResource{
			name:      "hello-pod" + ns1,
			namespace: ns1,
			template:  pingPodTemplate,
		}
		testpod.createPingPod(oc)
		waitPodReady(oc, testpod.namespace, testpod.name)

		Curlexternal2PodPass(oc, host, testpod.namespace, testpod.name)

	})

})

var _ = g.Describe("[OTP][sig-networking] SDN OVN ibgp special case", func() {
	defer g.GinkgoRecover()

	var (
		oc                   = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		ipStackType          string
		host                 = ""
		externalFRRIP1       string
		externalFRRIP2       string
		frrContainerID       string
		allNodes             []string
		podNetwork1Map       = make(map[string]string)
		podNetwork2Map       = make(map[string]string)
		nodesIP1Map          = make(map[string]string)
		nodesIP2Map          = make(map[string]string)
		allNodesIP2          []string
		allNodesIP1          []string
		frrNamespace         = "openshift-frr-k8s"
		raName               string
		frrConfigurationName string
		advertiseType        = "PodNetwork"
	)

	g.JustBeforeEach(func() {
		host = os.Getenv("QE_HYPERVISOR_PUBLIC_ADDRESS")
		if host == "" {
			g.Skip("hypervisorHost is nil, please set env QE_HYPERVISOR_PUBLIC_ADDRESS first!!!")
		}

		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}

		SkipIfExternalFRRExists(host)

	})

	g.JustAfterEach(func() {
		removeResource(oc, true, true, "ra", raName)
		removeResource(oc, true, true, "frrconfiguration", frrConfigurationName, "-n", frrNamespace)
		sshRunCmd(host, "root", "sudo podman rm -f "+frrContainerID)
		sshRunCmd(host, "root", "rm -rf "+"/tmp/bgp-test-frr")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-78340-Newly added node can join route advertisement [Disruptive]", func() {

		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			receiveTemplate      = filepath.Join(buildPruningBaseDir, "bgp/receive_all_template.yaml")
			receiveDSTemplate    = filepath.Join(buildPruningBaseDir, "bgp/receive_all_dualstack_template.yaml")
			raDefaultNWTemplate  = filepath.Join(buildPruningBaseDir, "bgp/ra_defaultnetwork_template.yaml")
			raCUDNTemplate       = filepath.Join(buildPruningBaseDir, "bgp/ra_cudn_template.yaml")
			asn                  = 64512
			nodeErr              error
			matchLabelKey        = "cudn-bgp"
			matchValues          = []string{"cudn-network-l3" + getRandomString(), "cudn-network-l2" + getRandomString()}
			cudnNames            = []string{"l3-udn-network-78340", "l2-udn-network-78340"}
			networkselectorkey   = "app"
			networkselectorvalue = "udn"
		)

		ipStackType = checkIPStackType(oc)
		var err error
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("1. Save a worker node's yaml first, then delete the worker node, it will be added back in step 4")
		nodeDeleteAddBack := nodeList.Items[len(nodeList.Items)-1].Name
		e2e.Logf("node to be deleted then added back later: %v", nodeDeleteAddBack)

		// save the yaml of the node that will be deleted
		nodeYAMLFilename := nodeDeleteAddBack + ".yaml"
		nodeYAMLFile, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeDeleteAddBack, "-oyaml").OutputToFile(nodeYAMLFilename)
		o.Expect(err).NotTo(o.HaveOccurred())

		//frr-k8s-webhook-server pod could be on the deleted node, if that, need to wait it be relocated to another node and back to running state
		//get the node name of frr-k8s-webhook-server pod
		frrWebHookPodList, err := compat_otp.GetAllPodsWithLabel(oc, frrNamespace, "component=frr-k8s-webhook-server")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(frrWebHookPodList)).Should(o.Equal(1))
		frr8ksPodNodeName, getNodeErr := compat_otp.GetPodNodeName(oc, frrNamespace, frrWebHookPodList[0])
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		o.Expect(frr8ksPodNodeName).NotTo(o.BeEmpty())

		// delete the node and make sure frr-k8s-webhook-server pod is running before proceeding
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("node", nodeDeleteAddBack).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		if frr8ksPodNodeName == nodeDeleteAddBack {
			// if frr-k8s webhook server pod happened to be on the deleted node, need to wait for it to be relocated to another node
			time.Sleep(60 * time.Second)
		}
		waitForPodWithLabelReady(oc, frrNamespace, "component=frr-k8s-webhook-server")

		defer os.Remove(nodeYAMLFile)
		defer func() {
			e2e.Logf("Recreate the node")
			oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", nodeYAMLFile).Execute()
			checkNodeStatus(oc, nodeDeleteAddBack, "Ready")
		}()

		compat_otp.By("2. With remaining nodes on cluster, enable routeAdvertisement on default network first")
		compat_otp.By("check if FRR routeAdvertisements is enabled")
		if !IsFrrRouteAdvertisementEnabled(oc) {
			enableFRRRouteAdvertisement(oc)
			if !IsFrrRouteAdvertisementEnabled(oc) || !areFRRPodsReady(oc, frrNamespace) {
				g.Skip("FRR routeAdvertisement is still not enabled on the cluster, or FRR pods are not ready, skip the test!!!")
			}
		}

		compat_otp.By("Get IPs of cluster nodes, and IP map of all existing nodes")
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
		o.Expect(externalFRRIP1).NotTo(o.BeEmpty())
		if ipStackType == "dualstack" {
			o.Expect(externalFRRIP2).NotTo(o.BeEmpty())
		}

		emptyArray := []string{}
		if ipStackType == "dualstack" {
			frrContainerID = createExternalFrrRouter(host, "", allNodesIP1, allNodesIP2, emptyArray, emptyArray)
		} else if ipStackType == "ipv4single" {
			frrContainerID = createExternalFrrRouter(host, "", allNodesIP1, emptyArray, emptyArray, emptyArray)
		} else if ipStackType == "ipv6single" {
			frrContainerID = createExternalFrrRouter(host, "", emptyArray, allNodesIP1, emptyArray, emptyArray)
		}

		compat_otp.By("Get default podNetworks of all cluster nodes")
		podNetwork2Map, podNetwork1Map = getHostPodNetwork(oc, allNodes, "default")
		o.Expect(len(podNetwork2Map)).NotTo(o.BeEquivalentTo(0))
		o.Expect(len(podNetwork1Map)).NotTo(o.BeEquivalentTo(0))

		compat_otp.By("Apply receive_all frrconfiguration and routeAdvertisements yamls to cluster")
		frrConfigurationName = "receive-all"
		switch ipStackType {
		case "ipv4single":
			frrconfigration1 := frrconfigurationResource{
				name:           frrConfigurationName,
				namespace:      frrNamespace,
				asnLocal:       asn,
				asnRemote:      asn,
				externalFRRIP1: externalFRRIP1,
				template:       receiveTemplate,
			}
			frrconfigration1.createFRRconfigration(oc)
			output, frrConfigErr := oc.AsAdmin().Run("get").Args("frrconfiguration", "-n", frrNamespace).Output()
			o.Expect(frrConfigErr).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, frrconfigration1.name)).To(o.BeTrue())
		case "dualstack":
			frrconfigrationDS := frrconfigurationResourceDS{
				name:           frrConfigurationName,
				namespace:      frrNamespace,
				asnLocal:       asn,
				asnRemote:      asn,
				externalFRRIP1: externalFRRIP1,
				externalFRRIP2: externalFRRIP2,
				template:       receiveDSTemplate,
			}
			frrconfigrationDS.createFRRconfigrationDS(oc)
			output, frrConfigErr := oc.AsAdmin().Run("get").Args("frrconfiguration", "-n", frrNamespace).Output()
			o.Expect(frrConfigErr).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, frrconfigrationDS.name)).To(o.BeTrue())
		default:
			e2e.Logf("Other ipstack type (i.e singlev6) is currently not supported due to bug in frr.")
			g.Skip("Skip other unsupported ipstack type for now.")
		}

		raName = "default"
		params := []string{"-f", raDefaultNWTemplate, "-p", "NAME=" + raName, "ADVERTISETYPE=" + advertiseType}
		compat_otp.ApplyNsResourceFromTemplate(oc, "default", params...)
		raErr := checkRAStatus(oc, raName, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - routeAdvertisement applied is accepted")

		// wait a little time for default network to be advertised
		time.Sleep(60 * time.Second)

		compat_otp.By("Verify cluster's default network is advertised with remaining nodes")
		o.Eventually(func() bool {
			result := verifyRouteAdvertisement(oc, host, externalFRRIP2, externalFRRIP1, frrContainerID, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map)
			return result
		}, "60s", "15s").Should(o.BeTrue(), "BGP route advertisement of default network did not succeed!!")
		e2e.Logf("SUCCESS - BGP enabled, default network is advertised!!!")

		compat_otp.By("2. Create L3 CUDN, and L2 CUDN advertisement if gateway is in shared gateway mode")
		compat_otp.By("2.1 Create UDN namespace and L3 CUDN, label UDN namespace and L3 CUDN accordingly")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s-", matchLabelKey)).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[0])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		var cidr, ipv4cidr, ipv6cidr []string
		ipv4cidr = []string{"10.150.0.0/16", "20.150.0.0/16"}
		ipv6cidr = []string{"2010:100:200::/48", "2011:100:200::/48"}
		cidr = []string{"10.150.0.0/16", "20.150.0.0/16"}
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::/48", "2011:100:200::/48"}
		}

		compat_otp.By("2.2. Create L3 CUDN, and label the L3 CUDN to match networkSelector of RA")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[0])
		_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[0], cudnNames[0], ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		o.Expect(err).NotTo(o.HaveOccurred())

		//label userdefinednetwork with label app=udn
		setUDNLabel(oc, cudnNames[0], "app=udn")

		gwMode := getOVNGatewayMode(oc)
		var ns3 string
		if gwMode == "shared" {
			compat_otp.By("2.3. When cluster in SGW mode, create another UDN namespace for L2 CUDN, and label it with cudn selector")
			oc.CreateNamespaceUDN()
			ns3 = oc.Namespace()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns3, fmt.Sprintf("%s-", matchLabelKey)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns3, fmt.Sprintf("%s=%s", matchLabelKey, matchValues[1])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By("3.4 create L2 CUDN L2 in ns3, and label the L2 CUDN to match networkSelector of RA")
			defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnNames[1])
			_, err = applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchValues[1], cudnNames[1], ipv4cidr[1], ipv6cidr[1], cidr[1], "layer2")
			o.Expect(err).NotTo(o.HaveOccurred())

			// label CUDN L2 to match networkSelector of RA
			setUDNLabel(oc, cudnNames[1], "app=udn")
		}

		compat_otp.By("3. Apply a RA for CUDN with matching networkSelector")
		raname := "ra-cudn"
		params = []string{"-f", raCUDNTemplate, "-p", "NAME=" + raname, "NETWORKSELECTORKEY=" + networkselectorkey, "NETWORKSELECTORVALUE=" + networkselectorvalue, "ADVERTISETYPE=" + advertiseType}
		defer removeResource(oc, true, true, "ra", raname)
		compat_otp.ApplyNsResourceFromTemplate(oc, oc.Namespace(), params...)
		raErr = checkRAStatus(oc, raname, "Accepted")
		compat_otp.AssertWaitPollNoErr(raErr, "routeAdvertisement applied does not have the right condition status")
		e2e.Logf("SUCCESS - UDN routeAdvertisement applied is accepted")

		compat_otp.By("3.1  Verify L3 CUDN network is advertised with cluster's remaining nodes")
		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 := getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[0])
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
		e2e.Logf("SUCCESS - L3 UDN network %s for namespace %s advertised to external !!!", cudnNames[0], ns2)

		if gwMode == "shared" {
			compat_otp.By("3.2. verify CUDN L2 is advertised to external")
			o.Eventually(func() bool {
				result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "5s").Should(o.BeTrue(), "BGP UDN route advertisement did not succeed!!")
			e2e.Logf("SUCCESS - In SGW mode, L2 UDN network %s for namespace %s is advertised to external !!!", cudnNames[1], ns3)
		}

		compat_otp.By("4. Add the deleted node back, verify its PodNetworks of default network and UDN will be advertised as well in step 5")
		compat_otp.By("4.1 Add the deleted node back, wait till the node is in Ready state and its frr-k8s pod is ready")
		err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", nodeYAMLFile).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		checkNodeStatus(oc, nodeDeleteAddBack, "Ready")
		frrk8sPod, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", frrNamespace, "pod", "-l app=frr-k8s", "--field-selector", "spec.nodeName="+nodeDeleteAddBack, "-o=jsonpath={.items[0].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The frr-k8s pod on node %s is %s", nodeDeleteAddBack, frrk8sPod)
		o.Expect(frrk8sPod).NotTo(o.BeEmpty())
		waitPodReady(oc, frrNamespace, frrk8sPod)

		compat_otp.By("4.2 Add frr configuration for the new node into frr.conf of external frr")
		nodeIP2, nodeIP1 := getNodeIP(oc, nodeDeleteAddBack)

		vtyshCmds1 := []string{"configure terminal",
			"router bgp 64512",
			"neighbor " + nodeIP1 + " remote-as 64512",
			"neighbor " + nodeIP1 + " activate",
			"neighbor " + nodeIP1 + " next-hop-self",
			"neighbor " + nodeIP1 + " route-reflector-client",
			"end",
			"write"}

		var cmdString2, cmdString1 string
		for _, cmd1 := range vtyshCmds1 {
			cmdString1 = cmdString1 + " -c \"" + cmd1 + "\""
		}
		externalFrrCmd1 := "sudo podman exec -it " + frrContainerID + " vtysh " + cmdString1
		err = sshRunCmd(host, "root", externalFrrCmd1)
		o.Expect(err).NotTo(o.HaveOccurred())

		if nodeIP2 != "" {
			vtyshCmds2 := []string{"configure terminal",
				"router bgp 64512",
				"neighbor " + nodeIP2 + " remote-as 64512",
				"neighbor " + nodeIP2 + " activate",
				"neighbor " + nodeIP2 + " next-hop-self",
				"neighbor " + nodeIP2 + " route-reflector-client",
				"end",
				"write"}

			for _, cmd2 := range vtyshCmds2 {
				cmdString2 = cmdString2 + " -c \"" + cmd2 + "\""
			}

			externalFrrCmd2 := "sudo podman exec -it " + frrContainerID + " vtysh " + cmdString2
			err = sshRunCmd(host, "root", externalFrrCmd2)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		// reload the updated frr.conf into running-conf, verify new node is in running configuration
		vtyshReloadCmd := "sudo podman exec -it " + frrContainerID + " vtysh -b"
		err = sshRunCmd(host, "root", vtyshReloadCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err := sshRunCmdOutPut(host, "root", "sudo podman exec -it "+frrContainerID+" vtysh -c \" show running-conf \"")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, nodeIP1)).To(o.BeTrue())
		if ipStackType == "dualstack" {
			o.Expect(strings.Contains(output, nodeIP2)).To(o.BeTrue())
		}

		compat_otp.By("5. Verify newly added node joined advertised default network and UDN, route advertisement on existing nodes are unaffected")
		compat_otp.By("Get all nodes including the newly added node")
		allNodes, nodeErr = compat_otp.GetAllNodes(oc)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(len(allNodes)).NotTo(o.BeEquivalentTo(0))

		compat_otp.By("Get default and L3 CUDN podNetworks of new node")
		nodesIP2Map[nodeDeleteAddBack] = nodeIP2
		nodesIP1Map[nodeDeleteAddBack] = nodeIP1
		if ipStackType == "dualstack" {
			hostSubnetCIDRv4, hostSubnetCIDRv6 := getNodeSubnetDualStack(oc, nodeDeleteAddBack, "default")
			o.Expect(hostSubnetCIDRv4).NotTo(o.BeEmpty())
			o.Expect(hostSubnetCIDRv6).NotTo(o.BeEmpty())
			podNetwork1Map[nodeDeleteAddBack] = hostSubnetCIDRv4
			podNetwork2Map[nodeDeleteAddBack] = hostSubnetCIDRv6
			hostSubnetCIDRv4, hostSubnetCIDRv6 = getNodeSubnetDualStack(oc, nodeDeleteAddBack, "cluster_udn"+"_"+cudnNames[0])
			UDNnetwork_ipv4_ns1[nodeDeleteAddBack] = hostSubnetCIDRv4
			UDNnetwork_ipv6_ns1[nodeDeleteAddBack] = hostSubnetCIDRv6
		} else {
			hostSubnetCIDR := getNodeSubnet(oc, nodeDeleteAddBack, "default")
			o.Expect(hostSubnetCIDR).NotTo(o.BeEmpty())
			podNetwork1Map[nodeDeleteAddBack] = hostSubnetCIDR
			podNetwork2Map[nodeDeleteAddBack] = ""
			hostSubnetCIDR = getNodeSubnet(oc, nodeDeleteAddBack, "cluster_udn"+"_"+cudnNames[0])
			UDNnetwork_ipv4_ns1[nodeDeleteAddBack] = hostSubnetCIDR
			UDNnetwork_ipv6_ns1[nodeDeleteAddBack] = ""
		}
		e2e.Logf("nodesIP1Map: %v", nodesIP1Map)
		e2e.Logf("nodesIP2Map: %v", nodesIP2Map)
		e2e.Logf("podNetwork1Map: %v", podNetwork1Map)
		e2e.Logf("podNetwork2Map: %v", podNetwork2Map)
		e2e.Logf("UDNnetwork_ipv4_ns1: %v", UDNnetwork_ipv4_ns1)
		e2e.Logf("UDNnetwork_ipv6_ns1: %v", UDNnetwork_ipv6_ns1)

		// wait a little time for new node be advertised
		time.Sleep(60 * time.Second)

		compat_otp.By("5.1 Verify newly added node joined with other cluster nodes to advertise default network ")
		o.Eventually(func() bool {
			result := verifyRouteAdvertisement(oc, host, externalFRRIP2, externalFRRIP1, frrContainerID, allNodes, podNetwork1Map, podNetwork2Map, nodesIP1Map, nodesIP2Map)
			return result
		}, "90s", "15s").Should(o.BeTrue(), "BGP route advertisement of default network did not succeed!!")
		e2e.Logf("5.1 SUCCESS - default network advertisement for new node and other existing nodes!!!")

		compat_otp.By("5.2  Verify newly added node joined with other cluster nodes to advertise L3 CUDN network")
		UDNnetwork_ipv6_ns1, UDNnetwork_ipv4_ns1 = getHostPodNetwork(oc, allNodes, "cluster_udn"+"_"+cudnNames[0])
		o.Eventually(func() bool {
			result := verifyIPRoutesOnExternalFrr(host, allNodes, UDNnetwork_ipv4_ns1, UDNnetwork_ipv6_ns1, nodesIP1Map, nodesIP2Map, true)
			return result
		}, "60s", "10s").Should(o.BeTrue(), "BGP L3 UDN route advertisement did not succeed!!")
		e2e.Logf("5.2 SUCCESS - L3 UDN network advertisement for new node and other existing nodes !!!")

		if gwMode == "shared" {
			compat_otp.By("5.3. Verify newly added node joine with other clusters to advertise L2 CUDN network")
			o.Eventually(func() bool {
				result := verifyUDNL2RouteOnExternalFrr(host, allNodes, cidr[1], ipv6cidr[1], nodesIP1Map, nodesIP2Map, true)
				return result
			}, "60s", "5s").Should(o.BeTrue(), "BGP L2 UDN route advertisement did not succeed!!")
			e2e.Logf("5.3 SUCCESS - In SGW mode, L2 UDN network advertisement for new node and other existing nodes !!!")
		}
	})

})
