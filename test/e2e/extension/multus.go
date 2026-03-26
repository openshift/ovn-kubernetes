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
	"github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN multus", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-multus", compat_otp.KubeConfigPath())

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	// OCP-46387 failed in 4.14 due to https://issues.redhat.com/browse/OCPBUGS-11082 and https://issues.redhat.com/browse/NP-752
	// Enable this case until Dev fix the issue
	/*
		// author: weliang@redhat.com
		g.It("Author:weliang-Medium-46387-[BZ 1896533] network operator degraded due to additionalNetwork in non-existent namespace. [Disruptive]", func() {
			var (
				patchSResource = "networks.operator.openshift.io/cluster"
				patchInfo      = fmt.Sprintf("{\"spec\":{\"additionalNetworks\": [{\"name\": \"secondary\",\"namespace\":\"ocp-46387\",\"simpleMacvlanConfig\": {\"ipamConfig\": {\"staticIPAMConfig\": {\"addresses\": [{\"address\": \"10.1.1.0/24\"}] },\"type\": \"static\"}},\"type\": \"SimpleMacvlan\"}]}}")
			)

			g.By("create new namespace")
			namespace := fmt.Sprintf("ocp-46387")
			err := oc.Run("new-project").Args(namespace).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			defer oc.AsAdmin().Run("delete").Args("project", namespace, "--ignore-not-found").Execute()

			g.By("Configure network-attach-definition through network operator")
			patchResourceAsAdmin(oc, patchSResource, patchInfo)
			defer oc.AsAdmin().WithoutNamespace().Run("patch").Args(patchSResource, "-p", `[{"op": "remove", "path": "/spec/additionalNetworks"}]`, "--type=json").Execute()

			//Testing will exit when network operator is in abnormal state during 60 seconding of checking operator.
			g.By("Check NetworkOperatorStatus")
			checkNetworkOperatorState(oc, 10, 60)

			g.By("Delete the namespace")
			nsErr := oc.AsAdmin().Run("delete").Args("project", namespace, "--ignore-not-found").Execute()
			o.Expect(nsErr).NotTo(o.HaveOccurred())

			//Testing will exit when network operator is in abnormal state during 60 seconding of checking operator.
			g.By("Check NetworkOperatorStatus after deleting namespace")
			checkNetworkOperatorState(oc, 10, 60)
		})
	*/

	// author: weliang@redhat.com
	g.It("Author:weliang-High-57589-[NETWORKCUSIM] Whereabouts CNI timesout while iterating exclude range", func() {
		//https://issues.redhat.com/browse/OCPBUGS-2948 : Whereabouts CNI timesout while iterating exclude range

		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			netAttachDefFile1   = filepath.Join(buildPruningBaseDir, "multus/ipv6-excludes-largeranges-NAD.yaml")
			multusPodTemplate   = filepath.Join(buildPruningBaseDir, "multinetworkpolicy/MultiNetworkPolicy-pod-template.yaml")
		)

		ns1 := oc.Namespace()

		g.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Create a custom resource network-attach-defintion in tested namespace")
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", netAttachDefFile1, "-n", ns1).Execute()
			}
		}()
		netAttachDefErr := oc.AsAdmin().Run("create").Args("-f", netAttachDefFile1, "-n", ns1).Execute()
		o.Expect(netAttachDefErr).NotTo(o.HaveOccurred())
		netAttachDefOutput, netAttachDefOutputErr := oc.Run("get").Args("net-attach-def", "-n", ns1).Output()
		o.Expect(netAttachDefOutputErr).NotTo(o.HaveOccurred())
		o.Expect(netAttachDefOutput).To(o.ContainSubstring("nad-w-excludes"))

		g.By("Create a multus pod to use above network-attach-defintion")
		ns1MultusPod1 := testPodMultinetwork{
			name:      "ns1-multuspod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			nadname:   "nad-w-excludes",
			labelname: "blue-multuspod",
			template:  multusPodTemplate,
		}
		ns1MultusPod1.createTestPodMultinetwork(oc)
		waitPodReady(oc, ns1MultusPod1.namespace, ns1MultusPod1.name)

		g.By("check the created multus pod to get the right ipv6 CIDR")
		multusPodIPv6 := getPodMultiNetworkIPv6(oc, ns1, ns1MultusPod1.name)
		e2e.Logf("The v6 address of pod's second interface is: %v", multusPodIPv6)
		o.Expect(strings.HasPrefix(multusPodIPv6, "fd43:11f1:3daa:bbaa::")).Should(o.BeTrue())
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-NonHyperShiftHOST-High-59875-[NETWORKCUSIM] Configure ignored namespaces into multus-admission-controller", func() {
		//https://issues.redhat.com/browse/OCPBUGS-6499:Configure ignored namespaces into multus-admission-controller

		ns1 := "openshift-multus"
		expectedOutpu := "-ignore-namespaces"
		g.By("Check multus-admission-controller is configured with ignore-namespaces")
		multusOutput, multusErr := oc.AsAdmin().Run("get").Args("deployment.apps/multus-admission-controller", "-n", ns1, "-o=jsonpath={.spec.template.spec.containers[0].command[2]}").Output()
		compat_otp.AssertWaitPollNoErr(multusErr, "The deployment.apps/multus-admission-controller is not created")
		o.Expect(multusOutput).To(o.ContainSubstring(expectedOutpu))

		g.By("Check all multus-additional-cni-plugins pods are Running well")
		o.Expect(waitForPodWithLabelReady(oc, ns1, "app=multus-additional-cni-plugins")).NotTo(o.HaveOccurred())
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-Medium-59440-Verify whereabouts-reconciler after creating additionalNetworks. [Disruptive]", func() {
		var (
			patchSResource = "networks.operator.openshift.io/cluster"
			patchInfo      = fmt.Sprintf(`{"spec":{ "additionalNetworks": [{"name": "whereabouts-shim", "namespace": "default","rawCNIConfig":"{\"cniVersion\":\"0.3.0\",\"type\":\"bridge\",\"name\":\"cnitest0\",\"ipam\": {\"type\":\"whereabouts\",\"subnet\":\"192.0.2.0/24\"}}","type":"Raw"}]}}`)
			ns             = "openshift-multus"
		)

		g.By("Check there are no whereabouts-reconciler pods and ds in the openshift-multus namespace before creating additionalNetworks ")
		podStatus, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", "app=whereabouts-reconciler", "-ojsonpath={.items[*].status.conditions[?(@.type==\"Ready\")].status}").Output()
		_, dsErrBefore := oc.AsAdmin().Run("get").Args("daemonset.apps/whereabouts-reconciler", "-n", ns).Output()
		if podStatus != "" || dsErrBefore == nil {
			g.Skip("whereabouts-reconciler pods or daemonset already exist in openshift-multus namespace, skipping test")
		}

		g.By("Check NetworkOperatorStatus is healthy before proceeding")
		networkOperatorOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "network").Output()
		if err != nil {
			g.Skip("Failed to get network operator status, skipping test")
		}
		matched, _ := regexp.MatchString("True.*False.*False", networkOperatorOutput)
		if !matched {
			g.Skip("NetworkOperatorStatus is not healthy, skipping test")
		}

		g.By("Add additionalNetworks through network operator")
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("patch").Args(patchSResource, "-p", `[{"op": "remove", "path": "/spec/additionalNetworks"}]`, "--type=json").Execute()
			g.By("Check NetworkOperatorStatus to ensure the cluster is health after modification")
			checkNetworkOperatorState(oc, 10, 60)
		}()
		patchResourceAsAdmin(oc, patchSResource, patchInfo)

		g.By("Check whereabouts-reconciler pods and ds are created in the openshift-multus namespace after creating additionalNetworks ")
		o.Expect(waitForPodWithLabelReady(oc, ns, "app=whereabouts-reconciler")).NotTo(o.HaveOccurred())
		dsOutput, dsErrAfter := oc.AsAdmin().Run("get").Args("daemonset.apps/whereabouts-reconciler", "-n", ns).Output()
		o.Expect(dsErrAfter).NotTo(o.HaveOccurred())
		o.Expect(dsOutput).To(o.ContainSubstring("whereabouts-reconciler"))

		g.By("Check there are no whereabouts-reconciler pods and ds in the openshift-multus namespace after deleting additionalNetworks ")
		oc.AsAdmin().WithoutNamespace().Run("patch").Args(patchSResource, "-p", `[{"op": "remove", "path": "/spec/additionalNetworks"}]`, "--type=json").Execute()
		o.Eventually(func() bool {
			result := true
			_, err := oc.AsAdmin().Run("get").Args("pod", "-n", ns, "-l", "app=whereabouts-reconciler").Output()
			if err != nil {
				e2e.Logf("Wait for whereabouts-reconciler pods to be deleted")
				result = false
			}
			return result
		}, "60s", "5s").Should(o.BeTrue(), fmt.Sprintf("whereabouts-reconciler pods are not deleted"))
		o.Eventually(func() bool {
			result := true
			_, err := oc.AsAdmin().Run("get").Args("daemonset.apps/whereabouts-reconciler", "-n", ns).Output()
			if err != nil {
				e2e.Logf("Wait for daemonset.apps/whereabouts-reconciler to be deleted")
				result = false
			}
			return result
		}, "60s", "5s").Should(o.BeTrue(), fmt.Sprintf("daemonset.apps/whereabouts-reconciler is not deleted"))
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-Medium-64958-[NETWORKCUSIM] Unable to set default-route when istio sidecar is injected. [Serial]", func() {
		//https://issues.redhat.com/browse/OCPBUGS-7844
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			netAttachDefFile    = filepath.Join(buildPruningBaseDir, "multus/istiosidecar-NAD.yaml")
			testPod             = filepath.Join(buildPruningBaseDir, "multus/istiosidecar-pod.yaml")
		)

		compat_otp.By("Create a new namespace")
		ns1 := "test-64958"
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.DeleteSpecifiedNamespaceAsAdmin(ns1)
			}
		}()
		oc.CreateSpecifiedNamespaceAsAdmin(ns1)

		compat_otp.By("Create a custom resource network-attach-defintion in the namespace")
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", netAttachDefFile, "-n", ns1).Execute()
			}
		}()
		netAttachDefErr := oc.AsAdmin().Run("create").Args("-f", netAttachDefFile, "-n", ns1).Execute()
		o.Expect(netAttachDefErr).NotTo(o.HaveOccurred())
		netAttachDefOutput, netAttachDefOutputErr := oc.AsAdmin().Run("get").Args("net-attach-def", "-n", ns1).Output()
		o.Expect(netAttachDefOutputErr).NotTo(o.HaveOccurred())
		o.Expect(netAttachDefOutput).To(o.ContainSubstring("test-nad"))

		compat_otp.By("Create a pod consuming above network-attach-defintion in ns1")
		createResourceFromFile(oc, ns1, testPod)
		o.Expect(waitForPodWithLabelReady(oc, ns1, "name=testpod")).NotTo(o.HaveOccurred(), "The test pod in ns/%s is not ready", ns1)

		compat_otp.By("Check the default-route is created when istio sidecar is injected")
		routeLog, routeErr := execCommandInSpecificPod(oc, ns1, "testpod", "ip route")
		o.Expect(routeErr).NotTo(o.HaveOccurred())
		o.Expect(routeLog).To(o.ContainSubstring("default via 172.19.55.99 dev net1"))
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-Medium-66876-Support Dual Stack IP assignment for whereabouts CNI/IPAM", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			dualstackNADTemplate   = filepath.Join(buildPruningBaseDir, "multus/dualstack-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming/multihoming-pod-template.yaml")
			nadName                = "dualstack"
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has fewer than two nodes")
		}

		compat_otp.By("Get the name of namespace")
		ns1 := oc.Namespace()

		compat_otp.By("Create a custom resource network-attach-defintion in the test namespace")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nadName, "-n", ns1).Execute()
		nad1ns1 := dualstackNAD{
			nadname:        nadName,
			namespace:      ns1,
			plugintype:     "macvlan",
			mode:           "bridge",
			ipamtype:       "whereabouts",
			ipv4range:      "192.168.10.0/24",
			ipv6range:      "fd00:dead:beef:10::/64",
			ipv4rangestart: "",
			ipv4rangeend:   "",
			ipv6rangestart: "",
			ipv6rangeend:   "",
			template:       dualstackNADTemplate,
		}
		nad1ns1.createDualstackNAD(oc)

		compat_otp.By("Check if the network-attach-defintion is created")
		if checkNAD(oc, ns1, nadName) {
			e2e.Logf("The correct network-attach-defintion: %v is created!", nadName)
		} else {
			e2e.Failf("The correct network-attach-defintion: %v is not created!", nadName)
		}

		compat_otp.By("Create 1st pod consuming above network-attach-defintion in ns1")
		pod1 := testMultihomingPod{
			name:       "dualstack-pod-1",
			namespace:  ns1,
			podlabel:   "dualstack-pod1",
			nadname:    nadName,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		pod1.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns1, "name=dualstack-pod1")).NotTo(o.HaveOccurred())

		compat_otp.By("Create 2nd pod consuming above network-attach-defintion in ns1")
		pod2 := testMultihomingPod{
			name:       "dualstack-pod-2",
			namespace:  ns1,
			podlabel:   "dualstack-pod2",
			nadname:    nadName,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		pod2.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns1, "name=dualstack-pod2")).NotTo(o.HaveOccurred())

		compat_otp.By("Get two pods' name")
		podList, podListErr := compat_otp.GetAllPods(oc, ns1)
		o.Expect(podListErr).NotTo(o.HaveOccurred())
		o.Expect(len(podList)).Should(o.Equal(2))

		compat_otp.By("Get IPs of the pod1ns1's secondary interface in first namespace.")
		pod1ns1IPv4, pod1ns1IPv6 := getPodMultiNetwork(ns1, podList[0])
		e2e.Logf("The v4 address of pod1ns1is: %v", pod1ns1IPv4)
		e2e.Logf("The v6 address of pod1ns1is: %v", pod1ns1IPv6)

		compat_otp.By("Get IPs of the pod2ns1's secondary interface in first namespace.")
		pod2ns1IPv4, pod2ns1IPv6 := getPodMultiNetwork(ns1, podList[1])
		e2e.Logf("The v4 address of pod2ns1is: %v", pod2ns1IPv4)
		e2e.Logf("The v6 address of pod2ns1is: %v", pod2ns1IPv6)

		g.By("Both ipv4 and ipv6 curl should pass between two pods")
		curlPod2PodMultiNetworkPass(ns1, podList[0], pod2ns1IPv4, pod2ns1IPv6)
		curlPod2PodMultiNetworkPass(ns1, podList[1], pod1ns1IPv4, pod1ns1IPv6)
	})
	g.It("Author:weliang-Medium-69947-The macvlan pod will send Unsolicited Neighbor Advertisements after it is created", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			dualstackNADTemplate   = filepath.Join(buildPruningBaseDir, "multus/dualstack-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming/multihoming-pod-template.yaml")
			nadName                = "whereabouts-dualstack"
			sniffMultusPodTemplate = filepath.Join(buildPruningBaseDir, "multus/sniff-multus-pod-template.yaml")
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("This case requires at least one worker node")
		}

		compat_otp.By("Get the name of namespace")
		ns := oc.Namespace()
		defer compat_otp.RecoverNamespaceRestricted(oc, ns)
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("Create a custom resource network-attach-defintion")
		defer removeResource(oc, true, true, "net-attach-def", nadName, "-n", ns)
		nadns := dualstackNAD{
			nadname:        nadName,
			namespace:      ns,
			plugintype:     "macvlan",
			mode:           "bridge",
			ipamtype:       "whereabouts",
			ipv4range:      "192.168.10.0/24",
			ipv6range:      "fd00:dead:beef:10::/64",
			ipv4rangestart: "",
			ipv4rangeend:   "",
			ipv6rangestart: "",
			ipv6rangeend:   "",
			template:       dualstackNADTemplate,
		}
		nadns.createDualstackNAD(oc)

		compat_otp.By("Check if the network-attach-defintion is created")
		if checkNAD(oc, ns, nadName) {
			e2e.Logf("The correct network-attach-defintion: %v is created!", nadName)
		} else {
			e2e.Failf("The correct network-attach-defintion: %v is not created!", nadName)
		}

		compat_otp.By("Create a sniff pod to capture the traffic from pod's secondary network")
		pod1 := testPodMultinetwork{
			name:      "sniff-pod",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			nadname:   nadName,
			labelname: "sniff-pod",
			template:  sniffMultusPodTemplate,
		}
		pod1.createTestPodMultinetwork(oc)
		compat_otp.AssertWaitPollNoErr(waitForPodWithLabelReady(oc, ns, "name="+pod1.labelname), fmt.Sprintf("Waiting for pod with label name=%s become ready timeout", pod1.labelname))

		compat_otp.By("The sniff pod start to capture the Unsolicited Neighbor Advertisements from pod's secondary network")
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", ns, pod1.labelname, "bash", "-c",
			`timeout --preserve-status 30 tcpdump -e -i net1 icmp6 and icmp6[0] = 136 -nvvv`).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create a pod consuming above network-attach-defintion")
		pod2 := testMultihomingPod{
			name:       "dualstack-pod",
			namespace:  ns,
			podlabel:   "dualstack-pod",
			nadname:    nadName,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		pod2.createTestMultihomingPod(oc)
		compat_otp.AssertWaitPollNoErr(waitForPodWithLabelReady(oc, ns, "name="+pod2.podlabel), fmt.Sprintf("Waiting for pod with label name=%s become ready timeout", pod2.podlabel))

		compat_otp.By("The sniff pod will get Unsolicited Neighbor Advertisements, not neighbor solicitation")
		cmdErr := cmdTcpdump.Wait()
		o.Expect(cmdErr).NotTo(o.HaveOccurred())

		// Check for Unsolicited NA: type 136 and only [override] flag (no [solicited])
		rawOutput := cmdOutput.String()
		fmt.Println("rawOutput:\n", rawOutput)
		o.Expect(rawOutput).To(o.MatchRegexp(
			`neighbor advertisement.*Flags \[override\]`),
			"No unsolicited NA found. Full output:\n%s", rawOutput)
	})

	g.It("Author:weliang-Medium-72202-[Multus] NAD without configuring network_name. [Disruptive]", func() {
		var (
			buildPruningBaseDir                 = testdata.FixturePath("networking")
			nad1Name                            = "ip-overlapping-1"
			nad2Name                            = "ip-overlapping-2"
			pod1Name                            = "ip-overlapping-pod1"
			pod2Name                            = "ip-overlapping-pod2"
			ipv4range1                          = "192.168.20.0/29"
			ipv4range2                          = "192.168.20.0/24"
			interfaceName                       = "net1"
			whereaboutsoverlappingIPNADTemplate = filepath.Join(buildPruningBaseDir, "multus/whereabouts-overlappingIP-NAD-template.yaml")
			multihomingPodTemplate              = filepath.Join(buildPruningBaseDir, "multihoming/multihoming-pod-template.yaml")
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("This case requires at least one worker node")
		}

		compat_otp.By("Get the name of namespace")
		ns := oc.Namespace()
		defer compat_otp.RecoverNamespaceRestricted(oc, ns)
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("Configuring first NetworkAttachmentDefinition")
		defer removeResource(oc, true, true, "net-attach-def", nad1Name, "-n", ns)

		nad1 := whereaboutsoverlappingIPNAD{
			nadname:           nad1Name,
			namespace:         ns,
			plugintype:        "macvlan",
			mode:              "bridge",
			ipamtype:          "whereabouts",
			ipv4range:         ipv4range1,
			enableoverlapping: true,
			networkname:       "",
			template:          whereaboutsoverlappingIPNADTemplate,
		}
		nad1.createWhereaboutsoverlappingIPNAD(oc)

		compat_otp.By("Verifying the configued NetworkAttachmentDefinition")
		if checkNAD(oc, ns, nad1Name) {
			e2e.Logf("The correct network-attach-defintion: %v is created!", nad1Name)
		} else {
			e2e.Failf("The correct network-attach-defintion: %v is not created!", nad1Name)
		}

		compat_otp.By("Configuring pods to get additional network defined in first NAD")
		nad1pod := testMultihomingPod{
			name:       pod1Name,
			namespace:  ns,
			podlabel:   pod1Name,
			nadname:    nad1Name,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		nad1pod.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+nad1pod.podlabel)).NotTo(o.HaveOccurred())

		compat_otp.By("Configuring second NetworkAttachmentDefinition with setting true for enable_overlapping_ranges")
		defer removeResource(oc, true, true, "net-attach-def", nad2Name, "-n", ns)
		nad2 := whereaboutsoverlappingIPNAD{
			nadname:           nad2Name,
			namespace:         ns,
			plugintype:        "macvlan",
			mode:              "bridge",
			ipamtype:          "whereabouts",
			ipv4range:         ipv4range2,
			enableoverlapping: true,
			networkname:       "",
			template:          whereaboutsoverlappingIPNADTemplate,
		}
		nad2.createWhereaboutsoverlappingIPNAD(oc)

		compat_otp.By("Verifying the second NetworkAttachmentDefinition")
		if checkNAD(oc, ns, nad2Name) {
			e2e.Logf("The correct network-attach-defintion: %v is created!", nad2Name)
		} else {
			e2e.Failf("The correct network-attach-defintion: %v is not created!", nad2Name)
		}

		compat_otp.By("Configuring pods for additional network defined in second NAD")
		nad2pod := testMultihomingPod{
			name:       pod2Name,
			namespace:  ns,
			podlabel:   pod2Name,
			nadname:    nad2Name,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		nad2pod.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+nad2pod.podlabel)).NotTo(o.HaveOccurred())

		ippool1 := "192.168.20.0-29"
		ippool2 := "192.168.20.0-24"
		ipaddress1 := "192.168.20.1"
		ipaddress2 := "192.168.20.2"

		compat_otp.By("Verifing the correct network_names from ippools")
		ippoolsOutput, ippoolsOutputErr := oc.AsAdmin().Run("get").Args("ippools", "-n", "openshift-multus").Output()
		o.Expect(ippoolsOutputErr).NotTo(o.HaveOccurred())
		o.Expect(ippoolsOutput).To(o.And(o.ContainSubstring(ippool1), o.ContainSubstring(ippool2)))

		compat_otp.By("Verifing there are no ip overlapping IP addresses from overlappingrangeipreservations")
		overlappingrangeOutput, overlappingrangeOutputErr := oc.AsAdmin().Run("get").Args("overlappingrangeipreservations", "-A", "-n", "openshift-multus").Output()
		o.Expect(overlappingrangeOutputErr).NotTo(o.HaveOccurred())
		o.Expect(overlappingrangeOutput).To(o.And(o.ContainSubstring(ipaddress1), o.ContainSubstring(ipaddress2)))

		compat_otp.By("Getting IP from pod1's secondary interface")
		pod1List, getPod1Err := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+nad1pod.podlabel)
		o.Expect(getPod1Err).NotTo(o.HaveOccurred())
		o.Expect(len(pod1List)).NotTo(o.BeEquivalentTo(0))
		pod1Net1IPv4, _ := getPodMultiNetworks(oc, ns, pod1List[0], interfaceName)
		e2e.Logf("The v4 address of pod1's net1 is: %v", pod1Net1IPv4)
		o.Expect(strings.HasPrefix(pod1Net1IPv4, ipaddress1)).Should(o.BeTrue())

		compat_otp.By("Getting IP from pod2's secondary interface")
		pod2List, getPod2Err := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+nad2pod.podlabel)
		o.Expect(getPod2Err).NotTo(o.HaveOccurred())
		o.Expect(len(pod2List)).NotTo(o.BeEquivalentTo(0))
		pod2Net1IPv4, _ := getPodMultiNetworks(oc, ns, pod2List[0], interfaceName)
		e2e.Logf("The v4 address of pod2's net1 is: %v", pod2Net1IPv4)
		o.Expect(strings.HasPrefix(pod2Net1IPv4, ipaddress2)).Should(o.BeTrue())

		compat_otp.By("Deleting the second NetworkAttachmentDefinition and responding pods")
		removeResource(oc, true, true, "net-attach-def", nad2Name, "-n", ns)
		removeResource(oc, true, true, "pod", pod2List[0], "-n", ns)

		compat_otp.By("Deleting the secondary network_name from ippools")
		removeResource(oc, true, true, "ippools", ippool2, "-n", "openshift-multus")

		compat_otp.By("Reconfiguring second NetworkAttachmentDefinition with setting false for enable_overlapping_ranges")
		defer removeResource(oc, true, true, "net-attach-def", nad2Name, "-n", ns)
		nad2.enableoverlapping = false
		nad2.createWhereaboutsoverlappingIPNAD(oc)

		compat_otp.By("Reconfiguring pods for additional network defined in second NAD")
		nad2pod.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+nad2pod.podlabel)).NotTo(o.HaveOccurred())

		compat_otp.By("Verifing these is only one IP in overlappingrangeipreservations")
		overlappingrangeOutput1, overlappingrangeOutputErr1 := oc.AsAdmin().Run("get").Args("overlappingrangeipreservations", "-A", "-n", "openshift-multus").Output()
		o.Expect(overlappingrangeOutputErr1).NotTo(o.HaveOccurred())
		o.Expect(overlappingrangeOutput1).To(o.ContainSubstring(ipaddress1))
		o.Expect(overlappingrangeOutput1).NotTo(o.ContainSubstring(ipaddress2))

		compat_otp.By("Getting IP from pod2's secondary interface")
		podList2, getPod2Err2 := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+nad2pod.podlabel)
		o.Expect(getPod2Err2).NotTo(o.HaveOccurred())
		o.Expect(len(podList2)).NotTo(o.BeEquivalentTo(0))
		pod3Net1IPv4, _ := getPodMultiNetworks(oc, ns, podList2[0], interfaceName)
		e2e.Logf("The v4 address of pod2's net1 is: %v", pod3Net1IPv4)
		o.Expect(strings.HasPrefix(pod3Net1IPv4, ipaddress1)).Should(o.BeTrue())
	})

	g.It("Author:weliang-Medium-72203-[Multus] NAD using same network_name. [Disruptive]", func() {
		var (
			buildPruningBaseDir                 = testdata.FixturePath("networking")
			nad1Name                            = "ip-overlapping-1"
			nad2Name                            = "ip-overlapping-2"
			pod1Name                            = "ip-overlapping-pod1"
			pod2Name                            = "ip-overlapping-pod2"
			ipv4range1                          = "192.168.20.0/29"
			ipv4range2                          = "192.168.20.0/24"
			interfaceName                       = "net1"
			networkName                         = "blue-net"
			whereaboutsoverlappingIPNADTemplate = filepath.Join(buildPruningBaseDir, "multus/whereabouts-overlappingIP-NAD-template.yaml")
			multihomingPodTemplate              = filepath.Join(buildPruningBaseDir, "multihoming/multihoming-pod-template.yaml")
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("This case requires at least one worker node")
		}

		compat_otp.By("Get the name of namespace")
		ns := oc.Namespace()
		defer compat_otp.RecoverNamespaceRestricted(oc, ns)
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("Configuring first NetworkAttachmentDefinition")
		defer removeResource(oc, true, true, "net-attach-def", nad1Name, "-n", ns)

		nad1 := whereaboutsoverlappingIPNAD{
			nadname:           nad1Name,
			namespace:         ns,
			plugintype:        "macvlan",
			mode:              "bridge",
			ipamtype:          "whereabouts",
			ipv4range:         ipv4range1,
			enableoverlapping: true,
			networkname:       networkName,
			template:          whereaboutsoverlappingIPNADTemplate,
		}
		nad1.createWhereaboutsoverlappingIPNAD(oc)

		compat_otp.By("Verifying the configued NetworkAttachmentDefinition")
		if checkNAD(oc, ns, nad1Name) {
			e2e.Logf("The correct network-attach-defintion: %v is created!", nad1Name)
		} else {
			e2e.Failf("The correct network-attach-defintion: %v is not created!", nad1Name)
		}

		compat_otp.By("Configuring pods to get additional network defined in first NAD")
		nad1pod := testMultihomingPod{
			name:       pod1Name,
			namespace:  ns,
			podlabel:   pod1Name,
			nadname:    nad1Name,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		nad1pod.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+nad1pod.podlabel)).NotTo(o.HaveOccurred())

		compat_otp.By("Configuring second NetworkAttachmentDefinition with setting true for enable_overlapping_ranges")
		defer removeResource(oc, true, true, "net-attach-def", nad2Name, "-n", ns)
		nad2 := whereaboutsoverlappingIPNAD{
			nadname:           nad2Name,
			namespace:         ns,
			plugintype:        "macvlan",
			mode:              "bridge",
			ipamtype:          "whereabouts",
			ipv4range:         ipv4range2,
			enableoverlapping: true,
			networkname:       networkName,
			template:          whereaboutsoverlappingIPNADTemplate,
		}
		nad2.createWhereaboutsoverlappingIPNAD(oc)

		compat_otp.By("Verifying the second NetworkAttachmentDefinition")
		if checkNAD(oc, ns, nad2Name) {
			e2e.Logf("The correct network-attach-defintion: %v is created!", nad2Name)
		} else {
			e2e.Failf("The correct network-attach-defintion: %v is not created!", nad2Name)
		}

		compat_otp.By("Configuring pods for additional network defined in second NAD")
		nad2pod := testMultihomingPod{
			name:       pod2Name,
			namespace:  ns,
			podlabel:   pod2Name,
			nadname:    nad2Name,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		nad2pod.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+nad2pod.podlabel)).NotTo(o.HaveOccurred())

		ippool1 := "192.168.20.0-29"
		ippool2 := "192.168.20.0-24"
		ipaddress1 := "192.168.20.1"
		ipaddress2 := "192.168.20.2"

		compat_otp.By("Verifing the correct network_names from ippools")
		ippoolsOutput, ippoolsOutputErr := oc.AsAdmin().Run("get").Args("ippools", "-n", "openshift-multus").Output()
		o.Expect(ippoolsOutputErr).NotTo(o.HaveOccurred())
		o.Expect(ippoolsOutput).To(o.And(o.ContainSubstring(ippool1), o.ContainSubstring(ippool2)))

		compat_otp.By("Verifing there are no ip overlapping IP addresses from overlappingrangeipreservations")
		overlappingrangeOutput, overlappingrangeOutputErr := oc.AsAdmin().Run("get").Args("overlappingrangeipreservations", "-A", "-n", "openshift-multus").Output()
		o.Expect(overlappingrangeOutputErr).NotTo(o.HaveOccurred())
		o.Expect(overlappingrangeOutput).To(o.And(o.ContainSubstring(ipaddress1), o.ContainSubstring(ipaddress2)))

		compat_otp.By("Getting IP from pod1's secondary interface")
		pod1List, getPod1Err := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+nad1pod.podlabel)
		o.Expect(getPod1Err).NotTo(o.HaveOccurred())
		o.Expect(len(pod1List)).NotTo(o.BeEquivalentTo(0))
		pod1Net1IPv4, _ := getPodMultiNetworks(oc, ns, pod1List[0], interfaceName)
		e2e.Logf("The v4 address of pod1's net1 is: %v", pod1Net1IPv4)
		o.Expect(strings.HasPrefix(pod1Net1IPv4, ipaddress1)).Should(o.BeTrue())

		compat_otp.By("Getting IP from pod2's secondary interface")
		pod2List, getPod2Err := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+nad2pod.podlabel)
		o.Expect(getPod2Err).NotTo(o.HaveOccurred())
		o.Expect(len(pod2List)).NotTo(o.BeEquivalentTo(0))
		pod2Net1IPv4, _ := getPodMultiNetworks(oc, ns, pod2List[0], interfaceName)
		e2e.Logf("The v4 address of pod2's net1 is: %v", pod2Net1IPv4)
		o.Expect(strings.HasPrefix(pod2Net1IPv4, ipaddress2)).Should(o.BeTrue())

		compat_otp.By("Deleting the second NetworkAttachmentDefinition and corresponding pods")
		removeResource(oc, true, true, "net-attach-def", nad2Name, "-n", ns)
		removeResource(oc, true, true, "pod", pod2List[0], "-n", ns)

		compat_otp.By("Deleting the secondary network_name from ippools")
		removeResource(oc, true, true, "ippools", ippool2, "-n", "openshift-multus")

		compat_otp.By("Reconfiguring second NetworkAttachmentDefinition with setting false for enable_overlapping_ranges")
		defer removeResource(oc, true, true, "net-attach-def", nad2Name, "-n", ns)
		nad2.enableoverlapping = false
		nad2.createWhereaboutsoverlappingIPNAD(oc)

		compat_otp.By("Reconfiguring pods for additional network defined in second NAD")
		nad2pod.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+nad2pod.podlabel)).NotTo(o.HaveOccurred())

		compat_otp.By("Verifing these is only one IP in overlappingrangeipreservations")
		overlappingrangeOutput1, overlappingrangeOutputErr1 := oc.AsAdmin().Run("get").Args("overlappingrangeipreservations", "-A", "-n", "openshift-multus").Output()
		o.Expect(overlappingrangeOutputErr1).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(overlappingrangeOutput1, ipaddress1)).To(o.BeTrue())
		o.Expect(strings.Contains(overlappingrangeOutput1, ipaddress2)).To(o.BeFalse())

		compat_otp.By("Getting IP from pod2's secondary interface")
		podList2, getPod2Err2 := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+nad2pod.podlabel)
		o.Expect(getPod2Err2).NotTo(o.HaveOccurred())
		o.Expect(len(podList2)).NotTo(o.BeEquivalentTo(0))
		pod3Net1IPv4, _ := getPodMultiNetworks(oc, ns, podList2[0], interfaceName)
		e2e.Logf("The v4 address of pod2's net1 is: %v", pod3Net1IPv4)
		o.Expect(strings.HasPrefix(pod3Net1IPv4, ipaddress1)).Should(o.BeTrue())
	})

	g.It("Author:weliang-NonPreRelease-Longduration-Medium-74933-[NETWORKCUSIM] whereabouts ips are not reconciled when the node is rebooted forcely. [Disruptive]", func() {
		//https://issues.redhat.com/browse/OCPBUGS-35923: whereabouts ips are not reconciled when the node is rebooted forcely
		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			dualstackNADTemplate = filepath.Join(buildPruningBaseDir, "multus/dualstack-NAD-template.yaml")
			multusPodTemplate    = filepath.Join(buildPruningBaseDir, "multus/multus-Statefulset-pod-template.yaml")
			nad1Name             = "ip-overlapping-1"
			pod1Name             = "ip-overlapping-pod1"
		)

		compat_otp.By("Getting the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("This case requires at least one worker node")
		}

		compat_otp.By("Getting the name of namespace")
		ns := oc.Namespace()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				compat_otp.RecoverNamespaceRestricted(oc, ns)
			}
		}()
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("Deleting the network_names/ippools/overlapping created from this testing")
		ippool1 := "192.168.20.0-24"
		ippool2 := "fd00-dead-beef-10---64"
		overlapping1 := "192.168.20.1"
		overlapping2 := "fd00-dead-beef-10--1"
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "overlappingrangeipreservations.whereabouts.cni.cncf.io", overlapping1, "-n", "openshift-multus")
			}
		}()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "overlappingrangeipreservations.whereabouts.cni.cncf.io", overlapping2, "-n", "openshift-multus")
			}
		}()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "ippools.whereabouts.cni.cncf.io", ippool1, "-n", "openshift-multus")
			}
		}()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "ippools.whereabouts.cni.cncf.io", ippool2, "-n", "openshift-multus")
			}
		}()

		compat_otp.By("Creating a network-attach-defintion")
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", nad1Name, "-n", ns).Execute()
			}
		}()
		nadns := dualstackNAD{
			nadname:        nad1Name,
			namespace:      ns,
			plugintype:     "macvlan",
			mode:           "bridge",
			ipamtype:       "whereabouts",
			ipv4range:      "192.168.20.0/24",
			ipv6range:      "fd00:dead:beef:10::/64",
			ipv4rangestart: "",
			ipv4rangeend:   "",
			ipv6rangestart: "",
			ipv6rangeend:   "",
			template:       dualstackNADTemplate,
		}
		nadns.createDualstackNAD(oc)

		compat_otp.By("Verifying the configued NetworkAttachmentDefinition")
		if checkNAD(oc, ns, nad1Name) {
			e2e.Logf("The correct network-attach-defintion: %v is created!", nad1Name)
		} else {
			e2e.Failf("The correct network-attach-defintion: %v is not created!", nad1Name)
		}

		compat_otp.By("Configuring a pod to get additional network")
		replicasnum := strconv.Itoa(1)
		nad1pod := testMultusPod{
			name:       pod1Name,
			namespace:  ns,
			podlabel:   pod1Name,
			nadname:    nad1Name,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			replicas:   replicasnum,
			template:   multusPodTemplate,
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "pod", nad1pod.name, "-n", ns)
			}
		}()
		nad1pod.createTestMultusPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+nad1pod.podlabel)).NotTo(o.HaveOccurred())

		ipaddress1 := "192.168.20.1"
		ipaddress2 := "fd00:dead:beef:10::1"
		interfaceName := "net1"

		compat_otp.By("Getting IP from pod's secondary interface")
		pod1List, getPod1Err := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+nad1pod.podlabel)
		o.Expect(getPod1Err).NotTo(o.HaveOccurred())
		o.Expect(len(pod1List)).NotTo(o.BeEquivalentTo(0))
		pod1Net1IPv4, pod1Net1IPv6 := getPodMultiNetworks(oc, ns, pod1List[0], interfaceName)
		e2e.Logf("The v4 address of pod1's net1 is: %v", pod1Net1IPv4)
		e2e.Logf("The v6 address of pod1's net1 is: %v", pod1Net1IPv6)
		o.Expect(strings.HasPrefix(pod1Net1IPv4, ipaddress1)).Should(o.BeTrue())
		o.Expect(strings.HasPrefix(pod1Net1IPv6, ipaddress2)).Should(o.BeTrue())

		compat_otp.By("Rebooting the node where the statefulset pod is deployed")
		clusterOperators := []string{"dns", "ingress", "storage"}
		for _, operator := range clusterOperators {
			defer waitForClusterOperatorState(oc, operator, 100, 3, "True.*False.*False")
		}
		defer waitForNetworkOperatorState(oc, 100, 3, "True.*False.*False")
		defer checkNodeStatus(oc, nodeList.Items[0].Name, "Ready")
		forceRebootNode(oc, nodeList.Items[0].Name)

		compat_otp.By("Waiting for the StatefulSet pod to be deployed again")
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+nad1pod.podlabel)).NotTo(o.HaveOccurred())

		compat_otp.By("Getting IP from redployed pod's secondary interface, and both ipv4 and ipv6 are same as the ones pod get before.")
		pod2List, getPod2Err := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+nad1pod.podlabel)
		o.Expect(getPod2Err).NotTo(o.HaveOccurred())
		o.Expect(len(pod2List)).NotTo(o.BeEquivalentTo(0))
		pod2Net1IPv4, pod2Net1IPv6 := getPodMultiNetworks(oc, ns, pod2List[0], interfaceName)
		e2e.Logf("The v4 address of pod2's net1 is: %v", pod2Net1IPv4)
		e2e.Logf("The v4 address of pod2's net1 is: %v", pod2Net1IPv6)
		o.Expect(strings.HasPrefix(pod2Net1IPv4, ipaddress1)).Should(o.BeTrue())
		o.Expect(strings.HasPrefix(pod2Net1IPv6, ipaddress2)).Should(o.BeTrue())
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-Medium-76652-Support for Dummy CNI", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			netAttachDefFile       = filepath.Join(buildPruningBaseDir, "multus/support-dummy-CNI-NAD.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming/multihoming-pod-template.yaml")
		)

		compat_otp.By("Getting the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready node for the testing")
		}

		compat_otp.By("Getting the name of namespace")
		ns := oc.Namespace()

		nadNames := []string{"dummy-net", "mynet-a", "mynet-b"}
		compat_otp.By("Create three network-attach-defintions in the test namespace")
		defer removeResource(oc, true, true, "net-attach-def", nadNames[0], "-n", ns)
		defer removeResource(oc, true, true, "net-attach-def", nadNames[1], "-n", ns)
		defer removeResource(oc, true, true, "net-attach-def", nadNames[2], "-n", ns)
		netAttachDefErr := oc.AsAdmin().Run("create").Args("-f", netAttachDefFile, "-n", ns).Execute()
		o.Expect(netAttachDefErr).NotTo(o.HaveOccurred())

		compat_otp.By("Checking if three network-attach-defintions are created")
		for _, nadName := range nadNames {
			if checkNAD(oc, ns, nadName) {
				e2e.Logf("The correct network-attach-defintion: %v is created!", nadName)
			} else {
				e2e.Failf("The correct network-attach-defintion: %v is not created!", nadName)
			}
		}

		compat_otp.By("Creating 1st pod consuming NAD/mynet-b")
		pod1 := testMultihomingPod{
			name:       "sampleclient",
			namespace:  ns,
			podlabel:   "sampleclient",
			nadname:    nadNames[2],
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		pod1.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name=sampleclient")).NotTo(o.HaveOccurred())

		twoNadNames := nadNames[0] + "," + nadNames[1]
		compat_otp.By("Creating 2nd pod consuming NAD/dummy-net + mynet-a")
		pod2 := testMultihomingPod{
			name:       "sampleserver",
			namespace:  ns,
			podlabel:   "sampleserver",
			nadname:    twoNadNames,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		pod2.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name=sampleserver")).NotTo(o.HaveOccurred())

		compat_otp.By("Getting pods names")
		clientPod, getPodErr := compat_otp.GetAllPodsWithLabel(oc, ns, "name=sampleclient")
		o.Expect(getPodErr).NotTo(o.HaveOccurred())
		o.Expect(len(clientPod)).NotTo(o.BeEquivalentTo(0))

		compat_otp.By("5. Checking the service of dummy interface is accessible")
		o.Eventually(func() error {
			_, err := e2eoutput.RunHostCmd(ns, clientPod[0], "curl 10.10.10.2:8080 --connect-timeout 5")
			return err
		}, "60s", "10s").ShouldNot(o.HaveOccurred(), "The service of dummy interface is NOT accessible")
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-Medium-79604-Failed to create the sandbox-plugin on multus daemonset rollout [Disruptive]", func() {
		// https://issues.redhat.com/browse/OCPBUGS-48160
		compat_otp.By("Getting the count of multus-pods")
		allPods, getPodErr := compat_otp.GetAllPodsWithLabel(oc, "openshift-multus", "app=multus")
		o.Expect(getPodErr).NotTo(o.HaveOccurred())
		o.Expect(len(allPods)).ShouldNot(o.Equal(0))

		defer func() {
			errCVO := oc.AsAdmin().Run("scale").Args("-n", "openshift-cluster-version", "deployments/cluster-version-operator", "--replicas=1").Execute()
			o.Expect(errCVO).NotTo(o.HaveOccurred())
			errCNO := oc.AsAdmin().Run("scale").Args("-n", "openshift-network-operator", "deploy/network-operator", "--replicas=1").Execute()
			o.Expect(errCNO).NotTo(o.HaveOccurred())
		}()
		compat_otp.By("Disabling CVO and CNO")
		errCVO := oc.AsAdmin().Run("scale").Args("-n", "openshift-cluster-version", "deployments/cluster-version-operator", "--replicas=0").Execute()
		o.Expect(errCVO).NotTo(o.HaveOccurred())
		errCNO := oc.AsAdmin().Run("scale").Args("-n", "openshift-network-operator", "deploy/network-operator", "--replicas=0").Execute()
		o.Expect(errCNO).NotTo(o.HaveOccurred())

		compat_otp.By("Disabling daemonset by adding an invalid NodeSelector")
		_, errMultus := oc.AsAdmin().WithoutNamespace().Run("patch").
			Args("daemonset.apps/multus", "-n", "openshift-multus",
				"-p", `{"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/os":"linuxandwindow"}}}}}`,
				"--type=merge").Output()
		o.Expect(errMultus).NotTo(o.HaveOccurred())

		compat_otp.By("Verifying all multus pods are deleted")
		err := waitForPodsCount(oc, "openshift-multus", "app=multus", 0, 5*time.Second, 20*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Enabling daemonset by restoring the default NodeSelector")
		_, errMultus = oc.AsAdmin().WithoutNamespace().Run("patch").
			Args("daemonset.apps/multus", "-n", "openshift-multus",
				"-p", `{"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/os":"linux"}}}}}`,
				"--type=merge").Output()
		o.Expect(errMultus).NotTo(o.HaveOccurred())

		compat_otp.By("Verifying all multus pods are recreated")
		err = waitForPodsCount(oc, "openshift-multus", "app=multus", len(allPods), 5*time.Second, 20*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Enabling CVO and CNO")
		errCVO = oc.AsAdmin().Run("scale").Args("-n", "openshift-cluster-version", "deployments/cluster-version-operator", "--replicas=1").Execute()
		o.Expect(errCVO).NotTo(o.HaveOccurred())
		errCNO = oc.AsAdmin().Run("scale").Args("-n", "openshift-network-operator", "deploy/network-operator", "--replicas=1").Execute()
		o.Expect(errCNO).NotTo(o.HaveOccurred())
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-Medium-80524-Verify pods with isolated port using bridge-cni", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming/multihoming-pod-template.yaml")
			bridgeCNITemplate      = filepath.Join(buildPruningBaseDir, "multus/bridge-CNI-template.yaml")
		)

		compat_otp.By("Getting the ready and schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready nodes for testing")
		}

		compat_otp.By("Getting the name of the namespace")
		ns := oc.Namespace()

		compat_otp.By("Creating and verifying the configured network-attachment-definition with portIsolation:true")
		nad1 := bridgeCNINAD{
			nadname:        "bridge-isolated-true-ports",
			namespace:      ns,
			plugintype:     "bridge",
			ipamtype:       "host-local",
			ipv4range:      "192.168.10.0/24",
			ipv6range:      "FD00:192:168:10::0/64",
			ipv4rangestart: "192.168.10.1",
			ipv4rangeend:   "192.168.10.100",
			ipv6rangestart: "FD00:192:168:10::1",
			ipv6rangeend:   "FD00:192:168:10::100",
			portisolation:  "true",
			template:       bridgeCNITemplate,
		}
		nad1.createBridgeCNINAD(oc)
		verifyNAD(oc, ns, nad1.nadname)

		compat_otp.By("Creating two test pods consuming the above network-attachment-definition in the namespace")
		pod := []testMultihomingPod{}
		for i := 1; i < 3; i++ {
			podName := "multihoming-pod-" + strconv.Itoa(i)
			podLabel := "multihoming-pod" + strconv.Itoa(i)
			podenvName := "Hello multihoming-pod-" + strconv.Itoa(i)
			p := testMultihomingPod{
				name:       podName,
				namespace:  ns,
				podlabel:   podLabel,
				nadname:    nad1.nadname,
				nodename:   nodeList.Items[0].Name,
				podenvname: podenvName,
				template:   multihomingPodTemplate,
			}
			pod = append(pod, p)
			p.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns, "name="+podLabel)).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Getting the IP of pod1's secondary interface")
		pod1Name := getPodName(oc, ns, "name=multihoming-pod1")
		pod1IPv4, pod1IPv6 := getPodMultiNetwork(ns, pod1Name[0])

		compat_otp.By("Getting the IP of pod2's secondary interface")
		pod2Name := getPodName(oc, ns, "name=multihoming-pod2")
		pod2IPv4, pod2IPv6 := getPodMultiNetwork(ns, pod2Name[0])

		compat_otp.By("Verifying that communication between pods is blocked by the port isolation setting")
		curlPod2PodMultiNetworkFail(ns, pod1Name[0], pod2IPv4, pod2IPv6)
		curlPod2PodMultiNetworkFail(ns, pod2Name[0], pod1IPv4, pod1IPv6)
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-Medium-80525-Verify pods with isolated and non-isolated ports using bridge-CNI", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			netAttachDefFile       = filepath.Join(buildPruningBaseDir, "multus/bridge-whereabouts.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming/multihoming-pod-template.yaml")
			bridgeCNITemplate      = filepath.Join(buildPruningBaseDir, "multus/bridge-CNI-template.yaml")
		)

		compat_otp.By("Getting the ready and schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready nodes for testing")
		}

		compat_otp.By("Getting the namespace name")
		ns := oc.Namespace()

		compat_otp.By("Creating and verifying the configured network-attachment-definition with portIsolation:true")
		nad1 := bridgeCNINAD{
			nadname:        "bridge-isolated-true-ports",
			namespace:      ns,
			plugintype:     "bridge",
			ipamtype:       "host-local",
			ipv4range:      "192.168.10.0/24",
			ipv6range:      "FD00:192:168:10::0/64",
			ipv4rangestart: "192.168.10.1",
			ipv4rangeend:   "192.168.10.100",
			ipv6rangestart: "FD00:192:168:10::1",
			ipv6rangeend:   "FD00:192:168:10::100",
			portisolation:  "true",
			template:       bridgeCNITemplate,
		}
		nad1.createBridgeCNINAD(oc)
		verifyNAD(oc, ns, nad1.nadname)

		compat_otp.By("Creating and verifying the configured network-attachment-definition")
		nads := []nadInfo{
			{name: "bridge-whereabouts", filePath: netAttachDefFile},
		}
		createAndVerifyNAD(oc, ns, nads)

		compat_otp.By("Creating two test pods consuming the above network-attachment-definitions in the namespace")
		nadName := nad1.nadname + "," + "bridge-whereabouts"
		pod := []testMultihomingPod{}
		for i := 1; i < 3; i++ {
			podName := "multihoming-pod-" + strconv.Itoa(i)
			podLabel := "multihoming-pod" + strconv.Itoa(i)
			podenvName := "Hello OpenShift!"
			p := testMultihomingPod{
				name:       podName,
				namespace:  ns,
				podlabel:   podLabel,
				nadname:    nadName,
				nodename:   nodeList.Items[0].Name,
				podenvname: podenvName,
				template:   multihomingPodTemplate,
			}
			pod = append(pod, p)
			p.createTestMultihomingPod(oc)
			o.Expect(waitForPodWithLabelReady(oc, ns, "name="+podLabel)).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Getting the IP of pod1's net1 interface")
		pod1List, getPod1Err := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+"multihoming-pod1")
		o.Expect(getPod1Err).NotTo(o.HaveOccurred())
		o.Expect(len(pod1List)).NotTo(o.BeEquivalentTo(0))
		pod1Net1IPv4, pod1Net1IPv6 := getPodMultiNetworks(oc, ns, pod1List[0], "net1")
		e2e.Logf("The IPv4 address of pod1's net1 is: %v", pod1Net1IPv4)
		e2e.Logf("The IPv6 address of pod1's net1 is: %v", pod1Net1IPv6)

		compat_otp.By("Getting the IP of pod2's net1 interface")
		pod2List, getPod2Err := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+"multihoming-pod2")
		o.Expect(getPod2Err).NotTo(o.HaveOccurred())
		o.Expect(len(pod2List)).NotTo(o.BeEquivalentTo(0))
		pod2Net1IPv4, pod2Net1IPv6 := getPodMultiNetworks(oc, ns, pod2List[0], "net1")
		e2e.Logf("The IPv4 address of pod2's net1 is: %v", pod2Net1IPv4)
		e2e.Logf("The IPv6 address of pod2's net1 is: %v", pod2Net1IPv6)
		compat_otp.By("Verifying that communication between pods is blocked by the port isolation setting")
		curlPod2PodMultiNetworkFail(ns, pod1List[0], pod2Net1IPv4, pod2Net1IPv6)
		curlPod2PodMultiNetworkFail(ns, pod2List[0], pod1Net1IPv4, pod1Net1IPv6)

		compat_otp.By("Getting the IP of pod1's net2 interface")
		pod1net2IPv4, pod1net2IPv6 := getPodMultiNetworks(oc, ns, pod1List[0], "net2")
		e2e.Logf("The IPv4 address of pod1's net2 is: %v", pod1net2IPv4)
		e2e.Logf("The IPv6 address of pod1's net2 is: %v", pod1net2IPv6)

		compat_otp.By("Getting the IP of pod2's net2 interface")
		pod2net2IPv4, pod2net2IPv6 := getPodMultiNetworks(oc, ns, pod2List[0], "net2")
		e2e.Logf("The IPv4 address of pod2's net2 is: %v", pod2net2IPv4)
		e2e.Logf("The IPv6 address of pod2's net2 is: %v", pod2net2IPv6)

		compat_otp.By("Verifying that communication between pods is not blocked between net2 interfaces")
		curlPod2PodMultiNetworkPass(ns, pod1List[0], pod2net2IPv4, pod2net2IPv6)
		curlPod2PodMultiNetworkPass(ns, pod2List[0], pod1net2IPv4, pod1net2IPv6)
	})

	g.It("Author:weliang-Medium-80526-UDN Verify pods with isolated and non-isolated ports using bridge-cni", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			netAttachDefFile    = filepath.Join(buildPruningBaseDir, "multus/bridge-whereabouts.yaml")
			udnPodTemplate      = filepath.Join(buildPruningBaseDir, "udn/udn_test_pod_annotation_template_node.yaml")
			bridgeCNITemplate   = filepath.Join(buildPruningBaseDir, "multus/bridge-CNI-template.yaml")
		)

		compat_otp.By("Getting the ready and schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready nodes for testing")
		}

		compat_otp.By("Getting the namespace name")
		oc.CreateNamespaceUDN()
		ns := oc.Namespace()

		compat_otp.By("Creating Layer2 UDN CRD with Primary role")
		var cidr, ipv4cidr, ipv6cidr string
		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv4single" {
			cidr = "10.10.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "FC00:10:10::0/64"
			} else {
				ipv4cidr = "10.10.0.0/16"
				ipv6cidr = "FC00:10:10::0/64"
			}
		}
		createGeneralUDNCRD(oc, ns, "udn-80526", ipv4cidr, ipv6cidr, cidr, "layer2")

		compat_otp.By("Creating and verifying the configured network-attachment-definition with portIsolation:true")
		nad1 := bridgeCNINAD{
			nadname:        "bridge-isolated-true-ports",
			namespace:      ns,
			plugintype:     "bridge",
			ipamtype:       "host-local",
			ipv4range:      "192.168.10.0/24",
			ipv6range:      "FD00:192:168:10::0/64",
			ipv4rangestart: "192.168.10.1",
			ipv4rangeend:   "192.168.10.100",
			ipv6rangestart: "FD00:192:168:10::1",
			ipv6rangeend:   "FD00:192:168:10::100",
			portisolation:  "true",
			template:       bridgeCNITemplate,
		}
		nad1.createBridgeCNINAD(oc)
		verifyNAD(oc, ns, nad1.nadname)

		compat_otp.By("Creating and verifying the configured network-attachment-definition")
		nads := []nadInfo{
			{name: "bridge-whereabouts", filePath: netAttachDefFile},
		}
		createAndVerifyNAD(oc, ns, nads)

		compat_otp.By("Creating two test pods consuming the above network-attachment-definitions in the namespace")
		pods := make([]udnPodSecNADResourceNode, 3)
		nadName := nad1.nadname + "," + "bridge-whereabouts"
		var podNames []string
		for i := 0; i < 3; i++ {
			pods[i] = udnPodSecNADResourceNode{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: ns,
				nadname:   nadName,
				nodename:  nodeList.Items[0].Name,
				template:  udnPodTemplate,
			}
			pods[i].createUdnPodWithSecNADNode(oc)
			waitPodReady(oc, ns, pods[i].name)
			podNames = append(podNames, pods[i].name)
		}

		compat_otp.By("Getting the IP of pod1's net1 interface")
		pod1Net1IPv4, pod1Net1IPv6 := getPodMultiNetworks(oc, ns, podNames[0], "net1")
		e2e.Logf("The IPv4 address of pod1's net1 is: %v", pod1Net1IPv4)
		e2e.Logf("The IPv6 address of pod1's net1 is: %v", pod1Net1IPv6)

		compat_otp.By("Getting the IP of pod2's net1 interface")
		pod2Net1IPv4, pod2Net1IPv6 := getPodMultiNetworks(oc, ns, podNames[1], "net1")
		e2e.Logf("The IPv4 address of pod2's net1 is: %v", pod2Net1IPv4)
		e2e.Logf("The IPv6 address of pod2's net1 is: %v", pod2Net1IPv6)
		compat_otp.By("Verifying that communication between pods is blocked by the port isolation setting")
		curlPod2PodMultiNetworkFail(ns, podNames[0], pod2Net1IPv4, pod2Net1IPv6)
		curlPod2PodMultiNetworkFail(ns, podNames[1], pod1Net1IPv4, pod1Net1IPv6)

		compat_otp.By("Getting the IP of pod1's net2 interface")
		pod1net2IPv4, pod1net2IPv6 := getPodMultiNetworks(oc, ns, podNames[0], "net2")
		e2e.Logf("The IPv4 address of pod1's net2 is: %v", pod1net2IPv4)
		e2e.Logf("The IPv6 address of pod1's net2 is: %v", pod1net2IPv6)

		compat_otp.By("Getting the IP of pod2's net2 interface")
		pod2net2IPv4, pod2net2IPv6 := getPodMultiNetworks(oc, ns, podNames[1], "net2")
		e2e.Logf("The IPv4 address of pod2's net2 is: %v", pod2net2IPv4)
		e2e.Logf("The IPv6 address of pod2's net2 is: %v", pod2net2IPv6)

		compat_otp.By("Verifying that communication between pods is not blocked between net2 interfaces")
		curlPod2PodMultiNetworkPass(ns, podNames[0], pod2net2IPv4, pod2net2IPv6)
		curlPod2PodMultiNetworkPass(ns, podNames[1], pod1net2IPv4, pod1net2IPv6)
	})

	g.It("Author:weliang-Medium-81757-UDN Verify pods with isolated and non-isolated ports using same type of CNI and IPAM", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			udnPodTemplate      = filepath.Join(buildPruningBaseDir, "udn/udn_test_pod_annotation_template_node.yaml")
			bridgeCNITemplate   = filepath.Join(buildPruningBaseDir, "multus/bridge-CNI-template.yaml")
		)

		compat_otp.By("Getting the ready and schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready nodes for testing")
		}

		compat_otp.By("Getting the namespace name")
		oc.CreateNamespaceUDN()
		ns := oc.Namespace()

		compat_otp.By("Creating Layer2 UDN CRD with Primary role")
		var cidr, ipv4cidr, ipv6cidr string
		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv4single" {
			cidr = "10.10.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "FC00:10:10::0/64"
			} else {
				ipv4cidr = "10.10.0.0/16"
				ipv6cidr = "FC00:10:10::0/64"
			}
		}
		createGeneralUDNCRD(oc, ns, "udn-81757", ipv4cidr, ipv6cidr, cidr, "layer2")

		compat_otp.By("Creating and verifying the configured network-attachment-definition with portIsolation:true")
		nad1 := bridgeCNINAD{
			nadname:        "bridge-isolated-true-ports",
			namespace:      ns,
			plugintype:     "bridge",
			ipamtype:       "host-local",
			ipv4range:      "192.168.10.0/24",
			ipv6range:      "FD00:192:168:10::0/64",
			ipv4rangestart: "192.168.10.1",
			ipv4rangeend:   "192.168.10.100",
			ipv6rangestart: "FD00:192:168:10::1",
			ipv6rangeend:   "FD00:192:168:10::100",
			portisolation:  "true",
			template:       bridgeCNITemplate,
		}
		nad1.createBridgeCNINAD(oc)
		verifyNAD(oc, ns, nad1.nadname)

		compat_otp.By("Creating and verifying the configured network-attachment-definition with portIsolation:false")
		nad2 := bridgeCNINAD{
			nadname:        "bridge-isolated-false-ports",
			namespace:      ns,
			plugintype:     "bridge",
			ipamtype:       "host-local",
			ipv4range:      "192.168.20.0/24",
			ipv6range:      "FD00:192:168:20::0/64",
			ipv4rangestart: "192.168.20.1",
			ipv4rangeend:   "192.168.20.100",
			ipv6rangestart: "FD00:192:168:20::1",
			ipv6rangeend:   "FD00:192:168:20::100",
			portisolation:  "false",
			template:       bridgeCNITemplate,
		}
		nad2.createBridgeCNINAD(oc)
		verifyNAD(oc, ns, nad2.nadname)

		compat_otp.By("Creating two test pods consuming the above network-attachment-definitions in the namespace")
		pods := make([]udnPodSecNADResourceNode, 3)
		nadName := nad1.nadname + "," + nad2.nadname
		var podNames []string
		for i := 0; i < 3; i++ {
			pods[i] = udnPodSecNADResourceNode{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: ns,
				nadname:   nadName,
				nodename:  nodeList.Items[0].Name,
				template:  udnPodTemplate,
			}
			pods[i].createUdnPodWithSecNADNode(oc)
			waitPodReady(oc, ns, pods[i].name)
			podNames = append(podNames, pods[i].name)
		}

		compat_otp.By("Getting the IP of pod1's net1 interface")
		pod1Net1IPv4, pod1Net1IPv6 := getPodMultiNetworks(oc, ns, podNames[0], "net1")
		e2e.Logf("The IPv4 address of pod1's net1 is: %v", pod1Net1IPv4)
		e2e.Logf("The IPv6 address of pod1's net1 is: %v", pod1Net1IPv6)

		compat_otp.By("Getting the IP of pod2's net1 interface")
		pod2Net1IPv4, pod2Net1IPv6 := getPodMultiNetworks(oc, ns, podNames[1], "net1")
		e2e.Logf("The IPv4 address of pod2's net1 is: %v", pod2Net1IPv4)
		e2e.Logf("The IPv6 address of pod2's net1 is: %v", pod2Net1IPv6)

		compat_otp.By("Verifying that communication between pods is blocked by the port isolation setting")
		curlPod2PodMultiNetworkFail(ns, podNames[0], pod2Net1IPv4, pod2Net1IPv6)
		curlPod2PodMultiNetworkFail(ns, podNames[1], pod1Net1IPv4, pod1Net1IPv6)
		compat_otp.By("Getting the IP of pod1's net2 interface")
		pod1net2IPv4, pod1net2IPv6 := getPodMultiNetworks(oc, ns, podNames[0], "net2")
		e2e.Logf("The IPv4 address of pod1's net2 is: %v", pod1net2IPv4)
		e2e.Logf("The IPv6 address of pod1's net2 is: %v", pod1net2IPv6)

		compat_otp.By("Getting the IP of pod2's net2 interface")
		pod2net2IPv4, pod2net2IPv6 := getPodMultiNetworks(oc, ns, podNames[1], "net2")
		e2e.Logf("The IPv4 address of pod2's net2 is: %v", pod2net2IPv4)
		e2e.Logf("The IPv6 address of pod2's net2 is: %v", pod2net2IPv6)
		compat_otp.By("Verifying that communication between pods is not blocked between net2 interfaces")
		curlPod2PodMultiNetworkPass(ns, podNames[0], pod2net2IPv4, pod2net2IPv6)
		curlPod2PodMultiNetworkPass(ns, podNames[1], pod1net2IPv4, pod1net2IPv6)
	})

	g.It("Author:weliang-Medium-77102-76219-Checking Rule of ocp4-cis-file-permissions-cni-conf.", func() {
		compat_otp.By("Check permissions of multus CNI config in multus pods")
		multusConfigPath := "/host/etc/cni/net.d/00-multus.conf"
		expectedMultusPerm := "600 " + multusConfigPath

		multusPods, err := compat_otp.GetAllPodsWithLabel(oc, "openshift-multus", "app=multus")
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, pod := range multusPods {
			out, err := execCommandInSpecificPod(oc, "openshift-multus", pod, "stat -c '%a %n' "+multusConfigPath)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(out).To(o.ContainSubstring(expectedMultusPerm))
		}

		compat_otp.By("Check permissions of multus and whereabouts config on each node")
		workerNodes, err := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(err).NotTo(o.HaveOccurred())

		whereaboutsDir := "/etc/kubernetes/cni/net.d/whereabouts.d"
		whereaboutsConf := whereaboutsDir + "/whereabouts.conf"
		whereaboutsKubeconfig := whereaboutsDir + "/whereabouts.kubeconfig"
		expectedWhereaboutsPerm := "600 " + whereaboutsConf
		expectedKubeconfigPerm := "600 " + whereaboutsKubeconfig
		cniNetDir := "/etc/kubernetes/cni/net.d/"
		expectedCronExpr := `"reconciler_cron_expression": "30 4 * * *"`

		for _, node := range workerNodes {
			lsOut, err := compat_otp.DebugNodeWithOptionsAndChroot(oc, node, []string{"-q"}, "ls", "-l", cniNetDir)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(lsOut).Should(o.And(
				o.ContainSubstring("00-multus.conf"),
				o.ContainSubstring("whereabouts.d"),
			))

			statOut, err := compat_otp.DebugNodeWithOptionsAndChroot(oc, node, []string{"-q"}, "stat", "-c", "%a %n", whereaboutsConf, whereaboutsKubeconfig)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(statOut).Should(o.And(
				o.ContainSubstring(expectedWhereaboutsPerm),
				o.ContainSubstring(expectedKubeconfigPerm),
			))

			catOut, err := compat_otp.DebugNodeWithOptionsAndChroot(oc, node, []string{"-q"}, "cat", whereaboutsConf)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(catOut).To(o.ContainSubstring(expectedCronExpr))
		}
	})

	g.It("Author:weliang-Medium-77301-Pods can reach their service when a NetworkAttachmentDefinition is configured", func() {
		// Bug: https://issues.redhat.com/browse/OCPBUGS-39009: Pods cannot reach their service when a NetworkAttachmentDefinition is configured
		var (
			baseDir                = testdata.FixturePath("networking")
			nadTemplate            = filepath.Join(baseDir, "multus/whereabouts-overlappingIP-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(baseDir, "multihoming/multihoming-pod-template.yaml")
			serviceTemplate        = filepath.Join(baseDir, "service-generic-template.yaml")
			ns                     = oc.Namespace()
			nadName                = "whereabouts-scale"
			svcName                = "blue-service"
			podLabel               = "blue-openshift"
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("The cluster has no ready node")
		}

		nad := whereaboutsoverlappingIPNAD{
			nadname:           nadName,
			namespace:         ns,
			plugintype:        "macvlan",
			mode:              "bridge",
			ipamtype:          "whereabouts",
			ipv4range:         "192.168.0.0/16",
			enableoverlapping: false,
			networkname:       "",
			template:          nadTemplate,
		}
		defer removeResource(oc, true, true, "net-attach-def", nadName, "-n", ns)
		nad.createWhereaboutsoverlappingIPNAD(oc)

		pod := testMultihomingPod{
			name:       "blue-pod",
			namespace:  ns,
			podlabel:   podLabel,
			nadname:    nadName,
			nodename:   nodeList.Items[0].Name,
			podenvname: "Hello Blue Pod-1 Example",
			template:   multihomingPodTemplate,
		}
		defer removeResource(oc, true, true, "rc", pod.name, "-n", ns)
		pod.createTestMultihomingPod(oc)
		o.Expect(waitForPodWithLabelReady(oc, ns, "name="+pod.podlabel)).NotTo(o.HaveOccurred())

		podList, podListErr := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+podLabel)
		o.Expect(podListErr).NotTo(o.HaveOccurred())
		o.Expect(len(podList)).NotTo(o.BeZero())
		realPod := podList[0]

		svc := genericServiceResource{
			servicename:           svcName,
			namespace:             ns,
			protocol:              "TCP",
			selector:              podLabel,
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "SingleStack",
			externalTrafficPolicy: "",
			internalTrafficPolicy: "Cluster",
			template:              serviceTemplate,
		}
		defer removeResource(oc, true, true, "service", svc.servicename, "-n", ns)
		svc.createServiceFromParams(oc)
		svcOutput, svcErr := oc.AsAdmin().Run("get").Args("service", svc.servicename, "-n", ns).Output()
		o.Expect(svcErr).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).To(o.ContainSubstring(svc.servicename))

		CurlPod2SvcPass(oc, ns, ns, realPod, svc.servicename)
	})

	g.It("Author:weliang-Medium-83708-The ipvlan pod will send Unsolicited Neighbor Advertisements after it is created. [Serial]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			dualstackNADTemplate   = filepath.Join(buildPruningBaseDir, "multus/dualstack-NAD-template.yaml")
			multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming/multihoming-pod-template.yaml")
			nadName                = "whereabouts-dualstack"
			sniffMultusPodTemplate = filepath.Join(buildPruningBaseDir, "multus/sniff-multus-pod-template.yaml")
		)

		compat_otp.By("Get the ready-schedulable worker nodes")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("This case requires at least one worker node")
		}

		compat_otp.By("Get the name of namespace")
		ns := oc.Namespace()
		defer compat_otp.RecoverNamespaceRestricted(oc, ns)
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("Create a custom resource network-attach-defintion")
		defer removeResource(oc, true, true, "net-attach-def", nadName, "-n", ns)
		nadns := dualstackNAD{
			nadname:        nadName,
			namespace:      ns,
			plugintype:     "ipvlan",
			mode:           "l2",
			ipamtype:       "whereabouts",
			ipv4range:      "192.168.10.0/24",
			ipv6range:      "fd00:dead:beef:10::/64",
			ipv4rangestart: "",
			ipv4rangeend:   "",
			ipv6rangestart: "",
			ipv6rangeend:   "",
			template:       dualstackNADTemplate,
		}
		nadns.createDualstackNAD(oc)

		compat_otp.By("Check if the network-attach-defintion is created")
		if checkNAD(oc, ns, nadName) {
			e2e.Logf("The correct network-attach-defintion: %v is created!", nadName)
		} else {
			e2e.Failf("The correct network-attach-defintion: %v is not created!", nadName)
		}

		compat_otp.By("Create a sniff pod to capture the traffic from pod's secondary network")
		pod1 := testPodMultinetwork{
			name:      "sniff-pod",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			nadname:   nadName,
			labelname: "sniff-pod",
			template:  sniffMultusPodTemplate,
		}
		pod1.createTestPodMultinetwork(oc)
		compat_otp.AssertWaitPollNoErr(waitForPodWithLabelReady(oc, ns, "name="+pod1.labelname), fmt.Sprintf("Waiting for pod with label name=%s become ready timeout", pod1.labelname))

		compat_otp.By("The sniff pod start to capture the Unsolicited Neighbor Advertisements from pod's secondary network")
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", ns, pod1.labelname, "bash", "-c",
			`timeout --preserve-status 30 tcpdump -e -i net1 icmp6 and icmp6[0] = 136 -nvvv`).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create a pod consuming above network-attach-defintion")
		pod2 := testMultihomingPod{
			name:       "dualstack-pod",
			namespace:  ns,
			podlabel:   "dualstack-pod",
			nadname:    nadName,
			nodename:   nodeList.Items[0].Name,
			podenvname: "",
			template:   multihomingPodTemplate,
		}
		pod2.createTestMultihomingPod(oc)
		compat_otp.AssertWaitPollNoErr(waitForPodWithLabelReady(oc, ns, "name="+pod2.podlabel), fmt.Sprintf("Waiting for pod with label name=%s become ready timeout", pod2.podlabel))

		compat_otp.By("The sniff pod will get Unsolicited Neighbor Advertisements, not neighbor solicitation")
		cmdErr := cmdTcpdump.Wait()
		o.Expect(cmdErr).NotTo(o.HaveOccurred())

		// Check for Unsolicited NA: type 136 and only [override] flag (no [solicited])
		rawOutput := cmdOutput.String()
		fmt.Println("rawOutput:\n", rawOutput)
		o.Expect(rawOutput).To(o.MatchRegexp(
			`neighbor advertisement.*Flags \[override\]`),
			"No unsolicited NA found. Full output:\n%s", rawOutput)
	})
})
