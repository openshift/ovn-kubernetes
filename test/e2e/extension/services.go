package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	clusterinfra "github.com/openshift/origin/test/extended/util/compat_otp/clusterinfra"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN service", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-services", compat_otp.KubeConfigPath())

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-WRS-High-50347-V-ACS.04-[FdpOvnOvs] internalTrafficPolicy set Local for pod/node to service access", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("Create a namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("create 1st hello pod in ns1")

		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		g.By("Create a test service which is in front of the above pods")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns1,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "",
			internalTrafficPolicy: "Local",
			externalTrafficPolicy: "", //This no value parameter will be ignored
			template:              genericServiceTemplate,
		}
		svc.ipFamilyPolicy = "SingleStack"
		svc.createServiceFromParams(oc)

		g.By("Create second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("Create a pod hello-pod2 in second namespace, pod located the same node")
		pod2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns2,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, ns2, pod2.name)

		g.By("Create second pod hello-pod3 in second namespace, pod located on the different node")
		pod3 := pingPodResourceNode{
			name:      "hello-pod3",
			namespace: ns2,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod3.createPingPodNode(oc)
		waitPodReady(oc, ns2, pod3.name)

		g.By("curl from hello-pod2 to service:port")
		CurlPod2SvcPass(oc, ns2, ns1, "hello-pod2", "test-service")

		g.By("curl from hello-pod3 to service:port should be failling")
		CurlPod2SvcFail(oc, ns2, ns1, "hello-pod3", "test-service")

		g.By("Curl from node0 to service:port")
		CurlNode2SvcPass(oc, pod1.nodename, ns1, "test-service")
		g.By("Curl from node1 to service:port")
		CurlNode2SvcFail(oc, nodeList.Items[1].Name, ns1, "test-service")

		ipStackType := checkIPStackType(oc)

		if ipStackType == "dualstack" {
			g.By("Delete testservice from ns")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", "test-service", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			g.By("Checking pod to svc:port behavior now on with PreferDualStack Service")
			svc.ipFamilyPolicy = "PreferDualStack"
			svc.createServiceFromParams(oc)
			g.By("curl from hello-pod2 to service:port")
			CurlPod2SvcPass(oc, ns2, ns1, "hello-pod2", "test-service")

			g.By("curl from hello-pod3 to service:port should be failling")
			CurlPod2SvcFail(oc, ns2, ns1, "hello-pod3", "test-service")

			g.By("Curl from node0 to service:port")
			//Due to bug 2078691,skip below step for now.
			//CurlNode2SvcPass(oc, pod1.nodename, ns1,"test-service")
			g.By("Curl from node1 to service:port")
			CurlNode2SvcFail(oc, nodeList.Items[1].Name, ns1, "test-service")

		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-WRS-High-50348-V-ACS.04-[FdpOvnOvs] internalTrafficPolicy set Local for pod/node to service access with hostnetwork pod backend. [Serial]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			hostNetworkPodTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-hostnetwork-specific-node-template.yaml")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("Create a namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()
		//Required for hostnetwork pod
		compat_otp.By("Set namespace as privileged for Hostnetworked Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		g.By("create 1st hello pod in ns1")

		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  hostNetworkPodTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		g.By("Create a test service which is in front of the above pods")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns1,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "",
			internalTrafficPolicy: "Local",
			externalTrafficPolicy: "", //This no value parameter will be ignored
			template:              genericServiceTemplate,
		}
		svc.ipFamilyPolicy = "SingleStack"
		svc.createServiceFromParams(oc)

		g.By("Create second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("Create a pod hello-pod2 in second namespace, pod located the same node")
		pod2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns2,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, ns2, pod2.name)

		g.By("Create second pod hello-pod3 in second namespace, pod located on the different node")
		pod3 := pingPodResourceNode{
			name:      "hello-pod3",
			namespace: ns2,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod3.createPingPodNode(oc)
		waitPodReady(oc, ns2, pod3.name)

		g.By("curl from hello-pod2 to service:port")
		CurlPod2SvcPass(oc, ns2, ns1, "hello-pod2", "test-service")

		g.By("curl from hello-pod3 to service:port should be failing")
		CurlPod2SvcFail(oc, ns2, ns1, "hello-pod3", "test-service")

		g.By("Curl from node1 to service:port")
		CurlNode2SvcFail(oc, nodeList.Items[1].Name, ns1, "test-service")

		g.By("Curl from node0 to service:port")
		CurlNode2SvcPass(oc, nodeList.Items[0].Name, ns1, "test-service")

		ipStackType := checkIPStackType(oc)

		if ipStackType == "dualstack" {
			g.By("Delete testservice from ns")
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", "test-service", "-n", ns1).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			g.By("Checking pod to svc:port behavior now on with PreferDualStack Service")
			svc.ipFamilyPolicy = "PreferDualStack"
			svc.createServiceFromParams(oc)
			g.By("curl from hello-pod2 to service:port")
			CurlPod2SvcPass(oc, ns2, ns1, "hello-pod2", "test-service")

			g.By("curl from hello-pod3 to service:port should be failing")
			CurlPod2SvcFail(oc, ns2, ns1, "hello-pod3", "test-service")

			g.By("Curl from node1 to service:port")
			CurlNode2SvcFail(oc, nodeList.Items[1].Name, ns1, "test-service")

		}
	})

	// author: weliang@redhat.com
	g.It("Author:weliang-Medium-57344-[NETWORKCUSIM] Add support for service session affinity timeout", func() {
		//Bug: https://issues.redhat.com/browse/OCPBUGS-4502
		var (
			buildPruningBaseDir         = testdata.FixturePath("networking")
			servicesBaseDir             = testdata.FixturePath("networking/services")
			pingPodTemplate             = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			sessionAffinitySvcv4        = filepath.Join(servicesBaseDir, "sessionaffinity-svcv4.yaml")
			sessionAffinitySvcdualstack = filepath.Join(servicesBaseDir, "sessionaffinity-svcdualstack.yaml")
			sessionAffinityPod1         = filepath.Join(servicesBaseDir, "sessionaffinity-pod1.yaml")
			sessionAffinityPod2         = filepath.Join(servicesBaseDir, "sessionaffinity-pod2.yaml")
		)

		ns1 := oc.Namespace()

		g.By("create two pods which will be the endpoints for sessionaffinity service in ns1")
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", sessionAffinityPod1, "-n", ns1).Execute()
			}
		}()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", sessionAffinityPod2, "-n", ns1).Execute()
			}
		}()
		createResourceFromFile(oc, ns1, sessionAffinityPod1)
		waitPodReady(oc, ns1, "blue-pod-1")
		createResourceFromFile(oc, ns1, sessionAffinityPod2)
		waitPodReady(oc, ns1, "blue-pod-2")

		g.By("create a testing pod in ns1")
		pod1 := pingPodResource{
			name:      "hello-pod1",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1.name, "-n", pod1.namespace).Execute()
			}
		}()
		pod1.createPingPod(oc)
		waitPodReady(oc, ns1, pod1.name)

		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.By("test ipv4 singlestack cluster")
			g.By("create a sessionaffinity service in ns1")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", sessionAffinitySvcv4, "-n", ns1).Execute()
			createsvcerr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", sessionAffinitySvcv4, "-n", ns1).Execute()
			o.Expect(createsvcerr).NotTo(o.HaveOccurred())
			svcoutput, svcerr := oc.AsAdmin().Run("get").Args("service", "-n", ns1).Output()
			o.Expect(svcerr).NotTo(o.HaveOccurred())
			o.Expect(svcoutput).To(o.ContainSubstring("sessionaffinitysvcv4"))
			serviceIPv4 := getSvcIPv4(oc, ns1, "sessionaffinitysvcv4")

			// timeoutSeconds in sessionAffinityConfig is set 10s, traffic will LB after curl sleep more than 10s
			g.By("Traffic will LB to two endpoints with sleep 15s in curl")
			trafficoutput, trafficerr := e2eoutput.RunHostCmd(ns1, pod1.name, "for i in 1 2 3 4 5 6 7 8 9 10; do curl "+serviceIPv4+":8080; sleep 11; done")
			o.Expect(trafficerr).NotTo(o.HaveOccurred())
			if strings.Contains(trafficoutput, "Hello Blue Pod-1") && strings.Contains(trafficoutput, "Hello Blue Pod-2") {
				e2e.Logf("Pass : Traffic LB to two endpoints when curl sleep more than 10s")
			} else {
				e2e.Failf("Fail: Traffic does not LB to two endpoints when curl sleep more than 10s")
			}

			// timeoutSeconds in sessionAffinityConfig is set 10s, traffic will not LB after curl sleep less than 10s
			g.By("Traffic will not LB to two endpoints without sleep 15s in curl")
			trafficoutput1, trafficerr1 := e2eoutput.RunHostCmd(ns1, pod1.name, "for i in 1 2 3 4 5 6 7 8 9 10; do curl "+serviceIPv4+":8080; sleep 9; done")
			o.Expect(trafficerr1).NotTo(o.HaveOccurred())
			if (strings.Contains(trafficoutput1, "Hello Blue Pod-1") && !strings.Contains(trafficoutput1, "Hello Blue Pod-2")) || (strings.Contains(trafficoutput1, "Hello Blue Pod-2") && !strings.Contains(trafficoutput1, "Hello Blue Pod-1")) {
				e2e.Logf("Pass : Traffic does not LB to two endpoints when curl sleep less than 10s")
			} else {
				e2e.Failf("Fail: Traffic LB to two endpoints when curl sleep less than 10s")
			}
		}

		if ipStackType == "dualstack" {
			g.By("test dualstack cluster")
			g.By("create a sessionaffinity service in ns1")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", sessionAffinitySvcdualstack, "-n", ns1).Execute()
			createsvcerr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", sessionAffinitySvcdualstack, "-n", ns1).Execute()
			o.Expect(createsvcerr).NotTo(o.HaveOccurred())
			svcoutput, svcerr := oc.AsAdmin().Run("get").Args("service", "-n", ns1).Output()
			o.Expect(svcerr).NotTo(o.HaveOccurred())
			o.Expect(svcoutput).To(o.ContainSubstring("sessionaffinitysvcdualstack"))
			serviceIPv4 := getSvcIPv4(oc, ns1, "sessionaffinitysvcdualstack")
			serviceIPv6 := getSvcIPv6(oc, ns1, "sessionaffinitysvcdualstack")

			// Test ipv4 traffic in dualstack cluster
			// timeoutSeconds in sessionAffinityConfig is set 10s, traffic will LB after curl sleep more than 10s
			g.By("Traffic will LB to two endpoints with sleep 15s in curl")
			trafficoutput, trafficerr := e2eoutput.RunHostCmd(ns1, pod1.name, "for i in 1 2 3 4 5 6 7 8 9 10; do curl "+serviceIPv4+":8080; sleep 11; done")
			o.Expect(trafficerr).NotTo(o.HaveOccurred())
			if strings.Contains(trafficoutput, "Hello Blue Pod-1") && strings.Contains(trafficoutput, "Hello Blue Pod-2") {
				e2e.Logf("Pass : Traffic LB to two endpoints when curl sleep more than 10s")
			} else {
				e2e.Failf("Fail: Traffic does not LB to two endpoints when curl sleep more than 10s")
			}

			// timeoutSeconds in sessionAffinityConfig is set 10s, traffic will not LB after curl sleep less than 10s
			g.By("Traffic will not LB to two endpoints without sleep 15s in curl")
			trafficoutput1, trafficerr1 := e2eoutput.RunHostCmd(ns1, pod1.name, "for i in 1 2 3 4 5 6 7 8 9 10; do curl "+serviceIPv4+":8080; sleep 9; done")
			o.Expect(trafficerr1).NotTo(o.HaveOccurred())
			if (strings.Contains(trafficoutput1, "Hello Blue Pod-1") && !strings.Contains(trafficoutput1, "Hello Blue Pod-2")) || (strings.Contains(trafficoutput1, "Hello Blue Pod-2") && !strings.Contains(trafficoutput1, "Hello Blue Pod-1")) {
				e2e.Logf("Pass : Traffic does not LB to two endpoints when curl sleep less than 10s")
			} else {
				e2e.Failf("Fail: Traffic LB to two endpoints when curl sleep less than 10s")
			}

			// Tes ipv6 traffic in dualstack cluster
			// timeoutSeconds in sessionAffinityConfig is set 10s, traffic will LB after curl sleep more than 10s
			g.By("Traffic will LB to two endpoints with sleep 15s in curl")
			v6trafficoutput, v6trafficerr := e2eoutput.RunHostCmd(ns1, pod1.name, "for i in 1 2 3 4 5 6 7 8 9 10; do curl -g -6 ["+serviceIPv6+"]:8080; sleep 11; done")
			o.Expect(v6trafficerr).NotTo(o.HaveOccurred())
			if strings.Contains(v6trafficoutput, "Hello Blue Pod-1") && strings.Contains(v6trafficoutput, "Hello Blue Pod-2") {
				e2e.Logf("Pass : Traffic LB to two endpoints when curl sleep more than 10s")
			} else {
				e2e.Failf("Fail: Traffic does not LB to two endpoints when curl sleep more than 10s")
			}

			// timeoutSeconds in sessionAffinityConfig is set 10s, traffic will not LB after curl sleep less than 10s
			g.By("Traffic will not LB to two endpoints without sleep 15s in curl")
			v6trafficoutput1, v6trafficerr1 := e2eoutput.RunHostCmd(ns1, pod1.name, "for i in 1 2 3 4 5 6 7 8 9 10; do curl -g -6 ["+serviceIPv6+"]:8080; sleep 9; done")
			o.Expect(v6trafficerr1).NotTo(o.HaveOccurred())
			if (strings.Contains(v6trafficoutput1, "Hello Blue Pod-1") && !strings.Contains(v6trafficoutput1, "Hello Blue Pod-2")) || (strings.Contains(v6trafficoutput1, "Hello Blue Pod-2") && !strings.Contains(v6trafficoutput1, "Hello Blue Pod-1")) {
				e2e.Logf("Pass : Traffic does not LB to two endpoints when curl sleep less than 10s")
			} else {
				e2e.Failf("Fail: Traffic LB to two endpoints when curl sleep less than 10s")
			}
		}
	})
	// author: asood@redhat.com
	g.It("Longduration-NonPreRelease-Author:asood-High-62293-[FdpOvnOvs] Validate all the constructs are created on logical routers and logical switches for a service type loadbalancer. [Disruptive]", func() {
		// Bug: https://issues.redhat.com/browse/OCPBUGS-5930 (Duplicate bug https://issues.redhat.com/browse/OCPBUGS-7000)
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			svcEndpoints           []svcEndpontDetails
			lsConstruct            string
			lrConstruct            string
		)
		platform := compat_otp.CheckPlatform(oc)
		//vSphere does not have LB service support yet
		e2e.Logf("platform %s", platform)
		if !(strings.Contains(platform, "gcp") || strings.Contains(platform, "aws") || strings.Contains(platform, "azure")) {
			g.Skip("Skip for non-supported auto scaling machineset platforms!!")
		}

		workerNodes, err := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Get namespace")
		ns := oc.Namespace()

		compat_otp.By(fmt.Sprintf("create 1st hello pod in %s", ns))
		pod := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns,
			nodename:  workerNodes[0],
			template:  pingPodNodeTemplate,
		}
		pod.createPingPodNode(oc)
		waitPodReady(oc, ns, pod.name)

		compat_otp.By("Create a test service which is in front of the above pod")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "LoadBalancer",
			ipFamilyPolicy:        "SingleStack",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "Cluster",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		compat_otp.By("Create a new machineset to add new nodes")
		clusterinfra.SkipConditionally(oc)
		infrastructureName := clusterinfra.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-62293"
		ms := clusterinfra.MachineSetDescription{Name: machinesetName, Replicas: 2}
		defer ms.DeleteMachineSet(oc)
		ms.CreateMachineSet(oc)
		clusterinfra.WaitForMachinesRunning(oc, 2, machinesetName)
		machineName := clusterinfra.GetMachineNamesFromMachineSet(oc, machinesetName)
		nodeName0 := clusterinfra.GetNodeNameFromMachine(oc, machineName[0])
		nodeName1 := clusterinfra.GetNodeNameFromMachine(oc, machineName[1])
		e2e.Logf("The nodes %s and %s added successfully", nodeName0, nodeName1)

		compat_otp.By(fmt.Sprintf("create 2nd hello pod in %s on newly created node %s", ns, nodeName0))
		pod = pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns,
			nodename:  nodeName0,
			template:  pingPodNodeTemplate,
		}
		pod.createPingPodNode(oc)
		waitPodReady(oc, ns, pod.name)

		compat_otp.By("Get backend pod details of user service")
		allPods, getPodErr := compat_otp.GetAllPodsWithLabel(oc, ns, "name=hello-pod")
		o.Expect(getPodErr).NotTo(o.HaveOccurred())
		o.Expect(len(allPods)).NotTo(o.BeEquivalentTo(0))
		for _, eachPod := range allPods {
			nodeName, nodeNameErr := compat_otp.GetPodNodeName(oc, ns, eachPod)
			o.Expect(nodeNameErr).NotTo(o.HaveOccurred())
			podIP := getPodIPv4(oc, ns, eachPod)
			ovnkubeNodePod, ovnKubeNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
			o.Expect(ovnKubeNodePodErr).NotTo(o.HaveOccurred())
			svcEndpoint := svcEndpontDetails{
				ovnKubeNodePod: ovnkubeNodePod,
				nodeName:       nodeName,
				podIP:          podIP,
			}
			svcEndpoints = append(svcEndpoints, svcEndpoint)
		}

		compat_otp.By("Get logical route and switch on node for endpoints of both services to validate they exist on both new and old node")
		for _, eachEndpoint := range svcEndpoints {
			lsConstruct = eachEndpoint.getOVNConstruct(oc, "ls-list")
			o.Expect(lsConstruct).NotTo(o.BeEmpty())
			e2e.Logf("Logical Switch %s on node %s", lsConstruct, eachEndpoint.nodeName)
			o.Expect(eachEndpoint.getOVNLBContruct(oc, "ls-lb-list", lsConstruct)).To(o.BeTrue())
			lrConstruct = eachEndpoint.getOVNConstruct(oc, "lr-list")
			o.Expect(lrConstruct).NotTo(o.BeEmpty())
			e2e.Logf("Logical Router %s on node %s", lrConstruct, eachEndpoint.nodeName)
			o.Expect(eachEndpoint.getOVNLBContruct(oc, "lr-lb-list", lrConstruct)).To(o.BeTrue())
		}

		compat_otp.By("Validate kubernetes service is reachable from all nodes including new nodes")
		allNodes, nodeErr := compat_otp.GetAllNodes(oc)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(len(allNodes)).NotTo(o.BeEquivalentTo(0))
		for i := 0; i < len(allNodes); i++ {
			output, err := compat_otp.DebugNodeWithChroot(oc, allNodes[i], "bash", "-c", "curl -s -k https://172.30.0.1/healthz --connect-timeout 5")
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, "ok")).To(o.BeTrue())
		}

	})
	// author: asood@redhat.com
	g.It("Author:asood-Longduration-NonPreRelease-High-63156-[NETWORKCUSIM] Verify the nodeport is not allocated to VIP based LoadBalancer service type. [Disruptive]", func() {
		// LoadBalancer service implementation are different on cloud provider and bare metal platform
		// https://issues.redhat.com/browse/OCPBUGS-10874 (aws and azure pending support)
		var (
			testDataDir                 = testdata.FixturePath("networking/metallb")
			loadBalancerServiceTemplate = filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
			serviceLabelKey             = "environ"
			serviceLabelValue           = "Test"
			svc_names                   = [2]string{"hello-world-cluster", "hello-world-local"}
			svc_etp                     = [2]string{"Cluster", "Local"}
			namespaces                  []string
		)
		platform := compat_otp.CheckPlatform(oc)
		e2e.Logf("platform %s", platform)
		if !(strings.Contains(platform, "gcp")) {
			g.Skip("Skip for non-supported platorms!")
		}
		masterNodes, err := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Get first namespace and create another")
		ns := oc.Namespace()
		namespaces = append(namespaces, ns)
		oc.SetupProject()
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		var desiredMode string
		origMode := getOVNGatewayMode(oc)
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				switchOVNGatewayMode(oc, origMode)
			}
		}()
		g.By("Validate services in original gateway mode " + origMode)
		for j := 0; j < 2; j++ {
			for i := 0; i < 2; i++ {
				svcName := svc_names[i] + "-" + strconv.Itoa(j)
				g.By("Create a service " + svc_names[i] + " with ExternalTrafficPolicy " + svc_etp[i])
				svc := loadBalancerServiceResource{
					name:                          svcName,
					namespace:                     namespaces[i],
					externaltrafficpolicy:         svc_etp[i],
					labelKey:                      serviceLabelKey,
					labelValue:                    serviceLabelValue,
					allocateLoadBalancerNodePorts: false,
					template:                      loadBalancerServiceTemplate,
				}
				result := createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
				o.Expect(result).To(o.BeTrue())

				g.By("Check LoadBalancer service status")
				err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
				o.Expect(err).NotTo(o.HaveOccurred())
				g.By("Get LoadBalancer service IP")
				svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
				g.By("Validate service")
				result = validateService(oc, masterNodes[0], svcIP)
				o.Expect(result).To(o.BeTrue())
				g.By("Check nodePort is not assigned to service")
				nodePort := getLoadBalancerSvcNodePort(oc, svc.namespace, svc.name)
				o.Expect(nodePort).To(o.BeEmpty())
			}
			if j == 0 {
				g.By("Change the shared gateway mode to local gateway mode")
				if origMode == "local" {
					desiredMode = "shared"
				} else {
					desiredMode = "local"
				}
				e2e.Logf("Cluster is currently on gateway mode %s", origMode)
				e2e.Logf("Desired mode is %s", desiredMode)

				switchOVNGatewayMode(oc, desiredMode)
				g.By("Validate services in modified gateway mode " + desiredMode)
			}
		}

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-65796-[NETWORKCUSIM] Recreated service should have correct load_balancer nb entries for same name load_balancer. [Serial]", func() {
		// From customer bug https://issues.redhat.com/browse/OCPBUGS-11716
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		)

		compat_otp.By("Get namespace ")
		ns := oc.Namespace()

		compat_otp.By("create hello pod in namespace")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, ns, pod1.name)

		ipStack := checkIPStackType(oc)
		var podIPv6, podIPv4 string
		if ipStack == "dualstack" {
			podIPv6, podIPv4 = getPodIP(oc, ns, pod1.name)
		} else if ipStack == "ipv6single" {
			podIPv6, _ = getPodIP(oc, ns, pod1.name)
		} else {
			podIPv4, _ = getPodIP(oc, ns, pod1.name)
		}

		compat_otp.By("Create a test service which is in front of the above pods")
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

		if ipStack == "dualstack" {
			svc.ipFamilyPolicy = "PreferDualStack"
		} else {
			svc.ipFamilyPolicy = "SingleStack"
		}
		svc.createServiceFromParams(oc)

		compat_otp.By("Check service status")
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("Get service IP")
		var svcIP6, svcIP4, clusterVIP string
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			svcIP6, svcIP4 = getSvcIP(oc, svc.namespace, svc.servicename)
		} else {
			svcIP4, _ = getSvcIP(oc, svc.namespace, svc.servicename)
		}
		e2e.Logf("ipstack type: %s, SVC's IPv4: %s, SVC's IPv6: %s", ipStack, svcIP4, svcIP6)

		compat_otp.By("Check nb loadbalancer entries")
		ovnPod := getOVNKMasterOVNkubeNode(oc)
		o.Expect(ovnPod).ShouldNot(o.BeEmpty())
		e2e.Logf("\n ovnKMasterPod: %v\n", ovnPod)
		lbCmd := fmt.Sprintf("ovn-nbctl --column vip find load_balancer name=Service_%s/%s_TCP_cluster", ns, svc.servicename)
		lbOutput, err := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lbCmd)
		e2e.Logf("\nlbOutput: %s\n", lbOutput)
		o.Expect(err).NotTo(o.HaveOccurred())
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			clusterVIP = fmt.Sprintf("\"[%s]:%s\"=\"[%s]:%s\"", svcIP6, "27017", podIPv6, "8080")
			o.Expect(lbOutput).Should(o.ContainSubstring(clusterVIP))

		}
		if ipStack == "dualstack" || ipStack == "ipv4single" {
			clusterVIP = fmt.Sprintf("\"%s:%s\"=\"%s:%s\"", svcIP4, "27017", podIPv4, "8080")
			o.Expect(lbOutput).Should(o.ContainSubstring(clusterVIP))
		}

		compat_otp.By("Delete svc")
		removeResource(oc, true, true, "service", svc.servicename, "-n", ns)

		compat_otp.By("Manually add load_balancer entry in nb with same name as previous one.")
		// no need to defer to remove, as this will be overrided by following service recreated.
		var lbCmdAdd string
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			lbCmdAdd = fmt.Sprintf("ovn-nbctl lb-add \"Service_%s/%s_TCP_cluster\" [%s]:%s [%s]:%s", ns, svc.servicename, svcIP6, "27017", podIPv6, "8080")
			_, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lbCmdAdd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		if ipStack == "dualstack" || ipStack == "ipv4single" {
			lbCmdAdd = fmt.Sprintf("ovn-nbctl lb-add \"Service_%s/%s_TCP_cluster\" %s:%s %s:%s", ns, svc.servicename, svcIP4, "27017", podIPv4, "8080")
			_, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lbCmdAdd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Recreate svc")
		svc.createServiceFromParams(oc)
		svcOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("Get service IP again")
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			svcIP6, svcIP4 = getSvcIP(oc, svc.namespace, svc.servicename)
		} else {
			svcIP4, _ = getSvcIP(oc, svc.namespace, svc.servicename)
		}
		e2e.Logf("ipstack type: %s, recreated SVC's IPv4: %s, SVC's IPv6: %s", ipStack, svcIP4, svcIP6)

		compat_otp.By("No error logs")
		podlogs, getLogsErr := oc.AsAdmin().Run("logs").Args(ovnPod, "-n", "openshift-ovn-kubernetes", "-c", "ovnkube-controller", "--since", "90s").Output()
		o.Expect(getLogsErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(podlogs, "failed to ensure service")).ShouldNot(o.BeTrue())

		compat_otp.By("Check nb load_balancer entries again!")
		lbOutput, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lbCmd)
		e2e.Logf("\nlbOutput after SVC recreated: %s\n", lbOutput)
		o.Expect(err).NotTo(o.HaveOccurred())
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			clusterVIP = fmt.Sprintf("\"[%s]:%s\"=\"[%s]:%s\"", svcIP6, "27017", podIPv6, "8080")
			o.Expect(lbOutput).Should(o.ContainSubstring(clusterVIP))

		}
		if ipStack == "dualstack" || ipStack == "ipv4single" {
			clusterVIP = fmt.Sprintf("\"%s:%s\"=\"%s:%s\"", svcIP4, "27017", podIPv4, "8080")
			o.Expect(lbOutput).Should(o.ContainSubstring(clusterVIP))
		}

		compat_otp.By("Validate service")
		CurlPod2SvcPass(oc, ns, ns, pod1.name, svc.servicename)
	})

	// author: asood@redhat.com
	g.It("Author:asood-High-46015-[FdpOvnOvs] [NETWORKCUSIM] Verify traffic to outside the cluster redirected when OVN is used and NodePort service is configured.", func() {
		// Customer bug https://bugzilla.redhat.com/show_bug.cgi?id=1946696
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		)

		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		compat_otp.By("1. Get list of worker nodes")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough node available, need at least two nodes for the test, skip the case!!")
		}

		compat_otp.By("2. Get namespace ")
		ns := oc.Namespace()

		compat_otp.By("3. Create a hello pod in ns")
		pod := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod.createPingPodNode(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		compat_otp.By("4. Create a nodePort type service fronting the above pod")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "NodePort",
			ipFamilyPolicy:        "",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "", //This no value parameter will be ignored
			template:              genericServiceTemplate,
		}
		if ipStackType == "dualstack" {
			svc.ipFamilyPolicy = "PreferDualStack"
		} else {
			svc.ipFamilyPolicy = "SingleStack"
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "service", svc.servicename, "-n", svc.namespace)
			}
		}()
		svc.createServiceFromParams(oc)
		compat_otp.By("5. Get NodePort at which service listens.")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6. Validate external traffic to node port is redirected.")
		CurlNodePortPass(oc, nodeList.Items[1].Name, nodeList.Items[0].Name, nodePort)
		curlCmd := fmt.Sprintf("curl -4 -v http://www.google.de:%s --connect-timeout 5", nodePort)
		resp, err := compat_otp.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "/bin/bash", "-c", curlCmd)
		if (err != nil) || (resp != "") {
			o.Expect(strings.Contains(resp, "Hello OpenShift")).To(o.BeFalse())
		}
	})
	//asood@redhat.com
	g.It("Author:asood-NonPreRelease-Longduration-Critical-63301-[FdpOvnOvs] [NETWORKCUSIM] Kube's API intermitent timeout via sdn or internal services from nodes or pods using hostnetwork. [Disruptive]", func() {
		// From customer bug https://issues.redhat.com/browse/OCPBUGS-5828
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			hostNetworkPodTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-hostnetwork-specific-node-template.yaml")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		)
		//The test can run on the platforms that have nodes in same subnet as the hostnetworked pod backed service is accessible only such clusters.
		//The test also adds a bad route on the node from where the service is accessed for testing purpose.
		compat_otp.By("Check the platform if it is suitable for running the test")
		platform := compat_otp.CheckPlatform(oc)
		ipStackType := checkIPStackType(oc)
		if !strings.Contains(platform, "vsphere") && !strings.Contains(platform, "baremetal") {
			g.Skip("Unsupported platform, skipping the test")
		}
		if !strings.Contains(ipStackType, "ipv4single") {
			g.Skip("Unsupported stack, skipping the test")
		}
		compat_otp.By("Get the schedulable worker nodes in ready state")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least two worker nodes")
		}

		compat_otp.By("Switch the GW mode to Local")
		origMode := getOVNGatewayMode(oc)
		desiredMode := "local"
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				switchOVNGatewayMode(oc, origMode)
			}
		}()
		switchOVNGatewayMode(oc, desiredMode)

		compat_otp.By("Get namespace ")
		ns := oc.Namespace()

		compat_otp.By("Set namespace as privileged for Hostnetworked Pods")
		compat_otp.SetNamespacePrivileged(oc, ns)
		compat_otp.By("Create pod on host network in namespace")
		pod1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			template:  hostNetworkPodTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns, pod1.name)
		compat_otp.By("Create a test service which is in front of the above pods")
		svc := genericServiceResource{
			servicename:           "test-service-63301",
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

		compat_otp.By("Get service IP")
		//nodeIP1 and nodeIP2 will be IPv6 and IPv4 respectively in case of dual stack and IPv4/IPv6 in 2nd var case of single
		_, nodeIP := getNodeIP(oc, nodeList.Items[0].Name)
		var curlCmd, addRouteCmd, delRouteCmd string

		svcIPv4 := getSvcIPv4(oc, svc.namespace, svc.servicename)
		curlCmd = fmt.Sprintf("curl -v %s:27017 --connect-timeout 5", svcIPv4)
		addRouteCmd = fmt.Sprintf("route add %s gw 127.0.0.1 lo", nodeIP)
		delRouteCmd = fmt.Sprintf("route delete %s", nodeIP)

		compat_otp.By("Create another pod for pinging the service")
		pod2 := pingPodResourceNode{
			name:      "ping-hello-pod",
			namespace: ns,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, pod2.namespace, pod2.name)
		compat_otp.LabelPod(oc, pod2.namespace, pod2.name, "name-")
		compat_otp.LabelPod(oc, pod2.namespace, pod2.name, "name=ping-hello-pod")

		compat_otp.By("Validate the service from pod on cluster network")
		CurlPod2SvcPass(oc, ns, ns, pod2.name, svc.servicename)

		compat_otp.By("Validate the service from pod on host network")
		output, err := compat_otp.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "bash", "-c", curlCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "Hello OpenShift!")).To(o.BeTrue())

		compat_otp.By("Create a bad route to node where pod backing the service is running, on the host from where service is accessed ")

		defer compat_otp.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "/bin/bash", "-c", delRouteCmd)
		_, err = compat_otp.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "/bin/bash", "-c", addRouteCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Validate the service from pod on cluster network to verify it fails")
		CurlPod2SvcFail(oc, ns, ns, pod2.name, svc.servicename)

		compat_otp.By("Validate the service from pod on host network to verify it fails")
		output, err = compat_otp.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "bash", "-c", curlCmd)
		if (err != nil) || (output != "") {
			o.Expect(strings.Contains(output, "Hello OpenShift!")).To(o.BeFalse())
		}
		compat_otp.By("Delete the route that was added")
		_, err = compat_otp.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "/bin/bash", "-c", delRouteCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-High-71385-[NETWORKCUSIM]OVNK only choose LB endpoints from ready pods unless there are only terminating pods still in serving state left to choose.", func() {

		// For customer bug https://issues.redhat.com/browse/OCPBUGS-24363
		// OVNK choose LB endpoints in the following sequence:
		// 1. when there is/are pods in Ready state, ovnk ONLY choose endpoints of ready pods
		// 2. When there is/are no ready pods, ovnk choose endpoints that terminating + serving endpoints

		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod-with-special-lifecycle.yaml")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")

		compat_otp.By("1.Get namespace \n")
		ns := oc.Namespace()

		compat_otp.By("2. Create test pods and scale test pods to 5 \n")
		createResourceFromFile(oc, ns, testPodFile)
		err := oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=5", "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, ns, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "Not all test pods with label name=test-pods are ready")

		compat_otp.By("3. Create a service in front of the above test pods \n")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "test-pods",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "", //This no value parameter will be ignored
			template:              genericServiceTemplate,
		}

		ipStack := checkIPStackType(oc)
		if ipStack == "dualstack" {
			svc.ipFamilyPolicy = "PreferDualStack"
		} else {
			svc.ipFamilyPolicy = "SingleStack"
		}
		svc.createServiceFromParams(oc)

		compat_otp.By("4. Check OVN service lb status \n")
		svcOutput, svcErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename).Output()
		o.Expect(svcErr).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("5. Get IP for the OVN service lb \n")
		var svcIPv6, svcIPv4, podIPv6, podIPv4 string
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			svcIPv6, svcIPv4 = getSvcIP(oc, svc.namespace, svc.servicename)
		} else {
			svcIPv4, _ = getSvcIP(oc, svc.namespace, svc.servicename)
		}
		e2e.Logf("On this %s cluster, IP for service IP are svcIPv6: %s,  svcIPv4: %s", ipStack, svcIPv6, svcIPv4)

		compat_otp.By("6. Check OVN service lb endpoints in northdb, it should include all running backend test pods \n")
		allPods, getPodErr := compat_otp.GetAllPodsWithLabel(oc, ns, "name=test-pods")
		o.Expect(getPodErr).NotTo(o.HaveOccurred())
		o.Expect(len(allPods)).NotTo(o.BeEquivalentTo(0))

		var expectedEndpointsv6, expectedEndpointsv4 []string
		for _, eachPod := range allPods {
			if ipStack == "dualstack" {
				podIPv6, podIPv4 = getPodIP(oc, ns, eachPod)
				expectedEndpointsv6 = append(expectedEndpointsv6, "["+podIPv6+"]:8080")
				expectedEndpointsv4 = append(expectedEndpointsv4, podIPv4+":8080")
			} else if ipStack == "ipv6single" {
				podIPv6, _ = getPodIP(oc, ns, eachPod)
				expectedEndpointsv6 = append(expectedEndpointsv6, "["+podIPv6+"]:8080")
			} else {
				podIPv4, _ = getPodIP(oc, ns, eachPod)
				expectedEndpointsv4 = append(expectedEndpointsv4, podIPv4+":8080")
			}
		}
		e2e.Logf("\n On this %s cluster, V6 endpoints of service lb are expected to be: %v\n", ipStack, expectedEndpointsv6)
		e2e.Logf("\n On this %s cluster, V4 endpoints of service lb are expected to be: %v\n", ipStack, expectedEndpointsv4)

		// check service lb endpoints in northdb on each node's ovnkube-pod
		nodeList, nodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList)).NotTo(o.BeEquivalentTo(0))

		var endpointsv6, endpointsv4 []string
		var epErr error
		for _, eachNode := range nodeList {
			if ipStack == "dualstack" || ipStack == "ipv6single" {
				endpointsv6, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, "\\["+svcIPv6+"\\]:27017")
				e2e.Logf("\n Got V6 endpoints of service lb for node %s : %v\n", eachNode, expectedEndpointsv6)
				o.Expect(epErr).NotTo(o.HaveOccurred())
				o.Expect(unorderedEqual(endpointsv6, expectedEndpointsv6)).Should(o.BeTrue(), fmt.Sprintf("V6 service lb endpoints on node %sdo not match expected endpoints!", eachNode))
			}
			if ipStack == "dualstack" || ipStack == "ipv4single" {
				endpointsv4, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, svcIPv4+":27017")
				e2e.Logf("\n Got V4 endpoints of service lb for node %s : %v\n", eachNode, expectedEndpointsv4)
				o.Expect(epErr).NotTo(o.HaveOccurred())
				o.Expect(unorderedEqual(endpointsv4, expectedEndpointsv4)).Should(o.BeTrue(), fmt.Sprintf("V4 service lb endpoints on node %sdo not match expected endpoints!", eachNode))
			}
		}

		compat_otp.By("7. Scale test pods down to 2 \n")
		scaleErr := oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=2", "-n", ns).Execute()
		o.Expect(scaleErr).NotTo(o.HaveOccurred())

		var terminatingPods []string
		o.Eventually(func() bool {
			terminatingPods = getAllPodsWithLabelAndCertainState(oc, ns, "name=test-pods", "Terminating")
			return len(terminatingPods) == 3
		}, "30s", "5s").Should(o.BeTrue(), "Test pods did not scale down to 2")
		e2e.Logf("\n terminatingPods: %v\n", terminatingPods)

		var expectedCleanedUpEPsv6, expectedCleanedUpEPsv4, expectedRemindedEPsv6, expectedRemindedEPsv4, actualFinalEPsv6, actualFinalEPsv4 []string
		for _, eachPod := range terminatingPods {
			if ipStack == "dualstack" {
				podIPv6, podIPv4 = getPodIP(oc, ns, eachPod)
				expectedCleanedUpEPsv6 = append(expectedCleanedUpEPsv6, "["+podIPv6+"]:8080")
				expectedCleanedUpEPsv4 = append(expectedCleanedUpEPsv4, podIPv4+":8080")
			} else if ipStack == "ipv6single" {
				podIPv6, _ = getPodIP(oc, ns, eachPod)
				expectedCleanedUpEPsv6 = append(expectedCleanedUpEPsv6, "["+podIPv6+"]:8080")
			} else {
				podIPv4, _ = getPodIP(oc, ns, eachPod)
				expectedCleanedUpEPsv4 = append(expectedCleanedUpEPsv4, podIPv4+":8080")
			}
		}
		e2e.Logf("\n On this %s cluster, V6 endpoints of service lb are expected to be cleaned up: %v\n", ipStack, expectedCleanedUpEPsv6)
		e2e.Logf("\n On this %s cluster, V4 endpoints of service lb are expected to be cleaned up: %v\n", ipStack, expectedCleanedUpEPsv4)

		runningPods := getAllPodsWithLabelAndCertainState(oc, ns, "name=test-pods", "Running")
		o.Expect(len(runningPods)).To(o.BeEquivalentTo(2))
		e2e.Logf("\n runningPods: %v\n", runningPods)

		for _, eachPod := range runningPods {
			if ipStack == "dualstack" {
				podIPv6, podIPv4 = getPodIP(oc, ns, eachPod)
				expectedRemindedEPsv6 = append(expectedRemindedEPsv6, "["+podIPv6+"]:8080")
				expectedRemindedEPsv4 = append(expectedRemindedEPsv4, podIPv4+":8080")
			} else if ipStack == "ipv6single" {
				podIPv6, _ = getPodIP(oc, ns, eachPod)
				expectedRemindedEPsv6 = append(expectedRemindedEPsv6, "["+podIPv6+"]:8080")
			} else {
				podIPv4, _ = getPodIP(oc, ns, eachPod)
				expectedRemindedEPsv4 = append(expectedRemindedEPsv4, podIPv4+":8080")
			}
		}
		e2e.Logf("\n On this %s cluster, V6 endpoints of service lb are expected to remind: %v\n", ipStack, expectedRemindedEPsv6)
		e2e.Logf("\n On this %s cluster, V4 endpoints of service lb are expected to remind: %v\n", ipStack, expectedRemindedEPsv4)

		compat_otp.By("8. Check lb-list entries in northdb again in each node's ovnkube-node pod, only Ready pods' endpoints reminded in service lb endpoints \n")
		for _, eachNode := range nodeList {
			if ipStack == "dualstack" || ipStack == "ipv6single" {
				actualFinalEPsv6, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, "\\["+svcIPv6+"\\]:27017")
				e2e.Logf("\n\n After scale-down to 2, V6 endpoints from lb-list output on node %s northdb: %v\n\n", eachNode, actualFinalEPsv6)
				o.Expect(epErr).NotTo(o.HaveOccurred())
				o.Expect(unorderedEqual(actualFinalEPsv6, expectedRemindedEPsv6)).Should(o.BeTrue(), fmt.Sprintf("After scale-down, V6 service lb endpoints on node %s do not match expected endpoints!", eachNode))
			}
			if ipStack == "dualstack" || ipStack == "ipv4single" {
				actualFinalEPsv4, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, svcIPv4+":27017")
				o.Expect(epErr).NotTo(o.HaveOccurred())
				e2e.Logf("\n\n After scale-down to 2, V4 endpoints from lb-list output on node %s northdb: %v\n\n", eachNode, actualFinalEPsv4)
				o.Expect(unorderedEqual(actualFinalEPsv4, expectedRemindedEPsv4)).Should(o.BeTrue(), fmt.Sprintf("After scale-down, V4 service lb endpoints on node %s do not match expected endpoints!", eachNode))
			}
			// Verify terminating pods' endpoints are not in final service lb endpoints
			if ipStack == "dualstack" || ipStack == "ipv6single" {
				for _, ep := range expectedCleanedUpEPsv6 {
					o.Expect(isValueInList(ep, actualFinalEPsv6)).ShouldNot(o.BeTrue(), fmt.Sprintf("After scale-down, terminating pod's V6 endpoint %s is not cleaned up from V6 service lb endpoint", ep))
				}
			}
			if ipStack == "dualstack" || ipStack == "ipv4single" {
				for _, ep := range expectedCleanedUpEPsv4 {
					o.Expect(isValueInList(ep, actualFinalEPsv4)).ShouldNot(o.BeTrue(), fmt.Sprintf("After scale-down, terminating pod's V4 endpoint %s is not cleaned up from V4 service lb endpoint", ep))
				}
			}
		}

		compat_otp.By("9. Wait for all three terminating pods from step 7-8 to disappear so that only two running pods are left\n")
		o.Eventually(func() bool {
			allPodsWithLabel := getPodName(oc, ns, "name=test-pods")
			runningPods = getAllPodsWithLabelAndCertainState(oc, ns, "name=test-pods", "Running")
			return len(runningPods) == len(allPodsWithLabel)
		}, "180s", "10s").Should(o.BeTrue(), "Terminating pods did not disappear after waiting enough time")

		compat_otp.By("10. Scale test pods down to 0 \n")
		scaleErr = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=0", "-n", ns).Execute()
		o.Expect(scaleErr).NotTo(o.HaveOccurred())

		o.Eventually(func() bool {
			terminatingPods = getAllPodsWithLabelAndCertainState(oc, ns, "name=test-pods", "Terminating")
			return len(terminatingPods) == 2
		}, "30s", "5s").Should(o.BeTrue(), "Test pods did not scale down to 0")
		e2e.Logf("\n terminatingPods: %v\n", terminatingPods)

		compat_otp.By("11. Check lb-list entries in northdb again in each node's ovnkube-node pod, verify that the two terminating but serving pods reminded in service lb endpoints \n")

		// expectedRemindedEPv4 or expectedRemindedEPv6 or both are still expected in NBDB for a little while,
		// that is because these two pods transition from Running state to terminating but serving state and there is no other running pod available
		for _, eachNode := range nodeList {
			if ipStack == "dualstack" || ipStack == "ipv6single" {
				actualFinalEPsv6, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, "\\["+svcIPv6+"\\]:27017")
				e2e.Logf("\n\n After scale-down to 0, V6 endpoints from lb-list output on node %s northdb: %v\n\n", eachNode, actualFinalEPsv6)
				o.Expect(epErr).NotTo(o.HaveOccurred())
				o.Expect(unorderedEqual(actualFinalEPsv6, expectedRemindedEPsv6)).Should(o.BeTrue(), fmt.Sprintf("After scale-down, V6 service lb endpoints on node %s do not match expected endpoints!", eachNode))
			}
			if ipStack == "dualstack" || ipStack == "ipv4single" {
				actualFinalEPsv4, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, svcIPv4+":27017")
				o.Expect(epErr).NotTo(o.HaveOccurred())
				e2e.Logf("\n\n After scale-down to 0, V4 endpoints from lb-list output on node %s northdb: %v\n\n", eachNode, actualFinalEPsv4)
				o.Expect(unorderedEqual(actualFinalEPsv4, expectedRemindedEPsv4)).Should(o.BeTrue(), fmt.Sprintf("After scale-down, V4 service lb endpoints on node %s do not match expected endpoints!", eachNode))
			}
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-High-37033-[NETWORKCUSIM] ExternalVM access cluster through externalIP. [Disruptive]", func() {

		// This is for https://bugzilla.redhat.com/show_bug.cgi?id=1900118 and https://bugzilla.redhat.com/show_bug.cgi?id=1890270

		buildPruningBaseDir := testdata.FixturePath("networking")
		externalIPServiceTemplate := filepath.Join(buildPruningBaseDir, "externalip_service1-template.yaml")
		externalIPPodTemplate := filepath.Join(buildPruningBaseDir, "externalip_pod-template.yaml")
		var workers, nonExternalIPNodes []string
		var proxyHost, RDUHost, intf string

		if !(isPlatformSuitable(oc)) {
			g.Skip("These cases can only be run on networking team's private RDU clusters, skip for other envrionment!!!")
		}
		workers = excludeSriovNodes(oc)
		if len(workers) < 2 {
			g.Skip("Not enough nodes, need minimal 2 nodes on RDU for the test, skip the case!!")
		}
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || strings.Contains(msg, "sriov.openshift-qe.sdn.com") {
			proxyHost = "10.8.1.181"
			RDUHost = "openshift-qe-028.lab.eng.rdu2.redhat.com"
			intf = "sriovbm"
		}
		if err != nil || strings.Contains(msg, "offload.openshift-qe.sdn.com") {
			proxyHost = "10.8.1.179"
			RDUHost = "openshift-qe-026.lab.eng.rdu2.redhat.com"
			intf = "offloadbm"
		}

		compat_otp.By("1. Get namespace, create an externalIP pod in it\n")
		ns := oc.Namespace()
		pod1 := externalIPPod{
			name:      "externalip-pod",
			namespace: ns,
			template:  externalIPPodTemplate,
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "pod", pod1.name, "-n", pod1.namespace)
			}
		}()

		pod1.createExternalIPPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("2.Find another node, get its host CIDR, and one unused IP in its subnet \n")
		externalIPPodNode, err := compat_otp.GetPodNodeName(oc, pod1.namespace, pod1.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(externalIPPodNode).NotTo(o.Equal(""))
		e2e.Logf("ExternalIP pod is on node: %s", externalIPPodNode)

		for _, node := range workers {
			if node != externalIPPodNode {
				nonExternalIPNodes = append(nonExternalIPNodes, node)
			}
		}
		e2e.Logf("\n nonExternalIPNodes are: %v\n", nonExternalIPNodes)

		sub := getEgressCIDRsForNode(oc, nonExternalIPNodes[0])
		freeIPs := findUnUsedIPsOnNodeOrFail(oc, nonExternalIPNodes[0], sub, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		compat_otp.By("4.Patch update network.config with the host CIDR to enable externalIP \n")
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				patchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{}}}}")
			}
		}()
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				patchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{\"allowedCIDRs\":[]}}}}")
			}
		}()
		patchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{\"allowedCIDRs\":[\""+sub+"\"]}}}}")

		compat_otp.By("5.Create an externalIP service with the unused IP address obtained above as externalIP\n")
		svc := externalIPService{
			name:       "service-unsecure",
			namespace:  ns,
			externalIP: freeIPs[0],
			template:   externalIPServiceTemplate,
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
			}
		}()
		parameters := []string{"--ignore-unknown-parameters=true", "-f", svc.template, "-p", "NAME=" + svc.name, "EXTERNALIP=" + svc.externalIP}
		compat_otp.ApplyNsResourceFromTemplate(oc, svc.namespace, parameters...)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.name).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.name))

		g.By("Get the Node IP from any node, add a static route on the test runner host to assist the test")
		nodeIP := getNodeIPv4(oc, ns, nonExternalIPNodes[0])
		ipRouteDeleteCmd := "ip route delete " + svc.externalIP
		defer sshRunCmd(RDUHost, "root", ipRouteDeleteCmd)
		ipRouteAddCmd := "ip route add " + svc.externalIP + " via " + nodeIP + " dev " + intf
		err = sshRunCmd(proxyHost, "root", ipRouteAddCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6.Validate the externalIP service from external of the cluster (from test runner)\n")
		svc4URL := net.JoinHostPort(svc.externalIP, "27017")
		svcChkCmd := fmt.Sprintf("curl -H 'Cache-Control: no-cache' -x 'http://%s:8888' %s --connect-timeout 5", proxyHost, svc4URL)
		e2e.Logf("\n svcChkCmd: %v\n", svcChkCmd)
		output, curlErr := exec.Command("bash", "-c", svcChkCmd).Output()
		o.Expect(curlErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(string(output), "Hello OpenShift")).Should(o.BeTrue(), "The externalIP service is not reachable as expected")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-High-43492-[NETWORKCUSIM] ExternalIP for node that has secondary IP. [Disruptive]", func() {

		// This is for bug https://bugzilla.redhat.com/show_bug.cgi?id=1959798

		buildPruningBaseDir := testdata.FixturePath("networking")
		externalIPServiceTemplate := filepath.Join(buildPruningBaseDir, "externalip_service1-template.yaml")
		externalIPPodTemplate := filepath.Join(buildPruningBaseDir, "externalip_pod-template.yaml")
		intf := "br-ex"
		var workers, nonExternalIPNodes []string
		var proxyHost string

		platform := compat_otp.CheckPlatform(oc)
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || strings.Contains(msg, "sriov.openshift-qe.sdn.com") {
			platform = "rdu1"
			proxyHost = "10.8.1.181"
		}
		if err != nil || strings.Contains(msg, "offload.openshift-qe.sdn.com") {
			platform = "rdu2"
			proxyHost = "10.8.1.179"
		}

		if strings.Contains(platform, "rdu1") || strings.Contains(platform, "rdu2") {
			workers = excludeSriovNodes(oc)
			if len(workers) < 2 {
				g.Skip("Not enough nodes, need minimal 2 nodes on RDU for the test, skip the case!!")
			}
		} else {
			nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
			o.Expect(err).NotTo(o.HaveOccurred())

			// for other non-RDU platforms, need minimal 3 nodes for the test
			if len(nodeList.Items) < 3 {
				g.Skip("Not enough worker nodes for this test, skip the case!!")
			}
			for _, node := range nodeList.Items {
				workers = append(workers, node.Name)
			}
		}

		compat_otp.By("1. Get namespace, create an externalIP pod in it\n")
		ns := oc.Namespace()
		pod1 := externalIPPod{
			name:      "externalip-pod",
			namespace: ns,
			template:  externalIPPodTemplate,
		}
		pod1.createExternalIPPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("2.Find another node, get its host CIDR, and one unused IP in its subnet \n")
		externalIPPodNode, err := compat_otp.GetPodNodeName(oc, pod1.namespace, pod1.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(externalIPPodNode).NotTo(o.Equal(""))
		e2e.Logf("ExternalIP pod is on node: %s", externalIPPodNode)

		for _, node := range workers {
			if node != externalIPPodNode {
				nonExternalIPNodes = append(nonExternalIPNodes, node)
			}
		}
		e2e.Logf("\n nonExternalIPNodes are: %v\n", nonExternalIPNodes)

		sub := getEgressCIDRsForNode(oc, nonExternalIPNodes[0])
		freeIPs := findUnUsedIPsOnNodeOrFail(oc, nonExternalIPNodes[0], sub, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		_, hostIPwithPrefix := getIPv4AndIPWithPrefixForNICOnNode(oc, nonExternalIPNodes[0], intf)
		prefix := strings.Split(hostIPwithPrefix, "/")[1]
		e2e.Logf("\n On host %s, prefix of the host ip address: %v\n", nonExternalIPNodes[0], prefix)

		compat_otp.By(fmt.Sprintf("3. Add secondary IP %s to br-ex on the node %s", freeIPs[0]+"/"+prefix, nonExternalIPNodes[0]))
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				delIPFromInferface(oc, nonExternalIPNodes[0], freeIPs[0], intf)
			}
		}()
		addIPtoInferface(oc, nonExternalIPNodes[0], freeIPs[0]+"/"+prefix, intf)

		compat_otp.By("4.Patch update network.config with the host CIDR to enable externalIP \n")
		original, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("network/cluster", "-ojsonpath={.spec.externalIP}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		patch := `[{"op": "replace", "path": "/spec/externalIP", "value": ` + original + `}]`
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("patch").Args("network/cluster", "-p", patch, "--type=json").Execute()
			}
		}()
		patchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{\"allowedCIDRs\":[\""+sub+"\"]}}}}")

		compat_otp.By("5.Create an externalIP service with the unused IP address obtained above as externalIP\n")
		svc := externalIPService{
			name:       "service-unsecure",
			namespace:  ns,
			externalIP: freeIPs[0],
			template:   externalIPServiceTemplate,
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
			}
		}()
		parameters := []string{"--ignore-unknown-parameters=true", "-f", svc.template, "-p", "NAME=" + svc.name, "EXTERNALIP=" + svc.externalIP}
		compat_otp.ApplyNsResourceFromTemplate(oc, svc.namespace, parameters...)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.name).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.name))

		// For RDU, curl the externalIP service from test runner through proxy
		// For other platforms, since it is hard to get external host on same subnet of the secondary IP, we use another non-externalIP node as simulated test enviornment to validate
		compat_otp.By("6.Validate the externalIP service\n")
		svc4URL := net.JoinHostPort(svc.externalIP, "27017")
		var host string
		if platform == "rdu1" || platform == "rdu2" {
			compat_otp.By(fmt.Sprintf("On %s,  use test runner to validate the externalIP service", platform))
			host = proxyHost
		} else {
			compat_otp.By(fmt.Sprintf("On %s,  use another non-externalIP node to validate the externalIP service", platform))
			host = nonExternalIPNodes[1]
		}
		checkSvcErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
			if validateService(oc, host, svc4URL) {
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, "The externalIP service is not reachable as expected")

		compat_otp.By("7.Check OVN-KUBE-EXTERNALIP iptables chain is updated correctly\n")
		for _, node := range workers {
			output, err := compat_otp.DebugNodeWithChroot(oc, node, "/bin/bash", "-c", "iptables -n -v -t nat -L OVN-KUBE-EXTERNALIP")
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, svc.externalIP)).Should(o.BeTrue(), fmt.Sprintf("OVN-KUBE-EXTERNALIP iptables chain was not updated correctly on node %s", node))
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-24672-ExternalIP configured from autoAssignCIDRs. [Disruptive]", func() {

		// Skip on HyperShift hosted cluster because network/cluster resource cannot be modified directly
		if compat_otp.IsHypershiftHostedCluster(oc) {
			g.Skip("This test is not suitable to run on hosted cluster, skip on hosted cluster.")
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")

		platform := compat_otp.CheckPlatform(oc)
		e2e.Logf("platform %s", platform)
		acceptedPlatform := strings.Contains(platform, "gcp") || strings.Contains(platform, "azure")
		if !acceptedPlatform || checkDisconnect(oc) {
			g.Skip("Test cases should be run on connected GCP, Azure, skip for other platforms or disconnected cluster!!")
		}
		// skip if no spec.publicZone specified in dns.config
		// the private cluster will be skipped as well
		// refer to https://issues.redhat.com/browse/OCPQE-22704
		dnsPublicZone, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("dns.config/cluster", "-ojsonpath={.spec.publicZone}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if dnsPublicZone == "" {
			g.Skip("Skip for the platforms that no dns publicZone specified")
		}

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		if len(nodeList.Items) < 2 {
			g.Skip("Not enough nodes, need 2 nodes for the test, skip the case!!")
		}

		compat_otp.By("1. Get namespace\n")
		ns := oc.Namespace()

		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "LoadBalancer",
			ipFamilyPolicy:        "SingleStack",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "Cluster",
			template:              genericServiceTemplate,
		}

		// For GCP/Azure, create a loadbalancer service first to get LB service's LB ip address, then derive its subnet to be used in step 3,
		compat_otp.By("2. For public cloud platform, create a loadBalancer service first\n")
		svc.createServiceFromParams(oc)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("3. Create a test pod\n")
		pod := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod.createPingPodNode(oc)
		waitPodReady(oc, ns, pod.name)

		compat_otp.By("4. For GCP/Azure, get LB's ip address\n")
		svcExternalIP := getLBSVCIP(oc, svc.namespace, svc.servicename)
		e2e.Logf("Got externalIP service IP: %v", svcExternalIP)
		o.Expect(svcExternalIP).NotTo(o.BeEmpty())

		compat_otp.By("5. Derive LB's subnet from its IP address\n")
		ingressLBIP := net.ParseIP(svcExternalIP)
		if ingressLBIP == nil {
			g.Skip("Did not get valid IP address for the host of LB service, skip the rest of test!!")
		}
		mask := net.CIDRMask(24, 32) // Assuming /24 subnet mask
		subnet := ingressLBIP.Mask(mask).String() + "/24"
		e2e.Logf("LB's subnet: %v", subnet)

		compat_otp.By("6. Patch update network.config with subnet obtained above to enable autoAssignCIDR for externalIP\n")
		original, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("network/cluster", "-ojsonpath={.spec.externalIP}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		patch := `[{"op": "replace", "path": "/spec/externalIP", "value": ` + original + `}]`
		defer oc.AsAdmin().WithoutNamespace().Run("patch").Args("network/cluster", "-p", patch, "--type=json").Execute()
		patchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"autoAssignCIDRs\":[\""+subnet+"\"]}}}")
		patchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{\"allowedCIDRs\":[\""+subnet+"\"]}}}}")

		// Wait a little for autoAssignCIDR to take effect
		time.Sleep(10 * time.Second)

		compat_otp.By("7.Curl the externalIP service from test runner\n")
		svc4URL := net.JoinHostPort(svcExternalIP, "27017")
		svcChkCmd := fmt.Sprintf("curl  %s --connect-timeout 30", svc4URL)
		e2e.Logf("\n svcChkCmd: %v\n", svcChkCmd)
		checkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 30*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err1 := exec.Command("bash", "-c", svcChkCmd).Output()
			if err1 != nil {
				e2e.Logf("got err:%v, and try next round", err1)
				return false, nil
			}
			o.Expect(strings.Contains(string(output), "Hello OpenShift")).Should(o.BeTrue(), "The externalIP service is not reachable as expected")
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Fail to curl the externalIP service from test runner %s", svc4URL))
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-High-74601-Verify traffic and OVNK LB endpoints in nbdb for LoadBalancer Service when externalTrafficPolicy is set to Cluster.[Serial]", func() {

		// For customer bug https://issues.redhat.com/browse/OCPBUGS-24363
		// OVNK choose LB endpoints in the following sequence:
		// 1. when there is/are pods in Ready state, ovnk ONLY choose endpoints of ready pods
		// 2. When there is/are no ready pods, ovnk choose endpoints that terminating + serving endpoints

		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod-with-special-lifecycle.yaml")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")

		platform := compat_otp.CheckPlatform(oc)

		scheduleableNodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		acceptedPlatform := strings.Contains(platform, "gcp") || strings.Contains(platform, "azure")
		if !acceptedPlatform || len(scheduleableNodeList.Items) < 2 {
			g.Skip("Test cases should be run on GCP or Azure cluster with ovn network plugin, minimal 2 nodes are required, skip for others that do not meet the test requirement")
		}

		compat_otp.By("1. Get namespace, create 2 test pods in it, create a service in front of the test pods \n")
		ns := oc.Namespace()
		createResourceFromFile(oc, ns, testPodFile)
		err = waitForPodWithLabelReady(oc, ns, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "Not all test pods with label name=test-pods are ready")

		compat_otp.By("2. Create a service in front of the above test pods \n")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "test-pods",
			serviceType:           "LoadBalancer",
			ipFamilyPolicy:        "SingleStack",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "Cluster",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.servicename))

		compat_otp.By("3. Get IP for the OVN service lb \n")
		var svcIPv4, podIPv4, curlSVC4ChkCmd string
		svcIPv4, _ = getSvcIP(oc, svc.namespace, svc.servicename)
		curlSVC4ChkCmd = fmt.Sprintf("for i in {1..10}; do curl %s --connect-timeout 5 ; sleep 2;echo ;done", net.JoinHostPort(svcIPv4, "27017"))
		e2e.Logf("IP for service IP: %s", svcIPv4)

		compat_otp.By("4. Before scale down test pods, check OVN service lb endpoints in northdb and traffic at endpoints \n")
		compat_otp.By("4.1. Check OVN service lb endpoints in northdb, it should include all running backend test pods \n")
		allPods, getPodErr := compat_otp.GetAllPodsWithLabel(oc, ns, "name=test-pods")
		o.Expect(getPodErr).NotTo(o.HaveOccurred())
		o.Expect(len(allPods)).NotTo(o.BeEquivalentTo(0))

		var expectedEndpointsv4 []string
		podNodeNames := make(map[string]string)
		podIPv4s := make(map[string]string)
		for _, eachPod := range allPods {
			nodeName, getNodeErr := compat_otp.GetPodNodeName(oc, ns, eachPod)
			o.Expect(getNodeErr).NotTo(o.HaveOccurred())
			podNodeNames[eachPod] = nodeName
			podIPv4, _ = getPodIP(oc, ns, eachPod)
			podIPv4s[eachPod] = podIPv4
			expectedEndpointsv4 = append(expectedEndpointsv4, podIPv4+":8080")

		}
		e2e.Logf("\n V4 endpoints of service lb are expected to be: %v\n", expectedEndpointsv4)

		// check service lb endpoints in northdb on each node's ovnkube-pod
		nodeList, nodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList)).NotTo(o.BeEquivalentTo(0))

		var endpointsv4 []string
		var epErr error
		for _, eachNode := range nodeList {
			endpointsv4, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, svcIPv4+":27017")
			e2e.Logf("\n Got V4 endpoints of service lb for node %s : %v\n", eachNode, expectedEndpointsv4)
			o.Expect(epErr).NotTo(o.HaveOccurred())
			o.Expect(unorderedEqual(endpointsv4, expectedEndpointsv4)).Should(o.BeTrue(), fmt.Sprintf("V4 service lb endpoints on node %sdo not match expected endpoints!", eachNode))

		}

		compat_otp.By("4.2. Verify all running pods get traffic \n")
		var channels [2]chan string
		// Initialize each channel in the array
		for i := range channels {
			channels[i] = make(chan string)
		}

		compat_otp.By(" Start tcpdump on each pod's node")
		for i, pod := range allPods {
			go func(i int, pod string) {
				defer g.GinkgoRecover()
				tcpdumpCmd := fmt.Sprintf(`timeout 60s tcpdump -c 4 -nneep -i any "(dst port 8080) and (dst %s)"`, podIPv4s[pod])
				outputTcpdump, _ := oc.AsAdmin().WithoutNamespace().Run("debug").Args("-n", "default", "node/"+podNodeNames[pod], "--", "bash", "-c", tcpdumpCmd).Output()
				channels[i] <- outputTcpdump
			}(i, pod)
		}
		// add sleep time to let the ping action happen later after tcpdump is enabled.
		time.Sleep(5 * time.Second)

		compat_otp.By(" Curl the externalIP service from test runner\n")
		output, curlErr := exec.Command("bash", "-c", curlSVC4ChkCmd).Output()
		o.Expect(curlErr).NotTo(o.HaveOccurred())

		for i, pod := range allPods {
			receivedMsg := <-channels[i]
			e2e.Logf(" at step 4.2, tcpdumpOutput for node %s is \n%s\n\n", podNodeNames[pod], receivedMsg)
			o.Expect(strings.Contains(receivedMsg, podIPv4s[pod])).Should(o.BeTrue())
		}
		o.Expect(strings.Contains(string(output), "Hello OpenShift")).Should(o.BeTrue(), "The externalIP service is not reachable as expected")

		compat_otp.By("5. Scale test pods down to 1 \n")
		scaleErr := oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=1", "-n", ns).Execute()
		o.Expect(scaleErr).NotTo(o.HaveOccurred())

		allPods = allPods[:0]
		var terminatingPods []string
		o.Eventually(func() bool {
			terminatingPods = getAllPodsWithLabelAndCertainState(oc, ns, "name=test-pods", "Terminating")
			return len(terminatingPods) == 1
		}, "30s", "5s").Should(o.BeTrue(), "Test pods did not scale down to 1")
		e2e.Logf("\n terminatingPods: %v\n", terminatingPods)
		allPods = append(allPods, terminatingPods[0])

		var expectedCleanedUpEPsv4, expectedRemindedEPsv4, actualFinalEPsv4 []string
		for _, eachPod := range terminatingPods {
			expectedCleanedUpEPsv4 = append(expectedCleanedUpEPsv4, podIPv4s[eachPod]+":8080")
		}
		e2e.Logf("\n V4 endpoints of service lb are expected to be cleaned up: %v\n", expectedCleanedUpEPsv4)

		runningPods := getAllPodsWithLabelAndCertainState(oc, ns, "name=test-pods", "Running")
		o.Expect(len(runningPods)).To(o.BeEquivalentTo(1))
		e2e.Logf("\n runningPods: %v\n", runningPods)
		allPods = append(allPods, runningPods[0])

		for _, eachPod := range runningPods {
			expectedRemindedEPsv4 = append(expectedRemindedEPsv4, podIPv4s[eachPod]+":8080")
		}
		e2e.Logf("\n V4 endpoints of service lb are expected to remind: %v\n", expectedRemindedEPsv4)

		compat_otp.By("5.1. Check lb-list entries in northdb again in each node's ovnkube-node pod, only Ready pods' endpoints reminded in service lb endpoints \n")
		for _, eachNode := range nodeList {
			actualFinalEPsv4, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, svcIPv4+":27017")
			o.Expect(epErr).NotTo(o.HaveOccurred())
			e2e.Logf("\n\n After scale-down to 2, V4 endpoints from lb-list output on node %s northdb: %v\n\n", eachNode, actualFinalEPsv4)
			o.Expect(unorderedEqual(actualFinalEPsv4, expectedRemindedEPsv4)).Should(o.BeTrue(), fmt.Sprintf("After scale-down, V4 service lb endpoints on node %s do not match expected endpoints!", eachNode))

			// Verify terminating pods' endpoints are not in final service lb endpoints
			for _, ep := range expectedCleanedUpEPsv4 {
				o.Expect(isValueInList(ep, actualFinalEPsv4)).ShouldNot(o.BeTrue(), fmt.Sprintf("After scale-down, terminating pod's V4 endpoint %s is not cleaned up from V4 service lb endpoint", ep))
			}
		}

		compat_otp.By("5.2 Verify only the running pod receives traffic, the terminating pod does not receive traffic \n")
		for i, pod := range allPods {
			go func(i int, pod string) {
				defer g.GinkgoRecover()
				tcpdumpCmd := fmt.Sprintf(`timeout 60s tcpdump -c 4 -nneep -i any "(dst port 8080) and (dst %s)"`, podIPv4s[pod])
				outputTcpdump, _ := oc.AsAdmin().WithoutNamespace().Run("debug").Args("-n", "default", "node/"+podNodeNames[pod], "--", "bash", "-c", tcpdumpCmd).Output()
				channels[i] <- outputTcpdump
			}(i, pod)
		}

		// add sleep time to let the ping action happen later after tcpdump is enabled.
		time.Sleep(5 * time.Second)
		output, curlErr = exec.Command("bash", "-c", curlSVC4ChkCmd).Output()
		o.Expect(curlErr).NotTo(o.HaveOccurred())

		for i, pod := range allPods {
			receivedMsg := <-channels[i]
			e2e.Logf(" at step 5.2, tcpdumpOutput for node %s is \n%s\n\n", podNodeNames[pod], receivedMsg)
			if pod == terminatingPods[0] {
				o.Expect(strings.Contains(receivedMsg, "0 packets captured")).Should(o.BeTrue())
			} else {
				o.Expect(strings.Contains(receivedMsg, podIPv4s[pod])).Should(o.BeTrue())
			}
		}
		o.Expect(strings.Contains(string(output), "Hello OpenShift")).Should(o.BeTrue(), "The externalIP service is not reachable as expected")

		compat_otp.By("5.3. Wait for terminating pod from step 7 to disappear so that there is only one running pod left\n")
		o.Eventually(func() bool {
			allPodsWithLabel := getPodName(oc, ns, "name=test-pods")
			runningPods = getAllPodsWithLabelAndCertainState(oc, ns, "name=test-pods", "Running")
			return len(runningPods) == len(allPodsWithLabel)
		}, "180s", "10s").Should(o.BeTrue(), "Terminating pods did not disappear after waiting enough time")

		compat_otp.By("6. Scale test pods down to 0 \n")
		scaleErr = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=0", "-n", ns).Execute()
		o.Expect(scaleErr).NotTo(o.HaveOccurred())

		o.Eventually(func() bool {
			terminatingPods = getAllPodsWithLabelAndCertainState(oc, ns, "name=test-pods", "Terminating")
			return len(terminatingPods) == 1
		}, "30s", "5s").Should(o.BeTrue(), "Test pods did not scale down to 0")
		e2e.Logf("\n terminatingPods: %v\n", terminatingPods)

		compat_otp.By("6.1. Check lb-list entries in northdb again in each node's ovnkube-node pod, verify that the two terminating but serving pods reminded in service lb endpoints \n")

		// expectedRemindedEPv4 are still expected in NBDB for a little while,
		// that is because the last pod transition from Running state to terminating but serving state and there is no other running pod available
		for _, eachNode := range nodeList {
			actualFinalEPsv4, epErr = getLBListEndpointsbySVCIPPortinNBDB(oc, eachNode, svcIPv4+":27017")
			o.Expect(epErr).NotTo(o.HaveOccurred())
			e2e.Logf("\n\n After scale-down to 0, V4 endpoints from lb-list output on node %s northdb: %v\n\n", eachNode, actualFinalEPsv4)
			o.Expect(unorderedEqual(actualFinalEPsv4, expectedRemindedEPsv4)).Should(o.BeTrue(), fmt.Sprintf("After scale-down, V4 service lb endpoints on node %s do not match expected endpoints!", eachNode))
		}

		compat_otp.By("6.2 Verify that the terminating pod still receives traffic because there is no other running pod\n")
		for i, pod := range terminatingPods {
			go func(i int, pod string) {
				defer g.GinkgoRecover()
				tcpdumpCmd := fmt.Sprintf(`timeout 60s tcpdump -c 4 -nneep -i any "(dst port 8080) and (dst %s)"`, podIPv4s[pod])
				outputTcpdump, _ := oc.AsAdmin().WithoutNamespace().Run("debug").Args("-n", "default", "node/"+podNodeNames[pod], "--", "bash", "-c", tcpdumpCmd).Output()
				channels[i] <- outputTcpdump
			}(i, pod)
		}

		// add sleep time to let the ping action happen later after tcpdump is enabled.
		time.Sleep(5 * time.Second)
		output, curlErr = exec.Command("bash", "-c", curlSVC4ChkCmd).Output()
		o.Expect(curlErr).NotTo(o.HaveOccurred())

		for i, pod := range terminatingPods {
			receivedMsg := <-channels[i]
			e2e.Logf(" at step 6.2, tcpdumpOutput for node %s is \n%s\n\n", podNodeNames[pod], receivedMsg)
			o.Expect(strings.Contains(receivedMsg, podIPv4s[pod])).Should(o.BeTrue())
		}
		o.Expect(strings.Contains(string(output), "Hello OpenShift")).Should(o.BeTrue(), "The externalIP service is not reachable as expected")
	})
	g.It("Author:asood-Medium-75424-[NETWORKCUSIM] SessionAffinity does not work after scaling down the Pods", func() {
		//Bug: https://issues.redhat.com/browse/OCPBUGS-28604
		var (
			buildPruningBaseDir        = testdata.FixturePath("networking")
			servicesBaseDir            = testdata.FixturePath("networking/services")
			pingPodTemplate            = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			sessionAffinitySvcTemplate = filepath.Join(servicesBaseDir, "sessionaffinity-svc-template.yaml")
			customResponsePodTemplate  = filepath.Join(servicesBaseDir, "custom-response-pod-template.yaml")
			labelKey                   = "name"
			labelVal                   = "openshift"
			testID                     = "75424"
			curlCmdList                = []string{}
		)

		ns := oc.Namespace()

		compat_otp.By(fmt.Sprintf("Create pods that will serve as the endpoints for Session Affinity enabled service in %s project", ns))
		customResponsePod := customResponsePodResource{
			name:        " ",
			namespace:   ns,
			labelKey:    labelKey,
			labelVal:    labelVal,
			responseStr: " ",
			template:    customResponsePodTemplate,
		}
		for i := 0; i < 3; i++ {
			customResponsePod.name = "hello-pod-" + strconv.Itoa(i)
			customResponsePod.responseStr = "Hello from " + customResponsePod.name
			customResponsePod.createCustomResponsePod(oc)
			waitPodReady(oc, ns, customResponsePod.name)
		}

		compat_otp.By(fmt.Sprintf("Create a test pod in %s", ns))
		testPod := pingPodResource{
			name:      "test-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		testPod.createPingPod(oc)
		waitPodReady(oc, ns, testPod.name)

		svc := sessionAffinityServiceResource{
			name:           " ",
			namespace:      ns,
			ipFamilyPolicy: " ",
			selLabelKey:    labelKey,
			SelLabelVal:    labelVal,
			template:       sessionAffinitySvcTemplate,
		}

		ipStackType := checkIPStackType(oc)
		compat_otp.By(fmt.Sprintf("Create a service with session affinity enabled on %s cluster", ipStackType))
		if ipStackType == "dualstack" {
			svc.name = "dualstacksvc-" + testID
			svc.ipFamilyPolicy = "PreferDualStack"
			defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
			svc.createSessionAffiniltyService(oc)
			svcOutput, svcErr := oc.AsAdmin().Run("get").Args("service", "-n", svc.namespace).Output()
			o.Expect(svcErr).NotTo(o.HaveOccurred())
			o.Expect(svcOutput).To(o.ContainSubstring(svc.name))
			serviceIPv6, serviceIPv4 := getSvcIP(oc, svc.namespace, svc.name)
			curlCmdList = append(curlCmdList, fmt.Sprintf("curl %s:8080 --connect-timeout 5", serviceIPv4))
			curlCmdList = append(curlCmdList, fmt.Sprintf("curl -g -6 [%s]:8080 --connect-timeout 5", serviceIPv6))

		} else {
			svc.ipFamilyPolicy = "SingleStack"
			svc.name = "singlestack-" + ipStackType + "-svc-" + testID
			defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
			svc.createSessionAffiniltyService(oc)
			svcOutput, svcErr := oc.AsAdmin().Run("get").Args("service", "-n", svc.namespace).Output()
			o.Expect(svcErr).NotTo(o.HaveOccurred())
			o.Expect(svcOutput).To(o.ContainSubstring(svc.name))

			if ipStackType == "ipv6single" {
				serviceIPv6, _ := getSvcIP(oc, svc.namespace, svc.name)
				curlCmdList = append(curlCmdList, fmt.Sprintf("curl -g -6 [%s]:8080 --connect-timeout 5", serviceIPv6))
			} else {
				serviceIPv4 := getSvcIPv4(oc, svc.namespace, svc.name)
				curlCmdList = append(curlCmdList, fmt.Sprintf("curl %s:8080 --connect-timeout 5", serviceIPv4))
			}
		}

		for _, curlCmd := range curlCmdList {
			compat_otp.By(fmt.Sprintf("Test session affinity using request '%s' cluster", curlCmd))
			e2e.Logf("Send first request to service")
			firstResponse1, requestErr := e2eoutput.RunHostCmd(ns, testPod.name, curlCmd)
			o.Expect(requestErr).NotTo(o.HaveOccurred())
			e2e.Logf("Request response: %s", firstResponse1)
			for i := 0; i < 9; i++ {
				requestResp, requestErr := e2eoutput.RunHostCmd(ns, testPod.name, curlCmd)
				o.Expect(requestErr).NotTo(o.HaveOccurred())
				o.Expect(strings.Contains(requestResp, firstResponse1)).To(o.BeTrue())

			}
			e2e.Logf("Find the pod serving request and delete it")
			respStr := strings.Split(strings.TrimRight(firstResponse1, "\n"), " ")
			o.Expect(len(respStr)).To(o.BeEquivalentTo(3))
			o.Expect(respStr[2]).NotTo(o.BeEmpty())
			removeResource(oc, true, true, "pod", respStr[2], "-n", ns)

			e2e.Logf(fmt.Sprintf("Send first request to service after deleting the previously serving pod %s", respStr[2]))
			firstResponse2, requestErr := e2eoutput.RunHostCmd(ns, testPod.name, curlCmd)
			o.Expect(requestErr).NotTo(o.HaveOccurred())
			e2e.Logf("Request response: %s", firstResponse2)
			o.Expect(strings.Contains(firstResponse2, firstResponse1)).To(o.BeFalse())
			for i := 0; i < 9; i++ {
				requestResp, requestErr := e2eoutput.RunHostCmd(ns, testPod.name, curlCmd)
				o.Expect(requestErr).NotTo(o.HaveOccurred())
				o.Expect(strings.Contains(requestResp, firstResponse2)).To(o.BeTrue())

			}

		}

	})

	g.It("Author:meinli-Critical-78262-Validate pod/host to hostnetwork pod/nodeport with hostnetwork pod backend on same/diff workers", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			hostNetworkPodTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-hostnetwork-specific-node-template.yaml")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			ipFamilyPolicy         = "SingleStack"
		)

		platform := compat_otp.CheckPlatform(oc)
		if !(strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "none")) {
			g.Skip("These cases can only be run on networking team's private RDU BM cluster, vSphere and IPI/UPI BM, skip for other platforms!!!")
		}

		compat_otp.By("1. Get namespace, master and worker node")
		ns := oc.Namespace()
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This case requires 3 nodes, but the cluster has less than three nodes")
		}
		o.Expect(err).NotTo(o.HaveOccurred())
		//Required for hostnetwork pod
		compat_otp.By("Set namespace as privileged for Hostnetworked Pods")
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("2. Create hostnetwork pod in ns")
		hostpod := pingPodResourceNode{
			name:      "hostnetwork-pod",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			template:  hostNetworkPodTemplate,
		}
		hostpod.createPingPodNode(oc)
		waitPodReady(oc, ns, hostpod.name)

		compat_otp.By("3. Create nodeport service with hostnetwork pod backend when externalTrafficPolicy=Local")
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			ipFamilyPolicy = "PreferDualStack"
		}
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "NodePort",
			ipFamilyPolicy:        ipFamilyPolicy,
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "Local",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Create two normal pods on diff workers")
		pods := make([]pingPodResourceNode, 2)
		for i := 0; i < 2; i++ {
			pods[i] = pingPodResourceNode{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: ns,
				nodename:  nodeList.Items[i].Name,
				template:  pingPodNodeTemplate,
			}
			pods[i].createPingPodNode(oc)
			waitPodReady(oc, ns, pods[i].name)

			defer compat_otp.LabelPod(oc, ns, pods[i].name, "name-")
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns, "pod", pods[i].name, fmt.Sprintf("name=hello-pod-%d", i), "--overwrite=true").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("5. Validate host to pod on same/diff workers")
		CurlNode2PodPass(oc, pods[0].nodename, ns, pods[0].name)
		CurlNode2PodPass(oc, pods[1].nodename, ns, pods[0].name)

		compat_otp.By("6. Validate pod to host network pod on same/diff workers")
		CurlPod2PodPass(oc, ns, pods[0].name, ns, hostpod.name)
		CurlPod2PodPass(oc, ns, pods[1].name, ns, hostpod.name)

		compat_otp.By("7. Validate pod to nodePort with hostnetwork pod backend on same/diff workers when externalTrafficPolicy=Local")
		CurlPod2NodePortPass(oc, ns, pods[0].name, nodeList.Items[0].Name, nodePort)
		CurlPod2NodePortFail(oc, ns, pods[0].name, nodeList.Items[1].Name, nodePort)

		compat_otp.By("8. Validate host to nodePort with hostnetwork pod backend on same/diff workers when externalTrafficPolicy=Local")
		CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[0].Name, nodePort)
		CurlNodePortFail(oc, nodeList.Items[2].Name, nodeList.Items[1].Name, nodePort)

		compat_otp.By("9. Validate pod to nodeport with hostnetwork pod backend on diff workers when externalTrafficPolicy=Cluster")
		compat_otp.By("9.1 Create nodeport service with externalTrafficPolicy=Cluster in ns1 and ns2")
		removeResource(oc, true, true, "svc", "test-service", "-n", ns)
		svc.externalTrafficPolicy = "Cluster"
		svc.createServiceFromParams(oc)
		nodePort, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("9.2 Validate pod to nodePort with hostnetwork pod backend on same/diff workers when externalTrafficPolicy=Cluster")
		CurlPod2NodePortPass(oc, ns, pods[0].name, nodeList.Items[0].Name, nodePort)
		CurlPod2NodePortPass(oc, ns, pods[0].name, nodeList.Items[1].Name, nodePort)

		compat_otp.By("10. Validate host to nodePort with hostnetwork pod backend on same/diff workers when externalTrafficPolicy=Cluster")
		CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[0].Name, nodePort)
		CurlNodePortPass(oc, nodeList.Items[2].Name, nodeList.Items[1].Name, nodePort)
	})

})
