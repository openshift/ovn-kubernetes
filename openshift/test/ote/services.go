package ote

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = Describe("[sig-network] SDN services", func() {
	defer GinkgoRecover()

	var oc = exutil.NewCLI("networking-services")

	BeforeEach(func() {
		networkType := oteutils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote] 68920-kubernetes service route is recoverable if it's cleared", Label("Disruptive"), func() {
		// Regression coverage for OCPBUGS-1715: the route to the service subnet on
		// a node must be restored automatically by ovnkube-node after being deleted.
		nodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "node-role.kubernetes.io/worker,kubernetes.io/os=linux", "-o", "jsonpath={.items[0].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(nodeName).NotTo(o.BeEmpty(), "no linux worker node found")

		By("Get service subnets")
		svcSubnetStr, getSubnetsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("network.operator", "cluster", `-ojsonpath={.spec.serviceNetwork}`).Output()
		o.Expect(getSubnetsErr).NotTo(o.HaveOccurred())
		svcSubnets := strings.Split(strings.Trim(svcSubnetStr, "[]"), ",")

		for _, svcSubnet := range svcSubnets {
			svcSubnet := strings.Trim(svcSubnet, `"`)
			var verFlag string
			if strings.Count(svcSubnet, ":") >= 2 {
				verFlag = "-6"
			} else if strings.Count(svcSubnet, ".") >= 2 {
				verFlag = "-4"
			}

			By("Delete the service route on one of the worker nodes")
			origSvcRouteStr, getRouteErr := oteutils.DebugNode(oc, nodeName, "ip", verFlag, "route", "show", svcSubnet)
			o.Expect(getRouteErr).NotTo(o.HaveOccurred())
			e2e.Logf("original service route is: -- %s --", origSvcRouteStr)
			re := regexp.MustCompile(svcSubnet + ".*\n")
			matches := re.FindAllString(origSvcRouteStr, -1)
			o.Expect(matches).NotTo(o.BeEmpty(), "failed to find service route for subnet %s", svcSubnet)
			origSvcRoute := strings.Trim(matches[0], "\n")

			defer func() {
				svcRoute1, deferErr := oteutils.DebugNode(oc, nodeName, "ip", verFlag, "route", "show", svcSubnet)
				o.Expect(deferErr).NotTo(o.HaveOccurred())
				if !strings.Contains(svcRoute1, origSvcRoute) {
					_, _ = oteutils.DebugNode(oc, nodeName, "bash", "-c", "ip "+verFlag+" route add "+origSvcRoute)
				}
			}()

			delCmd := "ip " + verFlag + " route del " + origSvcRoute
			_, delRouteErr := oteutils.DebugNode(oc, nodeName, "bash", "-c", delCmd)
			o.Expect(delRouteErr).NotTo(o.HaveOccurred())

			By("Check the service route is restored")
			routeErr := wait.PollUntilContextTimeout(context.TODO(), 15*time.Second, 300*time.Second, true, func(_ context.Context) (bool, error) {
				svcRoute, getRouteErr1 := oteutils.DebugNode(oc, nodeName, "ip", verFlag, "route", "show", svcSubnet)
				o.Expect(getRouteErr1).NotTo(o.HaveOccurred())
				if strings.Contains(svcRoute, origSvcRoute) {
					return true, nil
				}
				e2e.Logf("Route is not restored yet, retrying")
				return false, nil
			})
			o.Expect(routeErr).NotTo(o.HaveOccurred(), fmt.Sprintf("service route %q was not restored", origSvcRoute))
		}
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote] 65796-Recreated service should have correct load_balancer nb entries for same name load_balancer", Serial, func() {
		// Regression coverage for OCPBUGS-11716: after a service is recreated, its OVN
		// northbound load_balancer entries must be correct and ovnkube-controller must
		// not log "failed to ensure service".
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")

		By("Get namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		By("Create hello pod in namespace")
		pod1 := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod1.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, ns, pod1.Name)

		ipStack := oteutils.CheckIPStackType(oc)
		var podIPv6, podIPv4 string
		if ipStack == "dualstack" {
			podIPv6, podIPv4 = oteutils.GetPodIP(oc, ns, pod1.Name)
		} else if ipStack == "ipv6single" {
			podIPv6, _ = oteutils.GetPodIP(oc, ns, pod1.Name)
		} else {
			podIPv4, _ = oteutils.GetPodIP(oc, ns, pod1.Name)
		}

		By("Create a ClusterIP service in front of the pod")
		svc := oteutils.GenericServiceResource{
			ServiceName:           "test-service",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			InternalTrafficPolicy: "Cluster",
			Template:              genericServiceTemplate,
		}
		if ipStack == "dualstack" {
			svc.IPFamilyPolicy = "PreferDualStack"
		} else {
			svc.IPFamilyPolicy = "SingleStack"
		}
		svc.CreateServiceFromParams(oc)

		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.ServiceName).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.ServiceName))

		By("Get service IP")
		var svcIP6, svcIP4, clusterVIP string
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			svcIP6, svcIP4 = oteutils.GetSvcIP(oc, ns, svc.ServiceName)
		} else {
			svcIP4, _ = oteutils.GetSvcIP(oc, ns, svc.ServiceName)
		}
		e2e.Logf("ipstack type: %s, SVC's IPv4: %s, SVC's IPv6: %s", ipStack, svcIP4, svcIP6)

		By("Check nb load_balancer entries")
		ovnPod := oteutils.GetOVNKMasterOVNkubeNode(oc)
		o.Expect(ovnPod).ShouldNot(o.BeEmpty())
		lbCmd := fmt.Sprintf("ovn-nbctl --column vip find load_balancer name=Service_%s/%s_TCP_cluster", ns, svc.ServiceName)
		lbOutput, err := oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lbCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("lbOutput: %s", lbOutput)
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			clusterVIP = fmt.Sprintf("\"[%s]:%s\"=\"[%s]:%s\"", svcIP6, "27017", podIPv6, "8080")
			o.Expect(lbOutput).Should(o.ContainSubstring(clusterVIP))
		}
		if ipStack == "dualstack" || ipStack == "ipv4single" {
			clusterVIP = fmt.Sprintf("\"%s:%s\"=\"%s:%s\"", svcIP4, "27017", podIPv4, "8080")
			o.Expect(lbOutput).Should(o.ContainSubstring(clusterVIP))
		}

		By("Delete the service")
		oteutils.RemoveResource(oc, true, true, "service", svc.ServiceName, "-n", ns)

		By("Manually add a load_balancer entry in nb with the same name as the previous one")
		var lbCmdAdd string
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			lbCmdAdd = fmt.Sprintf("ovn-nbctl lb-add \"Service_%s/%s_TCP_cluster\" [%s]:%s [%s]:%s", ns, svc.ServiceName, svcIP6, "27017", podIPv6, "8080")
			_, err = oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lbCmdAdd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		if ipStack == "dualstack" || ipStack == "ipv4single" {
			lbCmdAdd = fmt.Sprintf("ovn-nbctl lb-add \"Service_%s/%s_TCP_cluster\" %s:%s %s:%s", ns, svc.ServiceName, svcIP4, "27017", podIPv4, "8080")
			_, err = oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lbCmdAdd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		By("Recreate the service")
		svc.CreateServiceFromParams(oc)
		svcOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.ServiceName).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.ServiceName))

		By("Get service IP again")
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			svcIP6, svcIP4 = oteutils.GetSvcIP(oc, ns, svc.ServiceName)
		} else {
			svcIP4, _ = oteutils.GetSvcIP(oc, ns, svc.ServiceName)
		}
		e2e.Logf("ipstack type: %s, recreated SVC's IPv4: %s, SVC's IPv6: %s", ipStack, svcIP4, svcIP6)

		By("ovnkube-controller should not log 'failed to ensure service'")
		podlogs, getLogsErr := oc.AsAdmin().WithoutNamespace().Run("logs").Args(ovnPod, "-n", "openshift-ovn-kubernetes", "-c", "ovnkube-controller", "--since", "90s").Output()
		o.Expect(getLogsErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(podlogs, "failed to ensure service")).ShouldNot(o.BeTrue())

		By("Check nb load_balancer entries again")
		lbOutput, err = oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lbCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("lbOutput after SVC recreated: %s", lbOutput)
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			clusterVIP = fmt.Sprintf("\"[%s]:%s\"=\"[%s]:%s\"", svcIP6, "27017", podIPv6, "8080")
			o.Expect(lbOutput).Should(o.ContainSubstring(clusterVIP))
		}
		if ipStack == "dualstack" || ipStack == "ipv4single" {
			clusterVIP = fmt.Sprintf("\"%s:%s\"=\"%s:%s\"", svcIP4, "27017", podIPv4, "8080")
			o.Expect(lbOutput).Should(o.ContainSubstring(clusterVIP))
		}

		By("Validate service connectivity")
		oteutils.CurlPod2SvcPass(oc, ns, ns, pod1.Name, svc.ServiceName)
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote] 63301-Kube's API intermittent timeout via sdn or internal services from nodes or pods using hostnetwork", Label("Disruptive"), func() {
		// Regression coverage for OCPBUGS-5828. Runs on platforms whose nodes share a
		// subnet with the hostnetwork-backed service, and adds a bad route for testing.
		buildPruningBaseDir := testdata.FixturePath("networking")
		hostNetworkPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-hostnetwork-specific-node-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")

		By("Check the platform and IP stack are suitable for running the test")
		platform := oteutils.CheckPlatform(oc)
		ipStackType := oteutils.CheckIPStackType(oc)
		if !strings.Contains(platform, "vsphere") && !strings.Contains(platform, "baremetal") && !strings.Contains(platform, "none") {
			Skip("Unsupported platform, skipping the test")
		}
		if ipStackType != "ipv4single" {
			Skip("Unsupported stack, skipping the test")
		}

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			Skip("This test requires at least two worker nodes")
		}

		By("Switch the gateway mode to local")
		origMode := oteutils.GetOVNGatewayMode(oc)
		defer oteutils.SwitchOVNGatewayMode(oc, origMode)
		oteutils.SwitchOVNGatewayMode(oc, "local")

		By("Get namespace and set it privileged for hostnetwork pods")
		oc.SetupProject()
		ns := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns)

		By("Create a hostnetwork pod as the service backend")
		pod1 := oteutils.PingPodResourceNode{
			Name:      "hello-pod",
			Namespace: ns,
			Nodename:  nodeList.Items[0].Name,
			Template:  hostNetworkPodTemplate,
		}
		pod1.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, ns, pod1.Name)

		By("Create a ClusterIP service in front of the hostnetwork pod")
		svc := oteutils.GenericServiceResource{
			ServiceName:           "test-service-63301",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IPFamilyPolicy:        "SingleStack",
			InternalTrafficPolicy: "Cluster",
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.ServiceName).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.ServiceName))

		_, nodeIP := oteutils.GetNodeIP(oc, nodeList.Items[0].Name)
		svcIPv4 := oteutils.GetSvcIPv4(oc, svc.Namespace, svc.ServiceName)
		curlCmd := fmt.Sprintf("curl -v %s:27017 --connect-timeout 5", svcIPv4)
		addRouteCmd := fmt.Sprintf("route add %s gw 127.0.0.1 lo", nodeIP)
		delRouteCmd := fmt.Sprintf("route delete %s", nodeIP)

		By("Create a client pod on a different node")
		pod2 := oteutils.PingPodResourceNode{
			Name:      "ping-hello-pod",
			Namespace: ns,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}
		pod2.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, pod2.Namespace, pod2.Name)
		_ = oteutils.LabelPod(oc, pod2.Namespace, pod2.Name, "name-")
		_ = oteutils.LabelPod(oc, pod2.Namespace, pod2.Name, "name=ping-hello-pod")

		By("Validate the service from a pod on the cluster network")
		oteutils.CurlPod2SvcPass(oc, ns, ns, pod2.Name, svc.ServiceName)

		By("Validate the service from the host network")
		output, err := oteutils.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "bash", "-c", curlCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("Hello OpenShift!"))

		By("Add a bad route to the backend node on the client node")
		defer func() {
			_, _ = oteutils.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "/bin/bash", "-c", delRouteCmd)
		}()
		_, err = oteutils.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "/bin/bash", "-c", addRouteCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		By("Validate the service from a cluster-network pod now fails")
		oteutils.CurlPod2SvcFail(oc, ns, ns, pod2.Name, svc.ServiceName)

		By("Validate the service from the host network now fails")
		output, err = oteutils.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "bash", "-c", curlCmd)
		if err != nil || output != "" {
			o.Expect(output).ShouldNot(o.ContainSubstring("Hello OpenShift!"))
		}

		By("Delete the bad route")
		_, err = oteutils.DebugNodeWithChroot(oc, nodeList.Items[1].Name, "/bin/bash", "-c", delRouteCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote] 76796-Idling/Unidling services should work for UDN pods (L3/L2)", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		testDataDirUDN := testdata.FixturePath("networking", "udn")
		testSvcFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		udnNadtemplate := filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
		udnPodTemplate := filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")

		ipStackType := oteutils.CheckIPStackType(oc)

		By("Create two UDN namespaces (layer3 and layer2)")
		ns1 := oteutils.CreateNamespaceUDN(oc)
		ns2 := oteutils.CreateNamespaceUDN(oc)
		nadNS := []string{ns1, ns2}
		nadResourcename := []string{"l3-network-" + ns1, "l2-network-" + ns2}
		topo := []string{"layer3", "layer2"}

		var subnet []string
		switch ipStackType {
		case "ipv4single":
			subnet = []string{"10.150.0.0/16/24", "10.152.0.0/16"}
		case "ipv6single":
			subnet = []string{"2010:100:200::0/60", "2012:100:200::0/60"}
		default:
			subnet = []string{"10.150.0.0/16/24,2010:100:200::0/60", "10.152.0.0/16,2012:100:200::0/60"}
		}

		By("Create the primary UDN NAD in each namespace")
		for i := 0; i < 2; i++ {
			nad := oteutils.UdnNetDefResource{
				Nadname:          nadResourcename[i],
				Namespace:        nadNS[i],
				NadNetworkName:   nadResourcename[i],
				Topology:         topo[i],
				Subnet:           subnet[i],
				NetAttachDefName: nadNS[i] + "/" + nadResourcename[i],
				Role:             "primary",
				Template:         udnNadtemplate,
			}
			nad.CreateUdnNad(oc)
		}

		By("Create the test service and backend pods in each namespace")
		for i := 0; i < len(nadNS); i++ {
			oteutils.CreateResourceFromFile(oc, nadNS[i], testSvcFile)
			err := oteutils.WaitForPodWithLabelReady(oc, nadNS[i], "name=test-pods")
			o.Expect(err).NotTo(o.HaveOccurred())
			svcOutput, svcErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", nadNS[i]).Output()
			o.Expect(svcErr).NotTo(o.HaveOccurred())
			o.Expect(svcOutput).To(o.ContainSubstring("test-service"))
		}

		if ipStackType == "dualstack" {
			for i := 0; i < 2; i++ {
				oteutils.RemoveResource(oc, true, true, "service", "test-service", "-n", nadNS[i])
				svc := oteutils.GenericServiceResource{
					ServiceName:           "test-service",
					Namespace:             nadNS[i],
					Protocol:              "TCP",
					Selector:              "test-pods",
					ServiceType:           "ClusterIP",
					IPFamilyPolicy:        "PreferDualStack",
					InternalTrafficPolicy: "Cluster",
					Template:              genericServiceTemplate,
				}
				svc.CreateServiceFromParams(oc)
			}
		}

		By("Idle test-service in both namespaces")
		for _, ns := range nadNS {
			idleOutput, idleErr := oc.AsAdmin().WithoutNamespace().Run("idle").Args("-n", ns, "test-service").Output()
			o.Expect(idleErr).NotTo(o.HaveOccurred())
			o.Expect(idleOutput).To(o.ContainSubstring(fmt.Sprintf("The service \"%s/test-service\" has been marked as idled", ns)))
		}

		By("Verify the backend pods are terminated after idling")
		for _, ns := range nadNS {
			err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 60*time.Second, false, func(_ context.Context) (bool, error) {
				output, getPodErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns).Output()
				o.Expect(getPodErr).NotTo(o.HaveOccurred())
				if strings.Contains(output, "No resources found") {
					return true, nil
				}
				e2e.Logf("pods are not terminated yet, retrying")
				return false, nil
			})
			o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("pods in %s were not terminated after idling", ns))
		}

		By("Create a client UDN pod in each namespace")
		pods := make([]oteutils.UdnPodResource, 2)
		for i := 0; i < 2; i++ {
			pods[i] = oteutils.UdnPodResource{
				Name:      "hello-pod",
				Namespace: nadNS[i],
				Label:     "hello-pod",
				Template:  udnPodTemplate,
			}
			pods[i].CreateUdnPod(oc)
			oteutils.WaitPodReady(oc, pods[i].Namespace, pods[i].Name)
		}

		By("Verify the service is reachable (unidles) for layer3")
		oteutils.CurlPod2SvcPass(oc, ns1, ns1, pods[0].Name, "test-service")

		By("Verify the service is reachable (unidles) for layer2")
		oteutils.CurlPod2SvcPass(oc, ns2, ns2, pods[1].Name, "test-service")
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote] 63156-Verify the nodeport is not allocated to VIP based LoadBalancer service type", Label("Disruptive"), func() {
		// LoadBalancer service implementation differs by platform; this verifies that
		// a LoadBalancer service with allocateLoadBalancerNodePorts=false gets no
		// nodePort, in both gateway modes.
		buildPruningBaseDir := testdata.FixturePath("networking")
		loadBalancerServiceTemplate := filepath.Join(buildPruningBaseDir, "loadbalancer-svc-template.yaml")
		serviceLabelKey := "environ"
		serviceLabelValue := "Test"
		svcNames := [2]string{"hello-world-cluster", "hello-world-local"}
		svcETP := [2]string{"Cluster", "Local"}

		platform := oteutils.CheckPlatform(oc)
		if !strings.Contains(platform, "gcp") {
			Skip("Skip for non-supported platforms!")
		}
		masterNodes, err := oteutils.GetClusterNodesBy(oc, "master")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(masterNodes).NotTo(o.BeEmpty())

		By("Get first namespace and create another")
		var namespaces []string
		namespaces = append(namespaces, oc.Namespace())
		oc.SetupProject()
		namespaces = append(namespaces, oc.Namespace())

		origMode := oteutils.GetOVNGatewayMode(oc)
		defer oteutils.SwitchOVNGatewayMode(oc, origMode)

		for j := 0; j < 2; j++ {
			for i := 0; i < 2; i++ {
				svcName := fmt.Sprintf("%s-%d", svcNames[i], j)
				By(fmt.Sprintf("Create LoadBalancer service %s with ExternalTrafficPolicy %s", svcName, svcETP[i]))
				svc := oteutils.LoadBalancerServiceResource{
					Name:                          svcName,
					Namespace:                     namespaces[i],
					Protocol:                      "TCP",
					ExternalTrafficPolicy:         svcETP[i],
					LabelKey:                      serviceLabelKey,
					LabelValue:                    serviceLabelValue,
					AllocateLoadBalancerNodePorts: false,
					Template:                      loadBalancerServiceTemplate,
				}
				svc.CreateLoadBalancerService(oc)

				By("Check LoadBalancer service status")
				o.Expect(oteutils.CheckLoadBalancerSvcStatus(oc, svc.Namespace, svc.Name)).NotTo(o.HaveOccurred())

				By("Validate the service via its LoadBalancer IP")
				svcIP := oteutils.GetLoadBalancerSvcIP(oc, svc.Namespace, svc.Name)
				o.Expect(oteutils.ValidateService(oc, masterNodes[0], svcIP)).To(o.BeTrue())

				By("Check nodePort is not assigned to the service")
				o.Expect(oteutils.GetLoadBalancerSvcNodePort(oc, svc.Namespace, svc.Name)).To(o.BeEmpty())
			}
			if j == 0 {
				desiredMode := "local"
				if origMode == "local" {
					desiredMode = "shared"
				}
				By("Switch the gateway mode to " + desiredMode)
				oteutils.SwitchOVNGatewayMode(oc, desiredMode)
			}
		}
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote] 62293-Validate all the constructs are created on logical routers and logical switches for a service type loadbalancer", Label("Disruptive"), func() {
		// Regression coverage for OCPBUGS-5930: a LoadBalancer service's OVN NB
		// load_balancer entries must exist on the logical switch and gateway router
		// of every endpoint node, including nodes added after the service is created.
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")

		platform := oteutils.CheckPlatform(oc)
		if !strings.Contains(platform, "gcp") && !strings.Contains(platform, "aws") && !strings.Contains(platform, "azure") {
			Skip("Skip for non-supported auto scaling machineset platforms!")
		}

		workerNodes, err := oteutils.GetClusterNodesBy(oc, "worker")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(workerNodes).NotTo(o.BeEmpty())

		ns := oc.Namespace()

		By("Create the first backend pod")
		pod := oteutils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns,
			Nodename:  workerNodes[0],
			Template:  pingPodNodeTemplate,
		}
		pod.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, ns, pod.Name)

		By("Create a LoadBalancer service in front of the pod")
		svc := oteutils.GenericServiceResource{
			ServiceName:           "test-service",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "LoadBalancer",
			IPFamilyPolicy:        "SingleStack",
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "Cluster",
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)

		By("Create a new machineset to add nodes")
		infrastructureName := oteutils.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-62293"
		ms := oteutils.MachineSetDescription{Name: machinesetName, Replicas: 2}
		defer func() { _ = ms.DeleteMachineSet(oc) }()
		ms.CreateMachineSet(oc)
		machineNames := oteutils.GetMachineNamesFromMachineSet(oc, machinesetName)
		o.Expect(len(machineNames)).To(o.BeNumerically(">=", 1))
		nodeName0 := oteutils.GetNodeNameFromMachine(oc, machineNames[0])
		o.Expect(nodeName0).NotTo(o.BeEmpty())

		By("Create a second backend pod on the newly added node")
		pod = oteutils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns,
			Nodename:  nodeName0,
			Template:  pingPodNodeTemplate,
		}
		pod.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, ns, pod.Name)

		By("Collect backend pod endpoint details")
		var svcEndpoints []oteutils.SvcEndpointDetails
		allPods, getPodErr := oteutils.GetAllPodsWithLabel(oc, ns, "name=hello-pod")
		o.Expect(getPodErr).NotTo(o.HaveOccurred())
		o.Expect(allPods).NotTo(o.BeEmpty())
		for _, eachPod := range allPods {
			nodeName, nodeNameErr := oteutils.GetPodNodeName(oc, ns, eachPod)
			o.Expect(nodeNameErr).NotTo(o.HaveOccurred())
			podIP := oteutils.GetPodIPv4(oc, ns, eachPod)
			ovnkubeNodePod, podErr := oteutils.GetPodNameOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
			o.Expect(podErr).NotTo(o.HaveOccurred())
			svcEndpoints = append(svcEndpoints, oteutils.SvcEndpointDetails{
				OvnKubeNodePod: ovnkubeNodePod,
				NodeName:       nodeName,
				PodIP:          podIP,
			})
		}

		By("Validate logical switch and router load_balancer constructs exist for every endpoint node")
		for _, eachEndpoint := range svcEndpoints {
			lsConstruct := eachEndpoint.GetOVNConstruct(oc, "ls-list")
			o.Expect(lsConstruct).NotTo(o.BeEmpty())
			o.Expect(eachEndpoint.GetOVNLBConstruct(oc, "ls-lb-list", lsConstruct)).To(o.BeTrue())
			lrConstruct := eachEndpoint.GetOVNConstruct(oc, "lr-list")
			o.Expect(lrConstruct).NotTo(o.BeEmpty())
			o.Expect(eachEndpoint.GetOVNLBConstruct(oc, "lr-lb-list", lrConstruct)).To(o.BeTrue())
		}

		By("Validate the kubernetes service is reachable from all nodes including new ones")
		allNodes, nodeErr := oteutils.GetAllNodes(oc)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(allNodes).NotTo(o.BeEmpty())
		for _, node := range allNodes {
			output, curlErr := oteutils.DebugNodeWithChroot(oc, node, "bash", "-c", "curl -s -k https://172.30.0.1/healthz --connect-timeout 5")
			o.Expect(curlErr).NotTo(o.HaveOccurred())
			o.Expect(output).Should(o.ContainSubstring("ok"))
		}
	})
})
