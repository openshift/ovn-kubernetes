package otp

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"
	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/utils"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[sig-network][Suite:openshift/ovn-kubernetes] SDN network segmentation services", func() {
	defer g.GinkgoRecover()

	var (
		oc             = exutil.NewCLI("networking-udn")
		testDataDirUDN = testdata.FixturePath("networking/network_segmentation/udn")
	)

	g.BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP] 76017-Service should be able to access for same NAD UDN pods in different namespaces (L3/L2)", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			udnNadtemplate         = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			udnPodTemplate         = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			ipFamilyPolicy         = "SingleStack"
		)

		ipStackType := otputils.CheckIPStackType(oc)

		g.By("Get first namespace")
		var nadNS []string = make([]string, 0, 4)

		g.By("Create another 3 namespaces")
		for i := 0; i < 4; i++ {
			oc.CreateNamespaceUDN()
			nadNS = append(nadNS, oc.Namespace())
		}

		nadResourcename := []string{"l3-network-test", "l2-network-test"}
		topo := []string{"layer3", "layer3", "layer2", "layer2"}

		var subnet []string
		if ipStackType == "ipv4single" {
			subnet = []string{"10.150.0.0/16/24", "10.150.0.0/16/24", "10.152.0.0/16", "10.152.0.0/16"}
		} else {
			if ipStackType == "ipv6single" {
				subnet = []string{"2010:100:200::0/60", "2010:100:200::0/60", "2012:100:200::0/60", "2012:100:200::0/60"}
			} else {
				subnet = []string{"10.150.0.0/16/24,2010:100:200::0/60", "10.150.0.0/16/24,2010:100:200::0/60", "10.152.0.0/16,2012:100:200::0/60", "10.152.0.0/16,2012:100:200::0/60"}
				ipFamilyPolicy = "PreferDualStack"
			}
		}

		g.By("5. Create same NAD in ns1 ns2 for layer3")
		nad := make([]otputils.UdnNetDefResource, 4)
		for i := 0; i < 2; i++ {
			g.By(fmt.Sprintf("create NAD %s in namespace %s", nadResourcename[0], nadNS[i]))
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadResourcename[0],
				Namespace:        nadNS[i],
				NadNetworkName:   nadResourcename[0],
				Topology:         topo[i],
				Subnet:           subnet[i],
				NetAttachDefName: nadNS[i] + "/" + nadResourcename[0],
				Role:             "primary",
				Template:         udnNadtemplate,
			}
			nad[i].CreateUdnNad(oc)
		}

		g.By("6. Create same NAD in ns3 ns4 for layer 2")
		for i := 2; i < 4; i++ {
			g.By(fmt.Sprintf("create NAD %s in namespace %s", nadResourcename[1], nadNS[i]))
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadResourcename[1],
				Namespace:        nadNS[i],
				NadNetworkName:   nadResourcename[1],
				Topology:         topo[i],
				Subnet:           subnet[i],
				NetAttachDefName: nadNS[i] + "/" + nadResourcename[1],
				Role:             "primary",
				Template:         udnNadtemplate,
			}
			nad[i].CreateUdnNad(oc)
		}

		g.By("7. Create one pod in respective namespaces ns1,ns2,ns3,ns4")
		pod := make([]otputils.UdnPodResource, 4)
		for i := 0; i < 4; i++ {
			pod[i] = otputils.UdnPodResource{
				Name:      "hello-pod",
				Namespace: nadNS[i],
				Label:     "hello-pod",
				Template:  udnPodTemplate,
			}
			pod[i].CreateUdnPod(oc)
			otputils.WaitPodReady(oc, pod[i].Namespace, pod[i].Name)

			// add a step to check ovn-udn1 created.
			output, err := e2eoutput.RunHostCmd(pod[i].Namespace, pod[i].Name, "ip -o link show")
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).Should(o.ContainSubstring("ovn-udn1"))
		}

		g.By("8. Create service in ns2,ns4")
		svc1 := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             nadNS[1],
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        ipFamilyPolicy,
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		svc1.CreateServiceFromParams(oc)

		svc2 := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             nadNS[3],
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        ipFamilyPolicy,
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		svc2.CreateServiceFromParams(oc)
		g.By("9. Verify ClusterIP service in ns2 can be accessed from pod in ns1 for layer 3")
		otputils.CurlPod2SvcPass(oc, nadNS[0], nadNS[1], pod[0].Name, svc1.Servicename)
		g.By("10. Verify ClusterIP service in ns4 can be accessed from pod in ns3 for layer 2")
		otputils.CurlPod2SvcPass(oc, nadNS[2], nadNS[3], pod[2].Name, svc2.Servicename)
	})

	g.It("[JIRA:Networking][OTP] 76732-Validate pod2Service/nodePortService for UDN(Layer2)", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			udnCRDdualStack        = filepath.Join(testDataDirUDN, "udn_crd_layer2_dualstack_template.yaml")
			udnCRDSingleStack      = filepath.Join(testDataDirUDN, "udn_crd_layer2_singlestack_template.yaml")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			testPodFile            = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			ipFamilyPolicy         = "SingleStack"
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This test requires at least 3 worker nodes which is not fulfilled. ")
		}

		g.By("1. Obtain first namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		g.By("2. Create CRD for UDN")
		ipStackType := otputils.CheckIPStackType(oc)
		var cidr, ipv4cidr, ipv6cidr string
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::0/48"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::0/48"
				ipFamilyPolicy = "PreferDualStack"
			}
		}

		g.By("Create CRD for UDN")
		var udncrd otputils.UdnCRDResource
		if ipStackType == "dualstack" {
			udncrd = otputils.UdnCRDResource{
				Crdname:  "udn-network-76732",
				Namespace: ns1,
				Role:     "Primary",
				IPv4cidr: ipv4cidr,
				IPv6cidr: ipv6cidr,
				Template: udnCRDdualStack,
			}
			udncrd.CreateLayer2DualStackUDNCRD(oc)

		} else {
			udncrd = otputils.UdnCRDResource{
				Crdname:  "udn-network-76732",
				Namespace: ns1,
				Role:     "Primary",
				Cidr:     cidr,
				Template: udnCRDSingleStack,
			}
			udncrd.CreateLayer2SingleStackUDNCRD(oc)
		}

		g.By("3. Create a pod deployed on node0 as backend pod for service.")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod-1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("4. create a udn client pod in ns1 on different node as pod1")
		clientPod1 := otputils.PingPodResourceNode{
			Name:      "client-pod-1",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodTemplate,
		}
		clientPod1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, clientPod1.Namespace, clientPod1.Name)
		// Update label for pod2 to a different one
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns1, "pod", clientPod1.Name, "name=client-pod-1", "--overwrite=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. create a udn client pod in ns1 on same node as pod1")
		clientPod2 := otputils.PingPodResourceNode{
			Name:      "client-pod-2",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodTemplate,
		}
		clientPod2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, clientPod2.Namespace, clientPod2.Name)
		// Update label for pod3 to a different one
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns1, "pod", clientPod2.Name, "name=client-pod-2", "--overwrite=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. create a service in ns1")
		svc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             ns1,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        ipFamilyPolicy,
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)

		g.By("7. Verify ClusterIP service can be accessed from both clientPod1 and clientPod2")
		otputils.CurlPod2SvcPass(oc, ns1, ns1, clientPod1.Name, svc.Servicename)
		otputils.CurlPod2SvcPass(oc, ns1, ns1, clientPod2.Name, svc.Servicename)

		g.By("8. Create a second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()
		g.By("9. Create service and pods which are on default network.")
		otputils.CreateResourceFromFile(oc, ns2, testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns2, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPodName := otputils.GetPodName(oc, ns2, "name=test-pods")

		g.By("10. Not be able to access udn service from default network.")
		otputils.CurlPod2SvcFail(oc, ns2, ns1, testPodName[0], svc.Servicename)
		g.By("11. Not be able to access default network service from udn network.")
		otputils.CurlPod2SvcFail(oc, ns1, ns2, clientPod1.Name, "test-service")

		g.By("11. Create third namespace for udn pod")
		oc.CreateNamespaceUDN()
		ns3 := oc.Namespace()

		g.By("12. Create CRD in third namespace")
		if ipStackType == "ipv4single" {
			cidr = "10.160.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:200:200::0/48"
			} else {
				ipv4cidr = "10.160.0.0/16"
				ipv6cidr = "2010:200:200::0/48"
			}
		}
		var udncrdns3 otputils.UdnCRDResource
		if ipStackType == "dualstack" {
			udncrdns3 = otputils.UdnCRDResource{
				Crdname:  "udn-network-ds-76732-ns3",
				Namespace: ns3,
				Role:     "Primary",
				IPv4cidr: ipv4cidr,
				IPv6cidr: ipv6cidr,
				Template: udnCRDdualStack,
			}
			udncrdns3.CreateLayer2DualStackUDNCRD(oc)
		} else {
			udncrdns3 = otputils.UdnCRDResource{
				Crdname:  "udn-network-ss-76732-ns3",
				Namespace: ns3,
				Role:     "Primary",
				Cidr:     cidr,
				Template: udnCRDSingleStack,
			}
			udncrdns3.CreateLayer2SingleStackUDNCRD(oc)
		}
		err = otputils.WaitUDNCRDApplied(oc, ns3, udncrdns3.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("13. Create a udn pod in third namespace")
		otputils.CreateResourceFromFile(oc, ns3, testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns3, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPodNameNS3 := otputils.GetPodName(oc, ns3, "name=test-pods")

		g.By("14. Verify different udn network, service was isolated.")
		otputils.CurlPod2SvcFail(oc, ns3, ns1, testPodNameNS3[0], svc.Servicename)

		g.By("15.Update internalTrafficPolicy as Local for udn service in ns1.")
		patch := `[{"op": "replace", "path": "/spec/internalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", ns1, "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("15.1. Verify ClusterIP service can be accessed from pod3 which is deployed same node as service back-end pod.")
		otputils.CurlPod2SvcPass(oc, ns1, ns1, clientPod2.Name, svc.Servicename)
		g.By("15.2. Verify ClusterIP service can NOT be accessed from pod2 which is deployed different node as service back-end pod.")
		otputils.CurlPod2SvcFail(oc, ns1, ns1, clientPod1.Name, svc.Servicename)

		g.By("16. Verify nodePort service can be accessed.")
		g.By("16.1 Delete testservice from ns1")
		otputils.RemoveResource(oc, true, true, "service", "test-service", "-n", ns1)
		g.By("16.2 Create testservice with NodePort in ns1")
		svc.ServiceType = "NodePort"
		svc.CreateServiceFromParams(oc)

		g.By("16.3 From a third node, be able to access node0:nodePort")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns1, svc.Servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		thirdNode := nodeList.Items[2].Name
		o.Expect(err).NotTo(o.HaveOccurred())
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[0].Name, nodePort)
		g.By("16.4 From a third node, be able to access node1:nodePort")
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[1].Name, nodePort)
		g.By("16.5 From pod node, be able to access nodePort service")
		otputils.CurlNodePortPass(oc, nodeList.Items[0].Name, nodeList.Items[0].Name, nodePort)
		otputils.CurlNodePortPass(oc, nodeList.Items[0].Name, nodeList.Items[1].Name, nodePort)

		g.By("17.Update externalTrafficPolicy as Local for udn service in ns1.")
		patch = `[{"op": "replace", "path": "/spec/externalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", ns1, "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("17.1 From a third node, be able to access node0:nodePort")
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[0].Name, nodePort)
		g.By("17.2 From a third node, NOT be able to access node1:nodePort")
		otputils.CurlNodePortFail(oc, thirdNode, nodeList.Items[1].Name, nodePort)
	})

	g.It("[JIRA:Networking][OTP] 75942-Validate pod2Service/nodePortService for UDN(Layer3)", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			udnCRDdualStack        = filepath.Join(testDataDirUDN, "udn_crd_dualstack2_template.yaml")
			udnCRDSingleStack      = filepath.Join(testDataDirUDN, "udn_crd_singlestack_template.yaml")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			testPodFile            = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			ipFamilyPolicy         = "SingleStack"
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This test requires at least 3 worker nodes which is not fulfilled. ")
		}

		g.By("1. Obtain first namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		g.By("2. Create CRD for UDN")
		ipStackType := otputils.CheckIPStackType(oc)
		var cidr, ipv4cidr, ipv6cidr string
		var prefix, ipv4prefix, ipv6prefix int32
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
			prefix = 24
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::0/48"
				prefix = 64
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv4prefix = 24
				ipv6cidr = "2010:100:200::0/48"
				ipv6prefix = 64
				ipFamilyPolicy = "PreferDualStack"
			}
		}
		var udncrd otputils.UdnCRDResource
		if ipStackType == "dualstack" {
			udncrd = otputils.UdnCRDResource{
				Crdname:    "udn-network-ds-75942",
				Namespace:  ns1,
				Role:       "Primary",
				IPv4cidr:   ipv4cidr,
				IPv4prefix: ipv4prefix,
				IPv6cidr:   ipv6cidr,
				IPv6prefix: ipv6prefix,
				Template:   udnCRDdualStack,
			}
			udncrd.CreateUdnCRDDualStack(oc)
		} else {
			udncrd = otputils.UdnCRDResource{
				Crdname:  "udn-network-ss-75942",
				Namespace: ns1,
				Role:     "Primary",
				Cidr:     cidr,
				Prefix:   prefix,
				Template: udnCRDSingleStack,
			}
			udncrd.CreateUdnCRDSingleStack(oc)
		}
		err := otputils.WaitUDNCRDApplied(oc, ns1, udncrd.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create a pod deployed on node0 as backend pod for service.")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod-1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("4. create a udn client pod in ns1 on different node as pod1")
		pod2ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod-2",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodTemplate,
		}
		pod2ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)
		// Update label for pod2 to a different one
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns1, "pod", pod2ns1.Name, "name=hello-pod-2", "--overwrite=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. create a udn client pod in ns1 on same node as pod1")
		pod3ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod-3",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodTemplate,
		}
		pod3ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod3ns1.Namespace, pod3ns1.Name)
		// Update label for pod3 to a different one
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns1, "pod", pod3ns1.Name, "name=hello-pod-3", "--overwrite=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. create a ClusterIP service in ns1")
		svc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             ns1,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        ipFamilyPolicy,
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)

		g.By("7. Verify ClusterIP service can be accessed from both pod2 and pod3")
		otputils.CurlPod2SvcPass(oc, ns1, ns1, pod2ns1.Name, svc.Servicename)
		otputils.CurlPod2SvcPass(oc, ns1, ns1, pod3ns1.Name, svc.Servicename)

		g.By("8. Create second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()
		g.By("9. Create service and pods which are on default network.")
		otputils.CreateResourceFromFile(oc, ns2, testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns2, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPodName := otputils.GetPodName(oc, ns2, "name=test-pods")

		g.By("10. Not be able to access udn service from default network.")
		otputils.CurlPod2SvcFail(oc, ns2, ns1, testPodName[0], svc.Servicename)
		g.By("11. Not be able to access default network service from udn network.")
		otputils.CurlPod2SvcFail(oc, ns1, ns2, pod2ns1.Name, "test-service")

		g.By("11. Create third namespace for udn pod")
		oc.CreateNamespaceUDN()
		ns3 := oc.Namespace()

		g.By("12. Create CRD in third namespace")
		if ipStackType == "ipv4single" {
			cidr = "10.160.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:200:200::0/48"
				prefix = 64
			} else {
				ipv4cidr = "10.160.0.0/16"
				ipv4prefix = 24
				ipv6cidr = "2010:200:200::0/48"
				ipv6prefix = 64
			}
		}
		var udncrdns3 otputils.UdnCRDResource
		if ipStackType == "dualstack" {
			udncrdns3 = otputils.UdnCRDResource{
				Crdname:    "udn-network-ds-75942-ns3",
				Namespace:  ns3,
				Role:       "Primary",
				IPv4cidr:   ipv4cidr,
				IPv4prefix: ipv4prefix,
				IPv6cidr:   ipv6cidr,
				IPv6prefix: ipv6prefix,
				Template:   udnCRDdualStack,
			}
			udncrdns3.CreateUdnCRDDualStack(oc)
		} else {
			udncrdns3 = otputils.UdnCRDResource{
				Crdname:  "udn-network-ss-75942-ns3",
				Namespace: ns3,
				Role:     "Primary",
				Cidr:     cidr,
				Prefix:   prefix,
				Template: udnCRDSingleStack,
			}
			udncrdns3.CreateUdnCRDSingleStack(oc)
		}
		err = otputils.WaitUDNCRDApplied(oc, ns3, udncrdns3.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("13. Create a udn pod in third namespace")
		otputils.CreateResourceFromFile(oc, ns3, testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns3, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPodNameNS3 := otputils.GetPodName(oc, ns3, "name=test-pods")

		g.By("14. Verify different udn network, service was isolated.")
		otputils.CurlPod2SvcFail(oc, ns3, ns1, testPodNameNS3[0], svc.Servicename)

		g.By("15.Update internalTrafficPolicy as Local for udn service in ns1.")
		patch := `[{"op": "replace", "path": "/spec/internalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", ns1, "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("15.1. Verify ClusterIP service can be accessed from pod3 which is deployed same node as service back-end pod.")
		otputils.CurlPod2SvcPass(oc, ns1, ns1, pod3ns1.Name, svc.Servicename)
		g.By("15.2. Verify ClusterIP service can NOT be accessed from pod2 which is deployed different node as service back-end pod.")
		otputils.CurlPod2SvcFail(oc, ns1, ns1, pod2ns1.Name, svc.Servicename)

		g.By("16. Verify nodePort service can be accessed.")
		g.By("16.1 Delete testservice from ns1")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", "test-service", "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("16.2 Create testservice with NodePort in ns1")
		svc.ServiceType = "NodePort"
		svc.CreateServiceFromParams(oc)

		g.By("16.3 From a third node, be able to access node0:nodePort")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns1, svc.Servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		thirdNode := nodeList.Items[2].Name
		o.Expect(err).NotTo(o.HaveOccurred())
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[0].Name, nodePort)
		g.By("16.4 From a third node, be able to access node1:nodePort")
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[1].Name, nodePort)
		g.By("16.5 From pod node, be able to access nodePort service")
		otputils.CurlNodePortPass(oc, nodeList.Items[0].Name, nodeList.Items[0].Name, nodePort)
		otputils.CurlNodePortPass(oc, nodeList.Items[0].Name, nodeList.Items[1].Name, nodePort)

		g.By("17.Update externalTrafficPolicy as Local for udn service in ns1.")
		patch = `[{"op": "replace", "path": "/spec/externalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", ns1, "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("17.1 From a third node, be able to access node0:nodePort")
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[0].Name, nodePort)
		g.By("17.2 From a third node, NOT be able to access node1:nodePort")
		otputils.CurlNodePortFail(oc, thirdNode, nodeList.Items[1].Name, nodePort)
	})

	g.It("[JIRA:Networking][OTP] 76014-Validate LoadBalancer service for UDN pods (Layer3/Layer2)", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		udnPodTemplate := filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		udnCRDSingleStack := filepath.Join(testDataDirUDN, "udn_crd_singlestack_template.yaml")
		udnL2CRDSingleStack := filepath.Join(testDataDirUDN, "udn_crd_layer2_singlestack_template.yaml")

		platform := otputils.CheckPlatform(oc)
		e2e.Logf("platform %s", platform)
		acceptedPlatform := strings.Contains(platform, "gcp") || strings.Contains(platform, "azure") || strings.Contains(platform, "aws")
		if !acceptedPlatform {
			g.Skip("Test cases should be run on connected AWS,GCP, Azure, skip for other platforms or disconnected cluster!!")
		}
		if otputils.CheckIPStackType(oc) == "ipv6single" {
			g.Skip("LoadBalancer UDN service test is only parameterized for IPv4 single-stack today")
		}

		g.By("1. Get namespaces and create a new namespace ")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		nadNS := []string{ns1, ns2}

		g.By("2. Create CRD for UDN for layer 3")
		udncrd := otputils.UdnCRDResource{
			Crdname:  "udn-network-l3-76014",
			Namespace: nadNS[0],
			Role:     "Primary",
			Cidr:     "10.200.0.0/16",
			Prefix:   24,
			Template: udnCRDSingleStack,
		}
		udncrd.CreateUdnCRDSingleStack(oc)
		err := otputils.WaitUDNCRDApplied(oc, nadNS[0], udncrd.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create CRD for UDN for layer 2")
		udnl2crd := otputils.UdnCRDResource{
			Crdname:  "udn-network-l2-76014",
			Namespace: nadNS[1],
			Role:     "Primary",
			Cidr:     "10.210.0.0/16",
			Template: udnL2CRDSingleStack,
		}
		udnl2crd.CreateLayer2SingleStackUDNCRD(oc)
		err = otputils.WaitUDNCRDApplied(oc, nadNS[1], udnl2crd.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Create a pod for service per namespace.")
		pod := make([]otputils.UdnPodResource, 2)
		for i := 0; i < 2; i++ {
			pod[i] = otputils.UdnPodResource{
				Name:      "hello-pod",
				Namespace: nadNS[i],
				Label:     "hello-pod",
				Template:  udnPodTemplate,
			}
			pod[i].CreateUdnPod(oc)
			otputils.WaitPodReady(oc, pod[i].Namespace, pod[i].Name)
		}

		g.By("5. Create LoadBalancer service.")
		svc := make([]otputils.GenericServiceResource, 2)
		for i := 0; i < 2; i++ {
			svc[i] = otputils.GenericServiceResource{
				Servicename:           "test-service",
				Namespace:             nadNS[i],
				Protocol:              "TCP",
				Selector:              "hello-pod",
				ServiceType:           "LoadBalancer",
				IpFamilyPolicy:        "SingleStack",
				InternalTrafficPolicy: "Cluster",
				ExternalTrafficPolicy: "Cluster",
				Template:              genericServiceTemplate,
			}
			svc[i].CreateServiceFromParams(oc)
			svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", nadNS[i], svc[i].Servicename).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(svcOutput).Should(o.ContainSubstring(svc[i].Servicename))
		}

		g.By("6. Get LoadBalancer service URL.")
		var svcExternalIP [2]string
		for i := 0; i < 2; i++ {
			if platform == "aws" {
				svcExternalIP[i] = otputils.GetLBSVCHostname(oc, nadNS[i], svc[i].Servicename)
			} else {
				svcExternalIP[i] = otputils.GetLBSVCIP(oc, nadNS[i], svc[i].Servicename)
			}
			e2e.Logf("Got externalIP service IP: %v from namespace %s", svcExternalIP[i], nadNS[i])
			o.Expect(svcExternalIP[i]).NotTo(o.BeEmpty())
		}

		g.By("7.Curl the service from test runner\n")
		var svcURL [2]string
		for i := 0; i < 2; i++ {
			svcURL[i] = net.JoinHostPort(svcExternalIP[i], "27017")
			e2e.Logf("\n svcURL: %v\n", svcURL[i])

			err = wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
				output, err1 := exec.Command("curl", svcURL[i], "--connect-timeout", "30").Output()
				if err1 != nil || !strings.Contains(string(output), "Hello OpenShift") {
					e2e.Logf("got err:%v, and try next round", err1)
					return false, nil
				}
				e2e.Logf("The external service %v access passed!", svcURL[i])
				return true, nil
			})
			o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Fail to curl the externalIP service from test runner %s", svcURL[i]))
		}
	})

	g.It("[JIRA:Networking][OTP] 78767-Validate service for CUDN(Layer3)", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			testPodFile            = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			ipFamilyPolicy         = "SingleStack"
			key                    = "test.cudn.layer3"
			crdName                = "cudn-network-78767"
			crdName2               = "cudn-network-78767-2"
			values                 = []string{"value-78767-1", "value-78767-2"}
			values2                = []string{"value2-78767-1", "value2-78767-2"}
			cudnNS                 = []string{}
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This test requires at least 3 worker nodes which is not fulfilled. ")
		}

		g.By("1. Create CRD for CUDN")
		ipStackType := otputils.CheckIPStackType(oc)
		var cidr, ipv4cidr, ipv6cidr string
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::0/60"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::0/60"
				ipFamilyPolicy = "PreferDualStack"
			}
		}

		defer otputils.RemoveResource(oc, true, true, "clusteruserdefinednetwork", crdName)
		_, err := otputils.CreateCUDNCRD(oc, key, crdName, ipv4cidr, ipv6cidr, cidr, "layer3", values)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("2. Create 2 namespaces and add related values.")
		for i := 0; i < 2; i++ {
			oc.CreateNamespaceUDN()
			cudnNS = append(cudnNS, oc.Namespace())
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS[i], fmt.Sprintf("%s-", key)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS[i], fmt.Sprintf("%s=%s", key, values[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("3. Create a pod deployed on node0 as backend pod for service.")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod-1",
			Namespace: cudnNS[0],
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodTemplate,
		}
		defer otputils.RemoveResource(oc, true, true, "pod", pod1ns1.Name, "-n", pod1ns1.Namespace)
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("4. create a udn client pod in ns1")
		pod2ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod-2",
			Namespace: cudnNS[0],
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodTemplate,
		}
		defer otputils.RemoveResource(oc, true, true, "pod", pod2ns1.Name, "-n", pod2ns1.Namespace)
		pod2ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)
		// Update label for pod2 to a different one
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", cudnNS[0], "pod", pod2ns1.Name, "name=hello-pod-2", "--overwrite=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. create a udn client pod in ns2. ")
		pod1ns2 := otputils.PingPodResourceNode{
			Name:      "hello-pod-3",
			Namespace: cudnNS[1],
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodTemplate,
		}
		defer otputils.RemoveResource(oc, true, true, "pod", pod1ns2.Name, "-n", pod1ns2.Namespace)
		pod1ns2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns2.Namespace, pod1ns2.Name)

		g.By("6. create a ClusterIP service in ns1")
		svc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             cudnNS[0],
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        ipFamilyPolicy,
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)

		g.By("7. Verify ClusterIP service can be accessed from both pod2 in ns1 and pod3 in ns2")
		otputils.CurlPod2SvcPass(oc, cudnNS[0], cudnNS[0], pod2ns1.Name, svc.Servicename)
		otputils.CurlPod2SvcPass(oc, cudnNS[1], cudnNS[0], pod1ns2.Name, svc.Servicename)

		g.By("8. Create third namespace")
		oc.SetupProject()
		cudnNS = append(cudnNS, oc.Namespace())

		g.By("9. Create service and pods which are on default network.")
		otputils.CreateResourceFromFile(oc, cudnNS[2], testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, cudnNS[2], "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPodName := otputils.GetPodName(oc, cudnNS[2], "name=test-pods")

		g.By("10. Not be able to access cudn service from default network.")
		otputils.CurlPod2SvcFail(oc, cudnNS[2], cudnNS[0], testPodName[0], svc.Servicename)
		g.By("11. Not be able to access default network service from cudn network.")
		otputils.CurlPod2SvcFail(oc, cudnNS[1], cudnNS[2], pod1ns2.Name, "test-service")

		g.By("11. Create fourth namespace for cudn pod")
		oc.CreateNamespaceUDN()
		cudnNS = append(cudnNS, oc.Namespace())
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS[3], fmt.Sprintf("%s=%s", key, values2[0])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("12. Create CRD in fourth namespace")
		if ipStackType == "ipv4single" {
			cidr = "10.151.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2011:100:200::0/60"
			} else {
				ipv4cidr = "10.151.0.0/16"
				ipv6cidr = "2011:100:200::0/60"
			}
		}
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS[3], fmt.Sprintf("%s-", key)).Execute()
			otputils.RemoveResource(oc, true, true, "namespace", cudnNS[3])
			otputils.RemoveResource(oc, true, true, "clusteruserdefinednetwork", crdName2)
		}()
		_, err = otputils.CreateCUDNCRD(oc, key, crdName2, ipv4cidr, ipv6cidr, cidr, "layer3", values2)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("13. Create a udn pod in fourth namespace")
		otputils.CreateResourceFromFile(oc, cudnNS[3], testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, cudnNS[3], "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPodNameNS3 := otputils.GetPodName(oc, cudnNS[3], "name=test-pods")

		g.By("14. Verify different cudn network, service was isolated.")
		otputils.CurlPod2SvcFail(oc, cudnNS[3], cudnNS[0], testPodNameNS3[0], svc.Servicename)

		g.By("15.Update internalTrafficPolicy as Local for cudn service in ns1.")
		patch := `[{"op": "replace", "path": "/spec/internalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", cudnNS[0], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("15.1. Verify ClusterIP service can be accessed from pod3 which is deployed same node as service back-end pod.")
		otputils.CurlPod2SvcPass(oc, cudnNS[1], cudnNS[0], pod1ns2.Name, svc.Servicename)
		g.By("15.2. Verify ClusterIP service can NOT be accessed from pod2 which is deployed different node as service back-end pod.")
		otputils.CurlPod2SvcFail(oc, cudnNS[0], cudnNS[0], pod2ns1.Name, svc.Servicename)

		g.By("16. Verify nodePort service can be accessed.")
		g.By("16.1 Delete testservice from ns1")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", "test-service", "-n", cudnNS[0]).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("16.2 Create testservice with NodePort in ns1")
		svc.ServiceType = "NodePort"
		svc.CreateServiceFromParams(oc)

		g.By("16.3 From a third node, be able to access node0:nodePort")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", cudnNS[0], svc.Servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		thirdNode := nodeList.Items[2].Name
		o.Expect(err).NotTo(o.HaveOccurred())
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[0].Name, nodePort)
		g.By("16.4 From a third node, be able to access node1:nodePort")
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[1].Name, nodePort)
		g.By("16.5 From pod node, be able to access nodePort service")
		otputils.CurlNodePortPass(oc, nodeList.Items[0].Name, nodeList.Items[0].Name, nodePort)
		otputils.CurlNodePortPass(oc, nodeList.Items[0].Name, nodeList.Items[1].Name, nodePort)

		g.By("17.Update externalTrafficPolicy as Local for udn service in ns1.")
		patch = `[{"op": "replace", "path": "/spec/externalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", cudnNS[0], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("17.1 From a third node, be able to access node0:nodePort")
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[0].Name, nodePort)
		g.By("17.2 From a third node, NOT be able to access node1:nodePort")
		otputils.CurlNodePortFail(oc, thirdNode, nodeList.Items[1].Name, nodePort)
	})

	g.It("[JIRA:Networking][OTP] 78768-Validate service for CUDN(Layer2)", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			testPodFile            = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			ipFamilyPolicy         = "SingleStack"
			key                    = "test.cudn.layer2"
			crdName                = "cudn-network-78768"
			crdName2               = "cudn-network-78768-2"
			values                 = []string{"value-78768-1", "value-78768-2"}
			values2                = []string{"value2-78768-1", "value2-78768-2"}
			cudnNS                 = []string{}
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This test requires at least 3 worker nodes which is not fulfilled. ")
		}

		g.By("1. Create CRD for CUDN")
		ipStackType := otputils.CheckIPStackType(oc)
		var cidr, ipv4cidr, ipv6cidr string
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::0/60"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::0/60"
				ipFamilyPolicy = "PreferDualStack"
			}
		}

		defer otputils.RemoveResource(oc, true, true, "clusteruserdefinednetwork", crdName)
		_, err := otputils.CreateCUDNCRD(oc, key, crdName, ipv4cidr, ipv6cidr, cidr, "layer2", values)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("2. Create 2 namespaces and add related values.")
		for i := 0; i < 2; i++ {
			oc.CreateNamespaceUDN()
			cudnNS = append(cudnNS, oc.Namespace())
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS[i], fmt.Sprintf("%s-", key)).Execute()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS[i], fmt.Sprintf("%s=%s", key, values[i])).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("3. Create a pod deployed on node0 as backend pod for service.")
		pod1ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod-1",
			Namespace: cudnNS[0],
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodTemplate,
		}
		defer otputils.RemoveResource(oc, true, true, "pod", pod1ns1.Name, "-n", pod1ns1.Namespace)
		pod1ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("4. create a udn client pod in ns1")
		pod2ns1 := otputils.PingPodResourceNode{
			Name:      "hello-pod-2",
			Namespace: cudnNS[0],
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodTemplate,
		}
		defer otputils.RemoveResource(oc, true, true, "pod", pod2ns1.Name, "-n", pod2ns1.Namespace)
		pod2ns1.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)
		// Update label for pod2 to a different one
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", cudnNS[0], "pod", pod2ns1.Name, "name=hello-pod-2", "--overwrite=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. create a udn client pod in ns2. ")
		pod1ns2 := otputils.PingPodResourceNode{
			Name:      "hello-pod-3",
			Namespace: cudnNS[1],
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodTemplate,
		}
		defer otputils.RemoveResource(oc, true, true, "pod", pod1ns2.Name, "-n", pod1ns2.Namespace)
		pod1ns2.CreatePingPodNode(oc)
		otputils.WaitPodReady(oc, pod1ns2.Namespace, pod1ns2.Name)

		g.By("6. create a ClusterIP service in ns1")
		svc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             cudnNS[0],
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        ipFamilyPolicy,
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)

		g.By("7. Verify ClusterIP service can be accessed from both pod2 in ns1 and pod3 in ns2")
		otputils.CurlPod2SvcPass(oc, cudnNS[0], cudnNS[0], pod2ns1.Name, svc.Servicename)
		otputils.CurlPod2SvcPass(oc, cudnNS[1], cudnNS[0], pod1ns2.Name, svc.Servicename)

		g.By("8. Create third namespace")
		oc.SetupProject()
		cudnNS = append(cudnNS, oc.Namespace())

		g.By("9. Create service and pods which are on default network.")
		otputils.CreateResourceFromFile(oc, cudnNS[2], testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, cudnNS[2], "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPodName := otputils.GetPodName(oc, cudnNS[2], "name=test-pods")

		g.By("10. Not be able to access cudn service from default network.")
		otputils.CurlPod2SvcFail(oc, cudnNS[2], cudnNS[0], testPodName[0], svc.Servicename)
		g.By("11. Not be able to access default network service from cudn network.")
		otputils.CurlPod2SvcFail(oc, cudnNS[1], cudnNS[2], pod1ns2.Name, "test-service")

		g.By("11. Create fourth namespace for cudn pod")
		oc.CreateNamespaceUDN()
		cudnNS = append(cudnNS, oc.Namespace())
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS[3], fmt.Sprintf("%s=%s", key, values2[0])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("12. Create CRD in fourth namespace")
		if ipStackType == "ipv4single" {
			cidr = "10.151.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2011:100:200::0/60"
			} else {
				ipv4cidr = "10.151.0.0/16"
				ipv6cidr = "2011:100:200::0/60"
			}
		}
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", cudnNS[3], fmt.Sprintf("%s-", key)).Execute()
			otputils.RemoveResource(oc, true, true, "namespace", cudnNS[3])
			otputils.RemoveResource(oc, true, true, "clusteruserdefinednetwork", crdName2)
		}()
		_, err = otputils.CreateCUDNCRD(oc, key, crdName2, ipv4cidr, ipv6cidr, cidr, "layer2", values2)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("13. Create a udn pod in fourth namespace")
		otputils.CreateResourceFromFile(oc, cudnNS[3], testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, cudnNS[3], "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testPodNameNS3 := otputils.GetPodName(oc, cudnNS[3], "name=test-pods")

		g.By("14. Verify different cudn network, service was isolated.")
		otputils.CurlPod2SvcFail(oc, cudnNS[3], cudnNS[0], testPodNameNS3[0], svc.Servicename)

		g.By("15.Update internalTrafficPolicy as Local for cudn service in ns1.")
		patch := `[{"op": "replace", "path": "/spec/internalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", cudnNS[0], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("15.1. Verify ClusterIP service can be accessed from pod3 which is deployed same node as service back-end pod.")
		otputils.CurlPod2SvcPass(oc, cudnNS[1], cudnNS[0], pod1ns2.Name, svc.Servicename)
		g.By("15.2. Verify ClusterIP service can NOT be accessed from pod2 which is deployed different node as service back-end pod.")
		otputils.CurlPod2SvcFail(oc, cudnNS[0], cudnNS[0], pod2ns1.Name, svc.Servicename)

		g.By("16. Verify nodePort service can be accessed.")
		g.By("16.1 Delete testservice from ns1")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", "test-service", "-n", cudnNS[0]).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("16.2 Create testservice with NodePort in ns1")
		svc.ServiceType = "NodePort"
		svc.CreateServiceFromParams(oc)

		g.By("16.3 From a third node, be able to access node0:nodePort")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", cudnNS[0], svc.Servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		thirdNode := nodeList.Items[2].Name
		o.Expect(err).NotTo(o.HaveOccurred())
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[0].Name, nodePort)
		g.By("16.4 From a third node, be able to access node1:nodePort")
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[1].Name, nodePort)
		g.By("16.5 From pod node, be able to access nodePort service")
		otputils.CurlNodePortPass(oc, nodeList.Items[0].Name, nodeList.Items[0].Name, nodePort)
		otputils.CurlNodePortPass(oc, nodeList.Items[0].Name, nodeList.Items[1].Name, nodePort)

		g.By("17.Update externalTrafficPolicy as Local for udn service in ns1.")
		patch = `[{"op": "replace", "path": "/spec/externalTrafficPolicy", "value": "Local"}]`
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("service/test-service", "-n", cudnNS[0], "-p", patch, "--type=json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("17.1 From a third node, be able to access node0:nodePort")
		otputils.CurlNodePortPass(oc, thirdNode, nodeList.Items[0].Name, nodePort)
		g.By("17.2 From a third node, NOT be able to access node1:nodePort")
		otputils.CurlNodePortFail(oc, thirdNode, nodeList.Items[1].Name, nodePort)
	})

	g.It("[JIRA:Networking][OTP][Serial] 44790-Validate ExternalIP service for default and UDN pods - setup", func() {
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This test requires at least 3 worker nodes which is not fulfilled. ")
		}

		ipStackType := otputils.CheckIPStackType(oc)
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			netsegDir              = testdata.FixturePath("networking/network_segmentation")
			rcPingPodTemplate      = filepath.Join(netsegDir, "rc-ping-for-pod-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			allNS                  = []string{"79163-upgrade-ns1", "79163-upgrade-ns2", "79163-upgrade-ns3"}
			ipFamilyPolicy         = "SingleStack"
			serviceName            = "test-service"
		)

		g.By("1. Create three namespaces, ns1 and ns2 for udn network testing, ns3 for default network testing")
		for i := 0; i < 2; i++ {
			oc.CreateSpecificNamespaceUDN(allNS[i])
		}
		oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", allNS[2]).Execute()

		g.By("2. Find externalIP for testing")
		var externalIP, externalIPv6 []string
		for i := 0; i < 3; i++ {
			nodeIP1, nodeIP2 := otputils.GetNodeIP(oc, nodeList.Items[i].Name)
			externalIP = append(externalIP, nodeIP2)
			if ipStackType == "dualstack" {
				externalIPv6 = append(externalIPv6, nodeIP1)
			}
		}

		g.By("3. Patch network.config to enable externalIP")
		allowedCIDRs := `"` + externalIP[0] + `","` + externalIP[1] + `","` + externalIP[2] + `"`
		if ipStackType == "dualstack" {
			allowedCIDRs = allowedCIDRs + `,"` + externalIPv6[0] + `","` + externalIPv6[1] + `","` + externalIPv6[2] + `"`
		}
		otputils.PatchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{\"allowedCIDRs\":["+allowedCIDRs+"]}}}}")

		g.By("4. Create CRD for layer3 UDN in namespace ns1")
		var cidr, ipv4cidr, ipv6cidr string
		if ipStackType == "ipv4single" {
			cidr = "10.150.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2010:100:200::0/48"
			} else {
				ipv4cidr = "10.150.0.0/16"
				ipv6cidr = "2010:100:200::0/48"
				ipFamilyPolicy = "PreferDualStack"
			}
		}
		otputils.CreateGeneralUDNCRD(oc, allNS[0], "udn-network-"+allNS[0], ipv4cidr, ipv6cidr, cidr, "layer3")

		g.By("5. Create CRD for layer2 UDN in namespace ns2")
		if ipStackType == "ipv4single" {
			cidr = "10.151.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr = "2011:100:200::0/48"
			} else {
				ipv4cidr = "10.151.0.0/16"
				ipv6cidr = "2011:100:200::0/48"
				ipFamilyPolicy = "PreferDualStack"
			}
		}
		otputils.CreateGeneralUDNCRD(oc, allNS[1], "udn-network-"+allNS[1], ipv4cidr, ipv6cidr, cidr, "layer2")

		g.By("6. Create pod as backend pod for service in each ns")
		var podsBackendName []string
		for i := 0; i < 3; i++ {
			podsBackend := otputils.ReplicationControllerPingPodResource{
				Name:      "hello-pod-1",
				Replicas:  0,
				Namespace: allNS[i],
				Template:  rcPingPodTemplate,
			}
			podsBackend.CreateReplicaController(oc)
			e2e.Logf("schedule backend pod to %s", nodeList.Items[i].Name)
			patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("rc/"+podsBackend.Name, "-n", allNS[i], "-p", "{\"spec\":{\"replicas\":1,\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\""+nodeList.Items[i].Name+"\"}}}}}", "--type=merge").Execute()
			o.Expect(patchErr).NotTo(o.HaveOccurred())
			err := otputils.WaitForPodWithLabelReady(oc, podsBackend.Namespace, "name="+podsBackend.Name)
			o.Expect(err).NotTo(o.HaveOccurred(), "The backend pod is not ready")
			podsBackendName = append(podsBackendName, otputils.GetPodName(oc, allNS[i], "name="+podsBackend.Name)[0])
		}

		g.By("7. Create udn client pod on different node in ns1 and ns2")
		var udnClientName []string
		for i := 0; i < 2; i++ {
			udnClient := otputils.ReplicationControllerPingPodResource{
				Name:      "hello-pod-2",
				Replicas:  0,
				Namespace: allNS[i],
				Template:  rcPingPodTemplate,
			}
			udnClient.CreateReplicaController(oc)
			e2e.Logf("schedule udn client pod to %s", nodeList.Items[2].Name)
			patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("rc/"+udnClient.Name, "-n", allNS[i], "-p", "{\"spec\":{\"replicas\":1,\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\""+nodeList.Items[2].Name+"\"}}}}}", "--type=merge").Execute()
			o.Expect(patchErr).NotTo(o.HaveOccurred())
			err := otputils.WaitForPodWithLabelReady(oc, udnClient.Namespace, "name="+udnClient.Name)
			o.Expect(err).NotTo(o.HaveOccurred(), "The udn client pod is not ready")
			udnClientName = append(udnClientName, otputils.GetPodName(oc, allNS[i], "name="+udnClient.Name)[0])
		}

		g.By("8. Create a ClusterIP service in each ns")
		for i := 0; i < 3; i++ {
			svc := otputils.GenericServiceResource{
				Servicename:           serviceName,
				Namespace:             allNS[i],
				Protocol:              "TCP",
				Selector:              "hello-pod-1",
				ServiceType:           "ClusterIP",
				IpFamilyPolicy:        ipFamilyPolicy,
				InternalTrafficPolicy: "Cluster",
				ExternalTrafficPolicy: "",
				Template:              genericServiceTemplate,
			}
			svc.CreateServiceFromParams(oc)
			e2e.Logf("Patch ExternalIP to service")
			otputils.PatchResourceAsAdmin(oc, "svc/"+svc.Servicename, fmt.Sprintf("{\"spec\":{\"externalIPs\": [\"%s\"]}}", externalIP[i]), allNS[i])
			svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[i], svc.Servicename).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(svcOutput).Should(o.ContainSubstring(externalIP[i]))
		}

		g.By("9. Validate the externalIP service for default network")
		_, err := e2eoutput.RunHostCmdWithRetries(allNS[2], podsBackendName[2], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIP[2], "27017"), 5*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())

		for i := 0; i < 2; i++ {
			if i == 0 {
				g.By("10. Validate the externalIP service for layer3 UDN")
			} else {
				g.By("11. Validate the externalIP service for layer2 UDN")
			}
			g.By("Validate the externalIP service can be accessed from another udn pod")
			_, err := e2eoutput.RunHostCmdWithRetries(allNS[i], udnClientName[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIP[i], "27017"), 5*time.Second, 15*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("Validate the externalIP service can be accessed from same node as service backend pod")
			_, err = otputils.DebugNode(oc, nodeList.Items[i].Name, "curl", net.JoinHostPort(externalIP[i], "27017"), "-s", "--connect-timeout", "5")
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("Validate the externalIP service can be accessed from different node than service backend pod")
			_, err = otputils.DebugNode(oc, nodeList.Items[2].Name, "curl", net.JoinHostPort(externalIP[i], "27017"), "-s", "--connect-timeout", "5")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		if ipStackType == "dualstack" {
			g.By("Retest it with IPv6 address in dualstack cluster")
			g.By("12. Patch IPv6 ExternalIP to service")
			for i := 0; i < 3; i++ {
				otputils.PatchResourceAsAdmin(oc, "svc/"+serviceName, fmt.Sprintf("{\"spec\":{\"externalIPs\": [\"%s\",\"%s\"]}}", externalIP[i], externalIPv6[i]), allNS[i])
				svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[i], serviceName).Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(svcOutput).Should(o.ContainSubstring(serviceName))
			}

			g.By("13. Validate the externalIP service for default network")
			_, err := e2eoutput.RunHostCmdWithRetries(allNS[2], podsBackendName[2], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIPv6[2], "27017"), 5*time.Second, 15*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())

			for i := 0; i < 2; i++ {
				if i == 0 {
					g.By("14. Validate the externalIP service for layer3 UDN - ipv6")
				} else {
					g.By("15. Validate the externalIP service for layer2 UDN - ipv6")
				}
				g.By("Validate the externalIP service can be accessed from another udn pod - ipv6")
				_, err := e2eoutput.RunHostCmdWithRetries(allNS[i], udnClientName[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIPv6[i], "27017"), 5*time.Second, 15*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Validate the externalIP service can be accessed from same node as service backend pod - ipv6")
				_, err = otputils.DebugNode(oc, nodeList.Items[i].Name, "curl", net.JoinHostPort(externalIPv6[i], "27017"), "-s", "--connect-timeout", "5")
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Validate the externalIP service can be accessed from different node than service backend pod - ipv6")
				_, err = otputils.DebugNode(oc, nodeList.Items[2].Name, "curl", net.JoinHostPort(externalIPv6[i], "27017"), "-s", "--connect-timeout", "5")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}
	})

	g.It("[JIRA:Networking][OTP][Serial] 79163-Validate ExternalIP service for default and UDN pods - verify", func() {
		defer otputils.PatchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{}}}}")
		defer otputils.PatchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{\"allowedCIDRs\":[]}}}}")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("This test requires at least 3 worker nodes which is not fulfilled. ")
		}

		ipStackType := otputils.CheckIPStackType(oc)
		var (
			allNS           = []string{"79163-upgrade-ns1", "79163-upgrade-ns2", "79163-upgrade-ns3"}
			podBackendLabel = "hello-pod-1"
			udnClientLabel  = "hello-pod-2"
		)

		g.By("1. Check the three namespaces are carried over")
		for i := 0; i < 3; i++ {
			nsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", allNS[i]).Execute()
			if nsErr != nil {
				g.Skip("Skip the PstChkUpgrade test as namespace " + allNS[i] + " does not exist, PreChkUpgrade test did not run")
			}
		}
		for i := 0; i < 3; i++ {
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", allNS[i], "--ignore-not-found=true").Execute()
		}

		g.By("2. Get externalIP from preserved services")
		var externalIP, externalIPv6 []string
		for i := 0; i < 3; i++ {
			rawIPs, svcErr := oc.AsAdmin().WithoutNamespace().Run("get").Args(
				"service", "test-service", "-n", allNS[i], "-o=jsonpath={.spec.externalIPs[*]}",
			).Output()
			o.Expect(svcErr).NotTo(o.HaveOccurred())
			ips := strings.Fields(strings.TrimSpace(rawIPs))
			o.Expect(ips).NotTo(o.BeEmpty())
			externalIP = append(externalIP, ips[0])
			if ipStackType == "dualstack" {
				o.Expect(len(ips)).To(o.BeNumerically(">=", 2))
				externalIPv6 = append(externalIPv6, ips[1])
			}
		}

		g.By("3. Get backend pod from preserved namespaces")
		var podsBackendName []string
		for i := 0; i < 3; i++ {
			err := otputils.WaitForPodWithLabelReady(oc, allNS[i], "name="+podBackendLabel)
			o.Expect(err).NotTo(o.HaveOccurred(), "The backend pod is not ready")
			podsBackendName = append(podsBackendName, otputils.GetPodName(oc, allNS[i], "name="+podBackendLabel)[0])
		}

		g.By("4. Get udn clients from preserved namespaces")
		var udnClientName []string
		for i := 0; i < 2; i++ {
			err := otputils.WaitForPodWithLabelReady(oc, allNS[i], "name="+udnClientLabel)
			o.Expect(err).NotTo(o.HaveOccurred(), "The udn client pod is not ready")
			udnClientName = append(udnClientName, otputils.GetPodName(oc, allNS[i], "name="+udnClientLabel)[0])
		}

		g.By("5. Validate the externalIP service for default network")
		_, err := e2eoutput.RunHostCmdWithRetries(allNS[2], podsBackendName[2], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIP[2], "27017"), 5*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())

		for i := 0; i < 2; i++ {
			if i == 0 {
				g.By("6. Validate the externalIP service for layer3 UDN")
			} else {
				g.By("7. Validate the externalIP service for layer2 UDN")
			}
			g.By("Validate the externalIP service can be accessed from another udn pod")
			_, err := e2eoutput.RunHostCmdWithRetries(allNS[i], udnClientName[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIP[i], "27017"), 5*time.Second, 15*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("Validate the externalIP service can be accessed from same node as service backend pod")
			_, err = otputils.DebugNode(oc, nodeList.Items[i].Name, "curl", net.JoinHostPort(externalIP[i], "27017"), "-s", "--connect-timeout", "5")
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("Validate the externalIP service can be accessed from different node than service backend pod")
			_, err = otputils.DebugNode(oc, nodeList.Items[2].Name, "curl", net.JoinHostPort(externalIP[i], "27017"), "-s", "--connect-timeout", "5")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		if ipStackType == "dualstack" {
			g.By("Retest it with IPv6 address in dualstack cluster")

			g.By("8. Validate the externalIP service for default network")
			_, err := e2eoutput.RunHostCmdWithRetries(allNS[2], podsBackendName[2], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIPv6[2], "27017"), 5*time.Second, 15*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())

			for i := 0; i < 2; i++ {
				if i == 0 {
					g.By("9. Validate the externalIP service for layer3 UDN - ipv6")
				} else {
					g.By("10. Validate the externalIP service for layer2 UDN - ipv6")
				}
				g.By("Validate the externalIP service can be accessed from another udn pod - ipv6")
				_, err := e2eoutput.RunHostCmdWithRetries(allNS[i], udnClientName[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIPv6[i], "27017"), 5*time.Second, 15*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Validate the externalIP service can be accessed from same node as service backend pod - ipv6")
				_, err = otputils.DebugNode(oc, nodeList.Items[i].Name, "curl", net.JoinHostPort(externalIPv6[i], "27017"), "-s", "--connect-timeout", "5")
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Validate the externalIP service can be accessed from different node than service backend pod - ipv6")
				_, err = otputils.DebugNode(oc, nodeList.Items[2].Name, "curl", net.JoinHostPort(externalIPv6[i], "27017"), "-s", "--connect-timeout", "5")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}
	})
})
