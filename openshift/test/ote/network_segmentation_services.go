package ote

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = Describe("[sig-network] SDN network segmentation services", func() {
	defer GinkgoRecover()

	var oc = exutil.NewCLI("networking-udn")

	BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:NetworkSegmentation] 44790-Validate ExternalIP service for default and UDN pods - setup", Label("Disruptive"), func() {
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			Skip("This test requires at least 3 worker nodes which is not fulfilled. ")
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

		By("1. Create three namespaces, ns1 and ns2 for udn network testing, ns3 for default network testing")
		for i := 0; i < 2; i++ {
			oc.CreateSpecificNamespaceUDN(allNS[i])
		}
		_ = oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", allNS[2]).Execute()

		By("2. Find externalIP for testing")
		var externalIP, externalIPv6 []string
		for i := 0; i < 3; i++ {
			nodeIP1, nodeIP2 := otputils.GetNodeIP(oc, nodeList.Items[i].Name)
			externalIP = append(externalIP, nodeIP2)
			if ipStackType == "dualstack" {
				externalIPv6 = append(externalIPv6, nodeIP1)
			}
		}

		By("3. Patch network.config to enable externalIP")
		allowedCIDRs := `"` + externalIP[0] + `","` + externalIP[1] + `","` + externalIP[2] + `"`
		if ipStackType == "dualstack" {
			allowedCIDRs = allowedCIDRs + `,"` + externalIPv6[0] + `","` + externalIPv6[1] + `","` + externalIPv6[2] + `"`
		}
		otputils.PatchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{\"allowedCIDRs\":["+allowedCIDRs+"]}}}}")

		By("4. Create CRD for layer3 UDN in namespace ns1")
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

		By("5. Create CRD for layer2 UDN in namespace ns2")
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

		By("6. Create pod as backend pod for service in each ns")
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

		By("7. Create udn client pod on different node in ns1 and ns2")
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

		By("8. Create a ClusterIP service in each ns")
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

		By("9. Validate the externalIP service for default network")
		_, err := e2eoutput.RunHostCmdWithRetries(allNS[2], podsBackendName[2], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIP[2], "27017"), 5*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())

		for i := 0; i < 2; i++ {
			if i == 0 {
				By("10. Validate the externalIP service for layer3 UDN")
			} else {
				By("11. Validate the externalIP service for layer2 UDN")
			}
			By("Validate the externalIP service can be accessed from another udn pod")
			_, err := e2eoutput.RunHostCmdWithRetries(allNS[i], udnClientName[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIP[i], "27017"), 5*time.Second, 15*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())

			By("Validate the externalIP service can be accessed from same node as service backend pod")
			_, err = otputils.DebugNode(oc, nodeList.Items[i].Name, "curl", net.JoinHostPort(externalIP[i], "27017"), "-s", "--connect-timeout", "5")
			o.Expect(err).NotTo(o.HaveOccurred())

			By("Validate the externalIP service can be accessed from different node than service backend pod")
			_, err = otputils.DebugNode(oc, nodeList.Items[2].Name, "curl", net.JoinHostPort(externalIP[i], "27017"), "-s", "--connect-timeout", "5")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		if ipStackType == "dualstack" {
			By("Retest it with IPv6 address in dualstack cluster")
			By("12. Patch IPv6 ExternalIP to service")
			for i := 0; i < 3; i++ {
				otputils.PatchResourceAsAdmin(oc, "svc/"+serviceName, fmt.Sprintf("{\"spec\":{\"externalIPs\": [\"%s\",\"%s\"]}}", externalIP[i], externalIPv6[i]), allNS[i])
				svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", allNS[i], serviceName).Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(svcOutput).Should(o.ContainSubstring(serviceName))
			}

			By("13. Validate the externalIP service for default network")
			_, err := e2eoutput.RunHostCmdWithRetries(allNS[2], podsBackendName[2], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIPv6[2], "27017"), 5*time.Second, 15*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())

			for i := 0; i < 2; i++ {
				if i == 0 {
					By("14. Validate the externalIP service for layer3 UDN - ipv6")
				} else {
					By("15. Validate the externalIP service for layer2 UDN - ipv6")
				}
				By("Validate the externalIP service can be accessed from another udn pod - ipv6")
				_, err := e2eoutput.RunHostCmdWithRetries(allNS[i], udnClientName[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIPv6[i], "27017"), 5*time.Second, 15*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())

				By("Validate the externalIP service can be accessed from same node as service backend pod - ipv6")
				_, err = otputils.DebugNode(oc, nodeList.Items[i].Name, "curl", net.JoinHostPort(externalIPv6[i], "27017"), "-s", "--connect-timeout", "5")
				o.Expect(err).NotTo(o.HaveOccurred())

				By("Validate the externalIP service can be accessed from different node than service backend pod - ipv6")
				_, err = otputils.DebugNode(oc, nodeList.Items[2].Name, "curl", net.JoinHostPort(externalIPv6[i], "27017"), "-s", "--connect-timeout", "5")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}
	})

	It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:NetworkSegmentation] 79163-Validate ExternalIP service for default and UDN pods - verify", Label("Disruptive"), func() {
		defer otputils.PatchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{}}}}")
		defer otputils.PatchResourceAsAdmin(oc, "network/cluster", "{\"spec\":{\"externalIP\":{\"policy\":{\"allowedCIDRs\":[]}}}}")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			Skip("This test requires at least 3 worker nodes which is not fulfilled. ")
		}

		ipStackType := otputils.CheckIPStackType(oc)
		var (
			allNS           = []string{"79163-upgrade-ns1", "79163-upgrade-ns2", "79163-upgrade-ns3"}
			podBackendLabel = "hello-pod-1"
			udnClientLabel  = "hello-pod-2"
		)

		By("1. Check the three namespaces are carried over")
		for i := 0; i < 3; i++ {
			nsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", allNS[i]).Execute()
			if nsErr != nil {
				Skip("Skip the PstChkUpgrade test as namespace " + allNS[i] + " does not exist, PreChkUpgrade test did not run")
			}
		}
		for i := 0; i < 3; i++ {
			defer func() {
				_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", allNS[i], "--ignore-not-found=true").Execute()
			}()
		}

		By("2. Get externalIP from preserved services")
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

		By("3. Get backend pod from preserved namespaces")
		var podsBackendName []string
		for i := 0; i < 3; i++ {
			err := otputils.WaitForPodWithLabelReady(oc, allNS[i], "name="+podBackendLabel)
			o.Expect(err).NotTo(o.HaveOccurred(), "The backend pod is not ready")
			podsBackendName = append(podsBackendName, otputils.GetPodName(oc, allNS[i], "name="+podBackendLabel)[0])
		}

		By("4. Get udn clients from preserved namespaces")
		var udnClientName []string
		for i := 0; i < 2; i++ {
			err := otputils.WaitForPodWithLabelReady(oc, allNS[i], "name="+udnClientLabel)
			o.Expect(err).NotTo(o.HaveOccurred(), "The udn client pod is not ready")
			udnClientName = append(udnClientName, otputils.GetPodName(oc, allNS[i], "name="+udnClientLabel)[0])
		}

		By("5. Validate the externalIP service for default network")
		_, err := e2eoutput.RunHostCmdWithRetries(allNS[2], podsBackendName[2], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIP[2], "27017"), 5*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())

		for i := 0; i < 2; i++ {
			if i == 0 {
				By("6. Validate the externalIP service for layer3 UDN")
			} else {
				By("7. Validate the externalIP service for layer2 UDN")
			}
			By("Validate the externalIP service can be accessed from another udn pod")
			_, err := e2eoutput.RunHostCmdWithRetries(allNS[i], udnClientName[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIP[i], "27017"), 5*time.Second, 15*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())

			By("Validate the externalIP service can be accessed from same node as service backend pod")
			_, err = otputils.DebugNode(oc, nodeList.Items[i].Name, "curl", net.JoinHostPort(externalIP[i], "27017"), "-s", "--connect-timeout", "5")
			o.Expect(err).NotTo(o.HaveOccurred())

			By("Validate the externalIP service can be accessed from different node than service backend pod")
			_, err = otputils.DebugNode(oc, nodeList.Items[2].Name, "curl", net.JoinHostPort(externalIP[i], "27017"), "-s", "--connect-timeout", "5")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		if ipStackType == "dualstack" {
			By("Retest it with IPv6 address in dualstack cluster")

			By("8. Validate the externalIP service for default network")
			_, err := e2eoutput.RunHostCmdWithRetries(allNS[2], podsBackendName[2], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIPv6[2], "27017"), 5*time.Second, 15*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())

			for i := 0; i < 2; i++ {
				if i == 0 {
					By("9. Validate the externalIP service for layer3 UDN - ipv6")
				} else {
					By("10. Validate the externalIP service for layer2 UDN - ipv6")
				}
				By("Validate the externalIP service can be accessed from another udn pod - ipv6")
				_, err := e2eoutput.RunHostCmdWithRetries(allNS[i], udnClientName[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(externalIPv6[i], "27017"), 5*time.Second, 15*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())

				By("Validate the externalIP service can be accessed from same node as service backend pod - ipv6")
				_, err = otputils.DebugNode(oc, nodeList.Items[i].Name, "curl", net.JoinHostPort(externalIPv6[i], "27017"), "-s", "--connect-timeout", "5")
				o.Expect(err).NotTo(o.HaveOccurred())

				By("Validate the externalIP service can be accessed from different node than service backend pod - ipv6")
				_, err = otputils.DebugNode(oc, nodeList.Items[2].Name, "curl", net.JoinHostPort(externalIPv6[i], "27017"), "-s", "--connect-timeout", "5")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}
	})
})
