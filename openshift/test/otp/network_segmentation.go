package otp

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
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

var _ = g.Describe("[sig-network][Suite:openshift/ovn-kubernetes] SDN network segmentation", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("otp-network-segmentation")

	var testDataDirUDN = testdata.FixturePath("networking", "network_segmentation", "udn")

	// helper: check NAD exists in namespace
	checkNAD := func(oc *exutil.CLI, ns string, nad string) bool {
		nadOutput, nadOutputErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("net-attach-def", "-n", ns).Output()
		o.Expect(nadOutputErr).NotTo(o.HaveOccurred())
		return strings.Contains(nadOutput, nad)
	}

	// helper: contains for string slice
	containsStr := func(s []string, str string) bool {
		for _, v := range s {
			if v == str {
				return true
			}
		}
		return false
	}

	// helper: wait for all pods in a namespace to be ready
	waitAllPodsReady := func(oc *exutil.CLI, namespace string) {
		err := wait.Poll(10*time.Second, 4*time.Minute, func() (bool, error) {
			template := "'{{- range .items -}}{{- range .status.conditions -}}{{- if ne .reason \"PodCompleted\" -}}{{- if eq .type \"Ready\" -}}{{- .status}} {{\" \"}}{{- end -}}{{- end -}}{{- end -}}{{- end -}}'"
			stdout, err := oc.AsAdmin().Run("get").Args("pods", "-n", namespace).Template(template).Output()
			if err != nil {
				e2e.Logf("the err:%v, and try next round", err)
				return false, nil
			}
			if strings.Contains(stdout, "False") {
				return false, nil
			}
			return true, nil
		})
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Some Pods are not ready in NS %s!", namespace))
	}

	g.It("[JIRA:Networking][OTP][Serial] 75223-Restarting ovn pods should not break UDN primary network traffic", func() {
		var (
			testDataDir    = testdata.FixturePath("networking")
			udnNadtemplate = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			testPodFile    = filepath.Join(testDataDir, "testpod.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)
		g.By("1. Create first namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		g.By("2. Create 2nd namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()

		nadResourcename := []string{"l3-network-" + ns1, "l3-network-" + ns2}
		nadNS := []string{ns1, ns2}
		var subnet []string
		if ipStackType == "ipv4single" {
			subnet = []string{"10.150.0.0/16/24", "10.151.0.0/16/24"}
		} else {
			if ipStackType == "ipv6single" {
				subnet = []string{"2010:100:200::0/60", "2011:100:200::0/60"}
			} else {
				subnet = []string{"10.150.0.0/16/24,2010:100:200::0/60", "10.151.0.0/16/24,2011:100:200::0/60"}
			}
		}

		nad := make([]otputils.UdnNetDefResource, 2)
		for i := 0; i < 2; i++ {
			g.By(fmt.Sprintf("create NAD %s in namespace %s", nadResourcename[i], nadNS[i]))
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadResourcename[i],
				Namespace:        nadNS[i],
				NadNetworkName:   nadResourcename[i],
				Topology:         "layer3",
				Subnet:           subnet[i],
				NetAttachDefName: nadNS[i] + "/" + nadResourcename[i],
				Role:             "primary",
				Template:         udnNadtemplate,
			}
			nad[i].CreateUdnNad(oc)
			g.By("Verifying the configured NetworkAttachmentDefinition")
			if checkNAD(oc, nadNS[i], nadResourcename[i]) {
				e2e.Logf("The correct network-attach-defintion: %v is created!", nadResourcename[i])
			} else {
				e2e.Failf("The correct network-attach-defintion: %v is not created!", nadResourcename[i])
			}
		}

		g.By("Create replica pods in ns1")
		otputils.CreateResourceFromFile(oc, ns1, testPodFile)
		err := otputils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testpodNS1Names := otputils.GetPodName(oc, ns1, "name=test-pods")
		otputils.CurlPod2PodPassUDN(oc, ns1, testpodNS1Names[0], ns1, testpodNS1Names[1])

		g.By("create replica pods in ns2")
		otputils.CreateResourceFromFile(oc, ns2, testPodFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns2, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testpodNS2Names := otputils.GetPodName(oc, ns2, "name=test-pods")
		otputils.CurlPod2PodPassUDN(oc, ns2, testpodNS2Names[0], ns2, testpodNS2Names[1])

		g.By("Restart OVN pods")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "--all", "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitAllPodsReady(oc, "openshift-ovn-kubernetes")

		g.By("Verify the connection in UDN primary network not broken.")
		otputils.CurlPod2PodPassUDN(oc, ns1, testpodNS1Names[0], ns1, testpodNS1Names[1])
		otputils.CurlPod2PodPassUDN(oc, ns2, testpodNS2Names[0], ns2, testpodNS2Names[1])
	})

	g.It("[JIRA:Networking][OTP] 75254-Check kubelet probes are allowed via default network LSP for the UDN pods", func() {
		var (
			udnCRDdualStack         = filepath.Join(testDataDirUDN, "udn_crd_dualstack2_template.yaml")
			udnCRDSingleStack       = filepath.Join(testDataDirUDN, "udn_crd_singlestack_template.yaml")
			udnPodLivenessTemplate  = filepath.Join(testDataDirUDN, "udn_test_pod_liveness_template.yaml")
			udnPodReadinessTemplate = filepath.Join(testDataDirUDN, "udn_test_pod_readiness_template.yaml")
			udnPodStartupTemplate   = filepath.Join(testDataDirUDN, "udn_test_pod_startup_template.yaml")
			livenessProbePort       = 8080
			readinessProbePort      = 8081
			startupProbePort        = 1234
		)

		g.By("1. Create privileged namespace")
		oc.CreateNamespaceUDN()
		ns := oc.Namespace()
		otputils.SetNamespacePrivileged(oc, ns)

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
			}
		}
		var udncrd otputils.UdnCRDResource
		if ipStackType == "dualstack" {
			udncrd = otputils.UdnCRDResource{
				Crdname:    "udn-network-ds-75254",
				Namespace:  ns,
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
				Crdname:   "udn-network-ss-75254",
				Namespace: ns,
				Role:      "Primary",
				Cidr:      cidr,
				Prefix:    prefix,
				Template:  udnCRDSingleStack,
			}
			udncrd.CreateUdnCRDSingleStack(oc)
		}
		err := otputils.WaitUDNCRDApplied(oc, ns, udncrd.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create a udn hello pod with liveness probe in ns1")
		pod1 := otputils.UdnPodWithProbeResource{
			Name:             "hello-pod-ns1-liveness",
			Namespace:        ns,
			Label:            "hello-pod",
			Port:             livenessProbePort,
			Failurethreshold: 1,
			Periodseconds:    1,
			Template:         udnPodLivenessTemplate,
		}
		pod1.CreateUdnPodWithProbe(oc)
		otputils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("4. Capture packets in pod " + pod1.Name + ", check liveness probe traffic is allowed via default network")
		tcpdumpCmd1 := fmt.Sprintf("timeout 5s tcpdump -nni eth0 port %v", pod1.Port)
		cmdTcpdump1, cmdOutput1, _, err1 := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", ns, pod1.Name, "--", "bash", "-c", tcpdumpCmd1).Background()
		defer cmdTcpdump1.Process.Kill()
		o.Expect(err1).NotTo(o.HaveOccurred())
		cmdTcpdump1.Wait()
		e2e.Logf("The captured packet is %s", cmdOutput1.String())
		expPacket1 := strconv.Itoa(pod1.Port) + ": Flags [S]"
		o.Expect(strings.Contains(cmdOutput1.String(), expPacket1)).To(o.BeTrue())

		g.By("5. Create a udn hello pod with readiness probe in ns1")
		pod2 := otputils.UdnPodWithProbeResource{
			Name:             "hello-pod-ns1-readiness",
			Namespace:        ns,
			Label:            "hello-pod",
			Port:             readinessProbePort,
			Failurethreshold: 1,
			Periodseconds:    1,
			Template:         udnPodReadinessTemplate,
		}
		pod2.CreateUdnPodWithProbe(oc)
		otputils.WaitPodReady(oc, pod2.Namespace, pod2.Name)

		g.By("6. Capture packets in pod " + pod2.Name + ", check readiness probe traffic is allowed via default network")
		tcpdumpCmd2 := fmt.Sprintf("timeout 5s tcpdump -nni eth0 port %v", pod2.Port)
		cmdTcpdump2, cmdOutput2, _, err2 := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", ns, pod2.Name, "--", "bash", "-c", tcpdumpCmd2).Background()
		defer cmdTcpdump2.Process.Kill()
		o.Expect(err2).NotTo(o.HaveOccurred())
		cmdTcpdump2.Wait()
		e2e.Logf("The captured packet is %s", cmdOutput2.String())
		expPacket2 := strconv.Itoa(pod2.Port) + ": Flags [S]"
		o.Expect(strings.Contains(cmdOutput2.String(), expPacket2)).To(o.BeTrue())

		g.By("7. Create a udn hello pod with startup probe in ns1")
		pod3 := otputils.UdnPodWithProbeResource{
			Name:             "hello-pod-ns1-startup",
			Namespace:        ns,
			Label:            "hello-pod",
			Port:             startupProbePort,
			Failurethreshold: 100,
			Periodseconds:    2,
			Template:         udnPodStartupTemplate,
		}
		pod3.CreateUdnPodWithProbe(oc)

		g.By("8. Start tcpdump before pod becomes Ready to capture startup probe traffic via default network")
		o.Eventually(func() string {
			phase, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod3.Name, "-n", ns, "-o=jsonpath={.status.phase}").Output()
			return phase
		}, "60s", "2s").Should(o.Equal("Running"))
		tcpdumpCmd3 := fmt.Sprintf("timeout 30s tcpdump -nni eth0 port %v", pod3.Port)
		cmdTcpdump3, cmdOutput3, _, err3 := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", ns, pod3.Name, "--", "bash", "-c", tcpdumpCmd3).Background()
		o.Expect(err3).NotTo(o.HaveOccurred())
		defer func() {
			if cmdTcpdump3 != nil && cmdTcpdump3.Process != nil {
				_ = cmdTcpdump3.Process.Kill()
			}
		}()
		otputils.WaitPodReady(oc, pod3.Namespace, pod3.Name)
		cmdTcpdump3.Wait()
		e2e.Logf("The captured packet is %s", cmdOutput3.String())
		expPacket3 := strconv.Itoa(pod3.Port) + ": Flags [S]"
		o.Expect(strings.Contains(cmdOutput3.String(), expPacket3)).To(o.BeTrue())
	})

	g.It("[JIRA:Networking][OTP] 75503-Overlapping pod CIDRs IPs are allowed in different primary NADs", func() {
		var (
			testDataDir    = testdata.FixturePath("networking")
			udnNadtemplate = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			testPodFile    = filepath.Join(testDataDir, "testpod.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has fewer than two nodes.")
		}

		ipStackType := otputils.CheckIPStackType(oc)
		g.By("1. Obtain first namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		g.By("2. Obtain 2nd namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()

		nadResourcename := []string{"l3-network-" + ns1, "l3-network-" + ns2}
		nadNS := []string{ns1, ns2}
		var subnet []string
		if ipStackType == "ipv4single" {
			subnet = []string{"10.150.0.0/26/29", "10.150.0.0/26/29"}
		} else {
			if ipStackType == "ipv6single" {
				subnet = []string{"2010:100:200::0/60", "2010:100:200::0/60"}
			} else {
				subnet = []string{"10.150.0.0/26/29,2010:100:200::0/60", "10.150.0.0/26/29,2010:100:200::0/60"}
			}
		}

		nad := make([]otputils.UdnNetDefResource, 2)
		for i := 0; i < 2; i++ {
			g.By(fmt.Sprintf("create NAD %s in namespace %s", nadResourcename[i], nadNS[i]))
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadResourcename[i],
				Namespace:        nadNS[i],
				NadNetworkName:   nadResourcename[i],
				Topology:         "layer3",
				Subnet:           subnet[i],
				NetAttachDefName: nadNS[i] + "/" + nadResourcename[i],
				Role:             "primary",
				Template:         udnNadtemplate,
			}
			nad[i].CreateUdnNad(oc)
			g.By("Verifying the configured NetworkAttachmentDefinition")
			if checkNAD(oc, nadNS[i], nadResourcename[i]) {
				e2e.Logf("The correct network-attach-defintion: %v is created!", nadResourcename[i])
			} else {
				e2e.Failf("The correct network-attach-defintion: %v is not created!", nadResourcename[i])
			}
		}

		g.By("Create replica pods in ns1")
		otputils.CreateResourceFromFile(oc, ns1, testPodFile)
		numberOfPods := "8"
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas="+numberOfPods, "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = otputils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testpodNS1Names := otputils.GetPodName(oc, ns1, "name=test-pods")
		e2e.Logf("Collect all the pods IPs in namespace %s", ns1)
		var podsNS1IP1, podsNS1IP2 []string
		for i := 0; i < len(testpodNS1Names); i++ {
			podIP1, podIP2 := otputils.GetPodIPUDN(oc, ns1, testpodNS1Names[i], "ovn-udn1")
			if podIP2 != "" {
				podsNS1IP2 = append(podsNS1IP2, podIP2)
			}
			podsNS1IP1 = append(podsNS1IP1, podIP1)
		}
		e2e.Logf("The IPs of pods in first namespace %s for UDN:\n %v %v", ns1, podsNS1IP1, podsNS1IP2)

		g.By("create replica pods in ns2")
		otputils.CreateResourceFromFile(oc, ns2, testPodFile)
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas="+numberOfPods, "-n", ns2).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = otputils.WaitForPodWithLabelReady(oc, ns2, "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		testpodNS2Names := otputils.GetPodName(oc, ns2, "name=test-pods")
		e2e.Logf("Collect all the pods IPs in namespace %s", ns2)
		var podsNS2IP1, podsNS2IP2 []string
		for i := 0; i < len(testpodNS2Names); i++ {
			podIP1, podIP2 := otputils.GetPodIPUDN(oc, ns2, testpodNS2Names[i], "ovn-udn1")
			if podIP2 != "" {
				podsNS2IP2 = append(podsNS2IP2, podIP2)
			}
			podsNS2IP1 = append(podsNS2IP1, podIP1)
		}
		e2e.Logf("The IPs of pods in second namespace %s for UDN:\n %v %v", ns2, podsNS2IP1, podsNS2IP2)

		testpodNS1NamesLen := len(testpodNS1Names)
		podsNS1IP1Len := len(podsNS1IP1)
		podsNS1IP2Len := len(podsNS1IP2)
		g.By("Verify udn network should be able to access in same network.")
		for i := 0; i < testpodNS1NamesLen; i++ {
			for j := 0; j < podsNS1IP1Len; j++ {
				if podsNS1IP2Len > 0 && podsNS1IP2[j] != "" {
					_, err = e2eoutput.RunHostCmd(ns1, testpodNS1Names[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(podsNS1IP2[j], "8080"))
					o.Expect(err).NotTo(o.HaveOccurred())
				}
				_, err = e2eoutput.RunHostCmd(ns1, testpodNS1Names[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(podsNS1IP1[j], "8080"))
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}

		podsNS2IP1Len := len(podsNS2IP1)
		podsNS2IP2Len := len(podsNS2IP2)
		g.By("Verify udn network should be isolated in different network.")
		for i := 0; i < testpodNS1NamesLen; i++ {
			for j := 0; j < podsNS2IP1Len; j++ {
				if podsNS2IP2Len > 0 && podsNS2IP2[j] != "" {
					if containsStr(podsNS1IP2, podsNS2IP2[j]) {
						// as the destination IP in ns2 is same as one in NS1, then it will be able to access that IP and has been executed in previous steps.
						continue
					} else {
						_, err = e2eoutput.RunHostCmd(ns1, testpodNS1Names[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(podsNS2IP2[j], "8080"))
						o.Expect(err).To(o.HaveOccurred())
					}
				}
				if containsStr(podsNS1IP1, podsNS2IP1[j]) {
					// as the destination IP in ns2 is same as one in NS1, then it will be able to access that IP and has been executed in previous steps..
					continue
				} else {
					_, err = e2eoutput.RunHostCmd(ns1, testpodNS1Names[i], "curl --connect-timeout 5 -s "+net.JoinHostPort(podsNS2IP1[j], "8080"))
					o.Expect(err).To(o.HaveOccurred())
				}
			}
		}
	})

	g.It("[JIRA:Networking][OTP] 75955-Verify UDN failed message when user defined join subnet overlaps user defined subnet Layer3", func() {
		var (
			netsegDir                             = testdata.FixturePath("networking/network_segmentation")
			udnCRDL3dualStack                     = filepath.Join(netsegDir, "udn/udn_crd_dualstack2_template.yaml")
			udnCRDL3SingleStack                   = filepath.Join(netsegDir, "udn/udn_crd_singlestack_template.yaml")
			UserDefinedPrimaryNetworkJoinSubnetV4 = "100.65.0.0/16"
			UserDefinedPrimaryNetworkJoinSubnetV6 = "fd99::/48"
		)

		ipStackType := otputils.CheckIPStackType(oc)
		g.By("1. Create namespace")
		oc.CreateNamespaceUDN()
		ns := oc.Namespace()

		g.By("2. Create CRD for UDN")
		var udncrd otputils.UdnCRDResource
		var cidr string
		var prefix, ipv4prefix, ipv6prefix int32
		if ipStackType == "ipv4single" {
			cidr = UserDefinedPrimaryNetworkJoinSubnetV4
			prefix = 24
		} else {
			if ipStackType == "ipv6single" {
				cidr = UserDefinedPrimaryNetworkJoinSubnetV6
				prefix = 64
			} else {
				ipv4prefix = 24
				ipv6prefix = 64
			}
		}
		if ipStackType == "dualstack" {
			udncrd = otputils.UdnCRDResource{
				Crdname:    "udn-network-75995",
				Namespace:  ns,
				Role:       "Primary",
				IPv4cidr:   UserDefinedPrimaryNetworkJoinSubnetV4,
				IPv4prefix: ipv4prefix,
				IPv6cidr:   UserDefinedPrimaryNetworkJoinSubnetV6,
				IPv6prefix: ipv6prefix,
				Template:   udnCRDL3dualStack,
			}
			udncrd.CreateUdnCRDDualStack(oc)
		} else {
			udncrd = otputils.UdnCRDResource{
				Crdname:   "udn-network-75995",
				Namespace: ns,
				Role:      "Primary",
				Cidr:      cidr,
				Prefix:    prefix,
				Template:  udnCRDL3SingleStack,
			}
			udncrd.CreateUdnCRDSingleStack(oc)
		}
		err := otputils.WaitUDNCRDApplied(oc, ns, udncrd.Crdname)
		o.Expect(err).To(o.HaveOccurred())

		g.By("3. Check UDN failed message")
		output, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("userdefinednetwork.k8s.ovn.org", udncrd.Crdname, "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.Or(
			o.ContainSubstring(fmt.Sprintf("user defined join subnet \"100.65.0.0/16\" overlaps user defined subnet \"%s\"", UserDefinedPrimaryNetworkJoinSubnetV4)),
			o.ContainSubstring(fmt.Sprintf("user defined join subnet \"fd99::/64\" overlaps user defined subnet \"%s\"", UserDefinedPrimaryNetworkJoinSubnetV6))))
	})

	g.It("[JIRA:Networking][OTP][Serial] 75984-Check udn pods isolation on user defined networks post OVN gateway migration", func() {
		var (
			udnNadtemplate = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			udnPodTemplate = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)

		g.By("1. Create first namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		g.By("2. Create 2nd namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		g.By("3. Create 3rd namespace")
		oc.CreateNamespaceUDN()
		ns3 := oc.Namespace()

		g.By("4. Create 4th namespace")
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
			g.By(fmt.Sprintf("create NAD %s in namespace %s", nadResourcename[i], nadNS[i]))
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
			g.By("create a udn hello pods in ns1 ns2 ns3 and ns4")
			pod[i] = otputils.UdnPodResource{
				Name:      "hello-pod",
				Namespace: nadNS[i],
				Label:     "hello-pod",
				Template:  udnPodTemplate,
			}
			pod[i].CreateUdnPod(oc)
			otputils.WaitPodReady(oc, pod[i].Namespace, pod[i].Name)
		}

		g.By("create another udn hello pod in ns1 to ensure layer3 connectivity post migration among them")
		podNs1 := otputils.UdnPodResource{
			Name:      "hello-pod-ns1",
			Namespace: nadNS[0],
			Label:     "hello-pod",
			Template:  udnPodTemplate,
		}
		podNs1.CreateUdnPod(oc)
		otputils.WaitPodReady(oc, podNs1.Namespace, podNs1.Name)

		g.By("create another udn hello pod in ns3 to ensure layer2 connectivity post migration among them")
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

	g.It("[JIRA:Networking][OTP][Serial] 76939-Check udn pods isolation on a scaled node", func() {
		var (
			udnPodTemplate     = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			udnPodTemplateNode = filepath.Join(testDataDirUDN, "udn_test_pod_template_node.yaml")
			udnCRDSingleStack  = filepath.Join(testDataDirUDN, "udn_crd_singlestack_template.yaml")
		)

		ipStackType := otputils.CheckIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())
		if ipStackType != "ipv4single" {
			g.Skip("This case requires IPv4 single stack cluster")
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
			g.Skip(fmt.Sprintf("Skipping test: platform %s is not supported for this test case", platform))
		}

		g.By("1. Create first namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		g.By("2. Create 2nd namespace")
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

		g.By("create a udn hello pod in ns1")
		pod1 := otputils.UdnPodResource{
			Name:      "hello-pod-ns1",
			Namespace: ns1,
			Label:     "hello-pod",
			Template:  udnPodTemplate,
		}
		pod1.CreateUdnPod(oc)
		otputils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		// Scale up a new node on the cluster using a new machineset
		g.By("3. Create a new machineset, get the new node created")
		infrastructureName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.infrastructureName}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		machinesetName := infrastructureName + "-76939"

		// Get an existing machineset to use as template
		existingMS, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("machineset", "-n", "openshift-machine-api", "-o=jsonpath={.items[0].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(existingMS).NotTo(o.BeEmpty())

		// Clone the machineset
		msJSON, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("machineset", existingMS, "-n", "openshift-machine-api", "-o", "json").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		// Create a temporary file with modified machineset
		msJSON = strings.ReplaceAll(msJSON, existingMS, machinesetName)

		tmpFile := fmt.Sprintf("/tmp/ms-%s.json", otputils.GetRandomString())
		err = oc.AsAdmin().WithoutNamespace().Run("get").Args("machineset", existingMS, "-n", "openshift-machine-api", "-o", "json").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		// Use oc to create a new machineset with replicas=1
		err = oc.AsAdmin().WithoutNamespace().Run("process").Args("-f", "-").Execute()
		// Fallback approach: scale an existing machineset
		_ = msJSON
		_ = tmpFile

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
			wait.Poll(30*time.Second, 15*time.Minute, func() (bool, error) {
				currentNodes, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/worker", "-o=jsonpath={.items[*].metadata.name}").Output()
				return len(strings.Fields(currentNodes)) <= len(nodesBeforeList), nil
			})
		}()

		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("machineset", existingMS, "-n", "openshift-machine-api", fmt.Sprintf("--replicas=%d", newReplicas)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		// Wait for new node to appear and become Ready
		var nodeName string
		err = wait.Poll(30*time.Second, 15*time.Minute, func() (bool, error) {
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

		g.By("create a udn hello pod in ns2")
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

	g.It("[JIRA:Networking][OTP][Serial] 77542-Check default network ports can be exposed on UDN pods layer3", func() {
		var (
			testDataDir         = testdata.FixturePath("networking")
			netsegDir           = testdata.FixturePath("networking/network_segmentation")
			sctpModule          = filepath.Join(netsegDir, "sctp/load-sctp-module.yaml")
			statefulSetHelloPod = filepath.Join(testDataDir, "statefulset-hello.yaml")
			tcpPort             = 8080
			udpPort             = 6000
			sctpPort            = 30102
		)

		g.By("Preparing the nodes for SCTP")
		otputils.PrepareSCTPModule(oc, sctpModule)

		g.By("1. Create the UDN namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()

		g.By("2. Create CRD for UDN in ns2")
		err := otputils.ApplyL3UDNtoNamespace(oc, ns2, 0)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create a udn hello pod in ns2 and get the node name")
		otputils.CreateResourceFromFile(oc, ns2, statefulSetHelloPod)
		pod2Err := otputils.WaitForPodWithLabelReady(oc, ns2, "app=hello")
		o.Expect(pod2Err).NotTo(o.HaveOccurred(), "The statefulSet pod is not ready")
		pod2Name := otputils.GetPodName(oc, ns2, "app=hello")[0]

		podNodeName, podNodeNameErr := otputils.GetPodNodeName(oc, ns2, pod2Name)
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())

		g.By("4. Create the non UDN namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("5. Create a hello pod in ns1")
		otputils.CreateResourceFromFile(oc, ns1, statefulSetHelloPod)
		pod1Err := otputils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
		o.Expect(pod1Err).NotTo(o.HaveOccurred(), "The statefulSet pod is not ready")
		pod1Name := otputils.GetPodName(oc, ns1, "app=hello")[0]

		g.By("6. Check host isolation from node to UDN pod's IP on default network on TCP/ICMP, should not be able to access")
		otputils.CurlNode2PodFail(oc, podNodeName, ns2, pod2Name)
		otputils.PingNode2PodFail(oc, podNodeName, ns2, pod2Name)

		g.By("7. Check ICMP/TCP/UDP/SCTP traffic between pods in ns1 and ns2, should not be able to access")
		otputils.PingPod2PodFail(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.CurlPod2PodFail(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "UDP", udpPort, false)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "SCTP", sctpPort, false)

		g.By("8. Add annotation to expose default network port on udn pod")
		annotationConf := `k8s.ovn.org/open-default-ports=[{"protocol":"icmp"}, {"protocol":"tcp","port":` + strconv.Itoa(tcpPort) + `}, {"protocol":"udp","port":` + strconv.Itoa(udpPort) + `}, {"protocol":"sctp","port":` + strconv.Itoa(sctpPort) + `}]`
		err = oc.AsAdmin().WithoutNamespace().Run("annotate").Args("pod", pod2Name, "-n", ns2, "--overwrite", annotationConf).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		time.Sleep(10 * time.Second)

		g.By("9. Check ICMP/TCP/UDP/SCTP traffic between pods in ns1 and ns2, should be able to access")
		otputils.PingPod2PodPass(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.CurlPod2PodPass(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "UDP", udpPort, true)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "SCTP", sctpPort, true)

		g.By("10. Check host isolation from node to UDN pod's IP on default network on TCP and ICMP, should be able to access")
		otputils.CurlNode2PodPass(oc, podNodeName, ns2, pod2Name)
		otputils.PingNode2PodPass(oc, podNodeName, ns2, pod2Name)
	})

	g.It("[JIRA:Networking][OTP][Serial] 77742-Check default network ports can be exposed on UDN pods layer2", func() {
		var (
			testDataDir         = testdata.FixturePath("networking")
			netsegDir           = testdata.FixturePath("networking/network_segmentation")
			sctpModule          = filepath.Join(netsegDir, "sctp/load-sctp-module.yaml")
			udnCRDdualStack     = filepath.Join(netsegDir, "udn/udn_crd_layer2_dualstack_template.yaml")
			udnCRDSingleStack   = filepath.Join(netsegDir, "udn/udn_crd_layer2_singlestack_template.yaml")
			statefulSetHelloPod = filepath.Join(testDataDir, "statefulset-hello.yaml")
			tcpPort             = 8080
			udpPort             = 6000
			sctpPort            = 30102
		)

		g.By("Preparing the nodes for SCTP")
		otputils.PrepareSCTPModule(oc, sctpModule)

		g.By("1. Create UDN namespace")
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()

		g.By("2. Create CRD for UDN in ns2")
		var cidr, ipv4cidr, ipv6cidr string
		ipStackType := otputils.CheckIPStackType(oc)
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
		udncrd := otputils.UdnCRDResource{
			Crdname:   "udn-l2-network-77742",
			Namespace: ns2,
			Role:      "Primary",
		}
		if ipStackType == "dualstack" {
			udncrd.IPv4cidr = ipv4cidr
			udncrd.IPv6cidr = ipv6cidr
			udncrd.Template = udnCRDdualStack
			udncrd.CreateLayer2DualStackUDNCRD(oc)
		} else {
			udncrd.Cidr = cidr
			udncrd.Template = udnCRDSingleStack
			udncrd.CreateLayer2SingleStackUDNCRD(oc)
		}
		err := otputils.WaitUDNCRDApplied(oc, ns2, udncrd.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create a udn hello pod in ns2 and get node name")
		otputils.CreateResourceFromFile(oc, ns2, statefulSetHelloPod)
		pod2Err := otputils.WaitForPodWithLabelReady(oc, ns2, "app=hello")
		o.Expect(pod2Err).NotTo(o.HaveOccurred(), "The statefulSet pod is not ready")
		pod2Name := otputils.GetPodName(oc, ns2, "app=hello")[0]

		podNodeName, podNodeNameErr := otputils.GetPodNodeName(oc, ns2, pod2Name)
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())

		g.By("4. Create non UDN namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("5. Create a hello pod in ns1")
		otputils.CreateResourceFromFile(oc, ns1, statefulSetHelloPod)
		pod1Err := otputils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
		o.Expect(pod1Err).NotTo(o.HaveOccurred(), "The statefulSet pod is not ready")
		pod1Name := otputils.GetPodName(oc, ns1, "app=hello")[0]

		g.By("6. Check host isolation from node to UDN pod's IP on default network on TCP/ICMP, should not be able to access")
		otputils.CurlNode2PodFail(oc, podNodeName, ns2, pod2Name)
		otputils.PingNode2PodFail(oc, podNodeName, ns2, pod2Name)

		g.By("7. Check ICMP/TCP/UDP/SCTP traffic between pods in ns1 and ns2, should not be able to access")
		otputils.PingPod2PodFail(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.CurlPod2PodFail(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "UDP", udpPort, false)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "SCTP", sctpPort, false)

		g.By("8. Add annotation to expose default network port on udn pod")
		annotationConf := `k8s.ovn.org/open-default-ports=[{"protocol":"icmp"}, {"protocol":"tcp","port":` + strconv.Itoa(tcpPort) + `}, {"protocol":"udp","port":` + strconv.Itoa(udpPort) + `}, {"protocol":"sctp","port":` + strconv.Itoa(sctpPort) + `}]`
		err = oc.AsAdmin().WithoutNamespace().Run("annotate").Args("pod", pod2Name, "-n", ns2, "--overwrite", annotationConf).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		time.Sleep(10 * time.Second)

		g.By("9. Check ICMP/TCP/UDP/SCTP traffic between pods in ns1 and ns2, should be able to access")
		otputils.PingPod2PodPass(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.CurlPod2PodPass(oc, ns1, pod1Name, ns2, pod2Name)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "UDP", udpPort, true)
		otputils.VerifyConnPod2Pod(oc, ns1, pod1Name, ns2, pod2Name, "SCTP", sctpPort, true)

		g.By("10. Check host isolation from node to UDN pod's IP on default network on TCP/ICMP, should be able to access")
		otputils.CurlNode2PodPass(oc, podNodeName, ns2, pod2Name)
		otputils.PingNode2PodPass(oc, podNodeName, ns2, pod2Name)
	})

	g.It("[JIRA:Networking][OTP] 78152-Check udn pods to kapi dns traffic should pass", func() {
		var (
			testDataDir     = testdata.FixturePath("networking")
			testPodTemplate = filepath.Join(testDataDir, "ping-for-pod-template.yaml")
			serviceTemplate = filepath.Join(testDataDir, "service-generic-template.yaml")
			ns              string
			ipStackType     = otputils.CheckIPStackType(oc)
		)
		g.By("1. create udn namespace")
		oc.CreateNamespaceUDN()
		ns = oc.Namespace()

		g.By("2. Create CRD for UDN")
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

		otputils.CreateGeneralUDNCRD(oc, ns, "udn-78152", ipv4cidr, ipv6cidr, cidr, "layer3")

		g.By("3. Create test pods and service")
		defer otputils.RemoveResource(oc, true, true, "pod", "testpod", "-n", ns)
		err := otputils.ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", testPodTemplate, "-p", "NAME=testpod", "NAMESPACE="+ns, "-n", ns)
		o.Expect(err).NotTo(o.HaveOccurred())

		err = otputils.WaitForPodWithLabelReady(oc, ns, "name=hello-pod")
		o.Expect(err).NotTo(o.HaveOccurred(), "pod with label name=hello-pod not ready")

		testSvc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        "PreferDualStack",
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              serviceTemplate,
		}
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", testSvc.Servicename, "-n", testSvc.Namespace).Execute()
		testSvc.CreateServiceFromParams(oc)

		g.By("4. check kapi traffic from testpod")
		cmd := "curl -k https://kubernetes.default:443/healthz"
		outPut, err := e2eoutput.RunHostCmd(ns, "testpod", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(outPut).Should(o.ContainSubstring("ok"))

		g.By("5. check dns traffic from testpod")
		svcIP1, svcIP2 := otputils.GetSvcIP(oc, ns, testSvc.Servicename)
		cmdDns := "nslookup " + testSvc.Servicename
		outPut, err = e2eoutput.RunHostCmd(ns, "testpod", cmdDns)
		o.Expect(err).NotTo(o.HaveOccurred())
		re1 := regexp.MustCompile(`Address:\s+` + svcIP1)
		res1 := re1.MatchString(outPut)
		o.Expect(res1).To(o.BeTrue())
		if svcIP2 != "" {
			re2 := regexp.MustCompile(`Address:\s+` + svcIP2)
			res2 := re2.MatchString(outPut)
			o.Expect(res2).To(o.BeTrue())
		}
	})

	g.It("[JIRA:Networking][OTP] 78381-Check cudn pods to kapi dns traffic layer 2", func() {
		var (
			testDataDir     = testdata.FixturePath("networking")
			testPodTemplate = filepath.Join(testDataDir, "ping-for-pod-template.yaml")
			serviceTemplate = filepath.Join(testDataDir, "service-generic-template.yaml")
			ns              string
			ipStackType     = otputils.CheckIPStackType(oc)
			values          = []string{"value-78381-1", "value-78381-2"}
			key             = "test.cudn.layer2"
		)
		g.By("1. create udn namespace")
		oc.CreateNamespaceUDN()
		ns = oc.Namespace()

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", key)).Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", key, values[0])).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("2. Create CRD for CUDN")
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

		defer otputils.RemoveResource(oc, true, true, "clusteruserdefinednetwork", "udn-78381")
		_, err = otputils.CreateCUDNCRD(oc, key, "udn-78381", ipv4cidr, ipv6cidr, cidr, "layer2", values)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3. Create test pods and service")
		defer otputils.RemoveResource(oc, true, true, "pod", "testpod", "-n", ns)
		err = otputils.ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", testPodTemplate, "-p", "NAME=testpod", "NAMESPACE="+ns, "-n", ns)
		o.Expect(err).NotTo(o.HaveOccurred())

		err = otputils.WaitForPodWithLabelReady(oc, ns, "name=hello-pod")
		o.Expect(err).NotTo(o.HaveOccurred(), "pod with label name=hello-pod not ready")

		testSvc := otputils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        "PreferDualStack",
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "",
			Template:              serviceTemplate,
		}
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", testSvc.Servicename, "-n", testSvc.Namespace).Execute()
		testSvc.CreateServiceFromParams(oc)

		g.By("4. check kapi traffic from testpod")
		cmd := "curl -k https://kubernetes.default:443/healthz"
		outPut, err := e2eoutput.RunHostCmd(ns, "testpod", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(outPut).Should(o.ContainSubstring("ok"))

		g.By("5. check dns traffic from testpod")
		svcIP1, svcIP2 := otputils.GetSvcIP(oc, ns, testSvc.Servicename)
		cmdDns := "nslookup " + testSvc.Servicename
		outPut, err = e2eoutput.RunHostCmd(ns, "testpod", cmdDns)
		o.Expect(err).NotTo(o.HaveOccurred())
		re1 := regexp.MustCompile(`Address:\s+` + svcIP1)
		res1 := re1.MatchString(outPut)
		o.Expect(res1).To(o.BeTrue())
		if svcIP2 != "" {
			re2 := regexp.MustCompile(`Address:\s+` + svcIP2)
			res2 := re2.MatchString(outPut)
			o.Expect(res2).To(o.BeTrue())
		}
	})

	g.It("[JIRA:Networking][OTP] 79095-Verify event is generated for IP exhaustion in user defined network", func() {
		var (
			testDataDirUDN = testdata.FixturePath("networking/network_segmentation/udn")
			udnNadtemplate = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			udnPodTemplate = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			testID         = "79095"
		)

		ipStackType := otputils.CheckIPStackType(oc)
		if ipStackType == "ipv6single" {
			g.Skip("This case cannot be run on ipv6 cluster")
		}

		g.By("1. Create a namespace")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		g.By("2. Create UDN NAD")
		nadResourcename := "l3-network-" + testID + "-" + ns1
		var subnet string
		if ipStackType == "ipv4single" {
			subnet = "10.200.0.0/16/30"
		} else {
			subnet = "10.200.0.0/16/30,2011:100:200::/60"
		}

		g.By(fmt.Sprintf("create NAD %s in namespace %s", nadResourcename, ns1))
		nad := otputils.UdnNetDefResource{
			Nadname:          nadResourcename,
			Namespace:        ns1,
			NadNetworkName:   nadResourcename,
			Topology:         "layer3",
			Subnet:           subnet,
			NetAttachDefName: ns1 + "/" + nadResourcename,
			Role:             "primary",
			Template:         udnNadtemplate,
		}
		nad.CreateUdnNad(oc)

		g.By("3. Create a udn hello pod in ns1")
		pod1 := otputils.UdnPodResource{
			Name:      "hello-pod-" + testID + "-ns1",
			Namespace: ns1,
			Label:     "hello-pod",
			Template:  udnPodTemplate,
		}
		pod1.CreateUdnPod(oc)

		g.By("4. Poll event log for IP allocation failure")
		o.Eventually(func() string {
			eventOutput, _ := oc.AsAdmin().Run("get").Args("event").Output()
			return eventOutput
		}, "60s", "5s").Should(o.ContainSubstring("failed to allocate new IPs"))
	})
})
