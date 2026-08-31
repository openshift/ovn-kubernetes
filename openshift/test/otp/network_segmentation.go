package otp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	exutil "github.com/openshift/origin/test/extended/util"

	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/utils"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"

	"k8s.io/apimachinery/pkg/util/wait"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

// isIPInCIDR checks if an IP address is within a CIDR range
func isIPInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

var _ = Describe("Network Segmentation", func() {
	defer GinkgoRecover()

	var oc = exutil.NewCLI("network-segmentation")

	BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	// 81190 - Verify IP Block network policy with CUDN with localnet topology
	//
	// Prerequisites (must be installed on cluster before running test):
	// 1. NMState Operator - Required for NodeNetworkConfigurationPolicy (NNCP) support
	//    See nmstate-install.yaml and nmstate-instance.yaml for installation
	//
	// The test will automatically:
	// - Enable MultiNetworkPolicy support via cluster network operator (if not already enabled)
	// - Create and cleanup all test resources (namespaces, CUDN, policies, pods, etc.)
	It("[JIRA:Networking][OTP][sig-network] 81190 Verify IP Block network policy with CUDN with localnet topology", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking")
			nncpFile                     = filepath.Join(buildPruningBaseDir, "cudn/nncp-bridge-mapping.yaml")
			cudnFile                     = filepath.Join(buildPruningBaseDir, "cudn/cluster-udn-localnet.yaml")
			statefulsetFile              = filepath.Join(buildPruningBaseDir, "cudn/statefulset-hello-cudn.yaml")
			multiNetPolIngressTemplate   = filepath.Join(buildPruningBaseDir, "networkpolicy/cudn/multi-networkpolicy-ingress-ipblock-template.yaml")
			multiNetPolEgressTemplate    = filepath.Join(buildPruningBaseDir, "networkpolicy/cudn/multi-networkpolicy-egress-ipblock-template.yaml")
			originalMultiNetPolSetting   string
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		Expect(err).NotTo(HaveOccurred())
		if len(nodeList.Items) < 2 {
			Skip("This case requires at least 2 worker nodes")
		}

		By("Step 0: Enable MultiNetworkPolicy support if not already enabled")
		// Check if MultiNetworkPolicy is enabled and save original value
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("network.operator.openshift.io", "cluster", "-o", "jsonpath={.spec.useMultiNetworkPolicy}").Output()
		originalMultiNetPolSetting = strings.TrimSpace(output)

		if err != nil || originalMultiNetPolSetting != "true" {
			By("Enabling MultiNetworkPolicy in cluster network operator")
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("network.operator.openshift.io", "cluster", "--type=merge", "-p", `{"spec":{"useMultiNetworkPolicy":true}}`).Execute()
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for MultiNetworkPolicy CRD to be available")
			err = wait.PollImmediate(10*time.Second, 5*time.Minute, func() (bool, error) {
				_, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd", "multi-networkpolicies.k8s.cni.cncf.io").Output()
				return err == nil, nil
			})
			Expect(err).NotTo(HaveOccurred(), "MultiNetworkPolicy CRD did not become available")

			// Register cleanup to restore MultiNetworkPolicy setting
			DeferCleanup(func() {
				if originalMultiNetPolSetting != "" && originalMultiNetPolSetting != "true" {
					By("Cleanup: Restoring original MultiNetworkPolicy setting")
					patchValue := fmt.Sprintf(`{"spec":{"useMultiNetworkPolicy":%s}}`, originalMultiNetPolSetting)
					_ = oc.AsAdmin().WithoutNamespace().Run("patch").Args("network.operator.openshift.io", "cluster", "--type=merge", "-p", patchValue).Execute()
				}
			})
		}

		By("Step 1: Create NNCP policy to map another network to br-ex ovs-bridge")
		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", nncpFile).Execute()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			By("Cleanup - Delete NNCP")
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("nncp", "bridge-mapping", "--ignore-not-found=true").Execute()
		})

		By("Wait for NNCP to be Available")
		err = wait.PollImmediate(5*time.Second, 3*time.Minute, func() (bool, error) {
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nncp", "bridge-mapping", "-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}").Output()
			if err != nil {
				return false, nil
			}
			return strings.Contains(output, "True"), nil
		})
		Expect(err).NotTo(HaveOccurred(), "NNCP bridge-mapping did not become Available")

		By("Step 2: Create first UDN namespace a1")
		err = oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", "a1").Execute()
		Expect(err).NotTo(HaveOccurred())
		ns1 := "a1"
		DeferCleanup(func() {
			By("Cleanup - Delete namespace a1")
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("namespace", ns1, "--ignore-not-found=true").Execute()
		})

		By("Step 3: Create second UDN namespace a2")
		err = oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", "a2").Execute()
		Expect(err).NotTo(HaveOccurred())
		ns2 := "a2"
		DeferCleanup(func() {
			By("Cleanup - Delete namespace a2")
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("namespace", ns2, "--ignore-not-found=true").Execute()
		})

		By("Step 4: Create ClusterUserDefinedNetwork secondary Localnet")
		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", cudnFile).Execute()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			By("Cleanup - Delete ClusterUserDefinedNetwork")
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("clusteruserdefinednetwork", "sec-localnet-net-ipblock", "--ignore-not-found=true").Execute()
		})

		By("Wait for ClusterUserDefinedNetwork to be ready")
		err = wait.PollImmediate(10*time.Second, 10*time.Minute, func() (bool, error) {
			// Check if CUDN exists and has NetworkCreated=True condition
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusteruserdefinednetwork", "sec-localnet-net-ipblock", "-o", "jsonpath={.status.conditions[?(@.type=='NetworkCreated')].status}").Output()
			if err != nil {
				fmt.Printf("CUDN check error: %v\n", err)
				return false, nil
			}

			if strings.Contains(output, "True") {
				fmt.Printf("CUDN NetworkCreated=True\n")
				return true, nil
			}

			// Debug: print current status
			statusOutput, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusteruserdefinednetwork", "sec-localnet-net-ipblock", "-o", "jsonpath={.status}").Output()
			fmt.Printf("CUDN status: %s\n", statusOutput)
			return false, nil
		})
		Expect(err).NotTo(HaveOccurred(), "ClusterUserDefinedNetwork did not become ready")

		By("Step 5: Deploy StatefulSet with 3 pods in namespace a1")
		otputils.CreateResourceFromFile(oc, ns1, statefulsetFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns1, "app=hello")
		Expect(err).NotTo(HaveOccurred(), "StatefulSet pods not ready in namespace a1")

		helloPodNamesNs1 := otputils.GetPodName(oc, ns1, "app=hello")
		Expect(len(helloPodNamesNs1)).To(Equal(3), "Expected 3 pods in namespace a1")

		By("Step 6: Deploy StatefulSet with 3 pods in namespace a2")
		otputils.CreateResourceFromFile(oc, ns2, statefulsetFile)
		err = otputils.WaitForPodWithLabelReady(oc, ns2, "app=hello")
		Expect(err).NotTo(HaveOccurred(), "StatefulSet pods not ready in namespace a2")

		helloPodNamesNs2 := otputils.GetPodName(oc, ns2, "app=hello")
		Expect(len(helloPodNamesNs2)).To(Equal(3), "Expected 3 pods in namespace a2")

		By("Step 7: Get CUDN IP addresses and node locations for all pods")
		// Get pod to node mapping for both namespaces
		podToNodeNs1 := make(map[string]string)
		podToNodeNs2 := make(map[string]string)
		podToIPsNs1 := make(map[string][]string)
		podToIPsNs2 := make(map[string][]string)

		for _, podName := range helloPodNamesNs1 {
			node, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", ns1, "-o", "jsonpath={.spec.nodeName}").Output()
			Expect(err).NotTo(HaveOccurred())
			podToNodeNs1[podName] = node

			ips, err := getCUDNPodIPs(oc, ns1, podName)
			Expect(err).NotTo(HaveOccurred())
			podToIPsNs1[podName] = ips
		}

		for _, podName := range helloPodNamesNs2 {
			node, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", ns2, "-o", "jsonpath={.spec.nodeName}").Output()
			Expect(err).NotTo(HaveOccurred())
			podToNodeNs2[podName] = node

			ips, err := getCUDNPodIPs(oc, ns2, podName)
			Expect(err).NotTo(HaveOccurred())
			podToIPsNs2[podName] = ips
		}

		// Find same-node pod pairs for connectivity testing
		type PodPair struct {
			ns1Pod, ns2Pod string
			ns1IPs, ns2IPs []string
		}
		var sameNodePairs []PodPair

		for ns1Pod, ns1Node := range podToNodeNs1 {
			for ns2Pod, ns2Node := range podToNodeNs2 {
				if ns1Node == ns2Node {
					sameNodePairs = append(sameNodePairs, PodPair{
						ns1Pod: ns1Pod,
						ns2Pod: ns2Pod,
						ns1IPs: podToIPsNs1[ns1Pod],
						ns2IPs: podToIPsNs2[ns2Pod],
					})
					break // Only need one pair per ns1 pod
				}
			}
		}

		Expect(len(sameNodePairs)).To(BeNumerically(">=", 2), "Need at least 2 same-node pod pairs for testing")
		By(fmt.Sprintf("Found %d same-node pod pairs for connectivity testing", len(sameNodePairs)))

		By("Step 8: Verify all pods can communicate before applying NetworkPolicy")
		// Use same-node pod pairs for localnet topology (cross-node traffic requires physical network configuration)
		verifyCurlSuccess(oc, ns1, sameNodePairs[0].ns1Pod, sameNodePairs[0].ns2IPs[0],
			fmt.Sprintf("Before policy: %s to %s (same node)", sameNodePairs[0].ns1Pod, sameNodePairs[0].ns2Pod))
		verifyCurlSuccess(oc, ns1, sameNodePairs[1].ns1Pod, sameNodePairs[1].ns2IPs[0],
			fmt.Sprintf("Before policy: %s to %s (same node)", sameNodePairs[1].ns1Pod, sameNodePairs[1].ns2Pod))
		verifyCurlSuccess(oc, ns2, sameNodePairs[0].ns2Pod, sameNodePairs[0].ns1IPs[0],
			fmt.Sprintf("Before policy: %s to %s (same node)", sameNodePairs[0].ns2Pod, sameNodePairs[0].ns1Pod))

		By("Step 9: Create Ingress IPBlock MultiNetworkPolicy in namespace a1")
		// Allow ingress only from 192.168.100.0/30 (IPs: .0, .1, .2, .3) and fd00:192:168:100::/126
		ingressPolicyNs1 := otputils.IpBlockCIDRsSingle{
			Name:      "ingress-ipblock",
			Template:  multiNetPolIngressTemplate,
			Cidr:      "192.168.100.0/30",
			Cidr2:     "fd00:192:168:100::/126",
			Namespace: ns1,
		}
		ingressPolicyNs1.CreateipBlockCIDRObjectSingle(oc)

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("multi-networkpolicies.k8s.cni.cncf.io", "-n", ns1).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(ContainSubstring("ingress-ipblock"))

		By("Wait for MultiNetworkPolicy to be applied")
		time.Sleep(10 * time.Second)

		By("Step 10: Verify Ingress IPBlock policy enforcement in namespace a1")
		// Test both IPv4 (Cidr) and IPv6 (Cidr2) ingress filtering
		for _, cidrTest := range []struct {
			cidr     string
			ipFamily string
		}{
			{ingressPolicyNs1.Cidr, "IPv4"},
			{ingressPolicyNs1.Cidr2, "IPv6"},
		} {
			if cidrTest.cidr == "" {
				continue // Skip if CIDR not defined
			}

			By(fmt.Sprintf("Testing ingress policy for %s CIDR: %s", cidrTest.ipFamily, cidrTest.cidr))
			var inRangePair, outRangePair *PodPair

			for i := range sameNodePairs {
				pair := &sameNodePairs[i]
				// Check each IP in ns2IPs array
				for _, ns2IP := range pair.ns2IPs {
					if isIPInCIDR(ns2IP, cidrTest.cidr) {
						if inRangePair == nil {
							inRangePair = pair
							verifyCurlSuccess(oc, ns2, pair.ns2Pod, pair.ns1IPs[0],
								fmt.Sprintf("Ingress allowed (%s): %s (IP %s) to %s (source in range, same node)",
									cidrTest.ipFamily, pair.ns2Pod, ns2IP, pair.ns1Pod))
						}
					} else {
						if outRangePair == nil {
							outRangePair = pair
							verifyCurlFailure(oc, ns2, pair.ns2Pod, pair.ns1IPs[0],
								fmt.Sprintf("Ingress blocked (%s): %s (IP %s) to %s (source outside range, same node)",
									cidrTest.ipFamily, pair.ns2Pod, ns2IP, pair.ns1Pod))
						}
					}
					if inRangePair != nil && outRangePair != nil {
						break
					}
				}
				if inRangePair != nil && outRangePair != nil {
					break
				}
			}
		}

		By("Step 11: Delete Ingress policy and verify connectivity is restored")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("multi-networkpolicies.k8s.cni.cncf.io", "ingress-ipblock", "-n", ns1).Execute()
		Expect(err).NotTo(HaveOccurred())
		time.Sleep(5 * time.Second)

		verifyCurlSuccess(oc, ns2, sameNodePairs[0].ns2Pod, sameNodePairs[0].ns1IPs[0],
			fmt.Sprintf("After ingress policy deletion: %s to %s (same node)", sameNodePairs[0].ns2Pod, sameNodePairs[0].ns1Pod))

		By("Step 12: Create Egress IPBlock MultiNetworkPolicy in both namespaces")
		// Allow egress only to 192.168.100.0/30 and fd00:192:168:100::/126
		egressPolicyNs1 := otputils.IpBlockCIDRsSingle{
			Name:      "egress-ipblock",
			Template:  multiNetPolEgressTemplate,
			Cidr:      "192.168.100.0/30",
			Cidr2:     "fd00:192:168:100::/126",
			Namespace: ns1,
		}
		egressPolicyNs1.CreateipBlockCIDRObjectSingle(oc)

		egressPolicyNs2 := otputils.IpBlockCIDRsSingle{
			Name:      "egress-ipblock",
			Template:  multiNetPolEgressTemplate,
			Cidr:      "192.168.100.0/30",
			Cidr2:     "fd00:192:168:100::/126",
			Namespace: ns2,
		}
		egressPolicyNs2.CreateipBlockCIDRObjectSingle(oc)

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("multi-networkpolicies.k8s.cni.cncf.io", "-n", ns1).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(ContainSubstring("egress-ipblock"))

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("multi-networkpolicies.k8s.cni.cncf.io", "-n", ns2).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(ContainSubstring("egress-ipblock"))

		By("Wait for Egress MultiNetworkPolicy to be applied")
		time.Sleep(10 * time.Second)

		By("Step 13: Verify Egress IPBlock policy enforcement")
		// Test both IPv4 (Cidr) and IPv6 (Cidr2) egress filtering
		for _, cidrTest := range []struct {
			cidr     string
			ipFamily string
		}{
			{egressPolicyNs1.Cidr, "IPv4"},
			{egressPolicyNs1.Cidr2, "IPv6"},
		} {
			if cidrTest.cidr == "" {
				continue // Skip if CIDR not defined
			}

			By(fmt.Sprintf("Testing egress policy for %s CIDR: %s", cidrTest.ipFamily, cidrTest.cidr))

			type EgressTest struct {
				srcNamespace, srcPod, destPod, destIP string
			}
			var allowedTests, blockedTests []EgressTest

			// Check all same-node pairs, testing both ns1→ns2 and ns2→ns1 traffic
			for i := range sameNodePairs {
				pair := &sameNodePairs[i]

				// Check ns1→ns2 traffic for each ns2 IP
				for _, ns2IP := range pair.ns2IPs {
					if isIPInCIDR(ns2IP, cidrTest.cidr) {
						allowedTests = append(allowedTests, EgressTest{ns1, pair.ns1Pod, pair.ns2Pod, ns2IP})
					} else {
						blockedTests = append(blockedTests, EgressTest{ns1, pair.ns1Pod, pair.ns2Pod, ns2IP})
					}
				}

				// Check ns2→ns1 traffic for each ns1 IP
				for _, ns1IP := range pair.ns1IPs {
					if isIPInCIDR(ns1IP, cidrTest.cidr) {
						allowedTests = append(allowedTests, EgressTest{ns2, pair.ns2Pod, pair.ns1Pod, ns1IP})
					} else {
						blockedTests = append(blockedTests, EgressTest{ns2, pair.ns2Pod, pair.ns1Pod, ns1IP})
					}
				}
			}

			// Run at least one test for allowed traffic if available
			if len(allowedTests) > 0 {
				test := allowedTests[0]
				verifyCurlSuccess(oc, test.srcNamespace, test.srcPod, test.destIP,
					fmt.Sprintf("Egress allowed (%s): %s to %s (IP %s, dest in range, same node)",
						cidrTest.ipFamily, test.srcPod, test.destPod, test.destIP))
			}

			// Run at least one test for blocked traffic if available
			if len(blockedTests) > 0 {
				test := blockedTests[0]
				verifyCurlFailure(oc, test.srcNamespace, test.srcPod, test.destIP,
					fmt.Sprintf("Egress blocked (%s): %s to %s (IP %s, dest outside range, same node)",
						cidrTest.ipFamily, test.srcPod, test.destPod, test.destIP))
			}
		}

		By("Step 14: Cleanup - Delete Egress policies")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("multi-networkpolicies.k8s.cni.cncf.io", "egress-ipblock", "-n", ns1).Execute()
		Expect(err).NotTo(HaveOccurred())
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("multi-networkpolicies.k8s.cni.cncf.io", "egress-ipblock", "-n", ns2).Execute()
		Expect(err).NotTo(HaveOccurred())

		By("Step 15: Verify connectivity is restored after policy deletion")
		time.Sleep(5 * time.Second)
		if len(sameNodePairs) > 1 {
			verifyCurlSuccess(oc, ns1, sameNodePairs[1].ns1Pod, sameNodePairs[1].ns2IPs[0],
				fmt.Sprintf("After egress policy deletion: %s to %s (same node)", sameNodePairs[1].ns1Pod, sameNodePairs[1].ns2Pod))
		}
	})
})

// getCUDNPodIPs extracts all CUDN IP addresses (IPv4 and IPv6) from the pod's network-status annotation
func getCUDNPodIPs(oc *exutil.CLI, namespace, podName string) ([]string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", namespace, "-o", "jsonpath={.metadata.annotations.k8s\\.v1\\.cni\\.cncf\\.io/network-status}").Output()
	if err != nil {
		return nil, err
	}

	// Unmarshal the network-status JSON
	var networkStatuses []nettypes.NetworkStatus
	if err := json.Unmarshal([]byte(output), &networkStatuses); err != nil {
		return nil, fmt.Errorf("failed to unmarshal network-status annotation: %v", err)
	}

	// Find the sec-localnet-net-ipblock network entry with ovn-udn2 interface
	for _, ns := range networkStatuses {
		if ns.Name == "sec-localnet-net-ipblock" && ns.Interface == "ovn-udn2" {
			// Return all IPs (both IPv4 and IPv6 for dual-stack)
			if len(ns.IPs) > 0 {
				return ns.IPs, nil
			}
		}
	}

	// Fallback: use ip command to get IPs from ovn-udn2 interface
	var ips []string
	for _, ipVersion := range []struct {
		flag   string
		filter string
	}{
		{"-4", "inet "},
		{"-6", "inet6 "},
	} {
		cmd := fmt.Sprintf("ip %s addr show ovn-udn2 | grep '%s' | awk '{print $2}' | cut -d'/' -f1 | head -n1", ipVersion.flag, ipVersion.filter)
		output, err = e2eoutput.RunHostCmd(namespace, podName, cmd)
		if err == nil {
			ip := strings.TrimSpace(output)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
	}

	if len(ips) > 0 {
		return ips, nil
	}

	return nil, fmt.Errorf("no IP addresses found on interface ovn-udn2 for pod %s", podName)
}

// getCUDNPodIP extracts the primary CUDN IP address (backward compatibility)
func getCUDNPodIP(oc *exutil.CLI, namespace, podName string) (string, error) {
	ips, err := getCUDNPodIPs(oc, namespace, podName)
	if err != nil {
		return "", err
	}
	if len(ips) > 0 {
		return ips[0], nil
	}
	return "", fmt.Errorf("no IP address found on interface ovn-udn2 for pod %s", podName)
}

// verifyCurlSuccess verifies that curl succeeds
func verifyCurlSuccess(oc *exutil.CLI, namespace, podName, targetIP, description string) {
	By(description)
	output, err := e2eoutput.RunHostCmd(namespace, podName, fmt.Sprintf("curl --interface ovn-udn2 %s:8080 --connect-timeout 5", targetIP))
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Expected curl to succeed: %s", description))
	Expect(output).Should(ContainSubstring("Hello OpenShift"))
}

// verifyCurlFailure verifies that curl fails with timeout
func verifyCurlFailure(oc *exutil.CLI, namespace, podName, targetIP, description string) {
	By(description)
	_, err := e2eoutput.RunHostCmd(namespace, podName, fmt.Sprintf("curl --interface ovn-udn2 %s:8080 --connect-timeout 5", targetIP))
	Expect(err).To(HaveOccurred(), fmt.Sprintf("Expected curl to fail: %s", description))
	Expect(err.Error()).Should(ContainSubstring("exit status 28"), "Expected connection timeout")
}
