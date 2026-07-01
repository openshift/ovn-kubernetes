package otp

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"
	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/utils"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"

	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

var _ = g.Describe("[sig-network][Feature:IPsec][Suite:openshift/network/ipsec] SDN IPsec", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-ipsec")

	g.It("[JIRA:Networking][OTP] 80232-After node rebooting IPSec pod2pod connection should work", g.Label("Disruptive"), func() {
		ipsecState := otputils.CheckIPsec(oc)
		if ipsecState == "Disabled" {
			g.Skip("IPsec not enabled, skipping test")
		}
		if ipsecState != "Full" {
			g.Skip("IPSec mode is not Full, skipping test")
		}

		testdataDir := testdata.FixturePath("networking")
		helloDaemonset := filepath.Join(testdataDir, "hello-pod-daemonset.yaml")
		ns := oc.Namespace()

		g.By("Verify IPSec loaded")
		nodes, err := otputils.GetAllNodesbyOSType(oc, "linux")
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The cluster has %v nodes", len(nodes))

		g.By("Get one worker node for rebooting")
		workerNode, err := otputils.GetFirstWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if otputils.IsHypershiftHostedCluster(oc) {
			otputils.VerifyIPSecLoadedInContainers(oc, len(nodes))
		} else {
			otputils.VerifyIPSecLoaded(oc, nodes[0], len(nodes))
		}

		g.By("Verify ipsec pods running before node rebooting")
		err = otputils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Create hello-pod-daemonset")
		otputils.CreateResourceFromFile(oc, ns, helloDaemonset)
		err = otputils.WaitForPodWithLabelReady(oc, ns, "name=hello-pod")
		o.Expect(err).NotTo(o.HaveOccurred(), "hello pods not ready before reboot")

		g.By("Check pod connectivity across nodes before reboot")
		o.Expect(otputils.VerifyPodConnCrossNodesSpecNS(oc, ns, "name=hello-pod")).Should(o.BeTrue(), "Pod connectivity check failed before reboot")

		g.By("Reboot the worker node")
		g.DeferCleanup(func() {
			otputils.CheckNodeStatus(oc, workerNode, "Ready")
		})
		otputils.RebootNode(oc, workerNode)
		otputils.CheckNodeStatus(oc, workerNode, "NotReady")
		otputils.CheckNodeStatus(oc, workerNode, "Ready")

		g.By("Wait for test pods to be running after reboot")
		err = otputils.WaitForPodWithLabelReady(oc, ns, "name=hello-pod")
		o.Expect(err).NotTo(o.HaveOccurred(), "hello pods not ready after reboot")

		g.By("Verify IPSec loaded after node reboot")
		if otputils.IsHypershiftHostedCluster(oc) {
			otputils.VerifyIPSecLoadedInContainers(oc, len(nodes))
		} else {
			otputils.VerifyIPSecLoaded(oc, nodes[0], len(nodes))
		}

		g.By("Verify ipsec pods running after node reboot")
		err = otputils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Check pod connectivity across nodes after reboot")
		o.Expect(otputils.VerifyPodConnCrossNodesSpecNS(oc, ns, "name=hello-pod")).Should(o.BeTrue(), "Pod connectivity check failed after reboot")
	})

	g.It("[JIRA:Networking][OTP] 67474-69176-IPSec tunnel up after restart or reboot node", g.Label("Serial", "Disruptive"), func() {
		rightIP, rightNode, _, _, leftIP, _, nodeCert, _ := setupIPsecNS(oc)

		g.By("Configure nmstate ipsec policy")
		otputils.CreateIPsecNMStateCR(oc)
		g.DeferCleanup(func() {
			otputils.DeleteIPsecNMStateCR(oc)
		})

		policyName := "ipsec-policy-transport-69176"
		tunnelName := "ipsec-transport-69176"
		g.DeferCleanup(func() {
			otputils.RemoveIPSecNNCP(oc, policyName, tunnelName, rightNode)
		})
		otputils.ConfigIPSecNNCP(oc, policyName, rightIP, rightNode, tunnelName, leftIP, nodeCert, "transport")

		g.By("Verify IPSec tunnel is up")
		otputils.VerifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		g.By("Reboot node with IPSec NS configured")
		g.DeferCleanup(func() {
			otputils.CheckNodeStatus(oc, rightNode, "Ready")
		})
		otputils.RebootNode(oc, rightNode)
		otputils.CheckNodeStatus(oc, rightNode, "NotReady")
		otputils.CheckNodeStatus(oc, rightNode, "Ready")

		g.By("Verify IPSec tunnel restored after reboot")
		o.Eventually(func() bool {
			cmd := fmt.Sprintf("ip xfrm policy get src %s dst %s dir out ; ip xfrm policy get src %s dst %s dir in", otputils.IpsecHostCIDR(rightIP), otputils.IpsecHostCIDR(leftIP), otputils.IpsecHostCIDR(leftIP), otputils.IpsecHostCIDR(rightIP))
			ipXfrmPolicy, ipsecErr := otputils.DebugNodeWithChroot(oc, rightNode, "/bin/bash", "-c", cmd)
			return ipsecErr == nil && strings.Contains(ipXfrmPolicy, "transport")
		}, "300s", "30s").Should(o.BeTrue(), "IPSec tunnel connection was not restored after reboot")

		g.By("Start tcpdump on ipsec right node")
		phyInf, nicError := otputils.GetSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		otputils.SetNamespacePrivileged(oc, oc.Namespace())
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().WithoutNamespace().Run("debug").Args("-n", "default", "node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer cmdTcpdump.Process.Kill()

		time.Sleep(5 * time.Second)
		g.By("Verify ICMP between nodes is encrypted by ESP")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = otputils.DebugNodeWithChroot(oc, rightNode, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump output: %s", cmdOutput.String())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring("ESP"))
	})

	g.It("[JIRA:Networking][OTP] 69178-38873-Tunnel mode setup and teardown via nmstate config", g.Label("Serial", "Disruptive"), func() {
		_, _, rightIP2, rightNode2, leftIP, leftNode, _, nodeCert2 := setupIPsecNS(oc)

		g.By("Configure nmstate ipsec policy")
		otputils.CreateIPsecNMStateCR(oc)
		g.DeferCleanup(func() {
			otputils.DeleteIPsecNMStateCR(oc)
		})

		policyName := "ipsec-policy-tunnel-69178"
		tunnelName := "plutoTunnelVM"
		nncpRemoved := false
		g.DeferCleanup(func() {
			if !nncpRemoved {
				otputils.RemoveIPSecNNCP(oc, policyName, tunnelName, rightNode2)
			}
		})
		otputils.ConfigIPSecNNCP(oc, policyName, rightIP2, rightNode2, tunnelName, leftIP, nodeCert2, "tunnel")

		g.By("Verify IPSec tunnel is up")
		otputils.VerifyIPSecTunnelUp(oc, rightNode2, rightIP2, leftIP, "tunnel")

		g.By("Start tcpdump on ipsec right node")
		phyInf, nicError := otputils.GetSnifPhyInf(oc, rightNode2)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		otputils.SetNamespacePrivileged(oc, oc.Namespace())
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().WithoutNamespace().Run("debug").Args("-n", "default", "node/"+rightNode2, "--", "bash", "-c", tcpdumpCmd).Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer cmdTcpdump.Process.Kill()

		time.Sleep(5 * time.Second)
		g.By("Verify ICMP encrypted by ESP")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = otputils.DebugNodeWithChroot(oc, rightNode2, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump output: %s", cmdOutput.String())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring("ESP"))

		g.By("Remove IPSec interface")
		otputils.RemoveIPSecNNCP(oc, policyName, tunnelName, rightNode2)
		nncpRemoved = true

		g.By("Verify IPSec interface was removed from node")
		ifaceList, ifaceErr := otputils.DebugNodeWithChroot(oc, rightNode2, "nmcli", "con", "show")
		o.Expect(ifaceErr).NotTo(o.HaveOccurred())
		o.Expect(ifaceList).NotTo(o.ContainSubstring(tunnelName))

		g.By("Verify the tunnel was torn down")
		otputils.VerifyIPSecTunnelDown(oc, rightNode2, rightIP2, leftIP, "tunnel")

		g.By("Verify connectivity to peer node is not broken")
		cmd := fmt.Sprintf("ip x p flush; ip x s flush; sleep 2; ping -c4 %s", rightIP2)
		_, err = otputils.DebugNodeWithChroot(oc, leftNode, "bash", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
	})
})

func setupIPsecNS(oc *exutil.CLI) (rightIP, rightNode, rightIP2, rightNode2, leftIP, leftNode, nodeCert, nodeCert2 string) {
	ipsecState := otputils.CheckIPsec(oc)
	if ipsecState == "Disabled" {
		g.Skip("IPsec not enabled, skipping test")
	}

	nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
	o.Expect(err).NotTo(o.HaveOccurred())
	if len(nodeList.Items) < 3 {
		g.Skip("IPSec NS tests require 3 nodes, but the cluster has fewer")
	}

	g.By("Check libreswan packages on nodes")
	rpmOutput, err := otputils.DebugNodeWithChroot(oc, nodeList.Items[0].Name, "bash", "-c", "rpm -qa | grep -i libreswan")
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(rpmOutput).To(o.ContainSubstring("libreswan-"))
	o.Expect(rpmOutput).To(o.ContainSubstring("NetworkManager-libreswan"))

	nodeNames := make([]string, 3)
	for i := 0; i < 3; i++ {
		nodeNames[i] = nodeList.Items[i].Name
	}
	sort.Strings(nodeNames)

	_, ip0 := otputils.GetNodeIP(oc, nodeNames[0])
	_, ip1 := otputils.GetNodeIP(oc, nodeNames[1])
	_, ip2 := otputils.GetNodeIP(oc, nodeNames[2])

	rightIP = ip0
	rightIP2 = ip1
	leftIP = ip2
	rightNode = otputils.GetNodeNameByIPv4(oc, rightIP)
	rightNode2 = otputils.GetNodeNameByIPv4(oc, rightIP2)
	leftNode = otputils.GetNodeNameByIPv4(oc, leftIP)
	nodeCert = otputils.IPsecCertName(rightIP)
	nodeCert2 = otputils.IPsecCertName(rightIP2)

	o.Expect(rightNode).NotTo(o.BeEmpty(), "Could not find node for IP %s", rightIP)
	o.Expect(rightNode2).NotTo(o.BeEmpty(), "Could not find node for IP %s", rightIP2)
	o.Expect(leftNode).NotTo(o.BeEmpty(), "Could not find node for IP %s", leftIP)

	if !otputils.IPsecCertsMCExists(oc) {
		g.By("Generate and deploy IPsec certificates")
		allIPs := []string{rightIP, rightIP2, leftIP}
		certs, certErr := otputils.GenerateIPsecCerts(allIPs)
		o.Expect(certErr).NotTo(o.HaveOccurred(), "Failed to generate IPsec certificates")

		rightIPs := []string{rightIP, rightIP2}
		deployErr := otputils.DeployIPsecCertsMachineConfig(oc, certs, leftIP, rightIPs)
		o.Expect(deployErr).NotTo(o.HaveOccurred(), "Failed to deploy IPsec certificates MachineConfig")
	} else {
		e2e.Logf("IPsec cert MachineConfig already present, skipping deployment")
	}

	return
}
