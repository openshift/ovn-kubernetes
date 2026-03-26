package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	"github.com/openshift/origin/test/extended/util/compat_otp"
	"github.com/tidwall/gjson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN IPSEC EW", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-ipsec", compat_otp.KubeConfigPath())

	g.BeforeEach(func() {
		networkType := compat_otp.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip case on cluster that has non-OVN network plugin!!")
		}

		ipsecState := checkIPsec(oc)
		if !strings.Contains(g.CurrentSpecReport().FullText(), "Skipped Setup") && ipsecState != "{}" && ipsecState != "Full" {
			g.Skip("IPsec not enabled or not a Skipped Setup specific case, skipping test!")
		}

	})

	// author: rbrattai@redhat.com
	g.It("Author:rbrattai-High-66652-Verify IPsec encapsulation is enabled for NAT-T", func() {
		// Epic https://issues.redhat.com/browse/SDN-2629

		platform := checkPlatform(oc)
		if !strings.Contains(platform, "ibmcloud") {
			g.Skip("Test requires IBMCloud, skip for other platforms!")
		}

		ns := "openshift-ovn-kubernetes"
		compat_otp.By("Checking ipsec_encapsulation in ovnkube-node pods")

		podList, podListErr := oc.AdminKubeClient().CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{
			LabelSelector: "app=ovnkube-node",
		})
		o.Expect(podListErr).NotTo(o.HaveOccurred())

		for _, pod := range podList.Items {
			cmd := "ovn-nbctl --no-leader-only get NB_Global . options"
			e2e.Logf("The command is: %v", cmd)
			command1 := []string{"-n", ns, "-c", "nbdb", pod.Name, "--", "bash", "-c", cmd}
			out, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args(command1...).Output()
			if err != nil {
				e2e.Logf("Execute command failed with  err:%v  and output is %v.", err, out)
			}
			o.Expect(err).NotTo(o.HaveOccurred())

			o.Expect(out).To(o.ContainSubstring(`ipsec_encapsulation="true"`))
		}

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-38846-Should be able to send node to node ESP traffic on IPsec clusters", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking/sriov")
			hostnwPodTmp        = filepath.Join(buildPruningBaseDir, "net-admin-cap-pod-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		compat_otp.By("Obtain a namespace.")
		ns1 := oc.Namespace()
		//Required for hostnetwork pod
		compat_otp.By("Set namespace as privileged for Hostnetworked Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("Create 1st hello pod in ns1")
		//create hostnetwork pod on worker0 and worker1, reuse sriov functions for hostnetwork creation which is actually not related to sriov.
		pod1 := sriovNetResource{
			name:      "host-pod1",
			namespace: ns1,
			tempfile:  hostnwPodTmp,
			kind:      "pod",
		}

		pod2 := sriovNetResource{
			name:      "host-pod2",
			namespace: ns1,
			tempfile:  hostnwPodTmp,
			kind:      "pod",
		}

		pod1.create(oc, "PODNAME="+pod1.name, "NODENAME="+nodeList.Items[0].Name)
		defer pod1.delete(oc)
		pod2.create(oc, "PODNAME="+pod2.name, "NODENAME="+nodeList.Items[1].Name)
		defer pod2.delete(oc)
		errPodRdy5 := waitForPodWithLabelReady(oc, ns1, "name="+pod1.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy5, "hostnetwork pod isn't ready")
		errPodRdy6 := waitForPodWithLabelReady(oc, ns1, "name="+pod2.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy6, "hostnetwork pod isn't ready")

		compat_otp.By("Send ESP traffic from pod1")
		nodeIP1, nodeIP2 := getNodeIP(oc, nodeList.Items[1].Name)
		socatCmd := fmt.Sprintf("nohup socat /dev/random ip-sendto:%s:50", nodeIP2)
		e2e.Logf("The socat command is %s", socatCmd)
		cmdSocat, _, _, _ := oc.Run("exec").Args("-n", ns1, pod2.name, "--", "bash", "-c", socatCmd).Background()
		defer cmdSocat.Process.Kill()

		compat_otp.By("Start tcpdump from pod2.")
		tcpdumpCmd := "timeout  --preserve-status 60 tcpdump -c 2 -i br-ex \"esp and less 1500\" "
		e2e.Logf("The tcpdump command is %s", tcpdumpCmd)
		outputTcpdump, err := e2eoutput.RunHostCmd(pod1.namespace, pod1.name, tcpdumpCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify ESP packets can be captured on pod2.")
		o.Expect(outputTcpdump).NotTo(o.ContainSubstring("0 packets captured"))

		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			compat_otp.By("Retest with  IPv6 address")
			compat_otp.By("Send ESP traffic from pod1")

			socatCmd := fmt.Sprintf("nohup socat /dev/random ip-sendto:%s:50", nodeIP1)
			e2e.Logf("The socat command is %s", socatCmd)
			cmdSocat, _, _, _ := oc.Run("exec").Args("-n", ns1, pod2.name, "--", "bash", "-c", socatCmd).Background()
			defer cmdSocat.Process.Kill()

			compat_otp.By("Start tcpdump from pod2.")
			tcpdumpCmd := "timeout  --preserve-status 60 tcpdump -c 2 -i br-ex \"esp and less 1500\" "
			e2e.Logf("The tcpdump command is %s", tcpdumpCmd)
			outputTcpdump, err := e2eoutput.RunHostCmd(pod1.namespace, pod1.name, tcpdumpCmd)
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By("Verify ESP packets can be captured on pod2.")
			o.Expect(outputTcpdump).NotTo(o.ContainSubstring("0 packets captured"))

		}

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-38845-High-37590-Restarting pluto daemon, restarting ovn-ipsec pods, pods connection should not be broken. [Disruptive]", func() {
		compat_otp.By("Get one worker node.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items) > 0).Should(o.BeTrue())

		compat_otp.By("kill pluto on one node.")
		pkillCmd := "pkill -SEGV pluto"
		_, err = compat_otp.DebugNodeWithChroot(oc, nodeList.Items[0].Name, "bash", "-c", pkillCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check the ipsec pods ")
		//Need to give it some hard coded time for ovn-ipsec pod to notice segfault
		ovnNS := "openshift-ovn-kubernetes"
		time.Sleep(90 * time.Second)
		err = waitForPodWithLabelReady(oc, ovnNS, "app=ovn-ipsec")
		compat_otp.AssertWaitPollNoErr(err, "ipsec pods are not ready after killing pluto")

		compat_otp.By("Restart ipsec pods")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", "-n", ovnNS, "-l", "app=ovn-ipsec").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, ovnNS, "app=ovn-ipsec")
		compat_otp.AssertWaitPollNoErr(err, "ipsec pods are not ready after killing pluto")

		compat_otp.By("Verify pods connection cross nodes after restarting ipsec pods")
		pass := verifyPodConnCrossNodes(oc)
		if !pass {
			g.Fail("Pods connection checking cross nodes failed!!")
		}
	})

	// author: huirwang@redhat.com
	g.It("[Level0] Author:huirwang-Critical-79184-pod2pod cross nodes traffic should work and not broken.", func() {
		compat_otp.By("Verify pods to pods connection cross nodes.")
		pass := verifyPodConnCrossNodes(oc)
		if !pass {
			g.Fail("Pods connection checking cross nodes failed!!")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonPreRelease-PreChkUpgrade-Critical-44834-pod2pod cross nodes connections work and pod2pod traffics get encrypted post upgrade", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		helloDaemonset := filepath.Join(buildPruningBaseDir, "hello-pod-daemonset.yaml")
		ns := "44834-upgrade-ipsec"

		compat_otp.By("Verify IPSec loaded")
		nodes, err := compat_otp.GetAllNodes(oc)
		e2e.Logf("The cluster has %v nodes", len(nodes))
		o.Expect(err).NotTo(o.HaveOccurred())
		if compat_otp.IsHypershiftHostedCluster(oc) {
			verifyIPSecLoadedInContainers(oc, len(nodes))
		} else {
			verifyIPSecLoaded(oc, nodes[0], len(nodes))
		}

		compat_otp.By("Verify ipsec pods running well before upgrade.")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("create new namespace")
		err = oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create hello-pod-daemonset in namespace.")
		createResourceFromFile(oc, ns, helloDaemonset)
		err = waitForPodWithLabelReady(oc, ns, "name=hello-pod")
		compat_otp.AssertWaitPollNoErr(err, "hello pods are not ready before upgrade!")

		compat_otp.By("Checking pods connection across nodes")
		if !verifyPodConnCrossNodesSpecNS(oc, ns, "name=hello-pod") {
			g.Fail("Pods connection checking cross nodes failed!!")
		}

		compat_otp.By("Verify the pod2pod traffic got encrypted.")
		pods := getPodName(oc, ns, "name=hello-pod")
		pod1 := pods[0]
		pod2 := pods[1]
		pod2Node, err := compat_otp.GetPodNodeName(oc, ns, pod2)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The source pod is  %s, the target pod is %s, the targe pod is on node %s", pod1, pod2, pod2Node)

		compat_otp.By("Check cluster is NAT-T enabled or not.")
		nattEnabled := checkIPSecNATTEanbled(oc)
		compat_otp.SetNamespacePrivileged(oc, ns)
		var tcpdumpCmd string
		if nattEnabled {
			tcpdumpCmd = "timeout 60s tcpdump -c 4 -nni br-ex udp port 4500 and greater 1300 "
		} else {
			tcpdumpCmd = "timeout 60s tcpdump -c 4 -nni br-ex esp and greater 1300 "
		}
		e2e.Logf("The tcpdump command is %s", tcpdumpCmd)

		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+pod2Node, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())
		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)

		e2e.Logf("From pod %s ping pod %s", pod1, pod2)
		pod2IP1, pod2IP2 := getPodIP(oc, ns, pod2)
		if pod2IP2 != "" {
			_, err := e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP1)
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP2)
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			_, err := e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP1)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Verify the pod2pod traffic got encrypted,no clear icmp text in the output")
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		if nattEnabled {
			o.Expect(strings.Contains(cmdOutput.String(), "UDP-encap")).Should(o.BeTrue())
		} else {
			o.Expect(strings.Contains(cmdOutput.String(), "ESP")).Should(o.BeTrue())
		}
		o.Expect(strings.Contains(cmdOutput.String(), "icmp")).ShouldNot(o.BeTrue())

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonPreRelease-PstChkUpgrade-Critical-44834-pod2pod cross nodes connections work and pod2pod traffics get encrypted post upgrade", func() {
		ns := "44834-upgrade-ipsec"
		nsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", ns).Execute()
		if nsErr != nil {
			g.Skip("Skip the PstChkUpgrade test as 44834-upgrade-ipsec namespace does not exist, PreChkUpgrade test did not run")
		}
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", ns, "--ignore-not-found=true").Execute()

		compat_otp.By("Verify IPSec loaded")
		nodes, err := compat_otp.GetAllNodes(oc)
		e2e.Logf("The cluster has %v nodes", len(nodes))
		o.Expect(err).NotTo(o.HaveOccurred())
		if compat_otp.IsHypershiftHostedCluster(oc) {
			verifyIPSecLoadedInContainers(oc, len(nodes))
		} else {
			verifyIPSecLoaded(oc, nodes[0], len(nodes))
		}

		compat_otp.By("Verify ipsec pods running well post upgrade.")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check hello-pod-daemonset in namespace 44834-upgrade-ipsec.")
		err = waitForPodWithLabelReady(oc, ns, "name=hello-pod")
		compat_otp.AssertWaitPollNoErr(err, "hello pods are not ready post upgrade.")

		compat_otp.By("Checking pods connection")
		if !verifyPodConnCrossNodesSpecNS(oc, ns, "name=hello-pod") {
			g.Fail("Pods connection checking cross nodes failed!!")
		}

		compat_otp.By("Verify the pod2pod traffic got encrypted.")
		pods := getPodName(oc, ns, "name=hello-pod")
		pod1 := pods[0]
		pod2 := pods[1]
		pod2Node, err := compat_otp.GetPodNodeName(oc, ns, pod2)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The source pod is  %s, the target pod is %s, the targe pod is on node %s", pod1, pod2, pod2Node)

		compat_otp.By("Check cluster is NAT-T enabled or not.")
		nattEnabled := checkIPSecNATTEanbled(oc)
		compat_otp.SetNamespacePrivileged(oc, ns)
		var tcpdumpCmd string
		if nattEnabled {
			tcpdumpCmd = "timeout 60s tcpdump -c 4 -nni br-ex udp port 4500 and greater 1300 "
		} else {
			tcpdumpCmd = "timeout 60s tcpdump -c 4 -nni br-ex esp and greater 1300 "
		}
		e2e.Logf("The tcpdump command is %s", tcpdumpCmd)

		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+pod2Node, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())
		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)

		e2e.Logf("From pod %s ping pod %s", pod1, pod2)
		pod2IP1, pod2IP2 := getPodIP(oc, ns, pod2)
		if pod2IP2 != "" {
			_, err := e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP1)
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP2)
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			_, err := e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP1)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Verify the pod2pod traffic got encrypted,no clear icmp text in the output")
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		if nattEnabled {
			o.Expect(strings.Contains(cmdOutput.String(), "UDP-encap")).Should(o.BeTrue())
		} else {
			o.Expect(strings.Contains(cmdOutput.String(), "ESP")).Should(o.BeTrue())
		}
		o.Expect(strings.Contains(cmdOutput.String(), "icmp")).ShouldNot(o.BeTrue())

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-Medium-37591-Make sure IPsec SA's are establishing in a transport mode", func() {
		compat_otp.By("Verify IPsec SA's are establishing in a transport mode ")
		compat_otp.By("Get one worker node.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items) > 0).Should(o.BeTrue())

		compat_otp.By("Check ipsec xfrm state")
		cmd := `ip x s  | grep -i "mode transport"`
		out, err := compat_otp.DebugNodeWithChroot(oc, nodeList.Items[0].Name, "bash", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf(out)
		o.Expect(strings.Contains(out, "mode transport")).Should(o.BeTrue())
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-39216-Pod created on IPsec cluster should have appropriate MTU size to accomdate IPsec Header.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		compat_otp.By("Get one worker node.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items) > 0).Should(o.BeTrue())

		compat_otp.By("Get MTU from  one worker node.")
		nodeMTU := getNodeMTU(oc, nodeList.Items[0].Name)

		g.By("Get a namespace")
		ns1 := oc.Namespace()
		g.By("Create one hello pod in the namespace")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("Get MTU from from the pod ")
		mtuCmd := `cat /sys/class/net/eth0/mtu`
		output, err := e2eoutput.RunHostCmd(ns1, pod1.name, mtuCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		podMTU, err := strconv.Atoi(strings.TrimSpace(output))
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The MTU in the pod is %v", podMTU)

		// OVN needs 100 byte header and IPsec needs another 46 bytes due to ESP etc so the pod's mtu must be 146 bytes less than cluster mtu
		compat_otp.By("Verify pod's mtu is less 146 bytes than nodes mtu")
		o.Expect((podMTU + 146) == nodeMTU).Should(o.BeTrue())
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-37392-pod to pod traffic on different nodes should be IPSec encrypted", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		helloDaemonset := filepath.Join(buildPruningBaseDir, "hello-pod-daemonset.yaml")
		ns := oc.Namespace()

		compat_otp.By("Verify IPSec loaded")
		nodes, err := compat_otp.GetAllNodes(oc)
		e2e.Logf("The cluster has %v nodes", len(nodes))
		o.Expect(err).NotTo(o.HaveOccurred())
		if compat_otp.IsHypershiftHostedCluster(oc) {
			verifyIPSecLoadedInContainers(oc, len(nodes))
		} else {
			verifyIPSecLoaded(oc, nodes[0], len(nodes))
		}

		compat_otp.By("Verify ipsec pods running well.")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create hello-pod-daemonset in namespace.")
		createResourceFromFile(oc, ns, helloDaemonset)
		err = waitForPodWithLabelReady(oc, ns, "name=hello-pod")
		compat_otp.AssertWaitPollNoErr(err, "hello pods are not ready!")

		compat_otp.By("Verify the pod2pod traffic got encrypted.")
		pods := getPodName(oc, ns, "name=hello-pod")
		pod1 := pods[0]
		pod2 := pods[1]
		pod2Node, err := compat_otp.GetPodNodeName(oc, ns, pod2)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The source pod is  %s, the target pod is %s, the targe pod is on node %s", pod1, pod2, pod2Node)

		compat_otp.By("Check cluster is NAT-T enabled or not.")
		nattEnabled := checkIPSecNATTEanbled(oc)
		compat_otp.SetNamespacePrivileged(oc, ns)
		var tcpdumpCmd string
		if nattEnabled {
			tcpdumpCmd = "timeout 60s tcpdump -c 4 -nni br-ex udp port 4500 and greater 1300 "
		} else {
			tcpdumpCmd = "timeout 60s tcpdump -c 4 -nni br-ex esp and greater 1300 "
		}
		e2e.Logf("The tcpdump command is %s", tcpdumpCmd)

		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+pod2Node, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())
		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)

		e2e.Logf("From pod %s ping pod %s", pod1, pod2)
		pod2IP1, pod2IP2 := getPodIP(oc, ns, pod2)
		if pod2IP2 != "" {
			_, err := e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP1)
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP2)
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			_, err := e2eoutput.RunHostCmd(ns, pod1, "ping -s 1500 -c4 "+pod2IP1)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Verify the pod2pod traffic got encrypted,no clear icmp text in the output")
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		if nattEnabled {
			o.Expect(strings.Contains(cmdOutput.String(), "UDP-encap")).Should(o.BeTrue())
		} else {
			o.Expect(strings.Contains(cmdOutput.String(), "ESP")).Should(o.BeTrue())
		}
		o.Expect(strings.Contains(cmdOutput.String(), "icmp")).ShouldNot(o.BeTrue())
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-Medium-80232-After node rebooting, IPSec pod2pod connection should work as well. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		helloDaemonset := filepath.Join(buildPruningBaseDir, "hello-pod-daemonset.yaml")
		ns := oc.Namespace()

		compat_otp.By("Verify IPSec loaded")
		nodes, err := compat_otp.GetAllNodes(oc)
		e2e.Logf("The cluster has %v nodes", len(nodes))
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Get one worker node which will be used for rebooting")
		workerNode, err := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if compat_otp.IsHypershiftHostedCluster(oc) {
			verifyIPSecLoadedInContainers(oc, len(nodes))
		} else {
			verifyIPSecLoaded(oc, nodes[0], len(nodes))
		}

		compat_otp.By("Verify ipsec pods running well before node rebooting.")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create hello-pod-daemonset in namespace.")
		createResourceFromFile(oc, ns, helloDaemonset)
		err = waitForPodWithLabelReady(oc, ns, "name=hello-pod")
		compat_otp.AssertWaitPollNoErr(err, "hello pods are not ready before upgrade!")

		compat_otp.By("Checking pods connection across nodes before rebooting node")
		if !verifyPodConnCrossNodesSpecNS(oc, ns, "name=hello-pod") {
			g.Fail("Pods connection checking cross nodes failed!!")
		}

		compat_otp.By("Reboot the worker node.")
		defer checkNodeStatus(oc, workerNode, "Ready")
		rebootNode(oc, workerNode)
		checkNodeStatus(oc, workerNode, "NotReady")
		checkNodeStatus(oc, workerNode, "Ready")

		compat_otp.By("Wait for all the test pods in running status  ")
		err = waitForPodWithLabelReady(oc, ns, "name=hello-pod")
		compat_otp.AssertWaitPollNoErr(err, "hello pods are not ready before upgrade!")

		compat_otp.By("Verify IPSec loaded after node rebooting.")
		if compat_otp.IsHypershiftHostedCluster(oc) {
			verifyIPSecLoadedInContainers(oc, len(nodes))
		} else {
			verifyIPSecLoaded(oc, nodes[0], len(nodes))
		}

		compat_otp.By("Verify ipsec pods running well after node rebooting.")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Checking pods connection across nodes")
		if !verifyPodConnCrossNodesSpecNS(oc, ns, "name=hello-pod") {
			g.Fail("Pods connection checking cross nodes failed!!")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-80993-IPSec mode switch between Full and External. [Disruptive]", func() {
		compat_otp.By("Swtich to IPSec External mode.")
		defer func() {
			ipsecState := checkIPsec(oc)
			if ipsecState != "Full" {
				_, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Full\"}}}}}", "--type=merge").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}()
		_, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"External\"}}}}}", "--type=merge").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Wait IPsec pods gone")
		err = waitForPodWithLabelGone(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify IPsec load is 0")
		workerNode, err := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyIPSecLoaded(oc, workerNode, 0)

		compat_otp.By("Verify IPsec xfrm state got cleared")
		cmd := "ip x s"
		out, err := compat_otp.DebugNodeWithChroot(oc, workerNode, "bash", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(out, "transport")).ShouldNot(o.BeTrue())

		compat_otp.By("Checking pods connection across nodes")
		if !verifyPodConnCrossNodes(oc) {
			g.Fail("Pods connection checking cross nodes failed!!")
		}

		compat_otp.By("Swtich to IPSec Full mode.")
		_, err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Full\"}}}}}", "--type=merge").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify ipsec pods running")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Get one node")
		nodes, err := compat_otp.GetAllNodes(oc)
		e2e.Logf("The cluster has %v nodes", len(nodes))
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify IPsec load connections")
		verifyIPSecLoaded(oc, workerNode, len(nodes))

		compat_otp.By("Checking pods connection across nodes")
		if !verifyPodConnCrossNodes(oc) {
			g.Fail("Pods connection checking cross nodes failed!!")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-80992-IPSec encryption traffic should not be affected when MachineConfig were rendered. [Disruptive]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking/sctp")
			sctpModule          = filepath.Join(buildPruningBaseDir, "load-sctp-module.yaml")
		)

		compat_otp.By("Make sure CNO is not in degraded status")
		err := compat_otp.CheckNetworkOperatorStatus(oc)
		if err != nil {
			g.Skip("CNO is in abnormal status before executing the case, skip the test!")
		}

		compat_otp.By("Applying a valid MachineConfig")
		// Here we use sctp MachineConfig which also can be benifited by sctp cases.
		err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", sctpModule).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Wait the MC applying getting started")
		o.Eventually(func() error {
			err := compat_otp.AssertOrCheckMCP(oc, "worker", 30*time.Second, 30*time.Second, false)
			return err
		}, "300s", "30s").ShouldNot(o.BeNil(), "MC applying didn't start yet.")

		compat_otp.By("Both IPsec container and host pods will be launched.")
		o.Eventually(func() bool {
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", "-n", "openshift-ovn-kubernetes").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("The ds in openshift-ovn-kubernetes are : \n", output)
			return strings.Contains(output, "ovn-ipsec-containerized") && strings.Contains(output, "ovn-ipsec-host")
		}, "300s", "30s").ShouldNot(o.BeFalse(), "IPSec ovn-ipsec-containerized pods were not launched.")

		compat_otp.By("Verify CNO status shows progress state")
		checkCNORenderState(oc)

		compat_otp.By("Get one worker node.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items) > 0).Should(o.BeTrue())

		compat_otp.By("Verify IPSec encryption traffic can be captured.")
		tcpdumpCmd1 := "timeout 60s tcpdump -c 4 -nni br-ex udp port 4500 "
		tcpdumpCmd2 := "timeout 60s tcpdump -c 4 -nni br-ex esp "
		platform := checkPlatform(oc)
		if strings.Contains(platform, "ibmcloud") {
			o.Expect(checkIPSecNATTEanbled(oc)).Should(o.BeTrue())
			output, err := compat_otp.DebugNode(oc, nodeList.Items[0].Name, "bash", "-c", tcpdumpCmd1)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, "UDP-encap")).Should(o.BeTrue())
		} else {
			o.Expect(checkIPSecNATTEanbled(oc)).Should(o.BeFalse())
			output, err := compat_otp.DebugNode(oc, nodeList.Items[0].Name, "bash", "-c", tcpdumpCmd2)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, "ESP")).Should(o.BeTrue())
		}

		compat_otp.By("Checking pods connection across nodes")
		if !verifyPodConnCrossNodes(oc) {
			g.Fail("Pods connection checking cross nodes failed!!")
		}

		compat_otp.By("Wait the MC were applied to worker nodes ")
		err = compat_otp.AssertOrCheckMCP(oc, "worker", 60*time.Second, 5*time.Minute, false)
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("MC applying done ")

		compat_otp.By("Wait ipsec container ds disappeared in openshift-ovn-kubernetes")
		o.Eventually(func() bool {
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", "-n", "openshift-ovn-kubernetes").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("The ds in openshift-ovn-kubernetes are : \n", output)
			return !strings.Contains(output, "ovn-ipsec-containerized") && strings.Contains(output, "ovn-ipsec-host")
		}, "300s", "30s").ShouldNot(o.BeNil(), "Timeout for waiting ovn-ipsec-containerized being removed!")

		compat_otp.By("Verify CNO is not in degraded  status")
		err = compat_otp.CheckNetworkOperatorStatus(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-80099-Verify encapsulation=Always/Auto works. [Disruptive]", func() {
		compat_otp.By("Configure IPSec Encyption to Always")
		configIPSecEncyptOption(oc, "Always")

		compat_otp.By("Verify ovndb, ipsec_encapsulation is true.")
		o.Expect(checkIPSecNATTEanbled(oc)).Should(o.BeTrue())

		compat_otp.By("Get one worker node.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items) > 0).Should(o.BeTrue())

		compat_otp.By("Verify udp 4500 packets can be captured")
		tcpdumpCmd1 := "timeout 60s tcpdump -c 4 -nni br-ex udp port 4500 "
		tcpdumpCmd2 := "timeout 60s tcpdump -c 4 -nni br-ex esp "
		output, err := compat_otp.DebugNode(oc, nodeList.Items[0].Name, "bash", "-c", tcpdumpCmd1)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "UDP-encap")).Should(o.BeTrue())

		compat_otp.By("Configure IPSec Encyption to Auto")
		configIPSecEncyptOption(oc, "Auto")

		platform := checkPlatform(oc)
		if strings.Contains(platform, "ibmcloud") {
			o.Expect(checkIPSecNATTEanbled(oc)).Should(o.BeTrue())
			output, err := compat_otp.DebugNode(oc, nodeList.Items[0].Name, "bash", "-c", tcpdumpCmd1)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, "UDP-encap")).Should(o.BeTrue())
		} else {
			o.Expect(checkIPSecNATTEanbled(oc)).Should(o.BeFalse())
			output, err := compat_otp.DebugNode(oc, nodeList.Items[0].Name, "bash", "-c", tcpdumpCmd2)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, "ESP")).Should(o.BeTrue())
		}

		compat_otp.By("Remove IPSec Encyption")
		removeIPSecOption := `[{"op": "remove", "path": "/spec/defaultNetwork/ovnKubernetesConfig/ipsecConfig/full"}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io/cluster", "--type=json", "-p", removeIPSecOption).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		if strings.Contains(platform, "ibmcloud") {
			o.Expect(checkIPSecNATTEanbled(oc)).Should(o.BeTrue())
		} else {
			o.Expect(checkIPSecNATTEanbled(oc)).Should(o.BeFalse())
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Medium-80237-Manually sending CSR for signing should be rejected by CNO. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking/ipsec")
		ipsecCSRFile := filepath.Join(buildPruningBaseDir, "ipsec-csr.yaml")
		csrName := "ipsec-csr-test-80237"

		compat_otp.By("Manually sent IPSec CSR")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("csr", csrName).Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", ipsecCSRFile).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify the CSR was rejected.")
		o.Eventually(func() bool {
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("csr", csrName, "-o=jsonpath={.status}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf(output)
			return strings.Contains(output, "Certificate Signing Request is set with invalid user name, can't sign it")
		}, "60s", "10s").Should(o.BeTrue(), "Time out, the rejected message was not found in the CSR. ")
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Medium-79805-Validate network co reflected degraded status while mcp degraded. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking/ipsec")
		invalidMCFile := filepath.Join(buildPruningBaseDir, "invalid-mc.yaml")

		compat_otp.By("Create invalid MC ")
		defer func() {
			err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("mc", "mc-invalid-extension").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			waitMCPExpectedStatus(oc, "worker", "Degraded", "False")
			waitForNetworkOperatorState(oc, 100, 15, "True.*False.*False")
		}()
		err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", invalidMCFile).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Wait worker MCP in degraded status. ")
		waitMCPExpectedStatus(oc, "worker", "Degraded", "True")

		compat_otp.By("Validate network co reflected degraded status while mcp degraded")
		waitForNetworkOperatorState(oc, 100, 15, "True.*False.*True")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co/network").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "worker machine config pool in degraded state")).Should(o.BeTrue())
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-Medium-82259-IPSec enabled/disabled test at runtime and verify metrics for hosted cluster. [Disruptive]", func() {
		if !compat_otp.IsHypershiftHostedCluster(oc) {
			g.Skip("Skip the test as this is only for hosted cluster.")
		}
		var (
			metricName = "ovnkube_controller_ipsec_enabled"
		)

		compat_otp.By("Disable IPSec.")
		defer func() {
			ipsecState := checkIPsec(oc)
			if ipsecState != "Full" {
				_, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Full\"}}}}}", "--type=merge").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}()
		_, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Disabled\"}}}}}", "--type=merge").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Wait IPsec pods gone")
		err = waitForPodWithLabelGone(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check metrics for IPsec disabled")
		prometheusURL := "localhost:29103/metrics"
		containerName := "kube-rbac-proxy-node"
		ovnPod := getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")[0]
		e2e.Logf("The expected value of the %s is 0", metricName)
		ipsecDisabled := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
			metricValueAfterDisabled := getOVNMetricsInSpecificContainer(oc, containerName, ovnPod, prometheusURL, metricName)
			if metricValueAfterDisabled == "0" {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s when disabled IPSec and try again", metricName)
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(ipsecDisabled, fmt.Sprintf("Fail to get metric when disabled IPSec and the error is:%s", ipsecDisabled))

		compat_otp.By("Enable IPSec to Full mode.")
		_, err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Full\"}}}}}", "--type=merge").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify ipsec pods running")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Get one node")
		nodes, err := compat_otp.GetAllNodes(oc)
		e2e.Logf("The cluster has %v nodes", len(nodes))
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify IPsec load connections")
		verifyIPSecLoadedInContainers(oc, len(nodes))

		compat_otp.By("Check metrics for IPsec enabled/disabled after enabling at runtime")
		ovnPod = getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")[0]
		e2e.Logf("The expected value of the %s is 1", metricName)
		ipsecEnabled := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
			metricValueAfterEnabled := getOVNMetricsInSpecificContainer(oc, containerName, ovnPod, prometheusURL, metricName)
			if metricValueAfterEnabled == "1" {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s when enabled IPSec and try again", metricName)
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(ipsecEnabled, fmt.Sprintf("Fail to get metric when disabled IPSec and the error is:%s", ipsecEnabled))

		compat_otp.By("Checking pods connection across nodes")
		if !verifyPodConnCrossNodes(oc) {
			g.Fail("Pods connection checking cross nodes failed!!")
		}
	})

	// author: anusaxen@redhat.com
	g.It("Author:anusaxen-NonHyperShiftHOST-Longduration-Medium-83672-[FdpOvnOvs][Skipped Setup] IPSec Functionality check for FDP usecase. [Disruptive][Timeout:75m]", func() {
		compat_otp.By("Switch to IPSec Full mode.")
		defer func() {
			patchCmd := "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Disabled\"}}}}}"
			patchResourceAsAdmin(oc, "Network.operator.openshift.io/cluster", patchCmd)
			err := waitForPodWithLabelGone(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
			o.Expect(err).NotTo(o.HaveOccurred())
			err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
			o.Expect(err).NotTo(o.HaveOccurred())
			getmcpStatus(oc, "master")
			getmcpStatus(oc, "worker")
			waitForNetworkOperatorState(oc, 100, 18, "True.*False.*False")
		}()
		patchCmd := "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Full\"}}}}}"
		patchResourceAsAdmin(oc, "Network.operator.openshift.io/cluster", patchCmd)

		compat_otp.By("Wait for MCP status and IPsec/OVN pods Readiness")
		getmcpStatus(oc, "master")
		getmcpStatus(oc, "worker")
		err := waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		o.Expect(err).NotTo(o.HaveOccurred())
		waitForNetworkOperatorState(oc, 100, 18, "True.*False.*False")

		compat_otp.By("Checking pods connection across nodes")
		if !verifyPodConnCrossNodes(oc) {
			g.Fail("Pods connection checking cross nodes failed!!")
		}

	})
})

var _ = g.Describe("[OTP][sig-networking] SDN IPSEC NS", func() {
	defer g.GinkgoRecover()
	var (
		oc                   = compat_otp.NewCLI("networking-ipsec-ns", compat_otp.KubeConfigPath())
		leftPublicIP         string
		rightIP              string
		rightIP2             string
		leftIP               string
		nodeCert             string
		nodeCert2            string
		rightNode            string
		rightNode2           string
		leftNode             string
		ipsecTunnel          string
		platformvar          string
		certExpirationDate   = time.Date(2034, time.March, 10, 0, 0, 0, 0, time.UTC)
		ipsecBaseDir         = testdata.FixturePath("networking/ipsec")
		nsCertsMachineConfig = filepath.Join(ipsecBaseDir, "nsconfig-machine-config.yaml")
	)

	g.BeforeEach(func() {
		platform := compat_otp.CheckPlatform(oc)

		if !(strings.Contains(platform, "gcp") || strings.Contains(platform, "baremetal")) {
			g.Skip("Test cases should be run on GCP/RDU2 cluster with ovn network plugin, skip for other platforms !!")
		}
		e2e.Logf("Platform is %s", platform)

		// Set up the config object with existing IPsecConfig, setup testing config on
		// the selected nodes.
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("IPSec NS cases requires 3 nodes, but the cluster has less than three nodes")
		}

		ipsecState := checkIPsec(oc)
		if ipsecState == "Disabled" {
			g.Skip("IPsec not enabled, skiping test!")
		}

		//check if IPsec packages are present on the cluster
		rpm_output, err := compat_otp.DebugNodeWithChroot(oc, nodeList.Items[0].Name, "bash", "-c", "rpm -qa | grep -i libreswan")
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Confirm if required libreswan and NetworkManager-libreswan packagaes are present on node before validating IPsec usecases")
		o.Expect(strings.Contains(rpm_output, "libreswan-")).To(o.BeTrue())
		o.Expect(strings.Contains(rpm_output, "NetworkManager-libreswan")).To(o.BeTrue())

		switch platform {
		case "gcp":
			_, nodeIP1 := getNodeIP(oc, nodeList.Items[0].Name)
			_, nodeIP2 := getNodeIP(oc, nodeList.Items[1].Name)
			_, nodeIP3 := getNodeIP(oc, nodeList.Items[2].Name)

			actualWorkerNodeIPs := []string{nodeIP1, nodeIP2, nodeIP3} // Values to check

			ipsecTunnel = "Worker-2-4" //means 10.0.128.2 to 10.0.128.4 on GCP
			rightIP = "10.0.128.2"
			rightIP2 = "10.0.128.3"
			leftIP = "10.0.128.4"
			nodeCert = "10_0_128_2"
			nodeCert2 = "10_0_128_3"

			//Below logic ensure we have those worker nodes with these IPs present on GCE infra
			testIPs := []string{rightIP, rightIP2, leftIP}
			mapA := make(map[string]int)
			for _, val := range actualWorkerNodeIPs {
				mapA[val]++
			}

			mapB := make(map[string]int)
			for _, val := range testIPs {
				mapB[val]++
			}

			// Compare the two maps ot make sure GCE infra has required worker node IPs
			if reflect.DeepEqual(mapA, mapB) {
				e2e.Logf("GCE infra has required worker node IPs")
			} else {
				e2e.Failf("Failed to find the expected nodeIPs in GCE infra. Check if IPsec auto scripts needs to be updated")
			}

			checkMCPresence, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("mc", "99-worker-import-certs").Output()
			if err == nil && !strings.Contains(checkMCPresence, "not found") {
				e2e.Logf("Required machine config to deploy IPsec node certs and config is already present %s", checkMCPresence)
			} else {
				compat_otp.By("configure IPsec certs on the worker nodes")
				// The certificates for configuring NS IPsec between two worker nodes are deployed through machine config
				// `99-worker-import-certs` which is in the test/extended/testdata/ipsec/nsconfig-machine-config.yaml file.
				// This is a butane generated file via a butane config file.
				// The machine config mounts cert files into node's /etc/pki/certs directory and runs ipsec-addcert.sh script
				// to import those certs into Libreswan nss db and will be used by Libreswan for IPsec north south connection
				// configured via NodeNetworkConfigurationPolicy on the node. This file also mount nstest.conf on endpoint worker node
				// The certificates in the Machine Config has validity period of 120 months starting from March 10, 2024.
				// so proceed with test if system date is before March 10, 2034. Otherwise fail the test.
				if !time.Now().Before(certExpirationDate) {
					e2e.Logf("certficates in the Machine Config are expired, Please consider recreating those certificates")
				}
				err = oc.AsAdmin().Run("apply").Args("-f", nsCertsMachineConfig).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				// Wait for worker pool to apply the configs
				compat_otp.By("Wait for worker MCP to be updated")
				g.By("Check mcp to finish rolling out")
				err := getmcpStatus(oc, "worker")
				compat_otp.AssertWaitPollNoErr(err, "mcp is not updated")

				//check overall OVNK state and IPsec pods health
				checkOVNKState(oc)
				err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
				compat_otp.AssertWaitPollNoErr(err, "ovn-ipsec pods are not ready after user machine-config deployment")
				//check CNO health
				waitForNetworkOperatorState(oc, 60, 30, "True.*False.*False")
			}

		case "baremetal":
			msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
			if err != nil || !(strings.Contains(msg, "offload.openshift-qe.sdn.com")) {
				g.Skip("This case needs to be run on GCP or RDU2 cluster, skip other platforms!!!")
			}
			ipsecTunnel = "pluto-rdu2-VM"
			rightIP = "192.168.111.23"
			rightIP2 = "192.168.111.24"
			leftIP = "10.0.185.155"
			nodeCert = "proxy_cert"  //on RDU2 setup, since nodes are NAT'd and not accessible from ext VM, IPsec tunnels terminates at proxies and proxy reinitiate tunnels with worker nodes
			nodeCert2 = "proxy_cert" //so both nodes will have same proxy_cert with extSAN of proxy IP
			leftPublicIP = leftIP
			platformvar = "rdu2"
		}

		rightNode = getNodeNameByIPv4(oc, rightIP)
		rightNode2 = getNodeNameByIPv4(oc, rightIP2)
		leftNode = getNodeNameByIPv4(oc, leftIP)
		if rightNode == "" {
			g.Skip(fmt.Sprintf("There is no worker node with IPSEC rightIP %v, skip the testing.", rightIP))
		}

		//With 4.15+, use nmstate to config ipsec
		installNMstateOperator(oc)
	})

	// author: anusaxen@redhat.com
	g.It("Author:anusaxen-NonHyperShiftHOST-High-74222-[rdu2cluster] Transport tunnel can be setup for IPSEC NS in NAT env, [Serial][Disruptive]", func() {
		if platformvar != "rdu2" {
			g.Skip("This case is only applicable to RDU2 cluster, skipping this testcase.")
		}
		compat_otp.By("Configure nmstate ipsec policy")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		err := applyConfigTypeExtHost(leftPublicIP, "host2hostTransportRDU2")
		o.Expect(err).NotTo(o.HaveOccurred())

		policyName := "ipsec-policy-transport-74222"
		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode)
		configIPSecNMSatePolicy(oc, policyName, rightIP, rightNode, ipsecTunnel, leftIP, nodeCert, "transport")

		compat_otp.By("Checking ipsec session was established between worker node and external host")
		verifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode)
		phyInf, nicError := getSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s udp port 4500 and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and external host encrypted by UDP-encap")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = compat_otp.DebugNodeWithChroot(oc, rightNode, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), "UDP-encap")).Should(o.BeTrue())
	})

	g.It("Author:anusaxen-NonHyperShiftHOST-High-74223-[rdu2cluster] Tunnel mode can be setup for IPSEC NS in NAT env, [Serial][Disruptive]", func() {
		if platformvar != "rdu2" {
			g.Skip("This case is only applicable to RDU2 cluster, skipping this testcase.")
		}
		compat_otp.By("Configure nmstate ipsec policy")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		err := applyConfigTypeExtHost(leftPublicIP, "host2hostTunnelRDU2")
		o.Expect(err).NotTo(o.HaveOccurred())

		policyName := "ipsec-policy-transport-74223"
		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode2)
		configIPSecNMSatePolicy(oc, policyName, rightIP2, rightNode2, ipsecTunnel, leftIP, nodeCert2, "tunnel")

		compat_otp.By("Checking ipsec session was established between worker node and external host")
		verifyIPSecTunnelUp(oc, rightNode2, rightIP2, leftIP, "tunnel")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode2)
		phyInf, nicError := getSnifPhyInf(oc, rightNode2)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s udp port 4500 and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode2, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and external host encrypted by UDP-encap")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = compat_otp.DebugNodeWithChroot(oc, rightNode2, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), "UDP-encap")).Should(o.BeTrue())
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-High-67472-Transport tunnel can be setup for IPSEC NS, [Serial][Disruptive]", func() {
		if platformvar == "rdu2" {
			g.Skip("This case is only applicable to GCP, skipping this testcase.")
		}
		compat_otp.By("Configure nmstate ipsec policy")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		policyName := "ipsec-policy-transport-67472"
		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode)
		configIPSecNMSatePolicy(oc, policyName, rightIP, rightNode, ipsecTunnel, leftIP, nodeCert, "transport")

		compat_otp.By("Checking ipsec session was established between inititing worker node and ep worker node")
		verifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode)
		phyInf, nicError := getSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and ep worker node encrypted by ESP")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = compat_otp.DebugNodeWithChroot(oc, rightNode, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring("ESP"))
		cmdTcpdump.Process.Kill()
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-High-67473-Service nodeport can be accessed with ESP encrypted, [Serial][Disruptive]", func() {
		if platformvar == "rdu2" {
			g.Skip("This case is only applicable to GCP, skipping this testcase.")
		}
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		)

		compat_otp.By("Configure nmstate ipsec policy")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		policyName := "ipsec-policy-67473"
		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode)
		configIPSecNMSatePolicy(oc, policyName, rightIP, rightNode, ipsecTunnel, leftIP, nodeCert, "transport")

		compat_otp.By("Checking ipsec session was established between initiating worker node and ep worker node")
		verifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		g.By("Create a namespace")
		ns1 := oc.Namespace()
		g.By("create 1st hello pod in ns1")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  rightNode,
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
			serviceType:           "NodePort",
			ipFamilyPolicy:        "",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "", //This no value parameter will be ignored
			template:              genericServiceTemplate,
		}
		svc.ipFamilyPolicy = "SingleStack"
		svc.createServiceFromParams(oc)

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode)
		phyInf, nicError := getSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())
		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.

		compat_otp.By("Checking the traffic is encrypted by ESP when curl NodePort service from ep worker node")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns1, "test-service", "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		curlCmd := fmt.Sprintf("curl %s:%s &", rightIP, nodePort)
		time.Sleep(5 * time.Second)

		_, err = compat_otp.DebugNodeWithChroot(oc, leftNode, "bash", "-c", curlCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for http is \n%s", cmdOutput.String())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring("ESP"))
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Longduration-NonPreRelease-Medium-67474-Medium-69176-IPSec tunnel can be up after restart IPSec service or restart node, [Serial][Disruptive]", func() {
		if platformvar == "rdu2" {
			g.Skip("This case is only applicable to GCP, skipping this testcase.")
		}
		compat_otp.By("Configure nmstate ipsec policy")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		policyName := "ipsec-policy-transport-69176"
		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode)
		configIPSecNMSatePolicy(oc, policyName, rightIP, rightNode, ipsecTunnel, leftIP, nodeCert, "transport")

		compat_otp.By("Checking ipsec session was established between worker node and ep worker node")
		verifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		//Due to bug https://issues.redhat.com/browse/OCPBUGS-27839,skip below step for now"
		/*compat_otp.By("Restart ipsec service on right node")
		ns := oc.Namespace()
		cmd2 := "systemctl restart ipsec.service"
		_, ipsecErr = compat_otp.DebugNodeWithChroot(oc, rightNode, "/bin/bash", "-c", cmd2)
		o.Expect(ipsecErr).NotTo(o.HaveOccurred())*/

		compat_otp.By("Reboot node which is configured IPSec NS")
		defer checkNodeStatus(oc, rightNode, "Ready")
		rebootNode(oc, rightNode)
		checkNodeStatus(oc, rightNode, "NotReady")
		checkNodeStatus(oc, rightNode, "Ready")

		compat_otp.By("Verify ipsec session was established between worker node and ep worker node!")
		o.Eventually(func() bool {
			cmd := fmt.Sprintf("ip xfrm policy get src %s/32 dst %s/32 dir out ; ip xfrm policy get src %s/32 dst %s/32 dir in  ", rightIP, leftIP, leftIP, rightIP)
			ipXfrmPolicy, ipsecErr := compat_otp.DebugNodeWithChroot(oc, rightNode, "/bin/bash", "-c", cmd)
			return ipsecErr == nil && strings.Contains(ipXfrmPolicy, "transport")
		}, "300s", "30s").Should(o.BeTrue(), "IPSec tunnel connection was not restored.")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode)
		phyInf, nicError := getSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and ep worker node encrypted by ESP")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = compat_otp.DebugNodeWithChroot(oc, rightNode, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring("ESP"))
		cmdTcpdump.Process.Kill()
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-High-67475-Be able to access hostnetwork pod with traffic encrypted,  [Serial][Disruptive]", func() {
		if platformvar == "rdu2" {
			g.Skip("This case is only applicable to GCP, skipping this testcase.")
		}
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			hostPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-hostnetwork-specific-node-template.yaml")
		)

		compat_otp.By("Configure nmstate ipsec policy")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)
		policyName := "ipsec-policy-67475"
		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode)
		configIPSecNMSatePolicy(oc, policyName, rightIP, rightNode, ipsecTunnel, leftIP, nodeCert, "transport")

		compat_otp.By("Checking ipsec session was established between worker node and ep worker node")
		verifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		g.By("Create a namespace")
		ns1 := oc.Namespace()
		//Required for hostnetwork pod
		compat_otp.By("Set namespace as privileged for Hostnetworked Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)
		g.By("create a hostnetwork pod in ns1")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  rightNode,
			template:  hostPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode)
		phyInf, nicError := getSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		compat_otp.By("Checking the traffic is encrypted by ESP when curl hostpod from ep worker node")
		time.Sleep(5 * time.Second)
		curlCmd := fmt.Sprintf("curl %s:%s &", rightIP, "8080")
		_, err = compat_otp.DebugNodeWithChroot(oc, leftNode, "bash", "-c", curlCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump output for curl to hostpod is \n%s", cmdOutput.String())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring("ESP"))
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-High-69178-High-38873-Tunnel mode can be setup for IPSec NS,IPSec NS tunnel can be teared down by nmstate config. [Serial][Disruptive]", func() {
		if platformvar == "rdu2" {
			g.Skip("This case is only applicable to GCP, skipping this testcase.")
		}
		compat_otp.By("Configure nmstate ipsec policy")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		var (
			policyName  = "ipsec-policy-tunnel-69178"
			ipsecTunnel = "plutoTunnelVM"
		)

		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode2)
		configIPSecNMSatePolicy(oc, policyName, rightIP2, rightNode2, ipsecTunnel, leftIP, nodeCert2, "tunnel")

		compat_otp.By("Checking ipsec session was established between worker node and ep worker node")
		verifyIPSecTunnelUp(oc, rightNode2, rightIP2, leftIP, "tunnel")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode2)
		phyInf, nicError := getSnifPhyInf(oc, rightNode2)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode2, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and ep worker node encrypted by ESP")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = compat_otp.DebugNodeWithChroot(oc, rightNode2, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring("ESP"))
		cmdTcpdump.Process.Kill()

		compat_otp.By("Remove IPSec interface")
		removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode2)

		compat_otp.By("Verify IPSec interface was removed from node")
		ifaceList, ifaceErr := compat_otp.DebugNodeWithChroot(oc, rightNode2, "nmcli", "con", "show")
		o.Expect(ifaceErr).NotTo(o.HaveOccurred())
		e2e.Logf(ifaceList)
		o.Expect(ifaceList).NotTo(o.ContainSubstring(ipsecTunnel))

		compat_otp.By("Verify the tunnel was teared down")
		verifyIPSecTunnelDown(oc, rightNode2, rightIP2, leftIP, "tunnel")

		compat_otp.By("Verify connection to ep worker node was not broken")
		// workaorund for bug https://issues.redhat.com/browse/RHEL-24802
		cmd := fmt.Sprintf("ip x p flush;ip x s flush; sleep 2; ping -c4 %s &", rightIP2)
		_, err = compat_otp.DebugNodeWithChroot(oc, leftNode, "bash", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	//author: anusaxen@redhat.com
	g.It("Author:anusaxen-NonHyperShiftHOST-Longduration-NonPreRelease-High-71465-Multiplexing Tunnel and Transport type IPsec should work with IPsec endpoint. [Serial][Disruptive]", func() {
		if platformvar == "rdu2" {
			g.Skip("This case is only applicable to GCP, skipping this testcase.")
		}
		compat_otp.By("Configure nmstate ipsec policies for both Transport and Tunnel Type")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		var (
			policyName  = "ipsec-policy-transport-71465"
			ipsecTunnel = "plutoTransportVM"
		)
		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode)
		configIPSecNMSatePolicy(oc, policyName, rightIP, rightNode, ipsecTunnel, leftIP, nodeCert, "transport")
		compat_otp.By("Checking ipsec session for transport mode was established between worker node and ep worker node")
		verifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		var (
			policyName2  = "ipsec-policy-tunnel-71465"
			ipsecTunnel2 = "plutoTunnelVM"
		)
		defer removeIPSecConfig(oc, policyName2, ipsecTunnel2, rightNode2)
		configIPSecNMSatePolicy(oc, policyName2, rightIP2, rightNode2, ipsecTunnel2, leftIP, nodeCert2, "tunnel")

		compat_otp.By("Checking ipsec session for tunnel mode was established between worker node and ep worker node")
		verifyIPSecTunnelUp(oc, rightNode2, rightIP2, leftIP, "tunnel")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode)
		phyInf, nicError := getSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		//we just need to check traffic on any of rightIP/rightNode to make sure tunnel multiplexing didn't break the whole functionality as tunnel multiplexing has been already verified in above steps
		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and ep worker node encrypted by ESP")
		pingCmd := fmt.Sprintf("ping -c4 %s &", rightIP)

		_, err = compat_otp.DebugNodeWithChroot(oc, leftNode, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring("ESP"))

	})

	//author: anusaxen@redhat.com
	g.It("Author:anusaxen-NonHyperShiftHOST-High-74221-[rdu2cluster] Tunnel mode can be setup for IPSec NS in NAT env - Host2Net [Serial][Disruptive]", func() {
		if platformvar != "rdu2" {
			g.Skip("This case is only applicable to local RDU2 BareMetal cluster, skipping this testcase.")
		}
		compat_otp.By("Configure nmstate ipsec policy for host2net Tunnel Type")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		var (
			policyName          = "ipsec-policy-tunnel-host2net-74221"
			ipsecTunnel         = "plutoTunnelVM_host2net"
			rightNetworkAddress = "10.0.184.0" //OSP VM has network address of 10.0.184.0 with eth0 IP 10.0.185.155/22
			rightNetworkCidr    = "/22"
		)

		err := applyConfigTypeExtHost(leftPublicIP, "host2netTunnelRDU2")
		o.Expect(err).NotTo(o.HaveOccurred())

		removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode2)
		configIPSecNMSatePolicyHost2net(oc, policyName, rightIP2, rightNode2, ipsecTunnel, leftIP, rightNetworkAddress, rightNetworkCidr, nodeCert2, "tunnel")

		compat_otp.By("Checking ipsec session was established between worker node and external host")
		verifyIPSecTunnelUphost2netTunnel(oc, rightNode2, rightIP2, rightNetworkAddress, "tunnel")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode2)
		phyInf, nicError := getSnifPhyInf(oc, rightNode2)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s udp port 4500 and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode2, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and external host encrypted by UDP-encap")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = compat_otp.DebugNodeWithChroot(oc, rightNode2, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), "UDP-encap")).Should(o.BeTrue())
	})

	//author: anusaxen@redhat.com
	g.It("Author:anusaxen-NonHyperShiftHOST-High-74220-[rdu2cluster] Transport mode can be setup for IPSec NS in NAT env - Host2Net [Serial][Disruptive]", func() {
		if platformvar != "rdu2" {
			g.Skip("This case is only applicable to local RDU2 BareMetal cluster, skipping this testcase.")
		}
		compat_otp.By("Configure nmstate ipsec policy for host2net Transport Type")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		var (
			policyName          = "ipsec-policy-transport-host2net-74220"
			ipsecTunnel         = "plutoTransportVM_host2net"
			rightNetworkAddress = "10.0.184.0" //OSP VM has network address of 10.0.184.0 with mgmt IP 10.0.185.155/22
			rightNetworkCidr    = "/22"
		)

		err := applyConfigTypeExtHost(leftPublicIP, "host2netTransportRDU2")
		o.Expect(err).NotTo(o.HaveOccurred())

		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode)
		configIPSecNMSatePolicyHost2net(oc, policyName, rightIP, rightNode, ipsecTunnel, leftIP, rightNetworkAddress, rightNetworkCidr, nodeCert, "transport")

		compat_otp.By("Checking ipsec session was established between worker node and external host")
		verifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode)
		phyInf, nicError := getSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s udp port 4500 and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		// As above tcpdump command will be executed in background, add sleep time to let the ping action happen later after that.
		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and external host encrypted by UDP-encap")
		pingCmd := fmt.Sprintf("ping -c4 %s &", leftIP)
		_, err = compat_otp.DebugNodeWithChroot(oc, rightNode, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), "UDP-encap")).Should(o.BeTrue())
	})

	// author: anusaxen@redhat.com
	g.It("Author:ansaxen-NonHyperShiftHOST-Medium-73554-External Traffic should still be IPsec encrypted in presense of Admin Network Policy application at egress node [Disruptive]", func() {
		if platformvar == "rdu2" {
			g.Skip("This case is only applicable to GCP, skipping this testcase.")
		}
		var (
			testID         = "73554"
			testDataDir    = testdata.FixturePath("networking")
			banpCRTemplate = filepath.Join(testDataDir, "adminnetworkpolicy", "banp-single-rule-template-node.yaml")
			anpCRTemplate  = filepath.Join(testDataDir, "adminnetworkpolicy", "anp-single-rule-template-node.yaml")
			matchLabelKey  = "kubernetes.io/metadata.name"
		)

		g.By("Add label to OCP egress node")
		defer compat_otp.DeleteLabelFromNode(oc, rightNode, "team-")
		compat_otp.AddLabelToNode(oc, rightNode, "team", "qe")

		compat_otp.By("Create a Baseline Admin Network Policy with allow action")
		banpCR := singleRuleBANPPolicyResourceNode{
			name:       "default",
			subjectKey: matchLabelKey,
			subjectVal: "openshift-nmstate",
			policyType: "egress",
			direction:  "to",
			ruleName:   "default-allow-egress",
			ruleAction: "Allow",
			ruleKey:    "node-role.kubernetes.io/worker",
			template:   banpCRTemplate,
		}
		defer removeResource(oc, true, true, "banp", banpCR.name)
		banpCR.createSingleRuleBANPNode(oc)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("banp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, banpCR.name)).To(o.BeTrue())

		compat_otp.By("Verify ANP with different actions and priorities")
		anpIngressRuleCR := singleRuleANPPolicyResourceNode{
			name:       "anp-" + testID + "-1",
			subjectKey: matchLabelKey,
			subjectVal: "openshift-nmstate",
			priority:   1,
			policyType: "egress",
			direction:  "to",
			ruleName:   "node-as-egress-peer-" + testID,
			ruleAction: "Allow",
			ruleKey:    "team",
			nodeKey:    "node-role.kubernetes.io/worker",
			ruleVal:    "qe",
			actionname: "egress",
			actiontype: "Allow",
			template:   anpCRTemplate,
		}
		defer removeResource(oc, true, true, "anp", anpIngressRuleCR.name)
		anpIngressRuleCR.createSingleRuleANPNode(oc)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, anpIngressRuleCR.name)).To(o.BeTrue())

		compat_otp.By("Configure nmstate ipsec policy")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)
		policyName := "ipsec-policy-transport-" + testID
		defer removeIPSecConfig(oc, policyName, ipsecTunnel, rightNode)
		configIPSecNMSatePolicy(oc, policyName, rightIP, rightNode, ipsecTunnel, leftIP, nodeCert, "transport")

		compat_otp.By("Checking ipsec session was established between worker node and ep worker node")
		verifyIPSecTunnelUp(oc, rightNode, rightIP, leftIP, "transport")

		compat_otp.By("Start tcpdump on ipsec right node")
		e2e.Logf("Trying to get physical interface on the node,%s", rightNode)
		phyInf, nicError := getSnifPhyInf(oc, rightNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		time.Sleep(5 * time.Second)
		compat_otp.By("Checking icmp between worker node and ep worker node encrypted by ESP")
		pingCmd := fmt.Sprintf("ping -c4 %s &", rightIP)
		_, err = compat_otp.DebugNodeWithChroot(oc, leftNode, "bash", "-c", pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdTcpdump.Wait()
		e2e.Logf("tcpdump for ping is \n%s", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), "ESP")).Should(o.BeTrue())
		cmdTcpdump.Process.Kill()

		compat_otp.By("Start tcpdump on ipsec right node again")
		tcpdumpCmd2 := fmt.Sprintf("timeout 60s tcpdump -nni %s esp and dst %s", phyInf, leftIP)
		cmdTcpdump2, cmdOutput2, _, err := oc.AsAdmin().Run("debug").Args("node/"+rightNode, "--", "bash", "-c", tcpdumpCmd2).Background()
		defer cmdTcpdump2.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Checking traffic between worker node and ep worker node is encrypted by ESP")
		time.Sleep(5 * time.Second)
		cmdTcpdump2.Wait()
		e2e.Logf("tcpdump for ssh is \n%s", cmdOutput2.String())
		o.Expect(strings.Contains(cmdOutput.String(), "ESP")).Should(o.BeTrue())
	})

})

var _ = g.Describe("[OTP][sig-networking] SDN IPSEC Metrics", func() {
	// Move some ipsec cases from metrics.go here, that is convieninet to use "SDN IPSEC" to grab all ipsec cases to run regression.
	// Use a seperate Describe funciton here, this is not limited to ipsec  clusters, the cases can be flexible to have prequisite in case level accordingly.
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-ipsec", compat_otp.KubeConfigPath())

	g.BeforeEach(func() {
		networkType := compat_otp.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip case on cluster that has non-OVN network plugin!!")
		}
	})

	g.It("Author:qiowang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-64077-[NETWORKCUSIM] IPSec enabled/disabled test at runtime and verify metrics. [Disruptive] [Slow]", func() {
		//As enable/disable IPSec requires applying mc and nodes reboot which costs a longer time, include more test points in this case.
		var (
			metricName = "ovnkube_controller_ipsec_enabled"
		)

		ipsecState := checkIPsec(oc)
		if ipsecState == "{}" || ipsecState == "Full" || ipsecState == "External" {
			g.Skip("Skip the testing in the ipsec enabled clusters!!!")
		}

		compat_otp.By("1. Enable IPsec at runtime")
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				configIPSecAtRuntime(oc, "disabled")
			}
		}()
		enableErr := configIPSecAtRuntime(oc, "full")
		o.Expect(enableErr).NotTo(o.HaveOccurred())

		compat_otp.By("2. Check metrics for IPsec enabled/disabled after enabling at runtime")
		prometheusURL := "localhost:29103/metrics"
		containerName := "kube-rbac-proxy-node"
		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		e2e.Logf("The expected value of the %s is 1", metricName)
		ipsecEnabled := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
			metricValueAfterEnabled := getOVNMetricsInSpecificContainer(oc, containerName, ovnMasterPodName, prometheusURL, metricName)
			if metricValueAfterEnabled == "1" {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s when enabled IPSec and try again", metricName)
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(ipsecEnabled, fmt.Sprintf("Fail to get metric when enabled IPSec and the error is:%s", ipsecEnabled))

		//Add one more step check to cover bug https://issues.redhat.com/browse/OCPBUGS-29305
		compat_otp.By("3. Verify no openssl error in ipsec pods ds")
		output, ipsecDSErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", "ovn-ipsec-host", "-n", "openshift-ovn-kubernetes", "-o", "yaml").Output()
		o.Expect(ipsecDSErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "checkedn")).NotTo(o.BeTrue())
		o.Expect(strings.Contains(output, "checkend")).To(o.BeTrue())

		compat_otp.By("Verify IPSec loaded")
		nodes, err := compat_otp.GetAllNodes(oc)
		e2e.Logf("The cluster has %v nodes", len(nodes))
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Get one worker node")
		workerNode, err := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyIPSecLoaded(oc, workerNode, len(nodes))

		compat_otp.By("4. Disable IPsec at runtime")
		disableErr := configIPSecAtRuntime(oc, "disabled")
		o.Expect(disableErr).NotTo(o.HaveOccurred())

		compat_otp.By("5. Check metrics for IPsec enabled/disabled after disabling at runtime")
		ovnMasterPodName = getOVNKMasterOVNkubeNode(oc)
		e2e.Logf("The expected value of the %s is 0", metricName)
		ipsecDisabled := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
			metricValueAfterDisabled := getOVNMetricsInSpecificContainer(oc, containerName, ovnMasterPodName, prometheusURL, metricName)
			if metricValueAfterDisabled == "0" {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s when disabled IPSec and try again", metricName)
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(ipsecDisabled, fmt.Sprintf("Fail to get metric when disabled IPSec and the error is:%s", ipsecDisabled))
	})

	// author huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-High-72893-IPSec state can be shown in prometheus endpoint.", func() {
		metricQuery := "openshift:openshift_network_operator_ipsec_state:info"

		compat_otp.By(fmt.Sprintf("Check that the metric %s is exposed to telemetry", metricQuery))
		expectedExposedMetric := fmt.Sprintf(`{__name__=\"%s\"}`, metricQuery)
		telemetryConfig, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("configmap", "-n", "openshift-monitoring", "telemetry-config", "-o=jsonpath={.data}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(telemetryConfig).To(o.ContainSubstring(expectedExposedMetric),
			"Metric %s, is not exposed to telemetry", metricQuery)

		mon, err := compat_otp.NewPrometheusMonitor(oc.AsAdmin())
		o.Expect(err).NotTo(o.HaveOccurred(), "Error creating new prometheus monitor")

		compat_otp.By(fmt.Sprintf("Verify the metric %s displays the right value", metricQuery))

		queryResult, err := mon.SimpleQuery(metricQuery)
		o.Expect(err).NotTo(o.HaveOccurred(),
			"Error querying metric: %s", metricQuery)

		jsonResult := gjson.Parse(queryResult)
		e2e.Logf(jsonResult.String())
		status := jsonResult.Get("status").String()
		o.Expect(status).Should(o.Equal("success"),
			"Query %s execution failed: %s", metricQuery, status)
		is_legacy_api := gjson.Parse(queryResult).Get("data.result.0.metric.is_legacy_api").String()
		mode := gjson.Parse(queryResult).Get("data.result.0.metric.mode").String()
		metricValue := gjson.Parse(queryResult).Get("data.result.0.value.1").String()
		o.Expect(metricValue).Should(o.Equal("1"))

		ipsecState := checkIPsec(oc)
		switch ipsecState {
		case "Full":
			o.Expect(is_legacy_api).Should(o.Equal("false"))
			o.Expect(mode).Should(o.Equal("Full"))
		case "External":
			o.Expect(is_legacy_api).Should(o.Equal("false"))
			o.Expect(mode).Should(o.Equal("External"))
		case "Disabled":
			o.Expect(is_legacy_api).Should(o.Equal("false"))
			o.Expect(mode).Should(o.Equal("Disabled"))
		case "{}":
			o.Expect(is_legacy_api).Should(o.Equal("true"))
			o.Expect(mode).Should(o.Equal("Full"))
		default:
			o.Expect(is_legacy_api).Should(o.Equal("N/A - ipsec not supported (non-OVN network)"))
			o.Expect(mode).Should(o.Equal("Disabled"))
		}
	})
})
