package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

var _ = g.Describe("[OTP][sig-networking] SDN misc", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-ovnkubernetes", compat_otp.KubeConfigPath())
	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	// author: anusaxen@redhat.com
	g.It("Author:anusaxen-Medium-49216-ovnkube-node logs should not print api token in logs. ", func() {
		g.By("it's for bug 2009857")
		workerNode, err := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		ovnkubePod, err := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", workerNode)
		o.Expect(err).NotTo(o.HaveOccurred())
		podlogs, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args(ovnkubePod, "-n", "openshift-ovn-kubernetes", "-c", "ovnkube-controller").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(podlogs).NotTo(o.ContainSubstring("kube-api-token"))
		g.By("ovnkube-node logs doesn't contain api-token")
	})

	//author: zzhao@redhat.com
	g.It("NonHyperShiftHOST-Author:zzhao-Medium-54742- Completed pod ip can be released.[Flaky]", func() {
		g.By("it's for bug 2091157,Check the ovnkube-master logs to see if completed pod already release ip")
		result := findLogFromPod(oc, "Releasing IPs for Completed pod", "openshift-ovn-kubernetes", "app=ovnkube-node", "ovnkube-controller")
		o.Expect(result).To(o.BeTrue())
	})

	// author: anusaxen@redhat.com
	g.It("Author:anusaxen-NonHyperShiftHOST-NonPreRelease-High-55144-[FdpOvnOvs] [NETWORKCUSIM] Switching OVN gateway modes should not delete custom routes created on node logical routers.[Disruptive] ", func() {
		compat_otp.By("it's for bug 2042516")
		var desiredMode string

		//need to find out original mode cluster is on so that we can revert back to same post test
		origMode := getOVNGatewayMode(oc)
		if origMode == "local" {
			desiredMode = "shared"
		} else {
			desiredMode = "local"
		}
		e2e.Logf("Cluster is currently on gateway mode %s", origMode)
		e2e.Logf("Desired mode is %s", desiredMode)
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("This case requires at least one schedulable node")
		}
		compat_otp.By("Add a logical route on a node")
		nodeLogicalRouterName := "GR_" + nodeList.Items[0].Name
		ovnKNodePod, ovnkNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		lrRouteListDelCmd := "ovn-nbctl lr-route-del " + nodeLogicalRouterName + " 192.168.122.0/24 192.168.122.4"
		lrRouteListAddCmd := "ovn-nbctl lr-route-add " + nodeLogicalRouterName + " 192.168.122.0/24 192.168.122.4"

		defer compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKNodePod, lrRouteListDelCmd)
		_, lrlErr1 := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKNodePod, lrRouteListAddCmd)
		o.Expect(lrlErr1).NotTo(o.HaveOccurred())
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				switchOVNGatewayMode(oc, origMode)
			}
		}()
		switchOVNGatewayMode(oc, desiredMode)
		compat_otp.By("List the logical route on a node after gateway mode switch")
		lrRouteListCmd := "ovn-nbctl lr-route-list " + nodeLogicalRouterName
		ovnKNodePod, ovnkNodePodErr = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))

		defer compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKNodePod, lrRouteListDelCmd)
		lRlOutput, lrlErr2 := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKNodePod, lrRouteListCmd)
		o.Expect(lrlErr2).NotTo(o.HaveOccurred())
		o.Expect(lRlOutput).To(o.ContainSubstring("192.168.122.0/24"))
		o.Expect(lRlOutput).To(o.ContainSubstring("192.168.122.4"))

		//reverting back cluster to original mode it was on and deleting fake route
		switchOVNGatewayMode(oc, origMode)
		compat_otp.By("List the logical route on a node after gateway mode revert")
		ovnKNodePod, ovnkNodePodErr = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))

		defer compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKNodePod, lrRouteListDelCmd)
		_, lrlErr3 := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKNodePod, lrRouteListCmd)
		o.Expect(lrlErr3).NotTo(o.HaveOccurred())
		o.Expect(lRlOutput).To(o.ContainSubstring("192.168.122.0/24"))
		o.Expect(lRlOutput).To(o.ContainSubstring("192.168.122.4"))

		compat_otp.By("Delete the logical route on a node after gateway mode revert")
		_, lrlErr4 := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKNodePod, lrRouteListDelCmd)
		o.Expect(lrlErr4).NotTo(o.HaveOccurred())
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-Medium-61312-[NETWORKCUSIM] Unsupported scenarios in expanding cluster networks should be denied. [Disruptive]", func() {

		ipStackType := checkIPStackType(oc)
		if ipStackType != "ipv4single" {
			g.Skip("The feature is currently supported on IPv4 cluster only, skip for other IP stack type for now")
		}

		origNetworkCIDR, orighostPrefix := getClusterNetworkInfo(oc)
		origNetAddress := strings.Split(origNetworkCIDR, "/")[0]
		origNetMaskVal, _ := strconv.Atoi(strings.Split(origNetworkCIDR, "/")[1])
		origHostPrefixVal, _ := strconv.Atoi(orighostPrefix)
		e2e.Logf("Original netAddress:%v, netMask:%v, hostPrefix: %v", origNetAddress, origNetMaskVal, origHostPrefixVal)

		g.By("1. Verify that decreasing IP space by larger CIDR mask is not allowed")
		newCIDR := origNetAddress + "/" + strconv.Itoa(origNetMaskVal+1)
		e2e.Logf("Attempt to change to newCIDR: %v", newCIDR)

		// patch command will be executed even though invalid config is supplied, so still call patchResourceAsAdmin function
		restorePatchValue := "{\"spec\":{\"clusterNetwork\":[{\"cidr\":\"" + origNetworkCIDR + "\", \"hostPrefix\":" + orighostPrefix + "}],\"networkType\":\"OVNKubernetes\"}}"

		defer patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", restorePatchValue)
		patchValue := "{\"spec\":{\"clusterNetwork\":[{\"cidr\":\"" + newCIDR + "\", \"hostPrefix\":" + orighostPrefix + "}],\"networkType\":\"OVNKubernetes\"}}"
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchValue)

		o.Eventually(func() string {
			return getCNOStatusCondition(oc)
		}, 60*time.Second, 3*time.Second).Should(o.ContainSubstring(`invalid configuration: [reducing IP range with a larger CIDR mask for clusterNetwork CIDR is unsupported]`))

		// restore to original valid config before next step
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", restorePatchValue)
		o.Eventually(func() string {
			return getCNOStatusCondition(oc)
		}, 60*time.Second, 3*time.Second).ShouldNot(o.ContainSubstring(`invalid configuration: [reducing IP range with a larger CIDR mask for clusterNetwork CIDR is unsupported]`))

		g.By("2. Verify that changing hostPrefix is not allowed")
		newHostPrefix := strconv.Itoa(origHostPrefixVal + 1)
		e2e.Logf("Attempt to change to newHostPrefix: %v", newHostPrefix)

		// patch command will be executed even though invalid config is supplied, so still call patchResourceAsAdmin function
		patchValue = "{\"spec\":{\"clusterNetwork\":[{\"cidr\":\"" + origNetworkCIDR + "\", \"hostPrefix\":" + newHostPrefix + "}],\"networkType\":\"OVNKubernetes\"}}"
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchValue)
		o.Eventually(func() string {
			return getCNOStatusCondition(oc)
		}, 60*time.Second, 3*time.Second).Should(o.ContainSubstring(`invalid configuration: [modifying a clusterNetwork's hostPrefix value is unsupported]`))

		// restore to original valid config before next step
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", restorePatchValue)
		o.Eventually(func() string {
			return getCNOStatusCondition(oc)
		}, 60*time.Second, 3*time.Second).ShouldNot(o.ContainSubstring(`invalid configuration: [modifying a clusterNetwork's hostPrefix value is unsupported]`))

		newHostPrefix = strconv.Itoa(origHostPrefixVal - 1)
		e2e.Logf("Attempt to change to newHostPrefix: %v", newHostPrefix)

		// patch command will be executed even though invalid config is supplied, so still call patchResourceAsAdmin function
		patchValue = "{\"spec\":{\"clusterNetwork\":[{\"cidr\":\"" + origNetworkCIDR + "\", \"hostPrefix\":" + newHostPrefix + "}],\"networkType\":\"OVNKubernetes\"}}"
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchValue)
		o.Eventually(func() string {
			return getCNOStatusCondition(oc)
		}, 60*time.Second, 3*time.Second).Should(o.ContainSubstring(`invalid configuration: [modifying a clusterNetwork's hostPrefix value is unsupported]`))

		// restore to original valid config before next step
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", restorePatchValue)
		o.Eventually(func() string {
			return getCNOStatusCondition(oc)
		}, 60*time.Second, 3*time.Second).ShouldNot(o.ContainSubstring(`invalid configuration: [modifying a clusterNetwork's hostPrefix value is unsupported]`))

		g.By("3. Verify that changing network IP is not allowed")
		subAddress := strings.Split(origNetAddress, ".")
		subAddressB, _ := strconv.Atoi(subAddress[1])
		newSubAddressB := strconv.Itoa(subAddressB + 1)
		newNetAddress := subAddress[0] + "." + newSubAddressB + "." + subAddress[2] + "." + subAddress[3]
		newCIDR = newNetAddress + "/" + strconv.Itoa(origNetMaskVal)
		e2e.Logf("Attempt to change to newCIDR: %v", newCIDR)

		// patch command will be executed even though invalid config is supplied, so still call patchResourceAsAdmin function
		patchValue = "{\"spec\":{\"clusterNetwork\":[{\"cidr\":\"" + newCIDR + "\", \"hostPrefix\":" + orighostPrefix + "}],\"networkType\":\"OVNKubernetes\"}}"
		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", patchValue)
		o.Eventually(func() string {
			return getCNOStatusCondition(oc)
		}, 60*time.Second, 3*time.Second).Should(o.ContainSubstring(`invalid configuration: [modifying IP network value for clusterNetwork CIDR is unsupported]`))

		patchResourceAsAdmin(oc, "Network.config.openshift.io/cluster", restorePatchValue)
		o.Eventually(func() string {
			return getCNOStatusCondition(oc)
		}, 60*time.Second, 3*time.Second).ShouldNot(o.ContainSubstring(`invalid configuration: [modifying IP network value for clusterNetwork CIDR is unsupported]`))
	})

	//author: zzhao@redhat.com
	//bug: https://issues.redhat.com/browse/OCPBUGS-2827
	g.It("NonHyperShiftHOST-ConnectedOnly-ROSA-OSD_CCS-Author:zzhao-Medium-64297- check nodeport service with large mtu.[Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			hostPortServiceFile = filepath.Join(buildPruningBaseDir, "ocpbug-2827/hostport.yaml")
			mtuTestFile         = filepath.Join(buildPruningBaseDir, "ocpbug-2827/mtutest.yaml")
			ns1                 = "openshift-kube-apiserver"
		)
		platform := compat_otp.CheckPlatform(oc)
		acceptedPlatform := strings.Contains(platform, "aws")
		if !acceptedPlatform {
			g.Skip("Test cases should be run on AWS cluster with ovn network plugin, skip for other platforms or other network plugin!!")
		}

		g.By("create nodeport service in namespace")
		defer removeResource(oc, true, true, "-f", hostPortServiceFile, "-n", ns1)
		createResourceFromFile(oc, ns1, hostPortServiceFile)

		g.By("create mtutest pod")
		defer removeResource(oc, true, true, "-f", mtuTestFile, "-n", ns1)
		createResourceFromFile(oc, ns1, mtuTestFile)
		err := waitForPodWithLabelReady(oc, ns1, "app=mtu-tester")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label app=mtu-tester not ready")
		mtuTestPod := getPodName(oc, ns1, "app=mtu-tester")

		g.By("get one nodeip")
		PodNodeName, nodeErr := compat_otp.GetPodNodeName(oc, ns1, mtuTestPod[0])
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		nodeIp := getNodeIPv4(oc, ns1, PodNodeName)

		output, err := e2eoutput.RunHostCmd(ns1, mtuTestPod[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(nodeIp, "31251")+"?mtu=8849 2>/dev/null | cut -b-10")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "Terminated")).To(o.BeFalse())
		output, err = e2eoutput.RunHostCmd(ns1, mtuTestPod[0], "curl --connect-timeout 5 -s "+net.JoinHostPort(nodeIp, "31251")+"?mtu=8850 2>/dev/null | cut -b-10")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "Terminated")).To(o.BeFalse())
	})

	// author: anusaxen@redhat.com
	g.It("Author:anusaxen-High-64151-check node healthz port is enabled for ovnk in CNO for GCP", func() {
		e2e.Logf("It is for OCPBUGS-7158")
		platform := checkPlatform(oc)
		if !strings.Contains(platform, "gcp") {
			g.Skip("Skip for un-expected platform,not GCP!")
		}
		g.By("Expect healtz-bind-address to be present in ovnkube-config config map")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("cm", "-n", "openshift-ovn-kubernetes", "ovnkube-config", "-ojson").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "0.0.0.0:10256")).To(o.BeTrue())

		g.By("Make sure healtz-bind-address is reachable via nodes")
		worker_node, err := compat_otp.GetFirstLinuxWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err = compat_otp.DebugNode(oc, worker_node, "bash", "-c", "curl -v http://0.0.0.0:10256/healthz")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("HTTP/1.1 200 OK"))
	})

	// author: jechen@redhat.com
	g.It("Longduration-NonPreRelease-Author:jechen-High-68418-Same name pod can be recreated on new node and still work on OVN cluster. [Disruptive]", func() {

		// This is for customer bug: https://issues.redhat.com/browse/OCPBUGS-18681

		buildPruningBaseDir := testdata.FixturePath("networking")
		kubeletKillerPodTemplate := filepath.Join(buildPruningBaseDir, "kubelet-killer-pod-template.yaml")

		compat_otp.By("1. Create a new machineset, get the new node created\n")
		clusterinfra.SkipConditionally(oc)
		infrastructureName := clusterinfra.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-68418"
		ms := clusterinfra.MachineSetDescription{Name: machinesetName, Replicas: 1}
		defer clusterinfra.WaitForMachinesDisapper(oc, machinesetName)
		defer ms.DeleteMachineSet(oc)
		ms.CreateMachineSet(oc)

		clusterinfra.WaitForMachinesRunning(oc, 1, machinesetName)
		machineName := clusterinfra.GetMachineNamesFromMachineSet(oc, machinesetName)
		o.Expect(len(machineName)).ShouldNot(o.Equal(0))
		nodeName := clusterinfra.GetNodeNameFromMachine(oc, machineName[0])
		e2e.Logf("Get nodeName: %v", nodeName)

		compat_otp.By("2. Create kubelet-killer pod on the node\n")
		kkPod := kubeletKillerPod{
			name:      "kubelet-killer-68418",
			namespace: "openshift-machine-api",
			nodename:  nodeName,
			template:  kubeletKillerPodTemplate,
		}
		kkPod.createKubeletKillerPodOnNode(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "kubelet-killer-68418", "-n", kkPod.namespace, "--ignore-not-found=true").Execute()

		// After Kubelet-killer pod is created, it kills the node it resides on, kubelet-killer pod quickly transitioned into pending phase and stays in pending phase after its node becomes NotReady
		podStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", kkPod.name, "-n", kkPod.namespace, "-o=jsonpath={.status.phase}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("kkPod status:%v", podStatus)
		o.Expect(regexp.MatchString("Pending", podStatus)).Should(o.BeTrue())

		// node is expected to be in NotReady state after kubelet killer pod kills its kubelet
		checkNodeStatus(oc, nodeName, "NotReady")

		compat_otp.By("3. Delete the node and its machineset, and delete the kubelet-killer pod\n")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("machines.machine.openshift.io", machineName[0], "-n", "openshift-machine-api").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		// Verify the machineset is deleted
		ms.DeleteMachineSet(oc)
		clusterinfra.WaitForMachinesRunning(oc, 0, machinesetName)

		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "kubelet-killer-68418", "-n", kkPod.namespace, "--ignore-not-found=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Recreate the machineset, get the newer node created\n")
		ms2 := clusterinfra.MachineSetDescription{Name: machinesetName, Replicas: 1}
		defer ms2.DeleteMachineSet(oc)
		ms2.CreateMachineSet(oc)

		clusterinfra.WaitForMachinesRunning(oc, 1, machinesetName)
		machineName = clusterinfra.GetMachineNamesFromMachineSet(oc, machinesetName)
		o.Expect(len(machineName)).ShouldNot(o.Equal(0))
		newNodeName := clusterinfra.GetNodeNameFromMachine(oc, machineName[0])

		compat_otp.By("5. Recreate kubelet-killer pod with same pod name on the newer node\n")
		kkPod2 := kubeletKillerPod{
			name:      "kubelet-killer-68418",
			namespace: "openshift-machine-api",
			nodename:  newNodeName,
			template:  kubeletKillerPodTemplate,
		}
		kkPod2.createKubeletKillerPodOnNode(oc)

		// After Kubelet-killer pod2 is created, it kills the node it resides on, kubelet-killer pod quickly transitioned into pending phase and stays in pending phase after its node becomes NotReady
		podStatus, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", kkPod2.name, "-n", kkPod2.namespace, "-o=jsonpath={.status.phase}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("kkPod2 status:%v", podStatus)
		o.Expect(regexp.MatchString("Pending", podStatus)).Should(o.BeTrue())

		// Verify kubelet-killer pod was able to be recreated and does it job of killing the node
		checkNodeStatus(oc, newNodeName, "NotReady")

		compat_otp.By("6. Verify ErrorAddingLogicalPort or FailedCreateSandBox events are not generated when pod is recreated\n")
		podDescribe, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("pod", kkPod2.name, "-n", kkPod2.namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(regexp.MatchString("ErrorAddingLogicalPort", podDescribe)).Should(o.BeFalse())
		o.Expect(regexp.MatchString("FailedCreatedPodSandBox", podDescribe)).Should(o.BeFalse())

		compat_otp.By("7. Cleanup after test: delete the node and its machineset, then delete the kubelet-killer pod\n")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("machines.machine.openshift.io", machineName[0], "-n", "openshift-machine-api").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		// Verify the machineset is deleted
		ms.DeleteMachineSet(oc)

		// 960s total wait.poll time may not be enough for some type of clusters, add some sleep time before WaitForMachinesRunning
		time.Sleep(180 * time.Second)
		clusterinfra.WaitForMachinesRunning(oc, 0, machinesetName)

		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "kubelet-killer-68418", "-n", kkPod.namespace, "--ignore-not-found=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

	})
	// author: asood@redhat.com
	// https://issues.redhat.com/browse/OCPBUGS-4825
	g.It("Author:asood-Medium-66047-[FdpOvnOvs] [NETWORKCUSIM] Verify allocated IP address of the pod on a specific node with completed status when delete is released in OVN DB", func() {
		var (
			buildPruningBaseDir      = testdata.FixturePath("networking")
			completedPodNodeTemplate = filepath.Join(buildPruningBaseDir, "completed-pod-specific-node-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items)).NotTo(o.BeEquivalentTo(0))

		compat_otp.By("Get namespace")
		ns := oc.Namespace()

		compat_otp.By("Create pods with completed status")
		for i := 0; i < 50; i++ {
			podns := pingPodResourceNode{
				name:      "completed-pod-" + strconv.Itoa(i),
				namespace: ns,
				nodename:  nodeList.Items[0].Name,
				template:  completedPodNodeTemplate,
			}
			podns.createPingPodNode(oc)
		}
		compat_otp.By("Count all the pods with completed status")
		allPods, getPodErr := compat_otp.GetAllPodsWithLabel(oc, ns, "name=completed-pod")
		o.Expect(getPodErr).NotTo(o.HaveOccurred())
		o.Expect(len(allPods)).To(o.BeEquivalentTo(50))
		// Allow the last pod IP to be released before checking NB DB
		time.Sleep(10 * time.Second)

		compat_otp.By("Verify there are no IP in NB DB for the completed pods")
		ovnKNodePod, ovnkNodePodErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeList.Items[0].Name)
		o.Expect(ovnkNodePodErr).NotTo(o.HaveOccurred())
		o.Expect(ovnKNodePod).ShouldNot(o.Equal(""))
		getCmd := fmt.Sprintf("ovn-nbctl show | grep '%s' | wc -l", ns)
		getCount, getCmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKNodePod, "ovnkube-controller", getCmd)
		o.Expect(getCmdErr).NotTo(o.HaveOccurred())
		o.Expect(strconv.Atoi(getCount)).To(o.BeEquivalentTo(0))

		compat_otp.By("Delete all the pods with completed status")
		_, delPodErr := oc.AsAdmin().Run("delete").Args("pod", "-l", "name=completed-pod", "-n", ns).Output()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())
	})

	g.It("Author:qiowang-Medium-69761-Check apbexternalroute status when all zones reported success", func() {
		ipStackType := checkIPStackType(oc)
		var externalGWIP1, externalGWIP2 string
		if ipStackType == "dualstack" {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "2011::11"
		} else if ipStackType == "ipv6single" {
			externalGWIP1 = "2011::11"
			externalGWIP2 = "2011::12"
		} else {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "1.1.1.2"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		apbExternalRouteTemplate := filepath.Join(buildPruningBaseDir, "apbexternalroute-static-template.yaml")

		compat_otp.By("1. Create Admin Policy Based External route object")
		ns := oc.Namespace()
		apbExternalRoute := apbStaticExternalRoute{
			name:       "externalgw-69761",
			labelkey:   "kubernetes.io/metadata.name",
			labelvalue: ns,
			ip1:        externalGWIP1,
			ip2:        externalGWIP2,
			bfd:        false,
			template:   apbExternalRouteTemplate,
		}
		defer apbExternalRoute.deleteAPBExternalRoute(oc)
		apbExternalRoute.createAPBExternalRoute(oc)

		compat_otp.By("2. Check status of apbexternalroute object")
		checkErr := checkAPBExternalRouteStatus(oc, apbExternalRoute.name, "Success")
		compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("apbexternalroute %s doesn't succeed in time", apbExternalRoute.name))
		messages, messagesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.name, `-ojsonpath={.status.messages}`).Output()
		o.Expect(messagesErr).NotTo(o.HaveOccurred())
		nodes, getNodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			o.Expect(messages).Should(o.ContainSubstring(node + ": configured external gateway IPs: " + apbExternalRoute.ip1 + "," + apbExternalRoute.ip2))
		}
	})

	g.It("Author:qiowang-Medium-69762-Check egressfirewall status when all zones reported success", func() {
		ipStackType := checkIPStackType(oc)
		var egressFWCIDR1, egressFWCIDR2 string
		if ipStackType == "dualstack" {
			egressFWCIDR1 = "2.1.1.0/24"
			egressFWCIDR2 = "2021::/96"
		} else if ipStackType == "ipv6single" {
			egressFWCIDR1 = "2021::/96"
			egressFWCIDR2 = "2022::/96"
		} else {
			egressFWCIDR1 = "2.1.1.0/24"
			egressFWCIDR2 = "2.1.2.0/24"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")

		compat_otp.By("1. Create egressfirewall object")
		ns := oc.Namespace()
		egressFW := egressFirewall5{
			name:        "default",
			namespace:   ns,
			ruletype1:   "Allow",
			rulename1:   "cidrSelector",
			rulevalue1:  egressFWCIDR1,
			protocol1:   "TCP",
			portnumber1: 80,
			ruletype2:   "Allow",
			rulename2:   "cidrSelector",
			rulevalue2:  egressFWCIDR2,
			protocol2:   "TCP",
			portnumber2: 80,
			template:    egressFWTemplate,
		}
		defer removeResource(oc, true, true, "egressfirewall", egressFW.name, "-n", egressFW.namespace)
		egressFW.createEgressFW5Object(oc)

		compat_otp.By("2. Check status of egressfirewall object")
		checkErr := checkEgressFWStatus(oc, egressFW.name, ns, "EgressFirewall Rules applied")
		compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("EgressFirewall Rule %s doesn't apply in time", egressFW.name))
		messages, messagesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.name, "-n", egressFW.namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(messagesErr).NotTo(o.HaveOccurred())
		nodes, getNodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			o.Expect(messages).Should(o.ContainSubstring(node + ": EgressFirewall Rules applied"))
		}
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Longduration-NonPreRelease-Author:huirwang-High-69198-Oversized UDP packet handling. [Disruptive]", func() {
		//It is for customer bug https://issues.redhat.com/browse/OCPBUGS-23334
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressIPTemplate    = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		)

		// This case needs an external host, will run it on rdu1 cluster only.
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com")) {
			g.Skip("This case will only run on rdu1 cluster, skip for other envrionment!!!")
		}

		compat_otp.By("Switch to local gate way mode.")
		defer switchOVNGatewayMode(oc, "shared")
		switchOVNGatewayMode(oc, "local")

		ns1 := oc.Namespace()
		workers := excludeSriovNodes(oc)
		o.Expect(len(workers) > 0).Should(o.BeTrue())
		compat_otp.By("create a hello pod in first namespace")
		pod1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns1,
			nodename:  workers[0],
			template:  pingPodTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Label one worker node as egress node")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], "k8s.ovn.org/egress-assignable")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], "k8s.ovn.org/egress-assignable", "true")

		compat_otp.By("Create egressIP object")
		freeIPs := findFreeIPs(oc, workers[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-69198",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer removeResource(oc, true, true, "egressip", egressip1.name)
		egressip1.createEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Add matched label to test namespace")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Start iperf3 on external host")
		iperfServerCmd := "nohup iperf3 -s &"
		exteranlHost := "10.8.1.181"
		defer func() {
			err = sshRunCmd(exteranlHost, "root", "pkill iperf3 &")
			o.Expect(err).NotTo(o.HaveOccurred())
		}()
		go func() {
			err = sshRunCmd(exteranlHost, "root", iperfServerCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}()

		// iperf3 would start in parallel, adding wait time to ensure iperf3 started.
		time.Sleep(10 * time.Second)
		compat_otp.By("Start iperf3 client on test pod and send udp traffic")
		iperfClientCmd := "iperf3 -u -n 1647 -l 1647 -c 192.168.111.1 -R -d -i 10"
		res, err := compat_otp.RemoteShPodWithBash(oc, ns1, pod1.name, iperfClientCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(res, "iperf Done")).Should(o.BeTrue(), fmt.Sprintf("The client sent large packet to server failed with message: %s", res))
		o.Expect(strings.Contains(res, "iperf3: error - control socket has closed unexpectedly")).ShouldNot(o.BeTrue(), fmt.Sprintf("The client sokcet was closed unexpectedly with error :%s", res))

		compat_otp.By("Remove matched label to test namespace")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Again--start iperf3 client on test pod and send udp traffic")
		res, err = compat_otp.RemoteShPodWithBash(oc, ns1, pod1.name, iperfClientCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(res, "iperf Done")).Should(o.BeTrue(), fmt.Sprintf("The client sent large packet to server failed with message: %s", res))
		o.Expect(strings.Contains(res, "iperf3: error - control socket has closed unexpectedly")).ShouldNot(o.BeTrue(), fmt.Sprintf("The client sokcet was closed unexpectedly with error :%s", res))
	})

	g.It("Author:qiowang-Medium-69875-Check apbexternalroute status when there is zone reported failure [Disruptive]", func() {
		ipStackType := checkIPStackType(oc)
		var externalGWIP1, externalGWIP2 string
		if ipStackType == "dualstack" {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "2011::11"
		} else if ipStackType == "ipv6single" {
			externalGWIP1 = "2011::11"
			externalGWIP2 = "2011::12"
		} else {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "1.1.1.2"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		apbExternalRouteTemplate := filepath.Join(buildPruningBaseDir, "apbexternalroute-static-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		workerNode, getWorkerErr := compat_otp.GetFirstLinuxWorkerNode(oc)
		o.Expect(getWorkerErr).NotTo(o.HaveOccurred())

		compat_otp.By("1. Create pod on one worker node")
		ns := oc.Namespace()
		pod := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns,
			nodename:  workerNode,
			template:  pingPodNodeTemplate,
		}
		defer pod.deletePingPodNode(oc)
		pod.createPingPodNode(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		compat_otp.By("2. Remove node annotation k8s.ovn.org/l3-gateway-config")
		annotation, getAnnotationErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("node/"+workerNode, "-o", "jsonpath='{.metadata.annotations.k8s\\.ovn\\.org/l3-gateway-config}'").Output()
		o.Expect(getAnnotationErr).NotTo(o.HaveOccurred())
		defer compat_otp.AddAnnotationsToSpecificResource(oc, "node/"+workerNode, "", "k8s.ovn.org/l3-gateway-config="+strings.Trim(annotation, "'"))
		compat_otp.RemoveAnnotationFromSpecificResource(oc, "node/"+workerNode, "", "k8s.ovn.org/l3-gateway-config")

		compat_otp.By("3. Create Admin Policy Based External route object")
		apbExternalRoute := apbStaticExternalRoute{
			name:       "externalgw-69875",
			labelkey:   "kubernetes.io/metadata.name",
			labelvalue: ns,
			ip1:        externalGWIP1,
			ip2:        externalGWIP2,
			bfd:        false,
			template:   apbExternalRouteTemplate,
		}
		defer apbExternalRoute.deleteAPBExternalRoute(oc)
		apbExternalRoute.createAPBExternalRoute(oc)

		compat_otp.By("4. Check status of apbexternalroute object")
		checkErr := checkAPBExternalRouteStatus(oc, apbExternalRoute.name, "Fail")
		compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("apbexternalroute %s doesn't show Fail in time", apbExternalRoute.name))
		messages, messagesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.name, `-ojsonpath={.status.messages}`).Output()
		o.Expect(messagesErr).NotTo(o.HaveOccurred())
		nodes, getNodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			if node == workerNode {
				o.Expect(messages).Should(o.ContainSubstring(node + ": " + node + " failed to apply policy"))
			} else {
				o.Expect(messages).Should(o.ContainSubstring(node + ": configured external gateway IPs: " + apbExternalRoute.ip1 + "," + apbExternalRoute.ip2))
			}
		}
	})

	g.It("Author:qiowang-Medium-69873-Medium-69874-Check apbexternalroute/egressfirewall status when no failure reported and not all zones reported success [Disruptive]", func() {
		nodes, getNodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		if len(nodes) < 2 {
			g.Skip("Not enough nodes for the test, need at least 2 linux nodes, skip the case!!")
		}

		ipStackType := checkIPStackType(oc)
		var externalGWIP1, externalGWIP2, egressFWCIDR1, egressFWCIDR2 string
		if ipStackType == "dualstack" {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "2011::11"
			egressFWCIDR1 = "2.1.1.0/24"
			egressFWCIDR2 = "2021::/96"
		} else if ipStackType == "ipv6single" {
			externalGWIP1 = "2011::11"
			externalGWIP2 = "2011::12"
			egressFWCIDR1 = "2021::/96"
			egressFWCIDR2 = "2022::/96"
		} else {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "1.1.1.2"
			egressFWCIDR1 = "2.1.1.0/24"
			egressFWCIDR2 = "2.1.2.0/24"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		apbExternalRouteTemplate := filepath.Join(buildPruningBaseDir, "apbexternalroute-static-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")

		compat_otp.By("1. Reboot one worker node, wait it becomes NotReady")
		workerNode, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "node-role.kubernetes.io/worker,kubernetes.io/os=linux", "-o", "jsonpath={.items[0].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer checkNodeStatus(oc, workerNode, "Ready")
		defaultInt := "br-ex"
		fileContent := fmt.Sprintf("ifconfig %s down; sleep 120; ifconfig %s up;", defaultInt, defaultInt)
		createFileCmd := `echo -e "` + fileContent + `" > /tmp/test.sh`
		_, err1 := compat_otp.DebugNodeWithChroot(oc, workerNode, "bash", "-c", createFileCmd)
		o.Expect(err1).NotTo(o.HaveOccurred())
		delFileCmd := "rm -rf /tmp/test.sh"
		defer compat_otp.DebugNodeWithChroot(oc, workerNode, "bash", "-c", delFileCmd)
		chmodCmd := "chmod +x /tmp/test.sh"
		_, err2 := compat_otp.DebugNodeWithChroot(oc, workerNode, "bash", "-c", chmodCmd)
		o.Expect(err2).NotTo(o.HaveOccurred())
		testCmd := "/tmp/test.sh"
		runCmd, _, _, runCmdErr := oc.AsAdmin().Run("debug").Args("node/"+workerNode, "--to-namespace", "default", "--", "chroot", "/host", "bash", "-c", testCmd).Background()
		defer runCmd.Process.Kill()
		o.Expect(runCmdErr).NotTo(o.HaveOccurred())
		checkNodeStatus(oc, workerNode, "NotReady")

		compat_otp.By("2. Create Admin Policy Based External route object with static gateway when the worker node in NotReady status")
		ns := oc.Namespace()
		apbExternalRoute := apbStaticExternalRoute{
			name:       "externalgw-69873",
			labelkey:   "kubernetes.io/metadata.name",
			labelvalue: ns,
			ip1:        externalGWIP1,
			ip2:        externalGWIP2,
			bfd:        false,
			template:   apbExternalRouteTemplate,
		}
		defer apbExternalRoute.deleteAPBExternalRoute(oc)
		apbExternalRoute.createAPBExternalRoute(oc)

		compat_otp.By("3. Create egressfirewall object with allow rule when the worker node in NotReady status")
		egressFW := egressFirewall5{
			name:        "default",
			namespace:   ns,
			ruletype1:   "Allow",
			rulename1:   "cidrSelector",
			rulevalue1:  egressFWCIDR1,
			protocol1:   "TCP",
			portnumber1: 80,
			ruletype2:   "Allow",
			rulename2:   "cidrSelector",
			rulevalue2:  egressFWCIDR2,
			protocol2:   "TCP",
			portnumber2: 80,
			template:    egressFWTemplate,
		}
		defer removeResource(oc, true, true, "egressfirewall", egressFW.name, "-n", egressFW.namespace)
		egressFW.createEgressFW5Object(oc)

		compat_otp.By("4. Check status of apbexternalroute/egressfirewall object")
		apbExtRouteSta, apbExtRouteStaErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.name, `-ojsonpath={.status.status}`).Output()
		o.Expect(apbExtRouteStaErr).NotTo(o.HaveOccurred())
		o.Expect(apbExtRouteSta).Should(o.BeEmpty())
		apbExtRouteMsgs, apbExtRouteMsgsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.name, `-ojsonpath={.status.messages}`).Output()
		o.Expect(apbExtRouteMsgsErr).NotTo(o.HaveOccurred())
		egressFWStatus, egressFWStatusErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.name, "-n", egressFW.namespace, `-ojsonpath={.status.status}`).Output()
		o.Expect(egressFWStatusErr).NotTo(o.HaveOccurred())
		o.Expect(egressFWStatus).Should(o.BeEmpty())
		egressFWMsgs, egressFWMsgsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.name, "-n", egressFW.namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(egressFWMsgsErr).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			if node == workerNode {
				o.Expect(strings.Contains(apbExtRouteMsgs, node+": configured external gateway IPs: "+apbExternalRoute.ip1+","+apbExternalRoute.ip2)).ShouldNot(o.BeTrue())
				o.Expect(strings.Contains(egressFWMsgs, node+": EgressFirewall Rules applied")).ShouldNot(o.BeTrue())
			} else {
				o.Expect(strings.Contains(apbExtRouteMsgs, node+": configured external gateway IPs: "+apbExternalRoute.ip1+","+apbExternalRoute.ip2)).Should(o.BeTrue())
				o.Expect(strings.Contains(egressFWMsgs, node+": EgressFirewall Rules applied")).Should(o.BeTrue())
			}
		}

		compat_otp.By("5. Wait for the rebooted worker node back")
		checkNodeStatus(oc, workerNode, "Ready")

		compat_otp.By("6. Check status of apbexternalroute/egressfirewall object after the rebooted worker node back")
		apbExtRouteCheckErr := checkAPBExternalRouteStatus(oc, apbExternalRoute.name, "Success")
		compat_otp.AssertWaitPollNoErr(apbExtRouteCheckErr, fmt.Sprintf("apbexternalroute %s doesn't succeed in time", apbExternalRoute.name))
		apbExtRouteMsgs2, apbExtRouteMsgsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.name, `-ojsonpath={.status.messages}`).Output()
		o.Expect(apbExtRouteMsgsErr2).NotTo(o.HaveOccurred())
		egressFWCheckErr := checkEgressFWStatus(oc, egressFW.name, ns, "EgressFirewall Rules applied")
		compat_otp.AssertWaitPollNoErr(egressFWCheckErr, fmt.Sprintf("EgressFirewall Rule %s doesn't apply in time", egressFW.name))
		egressFWMsgs2, egressFWMsgsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.name, "-n", egressFW.namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(egressFWMsgsErr2).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			o.Expect(strings.Contains(apbExtRouteMsgs2, node+": configured external gateway IPs: "+apbExternalRoute.ip1+","+apbExternalRoute.ip2)).Should(o.BeTrue())
			o.Expect(strings.Contains(egressFWMsgs2, node+": EgressFirewall Rules applied")).Should(o.BeTrue())
		}
	})

	g.It("Author:qiowang-Medium-69876-Check egressfirewall status when there is zone reported failure", func() {
		ipStackType := checkIPStackType(oc)
		var egressFWCIDR1, egressFWCIDR2 string
		if ipStackType == "dualstack" {
			egressFWCIDR1 = "1.1.1.1"
			egressFWCIDR2 = "2011::11"
		} else if ipStackType == "ipv6single" {
			egressFWCIDR1 = "2011::11"
			egressFWCIDR2 = "2012::11"
		} else {
			egressFWCIDR1 = "1.1.1.1"
			egressFWCIDR2 = "2.1.1.1"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")

		compat_otp.By("1. Create egressfirewall object which missing CIDR prefix")
		ns := oc.Namespace()
		egressFW := egressFirewall5{
			name:        "default",
			namespace:   ns,
			ruletype1:   "Allow",
			rulename1:   "cidrSelector",
			rulevalue1:  egressFWCIDR1,
			protocol1:   "TCP",
			portnumber1: 80,
			ruletype2:   "Allow",
			rulename2:   "cidrSelector",
			rulevalue2:  egressFWCIDR2,
			protocol2:   "TCP",
			portnumber2: 80,
			template:    egressFWTemplate,
		}
		defer removeResource(oc, true, true, "egressfirewall", egressFW.name, "-n", egressFW.namespace)
		egressFW.createEgressFW5Object(oc)

		compat_otp.By("2. Check status of egressfirewall object")
		checkErr := checkEgressFWStatus(oc, egressFW.name, ns, "EgressFirewall Rules not correctly applied")
		compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("EgressFirewall Rule %s doesn't show failure in time", egressFW.name))
		messages, messagesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.name, "-n", egressFW.namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(messagesErr).NotTo(o.HaveOccurred())
		nodes, getNodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			o.Expect(strings.Contains(messages, node+": EgressFirewall Rules not correctly applied")).Should(o.BeTrue())
		}
	})

	g.It("NonHyperShiftHOST-NonPreRelease-Author:qiowang-Medium-70011-Medium-70012-Check apbexternalroute/egressfirewall status when machine added/removed [Disruptive]", func() {
		clusterinfra.SkipConditionally(oc)
		nodes, getNodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())

		ipStackType := checkIPStackType(oc)
		var externalGWIP1, externalGWIP2, egressFWCIDR1, egressFWCIDR2 string
		if ipStackType == "dualstack" {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "2011::11"
			egressFWCIDR1 = "2.1.1.0/24"
			egressFWCIDR2 = "2021::/96"
		} else if ipStackType == "ipv6single" {
			externalGWIP1 = "2011::11"
			externalGWIP2 = "2011::12"
			egressFWCIDR1 = "2021::/96"
			egressFWCIDR2 = "2022::/96"
		} else {
			externalGWIP1 = "1.1.1.1"
			externalGWIP2 = "1.1.1.2"
			egressFWCIDR1 = "2.1.1.0/24"
			egressFWCIDR2 = "2.1.2.0/24"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		apbExternalRouteTemplate := filepath.Join(buildPruningBaseDir, "apbexternalroute-static-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")

		compat_otp.By("1. Create Admin Policy Based External route object with static gateway")
		ns := oc.Namespace()
		apbExternalRoute := apbStaticExternalRoute{
			name:       "externalgw-70011",
			labelkey:   "kubernetes.io/metadata.name",
			labelvalue: ns,
			ip1:        externalGWIP1,
			ip2:        externalGWIP2,
			bfd:        false,
			template:   apbExternalRouteTemplate,
		}
		defer apbExternalRoute.deleteAPBExternalRoute(oc)
		apbExternalRoute.createAPBExternalRoute(oc)

		compat_otp.By("2. Create egressfirewall object with allow rule")
		egressFW := egressFirewall5{
			name:        "default",
			namespace:   ns,
			ruletype1:   "Allow",
			rulename1:   "cidrSelector",
			rulevalue1:  egressFWCIDR1,
			protocol1:   "TCP",
			portnumber1: 80,
			ruletype2:   "Allow",
			rulename2:   "cidrSelector",
			rulevalue2:  egressFWCIDR2,
			protocol2:   "TCP",
			portnumber2: 80,
			template:    egressFWTemplate,
		}
		defer removeResource(oc, true, true, "egressfirewall", egressFW.name, "-n", egressFW.namespace)
		egressFW.createEgressFW5Object(oc)

		compat_otp.By("3. Check status of apbexternalroute/egressfirewall object")
		apbExtRouteCheckErr1 := checkAPBExternalRouteStatus(oc, apbExternalRoute.name, "Success")
		compat_otp.AssertWaitPollNoErr(apbExtRouteCheckErr1, fmt.Sprintf("apbexternalroute %s doesn't succeed in time", apbExternalRoute.name))
		apbExtRouteMsgs1, apbExtRouteMsgsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.name, `-ojsonpath={.status.messages}`).Output()
		o.Expect(apbExtRouteMsgsErr1).NotTo(o.HaveOccurred())
		egressFWCheckErr1 := checkEgressFWStatus(oc, egressFW.name, ns, "EgressFirewall Rules applied")
		compat_otp.AssertWaitPollNoErr(egressFWCheckErr1, fmt.Sprintf("EgressFirewall Rule %s doesn't apply in time", egressFW.name))
		egressFWMsgs1, egressFWMsgsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.name, "-n", egressFW.namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(egressFWMsgsErr1).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			o.Expect(strings.Contains(apbExtRouteMsgs1, node+": configured external gateway IPs: "+apbExternalRoute.ip1+","+apbExternalRoute.ip2)).Should(o.BeTrue())
			o.Expect(strings.Contains(egressFWMsgs1, node+": EgressFirewall Rules applied")).Should(o.BeTrue())
		}

		compat_otp.By("4. Add machine")
		infrastructureName := clusterinfra.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-70011"
		ms := clusterinfra.MachineSetDescription{Name: machinesetName, Replicas: 1}
		defer clusterinfra.WaitForMachinesDisapper(oc, machinesetName)
		defer ms.DeleteMachineSet(oc)
		ms.CreateMachineSet(oc)
		newNode := clusterinfra.GetNodeNameFromMachine(oc, clusterinfra.GetMachineNamesFromMachineSet(oc, machinesetName)[0])
		e2e.Logf("New node is:%s", newNode)

		compat_otp.By("5. Check status of apbexternalroute/egressfirewall object when new machine added")
		apbExtRouteCheckErr2 := checkAPBExternalRouteStatus(oc, apbExternalRoute.name, "Success")
		compat_otp.AssertWaitPollNoErr(apbExtRouteCheckErr2, fmt.Sprintf("apbexternalroute %s doesn't succeed in time", apbExternalRoute.name))
		apbExtRouteMsgs2, apbExtRouteMsgsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.name, `-ojsonpath={.status.messages}`).Output()
		o.Expect(apbExtRouteMsgsErr2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(apbExtRouteMsgs2, newNode+": configured external gateway IPs: "+apbExternalRoute.ip1+","+apbExternalRoute.ip2)).Should(o.BeTrue())
		egressFWCheckErr2 := checkEgressFWStatus(oc, egressFW.name, ns, "EgressFirewall Rules applied")
		compat_otp.AssertWaitPollNoErr(egressFWCheckErr2, fmt.Sprintf("EgressFirewall Rule %s doesn't apply in time", egressFW.name))
		egressFWMsgs2, egressFWMsgsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.name, "-n", egressFW.namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(egressFWMsgsErr2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(egressFWMsgs2, newNode+": EgressFirewall Rules applied")).Should(o.BeTrue())

		compat_otp.By("6. Remove machine")
		ms.DeleteMachineSet(oc)
		clusterinfra.WaitForMachinesDisapper(oc, machinesetName)

		compat_otp.By("7. Check status of apbexternalroute/egressfirewall object after machine removed")
		apbExtRouteCheckErr3 := checkAPBExternalRouteStatus(oc, apbExternalRoute.name, "Success")
		compat_otp.AssertWaitPollNoErr(apbExtRouteCheckErr3, fmt.Sprintf("apbexternalroute %s doesn't succeed in time", apbExternalRoute.name))
		apbExtRouteMsgs3, apbExtRouteMsgsErr3 := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", apbExternalRoute.name, `-ojsonpath={.status.messages}`).Output()
		o.Expect(apbExtRouteMsgsErr3).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(apbExtRouteMsgs3, newNode+": configured external gateway IPs: "+apbExternalRoute.ip1+","+apbExternalRoute.ip2)).ShouldNot(o.BeTrue())
		egressFWCheckErr3 := checkEgressFWStatus(oc, egressFW.name, ns, "EgressFirewall Rules applied")
		compat_otp.AssertWaitPollNoErr(egressFWCheckErr3, fmt.Sprintf("EgressFirewall Rule %s doesn't apply in time", egressFW.name))
		egressFWMsgs3, egressFWMsgsErr3 := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.name, "-n", egressFW.namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(egressFWMsgsErr3).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(egressFWMsgs3, newNode+": EgressFirewall Rules applied")).ShouldNot(o.BeTrue())
	})

	// author: jechen@redhat.com
	g.It("Longduration-NonPreRelease-Author:jechen-High-72028-Join switch IP and management port IP for newly added node should be synced correctly into NBDB, pod on new node can communicate with old pod on old node. [Disruptive]", func() {

		// This is for customer bug: https://issues.redhat.com/browse/OCPBUGS-28724

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		allowFromAllNSNetworkPolicyFile := filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-all-namespaces.yaml")

		clusterinfra.SkipConditionally(oc)

		compat_otp.By("1. Get an existing schedulable node\n")
		currentNodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		oldNode := currentNodeList.Items[0].Name

		compat_otp.By("2. Obtain the namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("3.Create a network policy in the namespace\n")
		createResourceFromFile(oc, ns1, allowFromAllNSNetworkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-from-all-namespaces"))

		compat_otp.By("4. Create a test pod on the namespace on the existing node\n")
		podOnOldNode := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  oldNode,
			template:  pingPodNodeTemplate,
		}
		podOnOldNode.createPingPodNode(oc)
		waitPodReady(oc, podOnOldNode.namespace, podOnOldNode.name)

		compat_otp.By("5. Create a new machineset, get the new node created\n")
		infrastructureName := clusterinfra.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-72028"
		ms := clusterinfra.MachineSetDescription{Name: machinesetName, Replicas: 1}
		defer clusterinfra.WaitForMachinesDisapper(oc, machinesetName)
		defer ms.DeleteMachineSet(oc)
		ms.CreateMachineSet(oc)

		clusterinfra.WaitForMachinesRunning(oc, 1, machinesetName)
		machineName := clusterinfra.GetMachineNamesFromMachineSet(oc, machinesetName)
		o.Expect(len(machineName)).ShouldNot(o.Equal(0))
		newNodeName := clusterinfra.GetNodeNameFromMachine(oc, machineName[0])
		e2e.Logf("Get new node name: %s", newNodeName)

		compat_otp.By("6. Create second namespace,create another test pod in it on the new node\n")
		oc.SetupProject()
		ns2 := oc.Namespace()

		podOnNewNode := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns2,
			nodename:  newNodeName,
			template:  pingPodNodeTemplate,
		}
		podOnNewNode.createPingPodNode(oc)
		waitPodReady(oc, podOnNewNode.namespace, podOnNewNode.name)

		compat_otp.By("7. Get management IP(s) and join switch IP(s) for the new node\n")
		ipStack := checkIPStackType(oc)
		var nodeOVNK8sMgmtIPv4, nodeOVNK8sMgmtIPv6 string
		if ipStack == "dualstack" || ipStack == "ipv6single" {
			nodeOVNK8sMgmtIPv6 = getOVNK8sNodeMgmtIPv6(oc, newNodeName)
		}
		if ipStack == "dualstack" || ipStack == "ipv4single" {
			nodeOVNK8sMgmtIPv4 = getOVNK8sNodeMgmtIPv4(oc, newNodeName)
		}
		e2e.Logf("\n ipStack type:  %s, nodeOVNK8sMgmtIPv4: %s, nodeOVNK8sMgmtIPv6: ---->%s<---- \n", ipStack, nodeOVNK8sMgmtIPv4, nodeOVNK8sMgmtIPv6)

		joinSwitchIPv4, joinSwitchIPv6 := getJoinSwitchIPofNode(oc, newNodeName)
		e2e.Logf("\n Got joinSwitchIPv4: %v, joinSwitchIPv6: %v\n", joinSwitchIPv4, joinSwitchIPv6)

		compat_otp.By("8. Check host network adresses in each node's northdb, it should include join switch IP and management IP of newly added node\n")
		allNodeList, nodeErr := compat_otp.GetAllNodes(oc)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(len(allNodeList)).NotTo(o.BeEquivalentTo(0))

		for _, eachNodeName := range allNodeList {
			ovnKubePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", eachNodeName)
			o.Expect(podErr).NotTo(o.HaveOccurred())
			o.Expect(ovnKubePod).ShouldNot(o.Equal(""))
			if ipStack == "dualstack" || ipStack == "ipv4single" {
				externalIDv4 := "external_ids:\\\"k8s.ovn.org/id\\\"=\\\"default-network-controller:Namespace:openshift-host-network:v4\\\""
				hostNetworkIPsv4 := getHostNetworkIPsinNBDB(oc, eachNodeName, externalIDv4)
				e2e.Logf("\n Got hostNetworkIPsv4 for node %s : %v\n", eachNodeName, hostNetworkIPsv4)
				o.Expect(contains(hostNetworkIPsv4, nodeOVNK8sMgmtIPv4)).Should(o.BeTrue(), fmt.Sprintf("New node's mgmt IPv4 is not updated to node %s in NBDB!", eachNodeName))
				o.Expect(unorderedContains(hostNetworkIPsv4, joinSwitchIPv4)).Should(o.BeTrue(), fmt.Sprintf("New node's join switch IPv4 is not updated to node %s in NBDB!", eachNodeName))
			}
			if ipStack == "dualstack" || ipStack == "ipv6single" {
				externalIDv6 := "external_ids:\\\"k8s.ovn.org/id\\\"=\\\"default-network-controller:Namespace:openshift-host-network:v6\\\""
				hostNetworkIPsv6 := getHostNetworkIPsinNBDB(oc, eachNodeName, externalIDv6)
				e2e.Logf("\n Got hostNetworkIPsv6 for node %s : %v\n", eachNodeName, hostNetworkIPsv6)
				o.Expect(contains(hostNetworkIPsv6, nodeOVNK8sMgmtIPv6)).Should(o.BeTrue(), fmt.Sprintf("New node's mgmt IPv6 is not updated to node %s in NBDB!", eachNodeName))
				o.Expect(unorderedContains(hostNetworkIPsv6, joinSwitchIPv6)).Should(o.BeTrue(), fmt.Sprintf("New node's join switch IPv6 is not updated to node %s in NBDB!", eachNodeName))
			}
		}

		compat_otp.By("9. Verify that new pod on new node can communicate with old pod on old node \n")
		CurlPod2PodPass(oc, podOnOldNode.namespace, podOnOldNode.name, podOnNewNode.namespace, podOnNewNode.name)
		CurlPod2PodPass(oc, podOnNewNode.namespace, podOnNewNode.name, podOnOldNode.namespace, podOnOldNode.name)
	})

	g.It("Author:qiowang-Medium-68920-[NETWORKCUSIM] kubernetes service route is recoverable if it's cleared [Disruptive]", func() {
		e2e.Logf("It is for OCPBUGS-1715")
		nodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "node-role.kubernetes.io/worker,kubernetes.io/os=linux", "-o", "jsonpath={.items[0].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Get service subnets")
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

			compat_otp.By("Delete service route on one of the worker node")
			origSvcRouteStr, getRouteErr := compat_otp.DebugNode(oc, nodeName, "ip", verFlag, "route", "show", svcSubnet)
			e2e.Logf("original service route is: -- %s --", origSvcRouteStr)
			o.Expect(getRouteErr).NotTo(o.HaveOccurred())
			re := regexp.MustCompile(svcSubnet + ".*\n")
			origSvcRouteLine := re.FindAllString(origSvcRouteStr, -1)[0]
			origSvcRoute := strings.Trim(origSvcRouteLine, "\n")
			defer func() {
				svcRoute1, deferErr := compat_otp.DebugNode(oc, nodeName, "ip", verFlag, "route", "show", svcSubnet)
				o.Expect(deferErr).NotTo(o.HaveOccurred())
				if !strings.Contains(svcRoute1, origSvcRoute) {
					addCmd := "ip " + verFlag + " route add " + origSvcRoute
					compat_otp.DebugNode(oc, nodeName, "bash", "-c", addCmd)
				}
			}()
			delCmd := "ip " + verFlag + " route del " + origSvcRoute
			_, delRouteErr := compat_otp.DebugNode(oc, nodeName, "bash", "-c", delCmd)
			o.Expect(delRouteErr).NotTo(o.HaveOccurred())

			compat_otp.By("Check the service route is restored")
			routeOutput := wait.Poll(15*time.Second, 300*time.Second, func() (bool, error) {
				svcRoute, getRouteErr1 := compat_otp.DebugNode(oc, nodeName, "ip", verFlag, "route", "show", svcSubnet)
				o.Expect(getRouteErr1).NotTo(o.HaveOccurred())
				if strings.Contains(svcRoute, origSvcRoute) {
					return true, nil
				}
				e2e.Logf("Route is not restored and try again")
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(routeOutput, fmt.Sprintf("Fail to restore route and the error is:%s", routeOutput))
		}
	})

	// author: anusaxen@redhat.com
	//bug: https://issues.redhat.com/browse/OCPBUGS-11266
	g.It("Author:anusaxen-Medium-66884-Larger packet size than Cluster MTU should not cause packet drops", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)
		platform := checkPlatform(oc)
		if !strings.Contains(platform, "aws") {
			g.Skip("Test requires AWS, skip for other platforms!")
		}

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		compat_otp.By("create a hello pod1 in namespace")
		pod1ns := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: oc.Namespace(),
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1ns.createPingPodNode(oc)
		waitPodReady(oc, pod1ns.namespace, pod1ns.name)

		compat_otp.By("create a hello-pod2 in namespace")
		pod2ns := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: oc.Namespace(),
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod2ns.createPingPodNode(oc)
		waitPodReady(oc, pod2ns.namespace, pod2ns.name)
		compat_otp.By("Get IP of the hello-pod2")
		helloPod2IP := getPodIPv4(oc, oc.Namespace(), "hello-pod2")

		//Cluster network MTU on AWS is 8901 and negotiated MSS is 8849 which accomodates TCP and IP header etc. We will use MSS of 9000 in this test
		iperfClientCmd := "iperf3 -c " + helloPod2IP + " -p 60001 -b 30M -N -V -M 9000|grep -i -A 5 'Test Complete' | grep -i -A 1 'Retr' | awk '{ print $9 }' | tail -1"
		iperfServerCmd := "nohup iperf3 -s -p 60001&"

		cmdBackground, _, _, errBackground := oc.Run("exec").Args("-n", pod2ns.namespace, pod2ns.name, "--", "/bin/sh", "-c", iperfServerCmd).Background()
		defer cmdBackground.Process.Kill()
		o.Expect(errBackground).NotTo(o.HaveOccurred())
		retr_count, err := oc.Run("exec").Args("-n", pod1ns.namespace, pod1ns.name, "--", "/bin/sh", "-c", iperfClientCmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf(fmt.Sprintf("Total Retr count is \n %s", retr_count))
		retr_count_int, err := strconv.Atoi(retr_count)
		o.Expect(err).NotTo(o.HaveOccurred())
		//iperf simulates 10 iterations with 30Mbps so we expect retr count of not more than 1 per iteration hence should not be more than 10 in total
		o.Expect(retr_count_int < 11).To(o.BeTrue())

	})

	//author: anusaxen@redhat.com
	g.It("Author:anusaxen-High-73205-High-72817-Make sure internalJoinSubnet and internalTransitSwitchSubnet is configurable post install as a Day 2 operation [Disruptive]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		)
		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		compat_otp.By("create a hello pod1 in namespace")
		pod1ns := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: oc.Namespace(),
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1ns.createPingPodNode(oc)
		waitPodReady(oc, oc.Namespace(), pod1ns.name)

		compat_otp.By("create a hello-pod2 in namespace")
		pod2ns := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: oc.Namespace(),
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod2ns.createPingPodNode(oc)
		waitPodReady(oc, oc.Namespace(), pod2ns.name)

		g.By("Create a test service backing up both the above pods")
		svc := genericServiceResource{
			servicename:           "test-service-73205",
			namespace:             oc.Namespace(),
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "",
			template:              genericServiceTemplate,
		}
		if ipStackType == "ipv4single" {
			svc.ipFamilyPolicy = "SingleStack"
		} else {
			svc.ipFamilyPolicy = "PreferDualStack"
		}
		svc.createServiceFromParams(oc)
		//custom patches to test depending on type of cluster addressing
		customPatchIPv4 := "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipv4\":{\"internalJoinSubnet\": \"100.99.0.0/16\",\"internalTransitSwitchSubnet\": \"100.69.0.0/16\"}}}}}"
		customPatchIPv6 := "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipv6\":{\"internalJoinSubnet\": \"ab98::/64\",\"internalTransitSwitchSubnet\": \"ab97::/64\"}}}}}"
		customPatchDualstack := "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipv4\":{\"internalJoinSubnet\": \"100.99.0.0/16\",\"internalTransitSwitchSubnet\": \"100.69.0.0/16\"},\"ipv6\": {\"internalJoinSubnet\": \"ab98::/64\",\"internalTransitSwitchSubnet\": \"ab97::/64\"}}}}}"

		//gather original cluster values so that we can defer to them later once test done
		currentinternalJoinSubnetIPv4Value, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("Network.operator.openshift.io/cluster", "-o=jsonpath={.items[*].spec.defaultNetwork.ovnKubernetesConfig.ipv4.internalJoinSubnet}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		currentinternalTransitSwSubnetIPv4Value, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("Network.operator.openshift.io/cluster", "-o=jsonpath={.items[*].spec.defaultNetwork.ovnKubernetesConfig.ipv4.internalTransitSwitchSubnet}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		currentinternalJoinSubnetIPv6Value, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("Network.operator.openshift.io/cluster", "-o=jsonpath={.items[*].spec.defaultNetwork.ovnKubernetesConfig.ipv6.internalJoinSubnet}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		currentinternalTransitSwSubnetIPv6Value, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("Network.operator.openshift.io/cluster", "-o=jsonpath={.items[*].spec.defaultNetwork.ovnKubernetesConfig.ipv6.internalTransitSwitchSubnet}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		//if any of value is null on exisiting cluster, it indicates that cluster came up with following default values assigned by OVNK
		if (currentinternalJoinSubnetIPv4Value == "") || (currentinternalJoinSubnetIPv6Value == "") {
			currentinternalJoinSubnetIPv4Value = "100.64.0.0/16"
			currentinternalTransitSwSubnetIPv4Value = "100.88.0.0/16"
			currentinternalJoinSubnetIPv6Value = "fd98::/64"
			currentinternalTransitSwSubnetIPv6Value = "fd97::/64"
		}

		//vars to patch cluster back to original state
		patchIPv4original := "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipv4\":{\"internalJoinSubnet\": \"" + currentinternalJoinSubnetIPv4Value + "\",\"internalTransitSwitchSubnet\": \"" + currentinternalTransitSwSubnetIPv4Value + "\"}}}}}"
		patchIPv6original := "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipv6\":{\"internalJoinSubnet\": \"" + currentinternalJoinSubnetIPv6Value + "\",\"internalTransitSwitchSubnet\": \"" + currentinternalTransitSwSubnetIPv6Value + "\"}}}}}"
		patchDualstackoriginal := "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipv4\":{\"internalJoinSubnet\": \"" + currentinternalJoinSubnetIPv4Value + "\",\"internalTransitSwitchSubnet\": \"" + currentinternalTransitSwSubnetIPv4Value + "\"},\"ipv6\": {\"internalJoinSubnet\": \"" + currentinternalJoinSubnetIPv6Value + "\",\"internalTransitSwitchSubnet\": \"" + currentinternalTransitSwSubnetIPv6Value + "\"}}}}}"

		if ipStackType == "ipv4single" {
			defer func() {
				patchResourceAsAdmin(oc, "Network.operator.openshift.io/cluster", patchIPv4original)
				err := checkOVNKState(oc)
				compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("OVNkube didn't trigger or rolled out successfully post oc patch"))
			}()
			patchResourceAsAdmin(oc, "Network.operator.openshift.io/cluster", customPatchIPv4)
		} else if ipStackType == "ipv6single" {
			defer func() {
				patchResourceAsAdmin(oc, "Network.operator.openshift.io/cluster", patchIPv6original)
				err := checkOVNKState(oc)
				compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("OVNkube didn't trigger or rolled out successfully post oc patch"))
			}()
			patchResourceAsAdmin(oc, "Network.operator.openshift.io/cluster", customPatchIPv6)
		} else {
			defer func() {
				patchResourceAsAdmin(oc, "Network.operator.openshift.io/cluster", patchDualstackoriginal)
				err := checkOVNKState(oc)
				compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("OVNkube didn't trigger or rolled out successfully post oc patch"))
			}()
			patchResourceAsAdmin(oc, "Network.operator.openshift.io/cluster", customPatchDualstack)
		}
		err = checkOVNKState(oc)
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("OVNkube never trigger or rolled out successfully post oc patch"))
		//check usual svc and pod connectivities post migration which also ensures disruption doesn't last post successful rollout
		CurlPod2PodPass(oc, oc.Namespace(), pod1ns.name, oc.Namespace(), pod2ns.name)
		CurlPod2SvcPass(oc, oc.Namespace(), oc.Namespace(), pod1ns.name, "test-service-73205")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-High-74589-[NETWORKCUSIM] Pod-to-external TCP connectivity using port in range of snat port.", func() {

		// For customer bug https://issues.redhat.com/browse/OCPBUGS-32202

		buildPruningBaseDir := testdata.FixturePath("networking")
		genericServiceTemplate := filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
		testPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		url := "www.example.com"

		ipStackType := checkIPStackType(oc)
		if checkDisconnect(oc) || ipStackType == "ipv6single" {
			g.Skip("Skip the test on disconnected cluster or singlev6 cluster.")
		}

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough node available, need at least one node for the test, skip the case!!")
		}

		compat_otp.By("1. create a namespace, create nodeport service on one node")
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("2. Create a hello pod in ns")
		pod1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			template:  testPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("3. Create a nodePort type service fronting the above pod")
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
		compat_otp.By("4. Get NodePort at which service listens.")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.servicename, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("5. From external, curl NodePort service with its port to make sure NodePort service works")
		CurlNodePortPass(oc, nodeList.Items[1].Name, nodeList.Items[0].Name, nodePort)

		compat_otp.By("6. Create another test pod on another node, from the test pod to curl local port of external url, verify the connection can succeed\n")
		pod2 := pingPodResourceNode{
			name:      "testpod",
			namespace: ns,
			nodename:  nodeList.Items[1].Name,
			template:  testPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, ns, pod2.name)

		cmd := fmt.Sprintf("curl --local-port 32012 -v -I -L http://%s", url)
		expectedString := fmt.Sprintf(`^* Connected to %s \(([\d\.]+)\) port 80 `, url)
		re := regexp.MustCompile(expectedString)
		connectErr := wait.Poll(3*time.Second, 15*time.Second, func() (bool, error) {
			_, execCmdOutput, err := e2eoutput.RunHostCmdWithFullOutput(ns, pod2.name, cmd)
			if err != nil {
				e2e.Logf("Getting err :%v, trying again...", err)
				return false, nil
			}
			if !re.MatchString(execCmdOutput) {
				e2e.Logf("Did not get expected output, trying again...")
				e2e.Logf("\n execCmdOutput is %v\n", execCmdOutput)
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(connectErr, fmt.Sprintf("Connection to %s did not succeed!", url))
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-75613-[NETWORKCUSIM] Should be able to access applications when client ephemeral port is 22623 or 22624", func() {
		// https://issues.redhat.com/browse/OCPBUGS-37541
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
		)
		g.By("Get new namespace")
		ns1 := oc.Namespace()

		g.By("Create test pods")
		createResourceFromFile(oc, ns1, testPodFile)
		err := waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		g.By("Should be able to access applications when client ephemeral port is 22623 or 22624")
		testPodName := getPodName(oc, ns1, "name=test-pods")
		pod1Name := testPodName[0]
		localPort := []string{"22623", "22624"}

		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			pod2IP1, pod2IP2 := getPodIP(oc, ns1, testPodName[1])
			for i := 0; i < 2; i++ {
				curlCmd := fmt.Sprintf("curl --connect-timeout 5 -s %s --local-port %s", net.JoinHostPort(pod2IP1, "8080"), localPort[i])
				_, err := e2eoutput.RunHostCmdWithRetries(ns1, pod1Name, curlCmd, 60*time.Second, 120*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())
				curlCmd = fmt.Sprintf("curl --connect-timeout 5 -s %s --local-port %s", net.JoinHostPort(pod2IP2, "8080"), localPort[i])
				// Need wait 1 minute for local binding port released
				_, err = e2eoutput.RunHostCmdWithRetries(ns1, pod1Name, curlCmd, 60*time.Second, 120*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		} else {
			pod2IP1, _ := getPodIP(oc, ns1, testPodName[1])
			for i := 0; i < 2; i++ {
				curlCmd := fmt.Sprintf("curl --connect-timeout 5 -s %s --local-port %s", net.JoinHostPort(pod2IP1, "8080"), localPort[i])
				_, err := e2eoutput.RunHostCmdWithRetries(ns1, pod1Name, curlCmd, 60*time.Second, 120*time.Second)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-75758-[NETWORKCUSIM] Bad certificate should not cause ovn pods crash. [Disruptive]", func() {
		// https://issues.redhat.com/browse/OCPBUGS-36195

		compat_otp.By("Get one worker node.")
		node1, err := compat_otp.GetFirstCoreOsWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(node1) < 1 {
			g.Skip("Skip the test as no enough worker nodes.")
		}

		compat_otp.By("Get the ovnkube-node pod on specific node.")
		ovnPod, err := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", node1)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(ovnPod).ShouldNot(o.BeEmpty())

		compat_otp.By("Create bad ovnkube-node-certs certificate")
		cmd := `cd /var/lib/ovn-ic/etc/ovnkube-node-certs && ls | grep '^ovnkube-client-.*\.pem$' | grep -v 'ovnkube-client-current.pem' | xargs -I {} sh -c 'echo "" > {}'`
		_, err = compat_otp.DebugNodeWithChroot(oc, node1, "bash", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Restart ovnkube-node pod on specific node.")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnPod, "-n", "openshift-ovn-kubernetes", "--ignore-not-found=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Wait ovnkube-node pod to be running")
		ovnPod, err = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", node1)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(ovnPod).ShouldNot(o.BeEmpty())
		compat_otp.AssertPodToBeReady(oc, ovnPod, "openshift-ovn-kubernetes")
	})

	// author: meinli@redhat.com
	g.It("Author:meinli-Medium-45146-[NETWORKCUSIM] Pod should be healthy when gw IP is single stack on dual stack cluster", func() {
		// https://bugzilla.redhat.com/show_bug.cgi?id=1986708
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)
		ipStackType := checkIPStackType(oc)
		if ipStackType != "dualstack" {
			g.Skip("This case is only validate in DualStack cluster, skip it!!!")
		}
		compat_otp.By("1. Get namespace")
		ns := oc.Namespace()

		compat_otp.By("2. Create a pod in ns namespace")
		pod := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod.name, "-n", pod.namespace).Execute()
			}
		}()
		pod.createPingPod(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		compat_otp.By("3. Patch annotation for hello-pod")
		annotationsCmd := fmt.Sprintf(`{ "metadata":{
			"annotations": {
			  "k8s.ovn.org/routing-namespaces": "%s",
			  "k8s.ovn.org/routing-network": "foo",
			  "k8s.v1.cni.cncf.io/network-status": "[{\"name\":\"foo\",\"interface\":\"net1\",\"ips\":[\"172.19.0.5\"],\"mac\":\"01:23:45:67:89:10\"}]"
			}
		  }
		}`, ns)
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("pod", pod.name, "-n", ns, "-p", annotationsCmd, "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Verify pod is healthy and running")
		waitPodReady(oc, ns, pod.name)
	})

	// author: meinli@redhat.com
	g.It("Author:meinli-NonPreRelease-Medium-34674-Ensure ovnkube-master nbdb and sbdb exit properly. [Disruptive]", func() {
		compat_otp.By("1. Enable ovnkube-master pod debug log by ovn-appctl")
		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		o.Expect(ovnMasterPodName).NotTo(o.BeEmpty())
		MasterNodeName, err := compat_otp.GetPodNodeName(oc, "openshift-ovn-kubernetes", ovnMasterPodName)
		o.Expect(err).NotTo(o.HaveOccurred())

		ctls := []string{"ovnnb_db.ctl", "ovnsb_db.ctl"}
		for _, ctl := range ctls {
			dbgCmd := fmt.Sprintf("ovn-appctl -t /var/run/ovn/%s vlog/set console:jsonrpc:dbg", ctl)
			_, err := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, dbgCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("2. Check ovnkube-master pod debug log enabled successfully and make hard-link(ln) to preserve log")
		LogsPath := "/var/log/pods/openshift-ovn-kubernetes_ovnkube-node-*"
		var wg sync.WaitGroup
		Database := []string{"nbdb", "sbdb"}
		for _, db := range Database {
			wg.Add(1)
			go func() {
				defer g.GinkgoRecover()
				defer wg.Done()
				logPath := filepath.Join(LogsPath, db, "*.log")
				checkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, false, func(cxt context.Context) (bool, error) {
					resultOutput, err := compat_otp.DebugNodeWithChroot(oc, MasterNodeName, "/bin/bash", "-c", fmt.Sprintf("tail -10 %s", logPath))
					o.Expect(err).NotTo(o.HaveOccurred())
					if strings.Contains(resultOutput, "jsonrpc") {
						e2e.Logf("ovnkube-pod debug log has been successfully enabled!!!")
						// select the most recent file to do hard-link
						_, lnErr := compat_otp.DebugNodeWithChroot(oc, MasterNodeName, "/bin/bash", "-c", fmt.Sprintf("ln -v $(ls -1t %s | head -n 1) /var/log/%s.log", logPath, db))
						o.Expect(lnErr).NotTo(o.HaveOccurred())
						return true, nil
					}
					e2e.Logf("%v,Waiting for ovnkube-master pod debug log enable, try again ...,", err)
					return false, nil
				})
				compat_otp.AssertWaitPollNoErr(checkErr, "Enable ovnkube-master pod debug log timeout.")
			}()
		}
		wg.Wait()

		compat_otp.By("3. delete the ovnkube-master pod and check log process should be exited")
		defer checkOVNKState(oc)
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnMasterPodName, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, db := range Database {
			wg.Add(1)
			go func() {
				defer g.GinkgoRecover()
				defer wg.Done()
				defer compat_otp.DebugNodeWithChroot(oc, MasterNodeName, "/bin/bash", "-c", fmt.Sprintf("rm -f /var/log/%s.log", db))
				checkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, false, func(cxt context.Context) (bool, error) {
					output, err := compat_otp.DebugNodeWithChroot(oc, MasterNodeName, "/bin/bash", "-c", fmt.Sprintf("tail -10 /var/log/%s.log", db))
					o.Expect(err).NotTo(o.HaveOccurred())
					if strings.Contains(output, fmt.Sprintf("Exiting ovn%s_db", strings.Split(db, "db")[0])) {
						e2e.Logf(fmt.Sprintf("ovnkube-master pod %s exit properly!!!", db))
						return true, nil
					}
					e2e.Logf("%v,Waiting for ovnkube-master pod log sync up, try again ...,", err)
					return false, nil
				})
				compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Check ovnkube-master pod %s debug log timeout.", db))
			}()
		}
		wg.Wait()
	})

	// author: meinli@redhat.com
	g.It("Author:meinli-Medium-72506-Traffic with dst ip from service CIDR that doesn't match existing svc ip+port should be dropped", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testSvcFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
		)

		compat_otp.By("1. Get namespace and worker node")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("This case requires one node, but the cluster han't one")
		}
		workerNode := nodeList.Items[0].Name
		ns := oc.Namespace()

		compat_otp.By("2. create a service")
		createResourceFromFile(oc, ns, testSvcFile)
		ServiceOutput, serviceErr := oc.WithoutNamespace().Run("get").Args("service", "-n", ns).Output()
		o.Expect(serviceErr).NotTo(o.HaveOccurred())
		o.Expect(ServiceOutput).To(o.ContainSubstring("test-service"))

		compat_otp.By("3. Curl clusterIP svc from node")
		svcIP1, svcIP2 := getSvcIP(oc, ns, "test-service")
		if svcIP2 != "" {
			svc4URL := net.JoinHostPort(svcIP2, "27018")
			output, _ := compat_otp.DebugNode(oc, workerNode, "curl", svc4URL, "--connect-timeout", "5")
			o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("Failed")))
		}
		svcURL := net.JoinHostPort(svcIP1, "27018")
		output, _ := compat_otp.DebugNode(oc, workerNode, "curl", svcURL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("Failed")))

		compat_otp.By("4. Validate the drop packets counter is increasing from svc network")
		ovnkubePodName, err := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", workerNode)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmd := "ovs-ofctl dump-flows br-ex | grep -i 'priority=115'"
		output, err = e2eoutput.RunHostCmd("openshift-ovn-kubernetes", ovnkubePodName, cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		r := regexp.MustCompile(`n_packets=(\d+).*?actions=drop`)
		matches := r.FindAllStringSubmatch(output, -1)
		// only compare the latest action drop to make sure won't be influenced by other case
		o.Expect(len(matches)).ShouldNot(o.Equal(0))
		o.Expect(strconv.Atoi(matches[len(matches)-1][1])).To(o.BeNumerically(">", 0))

		compat_otp.By("5. Validate no packet are seen on br-ex from src")
		if svcIP2 != "" {
			output, err := e2eoutput.RunHostCmd("openshift-ovn-kubernetes", ovnkubePodName, fmt.Sprintf("ovs-ofctl dump-flows br-ex | grep -i 'src=%s'", svcIP2))
			o.Expect(err).To(o.HaveOccurred())
			o.Expect(output).To(o.BeEmpty())
		}
		output, err = e2eoutput.RunHostCmd("openshift-ovn-kubernetes", ovnkubePodName, fmt.Sprintf("ovs-ofctl dump-flows br-ex | grep -i 'src=%s'", svcIP1))
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(output).To(o.BeEmpty())
	})

	g.It("Author:qiowang-High-48945-network should recover after NetworkManager restart on host [Disruptive]", func() {
		//Bug: https://bugzilla.redhat.com/show_bug.cgi?id=2048352
		nodeList, getNodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		if len(nodeList) < 1 {
			g.Skip("Not enough node for the test, skip it!!")
		}

		compat_otp.By("1. restart NetworkManager on host")
		nodeName := nodeList[0]
		nodeIP1, nodeIP2 := getNodeIP(oc, nodeName)
		_, cmdErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "systemctl", "restart", "NetworkManager")
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		defer func() {
			e2e.Logf("restart ovnkube-node pod to recover the masquerade ip")
			podName, getPodNameErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
			o.Expect(getPodNameErr).NotTo(o.HaveOccurred())
			delPodErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", podName, "-n", "openshift-ovn-kubernetes", "--ignore-not-found=true").Execute()
			o.Expect(delPodErr).NotTo(o.HaveOccurred())
			podName, getPodNameErr = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
			o.Expect(getPodNameErr).NotTo(o.HaveOccurred())
			waitPodReady(oc, "openshift-ovn-kubernetes", podName)
		}()

		compat_otp.By("2. check network, should recover after NetworkManager restart")
		checkNodeStatus(oc, nodeName, "Ready")
		ovnErr := waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		o.Expect(ovnErr).NotTo(o.HaveOccurred())
		ifaceConf, ifaceErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "ip", "address", "show", "br-ex")
		o.Expect(ifaceErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceConf, nodeIP2)).Should(o.BeTrue())
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			o.Expect(strings.Contains(ifaceConf, nodeIP1)).Should(o.BeTrue())
		}
	})

	g.It("Author:anusaxen-Critical-80439-[NETWORKCUSIM] pod to external traffic doesn't require OVN to create mac-binding entry for Join subnet gateway IP [Disruptive]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)
		var macUUIDCmdOutput, uuid, joinSubGWIP string

		ipStackType := checkIPStackType(oc)
		if ipStackType != "ipv4single" {
			g.Skip("The is supported on IPv4 cluster only, skip for other IP stack type for now")
		}
		joinSubGWIP = "100.64.0.1"
		workerNode, err := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Create pod on one worker node")
		ns := oc.Namespace()
		pod := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns,
			nodename:  workerNode,
			template:  pingPodNodeTemplate,
		}
		defer pod.deletePingPodNode(oc)
		pod.createPingPodNode(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		//check pod to external tarffic to make sure before proceeding
		curlPod2ExternalPass(oc, ns, "hello-pod")

		ovnKubeNodePod := ovnkubeNodePod(oc, workerNode)
		//note: under "ovn-nbctl find Logical_Router name=GR_xx", dynamic_neigh_routers="false" is default setting
		setLogicalRouterFlagCmd := fmt.Sprintf("ovn-nbctl set logical_router GR_%s options:dynamic_neigh_routers=true", workerNode)
		_, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, setLogicalRouterFlagCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			setLogicalRouterFlagCmd = fmt.Sprintf("ovn-nbctl set logical_router GR_%s options:dynamic_neigh_routers=false", workerNode)
			_, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, setLogicalRouterFlagCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}()
		//this pod's external traffic should generate an RTOJ entry that corresponds to the gateway IP of 100.64.0.1/fd98::1 in the SBDB, provided that the dynamic_neigh_router option is enabled.
		curlPod2ExternalPass(oc, ns, "hello-pod")

		macBindingCmd := fmt.Sprintf("ovn-sbctl find mac_binding")
		macBindCmdOutput, err := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, macBindingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(macBindCmdOutput, joinSubGWIP)).Should(o.BeTrue())

		//change dynamic_neigh_router flag to false
		setLogicalRouterFlagCmd = fmt.Sprintf("ovn-nbctl set logical_router GR_%s options:dynamic_neigh_routers=false", workerNode)
		_, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, setLogicalRouterFlagCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		//delete rtoj entry corresponding to Join subnet gateway IP
		findMacBindingUUIDCmd := fmt.Sprintf("ovn-sbctl --format=table --no-heading --columns=_UUID find mac_binding ip=%s", joinSubGWIP)
		macUUIDCmdOutput, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, findMacBindingUUIDCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		//ignoring the Defaulted container stdouts from bash
		macUUIDCmdOutputline := strings.Split(macUUIDCmdOutput, "\n")
		if len(macUUIDCmdOutputline) >= 2 {
			uuid = macUUIDCmdOutputline[1]
			o.Expect(uuid).NotTo(o.BeEmpty())
			e2e.Logf("mac-binding entry UUID is %s", uuid)
		}

		destroyMacBindingCmd := fmt.Sprintf("ovn-sbctl --no-leader-only destroy mac_binding %s", uuid)
		_, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, destroyMacBindingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		//ensure external ping traffic continues to function, while also preventing the recreation of the entry.
		//additionally, it is important to ensure that OVN consistently recognizes the MAC address of the cluster router port without requiring MAC binding entries.
		curlPod2ExternalPass(oc, ns, "hello-pod")
		macBindCmdOutput, err = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, macBindingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(macBindCmdOutput, joinSubGWIP)).ShouldNot(o.BeTrue())
	})
})
