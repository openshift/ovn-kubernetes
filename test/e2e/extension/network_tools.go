package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	netutils "k8s.io/utils/net"
)

var _ = g.Describe("[OTP][sig-networking] SDN network-tools ovnkube-trace", func() {
	defer g.GinkgoRecover()

	var (
		oc               = compat_otp.NewCLI("networking-tools", compat_otp.KubeConfigPath())
		expPod2PodResult = []string{"ovn-trace source pod to destination pod indicates success",
			"ovn-trace destination pod to source pod indicates success",
			"ovs-appctl ofproto/trace source pod to destination pod indicates success",
			"ovs-appctl ofproto/trace destination pod to source pod indicates success",
			"ovn-detrace source pod to destination pod indicates success",
			"ovn-detrace destination pod to source pod indicates success"}
		expPod2PodRemoteResult = []string{"ovn-trace (remote) source pod to destination pod indicates success",
			"ovn-trace (remote) destination pod to source pod indicates success"}
		expPod2SvcResult = []string{"ovn-trace source pod to service clusterIP indicates success"}
		expPod2IPResult  = []string{"ovn-trace from pod to IP indicates success",
			"ovs-appctl ofproto/trace pod to IP indicates success",
			"ovn-detrace pod to external IP indicates success"}
		image = "openshift/network-tools:latest"
	)

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	// author: qiowang@redhat.com
	g.It("Author:qiowang-Medium-67625-Medium-67648-Check ovnkube-trace - pod2pod traffic and pod2hostnetworkpod traffic", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			hostNetworkPodTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-hostnetwork-specific-node-template.yaml")
		)
		nodeList, getNodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough nodes available for the test, skip the case!!")
		}
		workerNode1 := nodeList.Items[0].Name
		workerNode2 := nodeList.Items[1].Name
		tmpPath := "/tmp/ocp-67625-67648"
		defer os.RemoveAll(tmpPath)

		compat_otp.By("1. Create hello-pod1, pod located on the first node")
		ns := oc.Namespace()
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns,
			nodename:  workerNode1,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("2. Create hello-pod2 and hostnetwork hostnetwork-hello-pod2, pod located on the first node")
		//Required for hostnetwork pod
		compat_otp.By("Set namespace as privileged for Hostnetworked Pods")
		compat_otp.SetNamespacePrivileged(oc, ns)
		pod2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns,
			nodename:  workerNode1,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, pod2.namespace, pod2.name)
		hostnetworkPod2 := pingPodResourceNode{
			name:      "hostnetwork-hello-pod2",
			namespace: ns,
			nodename:  workerNode1,
			template:  hostNetworkPodTemplate,
		}
		hostnetworkPod2.createPingPodNode(oc)
		waitPodReady(oc, hostnetworkPod2.namespace, hostnetworkPod2.name)

		compat_otp.By("3. Create hello-pod3 and hostnetwork hostnetwork-hello-pod3, pod located on the second node")
		pod3 := pingPodResourceNode{
			name:      "hello-pod3",
			namespace: ns,
			nodename:  workerNode2,
			template:  pingPodNodeTemplate,
		}
		pod3.createPingPodNode(oc)
		waitPodReady(oc, pod3.namespace, pod3.name)
		hostnetworkPod3 := pingPodResourceNode{
			name:      "hostnetwork-hello-pod3",
			namespace: ns,
			nodename:  workerNode2,
			template:  hostNetworkPodTemplate,
		}
		hostnetworkPod3.createPingPodNode(oc)
		waitPodReady(oc, hostnetworkPod3.namespace, hostnetworkPod3.name)

		compat_otp.By("4. Simulate traffic between pod and pod when they land on the same node")
		podIP1 := getPodIPv4(oc, ns, pod1.name)
		addrFamily := "ip4"
		if netutils.IsIPv6String(podIP1) {
			addrFamily = "ip6"
		}
		cmd := "ovnkube-trace -src-namespace " + ns + " -src " + pod1.name + " -dst-namespace " + ns + " -dst " + pod2.name + " -tcp -addr-family " + addrFamily
		traceOutput, cmdErr := collectMustGather(oc, tmpPath, image, []string{cmd})
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		for _, expResult := range expPod2PodResult {
			o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
		}

		compat_otp.By("5. Simulate traffic between pod and pod when they land on different nodes")
		cmd = "ovnkube-trace -src-namespace " + ns + " -src " + pod1.name + " -dst-namespace " + ns + " -dst " + pod3.name + " -tcp -addr-family " + addrFamily
		traceOutput, cmdErr = collectMustGather(oc, tmpPath, image, []string{cmd})
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		for _, expResult := range expPod2PodResult {
			o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
		}
		for _, expResult := range expPod2PodRemoteResult {
			o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
		}

		compat_otp.By("6. Simulate traffic between pod and hostnetwork pod when they land on the same node")
		cmd = "ovnkube-trace -src-namespace " + ns + " -src " + pod1.name + " -dst-namespace " + ns + " -dst " + hostnetworkPod2.name + " -udp -addr-family " + addrFamily
		traceOutput, cmdErr = collectMustGather(oc, tmpPath, image, []string{cmd})
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		for _, expResult := range expPod2PodResult {
			o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
		}

		compat_otp.By("7. Simulate traffic between pod and hostnetwork pod when they land on different nodes")
		cmd = "ovnkube-trace -src-namespace " + ns + " -src " + pod1.name + " -dst-namespace " + ns + " -dst " + hostnetworkPod3.name + " -udp -addr-family " + addrFamily
		traceOutput, cmdErr = collectMustGather(oc, tmpPath, image, []string{cmd})
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		for _, expResult := range expPod2PodResult {
			o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
		}
		o.Expect(strings.Contains(string(traceOutput), expPod2PodRemoteResult[1])).Should(o.BeTrue())
	})

	g.It("Author:qiowang-Medium-67649-Check ovnkube-trace - pod2service traffic", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)
		nodeList, getNodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Not enough nodes available for the test, skip the case!!")
		}
		tmpPath := "/tmp/ocp-67649"
		defer os.RemoveAll(tmpPath)

		compat_otp.By("1. Create hello-pod")
		ns := oc.Namespace()
		pod := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod.createPingPod(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		compat_otp.By("2. Simulate traffic between pod and service")
		podIP1 := getPodIPv4(oc, ns, pod.name)
		addrFamily := "ip4"
		if netutils.IsIPv6String(podIP1) {
			addrFamily = "ip6"
		}
		cmd := "ovnkube-trace -src-namespace " + ns + " -src " + pod.name + " -dst-namespace openshift-dns -service dns-default -tcp -addr-family " + addrFamily
		traceOutput, cmdErr := collectMustGather(oc, tmpPath, image, []string{cmd})
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		for _, expResult := range expPod2PodResult {
			o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
		}
		for _, expResult := range expPod2SvcResult {
			o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
		}
	})

	g.It("Author:qiowang-NonPreRelease-Medium-55180-Check ovnkube-trace - pod2external traffic [Disruptive]", func() {
		var (
			testScope           = []string{"without egressip", "with egressip"}
			egressNodeLabel     = "k8s.ovn.org/egress-assignable"
			externalIPv4        = "8.8.8.8"
			externalIPv6        = "2001:4860:4860::8888"
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIPTemplate    = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)
		nodeList, getNodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Not enough nodes available for the test, skip the case!!")
		}

		// check if the cluster supported for test steps related to egressip
		// focus on RDU dualstack/ipv6single cluster for ipv6 traffic, and other supported platforms for ipv4 traffic
		testList := []string{testScope[0]}
		addrFamily := "ip4"
		externalIP := externalIPv4
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" || ipStackType == "ipv6single" {
			addrFamily = "ip6"
			externalIP = externalIPv6
			msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
			if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com") || strings.Contains(msg, "offload.openshift-qe.sdn.com")) {
				e2e.Logf("Test steps related egressip will only run on rdu1 or rdu2 dualstack/ipv6single cluster, skip for other envrionment!!")
			} else {
				testList = append(testList, testScope[1])
			}
		} else {
			platform := compat_otp.CheckPlatform(oc)
			acceptedPlatform := strings.Contains(platform, "aws") || strings.Contains(platform, "gcp") || strings.Contains(platform, "openstack") || strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "azure") || strings.Contains(platform, "nutanix")
			if !acceptedPlatform {
				e2e.Logf("Test steps related egressip should be run on AWS/GCP/Azure/Openstack/Vsphere/BareMetal/Nutanix cluster, will skip for other platforms!!")
			} else {
				testList = append(testList, testScope[1])
			}
		}

		tmpPath := "/tmp/ocp-55180"
		defer os.RemoveAll(tmpPath)

		var nsList, podList []string
		for _, testItem := range testList {
			compat_otp.By("Verify pod2external traffic when the pod associate " + testItem)
			compat_otp.By("Create namespace")
			oc.SetupProject()
			ns := oc.Namespace()
			nsList = append(nsList, ns)

			if testItem == "with egressip" {
				compat_otp.By("Label namespace with name=test")
				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name-").Execute()
				nsLabelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name=test").Execute()
				o.Expect(nsLabelErr).NotTo(o.HaveOccurred())

				compat_otp.By("Label EgressIP node")
				egressNode := nodeList.Items[0].Name
				defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
				e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

				compat_otp.By("Create egressip object")
				var freeIPs []string
				if ipStackType == "dualstack" || ipStackType == "ipv6single" {
					freeIPs = findFreeIPv6s(oc, egressNode, 2)
				} else {
					freeIPs = findFreeIPs(oc, egressNode, 2)
				}
				o.Expect(len(freeIPs)).Should(o.Equal(2))
				egressip := egressIPResource1{
					name:      "egressip-55180",
					template:  egressIPTemplate,
					egressIP1: freeIPs[0],
					egressIP2: freeIPs[1],
				}
				defer egressip.deleteEgressIPObject1(oc)
				egressip.createEgressIPObject1(oc)
				egressIPMaps := getAssignedEIPInEIPObject(oc, egressip.name)
				o.Expect(len(egressIPMaps)).Should(o.Equal(1))
			}

			compat_otp.By("Create test pod in the namespace")
			pod := pingPodResource{
				name:      "hello-pod",
				namespace: ns,
				template:  pingPodTemplate,
			}
			pod.createPingPod(oc)
			waitPodReady(oc, pod.namespace, pod.name)
			podList = append(podList, pod.name)

			compat_otp.By("Simulate traffic between pod and external IP, pod associate " + testItem)
			cmd := "ovnkube-trace -src-namespace " + ns + " -src " + pod.name + " -dst-ip " + externalIP + " -tcp -addr-family " + addrFamily
			traceOutput, cmdErr := collectMustGather(oc, tmpPath, image, []string{cmd})
			o.Expect(cmdErr).NotTo(o.HaveOccurred())
			for _, expResult := range expPod2IPResult {
				o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
			}
		}

		compat_otp.By("Switch gateway mode")
		origMode := getOVNGatewayMode(oc)
		var desiredMode string
		if origMode == "local" {
			desiredMode = "shared"
		} else {
			desiredMode = "local"
		}
		e2e.Logf("Cluster is currently on gateway mode %s", origMode)
		e2e.Logf("Desired mode is %s", desiredMode)
		defer switchOVNGatewayMode(oc, origMode)
		switchOVNGatewayMode(oc, desiredMode)

		for i, testItem := range testList {
			compat_otp.By("Simulate traffic between pod and external IP, pod associate " + testItem)
			cmd := "ovnkube-trace -src-namespace " + nsList[i] + " -src " + podList[i] + " -dst-ip " + externalIP + " -tcp -addr-family " + addrFamily
			traceOutput, cmdErr := collectMustGather(oc, tmpPath, image, []string{cmd})
			o.Expect(cmdErr).NotTo(o.HaveOccurred())
			for _, expResult := range expPod2IPResult {
				o.Expect(strings.Contains(string(traceOutput), expResult)).Should(o.BeTrue())
			}
		}
	})
})

var _ = g.Describe("[OTP][sig-networking] SDN network-tools scripts", func() {
	defer g.GinkgoRecover()

	var (
		oc    = compat_otp.NewCLI("networking-tools", compat_otp.KubeConfigPath())
		image = "openshift/network-tools:latest"
	)

	g.It("Author:qiowang-NonHyperShiftHOST-Medium-55890-Verify functionality of network-tools script - ovn-get", func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
		scriptName := "ovn-get"

		compat_otp.By("1. Get ovn-k/nbdb/sbdb leaders with " + scriptName + " script")
		e2e.Logf("Get ovnk leader pod")
		ovnkLeader := getOVNKMasterPod(oc)
		mustgatherDir := "/tmp/must-gather-55890-1"
		defer os.RemoveAll(mustgatherDir)
		parameters := []string{"network-tools", scriptName, "leaders"}
		output, cmdErr := collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ovn-k master leader "+ovnkLeader)).Should(o.BeTrue())
		o.Expect(strings.Contains(output, "nbdb leader not applicable in ovn-ic mode")).Should(o.BeTrue())
		o.Expect(strings.Contains(output, "sbdb leader not applicable in ovn-ic mode")).Should(o.BeTrue())

		compat_otp.By("2. Download dbs with " + scriptName + " script")
		e2e.Logf("Get all ovnkube-node pods")
		ovnNodePods := getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		mustgatherDir = "/tmp/must-gather-55890-2"
		defer os.RemoveAll(mustgatherDir)
		parameters = []string{"network-tools", scriptName, "dbs"}
		_, cmdErr = collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		files, getFilesErr := exec.Command("bash", "-c", "ls -l "+mustgatherDir+"/*").Output()
		o.Expect(getFilesErr).NotTo(o.HaveOccurred())
		for _, podName := range ovnNodePods {
			o.Expect(strings.Contains(string(files), podName+"_nbdb")).Should(o.BeTrue())
			o.Expect(strings.Contains(string(files), podName+"_sbdb")).Should(o.BeTrue())
		}

		compat_otp.By("3. Get ovn cluster mode with " + scriptName + " script")
		mustgatherDir = "/tmp/must-gather-55890-3"
		defer os.RemoveAll(mustgatherDir)
		parameters = []string{"network-tools", scriptName, "mode"}
		output, cmdErr = collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "cluster is running in multi-zone (ovn-interconnect / ovn-ic)")).Should(o.BeTrue())
	})

	g.It("Author:qiowang-Medium-55889-Verify functionality of network-tools script - ovn-db-run-command", func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
		scriptName := "ovn-db-run-command"

		compat_otp.By("1. Run ovn-nbctl command with " + scriptName + " script")
		mustgatherDir := "/tmp/must-gather-55889-1"
		defer os.RemoveAll(mustgatherDir)
		parameters := []string{"network-tools", scriptName, "ovn-nbctl", "lr-list"}
		output, cmdErr := collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ovn_cluster_router")).Should(o.BeTrue())

		compat_otp.By("2. Run ovn-sbctl command with " + scriptName + " script")
		mustgatherDir = "/tmp/must-gather-55889-2"
		defer os.RemoveAll(mustgatherDir)
		parameters = []string{"network-tools", scriptName, "ovn-sbctl", "show"}
		output, cmdErr = collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "Port_Binding")).Should(o.BeTrue())

		compat_otp.By("3. Run ovndb command in specified pod with " + scriptName + " script")
		ovnNodePods := getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		nodeName, getNodeErr := compat_otp.GetPodNodeName(oc, "openshift-ovn-kubernetes", ovnNodePods[0])
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		mustgatherDir = "/tmp/must-gather-55889-3"
		defer os.RemoveAll(mustgatherDir)
		parameters = []string{"network-tools", scriptName, "-p", ovnNodePods[0], "ovn-nbctl", "lr-list"}
		output, cmdErr = collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "GR_"+nodeName)).Should(o.BeTrue())
	})

	g.It("Author:qiowang-Medium-55887-Verify functionality of network-tools script - pod-run-netns-command", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			scriptName          = "pod-run-netns-command"
		)
		nodeList, getNodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Not enough nodes available for the test, skip the case!!")
		}

		compat_otp.By("0. Create hello-pod")
		ns := oc.Namespace()
		pod := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod.createPingPod(oc)
		waitPodReady(oc, pod.namespace, pod.name)
		podIP := getPodIPv4(oc, ns, pod.name)

		compat_otp.By("1. Run multiple commands with " + scriptName + " script")
		mustgatherDir := "/tmp/must-gather-55887-1"
		defer os.RemoveAll(mustgatherDir)
		parameters := []string{"network-tools", scriptName, "--multiple-commands", pod.namespace, pod.name, "ip a show eth0; ip a show lo"}
		output, cmdErr := collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, podIP)).Should(o.BeTrue())
		o.Expect(strings.Contains(output, "127.0.0.1")).Should(o.BeTrue())

		compat_otp.By("2. Run command that needs to preserve the literal meaning of with " + scriptName + " script")
		mustgatherDir = "/tmp/must-gather-55887-2"
		defer os.RemoveAll(mustgatherDir)
		parameters = []string{"network-tools", scriptName, "--no-substitution", pod.namespace, pod.name, `'i=0; i=$(( $i + 1 )); echo result$i'`}
		output, cmdErr = collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "result1")).Should(o.BeTrue())

		compat_otp.By("3. Run command and save the debug pod for 5 minutes with " + scriptName + " script")
		mustgatherDir = "/tmp/must-gather-55887-3"
		defer os.RemoveAll(mustgatherDir)
		parameters = []string{"network-tools", scriptName, "--preserve-pod", pod.namespace, pod.name, "timeout 5 tcpdump"}
		output, cmdErr = collectMustGather(oc, mustgatherDir, image, parameters)
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "DONE")).Should(o.BeTrue())
	})
})
