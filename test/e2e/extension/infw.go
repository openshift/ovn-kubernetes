package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN infw", func() {
	defer g.GinkgoRecover()

	var (
		oc                       = compat_otp.NewCLI("networking-infw", compat_otp.KubeConfigPath())
		opNamespace              = "openshift-ingress-node-firewall"
		opName                   = "ingress-node-firewall"
		catalogNamespace         = "openshift-marketplace"
		catalogSourceName        = "ingress-node-firewall-operator-fbc-catalog"
		imageDigestMirrorSetName = "ingress-node-firewall-images-mirror-set"
		testDataDirMetallb       = testdata.FixturePath("networking/metallb")
		testDataDirInfw          = testdata.FixturePath("networking/ingressnodefirewall")
	)

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("This is required to run on OVNKubernetes Network Backened")
		}

		windowNodeList, err := compat_otp.GetAllNodesbyOSType(oc, "windows")
		o.Expect(err).NotTo(o.HaveOccurred())

		if len(windowNodeList) > 0 {
			g.Skip("INFW usecases are not compatible to run on Cluster with window nodes")
		}

		//leveraging few templates and utils from metallb code
		namespaceTemplate := filepath.Join(testDataDirMetallb, "namespace-template.yaml")
		operatorGroupTemplate := filepath.Join(testDataDirMetallb, "operatorgroup-template.yaml")
		subscriptionTemplate := filepath.Join(testDataDirMetallb, "subscription-template.yaml")
		catalogSourceTemplate := filepath.Join(testDataDirInfw, "catalogsource-template.yaml")
		imageDigestMirrorSetFile := filepath.Join(testDataDirInfw, "image-digest-mirrorset.yaml")
		sub := subscriptionResource{
			name:             "ingress-node-firewall-sub",
			namespace:        opNamespace,
			operatorName:     opName,
			catalog:          catalogSourceName,
			catalogNamespace: catalogNamespace,
			template:         subscriptionTemplate,
		}
		ns := namespaceResource{
			name:     opNamespace,
			template: namespaceTemplate,
		}
		og := operatorGroupResource{
			name:             opName,
			namespace:        opNamespace,
			targetNamespaces: opNamespace,
			template:         operatorGroupTemplate,
		}
		catalogSourceName = setupOperatorCatalogSource(oc, "ingress-node-firewall", catalogSourceName, imageDigestMirrorSetName, catalogNamespace, imageDigestMirrorSetFile, catalogSourceTemplate)
		sub.catalog = catalogSourceName
		operatorInstall(oc, sub, ns, og)
		g.By("Making sure CRDs are also installed")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ingressnodefirewallconfigs.ingressnodefirewall.openshift.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "ingressnodefirewallnodestates.ingressnodefirewall.openshift.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "ingressnodefirewalls.ingressnodefirewall.openshift.io")).To(o.BeTrue())
	})

	g.It("[Level0] Author:anusaxen-High-61481-StagerunBoth-Ingress Node Firewall Operator Installation ", func() {
		g.By("Checking Ingress Node Firewall operator and CRDs installation")
		e2e.Logf("Operator install and CRDs check successfull!")
		g.By("SUCCESS -  Ingress Node Firewall operator and CRDs installed")

	})

	g.It("Author:anusaxen-WRS-High-54714-V-BR.53-Check Ingress Firewall Allow/Deny functionality for TCP via Nodeport svc [Serial][Disruptive]", func() {
		var (
			buildPruningBaseDir           = testdata.FixturePath("networking")
			testDataDirInfw               = testdata.FixturePath("networking/ingressnodefirewall")
			pingPodNodeTemplate           = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate        = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			infwCRtemplate                = filepath.Join(testDataDirInfw, "infw.yaml")
			infwCR_multiple_cidr_template = filepath.Join(testDataDirInfw, "infw-multiple-cidr.yaml")
			infwCfgTemplate               = filepath.Join(testDataDirInfw, "infw-config.yaml")
		)
		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		platform := checkPlatform(oc)
		if strings.Contains(platform, "vsphere") || ipStackType == "dualstack" || ipStackType == "ipv6single" {
			g.By("Proceeding test on supported platform..")
		} else {
			g.Skip("Skip for un-expected platform, not vsphere or dualstack or ipv6single!")
		}
		g.By("Create a namespace for the scenario")
		g.By("Obtain the namespace")
		ns := oc.Namespace()

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("create a hello pod in ns")
		pod := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod.createPingPodNode(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		g.By("Create a test service backing up the above pod")
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
		//familyPolicy doesn't matter in this case
		if ipStackType == "dualstack" {
			svc.ipFamilyPolicy = "RequireDualStack"
		} else {
			svc.ipFamilyPolicy = "SingleStack"
		}
		svc.createServiceFromParams(oc)

		g.By("Get service NodePort and NodeIP value")
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, "test-service", "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		//we need a port range to evaluate rule properly, say if nodeport is 33000, we would try a range of 33000-33005 which port_range var will store
		var intvar int
		var end_range string
		intvar, parseIntErr := strconv.Atoi(nodePort)
		o.Expect(parseIntErr).NotTo(o.HaveOccurred())
		end_range = strconv.Itoa(intvar + 5)
		port_range := nodePort + "-" + end_range

		//Prior to creating blocking Ingress Node firewall for TCP nodeport svc, we will make sure that NodePort svc is accessible from another node (non pod node) say
		CurlNodePortPass(oc, nodeList.Items[1].Name, nodeList.Items[0].Name, nodePort)

		g.By("create Ingress node firewall config")
		infwCfg := infwConfigResource{
			namespace: "openshift-ingress-node-firewall",
			nodelabel: "node-role.kubernetes.io/worker",
			template:  infwCfgTemplate,
		}
		defer deleteinfwCfg(oc)
		infwCfg.createinfwConfig(oc)
		waitforInfwDaemonsready(oc)

		//get cluster default mgmt interface
		primaryInf := getPrimaryNICname(oc)
		//nodeIP1 and nodeIP2 will be IPv6 and IPv4 respectively in case of dual stack and IPv4/IPv6 in 2nd var case of single
		nodeIP1, nodeIP2 := getNodeIP(oc, nodeList.Items[1].Name)

		infwCR_multiple := infwCResource_multiple_cidr{
			name:          "infw-block-nport-tcp",
			primary_inf:   primaryInf,
			nodelabel:     "node-role.kubernetes.io/worker",
			src_cidr1:     "",
			src_cidr2:     "",
			protocoltype1: "tcp",
			protocol_1:    "TCP",
			range_1:       port_range,
			action_1:      "Deny",
			protocoltype2: "tcp",
			protocol_2:    "TCP",
			range_2:       port_range,
			action_2:      "Allow",
			template:      infwCR_multiple_cidr_template,
		}

		infwCR_single := infwCResource{
			name:          "infw-block-nport-tcp",
			primary_inf:   primaryInf,
			nodelabel:     "node-role.kubernetes.io/worker",
			src_cidr1:     "",
			protocol_1:    "TCP",
			protocoltype1: "tcp",
			range_1:       port_range,
			action_1:      "Deny",
			protocoltype2: "tcp",
			protocol_2:    "TCP",
			range_2:       port_range,
			action_2:      "Allow",
			template:      infwCRtemplate,
		}

		if ipStackType == "dualstack" {
			g.By("create infw CR with multiple cidrs containing both IPv4 and IPv6 addresses")
			g.By("create Ingress node firewall Rule for dual stack")
			infwCR_multiple.src_cidr1 = nodeIP1 + "/128"
			infwCR_multiple.src_cidr2 = nodeIP2 + "/32"
			defer deleteinfwCR(oc, infwCR_multiple.name)
			infwCR_multiple.createinfwCR_multiple_cidr(oc)
		} else {
			if ipStackType == "ipv6single" {
				infwCR_single.src_cidr1 = nodeIP2 + "/128"
				g.By("create Ingress node firewall Rule Custom Resource for IPv6 single stack")
			} else {
				infwCR_single.src_cidr1 = nodeIP2 + "/32"
				g.By("create Ingress node firewall Rule Custom Resource for IPv4 single stack")
			}
			defer deleteinfwCR(oc, infwCR_single.name)
			infwCR_single.createinfwCR(oc)
		}

		//based on above rule order 1 should execute and action deny should trigger so we expect CurlNodePortFail to execute sucessfully
		CurlNodePortFail(oc, nodeList.Items[1].Name, nodeList.Items[0].Name, nodePort)

		//make sure events were logged for Deny events
		infwDaemon := getinfwDaemonForNode(oc, nodeList.Items[0].Name)
		output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", "openshift-ingress-node-firewall", infwDaemon, "-c", "events").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ruleId 1 action Drop")).Should(o.BeTrue())

		//remove the previous rules to establish the new one, then restart the infw daemons to reset the previous statistics and redeploy infw rule
		deleteinfwCR(oc, "--all")
		restartInfwDaemons(oc)

		//Now make action 1 as Allow and make sure it pass
		infwCR_single.action_1 = "Allow"
		infwCR_multiple.action_1 = "Allow"
		if ipStackType == "dualstack" {
			infwCR_multiple.createinfwCR_multiple_cidr(oc)
		} else {
			infwCR_single.createinfwCR(oc)
		}
		CurlNodePortPass(oc, nodeList.Items[1].Name, nodeList.Items[0].Name, nodePort)

		//Delete  INFW components and wait for them to re-spawn and make sure CurlNodePortPass works again
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("deployment", "ingress-node-firewall-controller-manager", "-n", "openshift-ingress-node-firewall").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("ds", "ingress-node-firewall-daemon", "-n", "openshift-ingress-node-firewall").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		CurlNodePortPass(oc, nodeList.Items[1].Name, nodeList.Items[0].Name, nodePort)

	})

	g.It("Author:anusaxen-WRS-High-54992-V-BR.53-Check Ingress Firewall Allow/Deny functionality for UDP via Nodeport svc [Serial]", func() {
		var (
			buildPruningBaseDir           = testdata.FixturePath("networking")
			testDataDirInfw               = testdata.FixturePath("networking/ingressnodefirewall")
			udpListenerPod                = filepath.Join(buildPruningBaseDir, "udp-listener.yaml")
			infwCRtemplate                = filepath.Join(testDataDirInfw, "infw.yaml")
			infwCR_multiple_cidr_template = filepath.Join(testDataDirInfw, "infw-multiple-cidr.yaml")
			infwCfgTemplate               = filepath.Join(testDataDirInfw, "infw-config.yaml")
		)
		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		platform := checkPlatform(oc)
		if strings.Contains(platform, "vsphere") || ipStackType == "dualstack" || ipStackType == "ipv6single" {
			g.By("Proceeding test on supported platform..")
		} else {
			g.Skip("Skip for un-expected platform, not vsphere or dualstack or ipv6single!")
		}

		g.By("Create a namespace for the scenario")
		g.By("Obtain the namespace")
		ns := oc.Namespace()

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("create UDP Listener Pod")
		createResourceFromFile(oc, oc.Namespace(), udpListenerPod)
		err = waitForPodWithLabelReady(oc, oc.Namespace(), "name=udp-pod")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=udp-pod not ready")

		var udpPodName []string
		udpPodName = getPodName(oc, oc.Namespace(), "name=udp-pod")
		err = oc.AsAdmin().WithoutNamespace().Run("expose").Args("pod", udpPodName[0], "-n", ns, "--type=NodePort", "--port=8080", "--protocol=UDP").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		podNodeName, getNodeNameErr := compat_otp.GetPodNodeName(oc, ns, udpPodName[0])
		o.Expect(getNodeNameErr).NotTo(o.HaveOccurred())
		masterNode, getMasterNodeErr := compat_otp.GetFirstMasterNode(oc) //let say this would act as a source node to reach to that exposed UDP service
		o.Expect(getMasterNodeErr).NotTo(o.HaveOccurred())

		g.By("Get service NodePort and NodeIP value")
		//expose command will use same service name as pod name
		nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, udpPodName[0], "-o=jsonpath={.spec.ports[*].nodePort}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		//we need a port range to evaluate rule properly, say if nodeport is 33000, we would try a range of 33000-33005 which port_range var will store
		var intvar int
		var end_range string
		intvar, parseIntErr := strconv.Atoi(nodePort)
		o.Expect(parseIntErr).NotTo(o.HaveOccurred())
		end_range = strconv.Itoa(intvar + 5)
		port_range := nodePort + "-" + end_range

		g.By("create Ingress node firewall config")
		infwCfg := infwConfigResource{
			namespace: "openshift-ingress-node-firewall",
			nodelabel: "node-role.kubernetes.io/worker",
			template:  infwCfgTemplate,
		}
		defer deleteinfwCfg(oc)
		infwCfg.createinfwConfig(oc)
		waitforInfwDaemonsready(oc)

		//get cluster default mgmt interface
		primaryInf := getPrimaryNICname(oc)
		//nodeIP1 and nodeIP2 will be IPv6 and IPv4 respectively in case of dual stack and IPv4/IPv6 in 2nd var case of single. This is for src master node
		nodeIP1, nodeIP2 := getNodeIP(oc, masterNode)
		//nodeIP for podNode
		_, podNodeIP := getNodeIP(oc, podNodeName)

		infwCR_multiple := infwCResource_multiple_cidr{
			name:          "infw-block-nport-udp",
			primary_inf:   primaryInf,
			nodelabel:     "node-role.kubernetes.io/worker",
			src_cidr1:     "",
			src_cidr2:     "",
			protocoltype1: "udp",
			protocol_1:    "UDP",
			range_1:       port_range,
			action_1:      "Deny",
			protocoltype2: "udp",
			protocol_2:    "UDP",
			range_2:       port_range,
			action_2:      "Allow",
			template:      infwCR_multiple_cidr_template,
		}

		infwCR_single := infwCResource{
			name:          "infw-block-nport-udp",
			primary_inf:   primaryInf,
			nodelabel:     "node-role.kubernetes.io/worker",
			src_cidr1:     "",
			protocoltype1: "udp",
			protocol_1:    "UDP",
			range_1:       port_range,
			action_1:      "Deny",
			protocoltype2: "udp",
			protocol_2:    "UDP",
			range_2:       port_range,
			action_2:      "Allow",
			template:      infwCRtemplate,
		}

		if ipStackType == "dualstack" {
			g.By("create infw CR with multiple cidrs containing both IPv4 and IPv6 addresses")
			g.By("create Ingress node firewall Rule for dual stack")
			infwCR_multiple.src_cidr1 = nodeIP1 + "/128"
			infwCR_multiple.src_cidr2 = nodeIP2 + "/32"
			defer deleteinfwCR(oc, infwCR_multiple.name)
			infwCR_multiple.createinfwCR_multiple_cidr(oc)
		} else {
			if ipStackType == "ipv6single" {
				infwCR_single.src_cidr1 = nodeIP2 + "/128"
				g.By("create Ingress node firewall Rule Custom Resource for IPv6 single stack")
			} else {
				infwCR_single.src_cidr1 = nodeIP2 + "/32"
				g.By("create Ingress node firewall Rule Custom Resource for IPv4 single stack")
			}
			defer deleteinfwCR(oc, infwCR_single.name)
			infwCR_single.createinfwCR(oc)
		}

		g.By("send a hello message to udp listener from a master node to pod node")
		cmd := "echo -n hello >/dev/udp/" + podNodeIP + "/" + nodePort
		_, err = compat_otp.DebugNode(oc, masterNode, "bash", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		infwDaemon := getinfwDaemonForNode(oc, podNodeName)
		//Now confirm by looking into infw daemon stats for that podNode whether drop stats are present which confirms packets were denied from master node src
		output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", "openshift-ingress-node-firewall", infwDaemon, "-c", "events").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ruleId 1 action Drop")).Should(o.BeTrue())
		//Now make action 1 as Allow and make sure it pass

		infwCR_single.action_1 = "Allow"
		infwCR_multiple.action_1 = "Allow"

		//remove the previous rules to establish the new one, then restart the infw daemons to reset the previous statistics and redeploy infw rule
		deleteinfwCR(oc, "--all")
		restartInfwDaemons(oc)

		if ipStackType == "dualstack" {
			infwCR_multiple.createinfwCR_multiple_cidr(oc)
		} else {
			infwCR_single.createinfwCR(oc)
		}
		g.By("send a hello message to udp listener from a master node to pod node again")
		cmd = "echo -n hello >/dev/udp/" + podNodeIP + "/" + nodePort
		_, err = compat_otp.DebugNode(oc, masterNode, "bash", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		infwDaemon = getinfwDaemonForNode(oc, podNodeName)
		_, err = oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", "openshift-ingress-node-firewall", infwDaemon, "-c", "events").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

	})

	g.It("Author:anusaxen-ROSA-WRS-High-55411-V-BR.53-Check Ingress Firewall Allow/Deny functionality for ICMP [Serial]", func() {
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			testDataDirInfw        = testdata.FixturePath("networking/ingressnodefirewall")
			infwCR_ICMP_template   = filepath.Join(testDataDirInfw, "infw-icmp.yaml")
			infwCR_ICMPv6_template = filepath.Join(testDataDirInfw, "infw-icmpv6.yaml")
			infwCfgTemplate        = filepath.Join(testDataDirInfw, "infw-config.yaml")
			pingPodNodeTemplate    = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())
		if ipStackType == "dualstack" {
			g.Skip("This case requires single stack cluster")
		}

		g.By("Create first namespace")
		ns1 := oc.Namespace()

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}
		g.By("create a hello pod in first namespace")
		podns1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		podns1.createPingPodNode(oc)
		waitPodReady(oc, podns1.namespace, podns1.name)

		g.By("Create Second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()
		g.By("create a hello-pod on 2nd namesapce on different node")
		podns2 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns2,
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		podns2.createPingPodNode(oc)
		waitPodReady(oc, podns2.namespace, podns2.name)

		g.By("Get IP of the hello-pods")
		hellopodIPns1, _ := getPodIP(oc, ns1, podns1.name)
		hellopodIPns2, _ := getPodIP(oc, ns2, podns2.name)

		//OVN geneve interface name
		primaryInf := "genev_sys_6081"

		infwCR_icmp := infwCResource_icmp{
			name:        "infw-block-icmp",
			primary_inf: primaryInf,
			nodelabel:   "node-role.kubernetes.io/worker",
			src_cidr:    "",
			action_1:    "Deny",
			action_2:    "Allow",
			template:    infwCR_ICMP_template,
		}

		infwCR_icmpv6 := infwCResource_icmp{
			name:        "infw-block-icmpv6",
			primary_inf: primaryInf,
			nodelabel:   "node-role.kubernetes.io/worker",
			src_cidr:    "",
			action_1:    "Deny",
			action_2:    "Allow",
			template:    infwCR_ICMPv6_template,
		}

		g.By("create Ingress node firewall config")
		infwCfg := infwConfigResource{
			namespace: "openshift-ingress-node-firewall",
			nodelabel: "node-role.kubernetes.io/worker",
			template:  infwCfgTemplate,
		}
		defer deleteinfwCfg(oc)
		infwCfg.createinfwConfig(oc)
		waitforInfwDaemonsready(oc)

		var cmd []string
		pingCmdv4 := "ping -c4 " + hellopodIPns2
		pingCmdv6 := "ping6 -c4 " + hellopodIPns2

		if ipStackType == "ipv6single" {
			infwCR_icmpv6.src_cidr = hellopodIPns1 + "/128"
			g.By("create Ingress node firewall Rule Custom Resource for IPv6 single stack")
			defer deleteinfwCR(oc, infwCR_icmpv6.name)
			infwCR_icmpv6.createinfwICMP(oc)
			cmd = []string{"-n", ns1, podns1.name, "--", "/bin/sh", "-c", pingCmdv6}
		} else {
			infwCR_icmp.src_cidr = hellopodIPns1 + "/32"
			g.By("create Ingress node firewall Rule Custom Resource for IPv4 single stack")
			defer deleteinfwCR(oc, infwCR_icmp.name)
			infwCR_icmp.createinfwICMP(oc)
			cmd = []string{"-n", ns1, podns1.name, "--", "/bin/sh", "-c", pingCmdv4}
		}

		msg, _ := oc.WithoutNamespace().AsAdmin().Run("exec").Args(cmd...).Output()
		o.Expect(msg).To(o.ContainSubstring("100% packet loss"))

		//make sure events were logged for Deny events
		infwDaemon := getinfwDaemonForNode(oc, nodeList.Items[1].Name)
		output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", "openshift-ingress-node-firewall", infwDaemon, "-c", "events").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ruleId 1 action Drop")).Should(o.BeTrue())

		//remove the previous rules to establish the new one and redeploy infw rule in successive steps
		deleteinfwCR(oc, "--all")

		g.By("create infw CR for ICMP again with both Allow actions")
		if ipStackType == "ipv6single" {
			infwCR_icmpv6.action_1 = "Allow"
			infwCR_icmpv6.createinfwICMP(oc)
		} else {
			infwCR_icmp.action_1 = "Allow"
			infwCR_icmp.createinfwICMP(oc)
		}
		msg, _ = oc.WithoutNamespace().AsAdmin().Run("exec").Args(cmd...).Output()
		o.Expect(msg).NotTo(o.ContainSubstring("100% packet loss"))

	})

	g.It("Author:anusaxen-Longduration-NonPreRelease-WRS-High-55410-V-BR.53-Check Ingress Firewall Allow/Deny functionality for SCTP [Serial]", func() {
		var (
			buildPruningBaseDir           = testdata.FixturePath("networking/sctp")
			testDataDirInfw               = testdata.FixturePath("networking/ingressnodefirewall")
			infwCRtemplate                = filepath.Join(testDataDirInfw, "infw.yaml")
			infwCR_multiple_cidr_template = filepath.Join(testDataDirInfw, "infw-multiple-cidr.yaml")
			infwCfgTemplate               = filepath.Join(testDataDirInfw, "infw-config.yaml")
			sctpModule                    = filepath.Join(buildPruningBaseDir, "load-sctp-module.yaml")
			sctpServerPodName             = "sctpserver"
			sctpClientPodname             = "sctpclient"
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("install load-sctp-module in all workers")
		prepareSCTPModule(oc, sctpModule)

		g.By("create new namespace")
		oc.SetupProject()
		defer compat_otp.RecoverNamespaceRestricted(oc, oc.Namespace())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())

		client_pod_pmtrs := map[string]string{
			"$nodename":  nodeList.Items[0].Name,
			"$namespace": oc.Namespace(),
		}

		g.By("creating sctp client pod in namespace")
		createSCTPclientOnNode(oc, client_pod_pmtrs)
		err1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=sctpclient")
		compat_otp.AssertWaitPollNoErr(err1, "sctpClientPod is not running")

		server_pod_pmtrs := map[string]string{
			"$nodename":  nodeList.Items[1].Name,
			"$namespace": oc.Namespace(),
		}

		g.By("creating sctp server pod in namespace")
		createSCTPserverOnNode(oc, server_pod_pmtrs)
		err1 = waitForPodWithLabelReady(oc, oc.Namespace(), "name=sctpserver")
		compat_otp.AssertWaitPollNoErr(err1, "sctpServerPod is not running")

		//re-using SCTP testdata where nodePort value is hardcoded
		nodePort := "30102"

		//we need a port range to evaluate rule properly, say if nodeport is 33000, we would try a range of 33000-33005 which port_range var will store
		var intvar int
		var end_range string
		intvar, parseIntErr := strconv.Atoi(nodePort)
		o.Expect(parseIntErr).NotTo(o.HaveOccurred())
		end_range = strconv.Itoa(intvar + 5)
		port_range := nodePort + "-" + end_range

		g.By("create Ingress node firewall config")
		infwCfg := infwConfigResource{
			namespace: "openshift-ingress-node-firewall",
			nodelabel: "node-role.kubernetes.io/worker",
			template:  infwCfgTemplate,
		}
		defer deleteinfwCfg(oc)
		infwCfg.createinfwConfig(oc)
		waitforInfwDaemonsready(oc)

		//OVN geneve interface name
		primaryInf := "genev_sys_6081"

		//get Pod IPs depending on clustertype
		sctpClientPodIP1, sctpClientPodIP2 := getPodIP(oc, oc.Namespace(), sctpClientPodname)
		//just interested in ServerPodIP1 as getPodIP stores IPv4, IPv6 and IPv4 address in 1st var for dualstack, single stack IPv6 and single stack IPv4 respectively
		sctpServerPodIP1, _ := getPodIP(oc, oc.Namespace(), sctpServerPodName)

		infwCR_single := infwCResource{
			name:          "infw-block-stcp",
			primary_inf:   primaryInf,
			nodelabel:     "node-role.kubernetes.io/worker",
			src_cidr1:     "",
			protocol_1:    "SCTP",
			protocoltype1: "sctp",
			range_1:       port_range,
			action_1:      "Allow",
			protocoltype2: "sctp",
			protocol_2:    "SCTP",
			range_2:       port_range,
			action_2:      "Allow",
			template:      infwCRtemplate,
		}

		infwCR_multiple := infwCResource_multiple_cidr{
			name:          "infw-block-sctp",
			primary_inf:   primaryInf,
			nodelabel:     "node-role.kubernetes.io/worker",
			src_cidr1:     "",
			src_cidr2:     "",
			protocoltype1: "sctp",
			protocol_1:    "SCTP",
			range_1:       port_range,
			action_1:      "Allow",
			protocoltype2: "sctp",
			protocol_2:    "SCTP",
			range_2:       port_range,
			action_2:      "Allow",
			template:      infwCR_multiple_cidr_template,
		}

		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			g.By("create infw CR with multiple cidrs containing both IPv4 and IPv6 sctpClient addresses")
			g.By("create Ingress node firewall Rule for dual stack")
			infwCR_multiple.src_cidr1 = sctpClientPodIP2 + "/32"
			infwCR_multiple.src_cidr2 = sctpClientPodIP1 + "/128"
			defer deleteinfwCR(oc, infwCR_multiple.name)
			infwCR_multiple.createinfwCR_multiple_cidr(oc)
		} else {
			if ipStackType == "ipv6single" {
				infwCR_single.src_cidr1 = sctpClientPodIP1 + "/128"
				g.By("create Ingress node firewall Rule Custom Resource for IPv6 single stack")
			} else {
				infwCR_single.src_cidr1 = sctpClientPodIP1 + "/32"
				g.By("create Ingress node firewall Rule Custom Resource for IPv4 single stack")
			}
			defer deleteinfwCR(oc, infwCR_single.name)
			infwCR_single.createinfwCR(oc)
		}

		g.By("sctpserver pod start to wait for sctp traffic")
		_, _, _, err = oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		//normally the process should start immediately but we have seen 1-2 seconds delay using ncat-sctp under such circumstances so keeping 5 sec to make sure
		time.Sleep(5 * time.Second)

		g.By("check sctp process enabled in the sctp server pod")
		msg, err := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

		//sctpServerPodIP1 will be either IPv6 or IPv4 according to cluster type (for dual stack it would be IPv6)
		g.By("sctpclient pod start to send sctp traffic")
		_, err1 = e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'test traffic' | { ncat -v "+sctpServerPodIP1+" 30102 --sctp; }")
		o.Expect(err1).NotTo(o.HaveOccurred())

		g.By("server sctp process will end after get sctp traffic from sctp client")
		//normally the process should end immediately but we have seen 1-2 seconds delay using ncat-sctp under such circumstances so keeping 5 sec to make sure
		time.Sleep(5 * time.Second)
		msg1, err1 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(msg1).NotTo(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"))

		//remove the previous rules to establish the new one and redeploy infw rule in successive steps
		deleteinfwCR(oc, "--all")
		//now lets make action 1 as Deny and make sure we expect error when we start test traffic, restart daemons to clear stats
		infwCR_single.action_1 = "Deny"
		infwCR_multiple.action_1 = "Deny"
		restartInfwDaemons(oc)

		if ipStackType == "dualstack" {
			g.By("create infw CR with multiple cidrs containing both IPv4 and IPv6 sctpClient addresses")
			g.By("create Ingress node firewall Rule for dual stack")
			infwCR_multiple.src_cidr1 = sctpClientPodIP2 + "/32"
			infwCR_multiple.src_cidr2 = sctpClientPodIP1 + "/128"
			infwCR_multiple.createinfwCR_multiple_cidr(oc)
		} else {
			if ipStackType == "ipv6single" {
				infwCR_single.src_cidr1 = sctpClientPodIP1 + "/128"
				g.By("create Ingress node firewall Rule Custom Resource for IPv6 single stack")
			} else {
				infwCR_single.src_cidr1 = sctpClientPodIP1 + "/32"
				g.By("create Ingress node firewall Rule Custom Resource for IPv4 single stack")
			}
			infwCR_single.createinfwCR(oc)
		}

		g.By("sctpserver pod start to wait for sctp traffic")
		_, _, _, err = oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		//normally the process should start immediately but we have seen 1-2 seconds delay using ncat-sctp under such circumstances so keeping 5 sec to make sure
		time.Sleep(5 * time.Second)

		g.By("check sctp process enabled in the sctp server pod")
		msg, err = e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

		//sctpServerPodIP1 will be either IPv6 or IPv4 according to cluster type (for dual stack it would be IPv6)
		g.By("sctpclient pod start to send sctp traffic")
		_, err1 = e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'test traffic' | { ncat -v "+sctpServerPodIP1+" 30102 --sctp; }")
		o.Expect(err1).To(o.HaveOccurred()) //this traffic should be denied based on later created infw policy

		//make sure events were logged for Deny events post daemons restart at line 664, Ref.OCPBUGS-11888
		podNodeName, getNodeNameErr := compat_otp.GetPodNodeName(oc, oc.Namespace(), "sctpserver")
		o.Expect(getNodeNameErr).NotTo(o.HaveOccurred())

		infwDaemon := getinfwDaemonForNode(oc, podNodeName)
		output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", "openshift-ingress-node-firewall", infwDaemon, "-c", "events").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ruleId 1 action Drop")).Should(o.BeTrue())

	})
	g.It("Longduration-NonPreRelease-Author:anusaxen-Medium-54973-Make sure events and metrics are logged for ingress-node-firewall-daemon [Serial]", func() {
		var (
			testDataDirInfw = testdata.FixturePath("networking/ingressnodefirewall")
			infwCfgTemplate = filepath.Join(testDataDirInfw, "infw-config.yaml")
		)

		g.By("Events are being monitored in testcases wherever applicable so we will make sure metrics are being relayed to concerned port")
		worker_node, err := compat_otp.GetFirstLinuxWorkerNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("create Ingress node firewall config")
		infwCfg := infwConfigResource{
			namespace: "openshift-ingress-node-firewall",
			nodelabel: "node-role.kubernetes.io/worker",
			template:  infwCfgTemplate,
		}
		defer deleteinfwCfg(oc)
		infwCfg.createinfwConfig(oc)
		waitforInfwDaemonsready(oc)

		infwDaemon := getinfwDaemonForNode(oc, worker_node)
		cmd := "curl 127.0.0.1:39301/metrics"
		output, err := execCommandInSpecificPod(oc, "openshift-ingress-node-firewall", infwDaemon, cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("ingressnodefirewall"))

	})

	g.It("Author:anusaxen-High-55414-Check multiple CIDRS with multiple rules functionality with Ingress Firewall Node Operator [Serial]", func() {
		var (
			buildPruningBaseDirSCTP       = testdata.FixturePath("networking/sctp")
			buildPruningBaseDir           = testdata.FixturePath("networking")
			sctpModule                    = filepath.Join(buildPruningBaseDirSCTP, "load-sctp-module.yaml")
			sctpServerPodName             = "sctpserver"
			sctpClientPodname             = "sctpclient"
			testDataDirInfw               = testdata.FixturePath("networking/ingressnodefirewall")
			infwCR_multiple_cidr_template = filepath.Join(testDataDirInfw, "infw-multiple-cidr.yaml")
			infwCfgTemplate               = filepath.Join(testDataDirInfw, "infw-config.yaml")
			pingPodNodeTemplate           = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())
		if ipStackType == "dualstack" {
			g.Skip("This case requires single stack cluster")
		}

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("install load-sctp-module in all workers")
		prepareSCTPModule(oc, sctpModule)

		g.By("create new namespace")
		oc.SetupProject()
		defer compat_otp.RecoverNamespaceRestricted(oc, oc.Namespace())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())

		client_pod_pmtrs := map[string]string{
			"$nodename":  nodeList.Items[0].Name,
			"$namespace": oc.Namespace(),
		}

		g.By("creating sctp client pod in namespace")
		createSCTPclientOnNode(oc, client_pod_pmtrs)
		err1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=sctpclient")
		compat_otp.AssertWaitPollNoErr(err1, "sctpClientPod is not running")

		server_pod_pmtrs := map[string]string{
			"$nodename":  nodeList.Items[1].Name,
			"$namespace": oc.Namespace(),
		}

		g.By("creating sctp server pod in namespace")
		createSCTPserverOnNode(oc, server_pod_pmtrs)
		err1 = waitForPodWithLabelReady(oc, oc.Namespace(), "name=sctpserver")
		compat_otp.AssertWaitPollNoErr(err1, "sctpServerPod is not running")

		g.By("create a hello pod client in same namespace as of SCTP for TCP traffic check on same node as sctp client")
		pod := pingPodResourceNode{
			name:      "hello-pod-client",
			namespace: oc.Namespace(),
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod.createPingPodNode(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		g.By("create a hello pod server in same namespace as of SCTP for TCP traffic check on same node as sctp server")
		pod = pingPodResourceNode{
			name:      "hello-pod-server",
			namespace: oc.Namespace(),
			nodename:  nodeList.Items[1].Name,
			template:  pingPodNodeTemplate,
		}
		pod.createPingPodNode(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		//re-using SCTP testdata where nodePort value is hardcoded
		nodePort := "30102"

		//we need a port range to evaluate rule properly, say if nodeport is 33000, we would try a range of 33000-33005 which port_range var will store
		var intvar int
		var end_range string
		intvar, parseIntErr := strconv.Atoi(nodePort)
		o.Expect(parseIntErr).NotTo(o.HaveOccurred())
		end_range = strconv.Itoa(intvar + 5)
		port_range_sctp := nodePort + "-" + end_range
		port_range_tcp := "8080-8081"

		g.By("create Ingress node firewall config")
		infwCfg := infwConfigResource{
			namespace: "openshift-ingress-node-firewall",
			nodelabel: "node-role.kubernetes.io/worker",
			template:  infwCfgTemplate,
		}
		defer deleteinfwCfg(oc)
		infwCfg.createinfwConfig(oc)
		waitforInfwDaemonsready(oc)

		//OVN geneve interface name
		primaryInf := "genev_sys_6081"

		//get Pod IPs depending on clustertype
		sctpClientPodIP, _ := getPodIP(oc, oc.Namespace(), sctpClientPodname)
		//just interested in ServerPodIP1 as getPodIP stores IPv4, IPv6 and IPv4 address in 1st var for dualstack, single stack IPv6 and single stack IPv4 respectively
		sctpServerPodIP, _ := getPodIP(oc, oc.Namespace(), sctpServerPodName)
		helloPodClientIP, _ := getPodIP(oc, oc.Namespace(), "hello-pod-client")

		infwCR_multiple := infwCResource_multiple_cidr{
			name:          "infw-allow-sctp-tcp",
			primary_inf:   primaryInf,
			nodelabel:     "node-role.kubernetes.io/worker",
			src_cidr1:     "",
			src_cidr2:     "",
			protocoltype1: "sctp",
			protocol_1:    "SCTP",
			range_1:       port_range_sctp,
			action_1:      "Allow",
			protocoltype2: "tcp",
			protocol_2:    "TCP",
			range_2:       port_range_tcp,
			action_2:      "Allow",
			template:      infwCR_multiple_cidr_template,
		}

		if ipStackType == "ipv6single" {
			g.By("Create Custom Resource for IPv6 single stack")
			infwCR_multiple.src_cidr1 = sctpClientPodIP + "/128"
			infwCR_multiple.src_cidr2 = helloPodClientIP + "/128"
		} else {
			g.By("Create Custom Resource for IPv4 single stack")
			infwCR_multiple.src_cidr1 = sctpClientPodIP + "/32"
			infwCR_multiple.src_cidr2 = helloPodClientIP + "/32"
		}
		defer deleteinfwCR(oc, "--all")
		infwCR_multiple.createinfwCR_multiple_cidr(oc)

		//check sctp traffic as per allow rule
		g.By("sctpserver pod start to wait for sctp traffic")
		_, _, _, err = oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		//normally the process should start immediately but we have seen 1-2 seconds delay using ncat-sctp under such circumstances so keeping 5 sec to make sure
		time.Sleep(5 * time.Second)

		g.By("check sctp process enabled in the sctp server pod")
		msg, err := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

		//sctpServerPodIP1 will be either IPv6 or IPv4 according to cluster type
		g.By("sctpclient pod start to send sctp traffic")
		_, err1 = e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'test traffic' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")
		o.Expect(err1).NotTo(o.HaveOccurred())

		//check tcp traffic as per allow rule
		CurlPod2PodPass(oc, oc.Namespace(), "hello-pod-client", oc.Namespace(), "hello-pod-server")

		//delete infw-allow-sctp-tcp CR created above
		//using --all arg to delete all CR to make sure. This usecase has different CR names so defer delete/defer with spefic CR is not a great idea
		deleteinfwCR(oc, "--all")

		//Re-create CR with Deny rules now
		infwCR_multiple.action_1 = "Deny"
		infwCR_multiple.action_2 = "Deny"
		infwCR_multiple.name = "infw-block-sctp-tcp"
		if ipStackType == "ipv6single" {
			g.By("Create Custom Resource for IPv6 single stack")
			infwCR_multiple.src_cidr1 = sctpClientPodIP + "/128"
			infwCR_multiple.src_cidr2 = helloPodClientIP + "/128"
		} else {
			g.By("Create Custom Resource for IPv4 single stack")
			infwCR_multiple.src_cidr1 = sctpClientPodIP + "/32"
			infwCR_multiple.src_cidr2 = helloPodClientIP + "/32"
		}
		infwCR_multiple.createinfwCR_multiple_cidr(oc)

		//check sctp traffic as per Deny rule
		g.By("sctpserver pod start to wait for sctp traffic")
		_, _, _, err = oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		//normally the process should start immediately but we have seen 1-2 seconds delay using ncat-sctp under such circumstances so keeping 5 sec to make sure
		time.Sleep(5 * time.Second)

		g.By("check sctp process enabled in the sctp server pod")
		msg, err = e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

		//sctpServerPodIP1 will be either IPv6 or IPv4 according to cluster type
		g.By("sctpclient pod start to send sctp traffic")
		_, err1 = e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'test traffic' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")
		o.Expect(err1).To(o.HaveOccurred())

		//check tcp traffic as per Deny rule
		CurlPod2PodFail(oc, oc.Namespace(), "hello-pod-client", oc.Namespace(), "hello-pod-server")

	})

	g.It("Author:anusaxen-ROSA-High-73844-Check Ingress Node Firewall functionality for blocking SSH traffic [Serial]", func() {
		var (
			testDataDirInfw = testdata.FixturePath("networking/ingressnodefirewall")
			infwCRtemplate  = filepath.Join(testDataDirInfw, "infw.yaml")
			infwCfgTemplate = filepath.Join(testDataDirInfw, "infw-config.yaml")
		)
		ipStackType := checkIPStackType(oc)
		o.Expect(ipStackType).NotTo(o.BeEmpty())
		if ipStackType == "dualstack" {
			g.Skip("This case requires single stack cluster IPv4/IPv6")
		}

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("create Ingress node firewall config")
		infwCfg := infwConfigResource{
			namespace: "openshift-ingress-node-firewall",
			nodelabel: "node-role.kubernetes.io/worker",
			template:  infwCfgTemplate,
		}
		defer deleteinfwCfg(oc)
		infwCfg.createinfwConfig(oc)
		waitforInfwDaemonsready(oc)

		//get cluster default mgmt interface
		primaryInf := getPrimaryNICname(oc)

		infwCR_single := infwCResource{
			name:          "infw-block-ssh",
			primary_inf:   primaryInf,
			nodelabel:     "node-role.kubernetes.io/worker",
			src_cidr1:     "",
			protocol_1:    "TCP",
			protocoltype1: "tcp",
			range_1:       "22", //ssh port
			action_1:      "Deny",
			protocoltype2: "tcp",
			protocol_2:    "TCP",
			range_2:       "22",
			action_2:      "Allow",
			template:      infwCRtemplate,
		}

		if ipStackType == "ipv6single" {
			//ssh traffic coming towards any worker node should be blocked
			infwCR_single.src_cidr1 = "::/0"
			g.By("create Ingress node firewall Rule Custom Resource for IPv6 single stack")
		} else {
			//ssh traffic coming towards any worker node should be blocked
			infwCR_single.src_cidr1 = "0.0.0.0/0"
			g.By("create Ingress node firewall Rule Custom Resource for IPv4 single stack")
		}
		defer deleteinfwCR(oc, infwCR_single.name)
		infwCR_single.createinfwCR(oc)

		//Identify the first master node to act as ssh source fo worker node
		firstMasterNode, err := compat_otp.GetFirstMasterNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		sshcmd := "ssh -o ConnectTimeout=1 core@" + nodeList.Items[0].Name
		sshOutput, _ := compat_otp.DebugNodeWithChroot(oc, firstMasterNode, "/bin/bash", "-c", sshcmd)
		o.Expect(strings.Contains(sshOutput, "Connection timed out")).Should(o.BeTrue())

		//get corresponding infw daemon pod for targeted worker
		infwDaemon := getinfwDaemonForNode(oc, nodeList.Items[0].Name)
		//make sure events were logged for ssh Deny
		output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", "openshift-ingress-node-firewall", infwDaemon, "-c", "events").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ruleId 1 action Drop")).Should(o.BeTrue())
		o.Expect(strings.Contains(output, "dstPort 22")).Should(o.BeTrue())

	})
})
