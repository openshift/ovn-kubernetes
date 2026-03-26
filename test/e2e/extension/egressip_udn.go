package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	clusterinfra "github.com/openshift/origin/test/extended/util/compat_otp/clusterinfra"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	netutils "k8s.io/utils/net"
)

var _ = g.Describe("[OTP][sig-networking] SDN udn EgressIP", func() {
	defer g.GinkgoRecover()

	var (
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
	)

	g.BeforeEach(func() {

		platform := compat_otp.CheckPlatform(oc)
		networkType := checkNetworkType(oc)
		e2e.Logf("\n\nThe platform is %v,  networkType is %v\n", platform, networkType)

		acceptedPlatform := strings.Contains(platform, "aws") || strings.Contains(platform, "gcp") || strings.Contains(platform, "openstack") || strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "azure") || strings.Contains(platform, "none") || strings.Contains(platform, "nutanix") || strings.Contains(platform, "powervs")
		if !acceptedPlatform || !strings.Contains(networkType, "ovn") {
			g.Skip("Test cases should be run on AWS/GCP/Azure/Openstack/Vsphere/BareMetal/Nutanix/Powervs cluster with ovn network plugin, skip for other platforms or other non-OVN network plugin!!")
		}

		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv6single" {
			// Not able to run on IPv6 single cluster for now due to cluster disconnect limiation.
			g.Skip("Skip IPv6 Single cluster.")
		}

		if !(strings.Contains(platform, "none") || strings.Contains(platform, "powervs")) && (checkProxy(oc) || checkDisconnect(oc)) {
			g.Skip("This is proxy/disconnect cluster, skip the test.")
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-77654-Validate egressIP with mixed of multiple non-overlapping UDNs and default network(layer3/2 and IPv4 only) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			allNS               []string
		)

		compat_otp.By("1 Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}
		egressNode := nodeList.Items[0].Name
		theOtherNode := nodeList.Items[1].Name

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("2.1 Obtain first namespace, create four more namespaces")
		// first namespace is used for default network, second and third namespaces will be used for layer3 UDNs, last two namespaces will be used for layer2 UDN
		ns := oc.Namespace()
		allNS = append(allNS, ns)
		for i := 0; i < 4; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			allNS = append(allNS, ns)
		}

		compat_otp.By("2.2 Apply a label to all namespaces that matches namespaceSelector defined in egressIP object")
		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3 Create two different layer3 UDNs in 2nd and 3rd namespaces, two different layer2 UDN in last two namespaces")
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/48", "2011:100:200::0/48"}

		for i := 1; i < 3; i++ {
			createGeneralUDNCRD(oc, allNS[i], "udn-network-layer3-"+allNS[i], ipv4cidr[i-1], ipv6cidr[i-1], cidr[i-1], "layer3")
			createGeneralUDNCRD(oc, allNS[i+2], "udn-network-layer2-"+allNS[i+2], ipv4cidr[i-1], ipv6cidr[i-1], cidr[i-1], "layer2")
		}

		compat_otp.By("4. Create an egressip object, verify egressIP is assigned to egress node")
		freeIPs := findFreeIPs(oc, nodeList.Items[0].Name, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-77654",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNode))

		compat_otp.By("5.1 In each namespace, create two test pods, the first one on egressNode, the second one on nonEgressNode ")
		compat_otp.By("5.2 Apply label to all pods that matches podSelector definied in egressIP object")
		testpods1 := make([]pingPodResourceNode, len(allNS))
		testpods2 := make([]pingPodResourceNode, len(allNS))
		for i := 0; i < len(allNS); i++ {
			// testpods1 are local pods that co-locate on egress node
			testpods1[i] = pingPodResourceNode{
				name:      "hello-pod1-" + allNS[i],
				namespace: allNS[i],
				nodename:  egressNode,
				template:  pingPodNodeTemplate,
			}
			testpods1[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods1[i].name)
			defer compat_otp.LabelPod(oc, allNS[i], testpods1[i].name, "color-")
			err = compat_otp.LabelPod(oc, allNS[i], testpods1[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())

			// testpods1 are remote pods on the other non-egress node
			testpods2[i] = pingPodResourceNode{
				name:      "hello-pod2-" + allNS[i],
				namespace: allNS[i],
				nodename:  theOtherNode,
				template:  pingPodNodeTemplate,
			}
			testpods2[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods2[i].name)
			defer compat_otp.LabelPod(oc, allNS[i], testpods2[i].name, "color-")
			err = compat_otp.LabelPod(oc, allNS[i], testpods2[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("6. Verify egressIP from each namespace, egress traffic from these pods should use egressIP as their sourceIP regardless it is from layer3 UDN, default network or layer2 UDN")
		var dstHost, primaryInf string
		var infErr error
		compat_otp.By("6.1 Use tcpdump to verify egressIP.")
		e2e.Logf("Trying to get physical interface on the egressNode,%s", egressNode)
		primaryInf, infErr = getSnifPhyInf(oc, nodeList.Items[0].Name)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost = nslookDomainName("ifconfig.me")
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod := getRequestURL(dstHost)

		compat_otp.By("6.2 Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		for i := 0; i < len(allNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[i], testpods1[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[i], testpods2[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-77655-Validate egressIP with mixed of multiple overlapping UDNs and default network(layer3/2 and IPv4 only) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			allNS               []string
		)

		compat_otp.By("1 Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, the prerequirement was not fullfilled, skip the case!!")
		}
		egressNode := nodeList.Items[0].Name
		theOtherNode := nodeList.Items[1].Name

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("2.1 Obtain first namespace, create four more namespaces")
		// first namespace is for default network, 2nd and 3rd namespaces will be used for layer3 UDNs, last two namespaces will be used for layer2 UDN
		ns := oc.Namespace()
		allNS = append(allNS, ns)
		for i := 0; i < 4; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			allNS = append(allNS, ns)
		}

		compat_otp.By("2.2 Apply a label to all namespaces that matches namespaceSelector defined in egressIP object")
		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3. Create two overlapping layer3 UDNs in 2rd and 3rd namesapces, create two overlapping layer2 UDN in last two namespaces")
		cidr := []string{"10.150.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/48"}

		for i := 1; i < 3; i++ {
			createGeneralUDNCRD(oc, allNS[i], "udn-network-layer3-"+allNS[i], ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
			createGeneralUDNCRD(oc, allNS[i+2], "udn-network-layer2-"+allNS[i+2], ipv4cidr[0], ipv6cidr[0], cidr[0], "layer2")
		}

		compat_otp.By("4. Create an egressip object, verify egressIP is assigned to egress node")
		freeIPs := findFreeIPs(oc, nodeList.Items[0].Name, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-77655",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNode))

		compat_otp.By("5.1 In each namespace, create two test pods, the first one on egressNode, the second one on nonEgressNode ")
		compat_otp.By("5.2 Apply label to all pods that matches podSelector definied in egressIP object")
		testpods1 := make([]pingPodResourceNode, len(allNS))
		testpods2 := make([]pingPodResourceNode, len(allNS))
		for i := 0; i < len(allNS); i++ {
			// testpods1 are lcaol pods that co-locate on egress node
			testpods1[i] = pingPodResourceNode{
				name:      "hello-pod1-" + allNS[i],
				namespace: allNS[i],
				nodename:  egressNode,
				template:  pingPodNodeTemplate,
			}
			testpods1[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods1[i].name)
			defer compat_otp.LabelPod(oc, allNS[i], testpods1[i].name, "color-")
			err = compat_otp.LabelPod(oc, allNS[i], testpods1[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())

			// testpods1 are remote pods on the other non-egress node
			testpods2[i] = pingPodResourceNode{
				name:      "hello-pod2-" + allNS[i],
				namespace: allNS[i],
				nodename:  theOtherNode,
				template:  pingPodNodeTemplate,
			}
			testpods2[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods2[i].name)
			defer compat_otp.LabelPod(oc, allNS[i], testpods2[i].name, "color-")
			err = compat_otp.LabelPod(oc, allNS[i], testpods2[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("6. Verify egressIP from each namespace, egress traffic from these pods should use egressIP as their sourceIP regardless it is from UDN or default network")
		var dstHost, primaryInf string
		var infErr error
		compat_otp.By("6.1 Use tcpdump to verify egressIP.")
		e2e.Logf("Trying to get physical interface on the egressNode %s", egressNode)
		primaryInf, infErr = getSnifPhyInf(oc, nodeList.Items[0].Name)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost = nslookDomainName("ifconfig.me")
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod := getRequestURL(dstHost)

		compat_otp.By("6.2 Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		for i := 0; i < len(allNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[i], testpods1[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[i], testpods2[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-Longduration-NonPreRelease-High-77744-Validate egressIP Failover with non-overlapping and overlapping UDNs (layer3/2 and IPv4 only) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			udnNS               []string
		)

		compat_otp.By("1. Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")

		compat_otp.By("2.1 Obtain first namespace, create five more namespaces")
		// first three namespaces will be used for layer3 UDNs, last three namespaces will be used for layer2 UDN
		oc.CreateNamespaceUDN()
		ns := oc.Namespace()
		udnNS = append(udnNS, ns)
		for i := 0; i < 5; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			udnNS = append(udnNS, ns)
		}

		compat_otp.By("2.2 Apply a label to all namespaces that matches namespaceSelector defined in egressIP object")
		for _, ns := range udnNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3. Create non overlapping & overlapping layer3 UDNs in three namesapces, create non-overlapping & overlapping layer2 UDN in last three namespaces")
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/60", "2011:100:200::0/60", "2011:100:200::0/60"}

		for i := 0; i < 3; i++ {
			createGeneralUDNCRD(oc, udnNS[i], "udn-network-layer3-"+udnNS[i], ipv4cidr[i], ipv6cidr[i], cidr[i], "layer3")
			createGeneralUDNCRD(oc, udnNS[i+3], "udn-network-layer2-"+udnNS[i+3], ipv4cidr[i], ipv6cidr[i], cidr[i], "layer2")
		}

		compat_otp.By("4. Create an egressip object, verify egressIP is assigned to egress node")
		freeIPs := findFreeIPs(oc, egressNodes[0], 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-77744",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNodes[0]))

		compat_otp.By("5.1 In each namespace, create two test pods, the first one on egressNode, the second one on nonEgressNode ")
		compat_otp.By("5.2 Apply label to all pods that matches podSelector definied in egressIP object")
		testpods1 := make([]pingPodResourceNode, len(udnNS))
		testpods2 := make([]pingPodResourceNode, len(udnNS))
		for i := 0; i < len(udnNS); i++ {
			// testpods1 are pods on egressNode
			testpods1[i] = pingPodResourceNode{
				name:      "hello-pod1-" + udnNS[i],
				namespace: udnNS[i],
				nodename:  egressNodes[0],
				template:  pingPodNodeTemplate,
			}
			testpods1[i].createPingPodNode(oc)
			waitPodReady(oc, udnNS[i], testpods1[i].name)
			defer compat_otp.LabelPod(oc, udnNS[i], testpods1[i].name, "color-")
			err = compat_otp.LabelPod(oc, udnNS[i], testpods1[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())

			// testpods2 are pods on nonEgressNode, egressNodes[1] is currently not a egress node as it is not labelled with egressNodeLabel
			testpods2[i] = pingPodResourceNode{
				name:      "hello-pod2-" + udnNS[i],
				namespace: udnNS[i],
				nodename:  egressNodes[1],
				template:  pingPodNodeTemplate,
			}
			testpods2[i].createPingPodNode(oc)
			waitPodReady(oc, udnNS[i], testpods2[i].name)
			defer compat_otp.LabelPod(oc, udnNS[i], testpods2[i].name, "color-")
			err = compat_otp.LabelPod(oc, udnNS[i], testpods2[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("6. Verify egressIP from each namespace, egress traffic from these pods should use egressIP as their sourceIP regardless it is from overlapping or non-overlapping UDN")
		var dstHost, primaryInf, tcpdumpCmd, cmdOnPod string
		var infErr error
		compat_otp.By("6.1 Use tcpdump to verify egressIP.")
		e2e.Logf("Trying to get physical interface on the egressNode %s", egressNodes[0])
		primaryInf, infErr = getSnifPhyInf(oc, nodeList.Items[0].Name)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost = nslookDomainName("ifconfig.me")
		tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod = getRequestURL(dstHost)

		compat_otp.By("6.2 Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		for i := 0; i < len(udnNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, udnNS[i], testpods1[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, udnNS[i], testpods2[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("7. Label the second node with egressNodeLabel, unlabel the first node, verify egressIP still works after failover.\n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")

		compat_otp.By("8. Check the egress node was updated in the egressip object.\n")
		egressipErr := wait.PollUntilContextTimeout(context.Background(), 20*time.Second, 360*time.Second, false, func(cxt context.Context) (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 1 || egressIPMaps1[0]["node"] == egressNodes[0] {
				e2e.Logf("Wait for new egress node applied,try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to update egress node:%v", egressipErr))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNodes[1]))

		compat_otp.By("9. Validate egressIP again after egressIP failover \n")
		compat_otp.By("9.1 Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods after egressIP failover")
		for i := 0; i < len(udnNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[1], tcpdumpCmd, udnNS[i], testpods1[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNodes[1], tcpdumpCmd, udnNS[i], testpods2[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-Medium-78276-non-overlapping and overlapping UDN egressIP Pods will not be affected by the egressIP set on other netnamespace(layer3/2 and IPv4 only) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			allNS               []string
		)

		compat_otp.By("1. Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Need at least 1 node for the test, the prerequirement was not fullfilled, skip the case!!")
		}
		egressNode := nodeList.Items[0].Name

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("2.1 Obtain first namespace, create five more namespaces")
		oc.CreateNamespaceUDN()
		ns := oc.Namespace()
		allNS = append(allNS, ns)
		for i := 0; i < 5; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			allNS = append(allNS, ns)
		}

		compat_otp.By("2.2 Apply a label to all namespaces that matches namespaceSelector defined in egressIP object")
		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3. Create non-overlapping & overlapping layer3 UDNs in first three namesapces, create non-overlapping & overlapping layer2 UDN in last three namespaces")
		cidr := []string{"10.150.0.0/16", "10.151.0.0/16", "10.151.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16", "10.151.0.0/16", "10.151.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/60", "2011:100:200::0/60", "2011:100:200::0/60"}
		for i := 0; i < 3; i++ {
			createGeneralUDNCRD(oc, allNS[i], "udn-network-layer3-"+allNS[i], ipv4cidr[i], ipv6cidr[i], cidr[i], "layer3")
			createGeneralUDNCRD(oc, allNS[i+3], "udn-network-layer2-"+allNS[i+3], ipv4cidr[i], ipv6cidr[i], cidr[i], "layer2")
		}

		compat_otp.By("4. Get 3 unused IPs from the same subnet of the egressNode,create 3 egressIP objects with same namespaceSelector but different podSelector")
		freeIPs := findFreeIPs(oc, egressNode, 3)
		o.Expect(len(freeIPs)).Should(o.Equal(3))

		podLabelValues := []string{"pink", "blue", "red", "pink", "blue", "red"}
		egressips := make([]egressIPResource1, 3)
		for i := 0; i < 3; i++ {
			egressips[i] = egressIPResource1{
				name:          "egressip-78276-" + strconv.Itoa(i),
				template:      egressIP2Template,
				egressIP1:     freeIPs[i],
				nsLabelKey:    "org",
				nsLabelValue:  "qe",
				podLabelKey:   "color",
				podLabelValue: podLabelValues[i],
			}
			egressips[i].createEgressIPObject2(oc)
			defer egressips[i].deleteEgressIPObject1(oc)
			egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressips[i].name)
			o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		}

		compat_otp.By("5. In each namespace, create a test pod, apply to test pod with label that matches podSelector definied in egressIP object")
		testpods := make([]pingPodResource, len(allNS))
		for i := 0; i < len(allNS); i++ {
			testpods[i] = pingPodResource{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: allNS[i],
				template:  pingPodTemplate,
			}
			testpods[i].createPingPod(oc)
			waitPodReady(oc, testpods[i].namespace, testpods[i].name)
			defer compat_otp.LabelPod(oc, allNS[i], testpods[i].name, "color-")
			err = compat_otp.LabelPod(oc, allNS[i], testpods[i].name, "color="+podLabelValues[i])
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("6. Verify egressIP from each namespace, egress traffic from each pod should use egressIP defined in the egressIP object the pod qualifies")
		var dstHost, primaryInf string
		var infErr error
		e2e.Logf("Trying to get physical interface on the egressNode,%s", egressNode)
		primaryInf, infErr = getSnifPhyInf(oc, nodeList.Items[0].Name)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost = nslookDomainName("ifconfig.me")
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)

		compat_otp.By("Use tcpdump captured on egressNode to verify egressIP each pod")
		for i := 0; i < 3; i++ {
			_, cmdOnPod := getRequestURL(dstHost)

			// Verify from layer3 UDN pods
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[i], testpods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[i])).To(o.BeTrue())

			// Verify from layer2 UDN pods
			tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[i+3], testpods[i+3].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[i])).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-78199-egressIP still works correctly after a UDN network gets deleted then recreated (layer3/2 and IPv4 only) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		compat_otp.By("1 Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, nodesToBeUsed := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || nodesToBeUsed == nil || len(nodesToBeUsed) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}
		egressNode := nodesToBeUsed[0]

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("2.1 Obtain first namespace, create another namespace")
		// first namespace for layer3 UDNs, second namespace will be used for layer2 UDN
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		allNS := []string{ns1, ns2}

		compat_otp.By("2.2 Apply a label to all namespaces that matches namespaceSelector definied in egressIP object")
		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3.1 Create an UDN layer3 in ns1")
		cidr := []string{"10.150.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/48"}
		createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		createGeneralUDNCRD(oc, ns2, "udn-network-layer2-"+ns2, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer2")

		compat_otp.By("4. Create an egressip object, verify egressIP is assigned to egress node")
		freeIPs := findFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-78199",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNode))

		compat_otp.By("5.1 In the namespace, create two test pods, the first one on egressNode, the second one on nonEgressNode ")
		compat_otp.By("5.2 Apply to all pods with label that matches podSelector definied in egressIP object")
		var testpods [2][2]pingPodResourceNode
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				testpods[j][i] = pingPodResourceNode{
					name:      "hello-pod" + strconv.Itoa(i) + "-" + allNS[j],
					namespace: ns1,
					nodename:  nodesToBeUsed[i],
					template:  pingPodNodeTemplate,
				}
				testpods[j][i].createPingPodNode(oc)
				waitPodReady(oc, ns1, testpods[j][i].name)
				defer compat_otp.LabelPod(oc, ns1, testpods[j][i].name, "color-")
				err = compat_otp.LabelPod(oc, ns1, testpods[j][i].name, "color=pink")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}

		compat_otp.By("6. Verify egressIP from each namespace, egress traffic from these pods should use egressIP as their sourceIP regardless it is from overlapping or non-overlapping UDN")
		var dstHost, primaryInf, tcpdumpCmd, cmdOnPod string
		var infErr error
		compat_otp.By("6.1 Use tcpdump to verify egressIP.")
		e2e.Logf("Trying to get physical interface on the egressNode %s", egressNode)
		primaryInf, infErr = getSnifPhyInf(oc, nodeList.Items[0].Name)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost = nslookDomainName("ifconfig.me")
		tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod = getRequestURL(dstHost)

		compat_otp.By("6.2 Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, ns1, testpods[j][i].name, cmdOnPod)
				o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			}
		}

		compat_otp.By("7. Delete local and remote test pods that are associated with UDNs, then delete the UDNs.\n")
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				removeResource(oc, true, true, "pod", testpods[j][i].name, "-n", testpods[j][i].namespace)
			}
		}
		removeResource(oc, true, true, "UserDefinedNetwork", "udn-network-layer3-"+ns1, "-n", ns1)
		removeResource(oc, true, true, "UserDefinedNetwork", "udn-network-layer2-"+ns2, "-n", ns2)

		compat_otp.By("8. Recreate layer3 and layer2 UDNs, recreate local/remote test pods.\n")
		createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		createGeneralUDNCRD(oc, ns2, "udn-network-layer2-"+ns2, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer2")

		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				testpods[j][i].createPingPodNode(oc)
				waitPodReady(oc, ns1, testpods[j][i].name)
				defer compat_otp.LabelPod(oc, ns1, testpods[j][i].name, "color-")
				err = compat_otp.LabelPod(oc, ns1, testpods[j][i].name, "color=pink")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}

		compat_otp.By("9. Validate egressIP again after recreating UDNs \n")
		compat_otp.By("9.1 Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods again after UDN recreation")
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, ns1, testpods[j][i].name, cmdOnPod)
				o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			}
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-78200-egressIP still works correctly after OVNK restarted on local and remote client host  (layer3/2 and IPv4 only) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		compat_otp.By("1 Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, nodesToBeUsed := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || nodesToBeUsed == nil || len(nodesToBeUsed) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}
		egressNode := nodesToBeUsed[0]

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("2 Obtain a namespace, create a second one, apply a label to both namespaces that matches namespaceSelector definied in egressIP object")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		allNS := []string{ns1, ns2}

		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3. Create a layer3 UDN in ns1, and another layer2 UDN in ns2")
		cidr := []string{"10.150.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/48"}
		createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		createGeneralUDNCRD(oc, ns2, "udn-network-layer2-"+ns2, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer2")

		compat_otp.By("4. Create an egressip object, verify egressIP is assigned to egress node")
		freeIPs := findFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-78200",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNode))

		compat_otp.By("5.1 In the namespace, create two test pods, the first one on egressNode, the second one on nonEgressNode ")
		compat_otp.By("5.2 Apply to all pods with label that matches podSelector defined in egressIP object")
		var testpods [2][2]pingPodResourceNode
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				testpods[j][i] = pingPodResourceNode{
					name:      "hello-pod" + strconv.Itoa(i) + "-" + allNS[j],
					namespace: allNS[j],
					nodename:  nodesToBeUsed[i],
					template:  pingPodNodeTemplate,
				}
				testpods[j][i].createPingPodNode(oc)
				waitPodReady(oc, allNS[j], testpods[j][i].name)
				defer compat_otp.LabelPod(oc, allNS[j], testpods[j][i].name, "color-")
				err = compat_otp.LabelPod(oc, allNS[j], testpods[j][i].name, "color=pink")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}

		compat_otp.By("6. Verify egress traffic from these local or remote egressIP pods should use egressIP as their sourceIP")
		var dstHost, primaryInf, tcpdumpCmd, cmdOnPod string
		var infErr error
		compat_otp.By("6.1 Use tcpdump to verify egressIP.")
		e2e.Logf("Trying to get physical interface on the egressNode %s", egressNode)
		primaryInf, infErr = getSnifPhyInf(oc, egressNode)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost = nslookDomainName("ifconfig.me")
		tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod = getRequestURL(dstHost)

		compat_otp.By("6.2 Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[j], testpods[j][i].name, cmdOnPod)
				o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			}
		}

		compat_otp.By("7. Restart ovnkube-node pod of client host that local egressIP pod are on.\n")
		// Since local egressIP pods are on egress node, restart ovnkube-pod of egress node
		ovnkPod := ovnkubeNodePod(oc, egressNode)
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnkPod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		waitForNetworkOperatorState(oc, 100, 18, "True.*False.*False")

		compat_otp.By("8. Validate egressIP again after restarting ovnkude-node pod of client host that local egressIP pods are on \n")
		compat_otp.By("Use tcpdump captured on egressNode to verify egressIP from local pods again after OVNK restart")
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[j], testpods[j][i].name, cmdOnPod)
				o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			}
		}

		compat_otp.By("9. Restart ovnkube-node pod of client host that remote egressIP pods are on.\n")
		// Since remote egressIP pod is on non-egress node, restart ovnkube-pod of the non-egress node nodesToBeUsed[1]
		ovnkPod = ovnkubeNodePod(oc, nodesToBeUsed[1])
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnkPod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		waitForNetworkOperatorState(oc, 100, 18, "True.*False.*False")

		compat_otp.By("10. Validate egressIP again after restarting ovnkude-node pod of client host that remote egressIP pods on \n")
		compat_otp.By("Use tcpdump captured on egressNode to verify egressIP from remote pods again after OVNK restart")
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < 2; i++ {
				tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[j], testpods[j][i].name, cmdOnPod)
				o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			}
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-Longduration-NonPreRelease-High-78293-After reboot egress node EgressIP on UDN still work (layer3/2 and IPv4). [Disruptive]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		)

		compat_otp.By("1. Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Need at least 1 node for the test, the prerequirement was not fullfilled, skip the case!!")
		}
		egressNode := nodeList.Items[0].Name

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("2 Obtain a namespace, create a second one, apply a label to both namespaces that matches namespaceSelector definied in egressIP object")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		allNS := []string{ns1, ns2}

		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3. Create a layer3 UDN in ns1, create a layer2 UDN in ns2")
		cidr := []string{"10.150.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/48"}
		createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		createGeneralUDNCRD(oc, ns2, "udn-network-layer2-"+ns2, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer2")

		compat_otp.By("4. Get 1 unused IPs from the same subnet of the egressNode,create an egressIP object")
		freeIPs := findFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip := egressIPResource1{
			name:          "egressip-78293",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip.createEgressIPObject2(oc)
		defer egressip.deleteEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("5. In each namespace, create a test pod, apply to test pod with label that matches podSelector definied in egressIP object")
		testpods := make([]pingPodResource, len(allNS))
		for i := 0; i < len(allNS); i++ {
			testpods[i] = pingPodResource{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: allNS[i],
				template:  pingPodTemplate,
			}
			testpods[i].createPingPod(oc)
			waitPodReady(oc, testpods[i].namespace, testpods[i].name)
			defer compat_otp.LabelPod(oc, allNS[i], testpods[i].name, "color-")
			err = compat_otp.LabelPod(oc, allNS[i], testpods[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("6. Verify that egress traffic from pod use egressIP as its sourceIP")
		primaryInf, infErr := getSnifPhyInf(oc, egressNode)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost := nslookDomainName("ifconfig.me")
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod := getRequestURL(dstHost)
		for i := 0; i < len(allNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[i], testpods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("7.Reboot egress node.\n")
		defer checkNodeStatus(oc, egressNode, "Ready")
		rebootNode(oc, egressNode)
		checkNodeStatus(oc, egressNode, "NotReady")
		checkNodeStatus(oc, egressNode, "Ready")
		for i := 0; i < len(allNS); i++ {
			waitPodReady(oc, testpods[i].namespace, testpods[i].name)
			err = compat_otp.LabelPod(oc, allNS[i], testpods[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("8. Check EgressIP is assigned again after reboot.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip.name, 1)

		compat_otp.By("8. Validate egressIP after node reboot \n")
		for i := 0; i < len(allNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode, tcpdumpCmd, allNS[i], testpods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-Longduration-NonPreRelease-High-78422-EgressIP on UDN still works on next available egress node after previous assigned egress node was deleted (layer3/2 and IPv4 only). [Disruptive]", func() {

		platform := compat_otp.CheckPlatform(oc)
		if strings.Contains(platform, "baremetal") || strings.Contains(platform, "none") {
			g.Skip("Skip for non-supported auto scaling machineset platforms!!")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")

		compat_otp.By("1. Get an existing worker node to be non-egress node.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Need at least 1 worker node, skip the test as the requirement was not fulfilled.")
		}
		nonEgressNode := nodeList.Items[0].Name

		compat_otp.By("2.Create a new machineset with 2 nodes")
		clusterinfra.SkipConditionally(oc)
		infrastructureName := clusterinfra.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-78422"
		ms := clusterinfra.MachineSetDescription{Name: machinesetName, Replicas: 2}
		defer clusterinfra.WaitForMachinesDisapper(oc, machinesetName)
		defer ms.DeleteMachineSet(oc)
		ms.CreateMachineSet(oc)

		clusterinfra.WaitForMachinesRunning(oc, 2, machinesetName)
		machineNames := clusterinfra.GetMachineNamesFromMachineSet(oc, machinesetName)
		nodeName0 := clusterinfra.GetNodeNameFromMachine(oc, machineNames[0])
		nodeName1 := clusterinfra.GetNodeNameFromMachine(oc, machineNames[1])

		compat_otp.By("3.1 Obtain a namespace, create a second one, apply a label to both namespaces that matches namespaceSelector definied in egressIP object")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		allNS := []string{ns1, ns2}

		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3.2. Create a layer3 UDN in ns1, create a layer2 UDN in ns2")
		cidr := []string{"10.150.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/48"}
		createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")
		createGeneralUDNCRD(oc, ns2, "udn-network-layer2-"+ns2, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer2")

		compat_otp.By("4. Apply EgressLabel to the first node created by the new machineset\n")
		// No need to defer unlabeling the node, as the node will be defer deleted with machineset before end of the test case
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeName0, egressNodeLabel, "true")

		compat_otp.By("5. Get an unused IP address from the first node, create an egressip object with the IP\n")
		freeIPs := findFreeIPs(oc, nodeName0, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip := egressIPResource1{
			name:          "egressip-78422",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip.createEgressIPObject2(oc)
		defer egressip.deleteEgressIPObject1(oc)
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))
		o.Expect(egressIPMaps[0]["node"]).Should(o.Equal(nodeName0))

		compat_otp.By("6. Create a test pod on the non-egress node, apply to the pod with a label that matches podSelector in egressIP object \n")
		testpods := make([]pingPodResourceNode, len(allNS))
		for i := 0; i < len(allNS); i++ {
			testpods[i] = pingPodResourceNode{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: allNS[i],
				nodename:  nonEgressNode,
				template:  pingPodNodeTemplate,
			}
			testpods[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods[i].name)
			defer compat_otp.LabelPod(oc, allNS[i], testpods[i].name, "color-")
			err = compat_otp.LabelPod(oc, allNS[i], testpods[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("7. Get tcpdump on first egress node, verify that egressIP works on first egress node")
		primaryInf, infErr := getSnifPhyInf(oc, nodeName0)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost := nslookDomainName("ifconfig.me")
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod := getRequestURL(dstHost)
		for i := 0; i < len(allNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, machineNames[0], tcpdumpCmd, allNS[i], testpods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("8. Apply EgressLabel to the second node created by the new machineset.\n")
		// No need to defer unlabeling the node, as the node will be deleted with machineset before the end of the test case
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeName1, egressNodeLabel, "true")

		compat_otp.By("9. Delete the first egress node, verify egressIP migrates to the second egress node.\n")
		removeResource(oc, true, true, "machines.machine.openshift.io", machineNames[0], "-n", "openshift-machine-api")

		o.Eventually(func() bool {
			egressIPMaps := getAssignedEIPInEIPObject(oc, egressip.name)
			return len(egressIPMaps) == 1 && egressIPMaps[0]["node"] == nodeName1
		}, "120s", "10s").Should(o.BeTrue(), "egressIP was not migrated to next available egress node!!")

		compat_otp.By("10. Get tcpdump on second egress node, verify that egressIP still works after migrating to second egress node")
		primaryInf, infErr = getSnifPhyInf(oc, nodeName1)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod = getRequestURL(dstHost)
		for i := 0; i < len(allNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, nodeName1, tcpdumpCmd, allNS[i], testpods[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-78453-Traffic is load balanced between egress nodes for egressIP UDN (layer3 and IPv4 only) .[Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("1. Get two worker nodes that are in same subnet, they will be used as egress-assignable nodes, get a third node as non-egress node\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 || len(nodeList.Items) < 3 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		var nonEgressNode string
		for _, node := range nodeList.Items {
			if !contains(egressNodes, node.Name) {
				nonEgressNode = node.Name
				break
			}
		}

		compat_otp.By("2. Apply EgressLabel Key to nodes.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)

		compat_otp.By("3 Obtain first namespace, apply layer3 UDN CRD to it, add to the namespace with a label matching the namespaceSelector of egressIP object that will be created in step 4")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged namespace for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		cidr := []string{"10.150.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/48"}
		createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer3")

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNodes[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-78453",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		//Replace matchLabel with matchExpressions
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-78453", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchExpressions\":[{\"key\": \"name\", \"operator\": \"In\", \"values\": [\"test\"]}]}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-78453", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchLabels\":null}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		compat_otp.By("5. Create two pods, one pod is local to egress node, another pod is remote to egress node ")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1-" + ns1,
			namespace: ns1,
			nodename:  egressNodes[0],
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		pod2 := pingPodResourceNode{
			name:      "hello-pod2-" + ns1,
			namespace: ns1,
			nodename:  nonEgressNode,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod2.name)

		compat_otp.By("6. Check source IP is randomly one of egress ips.\n")
		compat_otp.By("6.1 Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], "tcpdump", "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], "tcpdump", "true")
		primaryInf, infErr := getSnifPhyInf(oc, egressNodes[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost := nslookDomainName("ifconfig.me")
		defer deleteTcpdumpDS(oc, "tcpdump-78453", ns1)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-78453", "tcpdump", "true", dstHost, primaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("6.2 Verify egressIP load balancing from local pod.")
		egressipErr := wait.PollUntilContextTimeout(context.Background(), 100*time.Second, 100*time.Second, false, func(cxt context.Context) (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[0], true) != nil || checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[1], true) != nil || err != nil {
				e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump for local pod %s", freeIPs[0], freeIPs[1], pod1.name))

		compat_otp.By("6.3 Verify egressIP load balancing from remote pod.")
		egressipErr = wait.PollUntilContextTimeout(context.Background(), 100*time.Second, 100*time.Second, false, func(cxt context.Context) (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, pod2.namespace, pod2.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[0], true) != nil || checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[1], true) != nil || err != nil {
				e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump for remote pod %s", freeIPs[0], freeIPs[1], pod2.name))
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-79097-Traffic is load balanced between egress nodes for egressIP UDN (layer2 and IPv4 only) .[Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("1. Get two worker nodes that are in same subnet, they will be used as egress-assignable nodes, get a third node as non-egress node\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 || len(nodeList.Items) < 3 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		var nonEgressNode string
		for _, node := range nodeList.Items {
			if !contains(egressNodes, node.Name) {
				nonEgressNode = node.Name
				break
			}
		}

		compat_otp.By("2. Apply EgressLabel Key to nodes.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)

		compat_otp.By("3 Obtain first namespace, apply layer2 UDN CRD to it, add to the namespace with a label matching the namespaceSelector of egressIP object that will be created in step 4")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for hostnetworked sniffer pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		cidr := []string{"10.150.0.0/16"}
		ipv4cidr := []string{"10.150.0.0/16"}
		ipv6cidr := []string{"2010:100:200::0/48"}
		createGeneralUDNCRD(oc, ns1, "udn-network-layer2-"+ns1, ipv4cidr[0], ipv6cidr[0], cidr[0], "layer2")

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNodes[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-78453",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		//Replce matchLabel with matchExpressions
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-78453", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchExpressions\":[{\"key\": \"name\", \"operator\": \"In\", \"values\": [\"test\"]}]}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-78453", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchLabels\":null}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		compat_otp.By("5. Create two pods, one pod is local to egress node, another pod is remote to egress node ")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1-" + ns1,
			namespace: ns1,
			nodename:  egressNodes[0],
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		pod2 := pingPodResourceNode{
			name:      "hello-pod2-" + ns1,
			namespace: ns1,
			nodename:  nonEgressNode,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod2.name)

		compat_otp.By("6. Check source IP is randomly one of egress ips.\n")
		compat_otp.By("6.1 Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], "tcpdump", "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], "tcpdump", "true")
		primaryInf, infErr := getSnifPhyInf(oc, egressNodes[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost := nslookDomainName("ifconfig.me")
		defer deleteTcpdumpDS(oc, "tcpdump-78453", ns1)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-78453", "tcpdump", "true", dstHost, primaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("6.2 Verify egressIP load balancing from local pod.")
		egressipErr := wait.PollUntilContextTimeout(context.Background(), 100*time.Second, 100*time.Second, false, func(cxt context.Context) (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[0], true) != nil || checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[1], true) != nil || err != nil {
				e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump for local pod %s", freeIPs[0], freeIPs[1], pod1.name))

		compat_otp.By("6.3 Verify egressIP load balancing from remote pod.")
		egressipErr = wait.PollUntilContextTimeout(context.Background(), 100*time.Second, 100*time.Second, false, func(cxt context.Context) (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, pod2.namespace, pod2.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[0], true) != nil || checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[1], true) != nil || err != nil {
				e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump for remote pod %s", freeIPs[0], freeIPs[1], pod2.name))
	})

})

var _ = g.Describe("[OTP][sig-networking] SDN udn EgressIP IPv6", func() {
	defer g.GinkgoRecover()

	var (
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		dstHostv6       = "2620:52:0:800:3673:5aff:fe99:92f0"
		ipStackType     string
	)

	g.BeforeEach(func() {

		SkipIfNoFeatureGate(oc, "NetworkSegmentation")

		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com") || strings.Contains(msg, "offload.openshift-qe.sdn.com")) {
			g.Skip("This case will only run on rdu1 or rdu2 dual stack cluster. , skip for other envrionment!!!")
		}

		ipStackType = checkIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.Skip("It is not a dualsatck or singlev6 cluster, skip this test!!!")
		}

		if strings.Contains(msg, "offload.openshift-qe.sdn.com") {
			dstHostv6 = "2620:52:0:800:3673:5aff:fe98:d2d0"
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-77840-Validate egressIP with mixed of multiple non-overlapping UDNs and default network(layer3 and IPv6/dualstack) [Serial]", func() {

		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP1Template   = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		compat_otp.By("1 Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		var egressNode1, egressNode2, nonEgressNode string
		var freeIPs []string
		if ipStackType == "dualstack" && len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test on dualstack cluster, the prerequirement was not fullfilled, skip the case!!")
		}
		if ipStackType == "ipv6single" && len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test on singlev6 cluster, the prerequirement was not fullfilled, skip the case!!")
		}

		if ipStackType == "dualstack" {
			egressNode1 = nodeList.Items[0].Name
			egressNode2 = nodeList.Items[1].Name
			nonEgressNode = nodeList.Items[2].Name
			freeIPs = findFreeIPs(oc, egressNode1, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPv6s := findFreeIPv6s(oc, egressNode2, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPs = append(freeIPs, freeIPv6s[0])
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		} else if ipStackType == "ipv6single" {
			egressNode1 = nodeList.Items[0].Name
			nonEgressNode = nodeList.Items[1].Name
			freeIPs = findFreeIPv6s(oc, egressNode1, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		}
		e2e.Logf("egressIPs to use: %s", freeIPs)

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")

		compat_otp.By("2.1 Obtain first namespace for default network, create two more namespaces for two non-overlapping UDNs")
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns3 := oc.Namespace()
		udnNS := []string{ns2, ns3}
		allNS := []string{ns1, ns2, ns3}

		compat_otp.By("2.3 Apply a label to all namespaces that matches namespaceSelector definied in egressIP object")
		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name=test").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3. Create two different layer3 UDNs in namesapce ns1 and ns2")
		var cidr, ipv4cidr, ipv6cidr []string
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::0/48", "2011:100:200::0/48"}
		} else {
			ipv4cidr = []string{"10.150.0.0/16", "10.151.0.0/16"}
			ipv6cidr = []string{"2010:100:200::0/48", "2011:100:200::0/48"}
		}
		for i := 0; i < 2; i++ {
			if ipStackType == "ipv6single" {
				createGeneralUDNCRD(oc, udnNS[i], "udn-network-layer3-"+udnNS[i], "", "", cidr[i], "layer3")
			} else {
				createGeneralUDNCRD(oc, udnNS[i], "udn-network-layer3-"+udnNS[i], ipv4cidr[i], ipv6cidr[i], "", "layer3")
			}
		}

		compat_otp.By("4. Create an egressip object")
		egressip1 := egressIPResource1{
			name:      "egressip-77840",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		var assignedEIPNodev4, assignedEIPNodev6, assignedEIPv6Addr string
		if ipStackType == "dualstack" {
			o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
			for _, eipMap := range egressIPMaps1 {
				if netutils.IsIPv4String(eipMap["egressIP"]) {
					assignedEIPNodev4 = eipMap["node"]
				}
				if netutils.IsIPv6String(eipMap["egressIP"]) {
					assignedEIPNodev6 = eipMap["node"]
					assignedEIPv6Addr = eipMap["egressIP"]
				}
			}
			o.Expect(assignedEIPNodev4).NotTo(o.Equal(""))
			o.Expect(assignedEIPNodev6).NotTo(o.Equal(""))
			e2e.Logf("For the dualstack EIP,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)
		} else {
			o.Expect(len(egressIPMaps1) == 1).Should(o.BeTrue())
			assignedEIPNodev6 = egressNode1
			assignedEIPv6Addr = egressIPMaps1[0]["egressIP"]
		}

		compat_otp.By("5.1 In each namespace, create two test pods, the first one on egressNode, the second one on nonEgressNode ")
		compat_otp.By("5.2 Apply label to all pods that matches podSelector definied in egressIP object")
		testpods1 := make([]pingPodResourceNode, len(allNS))
		testpods2 := make([]pingPodResourceNode, len(allNS))
		testpods3 := make([]pingPodResourceNode, len(allNS))
		for i := 0; i < len(allNS); i++ {
			if ipStackType == "dualstack" {
				// testpods1 are local pods that co-locate on assignedEIPNodev4 for dualstack
				testpods1[i] = pingPodResourceNode{
					name:      "hello-pod1-" + allNS[i],
					namespace: allNS[i],
					nodename:  assignedEIPNodev4,
					template:  pingPodNodeTemplate,
				}
				testpods1[i].createPingPodNode(oc)
				waitPodReady(oc, allNS[i], testpods1[i].name)
			}

			// testpods2 are local pods that co-locate on assignedEIPNodev6
			testpods2[i] = pingPodResourceNode{
				name:      "hello-pod2-" + allNS[i],
				namespace: allNS[i],
				nodename:  assignedEIPNodev6,
				template:  pingPodNodeTemplate,
			}
			testpods2[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods2[i].name)

			// testpods3 are remote pods on the other non-egress node
			testpods3[i] = pingPodResourceNode{
				name:      "hello-pod3-" + allNS[i],
				namespace: allNS[i],
				nodename:  nonEgressNode,
				template:  pingPodNodeTemplate,
			}
			testpods3[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods3[i].name)
		}

		compat_otp.By("6. Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		e2e.Logf("Trying to get physical interface on the node,%s", egressNode1)
		primaryInf, infErr := getSnifPhyInf(oc, egressNode1)
		o.Expect(infErr).NotTo(o.HaveOccurred())

		for i := 0; i < len(allNS); i++ {
			if ipStackType == "dualstack" {
				compat_otp.By("6.1 Verify egressIP from IPv4 perspective")
				dstHostv4 := nslookDomainName("ifconfig.me")
				compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
				tcpdumpCmdv4 := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHostv4)
				_, cmdOnPodv4 := getRequestURL(dstHostv4)
				compat_otp.By("6.2 Verify v4 egressIP from test pods local to egress node")
				tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, allNS[i], testpods1[i].name, cmdOnPodv4)
				o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
				compat_otp.By("6.3 Verify v4 egressIP from test pods remote to egress node")
				tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, allNS[i], testpods3[i].name, cmdOnPodv4)
				o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
			}

			compat_otp.By("6.4 Verify egressIP from IPv6 perspective")
			tcpdumpCmdv6 := fmt.Sprintf("timeout 90s tcpdump -c 3 -nni %s ip6 and host %s", primaryInf, dstHostv6)
			_, cmdOnPodv6 := getRequestURL("[" + dstHostv6 + "]")
			compat_otp.By("6.5 Verify v6 egressIP from test pods local to egress node")
			tcpdumOutputv6 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, allNS[i], testpods2[i].name, cmdOnPodv6)
			o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
			compat_otp.By("6.6 Verify v6 egressIP from test pods remote to egress node")
			tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, allNS[i], testpods3[i].name, cmdOnPodv6)
			o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-77841-Validate egressIP with mixed of multiple overlapping UDNs and default network(layer3 and IPv6/dualstack) [Serial]", func() {

		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP1Template   = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		compat_otp.By("1 Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		var egressNode1, egressNode2, nonEgressNode string
		var freeIPs []string
		if ipStackType == "dualstack" && len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test on dualstack cluster, the prerequirement was not fullfilled, skip the case!!")
		}
		if ipStackType == "ipv6single" && len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test on singlev6 cluster, the prerequirement was not fullfilled, skip the case!!")
		}

		if ipStackType == "dualstack" {
			egressNode1 = nodeList.Items[0].Name
			egressNode2 = nodeList.Items[1].Name
			nonEgressNode = nodeList.Items[2].Name
			freeIPs = findFreeIPs(oc, egressNode1, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPv6s := findFreeIPv6s(oc, egressNode2, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPs = append(freeIPs, freeIPv6s[0])
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		} else if ipStackType == "ipv6single" {
			egressNode1 = nodeList.Items[0].Name
			nonEgressNode = nodeList.Items[1].Name
			freeIPs = findFreeIPv6s(oc, egressNode1, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		}
		e2e.Logf("egressIPs to use: %s", freeIPs)

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")

		compat_otp.By("2.1 Obtain first namespace for default network, create two more namespaces for two overlapping UDNs")
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns3 := oc.Namespace()
		udnNS := []string{ns2, ns3}
		allNS := []string{ns1, ns2, ns3}

		compat_otp.By("2.2 Apply a label to all namespaces that matches namespaceSelector definied in egressIP object")
		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name=test").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("3. Create two overlapping layer3 UDNs between namesapce ns1 and ns2")
		var cidr, ipv4cidr, ipv6cidr []string
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::0/48"}
		} else {
			ipv4cidr = []string{"10.150.0.0/16"}
			ipv6cidr = []string{"2010:100:200::0/48"}
		}
		for i := 0; i < 2; i++ {
			if ipStackType == "ipv6single" {
				createGeneralUDNCRD(oc, udnNS[i], "udn-network-layer3-"+udnNS[i], "", "", cidr[0], "layer3")
			} else {
				createGeneralUDNCRD(oc, udnNS[i], "udn-network-layer3-"+udnNS[i], ipv4cidr[0], ipv6cidr[0], "", "layer3")
			}
		}

		compat_otp.By("4. Create an egressip object")
		egressip1 := egressIPResource1{
			name:      "egressip-77841",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		var assignedEIPNodev4, assignedEIPNodev6, assignedEIPv6Addr string
		if ipStackType == "dualstack" {
			o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
			for _, eipMap := range egressIPMaps1 {
				if netutils.IsIPv4String(eipMap["egressIP"]) {
					assignedEIPNodev4 = eipMap["node"]
				}
				if netutils.IsIPv6String(eipMap["egressIP"]) {
					assignedEIPNodev6 = eipMap["node"]
					assignedEIPv6Addr = eipMap["egressIP"]
				}
			}
			o.Expect(assignedEIPNodev4).NotTo(o.Equal(""))
			o.Expect(assignedEIPNodev6).NotTo(o.Equal(""))
			e2e.Logf("For the dualstack EIP,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)
		} else {
			o.Expect(len(egressIPMaps1) == 1).Should(o.BeTrue())
			assignedEIPNodev6 = egressNode1
			assignedEIPv6Addr = egressIPMaps1[0]["egressIP"]
		}

		compat_otp.By("5.1 In each namespace, create two test pods, the first one on egressNode, the second one on nonEgressNode ")
		compat_otp.By("5.2 Apply label to all pods that matches podSelector definied in egressIP object")
		testpods1 := make([]pingPodResourceNode, len(allNS))
		testpods2 := make([]pingPodResourceNode, len(allNS))
		testpods3 := make([]pingPodResourceNode, len(allNS))
		for i := 0; i < len(allNS); i++ {
			if ipStackType == "dualstack" {
				// testpods1 are local pods that co-locate on assignedEIPNodev4 for dualstack
				testpods1[i] = pingPodResourceNode{
					name:      "hello-pod1-" + allNS[i],
					namespace: allNS[i],
					nodename:  assignedEIPNodev4,
					template:  pingPodNodeTemplate,
				}
				testpods1[i].createPingPodNode(oc)
				waitPodReady(oc, allNS[i], testpods1[i].name)
			}

			// testpods2 are local pods that co-locate on assignedEIPNodev6
			testpods2[i] = pingPodResourceNode{
				name:      "hello-pod2-" + allNS[i],
				namespace: allNS[i],
				nodename:  assignedEIPNodev6,
				template:  pingPodNodeTemplate,
			}
			testpods2[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods2[i].name)

			// testpods3 are remote pods on the other non-egress node
			testpods3[i] = pingPodResourceNode{
				name:      "hello-pod3-" + allNS[i],
				namespace: allNS[i],
				nodename:  nonEgressNode,
				template:  pingPodNodeTemplate,
			}
			testpods3[i].createPingPodNode(oc)
			waitPodReady(oc, allNS[i], testpods3[i].name)
		}

		compat_otp.By("6. Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		e2e.Logf("Trying to get physical interface on the node,%s", egressNode1)
		primaryInf, infErr := getSnifPhyInf(oc, egressNode1)
		o.Expect(infErr).NotTo(o.HaveOccurred())

		for i := 0; i < len(allNS); i++ {
			if ipStackType == "dualstack" {
				compat_otp.By("6.1 Verify egressIP from IPv4 perspective")
				dstHostv4 := nslookDomainName("ifconfig.me")
				compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
				tcpdumpCmdv4 := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHostv4)
				_, cmdOnPodv4 := getRequestURL(dstHostv4)
				compat_otp.By("6.2 Verify v4 egressIP from test pods local to egress node")
				tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, allNS[i], testpods1[i].name, cmdOnPodv4)
				o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
				compat_otp.By("6.3 Verify v4 egressIP from test pods remote to egress node")
				tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, allNS[i], testpods3[i].name, cmdOnPodv4)
				o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
			}

			compat_otp.By("6.4 Verify egressIP from IPv6 perspective")
			tcpdumpCmdv6 := fmt.Sprintf("timeout 60s tcpdump -c 3 -nni %s ip6 and host %s", primaryInf, dstHostv6)
			_, cmdOnPodv6 := getRequestURL("[" + dstHostv6 + "]")
			compat_otp.By("6.5 Verify v6 egressIP from test pods local to egress node")
			tcpdumOutputv6 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, allNS[i], testpods2[i].name, cmdOnPodv6)
			o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
			compat_otp.By("6.6 Verify v6 egressIP from test pods remote to egress node")
			tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, allNS[i], testpods3[i].name, cmdOnPodv6)
			o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-Longduration-NonPreRelease-High-77842-Validate egressIP Failover with non-overlapping and overlapping UDNs (layer3 and IPv6 only) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		compat_otp.By("1 Get node list, apply EgressLabel Key to one node to make it egressNode")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")

		compat_otp.By("2.1 Create three UDN namespaces")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns2 := oc.Namespace()
		oc.CreateNamespaceUDN()
		ns3 := oc.Namespace()
		udnNS := []string{ns1, ns2, ns3}

		compat_otp.By("3.1. Create non-overlapping layer3 UDNs between ns1 and ns2, overlapping layer3 UDN between ns2 and ns3")
		compat_otp.By("3.2 Apply a label to all namespaces that matches namespaceSelector definied in egressIP object")
		var cidr, ipv4cidr, ipv6cidr []string
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::0/60", "2011:100:200::0/60", "2011:100:200::0/60"}
		} else {
			ipv4cidr = []string{"10.150.0.0/16", "10.151.0.0/16", "10.151.0.0/16"}
			ipv6cidr = []string{"2010:100:200::0/60", "2011:100:200::0/60", "2011:100:200::0/60"}
		}
		for i := 0; i < len(udnNS); i++ {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", udnNS[i], "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", udnNS[i], "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			if ipStackType == "ipv6single" {
				createGeneralUDNCRD(oc, udnNS[i], "udn-network-layer3-"+udnNS[i], "", "", cidr[i], "layer3")
			} else {
				createGeneralUDNCRD(oc, udnNS[i], "udn-network-layer3-"+udnNS[i], ipv4cidr[i], ipv6cidr[i], "", "layer3")
			}
		}

		compat_otp.By("4. Create an egressip object, verify egressIP is assigned to egress node")
		freeIPs := findFreeIPv6s(oc, egressNodes[0], 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-77842",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNodes[0]))

		compat_otp.By("4.1 In each namespace, create two test pods, the first one on egressNode, the second one on nonEgressNode ")
		compat_otp.By("4.2 Apply label to all pods that matches podSelector definied in egressIP object")
		testpods1 := make([]pingPodResourceNode, len(udnNS))
		testpods2 := make([]pingPodResourceNode, len(udnNS))
		for i := 0; i < len(udnNS); i++ {
			// testpods1 are pods on egressNode
			testpods1[i] = pingPodResourceNode{
				name:      "hello-pod1-" + udnNS[i],
				namespace: udnNS[i],
				nodename:  egressNodes[0],
				template:  pingPodNodeTemplate,
			}
			testpods1[i].createPingPodNode(oc)
			waitPodReady(oc, udnNS[i], testpods1[i].name)
			defer compat_otp.LabelPod(oc, udnNS[i], testpods1[i].name, "color-")
			err = compat_otp.LabelPod(oc, udnNS[i], testpods1[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())

			// testpods2 are pods on nonEgressNode, egressNodes[1] is currently not a egress node as it has not been labelled with egressNodeLabel yet
			testpods2[i] = pingPodResourceNode{
				name:      "hello-pod2-" + udnNS[i],
				namespace: udnNS[i],
				nodename:  egressNodes[1],
				template:  pingPodNodeTemplate,
			}
			testpods2[i].createPingPodNode(oc)
			waitPodReady(oc, udnNS[i], testpods2[i].name)
			defer compat_otp.LabelPod(oc, udnNS[i], testpods2[i].name, "color-")
			err = compat_otp.LabelPod(oc, udnNS[i], testpods2[i].name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("5. Verify egressIP from each namespace, egress traffic from these pods should use egressIP as their sourceIP regardless it is from overlapping or non-overlapping UDN")
		var primaryInf, tcpdumpCmd, cmdOnPod string
		var infErr error
		compat_otp.By("5.1 Use tcpdump to verify egressIP.")
		e2e.Logf("Trying to get physical interface on the egressNode %s", egressNodes[0])
		primaryInf, infErr = getSnifPhyInf(oc, nodeList.Items[0].Name)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 3 -nni %s ip6 and host %s", primaryInf, dstHostv6)
		_, cmdOnPod = getRequestURL("[" + dstHostv6 + "]")

		compat_otp.By("5.2 Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		for i := 0; i < len(udnNS); i++ {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, udnNS[i], testpods1[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNodes[0], tcpdumpCmd, udnNS[i], testpods2[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("6. Label the second node with egressNodeLabel, unlabel the first node, verify egressIP still works after failover.\n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")

		compat_otp.By("7. Check the egress node was updated in the egressip object.\n")
		egressipErr := wait.PollUntilContextTimeout(context.Background(), 20*time.Second, 360*time.Second, false, func(cxt context.Context) (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 1 || egressIPMaps1[0]["node"] == egressNodes[0] {
				e2e.Logf("Wait for new egress node applied,try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to update egress node:%v", egressipErr))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNodes[1]))

		compat_otp.By("8. Validate egressIP again after egressIP failover \n")
		for i := 0; i < len(udnNS); i++ {
			compat_otp.By("8.1 Use tcpdump captured on egressNode to verify egressIP from local pods after egressIP failover")
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNodes[1], tcpdumpCmd, udnNS[i], testpods1[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
			compat_otp.By("8.2 Use tcpdump captured on egressNode to verify egressIP from remote pods after egressIP failover")
			tcpdumOutput = getTcpdumpOnNodeCmdFromPod(oc, egressNodes[1], tcpdumpCmd, udnNS[i], testpods2[i].name, cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-78247-egressIP still works correctly after a UDN network gets deleted then recreated (layer3 + v6 or dualstack) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP1Template   = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		compat_otp.By("1. Get node list, apply EgressLabel Key to one node to make it egressNode, for dualstack, need to label two nodes to be egressNodes")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		var egressNode1, egressNode2, nonEgressNode string
		var freeIPs []string
		if ipStackType == "dualstack" && len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test on dualstack cluster, the prerequirement was not fullfilled, skip the case!!")
		}
		if ipStackType == "ipv6single" && len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test on singlev6 cluster, the prerequirement was not fullfilled, skip the case!!")
		}

		if ipStackType == "dualstack" {
			egressNode1 = nodeList.Items[0].Name
			egressNode2 = nodeList.Items[1].Name
			nonEgressNode = nodeList.Items[2].Name
			freeIPs = findFreeIPs(oc, egressNode1, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPv6s := findFreeIPv6s(oc, egressNode2, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPs = append(freeIPs, freeIPv6s[0])
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		} else if ipStackType == "ipv6single" {
			egressNode1 = nodeList.Items[0].Name
			nonEgressNode = nodeList.Items[1].Name
			freeIPs = findFreeIPv6s(oc, egressNode1, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		}
		e2e.Logf("egressIPs to use: %s", freeIPs)

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")

		compat_otp.By("2. Obtain a namespace ns1, apply to ns1 with label that matches namespaceSelector definied in egressIP object")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3.1 Create a layer3 UDN in ns1")
		var cidr, ipv4cidr, ipv6cidr []string
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::0/48"}
		} else {
			ipv4cidr = []string{"10.150.0.0/16"}
			ipv6cidr = []string{"2010:100:200::0/48"}
		}

		if ipStackType == "ipv6single" {
			createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, "", "", cidr[0], "layer3")
		} else {
			createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], "", "layer3")
		}

		compat_otp.By("4. Create an egressip object")
		egressip1 := egressIPResource1{
			name:      "egressip-78247",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)

		// For dualstack, need to find out the actual nodes where v4 and v6 egressIP address are assigned
		var assignedEIPNodev4, assignedEIPNodev6, assignedEIPv6Addr string
		if ipStackType == "dualstack" {
			o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
			for _, eipMap := range egressIPMaps1 {
				if netutils.IsIPv4String(eipMap["egressIP"]) {
					assignedEIPNodev4 = eipMap["node"]
				}
				if netutils.IsIPv6String(eipMap["egressIP"]) {
					assignedEIPNodev6 = eipMap["node"]
					assignedEIPv6Addr = eipMap["egressIP"]
				}
			}
			o.Expect(assignedEIPNodev4).NotTo(o.Equal(""))
			o.Expect(assignedEIPNodev6).NotTo(o.Equal(""))
			e2e.Logf("For the dualstack EIP,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)
		} else {
			o.Expect(len(egressIPMaps1) == 1).Should(o.BeTrue())
			assignedEIPNodev6 = egressNode1
			assignedEIPv6Addr = egressIPMaps1[0]["egressIP"]
		}

		compat_otp.By("5.1 In the namespace, create local test pod on egressNode, create remote test pod on nonEgressNode ")
		var testpods []pingPodResourceNode
		var testpod1 pingPodResourceNode
		if ipStackType == "dualstack" {
			// testpod1 is local pod on assignedEIPNodev4 for dualstack
			testpod1 = pingPodResourceNode{
				name:      "hello-pod1-" + ns1,
				namespace: ns1,
				nodename:  assignedEIPNodev4,
				template:  pingPodNodeTemplate,
			}
			testpod1.createPingPodNode(oc)
			waitPodReady(oc, ns1, testpod1.name)
			testpods = append(testpods, testpod1)
		}

		// testpod2 is local pod on assignedEIPNodev6 for dualstack
		testpod2 := pingPodResourceNode{
			name:      "hello-pod2-" + ns1,
			namespace: ns1,
			nodename:  assignedEIPNodev6,
			template:  pingPodNodeTemplate,
		}
		testpod2.createPingPodNode(oc)
		waitPodReady(oc, ns1, testpod2.name)
		testpods = append(testpods, testpod2)

		// testpod3 is remote pod on the other non-egress node
		testpod3 := pingPodResourceNode{
			name:      "hello-pod3-" + ns1,
			namespace: ns1,
			nodename:  nonEgressNode,
			template:  pingPodNodeTemplate,
		}
		testpod3.createPingPodNode(oc)
		waitPodReady(oc, ns1, testpod3.name)
		testpods = append(testpods, testpod3)

		compat_otp.By("6. Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		primaryInf, infErr := getSnifPhyInf(oc, egressNode1)
		o.Expect(infErr).NotTo(o.HaveOccurred())

		var dstHostv4, tcpdumpCmdv4, cmdOnPodv4, tcpdumpCmdv6, cmdOnPodv6 string
		if ipStackType == "dualstack" {
			compat_otp.By("Verify egressIP from IPv4 perspective")
			dstHostv4 = nslookDomainName("ifconfig.me")
			compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
			tcpdumpCmdv4 = fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHostv4)
			_, cmdOnPodv4 = getRequestURL(dstHostv4)
			compat_otp.By("6.1 Verify v4 egressIP from test pods local to egress node")
			tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod1.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
			compat_otp.By("6.2 Verify v4 egressIP from test pods remote to egress node")
			tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod3.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("Verify egressIP from IPv6 perspective")
		tcpdumpCmdv6 = fmt.Sprintf("timeout 60s tcpdump -c 3 -nni %s ip6 and host %s", primaryInf, dstHostv6)
		_, cmdOnPodv6 = getRequestURL("[" + dstHostv6 + "]")
		compat_otp.By("6.3 Verify v6 egressIP from test pods local to egress node")
		tcpdumOutputv6 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod2.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
		compat_otp.By("6.4 Verify v6 egressIP from test pods remote to egress node")
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod3.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())

		compat_otp.By("7. Delete local and remote test pods that are associated with UDN in ns1 first, then delete the UDN.\n")
		for i := 0; i < len(testpods); i++ {
			removeResource(oc, true, true, "pod", testpods[i].name, "-n", testpods[i].namespace)
		}
		removeResource(oc, true, true, "UserDefinedNetwork", "udn-network-layer3-"+ns1, "-n", ns1)

		compat_otp.By("8. Recreate the UDN and local/remote test pods in ns1.\n")
		if ipStackType == "ipv6single" {
			createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, "", "", cidr[0], "layer3")
		} else {
			createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], "", "layer3")
		}

		for i := 0; i < len(testpods); i++ {
			testpods[i].createPingPodNode(oc)
			waitPodReady(oc, ns1, testpods[i].name)
		}

		compat_otp.By("9. Validate egressIP again from local and remote pods after recreating UDN \n")
		if ipStackType == "dualstack" {
			compat_otp.By("Verify egressIP from IPv4 perspective")
			compat_otp.By("9.1 Verify v4 egressIP from test pods local to egress node")
			tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod1.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
			compat_otp.By("9.2 Verify v4 egressIP from test pods remote to egress node")
			tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod3.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("Verify egressIP from IPv6 perspective")
		compat_otp.By("9.3 Verify v6 egressIP from test pods local to egress node")
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod2.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
		compat_otp.By("9.4 Verify v6 egressIP from test pods remote to egress node")
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod3.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-78274-egressIP still works correctly after OVNK restarted on local and remote client host (layer3 + v6 or dualstack) [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP1Template   = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		compat_otp.By("1. Get node list, apply EgressLabel Key to one node to make it egressNode, for dualstack, need to label two nodes to be egressNodes")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		var egressNode1, egressNode2, nonEgressNode string
		var freeIPs []string
		if ipStackType == "dualstack" && len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test on dualstack cluster, the prerequirement was not fullfilled, skip the case!!")
		}
		if ipStackType == "ipv6single" && len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test on singlev6 cluster, the prerequirement was not fullfilled, skip the case!!")
		}

		if ipStackType == "dualstack" {
			egressNode1 = nodeList.Items[0].Name
			egressNode2 = nodeList.Items[1].Name
			nonEgressNode = nodeList.Items[2].Name
			freeIPs = findFreeIPs(oc, egressNode1, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPv6s := findFreeIPv6s(oc, egressNode2, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPs = append(freeIPs, freeIPv6s[0])
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		} else if ipStackType == "ipv6single" {
			egressNode1 = nodeList.Items[0].Name
			nonEgressNode = nodeList.Items[1].Name
			freeIPs = findFreeIPv6s(oc, egressNode1, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		}
		e2e.Logf("egressIPs to use: %s", freeIPs)

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")

		compat_otp.By("2. Obtain a namespace, apply a label to the namespace that matches namespaceSelector definied in egressIP object")
		oc.CreateNamespaceUDN()
		ns1 := oc.Namespace()

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3. Create a layer3 UDN in ns1")
		var cidr, ipv4cidr, ipv6cidr []string
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::0/48"}
		} else {
			ipv4cidr = []string{"10.150.0.0/16"}
			ipv6cidr = []string{"2010:100:200::0/48"}
		}
		for i := 0; i < 2; i++ {
			if ipStackType == "ipv6single" {
				createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, "", "", cidr[0], "layer3")
			} else {
				createGeneralUDNCRD(oc, ns1, "udn-network-layer3-"+ns1, ipv4cidr[0], ipv6cidr[0], "", "layer3")
			}
		}

		compat_otp.By("4. Create an egressip object")
		egressip1 := egressIPResource1{
			name:      "egressip-78274",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)

		// For dualstack, need to find out the actual nodes where v4 and v6 egressIP address are assigned
		var assignedEIPNodev4, assignedEIPNodev6, assignedEIPv6Addr string
		if ipStackType == "dualstack" {
			o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
			for _, eipMap := range egressIPMaps1 {
				if netutils.IsIPv4String(eipMap["egressIP"]) {
					assignedEIPNodev4 = eipMap["node"]
				}
				if netutils.IsIPv6String(eipMap["egressIP"]) {
					assignedEIPNodev6 = eipMap["node"]
					assignedEIPv6Addr = eipMap["egressIP"]
				}
			}
			o.Expect(assignedEIPNodev4).NotTo(o.Equal(""))
			o.Expect(assignedEIPNodev6).NotTo(o.Equal(""))
			e2e.Logf("For the dualstack EIP,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)
		} else {
			o.Expect(len(egressIPMaps1) == 1).Should(o.BeTrue())
			assignedEIPNodev6 = egressNode1
			assignedEIPv6Addr = egressIPMaps1[0]["egressIP"]
		}

		compat_otp.By("5.1 In the namespace, create local test pod on egressNode, create remote test pod on nonEgressNode ")
		var testpod1, testpod2, testpod3 pingPodResourceNode
		if ipStackType == "dualstack" {
			// testpod1 is local pod on assignedEIPNodev4 for dualstack
			testpod1 = pingPodResourceNode{
				name:      "hello-pod1-" + ns1,
				namespace: ns1,
				nodename:  assignedEIPNodev4,
				template:  pingPodNodeTemplate,
			}
			testpod1.createPingPodNode(oc)
			waitPodReady(oc, ns1, testpod1.name)
		}

		// testpod2 is local pod on assignedEIPNodev6 for dualstack
		testpod2 = pingPodResourceNode{
			name:      "hello-pod2-" + ns1,
			namespace: ns1,
			nodename:  assignedEIPNodev6,
			template:  pingPodNodeTemplate,
		}
		testpod2.createPingPodNode(oc)
		waitPodReady(oc, ns1, testpod2.name)

		// testpod3 is remote pod on the other non-egress node
		testpod3 = pingPodResourceNode{
			name:      "hello-pod3-" + ns1,
			namespace: ns1,
			nodename:  nonEgressNode,
			template:  pingPodNodeTemplate,
		}
		testpod3.createPingPodNode(oc)
		waitPodReady(oc, ns1, testpod3.name)

		compat_otp.By("6. Use tcpdump captured on egressNode to verify egressIP from local pods and remote pods")
		primaryInf, infErr := getSnifPhyInf(oc, egressNode1)
		o.Expect(infErr).NotTo(o.HaveOccurred())

		var dstHostv4, tcpdumpCmdv4, cmdOnPodv4, tcpdumpCmdv6, cmdOnPodv6 string
		if ipStackType == "dualstack" {
			compat_otp.By("Verify egressIP from IPv4 perspective")
			dstHostv4 = nslookDomainName("ifconfig.me")
			compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
			tcpdumpCmdv4 = fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHostv4)
			_, cmdOnPodv4 = getRequestURL(dstHostv4)
			compat_otp.By("6.1 Verify v4 egressIP from test pods local to egress node")
			tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod1.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
			compat_otp.By("6.2 Verify v4 egressIP from test pods remote to egress node")
			tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod3.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("Verify egressIP from IPv6 perspective")
		tcpdumpCmdv6 = fmt.Sprintf("timeout 60s tcpdump -c 3 -nni %s ip6 and host %s", primaryInf, dstHostv6)
		_, cmdOnPodv6 = getRequestURL("[" + dstHostv6 + "]")
		compat_otp.By("6.3 Verify v6 egressIP from test pods local to egress node")
		tcpdumOutputv6 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod2.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
		compat_otp.By("6.4 Verify v6 egressIP from test pods remote to egress node")
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod3.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())

		compat_otp.By("7. Restart ovnkube-node pod of client host that local egressIP pod is on.\n")
		// Since local egressIP pod is on egress node, so just to restart ovnkube-pod of egress node
		ovnkPod := ovnkubeNodePod(oc, egressNode1)
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnkPod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		if ipStackType == "dualstack" {
			ovnkPod := ovnkubeNodePod(oc, egressNode2)
			err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnkPod, "-n", "openshift-ovn-kubernetes").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		}

		compat_otp.By("8. Validate egressIP again from local and remote pods after recreating UDN \n")
		if ipStackType == "dualstack" {
			compat_otp.By("Verify egressIP from IPv4 perspective")
			compat_otp.By("8.1 Verify v4 egressIP from test pods local to egress node")
			tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod1.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
			compat_otp.By("8.2 Verify v4 egressIP from test pods remote to egress node")
			tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod3.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("Verify egressIP from IPv6 perspective")
		compat_otp.By("8.3 Verify v6 egressIP from test pods local to egress node")
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod2.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
		compat_otp.By("8.4 Verify v6 egressIP from test pods remote to egress node")
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod3.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())

		compat_otp.By("9. Restart ovnkube-node pod of client host that remote egressIP pod is on.\n")
		// Since local egressIP pod is on egress node, so just to restart ovnkube-pod of egress node
		ovnkPod = ovnkubeNodePod(oc, nonEgressNode)
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnkPod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		compat_otp.By("10. Validate egressIP again from local and remote pods after recreating UDN \n")
		if ipStackType == "dualstack" {
			compat_otp.By("Verify egressIP from IPv4 perspective")
			compat_otp.By("10.1 Verify v4 egressIP from test pods local to egress node")
			tcpdumOutputv4 := getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod1.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
			compat_otp.By("10.2 Verify v4 egressIP from test pods remote to egress node")
			tcpdumOutputv4 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev4, tcpdumpCmdv4, ns1, testpod3.name, cmdOnPodv4)
			o.Expect(strings.Contains(tcpdumOutputv4, freeIPs[0])).To(o.BeTrue())
		}

		compat_otp.By("Verify egressIP from IPv6 perspective")
		compat_otp.By("10.3 Verify v6 egressIP from test pods local to egress node")
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod2.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
		compat_otp.By("10.4 Verify v6 egressIP from test pods remote to egress node")
		tcpdumOutputv6 = getTcpdumpOnNodeCmdFromPod(oc, assignedEIPNodev6, tcpdumpCmdv6, ns1, testpod3.name, cmdOnPodv6)
		o.Expect(strings.Contains(tcpdumOutputv6, assignedEIPv6Addr)).To(o.BeTrue())
	})
})
