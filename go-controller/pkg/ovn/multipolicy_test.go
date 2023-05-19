package ovn

import (
	"context"
	"fmt"
	"net"
	"strings"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	mnpapi "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/urfave/cli/v2"

	ovncnitypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func convertNetPolicyToMultiNetPolicy(policy *knet.NetworkPolicy) *mnpapi.MultiNetworkPolicy {
	var mpolicy mnpapi.MultiNetworkPolicy
	var ipb *mnpapi.IPBlock

	mpolicy.Name = policy.Name
	mpolicy.Namespace = policy.Namespace
	mpolicy.Spec.PodSelector = policy.Spec.PodSelector
	mpolicy.Annotations = policy.Annotations
	mpolicy.Spec.Ingress = make([]mnpapi.MultiNetworkPolicyIngressRule, len(policy.Spec.Ingress))
	for i, ingress := range policy.Spec.Ingress {
		var mingress mnpapi.MultiNetworkPolicyIngressRule
		mingress.Ports = make([]mnpapi.MultiNetworkPolicyPort, len(ingress.Ports))
		for j, port := range ingress.Ports {
			mingress.Ports[j] = mnpapi.MultiNetworkPolicyPort{
				Protocol: port.Protocol,
				Port:     port.Port,
			}
		}
		mingress.From = make([]mnpapi.MultiNetworkPolicyPeer, len(ingress.From))
		for j, from := range ingress.From {
			ipb = nil
			if from.IPBlock != nil {
				ipb = &mnpapi.IPBlock{CIDR: from.IPBlock.CIDR, Except: from.IPBlock.Except}
			}
			mingress.From[j] = mnpapi.MultiNetworkPolicyPeer{
				PodSelector:       from.PodSelector,
				NamespaceSelector: from.NamespaceSelector,
				IPBlock:           ipb,
			}
		}
		mpolicy.Spec.Ingress[i] = mingress
	}
	mpolicy.Spec.Egress = make([]mnpapi.MultiNetworkPolicyEgressRule, len(policy.Spec.Egress))
	for i, egress := range policy.Spec.Egress {
		var megress mnpapi.MultiNetworkPolicyEgressRule
		megress.Ports = make([]mnpapi.MultiNetworkPolicyPort, len(egress.Ports))
		for j, port := range egress.Ports {
			megress.Ports[j] = mnpapi.MultiNetworkPolicyPort{
				Protocol: port.Protocol,
				Port:     port.Port,
			}
		}
		megress.To = make([]mnpapi.MultiNetworkPolicyPeer, len(egress.To))
		for j, to := range egress.To {
			ipb = nil
			if to.IPBlock != nil {
				ipb = &mnpapi.IPBlock{CIDR: to.IPBlock.CIDR, Except: to.IPBlock.Except}
			}
			megress.To[j] = mnpapi.MultiNetworkPolicyPeer{
				PodSelector:       to.PodSelector,
				NamespaceSelector: to.NamespaceSelector,
				IPBlock:           ipb,
			}
		}
		mpolicy.Spec.Egress[i] = megress
	}
	mpolicy.Spec.PolicyTypes = make([]mnpapi.MultiPolicyType, len(policy.Spec.PolicyTypes))
	for i, policytype := range policy.Spec.PolicyTypes {
		mpolicy.Spec.PolicyTypes[i] = mnpapi.MultiPolicyType(policytype)
	}
	return &mpolicy
}

func (p testPod) addNetwork(netName, nadName, nodeSubnet, nodeMgtIP, nodeGWIP, podIP, podMAC string) {
	podInfo, ok := p.secondaryPodInfos[netName]
	if !ok {
		podInfo = &secondaryPodInfo{
			nodeSubnet:  nodeSubnet,
			nodeMgtIP:   nodeMgtIP,
			nodeGWIP:    nodeGWIP,
			allportInfo: map[string]portInfo{},
		}
		p.secondaryPodInfos[netName] = podInfo
	}
	portName := util.GetSecondaryNetworkLogicalPortName(p.namespace, p.podName, nadName)
	podInfo.allportInfo[nadName] = portInfo{
		portUUID: portName + "-UUID",
		podIP:    podIP,
		podMAC:   podMAC,
		portName: portName,
	}
}

func (p testPod) getNetworkPortInfo(netName, nadName string) *portInfo {
	podInfo, ok := p.secondaryPodInfos[netName]
	if !ok {
		return nil
	}
	info, ok := podInfo.allportInfo[nadName]
	if !ok {
		return nil
	}

	return &info
}

func addPodNetwork(pod *v1.Pod, secondaryPodInfos map[string]*secondaryPodInfo) {
	nadNames := []string{}
	for _, podInfo := range secondaryPodInfos {
		for nadName := range podInfo.allportInfo {
			nadNames = append(nadNames, nadName)
		}
	}
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[nettypes.NetworkAttachmentAnnot] = strings.Join(nadNames, ",")
}

func (p testPod) populateSecondaryNetworkLogicalSwitchCache(fakeOvn *FakeOVN, ocInfo secondaryControllerInfo) {
	var err error
	switch ocInfo.bnc.TopologyType() {
	case ovntypes.Layer3Topology:
		podInfo := p.secondaryPodInfos[ocInfo.bnc.GetNetworkName()]
		uuid := getLogicalSwitchUUID(fakeOvn.controller.nbClient, ocInfo.bnc.GetNetworkScopedName(p.nodeName))
		err = ocInfo.bnc.lsManager.AddSwitch(ocInfo.bnc.GetNetworkScopedName(p.nodeName), uuid, []*net.IPNet{ovntest.MustParseIPNet(podInfo.nodeSubnet)})
	case ovntypes.Layer2Topology:
		uuid := getLogicalSwitchUUID(fakeOvn.controller.nbClient, ocInfo.bnc.GetNetworkScopedName(ovntypes.OVNLayer2Switch))
		subnet := ocInfo.bnc.Subnets()[0]
		err = ocInfo.bnc.lsManager.AddSwitch(ocInfo.bnc.GetNetworkScopedName(ovntypes.OVNLayer2Switch), uuid, []*net.IPNet{subnet.CIDR})
	case ovntypes.LocalnetTopology:
		uuid := getLogicalSwitchUUID(fakeOvn.controller.nbClient, ocInfo.bnc.GetNetworkScopedName(ovntypes.OVNLayer2Switch))
		subnet := ocInfo.bnc.Subnets()[0]
		err = ocInfo.bnc.lsManager.AddSwitch(ocInfo.bnc.GetNetworkScopedName(ovntypes.OVNLocalnetSwitch), uuid, []*net.IPNet{subnet.CIDR})
	}
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

func getExpectedDataPodsAndSwitchesForSecondaryNetwork(fakeOvn *FakeOVN, pods []testPod) []libovsdb.TestData {
	data := []libovsdb.TestData{}
	for _, ocInfo := range fakeOvn.secondaryControllers {
		nodeslsps := make(map[string][]string)
		var switchName string
		for _, pod := range pods {
			podInfo, ok := pod.secondaryPodInfos[ocInfo.bnc.GetNetworkName()]
			if !ok {
				continue
			}
			for nad, portInfo := range podInfo.allportInfo {
				portName := portInfo.portName
				var lspUUID string
				if len(portInfo.portUUID) == 0 {
					lspUUID = portName + "-UUID"
				} else {
					lspUUID = portInfo.portUUID
				}
				podAddr := fmt.Sprintf("%s %s", portInfo.podMAC, portInfo.podIP)
				lsp := &nbdb.LogicalSwitchPort{
					UUID:      lspUUID,
					Name:      portName,
					Addresses: []string{podAddr},
					ExternalIDs: map[string]string{
						"pod":                       "true",
						"namespace":                 pod.namespace,
						ovntypes.NetworkExternalID:  ocInfo.bnc.GetNetworkName(),
						ovntypes.NADExternalID:      nad,
						ovntypes.TopologyExternalID: ocInfo.bnc.TopologyType(),
					},
					Options: map[string]string{
						"requested-chassis": pod.nodeName,
						"iface-id-ver":      pod.podName,
					},

					PortSecurity: []string{podAddr},
				}
				if pod.noIfaceIdVer {
					delete(lsp.Options, "iface-id-ver")
				}
				data = append(data, lsp)
				switch ocInfo.bnc.TopologyType() {
				case ovntypes.Layer3Topology:
					switchName = ocInfo.bnc.GetNetworkScopedName(pod.nodeName)
				case ovntypes.Layer2Topology:
					switchName = ocInfo.bnc.GetNetworkScopedName(ovntypes.OVNLayer2Switch)
				case ovntypes.LocalnetTopology:
					switchName = ocInfo.bnc.GetNetworkScopedName(ovntypes.OVNLocalnetSwitch)
				}
				nodeslsps[switchName] = append(nodeslsps[switchName], lspUUID)
			}
			data = append(data, &nbdb.LogicalSwitch{
				UUID:        switchName + "-UUID",
				Name:        switchName,
				Ports:       nodeslsps[switchName],
				ExternalIDs: map[string]string{ovntypes.NetworkExternalID: ocInfo.bnc.GetNetworkName()},
			})
		}
	}
	return data
}

func getMultiPolicyData(networkPolicy *knet.NetworkPolicy, localPortUUIDs []string, peerNamespaces []string,
	tcpPeerPorts []int32, netInfo util.NetInfo) []libovsdb.TestData {
	return getPolicyDataHelper(networkPolicy, localPortUUIDs, peerNamespaces, tcpPeerPorts, "",
		false, false, netInfo)
}

func getMultiDefaultDenyData(networkPolicy *knet.NetworkPolicy, ports []string, netInfo util.NetInfo) []libovsdb.TestData {
	policyTypeIngress, policyTypeEgress := getPolicyType(networkPolicy)
	return getDefaultDenyDataHelper(networkPolicy.Namespace, policyTypeIngress, policyTypeEgress,
		ports, "", "", netInfo)
}

var _ = ginkgo.Describe("OVN MultiNetworkPolicy Operations", func() {
	const (
		namespaceName1              = "namespace1"
		namespaceName2              = "namespace2"
		netPolicyName1              = "networkpolicy1"
		nodeName                    = "node1"
		secondaryNetworkName        = "network1"
		nadName                     = "nad1"
		labelName            string = "pod-name"
		labelVal             string = "server"
		portNum              int32  = 81
	)
	var (
		app       *cli.App
		fakeOvn   *FakeOVN
		initialDB libovsdb.TestSetup

		gomegaFormatMaxLength int
		nad                   *nettypes.NetworkAttachmentDefinition
		netInfo               util.NetInfo
	)

	ginkgo.BeforeEach(func() {
		var err error
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		config.OVNKubernetesFeature.EnableMultiNetwork = true
		config.OVNKubernetesFeature.EnableMultiNetworkPolicy = true

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fakeOvn = NewFakeOVN(true)

		gomegaFormatMaxLength = format.MaxLength
		format.MaxLength = 0
		logicalSwitch := &nbdb.LogicalSwitch{
			Name: nodeName,
			UUID: nodeName + "_UUID",
		}
		logicalLayer2Switch := &nbdb.LogicalSwitch{
			Name:        secondaryNetworkName + "_" + ovntypes.OVNLayer2Switch,
			UUID:        secondaryNetworkName + "_" + ovntypes.OVNLayer2Switch + "_UUID",
			ExternalIDs: map[string]string{ovntypes.NetworkExternalID: secondaryNetworkName},
		}
		initialData := getHairpinningACLsV4AndPortGroup()
		initialData = append(initialData, logicalSwitch)
		initialData = append(initialData, logicalLayer2Switch)
		initialDB = libovsdb.TestSetup{
			NBData: initialData,
		}
		nad, err = newNetworkAttachmentDefinition(
			namespaceName1,
			nadName,
			ovncnitypes.NetConf{
				NetConf: cnitypes.NetConf{
					Name: secondaryNetworkName,
					Type: "ovn-k8s-cni-overlay",
				},
				Topology: ovntypes.Layer2Topology,
				NADName:  util.GetNADName(namespaceName1, nadName),
				Subnets:  "10.1.1.1/24",
			},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		netconf, err := util.ParseNetConf(nad)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		netInfo, err = util.NewNetInfo(netconf)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.AfterEach(func() {
		fakeOvn.shutdown()
		format.MaxLength = gomegaFormatMaxLength
	})

	startOvn := func(dbSetup libovsdb.TestSetup, namespaces []v1.Namespace, networkPolicies []knet.NetworkPolicy,
		multinetworkPolicies []mnpapi.MultiNetworkPolicy, nads []nettypes.NetworkAttachmentDefinition,
		pods []testPod, podLabels map[string]string) {
		var podsList []v1.Pod
		for _, testPod := range pods {
			knetPod := newPod(testPod.namespace, testPod.podName, testPod.nodeName, testPod.podIP)
			if len(podLabels) > 0 {
				knetPod.Labels = podLabels
			}
			addPodNetwork(knetPod, testPod.secondaryPodInfos)
			podsList = append(podsList, *knetPod)
		}
		fakeOvn.startWithDBSetup(dbSetup,
			&v1.NamespaceList{
				Items: namespaces,
			},
			&v1.PodList{
				Items: podsList,
			},
			&v1.NodeList{
				Items: []v1.Node{
					*newNode("node1", "192.168.126.202/24"),
				},
			},
			&knet.NetworkPolicyList{
				Items: networkPolicies,
			},
			&mnpapi.MultiNetworkPolicyList{
				Items: multinetworkPolicies,
			},
			&nettypes.NetworkAttachmentDefinitionList{
				Items: nads,
			},
		)
		ocInfo, ok := fakeOvn.secondaryControllers[secondaryNetworkName]
		gomega.Expect(ok).To(gomega.Equal(true))

		for _, testPod := range pods {
			testPod.populateLogicalSwitchCache(fakeOvn, getLogicalSwitchUUID(fakeOvn.controller.nbClient, nodeName))
		}
		var err error
		if namespaces != nil {
			err = fakeOvn.controller.WatchNamespaces()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
		asf := ocInfo.asf
		gomega.Expect(asf).NotTo(gomega.Equal(nil))
		gomega.Expect(asf.ControllerName).To(gomega.Equal(secondaryNetworkName + "-network-controller"))

		if pods != nil {
			err = fakeOvn.controller.WatchPods()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
		err = fakeOvn.controller.WatchNetworkPolicy()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		for _, ocInfo := range fakeOvn.secondaryControllers {
			for _, testPod := range pods {
				testPod.populateSecondaryNetworkLogicalSwitchCache(fakeOvn, ocInfo)
			}
			if namespaces != nil {
				err = ocInfo.bnc.WatchNamespaces()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}
			if pods != nil {
				err = ocInfo.bnc.WatchPods()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}
			err = ocInfo.bnc.WatchMultiNetworkPolicy()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
	}

	getUpdatedInitialDB := func(tPods []testPod) []libovsdb.TestData {
		updatedSwitchAndPods := getExpectedDataPodsAndSwitches(tPods, []string{nodeName})
		secondarySwitchAndPods := getExpectedDataPodsAndSwitchesForSecondaryNetwork(fakeOvn, tPods)
		if len(secondarySwitchAndPods) != 0 {
			updatedSwitchAndPods = append(updatedSwitchAndPods, secondarySwitchAndPods...)
		}
		return append(getHairpinningACLsV4AndPortGroup(), updatedSwitchAndPods...)
	}

	ginkgo.Context("during execution", func() {
		ginkgo.It("correctly creating an multinetworkPolicy with a peer namespace label", func() {
			app.Action = func(ctx *cli.Context) error {
				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)
				policy := getMatchLabelsNetworkPolicy(netPolicyName1, namespace1.Name,
					namespace2.Name, "", true, true)
				policy.Annotations = map[string]string{PolicyForAnnotation: util.GetNADName(nad.Namespace, nad.Name)}
				mpolicy := convertNetPolicyToMultiNetPolicy(policy)
				startOvn(initialDB, []v1.Namespace{namespace1, namespace2}, nil, nil,
					[]nettypes.NetworkAttachmentDefinition{*nad}, nil, nil)

				_, err := fakeOvn.fakeClient.MultiNetworkPolicyClient.K8sCniCncfIoV1beta1().MultiNetworkPolicies(mpolicy.Namespace).
					Create(context.TODO(), mpolicy, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				_, err = fakeOvn.fakeClient.MultiNetworkPolicyClient.K8sCniCncfIoV1beta1().MultiNetworkPolicies(mpolicy.Namespace).
					Get(context.TODO(), mpolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				ocInfo := fakeOvn.secondaryControllers[secondaryNetworkName]
				ocInfo.asf.EventuallyExpectEmptyAddressSetExist(namespaceName1)
				ocInfo.asf.EventuallyExpectEmptyAddressSetExist(namespaceName2)

				gressPolicyExpectedData := getMultiPolicyData(policy, nil, []string{namespace2.Name},
					nil, netInfo)
				defaultDenyExpectedData := getMultiDefaultDenyData(policy, nil, netInfo)
				expectedData := initialDB.NBData
				expectedData = append(expectedData, gressPolicyExpectedData...)
				expectedData = append(expectedData, defaultDenyExpectedData...)

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdb.HaveData(expectedData))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("correctly creates and deletes network policy and multi network policy with the same policy", func() {
			app.Action = func(ctx *cli.Context) error {
				namespace1 := *newNamespace(namespaceName1)
				nPodTest := getTestPod(namespace1.Name, nodeName)
				nPodTest.addNetwork(secondaryNetworkName, util.GetNADName(nad.Namespace, nad.Name), "", "", "", "10.1.1.1", "0a:58:0a:01:01:01")
				networkPolicy := getPortNetworkPolicy(netPolicyName1, namespace1.Name, labelName, labelVal, portNum)
				startOvn(initialDB, []v1.Namespace{namespace1}, nil, nil,
					[]nettypes.NetworkAttachmentDefinition{*nad}, []testPod{nPodTest}, map[string]string{labelName: labelVal})

				ginkgo.By("Creating networkPolicy applied to the pod")
				_, err := fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).
					Create(context.TODO(), networkPolicy, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				_, err = fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).
					Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				fakeOvn.asf.ExpectAddressSetWithIPs(namespaceName1, []string{nPodTest.podIP})

				gressPolicyExpectedData1 := getPolicyData(networkPolicy, []string{nPodTest.portUUID},
					nil, []int32{portNum})
				defaultDenyExpectedData1 := getDefaultDenyData(networkPolicy, []string{nPodTest.portUUID})
				initData := getUpdatedInitialDB([]testPod{nPodTest})
				expectedData1 := append(initData, gressPolicyExpectedData1...)
				expectedData1 = append(expectedData1, defaultDenyExpectedData1...)
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdb.HaveData(expectedData1...))

				ginkgo.By("Creating multi-networkPolicy applied to the pod")
				mpolicy := convertNetPolicyToMultiNetPolicy(networkPolicy)
				mpolicy.Annotations = map[string]string{PolicyForAnnotation: util.GetNADName(nad.Namespace, nad.Name)}

				_, err = fakeOvn.fakeClient.MultiNetworkPolicyClient.K8sCniCncfIoV1beta1().MultiNetworkPolicies(mpolicy.Namespace).
					Create(context.TODO(), mpolicy, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				_, err = fakeOvn.fakeClient.MultiNetworkPolicyClient.K8sCniCncfIoV1beta1().MultiNetworkPolicies(mpolicy.Namespace).
					Get(context.TODO(), mpolicy.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				ocInfo := fakeOvn.secondaryControllers[secondaryNetworkName]
				portInfo := nPodTest.getNetworkPortInfo(secondaryNetworkName, util.GetNADName(nad.Namespace, nad.Name))
				gomega.Expect(portInfo).NotTo(gomega.Equal(nil))
				ocInfo.asf.ExpectAddressSetWithIPs(namespaceName1, []string{portInfo.podIP})

				gressPolicyExpectedData2 := getMultiPolicyData(networkPolicy, []string{portInfo.portUUID}, nil,
					[]int32{portNum}, netInfo)
				defaultDenyExpectedData2 := getMultiDefaultDenyData(networkPolicy, []string{portInfo.portUUID}, netInfo)
				expectedData2 := append(expectedData1, gressPolicyExpectedData2...)
				expectedData2 = append(expectedData2, defaultDenyExpectedData2...)
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdb.HaveData(expectedData2...))

				// Delete the multi network policy
				ginkgo.By("Deleting the multi network policy")
				err = fakeOvn.fakeClient.MultiNetworkPolicyClient.K8sCniCncfIoV1beta1().MultiNetworkPolicies(mpolicy.Namespace).
					Delete(context.TODO(), mpolicy.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// TODO: test server does not garbage collect ACLs, so we just expect policy & deny portgroups to be removed
				expectedData3 := append(expectedData1, gressPolicyExpectedData2[:len(gressPolicyExpectedData1)-1]...)
				expectedData3 = append(expectedData3, defaultDenyExpectedData2[:len(defaultDenyExpectedData2)-2]...)
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdb.HaveData(expectedData3))

				ginkgo.By("Deleting the network policy")
				err = fakeOvn.fakeClient.KubeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).
					Delete(context.TODO(), networkPolicy.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// TODO: test server does not garbage collect ACLs, so we just expect policy & deny portgroups to be removed
				expectedData4 := append(initData, gressPolicyExpectedData1[:len(gressPolicyExpectedData1)-1]...)
				expectedData4 = append(expectedData4, gressPolicyExpectedData2[:len(gressPolicyExpectedData2)-1]...)
				expectedData4 = append(expectedData4, defaultDenyExpectedData1[:len(defaultDenyExpectedData1)-2]...)
				expectedData4 = append(expectedData4, defaultDenyExpectedData2[:len(defaultDenyExpectedData2)-2]...)
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdb.HaveData(expectedData4))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})
})
