package ovn

import (
	"context"
	"fmt"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/urfave/cli/v2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var _ = Describe("OVN Multi-Homed pod operations for layer2 network", func() {
	var (
		app       *cli.App
		fakeOvn   *FakeOVN
		initialDB libovsdbtest.TestSetup
	)

	BeforeEach(func() {
		Expect(config.PrepareTestConfig()).To(Succeed()) // reset defaults

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fakeOvn = NewFakeOVN(true)
		initialDB = libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{},
		}

		config.OVNKubernetesFeature = *minimalFeatureConfig()
		config.Gateway.V4MasqueradeSubnet = dummyMasqueradeSubnet().String()
	})

	AfterEach(func() {
		fakeOvn.shutdown()
	})

	table.DescribeTable(
		"reconciles a new",
		func(netInfo secondaryNetInfo, testConfig testConfiguration) {
			const podIdx = 0
			podInfo := dummyL2TestPod(ns, netInfo, podIdx)
			if testConfig.configToOverride != nil {
				config.OVNKubernetesFeature = *testConfig.configToOverride
			}
			app.Action = func(ctx *cli.Context) error {
				pod := newMultiHomedPod(podInfo, netInfo)

				const nodeIPv4CIDR = "192.168.126.202/24"
				By(fmt.Sprintf("Creating a node named %q, with IP: %s", nodeName, nodeIPv4CIDR))
				testNode, err := newNodeWithSecondaryNets(nodeName, nodeIPv4CIDR, netInfo)
				Expect(err).NotTo(HaveOccurred())
				Expect(setupFakeOvnForLayer2Topology(fakeOvn, initialDB, netInfo, testNode, podInfo, pod)).To(Succeed())

				// for layer2 on interconnect, it is the cluster manager that
				// allocates the OVN annotation; on unit tests, this just
				// doesn't happen, and we create the pod with these annotations
				// set. Hence, no point checking they're the expected ones.
				// TODO: align the mocked annotations with the production code
				//   - currently missing setting the routes.
				if !config.OVNKubernetesFeature.EnableInterconnect {
					By("asserting the pod OVN pod networks annotation are the expected ones")
					// check that after start networks annotations and nbdb will be updated
					Eventually(func() string {
						return getPodAnnotations(fakeOvn.fakeClient.KubeClient, podInfo.namespace, podInfo.podName)
					}).WithTimeout(2 * time.Second).Should(MatchJSON(podInfo.getAnnotationsJson()))
				}

				expectationOptions := testConfig.expectationOptions
				By("asserting the OVN entities provisioned in the NBDB are the expected ones")
				Eventually(fakeOvn.nbClient).Should(
					libovsdbtest.HaveData(
						newSecondaryNetworkExpectationMachine(
							fakeOvn,
							[]testPod{podInfo},
							expectationOptions...,
						).expectedLogicalSwitchesAndPorts()...))

				return nil
			}

			Expect(app.Run([]string{app.Name})).To(Succeed())
		},
		table.Entry("pod on a user defined secondary network",
			dummySecondaryLayer2UserDefinedNetwork("100.200.0.0/16"),
			nonICClusterTestConfiguration(),
		),
	)
})

func dummySecondaryLayer2UserDefinedNetwork(subnets string) secondaryNetInfo {
	return secondaryNetInfo{
		netName:  secondaryNetworkName,
		nadName:  namespacedName(ns, nadName),
		topology: ovntypes.Layer2Topology,
		subnets:  subnets,
	}
}

func dummyL2TestPod(nsName string, info secondaryNetInfo, podIdx int) testPod {
	const nodeSubnet = "10.128.1.0/24"
	pod := newTPod(nodeName, nodeSubnet, "10.128.1.2", "10.128.1.1", fmt.Sprintf("%s-%d", podName, podIdx), fmt.Sprintf("10.128.1.%d", podIdx+3), fmt.Sprintf("0a:58:0a:80:01:%0.2d", podIdx+3), nsName)
	pod.addNetwork(
		info.netName,
		info.nadName,
		info.subnets,
		"",
		"",
		fmt.Sprintf("100.200.0.%d/16", podIdx+1),
		fmt.Sprintf("0a:58:64:c8:00:%0.2d", podIdx+1),
		"secondary",
		0,
		[]util.PodRoute{},
	)
	return pod
}

func expectedLayer2EgressEntities(netInfo util.NetInfo, gwConfig util.L3GatewayConfig, nodeName string) []libovsdbtest.TestData {
	const (
		nat1              = "nat1-UUID"
		nat2              = "nat2-UUID"
		nat3              = "nat3-UUID"
		sr1               = "sr1-UUID"
		sr2               = "sr2-UUID"
		routerPolicyUUID1 = "lrp1-UUID"
	)
	gwRouterName := fmt.Sprintf("GR_%s_test-node", netInfo.GetNetworkName())
	staticRouteOutputPort := ovntypes.GWRouterToExtSwitchPrefix + gwRouterName
	gwRouterToNetworkSwitchPortName := ovntypes.GWRouterToJoinSwitchPrefix + gwRouterName
	gwRouterToExtSwitchPortName := fmt.Sprintf("%s%s", ovntypes.GWRouterToExtSwitchPrefix, gwRouterName)

	expectedEntities := []libovsdbtest.TestData{
		&nbdb.LogicalRouter{
			Name:         gwRouterName,
			UUID:         gwRouterName + "-UUID",
			Nat:          []string{nat1, nat2, nat3},
			Ports:        []string{gwRouterToNetworkSwitchPortName + "-UUID", gwRouterToExtSwitchPortName + "-UUID"},
			StaticRoutes: []string{sr1, sr2},
			ExternalIDs:  gwRouterExternalIDs(netInfo, gwConfig),
			Options:      gwRouterOptions(gwConfig),
			Policies:     []string{routerPolicyUUID1},
		},
		expectedGWToNetworkSwitchRouterPort(gwRouterToNetworkSwitchPortName, netInfo, gwRouterIPAddress(), layer2SubnetGWAddr()),
		expectedGRStaticRoute(sr1, dummyMasqueradeSubnet().String(), nextHopMasqueradeIP().String(), nil, &staticRouteOutputPort, netInfo),
		expectedGRStaticRoute(sr2, ipv4DefaultRoute().String(), nodeGateway().IP.String(), nil, &staticRouteOutputPort, netInfo),

		newNATEntry(nat1, dummyJoinIP().IP.String(), gwRouterIPAddress().IP.String(), standardNonDefaultNetworkExtIDs(netInfo)),
		newNATEntry(nat2, dummyJoinIP().IP.String(), layer2Subnet().String(), standardNonDefaultNetworkExtIDs(netInfo)),
		newNATEntry(nat3, dummyJoinIP().IP.String(), layer2SubnetGWAddr().IP.String(), standardNonDefaultNetworkExtIDs(netInfo)),

		expectedGRToExternalSwitchLRP(gwRouterName, netInfo, nodePhysicalIPAddress(), udnGWSNATAddress()),
		expectedStaticMACBinding(gwRouterName, nextHopMasqueradeIP()),

		expectedLogicalRouterPolicy(routerPolicyUUID1, netInfo, nodeName, nodeIP().IP.String(), managementPortIP(layer2Subnet()).String()),
	}

	for _, entity := range expectedExternalSwitchAndLSPs(netInfo, gwConfig, nodeName) {
		expectedEntities = append(expectedEntities, entity)
	}
	return expectedEntities
}

func expectedGWToNetworkSwitchRouterPort(name string, netInfo util.NetInfo, networks ...*net.IPNet) *nbdb.LogicalRouterPort {
	options := map[string]string{"gateway_mtu": fmt.Sprintf("%d", 1400)}
	return expectedLogicalRouterPort(name, netInfo, options, networks...)
}

func layer2Subnet() *net.IPNet {
	return &net.IPNet{
		IP:   net.ParseIP("100.200.0.0"),
		Mask: net.CIDRMask(16, 32),
	}
}

func layer2SubnetGWAddr() *net.IPNet {
	return &net.IPNet{
		IP:   net.ParseIP("100.200.0.1"),
		Mask: net.CIDRMask(16, 32),
	}
}

func nodeGateway() *net.IPNet {
	return &net.IPNet{
		IP:   net.ParseIP("192.168.126.1"),
		Mask: net.CIDRMask(24, 32),
	}
}

func ipv4DefaultRoute() *net.IPNet {
	return &net.IPNet{
		IP:   net.ParseIP("0.0.0.0"),
		Mask: net.CIDRMask(0, 32),
	}
}

func dummyLayer2SecondaryUserDefinedNetwork(subnets string) secondaryNetInfo {
	return secondaryNetInfo{
		netName:  secondaryNetworkName,
		nadName:  namespacedName(ns, nadName),
		topology: ovntypes.Layer2Topology,
		subnets:  subnets,
	}
}

func newSecondaryLayer2NetworkController(cnci *CommonNetworkControllerInfo, netInfo util.NetInfo, nodeName string) *SecondaryLayer2NetworkController {
	layer2NetworkController := NewSecondaryLayer2NetworkController(cnci, netInfo)
	layer2NetworkController.gatewayManagers.Store(
		nodeName,
		newDummyGatewayManager(cnci.kube, cnci.nbClient, netInfo, cnci.watchFactory, nodeName),
	)
	return layer2NetworkController
}

func nodeIP() *net.IPNet {
	return &net.IPNet{
		IP:   net.ParseIP("192.168.126.202"),
		Mask: net.CIDRMask(24, 32),
	}
}

func setupFakeOvnForLayer2Topology(fakeOvn *FakeOVN, initialDB libovsdbtest.TestSetup, netInfo secondaryNetInfo, testNode *v1.Node, podInfo testPod, pod *v1.Pod) error {
	By(fmt.Sprintf("creating a network attachment definition for network: %s", netInfo.netName))
	nad, err := newNetworkAttachmentDefinition(
		ns,
		nadName,
		*netInfo.netconf(),
	)
	if err != nil {
		return err
	}
	By("setting up the OVN DB without any entities in it")
	if err = netInfo.setupOVNDependencies(&initialDB); err != nil {
		return err
	}

	fakeOvn.startWithDBSetup(
		initialDB,
		&v1.NamespaceList{
			Items: []v1.Namespace{
				*newNamespace(ns),
			},
		},
		&v1.NodeList{Items: []v1.Node{*testNode}},
		&v1.PodList{
			Items: []v1.Pod{
				*pod,
			},
		},
		&nadapi.NetworkAttachmentDefinitionList{
			Items: []nadapi.NetworkAttachmentDefinition{*nad},
		},
	)
	podInfo.populateLogicalSwitchCache(fakeOvn)

	// on IC, the test itself spits out the pod with the
	// annotations set, since on production it would be the
	// clustermanager to annotate the pod.
	if !config.OVNKubernetesFeature.EnableInterconnect {
		By("asserting the pod originally does *not* feature the OVN pod networks annotation")
		// pod exists, networks annotations don't
		pod, err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(podInfo.namespace).Get(context.Background(), podInfo.podName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		_, ok := pod.Annotations[util.OvnPodAnnotationName]
		if ok {
			return fmt.Errorf("pod annotation %s is not expected", util.OvnPodAnnotationName)
		}
	}

	if err = fakeOvn.controller.WatchNamespaces(); err != nil {
		return err
	}
	if err = fakeOvn.controller.WatchPods(); err != nil {
		return err
	}
	By("asserting the pod (once reconciled) *features* the OVN pod networks annotation")
	secondaryNetController, ok := fakeOvn.secondaryControllers[secondaryNetworkName]
	if ok != true {
		return fmt.Errorf("secondary network controller %s is expected", secondaryNetworkName)
	}

	secondaryNetController.bnc.ovnClusterLRPToJoinIfAddrs = dummyJoinIPs()
	podInfo.populateSecondaryNetworkLogicalSwitchCache(fakeOvn, secondaryNetController)
	if err = secondaryNetController.bnc.WatchNodes(); err != nil {
		return err
	}
	if err = secondaryNetController.bnc.WatchPods(); err != nil {
		return err
	}
	return nil
}
