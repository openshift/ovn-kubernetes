package ovn

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	cm "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/clustermanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	egressqosfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressqos/v1/apis/clientset/versioned/fake"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	lsm "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

var _ = ginkgo.Describe("OVN Interconnect Operations", func() {
	var (
		app             *cli.App
		f               *factory.WatchFactory
		stopChan        chan struct{}
		wg              *sync.WaitGroup
		libovsdbCleanup *libovsdbtest.Cleanup
		fakeClient      *util.OVNClientset
		kubeFakeClient  *fake.Clientset
		node1           tNode
		node2           tNode
		node3           tNode
		testNode1       v1.Node
		testNode2       v1.Node
		testNode3       v1.Node
		node1Annotator  kube.Annotator
		node2Annotator  kube.Annotator
		node3Annotator  kube.Annotator
		node1HostAddrs  sets.String
		node2HostAddrs  sets.String
		node3HostAddrs  sets.String
		node1Chassis    sbdb.Chassis
		node2Chassis    sbdb.Chassis
		node3Chassis    sbdb.Chassis
		initialNBDB     []libovsdbtest.TestData
		initialSBDB     []libovsdbtest.TestData
	)

	const (
		clusterIPNet   string = "10.1.0.0"
		clusterCIDR    string = clusterIPNet + "/16"
		joinSubnetCIDR string = "100.64.0.0/16/19"
		vlanID                = 1024
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		//gomega.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
		stopChan = make(chan struct{})
		wg = &sync.WaitGroup{}
		libovsdbCleanup = nil

		node1Chassis = sbdb.Chassis{Name: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6", Hostname: "node1", UUID: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6"}
		node2Chassis = sbdb.Chassis{Name: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac7", Hostname: "node2", UUID: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac7"}
		node3Chassis = sbdb.Chassis{Name: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac8", Hostname: "node3", UUID: "cb9ec8fa-b409-4ef3-9f42-d9283c47aac8"}

		node1 = tNode{
			Name:                 "node1",
			NodeIP:               "1.2.3.4",
			NodeLRPMAC:           "0a:58:0a:01:01:02",
			LrpIP:                "100.64.0.2",
			LrpIPv6:              "fd98::2",
			DrLrpIP:              "100.64.0.1",
			PhysicalBridgeMAC:    "11:22:33:44:55:01",
			SystemID:             node1Chassis.UUID,
			NodeSubnet:           "10.1.1.0/24",
			GWRouter:             types.GWRouterPrefix + "node1",
			GatewayRouterIPMask:  "172.16.16.2/24",
			GatewayRouterIP:      "172.16.16.2",
			GatewayRouterNextHop: "172.16.16.1",
			PhysicalBridgeName:   "br-eth0",
			NodeGWIP:             "10.1.1.1/24",
			NodeMgmtPortIP:       "10.1.1.2",
			NodeMgmtPortMAC:      "0a:58:0a:01:01:01",
			DnatSnatIP:           "169.254.0.1",
		}

		node2 = tNode{
			Name:                 "node2",
			NodeIP:               "1.2.3.5",
			NodeLRPMAC:           "0a:58:0a:01:01:03",
			LrpIP:                "100.64.0.3",
			LrpIPv6:              "fd98::3",
			DrLrpIP:              "100.64.0.1",
			PhysicalBridgeMAC:    "11:22:33:44:55:02",
			SystemID:             node2Chassis.UUID,
			NodeSubnet:           "10.1.2.0/24",
			GWRouter:             types.GWRouterPrefix + "node2",
			GatewayRouterIPMask:  "172.16.16.2/24",
			GatewayRouterIP:      "172.16.16.2",
			GatewayRouterNextHop: "172.16.16.1",
			PhysicalBridgeName:   "br-eth0",
			NodeGWIP:             "10.1.1.1/24",
			NodeMgmtPortIP:       "10.1.1.2",
			NodeMgmtPortMAC:      "0a:58:0a:01:01:02",
			DnatSnatIP:           "169.254.0.1",
		}

		node3 = tNode{
			Name:                 "node3",
			NodeIP:               "1.2.3.6",
			NodeLRPMAC:           "0a:58:0a:01:01:04",
			LrpIP:                "100.64.0.4",
			LrpIPv6:              "fd98::4",
			DrLrpIP:              "100.64.0.1",
			PhysicalBridgeMAC:    "11:22:33:44:55:03",
			SystemID:             node3Chassis.UUID,
			NodeSubnet:           "10.1.3.0/24",
			GWRouter:             types.GWRouterPrefix + "node3",
			GatewayRouterIPMask:  "172.16.16.2/24",
			GatewayRouterIP:      "172.16.16.2",
			GatewayRouterNextHop: "172.16.16.1",
			PhysicalBridgeName:   "br-eth0",
			NodeGWIP:             "10.1.1.1/24",
			NodeMgmtPortIP:       "10.1.1.2",
			NodeMgmtPortMAC:      "0a:58:0a:01:01:03",
			DnatSnatIP:           "169.254.0.1",
		}

		testNode1 = node1.k8sNode()
		testNode2 = node2.k8sNode()
		testNode3 = node3.k8sNode()

		gr := types.GWRouterPrefix + node1.Name
		node1_gw_datapath := &sbdb.DatapathBinding{
			UUID:        gr + "-UUID",
			ExternalIDs: map[string]string{"logical-router": gr + "-UUID", "name": gr},
		}

		gr = types.GWRouterPrefix + node2.Name
		node2_gw_datapath := &sbdb.DatapathBinding{
			UUID:        gr + "-UUID",
			ExternalIDs: map[string]string{"logical-router": gr + "-UUID", "name": gr},
		}

		gr = types.GWRouterPrefix + node3.Name
		node3_gw_datapath := &sbdb.DatapathBinding{
			UUID:        gr + "-UUID",
			ExternalIDs: map[string]string{"logical-router": gr + "-UUID", "name": gr},
		}

		initialNBDB = []libovsdbtest.TestData{
			newClusterJoinSwitch(),
			newOVNClusterRouter(),
			newRouterPortGroup(),
			newClusterPortGroup(),
		}

		initialSBDB = []libovsdbtest.TestData{
			&node1Chassis, &node2Chassis, &node3Chassis,
			node1_gw_datapath, node2_gw_datapath, node3_gw_datapath}

		egressFirewallFakeClient := &egressfirewallfake.Clientset{}
		egressIPFakeClient := &egressipfake.Clientset{}
		egressQoSFakeClient := &egressqosfake.Clientset{}

		kubeFakeClient = fake.NewSimpleClientset(&v1.NodeList{
			Items: []v1.Node{testNode1, testNode2, testNode3},
		})

		fakeClient = &util.OVNClientset{
			KubeClient:           kubeFakeClient,
			EgressIPClient:       egressIPFakeClient,
			EgressFirewallClient: egressFirewallFakeClient,
			EgressQoSClient:      egressQoSFakeClient,
		}

		var err error
		node1Annotator = kube.NewNodeAnnotator(&kube.Kube{kubeFakeClient}, testNode1.Name)
		l3GatewayConfig := node1.gatewayConfig(config.GatewayModeLocal, uint(vlanID))
		err = util.SetL3GatewayConfig(node1Annotator, l3GatewayConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		node1HostAddrs = sets.NewString(node1.NodeIP)
		err = util.SetNodeHostAddresses(node1Annotator, node1HostAddrs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		err = util.SetNodeManagementPortMACAddress(node1Annotator, ovntest.MustParseMAC(node1.NodeMgmtPortMAC))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		err = node1Annotator.Run()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		node2Annotator = kube.NewNodeAnnotator(&kube.Kube{kubeFakeClient}, testNode2.Name)
		l3GatewayConfig = node2.gatewayConfig(config.GatewayModeLocal, uint(vlanID))
		err = util.SetL3GatewayConfig(node2Annotator, l3GatewayConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		node2HostAddrs = sets.NewString(node2.NodeIP)
		err = util.SetNodeHostAddresses(node2Annotator, node2HostAddrs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		err = util.SetNodeManagementPortMACAddress(node2Annotator, ovntest.MustParseMAC(node2.NodeMgmtPortMAC))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		err = node2Annotator.Run()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		node3Annotator = kube.NewNodeAnnotator(&kube.Kube{kubeFakeClient}, testNode3.Name)
		l3GatewayConfig = node3.gatewayConfig(config.GatewayModeLocal, uint(vlanID))
		err = util.SetL3GatewayConfig(node3Annotator, l3GatewayConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		node3HostAddrs = sets.NewString(node3.NodeIP)
		err = util.SetNodeHostAddresses(node3Annotator, node3HostAddrs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		err = util.SetNodeManagementPortMACAddress(node3Annotator, ovntest.MustParseMAC(node3.NodeMgmtPortMAC))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		err = node3Annotator.Run()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.AfterEach(func() {
		close(stopChan)
		wg.Wait()
		if libovsdbCleanup != nil {
			libovsdbCleanup.Cleanup()
		}
		f.Shutdown()
		wg.Wait()
	})

	ginkgo.It("OVN Interconnect test", func() {
		app.Action = func(ctx *cli.Context) error {
			expectedClusterLBGroup := newLoadBalancerGroup()

			dbSetup := libovsdbtest.TestSetup{
				NBData: initialNBDB,
				SBData: initialSBDB,
			}

			_, err := config.InitConfig(ctx, nil, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			config.Kubernetes.HostNetworkNamespace = ""

			f, err = factory.NewClusterManagerWatchFactory(fakeClient.GetClusterManagerClientset())
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = f.Start()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			clusterManager := cm.NewClusterManager(fakeClient.GetClusterManagerClientset(), f, "identitiy", wg,
				record.NewFakeRecorder(0))
			gomega.Expect(clusterManager).NotTo(gomega.BeNil())

			err = clusterManager.Run()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			var libovsdbOvnNBClient, libovsdbOvnSBClient libovsdbclient.Client
			libovsdbOvnNBClient, libovsdbOvnSBClient, libovsdbCleanup, err = libovsdbtest.NewNBSBTestHarness(dbSetup)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			clusterController := NewOvnController(fakeClient.GetMasterClientset(), f, stopChan, addressset.NewFakeAddressSetFactory(),
				libovsdbOvnNBClient, libovsdbOvnSBClient,
				record.NewFakeRecorder(10), wg)
			gomega.Expect(clusterController).NotTo(gomega.BeNil())
			clusterController.SCTPSupport = true
			clusterController.loadBalancerGroupUUID = ""
			clusterController.defaultCOPPUUID, err = EnsureDefaultCOPP(clusterController.nbClient)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			_, _ = clusterController.createOvnClusterRouter()

			clusterController.joinSwIPManager, _ = lsm.NewJoinLogicalSwitchIPManager(clusterController.nbClient, expectedClusterLBGroup.UUID, []string{"node1"}, getJoinSwitchSubnets())
			_, err = clusterController.joinSwIPManager.EnsureJoinLRPIPs(types.OVNClusterRouter)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			l3GatewayConfig := node1.gatewayConfig(config.GatewayModeLocal, uint(vlanID))
			subnet := ovntest.MustParseIPNet(node1.NodeSubnet)
			err = clusterController.syncGatewayLogicalNetwork(&testNode1, l3GatewayConfig, []*net.IPNet{subnet}, node1HostAddrs)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			l3GatewayConfig = node2.gatewayConfig(config.GatewayModeLocal, uint(vlanID))
			subnet = ovntest.MustParseIPNet(node2.NodeSubnet)
			err = clusterController.syncGatewayLogicalNetwork(&testNode2, l3GatewayConfig, []*net.IPNet{subnet}, node2HostAddrs)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			l3GatewayConfig = node3.gatewayConfig(config.GatewayModeLocal, uint(vlanID))
			subnet = ovntest.MustParseIPNet(node3.NodeSubnet)
			err = clusterController.syncGatewayLogicalNetwork(&testNode3, l3GatewayConfig, []*net.IPNet{subnet}, node3HostAddrs)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			existingNodes, err := clusterController.kube.GetNodes()
			if err == nil {
				for _, node := range existingNodes.Items {
					clusterController.localZoneNodes.Store(node.Name, true)
				}
			}

			createTransitSwitchPortBindings(libovsdbOvnSBClient, existingNodes)

			err = triggerInterconnect(clusterController, "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			err = checkInterconnectResources(clusterController, "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Make node2 as remote node.  To do that change the zone of node 2 to some value.
			setNodeZone(node2Annotator, node2.Name, "foo", fakeClient.KubeClient)
			err = triggerInterconnect(clusterController, "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = checkInterconnectResources(clusterController, "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Make node3 as remote node.  To do that change the zone of node 2 to some value.
			setNodeZone(node3Annotator, node3.Name, "bar", fakeClient.KubeClient)
			err = triggerInterconnect(clusterController, "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = checkInterconnectResources(clusterController, "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Make node2 and node3 back to local nodes.
			setNodeZone(node2Annotator, node2.Name, "global", fakeClient.KubeClient)
			setNodeZone(node3Annotator, node3.Name, "global", fakeClient.KubeClient)
			err = triggerInterconnect(clusterController, "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = checkInterconnectResources(clusterController, "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			clusterManager.Stop()
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-cluster-subnets=" + clusterCIDR,
			"-init-cluster-manager",
			"-zone-join-switch-subnets=" + joinSubnetCIDR,
			"-enable-interconnect",
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
})

func triggerInterconnect(clusterController *DefaultNetworkController, zone string) error {
	nodes, _ := clusterController.kube.GetNodes()
	for _, node := range nodes.Items {
		if util.GetNodeZone(&node) == zone {
			err := clusterController.interconnectAddUpdateLocalNode(&node)
			if err != nil {
				return err
			}
		} else {
			err := clusterController.interconnectAddUpdateRemoteNode(&node)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func setNodeZone(nodeAnnotator kube.Annotator, nodeName, zone string, kubeClient kubernetes.Interface) error {
	err := util.SetNodeZone(nodeAnnotator, zone)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	err = nodeAnnotator.Run()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	gomega.Eventually(func() error {
		updatedNode, err := kubeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		updatedZone := util.GetNodeZone(updatedNode)
		if updatedZone != zone {
			return fmt.Errorf("expected node annotation for node to have updated zone - %s : but found %s", zone, updatedZone)
		}
		return nil
	}).ShouldNot(gomega.HaveOccurred())

	return err
}

func checkInterconnectResources(oc *DefaultNetworkController, zone string) error {
	nodes, _ := oc.kube.GetNodes()
	localZoneNodes := []v1.Node{}
	remoteZoneNodes := []v1.Node{}
	localZoneNodeNames := []string{}
	remoteZoneNodeNames := []string{}
	for _, node := range nodes.Items {
		nodeZone := util.GetNodeZone(&node)
		if nodeZone == zone {
			localZoneNodes = append(localZoneNodes, node)
			localZoneNodeNames = append(localZoneNodeNames, node.Name)
		} else {
			remoteZoneNodes = append(remoteZoneNodes, node)
			remoteZoneNodeNames = append(remoteZoneNodeNames, node.Name)
		}

	}

	sort.Strings(localZoneNodeNames)
	sort.Strings(remoteZoneNodeNames)
	// First check if transit switch exists or not
	s := nbdb.LogicalSwitch{
		Name: types.TransitSwitch,
	}

	ts, err := libovsdbops.GetLogicalSwitch(oc.nbClient, &s)

	if err != nil {
		return err
	}

	noOfTSPorts := len(localZoneNodes) + len(remoteZoneNodes)

	if len(ts.Ports) != noOfTSPorts {
		return fmt.Errorf("transit switch %s doesn't have expected logical ports.  Found %d : Expected %d ports",
			types.TransitSwitch, len(ts.Ports), noOfTSPorts)
	}
	// Checking just to be sure that the returned switch is infact transit switch.
	if ts.Name != types.TransitSwitch {
		return fmt.Errorf("transit switch %s not found in NB DB. Instead found %s", types.TransitSwitch, ts.Name)
	}

	tsPorts := make([]string, noOfTSPorts)
	i := 0
	for _, p := range ts.Ports {
		lp := nbdb.LogicalSwitchPort{
			UUID: p,
		}

		lsp, err := libovsdbops.GetLogicalSwitchPort(oc.nbClient, &lp)
		if err != nil {
			return err
		}
		tsPorts[i] = lsp.Name + ":" + lsp.Type
		i++
	}

	sort.Strings(tsPorts)

	// Verify Transit switch ports.
	// For local nodes, the transit switch port should be of type 'router'
	// and for remote zone nodes, it should be of type 'remote'.
	expectedTsPorts := make([]string, noOfTSPorts)
	i = 0
	for _, node := range localZoneNodes {
		// The logical port for the local zone nodes should be of type patch.
		nodeTSPortName := types.TransitSwitchToRouterPrefix + node.Name
		expectedTsPorts[i] = nodeTSPortName + ":router"
		i++
	}

	for _, node := range remoteZoneNodes {
		// The logical port for the local zone nodes should be of type patch.
		nodeTSPortName := types.TransitSwitchToRouterPrefix + node.Name
		expectedTsPorts[i] = nodeTSPortName + ":remote"
		i++
	}

	sort.Strings(expectedTsPorts)
	gomega.Expect(tsPorts).To(gomega.Equal(expectedTsPorts))

	r := nbdb.LogicalRouter{
		Name: types.OVNClusterRouter,
	}

	clusterRouter, err := libovsdbops.GetLogicalRouter(oc.nbClient, &r)
	if err != nil {
		return err
	}

	// Verify the OVN cluster router ports for each local node
	// connecting the Transit switch.
	icClusterRouterPorts := []string{}
	for _, p := range clusterRouter.Ports {
		lp := nbdb.LogicalRouterPort{
			UUID: p,
		}

		lrp, err := libovsdbops.GetLogicalRouterPort(oc.nbClient, &lp)
		if err != nil {
			return err
		}

		if lrp.Name[:len(types.RouterToTransitSwitchPrefix)] == types.RouterToTransitSwitchPrefix {
			icClusterRouterPorts = append(icClusterRouterPorts, lrp.Name)
		}
	}

	sort.Strings(icClusterRouterPorts)

	expectedICClusterRouterPorts := []string{}
	for _, node := range localZoneNodes {
		expectedICClusterRouterPorts = append(expectedICClusterRouterPorts, types.RouterToTransitSwitchPrefix+node.Name)
	}
	sort.Strings(expectedICClusterRouterPorts)

	gomega.Expect(icClusterRouterPorts).To(gomega.Equal(expectedICClusterRouterPorts))

	// Check the SB Chassis.
	chassisList, err := libovsdbops.ListChassis(oc.sbClient)

	if err != nil {
		return err
	}

	expectedLocalChassis := []string{}
	expectedRemoteChassis := []string{}
	for _, chassis := range chassisList {
		if chassis.ExternalIDs != nil && chassis.OtherConfig != nil {
			if chassis.ExternalIDs["is-remote"] == "false" && chassis.OtherConfig["is-remote"] == "false" {
				expectedLocalChassis = append(expectedLocalChassis, chassis.Hostname)
			}

			if chassis.ExternalIDs["is-remote"] == "true" && chassis.OtherConfig["is-remote"] == "true" {
				expectedRemoteChassis = append(expectedRemoteChassis, chassis.Hostname)
			}
		}
	}

	sort.Strings(expectedLocalChassis)
	sort.Strings(expectedRemoteChassis)
	gomega.Expect(localZoneNodeNames).To(gomega.Equal(expectedLocalChassis))
	gomega.Expect(remoteZoneNodeNames).To(gomega.Equal(expectedRemoteChassis))
	return nil
}

func createTransitSwitchPortBindings(sbClient libovsdbclient.Client, nodes *v1.NodeList) error {
	for _, node := range nodes.Items {
		pb := sbdb.PortBinding{
			LogicalPort: types.TransitSwitchToRouterPrefix + node.Name,
		}

		err := libovsdbops.CreatePortBinding(sbClient, &pb)
		if err != nil {
			return err
		}
	}

	return nil
}
