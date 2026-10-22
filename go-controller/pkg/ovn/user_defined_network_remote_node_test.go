package ovn

import (
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	zoneic "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/zone_interconnect"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("UDN remote node removal", func() {
	DescribeTable("preserves local topology and deletes remote objects", func(layer2 bool) {
		Expect(config.PrepareTestConfig()).To(Succeed())
		config.OVNKubernetesFeature.EnableInterconnect = true
		config.OVNKubernetesFeature.EnableMultiNetwork = true
		config.OVNKubernetesFeature.EnableNetworkSegmentation = true
		info := dummyPrimaryLayer3UserDefinedNetwork("100.200.0.0/16", "100.200.1.0/24")
		if layer2 {
			info = dummyPrimaryLayer2UserDefinedNetwork("100.200.0.0/16")
		}
		netInfo, err := util.NewNetInfo(info.netconf())
		Expect(err).NotTo(HaveOccurred())
		localRouterPort := &nbdb.LogicalRouterPort{UUID: "local-router-port", Name: "rtos-isolatednet_ovn_layer2_switch", MAC: "0a:58:64:c8:00:01", Networks: []string{"100.200.0.1/16"}}
		localSwitchPort := &nbdb.LogicalSwitchPort{UUID: "local-switch-port", Name: "stor-isolatednet_ovn_layer2_switch", Type: "router", Addresses: []string{"router"}, Options: map[string]string{"router-port": localRouterPort.Name}}
		localRouter := &nbdb.LogicalRouter{UUID: "local-router", Name: "GR_isolatednet_test-node", Ports: []string{localRouterPort.UUID}}
		localSwitch := &nbdb.LogicalSwitch{UUID: "local-switch", Name: "isolatednet_ovn_layer2_switch", Ports: []string{localSwitchPort.UUID}}
		remotePort := &nbdb.LogicalSwitchPort{UUID: "remote-port", Name: "stor-isolatednet_ovn_layer2_switch_remote-node", Type: "remote", Addresses: []string{"0a:58:64:c8:00:02 100.200.0.2/16"}}
		remoteRouterPort := &nbdb.LogicalRouterPort{UUID: "remote-router-port", Name: "isolatednet_rtots-remote-node", MAC: "0a:58:64:58:00:04", Networks: []string{"100.88.0.4/16"}}
		clusterRouter := &nbdb.LogicalRouter{UUID: "cluster-router", Name: "isolatednet_ovn_cluster_router", Ports: []string{remoteRouterPort.UUID}}
		if !layer2 {
			localSwitch.Name = "isolatednet_join"
			localSwitchPort.Name = "jtor-GR_isolatednet_test-node"
			localRouterPort.Name = "rtoj-GR_isolatednet_test-node"
			localSwitchPort.Options["router-port"] = localRouterPort.Name
			remotePort.Name = "isolatednet_tstor-remote-node"
		}
		localData := []libovsdbtest.TestData{localRouterPort, localSwitchPort, localRouter, localSwitch}
		localClusterPort := &nbdb.LogicalRouterPort{UUID: "local-cluster-port", Name: "rtos-isolatednet_test-node", MAC: "0a:58:64:c8:01:01", Networks: []string{"100.200.1.1/24"}}
		localTransitPort := &nbdb.LogicalRouterPort{UUID: "local-transit-port", Name: "isolatednet_rtots-test-node", MAC: "0a:58:64:58:00:03", Networks: []string{"100.88.0.3/16"}}
		localTransitSwitchPort := &nbdb.LogicalSwitchPort{UUID: "local-transit-switch-port", Name: "isolatednet_tstor-test-node", Type: "router", Addresses: []string{"router"}, Options: map[string]string{"router-port": localTransitPort.Name}}
		transitSwitch := &nbdb.LogicalSwitch{UUID: "transit-switch", Name: "isolatednet_transit_switch", Ports: []string{localTransitSwitchPort.UUID}}
		if !layer2 {
			clusterRouter.Ports = []string{localClusterPort.UUID, localTransitPort.UUID}
			localData = append(localData, localClusterPort, localTransitPort, localTransitSwitchPort, clusterRouter, transitSwitch)
		}
		initialData := append([]libovsdbtest.TestData{}, localData...)
		if layer2 {
			initialSwitch := *localSwitch
			initialSwitch.Ports = append([]string{localSwitchPort.UUID}, remotePort.UUID)
			initialData[3] = &initialSwitch
		} else {
			initialClusterRouter := *clusterRouter
			initialClusterRouter.Ports = []string{localClusterPort.UUID, localTransitPort.UUID, remoteRouterPort.UUID}
			initialTransitSwitch := *transitSwitch
			initialTransitSwitch.Ports = []string{localTransitSwitchPort.UUID, remotePort.UUID}
			initialData[7] = &initialClusterRouter
			initialData[8] = &initialTransitSwitch
			initialData = append(initialData, remoteRouterPort)
		}
		initialData = append(initialData, remotePort)
		fakeOvn := NewFakeOVN(true)
		fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{NBData: initialData})
		defer fakeOvn.shutdown()
		layer2Controller := &Layer2UserDefinedNetworkController{}
		layer3Controller := &Layer3UserDefinedNetworkController{}
		base := &layer3Controller.BaseUserDefinedNetworkController
		if layer2 {
			base = &layer2Controller.BaseUserDefinedNetworkController
		}
		base.nbClient = fakeOvn.nbClient
		base.sbClient = fakeOvn.sbClient
		base.ReconcilableNetInfo = util.NewReconcilableNetInfo(netInfo)
		base.localZoneNodes = &sync.Map{}
		base.lsManager = fakeOvn.controller.lsManager
		base.localZoneNodes.Store("test-node", true)
		remoteNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "remote-node"}}
		var deleteNode func(*corev1.Node) error
		var gatewayManagers *sync.Map
		By("checking that remote objects exist before removal")
		Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveDataSubset(remotePort))
		if layer2 {
			controller := layer2Controller
			controller.gatewayManagers.Store("test-node", controller.newGatewayManager("test-node"))
			deleteNode = controller.deleteNodeEvent
			gatewayManagers = &controller.gatewayManagers
		} else {
			base.zoneICHandler = zoneic.NewZoneInterconnectHandler(netInfo, fakeOvn.nbClient, fakeOvn.sbClient, nil)
			controller := layer3Controller
			controller.gatewayManagers.Store("test-node", controller.newGatewayManager("test-node"))
			deleteNode = controller.deleteNodeEvent
			gatewayManagers = &controller.gatewayManagers
		}
		Expect(deleteNode(remoteNode)).To(Succeed())
		Expect(deleteNode(remoteNode)).To(Succeed())
		By("checking the complete remaining database, including local port attachments")
		Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(localData...))
		_, local := base.localZoneNodes.Load("test-node")
		Expect(local).To(BeTrue())
		_, localGateway := gatewayManagers.Load("test-node")
		Expect(localGateway).To(BeTrue())

		By("checking that deleting the local node still cleans up its gateway")
		Expect(deleteNode(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node"}})).To(Succeed())
		if layer2 {
			localData = []libovsdbtest.TestData{&nbdb.LogicalSwitch{UUID: localSwitch.UUID, Name: localSwitch.Name}}
		} else {
			remainingClusterRouter := *clusterRouter
			remainingClusterRouter.Ports = []string{localTransitPort.UUID}
			localData = []libovsdbtest.TestData{&nbdb.LogicalSwitch{UUID: localSwitch.UUID, Name: localSwitch.Name}, &remainingClusterRouter, localTransitPort, localTransitSwitchPort, transitSwitch}
		}
		Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(localData...))
		_, local = base.localZoneNodes.Load("test-node")
		Expect(local).To(BeFalse())
		_, localGateway = gatewayManagers.Load("test-node")
		Expect(localGateway).To(BeFalse())
	}, Entry("Layer2", true), Entry("Layer3", false))
})
