package ovn

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/libovsdbops"
	ovnlb "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/loadbalancer"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	utilnet "k8s.io/utils/net"
)

var (
	nodeName = "test-node"
)

func init() {
	// libovsdb matcher might produce a lengthy output that will be cropped by
	// default gomega output limit, set to 0 to unlimit.
	format.MaxLength = 0
}

func generateGatewayInitExpectedNB(testData []libovsdb.TestData, expectedOVNClusterRouter *nbdb.LogicalRouter, expectedNodeSwitch *nbdb.LogicalSwitch, nodeName string, clusterIPSubnets []*net.IPNet, hostSubnets []*net.IPNet,
	l3GatewayConfig *util.L3GatewayConfig, joinLRPIPs, defLRPIPs []*net.IPNet, skipSnat bool, NodeMgmtPortIP string) []libovsdb.TestData {

	GRName := "GR_" + nodeName
	gwSwitchPort := types.JoinSwitchToGWRouterPrefix + GRName
	gwRouterPort := types.GWRouterToJoinSwitchPrefix + GRName
	externalSwitch := fmt.Sprintf("%s%s", types.ExternalSwitchPrefix, nodeName)
	externalRouterPort := types.GWRouterToExtSwitchPrefix + GRName
	externalSwitchPortToRouter := types.EXTSwitchToGWRouterPrefix + GRName

	networks := []string{}

	for i, joinLRPIP := range joinLRPIPs {
		networks = append(networks, joinLRPIP.String())
		joinStaticRouteNamedUUID := fmt.Sprintf("join-static-route-ovn-cluster-router-%v-UUID", i)
		expectedOVNClusterRouter.StaticRoutes = append(expectedOVNClusterRouter.StaticRoutes, joinStaticRouteNamedUUID)
		testData = append(testData, &nbdb.LogicalRouterStaticRoute{
			UUID:     joinStaticRouteNamedUUID,
			IPPrefix: joinLRPIP.IP.String(),
			Nexthop:  joinLRPIP.IP.String(),
		})
	}
	testData = append(testData, &nbdb.LogicalRouterPort{
		UUID:     gwRouterPort + "-UUID",
		Name:     gwRouterPort,
		MAC:      util.IPAddrToHWAddr(joinLRPIPs[0].IP).String(),
		Networks: networks,
	})
	grStaticRoutes := []string{}
	for i, subnet := range clusterIPSubnets {
		nexthop, _ := util.MatchIPNetFamily(utilnet.IsIPv6CIDR(subnet), defLRPIPs)
		grStaticRouteNamedUUID := fmt.Sprintf("static-subnet-route-%v-UUID", i)
		grStaticRoutes = append(grStaticRoutes, grStaticRouteNamedUUID)
		testData = append(testData, &nbdb.LogicalRouterStaticRoute{
			UUID:     grStaticRouteNamedUUID,
			IPPrefix: subnet.String(),
			Nexthop:  nexthop.IP.String(),
		})

	}
	for i, hostSubnet := range hostSubnets {
		joinLRPIP, _ := util.MatchIPNetFamily(utilnet.IsIPv6CIDR(hostSubnet), joinLRPIPs)
		ocrStaticRouteNamedUUID := fmt.Sprintf("subnet-static-route-ovn-cluster-router-%v-UUID", i)
		expectedOVNClusterRouter.StaticRoutes = append(expectedOVNClusterRouter.StaticRoutes, ocrStaticRouteNamedUUID)
		testData = append(testData, &nbdb.LogicalRouterStaticRoute{
			UUID:     ocrStaticRouteNamedUUID,
			Policy:   &nbdb.LogicalRouterStaticRoutePolicySrcIP,
			IPPrefix: hostSubnet.String(),
			Nexthop:  joinLRPIP.IP.String(),
		})
	}
	for i, nexthop := range l3GatewayConfig.NextHops {
		var allIPs string
		if utilnet.IsIPv6(nexthop) {
			allIPs = "::/0"
		} else {
			allIPs = "0.0.0.0/0"
		}

		nexthopStaticRouteNamedUUID := fmt.Sprintf("static-nexthop-route-%v-UUID", i)
		grStaticRoutes = append(grStaticRoutes, nexthopStaticRouteNamedUUID)

		testData = append(testData, &nbdb.LogicalRouterStaticRoute{
			UUID:       nexthopStaticRouteNamedUUID,
			IPPrefix:   allIPs,
			Nexthop:    nexthop.String(),
			OutputPort: &externalRouterPort,
		})
	}
	networks = []string{}
	physicalIPs := []string{}
	for _, ip := range l3GatewayConfig.IPAddresses {
		networks = append(networks, ip.String())
		physicalIPs = append(physicalIPs, ip.IP.String())
	}
	testData = append(testData, &nbdb.LogicalRouterPort{
		UUID: externalRouterPort + "-UUID",
		Name: externalRouterPort,
		MAC:  l3GatewayConfig.MACAddress.String(),
		ExternalIDs: map[string]string{
			"gateway-physical-ip": "yes",
		},
		Networks: networks,
	})

	natUUIDs := make([]string, 0, len(clusterIPSubnets))
	if !skipSnat {
		for _, subnet := range clusterIPSubnets {
			natUUID := libovsdbops.BuildNamedUUID()
			natUUIDs = append(natUUIDs, natUUID)
			physicalIP, _ := util.MatchIPNetFamily(utilnet.IsIPv6CIDR(subnet), l3GatewayConfig.IPAddresses)
			testData = append(testData, &nbdb.NAT{
				UUID:       natUUID,
				ExternalIP: physicalIP.IP.String(),
				LogicalIP:  subnet.String(),
				Options:    map[string]string{"stateless": "false"},
				Type:       nbdb.NATTypeSNAT,
			})
		}
	}

	testData = append(testData, &nbdb.LogicalRouter{
		UUID: GRName + "-UUID",
		Name: GRName,
		Options: map[string]string{
			"lb_force_snat_ip":              "router_ip",
			"snat-ct-zone":                  "0",
			"always_learn_from_arp_request": "false",
			"dynamic_neigh_routers":         "true",
			"chassis":                       l3GatewayConfig.ChassisID,
		},
		ExternalIDs: map[string]string{
			"physical_ip":  physicalIPs[0],
			"physical_ips": strings.Join(physicalIPs, ","),
		},
		Ports:        []string{gwRouterPort + "-UUID", externalRouterPort + "-UUID"},
		StaticRoutes: grStaticRoutes,
		Nat:          natUUIDs,
	})

	testData = append(testData, expectedOVNClusterRouter)

	if len(NodeMgmtPortIP) != 0 {
		_, nodeACL := generateAllowFromNodeData(nodeName, NodeMgmtPortIP)
		testData = append(testData, nodeACL)

		expectedNodeSwitch.ACLs = append(expectedNodeSwitch.ACLs, nodeACL.UUID)
	}

	testData = append(testData, expectedNodeSwitch)

	externalLogicalSwitchPort := &nbdb.LogicalSwitchPort{
		UUID:      l3GatewayConfig.InterfaceID + "-UUID",
		Addresses: []string{"unknown"},
		Type:      "localnet",
		Options: map[string]string{
			"network_name": types.PhysicalNetworkName,
		},
		Name: l3GatewayConfig.InterfaceID,
	}
	if l3GatewayConfig.VLANID != nil {
		intVlanID := int(*l3GatewayConfig.VLANID)
		externalLogicalSwitchPort.TagRequest = &intVlanID
	}
	testData = append(testData, externalLogicalSwitchPort)
	testData = append(testData,
		&nbdb.LogicalSwitchPort{
			UUID:      gwSwitchPort + "-UUID",
			Name:      gwSwitchPort,
			Type:      "router",
			Addresses: []string{"router"},
			Options: map[string]string{
				"router-port": gwRouterPort,
			},
		},
		&nbdb.LogicalSwitchPort{
			UUID: externalSwitchPortToRouter + "-UUID",
			Name: externalSwitchPortToRouter,
			Type: "router",
			Options: map[string]string{
				"router-port": externalRouterPort,
			},
			Addresses: []string{l3GatewayConfig.MACAddress.String()},
		},
		&nbdb.LogicalSwitch{
			UUID:  types.OVNJoinSwitch + "-UUID",
			Name:  types.OVNJoinSwitch,
			Ports: []string{gwSwitchPort + "-UUID"},
		},
		&nbdb.LogicalSwitch{
			UUID:  externalSwitch + "-UUID",
			Name:  externalSwitch,
			Ports: []string{l3GatewayConfig.InterfaceID + "-UUID", externalSwitchPortToRouter + "-UUID"},
		})
	return testData
}

var _ = ginkgo.Describe("Gateway Init Operations", func() {
	var (
		fakeOvn *FakeOVN
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		// TODO make contexts here for shared gw mode and local gw mode, right now this only tests shared gw
		config.Gateway.Mode = config.GatewayModeShared
		// Create new LBCache
		ovnlb.TestOnlySetCache(nil)

		fakeOvn = NewFakeOVN()
	})

	ginkgo.AfterEach(func() {
		fakeOvn.shutdown()
	})

	ginkgo.It("creates an IPv4 gateway in OVN", func() {
		expectedOVNClusterRouter := &nbdb.LogicalRouter{
			UUID: types.OVNClusterRouter + "-UUID",
			Name: types.OVNClusterRouter,
		}
		expectedNodeSwitch := &nbdb.LogicalSwitch{
			UUID: nodeName + "-UUID",
			Name: nodeName,
		}
		fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					UUID: types.OVNJoinSwitch + "-UUID",
					Name: types.OVNJoinSwitch,
				},
				expectedOVNClusterRouter,
				expectedNodeSwitch,
			},
		})

		clusterIPSubnets := ovntest.MustParseIPNets("10.128.0.0/14")
		hostSubnets := ovntest.MustParseIPNets("10.130.0.0/23")
		joinLRPIPs := ovntest.MustParseIPNets("100.64.0.3/16")
		defLRPIPs := ovntest.MustParseIPNets("100.64.0.1/16")
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    ovntest.MustParseIPNets("169.254.33.2/24"),
			NextHops:       ovntest.MustParseIPs("169.254.33.1"),
			NodePortEnable: true,
		}
		sctpSupport := false

		err := fakeOvn.controller.gatewayInit(nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, sctpSupport, joinLRPIPs, defLRPIPs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		testData := []libovsdb.TestData{}
		skipSnat := false
		// We don't set up the Allow from mgmt port ACL here
		mgmtPortIP := ""
		expectedDatabaseState := generateGatewayInitExpectedNB(testData, expectedOVNClusterRouter, expectedNodeSwitch, nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, joinLRPIPs, defLRPIPs, skipSnat, mgmtPortIP)
		gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
	})

	ginkgo.It("creates an IPv6 gateway in OVN", func() {
		expectedOVNClusterRouter := &nbdb.LogicalRouter{
			UUID: types.OVNClusterRouter + "-UUID",
			Name: types.OVNClusterRouter,
		}
		expectedNodeSwitch := &nbdb.LogicalSwitch{
			UUID: nodeName + "-UUID",
			Name: nodeName,
		}
		fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					UUID: types.OVNJoinSwitch + "-UUID",
					Name: types.OVNJoinSwitch,
				},
				expectedOVNClusterRouter,
				expectedNodeSwitch,
			},
		})

		clusterIPSubnets := ovntest.MustParseIPNets("fd01::/48")
		hostSubnets := ovntest.MustParseIPNets("fd01:0:0:2::/64")
		joinLRPIPs := ovntest.MustParseIPNets("fd98::3/64")
		defLRPIPs := ovntest.MustParseIPNets("fd98::1/64")
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    ovntest.MustParseIPNets("fd99::2/64"),
			NextHops:       ovntest.MustParseIPs("fd99::1"),
			NodePortEnable: true,
		}
		sctpSupport := false

		err := fakeOvn.controller.gatewayInit(nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, sctpSupport, joinLRPIPs, defLRPIPs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		testData := []libovsdb.TestData{}
		skipSnat := false
		// We don't set up the Allow from mgmt port ACL here
		mgmtPortIP := ""
		expectedDatabaseState := generateGatewayInitExpectedNB(testData, expectedOVNClusterRouter, expectedNodeSwitch, nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, joinLRPIPs, defLRPIPs, skipSnat, mgmtPortIP)
		gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
	})

	ginkgo.It("creates a dual-stack gateway in OVN", func() {
		expectedOVNClusterRouter := &nbdb.LogicalRouter{
			UUID: types.OVNClusterRouter + "-UUID",
			Name: types.OVNClusterRouter,
		}
		expectedNodeSwitch := &nbdb.LogicalSwitch{
			UUID: nodeName + "-UUID",
			Name: nodeName,
		}
		fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					UUID: types.OVNJoinSwitch + "-UUID",
					Name: types.OVNJoinSwitch,
				},
				expectedOVNClusterRouter,
				expectedNodeSwitch,
			},
		})

		clusterIPSubnets := ovntest.MustParseIPNets("10.128.0.0/14", "fd01::/48")
		hostSubnets := ovntest.MustParseIPNets("10.130.0.0/23", "fd01:0:0:2::/64")
		joinLRPIPs := ovntest.MustParseIPNets("100.64.0.3/16", "fd98::3/64")
		defLRPIPs := ovntest.MustParseIPNets("100.64.0.1/16", "fd98::1/64")
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    ovntest.MustParseIPNets("169.254.33.2/24", "fd99::2/64"),
			NextHops:       ovntest.MustParseIPs("169.254.33.1", "fd99::1"),
			NodePortEnable: true,
		}
		sctpSupport := false

		err := fakeOvn.controller.gatewayInit(nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, sctpSupport, joinLRPIPs, defLRPIPs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		testData := []libovsdb.TestData{}
		skipSnat := false
		// We don't set up the Allow from mgmt port ACL here
		mgmtPortIP := ""
		expectedDatabaseState := generateGatewayInitExpectedNB(testData, expectedOVNClusterRouter, expectedNodeSwitch, nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, joinLRPIPs, defLRPIPs, skipSnat, mgmtPortIP)
		gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
	})

	ginkgo.It("cleans up a single-stack gateway in OVN", func() {
		nodeName := "test-node"
		hostSubnet := ovntest.MustParseIPNets("10.130.0.0/23")

		mgmtPortIP := util.GetNodeManagementIfAddr(hostSubnet[0]).IP.String()

		mgmtPriority, _ := strconv.Atoi(types.MGMTPortPolicyPriority)
		nodeSubnetPriority, _ := strconv.Atoi(types.NodeSubnetPolicyPriority)
		interNodePriority, _ := strconv.Atoi(types.InterNodePolicyPriority)

		matchstr1 := fmt.Sprintf("ip4.src == %s && ip4.dst == nodePhysicalIP /* %s */", mgmtPortIP, nodeName)
		matchstr2 := fmt.Sprintf(`inport == "rtos-%s" && ip4.dst == nodePhysicalIP /* %s */`, nodeName, nodeName)
		matchstr3 := fmt.Sprintf("ip4.src == source && ip4.dst == nodePhysicalIP")
		matchstr4 := fmt.Sprintf(`ip4.src == NO DELETE  && ip4.dst != 10.244.0.0/16 /* inter-%s-no */`, nodeName)
		matchstr5 := fmt.Sprintf(`ip4.src == 10.244.0.2  && ip4.dst != 10.244.0.0/16 /* inter-%s */`, nodeName)
		matchstr6 := fmt.Sprintf("ip4.src == NO DELETE && ip4.dst == nodePhysicalIP /* %s-no */", nodeName)

		fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				&nbdb.LogicalRouterPort{
					Name:     types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName,
					UUID:     types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName + "-UUID",
					Networks: []string{"100.64.0.1/16"},
				},
				&nbdb.LoadBalancer{
					UUID:     "Service_default/kubernetes_TCP_node_router_ovn-control-plane",
					Name:     "Service_default/kubernetes_TCP_node_router_ovn-control-plane",
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					ExternalIDs: map[string]string{
						"k8s.ovn.org/kind":  "Service",
						"k8s.ovn.org/owner": "default/kubernetes",
					},
					Vips: map[string]string{
						"192.168.0.1:6443": "1.1.1.1:1,2.2.2.2:2",
						"[fe::1]:1":        "[fe::2]:1,[fe::2]:2",
					},
				},
				&nbdb.LogicalRouter{
					Name: types.GWRouterPrefix + nodeName,
					UUID: types.GWRouterPrefix + nodeName + "-UUID",
					LoadBalancer: []string{
						"Service_default/kubernetes_TCP_node_router_ovn-control-plane",
					},
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match1-UUID",
					Match:    matchstr1,
					Priority: mgmtPriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match2-UUID",
					Match:    matchstr2,
					Priority: nodeSubnetPriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match3-UUID",
					Match:    matchstr3,
					Priority: nodeSubnetPriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match4-UUID",
					Match:    matchstr4,
					Priority: interNodePriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match5-UUID",
					Match:    matchstr5,
					Priority: interNodePriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match6-UUID",
					Match:    matchstr6,
					Priority: nodeSubnetPriority,
				},
				&nbdb.LogicalRouterStaticRoute{
					Nexthop: "100.64.0.1",
					UUID:    "static-route-UUID",
				},
				&nbdb.LogicalRouter{
					Name:         types.OVNClusterRouter,
					UUID:         types.OVNClusterRouter + "-UUID",
					Policies:     []string{"match1-UUID", "match2-UUID", "match3-UUID", "match4-UUID", "match5-UUID", "match6-UUID"},
					StaticRoutes: []string{"static-route-UUID"},
				},
				&nbdb.LogicalSwitchPort{
					Name: types.JoinSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName,
					UUID: types.JoinSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName + "-UUID",
				},
				&nbdb.LogicalSwitch{
					Name: types.ExternalSwitchPrefix + nodeName,
					UUID: types.ExternalSwitchPrefix + nodeName + "-UUID ",
				},
				&nbdb.LogicalSwitch{
					Name: types.ExternalSwitchPrefix + types.ExternalSwitchPrefix + nodeName,
					UUID: types.ExternalSwitchPrefix + types.ExternalSwitchPrefix + nodeName + "-UUID",
				},
			},
		})

		err := fakeOvn.controller.gatewayCleanup(nodeName)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		expectedDatabaseState := []libovsdbtest.TestData{
			&nbdb.LogicalRouterPort{
				Name:     types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName,
				UUID:     types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName + "-UUID",
				Networks: []string{"100.64.0.1/16"},
			},
			&nbdb.LoadBalancer{
				UUID:     "Service_default/kubernetes_TCP_node_router_ovn-control-plane",
				Name:     "Service_default/kubernetes_TCP_node_router_ovn-control-plane",
				Protocol: &nbdb.LoadBalancerProtocolTCP,
				ExternalIDs: map[string]string{
					"k8s.ovn.org/kind":  "Service",
					"k8s.ovn.org/owner": "default/kubernetes",
				},
				Vips: map[string]string{
					"192.168.0.1:6443": "1.1.1.1:1,2.2.2.2:2",
					"[fe::1]:1":        "[fe::2]:1,[fe::2]:2",
				},
			},
			&nbdb.LogicalRouterPolicy{
				UUID:     "match3-UUID",
				Match:    matchstr3,
				Priority: nodeSubnetPriority,
			},
			&nbdb.LogicalRouterPolicy{
				UUID:     "match4-UUID",
				Match:    matchstr4,
				Priority: interNodePriority,
			},
			&nbdb.LogicalRouterPolicy{
				UUID:     "match6-UUID",
				Match:    matchstr6,
				Priority: nodeSubnetPriority,
			},
			&nbdb.LogicalRouter{
				Name:     types.OVNClusterRouter,
				UUID:     types.OVNClusterRouter + "-UUID",
				Policies: []string{"match3-UUID", "match4-UUID", "match6-UUID"},
			},
		}
		gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
	})

	ginkgo.It("cleans up a dual-stack gateway in OVN", func() {
		nodeName := "test-node"

		hostSubnets := ovntest.MustParseIPNets("10.130.0.0/23", "fd01:0:0:2::/64")

		mgmtPortIP := util.GetNodeManagementIfAddr(hostSubnets[0]).IP.String()

		mgmtPriority, _ := strconv.Atoi(types.MGMTPortPolicyPriority)
		nodeSubnetPriority, _ := strconv.Atoi(types.NodeSubnetPolicyPriority)
		interNodePriority, _ := strconv.Atoi(types.InterNodePolicyPriority)

		matchstr1 := fmt.Sprintf("ip4.src == %s && ip4.dst == nodePhysicalIP /* %s */", mgmtPortIP, nodeName)
		matchstr2 := fmt.Sprintf(`inport == "rtos-%s" && ip4.dst == nodePhysicalIP /* %s */`, nodeName, nodeName)
		matchstr3 := fmt.Sprintf("ip4.src == source && ip4.dst == nodePhysicalIP")
		matchstr4 := fmt.Sprintf(`ip4.src == NO DELETE  && ip4.dst != 10.244.0.0/16 /* inter-%s-no */`, nodeName)
		matchstr5 := fmt.Sprintf(`ip4.src == 10.244.0.2  && ip4.dst != 10.244.0.0/16 /* inter-%s */`, nodeName)
		matchstr6 := fmt.Sprintf("ip4.src == NO DELETE && ip4.dst == nodePhysicalIP /* %s-no */", nodeName)

		fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				&nbdb.LogicalRouterPort{
					Name:     types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName,
					UUID:     types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName + "-UUID",
					Networks: []string{"100.64.0.1/16", "fd98::1/64"},
				},
				&nbdb.LoadBalancer{
					UUID:     "Service_default/kubernetes_TCP_node_router_ovn-control-plane",
					Name:     "Service_default/kubernetes_TCP_node_router_ovn-control-plane",
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					ExternalIDs: map[string]string{
						"k8s.ovn.org/kind":  "Service",
						"k8s.ovn.org/owner": "default/kubernetes",
					},
					Vips: map[string]string{
						"192.168.0.1:6443": "1.1.1.1:1,2.2.2.2:2",
						"[fe::1]:1":        "[fe::2]:1,[fe::2]:2",
					},
				},
				&nbdb.LogicalRouter{
					Name: types.GWRouterPrefix + nodeName,
					UUID: types.GWRouterPrefix + nodeName + "-UUID",
					LoadBalancer: []string{
						"Service_default/kubernetes_TCP_node_router_ovn-control-plane",
					},
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match1-UUID",
					Match:    matchstr1,
					Priority: mgmtPriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match2-UUID",
					Match:    matchstr2,
					Priority: nodeSubnetPriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match3-UUID",
					Match:    matchstr3,
					Priority: nodeSubnetPriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match4-UUID",
					Match:    matchstr4,
					Priority: interNodePriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match5-UUID",
					Match:    matchstr5,
					Priority: interNodePriority,
				},
				&nbdb.LogicalRouterPolicy{
					UUID:     "match6-UUID",
					Match:    matchstr6,
					Priority: nodeSubnetPriority,
				},
				&nbdb.LogicalRouterStaticRoute{
					Nexthop: "100.64.0.1",
					UUID:    "static-route-1-UUID",
				},
				&nbdb.LogicalRouterStaticRoute{
					Nexthop: "fd98::1",
					UUID:    "static-route-2-UUID",
				},
				&nbdb.LogicalRouter{
					Name:         types.OVNClusterRouter,
					UUID:         types.OVNClusterRouter + "-UUID",
					Policies:     []string{"match1-UUID", "match2-UUID", "match3-UUID", "match4-UUID", "match5-UUID", "match6-UUID"},
					StaticRoutes: []string{"static-route-1-UUID", "static-route-2-UUID"},
				},
				&nbdb.LogicalSwitchPort{
					Name: types.JoinSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName,
					UUID: types.JoinSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName + "-UUID",
				},
				&nbdb.LogicalSwitch{
					Name: types.ExternalSwitchPrefix + nodeName,
					UUID: types.ExternalSwitchPrefix + nodeName + "-UUID ",
				},
				&nbdb.LogicalSwitch{
					Name: types.ExternalSwitchPrefix + types.ExternalSwitchPrefix + nodeName,
					UUID: types.ExternalSwitchPrefix + types.ExternalSwitchPrefix + nodeName + "-UUID",
				},
			},
		})

		err := fakeOvn.controller.gatewayCleanup(nodeName)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		expectedDatabaseState := []libovsdbtest.TestData{
			&nbdb.LogicalRouterPort{
				Name:     types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName,
				UUID:     types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName + "-UUID",
				Networks: []string{"100.64.0.1/16", "fd98::1/64"},
			},
			&nbdb.LoadBalancer{
				UUID:     "Service_default/kubernetes_TCP_node_router_ovn-control-plane",
				Name:     "Service_default/kubernetes_TCP_node_router_ovn-control-plane",
				Protocol: &nbdb.LoadBalancerProtocolTCP,
				ExternalIDs: map[string]string{
					"k8s.ovn.org/kind":  "Service",
					"k8s.ovn.org/owner": "default/kubernetes",
				},
				Vips: map[string]string{
					"192.168.0.1:6443": "1.1.1.1:1,2.2.2.2:2",
					"[fe::1]:1":        "[fe::2]:1,[fe::2]:2",
				},
			},
			&nbdb.LogicalRouterPolicy{
				UUID:     "match3-UUID",
				Match:    matchstr3,
				Priority: nodeSubnetPriority,
			},
			&nbdb.LogicalRouterPolicy{
				UUID:     "match4-UUID",
				Match:    matchstr4,
				Priority: interNodePriority,
			},
			&nbdb.LogicalRouterPolicy{
				UUID:     "match6-UUID",
				Match:    matchstr6,
				Priority: nodeSubnetPriority,
			},
			&nbdb.LogicalRouter{
				Name:     types.OVNClusterRouter,
				UUID:     types.OVNClusterRouter + "-UUID",
				Policies: []string{"match3-UUID", "match4-UUID", "match6-UUID"},
			},
		}
		gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
	})

	ginkgo.It("removes leftover SNAT entries during init", func() {
		expectedOVNClusterRouter := &nbdb.LogicalRouter{
			UUID: types.OVNClusterRouter + "-UUID",
			Name: types.OVNClusterRouter,
		}
		expectedNodeSwitch := &nbdb.LogicalSwitch{
			UUID: nodeName + "-UUID",
			Name: nodeName,
		}
		fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{
				&nbdb.LogicalSwitch{
					UUID: types.OVNJoinSwitch + "-UUID",
					Name: types.OVNJoinSwitch,
				},
				expectedOVNClusterRouter,
				expectedNodeSwitch,
			},
		})

		clusterIPSubnets := ovntest.MustParseIPNets("10.128.0.0/14")
		hostSubnets := ovntest.MustParseIPNets("10.130.0.0/23")
		joinLRPIPs := ovntest.MustParseIPNets("100.64.0.3/16")
		defLRPIPs := ovntest.MustParseIPNets("100.64.0.1/16")
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    ovntest.MustParseIPNets("169.254.33.2/24"),
			NextHops:       ovntest.MustParseIPs("169.254.33.1"),
			NodePortEnable: true,
		}
		sctpSupport := false
		config.Gateway.DisableSNATMultipleGWs = true

		err := fakeOvn.controller.gatewayInit(nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, sctpSupport, joinLRPIPs, defLRPIPs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		testData := []libovsdb.TestData{}
		skipSnat := true
		// We don't set up the Allow from mgmt port ACL here
		mgmtPortIP := ""
		expectedDatabaseState := generateGatewayInitExpectedNB(testData, expectedOVNClusterRouter, expectedNodeSwitch, nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, joinLRPIPs, defLRPIPs, skipSnat, mgmtPortIP)
		gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
	})
})
