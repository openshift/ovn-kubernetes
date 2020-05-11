package ovn

import (
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Gateway Init Operations", func() {
	It("correctly sorts gateway routers", func() {
		fexec := ovntest.NewFakeExec()
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovn-nbctl --timeout=15 --data=bare --format=table --no-heading --columns=name,options find logical_router options:lb_force_snat_ip!=-",
			Output: `node5      chassis=842fdade-747a-43b8-b40a-d8e8e26379fa lb_force_snat_ip=100.64.0.5
node2 chassis=6a47b33b-89d3-4d65-ac31-b19b549326c7 lb_force_snat_ip=100.64.0.2
node1 chassis=d17ddb5a-050d-42ab-ab50-7c6ce79a8f2e lb_force_snat_ip=100.64.0.1
node4 chassis=912d592c-904c-40cd-9ef1-c2e5b49a33dd lb_force_snat_ip=100.64.0.4`,
		})

		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		name, ip, err := getDefaultGatewayRouterIP()
		Expect(err).NotTo(HaveOccurred())
		Expect(name).To(Equal("node1"))
		Expect(ip.String()).To(Equal("100.64.0.1"))
		Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
	})

	It("ignores malformatted gateway router entires", func() {
		fexec := ovntest.NewFakeExec()
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovn-nbctl --timeout=15 --data=bare --format=table --no-heading --columns=name,options find logical_router options:lb_force_snat_ip!=-",
			Output: `node5      chassis=842fdade-747a-43b8-b40a-d8e8e26379fa lb_force_snat_ip=100.64.0.5
node2 chassis=6a47b33b-89d3-4d65-ac31-b19b549326c7 lb_force_snat_ip=asdfsadf
node1 chassis=d17ddb5a-050d-42ab-ab50-7c6ce79a8f2e lb_force_xxxxxxx=100.64.0.1
node4 chassis=912d592c-904c-40cd-9ef1-c2e5b49a33dd lb_force_snat_ip=100.64.0.4`,
		})

		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		name, ip, err := getDefaultGatewayRouterIP()
		Expect(err).NotTo(HaveOccurred())
		Expect(name).To(Equal("node4"))
		Expect(ip.String()).To(Equal("100.64.0.4"))
		Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
	})

	It("creates an IPv4 gateway in OVN", func() {
		clusterIPSubnet := []*net.IPNet{ovntest.MustParseIPNet("10.128.0.0/14")}
		hostSubnets := []*net.IPNet{ovntest.MustParseIPNet("10.130.0.0/23")}
		joinSubnets := []*net.IPNet{ovntest.MustParseIPNet("100.64.0.0/29")}
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    []*net.IPNet{ovntest.MustParseIPNet("169.254.33.2/24")},
			NextHops:       []net.IP{ovntest.MustParseIP("169.254.33.1")},
			NodePortEnable: true,
		}
		sctpSupport := false

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 -- --may-exist lr-add GR_test-node -- set logical_router GR_test-node options:chassis=SYSTEM-ID external_ids:physical_ip=169.254.33.2 external_ids:physical_ips=169.254.33.2",
			"ovn-nbctl --timeout=15 -- --may-exist ls-add join_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add join_test-node jtor-GR_test-node -- set logical_switch_port jtor-GR_test-node type=router options:router-port=rtoj-GR_test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoj-GR_test-node -- lrp-add GR_test-node rtoj-GR_test-node 0a:58:64:40:00:01 100.64.0.1/29",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add join_test-node jtod-test-node -- set logical_switch_port jtod-test-node type=router options:router-port=dtoj-test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del dtoj-test-node -- lrp-add ovn_cluster_router dtoj-test-node 0a:58:64:40:00:02 100.64.0.2/29",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:lb_force_snat_ip=100.64.0.1",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 10.128.0.0/14 100.64.0.2",
		})

		const (
			tcpLBUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
			udpLBUUID string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
		)
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=GR_test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=GR_test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:UDP_lb_gateway_router=GR_test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set logical_router GR_test-node load_balancer=" + tcpLBUUID + "," + udpLBUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --may-exist ls-add ext_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node INTERFACE-ID -- lsp-set-addresses INTERFACE-ID unknown -- lsp-set-type INTERFACE-ID localnet -- lsp-set-options INTERFACE-ID network_name=physnet",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoe-GR_test-node -- lrp-add GR_test-node rtoe-GR_test-node 11:22:33:44:55:66 169.254.33.2/24 -- set logical_router_port rtoe-GR_test-node external-ids:gateway-physical-ip=yes",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node etor-GR_test-node -- set logical_switch_port etor-GR_test-node type=router options:router-port=rtoe-GR_test-node addresses=\"11:22:33:44:55:66\"",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 0.0.0.0/0 169.254.33.1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router 10.130.0.0/23 100.64.0.1",
			"ovn-nbctl --timeout=15 --may-exist lr-nat-add GR_test-node snat 169.254.33.2 10.128.0.0/14",
		})

		err = gatewayInit(nodeName, clusterIPSubnet, hostSubnets, joinSubnets, l3GatewayConfig, sctpSupport)
		Expect(err).NotTo(HaveOccurred())
		Expect(fexec.CalledMatchesExpected()).To(BeTrue())
	})

	It("creates an IPv6 gateway in OVN", func() {
		clusterIPSubnet := []*net.IPNet{ovntest.MustParseIPNet("fd01::/48")}
		hostSubnets := []*net.IPNet{ovntest.MustParseIPNet("fd01:0:0:2::/64")}
		joinSubnets := []*net.IPNet{ovntest.MustParseIPNet("fd98::/125")}
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    []*net.IPNet{ovntest.MustParseIPNet("fd99::2/64")},
			NextHops:       []net.IP{ovntest.MustParseIP("fd99::1")},
			NodePortEnable: true,
		}
		sctpSupport := false

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 -- --may-exist lr-add GR_test-node -- set logical_router GR_test-node options:chassis=SYSTEM-ID external_ids:physical_ip=fd99::2 external_ids:physical_ips=fd99::2",
			"ovn-nbctl --timeout=15 -- --may-exist ls-add join_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add join_test-node jtor-GR_test-node -- set logical_switch_port jtor-GR_test-node type=router options:router-port=rtoj-GR_test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoj-GR_test-node -- lrp-add GR_test-node rtoj-GR_test-node 0a:58:fd:98:00:01 fd98::1/125",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add join_test-node jtod-test-node -- set logical_switch_port jtod-test-node type=router options:router-port=dtoj-test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del dtoj-test-node -- lrp-add ovn_cluster_router dtoj-test-node 0a:58:fd:98:00:02 fd98::2/125",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:lb_force_snat_ip=fd98::1",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node fd01::/48 fd98::2",
		})

		const (
			tcpLBUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
			udpLBUUID string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
		)
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=GR_test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=GR_test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:UDP_lb_gateway_router=GR_test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set logical_router GR_test-node load_balancer=" + tcpLBUUID + "," + udpLBUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --may-exist ls-add ext_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node INTERFACE-ID -- lsp-set-addresses INTERFACE-ID unknown -- lsp-set-type INTERFACE-ID localnet -- lsp-set-options INTERFACE-ID network_name=physnet",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoe-GR_test-node -- lrp-add GR_test-node rtoe-GR_test-node 11:22:33:44:55:66 fd99::2/64 -- set logical_router_port rtoe-GR_test-node external-ids:gateway-physical-ip=yes",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node etor-GR_test-node -- set logical_switch_port etor-GR_test-node type=router options:router-port=rtoe-GR_test-node addresses=\"11:22:33:44:55:66\"",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node ::/0 fd99::1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router fd01:0:0:2::/64 fd98::1",
			"ovn-nbctl --timeout=15 --may-exist lr-nat-add GR_test-node snat fd99::2 fd01::/48",
		})

		err = gatewayInit(nodeName, clusterIPSubnet, hostSubnets, joinSubnets, l3GatewayConfig, sctpSupport)
		Expect(err).NotTo(HaveOccurred())
		Expect(fexec.CalledMatchesExpected()).To(BeTrue())
	})

	It("creates a dual-stack gateway in OVN", func() {
		clusterIPSubnets := []*net.IPNet{
			ovntest.MustParseIPNet("10.128.0.0/14"),
			ovntest.MustParseIPNet("fd01::/48"),
		}
		hostSubnets := []*net.IPNet{
			ovntest.MustParseIPNet("10.130.0.0/23"),
			ovntest.MustParseIPNet("fd01:0:0:2::/64"),
		}
		joinSubnets := []*net.IPNet{
			ovntest.MustParseIPNet("100.64.0.0/29"),
			ovntest.MustParseIPNet("fd98::/125"),
		}
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:        config.GatewayModeLocal,
			ChassisID:   "SYSTEM-ID",
			InterfaceID: "INTERFACE-ID",
			MACAddress:  ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses: []*net.IPNet{
				ovntest.MustParseIPNet("169.254.33.2/24"),
				ovntest.MustParseIPNet("fd99::2/64"),
			},
			NextHops: []net.IP{
				ovntest.MustParseIP("169.254.33.1"),
				ovntest.MustParseIP("fd99::1"),
			},
			NodePortEnable: true,
		}
		sctpSupport := false

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 -- --may-exist lr-add GR_test-node -- set logical_router GR_test-node options:chassis=SYSTEM-ID external_ids:physical_ip=169.254.33.2 external_ids:physical_ips=169.254.33.2,fd99::2",
			"ovn-nbctl --timeout=15 -- --may-exist ls-add join_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add join_test-node jtor-GR_test-node -- set logical_switch_port jtor-GR_test-node type=router options:router-port=rtoj-GR_test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoj-GR_test-node -- lrp-add GR_test-node rtoj-GR_test-node 0a:58:64:40:00:01 100.64.0.1/29 fd98::1/125",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add join_test-node jtod-test-node -- set logical_switch_port jtod-test-node type=router options:router-port=dtoj-test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del dtoj-test-node -- lrp-add ovn_cluster_router dtoj-test-node 0a:58:64:40:00:02 100.64.0.2/29 fd98::2/125",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:lb_force_snat_ip=100.64.0.1",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 10.128.0.0/14 100.64.0.2",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node fd01::/48 fd98::2",
		})

		const (
			tcpLBUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
			udpLBUUID string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
		)
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=GR_test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=GR_test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:UDP_lb_gateway_router=GR_test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set logical_router GR_test-node load_balancer=" + tcpLBUUID + "," + udpLBUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --may-exist ls-add ext_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node INTERFACE-ID -- lsp-set-addresses INTERFACE-ID unknown -- lsp-set-type INTERFACE-ID localnet -- lsp-set-options INTERFACE-ID network_name=physnet",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoe-GR_test-node -- lrp-add GR_test-node rtoe-GR_test-node 11:22:33:44:55:66 169.254.33.2/24 fd99::2/64 -- set logical_router_port rtoe-GR_test-node external-ids:gateway-physical-ip=yes",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node etor-GR_test-node -- set logical_switch_port etor-GR_test-node type=router options:router-port=rtoe-GR_test-node addresses=\"11:22:33:44:55:66\"",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 0.0.0.0/0 169.254.33.1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node ::/0 fd99::1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router 10.130.0.0/23 100.64.0.1",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router fd01:0:0:2::/64 fd98::1",
			"ovn-nbctl --timeout=15 --may-exist lr-nat-add GR_test-node snat 169.254.33.2 10.128.0.0/14",
			"ovn-nbctl --timeout=15 --may-exist lr-nat-add GR_test-node snat fd99::2 fd01::/48",
		})

		err = gatewayInit(nodeName, clusterIPSubnets, hostSubnets, joinSubnets, l3GatewayConfig, sctpSupport)
		Expect(err).NotTo(HaveOccurred())
		Expect(fexec.CalledMatchesExpected()).To(BeTrue())
	})

	It("cleans up a single-stack gateway in OVN", func() {
		nodeName := "test-node"
		hostSubnet := ovntest.MustParseIPNet("10.130.0.0/23")
		const (
			nodeRouteUUID    string = "0cac12cf-3e0f-4682-b028-5ea2e0001962"
			nodemgtRouteUUID string = "0cac12cf-3e0f-4682-b028-5ea2e0001963"
			tcpLBUUID        string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
		)

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --if-exist get logical_router_port rtoj-GR_test-node networks",
			Output: "[\"100.64.0.1/29\"]",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"100.64.0.1\"",
			Output: nodeRouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + nodeRouteUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"10.130.0.2\"",
			Output: nodemgtRouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + nodemgtRouteUUID,
			"ovn-nbctl --timeout=15 --if-exist ls-del join_test-node",
			"ovn-nbctl --timeout=15 --if-exist lr-del GR_test-node",
			"ovn-nbctl --timeout=15 --if-exist ls-del ext_test-node",
			"ovn-nbctl --timeout=15 --if-exist lrp-del dtoj-test-node",
		})

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=GR_test-node",
			Output: "",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=GR_test-node",
			Output: "",
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 lb-del " + tcpLBUUID,
		})

		err = gatewayCleanup(nodeName, []*net.IPNet{hostSubnet})
		Expect(err).NotTo(HaveOccurred())
		Expect(fexec.CalledMatchesExpected()).To(BeTrue())
	})

	It("cleans up a dual-stack gateway in OVN", func() {
		nodeName := "test-node"
		hostSubnets := []*net.IPNet{
			ovntest.MustParseIPNet("10.130.0.0/23"),
			ovntest.MustParseIPNet("fd01:0:0:2::/64"),
		}
		const (
			v4RouteUUID    string = "0cac12cf-3e0f-4682-b028-5ea2e0001962"
			v6RouteUUID    string = "0cac12cf-4682-3e0f-b028-5ea2e0001962"
			v4mgtRouteUUID string = "0cac12cf-3e0f-4682-b028-5ea2e0001963"
			v6mgtRouteUUID string = "0cac12cf-4682-3e0f-b028-5ea2e0001963"
			tcpLBUUID      string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
		)

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --if-exist get logical_router_port rtoj-GR_test-node networks",
			Output: "[\"100.64.0.1/29\", \"fd98::1/125\"]",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"100.64.0.1\"",
			Output: v4RouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + v4RouteUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"fd98::1\"",
			Output: v6RouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + v6RouteUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"10.130.0.2\"",
			Output: v4mgtRouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + v4mgtRouteUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"fd01:0:0:2::2\"",
			Output: v6mgtRouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + v6mgtRouteUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exist ls-del join_test-node",
			"ovn-nbctl --timeout=15 --if-exist lr-del GR_test-node",
			"ovn-nbctl --timeout=15 --if-exist ls-del ext_test-node",
			"ovn-nbctl --timeout=15 --if-exist lrp-del dtoj-test-node",
		})

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=GR_test-node",
			Output: "",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=GR_test-node",
			Output: "",
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 lb-del " + tcpLBUUID,
		})

		err = gatewayCleanup(nodeName, hostSubnets)
		Expect(err).NotTo(HaveOccurred())
		Expect(fexec.CalledMatchesExpected()).To(BeTrue())
	})
})
