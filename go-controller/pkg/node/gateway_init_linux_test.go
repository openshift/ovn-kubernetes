// +build linux

package node

import (
	"bytes"
	"fmt"
	"syscall"

	"github.com/urfave/cli"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func shareGatewayInterfaceTest(app *cli.App, testNS ns.NetNS,
	eth0Name, eth0MAC, eth0IP, eth0GWIP, eth0CIDR string, gatewayVLANID uint) {
	const clusterCIDR string = "10.1.0.0/16"
	app.Action = func(ctx *cli.Context) error {
		const (
			nodeName   string = "node1"
			systemID   string = "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6"
			nodeSubnet string = "10.1.1.0/24"
		)

		fexec := ovntest.NewFakeExec()
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovs-vsctl --timeout=15 -- port-to-br eth0",
			Err: fmt.Errorf(""),
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovs-vsctl --timeout=15 -- br-exists eth0",
			Err: fmt.Errorf(""),
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovs-vsctl --timeout=15 -- --may-exist add-br breth0 -- br-set-external-id breth0 bridge-id breth0 -- br-set-external-id breth0 bridge-uplink eth0 -- set bridge breth0 fail-mode=standalone other_config:hwaddr=" + eth0MAC + " -- --may-exist add-port breth0 eth0 -- set port eth0 other-config:transient=true",
			Action: func() error {
				return testNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					// Create breth0 as a dummy link
					err := netlink.LinkAdd(&netlink.Dummy{
						LinkAttrs: netlink.LinkAttrs{
							Name:         "br" + eth0Name,
							HardwareAddr: ovntest.MustParseMAC(eth0MAC),
						},
					})
					Expect(err).NotTo(HaveOccurred())
					_, err = netlink.LinkByName("br" + eth0Name)
					Expect(err).NotTo(HaveOccurred())
					return nil
				})
			},
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface breth0 mac_in_use",
			Output: eth0MAC,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovs-vsctl --timeout=15 set bridge breth0 other-config:hwaddr=" + eth0MAC,
			"ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:ovn-bridge-mappings=" + util.PhysicalNetworkName + ":breth0",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:system-id",
			Output: systemID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-ofctl --no-stats --no-names dump-flows br-int table=41,ip,nw_src=" + clusterCIDR,
			Output: ` cookie=0x770ac8a6, table=41, priority=17,ip,metadata=0x3,nw_src=` + clusterCIDR + ` actions=ct(commit,table=42,zone=NXM_NX_REG12[0..15],nat(src=` + eth0IP + `))`,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=15 wait-until Interface patch-breth0_node1-to-br-int ofport>0 -- get Interface patch-breth0_node1-to-br-int ofport",
			Output: "5",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface eth0 ofport",
			Output: "7",
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovs-ofctl -O OpenFlow13 replace-flows breth0 -",
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovs-ofctl add-flow breth0 cookie=0xdeff105, priority=100, in_port=5, ip, actions=ct(commit, zone=64000), output:7",
			"ovs-ofctl add-flow breth0 cookie=0xdeff105, priority=50, in_port=7, ip, actions=ct(zone=64000, table=1)",
			"ovs-ofctl add-flow breth0 cookie=0xdeff105, priority=100, table=1, ct_state=+trk+est, actions=output:5",
			"ovs-ofctl add-flow breth0 cookie=0xdeff105, priority=100, table=1, ct_state=+trk+rel, actions=output:5",
			"ovs-ofctl add-flow breth0 cookie=0xdeff105, priority=0, table=1, actions=output:NORMAL",
		})
		// nodePortWatcher()
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface patch-breth0_node1-to-br-int ofport",
			Output: "5",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface eth0 ofport",
			Output: "7",
		})
		// syncServices()
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovs-ofctl dump-flows breth0",
			Output: `cookie=0x0, duration=8366.605s, table=0, n_packets=0, n_bytes=0, priority=100,ip,in_port="patch-breth0_no" actions=ct(commit,zone=64000),output:eth0
cookie=0x0, duration=8366.603s, table=0, n_packets=10642, n_bytes=10370438, priority=50,ip,in_port=eth0 actions=ct(table=1,zone=64000)
cookie=0x0, duration=8366.705s, table=0, n_packets=11549, n_bytes=1746901, priority=0 actions=NORMAL
cookie=0x0, duration=8366.602s, table=1, n_packets=0, n_bytes=0, priority=100,ct_state=+est+trk actions=output:"patch-breth0_no"
cookie=0x0, duration=8366.600s, table=1, n_packets=0, n_bytes=0, priority=100,ct_state=+rel+trk actions=output:"patch-breth0_no"
cookie=0x0, duration=8366.597s, table=1, n_packets=10641, n_bytes=10370087, priority=0 actions=LOCAL
`,
		})

		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		_, err = config.InitConfig(ctx, fexec, nil)
		Expect(err).NotTo(HaveOccurred())

		existingNode := v1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		}}

		fakeClient := fake.NewSimpleClientset(&v1.NodeList{
			Items: []v1.Node{existingNode},
		})

		stop := make(chan struct{})
		wf, err := factory.NewWatchFactory(fakeClient, stop)
		Expect(err).NotTo(HaveOccurred())
		defer close(stop)

		n := NewNode(nil, wf, existingNode.Name, stop)

		ipt, err := util.NewFakeWithProtocol(iptables.ProtocolIPv4)
		Expect(err).NotTo(HaveOccurred())

		nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient}, &existingNode)

		err = util.SetNodeHostSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNet(nodeSubnet))
		Expect(err).NotTo(HaveOccurred())
		err = nodeAnnotator.Run()
		Expect(err).NotTo(HaveOccurred())

		err = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			waiter := newStartupWaiter()
			err = n.initGateway(ovntest.MustParseIPNet(nodeSubnet), nodeAnnotator, waiter)
			Expect(err).NotTo(HaveOccurred())

			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())
			err = waiter.Wait()
			Expect(err).NotTo(HaveOccurred())

			// Verify the code moved eth0's IP address, MAC, and routes
			// over to breth0
			l, err := netlink.LinkByName("breth0")
			Expect(err).NotTo(HaveOccurred())
			addrs, err := netlink.AddrList(l, syscall.AF_INET)
			Expect(err).NotTo(HaveOccurred())
			var found bool
			expectedAddr, err := netlink.ParseAddr(eth0CIDR)
			Expect(err).NotTo(HaveOccurred())
			for _, a := range addrs {
				if a.IP.Equal(expectedAddr.IP) && bytes.Equal(a.Mask, expectedAddr.Mask) {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())

			Expect(l.Attrs().HardwareAddr.String()).To(Equal(eth0MAC))
			return nil
		})

		Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)

		expectedTables := map[string]util.FakeTable{
			"filter": {},
			"nat":    {},
		}
		Expect(ipt.MatchState(expectedTables)).NotTo(HaveOccurred())
		return nil
	}

	err := app.Run([]string{
		app.Name,
		"--cluster-subnets=" + clusterCIDR,
		"--init-gateways",
		"--gateway-interface=" + eth0Name,
		"--nodeport",
		"--gateway-vlanid=" + fmt.Sprintf("%d", gatewayVLANID),
	})
	Expect(err).NotTo(HaveOccurred())
}

var _ = Describe("Gateway Init Operations", func() {
	var app *cli.App
	var testNS ns.NetNS

	BeforeEach(func() {
		var err error
		testNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		// Set up a fake br-local & LocalnetGatewayNextHopPort
		testNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		err = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err := netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: "br-local",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: localnetGatewayNextHopPort,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(testNS.Close()).To(Succeed())
	})

	It("sets up a localnet gateway", func() {
		const mtu string = "1234"

		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName      string = "node1"
				brLocalnetMAC string = "11:22:33:44:55:66"
				brNextHopIp   string = "169.254.33.1"
				brNextHopCIDR string = brNextHopIp + "/24"
				systemID      string = "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6"
				nodeSubnet    string = "10.1.1.0/24"
			)

			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-vsctl --timeout=15 --may-exist add-br br-local",
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface br-local mac_in_use",
				Output: brLocalnetMAC,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-vsctl --timeout=15 set bridge br-local other-config:hwaddr=" + brLocalnetMAC,
				"ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:ovn-bridge-mappings=" + util.PhysicalNetworkName + ":br-local",
				"ovs-vsctl --timeout=15 --if-exists del-port br-local " + legacyLocalnetGatewayNextHopPort +
					" -- --may-exist add-port br-local " + localnetGatewayNextHopPort + " -- set interface " + localnetGatewayNextHopPort + " type=internal mtu_request=" + mtu + " mac=00\\:00\\:a9\\:fe\\:21\\:01",
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:system-id",
				Output: systemID,
			})

			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			existingNode := v1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			}}
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{existingNode},
			})
			stop := make(chan struct{})
			wf, err := factory.NewWatchFactory(fakeClient, stop)
			Expect(err).NotTo(HaveOccurred())
			defer close(stop)

			ipt, err := util.NewFakeWithProtocol(iptables.ProtocolIPv4)
			Expect(err).NotTo(HaveOccurred())
			util.SetIPTablesHelper(iptables.ProtocolIPv4, ipt)

			nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient}, &existingNode)
			err = util.SetNodeHostSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNet(nodeSubnet))
			Expect(err).NotTo(HaveOccurred())
			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			err = testNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				err = initLocalnetGateway(nodeName, ovntest.MustParseIPNet(nodeSubnet), wf, nodeAnnotator)
				Expect(err).NotTo(HaveOccurred())
				// Check if IP has been assigned to LocalnetGatewayNextHopPort
				link, err := netlink.LinkByName(localnetGatewayNextHopPort)
				Expect(err).NotTo(HaveOccurred())
				addrs, err := netlink.AddrList(link, syscall.AF_INET)
				Expect(err).NotTo(HaveOccurred())
				var foundAddr bool
				expectedAddr, err := netlink.ParseAddr(brNextHopCIDR)
				Expect(err).NotTo(HaveOccurred())
				for _, a := range addrs {
					if a.IP.Equal(expectedAddr.IP) && bytes.Equal(a.Mask, expectedAddr.Mask) {
						foundAddr = true
						break
					}
				}
				Expect(foundAddr).To(BeTrue())
				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)

			expectedTables := map[string]util.FakeTable{
				"filter": {
					"INPUT": []string{
						"-i " + localnetGatewayNextHopPort + " -m comment --comment from OVN to localhost -j ACCEPT",
					},
					"FORWARD": []string{
						"-j OVN-KUBE-NODEPORT",
						"-o " + localnetGatewayNextHopPort + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
						"-i " + localnetGatewayNextHopPort + " -j ACCEPT",
					},
					"OVN-KUBE-NODEPORT": []string{},
				},
				"nat": {
					"POSTROUTING": []string{
						"-s 169.254.33.2 -j MASQUERADE",
					},
					"PREROUTING": []string{
						"-j OVN-KUBE-NODEPORT",
					},
					"OUTPUT": []string{
						"-j OVN-KUBE-NODEPORT",
					},
					"OVN-KUBE-NODEPORT": []string{},
				},
			}
			Expect(ipt.MatchState(expectedTables)).NotTo(HaveOccurred())
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"--init-gateways",
			"--gateway-local",
			"--nodeport",
			"--mtu=" + mtu,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	Context("for NIC-based operations", func() {
		const (
			eth0Name string = "eth0"
			eth0IP   string = "192.168.1.10"
			eth0CIDR string = eth0IP + "/24"
			eth0GWIP string = "192.168.1.1"
		)
		var eth0MAC string

		BeforeEach(func() {
			// Set up a fake eth0
			err := testNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				err := netlink.LinkAdd(&netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Name: eth0Name,
					},
				})
				Expect(err).NotTo(HaveOccurred())
				l, err := netlink.LinkByName(eth0Name)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(l)
				Expect(err).NotTo(HaveOccurred())

				// Add an IP address
				addr, err := netlink.ParseAddr(eth0CIDR)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.AddrAdd(l, addr)
				Expect(err).NotTo(HaveOccurred())

				eth0MAC = l.Attrs().HardwareAddr.String()

				// And a default route
				err = netlink.RouteAdd(&netlink.Route{
					LinkIndex: l.Attrs().Index,
					Scope:     netlink.SCOPE_UNIVERSE,
					Dst:       ovntest.MustParseIPNet("0.0.0.0/0"),
					Gw:        ovntest.MustParseIP(eth0GWIP),
				})
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("sets up a shared interface gateway", func() {
			shareGatewayInterfaceTest(app, testNS, eth0Name, eth0MAC, eth0IP, eth0GWIP, eth0CIDR, 0)
		})

		It("sets up a shared interface gateway with tagged VLAN", func() {
			shareGatewayInterfaceTest(app, testNS, eth0Name, eth0MAC, eth0IP, eth0GWIP, eth0CIDR, 3000)
		})

	})
})
