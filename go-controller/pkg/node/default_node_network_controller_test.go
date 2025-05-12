package node

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	nadfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	adminpolicybasedrouteclient "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1/apis/clientset/versioned/fake"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/mocks"
	nodenft "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/nftables"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/routemanager"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	netlink_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/vishvananda/netlink"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	utilMocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const v4PMTUDNFTRules = `
add table inet ovn-kubernetes
add rule inet ovn-kubernetes no-pmtud ip daddr @no-pmtud-remote-node-ips-v4 meta l4proto icmp icmp type 3 icmp code 4 counter drop
add chain inet ovn-kubernetes no-pmtud { type filter hook output priority 0 ; comment "Block egress needs frag/packet too big to remote k8s nodes" ; }
add set inet ovn-kubernetes no-pmtud-remote-node-ips-v4 { type ipv4_addr ; comment "Block egress ICMP needs frag to remote Kubernetes nodes" ; }
add set inet ovn-kubernetes no-pmtud-remote-node-ips-v6 { type ipv6_addr ; comment "Block egress ICMPv6 packet too big to remote Kubernetes nodes" ; }
`

const v6PMTUDNFTRules = `
add table inet ovn-kubernetes
add rule inet ovn-kubernetes no-pmtud meta l4proto icmpv6 icmpv6 type 2 icmpv6 code 0 ip6 daddr @no-pmtud-remote-node-ips-v6 counter drop
add chain inet ovn-kubernetes no-pmtud { type filter hook output priority 0 ; comment "Block egress needs frag/packet too big to remote k8s nodes" ; }
add set inet ovn-kubernetes no-pmtud-remote-node-ips-v4 { type ipv4_addr ; comment "Block egress ICMP needs frag to remote Kubernetes nodes" ; }
add set inet ovn-kubernetes no-pmtud-remote-node-ips-v6 { type ipv6_addr ; comment "Block egress ICMPv6 packet too big to remote Kubernetes nodes" ; }
`

var _ = Describe("Node", func() {

	Describe("validateMTU", func() {
		var (
			kubeMock        *mocks.Interface
			netlinkOpsMock  *utilMocks.NetLinkOps
			netlinkLinkMock *netlink_mocks.Link

			nc *DefaultNodeNetworkController
		)

		const (
			nodeName  = "my-node"
			linkName  = "breth0"
			linkIPNet = "10.1.0.40/32"
			linkIndex = 4

			linkIPNet2 = "10.2.0.50/32"
			linkIndex2 = 5

			configDefaultMTU               = 1500 //value for config.Default.MTU
			mtuTooSmallForIPv4AndIPv6      = configDefaultMTU + types.GeneveHeaderLengthIPv4 - 1
			mtuOkForIPv4ButTooSmallForIPv6 = configDefaultMTU + types.GeneveHeaderLengthIPv4
			mtuOkForIPv4AndIPv6            = configDefaultMTU + types.GeneveHeaderLengthIPv6
			mtuTooSmallForSingleNode       = configDefaultMTU - 1
			mtuOkForSingleNode             = configDefaultMTU
		)

		BeforeEach(func() {
			kubeMock = new(mocks.Interface)
			netlinkOpsMock = new(utilMocks.NetLinkOps)
			netlinkLinkMock = new(netlink_mocks.Link)

			util.SetNetLinkOpMockInst(netlinkOpsMock)
			netlinkOpsMock.On("AddrList", nil, netlink.FAMILY_V4).
				Return([]netlink.Addr{
					{LinkIndex: linkIndex, IPNet: ovntest.MustParseIPNet(linkIPNet)},
					{LinkIndex: linkIndex2, IPNet: ovntest.MustParseIPNet(linkIPNet2)}}, nil)
			netlinkOpsMock.On("LinkByIndex", 4).Return(netlinkLinkMock, nil)

			nc = &DefaultNodeNetworkController{
				BaseNodeNetworkController: BaseNodeNetworkController{
					CommonNodeNetworkControllerInfo: CommonNodeNetworkControllerInfo{
						name: nodeName,
						Kube: kubeMock,
					},
					ReconcilableNetInfo: &util.DefaultNetInfo{},
				},
			}

			config.Default.MTU = configDefaultMTU
			config.Default.EffectiveEncapIP = "10.1.0.40"

		})

		AfterEach(func() {
			util.ResetNetLinkOpMockInst() // other tests in this package rely directly on netlink (e.g. gateway_init_linux_test.go)
		})

		Context("with a cluster in IPv4 mode", func() {

			BeforeEach(func() {
				config.IPv4Mode = true
				config.IPv6Mode = false
			})

			Context("with the node having a too small MTU", func() {

				It("should taint the node", func() {
					netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
						MTU:  mtuTooSmallForIPv4AndIPv6,
						Name: linkName,
					})

					err := nc.validateVTEPInterfaceMTU()
					Expect(err).To(HaveOccurred())
				})
			})

			Context("with the node having a big enough MTU", func() {

				It("should untaint the node", func() {
					netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
						MTU:  mtuOkForIPv4ButTooSmallForIPv6,
						Name: linkName,
					})

					err := nc.validateVTEPInterfaceMTU()
					Expect(err).NotTo(HaveOccurred())
				})
			})
		})

		Context("with a cluster in IPv6 mode", func() {
			BeforeEach(func() {
				config.IPv4Mode = false
				config.IPv6Mode = true
			})

			Context("with the node having a too small MTU", func() {

				It("should taint the node", func() {
					netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
						MTU:  mtuTooSmallForIPv4AndIPv6,
						Name: linkName,
					})

					err := nc.validateVTEPInterfaceMTU()
					Expect(err).To(HaveOccurred())
				})
			})

			Context("with the node having a big enough MTU", func() {

				It("should untaint the node", func() {
					netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
						MTU:  mtuOkForIPv4AndIPv6,
						Name: linkName,
					})

					err := nc.validateVTEPInterfaceMTU()
					Expect(err).NotTo(HaveOccurred())
				})
			})
		})

		Context("with a cluster in dual-stack mode", func() {
			BeforeEach(func() {
				config.IPv4Mode = true
				config.IPv6Mode = true
			})

			Context("with the node having a too small MTU", func() {

				It("should taint the node", func() {
					netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
						MTU:  mtuOkForIPv4ButTooSmallForIPv6,
						Name: linkName,
					})

					err := nc.validateVTEPInterfaceMTU()
					Expect(err).To(HaveOccurred())
				})
			})

			Context("with the node having a big enough MTU", func() {

				It("should untaint the node", func() {
					netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
						MTU:  mtuOkForIPv4AndIPv6,
						Name: linkName,
					})

					err := nc.validateVTEPInterfaceMTU()
					Expect(err).NotTo(HaveOccurred())
				})
			})
		})

		Context("with a single-node cluster", func() {
			BeforeEach(func() {
				config.Gateway.SingleNode = true
			})

			Context("with the node having a too small MTU", func() {

				It("should taint the node", func() {
					netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
						MTU:  mtuTooSmallForSingleNode,
						Name: linkName,
					})

					err := nc.validateVTEPInterfaceMTU()
					Expect(err).To(HaveOccurred())
				})
			})

			Context("with the node having a big enough MTU", func() {

				It("should untaint the node", func() {
					netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
						MTU:  mtuOkForSingleNode,
						Name: linkName,
					})

					err := nc.validateVTEPInterfaceMTU()
					Expect(err).NotTo(HaveOccurred())
				})
			})
		})

		Context("with multiple ovn encap IPs", func() {

			BeforeEach(func() {
				config.IPv4Mode = true
				config.IPv6Mode = false
				config.Default.EffectiveEncapIP = "10.1.0.40,10.2.0.50"
				netlinkOpsMock.On("LinkByIndex", 5).Return(netlinkLinkMock, nil)
			})

			It("all interfaces have big enough MTU", func() {
				netlinkLinkMock.On("Attrs").Return(&netlink.LinkAttrs{
					MTU:  mtuOkForIPv4AndIPv6,
					Name: linkName,
				})

				err := nc.validateVTEPInterfaceMTU()
				Expect(err).NotTo(HaveOccurred())
			})
		})

	})

	Describe("Node Operations", func() {
		var app *cli.App

		BeforeEach(func() {
			// Restore global default values before each testcase
			Expect(config.PrepareTestConfig()).To(Succeed())

			app = cli.NewApp()
			app.Name = "test"
			app.Flags = config.Flags
		})

		It("sets correct OVN external IDs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					nodeIP   string = "1.2.5.6"
					nodeName string = "cannot.be.resolv.ed"
					interval int    = 100000
					ofintval int    = 0
				)
				node := corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{
								Type:    corev1.NodeExternalIP,
								Address: nodeIP,
							},
						},
					},
				}

				fexec := ovntest.NewFakeExec()
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
						"external_ids:ovn-encap-type=geneve "+
						"external_ids:ovn-encap-ip=%s "+
						"external_ids:ovn-remote-probe-interval=%d "+
						"external_ids:ovn-bridge-remote-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=true "+
						"external_ids:ovn-set-local-ip=\"true\" "+
						"external_ids:hostname=\"%s\"",
						nodeIP, interval, ofintval, ofintval, nodeName),
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-vsctl --timeout=15 -- clear bridge br-int netflow" +
						" -- " +
						"clear bridge br-int sflow" +
						" -- " +
						"clear bridge br-int ipfix",
				})
				err := util.SetExec(fexec)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				config.OvnKubeNode.Mode = types.NodeModeFull
				err = setupOVNNode(&node)
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
		It("sets non-default OVN encap port", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					nodeIP      string = "1.2.5.6"
					nodeName    string = "cannot.be.resolv.ed"
					encapPort   uint   = 666
					interval    int    = 100000
					ofintval    int    = 0
					chassisUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
					encapUUID   string = "e4437094-0094-4223-9f14-995d98d5fff8"
				)

				fexec := ovntest.NewFakeExec()
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 " +
						"--if-exists get Open_vSwitch . external_ids:system-id"),
					Output: chassisUUID,
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovn-sbctl --timeout=15 --no-leader-only --data=bare --no-heading --columns=_uuid find "+
						"Encap chassis_name=%s", chassisUUID),
					Output: encapUUID,
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovn-sbctl --timeout=15 --no-leader-only set encap "+
						"%s options:dst_port=%d", encapUUID, encapPort),
				})

				err := util.SetExec(fexec)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())
				config.Default.EncapPort = encapPort
				err = setEncapPort(context.Background())
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
		It("sets non-default logical flow cache limits", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					nodeIP   string = "1.2.5.6"
					nodeName string = "cannot.be.resolv.ed"
					interval int    = 100000
					ofintval int    = 0
				)
				node := corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{
								Type:    corev1.NodeExternalIP,
								Address: nodeIP,
							},
						},
					},
				}

				fexec := ovntest.NewFakeExec()
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
						"external_ids:ovn-encap-type=geneve "+
						"external_ids:ovn-encap-ip=%s "+
						"external_ids:ovn-remote-probe-interval=%d "+
						"external_ids:ovn-bridge-remote-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=false "+
						"external_ids:ovn-set-local-ip=\"true\" "+
						"external_ids:ovn-limit-lflow-cache=1000 "+
						"external_ids:ovn-memlimit-lflow-cache-kb=100000 "+
						"external_ids:hostname=\"%s\"",
						nodeIP, interval, ofintval, ofintval, nodeName),
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-vsctl --timeout=15 -- clear bridge br-int netflow" +
						" -- " +
						"clear bridge br-int sflow" +
						" -- " +
						"clear bridge br-int ipfix",
				})
				err := util.SetExec(fexec)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				config.Default.LFlowCacheEnable = false
				config.Default.LFlowCacheLimit = 1000
				config.Default.LFlowCacheLimitKb = 100000
				config.OvnKubeNode.Mode = types.NodeModeFull
				err = setupOVNNode(&node)
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
		It("sets default IPFIX configuration", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					nodeIP    string = "1.2.5.6"
					nodeName  string = "cannot.be.resolv.ed"
					interval  int    = 100000
					ofintval  int    = 0
					ipfixPort int32  = 456
				)
				ipfixIP := net.IP{1, 2, 3, 4}

				node := corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{
								Type:    corev1.NodeExternalIP,
								Address: nodeIP,
							},
						},
					},
				}

				fexec := ovntest.NewFakeExec()
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
						"external_ids:ovn-encap-type=geneve "+
						"external_ids:ovn-encap-ip=%s "+
						"external_ids:ovn-remote-probe-interval=%d "+
						"external_ids:ovn-bridge-remote-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=true "+
						"external_ids:ovn-set-local-ip=\"true\" "+
						"external_ids:hostname=\"%s\"",
						nodeIP, interval, ofintval, ofintval, nodeName),
				})

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-vsctl --timeout=15 -- clear bridge br-int netflow" +
						" -- " +
						"clear bridge br-int sflow" +
						" -- " +
						"clear bridge br-int ipfix",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15"+
						" -- "+
						"--id=@ipfix create ipfix "+
						"targets=[\"%s:%d\"] cache_active_timeout=60 sampling=400"+
						" -- "+
						"set bridge br-int ipfix=@ipfix", ipfixIP, ipfixPort),
				})
				err := util.SetExec(fexec)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())
				config.Monitoring.IPFIXTargets = []config.HostPort{
					{Host: &ipfixIP, Port: ipfixPort},
				}
				err = setupOVNNode(&node)
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
		It("allows overriding IPFIX configuration", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					nodeIP    string = "1.2.5.6"
					nodeName  string = "cannot.be.resolv.ed"
					interval  int    = 100000
					ofintval  int    = 0
					ipfixPort int32  = 456
				)
				ipfixIP := net.IP{1, 2, 3, 4}

				node := corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{
								Type:    corev1.NodeExternalIP,
								Address: nodeIP,
							},
						},
					},
				}

				fexec := ovntest.NewFakeExec()
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
						"external_ids:ovn-encap-type=geneve "+
						"external_ids:ovn-encap-ip=%s "+
						"external_ids:ovn-remote-probe-interval=%d "+
						"external_ids:ovn-bridge-remote-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=true "+
						"external_ids:ovn-set-local-ip=\"true\" "+
						"external_ids:hostname=\"%s\"",
						nodeIP, interval, ofintval, ofintval, nodeName),
				})

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-vsctl --timeout=15 -- clear bridge br-int netflow" +
						" -- " +
						"clear bridge br-int sflow" +
						" -- " +
						"clear bridge br-int ipfix",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15"+
						" -- "+
						"--id=@ipfix create ipfix "+
						"targets=[\"%s:%d\"] cache_active_timeout=123 cache_max_flows=456 sampling=789"+
						" -- "+
						"set bridge br-int ipfix=@ipfix", ipfixIP, ipfixPort),
				})
				err := util.SetExec(fexec)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())
				config.Monitoring.IPFIXTargets = []config.HostPort{
					{Host: &ipfixIP, Port: ipfixPort},
				}
				config.IPFIX.CacheActiveTimeout = 123
				config.IPFIX.CacheMaxFlows = 456
				config.IPFIX.Sampling = 789
				err = setupOVNNode(&node)
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
		It("uses Node IP when the flow tracing targets only specify a port", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					nodeIP   string = "1.2.5.6"
					nodeName string = "anyhost.test"
					interval int    = 100000
					ofintval int    = 0
				)
				node := corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{
								Type:    corev1.NodeExternalIP,
								Address: nodeIP,
							},
						},
					},
				}

				fexec := ovntest.NewFakeExec()
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
						"external_ids:ovn-encap-type=geneve "+
						"external_ids:ovn-encap-ip=%s "+
						"external_ids:ovn-remote-probe-interval=%d "+
						"external_ids:ovn-bridge-remote-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=true "+
						"external_ids:ovn-set-local-ip=\"true\" "+
						"external_ids:hostname=\"%s\"",
						nodeIP, interval, ofintval, ofintval, nodeName),
				})

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-vsctl --timeout=15 -- clear bridge br-int netflow" +
						" -- " +
						"clear bridge br-int sflow" +
						" -- " +
						"clear bridge br-int ipfix",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-vsctl --timeout=15" +
						" -- " +
						"--id=@ipfix create ipfix " +
						// verify that the 1.2.5.6 IP has been attached to the :8888 target below
						`targets=["10.0.0.2:3030","1.2.5.6:8888","[2020:1111:f::1:933]:3333"] cache_active_timeout=60` +
						" -- " +
						"set bridge br-int ipfix=@ipfix",
				})
				err := util.SetExec(fexec)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				config.Monitoring.IPFIXTargets, err =
					config.ParseFlowCollectors("10.0.0.2:3030,:8888,[2020:1111:f::1:0933]:3333")
				config.IPFIX.CacheActiveTimeout = 60
				config.IPFIX.CacheMaxFlows = 0
				config.IPFIX.Sampling = 0
				Expect(err).NotTo(HaveOccurred())

				err = setupOVNNode(&node)
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})
	Describe("node pmtud management", func() {
		var (
			testNS ns.NetNS
			nc     *DefaultNodeNetworkController
			app    *cli.App
		)

		const (
			nodeName       = "my-node"
			remoteNodeName = "other-node"
		)

		BeforeEach(func() {
			var err error
			testNS, err = testutils.NewNS()
			Expect(err).NotTo(HaveOccurred())
			Expect(config.PrepareTestConfig()).To(Succeed())

			app = cli.NewApp()
			app.Name = "test"
			app.Flags = config.Flags
		})

		AfterEach(func() {
			util.ResetNetLinkOpMockInst() // other tests in this package rely directly on netlink (e.g. gateway_init_linux_test.go)
			Expect(testNS.Close()).To(Succeed())
		})

		Context("with a cluster in IPv4 mode", func() {
			const (
				ethName           string = "lo1337"
				nodeIP            string = "169.254.254.60"
				ethCIDR           string = nodeIP + "/24"
				otherNodeIP       string = "169.254.254.61"
				otherSubnetNodeIP string = "169.254.253.61"
				fullMask                 = 32
			)
			var link netlink.Link

			BeforeEach(func() {
				config.IPv4Mode = true
				config.IPv6Mode = false
				config.Gateway.Mode = config.GatewayModeShared

				// Note we must do this in default netNS because
				// nc.WatchNodes() will spawn goroutines which we cannot lock to the testNS
				ovntest.AddLink(ethName)

				var err error
				link, err = netlink.LinkByName(ethName)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(link)
				Expect(err).NotTo(HaveOccurred())

				// Add an IP address
				addr, err := netlink.ParseAddr(ethCIDR)
				Expect(err).NotTo(HaveOccurred())
				addr.Scope = int(netlink.SCOPE_UNIVERSE)
				err = netlink.AddrAdd(link, addr)
				Expect(err).NotTo(HaveOccurred())

			})

			AfterEach(func() {
				err := netlink.LinkDel(link)
				Expect(err).NotTo(HaveOccurred())
			})

			ovntest.OnSupportedPlatformsIt("adds and removes nftables rule for node in same subnet", func() {

				app.Action = func(_ *cli.Context) error {
					node := corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: nodeName,
						},
						Status: corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: nodeIP,
								},
							},
						},
					}

					otherNode := corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: remoteNodeName,
						},
						Status: corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: otherNodeIP,
								},
							},
						},
					}
					nft := nodenft.SetFakeNFTablesHelper()

					kubeFakeClient := fake.NewSimpleClientset(&corev1.NodeList{
						Items: []corev1.Node{node, otherNode},
					})
					fakeClient := &util.OVNNodeClientset{
						KubeClient:             kubeFakeClient,
						AdminPolicyRouteClient: adminpolicybasedrouteclient.NewSimpleClientset(),
						NetworkAttchDefClient:  nadfake.NewSimpleClientset(),
					}

					stop := make(chan struct{})
					wf, err := factory.NewNodeWatchFactory(fakeClient, nodeName)
					Expect(err).NotTo(HaveOccurred())
					wg := &sync.WaitGroup{}
					defer func() {
						close(stop)
						wg.Wait()
						wf.Shutdown()
					}()

					err = wf.Start()
					Expect(err).NotTo(HaveOccurred())
					routeManager := routemanager.NewController()
					cnnci := NewCommonNodeNetworkControllerInfo(kubeFakeClient, fakeClient.AdminPolicyRouteClient, wf, nil, nodeName, routeManager)
					nc = newDefaultNodeNetworkController(cnnci, stop, wg, routeManager, nil)
					nc.initRetryFrameworkForNode()
					err = setupPMTUDNFTSets()
					Expect(err).NotTo(HaveOccurred())
					err = setupPMTUDNFTChain()
					Expect(err).NotTo(HaveOccurred())
					defaultNetConfig := &bridgeUDNConfiguration{
						ofPortPatch: "patch-breth0_ov",
					}
					nc.Gateway = &gateway{
						openflowManager: &openflowManager{
							flowCache: map[string][]string{},
							defaultBridge: &bridgeConfiguration{
								netConfig: map[string]*bridgeUDNConfiguration{
									types.DefaultNetworkName: defaultNetConfig,
								},
							},
						},
					}

					// must run route manager manually which is usually started with nc.Start()
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						nc.routeManager.Run(stop, 10*time.Second)
						Expect(err).NotTo(HaveOccurred())
					}()
					By("start up should add nftables rules for remote node")

					err = nc.WatchNodes()
					Expect(err).NotTo(HaveOccurred())
					nftRules := v4PMTUDNFTRules + `
add element inet ovn-kubernetes no-pmtud-remote-node-ips-v4 { 169.254.254.61 }
`
					err = nodenft.MatchNFTRules(nftRules, nft.Dump())
					Expect(err).NotTo(HaveOccurred())
					gw := nc.Gateway.(*gateway)
					By("start up should add openflow rules for remote node")
					flows := gw.openflowManager.getFlowsByKey(getPMTUDKey(remoteNodeName))
					Expect(flows).To(HaveLen(1))

					By("deleting the remote node should remove the nftables element")
					err = kubeFakeClient.CoreV1().Nodes().Delete(context.TODO(), remoteNodeName, metav1.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(func() error {
						return nodenft.MatchNFTRules(v4PMTUDNFTRules, nft.Dump())
					}).WithTimeout(2 * time.Second).ShouldNot(HaveOccurred())
					Eventually(func() []string { return gw.openflowManager.getFlowsByKey(getPMTUDKey(remoteNodeName)) }).WithTimeout(2 * time.Second).Should(BeEmpty())
					return nil

				}

				err := app.Run([]string{app.Name})
				Expect(err).NotTo(HaveOccurred())
			})

			ovntest.OnSupportedPlatformsIt("adds and removes nftables rule for node in different subnet", func() {

				app.Action = func(_ *cli.Context) error {
					node := corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: nodeName,
						},
						Status: corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: nodeIP,
								},
							},
						},
					}

					otherNode := corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: remoteNodeName,
						},
						Status: corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: otherSubnetNodeIP,
								},
							},
						},
					}
					nft := nodenft.SetFakeNFTablesHelper()

					kubeFakeClient := fake.NewSimpleClientset(&corev1.NodeList{
						Items: []corev1.Node{node, otherNode},
					})
					fakeClient := &util.OVNNodeClientset{
						KubeClient:             kubeFakeClient,
						AdminPolicyRouteClient: adminpolicybasedrouteclient.NewSimpleClientset(),
						NetworkAttchDefClient:  nadfake.NewSimpleClientset(),
					}

					stop := make(chan struct{})
					wf, err := factory.NewNodeWatchFactory(fakeClient, nodeName)
					Expect(err).NotTo(HaveOccurred())
					wg := &sync.WaitGroup{}
					defer func() {
						close(stop)
						wg.Wait()
						wf.Shutdown()
					}()

					err = wf.Start()
					Expect(err).NotTo(HaveOccurred())
					routeManager := routemanager.NewController()
					cnnci := NewCommonNodeNetworkControllerInfo(kubeFakeClient, fakeClient.AdminPolicyRouteClient, wf, nil, nodeName, routeManager)
					nc = newDefaultNodeNetworkController(cnnci, stop, wg, routeManager, nil)
					nc.initRetryFrameworkForNode()
					err = setupPMTUDNFTSets()
					Expect(err).NotTo(HaveOccurred())
					err = setupPMTUDNFTChain()
					Expect(err).NotTo(HaveOccurred())
					defaultNetConfig := &bridgeUDNConfiguration{
						ofPortPatch: "patch-breth0_ov",
					}
					nc.Gateway = &gateway{
						openflowManager: &openflowManager{
							flowCache: map[string][]string{},
							defaultBridge: &bridgeConfiguration{
								netConfig: map[string]*bridgeUDNConfiguration{
									types.DefaultNetworkName: defaultNetConfig,
								},
							},
						},
					}

					// must run route manager manually which is usually started with nc.Start()
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						nc.routeManager.Run(stop, 10*time.Second)
						Expect(err).NotTo(HaveOccurred())
					}()
					By("start up should add nftables rules for remote node")

					err = nc.WatchNodes()
					Expect(err).NotTo(HaveOccurred())
					nftRules := v4PMTUDNFTRules + `
add element inet ovn-kubernetes no-pmtud-remote-node-ips-v4 { 169.254.253.61 }
`
					err = nodenft.MatchNFTRules(nftRules, nft.Dump())
					Expect(err).NotTo(HaveOccurred())
					gw := nc.Gateway.(*gateway)
					By("start up should add openflow rules for remote node")
					flows := gw.openflowManager.getFlowsByKey(getPMTUDKey(remoteNodeName))
					Expect(flows).To(HaveLen(1))

					By("deleting the remote node should remove the nftables element")
					err = kubeFakeClient.CoreV1().Nodes().Delete(context.TODO(), remoteNodeName, metav1.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(func() error {
						return nodenft.MatchNFTRules(v4PMTUDNFTRules, nft.Dump())
					}).WithTimeout(2 * time.Second).ShouldNot(HaveOccurred())
					Eventually(func() []string { return gw.openflowManager.getFlowsByKey(getPMTUDKey(remoteNodeName)) }).WithTimeout(2 * time.Second).Should(BeEmpty())
					return nil

				}

				err := app.Run([]string{app.Name})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("with a cluster in IPv6 mode", func() {
			const (
				ethName           string = "lo1337"
				nodeIP            string = "2001:db8:1::3"
				ethCIDR           string = nodeIP + "/64"
				otherNodeIP       string = "2001:db8:1::4"
				otherSubnetNodeIP string = "2002:db8:1::4"
				fullMask                 = 128
			)

			var link netlink.Link

			BeforeEach(func() {
				config.IPv4Mode = false
				config.IPv6Mode = true
				config.Gateway.Mode = config.GatewayModeShared

				// Note we must do this in default netNS because
				// nc.WatchNodes() will spawn goroutines which we cannot lock to the testNS
				ovntest.AddLink(ethName)

				var err error
				link, err = netlink.LinkByName(ethName)
				Expect(err).NotTo(HaveOccurred())
				err = netlink.LinkSetUp(link)
				Expect(err).NotTo(HaveOccurred())

				// Add an IP address
				addr, err := netlink.ParseAddr(ethCIDR)
				Expect(err).NotTo(HaveOccurred())
				addr.Scope = int(netlink.SCOPE_UNIVERSE)
				err = netlink.AddrAdd(link, addr)
				Expect(err).NotTo(HaveOccurred())

			})

			AfterEach(func() {
				err := netlink.LinkDel(link)
				Expect(err).NotTo(HaveOccurred())
			})

			ovntest.OnSupportedPlatformsIt("adds and removes nftables rule for node in same subnet", func() {

				app.Action = func(_ *cli.Context) error {
					node := corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: nodeName,
						},
						Status: corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: nodeIP,
								},
							},
						},
					}

					otherNode := corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: remoteNodeName,
						},
						Status: corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: otherNodeIP,
								},
							},
						},
					}
					nft := nodenft.SetFakeNFTablesHelper()

					kubeFakeClient := fake.NewSimpleClientset(&corev1.NodeList{
						Items: []corev1.Node{node, otherNode},
					})
					fakeClient := &util.OVNNodeClientset{
						KubeClient:             kubeFakeClient,
						AdminPolicyRouteClient: adminpolicybasedrouteclient.NewSimpleClientset(),
						NetworkAttchDefClient:  nadfake.NewSimpleClientset(),
					}

					stop := make(chan struct{})
					wf, err := factory.NewNodeWatchFactory(fakeClient, nodeName)
					Expect(err).NotTo(HaveOccurred())
					wg := &sync.WaitGroup{}
					defer func() {
						close(stop)
						wg.Wait()
						wf.Shutdown()
					}()

					err = wf.Start()
					Expect(err).NotTo(HaveOccurred())
					routeManager := routemanager.NewController()
					cnnci := NewCommonNodeNetworkControllerInfo(kubeFakeClient, fakeClient.AdminPolicyRouteClient, wf, nil, nodeName, routeManager)
					nc = newDefaultNodeNetworkController(cnnci, stop, wg, routeManager, nil)
					nc.initRetryFrameworkForNode()
					err = setupPMTUDNFTSets()
					Expect(err).NotTo(HaveOccurred())
					err = setupPMTUDNFTChain()
					Expect(err).NotTo(HaveOccurred())
					defaultNetConfig := &bridgeUDNConfiguration{
						ofPortPatch: "patch-breth0_ov",
					}
					nc.Gateway = &gateway{
						openflowManager: &openflowManager{
							flowCache: map[string][]string{},
							defaultBridge: &bridgeConfiguration{
								netConfig: map[string]*bridgeUDNConfiguration{
									types.DefaultNetworkName: defaultNetConfig,
								},
							},
						},
					}

					// must run route manager manually which is usually started with nc.Start()
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						nc.routeManager.Run(stop, 10*time.Second)
						Expect(err).NotTo(HaveOccurred())
					}()
					By("start up should add nftables rules for remote node")

					err = nc.WatchNodes()
					Expect(err).NotTo(HaveOccurred())
					nftRules := v6PMTUDNFTRules + `
add element inet ovn-kubernetes no-pmtud-remote-node-ips-v6 { 2001:db8:1::4 }
`
					err = nodenft.MatchNFTRules(nftRules, nft.Dump())
					Expect(err).NotTo(HaveOccurred())
					gw := nc.Gateway.(*gateway)
					By("start up should add openflow rules for remote node")
					flows := gw.openflowManager.getFlowsByKey(getPMTUDKey(remoteNodeName))
					Expect(flows).To(HaveLen(1))

					By("deleting the remote node should remove the nftables element")
					err = kubeFakeClient.CoreV1().Nodes().Delete(context.TODO(), remoteNodeName, metav1.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(func() error {
						return nodenft.MatchNFTRules(v6PMTUDNFTRules, nft.Dump())
					}).WithTimeout(2 * time.Second).ShouldNot(HaveOccurred())
					Eventually(func() []string { return gw.openflowManager.getFlowsByKey(getPMTUDKey(remoteNodeName)) }).WithTimeout(2 * time.Second).Should(BeEmpty())
					return nil
				}

				err := app.Run([]string{app.Name})
				Expect(err).NotTo(HaveOccurred())
			})

			ovntest.OnSupportedPlatformsIt("adds and removes nftables rule for node in different subnet", func() {

				app.Action = func(_ *cli.Context) error {
					node := corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: nodeName,
						},
						Status: corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: nodeIP,
								},
							},
						},
					}

					otherNode := corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: remoteNodeName,
						},
						Status: corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: otherSubnetNodeIP,
								},
							},
						},
					}
					nft := nodenft.SetFakeNFTablesHelper()

					kubeFakeClient := fake.NewSimpleClientset(&corev1.NodeList{
						Items: []corev1.Node{node, otherNode},
					})
					fakeClient := &util.OVNNodeClientset{
						KubeClient:             kubeFakeClient,
						AdminPolicyRouteClient: adminpolicybasedrouteclient.NewSimpleClientset(),
						NetworkAttchDefClient:  nadfake.NewSimpleClientset(),
					}

					stop := make(chan struct{})
					wf, err := factory.NewNodeWatchFactory(fakeClient, nodeName)
					Expect(err).NotTo(HaveOccurred())
					wg := &sync.WaitGroup{}
					defer func() {
						close(stop)
						wg.Wait()
						wf.Shutdown()
					}()

					err = wf.Start()
					Expect(err).NotTo(HaveOccurred())
					routeManager := routemanager.NewController()
					cnnci := NewCommonNodeNetworkControllerInfo(kubeFakeClient, fakeClient.AdminPolicyRouteClient, wf, nil, nodeName, routeManager)
					nc = newDefaultNodeNetworkController(cnnci, stop, wg, routeManager, nil)
					nc.initRetryFrameworkForNode()
					err = setupPMTUDNFTSets()
					Expect(err).NotTo(HaveOccurred())
					err = setupPMTUDNFTChain()
					Expect(err).NotTo(HaveOccurred())
					defaultNetConfig := &bridgeUDNConfiguration{
						ofPortPatch: "patch-breth0_ov",
					}
					nc.Gateway = &gateway{
						openflowManager: &openflowManager{
							flowCache: map[string][]string{},
							defaultBridge: &bridgeConfiguration{
								netConfig: map[string]*bridgeUDNConfiguration{
									types.DefaultNetworkName: defaultNetConfig,
								},
							},
						},
					}

					// must run route manager manually which is usually started with nc.Start()
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						nc.routeManager.Run(stop, 10*time.Second)
						Expect(err).NotTo(HaveOccurred())
					}()
					By("start up should add nftables rules for remote node")

					err = nc.WatchNodes()
					Expect(err).NotTo(HaveOccurred())
					nftRules := v6PMTUDNFTRules + `
add element inet ovn-kubernetes no-pmtud-remote-node-ips-v6 { 2002:db8:1::4 }
`
					err = nodenft.MatchNFTRules(nftRules, nft.Dump())
					Expect(err).NotTo(HaveOccurred())
					gw := nc.Gateway.(*gateway)
					By("start up should add openflow rules for remote node")
					flows := gw.openflowManager.getFlowsByKey(getPMTUDKey(remoteNodeName))
					Expect(flows).To(HaveLen(1))

					By("deleting the remote node should remove the nftables element")
					err = kubeFakeClient.CoreV1().Nodes().Delete(context.TODO(), remoteNodeName, metav1.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(func() error {
						return nodenft.MatchNFTRules(v6PMTUDNFTRules, nft.Dump())
					}).WithTimeout(2 * time.Second).ShouldNot(HaveOccurred())
					Eventually(func() []string { return gw.openflowManager.getFlowsByKey(getPMTUDKey(remoteNodeName)) }).WithTimeout(2 * time.Second).Should(BeEmpty())
					return nil
				}

				err := app.Run([]string{app.Name})
				Expect(err).NotTo(HaveOccurred())
			})

		})

	})

})
