package node

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/stretchr/testify/mock"
	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/mocks"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	netlink_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/vishvananda/netlink"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	utilMocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

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
					NetInfo: &util.DefaultNetInfo{},
				},
			}

			config.Default.MTU = configDefaultMTU
			config.Default.EncapIP = "10.1.0.40"

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
				config.Default.EncapIP = "10.1.0.40,10.2.0.50"
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
					ofintval int    = 180
				)
				node := kapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: kapi.NodeStatus{
						Addresses: []kapi.NodeAddress{
							{
								Type:    kapi.NodeExternalIP,
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
						"external_ids:ovn-openflow-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:hostname=\"%s\" "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=true "+
						"external_ids:ovn-set-local-ip=\"true\"",
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
					ofintval    int    = 180
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
					ofintval int    = 180
				)
				node := kapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: kapi.NodeStatus{
						Addresses: []kapi.NodeAddress{
							{
								Type:    kapi.NodeExternalIP,
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
						"external_ids:ovn-openflow-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:hostname=\"%s\" "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=false "+
						"external_ids:ovn-set-local-ip=\"true\" "+
						"external_ids:ovn-limit-lflow-cache=1000 "+
						"external_ids:ovn-memlimit-lflow-cache-kb=100000",
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
					ofintval  int    = 180
					ipfixPort int32  = 456
				)
				ipfixIP := net.IP{1, 2, 3, 4}

				node := kapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: kapi.NodeStatus{
						Addresses: []kapi.NodeAddress{
							{
								Type:    kapi.NodeExternalIP,
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
						"external_ids:ovn-openflow-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:hostname=\"%s\" "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=true "+
						"external_ids:ovn-set-local-ip=\"true\"",
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
					ofintval  int    = 180
					ipfixPort int32  = 456
				)
				ipfixIP := net.IP{1, 2, 3, 4}

				node := kapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: kapi.NodeStatus{
						Addresses: []kapi.NodeAddress{
							{
								Type:    kapi.NodeExternalIP,
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
						"external_ids:ovn-openflow-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:hostname=\"%s\" "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=true "+
						"external_ids:ovn-set-local-ip=\"true\"",
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
					ofintval int    = 180
				)
				node := kapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
					Status: kapi.NodeStatus{
						Addresses: []kapi.NodeAddress{
							{
								Type:    kapi.NodeExternalIP,
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
						"external_ids:ovn-openflow-probe-interval=%d "+
						"other_config:bundle-idle-timeout=%d "+
						"external_ids:hostname=\"%s\" "+
						"external_ids:ovn-is-interconn=false "+
						"external_ids:ovn-monitor-all=true "+
						"external_ids:ovn-ofctrl-wait-before-clear=0 "+
						"external_ids:ovn-enable-lflow-cache=true "+
						"external_ids:ovn-set-local-ip=\"true\"",
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

	Describe("reconcileConntrackUponEndpointSliceEvents", func() {
		const (
			testNamespace     = "test-ns"
			testServiceName   = "test-service"
			testEndpointSlice = "test-endpointslice"
		)

		var (
			udpProtocol       = corev1.ProtocolUDP
			tcpProtocol       = corev1.ProtocolTCP
			testEndpointPort1 = int32(8080)
			testEndpointPort2 = int32(8443)
			testServicePort1  = int32(80)
			testServicePort2  = int32(443)
		)

		// expectedConntrackFilter represents the expected parameters for a conntrack filter
		type expectedConntrackFilter struct {
			ip       string
			port     uint16
			protocol uint8
			family   netlink.InetFamily
		}

		// Test data structure for table-driven tests
		type reconcileConntrackTestCase struct {
			desc                   string
			service                *corev1.Service // nil means service not found
			oldEndpointSlice       *discovery.EndpointSlice
			newEndpointSlice       *discovery.EndpointSlice
			expectedConntrackCalls int
			expectedFilters        []expectedConntrackFilter
		}

		// Helper to create EndpointSlice
		makeEndpointSlice := func(portConfigs []struct {
			name     *string
			port     int32
			protocol corev1.Protocol
		}, addresses []string) *discovery.EndpointSlice {
			ports := make([]discovery.EndpointPort, len(portConfigs))
			for i, pc := range portConfigs {
				p := pc.port
				proto := pc.protocol
				ports[i] = discovery.EndpointPort{
					Name:     pc.name,
					Port:     &p,
					Protocol: &proto,
				}
			}

			return &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testEndpointSlice,
					Namespace: testNamespace,
					Labels: map[string]string{
						discovery.LabelServiceName: testServiceName,
					},
				},
				Ports: ports,
				Endpoints: []discovery.Endpoint{
					{Addresses: addresses},
				},
			}
		}

		// Helper to create Service
		makeService := func(portConfigs []struct {
			name       string
			port       int32
			targetPort int32
			protocol   corev1.Protocol
		}) *corev1.Service {
			ports := make([]corev1.ServicePort, len(portConfigs))
			for i, pc := range portConfigs {
				ports[i] = corev1.ServicePort{
					Name:       pc.name,
					Port:       pc.port,
					TargetPort: intstr.FromInt(int(pc.targetPort)),
					Protocol:   pc.protocol,
				}
			}

			return &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testServiceName,
					Namespace: testNamespace,
				},
				Spec: corev1.ServiceSpec{
					Ports: ports,
				},
			}
		}

		// Helper function to build expected ConntrackFilter for verification
		buildExpectedFilter := func(ef expectedConntrackFilter) *netlink.ConntrackFilter {
			filter := &netlink.ConntrackFilter{}

			// Add protocol
			if err := filter.AddProtocol(ef.protocol); err != nil {
				GinkgoT().Fatalf("Failed to add protocol to expected filter: %v", err)
			}

			// Add port
			if ef.port > 0 {
				if err := filter.AddPort(netlink.ConntrackOrigDstPort, ef.port); err != nil {
					GinkgoT().Fatalf("Failed to add port to expected filter: %v", err)
				}
			}

			// Add IP
			ipAddr := net.ParseIP(ef.ip)
			if ipAddr == nil {
				GinkgoT().Fatalf("Invalid IP address: %s", ef.ip)
			}
			if err := filter.AddIP(netlink.ConntrackReplyAnyIP, ipAddr); err != nil {
				GinkgoT().Fatalf("Failed to add IP to expected filter: %v", err)
			}

			return filter
		}

		DescribeTable("should handle conntrack deletion correctly",
			func(tc reconcileConntrackTestCase) {
				// Setup mock for ConntrackDeleteFilter
				mockNetLinkOps := new(utilMocks.NetLinkOps)
				util.SetNetLinkOpMockInst(mockNetLinkOps)
				defer util.ResetNetLinkOpMockInst()

				// Mock ConntrackDeleteFilter
				mockNetLinkOps.On("ConntrackDeleteFilter",
					mock.AnythingOfType("netlink.ConntrackTableType"),
					mock.AnythingOfType("netlink.InetFamily"),
					mock.AnythingOfType("*netlink.ConntrackFilter")).
					Return(uint(1), nil).Maybe()

				// Setup fake client with service if provided
				var fakeClient *fake.Clientset
				if tc.service != nil {
					fakeClient = fake.NewSimpleClientset(tc.service)
				} else {
					fakeClient = fake.NewSimpleClientset()
				}

				wf, err := factory.NewNodeWatchFactory(&util.OVNNodeClientset{
					KubeClient: fakeClient,
				}, "test-node")
				Expect(err).NotTo(HaveOccurred())
				defer wf.Shutdown()

				err = wf.Start()
				Expect(err).NotTo(HaveOccurred())

				nc := &DefaultNodeNetworkController{
					BaseNodeNetworkController: BaseNodeNetworkController{
						CommonNodeNetworkControllerInfo: CommonNodeNetworkControllerInfo{
							watchFactory: wf,
						},
					},
				}

				// Execute the function under test
				err = nc.reconcileConntrackUponEndpointSliceEvents(tc.oldEndpointSlice, tc.newEndpointSlice)
				Expect(err).NotTo(HaveOccurred())

				// Verify the number of ConntrackDeleteFilter calls
				mockNetLinkOps.AssertNumberOfCalls(GinkgoT(), "ConntrackDeleteFilter", tc.expectedConntrackCalls)

				// Collect all actual filters from the mock calls.
				actualFilters := []*netlink.ConntrackFilter{}
				for _, call := range mockNetLinkOps.Calls {
					if call.Method == "ConntrackDeleteFilter" {
						_, ok1 := call.Arguments.Get(0).(netlink.ConntrackTableType)
						_, ok2 := call.Arguments.Get(1).(netlink.InetFamily)
						filter, ok3 := call.Arguments.Get(2).(*netlink.ConntrackFilter)

						if ok1 && ok2 && ok3 {
							actualFilters = append(actualFilters, filter)
						}
					}
				}

				// Build the list of expected filters.
				expectedNetlinkFilters := make([]*netlink.ConntrackFilter, 0, len(tc.expectedFilters))
				for _, expectedFilter := range tc.expectedFilters {
					expectedNetlinkFilters = append(expectedNetlinkFilters, buildExpectedFilter(expectedFilter))
				}

				// Use gomega's ConsistOf to compare the actual and expected filters.
				Expect(actualFilters).To(ConsistOf(expectedNetlinkFilters), "The set of conntrack filters to be deleted should match the expected set.")
			},

			Entry("old endpointslice is nil",
				reconcileConntrackTestCase{
					desc: "should not delete any conntrack entries when old endpoint is nil",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{{name: "", port: testServicePort1, targetPort: testEndpointPort1, protocol: udpProtocol}}),
					oldEndpointSlice:       nil,
					newEndpointSlice:       &discovery.EndpointSlice{},
					expectedConntrackCalls: 0,
				},
			),

			Entry("service exists with matching unnamed port",
				reconcileConntrackTestCase{
					desc: "should delete conntrack with service port for unnamed port",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{{name: "", port: testServicePort1, targetPort: testEndpointPort1, protocol: udpProtocol}}),
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{{name: nil, port: testEndpointPort1, protocol: udpProtocol}},
						[]string{"10.0.0.1"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 1,
					expectedFilters: []expectedConntrackFilter{
						{ip: "10.0.0.1", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V4},
					},
				},
			),

			Entry("service exists with matching named port",
				reconcileConntrackTestCase{
					desc: "should delete conntrack with service port for named port",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{{name: "http", port: testServicePort1, targetPort: testEndpointPort1, protocol: udpProtocol}}),
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{{name: strPtr("http"), port: testEndpointPort1, protocol: udpProtocol}},
						[]string{"10.0.0.1"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 1,
					expectedFilters: []expectedConntrackFilter{
						{ip: "10.0.0.1", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V4},
					},
				},
			),

			Entry("service exists but port name mismatch",
				reconcileConntrackTestCase{
					desc: "should skip conntrack deletion when port name doesn't match",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{{name: "http", port: testServicePort1, targetPort: testEndpointPort1, protocol: udpProtocol}}),
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{{name: strPtr("grpc"), port: testEndpointPort1, protocol: udpProtocol}},
						[]string{"10.0.0.1"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 0,
				},
			),

			Entry("service not found",
				reconcileConntrackTestCase{
					desc:    "should return early without deleting conntrack when service not found",
					service: nil,
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{{name: nil, port: testEndpointPort1, protocol: udpProtocol}},
						[]string{"10.0.0.1"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 0,
				},
			),

			Entry("TCP protocol should be skipped",
				reconcileConntrackTestCase{
					desc: "should skip conntrack deletion for TCP protocol",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{{name: "", port: testServicePort1, targetPort: testEndpointPort1, protocol: tcpProtocol}}),
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{{name: nil, port: testEndpointPort1, protocol: tcpProtocol}},
						[]string{"10.0.0.1"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 0,
				},
			),

			Entry("multiple endpoints",
				reconcileConntrackTestCase{
					desc: "should delete conntrack for each endpoint",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{{name: "", port: testServicePort1, targetPort: testEndpointPort1, protocol: udpProtocol}}),
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{{name: nil, port: testEndpointPort1, protocol: udpProtocol}},
						[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 3,
					expectedFilters: []expectedConntrackFilter{
						{ip: "10.0.0.1", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V4},
						{ip: "10.0.0.2", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V4},
						{ip: "10.0.0.3", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V4},
					},
				},
			),

			Entry("IPv6 endpoint",
				reconcileConntrackTestCase{
					desc: "should delete conntrack for IPv6 endpoint",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{{name: "", port: testServicePort1, targetPort: testEndpointPort1, protocol: udpProtocol}}),
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{{name: nil, port: testEndpointPort1, protocol: udpProtocol}},
						[]string{"fd00::1"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 1,
					expectedFilters: []expectedConntrackFilter{
						{ip: "fd00::1", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V6},
					},
				},
			),

			Entry("dual-stack endpoints",
				reconcileConntrackTestCase{
					desc: "should delete conntrack for both IPv4 and IPv6",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{{name: "", port: testServicePort1, targetPort: testEndpointPort1, protocol: udpProtocol}}),
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{{name: nil, port: testEndpointPort1, protocol: udpProtocol}},
						[]string{"10.0.0.1", "fd00::1"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 2,
					expectedFilters: []expectedConntrackFilter{
						{ip: "10.0.0.1", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V4},
						{ip: "fd00::1", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V6},
					},
				},
			),

			Entry("multiple service ports with matching names",
				reconcileConntrackTestCase{
					desc: "should match correct service port by name for multiple ports",
					service: makeService([]struct {
						name       string
						port       int32
						targetPort int32
						protocol   corev1.Protocol
					}{
						{name: "http", port: testServicePort1, targetPort: testEndpointPort1, protocol: udpProtocol},
						{name: "https", port: testServicePort2, targetPort: testEndpointPort2, protocol: udpProtocol},
					}),
					oldEndpointSlice: makeEndpointSlice(
						[]struct {
							name     *string
							port     int32
							protocol corev1.Protocol
						}{
							{name: strPtr("http"), port: testEndpointPort1, protocol: udpProtocol},
							{name: strPtr("https"), port: testEndpointPort2, protocol: udpProtocol},
						},
						[]string{"10.0.0.1"},
					),
					newEndpointSlice:       nil,
					expectedConntrackCalls: 2,
					expectedFilters: []expectedConntrackFilter{
						{ip: "10.0.0.1", port: uint16(testServicePort1), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V4},
						{ip: "10.0.0.1", port: uint16(testServicePort2), protocol: syscall.IPPROTO_UDP, family: netlink.FAMILY_V4},
					},
				},
			),
		)
	})
})

// Helper function to create string pointer
func strPtr(s string) *string {
	return &s
}
