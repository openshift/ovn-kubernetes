package node

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/urfave/cli/v2"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/knftables"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressserviceapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressservice/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/controllers/egressservice"
	nodenft "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/nftables"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const nftablesRulesEgressServicesBase = `
add table inet ovn-kubernetes
add chain inet ovn-kubernetes egress-services { type nat hook postrouting priority 100 ; }
add map inet ovn-kubernetes egress-service-snat-v4 { type ipv4_addr : ipv4_addr ; }
add rule inet ovn-kubernetes egress-services mark == 0x3f0 return comment "DoNotSNAT"
add rule inet ovn-kubernetes egress-services snat to ip saddr map @egress-service-snat-v4
`

var _ = Describe("Egress Service Operations", func() {
	var (
		app         *cli.App
		fExec       *ovntest.FakeExec
		nft         *knftables.Fake
		netlinkMock *mocks.NetLinkOps
	)

	origNetlinkInst := util.GetNetLinkOps()

	BeforeEach(func() {
		// Restore global default values before each testcase
		Expect(config.PrepareTestConfig()).To(Succeed())
		netlinkMock = &mocks.NetLinkOps{}
		util.SetNetLinkOpMockInst(netlinkMock)

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
		_, _ = util.SetFakeIPTablesHelpers()
		fExec = ovntest.NewLooseCompareFakeExec()
		err := util.SetExec(fExec)
		Expect(err).NotTo(HaveOccurred())

		config.OVNKubernetesFeature.EnableEgressService = true
		_, cidr4, _ := net.ParseCIDR("10.128.0.0/16")
		config.Default.ClusterSubnets = []config.CIDRNetworkEntry{{CIDR: cidr4, HostSubnetLength: 24}}

		nft = nodenft.SetFakeNFTablesHelper()
	})

	AfterEach(func() {
		util.SetNetLinkOpMockInst(origNetlinkInst)
		config.OVNKubernetesFeature.EnableEgressService = false
	})

	Context("on egress service resource changes", func() {
		It("repairs nftables and ip rules when stale entries are present", func() {
			app.Action = func(*cli.Context) error {
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 --json rule show",
					Output: "[{\"priority\":5000,\"src\":\"10.128.0.3\",\"table\":\"wrongTable\"},{\"priority\":5000,\"src\":\"goneEp\",\"table\":\"mynetwork\"}," +
						"{\"priority\":5000,\"src\":\"10.128.0.3\",\"table\":\"mynetwork\"},{\"priority\":5000,\"src\":\"10.129.0.2\",\"table\":\"mynetwork\"}," +
						"{\"priority\":5000,\"src\":\"10.128.0.33\",\"table\":\"mynetwork2\"},{\"priority\":5000,\"src\":\"10.129.0.3\",\"table\":\"mynetwork2\"}," +
						"{\"priority\":5000,\"src\":\"10.128.0.4\",\"table\":\"mynetwork\"},{\"priority\":5000,\"src\":\"10.129.0.4\",\"table\":\"mynetwork\"}," +
						fmt.Sprintf("{\"priority\":5000,\"src\":\"%s\",\"sport\":31111,\"table\":\"mynetwork\"},", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP) +
						fmt.Sprintf("{\"priority\":5000,\"src\":\"%s\",\"sport\":30300,\"table\":\"mynetwork2\"}]", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP),
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.128.0.3 table wrongTable",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from goneEp table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ip -4 rule del prio 5000 from %s sport 31111 table mynetwork", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP),
					Err: nil,
				})

				tx := nft.NewTransaction()
				tx.Add(&knftables.Map{
					Name: egressservice.NFTablesMapV4,
					Type: "ipv4_addr : ipv4_addr",
				})
				tx.Add(&knftables.Element{
					Map:     egressservice.NFTablesMapV4,
					Key:     []string{"10.128.0.3"},
					Value:   []string{"5.5.5.5"},
					Comment: knftables.PtrTo("namespace1/service1"),
				})
				tx.Add(&knftables.Element{
					Map:     egressservice.NFTablesMapV4,
					Key:     []string{"10.128.0.88"}, // gone ep
					Value:   []string{"5.5.5.5"},
					Comment: knftables.PtrTo("namespace1/service1"),
				})
				tx.Add(&knftables.Element{
					Map:     egressservice.NFTablesMapV4,
					Key:     []string{"10.128.0.4"},
					Value:   []string{"5.200.5.12"}, // wrong lb
					Comment: knftables.PtrTo("namespace1/service3"),
				})
				tx.Add(&knftables.Element{
					Map:     egressservice.NFTablesMapV4,
					Key:     []string{"10.128.0.5"},
					Value:   []string{"1.2.3.4"},
					Comment: knftables.PtrTo("namespace13service6"), // gone service
				})
				tx.Add(&knftables.Element{
					Map:     egressservice.NFTablesMapV4,
					Key:     []string{"10.128.0.33"},
					Value:   []string{"1.2.3.4"},
					Comment: knftables.PtrTo("namespace1/service2"), // service with host=ALL
				})

				Expect(nft.Run(context.Background(), tx)).To(Succeed())
				epPortName := "https"
				epPortValue := int32(443)

				egressService := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "namespace1",
					},
					Spec: egressserviceapi.EgressServiceSpec{
						Network: "mynetwork",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: fakeNodeName,
					},
				}
				service := *newService("service1", "namespace1", "10.129.0.2",
					[]corev1.ServicePort{
						{
							NodePort: int32(31111),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "5.5.5.5",
							}},
						},
					},
					false, false,
				)

				ep1 := discovery.Endpoint{
					Addresses: []string{"10.128.0.3"},
				}
				epPort := discovery.EndpointPort{
					Name: &epPortName,
					Port: &epPortValue,
				}

				// host-networked endpoint, should not have an SNAT rule created
				ep2 := discovery.Endpoint{
					Addresses: []string{"192.168.18.15"},
					NodeName:  &fakeNodeName,
				}
				// endpointSlice.Endpoints is ovn-networked so this will
				// come under !hasLocalHostNetEp case
				endpointSlice := *newEndpointSlice(
					"service1",
					"namespace1",
					[]discovery.Endpoint{ep1, ep2},
					[]discovery.EndpointPort{epPort})

				egressService2 := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service2",
						Namespace: "namespace1",
					},
					Spec: egressserviceapi.EgressServiceSpec{
						Network: "mynetwork2",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: "ALL",
					},
				}
				service2 := *newService("service2", "namespace1", "10.129.0.3",
					[]corev1.ServicePort{
						{
							NodePort: int32(30300),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "5.5.5.6",
							}},
						},
					},
					true, false,
				)

				ep3 := discovery.Endpoint{
					Addresses: []string{"10.128.0.33"},
				}

				endpointSlice2 := *newEndpointSlice(
					"service2",
					"namespace1",
					[]discovery.Endpoint{ep3},
					[]discovery.EndpointPort{epPort})

				egressService3 := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service3",
						Namespace: "namespace1",
					},
					Spec: egressserviceapi.EgressServiceSpec{
						Network: "mynetwork",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: fakeNodeName,
					},
				}
				service3 := *newService("service3", "namespace1", "10.129.0.4",
					[]corev1.ServicePort{
						{
							NodePort: int32(32222),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "6.6.6.6",
							}},
						},
					},
					false, false,
				)

				ep3_1 := discovery.Endpoint{
					Addresses: []string{"10.128.0.4"},
				}
				endpointSlice3 := *newEndpointSlice(
					"service3",
					"namespace1",
					[]discovery.Endpoint{ep3_1},
					[]discovery.EndpointPort{epPort},
				)

				objects := []runtime.Object{
					&service,
					&service2,
					&service3,
					&endpointSlice,
					&endpointSlice2,
					&endpointSlice3,
					&egressService,
					&egressService2,
					&egressService3,
				}
				stopChan := make(chan struct{})
				wg := &sync.WaitGroup{}
				fakeClient := util.GetOVNClientset(objects...).GetNodeClientset()
				wf, err := factory.NewNodeWatchFactory(fakeClient, "node")
				Expect(err).ToNot(HaveOccurred())
				Expect(wf.Start()).To(Succeed())
				defer func() {
					close(stopChan)
					wg.Wait()
					wf.Shutdown()
				}()

				c, err := egressservice.NewController(
					stopChan,
					ovnKubeNodeSNATMark,
					"node",
					wf.EgressServiceInformer(),
					wf.ServiceInformer(),
					wf.EndpointSliceInformer(),
				)
				Expect(err).ToNot(HaveOccurred())
				err = c.Run(wg, 1)
				Expect(err).ToNot(HaveOccurred())

				expectedNFT := nftablesRulesEgressServicesBase + `
add element inet ovn-kubernetes egress-service-snat-v4 { 10.128.0.3 comment "namespace1/service1" : 5.5.5.5 }
add element inet ovn-kubernetes egress-service-snat-v4 { 10.128.0.4 comment "namespace1/service3" : 6.6.6.6 }
`
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
		It("manages iptables rules for LoadBalancer egress service backed by cluster networked pods", func() {
			app.Action = func(*cli.Context) error {
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ip -4 --json rule show",
					Output: "[]",
					Err:    nil,
				})

				epPortName := "https"
				epPortValue := int32(443)

				egressService := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "namespace1",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: fakeNodeName,
					},
				}
				service := *newService("service1", "namespace1", "10.129.0.2",
					[]corev1.ServicePort{
						{
							NodePort: int32(31111),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "5.5.5.5",
							}},
						},
					},
					false, false,
				)

				ep1 := discovery.Endpoint{
					Addresses: []string{"10.128.0.3"},
				}
				epPort := discovery.EndpointPort{
					Name: &epPortName,
					Port: &epPortValue,
				}

				// host-networked endpoint, should not have an SNAT rule created
				ep2 := discovery.Endpoint{
					Addresses: []string{"192.168.18.15"},
					NodeName:  &fakeNodeName,
				}
				// endpointSlice.Endpoints is ovn-networked so this will
				// come under !hasLocalHostNetEp case
				endpointSlice := *newEndpointSlice(
					"service1",
					"namespace1",
					[]discovery.Endpoint{ep1, ep2},
					[]discovery.EndpointPort{epPort},
				)

				objects := []runtime.Object{
					&service,
					&endpointSlice,
					&egressService,
				}
				stopChan := make(chan struct{})
				wg := &sync.WaitGroup{}
				fakeClient := util.GetOVNClientset(objects...).GetNodeClientset()
				wf, err := factory.NewNodeWatchFactory(fakeClient, "node")
				Expect(err).ToNot(HaveOccurred())
				Expect(wf.Start()).To(Succeed())
				defer func() {
					close(stopChan)
					wg.Wait()
					wf.Shutdown()
				}()

				c, err := egressservice.NewController(
					stopChan,
					ovnKubeNodeSNATMark,
					"node",
					wf.EgressServiceInformer(),
					wf.ServiceInformer(),
					wf.EndpointSliceInformer(),
				)
				Expect(err).ToNot(HaveOccurred())
				err = c.Run(wg, 1)
				Expect(err).ToNot(HaveOccurred())

				expectedNFT := nftablesRulesEgressServicesBase + `
add element inet ovn-kubernetes egress-service-snat-v4 { 10.128.0.3 comment "namespace1/service1" : 5.5.5.5 }
`
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				err = fakeClient.EgressServiceClient.K8sV1().EgressServices("namespace1").Delete(context.TODO(), "service1", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())

				expectedNFT = nftablesRulesEgressServicesBase
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("manages iptables/ip rules for LoadBalancer egress service backed by ovn-k pods with Network", func() {
			app.Action = func(*cli.Context) error {
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ip -4 --json rule show",
					Output: "[]",
					Err:    nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.129.0.2 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.128.0.3 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.129.0.10 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.128.0.11 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ip -4 rule add prio 5000 from %s sport 30300 table mynetwork", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP),
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.129.0.2 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.128.0.3 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.129.0.10 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.128.0.11 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ip -4 rule del prio 5000 from %s sport 30300 table mynetwork", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP),
					Err: nil,
				})
				epPortName := "https"
				epPortValue := int32(443)

				egressService := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "namespace1",
					},
					Spec: egressserviceapi.EgressServiceSpec{
						Network: "mynetwork",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: fakeNodeName,
					},
				}

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]corev1.ServicePort{
						{
							NodePort: int32(31111),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "5.5.5.5",
							}},
						},
					},
					false, false,
				)

				ep1 := discovery.Endpoint{
					Addresses: []string{"10.128.0.3"},
				}
				epPort := discovery.EndpointPort{
					Name: &epPortName,
					Port: &epPortValue,
				}

				// host-networked endpoint, should not have an SNAT rule created
				ep2 := discovery.Endpoint{
					Addresses: []string{"192.168.18.15"},
					NodeName:  &fakeNodeName,
				}
				// endpointSlice.Endpoints is ovn-networked so this will
				// come under !hasLocalHostNetEp case
				endpointSlice := *newEndpointSlice(
					"service1",
					"namespace1",
					[]discovery.Endpoint{ep1, ep2},
					[]discovery.EndpointPort{epPort})

				egressService2 := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service2",
						Namespace: "namespace1",
					},
					Spec: egressserviceapi.EgressServiceSpec{
						Network: "mynetwork",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: fakeNodeName,
					},
				}

				service2 := *newService("service2", "namespace1", "10.129.0.10",
					[]corev1.ServicePort{
						{
							NodePort: int32(30300),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "5.5.5.6",
							}},
						},
					},
					true, false,
				)

				ep3 := discovery.Endpoint{
					Addresses: []string{"10.128.0.11"},
				}

				// endpointSlice.Endpoints is ovn-networked so this will
				// come under !hasLocalHostNetEp case
				endpointSlice2 := *newEndpointSlice(
					"service2",
					"namespace1",
					[]discovery.Endpoint{ep3},
					[]discovery.EndpointPort{epPort},
				)

				objects := []runtime.Object{
					&service,
					&service2,
					&endpointSlice,
					&endpointSlice2,
					&egressService,
					&egressService2,
				}
				stopChan := make(chan struct{})
				wg := &sync.WaitGroup{}
				fakeClient := util.GetOVNClientset(objects...).GetNodeClientset()
				wf, err := factory.NewNodeWatchFactory(fakeClient, "node")
				Expect(err).ToNot(HaveOccurred())
				Expect(wf.Start()).To(Succeed())
				defer func() {
					close(stopChan)
					wg.Wait()
					wf.Shutdown()
				}()

				c, err := egressservice.NewController(
					stopChan,
					ovnKubeNodeSNATMark,
					"node",
					wf.EgressServiceInformer(),
					wf.ServiceInformer(),
					wf.EndpointSliceInformer(),
				)
				Expect(err).ToNot(HaveOccurred())
				err = c.Run(wg, 1)
				Expect(err).ToNot(HaveOccurred())

				expectedNFT := nftablesRulesEgressServicesBase + `
add element inet ovn-kubernetes egress-service-snat-v4 { 10.128.0.3 comment "namespace1/service1" : 5.5.5.5 }
add element inet ovn-kubernetes egress-service-snat-v4 { 10.128.0.11 comment "namespace1/service2" : 5.5.5.6 }
`
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				err = fakeClient.EgressServiceClient.K8sV1().EgressServices("namespace1").Delete(context.TODO(), "service1", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())

				err = fakeClient.EgressServiceClient.K8sV1().EgressServices("namespace1").Delete(context.TODO(), "service2", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())

				expectedNFT = nftablesRulesEgressServicesBase
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("manages ip rules for LoadBalancer egress service backed by ovn-k pods with Network and Host=ALL", func() {
			app.Action = func(*cli.Context) error {
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ip -4 --json rule show",
					Output: "[]",
					Err:    nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.129.0.2 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.128.0.3 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.129.0.10 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.128.0.11 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ip -4 rule add prio 5000 from %s sport 30300 table mynetwork", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP),
					Err: nil,
				})
				epPortName := "https"
				epPortValue := int32(443)

				egressService := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "namespace1",
					},
					Spec: egressserviceapi.EgressServiceSpec{
						Network: "mynetwork",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: "ALL",
					},
				}

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]corev1.ServicePort{
						{
							NodePort: int32(31111),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "5.5.5.5",
							}},
						},
					},
					false, false,
				)

				ep1 := discovery.Endpoint{
					Addresses: []string{"10.128.0.3"},
					NodeName:  &fakeNodeName,
				}
				epPort := discovery.EndpointPort{
					Name: &epPortName,
					Port: &epPortValue,
				}

				// host-networked endpoint, should not have an ip rule created
				ep2 := discovery.Endpoint{
					Addresses: []string{"192.168.18.15"},
					NodeName:  &fakeNodeName,
				}

				// ep that does not belong to our node should not have an ip rule created
				someOtherNode := "someOtherNode"
				ep3 := discovery.Endpoint{
					Addresses: []string{"10.128.1.5"},
					NodeName:  &someOtherNode,
				}
				// endpointSlice.Endpoints is ovn-networked so this will
				// come under !hasLocalHostNetEp case
				endpointSlice := *newEndpointSlice(
					"service1",
					"namespace1",
					[]discovery.Endpoint{ep1, ep2, ep3},
					[]discovery.EndpointPort{epPort})

				egressService2 := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service2",
						Namespace: "namespace1",
					},
					Spec: egressserviceapi.EgressServiceSpec{
						Network: "mynetwork",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: "ALL",
					},
				}

				service2 := *newService("service2", "namespace1", "10.129.0.10",
					[]corev1.ServicePort{
						{
							NodePort: int32(30300),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "5.5.5.6",
							}},
						},
					},
					true, false,
				)

				ep4 := discovery.Endpoint{
					Addresses: []string{"10.128.0.11"},
					NodeName:  &fakeNodeName,
				}

				endpointSlice2 := *newEndpointSlice(
					"service2",
					"namespace1",
					[]discovery.Endpoint{ep4},
					[]discovery.EndpointPort{epPort},
				)

				objects := []runtime.Object{
					&service,
					&service2,
					&endpointSlice,
					&endpointSlice2,
					&egressService,
					&egressService2,
				}
				stopChan := make(chan struct{})
				wg := &sync.WaitGroup{}
				fakeClient := util.GetOVNClientset(objects...).GetNodeClientset()
				wf, err := factory.NewNodeWatchFactory(fakeClient, "node")
				Expect(err).ToNot(HaveOccurred())
				Expect(wf.Start()).To(Succeed())
				defer func() {
					close(stopChan)
					wg.Wait()
					wf.Shutdown()
				}()

				c, err := egressservice.NewController(
					stopChan,
					ovnKubeNodeSNATMark,
					"node",
					wf.EgressServiceInformer(),
					wf.ServiceInformer(),
					wf.EndpointSliceInformer(),
				)
				Expect(err).ToNot(HaveOccurred())
				err = c.Run(wg, 1)
				Expect(err).ToNot(HaveOccurred())

				expectedNFT := nftablesRulesEgressServicesBase
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Eventually(func() bool {
					return fExec.CalledMatchesExpected()
				}).Should(BeTrue())

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.129.0.2 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.128.0.3 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.129.0.10 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.128.0.11 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ip -4 rule del prio 5000 from %s sport 30300 table mynetwork", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP),
					Err: nil,
				})

				err = fakeClient.EgressServiceClient.K8sV1().EgressServices("namespace1").Delete(context.TODO(), "service1", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())

				err = fakeClient.EgressServiceClient.K8sV1().EgressServices("namespace1").Delete(context.TODO(), "service2", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())

				expectedNFT = nftablesRulesEgressServicesBase
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Eventually(func() bool {
					return fExec.CalledMatchesExpected()
				}).Should(BeTrue())
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("updates network ip rules for LoadBalancer egress service when ETP changes", func() {
			app.Action = func(*cli.Context) error {
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ip -4 --json rule show",
					Output: "[]",
					Err:    nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.129.0.2 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule add prio 5000 from 10.128.0.3 table mynetwork",
					Err: nil,
				})
				epPortName := "https"
				epPortValue := int32(443)

				egressService := egressserviceapi.EgressService{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service1",
						Namespace: "namespace1",
					},
					Spec: egressserviceapi.EgressServiceSpec{
						Network: "mynetwork",
					},
					Status: egressserviceapi.EgressServiceStatus{
						Host: "ALL",
					},
				}

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]corev1.ServicePort{
						{
							NodePort: int32(30300),
							Protocol: corev1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					corev1.ServiceTypeLoadBalancer,
					[]string{},
					corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{
								IP: "5.5.5.5",
							}},
						},
					},
					false, false,
				)

				ep1 := discovery.Endpoint{
					Addresses: []string{"10.128.0.3"},
					NodeName:  &fakeNodeName,
				}
				epPort := discovery.EndpointPort{
					Name: &epPortName,
					Port: &epPortValue,
				}

				// host-networked endpoint, should not have an ip rule created
				ep2 := discovery.Endpoint{
					Addresses: []string{"192.168.18.15"},
					NodeName:  &fakeNodeName,
				}

				// ep that does not belong to our node should not have an ip rule created
				someOtherNode := "someOtherNode"
				ep3 := discovery.Endpoint{
					Addresses: []string{"10.128.1.5"},
					NodeName:  &someOtherNode,
				}
				// endpointSlice.Endpoints is ovn-networked so this will
				// come under !hasLocalHostNetEp case
				endpointSlice := *newEndpointSlice(
					"service1",
					"namespace1",
					[]discovery.Endpoint{ep1, ep2, ep3},
					[]discovery.EndpointPort{epPort})

				objects := []runtime.Object{
					&service,
					&endpointSlice,
					&egressService,
				}
				stopChan := make(chan struct{})
				wg := &sync.WaitGroup{}
				fakeClient := util.GetOVNClientset(objects...).GetNodeClientset()
				wf, err := factory.NewNodeWatchFactory(fakeClient, "node")
				Expect(err).ToNot(HaveOccurred())
				Expect(wf.Start()).To(Succeed())
				defer func() {
					close(stopChan)
					wg.Wait()
					wf.Shutdown()
				}()

				c, err := egressservice.NewController(
					stopChan,
					ovnKubeNodeSNATMark,
					"node",
					wf.EgressServiceInformer(),
					wf.ServiceInformer(),
					wf.EndpointSliceInformer(),
				)
				Expect(err).ToNot(HaveOccurred())
				err = c.Run(wg, 1)
				Expect(err).ToNot(HaveOccurred())

				expectedNFT := nftablesRulesEgressServicesBase
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Eventually(func() bool {
					return fExec.CalledMatchesExpected()
				}).Should(BeTrue(), fExec.ErrorDesc)

				By("switching to ETP=Local an ip rule should be created for the masquerade IP")
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ip -4 rule add prio 5000 from %s sport 30300 table mynetwork", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP),
					Err: nil,
				})
				service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
				service.ResourceVersion = "100"
				_, err = fakeClient.KubeClient.CoreV1().Services("namespace1").Update(context.TODO(), &service, metav1.UpdateOptions{})
				Expect(err).ToNot(HaveOccurred())

				expectedNFT = nftablesRulesEgressServicesBase
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Eventually(func() bool {
					return fExec.CalledMatchesExpected()
				}).Should(BeTrue())

				By("switching back to ETP=Cluster the masquerade ip rule should be deleted")
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: fmt.Sprintf("ip -4 rule del prio 5000 from %s sport 30300 table mynetwork", config.Gateway.MasqueradeIPs.V4HostETPLocalMasqueradeIP),
					Err: nil,
				})
				service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
				service.ResourceVersion = "110"
				_, err = fakeClient.KubeClient.CoreV1().Services("namespace1").Update(context.TODO(), &service, metav1.UpdateOptions{})
				Expect(err).ToNot(HaveOccurred())

				expectedNFT = nftablesRulesEgressServicesBase
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Eventually(func() bool {
					return fExec.CalledMatchesExpected()
				}).Should(BeTrue())

				By("deleting the egress service the ip rules should be deleted")
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.129.0.2 table mynetwork",
					Err: nil,
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip -4 rule del prio 5000 from 10.128.0.3 table mynetwork",
					Err: nil,
				})

				err = fakeClient.EgressServiceClient.K8sV1().EgressServices("namespace1").Delete(context.TODO(), "service1", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())

				expectedNFT = nftablesRulesEgressServicesBase
				Eventually(func() error {
					return nodenft.MatchNFTRules(expectedNFT, nft.Dump())
				}).ShouldNot(HaveOccurred())

				Eventually(func() bool {
					return fExec.CalledMatchesExpected()
				}).Should(BeTrue())
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
