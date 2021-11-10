package node

import (
	"fmt"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	kapi "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

const (
	v4localnetGatewayIP = "10.244.0.1"
	v6localnetGatewayIP = "fd00:96:1::1"
)

func initFakeNodePortWatcher(iptV4, iptV6 util.IPTablesHelper) *nodePortWatcher {
	initIPTable := map[string]util.FakeTable{
		"nat":    {},
		"filter": {},
	}

	f4 := iptV4.(*util.FakeIPTables)
	err := f4.MatchState(initIPTable)
	Expect(err).NotTo(HaveOccurred())

	f6 := iptV6.(*util.FakeIPTables)
	err = f6.MatchState(initIPTable)
	Expect(err).NotTo(HaveOccurred())

	fNPW := nodePortWatcher{
		ofportPhys:  "eth0",
		gatewayIPv4: v4localnetGatewayIP,
		gatewayIPv6: v6localnetGatewayIP,
		serviceInfo: make(map[k8stypes.NamespacedName]*serviceConfig),
		ofm: &openflowManager{
			flowCache: map[string][]string{},
		},
	}
	return &fNPW
}

func startNodePortWatcher(n *nodePortWatcher, fakeClient *util.OVNClientset, fakeMgmtPortConfig *managementPortConfig) error {
	if err := initLocalGatewayIPTables(); err != nil {
		return err
	}

	k := &kube.Kube{fakeClient.KubeClient, nil, nil}
	n.nodeIPManager = newAddressManager(fakeNodeName, k, fakeMgmtPortConfig, n.watchFactory)

	n.watchFactory.AddServiceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc := obj.(*kapi.Service)
			n.AddService(svc)
		},
		UpdateFunc: func(old, new interface{}) {
			oldSvc := old.(*kapi.Service)
			newSvc := new.(*kapi.Service)
			n.UpdateService(oldSvc, newSvc)
		},
		DeleteFunc: func(obj interface{}) {
			svc := obj.(*kapi.Service)
			n.DeleteService(svc)
		},
	}, n.SyncServices)
	return nil
}

func newObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       k8stypes.UID(namespace),
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			"name": name,
		},
	}
}

func newService(name, namespace, ip string, ports []v1.ServicePort, serviceType v1.ServiceType, externalIPs []string, serviceStatus v1.ServiceStatus, isETPLocal bool) *v1.Service {
	externalTrafficPolicy := v1.ServiceExternalTrafficPolicyTypeCluster
	if isETPLocal {
		externalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal
	}
	return &v1.Service{
		ObjectMeta: newObjectMeta(name, namespace),
		Spec: v1.ServiceSpec{
			ClusterIP:             ip,
			Ports:                 ports,
			Type:                  serviceType,
			ExternalIPs:           externalIPs,
			ExternalTrafficPolicy: externalTrafficPolicy,
		},
		Status: serviceStatus,
	}
}

func newEndpoints(name, namespace string, eps []v1.EndpointSubset) *v1.Endpoints {
	return &v1.Endpoints{
		ObjectMeta: newObjectMeta(name, namespace),
		Subsets:    eps,
	}
}

var _ = Describe("Node Operations", func() {
	var (
		app                *cli.App
		fakeOvnNode        *FakeOVNNode
		fExec              *ovntest.FakeExec
		iptV4, iptV6       util.IPTablesHelper
		fNPW               *nodePortWatcher
		fakeMgmtPortConfig managementPortConfig
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
		fExec = ovntest.NewFakeExec()
		fakeOvnNode = NewFakeOVNNode(fExec)

		iptV4, iptV6 = util.SetFakeIPTablesHelpers()
		_, nodeNet, err := net.ParseCIDR("10.1.1.0/24")
		Expect(err).NotTo(HaveOccurred())
		// Make a fake MgmtPortConfig with only the fields we care about
		fakeMgmtPortIPFamilyConfig := managementPortIPFamilyConfig{
			ipt:        nil,
			allSubnets: nil,
			ifAddr:     nodeNet,
			gwIP:       nodeNet.IP,
		}
		fakeMgmtPortConfig = managementPortConfig{
			ifName:    fakeNodeName,
			link:      nil,
			routerMAC: nil,
			ipv4:      &fakeMgmtPortIPFamilyConfig,
			ipv6:      nil,
		}
		fNPW = initFakeNodePortWatcher(iptV4, iptV6)
	})

	Context("on startup", func() {
		It("removes stale iptables rules while keeping remaining intact", func() {
			app.Action = func(ctx *cli.Context) error {
				externalIP := "1.1.1.1"
				externalIPPort := int32(8032)
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-ofctl show ",
				})

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     externalIPPort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
					v1.ServiceStatus{},
					false,
				)

				fakeRules := getExternalIPTRules(service.Spec.Ports[0], externalIP, service.Spec.ClusterIP, false)
				addIptRules(fakeRules)
				fakeRules = getExternalIPTRules(
					v1.ServicePort{
						Port:     27000,
						Protocol: v1.ProtocolUDP,
						Name:     "This is going to dissapear I hope",
					},
					"10.10.10.10",
					"172.32.0.12",
					false,
				)
				addIptRules(fakeRules)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p UDP -d 10.10.10.10 --dport 27000 -j DNAT --to-destination 172.32.0.12:27000"),
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables = map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{},
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 = iptV4.(*util.FakeIPTables)
				err = f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("on add", func() {
		It("inits iptables rules with ExternalIP", func() {
			app.Action = func(ctx *cli.Context) error {
				externalIP := "1.1.1.1"
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-ofctl show ",
				})

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
					v1.ServiceStatus{},
					false,
				)
				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{},
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("inits iptables rules with NodePort", func() {
			app.Action = func(ctx *cli.Context) error {

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: int32(31111),
							Protocol: v1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					v1.ServiceTypeNodePort,
					nil,
					v1.ServiceStatus{},
					false,
				)
				endpoints := *newEndpoints("service1", "namespace1", []v1.EndpointSubset{})

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
					&endpoints,
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s -m addrtype --dst-type LOCAL --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, service.Spec.Ports[0].NodePort, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-EXTERNALIP":    []string{},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("inits iptables rules with NodePort where ETP=local, LGW", func() {
			app.Action = func(ctx *cli.Context) error {
				config.Gateway.Mode = config.GatewayModeLocal
				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: int32(31111),
							Protocol: v1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					v1.ServiceTypeNodePort,
					nil,
					v1.ServiceStatus{},
					true,
				)
				addr := v1.EndpointAddress{
					IP: "10.244.0.3",
				}
				port := v1.EndpointPort{
					Name: "https",
					Port: int32(443),
				}
				ep := v1.EndpointSubset{
					Addresses: []v1.EndpointAddress{
						addr,
					},
					Ports: []v1.EndpointPort{
						port,
					},
				}
				// endpoints.Subset is ovn-networked so this will come under !hasLocalHostNetEp case
				endpoints := *newEndpoints("service1", "namespace1", []v1.EndpointSubset{ep})

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
					&endpoints,
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s -m addrtype --dst-type LOCAL --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, service.Spec.Ports[0].NodePort, types.V4HostETPLocalMasqueradeIP, service.Spec.Ports[0].NodePort),
						},
						"OVN-KUBE-EXTERNALIP": []string{},
						"OVN-KUBE-SNAT-MGMTPORT": []string{
							fmt.Sprintf("-p TCP --dport %v -j RETURN", service.Spec.Ports[0].NodePort),
						},
					},
					"filter": {},
				}
				expectedFlows := []string{
					"cookie=0x453ae29bcbbc08bd, priority=110, in_port=eth0, tcp, tp_dst=31111, actions=ct(commit,zone=64003,table=6)",
					"cookie=0x453ae29bcbbc08bd, priority=110, in_port=LOCAL, tcp, tp_src=31111, actions=ct(zone=64003,table=7)",
					"cookie=0xe745ecf105, priority=110, table=6, actions=output:LOCAL",
					"cookie=0xe745ecf105, priority=110, table=7, actions=output:eth0",
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				flows := fNPW.ofm.flowCache["NodePort_namespace1_service1_tcp_31111"]
				Expect(flows).To(Equal(expectedFlows))
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("inits iptables rules with LoadBalancer", func() {
			app.Action = func(ctx *cli.Context) error {
				externalIP := "1.1.1.1"
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-ofctl show ",
				})
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-ofctl show ",
				})
				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: int32(31111),
							Protocol: v1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					v1.ServiceTypeLoadBalancer,
					[]string{externalIP},
					v1.ServiceStatus{
						LoadBalancer: v1.LoadBalancerStatus{
							Ingress: []v1.LoadBalancerIngress{{
								IP: "5.5.5.5",
							}},
						},
					},
					false,
				)
				endpoints := *newEndpoints("service1", "namespace1", []v1.EndpointSubset{})

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
					&endpoints,
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s -m addrtype --dst-type LOCAL --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, service.Spec.Ports[0].NodePort, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("inits iptables rules with LoadBalancer where ETP=local, LGW mode", func() {
			app.Action = func(ctx *cli.Context) error {
				externalIP := "1.1.1.1"
				config.Gateway.Mode = config.GatewayModeLocal
				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: int32(31111),
							Protocol: v1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					v1.ServiceTypeLoadBalancer,
					[]string{externalIP},
					v1.ServiceStatus{
						LoadBalancer: v1.LoadBalancerStatus{
							Ingress: []v1.LoadBalancerIngress{{
								IP: "5.5.5.5",
							}},
						},
					},
					true,
				)
				// endpoints.Subset is empty and yet this will come under !hasLocalHostNetEp case
				endpoints := *newEndpoints("service1", "namespace1", []v1.EndpointSubset{})

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
					&endpoints,
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s -m addrtype --dst-type LOCAL --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, service.Spec.Ports[0].NodePort, types.V4HostETPLocalMasqueradeIP, service.Spec.Ports[0].NodePort),
						},
						"OVN-KUBE-SNAT-MGMTPORT": []string{
							fmt.Sprintf("-p TCP --dport %v -j RETURN", service.Spec.Ports[0].NodePort),
						},
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, types.V4HostETPLocalMasqueradeIP, service.Spec.Ports[0].NodePort),
						},
					},
					"filter": {},
				}
				expectedNodePortFlows := []string{
					"cookie=0x453ae29bcbbc08bd, priority=110, in_port=eth0, tcp, tp_dst=31111, actions=ct(commit,zone=64003,table=6)",
					"cookie=0x453ae29bcbbc08bd, priority=110, in_port=LOCAL, tcp, tp_src=31111, actions=ct(zone=64003,table=7)",
					"cookie=0xe745ecf105, priority=110, table=6, actions=output:LOCAL",
					"cookie=0xe745ecf105, priority=110, table=7, actions=output:eth0",
				}
				expectedLBIngressFlows := []string{
					"cookie=0x10c6b89e483ea111, priority=110, in_port=eth0, tcp, nw_dst=5.5.5.5, tp_dst=8080, actions=ct(commit,zone=64003,table=6)",
					"cookie=0x10c6b89e483ea111, priority=110, in_port=LOCAL, tcp, nw_src=5.5.5.5, tp_src=8080, actions=ct(zone=64003,table=7)",
					"cookie=0xe745ecf105, priority=110, table=6, actions=output:LOCAL",
					"cookie=0xe745ecf105, priority=110, table=7, actions=output:eth0",
				}
				expectedLBExternalIPFlows := []string{
					"cookie=0x71765945a31dc2f1, priority=110, in_port=eth0, tcp, nw_dst=1.1.1.1, tp_dst=8080, actions=ct(commit,zone=64003,table=6)",
					"cookie=0x71765945a31dc2f1, priority=110, in_port=LOCAL, tcp, nw_src=1.1.1.1, tp_src=8080, actions=ct(zone=64003,table=7)",
					"cookie=0xe745ecf105, priority=110, table=6, actions=output:LOCAL",
					"cookie=0xe745ecf105, priority=110, table=7, actions=output:eth0",
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				flows := fNPW.ofm.flowCache["NodePort_namespace1_service1_tcp_31111"]
				Expect(flows).To(Equal(expectedNodePortFlows))
				flows = fNPW.ofm.flowCache["Ingress_namespace1_service1_5.5.5.5_8080"]
				Expect(flows).To(Equal(expectedLBIngressFlows))
				flows = fNPW.ofm.flowCache["External_namespace1_service1_1.1.1.1_8080"]
				Expect(flows).To(Equal(expectedLBExternalIPFlows))
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("inits iptables rules with DualStack NodePort", func() {
			app.Action = func(ctx *cli.Context) error {
				nodePort := int32(31111)

				fNPW.gatewayIPv6 = v6localnetGatewayIP

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: nodePort,
							Protocol: v1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					v1.ServiceTypeNodePort,
					nil,
					v1.ServiceStatus{},
					false,
				)
				service.Spec.ClusterIPs = []string{"10.129.0.2", "fd00:10:96::10"}
				endpoints := *newEndpoints("service1", "namespace1", []v1.EndpointSubset{})

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
					&endpoints,
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables4 := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s -m addrtype --dst-type LOCAL --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, service.Spec.Ports[0].NodePort, service.Spec.ClusterIPs[0], service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-EXTERNALIP":    []string{},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables4)
				Expect(err).NotTo(HaveOccurred())

				expectedTables6 := map[string]util.FakeTable{
					"nat": {
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s -m addrtype --dst-type LOCAL --dport %v -j DNAT --to-destination [%s]:%v", service.Spec.Ports[0].Protocol, service.Spec.Ports[0].NodePort, service.Spec.ClusterIPs[1], service.Spec.Ports[0].Port),
						},
					},
					"filter": {},
				}
				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables6)
				Expect(err).NotTo(HaveOccurred())
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("inits iptables rules for ExternalIP with DualStack", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIPv4 := "10.10.10.1"
				externalIPv6 := "fd00:96:1::1"
				clusterIPv4 := "10.129.0.2"
				clusterIPv6 := "fd00:10:96::10"
				fNPW.gatewayIPv6 = v6localnetGatewayIP
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-ofctl show ",
				})
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-ofctl show ",
				})

				service := *newService("service1", "namespace1", clusterIPv4,
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIPv4, externalIPv6},
					v1.ServiceStatus{},
					false,
				)
				service.Spec.ClusterIPs = []string{clusterIPv4, clusterIPv6}
				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables4 := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIPv4, service.Spec.Ports[0].Port, clusterIPv4, service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-NODEPORT":      []string{},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables4)
				Expect(err).NotTo(HaveOccurred())

				expectedTables6 := map[string]util.FakeTable{
					"nat": {
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination [%s]:%v", service.Spec.Ports[0].Protocol, externalIPv6, service.Spec.Ports[0].Port, clusterIPv6, service.Spec.Ports[0].Port),
						},
					},
					"filter": {},
				}

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables6)
				Expect(err).NotTo(HaveOccurred())
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("on delete", func() {
		It("deletes iptables rules with ExternalIP", func() {
			app.Action = func(ctx *cli.Context) error {
				externalIP := "1.1.1.1"
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-ofctl show ",
				})

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
					v1.ServiceStatus{},
					false,
				)

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.DeleteService(&service)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT":      []string{},
						"OVN-KUBE-EXTERNALIP":    []string{},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				expectedTables = map[string]util.FakeTable{
					"nat":    {},
					"filter": {},
				}
				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("deletes iptables rules for NodePort", func() {
			app.Action = func(ctx *cli.Context) error {
				nodePort := int32(31111)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: nodePort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeNodePort,
					nil,
					v1.ServiceStatus{},
					false,
				)

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
				)

				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.DeleteService(&service)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT":      []string{},
						"OVN-KUBE-EXTERNALIP":    []string{},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				expectedTables = map[string]util.FakeTable{
					"nat":    {},
					"filter": {},
				}

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("on add and delete", func() {
		It("manages iptables rules with ExternalIP", func() {
			app.Action = func(ctx *cli.Context) error {
				externalIP := "10.10.10.1"
				externalIPPort := int32(8034)
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ovs-ofctl show ",
				})
				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     externalIPPort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
					v1.ServiceStatus{},
					false,
				)

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
				)
				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-NODEPORT":      []string{},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fNPW.DeleteService(&service)

				expectedTables = map[string]util.FakeTable{
					"nat": {
						"OVN-KUBE-EXTERNALIP": []string{},
						"OVN-KUBE-NODEPORT":   []string{},
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 = iptV4.(*util.FakeIPTables)
				err = f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())
				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("manages iptables rules for NodePort", func() {
			app.Action = func(ctx *cli.Context) error {
				nodePort := int32(38034)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: nodePort,
							Protocol: v1.ProtocolTCP,
							Port:     int32(8080),
						},
					},
					v1.ServiceTypeNodePort,
					nil,
					v1.ServiceStatus{},
					false,
				)

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
				)
				fNPW.watchFactory = fakeOvnNode.watcher
				startNodePortWatcher(fNPW, fakeOvnNode.fakeClient, &fakeMgmtPortConfig)
				fNPW.AddService(&service)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables := map[string]util.FakeTable{
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s -m addrtype --dst-type LOCAL --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, nodePort, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
						"OVN-KUBE-EXTERNALIP":    []string{},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fNPW.DeleteService(&service)

				expectedTables = map[string]util.FakeTable{
					"nat": {
						"OVN-KUBE-EXTERNALIP": []string{},
						"OVN-KUBE-NODEPORT":   []string{},
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-SNAT-MGMTPORT": []string{},
					},
					"filter": {},
				}

				f4 = iptV4.(*util.FakeIPTables)
				err = f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
