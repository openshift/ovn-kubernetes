package ovn

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/utils/net"
)

type fakeEgressIPDialer struct{}

func (f fakeEgressIPDialer) dial(ip net.IP, timeout time.Duration) bool {
	return true
}

var (
	reroutePolicyID            = "reroute_policy_id"
	natID                      = "nat_id"
	nodeLogicalRouterIPv6      = []string{"fef0::56"}
	nodeLogicalRouterIPv4      = []string{"100.64.0.2"}
	node2LogicalRouterIPv4     = []string{"100.64.0.3"}
	nodeLogicalRouterIfAddrV6  = nodeLogicalRouterIPv6[0] + "/125"
	nodeLogicalRouterIfAddrV4  = nodeLogicalRouterIPv4[0] + "/29"
	node2LogicalRouterIfAddrV4 = node2LogicalRouterIPv4[0] + "/29"
)

const (
	namespace       = "egressip-namespace"
	nodeInternalIP  = "def0::56"
	v4GatewayIP     = "10.128.0.1"
	podV4IP         = "10.128.0.15"
	podV6IP         = "ae70::66"
	v6GatewayIP     = "ae70::1"
	v6ClusterSubnet = "ae70::66/64"
	v6NodeSubnet    = "ae70::66/64"
	v4ClusterSubnet = "10.128.0.0/14"
	v4NodeSubnet    = "10.128.0.0/24"
	podName         = "egress-pod"
	egressIPName    = "egressip"
	inspectTimeout  = 4 * time.Second // arbitrary, to avoid failures on github CI
)

func newEgressIPMeta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:  k8stypes.UID(name),
		Name: name,
		Labels: map[string]string{
			"name": name,
		},
	}
}

var egressPodLabel = map[string]string{"egress": "needed"}

func setupNode(nodeName string, ipNets []string, mockAllocationIPs map[string]string) egressNode {
	var v4IP, v6IP net.IP
	var v4Subnet, v6Subnet *net.IPNet
	for _, ipNet := range ipNets {
		ip, net, _ := net.ParseCIDR(ipNet)
		if utilnet.IsIPv6CIDR(net) {
			v6Subnet = net
			v6IP = ip
		} else {
			v4Subnet = net
			v4IP = ip
		}
	}

	mockAllcations := map[string]string{}
	for mockAllocationIP, egressIPName := range mockAllocationIPs {
		mockAllcations[net.ParseIP(mockAllocationIP).String()] = egressIPName
	}

	node := egressNode{
		egressIPConfig: &util.ParsedNodeEgressIPConfiguration{
			V4: util.ParsedIFAddr{
				IP:  v4IP,
				Net: v4Subnet,
			},
			V6: util.ParsedIFAddr{
				IP:  v6IP,
				Net: v6Subnet,
			},
			Capacity: util.Capacity{
				IP:   util.UnlimitedNodeCapacity,
				IPv4: util.UnlimitedNodeCapacity,
				IPv6: util.UnlimitedNodeCapacity,
			},
		},
		allocations:        mockAllcations,
		name:               nodeName,
		isReady:            true,
		isReachable:        true,
		isEgressAssignable: true,
	}
	return node
}

var _ = ginkgo.Describe("OVN master EgressIP Operations", func() {
	var (
		app     *cli.App
		fakeOvn *FakeOVN
	)
	const (
		node1Name = "node1"
		node2Name = "node2"
	)

	clusterRouterDbSetup := libovsdbtest.TestSetup{
		NBData: []libovsdbtest.TestData{
			&nbdb.LogicalRouter{
				Name: ovntypes.OVNClusterRouter,
				UUID: ovntypes.OVNClusterRouter + "-UUID",
			},
		},
	}

	dialer = fakeEgressIPDialer{}

	getEgressIPAllocatorSizeSafely := func() int {
		fakeOvn.controller.eIPC.allocator.Lock()
		defer fakeOvn.controller.eIPC.allocator.Unlock()
		return len(fakeOvn.controller.eIPC.allocator.cache)
	}

	getEgressIPStatusLen := func(egressIPName string) func() int {
		return func() int {
			tmp, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Get(context.TODO(), egressIPName, metav1.GetOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			return len(tmp.Status.Items)
		}
	}

	getEgressIPStatus := func(egressIPName string) ([]string, []string) {
		tmp, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Get(context.TODO(), egressIPName, metav1.GetOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var egressIPs, nodes []string
		for _, status := range tmp.Status.Items {
			egressIPs = append(egressIPs, status.EgressIP)
			nodes = append(nodes, status.Node)
		}
		return egressIPs, nodes
	}

	getEgressIPReassignmentCount := func() int {
		reAssignmentCount := 0
		egressIPs, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().List(context.TODO(), metav1.ListOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, egressIP := range egressIPs.Items {
			if len(egressIP.Spec.EgressIPs) != len(egressIP.Status.Items) {
				reAssignmentCount++
			}
		}
		return reAssignmentCount
	}

	isEgressAssignableNode := func(nodeName string) func() bool {
		return func() bool {
			fakeOvn.controller.eIPC.allocator.Lock()
			defer fakeOvn.controller.eIPC.allocator.Unlock()
			if item, exists := fakeOvn.controller.eIPC.allocator.cache[nodeName]; exists {
				return item.isEgressAssignable
			}
			return false
		}
	}

	nodeSwitch := func() string {
		_, nodes := getEgressIPStatus(egressIPName)
		if len(nodes) != 1 {
			return ""
		}
		return nodes[0]
	}

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		config.OVNKubernetesFeature.EnableEgressIP = true

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fakeOvn = NewFakeOVN()
	})

	ginkgo.AfterEach(func() {
		fakeOvn.shutdown()
	})

	ginkgo.Context("On node UPDATE", func() {

		ginkgo.It("should re-assign EgressIPs and perform proper OVN transactions when pod is created after node egress label switch", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				node1IPv4 := "192.168.126.202/24"
				node2IPv4 := "192.168.126.51/24"

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV4IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeFalse())

				lsp := &nbdb.LogicalSwitchPort{Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name}
				fakeOvn.controller.nbClient.Get(context.Background(), lsp)
				gomega.Eventually(lsp.Options["nat-addresses"]).Should(gomega.Equal("router"))
				gomega.Eventually(lsp.Options["exclude-lb-vips-from-garp"]).Should(gomega.Equal("true"))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				node1.Labels = map[string]string{}
				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(nodeSwitch).Should(gomega.Equal(node2.Name))
				egressIPs, _ = getEgressIPStatus(egressIPName)
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				i, n, _ := net.ParseCIDR(podV4IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Create(context.TODO(), &egressPod, metav1.CreateOptions{})

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: egressIP,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("using EgressNode retry should re-assign EgressIPs and perform proper OVN transactions when pod is created after node egress label switch", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				node1IPv4 := "192.168.126.202/24"
				node2IPv4 := "192.168.126.51/24"

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV4IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					})

				err := fakeOvn.controller.WatchEgressIPNamespaces()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = fakeOvn.controller.WatchEgressIPPods()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = fakeOvn.controller.WatchEgressNodes()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				err = fakeOvn.controller.WatchEgressIP()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeFalse())

				lsp := &nbdb.LogicalSwitchPort{Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name}
				err = fakeOvn.controller.nbClient.Get(context.Background(), lsp)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(lsp.Options["nat-addresses"]).Should(gomega.Equal("router"))
				gomega.Eventually(lsp.Options["exclude-lb-vips-from-garp"]).Should(gomega.Equal("true"))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				node1.Labels = map[string]string{}
				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				ginkgo.By("Bringing down NBDB")
				// inject transient problem, nbdb is down
				fakeOvn.controller.nbClient.Close()
				gomega.Eventually(func() bool {
					return fakeOvn.controller.nbClient.Connected()
				}).Should(gomega.BeFalse())
				err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Delete(context.TODO(), node1.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// sleep long enough for TransactWithRetry to fail, causing egressnode operations to fail
				// there is a chance that both egressnode events(node1 removal and node2 update) will end up in the same event queue
				// sleep for double the time to allow for two consecutive TransactWithRetry timeouts
				time.Sleep(2 * (types.OVSDBTimeout + time.Second))
				// check to see if the retry cache has an entry
				key1 := node1.Name
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key1)
				}).ShouldNot(gomega.BeNil())
				retryEntry := fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key1)
				ginkgo.By("retry entry new obj be nil")
				gomega.Expect(retryEntry.newObj).To(gomega.BeNil())
				ginkgo.By("retry entry old obj should not be nil")
				gomega.Expect(retryEntry.oldObj).NotTo(gomega.BeNil())
				key2 := node2.Name
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key2)
				}).ShouldNot(gomega.BeNil())
				retryEntry = fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key2)
				ginkgo.By("retry entry new obj should not be nil")
				gomega.Expect(retryEntry.newObj).NotTo(gomega.BeNil())
				ginkgo.By("retry entry config should not be nil")
				gomega.Expect(retryEntry.config).NotTo(gomega.BeNil())
				connCtx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
				defer cancel()
				resetNBClient(connCtx, fakeOvn.controller.nbClient)
				fakeOvn.controller.retryEgressNodes.setRetryObjWithNoBackoff(key1)
				fakeOvn.controller.retryEgressNodes.setRetryObjWithNoBackoff(key2)
				fakeOvn.controller.retryEgressNodes.requestRetryObjs()
				// check the cache no longer has the entry
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key1)
				}).Should(gomega.BeNil())
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key2)
				}).Should(gomega.BeNil())
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(nodeSwitch).Should(gomega.Equal(node2.Name))
				egressIPs, _ = getEgressIPStatus(egressIPName)
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				i, n, _ := net.ParseCIDR(podV4IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Create(context.TODO(), &egressPod, metav1.CreateOptions{})

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: egressIP,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should re-assign EgressIPs and perform proper OVN transactions when namespace and pod is created after node egress label switch", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				node1IPv4 := "192.168.126.202/24"
				node2IPv4 := "192.168.126.51/24"

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV4IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Nat:  nil,
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					})

				i, n, _ := net.ParseCIDR(podV4IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeFalse())

				lsp := &nbdb.LogicalSwitchPort{Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name}
				fakeOvn.controller.nbClient.Get(context.Background(), lsp)
				gomega.Eventually(lsp.Options["nat-addresses"]).Should(gomega.Equal("router"))
				gomega.Eventually(lsp.Options["exclude-lb-vips-from-garp"]).Should(gomega.Equal("true"))

				fakeOvn.controller.WatchEgressIP()
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				node1.Labels = map[string]string{}
				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(nodeSwitch).Should(gomega.Equal(node2.Name))
				egressIPs, _ = getEgressIPStatus(egressIPName)
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Create(context.TODO(), egressNamespace, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Create(context.TODO(), &egressPod, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: egressIP,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}

				gomega.Eventually(fakeOvn.nbClient, inspectTimeout).Should(libovsdbtest.HaveData(expectedDatabaseState))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("On node DELETE", func() {

		ginkgo.It("should re-assign EgressIPs and perform proper OVN transactions when node's gateway objects are already deleted", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				node1IPv4 := "192.168.126.202/24"
				node2IPv4 := "192.168.126.51/24"

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV4IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{node2LogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
							&nbdb.LogicalSwitch{
								UUID: types.OVNJoinSwitch + "-UUID",
								Name: types.OVNJoinSwitch,
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeFalse())

				lsp := &nbdb.LogicalSwitchPort{Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name}
				fakeOvn.controller.nbClient.Get(context.Background(), lsp)
				gomega.Eventually(lsp.Options["nat-addresses"]).Should(gomega.Equal("router"))
				gomega.Eventually(lsp.Options["exclude-lb-vips-from-garp"]).Should(gomega.Equal("true"))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}
				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				i, n, _ := net.ParseCIDR(podV4IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Create(context.TODO(), &egressPod, metav1.CreateOptions{})

				expectedNatLogicalPort := "k8s-node1"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: egressIP,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{node2LogicalRouterIfAddrV4},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitch{
						UUID: types.OVNJoinSwitch + "-UUID",
						Name: types.OVNJoinSwitch,
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				err = fakeOvn.controller.gatewayCleanup(node1Name) // simulate an already deleted node
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Delete(context.TODO(), node1Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// E0608 12:53:33.728155 1161455 egressip.go:882] Allocator error: EgressIP: egressip claims to have an allocation on a node which is unassignable for egress IP: node1
				// W0608 12:53:33.728205 1161455 egressip.go:2030] Unable to retrieve gateway IP for node: node1, protocol is IPv6: false, err: attempt at finding node gateway router network information failed, err: unable to find router port rtoj-GR_node1: object not found
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(nodeSwitch).Should(gomega.Equal(node2.Name)) // egressIP successfully reassigned to node2
				egressIPs, _ = getEgressIPStatus(egressIPName)
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				expectedNatLogicalPort = "k8s-node2"
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: node2LogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: egressIP,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{node2LogicalRouterIfAddrV4},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitch{
						UUID: types.OVNJoinSwitch + "-UUID",
						Name: types.OVNJoinSwitch,
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("On node DELETE", func() {

		ginkgo.It("should re-assign EgressIPs and perform proper OVN transactions when node's gateway objects are already deleted", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				node1IPv4 := "192.168.126.202/24"
				node2IPv4 := "192.168.126.51/24"

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV4IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{node2LogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
							&nbdb.LogicalSwitch{
								UUID: types.OVNJoinSwitch + "-UUID",
								Name: types.OVNJoinSwitch,
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeFalse())

				lsp := &nbdb.LogicalSwitchPort{Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name}
				fakeOvn.controller.nbClient.Get(context.Background(), lsp)
				gomega.Eventually(lsp.Options["nat-addresses"]).Should(gomega.Equal("router"))
				gomega.Eventually(lsp.Options["exclude-lb-vips-from-garp"]).Should(gomega.Equal("true"))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}
				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				i, n, _ := net.ParseCIDR(podV4IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Create(context.TODO(), &egressPod, metav1.CreateOptions{})

				expectedNatLogicalPort := "k8s-node1"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: egressIP,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{node2LogicalRouterIfAddrV4},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitch{
						UUID: types.OVNJoinSwitch + "-UUID",
						Name: types.OVNJoinSwitch,
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				err = fakeOvn.controller.gatewayCleanup(node1Name) // simulate an already deleted node
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Delete(context.TODO(), node1Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// E0608 12:53:33.728155 1161455 egressip.go:882] Allocator error: EgressIP: egressip claims to have an allocation on a node which is unassignable for egress IP: node1
				// W0608 12:53:33.728205 1161455 egressip.go:2030] Unable to retrieve gateway IP for node: node1, protocol is IPv6: false, err: attempt at finding node gateway router network information failed, err: unable to find router port rtoj-GR_node1: object not found
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(nodeSwitch).Should(gomega.Equal(node2.Name)) // egressIP successfully reassigned to node2
				egressIPs, _ = getEgressIPStatus(egressIPName)
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				expectedNatLogicalPort = "k8s-node2"
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: node2LogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: egressIP,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{node2LogicalRouterIfAddrV4},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitch{
						UUID: types.OVNJoinSwitch + "-UUID",
						Name: types.OVNJoinSwitch,
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("IPv6 on pod UPDATE", func() {

		ginkgo.It("should remove OVN pod egress setup when EgressIP stops matching pod label", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV6IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
								Networks: []string{nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.name,
								UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.name,
								UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Nat:  nil,
							},
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
				}

				i, n, _ := net.ParseCIDR(podV6IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip6.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv6,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV6IP,
						ExternalIP: egressIP.String(),
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				podUpdate := newPod(namespace, podName, node1Name, podV6IP)

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Update(context.TODO(), podUpdate, metav1.UpdateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  nil,
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("egressIP pod retry should remove OVN pod egress setup when EgressIP stops matching pod label", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV6IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
								Networks: []string{nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.name,
								UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.name,
								UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Nat:  nil,
							},
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
				}

				i, n, _ := net.ParseCIDR(podV6IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip6.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv6,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV6IP,
						ExternalIP: egressIP.String(),
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				podUpdate := newPod(namespace, podName, node1Name, podV6IP)
				ginkgo.By("Bringing down NBDB")
				// inject transient problem, nbdb is down
				fakeOvn.controller.nbClient.Close()
				gomega.Eventually(func() bool {
					return fakeOvn.controller.nbClient.Connected()
				}).Should(gomega.BeFalse())
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Update(context.TODO(), podUpdate, metav1.UpdateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				time.Sleep(types.OVSDBTimeout + time.Second)
				// check to see if the retry cache has an entry
				key := getNamespacedName(podUpdate.Namespace, podUpdate.Name)
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressIPPods.getObjRetryEntry(key)
				}, inspectTimeout).ShouldNot(gomega.BeNil())
				retryEntry := fakeOvn.controller.retryEgressIPPods.getObjRetryEntry(key)
				ginkgo.By("retry entry new obj should not be nil")
				gomega.Expect(retryEntry.newObj).NotTo(gomega.BeNil())
				ginkgo.By("retry entry config should not be nil")
				gomega.Expect(retryEntry.config).NotTo(gomega.BeNil())
				connCtx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
				defer cancel()
				resetNBClient(connCtx, fakeOvn.controller.nbClient)
				fakeOvn.controller.retryEgressIPPods.setRetryObjWithNoBackoff(key)
				fakeOvn.controller.retryEgressIPPods.requestRetryObjs()
				// check the cache no longer has the entry
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressIPPods.getObjRetryEntry(key)
				}, inspectTimeout).Should(gomega.BeNil())
				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not treat pod update if pod already had assigned IP when it got the ADD", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV6IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
								Networks: []string{nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.name,
								UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.name,
								UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
							},
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
				}

				i, n, _ := net.ParseCIDR(podV6IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip6.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv6,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV6IP,
						ExternalIP: egressIP.String(),
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				podUpdate := newPodWithLabels(namespace, podName, node1Name, podV6IP, map[string]string{
					"egress": "needed",
					"some":   "update",
				})

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Update(context.TODO(), podUpdate, metav1.UpdateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should treat pod update if pod did not have an assigned IP when it got the ADD", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, "", egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
								Networks: []string{nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.name,
								UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.name,
								UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Nat:  nil,
							},
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
				}

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				podUpdate := newPodWithLabels(namespace, podName, node1Name, podV6IP, egressPodLabel)
				podUpdate.Annotations = map[string]string{
					"k8s.ovn.org/pod-networks": fmt.Sprintf("{\"default\":{\"ip_addresses\":[\"%s/23\"],\"mac_address\":\"0a:58:0a:83:00:0f\",\"gateway_ips\":[\"%s\"],\"ip_address\":\"%s/23\",\"gateway_ip\":\"%s\"}}", podV6IP, v6GatewayIP, podV6IP, v6GatewayIP),
				}
				i, n, _ := net.ParseCIDR(podV6IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Update(context.TODO(), podUpdate, metav1.UpdateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip6.src == %s", podV6IP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv6,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV6IP,
						ExternalIP: egressIP.String(),
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not treat pod DELETE if pod did not have an assigned IP when it got the ADD and we receive a DELETE before the IP UPDATE", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, "", egressPodLabel)
				egressNamespace := newNamespace(namespace)
				fakeOvn.startWithDBSetup(clusterRouterDbSetup,
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)
				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
				}

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod.Namespace).Delete(context.TODO(), egressPod.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("IPv6 on namespace UPDATE", func() {

		ginkgo.It("should remove OVN pod egress setup when EgressIP is deleted", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV6IP, egressPodLabel)
				egressNamespace := newNamespaceWithLabels(namespace, egressPodLabel)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
								Networks: []string{nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.name,
								UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.name,
								UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Nat:  nil,
							},
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
					},
				}

				i, n, _ := net.ParseCIDR(podV6IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip6.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv6,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV6IP,
						ExternalIP: egressIP.String(),
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				err = fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Delete(context.TODO(), eIP.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouter{
						Name: ovntypes.OVNClusterRouter,
						UUID: ovntypes.OVNClusterRouter + "-UUID",
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  nil,
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("egressIP retry should remove OVN pod egress setup when EgressIP is deleted", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV6IP, egressPodLabel)
				egressNamespace := newNamespaceWithLabels(namespace, egressPodLabel)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
								Networks: []string{nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.name,
								UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.name,
								UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Nat:  nil,
							},
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
					},
				}

				i, n, _ := net.ParseCIDR(podV6IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				ginkgo.By("Bringing down NBDB")
				// inject transient problem, nbdb is down
				fakeOvn.controller.nbClient.Close()
				gomega.Eventually(func() bool {
					return fakeOvn.controller.nbClient.Connected()
				}).Should(gomega.BeFalse())

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// sleep long enough for TransactWithRetry to fail, causing egressnode operations to fail
				time.Sleep(types.OVSDBTimeout + time.Second)
				// check to see if the retry cache has an entry
				key := eIP.Name
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressIPs.getObjRetryEntry(key)
				}, inspectTimeout).ShouldNot(gomega.BeNil())
				connCtx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
				defer cancel()
				resetNBClient(connCtx, fakeOvn.controller.nbClient)
				fakeOvn.controller.retryPods.setRetryObjWithNoBackoff(key)
				fakeOvn.controller.retryEgressIPs.requestRetryObjs()
				// check the cache no longer has the entry
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressIPs.getObjRetryEntry(key)
				}, inspectTimeout).Should(gomega.BeNil())
				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip6.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv6,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV6IP,
						ExternalIP: egressIP.String(),
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				err = fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Delete(context.TODO(), eIP.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouter{
						Name: ovntypes.OVNClusterRouter,
						UUID: ovntypes.OVNClusterRouter + "-UUID",
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  nil,
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should remove OVN pod egress setup when EgressIP stops matching", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV6IP, egressPodLabel)
				egressNamespace := newNamespaceWithLabels(namespace, egressPodLabel)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
								Networks: []string{nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.name,
								UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.name,
								UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Nat:  nil,
							},
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				i, n, _ := net.ParseCIDR(podV6IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})
				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
					},
				}

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip6.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv6,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV6IP,
						ExternalIP: egressIP.String(),
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				namespaceUpdate := newNamespace(namespace)

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), namespaceUpdate, metav1.UpdateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouter{
						Name: ovntypes.OVNClusterRouter,
						UUID: ovntypes.OVNClusterRouter + "-UUID",
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  nil,
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not remove OVN pod egress setup when EgressIP stops matching, but pod never had any IP to begin with", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, "", egressPodLabel)
				egressNamespace := newNamespaceWithLabels(namespace, egressPodLabel)
				fakeOvn.startWithDBSetup(clusterRouterDbSetup,
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta("egressip"),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
					},
				}

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				namespaceUpdate := newNamespace(namespace)

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.TODO(), namespaceUpdate, metav1.UpdateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})
	ginkgo.Context("on EgressIP UPDATE", func() {

		ginkgo.It("should update OVN on EgressIP .spec.egressips change", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.101"
				egressIP2 := "192.168.126.102"
				egressIP3 := "192.168.126.103"
				node1IPv4 := "192.168.126.202/24"
				node2IPv4 := "192.168.126.51/24"

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV4IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1, egressIP2},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{"100.64.0.3/29"},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{"100.64.0.2/29"},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					})

				i, n, _ := net.ParseCIDR(podV4IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(2))
				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				assignmentNode1, assignmentNode2 := nodes[0], nodes[1]
				assignedEgressIP1, assignedEgressIP2 := egressIPs[0], egressIPs[1]

				expectedNatLogicalPort1 := fmt.Sprintf("k8s-%s", assignmentNode1)
				expectedNatLogicalPort2 := fmt.Sprintf("k8s-%s", assignmentNode2)
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: []string{"100.64.0.2", "100.64.0.3"},
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-1-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: assignedEgressIP1,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-2-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: assignedEgressIP2,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort2,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + assignmentNode1,
						UUID: ovntypes.GWRouterPrefix + assignmentNode1 + "-UUID",
						Nat:  []string{"egressip-nat-1-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + assignmentNode2,
						UUID: ovntypes.GWRouterPrefix + assignmentNode2 + "-UUID",
						Nat:  []string{"egressip-nat-2-UUID"},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{"100.64.0.3/29"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				latest, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Get(context.TODO(), eIP.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				latest.Spec.EgressIPs = []string{egressIP3, egressIP2}
				_, err = fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Update(context.TODO(), latest, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(func() []string {
					egressIPs, _ = getEgressIPStatus(eIP.Name)
					return egressIPs
				}).Should(gomega.ConsistOf(egressIP3, egressIP2))

				egressIPs, nodes = getEgressIPStatus(eIP.Name)
				assignmentNode1, assignmentNode2 = nodes[0], nodes[1]
				assignedEgressIP1, assignedEgressIP2 = egressIPs[0], egressIPs[1]

				expectedNatLogicalPort1 = fmt.Sprintf("k8s-%s", assignmentNode1)
				expectedNatLogicalPort2 = fmt.Sprintf("k8s-%s", assignmentNode2)
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: []string{"100.64.0.2", "100.64.0.3"},
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-1-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: assignedEgressIP1,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-2-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: assignedEgressIP2,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort2,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + assignmentNode1,
						UUID: ovntypes.GWRouterPrefix + assignmentNode1 + "-UUID",
						Nat:  []string{"egressip-nat-1-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + assignmentNode2,
						UUID: ovntypes.GWRouterPrefix + assignmentNode2 + "-UUID",
						Nat:  []string{"egressip-nat-2-UUID"},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{"100.64.0.3/29"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should delete and re-create", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8e0d")
				updatedEgressIP := net.ParseIP("0:0:0:0:0:feff:c0a8:8ffd")

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV6IP, egressPodLabel)
				egressNamespace := newNamespaceWithLabels(namespace, egressPodLabel)

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
								Networks: []string{nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.name,
								UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.name,
								UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
								Nat:  nil,
							},
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				i, n, _ := net.ParseCIDR(podV6IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})
				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{
							egressIP.String(),
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
					},
				}

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP.Name)).Should(gomega.Equal(1))

				expectedNatLogicalPort := "k8s-node2"
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip6.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv6,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.name,
						Networks: []string{nodeLogicalRouterIfAddrV6},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV6IP,
						ExternalIP: egressIP.String(),
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.name,
						UUID: ovntypes.GWRouterPrefix + node1.name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.name,
						UUID: ovntypes.GWRouterPrefix + node2.name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				egressIPs, nodes := getEgressIPStatus(eIP.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP.String()))

				eIPUpdate, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Get(context.TODO(), eIP.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				eIPUpdate.Spec = egressipv1.EgressIPSpec{
					EgressIPs: []string{
						updatedEgressIP.String(),
					},
					PodSelector: metav1.LabelSelector{
						MatchLabels: egressPodLabel,
					},
					NamespaceSelector: metav1.LabelSelector{
						MatchLabels: egressPodLabel,
					},
				}

				_, err = fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Update(context.TODO(), eIPUpdate, metav1.UpdateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(func() []string {
					egressIPs, _ = getEgressIPStatus(eIP.Name)
					return egressIPs
				}).Should(gomega.ContainElement(updatedEgressIP.String()))

				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})

	ginkgo.Context("WatchEgressNodes", func() {

		ginkgo.It("should populated egress node data as they are tagged `egress assignable` with variants of IPv4/IPv6", func() {
			app.Action = func(ctx *cli.Context) error {

				node1IPv4 := "192.168.128.202/24"
				node1IPv6 := "0:0:0:0:0:feff:c0a8:8e0c/64"
				node2IPv4 := "192.168.126.51/24"

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node1",
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, node1IPv6),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":[\"%s\", \"%s\"]}", v4NodeSubnet, v6NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node2",
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{
					NBData: []libovsdbtest.TestData{
						&nbdb.LogicalRouter{
							Name: ovntypes.OVNClusterRouter,
							UUID: ovntypes.OVNClusterRouter + "-UUID",
						},
						&nbdb.LogicalRouter{
							Name: ovntypes.GWRouterPrefix + node1.Name,
							UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						},
						&nbdb.LogicalRouter{
							Name: ovntypes.GWRouterPrefix + node2.Name,
							UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						},
						&nbdb.LogicalSwitchPort{
							UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
							Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
							Type: "router",
							Options: map[string]string{
								"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							},
						},
						&nbdb.LogicalSwitchPort{
							UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
							Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
							Type: "router",
							Options: map[string]string{
								"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							},
						},
					},
				})
				fakeOvn.controller.WatchEgressNodes()
				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(0))

				node1.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, ip1V4Sub, err := net.ParseCIDR(node1IPv4)
				_, ip1V6Sub, err := net.ParseCIDR(node1IPv6)
				_, ip2V4Sub, err := net.ParseCIDR(node2IPv4)

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Create(context.TODO(), &node1, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(1))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node1.Name].egressIPConfig.V4.Net).To(gomega.Equal(ip1V4Sub))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node1.Name].egressIPConfig.V6.Net).To(gomega.Equal(ip1V6Sub))

				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Create(context.TODO(), &node2, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node2.Name].egressIPConfig.V4.Net).To(gomega.Equal(ip2V4Sub))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node1.Name].egressIPConfig.V4.Net).To(gomega.Equal(ip1V4Sub))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node1.Name].egressIPConfig.V6.Net).To(gomega.Equal(ip1V6Sub))

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("using retry to create egress node with forced error followed by an update", func() {
			app.Action = func(ctx *cli.Context) error {
				nodeIPv4 := "192.168.126.51/24"
				nodeIPv6 := "0:0:0:0:0:feff:c0a8:8e0c/64"
				node := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", nodeIPv4, nodeIPv6),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":[\"%s\", \"%s\"]}", v4NodeSubnet, v6NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				fakeOvn.startWithDBSetup(libovsdbtest.TestSetup{
					NBData: []libovsdbtest.TestData{
						&nbdb.LogicalRouter{
							Name: ovntypes.OVNClusterRouter,
							UUID: ovntypes.OVNClusterRouter + "-UUID",
						},
						&nbdb.LogicalRouter{
							Name: ovntypes.GWRouterPrefix + node.Name,
							UUID: ovntypes.GWRouterPrefix + node.Name + "-UUID",
						},
						&nbdb.LogicalSwitchPort{
							UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName + "UUID",
							Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName,
							Type: "router",
							Options: map[string]string{
								"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + nodeName,
							},
						},
					},
				})
				fakeOvn.controller.WatchEgressNodes()
				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(0))

				_, ipV4Sub, err := net.ParseCIDR(nodeIPv4)
				_, ipV6Sub, err := net.ParseCIDR(nodeIPv6)
				node.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Create(context.TODO(), &node, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				ginkgo.By("Bringing down NBDB")
				// inject transient problem, nbdb is down
				fakeOvn.controller.nbClient.Close()
				gomega.Eventually(func() bool {
					return fakeOvn.controller.nbClient.Connected()
				}).Should(gomega.BeFalse())

				// sleep long enough for TransactWithRetry to fail, causing egressnode operations to fail
				// there is a chance that both egressnode events(node1 removal and node2 update) will end up in the same event queue
				// sleep for double the time to allow for two consecutive TransactWithRetry timeouts
				time.Sleep(2 * (types.OVSDBTimeout + time.Second))
				// check to see if the retry cache has an entry
				key := node.Name
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key)
				}).ShouldNot(gomega.BeNil())
				retryEntry := fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key)
				ginkgo.By("retry entry new obj should not be nil")
				gomega.Expect(retryEntry.newObj).NotTo(gomega.BeNil())
				ginkgo.By("retry entry old obj should be nil")
				gomega.Expect(retryEntry.oldObj).To(gomega.BeNil())

				node.Labels = map[string]string{}
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				connCtx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
				defer cancel()
				resetNBClient(connCtx, fakeOvn.controller.nbClient)
				fakeOvn.controller.retryEgressNodes.setRetryObjWithNoBackoff(key)
				fakeOvn.controller.retryEgressNodes.requestRetryObjs()
				// check the cache no longer has the entry
				gomega.Eventually(func() *retryObjEntry {
					return fakeOvn.controller.retryEgressNodes.getObjRetryEntry(key)
				}).Should(gomega.BeNil())
				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(1))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node.Name].egressIPConfig.V4.Net).To(gomega.Equal(ipV4Sub))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node.Name].egressIPConfig.V6.Net).To(gomega.Equal(ipV6Sub))

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node.Name,
						UUID: ovntypes.GWRouterPrefix + node.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + nodeName,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("egressIP pod recreate with same name (stateful-sets) shouldn't use stale logicalPortCache entries", func() {
			app.Action = func(ctx *cli.Context) error {

				config.Gateway.DisableSNATMultipleGWs = true

				egressIP1 := "192.168.126.101"
				node1IPv4 := "192.168.126.12/24"

				egressPod1 := *newPodWithLabels(namespace, podName, node1Name, "", egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node1IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
							"k8s.ovn.org/l3-gateway-config":   `{"default":{"mode":"local","mac-address":"7e:57:f8:f0:3c:49", "ip-address":"192.168.126.12/24", "next-hop":"192.168.126.1"}}`,
							"k8s.ovn.org/node-chassis-id":     "79fdcfc4-6fe6-4cd3-8242-c0f85a4668ec",
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{
							{
								Node:     node1.Name,
								EgressIP: egressIP1,
							},
						},
					},
				}
				nodeSwitch := &nbdb.LogicalSwitch{
					UUID: node1.Name + "-UUID",
					Name: node1.Name,
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							nodeSwitch,
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod1},
					},
				)

				fakeOvn.controller.lsManager.AddNode(node1.Name, node1.Name+"-UUID", []*net.IPNet{ovntest.MustParseIPNet(v4NodeSubnet)})
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				egressPodPortInfo, err := fakeOvn.controller.logicalPortCache.get(util.GetLogicalPortName(egressPod1.Namespace, egressPod1.Name))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				egressPodIP, _, err := net.ParseCIDR(egressPodPortInfo.ips[0].String())
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(egressPodPortInfo.expires.IsZero()).To(gomega.BeTrue())
				podAddr := fmt.Sprintf("%s %s", egressPodPortInfo.mac.String(), egressPodIP)

				expectedNatLogicalPort1 := "k8s-node1"
				expectedDatabaseStatewithPod := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID1",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID", "reroute-UUID1"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID1"},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID1",
						LogicalIP:  egressPodIP.String(),
						ExternalIP: egressIP1,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
					nodeSwitch,
				}
				podLSP := &nbdb.LogicalSwitchPort{
					UUID:      util.GetLogicalPortName(egressPod1.Namespace, egressPod1.Name) + "-UUID",
					Name:      util.GetLogicalPortName(egressPod1.Namespace, egressPod1.Name),
					Addresses: []string{podAddr},
					ExternalIDs: map[string]string{
						"pod":       "true",
						"namespace": egressPod1.Namespace,
					},
					Options: map[string]string{
						"requested-chassis": egressPod1.Spec.NodeName,
						"iface-id-ver":      egressPod1.Name,
					},
					PortSecurity: []string{podAddr},
				}
				nodeSwitch.Ports = []string{podLSP.UUID}
				finalDatabaseStatewithPod := append(expectedDatabaseStatewithPod, podLSP)
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				_, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(finalDatabaseStatewithPod))

				// delete the pod
				err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(egressPod1.Namespace).Delete(context.TODO(),
					egressPod1.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseStateWithoutPod := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
					&nbdb.LogicalSwitch{
						UUID:  node1.Name + "-UUID",
						Name:  node1.Name,
						Ports: []string{},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseStateWithoutPod))
				// recreate pod with same name immediately; simulating handler race (pods v/s egressip) condition,
				// so instead of proper pod create, we try out egressIP pod setup which will be a no-op since pod doesn't exist
				ginkgo.By("should not add egress IP setup for a deleted pod whose entry exists in logicalPortCache")
				err = fakeOvn.controller.addPodEgressIPAssignments(egressIPName, eIP.Status.Items, &egressPod1)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// pod is gone but logicalPortCache holds the entry for 60seconds
				egressPodPortInfo, err = fakeOvn.controller.logicalPortCache.get(util.GetLogicalPortName(egressPod1.Namespace, egressPod1.Name))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(egressPodPortInfo.expires.IsZero()).To(gomega.BeFalse())
				staleEgressPodIP, _, err := net.ParseCIDR(egressPodPortInfo.ips[0].String())
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(staleEgressPodIP).To(gomega.Equal(egressPodIP))
				// no-op
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseStateWithoutPod))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should skip populating egress node data for nodes that have incorrect IP address", func() {
			app.Action = func(ctx *cli.Context) error {

				nodeIPv4 := "192.168.126.510/24"
				nodeIPv6 := "0:0:0:0:0:feff:c0a8:8e0c/64"
				node := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", nodeIPv4, nodeIPv6),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":[\"%s\", \"%s\"]}", v4NodeSubnet, v6NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
						},
					},
					&v1.NodeList{
						Items: []v1.Node{node},
					},
				)

				allocatorItems := func() int {
					return len(fakeOvn.controller.eIPC.allocator.cache)
				}

				err := fakeOvn.controller.WatchEgressNodes()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(allocatorItems).Should(gomega.Equal(0))

				node.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(allocatorItems).Should(gomega.Equal(0))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})

	ginkgo.Context("WatchEgressNodes running with WatchEgressIP", func() {

		ginkgo.It("should treat un-assigned EgressIPs when it is tagged", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				nodeIPv4 := "192.168.126.51/24"
				nodeIPv6 := "0:0:0:0:0:feff:c0a8:8e0c/64"

				node := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", nodeIPv4, nodeIPv6),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":[\"%s\", \"%s\"]}", v4NodeSubnet, v6NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node.Name,
								UUID: ovntypes.GWRouterPrefix + node.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node.Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node.Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node.Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node.Name,
						UUID: ovntypes.GWRouterPrefix + node.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node.Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node.Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node.Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(1))
				gomega.Eventually(isEgressAssignableNode(node.Name)).Should(gomega.BeFalse())
				gomega.Eventually(eIP.Status.Items).Should(gomega.HaveLen(0))

				node.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, ipv4Sub, err := net.ParseCIDR(nodeIPv4)
				_, ipv6Sub, err := net.ParseCIDR(nodeIPv6)

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(isEgressAssignableNode(node.Name)).Should(gomega.BeTrue())
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveLen(1))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node.Name].egressIPConfig.V4.Net).To(gomega.Equal(ipv4Sub))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node.Name].egressIPConfig.V6.Net).To(gomega.Equal(ipv6Sub))

				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(0))
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node.Name,
						UUID: ovntypes.GWRouterPrefix + node.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node.Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node.Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node.Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should result in error and event if specified egress IP is a cluster node IP", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.51"
				node1IPv4 := "192.168.128.202/24"
				node1IPv6 := "0:0:0:0:0:feff:c0a8:8e0c/64"
				node2IPv4 := "192.168.126.51/24"

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, node1IPv6),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":[\"%s\", \"%s\"]}", v4NodeSubnet, v6NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(0))
				gomega.Eventually(fakeOvn.fakeRecorder.Events).Should(gomega.HaveLen(3))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should re-assigned EgressIPs when more nodes get tagged if the first assignment attempt wasn't fully successful", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.25"
				egressIP2 := "192.168.126.30"
				node1IPv4 := "192.168.126.51/24"
				node2IPv4 := "192.168.126.101/24"

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node1IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node2IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1, egressIP2},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))

				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(1))

				recordedEvent := <-fakeOvn.fakeRecorder.Events
				gomega.Expect(recordedEvent).To(gomega.ContainSubstring("Not all egress IPs for EgressIP: %s could be assigned, please tag more nodes", eIP.Name))

				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}
				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(2))
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should remove stale EgressIP setup when node label is removed while ovnkube-master is not running and assign to newly labelled node", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.25"
				node1IPv4 := "192.168.126.51/24"

				egressPod := *newPodWithLabels(namespace, podName, node1Name, podV4IP, egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node1IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node1IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{
							{
								Node:     node1.Name,
								EgressIP: egressIP1,
							},
						},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: types.OVNClusterRouter,
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod},
					},
				)

				i, n, _ := net.ParseCIDR(podV4IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod.Namespace, egressPod.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(0))
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "default-no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"reroute-UUID", "default-no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}

				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should remove stale EgressIP setup when pod is deleted while ovnkube-master is not running", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.25"
				node1IPv4 := "192.168.126.51/24"

				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node1IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{
							{
								Node:     node1.Name,
								EgressIP: egressIP1,
							},
						},
					},
				}

				expectedNatLogicalPort := "k8s-node1"
				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPolicy{
								UUID:     "keep-me-UUID",
								Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
								Priority: types.DefaultNoRereoutePriority,
								Action:   nbdb.LogicalRouterPolicyActionAllow,
							},
							&nbdb.LogicalRouterPolicy{
								UUID: "remove-me-UUID",
								ExternalIDs: map[string]string{
									"name": eIP.Name,
								},
								Match:    "ip.src == 10.128.3.8",
								Priority: types.EgressIPReroutePriority,
								Action:   nbdb.LogicalRouterPolicyActionReroute,
							},
							&nbdb.LogicalRouter{
								Name:     ovntypes.OVNClusterRouter,
								UUID:     ovntypes.OVNClusterRouter + "-UUID",
								Policies: []string{"remove-me-UUID", "keep-me-UUID"},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Nat:  []string{"egressip-nat-UUID"},
							},
							&nbdb.NAT{
								UUID:       "egressip-nat-UUID",
								LogicalIP:  podV4IP,
								ExternalIP: egressIP1,
								ExternalIDs: map[string]string{
									"name": egressIPName,
								},
								Type:        nbdb.NATTypeSNAT,
								LogicalPort: &expectedNatLogicalPort,
								Options: map[string]string{
									"stateless": "false",
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
				)

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(0))
				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						UUID:     "keep-me-UUID",
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Priority: types.DefaultNoRereoutePriority,
						Action:   nbdb.LogicalRouterPolicyActionAllow,
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"keep-me-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID"},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID",
						LogicalIP:  podV4IP,
						ExternalIP: egressIP1,
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should only get assigned EgressIPs which matches their subnet when the node is tagged", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				node1IPv4 := "192.168.128.202/24"
				node1IPv6 := "0:0:0:0:0:feff:c0a8:8e0c/64"
				node2IPv4 := "192.168.126.51/24"

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, node1IPv6),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				_, ip1V4Sub, err := net.ParseCIDR(node1IPv4)
				_, ip1V6Sub, err := net.ParseCIDR(node1IPv6)
				_, ip2V4Sub, err := net.ParseCIDR(node2IPv4)

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeFalse())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeFalse())
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node1.Name].egressIPConfig.V4.Net).To(gomega.Equal(ip1V4Sub))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node1.Name].egressIPConfig.V6.Net).To(gomega.Equal(ip1V6Sub))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache[node2.Name].egressIPConfig.V4.Net).To(gomega.Equal(ip2V4Sub))
				gomega.Eventually(eIP.Status.Items).Should(gomega.HaveLen(0))

				node1.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(0))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())

				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(1))

				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))

				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))
				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(0))
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should try re-assigning EgressIP until all defined egress IPs are assigned", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.101"
				egressIP2 := "192.168.126.102"
				node1IPv4 := "192.168.126.12/24"
				node2IPv4 := "192.168.126.51/24"

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node1IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node2IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1, egressIP2},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(0))

				node1.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				_, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))

				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(1))

				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(2))
				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(0))

				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should ensure SNATs towards egressIP and nodeIP are correctly configured during egressIP re-assignment", func() {
			app.Action = func(ctx *cli.Context) error {
				config.Gateway.DisableSNATMultipleGWs = true

				egressIP1 := "192.168.126.101"
				egressIP2 := "192.168.126.102"
				node1IPv4 := "192.168.126.12/24"
				node2IPv4 := "192.168.126.51/24"

				egressPod1 := *newPodWithLabels(namespace, podName, node1Name, podV4IP, egressPodLabel)
				egressPod2 := *newPodWithLabels(namespace, "egress-pod2", node2Name, "10.128.0.16", egressPodLabel)
				egressNamespace := newNamespace(namespace)

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node1IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
							"k8s.ovn.org/l3-gateway-config":   `{"default":{"mode":"local","mac-address":"7e:57:f8:f0:3c:49", "ip-address":"192.168.126.12/24", "next-hop":"192.168.126.1"}}`,
							"k8s.ovn.org/node-chassis-id":     "79fdcfc4-6fe6-4cd3-8242-c0f85a4668ec",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\"}", node2IPv4),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
							"k8s.ovn.org/l3-gateway-config":   `{"default":{"mode":"local","mac-address":"7e:57:f8:f0:3c:49", "ip-address":"192.168.126.51/24", "next-hop":"192.168.126.1"}}`,
							"k8s.ovn.org/node-chassis-id":     "89fdcfc4-6fe6-4cd3-8242-c0f85a4668ec",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1, egressIP2},
						PodSelector: metav1.LabelSelector{
							MatchLabels: egressPodLabel,
						},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": egressNamespace.Name,
							},
						},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{"100.64.0.2/29"},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{"100.64.0.3/29"},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1, node2},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{*egressNamespace},
					},
					&v1.PodList{
						Items: []v1.Pod{egressPod1, egressPod2},
					},
				)

				i, n, _ := net.ParseCIDR(podV4IP + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod1.Namespace, egressPod1.Name), "", nil, []*net.IPNet{n})
				i, n, _ = net.ParseCIDR("10.128.0.16" + "/23")
				n.IP = i
				fakeOvn.controller.logicalPortCache.add("", util.GetLogicalPortName(egressPod2.Namespace, egressPod2.Name), "", nil, []*net.IPNet{n})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{"100.64.0.3/29"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(0))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeFalse())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeFalse())

				node1.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeFalse())
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(1))
				eips, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))

				expectedNatLogicalPort1 := "k8s-node1"
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod1.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: []string{"100.64.0.2"},
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID1",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod2.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: []string{"100.64.0.2"},
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID2",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID", "reroute-UUID1", "reroute-UUID2"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID1", "egressip-nat-UUID2"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID1",
						LogicalIP:  podV4IP,
						ExternalIP: eips[0],
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID2",
						LogicalIP:  "10.128.0.16",
						ExternalIP: eips[0],
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{"100.64.0.3/29"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				node2.Labels = map[string]string{
					"k8s.ovn.org/egress-assignable": "",
				}

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(isEgressAssignableNode(node1.Name)).Should(gomega.BeTrue())
				gomega.Eventually(isEgressAssignableNode(node2.Name)).Should(gomega.BeTrue())
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(2))
				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(0))

				eips, nodes = getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))
				gomega.Expect(nodes[1]).To(gomega.Equal(node2.Name))

				expectedNatLogicalPort2 := "k8s-node2"
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod1.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: []string{"100.64.0.2", "100.64.0.3"},
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID1",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod2.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: []string{"100.64.0.2", "100.64.0.3"},
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID2",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID1",
						LogicalIP:  podV4IP,
						ExternalIP: eips[0],
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID2",
						LogicalIP:  "10.128.0.16",
						ExternalIP: eips[0],
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID3",
						LogicalIP:  podV4IP,
						ExternalIP: eips[1],
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort2,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID4",
						LogicalIP:  "10.128.0.16",
						ExternalIP: eips[1],
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort2,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID", "reroute-UUID1", "reroute-UUID2"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID1", "egressip-nat-UUID2"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID3", "egressip-nat-UUID4"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{"100.64.0.3/29"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				// remove label from node2
				node2.Labels = map[string]string{}

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node2, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(1))

				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod1.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID1",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.EgressIPReroutePriority,
						Match:    fmt.Sprintf("ip4.src == %s", egressPod2.Status.PodIP),
						Action:   nbdb.LogicalRouterPolicyActionReroute,
						Nexthops: nodeLogicalRouterIPv4,
						ExternalIDs: map[string]string{
							"name": eIP.Name,
						},
						UUID: "reroute-UUID2",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID1",
						LogicalIP:  podV4IP,
						ExternalIP: eips[0],
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID2",
						LogicalIP:  "10.128.0.16",
						ExternalIP: eips[0],
						ExternalIDs: map[string]string{
							"name": egressIPName,
						},
						Type:        nbdb.NATTypeSNAT,
						LogicalPort: &expectedNatLogicalPort1,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID3",
						LogicalIP:  "10.128.0.16",
						ExternalIP: "192.168.126.51", // adds back SNAT towards nodeIP
						Type:       nbdb.NATTypeSNAT,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID", "reroute-UUID1", "reroute-UUID2"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID1", "egressip-nat-UUID2"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID3"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{"100.64.0.3/29"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				// remove label from node1
				node1.Labels = map[string]string{}

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), &node1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(0))
				gomega.Eventually(getEgressIPReassignmentCount).Should(gomega.Equal(1)) // though 2 egressIPs to be re-assigned its only 1 egressIP object

				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID1",
						LogicalIP:  podV4IP,
						ExternalIP: "192.168.126.12", // adds back SNAT towards nodeIP
						Type:       nbdb.NATTypeSNAT,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.NAT{
						UUID:       "egressip-nat-UUID3",
						LogicalIP:  "10.128.0.16",
						ExternalIP: "192.168.126.51",
						Type:       nbdb.NATTypeSNAT,
						Options: map[string]string{
							"stateless": "false",
						},
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID1"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Nat:  []string{"egressip-nat-UUID3"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{"100.64.0.3/29"},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{"100.64.0.2/29"},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should re-balance EgressIPs when their node is removed", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				node1IPv4 := "192.168.126.12/24"
				node1IPv6 := "0:0:0:0:0:feff:c0a8:8e0c/64"
				node2IPv4 := "192.168.126.51/24"

				node1 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node1IPv4, node1IPv6),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":[\"%s\", \"%s\"]}", v4NodeSubnet, v6NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}
				node2 := v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Annotations: map[string]string{
							"k8s.ovn.org/node-primary-ifaddr": fmt.Sprintf("{\"ipv4\": \"%s\", \"ipv6\": \"%s\"}", node2IPv4, ""),
							"k8s.ovn.org/node-subnets":        fmt.Sprintf("{\"default\":\"%s\"}", v4NodeSubnet),
						},
						Labels: map[string]string{
							"k8s.ovn.org/egress-assignable": "",
						},
					},
					Status: v1.NodeStatus{
						Conditions: []v1.NodeCondition{
							{
								Type:   v1.NodeReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4, nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1.Name,
								UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2.Name,
								UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
								},
							},
							&nbdb.LogicalSwitchPort{
								UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
								Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
								Type: "router",
								Options: map[string]string{
									"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
								},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
					&v1.NodeList{
						Items: []v1.Node{node1},
					})

				fakeOvn.controller.WatchEgressIPNamespaces()
				fakeOvn.controller.WatchEgressIPPods()
				fakeOvn.controller.WatchEgressNodes()
				fakeOvn.controller.WatchEgressIP()

				expectedDatabaseState := []libovsdbtest.TestData{
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4, nodeLogicalRouterIfAddrV6},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(1))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Create(context.TODO(), &node2, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4, nodeLogicalRouterIfAddrV6},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes = getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.Name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))
				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(2))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Nodes().Delete(context.TODO(), node1.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(getEgressIPAllocatorSizeSafely).Should(gomega.Equal(1))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).ToNot(gomega.HaveKey(node1.Name))
				gomega.Expect(fakeOvn.controller.eIPC.allocator.cache).To(gomega.HaveKey(node2.Name))
				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))

				getNewNode := func() string {
					_, nodes = getEgressIPStatus(egressIPName)
					if len(nodes) > 0 {
						return nodes[0]
					}
					return ""
				}

				gomega.Eventually(getNewNode).Should(gomega.Equal(node2.Name))
				egressIPs, _ = getEgressIPStatus(egressIPName)
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				expectedDatabaseState = []libovsdbtest.TestData{
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4, nodeLogicalRouterIfAddrV6},
					},
					&nbdb.LogicalRouterPort{
						UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name + "-UUID",
						Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2.Name,
						Networks: []string{nodeLogicalRouterIfAddrV4},
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    "ip4.src == 10.128.0.0/14 && ip4.dst == 10.128.0.0/14",
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-UUID",
					},
					&nbdb.LogicalRouterPolicy{
						Priority: types.DefaultNoRereoutePriority,
						Match:    fmt.Sprintf("ip4.src == 10.128.0.0/14 && ip4.dst == %s", config.Gateway.V4JoinSubnet),
						Action:   nbdb.LogicalRouterPolicyActionAllow,
						UUID:     "no-reroute-service-UUID",
					},
					&nbdb.LogicalRouter{
						Name:     ovntypes.OVNClusterRouter,
						UUID:     ovntypes.OVNClusterRouter + "-UUID",
						Policies: []string{"no-reroute-UUID", "no-reroute-service-UUID"},
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node1.Name,
						UUID: ovntypes.GWRouterPrefix + node1.Name + "-UUID",
					},
					&nbdb.LogicalRouter{
						Name: ovntypes.GWRouterPrefix + node2.Name,
						UUID: ovntypes.GWRouterPrefix + node2.Name + "-UUID",
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node1Name,
						Type: "router",
						Options: map[string]string{
							"router-port": types.GWRouterToExtSwitchPrefix + "GR_" + node1Name,
						},
					},
					&nbdb.LogicalSwitchPort{
						UUID: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name + "UUID",
						Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + node2Name,
						Type: "router",
						Options: map[string]string{
							"router-port":               types.GWRouterToExtSwitchPrefix + "GR_" + node2Name,
							"nat-addresses":             "router",
							"exclude-lb-vips-from-garp": "true",
						},
					},
				}
				gomega.Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedDatabaseState))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})

	ginkgo.Context("Dual-stack assignment", func() {

		ginkgo.It("should be able to allocate non-conflicting IPv4 on node which can host it, even if it happens to be the node with more assignments", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()
				egressIP := "192.168.126.99"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus1"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus1", "192.168.126.102": "bogus2"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
				}
				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(1))
				gomega.Expect(assignedStatuses[0].Node).To(gomega.Equal(node2.name))
				gomega.Expect(assignedStatuses[0].EgressIP).To(gomega.Equal(net.ParseIP(egressIP).String()))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})

	ginkgo.Context("IPv4 assignment", func() {

		ginkgo.It("Should not be able to assign egress IP defined in CIDR notation", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIPs := []string{"192.168.126.99/32"}

				node1 := setupNode(node1Name, []string{"192.168.126.12/24"}, map[string]string{"192.168.126.102": "bogus1", "192.168.126.111": "bogus2"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: egressIPs,
					},
				}

				validatedIPs, err := fakeOvn.controller.validateEgressIPSpec(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(err.Error()).To(gomega.Equal(fmt.Sprintf("unable to parse provided EgressIP: %s, invalid", egressIPs[0])))
				gomega.Expect(validatedIPs).To(gomega.HaveLen(0))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})

	ginkgo.Context("IPv6 assignment", func() {

		ginkgo.It("should be able to allocate non-conflicting IP on node with lowest amount of allocations", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP := "0:0:0:0:0:feff:c0a8:8e0f"
				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
				}
				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(1))
				gomega.Expect(assignedStatuses[0].Node).To(gomega.Equal(node2.name))
				gomega.Expect(assignedStatuses[0].EgressIP).To(gomega.Equal(net.ParseIP(egressIP).String()))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should be able to allocate several EgressIPs and avoid the same node", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP1 := "0:0:0:0:0:feff:c0a8:8e0d"
				egressIP2 := "0:0:0:0:0:feff:c0a8:8e0f"
				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1, egressIP2},
					},
				}
				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(2))
				gomega.Expect(assignedStatuses[0].Node).To(gomega.Equal(node2.name))
				gomega.Expect(assignedStatuses[0].EgressIP).To(gomega.Equal(net.ParseIP(egressIP1).String()))
				gomega.Expect(assignedStatuses[1].Node).To(gomega.Equal(node1.name))
				gomega.Expect(assignedStatuses[1].EgressIP).To(gomega.Equal(net.ParseIP(egressIP2).String()))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should be able to allocate several EgressIPs and avoid the same node and leave one un-assigned without error", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP1 := "0:0:0:0:0:feff:c0a8:8e0d"
				egressIP2 := "0:0:0:0:0:feff:c0a8:8e0e"
				egressIP3 := "0:0:0:0:0:feff:c0a8:8e0f"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1, egressIP2, egressIP3},
					},
				}
				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(2))
				gomega.Expect(assignedStatuses[0].Node).To(gomega.Equal(node2.name))
				gomega.Expect(assignedStatuses[0].EgressIP).To(gomega.Equal(net.ParseIP(egressIP1).String()))
				gomega.Expect(assignedStatuses[1].Node).To(gomega.Equal(node1.name))
				gomega.Expect(assignedStatuses[1].EgressIP).To(gomega.Equal(net.ParseIP(egressIP2).String()))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should return the already allocated IP with the same node if it is allocated again", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP := "0:0:0:0:0:feff:c0a8:8e32"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{egressIP: egressIPName, "0:0:0:0:0:feff:c0a8:8e1e": "bogus1"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus2"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				egressIPs := []string{egressIP}
				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: egressIPs,
					},
				}

				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(1))
				gomega.Expect(assignedStatuses[0].Node).To(gomega.Equal(node1Name))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not be able to allocate node IP", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP := "0:0:0:0:0:feff:c0a8:8e0c"

				node1 := setupNode(node1Name, []string{egressIP + "/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
				}
				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(0))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not be able to allocate conflicting compressed IP", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP := "::feff:c0a8:8e32"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				egressIPs := []string{egressIP}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: egressIPs,
					},
				}

				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(0))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not be able to allocate IPv4 IP on nodes which can only host IPv6", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP := "192.168.126.16"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIPs := []string{egressIP}
				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: eIPs,
					},
				}

				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(0))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should be able to allocate non-conflicting compressed uppercase IP", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP := "::FEFF:C0A8:8D32"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
				}
				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(1))
				gomega.Expect(assignedStatuses[0].Node).To(gomega.Equal(node2.name))
				gomega.Expect(assignedStatuses[0].EgressIP).To(gomega.Equal(net.ParseIP(egressIP).String()))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not be able to allocate conflicting compressed uppercase IP", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIP := "::FEFF:C0A8:8E32"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2
				egressIPs := []string{egressIP}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: egressIPs,
					},
				}

				assignedStatuses := fakeOvn.controller.assignEgressIPs(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(0))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not be able to allocate invalid IP", func() {
			app.Action = func(ctx *cli.Context) error {

				fakeOvn.start()

				egressIPs := []string{"0:0:0:0:0:feff:c0a8:8e32:5"}

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: egressIPs,
					},
				}

				assignedStatuses, err := fakeOvn.controller.validateEgressIPSpec(eIP.Name, eIP.Spec.EgressIPs)
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(err.Error()).To(gomega.Equal(fmt.Sprintf("unable to parse provided EgressIP: %s, invalid", egressIPs[0])))
				gomega.Expect(assignedStatuses).To(gomega.HaveLen(0))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("WatchEgressIP", func() {

		ginkgo.It("should update status correctly for single-stack IPv4", func() {
			app.Action = func(ctx *cli.Context) error {
				fakeOvn.startWithDBSetup(clusterRouterDbSetup)

				egressIP := "192.168.126.10"
				node1 := setupNode(node1Name, []string{"192.168.126.12/24"}, map[string]string{"192.168.126.102": "bogus1", "192.168.126.111": "bogus2"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"name": "does-not-exist",
							},
						},
					},
				}

				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should update status correctly for single-stack IPv6", func() {
			app.Action = func(ctx *cli.Context) error {
				fakeOvn.startWithDBSetup(clusterRouterDbSetup)

				egressIP := "0:0:0:0:0:feff:c0a8:8e0d"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e32": "bogus1", "0:0:0:0:0:feff:c0a8:8e1e": "bogus2"})
				node2 := setupNode(node2Name, []string{"0:0:0:0:0:fedf:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
				}

				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(net.ParseIP(egressIP).String()))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should update status correctly for dual-stack", func() {
			app.Action = func(ctx *cli.Context) error {
				fakeOvn.startWithDBSetup(clusterRouterDbSetup)

				egressIPv4 := "192.168.126.101"
				egressIPv6 := "0:0:0:0:0:feff:c0a8:8e0d"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{"0:0:0:0:0:feff:c0a8:8e23": "bogus1"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus2", "192.168.126.102": "bogus3"})

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIPv4, egressIPv6},
					},
				}

				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(2))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes).To(gomega.ConsistOf(node2.name, node1.name))
				gomega.Expect(egressIPs).To(gomega.ConsistOf(net.ParseIP(egressIPv6).String(), net.ParseIP(egressIPv4).String()))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("syncEgressIP for dual-stack", func() {

		ginkgo.It("should not update valid assignments", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIPv4 := "192.168.126.101"
				egressIPv6 := "0:0:0:0:0:feff:c0a8:8e0d"

				node1 := setupNode(node1Name, []string{"0:0:0:0:0:feff:c0a8:8e0c/64"}, map[string]string{})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.102": "bogus3"})

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIPv4, egressIPv6},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{
							{
								EgressIP: egressIPv4,
								Node:     node2.name,
							},
							{
								EgressIP: net.ParseIP(egressIPv6).String(),
								Node:     node1.name,
							},
						},
					},
				}

				fakeOvn.startWithDBSetup(clusterRouterDbSetup,
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(2))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes).To(gomega.ConsistOf(eIP.Status.Items[0].Node, eIP.Status.Items[1].Node))
				gomega.Expect(egressIPs).To(gomega.ConsistOf(eIP.Status.Items[0].EgressIP, eIP.Status.Items[1].EgressIP))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("syncEgressIP for IPv4", func() {

		ginkgo.It("should update invalid assignments on duplicated node", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.101"
				egressIP2 := "192.168.126.100"

				node1 := setupNode(node1Name, []string{"192.168.126.12/24"}, map[string]string{egressIP1: egressIPName, egressIP2: egressIPName})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus3"})

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1, egressIP2},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{
							{
								EgressIP: egressIP1,
								Node:     node1.name,
							},
							{
								EgressIP: egressIP2,
								Node:     node1.name,
							},
						},
					},
				}
				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1Name,
								UUID: ovntypes.GWRouterPrefix + node1Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2Name,
								UUID: ovntypes.GWRouterPrefix + node2Name + "-UUID",
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(2))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes).To(gomega.ConsistOf(node1.name, node2.name))
				gomega.Expect(egressIPs).To(gomega.ConsistOf(eIP.Status.Items[0].EgressIP, eIP.Status.Items[1].EgressIP))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should update invalid assignments with incorrectly parsed IP", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.101"
				egressIPIncorrect := "192.168.126.1000"

				node1 := setupNode(node1Name, []string{"192.168.126.12/24"}, map[string]string{"192.168.126.102": "bogus1", "192.168.126.111": "bogus2"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus3"})

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{
							{
								EgressIP: egressIPIncorrect,
								Node:     node1.name,
							},
						},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1Name,
								UUID: ovntypes.GWRouterPrefix + node1Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2Name,
								UUID: ovntypes.GWRouterPrefix + node2Name + "-UUID",
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP1))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should update invalid assignments with unhostable IP on a node", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.101"
				egressIPIncorrect := "192.168.128.100"

				node1 := setupNode(node1Name, []string{"192.168.126.12/24"}, map[string]string{"192.168.126.102": "bogus1", "192.168.126.111": "bogus2"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus3"})

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{
							{
								EgressIP: egressIPIncorrect,
								Node:     node1.name,
							},
						},
					},
				}

				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1Name,
								UUID: ovntypes.GWRouterPrefix + node1Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2Name,
								UUID: ovntypes.GWRouterPrefix + node2Name + "-UUID",
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
						},
					},
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP1))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should not update valid assignment", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP1 := "192.168.126.101"

				node1 := setupNode(node1Name, []string{"192.168.126.12/24"}, map[string]string{"192.168.126.111": "bogus2"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus3"})

				eIP := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1},
					},
					Status: egressipv1.EgressIPStatus{
						Items: []egressipv1.EgressIPStatusItem{
							{
								EgressIP: egressIP1,
								Node:     node1.name,
							},
						},
					},
				}

				fakeOvn.startWithDBSetup(clusterRouterDbSetup,
					&egressipv1.EgressIPList{
						Items: []egressipv1.EgressIP{eIP},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				fakeOvn.controller.WatchEgressIP()

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node1.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP1))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("AddEgressIP for IPv4", func() {

		ginkgo.It("should not create two EgressIPs with same egress IP value", func() {
			app.Action = func(ctx *cli.Context) error {
				egressIP1 := "192.168.126.101"

				node1 := setupNode(node1Name, []string{"192.168.126.12/24"}, map[string]string{"192.168.126.102": "bogus1", "192.168.126.111": "bogus2"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus3"})

				eIP1 := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta("egressip"),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1},
					},
				}
				eIP2 := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta("egressip2"),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP1},
					},
				}

				fakeOvn.startWithDBSetup(clusterRouterDbSetup)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2

				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP1, metav1.CreateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP1.Name)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(eIP1.Name)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP1))

				_, err = fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP2, metav1.CreateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(eIP2.Name)).Should(gomega.Equal(0))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

	})

	ginkgo.Context("UpdateEgressIP for IPv4", func() {

		ginkgo.It("should perform re-assingment of EgressIPs", func() {
			app.Action = func(ctx *cli.Context) error {

				egressIP := "192.168.126.101"
				updateEgressIP := "192.168.126.10"

				node1 := setupNode(node1Name, []string{"192.168.126.41/24"}, map[string]string{"192.168.126.102": "bogus1", "192.168.126.111": "bogus2"})
				node2 := setupNode(node2Name, []string{"192.168.126.51/24"}, map[string]string{"192.168.126.68": "bogus3"})

				eIP1 := egressipv1.EgressIP{
					ObjectMeta: newEgressIPMeta(egressIPName),
					Spec: egressipv1.EgressIPSpec{
						EgressIPs: []string{egressIP},
					},
				}
				fakeOvn.startWithDBSetup(
					libovsdbtest.TestSetup{
						NBData: []libovsdbtest.TestData{
							&nbdb.LogicalRouter{
								Name: ovntypes.OVNClusterRouter,
								UUID: ovntypes.OVNClusterRouter + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node1Name,
								UUID: ovntypes.GWRouterPrefix + node1Name + "-UUID",
							},
							&nbdb.LogicalRouter{
								Name: ovntypes.GWRouterPrefix + node2Name,
								UUID: ovntypes.GWRouterPrefix + node2Name + "-UUID",
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node1Name,
								Networks: []string{nodeLogicalRouterIfAddrV4, nodeLogicalRouterIfAddrV6},
							},
							&nbdb.LogicalRouterPort{
								UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2Name + "-UUID",
								Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + node2Name,
								Networks: []string{nodeLogicalRouterIfAddrV4},
							},
						},
					},
				)

				fakeOvn.controller.eIPC.allocator.cache[node1.name] = &node1
				fakeOvn.controller.eIPC.allocator.cache[node2.name] = &node2
				fakeOvn.controller.WatchEgressIP()

				_, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Create(context.TODO(), &eIP1, metav1.CreateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())

				gomega.Eventually(getEgressIPStatusLen(egressIPName)).Should(gomega.Equal(1))
				egressIPs, nodes := getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				gomega.Expect(egressIPs[0]).To(gomega.Equal(egressIP))

				eIPToUpdate, err := fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Get(context.TODO(), eIP1.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				eIPToUpdate.Spec.EgressIPs = []string{updateEgressIP}

				_, err = fakeOvn.fakeClient.EgressIPClient.K8sV1().EgressIPs().Update(context.TODO(), eIPToUpdate, metav1.UpdateOptions{})
				gomega.Expect(err).ToNot(gomega.HaveOccurred())

				getEgressIP := func() string {
					egressIPs, _ = getEgressIPStatus(egressIPName)
					if len(egressIPs) == 0 {
						return "try again"
					}
					return egressIPs[0]
				}

				gomega.Eventually(getEgressIP).Should(gomega.Equal(updateEgressIP))
				_, nodes = getEgressIPStatus(egressIPName)
				gomega.Expect(nodes[0]).To(gomega.Equal(node2.name))
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})
})
