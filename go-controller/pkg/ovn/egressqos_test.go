package ovn

import (
	"context"
	"fmt"
	"net"

	"github.com/onsi/ginkgo"
	ginkgotable "github.com/onsi/ginkgo/extensions/table"
	"github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressqosapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressqos/v1"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
)

func newEgressQoSObject(name, namespace string, egressRules []egressqosapi.EgressQoSRule) *egressqosapi.EgressQoS {
	return &egressqosapi.EgressQoS{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: egressqosapi.EgressQoSSpec{
			Egress: egressRules,
		},
	}
}

var _ = ginkgo.Describe("OVN EgressQoS Operations", func() {
	var (
		app            *cli.App
		fakeOVN        *FakeOVN
		controllerName = DefaultNetworkControllerName
	)

	namespaceT := *newNamespace("namespace1")
	// namespace address set hash name
	asv4, asv6 := addressset.GetHashNamesForAS(getNamespaceAddrSetDbIDs(namespaceT.Name, controllerName))
	qosAS := getEgressQosAddrSetDbIDs(namespaceT.Name, fmt.Sprintf("%d", EgressQoSFlowStartPriority), controllerName)
	// egress qos 0th rule address set hash names
	qosASv4, qosASv6 := addressset.GetHashNamesForAS(qosAS)

	const (
		node1Name string = "node1"
		node2Name string = "node2"
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		config.OVNKubernetesFeature.EnableEgressQoS = true

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fakeOVN = NewFakeOVN(true)
	})

	ginkgo.AfterEach(func() {
		fakeOVN.shutdown()
	})

	ginkgotable.DescribeTable("reconciles existing and non-existing egressqoses without PodSelectors",
		func(ipv4Mode, ipv6Mode bool, dst1, dst2, match1, match2 string) {
			app.Action = func(ctx *cli.Context) error {
				config.IPv4Mode = ipv4Mode
				config.IPv6Mode = ipv6Mode

				staleQoS := &nbdb.QoS{
					Direction:   nbdb.QoSDirectionToLport,
					Match:       "some-match",
					Priority:    EgressQoSFlowStartPriority,
					Action:      map[string]int{nbdb.QoSActionDSCP: 50},
					ExternalIDs: map[string]string{"EgressQoS": "staleNS"},
					UUID:        "staleQoS-UUID",
				}
				staleAddrSet, _ := addressset.GetDbObjsForAS(
					getEgressQosAddrSetDbIDs("staleNS", "1000", controllerName),
					[]net.IP{net.ParseIP("1.2.3.4")})

				node1Switch := &nbdb.LogicalSwitch{
					UUID:     "node1-UUID",
					Name:     node1Name,
					QOSRules: []string{staleQoS.UUID},
				}

				node2Switch := &nbdb.LogicalSwitch{
					UUID: "node2-UUID",
					Name: node2Name,
				}

				joinSwitch := &nbdb.LogicalSwitch{
					UUID:     "join-UUID",
					Name:     types.OVNJoinSwitch,
					QOSRules: []string{staleQoS.UUID},
				}

				dbSetup := libovsdbtest.TestSetup{
					NBData: []libovsdbtest.TestData{
						staleQoS,
						staleAddrSet,
						node1Switch,
						node2Switch,
						joinSwitch,
					},
				}

				fakeOVN.startWithDBSetup(dbSetup,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT,
						},
					},
				)

				// Create one EgressQoS
				eq := newEgressQoSObject("default", namespaceT.Name, []egressqosapi.EgressQoSRule{
					{
						DstCIDR: &dst1,
						DSCP:    50,
					},
					{
						DstCIDR: &dst2,
						DSCP:    60,
					},
				})
				eq.ResourceVersion = "1"
				_, err := fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Create(context.TODO(), eq, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOVN.InitAndRunEgressQoSController()

				qos1 := &nbdb.QoS{
					Direction:   nbdb.QoSDirectionToLport,
					Match:       match1,
					Priority:    EgressQoSFlowStartPriority,
					Action:      map[string]int{nbdb.QoSActionDSCP: 50},
					ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
					UUID:        "qos1-UUID",
				}
				qos2 := &nbdb.QoS{
					Direction:   nbdb.QoSDirectionToLport,
					Match:       match2,
					Priority:    EgressQoSFlowStartPriority - 1,
					Action:      map[string]int{nbdb.QoSActionDSCP: 60},
					ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
					UUID:        "qos2-UUID",
				}
				node1Switch.QOSRules = []string{qos1.UUID, qos2.UUID}
				node2Switch.QOSRules = []string{qos1.UUID, qos2.UUID}
				expectedDatabaseState := []libovsdbtest.TestData{
					qos1,
					qos2,
					node1Switch,
					node2Switch,
					joinSwitch,
				}

				gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

				// Update the EgressQoS
				eq.Spec.Egress = []egressqosapi.EgressQoSRule{
					{
						DstCIDR: &dst1,
						DSCP:    40,
					},
				}
				eq.ResourceVersion = "2"
				_, err = fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Update(context.TODO(), eq, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				qos3 := &nbdb.QoS{
					Direction:   nbdb.QoSDirectionToLport,
					Match:       match1,
					Priority:    EgressQoSFlowStartPriority,
					Action:      map[string]int{nbdb.QoSActionDSCP: 40},
					ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
					UUID:        "qos3-UUID",
				}
				node1Switch.QOSRules = []string{qos3.UUID}
				node2Switch.QOSRules = []string{qos3.UUID}
				expectedDatabaseState = []libovsdbtest.TestData{
					qos3,
					node1Switch,
					node2Switch,
					joinSwitch,
				}

				gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

				// Delete the EgressQoS
				err = fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Delete(context.TODO(), eq.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				node1Switch.QOSRules = []string{}
				node2Switch.QOSRules = []string{}
				expectedDatabaseState = []libovsdbtest.TestData{
					node1Switch,
					node2Switch,
					joinSwitch,
				}

				gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		},
		ginkgotable.Entry("ipv4", true, false, "1.2.3.4/32", "5.6.7.8/32",
			fmt.Sprintf("(ip4.dst == 1.2.3.4/32) && ip4.src == $%s", asv4),
			fmt.Sprintf("(ip4.dst == 5.6.7.8/32) && ip4.src == $%s", asv4)),
		ginkgotable.Entry("ipv6", false, true, "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128", "2001:0db8:85a3:0000:0000:8a2e:0370:7335/128",
			fmt.Sprintf("(ip6.dst == 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128) && ip6.src == $%s", asv6),
			fmt.Sprintf("(ip6.dst == 2001:0db8:85a3:0000:0000:8a2e:0370:7335/128) && ip6.src == $%s", asv6)),
		ginkgotable.Entry("dual", true, true, "1.2.3.4/32", "2001:0db8:85a3:0000:0000:8a2e:0370:7335/128",
			fmt.Sprintf("(ip4.dst == 1.2.3.4/32) && (ip4.src == $%s || ip6.src == $%s)", asv4, asv6),
			fmt.Sprintf("(ip6.dst == 2001:0db8:85a3:0000:0000:8a2e:0370:7335/128) && (ip4.src == $%s || ip6.src == $%s)", asv4, asv6)),
	)

	ginkgotable.DescribeTable("reconciles existing and non-existing egressqoses with PodSelectors",
		func(ipv4Mode, ipv6Mode bool, podIP, dst1, dst2, match1, match2 string) {
			app.Action = func(ctx *cli.Context) error {
				config.IPv4Mode = ipv4Mode
				config.IPv6Mode = ipv6Mode

				staleQoS := &nbdb.QoS{
					Direction:   nbdb.QoSDirectionToLport,
					Match:       "some-match",
					Priority:    EgressQoSFlowStartPriority,
					Action:      map[string]int{nbdb.QoSActionDSCP: 50},
					ExternalIDs: map[string]string{"EgressQoS": "staleNS"},
					UUID:        "staleQoS-UUID",
				}
				staleAddrSet, _ := addressset.GetDbObjsForAS(
					getEgressQosAddrSetDbIDs("staleNS", "1000", controllerName),
					[]net.IP{net.ParseIP("1.2.3.4")})

				podT := newPodWithLabels(
					namespaceT.Name,
					"myPod",
					node1Name,
					podIP,
					map[string]string{"app": "nice"},
				)

				node1Switch := &nbdb.LogicalSwitch{
					UUID:     node1Name,
					Name:     node1Name,
					QOSRules: []string{staleQoS.UUID},
				}

				node2Switch := &nbdb.LogicalSwitch{
					UUID:     node2Name,
					Name:     node2Name,
					QOSRules: []string{},
				}

				joinSwitch := &nbdb.LogicalSwitch{
					UUID:     "join-UUID",
					Name:     types.OVNJoinSwitch,
					QOSRules: []string{staleQoS.UUID},
				}

				dbSetup := libovsdbtest.TestSetup{
					NBData: []libovsdbtest.TestData{
						staleQoS,
						staleAddrSet,
						node1Switch,
						node2Switch,
						joinSwitch,
					},
				}

				fakeOVN.startWithDBSetup(dbSetup,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*podT,
						},
					},
				)

				i, n, _ := net.ParseCIDR(podIP + "/23")
				n.IP = i
				fakeOVN.controller.logicalPortCache.add(podT, "", types.DefaultNetworkName, "", nil, []*net.IPNet{n})

				// Create one EgressQoS
				eq := newEgressQoSObject("default", namespaceT.Name, []egressqosapi.EgressQoSRule{
					{
						DstCIDR: &dst1,
						DSCP:    50,
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "nice",
							},
						},
					},
					{
						DstCIDR: &dst2,
						DSCP:    60,
					},
				})
				eq.ResourceVersion = "1"
				_, err := fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Create(context.TODO(), eq, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOVN.InitAndRunEgressQoSController()

				qos1 := &nbdb.QoS{
					Direction:   nbdb.QoSDirectionToLport,
					Match:       match1,
					Priority:    EgressQoSFlowStartPriority,
					Action:      map[string]int{nbdb.QoSActionDSCP: 50},
					ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
					UUID:        "qos1-UUID",
				}
				qos2 := &nbdb.QoS{
					Direction:   nbdb.QoSDirectionToLport,
					Match:       match2,
					Priority:    EgressQoSFlowStartPriority - 1,
					Action:      map[string]int{nbdb.QoSActionDSCP: 60},
					ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
					UUID:        "qos2-UUID",
				}
				node1Switch.QOSRules = []string{qos1.UUID, qos2.UUID}
				node2Switch.QOSRules = []string{qos1.UUID, qos2.UUID}
				expectedDatabaseState := []libovsdbtest.TestData{
					qos1,
					qos2,
					node1Switch,
					node2Switch,
					joinSwitch,
				}

				gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

				// Update the EgressQoS
				eq.Spec.Egress = []egressqosapi.EgressQoSRule{
					{
						DstCIDR: &dst1,
						DSCP:    40,
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "nice",
							},
						},
					},
				}
				eq.ResourceVersion = "2"
				_, err = fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Update(context.TODO(), eq, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				qos3 := &nbdb.QoS{
					Direction:   nbdb.QoSDirectionToLport,
					Match:       match1,
					Priority:    EgressQoSFlowStartPriority,
					Action:      map[string]int{nbdb.QoSActionDSCP: 40},
					ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
					UUID:        "qos3-UUID",
				}
				node1Switch.QOSRules = []string{qos3.UUID}
				node2Switch.QOSRules = []string{qos3.UUID}
				expectedDatabaseState = []libovsdbtest.TestData{
					qos3,
					node1Switch,
					node2Switch,
					joinSwitch,
				}

				gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

				// Delete the EgressQoS
				err = fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Delete(context.TODO(), eq.Name, metav1.DeleteOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				node1Switch.QOSRules = []string{}
				node2Switch.QOSRules = []string{}
				expectedDatabaseState = []libovsdbtest.TestData{
					node1Switch,
					node2Switch,
					joinSwitch,
				}

				gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		},
		ginkgotable.Entry("ipv4", true, false, "10.128.1.3", "1.2.3.4/32", "5.6.7.8/32",
			fmt.Sprintf("(ip4.dst == 1.2.3.4/32) && ip4.src == $%s", qosASv4),
			fmt.Sprintf("(ip4.dst == 5.6.7.8/32) && ip4.src == $%s", asv4)),
		ginkgotable.Entry("ipv6", false, true, "fd00:10:244:2::3", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128", "2001:0db8:85a3:0000:0000:8a2e:0370:7335/128",
			fmt.Sprintf("(ip6.dst == 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128) && ip6.src == $%s", qosASv6),
			fmt.Sprintf("(ip6.dst == 2001:0db8:85a3:0000:0000:8a2e:0370:7335/128) && ip6.src == $%s", asv6)),
		ginkgotable.Entry("dual", true, true, "10.128.1.3", "1.2.3.4/32", "2001:0db8:85a3:0000:0000:8a2e:0370:7335/128",
			fmt.Sprintf("(ip4.dst == 1.2.3.4/32) && (ip4.src == $%s || ip6.src == $%s)", qosASv4, qosASv6),
			fmt.Sprintf("(ip6.dst == 2001:0db8:85a3:0000:0000:8a2e:0370:7335/128) && (ip4.src == $%s || ip6.src == $%s)", asv4, asv6)),
	)

	ginkgo.It("should respond to node events correctly", func() {
		app.Action = func(ctx *cli.Context) error {
			namespaceT := *newNamespace("namespace1")

			node1Switch := &nbdb.LogicalSwitch{
				UUID: "node1-UUID",
				Name: node1Name,
			}

			node2Switch := &nbdb.LogicalSwitch{
				UUID: "node2-UUID",
				Name: node2Name,
			}

			joinSwitch := &nbdb.LogicalSwitch{
				UUID: "join-UUID",
				Name: types.OVNJoinSwitch,
			}

			dbSetup := libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					node1Switch,
					node2Switch,
					joinSwitch,
				},
			}

			fakeOVN.startWithDBSetup(dbSetup,
				&v1.NamespaceList{
					Items: []v1.Namespace{
						namespaceT,
					},
				},
			)

			// Create one EgressQoS
			eq := newEgressQoSObject("default", namespaceT.Name, []egressqosapi.EgressQoSRule{
				{
					DstCIDR: pointer.String("1.2.3.4/32"),
					DSCP:    50,
				},
				{
					DstCIDR: pointer.String("5.6.7.8/32"),
					DSCP:    60,
				},
			})
			_, err := fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Create(context.TODO(), eq, metav1.CreateOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			fakeOVN.InitAndRunEgressQoSController()

			qos1 := &nbdb.QoS{
				Direction:   nbdb.QoSDirectionToLport,
				Match:       fmt.Sprintf("(ip4.dst == 1.2.3.4/32) && ip4.src == $%s", asv4),
				Priority:    EgressQoSFlowStartPriority,
				Action:      map[string]int{nbdb.QoSActionDSCP: 50},
				ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
				UUID:        "qos1-UUID",
			}
			qos2 := &nbdb.QoS{
				Direction:   nbdb.QoSDirectionToLport,
				Match:       fmt.Sprintf("(ip4.dst == 5.6.7.8/32) && ip4.src == $%s", asv4),
				Priority:    EgressQoSFlowStartPriority - 1,
				Action:      map[string]int{nbdb.QoSActionDSCP: 60},
				ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
				UUID:        "qos2-UUID",
			}
			node1Switch.QOSRules = append(node1Switch.QOSRules, qos1.UUID, qos2.UUID)
			node2Switch.QOSRules = append(node2Switch.QOSRules, qos1.UUID, qos2.UUID)
			expectedDatabaseState := []libovsdbtest.TestData{
				qos1,
				qos2,
				node1Switch,
				node2Switch,
				joinSwitch,
			}

			gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

			_, node3Switch, err := createNodeAndLS(fakeOVN, "node3", "global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			node3Switch.QOSRules = []string{qos1.UUID, qos2.UUID}
			expectedDatabaseState = []libovsdbtest.TestData{
				qos1,
				qos2,
				node1Switch,
				node2Switch,
				node3Switch,
				joinSwitch,
			}

			gomega.Eventually(fakeOVN.nbClient, 3).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

			// Delete the EgressQoS
			err = fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Delete(context.TODO(), eq.Name, metav1.DeleteOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			node1Switch.QOSRules = []string{}
			node2Switch.QOSRules = []string{}
			node3Switch.QOSRules = []string{}
			expectedDatabaseState = []libovsdbtest.TestData{
				node1Switch,
				node2Switch,
				node3Switch,
				joinSwitch,
			}

			gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

			return nil
		}

		err := app.Run([]string{app.Name})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("should respond to node zone update events correctly", func() {
		app.Action = func(ctx *cli.Context) error {
			namespaceT := *newNamespace("namespace1")

			node1Switch := &nbdb.LogicalSwitch{
				UUID: "node1-UUID",
				Name: node1Name,
			}

			node2Switch := &nbdb.LogicalSwitch{
				UUID: "node2-UUID",
				Name: node2Name,
			}

			joinSwitch := &nbdb.LogicalSwitch{
				UUID: "join-UUID",
				Name: types.OVNJoinSwitch,
			}

			dbSetup := libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					node1Switch,
					node2Switch,
					joinSwitch,
				},
			}

			fakeOVN.startWithDBSetup(dbSetup,
				&v1.NamespaceList{
					Items: []v1.Namespace{
						namespaceT,
					},
				},
			)

			// Create one EgressQoS
			eq := newEgressQoSObject("default", namespaceT.Name, []egressqosapi.EgressQoSRule{
				{
					DstCIDR: pointer.String("1.2.3.4/32"),
					DSCP:    50,
				},
				{
					DstCIDR: pointer.String("5.6.7.8/32"),
					DSCP:    60,
				},
			})
			_, err := fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Create(context.TODO(), eq, metav1.CreateOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			fakeOVN.InitAndRunEgressQoSController()

			qos1 := &nbdb.QoS{
				Direction:   nbdb.QoSDirectionToLport,
				Match:       fmt.Sprintf("(ip4.dst == 1.2.3.4/32) && ip4.src == $%s", asv4),
				Priority:    EgressQoSFlowStartPriority,
				Action:      map[string]int{nbdb.QoSActionDSCP: 50},
				ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
				UUID:        "qos1-UUID",
			}
			qos2 := &nbdb.QoS{
				Direction:   nbdb.QoSDirectionToLport,
				Match:       fmt.Sprintf("(ip4.dst == 5.6.7.8/32) && ip4.src == $%s", asv4),
				Priority:    EgressQoSFlowStartPriority - 1,
				Action:      map[string]int{nbdb.QoSActionDSCP: 60},
				ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
				UUID:        "qos2-UUID",
			}
			node1Switch.QOSRules = append(node1Switch.QOSRules, qos1.UUID, qos2.UUID)
			node2Switch.QOSRules = append(node2Switch.QOSRules, qos1.UUID, qos2.UUID)
			expectedDatabaseState := []libovsdbtest.TestData{
				qos1,
				qos2,
				node1Switch,
				node2Switch,
				joinSwitch,
			}

			gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

			kapiNode, node3Switch, err := createNodeAndLS(fakeOVN, "node3", "non-global")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			expectedDatabaseState = []libovsdbtest.TestData{
				qos1,
				qos2,
				node1Switch,
				node2Switch,
				node3Switch,
				joinSwitch,
			}
			// we won't add any qos objects because node is not local
			gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

			// update the node's zone to be local
			kapiNode.Annotations["k8s.ovn.org/zone-name"] = "global"
			kapiNode.ResourceVersion = "100"
			_, err = fakeOVN.fakeClient.KubeClient.CoreV1().Nodes().Update(context.TODO(), kapiNode, metav1.UpdateOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			// we will now add qos objects because node became local
			node3Switch.QOSRules = []string{qos1.UUID, qos2.UUID}
			gomega.Eventually(fakeOVN.nbClient, 3).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

			// Delete the EgressQoS
			err = fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Delete(context.TODO(), eq.Name, metav1.DeleteOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			node1Switch.QOSRules = []string{}
			node2Switch.QOSRules = []string{}
			node3Switch.QOSRules = []string{}
			expectedDatabaseState = []libovsdbtest.TestData{
				node1Switch,
				node2Switch,
				node3Switch,
				joinSwitch,
			}

			gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))

			return nil
		}

		err := app.Run([]string{app.Name})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("should respond to pod events correctly", func() {
		app.Action = func(ctx *cli.Context) error {
			namespaceT := *newNamespace("namespace1")

			node1Switch := &nbdb.LogicalSwitch{
				UUID: "node1-UUID",
				Name: node1Name,
			}

			podLocalT := newPodWithLabels(
				namespaceT.Name,
				"myPod",
				node1Name,
				"10.128.1.3",
				map[string]string{"rule1": "1"},
			)
			podRemoteT := newPodWithLabels(
				namespaceT.Name,
				"myPod2",
				node2Name,
				"10.128.2.3",
				map[string]string{"rule2": "2"},
			)

			dbSetup := libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					node1Switch,
				},
			}

			fakeOVN.startWithDBSetup(dbSetup,
				&v1.NamespaceList{
					Items: []v1.Namespace{
						namespaceT,
					},
				},
				&v1.PodList{
					Items: []v1.Pod{
						*podLocalT,
						*podRemoteT,
					},
				},
			)

			i, n, _ := net.ParseCIDR("10.128.1.3" + "/23")
			n.IP = i
			fakeOVN.controller.logicalPortCache.add(podLocalT, "", types.DefaultNetworkName, "", nil, []*net.IPNet{n})
			// add pod to local zone (isPodScheduledinLocalZone logic depends on cache entry)
			fakeOVN.controller.localZoneNodes.Store(podLocalT.Spec.NodeName, true)

			eq := newEgressQoSObject("default", namespaceT.Name, []egressqosapi.EgressQoSRule{
				{
					DstCIDR: pointer.String("1.2.3.4/32"),
					DSCP:    40,
				},
				{
					DstCIDR: pointer.String("5.6.7.8/32"),
					DSCP:    50,
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"rule1": "1",
						},
					},
				},
				{
					DstCIDR: pointer.String("5.6.7.8/32"),
					DSCP:    60,
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"rule2": "2",
						},
					},
				},
			})
			_, err := fakeOVN.fakeClient.EgressQoSClient.K8sV1().EgressQoSes(namespaceT.Name).Create(context.TODO(), eq, metav1.CreateOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			fakeOVN.InitAndRunEgressQoSController()

			qos1 := &nbdb.QoS{
				Direction:   nbdb.QoSDirectionToLport,
				Match:       fmt.Sprintf("(ip4.dst == 1.2.3.4/32) && ip4.src == $%s", asv4),
				Priority:    EgressQoSFlowStartPriority,
				Action:      map[string]int{nbdb.QoSActionDSCP: 40},
				ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
				UUID:        "qos1-UUID",
			}
			qosAS := getEgressQosAddrSetDbIDs(namespaceT.Name, fmt.Sprintf("%d", EgressQoSFlowStartPriority-1), controllerName)
			qosASv4, _ := addressset.GetHashNamesForAS(qosAS)
			qos2 := &nbdb.QoS{
				Direction:   nbdb.QoSDirectionToLport,
				Match:       fmt.Sprintf("(ip4.dst == 5.6.7.8/32) && ip4.src == $%s", qosASv4),
				Priority:    EgressQoSFlowStartPriority - 1,
				Action:      map[string]int{nbdb.QoSActionDSCP: 50},
				ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
				UUID:        "qos2-UUID",
			}
			qosAS = getEgressQosAddrSetDbIDs(namespaceT.Name, fmt.Sprintf("%d", EgressQoSFlowStartPriority-2), controllerName)
			qosASv4, _ = addressset.GetHashNamesForAS(qosAS)
			qos3 := &nbdb.QoS{
				Direction:   nbdb.QoSDirectionToLport,
				Match:       fmt.Sprintf("(ip4.dst == 5.6.7.8/32) && ip4.src == $%s", qosASv4),
				Priority:    EgressQoSFlowStartPriority - 2,
				Action:      map[string]int{nbdb.QoSActionDSCP: 60},
				ExternalIDs: map[string]string{"EgressQoS": namespaceT.Name},
				UUID:        "qos3-UUID",
			}
			node1Switch.QOSRules = append(node1Switch.QOSRules, qos1.UUID, qos2.UUID, qos3.UUID)
			expectedDatabaseState := []libovsdbtest.TestData{
				qos1,
				qos2,
				qos3,
				node1Switch,
			}

			gomega.Eventually(fakeOVN.nbClient).Should(libovsdbtest.HaveDataIgnoringUUIDs(expectedDatabaseState))
			qos2AS := getEgressQosAddrSetDbIDs(namespaceT.Name, "999", controllerName)
			qos3AS := getEgressQosAddrSetDbIDs(namespaceT.Name, "998", controllerName)

			ginkgo.By("Creating pod that matches the first rule only should add its ips to the first address set")
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos2AS, []string{"10.128.1.3"})
			fakeOVN.asf.ExpectAddressSetWithIPs(qos3AS, []string{}) // podRemoteT is not local to this zone, so we won't handle it

			ginkgo.By("Updating local pod to match both rules should add its ips to both address sets")
			podLocalT.Labels = map[string]string{"rule1": "1", "rule2": "2"}
			podLocalT.ResourceVersion = "100"
			_, err = fakeOVN.fakeClient.KubeClient.CoreV1().Pods(podLocalT.Namespace).Update(context.TODO(), podLocalT, metav1.UpdateOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos2AS, []string{"10.128.1.3"})
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos3AS, []string{"10.128.1.3"})

			ginkgo.By("Updating local pod to match the second rule only should remove its ips from the first's address set")
			podLocalT.Labels = map[string]string{"rule2": "2"}
			podLocalT.ResourceVersion = "200"
			_, err = fakeOVN.fakeClient.KubeClient.CoreV1().Pods(podLocalT.Namespace).Update(context.TODO(), podLocalT, metav1.UpdateOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos2AS, []string{})
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos3AS, []string{"10.128.1.3"})

			ginkgo.By("Updating remote pod to now become local; we should see it's IP in the address-set")
			podRemoteT.Spec.NodeName = node1Name // hacking the zone transfer of a pod
			podRemoteT.ResourceVersion = "200"
			_, err = fakeOVN.fakeClient.KubeClient.CoreV1().Pods(podRemoteT.Namespace).Update(context.TODO(), podRemoteT, metav1.UpdateOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos2AS, []string{})
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos3AS, []string{"10.128.1.3", "10.128.2.3"})

			ginkgo.By("Deleting the local pods should be remove its ips from the address sets")
			err = fakeOVN.fakeClient.KubeClient.CoreV1().Pods(podLocalT.Namespace).Delete(context.TODO(), podLocalT.Name, metav1.DeleteOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = fakeOVN.fakeClient.KubeClient.CoreV1().Pods(podRemoteT.Namespace).Delete(context.TODO(), podRemoteT.Name, metav1.DeleteOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos2AS, []string{})
			fakeOVN.asf.EventuallyExpectAddressSetWithIPs(qos3AS, []string{})

			return nil
		}

		err := app.Run([]string{app.Name})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

})

func (o *FakeOVN) InitAndRunEgressQoSController() {
	klog.Warningf("#### [%p] INIT EgressQoS", o)
	o.controller.initEgressQoSController(o.watcher.EgressQoSInformer(), o.watcher.PodCoreInformer(), o.watcher.NodeCoreInformer())
	o.controller.runEgressQoSController(o.egressQoSWg, 1, o.stopChan)
}

func createNodeAndLS(fakeOVN *FakeOVN, name, zone string) (*v1.Node, *nbdb.LogicalSwitch, error) {
	node := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
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
	node.Annotations = map[string]string{
		"k8s.ovn.org/zone-name": zone,
	}
	kapiNode, err := fakeOVN.fakeClient.KubeClient.CoreV1().Nodes().Create(context.TODO(), &node, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	logicalSwitch := &nbdb.LogicalSwitch{
		UUID: name + "-UUID",
		Name: name,
	}

	if err := libovsdbops.CreateOrUpdateLogicalSwitch(fakeOVN.nbClient, logicalSwitch); err != nil {
		return nil, nil, fmt.Errorf("failed to create logical switch %s, error: %v", name, err)

	}

	return kapiNode, logicalSwitch, nil
}
