package ovn

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type networkPolicy struct{}

func newNetworkPolicyMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       types.UID(namespace),
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			"name": name,
		},
	}
}

func newNetworkPolicy(name, namespace string, podSelector metav1.LabelSelector, ingress []knet.NetworkPolicyIngressRule, egress []knet.NetworkPolicyEgressRule) *knet.NetworkPolicy {
	return &knet.NetworkPolicy{
		ObjectMeta: newNetworkPolicyMeta(name, namespace),
		Spec: knet.NetworkPolicySpec{
			PodSelector: podSelector,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func (n networkPolicy) baseCmds(fexec *ovntest.FakeExec, networkPolicy knet.NetworkPolicy) {
	readableGroupName := fmt.Sprintf("%s_%s", networkPolicy.Namespace, networkPolicy.Name)
	hashedGroupName := hashedPortGroup(readableGroupName)
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=external_ids find address_set",
		fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=%s", hashedGroupName),
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 create port_group name=%s external-ids:name=%s", hashedGroupName, readableGroupName),
		Output: fakeUUID,
	})
}
func (n networkPolicy) addNamespaceSelectorCmdsForGress(fexec *ovntest.FakeExec, networkPolicy knet.NetworkPolicy, gress string, i int) {
	hashedOVNName := hashedAddressSet(fmt.Sprintf("%s.%s.%s.%d", networkPolicy.Namespace, networkPolicy.Name, gress, i))
	fexec.AddFakeCmdsNoOutputNoError([]string{
		fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=%s", hashedOVNName),
		fmt.Sprintf("ovn-nbctl --timeout=15 create address_set name=%s external-ids:name=%s", hashedOVNName, fmt.Sprintf("%s.%s.%s.%v", networkPolicy.Namespace, networkPolicy.Name, gress, i)),
	})
}

func (n networkPolicy) addLocalPodCmds(fexec *ovntest.FakeExec, pod pod) {
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=ingressDefaultDeny",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @ingressDefaultDeny\" action=drop external-ids:default-deny-policy-type=Ingress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @ingressDefaultDeny && arp\" action=allow external-ids:default-deny-policy-type=Ingress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=egressDefaultDeny",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @egressDefaultDeny\" action=drop external-ids:default-deny-policy-type=Egress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @egressDefaultDeny && arp\" action=allow external-ids:default-deny-policy-type=Egress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + fakeUUID + " ports " + fakeUUID + " -- add port_group " + fakeUUID + " ports " + fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + fakeUUID + " ports " + fakeUUID + " -- add port_group " + fakeUUID + " ports " + fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + fakeUUID + " ports " + fakeUUID + " -- add port_group " + fakeUUID + " ports " + fakeUUID,
	})
}

func (n networkPolicy) addPodSelectorCmds(fexec *ovntest.FakeExec, pod pod, networkPolicy knet.NetworkPolicy, hasLocalPods bool, findAgain bool) {
	n.addNamespaceSelectorCmds(fexec, networkPolicy, findAgain)
	for i := range networkPolicy.Spec.Ingress {
		hashedOVNName := hashedAddressSet(fmt.Sprintf("%s.%s.%s.%d", networkPolicy.Namespace, networkPolicy.Name, "ingress", i))
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf(`ovn-nbctl --timeout=15 add address_set %s addresses "%s"`, hashedOVNName, pod.podIP),
		})
	}
	for i := range networkPolicy.Spec.Egress {
		hashedOVNName := hashedAddressSet(fmt.Sprintf("%s.%s.%s.%d", networkPolicy.Namespace, networkPolicy.Name, "egress", i))
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf(`ovn-nbctl --timeout=15 add address_set %s addresses "%s"`, hashedOVNName, pod.podIP),
		})
	}
	if hasLocalPods {
		n.addLocalPodCmds(fexec, pod)
	}
}

func (n networkPolicy) addNamespaceSelectorCmds(fexec *ovntest.FakeExec, networkPolicy knet.NetworkPolicy, findAgain bool) {
	n.baseCmds(fexec, networkPolicy)
	for i := range networkPolicy.Spec.Ingress {
		n.addNamespaceSelectorCmdsForGress(fexec, networkPolicy, "ingress", i)
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=%v external-ids:policy_type=Ingress", networkPolicy.Namespace, networkPolicy.Name, i),
			"ovn-nbctl --timeout=15 --id=@acl create acl priority=1001 direction=to-lport match=\"ip4.src == {$a10148211500778908391} && outport == @a14195333570786048679\" action=allow-related external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress -- add port_group " + fakeUUID + " acls @acl",
		})
		if findAgain {
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a10148211500778908391} && outport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
			})
		}
	}
	for i := range networkPolicy.Spec.Egress {
		n.addNamespaceSelectorCmdsForGress(fexec, networkPolicy, "egress", i)
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=%v external-ids:policy_type=Egress", networkPolicy.Namespace, networkPolicy.Name, i),
			"ovn-nbctl --timeout=15 --id=@acl create acl priority=1001 direction=to-lport match=\"ip4.dst == {$a9824637386382239951} && inport == @a14195333570786048679\" action=allow external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress -- add port_group " + fakeUUID + " acls @acl",
		})
		if findAgain {
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a9824637386382239951} && inport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
			})
		}
	}
}

func (n networkPolicy) delCmds(fexec *ovntest.FakeExec, pod pod, networkPolicy knet.NetworkPolicy, withLocal bool) {
	for i := range networkPolicy.Spec.Ingress {
		hashedOVNName := hashedAddressSet(fmt.Sprintf("%s.%s.%s.%d", networkPolicy.Namespace, networkPolicy.Name, "ingress", i))
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --if-exists destroy address_set %s", hashedOVNName),
		})
	}
	for i := range networkPolicy.Spec.Egress {
		hashedOVNName := hashedAddressSet(fmt.Sprintf("%s.%s.%s.%d", networkPolicy.Namespace, networkPolicy.Name, "egress", i))
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --if-exists destroy address_set %s", hashedOVNName),
		})
	}
	if withLocal {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + fakeUUID + " ports " + fakeUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + fakeUUID + " ports " + fakeUUID,
		})
	}
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=a14195333570786048679",
		Output: fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		fmt.Sprintf("ovn-nbctl --timeout=15 --if-exists destroy port_group %s", fakeUUID),
	})
}

func (n networkPolicy) delPodCmds(fexec *ovntest.FakeExec, networkPolicy knet.NetworkPolicy, withLocal bool, podIP string) {
	for i := range networkPolicy.Spec.Ingress {
		localPeerPods := fmt.Sprintf("%s.%s.%s.%d", networkPolicy.Namespace, networkPolicy.Name, "ingress", i)
		hashedLocalAddressSet := hashedAddressSet(localPeerPods)
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf(`ovn-nbctl --timeout=15 remove address_set %s addresses "%s"`, hashedLocalAddressSet, podIP),
		})
	}
	for i := range networkPolicy.Spec.Egress {
		localPeerPods := fmt.Sprintf("%s.%s.%s.%d", networkPolicy.Namespace, networkPolicy.Name, "egress", i)
		hashedLocalAddressSet := hashedAddressSet(localPeerPods)
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf(`ovn-nbctl --timeout=15 remove address_set %s addresses "%s"`, hashedLocalAddressSet, podIP),
		})
	}
	if withLocal {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + fakeUUID + " ports " + fakeUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + fakeUUID + " ports " + fakeUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + fakeUUID + " ports " + fakeUUID,
		})
	}
}

type multicastPolicy struct{}

func (p multicastPolicy) enableCmds(fExec *ovntest.FakeExec, ns string) {
	pg_name, pg_hash := getMulticastPortGroup(ns)

	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=" + pg_hash,
	})
	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 create port_group name=" + pg_hash + " external-ids:name=" + pg_name,
		Output: "fake_uuid",
	})

	match := getACLMatch(pg_hash, "ip4.mcast", knet.PolicyTypeEgress)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " action=allow external-ids:default-deny-policy-type=Egress",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --id=@acl create acl priority=1012 direction=from-lport " +
			match + " action=allow external-ids:default-deny-policy-type=Egress " +
			"-- add port_group fake_uuid acls @acl",
	})

	match = getMulticastACLMatch(ns)
	match = getACLMatch(pg_hash, match, knet.PolicyTypeIngress)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " action=allow external-ids:default-deny-policy-type=Ingress",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --id=@acl create acl priority=1012 direction=to-lport " +
			match + " action=allow external-ids:default-deny-policy-type=Ingress " +
			"-- add port_group fake_uuid acls @acl",
	})
}

func (p multicastPolicy) disableCmds(fExec *ovntest.FakeExec, ns string) {
	_, pg_hash := getMulticastPortGroup(ns)

	match := getACLMatch(pg_hash, "ip4.mcast", knet.PolicyTypeEgress)
	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " " + "action=allow external-ids:default-deny-policy-type=Egress",
		Output: "fake_uuid",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 remove port_group " + pg_hash + " acls fake_uuid",
	})

	match = getMulticastACLMatch(ns)
	match = getACLMatch(pg_hash, match, knet.PolicyTypeIngress)
	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " " + "action=allow external-ids:default-deny-policy-type=Ingress",
		Output: "fake_uuid",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 remove port_group " + pg_hash + " acls fake_uuid",
	})

	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=" + pg_hash,
		Output: "fake_uuid",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists destroy port_group fake_uuid",
	})
}

func (p multicastPolicy) addPodCmds(fExec *ovntest.FakeExec, ns string) {
	_, pg_hash := getMulticastPortGroup(ns)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 " +
			"--if-exists remove port_group " + pg_hash + " ports " + fakeUUID + " " +
			"-- add port_group " + pg_hash + " ports " + fakeUUID,
	})
}

func (p multicastPolicy) delPodCmds(fExec *ovntest.FakeExec, ns string) {
	_, pg_hash := getMulticastPortGroup(ns)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 " +
			"--if-exists remove port_group " + pg_hash + " ports " + fakeUUID,
	})
}

var _ = Describe("OVN NetworkPolicy Operations", func() {
	var (
		app     *cli.App
		fakeOvn *FakeOVN
		fExec   *ovntest.FakeExec
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOvn = NewFakeOVN(fExec)
	})

	AfterEach(func() {
		fakeOvn.shutdown()
	})

	Context("on startup", func() {

		It("reconciles an existing ingress networkPolicy with a namespace selector", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}
				nTest := namespace{}

				namespace1 := *newNamespace("namespace1")
				namespace2 := *newNamespace("namespace2")
				networkPolicy := *newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nTest.baseCmds(fExec, namespace1, namespace2)
				nTest.addCmds(fExec, namespace1, namespace2)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, true)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							networkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles an existing gress networkPolicy with a pod selector in its own namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}
				nTest := namespace{}

				namespace1 := *newNamespace("namespace1")

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.4",
					"11:22:33:44:55:66",
					namespace1.Name,
				)
				networkPolicy := *newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addCmdsForNonExistingPod(fExec)
				nTest.baseCmds(fExec, namespace1)
				nTest.addCmdsWithPods(fExec, nPodTest, namespace1)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addPodSelectorCmds(fExec, nPodTest, networkPolicy, true, false)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)

				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles an existing gress networkPolicy with a pod and namespace selector in another namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}
				nTest := namespace{}

				namespace1 := *newNamespace("namespace1")
				namespace2 := *newNamespace("namespace2")

				nPodTest := newTPod(
					"node2",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.4",
					"11:22:33:44:55:66",
					namespace2.Name,
				)
				networkPolicy := *newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addCmdsForNonExistingPod(fExec)
				nTest.baseCmds(fExec, namespace1, namespace2)
				nTest.addCmds(fExec, namespace1)
				nTest.addCmdsWithPods(fExec, nPodTest, namespace2)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addPodSelectorCmds(fExec, nPodTest, networkPolicy, false, false)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)

				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("during execution", func() {

		It("reconciles a deleted namespace referenced by a networkpolicy with a local running pod", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}
				nTest := namespace{}

				namespace1 := *newNamespace("namespace1")
				namespace2 := *newNamespace("namespace2")

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.4",
					"11:22:33:44:55:66",
					namespace1.Name,
				)

				networkPolicy := *newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addCmdsForNonExistingPod(fExec)
				nTest.baseCmds(fExec, namespace1, namespace2)
				nTest.addCmds(fExec, namespace2)
				nTest.addCmdsWithPods(fExec, nPodTest, namespace1)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, true)
				npTest.addLocalPodCmds(fExec, nPodTest)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)

				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				nTest.delCmds(fExec, namespace2)

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a10148211500778908391, $a6953373268003663638} && outport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
					Output: fakeUUID,
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 set acl " + fakeUUID + " match=\"ip4.src == {$a10148211500778908391} && outport == @a14195333570786048679\"",
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a6953373268003663638, $a9824637386382239951} && inport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
				})

				err = fakeOvn.fakeClient.CoreV1().Namespaces().Delete(namespace2.Name, metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted namespace referenced by a networkpolicy", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}
				nTest := namespace{}

				namespace1 := *newNamespace("namespace1")
				namespace2 := *newNamespace("namespace2")
				networkPolicy := *newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nTest.baseCmds(fExec, namespace1, namespace2)
				nTest.addCmds(fExec, namespace1, namespace2)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, true)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							networkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				nTest.delCmds(fExec, namespace2)
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a10148211500778908391, $a6953373268003663638} && outport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
					Output: fakeUUID,
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 set acl " + fakeUUID + " match=\"ip4.src == {$a10148211500778908391} && outport == @a14195333570786048679\"",
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a6953373268003663638, $a9824637386382239951} && inport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
				})

				err = fakeOvn.fakeClient.CoreV1().Namespaces().Delete(namespace2.Name, metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted pod referenced by a networkpolicy in its own namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}
				nTest := namespace{}

				namespace1 := *newNamespace("namespace1")

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.4",
					"11:22:33:44:55:66",
					namespace1.Name,
				)
				networkPolicy := *newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addCmdsForNonExistingPod(fExec)
				nTest.baseCmds(fExec, namespace1)
				nTest.addCmdsWithPods(fExec, nPodTest, namespace1)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addPodSelectorCmds(fExec, nPodTest, networkPolicy, true, false)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)

				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				nPodTest.delCmds(fExec)
				nPodTest.delFromNamespaceCmds(fExec, nPodTest, true)
				npTest.delPodCmds(fExec, networkPolicy, true, nPodTest.podIP)

				err = fakeOvn.fakeClient.CoreV1().Pods(nPodTest.namespace).Delete(nPodTest.podName, metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted pod referenced by a networkpolicy in another namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}
				nTest := namespace{}

				namespace1 := *newNamespace("namespace1")
				namespace2 := *newNamespace("namespace2")

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.4",
					"11:22:33:44:55:66",
					namespace2.Name,
				)
				networkPolicy := *newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addCmdsForNonExistingPod(fExec)
				nTest.baseCmds(fExec, namespace1, namespace2)
				nTest.addCmds(fExec, namespace1)
				nTest.addCmdsWithPods(fExec, nPodTest, namespace2)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addPodSelectorCmds(fExec, nPodTest, networkPolicy, false, false)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)

				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				nPodTest.delCmds(fExec)
				nPodTest.delFromNamespaceCmds(fExec, nPodTest, true)
				npTest.delPodCmds(fExec, networkPolicy, false, nPodTest.podIP)

				err = fakeOvn.fakeClient.CoreV1().Pods(nPodTest.namespace).Delete(nPodTest.podName, metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted networkpolicy", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}
				nTest := namespace{}

				namespace1 := *newNamespace("namespace1")

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.4",
					"11:22:33:44:55:66",
					namespace1.Name,
				)
				networkPolicy := *newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addCmdsForNonExistingPod(fExec)
				nTest.baseCmds(fExec, namespace1)
				nTest.addCmdsWithPods(fExec, nPodTest, namespace1)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addPodSelectorCmds(fExec, nPodTest, networkPolicy, true, false)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)

				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				npTest.delCmds(fExec, nPodTest, networkPolicy, true)

				err = fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Delete(networkPolicy.Name, metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("tests enabling/disabling multicast in a namespace", func() {
			app.Action = func(ctx *cli.Context) error {
				nTest := namespace{}
				namespace1 := *newNamespace("namespace1")

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
				)

				nTest.baseCmds(fExec, namespace1)
				nTest.addCmds(fExec, namespace1)
				fakeOvn.controller.WatchNamespaces()
				ns, err := fakeOvn.fakeClient.CoreV1().Namespaces().Get(
					namespace1.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(ns).NotTo(BeNil())

				// Multicast is denied by default.
				_, ok := ns.Annotations[nsMulticastAnnotation]
				Expect(ok).To(BeFalse())

				// Enable multicast in the namespace.
				mcastPolicy := multicastPolicy{}
				mcastPolicy.enableCmds(fExec, namespace1.Name)
				ns.Annotations[nsMulticastAnnotation] = "true"
				_, err = fakeOvn.fakeClient.CoreV1().Namespaces().Update(ns)
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				// Disable multicast in the namespace.
				mcastPolicy.disableCmds(fExec, namespace1.Name)
				ns.Annotations[nsMulticastAnnotation] = "false"
				_, err = fakeOvn.fakeClient.CoreV1().Namespaces().Update(ns)
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("tests enabling multicast in a namespace with a pod", func() {
			app.Action = func(ctx *cli.Context) error {
				nTest := namespace{}
				namespace1 := *newNamespace("namespace1")

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.4",
					"11:22:33:44:55:66",
					namespace1.Name,
				)

				nPodTest.baseCmds(fExec)
				nPodTest.addCmdsForNonExistingPod(fExec)
				nTest.baseCmds(fExec, namespace1)
				nTest.addCmdsWithPods(fExec, nPodTest, namespace1)
				nPodTest.addPodDenyMcast(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)

				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				ns, err := fakeOvn.fakeClient.CoreV1().Namespaces().Get(
					namespace1.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(ns).NotTo(BeNil())

				// Enable multicast in the namespace
				mcastPolicy := multicastPolicy{}
				mcastPolicy.enableCmds(fExec, namespace1.Name)
				// The pod should be added to the multicast allow port group.
				mcastPolicy.addPodCmds(fExec, namespace1.Name)
				ns.Annotations[nsMulticastAnnotation] = "true"
				_, err = fakeOvn.fakeClient.CoreV1().Namespaces().Update(ns)
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("tests adding a pod to a multicast enabled namespace", func() {
			app.Action = func(ctx *cli.Context) error {
				nTest := namespace{}
				namespace1 := *newNamespace("namespace1")

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.4",
					"11:22:33:44:55:66",
					namespace1.Name,
				)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
				)

				nPodTest.baseCmds(fExec)
				nTest.baseCmds(fExec, namespace1)
				nTest.addCmds(fExec, namespace1)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				ns, err := fakeOvn.fakeClient.CoreV1().Namespaces().Get(
					namespace1.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(ns).NotTo(BeNil())

				// Enable multicast in the namespace.
				mcastPolicy := multicastPolicy{}
				mcastPolicy.enableCmds(fExec, namespace1.Name)
				ns.Annotations[nsMulticastAnnotation] = "true"
				_, err = fakeOvn.fakeClient.CoreV1().Namespaces().Update(ns)
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				nPodTest.populateLogicalSwitchCache(fakeOvn)
				nPodTest.addCmdsForNonExistingPod(fExec)
				nPodTest.addPodDenyMcast(fExec)
				nTest.addPodCmds(fExec, nPodTest, namespace1, false)

				// The pod should be added to the multicast allow group.
				mcastPolicy.addPodCmds(fExec, namespace1.Name)

				_, err = fakeOvn.fakeClient.CoreV1().Pods(nPodTest.namespace).Create(newPod(
					nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				// Delete the pod from the namespace.
				mcastPolicy.delPodCmds(fExec, namespace1.Name)
				// The pod should be removed from the multicasts default deny
				// group and from the multicast allow group.
				nPodTest.delPodDenyMcast(fExec)
				nTest.delPodCmds(fExec, nPodTest, namespace1, false)
				nPodTest.delCmds(fExec)

				err = fakeOvn.fakeClient.CoreV1().Pods(nPodTest.namespace).Delete(
					nPodTest.podName, metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

var _ = Describe("OVN NetworkPolicy Low-Level Operations", func() {
	It("computes match strings from address sets correctly", func() {
		gp := newGressPolicy(knet.PolicyTypeIngress, 0)

		one := hashedAddressSet(fmt.Sprintf("testing.policy.ingress.1"))
		two := hashedAddressSet(fmt.Sprintf("testing.policy.ingress.2"))
		three := hashedAddressSet(fmt.Sprintf("testing.policy.ingress.3"))
		four := hashedAddressSet(fmt.Sprintf("testing.policy.ingress.4"))
		five := hashedAddressSet(fmt.Sprintf("testing.policy.ingress.5"))
		six := hashedAddressSet(fmt.Sprintf("testing.policy.ingress.6"))

		oldMatch, newMatch, changed := gp.addAddressSet(one)
		Expect(oldMatch).To(Equal("ip4"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025386827633950433}"))
		Expect(changed).To(BeTrue())

		oldMatch, newMatch, changed = gp.addAddressSet(two)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025386827633950433}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025386827633950433}"))
		Expect(changed).To(BeTrue())

		// address sets should be alphabetized
		oldMatch, newMatch, changed = gp.addAddressSet(three)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025386827633950433}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025384628610694011, $a14025386827633950433}"))
		Expect(changed).To(BeTrue())

		// re-adding an existing set is a no-op
		oldMatch, newMatch, changed = gp.addAddressSet(one)
		Expect(oldMatch).To(Equal(""))
		Expect(newMatch).To(Equal(""))
		Expect(changed).To(BeFalse())

		oldMatch, newMatch, changed = gp.addAddressSet(four)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025384628610694011, $a14025386827633950433}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025384628610694011, $a14025386827633950433, $a14025390126168835066}"))
		Expect(changed).To(BeTrue())

		// now delete a set
		oldMatch, newMatch, changed = gp.delAddressSet(one)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025384628610694011, $a14025386827633950433, $a14025390126168835066}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025384628610694011, $a14025390126168835066}"))
		Expect(changed).To(BeTrue())

		// deleting again is a no-op
		oldMatch, newMatch, changed = gp.delAddressSet(one)
		Expect(oldMatch).To(Equal(""))
		Expect(newMatch).To(Equal(""))
		Expect(changed).To(BeFalse())

		// add and delete some more...
		oldMatch, newMatch, changed = gp.addAddressSet(five)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025384628610694011, $a14025390126168835066}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025384628610694011, $a14025390126168835066, $a14025391225680463277}"))
		Expect(changed).To(BeTrue())

		oldMatch, newMatch, changed = gp.delAddressSet(three)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025384628610694011, $a14025390126168835066, $a14025391225680463277}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025390126168835066, $a14025391225680463277}"))
		Expect(changed).To(BeTrue())

		oldMatch, newMatch, changed = gp.delAddressSet(one)
		Expect(oldMatch).To(Equal(""))
		Expect(newMatch).To(Equal(""))
		Expect(changed).To(BeFalse())

		oldMatch, newMatch, changed = gp.addAddressSet(six)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025390126168835066, $a14025391225680463277}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025387927145578644, $a14025390126168835066, $a14025391225680463277}"))
		Expect(changed).To(BeTrue())

		oldMatch, newMatch, changed = gp.delAddressSet(two)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025383529099065800, $a14025387927145578644, $a14025390126168835066, $a14025391225680463277}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025387927145578644, $a14025390126168835066, $a14025391225680463277}"))
		Expect(changed).To(BeTrue())

		oldMatch, newMatch, changed = gp.delAddressSet(five)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025387927145578644, $a14025390126168835066, $a14025391225680463277}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025387927145578644, $a14025390126168835066}"))
		Expect(changed).To(BeTrue())

		oldMatch, newMatch, changed = gp.delAddressSet(six)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025387927145578644, $a14025390126168835066}"))
		Expect(newMatch).To(Equal("ip4.src == {$a14025390126168835066}"))
		Expect(changed).To(BeTrue())

		oldMatch, newMatch, changed = gp.delAddressSet(four)
		Expect(oldMatch).To(Equal("ip4.src == {$a14025390126168835066}"))
		Expect(newMatch).To(Equal("ip4"))
		Expect(changed).To(BeTrue())

		oldMatch, newMatch, changed = gp.delAddressSet(four)
		Expect(oldMatch).To(Equal(""))
		Expect(newMatch).To(Equal(""))
		Expect(changed).To(BeFalse())
	})
})
