package acl

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ingressDefaultDenySuffix = "ingressDefaultDeny"
	egressDefaultDenySuffix  = "egressDefaultDeny"
	arpAllowPolicySuffix     = "ARPallowPolicy"
	arpAllowPolicyMatch      = "(arp || nd)"
)

type aclSync struct {
	before *nbdb.ACL
	after  *libovsdbops.DbObjectIDs
}

func testSyncerWithData(data []aclSync, controllerName string, initialDbState, finalDbState []libovsdbtest.TestData,
	existingNodes []v1.Node) {
	// create initial db setup
	dbSetup := libovsdbtest.TestSetup{NBData: initialDbState}
	for _, asSync := range data {
		if asSync.after != nil {
			asSync.before.UUID = asSync.after.String() + "-UUID"
		} else {
			asSync.before.UUID = asSync.before.Match
		}
		dbSetup.NBData = append(dbSetup.NBData, asSync.before)
	}
	libovsdbOvnNBClient, _, libovsdbCleanup, err := libovsdbtest.NewNBSBTestHarness(dbSetup)
	defer libovsdbCleanup.Cleanup()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	// create expected data using addressSetFactory
	var expectedDbState []libovsdbtest.TestData
	if finalDbState != nil {
		expectedDbState = finalDbState
	} else {
		expectedDbState = initialDbState
	}
	for _, aclSync := range data {
		acl := aclSync.before
		if aclSync.after != nil {
			acl.ExternalIDs = aclSync.after.GetExternalIDs()
		}
		acl.Tier = types.DefaultACLTier
		expectedDbState = append(expectedDbState, acl)
	}
	// run sync
	syncer := NewACLSyncer(libovsdbOvnNBClient, controllerName)
	err = syncer.SyncACLs(&v1.NodeList{Items: existingNodes})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	// check results
	gomega.Eventually(libovsdbOvnNBClient).Should(libovsdbtest.HaveData(expectedDbState))
}

func joinACLName(substrings ...string) string {
	return strings.Join(substrings, "_")
}

func buildPortGroup(hashName, name string, ports []*nbdb.LogicalSwitchPort, acls []*nbdb.ACL) *nbdb.PortGroup {
	externalIds := map[string]string{"name": name}
	return libovsdbops.BuildPortGroup(hashName, ports, acls, externalIds)
}

var _ = ginkgo.Describe("OVN ACL Syncer", func() {
	const (
		controllerName = "fake-controller"
		namespace1     = "namespace1"
	)
	var syncerToBuildData = aclSyncer{
		controllerName: controllerName,
	}

	ginkgo.It("doesn't add 2 acls with the same PrimaryID", func() {
		testData := []aclSync{
			{
				before: libovsdbops.BuildACL(
					joinACLName(types.ClusterPortGroupNameBase, "DefaultDenyMulticastEgress"),
					nbdb.ACLDirectionFromLport,
					types.DefaultMcastDenyPriority,
					"(ip4.mcast || mldv1 || mldv2 || (ip6.dst[120..127] == 0xff && ip6.dst[116] == 1))",
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						defaultDenyPolicyTypeACLExtIdKey: "Egress",
					},
					nil,
					// syncer code is run before the net-pol handlers startup; thus realistically its tier0 at this point
					// when we get add events for net-pol's later, this will get updated to tier2 if needed
					// this is why we use the placeholder tier ACL for the tests in this file and in address_set_sync_test
					// instead of the default tier ACL
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultMcastACLDbIDs(mcastDefaultDenyID, "Egress"),
			},
			{
				before: libovsdbops.BuildACL(
					joinACLName(types.ClusterPortGroupNameBase, "DefaultDenyMulticastEgress"),
					nbdb.ACLDirectionFromLport,
					types.DefaultMcastDenyPriority,
					"(ip4.mcast || mldv1 || mldv2 || (ip6.dst[120..127] == 0xff && ip6.dst[116] == 1))",
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						defaultDenyPolicyTypeACLExtIdKey: "Egress",
					},
					nil,
					types.PlaceHolderACLTier,
				),
			},
		}
		testSyncerWithData(testData, controllerName, []libovsdbtest.TestData{}, nil, nil)
	})
	ginkgo.It("updates multicast acls", func() {
		testData := []aclSync{
			// defaultDenyEgressACL
			{
				before: libovsdbops.BuildACL(
					joinACLName(types.ClusterPortGroupNameBase, "DefaultDenyMulticastEgress"),
					nbdb.ACLDirectionFromLport,
					types.DefaultMcastDenyPriority,
					"(ip4.mcast || mldv1 || mldv2 || (ip6.dst[120..127] == 0xff && ip6.dst[116] == 1))",
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						defaultDenyPolicyTypeACLExtIdKey: "Egress",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultMcastACLDbIDs(mcastDefaultDenyID, "Egress"),
			},
			// defaultDenyIngressACL
			{
				before: libovsdbops.BuildACL(
					joinACLName(types.ClusterPortGroupNameBase, "DefaultDenyMulticastIngress"),
					nbdb.ACLDirectionToLport,
					types.DefaultMcastDenyPriority,
					"(ip4.mcast || mldv1 || mldv2 || (ip6.dst[120..127] == 0xff && ip6.dst[116] == 1))",
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						defaultDenyPolicyTypeACLExtIdKey: "Ingress",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultMcastACLDbIDs(mcastDefaultDenyID, "Ingress"),
			},
			// defaultAllowEgressACL
			{
				before: libovsdbops.BuildACL(
					joinACLName(types.ClusterRtrPortGroupNameBase, "DefaultAllowMulticastEgress"),
					nbdb.ACLDirectionFromLport,
					types.DefaultMcastAllowPriority,
					"inport == @clusterRtrPortGroup && (ip4.mcast || mldv1 || mldv2 || (ip6.dst[120..127] == 0xff && ip6.dst[116] == 1))",
					nbdb.ACLActionAllow,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						defaultDenyPolicyTypeACLExtIdKey: "Egress",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultMcastACLDbIDs(mcastAllowInterNodeID, "Egress"),
			},
			// defaultAllowIngressACL
			{
				before: libovsdbops.BuildACL(
					joinACLName(types.ClusterRtrPortGroupNameBase, "DefaultAllowMulticastIngress"),
					nbdb.ACLDirectionToLport,
					types.DefaultMcastAllowPriority,
					"outport == @clusterRtrPortGroup && (ip4.mcast || mldv1 || mldv2 || (ip6.dst[120..127] == 0xff && ip6.dst[116] == 1))",
					nbdb.ACLActionAllow,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						defaultDenyPolicyTypeACLExtIdKey: "Ingress",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultMcastACLDbIDs(mcastAllowInterNodeID, "Ingress"),
			},
			// nsAllowEgressACL
			{
				before: libovsdbops.BuildACL(
					joinACLName(namespace1, "MulticastAllowEgress"),
					nbdb.ACLDirectionFromLport,
					types.DefaultMcastAllowPriority,
					"inport == @a16982411286042166782 && ip4.mcast",
					nbdb.ACLActionAllow,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						defaultDenyPolicyTypeACLExtIdKey: "Egress",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getNamespaceMcastACLDbIDs(namespace1, "Egress"),
			},
			// nsAllowIngressACL
			{
				before: libovsdbops.BuildACL(
					joinACLName(namespace1, "MulticastAllowIngress"),
					nbdb.ACLDirectionToLport,
					types.DefaultMcastAllowPriority,
					"outport == @a16982411286042166782 && (igmp || (ip4.src == $a4322231855293774466 && ip4.mcast))",
					nbdb.ACLActionAllow,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						defaultDenyPolicyTypeACLExtIdKey: "Ingress",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getNamespaceMcastACLDbIDs(namespace1, "Ingress"),
			},
		}
		testSyncerWithData(testData, controllerName, []libovsdbtest.TestData{}, nil, nil)
	})
	ginkgo.It("updates allow from node acls", func() {
		nodeName := "node1"
		ipv4MgmtIP := "10.244.0.2"
		ipv6MgmtIP := "fd02:0:0:2::2"

		testData := []aclSync{
			// ipv4 acl
			{
				before: libovsdbops.BuildACL(
					"",
					nbdb.ACLDirectionToLport,
					types.DefaultAllowPriority,
					"ip4.src=="+ipv4MgmtIP,
					nbdb.ACLActionAllowRelated,
					types.OvnACLLoggingMeter,
					"",
					false,
					nil,
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getAllowFromNodeACLDbIDs(nodeName, ipv4MgmtIP),
			},
			// ipv6 acl
			{
				before: libovsdbops.BuildACL(
					"",
					nbdb.ACLDirectionToLport,
					types.DefaultAllowPriority,
					"ip6.src=="+ipv6MgmtIP,
					nbdb.ACLActionAllowRelated,
					types.OvnACLLoggingMeter,
					"",
					false,
					nil,
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getAllowFromNodeACLDbIDs(nodeName, ipv6MgmtIP),
			},
		}
		hostSubnets := map[string][]string{types.DefaultNetworkName: {"10.244.0.0/24", "fd02:0:0:2::2895/64"}}
		bytes, err := json.Marshal(hostSubnets)
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		existingNodes := []v1.Node{{
			ObjectMeta: metav1.ObjectMeta{
				Name:        nodeName,
				Annotations: map[string]string{"k8s.ovn.org/node-subnets": string(bytes)},
			}}}
		testSyncerWithData(testData, controllerName, []libovsdbtest.TestData{}, nil, existingNodes)
	})
	ginkgo.It("updates gress policy acls", func() {
		policyNamespace := "policyNamespace"
		policyName := "policyName"
		testData := []aclSync{
			{
				before: libovsdbops.BuildACL(
					policyNamespace+"_"+policyName+"_0",
					nbdb.ACLDirectionToLport,
					types.DefaultAllowPriority,
					"ip4.dst == 10.244.1.5/32 && inport == @a2653181086423119552",
					nbdb.ACLActionAllowRelated,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						l4MatchACLExtIdKey:     "tcp && 6380<=tcp.dst<=7000",
						ipBlockCIDRACLExtIdKey: "true",
						namespaceACLExtIdKey:   policyNamespace,
						policyACLExtIdKey:      policyName,
						policyTypeACLExtIdKey:  string(knet.PolicyTypeEgress),
						fmt.Sprintf(policyTypeNumACLExtIdKey, knet.PolicyTypeEgress): "0",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getNetpolGressACLDbIDs(policyNamespace, policyName, string(knet.PolicyTypeEgress),
					0, 0, 0),
			},
			{
				before: libovsdbops.BuildACL(
					policyNamespace+"_"+policyName+"_0",
					nbdb.ACLDirectionToLport,
					types.DefaultAllowPriority,
					"ip4.dst == 10.244.1.5/32 && inport == @a2653181086423119552",
					nbdb.ACLActionAllowRelated,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						l4MatchACLExtIdKey:     "tcp && 6380<=tcp.dst<=7000",
						ipBlockCIDRACLExtIdKey: "2",
						namespaceACLExtIdKey:   policyNamespace,
						policyACLExtIdKey:      policyName,
						policyTypeACLExtIdKey:  string(knet.PolicyTypeEgress),
						fmt.Sprintf(policyTypeNumACLExtIdKey, knet.PolicyTypeEgress): "0",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getNetpolGressACLDbIDs(policyNamespace, policyName, string(knet.PolicyTypeEgress),
					0, 0, 1),
			},
			{
				before: libovsdbops.BuildACL(
					policyNamespace+"_"+policyName+"_0",
					nbdb.ACLDirectionToLport,
					types.DefaultAllowPriority,
					"ip4.dst == 10.244.1.5/32 && inport == @a2653181086423119552",
					nbdb.ACLActionAllowRelated,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						l4MatchACLExtIdKey:     "tcp && 1<=tcp.dst<=3",
						ipBlockCIDRACLExtIdKey: "true",
						namespaceACLExtIdKey:   policyNamespace,
						policyACLExtIdKey:      policyName,
						policyTypeACLExtIdKey:  string(knet.PolicyTypeEgress),
						fmt.Sprintf(policyTypeNumACLExtIdKey, knet.PolicyTypeEgress): "0",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getNetpolGressACLDbIDs(policyNamespace, policyName, string(knet.PolicyTypeEgress),
					0, 1, 0),
			},
			{
				before: libovsdbops.BuildACL(
					policyNamespace+"_"+policyName+"_0",
					nbdb.ACLDirectionToLport,
					types.DefaultAllowPriority,
					"ip4.dst == 10.244.1.5/32 && inport == @a2653181086423119552",
					nbdb.ACLActionAllowRelated,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						l4MatchACLExtIdKey:     "tcp && 1<=tcp.dst<=3",
						ipBlockCIDRACLExtIdKey: "2",
						namespaceACLExtIdKey:   policyNamespace,
						policyACLExtIdKey:      policyName,
						policyTypeACLExtIdKey:  string(knet.PolicyTypeEgress),
						fmt.Sprintf(policyTypeNumACLExtIdKey, knet.PolicyTypeEgress): "0",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getNetpolGressACLDbIDs(policyNamespace, policyName, string(knet.PolicyTypeEgress),
					0, 1, 1),
			},
			{
				before: libovsdbops.BuildACL(
					policyNamespace+"_"+policyName+"_0",
					nbdb.ACLDirectionFromLport,
					types.DefaultAllowPriority,
					"(ip4.src == {$a3733136965153973077} || (ip4.src == 169.254.169.5 && ip4.dst == {$a3733136965153973077})) && outport == @a2653181086423119552",
					nbdb.ACLActionAllowRelated,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{
						l4MatchACLExtIdKey:     noneMatch,
						ipBlockCIDRACLExtIdKey: "false",
						namespaceACLExtIdKey:   policyNamespace,
						policyACLExtIdKey:      policyName,
						policyTypeACLExtIdKey:  string(knet.PolicyTypeIngress),
						fmt.Sprintf(policyTypeNumACLExtIdKey, knet.PolicyTypeIngress): "0",
					},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getNetpolGressACLDbIDs(policyNamespace, policyName, string(knet.PolicyTypeIngress),
					0, emptyIdx, emptyIdx),
			},
		}
		testSyncerWithData(testData, controllerName, []libovsdbtest.TestData{}, nil, nil)
	})
	ginkgo.It("updates default deny policy acls", func() {
		policyNamespace := "policyNamespace"

		defaultDenyPortGroupName := func(namespace, gressSuffix string) string {
			return joinACLName(util.HashForOVN(namespace), gressSuffix)
		}
		getStaleARPAllowACLName := func(ns string) string {
			return joinACLName(ns, arpAllowPolicySuffix)
		}
		egressPGName := defaultDenyPortGroupName(policyNamespace, egressDefaultDenySuffix)
		ingressPGName := defaultDenyPortGroupName(policyNamespace, ingressDefaultDenySuffix)
		staleARPEgressACL := libovsdbops.BuildACL(
			getStaleARPAllowACLName(policyNamespace),
			nbdb.ACLDirectionFromLport,
			types.DefaultAllowPriority,
			"inport == @"+egressPGName+" && "+staleArpAllowPolicyMatch,
			nbdb.ACLActionAllow,
			types.OvnACLLoggingMeter,
			"",
			false,
			map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeEgress)},
			nil,
			types.DefaultACLTier,
		)
		staleARPEgressACL.UUID = "staleARPEgressACL-UUID"
		egressDenyPG := buildPortGroup(
			egressPGName,
			egressPGName,
			nil,
			[]*nbdb.ACL{staleARPEgressACL},
		)
		egressDenyPG.UUID = egressDenyPG.Name + "-UUID"

		staleARPIngressACL := libovsdbops.BuildACL(
			getStaleARPAllowACLName(policyNamespace),
			nbdb.ACLDirectionToLport,
			types.DefaultAllowPriority,
			"outport == @"+ingressPGName+" && "+staleArpAllowPolicyMatch,
			nbdb.ACLActionAllow,
			types.OvnACLLoggingMeter,
			"",
			false,
			map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeIngress)},
			nil,
			types.DefaultACLTier,
		)
		staleARPIngressACL.UUID = "staleARPIngressACL-UUID"
		ingressDenyPG := buildPortGroup(
			ingressPGName,
			ingressPGName,
			nil,
			[]*nbdb.ACL{staleARPIngressACL},
		)
		ingressDenyPG.UUID = ingressDenyPG.Name + "-UUID"
		initialDb := []libovsdbtest.TestData{staleARPEgressACL, egressDenyPG, staleARPIngressACL, ingressDenyPG}
		finalEgressDenyPG := buildPortGroup(
			egressPGName,
			egressPGName,
			nil,
			nil,
		)
		finalEgressDenyPG.UUID = finalEgressDenyPG.Name + "-UUID"
		finalIngressDenyPG := buildPortGroup(
			ingressPGName,
			ingressPGName,
			nil,
			nil,
		)
		finalIngressDenyPG.UUID = finalIngressDenyPG.Name + "-UUID"
		// acls will stay since they are no garbage-collected by test server
		finalDb := []libovsdbtest.TestData{staleARPEgressACL, finalEgressDenyPG, staleARPIngressACL, finalIngressDenyPG}
		testData := []aclSync{
			// egress deny
			{
				before: libovsdbops.BuildACL(
					policyNamespace+"_"+egressDefaultDenySuffix,
					nbdb.ACLDirectionFromLport,
					types.DefaultDenyPriority,
					"inport == @"+egressPGName,
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeEgress)},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultDenyPolicyACLIDs(policyNamespace, string(knet.PolicyTypeEgress), defaultDenyACL),
			},
			// egress allow ARP
			{
				before: libovsdbops.BuildACL(
					getStaleARPAllowACLName(policyNamespace),
					nbdb.ACLDirectionFromLport,
					types.DefaultAllowPriority,
					"inport == @"+egressPGName+" && "+arpAllowPolicyMatch,
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeEgress)},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultDenyPolicyACLIDs(policyNamespace, string(knet.PolicyTypeEgress), arpAllowACL),
			},
			// egress deny
			{
				before: libovsdbops.BuildACL(
					policyNamespace+"_"+ingressDefaultDenySuffix,
					nbdb.ACLDirectionToLport,
					types.DefaultDenyPriority,
					"outport == @"+ingressPGName,
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeIngress)},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultDenyPolicyACLIDs(policyNamespace, string(knet.PolicyTypeIngress), defaultDenyACL),
			},
			// egress allow ARP
			{
				before: libovsdbops.BuildACL(
					getStaleARPAllowACLName(policyNamespace),
					nbdb.ACLDirectionToLport,
					types.DefaultAllowPriority,
					"outport == @"+ingressPGName+" && "+arpAllowPolicyMatch,
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeIngress)},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultDenyPolicyACLIDs(policyNamespace, string(knet.PolicyTypeIngress), arpAllowACL),
			},
		}
		testSyncerWithData(testData, controllerName, initialDb, finalDb, nil)
	})
	ginkgo.It("updates default deny policy acl with long names", func() {
		policyNamespace := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk" // longest allowed namespace name
		defaultDenyPortGroupName := func(namespace, gressSuffix string) string {
			return joinACLName(util.HashForOVN(namespace), gressSuffix)
		}
		getStaleARPAllowACLName := func(ns string) string {
			return joinACLName(ns, arpAllowPolicySuffix)
		}
		egressPGName := defaultDenyPortGroupName(policyNamespace, egressDefaultDenySuffix)
		ingressPGName := defaultDenyPortGroupName(policyNamespace, ingressDefaultDenySuffix)
		staleARPEgressACL := libovsdbops.BuildACL(
			getStaleARPAllowACLName(policyNamespace),
			nbdb.ACLDirectionFromLport,
			types.DefaultAllowPriority,
			"inport == @"+egressPGName+" && "+staleArpAllowPolicyMatch,
			nbdb.ACLActionAllow,
			types.OvnACLLoggingMeter,
			"",
			false,
			map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeEgress)},
			nil,
			types.DefaultACLTier,
		)
		staleARPEgressACL.UUID = "staleARPEgressACL-UUID"
		egressDenyPG := buildPortGroup(
			egressPGName,
			egressPGName,
			nil,
			[]*nbdb.ACL{staleARPEgressACL},
		)
		egressDenyPG.UUID = egressDenyPG.Name + "-UUID"

		staleARPIngressACL := libovsdbops.BuildACL(
			getStaleARPAllowACLName(policyNamespace),
			nbdb.ACLDirectionToLport,
			types.DefaultAllowPriority,
			"outport == @"+ingressPGName+" && "+staleArpAllowPolicyMatch,
			nbdb.ACLActionAllow,
			types.OvnACLLoggingMeter,
			"",
			false,
			map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeIngress)},
			nil,
			types.DefaultACLTier,
		)
		staleARPIngressACL.UUID = "staleARPIngressACL-UUID"
		ingressDenyPG := buildPortGroup(
			ingressPGName,
			ingressPGName,
			nil,
			[]*nbdb.ACL{staleARPIngressACL},
		)
		ingressDenyPG.UUID = ingressDenyPG.Name + "-UUID"
		initialDb := []libovsdbtest.TestData{staleARPEgressACL, egressDenyPG, staleARPIngressACL, ingressDenyPG}
		finalEgressDenyPG := buildPortGroup(
			egressPGName,
			egressPGName,
			nil,
			nil,
		)
		finalEgressDenyPG.UUID = finalEgressDenyPG.Name + "-UUID"
		finalIngressDenyPG := buildPortGroup(
			ingressPGName,
			ingressPGName,
			nil,
			nil,
		)
		finalIngressDenyPG.UUID = finalIngressDenyPG.Name + "-UUID"
		// acls will stay since they are no garbage-collected by test server
		finalDb := []libovsdbtest.TestData{staleARPEgressACL, finalEgressDenyPG, staleARPIngressACL, finalIngressDenyPG}

		testData := []aclSync{
			// egress deny
			{
				before: libovsdbops.BuildACL(
					policyNamespace,
					nbdb.ACLDirectionFromLport,
					types.DefaultDenyPriority,
					"inport == @"+egressPGName,
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeEgress)},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultDenyPolicyACLIDs(policyNamespace, string(knet.PolicyTypeEgress), defaultDenyACL),
			},
			// egress allow ARP
			{
				before: libovsdbops.BuildACL(
					getStaleARPAllowACLName(policyNamespace),
					nbdb.ACLDirectionFromLport,
					types.DefaultAllowPriority,
					"inport == @"+egressPGName+" && "+arpAllowPolicyMatch,
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeEgress)},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultDenyPolicyACLIDs(policyNamespace, string(knet.PolicyTypeEgress), arpAllowACL),
			},
			// egress deny
			{
				before: libovsdbops.BuildACL(
					policyNamespace,
					nbdb.ACLDirectionToLport,
					types.DefaultDenyPriority,
					"outport == @"+ingressPGName,
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeIngress)},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultDenyPolicyACLIDs(policyNamespace, string(knet.PolicyTypeIngress), defaultDenyACL),
			},
			// egress allow ARP
			{
				before: libovsdbops.BuildACL(
					getStaleARPAllowACLName(policyNamespace),
					nbdb.ACLDirectionToLport,
					types.DefaultAllowPriority,
					"outport == @"+ingressPGName+" && "+arpAllowPolicyMatch,
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{defaultDenyPolicyTypeACLExtIdKey: string(knet.PolicyTypeIngress)},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getDefaultDenyPolicyACLIDs(policyNamespace, string(knet.PolicyTypeIngress), arpAllowACL),
			},
		}
		testSyncerWithData(testData, controllerName, initialDb, finalDb, nil)
	})
	ginkgo.It("updates egress firewall acls", func() {
		testData := []aclSync{
			{
				before: libovsdbops.BuildACL(
					"random",
					nbdb.ACLDirectionFromLport,
					types.EgressFirewallStartPriority,
					"any",
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{egressFirewallACLExtIdKey: namespace1},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getEgressFirewallACLDbIDs(namespace1, 0),
			},
			{
				before: libovsdbops.BuildACL(
					"random2",
					nbdb.ACLDirectionFromLport,
					types.EgressFirewallStartPriority-1,
					"any2",
					nbdb.ACLActionDrop,
					types.OvnACLLoggingMeter,
					"",
					false,
					map[string]string{egressFirewallACLExtIdKey: namespace1},
					nil,
					types.PlaceHolderACLTier,
				),
				after: syncerToBuildData.getEgressFirewallACLDbIDs(namespace1, 1),
			},
		}
		testSyncerWithData(testData, controllerName, []libovsdbtest.TestData{}, nil, nil)
	})
})
