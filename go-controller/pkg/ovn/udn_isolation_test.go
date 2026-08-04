package ovn

import (
	"fmt"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("UDN Isolation", func() {
	BeforeEach(func() {
		Expect(config.PrepareTestConfig()).To(Succeed())
	})

	It("ACLs should be updated to the Primary tier ", func() {
		config.OVNKubernetesFeature.EnableMultiNetwork = true
		config.OVNKubernetesFeature.EnableNetworkSegmentation = true
		fakeController := getFakeController(DefaultNetworkControllerName)

		// build port group with one ACL that has default tier
		pgIDs := fakeController.getSecondaryPodsPortGroupDbIDs()
		pgName := libovsdbutil.GetPortGroupName(pgIDs)
		egressDenyIDs := fakeController.getUDNACLDbIDs(DenySecondaryACL, libovsdbutil.ACLEgress)
		match := libovsdbutil.GetACLMatch(pgName, "", libovsdbutil.ACLEgress)
		// in the real code we use BuildACL here instead of BuildACLWithDefaultTier
		egressDenyACL := libovsdbutil.BuildACLWithDefaultTier(egressDenyIDs, types.PrimaryUDNDenyPriority, match, nbdb.ACLActionDrop,
			nil, libovsdbutil.LportEgress)
		// required to make sure port group correctly references the ACL
		egressDenyACL.UUID = egressDenyIDs.String() + "-UUID"
		pg := libovsdbutil.BuildPortGroup(pgIDs, nil, []*nbdb.ACL{egressDenyACL})

		nbClient, nbCleanup, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{egressDenyACL, pg},
		}, nil)
		Expect(err).NotTo(HaveOccurred())
		defer nbCleanup.Cleanup()
		fakeController.nbClient = nbClient

		// now run the setupUDNACLs function which should create all ACLs and update the existing ACLs to the Primary tier
		Expect(fakeController.setupUDNACLs(nil)).To(Succeed())

		// verify that the egressDenyACL is updated to the Primary 0
		acls, err := libovsdbops.FindACLs(nbClient, []*nbdb.ACL{egressDenyACL})
		Expect(err).NotTo(HaveOccurred())
		Expect(acls).To(HaveLen(1))
		Expect(acls[0].Tier).To(Equal(types.PrimaryACLTier))
	})

	Describe("ConfigureAdvertisedNetworkIsolation", func() {
		expectedDropACLMatch := func() string {
			v4HashName, v6HashName := addressset.GetHashNamesForAS(GetAdvertisedNetworkSubnetsAddressSetDBIDs())
			var matches []string
			if config.IPv4Mode {
				matches = append(matches, fmt.Sprintf("(ip4.src == $%s && ip4.dst == $%s)", v4HashName, v4HashName))
			}
			if config.IPv6Mode {
				matches = append(matches, fmt.Sprintf("(ip6.src == $%s && ip6.dst == $%s)", v6HashName, v6HashName))
			}
			return strings.Join(matches, " || ")
		}

		expectedAddrSets := func() []libovsdbtest.TestData {
			var data []libovsdbtest.TestData
			v4set, v6set := addressset.GetTestDbAddrSets(GetAdvertisedNetworkSubnetsAddressSetDBIDs(), nil)
			if config.IPv4Mode {
				data = append(data, v4set)
			}
			if config.IPv6Mode {
				data = append(data, v6set)
			}
			return data
		}

		It("creates the port group and drop ACL on fresh install", func() {
			nbClient, nbCleanup, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{}, nil)
			Expect(err).NotTo(HaveOccurred())
			defer nbCleanup.Cleanup()

			Expect(ConfigureAdvertisedNetworkIsolation(nbClient)).To(Succeed())

			dropACL := libovsdbutil.BuildACL(GetAdvertisedNetworkSubnetsDropACLdbIDs(),
				types.AdvertisedNetworkDenyPriority, expectedDropACLMatch(),
				nbdb.ACLActionDrop, nil, libovsdbutil.LportEgressAfterLB, isolationTier)
			dropACL.UUID = "drop-acl-UUID"
			pg := libovsdbutil.BuildPortGroup(GetAdvertisedNetworkSubnetsDropPGdbIDs(), nil, []*nbdb.ACL{dropACL})
			pg.UUID = "drop-pg-UUID"
			expectedData := append([]libovsdbtest.TestData{dropACL, pg}, expectedAddrSets()...)
			Expect(nbClient).To(libovsdbtest.HaveData(expectedData))
		})

		It("migrates a single drop ACL from a switch to the port group", func() {
			dropACLdbIDs := GetAdvertisedNetworkSubnetsDropACLdbIDs()
			dropACL := libovsdbutil.BuildACL(dropACLdbIDs, types.AdvertisedNetworkDenyPriority,
				"(ip4.src == $fake && ip4.dst == $fake)", nbdb.ACLActionDrop, nil,
				libovsdbutil.LportEgressAfterLB, isolationTier)
			dropACL.UUID = "drop-acl-UUID"

			storLSP := &nbdb.LogicalSwitchPort{UUID: "stor-sw1-UUID", Name: types.SwitchToRouterPrefix + "sw1", Type: "router"}
			sw := &nbdb.LogicalSwitch{UUID: "sw1-UUID", Name: "sw1", Ports: []string{storLSP.UUID}, ACLs: []string{dropACL.UUID}}

			nbClient, nbCleanup, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{dropACL, sw, storLSP},
			}, nil)
			Expect(err).NotTo(HaveOccurred())
			defer nbCleanup.Cleanup()

			Expect(ConfigureAdvertisedNetworkIsolation(nbClient)).To(Succeed())

			expectedDropACL := libovsdbutil.BuildACL(dropACLdbIDs,
				types.AdvertisedNetworkDenyPriority, expectedDropACLMatch(),
				nbdb.ACLActionDrop, nil, libovsdbutil.LportEgressAfterLB, isolationTier)
			expectedDropACL.UUID = "drop-acl-UUID"
			expectedPG := libovsdbutil.BuildPortGroup(GetAdvertisedNetworkSubnetsDropPGdbIDs(), nil, []*nbdb.ACL{expectedDropACL})
			expectedPG.UUID = "drop-pg-UUID"
			expectedPG.Ports = []string{storLSP.UUID}
			expectedData := append([]libovsdbtest.TestData{
				expectedDropACL, expectedPG,
				&nbdb.LogicalSwitch{UUID: "sw1-UUID", Name: "sw1", Ports: []string{storLSP.UUID}},
				storLSP,
			}, expectedAddrSets()...)
			Expect(nbClient).To(libovsdbtest.HaveData(expectedData))
		})

		It("migrates duplicate drop ACLs from switches to the port group", func() {
			dropACLdbIDs := GetAdvertisedNetworkSubnetsDropACLdbIDs()
			dropACL1 := libovsdbutil.BuildACL(dropACLdbIDs, types.AdvertisedNetworkDenyPriority,
				"(ip4.src == $fake && ip4.dst == $fake)", nbdb.ACLActionDrop, nil,
				libovsdbutil.LportEgressAfterLB, isolationTier)
			dropACL1.UUID = "drop-acl-1-UUID"
			dropACL2 := libovsdbutil.BuildACL(dropACLdbIDs, types.AdvertisedNetworkDenyPriority,
				"(ip4.src == $fake && ip4.dst == $fake)", nbdb.ACLActionDrop, nil,
				libovsdbutil.LportEgressAfterLB, isolationTier)
			dropACL2.UUID = "drop-acl-2-UUID"

			sw1LSP := &nbdb.LogicalSwitchPort{UUID: "stor-sw1-UUID", Name: types.SwitchToRouterPrefix + "sw1", Type: "router"}
			sw1 := &nbdb.LogicalSwitch{UUID: "sw1-UUID", Name: "sw1", Ports: []string{sw1LSP.UUID}, ACLs: []string{dropACL1.UUID}}
			// emulate Layer 2 network
			sw2Name := "sw2_" + types.OVNLayer2Switch
			sw2LSP := &nbdb.LogicalSwitchPort{UUID: "stor-sw2-UUID", Name: types.SwitchToRouterPrefix + sw2Name, Type: "router"}
			sw2 := &nbdb.LogicalSwitch{UUID: "sw2-UUID", Name: sw2Name, Ports: []string{sw2LSP.UUID}, ACLs: []string{dropACL2.UUID}}

			nbClient, nbCleanup, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{dropACL1, dropACL2, sw1, sw2, sw1LSP, sw2LSP},
			}, nil)
			Expect(err).NotTo(HaveOccurred())
			defer nbCleanup.Cleanup()

			Expect(ConfigureAdvertisedNetworkIsolation(nbClient)).To(Succeed())

			expectedDropACL := libovsdbutil.BuildACL(dropACLdbIDs,
				types.AdvertisedNetworkDenyPriority, expectedDropACLMatch(),
				nbdb.ACLActionDrop, nil, libovsdbutil.LportEgressAfterLB, isolationTier)
			expectedDropACL.UUID = "drop-acl-1-UUID"
			expectedPG := libovsdbutil.BuildPortGroup(GetAdvertisedNetworkSubnetsDropPGdbIDs(), nil, []*nbdb.ACL{expectedDropACL})
			expectedPG.UUID = "drop-pg-UUID"
			expectedPG.Ports = []string{sw1LSP.UUID, sw2LSP.UUID}
			sw1.ACLs = nil
			sw2.ACLs = nil
			expectedData := append([]libovsdbtest.TestData{
				expectedDropACL, expectedPG,
				sw1, sw2,
				sw1LSP, sw2LSP,
			}, expectedAddrSets()...)
			Expect(nbClient).To(libovsdbtest.HaveData(expectedData))
		})

		It("skips migration but self-heals the drop ACL when the port group already exists", func() {
			dropACLdbIDs := GetAdvertisedNetworkSubnetsDropACLdbIDs()
			dropACL := libovsdbutil.BuildACL(dropACLdbIDs, types.AdvertisedNetworkDenyPriority,
				"(ip4.src == $fake && ip4.dst == $fake)", nbdb.ACLActionDrop, nil,
				libovsdbutil.LportEgressAfterLB, isolationTier)
			dropACL.UUID = "drop-acl-UUID"
			storLSP := &nbdb.LogicalSwitchPort{UUID: "stor-sw1-UUID", Name: types.SwitchToRouterPrefix + "sw1", Type: "router"}
			sw := &nbdb.LogicalSwitch{UUID: "sw1-UUID", Name: "sw1", Ports: []string{storLSP.UUID}}
			pg := libovsdbutil.BuildPortGroup(GetAdvertisedNetworkSubnetsDropPGdbIDs(), nil, []*nbdb.ACL{dropACL})
			pg.UUID = "drop-pg-UUID"
			pg.Ports = []string{storLSP.UUID}

			nbClient, nbCleanup, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{dropACL, pg, sw, storLSP},
			}, nil)
			Expect(err).NotTo(HaveOccurred())
			defer nbCleanup.Cleanup()

			Expect(ConfigureAdvertisedNetworkIsolation(nbClient)).To(Succeed())

			expectedDropACL := libovsdbutil.BuildACL(dropACLdbIDs,
				types.AdvertisedNetworkDenyPriority, expectedDropACLMatch(),
				nbdb.ACLActionDrop, nil, libovsdbutil.LportEgressAfterLB, isolationTier)
			expectedDropACL.UUID = "drop-acl-UUID"
			expectedPG := libovsdbutil.BuildPortGroup(GetAdvertisedNetworkSubnetsDropPGdbIDs(), nil, []*nbdb.ACL{expectedDropACL})
			expectedPG.UUID = "drop-pg-UUID"
			expectedPG.Ports = []string{storLSP.UUID}
			expectedData := append([]libovsdbtest.TestData{expectedDropACL, expectedPG, sw, storLSP}, expectedAddrSets()...)
			Expect(nbClient).To(libovsdbtest.HaveData(expectedData))
		})
	})

})
