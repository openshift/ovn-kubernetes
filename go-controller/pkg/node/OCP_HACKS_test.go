//go:build linux
// +build linux

package node

import (
	"sigs.k8s.io/knftables"

	nodenft "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/node/nftables"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// OCP HACK: expected MCS-blocking rules in the dedicated OpenShift nftables table.
const nftablesRulesMCSOpenShift = `
add table inet openshift-ovn-kubernetes
add chain inet openshift-ovn-kubernetes mcs-blocking
add rule inet openshift-ovn-kubernetes mcs-blocking tcp dport { 22623, 22624 } tcp flags syn / fin,syn,rst,ack reject
add chain inet openshift-ovn-kubernetes mcs-blocking-output { type filter hook output priority 0 ; }
add rule inet openshift-ovn-kubernetes mcs-blocking-output jump mcs-blocking
add chain inet openshift-ovn-kubernetes mcs-blocking-forward { type filter hook forward priority 0 ; }
add rule inet openshift-ovn-kubernetes mcs-blocking-forward jump mcs-blocking
`

var _ = Describe("OCP MCS-blocking nftables", func() {
	It("installs MCS-blocking rules in the openshift-ovn-kubernetes table", func() {
		nodenft.SetFakeNFTablesHelper()

		err := setupMCSBlockNFTRules()
		Expect(err).NotTo(HaveOccurred())

		ocpNFT, err := nodenft.GetOpenShiftNFTablesHelper()
		Expect(err).NotTo(HaveOccurred())

		ocpFake, ok := ocpNFT.(*knftables.Fake)
		Expect(ok).To(BeTrue(), "expected OpenShift nftables helper to be faked in unit tests")
		err = nodenft.MatchNFTRules(nftablesRulesMCSOpenShift, ocpFake.Dump())
		Expect(err).NotTo(HaveOccurred())

		mainNFT, err := nodenft.GetNFTablesHelper()
		Expect(err).NotTo(HaveOccurred())
		mainFake, ok := mainNFT.(*knftables.Fake)
		Expect(ok).To(BeTrue())
		Expect(mainFake.Dump()).NotTo(ContainSubstring("mcs-blocking"),
			"MCS rules must not appear in the shared ovn-kubernetes table")
	})
})

// END OCP HACK
