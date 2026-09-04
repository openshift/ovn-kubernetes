//go:build linux
// +build linux

package node

import (
	"context"
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog/v2"

	"sigs.k8s.io/knftables"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	nodeipt "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/node/iptables"
	nodenft "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/node/nftables"
)

const (
	mcsBlockingChain        = "mcs-blocking"
	mcsBlockingOutputChain  = "mcs-blocking-output"
	mcsBlockingForwardChain = "mcs-blocking-forward"
)

// cleanupLegacyMCSBlockIptRules best-effort deletes leftover host iptables MCS REJECT
// rules from before the nftables migration. Only the --syn variant is handled; the older
// non--syn variant predates any OCP version we could still be upgrading from.
func cleanupLegacyMCSBlockIptRules() {
	var delRules []nodeipt.Rule
	for _, protocol := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		if protocol == iptables.ProtocolIPv4 && !config.IPv4Mode {
			continue
		}
		if protocol == iptables.ProtocolIPv6 && !config.IPv6Mode {
			continue
		}
		for _, chain := range []string{"FORWARD", "OUTPUT"} {
			for _, port := range []string{"22623", "22624"} {
				delRules = append(delRules,
					nodeipt.Rule{
						Table:    "filter",
						Chain:    chain,
						Args:     []string{"-p", "tcp", "-m", "tcp", "--dport", port, "--syn", "-j", "REJECT"},
						Protocol: protocol,
					},
				)
			}
		}
	}
	_ = nodeipt.DelRules(delRules)
}

// cleanupLegacyMCSBlockNFTRulesFromSharedTable best-effort deletes leftover MCS-blocking
// chains from the shared ovn-kubernetes nftables table after they were moved to the
// openshift-ovn-kubernetes table.
func cleanupLegacyMCSBlockNFTRulesFromSharedTable() {
	nft, err := nodenft.GetNFTablesHelper()
	if err != nil {
		return
	}

	tx := nft.NewTransaction()
	// Delete hooked chains first, then the shared chain they jump to.
	for _, chain := range []string{mcsBlockingForwardChain, mcsBlockingOutputChain, mcsBlockingChain} {
		tx.Add(&knftables.Chain{Name: chain})
		tx.Flush(&knftables.Chain{Name: chain})
		tx.Delete(&knftables.Chain{Name: chain})
	}
	if err := nft.Run(context.TODO(), tx); err != nil && !knftables.IsNotFound(err) {
		klog.Warningf("failed to clean up legacy MCS nftables chains from ovn-kubernetes table: %v", err)
	}
}

// setupMCSBlockNFTRules inserts nftables rules to block local Machine Config Service
// ports. See https://github.com/openshift/ovn-kubernetes/pull/170
func setupMCSBlockNFTRules() error {
	cleanupLegacyMCSBlockNFTRulesFromSharedTable()

	// Use a separate OpenShift-specific table so these downstream-only rules don't end
	// up in the shared "ovn-kubernetes" table (and thus in upstream unit test dumps).
	nft, err := nodenft.GetOpenShiftNFTablesHelper()
	if err != nil {
		return fmt.Errorf("failed to setup MCS-blocking rules: %w", err)
	}

	tx := nft.NewTransaction()

	tx.Add(&knftables.Chain{
		Name: mcsBlockingChain,
	})
	tx.Flush(&knftables.Chain{
		Name: mcsBlockingChain,
	})
	tx.Add(&knftables.Rule{
		Chain: mcsBlockingChain,
		Rule: knftables.Concat(
			"tcp dport { 22623, 22624 } tcp flags syn / fin,syn,rst,ack",
			"reject",
		),
	})

	tx.Add(&knftables.Chain{
		Name:     mcsBlockingOutputChain,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
	})
	tx.Flush(&knftables.Chain{
		Name: mcsBlockingOutputChain,
	})
	tx.Add(&knftables.Rule{
		Chain: mcsBlockingOutputChain,
		Rule:  "jump " + mcsBlockingChain,
	})

	tx.Add(&knftables.Chain{
		Name:     mcsBlockingForwardChain,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.ForwardHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
	})
	tx.Flush(&knftables.Chain{
		Name: mcsBlockingForwardChain,
	})
	tx.Add(&knftables.Rule{
		Chain: mcsBlockingForwardChain,
		Rule:  "jump " + mcsBlockingChain,
	})

	if err := nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("failed to setup MCS-blocking rules: %w", err)
	}

	// If there are legacy IPTables rules left around, try to clean them up.
	cleanupLegacyMCSBlockIptRules()

	return nil
}
