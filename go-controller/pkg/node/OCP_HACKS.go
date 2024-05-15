//go:build linux
// +build linux

package node

import (
	"github.com/coreos/go-iptables/iptables"
	nodeipt "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/iptables"
)

// Block MCS Access. https://github.com/openshift/ovn-kubernetes/pull/170
func generateBlockMCSRules(rules *[]nodeipt.Rule, protocol iptables.Protocol) {
	var delRules []nodeipt.Rule

	for _, chain := range []string{"FORWARD", "OUTPUT"} {
		for _, port := range []string{"22623", "22624"} {
			*rules = append(*rules, nodeipt.Rule{
				Table:    "filter",
				Chain:    chain,
				Args:     []string{"-p", "tcp", "-m", "tcp", "--dport", port, "--syn", "-j", "REJECT"},
				Protocol: protocol,
			})
			// Delete the old "--syn"-less rules on upgrade
			delRules = append(delRules, nodeipt.Rule{
				Table:    "filter",
				Chain:    chain,
				Args:     []string{"-p", "tcp", "-m", "tcp", "--dport", port, "-j", "REJECT"},
				Protocol: protocol,
			})
		}
	}

	_ = nodeipt.DelRules(delRules)
}
