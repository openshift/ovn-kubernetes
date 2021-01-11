// +build linux

package node

func generateBlockMCSRules() (addRules, delRules []iptRule) {
	for _, chain := range []string{"FORWARD", "OUTPUT"} {
		for _, port := range []string{"22623", "22624"} {
			addRules = append(addRules, iptRule{
				table:    "filter",
				chain:    chain,
				args:     []string{"-p", "tcp", "-m", "tcp", "--dport", port, "--syn", "-j", "REJECT"},
			})
			// Delete the old "--syn"-less rules on upgrade
			delRules = append(delRules, iptRule{
				table:    "filter",
				chain:    chain,
				args:     []string{"-p", "tcp", "-m", "tcp", "--dport", port, "-j", "REJECT"},
			})
		}
	}
	return
}
