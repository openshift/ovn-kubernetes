// +build linux

package node

// OCP HACK: Block MCS Access. https://github.com/openshift/ovn-kubernetes/pull/170
func generateBlockMCSRules(rules *[]iptRule) {
	*rules = append(*rules, iptRule{
		table: "filter",
		chain: "FORWARD",
		args:  []string{"-p", "tcp", "-m", "tcp", "--dport", "22623", "-j", "REJECT"},
	})
	*rules = append(*rules, iptRule{
		table: "filter",
		chain: "FORWARD",
		args:  []string{"-p", "tcp", "-m", "tcp", "--dport", "22624", "-j", "REJECT"},
	})
	*rules = append(*rules, iptRule{
		table: "filter",
		chain: "OUTPUT",
		args:  []string{"-p", "tcp", "-m", "tcp", "--dport", "22623", "-j", "REJECT"},
	})
	*rules = append(*rules, iptRule{
		table: "filter",
		chain: "OUTPUT",
		args:  []string{"-p", "tcp", "-m", "tcp", "--dport", "22624", "-j", "REJECT"},
	})
}

// END OCP HACK

