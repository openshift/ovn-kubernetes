package annotate

import (
	// ensure all the ginkgo tests are loaded
	_ "github.com/ovn-org/ovn-kubernetes/test/e2e"
)

var (
	TestMaps = map[string][]string{
		// alpha features that are not gated
		"[Disabled:Alpha]": {},
		// tests for features that are not implemented in openshift
		"[Disabled:Unimplemented]": {
			`\[Feature:Service\]`,
			`\[Feature:NetworkPolicy\]`,
			`\[Feature:AdminNetworkPolicy\]`,
			`\[Feature:BaselineNetworkPolicy\]`,
			`\[Feature:EgressIP\]`,
			`\[Feature:EgressService\]`,
			`\[Feature:EgressFirewall\]`,
			`\[Feature:EgressQos\]`,
			`\[Feature:ExternalGateway\]`,
			`\[Feature:DisablePacketMTUCheck\]`,
			`\[Feature:VirtualMachineSupport\]`,
			`\[Feature:Interconnect\]`,
			`\[Feature:Multicast\]`,
			`\[Feature:MultiHoming\]`,
			`\[Feature:NodeIPMACMigration\]`,
			`\[Feature:OVSCPUPin\]`,
			`\[Feature:Unidle\]`,
			`Creating a static pod on a node Should successfully create then remove a static pod`,
			`Pod to external server PMTUD`,
			`Pod to pod TCP with low MTU`,
		},
		// tests that rely on special configuration that we do not yet support
		"[Disabled:SpecialConfig]": {},
		// tests that are known broken and need to be fixed upstream or in openshift
		// always add an issue here
		"[Disabled:Broken]": {},
		// tests that need to be temporarily disabled while the rebase is in progress.
		"[Disabled:RebaseInProgress]": {},
		// tests that may work, but we don't support them
		"[Disabled:Unsupported]": {},
		// tests too slow to be part of conformance
		"[Slow]": {},
		// tests that are known flaky
		"[Flaky]": {},
		// tests that must be run without competition
		"[Serial]": {},
		// Tests that don't pass on disconnected, either due to requiring
		// internet access for GitHub (e.g. many of the s2i builds), or
		// because of pullthrough not supporting ICSP (https://bugzilla.redhat.com/show_bug.cgi?id=1918376)
		"[Skipped:Disconnected]": {},
		"[Skipped:alibabacloud]": {},
		"[Skipped:aws]":          {},
		"[Skipped:azure]":        {},
		"[Skipped:baremetal]":    {},
		"[Skipped:gce]":          {},
		"[Skipped:ibmcloud]":     {},
		"[Skipped:kubevirt]":     {},
		"[Skipped:nutanix]":      {},
		"[Skipped:openstack]":    {},
		"[Skipped:ovirt]":        {},
		"[Skipped:vsphere]":      {},
		// These tests are skipped when openshift-tests needs to use a proxy to reach the
		// cluster -- either because the test won't work while proxied, or because the test
		// itself is testing a functionality using it's own proxy.
		"[Skipped:Proxy]":                 {},
		"[Skipped:SingleReplicaTopology]": {},
		// Tests which can't be run/don't make sense to run against a cluster with all optional capabilities disabled
		"[Skipped:NoOptionalCapabilities]": {},
		"[Skipped:ibmroks]":                {},
	}

	ExcludedTests = []string{
		`\[Disabled:`,
		`\[Disruptive\]`,
		`\[Skipped\]`,
		`\[Slow\]`,
		`\[Flaky\]`,
		`\[Local\]`,
	}
)
