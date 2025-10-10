package annotate

import (
	// ensure all the ginkgo tests are loaded
	_ "github.com/ovn-org/ovn-kubernetes/test/e2e"
)

var (
	// E2E tests are written with the support of ginkgo. ginkgo tests may contain Labels.

	// LabelToLabelMaps label -> label (ginkgo label)
	// Note: d/s we override label 'key' "Feature" to "OCPFeature"
	LabelToLabelMaps = map[string][]string{
		"[Disabled:Unimplemented]": {
			`[OCPFeature:Service]`,
			`[OCPFeature:NetworkPolicy]`,
			`[OCPFeature:AdminNetworkPolicy]`,
			`[OCPFeature:BaselineNetworkPolicy]`,
			`[OCPFeature:EgressIP]`,
			`[OCPFeature:EgressService]`,
			`[OCPFeature:EgressFirewall]`,
			`[OCPFeature:EgressQos]`,
			`[OCPFeature:ExternalGateway]`,
			`[OCPFeature:DisablePacketMTUCheck]`,
			`[OCPFeature:VirtualMachineSupport]`,
			`[OCPFeature:Interconnect]`,
			`[OCPFeature:Multicast]`,
			`[OCPFeature:MultiHoming]`,
			`[OCPFeature:NodeIPMACMigration]`,
			`[OCPFeature:OVSCPUPin]`,
			`[OCPFeature:Unidle]`,
			`[OCPFeature:RouteAdvertisements]`,
		},
	}
	// if a test name partially or fully contains one of the map value strings, then add the label to the test
	// label -> partial or full test name or regex to match a test name
	LabelToTestNameMatchMaps = map[string][]string{
		// alpha features that are not gated
		"[Disabled:Alpha]": {},
		// tests for features that are not implemented in openshift
		"[Disabled:Unimplemented]": {
			`Creating a static pod on a node Should successfully create then remove a static pod`,
			`Pod to external server PMTUD`,
			`Pod to pod TCP with low MTU`,
			`blocking ICMP needs frag`,
			// UDN test requires egress
			`pod2Egress on a user defined primary network`,
			`is isolated from the default network`,
			// requires host net port collision avoidance
			`EndpointSlices mirroring`,
			// reference kind nodes
			`Should validate connectivity within a namespace of pods on separate nodes`,
			// tied to KinD / container runtime
			`e2e delete databases`,
			`test e2e inter-node connectivity between worker nodes`,
			`e2e control plane`,
			`test e2e pod connectivity to host addresses`,
			`e2e br-int flow monitoring export validation`,
			`e2e ingress to host-networked pods traffic validation`,
			`e2e ingress traffic validation`,
			// pods dont drop privileges
			`Should validate the hairpinned traffic is always allowed`,
			// refactor to give pod sufficient privs for tcpdump
			`should be able to receive multicast IGMP query`,
			// refactor to give pod sufficient privs
			`UDN Pod should react to k8s.ovn.org/open-default-ports annotations changes`,
			// load balancer isn't becoming available from the cloud services. Ensure, we provider the correct provider to the k8 api which spawns the ext LB.
			`services on a user defined primary network should be reachable through their cluster IP, node port and load balancer L3 primary UDN, cluster-networked pods, NodePort service`,
			`services on a user defined primary network should be reachable through their cluster IP, node port and load balancer L2 primary UDN, cluster-networked pods, NodePort service`,
			// test gets interrupted when test timeout expires while testing pod and lack of pod connectivity.
			`a user defined primary network created using ClusterUserDefinedNetwork isolates overlapping CIDRs with L3 primary UDN`,
			`a user defined primary network created using NetworkAttachmentDefinitions isolates overlapping CIDRs with L3 primary UDN`,
			// tests are tied to KinD deployment and select nodes based on KinD deployment. Needs refactoring.
			`allow ingress traffic to one pod from a particular namespace`,
			// private image in upstream test & need privs for tcpdump
			`e2e NetworkQoS validation`,
			// unknown rc 7 code
			`Network Segmentation: API validations`,
			// 'Network allocation failed for at least one node'
			`Network Segmentation UserDefinedNetwork CRD Controller should correctly report subsystem error on node subnet allocation`,
			// requires implementation of overlay method (provider API)
			`Network Segmentation: Localnet using ClusterUserDefinedNetwork CR, pods in different namespaces, should communicate over localnet topology`,
			// pods dont drop privileges
			`should be able to send multicast UDP traffic between nodes`,
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
