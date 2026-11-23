// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/ginkgogroup"
)

// nofloodMACBindingGroup runs the standalone no-flood MAC binding mirroring
// specs as a single OTE test. The specs share the external containers, CUDNs
// and pods their Ordered container creates in BeforeAll, and build on each
// other: the mirroring specs start the pings that the stability and age-out
// specs assert on, and the last age-out spec relies on the one before it
// stopping them. Run one at a time, as OTE does, the later specs do not test
// what they claim.
//
// The members and the excluded specs must be the exact specs of the upstream
// Ordered container, the members in declaration order; the catalog does not
// build otherwise.
var nofloodMACBindingGroup = ginkgogroup.Group{
	// The cloud platform exclusion in shouldIncludeTest matches the name of
	// the group spec through nofloodMACBindingDescribe.
	Container: "Network Segmentation: " + nofloodMACBindingDescribe,
	Members: []string{
		"has no MAC bindings for the external containers before any traffic",
		"mirrors the binding learned by the CDN gateway router to every UDN",
		"mirrors a binding triggered by a UDN pod to the CDN and every other UDN",
		"binds node IPs statically on the UDNs instead of mirroring them",
		"never adds a static MAC binding to the default network gateway router",
		"does not mirror onto a secondary CUDN",
		"does not leak the bindings into the other nodes' zones",
		"keeps the mirrored bindings stable while the traffic lasts",
		"backfills a CUDN created after the bindings were learned, and reaps it on delete",
		"converges every gateway router onto the new MAC when the external container changes it",
		"ages out the CDN-triggered binding on every gateway router once traffic stops",
		"ages out the UDN-triggered binding on every gateway router once traffic stops",
	},
	Excluded: []string{
		// [Disabled:Broken] in openshift/test/annotate/rules.go.
		"reconverges after ovnkube-node restarts, without leaving orphan static bindings",
	},
}
