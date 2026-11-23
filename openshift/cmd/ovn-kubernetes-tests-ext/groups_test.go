// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test"
	ocpdeploymentconfig "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/generated"
	ocpinfraprovider "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/infraprovider"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
)

// setNoClusterProviders sets the providers `list tests` uses without a
// cluster.
func setNoClusterProviders() {
	deploymentconfig.Set(ocpdeploymentconfig.New(nil))
	infraprovider.Set(&ocpinfraprovider.OpenshiftInfraProvider{})
}

// catalog builds the catalog from the vendored upstream specs, as `list
// tests` does without a cluster.
var catalog = sync.OnceValues(func() (extensiontests.ExtensionTestSpecs, error) {
	setNoClusterProviders()
	return ginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite(extensiontests.AllTestsIncludingVendored())
})

// TestMain is also the entry point of the binary the no-flood group test
// re-executes. Without a cluster, it runs the upstream specs as a Ginkgo dry
// run: Ginkgo selects, orders and reports them without running their nodes.
func TestMain(m *testing.M) {
	if nofloodMACBindingGroup.Reentered() {
		if err := flag.Set("ginkgo.dry-run", "true"); err != nil {
			fmt.Fprintf(os.Stderr, "failed to request a dry run: %v\n", err)
			os.Exit(1)
		}
		setNoClusterProviders()
		os.Exit(nofloodMACBindingGroup.RunNative(func() error { return nil }))
	}
	os.Exit(m.Run())
}

// collectNofloodGroup returns the catalog, the catalog with the no-flood group
// collected, and the group spec.
func collectNofloodGroup(t *testing.T) (specs, collected extensiontests.ExtensionTestSpecs, group *extensiontests.ExtensionTestSpec) {
	t.Helper()
	specs, err := catalog()
	if err != nil {
		t.Fatalf("failed to build the catalog: %v", err)
	}
	collected, err = nofloodMACBindingGroup.Collect(specs, generated.AppendedAnnotations)
	if err != nil {
		t.Fatalf("the upstream container does not match the reviewed group: %v", err)
	}
	groupName := nofloodMACBindingGroup.Container + " [Suite:ovn-kubernetes/conformance/serial]"
	i := slices.IndexFunc(collected, func(spec *extensiontests.ExtensionTestSpec) bool { return spec.Name == groupName })
	if i < 0 {
		t.Fatalf("no spec %q", groupName)
	}
	return specs, collected, collected[i]
}

// TestNofloodMACBindingGroupMatchesTheUpstreamContainer checks the reviewed
// group against the catalog.
func TestNofloodMACBindingGroupMatchesTheUpstreamContainer(t *testing.T) {
	specs, collected, group := collectNofloodGroup(t)

	for _, spec := range collected {
		switch {
		case spec == group:
		case !slices.Contains(specs, spec):
			t.Errorf("spec %q was changed", spec.Name)
		case strings.HasPrefix(spec.Name, nofloodMACBindingGroup.Container+" ") &&
			spec.Name != nofloodMACBindingGroup.Container+" "+nofloodMACBindingGroup.Excluded[0]:
			t.Errorf("member %q is still an individual test", spec.Name)
		}
	}
	if got, want := len(collected), len(specs)-len(nofloodMACBindingGroup.Members)+1; got != want {
		t.Errorf("collected %d specs, want %d", got, want)
	}

	// The restart spec stays out, disabled, and the uplink specs are not
	// collected.
	for _, spec := range specs {
		excluded := spec.Name == nofloodMACBindingGroup.Container+" "+nofloodMACBindingGroup.Excluded[0]
		uplink := strings.HasPrefix(spec.Name, "Network Segmentation: MAC binding mirroring for multiple UDNs on same uplink ")
		if (excluded || uplink) && !slices.Contains(collected, spec) {
			t.Errorf("spec %q was collected", spec.Name)
		}
		if excluded && !strings.Contains(generated.AppendedAnnotations[spec.Name], "[Disabled:Broken]") {
			t.Errorf("excluded spec %q is not disabled", spec.Name)
		}
	}

	// OTE names the group like any spec, and tests.go gives it its lifecycle.
	labels := group.Labels.Clone().Insert(getTestExtensionLabels()...)
	labels.Insert(getPrependLabels(labels)...)
	if !labels.Has(featureLabelNetworkSegmentation) || !labels.Has("Serial") {
		t.Errorf("group labels = %v, want %s and Serial", labels, featureLabelNetworkSegmentation)
	}
	name := generatePrependedLabelsStr(labels) + " " + group.Name
	if !slices.Contains(test.InformingTests, name) {
		t.Errorf("test.InformingTests does not list %q", name)
	}
	if slices.Contains(test.BlockingTests, name) {
		t.Errorf("test.BlockingTests lists %q", name)
	}
}

// TestNofloodMACBindingGroupRunsExactlyItsUpstreamMembers runs the group spec
// against the vendored upstream specs, in a binary that registers the
// generated annotations like the OTE one. TestMain stands in for the re-entry
// in main, which it mirrors.
func TestNofloodMACBindingGroupRunsExactlyItsUpstreamMembers(t *testing.T) {
	_, _, group := collectNofloodGroup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result := group.Run(ctx)

	// Selecting, ordering or reporting anything but the members, in one
	// Ordered container, fails the group.
	if result.Result != extensiontests.ResultPassed {
		t.Fatalf("result = %s, want passed; error: %s", result.Result, result.Error)
	}
	var want, got []string
	for _, member := range nofloodMACBindingGroup.Members {
		want = append(want, member+"=passed")
	}
	for _, d := range result.Details {
		got = append(got, fmt.Sprintf("%s=%v", d.Name, d.Value))
	}
	if !slices.Equal(got, want) {
		t.Errorf("details = %q, want %q", got, want)
	}
}
