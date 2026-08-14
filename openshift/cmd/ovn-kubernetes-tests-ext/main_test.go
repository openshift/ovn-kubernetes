package main

import (
	"testing"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/util/sets"
)

// TestShouldIncludeTestWithoutClusterInfra exercises shouldIncludeTest on the
// ocpInfra == nil path. This path is taken during "list tests"/"info" and,
// importantly, whenever infra initialization fails intermittently. The KUBECONFIG
// environment variable distinguishes the two situations:
//
//   - KUBECONFIG unset: an informational listing with no cluster to talk to, so
//     every eligible test is included (including EVPN) to report the full catalog.
//   - KUBECONFIG set: infra init failed against a real cluster, so EVPN tests are
//     excluded because their prerequisites cannot be verified. Listing them would
//     otherwise cause a non-deterministic "no such tests" error at dispatch when a
//     later invocation with working infra and CheckForEVPN() == false drops them.
func TestShouldIncludeTestWithoutClusterInfra(t *testing.T) {
	// shouldIncludeTest reads the package-level ocpInfra global. Force the
	// nil (no cluster access) path and restore the original value afterwards.
	orig := ocpInfra
	ocpInfra = nil
	t.Cleanup(func() { ocpInfra = orig })

	tests := []struct {
		name          string
		kubeconfigSet bool
		spec          *extensiontests.ExtensionTestSpec
		want          bool
	}{
		// KUBECONFIG set: infra init failed, EVPN prerequisites unverifiable.
		{
			name:          "evpn test is excluded when KUBECONFIG is set but infra is unavailable",
			kubeconfigSet: true,
			spec: &extensiontests.ExtensionTestSpec{
				Name:      "[sig-network] EVPN basic connectivity",
				Lifecycle: extensiontests.LifecycleInforming,
				Labels:    sets.New(featureLabelEVPN),
			},
			want: false,
		},
		{
			name:          "non-evpn test is included when KUBECONFIG is set but infra is unavailable",
			kubeconfigSet: true,
			spec: &extensiontests.ExtensionTestSpec{
				Name:      "[sig-network] plain pod connectivity",
				Lifecycle: extensiontests.LifecycleBlocking,
				Labels:    sets.New(featureLabelNetworkSegmentation),
			},
			want: true,
		},
		// KUBECONFIG unset: informational listing, include everything eligible.
		{
			name:          "evpn test is included when KUBECONFIG is unset (informational listing)",
			kubeconfigSet: false,
			spec: &extensiontests.ExtensionTestSpec{
				Name:      "[sig-network] EVPN basic connectivity",
				Lifecycle: extensiontests.LifecycleInforming,
				Labels:    sets.New(featureLabelEVPN),
			},
			want: true,
		},
		{
			name:          "non-evpn test is included when KUBECONFIG is unset (informational listing)",
			kubeconfigSet: false,
			spec: &extensiontests.ExtensionTestSpec{
				Name:      "[sig-network] plain pod connectivity",
				Lifecycle: extensiontests.LifecycleBlocking,
				Labels:    sets.New(featureLabelNetworkSegmentation),
			},
			want: true,
		},
		// Lifecycle / disabled gating applies before the KUBECONFIG check.
		{
			name:          "test without a lifecycle is excluded regardless of KUBECONFIG",
			kubeconfigSet: true,
			spec: &extensiontests.ExtensionTestSpec{
				Name:      "[sig-network] unassigned lifecycle",
				Lifecycle: "",
				Labels:    sets.New[string](),
			},
			want: false,
		},
		{
			name:          "explicitly disabled test is excluded regardless of KUBECONFIG",
			kubeconfigSet: false,
			spec: &extensiontests.ExtensionTestSpec{
				Name:      "[sig-network] flaky thing [Disabled:SomeReason]",
				Lifecycle: extensiontests.LifecycleInforming,
				Labels:    sets.New[string](),
			},
			want: false,
		},
		{
			name:          "evpn test without a lifecycle is excluded even when KUBECONFIG is unset",
			kubeconfigSet: false,
			spec: &extensiontests.ExtensionTestSpec{
				Name:      "[sig-network] EVPN unassigned lifecycle",
				Lifecycle: "",
				Labels:    sets.New(featureLabelEVPN),
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The nil-infra branch reads KUBECONFIG. An empty value is
			// treated as unset by os.Getenv, which is exactly the
			// informational-listing case. t.Setenv restores any prior
			// value once the subtest completes.
			if tc.kubeconfigSet {
				t.Setenv("KUBECONFIG", "/tmp/nonexistent-kubeconfig")
			} else {
				t.Setenv("KUBECONFIG", "")
			}
			if got := shouldIncludeTest(tc.spec); got != tc.want {
				t.Errorf("shouldIncludeTest(%q) = %v, want %v", tc.spec.Name, got, tc.want)
			}
		})
	}
}
