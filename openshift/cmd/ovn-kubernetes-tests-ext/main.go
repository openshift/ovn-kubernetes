package main

import (
	"os"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test"
	_ "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/generated"
	ocpinfraprovider "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/infraprovider"

	// import ovn-kubernetes tests
	_ "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/spf13/cobra"

	"k8s.io/apimachinery/pkg/util/sets"

	// ensure providers are initialised for configuring infra
	_ "k8s.io/kubernetes/test/e2e/framework/providers/aws"
	_ "k8s.io/kubernetes/test/e2e/framework/providers/azure"
	_ "k8s.io/kubernetes/test/e2e/framework/providers/gce"
	_ "k8s.io/kubernetes/test/e2e/framework/providers/kubemark"
	_ "k8s.io/kubernetes/test/e2e/framework/providers/openstack"
	_ "k8s.io/kubernetes/test/e2e/framework/providers/vsphere"

	// ensure that logging flags are part of the command line.
	_ "k8s.io/component-base/logs/testinit"
)

var ocpInfra *ocpinfraprovider.OpenshiftInfraProvider

const (
	// Feature labels used for test categorization and filtering
	featureLabelEVPN                = "Feature:EVPN"
	featureLabelNetworkSegmentation = "Feature:NetworkSegmentation"
)

// shouldIncludeTest determines if a test should be included based on cluster capabilities
// and test labels. When ocpInfra is nil, behavior depends on whether KUBECONFIG is set:
// during an informational listing (KUBECONFIG unset) all eligible tests are included,
// including EVPN; when KUBECONFIG is set but infra initialization failed, EVPN tests are
// excluded because their prerequisites cannot be verified.
func shouldIncludeTest(spec *extensiontests.ExtensionTestSpec) bool {
	// Disable specs that are not explicitly assigned a lifecycle
	if spec.Lifecycle == "" {
		return false
	}
	// Exclude explicitly disabled tests
	if strings.Contains(spec.Name, "[Disabled:") {
		return false
	}

	// ocpInfra is nil during "list tests"/"info" and also when infra
	// initialization fails intermittently. Distinguish the two cases using
	// KUBECONFIG:
	//
	//   - KUBECONFIG unset: this is an informational listing with no cluster
	//     to talk to, so include all eligible tests (including EVPN) to report
	//     the full catalog.
	//
	//   - KUBECONFIG set but infra init failed: EVPN prerequisites cannot be
	//     verified. Exclude EVPN specs so listing stays consistent with
	//     execution; otherwise a later invocation where infra init succeeds
	//     and CheckForEVPN() returns false would drop them from the spec set,
	//     causing a non-deterministic "no such tests" error at dispatch.
	if ocpInfra == nil {
		if os.Getenv("KUBECONFIG") != "" {
			return !spec.Labels.Has(featureLabelEVPN)
		}
		return true
	}

	// EVPN tests: only include if EVPN is enabled in the cluster
	evpnEnabled := ocpInfra.CheckForEVPN()
	if !evpnEnabled && spec.Labels.Has(featureLabelEVPN) {
		return false
	}

	// Future feature-based filters can be added here

	// FUP: not having to detect the environment, and just be able to
	// run what we want through the definition of the appropriate test
	// suites

	return true
}

func main() {
	// Create our registry of openshift-tests extensions
	extensionRegistry := extension.NewRegistry()
	ovnTestsExtension := extension.NewExtension("openshift", "payload", "ovn-kubernetes")
	// TODO: register test images using tests extension
	// add ovn-kubernetes test suites into openshift suites
	// by default, we treat all tests as parallel and only expose tests as Serial if the appropriate label is added - "Serial"
	ovnTestsExtension.AddSuite(extension.Suite{
		Name: "ovn-kubernetes/conformance/serial",
		Parents: []string{
			"openshift/conformance/serial",
		},
		Qualifiers: []string{`labels.exists(l, l == "Serial")`},
	})

	ovnTestsExtension.AddSuite(extension.Suite{
		Name: "ovn-kubernetes/conformance/parallel",
		Parents: []string{
			"openshift/conformance/parallel",
		},
		Qualifiers: []string{`!labels.exists(l, l == "Serial")`},
	})

	specs, err := ginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite(extensiontests.AllTestsIncludingVendored())
	if err != nil {
		panic(err)
	}

	// Initialize cluster infra if kubeconfig is available. When no kubeconfig is present
	// (e.g. during "info" or "list tests") or infra initialization fails, ocpInfra stays
	// nil; in that case all eligible tests are included except those gated on infrastructure
	// we cannot verify (e.g. EVPN), while tests without a lifecycle and explicitly disabled
	// tests remain excluded (see shouldIncludeTest).
	// Ensure calling methods do not log any output, as this can break test listing with
	// errors such as: "invalid character 'I' looking for beginning of value"
	cfg, cfgErr := getKubeConfig()
	var infraErr error
	if cfgErr == nil {
		infra, err := ocpinfraprovider.New(cfg)
		if err != nil {
			infraErr = err
		} else {
			ocpInfra = infra
			infraprovider.Set(ocpInfra)
		}
	}

	// Initialization for kube ginkgo test framework needs to run before all tests execute
	specs.AddBeforeAll(func() {
		if cfgErr != nil {
			panic(cfgErr)
		}
		if infraErr != nil {
			panic(infraErr)
		}
		if err := initializeTestFramework(os.Getenv("TEST_PROVIDER"), cfg); err != nil {
			panic(err)
		}
	})

	informingTests := sets.New(test.InformingTests...)
	blockingTests := sets.New(test.BlockingTests...)

	specs.Walk(func(spec *extensiontests.ExtensionTestSpec) {
		for _, label := range getTestExtensionLabels() {
			spec.Labels.Insert(label)
		}

		// Exclude Network Segmentation tests on SingleReplica topology (e.g., MicroShift, SNO)
		// These tests require at least 2 nodes and will fail on single-node deployments
		if spec.Labels.Has(featureLabelNetworkSegmentation) {
			spec.Exclude(extensiontests.TopologyEquals("SingleReplica"))
		}

		if annotations, ok := generated.AppendedAnnotations[spec.Name]; ok {
			spec.Name += " " + annotations
		}

		// prepend other labels by matching on existing spec labels
		for _, label := range getPrependLabels(spec.Labels) {
			spec.Labels.Insert(label)
		}

		spec.Name = generatePrependedLabelsStr(spec.Labels) + " " + spec.Name // prepend ginkgo labels to test name

		switch {
		case informingTests.Has(spec.Name):
			spec.Lifecycle = extensiontests.LifecycleInforming
		case blockingTests.Has(spec.Name):
			spec.Lifecycle = extensiontests.LifecycleBlocking
		default:
			spec.Lifecycle = ""
		}
	})

	specs = specs.Select(shouldIncludeTest)

	ovnTestsExtension.AddSpecs(specs)
	extensionRegistry.Register(ovnTestsExtension)
	root := &cobra.Command{
		Long: "OVN-Kubernetes tests extension for OpenShift",
	}
	root.AddCommand(
		cmd.DefaultExtensionCommands(extensionRegistry)...,
	)
	if err := func() error {
		return root.Execute()
	}(); err != nil {
		os.Exit(1)
	}
}
