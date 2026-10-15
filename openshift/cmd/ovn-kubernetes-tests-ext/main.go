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
	featureLabelNoOverlay           = "Feature:NoOverlay"
	featureLabelRouteAdvertisements = "Feature:RouteAdvertisements"

	// defaultNetworkNoOverlaySuite identifies the no-overlay specs that assert on
	// the cluster default network rather than on a user defined network. They can
	// only run on a cluster installed with transport=NoOverlay.
	defaultNetworkNoOverlaySuite = "No-Overlay: Default network is enabled with no-overlay"
)

// Name fragments identifying specs that exercise no-overlay with managed
// routing, where ovn-kubernetes owns the BGP configuration. They need the
// cluster internal BGP fabric to be configured, see HasManagedBGP.
//
// The leading space matters: without it "unmanaged routing", used by the specs
// that bring their own RouteAdvertisements, would match too.
var managedRoutingNameFragments = []string{
	" managed routing",
	" managed mode routing",
}

// requiresManagedBGP reports whether the spec exercises managed routing.
func requiresManagedBGP(name string) bool {
	for _, fragment := range managedRoutingNameFragments {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

// shouldIncludeTest determines if a test should be included based on cluster capabilities
// and test labels. When ocpInfra is nil (no cluster access), all tests are included.
func shouldIncludeTest(spec *extensiontests.ExtensionTestSpec) bool {
	// Disable specs that are not explicitly assigned a lifecycle
	if spec.Lifecycle == "" {
		return false
	}
	// Exclude explicitly disabled tests
	if strings.Contains(spec.Name, "[Disabled:") {
		return false
	}

	// Without cluster access, include all eligible tests
	if ocpInfra == nil {
		return true
	}

	// EVPN tests: only include if EVPN is enabled in the cluster
	isEVPN := spec.Labels.Has(featureLabelEVPN)
	evpnEnabled := ocpInfra.CheckForEVPN()
	if !evpnEnabled && isEVPN {
		return false
	}

	// BGP tests: only include if the cluster advertises routes through FRR and
	// an external FRR router is reachable to inspect those routes with. EVPN
	// specs are left to the stricter EVPN check above, so that this does not
	// become a second way for the blocking EVPN suite to disappear.
	if !isEVPN && spec.Labels.Has(featureLabelRouteAdvertisements) && !ocpInfra.CheckForRouteAdvertisements() {
		return false
	}

	// No-overlay tests: only include if the cluster can run networks
	// unencapsulated. Specs covering the cluster default network additionally
	// require that network to have been installed with transport=NoOverlay.
	if spec.Labels.Has(featureLabelNoOverlay) {
		if !ocpInfra.CheckForNoOverlay() {
			return false
		}
		if strings.Contains(spec.Name, defaultNetworkNoOverlaySuite) && !ocpInfra.IsDefaultNetworkNoOverlay() {
			return false
		}
		// Managed routing has ovn-kubernetes create the RouteAdvertisements and
		// the FRRConfiguration itself, which it only does once the cluster
		// internal BGP fabric is configured.
		if requiresManagedBGP(spec.Name) && !ocpInfra.HasManagedBGP() {
			return false
		}
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
	// register OVN-Kubernetes e2e images to the openshift-tests extension
	if err := registerTestImages(ovnTestsExtension); err != nil {
		panic(err)
	}
	// add ovn-kubernetes test suites into openshift suites
	// by default, we treat all tests as parallel and only expose tests as Serial if the appropriate label is added - "Serial"
	// No Parents: these tests run only in ovn-kubernetes/conformance/*, not the product-wide openshift/conformance/*.
	// To inject a subset later, label those tests and add a suite with Parents=[openshift/conformance/parallel] + a matching qualifier.
	ovnTestsExtension.AddSuite(extension.Suite{
		Name:       "ovn-kubernetes/conformance/serial",
		Qualifiers: []string{`labels.exists(l, l == "Serial")`},
	})

	ovnTestsExtension.AddSuite(extension.Suite{
		Name:       "ovn-kubernetes/conformance/parallel",
		Qualifiers: []string{`!labels.exists(l, l == "Serial")`},
	})

	specs, err := ginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite(extensiontests.AllTestsIncludingVendored())
	if err != nil {
		panic(err)
	}

	// Initialize cluster infra if kubeconfig is available. When no kubeconfig is present
	// (e.g. during "info" or "list tests"), ocpInfra stays nil and all tests are listed.
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
