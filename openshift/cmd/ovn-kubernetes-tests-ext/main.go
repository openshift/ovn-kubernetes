package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test"
	ocpdeploymentconfig "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/generated"
	ocpinfraprovider "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/infraprovider"

	// import ovn-kubernetes tests
	_ "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/spf13/cobra"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/rest"

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

	// Without cluster access (or) kind cluster, include all eligible tests
	if ocpInfra == nil {
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

// initializeInfraProvider initializes the infrastructure provider based on cluster type.
// For kind clusters, it uses SSH-based command execution for OTE mode.
// For OpenShift clusters, it uses the standard OpenShift infrastructure provider.
func initializeInfraProvider(cfg *rest.Config) error {
	if infraprovider.IsKind() {
		infra, err := ocpinfraprovider.InitializeKindInfra()
		if err != nil {
			return fmt.Errorf("failed to initialize kind infrastructure: %w", err)
		}
		infraprovider.Set(infra)
	} else {
		infra, err := ocpinfraprovider.New(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize OpenShift infrastructure: %w", err)
		}
		infraprovider.Set(infra)
		// Set ocpInfra only for OpenShift clusters (not for kind)
		ocpInfra = infra
	}
	deploymentconfig.Set(ocpdeploymentconfig.New())
	return nil
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
	// (e.g. during "info" or "list tests"), ocpInfra stays nil and all tests are listed.
	// Ensure calling methods do not log any output, as this can break test listing with
	// errors such as: "invalid character 'I' looking for beginning of value"
	cfg, cfgErr := getKubeConfig()
	var infraErr error
	if cfgErr == nil {
		infraErr = initializeInfraProvider(cfg)
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
