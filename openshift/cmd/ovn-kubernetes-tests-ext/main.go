package main

import (
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
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/ipalloc"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/openshift-eng/openshift-tests-extension/pkg/util/sets"
	"github.com/spf13/cobra"

	"k8s.io/client-go/kubernetes"

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
	featureLabelEgressIP            = "Feature:EgressIP"
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

	// Without cluster access, include all eligible tests
	if ocpInfra == nil {
		return true
	}

	// EVPN tests: only include if EVPN is enabled in the cluster
	evpnEnabled := ocpInfra.CheckForEVPN()
	if !evpnEnabled && spec.Labels.Has(featureLabelEVPN) {
		return false
	}

	// EgressIP tests: include EgressIP tests only for baremetal cluster
	// Run LGW and IPv4 specific tests on the cluster which is eligible.
	canRunEgressIP := ocpInfra.CheckForEgressIP()
	v4, _ := ocpInfra.GetIPAddressFamily()
	if !canRunEgressIP && spec.Labels.Has(featureLabelEgressIP) {
		return false
	}
	if os.Getenv("OVN_GATEWAY_MODE") != "local" &&
		strings.Contains(spec.Name, "LGW") {
		return false
	}
	if !v4 && strings.Contains(spec.Name, "IPv4") {
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
			deploymentconfig.Set(ocpdeploymentconfig.New())
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
		kubeClient, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			panic(err)
		}
		err = ipalloc.InitPrimaryIPAllocator(kubeClient.CoreV1().Nodes())
		if err != nil {
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

		// Track labels from annotations separately to avoid prepending them
		annotationLabels := sets.New[string]()
		if annotations, ok := generated.AppendedAnnotations[spec.Name]; ok {
			spec.Name += " " + annotations
			// Parse labels from annotations (e.g., "[Serial][Suite:openshift/conformance/serial]")
			// and add them to spec.Labels so suite qualifiers can filter on them
			for _, label := range parseLabelsFromAnnotation(annotations) {
				spec.Labels.Insert(label)
				annotationLabels.Insert(label)
			}
		}

		// prepend other labels by matching on existing spec labels
		for _, label := range getPrependLabels(spec.Labels) {
			spec.Labels.Insert(label)
		}

		// Prepend labels, excluding those already in annotations
		spec.Name = generatePrependedLabelsStr(spec.Labels, annotationLabels) + " " + spec.Name

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
