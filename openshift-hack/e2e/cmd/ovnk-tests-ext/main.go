package main

import (
	"os"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/openshift/ovn-kubernetes/openshift-hack/e2e/pkg/generated"
	"github.com/spf13/cobra"

	_ "github.com/ovn-org/ovn-kubernetes/test/e2e"
	_ "k8s.io/kubernetes/test/e2e"
)

func main() {
	// Create our registry of openshift-tests extensions
	extensionRegistry := extension.NewRegistry()
	ovnTestsExtension := extension.NewExtension("openshift", "payload", "ovn-kubernetes")
	extensionRegistry.Register(ovnTestsExtension)
	// add ovn-kubernetes test suites into openshift suites
	ovnTestsExtension.AddSuite(extension.Suite{
		Name: "ovn-kubernetes/conformance/serial",
		Parents: []string{
			"openshift/conformance/serial",
		},
		Qualifiers: []string{`!labels.exists(l, l == "Serial") && labels.exists(l, l == "Conformance")`},
	})

	ovnTestsExtension.AddSuite(extension.Suite{
		Name: "ovn-kubernetes/conformance/parallel",
		Parents: []string{
			"openshift/conformance/parallel",
		},
		Qualifiers: []string{`!labels.exists(l, l == "Parallel") && labels.exists(l, l == "Conformance")`},
	})

	specs, err := ginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(err)
	}
	// Initialization for kube ginkgo test framework needs to run before all tests execute
	specs.AddBeforeAll(func() {
		if err := initializeTestFramework(os.Getenv("TEST_PROVIDER")); err != nil {
			panic(err)
		}
	})
	specs.Walk(func(spec *extensiontests.ExtensionTestSpec) {
		if annotations, ok := generated.Annotations[spec.Name]; ok {
			spec.Name += " " + annotations
		}
	})
	ovnTestsExtension.AddSpecs(specs)
	// Cobra stuff
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
