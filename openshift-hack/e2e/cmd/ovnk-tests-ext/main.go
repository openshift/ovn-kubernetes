package main

import (
	"os"
	"strings"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/openshift/ovn-kubernetes/openshift-hack/e2e/pkg/generated"
	"github.com/spf13/cobra"

	_ "github.com/ovn-org/ovn-kubernetes/test/e2e"
)

func main() {
	// Create our registry of openshift-tests extensions
	extensionRegistry := e.NewRegistry()
	ovnTestsExtension := e.NewExtension("openshift", "payload", "ovn-kubernetes")
	extensionRegistry.Register(ovnTestsExtension)
	// add ovn-kubernetes test suites into openshift suites
	ovnTestsExtension.AddSuite(e.Suite{
		Name: "ovn-kubernetes/conformance/serial",
		Parents: []string{
			"openshift/conformance/serial",
		},
		Qualifiers: []string{`!labels.exists(l, l == "Serial") && labels.exists(l, l == "Conformance")`},
	})

	ovnTestsExtension.AddSuite(e.Suite{
		Name: "ovn-kubernetes/conformance/parallel",
		Parents: []string{
			"openshift/conformance/parallel",
		},
		Qualifiers: []string{`!labels.exists(l, l == "Parallel") && labels.exists(l, l == "Conformance")`},
	})

	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(err)
	}
	// Initialization for kube ginkgo test framework needs to run before all tests execute
	specs.AddBeforeAll(func() {
		if err := initializeTestFramework(os.Getenv("TEST_PROVIDER")); err != nil {
			panic(err)
		}
	})
	// Annotations get prepended to test names, these are additions to upstream
	// tests for controlling skips, suite membership, etc.
	//
	// TODO:
	//		- Remove this annotation code, and migrate to Labels/Tags and
	//		  the environmental skip code from the enhancement once its implemented.
	//		- Make sure to account for test renames that occur because of removal of these
	//		  annotations
	specs.Walk(func(spec *extensiontests.ExtensionTestSpec) {
		if annotations, ok := generated.Annotations[spec.Name]; ok {
			spec.Name += " " + annotations
		}
	})
	specs = specs.Select(func(spec *extensiontests.ExtensionTestSpec) bool {
		return strings.Contains(spec.Name, "[ovn-kuberetes]")
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
