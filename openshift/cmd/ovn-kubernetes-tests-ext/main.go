package main

import (
	"os"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/openshift/test/generated"
	// import ovn-kubernetes tests
	_ "github.com/ovn-org/ovn-kubernetes/test/e2e"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/spf13/cobra"

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

// upstreamFeatureEnv mirrors the environment variables the upstream KinD test
// lanes export. The upstream suite reads them to decide whether a feature is
// available, and skips whole contexts when they are unset. OpenShift always
// runs OVN interconnect and ships user defined networks, so declare both as
// enabled here. Existing values win so a caller can still turn a feature off.
var upstreamFeatureEnv = map[string]string{
	"OVN_ENABLE_INTERCONNECT":     "true",
	"ENABLE_NETWORK_SEGMENTATION": "true",
}

func setUpstreamFeatureEnv() {
	for k, v := range upstreamFeatureEnv {
		if _, present := os.LookupEnv(k); present {
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			panic(err)
		}
	}
}

// egressIPStep5bSpec names the EgressIP spec that carries the pod to pod
// assertion this branch validates.
const egressIPStep5bSpec = "Should validate the egress IP functionality against remote hosts disabling egress nodes with egress-assignable label"

// keepSpec decides whether a spec is offered to OpenShift.
//
// The EgressIP suite is narrowed down to the spec that exercises step 5b. Every
// EgressIP spec mutates state the whole cluster shares, and OpenShift runs them
// from a parallel suite, so the rest of the suite only produces failures in
// which one spec has torn down another spec's EgressIP object, node labels or
// DaemonSet rollout. What is left is serialized in test/e2e/egressip.go.
func keepSpec(name string) bool {
	if strings.Contains(name, "[Disabled:") {
		return false
	}
	if !strings.Contains(name, "e2e egress IP validation") {
		return true
	}
	return strings.Contains(name, egressIPStep5bSpec)
}

func main() {
	setUpstreamFeatureEnv()

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
		for _, label := range getTestExtensionLabels() {
			spec.Labels.Insert(label)
		}

		if annotations, ok := generated.AppendedAnnotations[spec.Name]; ok {
			spec.Name += " " + annotations
		}
		spec.Name = generatePrependedLabelsStr(spec.Labels) + " " + spec.Name // prepend ginkgo labels to test name
	})

	specs = specs.Select(func(spec *extensiontests.ExtensionTestSpec) bool {
		return keepSpec(spec.Name)
	})

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
