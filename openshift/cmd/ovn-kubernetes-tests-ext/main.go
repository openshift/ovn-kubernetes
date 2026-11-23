// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test"
	ocpdeploymentconfig "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/generated"
	ocpinfraprovider "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/infraprovider"
	deploymentconfigapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	// import ovn-kubernetes tests
	_ "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/allocators"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"

	kclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

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
	featureLabelEgressIP            = "Feature:EgressIP"
	featureLabelMACSecurity         = "Feature:MACSecurity"
	// Test constants used for test categorization and filtering
	EIPSecondaryNetworkTestPrefix = "secondary-host-eip"
	// nofloodMACBindingDescribe is the Describe text of the upstream no-flood
	// MAC binding mirroring specs that run against isolated external containers.
	nofloodMACBindingDescribe = "MAC binding mirroring with ARP/NDP flood disabled"
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
	if ocpInfra == nil || !ocpInfra.HasClusterInfra() {
		return true
	}

	// EVPN tests: only include if EVPN is enabled in the cluster
	evpnEnabled := ocpInfra.CheckForEVPN()
	if !evpnEnabled && spec.Labels.Has(featureLabelEVPN) {
		return false
	}

	// secondary-host-eip tests: only include on platforms with a
	// pre-configured secondary network (currently baremetal only)
	if strings.Contains(spec.Name, EIPSecondaryNetworkTestPrefix) && !ocpInfra.HasSecondaryHostEIPSupport() {
		return false
	}
	// EgressIP host-networked pods tests require opening ports (30000 to 32767) on cluster nodes,
	// which is not yet configured on bastion-based platforms.
	if strings.Contains(spec.Name, "Should validate the egress IP SNAT functionality against host-networked pods") && ocpInfra.IsCloudPlatform() {
		return false
	}
	// The no-flood MAC binding mirroring specs need two external containers
	// with their own IP and MAC on the cluster's L2 network. On cloud
	// platforms the external containers share the bastion's IP, so the specs
	// could pass without exercising two distinct hosts.
	if strings.Contains(spec.Name, nofloodMACBindingDescribe) && ocpInfra.IsCloudPlatform() {
		return false
	}
	// On GCP, nodes have a /32 primary interface address
	// (k8s.ovn.org/node-primary-ifaddr: {"ipv4":"10.0.128.x/32"}), so
	// isOVNNetworkIP returns false for any EgressIP because no IP other
	// than the node's own can fall within a /32 network. This causes
	// BridgeEIPAddrManager to skip assigning the EIP to the bridge
	// interface, breaking IFA_PROTO verification. On OpenShift, network
	// segmentation is enabled by default so the IFA_PROTO check runs for
	// all network types including Cluster Default — hence the
	// "disabling egress nodes" test is also skipped for Cluster Default.
	// Tracking via https://redhat.atlassian.net/browse/OCPBUGS-122016.
	if ocpInfra.IsGCPPlatform() && spec.Labels.Has(featureLabelEgressIP) &&
		(spec.Labels.Has(featureLabelNetworkSegmentation) || strings.Contains(spec.Name, "Primary UDN") ||
			strings.Contains(spec.Name, "disabling egress nodes with egress-assignable label")) {
		return false
	}

	// FUP: not having to detect the environment, and just be able to
	// run what we want through the definition of the appropriate test
	// suites

	return true
}

// setUpTestProcess initializes the kube ginkgo test framework and the cluster
// for the tests this process runs.
func setUpTestProcess(cfg *rest.Config, cfgErr, infraErr error) error {
	if cfgErr != nil {
		return cfgErr
	}
	if infraErr != nil {
		return infraErr
	}
	if err := initializeTestFramework(os.Getenv("TEST_PROVIDER"), cfg); err != nil {
		return err
	}
	client, err := kclientset.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create k8s clientset: %w", err)
	}
	if err := ocpInfra.EnableSecondaryForwarding(client); err != nil {
		return fmt.Errorf("failed to enable secondary network forwarding: %w", err)
	}
	if err := allocators.InitPrimaryIPAllocator(client.CoreV1().Nodes()); err != nil {
		return fmt.Errorf("failed to initialize node primary IP allocator: %w", err)
	}
	return nil
}

func main() {
	// Create our registry of openshift-tests extensions
	extensionRegistry := extension.NewRegistry()
	ovnTestsExtension := extension.NewExtension("openshift", "payload", "ovn-kubernetes")
	// add ovn-kubernetes test suites into openshift suites
	// by default, we treat all tests as parallel and only expose tests as Serial if the appropriate label is added - "Serial"
	// No Parents: these tests run only in ovn-kubernetes/conformance/*, not the product-wide openshift/conformance/*.
	// To inject a subset later, label those tests and add a suite with Parents=[openshift/conformance/parallel] + a matching qualifier.
	ovnTestsExtension.AddSuite(extension.Suite{
		Name:        "ovn-kubernetes/conformance/serial",
		Parallelism: 1,
		Qualifiers:  []string{"name.contains('[Suite:ovn-kubernetes/conformance/serial') && !name.contains('[Suite:ovn-kubernetes/conformance/serial/virtualization')"},
	})

	ovnTestsExtension.AddSuite(extension.Suite{
		Name:       "ovn-kubernetes/conformance/parallel",
		Qualifiers: []string{"name.contains('[Suite:ovn-kubernetes/conformance/parallel') && !name.contains('[Suite:ovn-kubernetes/conformance/parallel/virtualization')"},
	})

	// The dedicated virtualization OTE lane selects this suite directly.
	ovnTestsExtension.AddSuite(extension.Suite{
		Name:        "ovn-kubernetes/conformance/serial/virtualization",
		Parallelism: 1,
		Qualifiers:  []string{"name.contains('[Suite:ovn-kubernetes/conformance/serial/virtualization]')"},
	})

	// Initialize cluster infra if kubeconfig is available. When no kubeconfig is present
	// (e.g. during "info" or "list tests"), ocpInfra stays nil and all tests are listed.
	// Must happen before BuildExtensionTestSpecsFromOpenShiftGinkgoSuite because Ginkgo
	// Entry() arguments are evaluated during tree construction, triggering UDN subnet
	// allocation which queries the infra provider for network exclusions.
	// Ensure calling methods do not log any output, as this can break test listing with
	// errors such as: "invalid character 'I' looking for beginning of value"
	cfg, cfgErr := getKubeConfig()
	// Set deployment config before infra provider initialization, because
	// ocpinfraprovider.New → configureTestEnvs calls deploymentconfig.Get().
	deploymentconfig.Set(ocpdeploymentconfig.New(cfg))
	var infraErr error
	if cfgErr == nil {
		infra, err := ocpinfraprovider.New(cfg)
		if err != nil {
			infraErr = err
		} else {
			ocpInfra = infra
		}
	}
	// Always set the infra provider so that tree-construction-time calls
	// (e.g. UDN subnet allocation) do not panic. When no cluster is
	// available, the provider returns safe zero-value defaults.
	if ocpInfra == nil {
		ocpInfra = &ocpinfraprovider.OpenshiftInfraProvider{}
	}
	infraprovider.Set(ocpInfra)

	// The no-flood group test re-executes this binary to run its specs in one
	// Ginkgo run, which has to start before the Ginkgo tree is built.
	if nofloodMACBindingGroup.Reentered() {
		os.Exit(nofloodMACBindingGroup.RunNative(func() error {
			return setUpTestProcess(cfg, cfgErr, infraErr)
		}))
	}

	specs, err := ginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite(extensiontests.AllTestsIncludingVendored())
	if err != nil {
		panic(err)
	}
	specs, err = nofloodMACBindingGroup.Collect(specs, generated.AppendedAnnotations)
	if err != nil {
		panic(err)
	}

	// Add the agnhost image to the required images
	deploymentconfig.Get().AddRequiredImage(deploymentconfigapi.Agnhost)
	// Register OVN-Kubernetes e2e images to the openshift-tests extension
	err = registerTestImages(ovnTestsExtension)
	if err != nil {
		panic(err)
	}

	// Initialization for kube ginkgo test framework needs to run before all tests execute
	specs.AddBeforeAll(func() {
		if err := setUpTestProcess(cfg, cfgErr, infraErr); err != nil {
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

	specs.AddAfterEach(func(res *extensiontests.ExtensionTestResult) {
		if res.Result != extensiontests.ResultFailed ||
			!strings.Contains(res.Error, ocpinfraprovider.ErrExternalInfraNotAvailable) {
			return
		}
		res.Result = extensiontests.ResultSkipped
		// Preserve the original failure as the skip reason. Consumers build the
		// JUnit skip message from Details and Output, not from Error, so the
		// reason would otherwise be lost.
		res.AddDetails("skip-reason", res.Error)
		res.Output = fmt.Sprintf("%s\nSKIPPED: %s", res.Output, res.Error)
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
