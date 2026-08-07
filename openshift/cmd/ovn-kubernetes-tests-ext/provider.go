package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ocphacke2e "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/reporters"
	"github.com/onsi/ginkgo/v2/types"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/test/e2e/framework"
)

// partially copied from https://github.com/openshift/origin/blob/17371a2c6a91e0426045fdd0ab3455c5b457622a/pkg/test/extensions/binary.go
// and https://github.com/openshift/origin/blob/e0a2fbc82ac1f97dc4fa84a00ed5739c94366926/pkg/clioptions/clusterdiscovery/provider.go
func initializeTestFramework(provider string, cfg *rest.Config) error {
	if len(provider) == 0 {
		provider = "{\"type\":\"skeleton\"}"
	}
	providerInfo := &ClusterConfiguration{}
	if err := json.Unmarshal([]byte(provider), &providerInfo); err != nil {
		return fmt.Errorf("provider must be a JSON object with the 'type' key at a minimum: %v", err)
	}
	if len(providerInfo.ProviderName) == 0 {
		return fmt.Errorf("provider must be a JSON object with the 'type' key")
	}
	config := &ClusterConfiguration{}
	if err := json.Unmarshal([]byte(provider), config); err != nil {
		return fmt.Errorf("provider must decode into the ClusterConfig object: %v", err)
	}

	// update framework.TestContext with loaded config
	framework.TestContext.Provider = config.ProviderName
	framework.TestContext.CloudConfig = framework.CloudConfig{
		ProjectID:   config.ProjectID,
		Region:      config.Region,
		Zone:        config.Zone,
		Zones:       config.Zones,
		NumNodes:    config.NumNodes,
		MultiMaster: config.MultiMaster,
		MultiZone:   config.MultiZone,
		ConfigFile:  config.ConfigFile,
		Provider:    framework.NullProvider{},
	}
	framework.TestContext.AllowedNotReadyNodes = 0
	framework.TestContext.MinStartupPods = -1
	framework.TestContext.MaxNodesToGather = 0
	framework.TestContext.KubeConfig = os.Getenv("KUBECONFIG")
	gomega.Expect(framework.TestContext.KubeConfig).NotTo(gomega.BeEmpty())
	framework.TestContext.DeleteNamespace = os.Getenv("DELETE_NAMESPACE") != "false"
	framework.TestContext.VerifyServiceAccount = true
	//TODO: do we really need the file systems?
	framework.TestContext.KubectlPath = "oc"
	if ad := os.Getenv("ARTIFACT_DIR"); len(strings.TrimSpace(ad)) == 0 {
		os.Setenv("ARTIFACT_DIR", filepath.Join(os.TempDir(), "artifacts"))
	}
	// "debian" is used when not set. At least GlusterFS tests need "custom".
	// (There is no option for "rhel" or "centos".)
	framework.TestContext.NodeOSDistro = "custom"
	framework.TestContext.MasterOSDistro = "custom"
	// set the host variable for kubectl
	gomega.Expect(cfg).NotTo(gomega.BeNil())
	framework.TestContext.Host = cfg.Host
	framework.TestContext.CreateTestingNS = func(ctx context.Context, baseName string, c kclientset.Interface, labels map[string]string) (*corev1.Namespace, error) {
		return ocphacke2e.CreateTestingNS(ctx, baseName, c, labels, true)
	}
	framework.TestContext.DumpLogsOnFailure = true
	framework.TestContext.ReportDir = os.Getenv("TEST_JUNIT_DIR")
	return nil
}

// WriteJUnitReport generates a JUnit file that is shorter than the one
// normally written by `ginkgo --junit-report`. This is needed because the full
// report can become too large for tools like Spyglass
// (https://github.com/kubernetes/kubernetes/issues/111510).
func writeJUnitReport(report ginkgo.Report, filename string) error {
	config := reporters.JunitReportConfig{
		// Remove details for specs where we don't care.
		OmitTimelinesForSpecState: types.SpecStatePassed | types.SpecStateSkipped,

		// Don't write <failure message="summary">. The same text is
		// also in the full text for the failure. If we were to write
		// both, then tools like kettle and spyglass would concatenate
		// the two strings and thus show duplicated information.
		OmitFailureMessageAttr: true,

		// All labels are also part of the spec texts in inline [] tags,
		// so we don't need to write them separately.
		OmitSpecLabels: true,
	}

	return reporters.GenerateJUnitReportWithConfig(report, filename, config)
}

func getKubeConfig() (*restclient.Config, error) {
	kubeConfig := os.Getenv("KUBECONFIG")
	if kubeConfig == "" {
		return nil, fmt.Errorf("KUBECONFIG env variable not set")
	}
	if _, err := os.Stat(kubeConfig); err != nil {
		return nil, fmt.Errorf("KUBECONFIG file %q not accessible: %w", kubeConfig, err)
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfig},
		&clientcmd.ConfigOverrides{})
	return clientConfig.ClientConfig()
}
