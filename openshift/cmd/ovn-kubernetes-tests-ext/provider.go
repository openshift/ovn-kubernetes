package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ocphacke2e "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kclientset "k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/test/e2e/framework"
)

// partially copied from https://github.com/openshift/origin/blob/17371a2c6a91e0426045fdd0ab3455c5b457622a/pkg/test/extensions/binary.go
// and https://github.com/openshift/origin/blob/e0a2fbc82ac1f97dc4fa84a00ed5739c94366926/pkg/clioptions/clusterdiscovery/provider.go
func initializeTestFramework(cfg *restclient.Config, provider string) error {
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

	// update testContext with loaded config
	testContext := &framework.TestContext
	testContext.Provider = config.ProviderName
	testContext.CloudConfig = framework.CloudConfig{
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
	testContext.AllowedNotReadyNodes = 0
	testContext.MinStartupPods = -1
	testContext.MaxNodesToGather = 0
	testContext.KubeConfig = os.Getenv("KUBECONFIG")
	gomega.Expect(testContext.KubeConfig).NotTo(gomega.BeEmpty())
	testContext.DeleteNamespace = os.Getenv("DELETE_NAMESPACE") != "false"
	testContext.VerifyServiceAccount = false
	//TODO: do we really need the file systems?
	testContext.KubectlPath = "oc"
	if ad := os.Getenv("ARTIFACT_DIR"); len(strings.TrimSpace(ad)) == 0 {
		os.Setenv("ARTIFACT_DIR", filepath.Join(os.TempDir(), "artifacts"))
	}
	// "debian" is used when not set. At least GlusterFS tests need "custom".
	// (There is no option for "rhel" or "centos".)
	testContext.NodeOSDistro = "custom"
	testContext.MasterOSDistro = "custom"
	// set the host variable for kubectl
	testContext.Host = cfg.Host
	testContext.CreateTestingNS = func(ctx context.Context, baseName string, c kclientset.Interface, labels map[string]string) (*corev1.Namespace, error) {
		return ocphacke2e.CreateTestingNS(ctx, baseName, c, labels, true)
	}
	testContext.DumpLogsOnFailure = true
	testContext.ReportDir = os.Getenv("TEST_JUNIT_DIR")
	return nil
}

func getKubeConfig() (*restclient.Config, error) {
	kubeConfig := os.Getenv("KUBECONFIG")
	if kubeConfig == "" {
		return nil, fmt.Errorf("KUBECONFIG env variable not set")
	}
	if _, err := os.Stat(kubeConfig); err != nil {
		return nil, fmt.Errorf("KUBECONFIG file %q not accessible: %w", kubeConfig, err)
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfig}, &clientcmd.ConfigOverrides{})
	return clientConfig.ClientConfig()
}
