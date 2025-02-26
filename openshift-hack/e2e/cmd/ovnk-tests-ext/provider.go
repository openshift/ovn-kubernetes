package main

import (
	"fmt"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
	"strings"

	"encoding/json"
	"k8s.io/kubernetes/test/e2e/framework"
	// these are loading important global flags that we need to get and set
	_ "k8s.io/kubernetes/test/e2e"
	_ "k8s.io/kubernetes/test/e2e/lifecycle"
)

// copied directly from github.com/openshift/origin/cmd/openshift-tests/provider.go
// and github.com/openshift/origin/test/extended/util/test.go
// but with the following changes:
// - removed CSI driver init
func initializeTestFramework(provider string) error {
	if len(provider) == 0 {
		return fmt.Errorf("provider must not be empty")
	}
	providerInfo := &ClusterConfiguration{}
	if err := json.Unmarshal([]byte(provider), &providerInfo); err != nil {
		return fmt.Errorf("provider must be a JSON object with the 'type' key at a minimum: %v", err)
	}
	if len(providerInfo.ProviderName) == 0 {
		return fmt.Errorf("provider must have a name")
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
	}
	testContext.AllowedNotReadyNodes = 0
	testContext.MinStartupPods = -1
	testContext.MaxNodesToGather = 0
	testContext.KubeConfig = os.Getenv("KUBECONFIG")

	if ad := os.Getenv("ARTIFACT_DIR"); len(strings.TrimSpace(ad)) == 0 {
		os.Setenv("ARTIFACT_DIR", filepath.Join(os.TempDir(), "artifacts"))
	}

	testContext.DeleteNamespace = os.Getenv("DELETE_NAMESPACE") != "false"
	testContext.VerifyServiceAccount = false
	//testfiles.AddFileSource(e2etestingmanifests.GetE2ETestingManifestsFS())
	//TODO: do we really need the file systems?

	testContext.KubectlPath = "kubectl"
	// context.KubeConfig = KubeConfigPath()
	testContext.KubeConfig = os.Getenv("KUBECONFIG")

	// "debian" is used when not set. At least GlusterFS tests need "custom".
	// (There is no option for "rhel" or "centos".)
	testContext.NodeOSDistro = "custom"
	testContext.MasterOSDistro = "custom"

	// load and set the host variable for kubectl
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: testContext.KubeConfig}, &clientcmd.ConfigOverrides{})
	cfg, err := clientConfig.ClientConfig()
	if err != nil {
		return err
	}
	testContext.Host = cfg.Host

	//testContext.CreateTestingNS = func(ctx context.Context, baseName string, c kclientset.Interface, labels map[string]string) (*corev1.Namespace, error) {
	//	return e2e.CreateTestingNS(ctx, baseName, c, labels, true)
	//}

	gomega.RegisterFailHandler(ginkgo.Fail)

	framework.AfterReadingAllFlags(testContext)
	testContext.DumpLogsOnFailure = true

	// these constants are taken from kube e2e and used by tests
	testContext.IPFamily = "ipv4"
	if config.HasIPv6 && !config.HasIPv4 {
		testContext.IPFamily = "ipv6"
	}

	testContext.ReportDir = os.Getenv("TEST_JUNIT_DIR")

	return nil
}
