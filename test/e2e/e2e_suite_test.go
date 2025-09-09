package e2e

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/diagnostics"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/ipalloc"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/label"

	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
	"k8s.io/kubernetes/test/e2e/framework"
	e2econfig "k8s.io/kubernetes/test/e2e/framework/config"
)

// https://github.com/kubernetes/kubernetes/blob/v1.16.4/test/e2e/e2e_test.go#L62

// handleFlags sets up all flags and parses the command line.
func handleFlags() {
	e2econfig.CopyFlags(e2econfig.Flags, flag.CommandLine)
	framework.RegisterCommonFlags(flag.CommandLine)
	framework.RegisterClusterFlags(flag.CommandLine)
	diagnostics.RegisterFlags(flag.CommandLine)
	flag.StringVar(&reportPath, "report-path", "/tmp/kind/logs", "the path to be used to dump test failure information")
	flag.Parse()
}

var _ = ginkgo.BeforeSuite(func() {
	// Make sure the framework's kubeconfig is set.
	gomega.Expect(framework.TestContext.KubeConfig).NotTo(gomega.Equal(""), fmt.Sprintf("%s env var not set", clientcmd.RecommendedConfigPathEnvVar))

	_, err := framework.LoadClientset()
	framework.ExpectNoError(err)
	config, err := framework.LoadConfig()
	framework.ExpectNoError(err)
	client, err := clientset.NewForConfig(config)
	framework.ExpectNoError(err, "k8 clientset is required to list nodes")
	err = ipalloc.InitPrimaryIPAllocator(client.CoreV1().Nodes())
	framework.ExpectNoError(err, "failed to initialize node primary IP allocator")
})

// required due to go1.13 issue: https://github.com/onsi/ginkgo/issues/602
func TestMain(m *testing.M) {
	// Register test flags, then parse flags.
	handleFlags()
	ProcessTestContextAndSetupLogging()

	// Set up infrastructure provider and deployment config
	config, err := framework.LoadConfig()
	if err != nil {
		klog.Fatalf("Failed to load config: %v", err)
	}
	if err := infraprovider.Set(config); err != nil {
		klog.Fatalf("Failed to configure infrastructure provider: %v", err)
	}
	if err := deploymentconfig.Set(config); err != nil {
		klog.Fatalf("Failed to detect deployment configuration: %v", err)
	}

	os.Exit(m.Run())
}

func TestE2E(t *testing.T) {
	if testing.Short() {
		return
	}
	if framework.TestContext.ReportDir != "" {
		if err := os.MkdirAll(framework.TestContext.ReportDir, 0755); err != nil {
			klog.Errorf("Failed creating report directory: %v", err)
		}
	}
	gomega.RegisterFailHandler(framework.Fail)
	ginkgo.RunSpecs(t, "E2E Suite", label.ComponentName())
}
