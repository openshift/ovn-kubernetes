// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	deploymentconfigapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/diagnostics"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/ipalloc"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/label"

	deploymentgeneric "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/configs/generic"
	deploymentkind "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/configs/kind"
	infraproviderkind "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/providers/kind"
	infraproviderssh "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/providers/ssh"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
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

	// Preload e2e test images into the cluster to avoid runtime pull
	// failures and timeouts during test execution.
	infraprovider.Get().PreloadImages(images.Required())

	_, err := framework.LoadClientset()
	framework.ExpectNoError(err)
	config, err := framework.LoadConfig()
	framework.ExpectNoError(err)
	client, err := clientset.NewForConfig(config)
	framework.ExpectNoError(err, "k8 clientset is required to list nodes")
	if os.Getenv(uplinkDPUGatewayNetworkEnv) == "" {
		err = ipalloc.InitPrimaryIPAllocator(client.CoreV1().Nodes())
		framework.ExpectNoError(err, "failed to initialize node primary IP allocator")
	} else {
		framework.Logf("Skipping primary IP allocator initialization for DPU Uplink e2e")
	}
})

// required due to go1.13 issue: https://github.com/onsi/ginkgo/issues/602
func TestMain(m *testing.M) {
	// Register test flags, then parse flags.
	handleFlags()
	ProcessTestContextAndSetupLogging()

	// Set up infrastructure provider and deployment config.
	// OVN_TEST_INFRA_PROVIDER=ssh selects the remote container-runtime SSH
	// provider (see test/e2e/infraprovider/providers/ssh). The upstream guardrail
	// runs it against a local KinD cluster whose nodes are containers on the SSH
	// host's runtime daemon.
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OVN_TEST_INFRA_PROVIDER"))) {
	case "", "kind":
		infraprovider.Set(infraproviderkind.New())
	case "ssh":
		cfg, err := infraproviderssh.ConfigFromEnv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to configure ssh infra provider: %v\n", err)
			os.Exit(1)
		}
		// When the ssh provider runs against a local KinD cluster (the upstream
		// guardrail), reuse KinD's image preload (local pull + `kind load`) so
		// required images reach the node image stores. This only works when the SSH
		// target is the same machine as the test runner (localhost); for a remote
		// SSH host images must be preloaded out of band.
		if infraprovider.IsKind() && infraproviderssh.IsLocalHost(cfg.Host) {
			kindForPreload := infraproviderkind.New()
			cfg.ImagePreloader = func(images []string) error {
				kindForPreload.PreloadImages(images)
				return nil
			}
		}
		sshProvider, err := infraproviderssh.New(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create ssh infra provider: %v\n", err)
			os.Exit(1)
		}
		infraprovider.Set(sshProvider)
	default:
		fmt.Fprintf(os.Stderr, "unknown OVN_TEST_INFRA_PROVIDER %q (expected \"kind\" or \"ssh\")\n",
			os.Getenv("OVN_TEST_INFRA_PROVIDER"))
		os.Exit(1)
	}
	deploymentconfig.Set(selectDeploymentConfig())

	code := m.Run()
	// Best-effort teardown: close providers that hold long-lived connections
	// (e.g. the ssh provider's cached SSH client) before exiting, preserving the
	// test exit code.
	if closer, ok := infraprovider.Get().(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "infra provider close: %v\n", err)
		}
	}
	os.Exit(code)
}

// selectDeploymentConfig chooses deployment metadata independently from the infra
// provider. KinD contexts use the KinD deployment config. Non-KinD contexts fall
// back to generic KinD-like defaults so TestMain does not panic; that does not
// by itself make the full e2e suite runnable on arbitrary clusters.
func selectDeploymentConfig() deploymentconfigapi.DeploymentConfig {
	if infraprovider.IsKind() {
		return deploymentkind.New()
	}
	return deploymentgeneric.New()
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
