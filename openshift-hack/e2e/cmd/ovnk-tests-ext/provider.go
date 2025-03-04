package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	ocphacke2e "github.com/ovn-org/ovn-kubernetes/openshift-hack/e2e"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/reporters"
	"github.com/onsi/ginkgo/v2/types"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	kclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e/framework"
)

// partially copied from github.com/openshift/origin/cmd/openshift-tests/provider.go
// and github.com/openshift/origin/test/extended/util/test.go
func initializeTestFramework(provider string) error {
	if len(provider) == 0 {
		provider = "{\"type\":\"skeleton\"}"
	}
	providerInfo := &ClusterConfiguration{}
	if err := json.Unmarshal([]byte(provider), &providerInfo); err != nil {
		return fmt.Errorf("provider must be a JSON object with the 'type' key at a minimum: %v", err)
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
	// load and set the host variable for kubectl
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: testContext.KubeConfig}, &clientcmd.ConfigOverrides{})
	cfg, err := clientConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to get client config: %v", err)
	}
	testContext.Host = cfg.Host
	testContext.CreateTestingNS = func(ctx context.Context, baseName string, c kclientset.Interface, labels map[string]string) (*corev1.Namespace, error) {
		return ocphacke2e.CreateTestingNS(ctx, baseName, c, labels, true)
	}
	testContext.DumpLogsOnFailure = true
	// these constants are taken from kube e2e and used by tests
	testContext.IPFamily = "ipv4"
	if config.HasIPv6 && !config.HasIPv4 {
		testContext.IPFamily = "ipv6"
	}
	testContext.ReportDir = os.Getenv("TEST_JUNIT_DIR")
	if testContext.ReportDir != "" {
		// Create the directory before running the suite. If
		// --report-dir is not unusable, we should report
		// that as soon as possible. This will be done by each worker
		// in parallel, so we will get "exists" error in most of them.
		if err := os.MkdirAll(testContext.ReportDir, 0777); err != nil && !os.IsExist(err) {
			klog.Errorf("Create report dir: %v", err)
			os.Exit(1)
		}
		ginkgoDir := path.Join(testContext.ReportDir, "ginkgo")
		if testContext.ReportCompleteGinkgo || testContext.ReportCompleteJUnit {
			if err := os.MkdirAll(ginkgoDir, 0777); err != nil && !os.IsExist(err) {
				klog.Errorf("Create <report-dir>/ginkgo: %v", err)
				os.Exit(1)
			}
		}
		if testContext.ReportCompleteGinkgo {
			ginkgo.ReportAfterSuite("Ginkgo JSON report", func(report ginkgo.Report) {
				gomega.Expect(reporters.GenerateJSONReport(report, path.Join(ginkgoDir, "report.json"))).NotTo(gomega.HaveOccurred())
			})
			ginkgo.ReportAfterSuite("JUnit XML report", func(report ginkgo.Report) {
				gomega.Expect(reporters.GenerateJUnitReport(report, path.Join(ginkgoDir, "report.xml"))).NotTo(gomega.HaveOccurred())
			})
		}
		ginkgo.ReportAfterSuite("OVN-Kubernetes e2e JUnit report", func(report ginkgo.Report) {
			// With Ginkgo v1, we used to write one file per
			// parallel node. Now Ginkgo v2 automatically merges
			// all results into a report for us. The 01 suffix is
			// kept in case that users expect files to be called
			// "junit_<prefix><number>.xml".
			junitReport := path.Join(testContext.ReportDir, "junit_"+testContext.ReportPrefix+"01.xml")

			// writeJUnitReport generates a JUnit file in the e2e
			// report directory that is shorter than the one
			// normally written by `ginkgo --junit-report`. This is
			// needed because the full report can become too large
			// for tools like Spyglass
			// (https://github.com/kubernetes/kubernetes/issues/111510).
			gomega.Expect(writeJUnitReport(report, junitReport)).NotTo(gomega.HaveOccurred())
		})
	}
	// default copied from k8 e2e test framework pkg
	// Reconfigure gomega defaults. The poll interval should be suitable
	// for most tests. The timeouts are more subjective and tests may want
	// to override them, but these defaults are still better for E2E than the
	// ones from Gomega (1s timeout, 10ms interval).
	var defaultTimeouts = framework.TimeoutContext{
		Poll:                      2 * time.Second, // from the former e2e/framework/pod poll interval
		PodStart:                  5 * time.Minute,
		PodStartShort:             2 * time.Minute,
		PodStartSlow:              15 * time.Minute,
		PodDelete:                 5 * time.Minute,
		ClaimProvision:            5 * time.Minute,
		ClaimProvisionShort:       1 * time.Minute,
		DataSourceProvision:       5 * time.Minute,
		ClaimBound:                3 * time.Minute,
		PVReclaim:                 3 * time.Minute,
		PVBound:                   3 * time.Minute,
		PVCreate:                  3 * time.Minute,
		PVDelete:                  5 * time.Minute,
		PVDeleteSlow:              20 * time.Minute,
		SnapshotCreate:            5 * time.Minute,
		SnapshotDelete:            5 * time.Minute,
		SnapshotControllerMetrics: 5 * time.Minute,
		SystemPodsStartup:         10 * time.Minute,
		NodeSchedulable:           30 * time.Minute,
		SystemDaemonsetStartup:    5 * time.Minute,
		NodeNotReady:              3 * time.Minute,
	}
	gomega.SetDefaultEventuallyPollingInterval(defaultTimeouts.Poll)
	gomega.SetDefaultConsistentlyPollingInterval(defaultTimeouts.Poll)
	gomega.SetDefaultEventuallyTimeout(defaultTimeouts.PodStart)
	gomega.SetDefaultConsistentlyDuration(defaultTimeouts.PodStartShort)

	err = infraprovider.Set(cfg)
	framework.ExpectNoError(err, "must configure infrastructure provider")
	deploymentconfig.Set(cfg)
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
