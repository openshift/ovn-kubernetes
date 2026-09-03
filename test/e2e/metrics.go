// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/feature"
)

// These smoke tests guard what the metrics unit tests structurally cannot: that
// the OVN/OVS metric endpoints actually serve their expected series against real
// daemons (catching parser-vs-real-output drift) and that the metrics servers
// are wired up in a real deployment. They deliberately assert only presence of a
// representative subset, not exact values, to stay stable across environments.
var _ = ginkgo.Describe("e2e OVN/OVS metrics", feature.Metrics, func() {
	const (
		ovnMetricsPort = 9476 // --ovn-metrics-bind-address, see dist/images/ovnkube.sh
		ovsMetricsPort = 9310 // ovs-metrics exporter
	)

	f := wrappedTestFramework("metrics")

	var (
		ovnNamespace string
		nodePod      corev1.Pod
	)

	ginkgo.BeforeEach(func() {
		ovnNamespace = deploymentconfig.Get().OVNKubernetesNamespace()
		pods, err := f.ClientSet.CoreV1().Pods(ovnNamespace).List(context.Background(), metav1.ListOptions{
			LabelSelector: "app=ovnkube-node",
		})
		framework.ExpectNoError(err, "listing ovnkube-node pods")
		gomega.Expect(pods.Items).NotTo(gomega.BeEmpty(), "no ovnkube-node pods found")
		nodePod = pods.Items[0]
		gomega.Expect(nodePod.Status.PodIP).NotTo(gomega.BeEmpty(), "ovnkube-node pod has no IP")
	})

	// scrape curls a metrics endpoint from inside the given container. ovnkube-node
	// runs host-networked, so its pod IP is the metrics bind address and every
	// container in the pod can reach both ports.
	scrape := func(container string, port int) string {
		url := fmt.Sprintf("http://%s:%d/metrics", nodePod.Status.PodIP, port)
		stdout, stderr, err := ExecCommandInContainerWithFullOutput(
			f, ovnNamespace, nodePod.Name, container,
			"curl", "-sS", "--max-time", "10", url,
		)
		framework.ExpectNoError(err, "curl %s failed: %s", url, stderr)
		gomega.Expect(stdout).NotTo(gomega.BeEmpty(), "empty metrics response from %s", url)
		return stdout
	}

	assertPresent := func(body string, names ...string) {
		for _, name := range names {
			// Match the metric name at the start of a sample line, with or
			// without a label set, e.g. `name 1` or `name{db_name="..."} 1`.
			present := false
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, name+" ") || strings.HasPrefix(line, name+"{") {
					present = true
					break
				}
			}
			gomega.Expect(present).To(gomega.BeTrue(), "expected metric %q missing from endpoint", name)
		}
	}

	ginkgo.It("delivers OVN controller and northd metrics, including the loop-collected ones", func() {
		body := scrape("ovnkube-controller", ovnMetricsPort)
		assertPresent(body,
			// northd status/connection metrics (background-loop gauges)
			"ovn_northd_status",
			"ovn_northd_nb_connection_status",
			"ovn_northd_sb_connection_status",
			// integration-bridge metrics (background-loop gauges)
			"ovn_controller_integration_bridge_openflow_total",
			"ovn_controller_integration_bridge_patch_ports",
			"ovn_controller_integration_bridge_geneve_ports",
			// a representative always-registered controller metric
			"ovn_controller_southbound_database_connected",
			// OVN DB gauges refreshed by the loop
			"ovn_db_db_size_bytes",
		)
	})

	ginkgo.It("delivers OVS metrics from the standalone exporter", func() {
		body := scrape("ovs-metrics-exporter", ovsMetricsPort)
		assertPresent(body,
			"ovs_build_info",
			"ovs_vswitchd_dp_flows_total",
		)
	})

	ginkgo.It("keeps the endpoint responsive to repeated scrapes", func() {
		// The scrape handler only serializes the in-memory registry (extraction
		// runs on its own loop), so repeated back-to-back scrapes must all return
		// promptly and non-empty regardless of daemon load.
		for i := 0; i < 5; i++ {
			gomega.Eventually(func() string {
				return scrape("ovnkube-controller", ovnMetricsPort)
			}).Within(20 * time.Second).ProbeEvery(time.Second).
				Should(gomega.ContainSubstring("ovn_northd_status"))
		}
	})
})
