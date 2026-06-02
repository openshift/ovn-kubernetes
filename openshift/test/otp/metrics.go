package otp

import (
	"net"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"

	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[sig-networking] OVN metrics", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-ovn-metrics")

	g.BeforeEach(func() {
		networkType := otputils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[OTP] 45841-Add OVN flow count metric", func() {
		var (
			namespace = "openshift-ovn-kubernetes"
			ovncmName = "kube-rbac-proxy-ovn-metrics"
			podLabel  = "app=ovnkube-node"
		)

		podName := otputils.GetLeaderInfo(oc, namespace, podLabel, "ovnkubernetes")
		prometheusURL := "localhost:29105/metrics"
		metricName := "ovn_controller_integration_bridge_openflow_total"

		metricsOutput := wait.Poll(10*time.Second, 120*time.Second, func() (bool, error) {
			metricValue := otputils.GetOVNMetricsInSpecificContainer(oc, ovncmName, podName, prometheusURL, metricName)
			if metricValue != "" {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s and try again", metricName)
			return false, nil
		})
		o.Expect(metricsOutput).NotTo(o.HaveOccurred(), "Fail to get metric %s", metricName)
	})

	g.It("[OTP] 47471-Record update to cache versus port binding", func() {
		var (
			namespace = "openshift-ovn-kubernetes"
			ovncmName = "kube-rbac-proxy-ovn-metrics"
			podLabel  = "app=ovnkube-node"
		)

		podName := otputils.GetLeaderInfo(oc, namespace, podLabel, "ovnkubernetes")
		prometheusURL := "localhost:29103/metrics"

		metrics := []string{
			"ovnkube_controller_pod_first_seen_lsp_created_duration_seconds_count",
			"ovnkube_controller_pod_lsp_created_port_binding_duration_seconds_count",
			"ovnkube_controller_pod_port_binding_port_binding_chassis_duration_seconds_count",
			"ovnkube_controller_pod_port_binding_chassis_port_binding_up_duration_seconds_count",
		}
		for _, m := range metrics {
			metricsOutput := wait.Poll(10*time.Second, 120*time.Second, func() (bool, error) {
				metricValue := otputils.GetOVNMetricsInSpecificContainer(oc, ovncmName, podName, prometheusURL, m)
				if metricValue != "" {
					return true, nil
				}
				e2e.Logf("Can't get correct metrics value of %s and try again", m)
				return false, nil
			})
			o.Expect(metricsOutput).NotTo(o.HaveOccurred(), "Fail to get metric %s", m)
		}
	})

	g.It("[OTP] 52072-Add mechanism to record duration for k8 kinds", func() {
		var (
			namespace = "openshift-ovn-kubernetes"
			podLabel  = "app=ovnkube-node"
		)

		podName := otputils.GetLeaderInfo(oc, namespace, podLabel, "ovnkubernetes")
		leaderNodeIP := otputils.GetPodIPv4(oc, namespace, podName)
		ip := net.ParseIP(leaderNodeIP)
		var prometheusURL string
		if ip.To4() == nil {
			prometheusURL = "https://[" + leaderNodeIP + "]:9103/metrics"
		} else {
			prometheusURL = "https://" + leaderNodeIP + ":9103/metrics"
		}

		metrics := []string{
			"ovnkube_controller_network_programming_ovn_duration_seconds_bucket",
			"ovnkube_controller_network_programming_duration_seconds_bucket",
		}
		for _, m := range metrics {
			otputils.CheckovnkubeMasterNetworkProgrammingetrics(oc, prometheusURL, m)
		}
	})
})
