package otp

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"
	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/utils"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
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

	g.It("[OTP] 47524-Metrics for ovn-appctl stopwatch/show command", func() {
		var (
			namespace = "openshift-ovn-kubernetes"
			ovncmName = "kube-rbac-proxy-ovn-metrics"
			podLabel  = "app=ovnkube-node"
		)

		podName := otputils.GetLeaderInfo(oc, namespace, podLabel, "ovnkubernetes")
		prometheusURL := "localhost:29105/metrics"

		metrics := []string{
			"ovn_controller_if_status_mgr_run_total_samples",
			"ovn_controller_if_status_mgr_run_long_term_avg",
			"ovn_controller_bfd_run_total_samples",
			"ovn_controller_bfd_run_long_term_avg",
			"ovn_controller_flow_installation_total_samples",
			"ovn_controller_flow_installation_long_term_avg",
			"ovn_controller_if_status_mgr_update_total_samples",
			"ovn_controller_if_status_mgr_update_long_term_avg",
			"ovn_controller_flow_generation_total_samples",
			"ovn_controller_flow_generation_long_term_avg",
			"ovn_controller_pinctrl_run_total_samples",
			"ovn_controller_pinctrl_run_long_term_avg",
			"ovn_controller_ofctrl_seqno_run_total_samples",
			"ovn_controller_ofctrl_seqno_run_long_term_avg",
			"ovn_controller_patch_run_total_samples",
			"ovn_controller_patch_run_long_term_avg",
			"ovn_controller_ct_zone_commit_total_samples",
			"ovn_controller_ct_zone_commit_long_term_avg",
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

	g.It("[OTP] 45689-Metrics for idling enable/disabled", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "metrics", "metrics-pod.yaml")
			testSvcFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			testPodName         = "hello-pod"
		)

		g.By("create new namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("get controller-manager service ip address")
		managertServiceIP := otputils.GetControllerManagerLeaderIP(oc)
		svcURL := net.JoinHostPort(managertServiceIP, "8443")
		prometheusURL := "https://" + svcURL + "/metrics"

		var metricNumber string
		metricsErr := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
			output := otputils.GetOVNMetrics(oc, prometheusURL)
			metricOutput, _ := exec.Command("bash", "-c", "cat "+output+" | grep openshift_unidle_events_total | awk 'NR==3{print $2}'").Output()
			metricNumber = strings.TrimSpace(string(metricOutput))
			e2e.Logf("The output of openshift_unidle_events metrics is : %v", metricNumber)
			if metricNumber != "" {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics of openshift_unidle_events and try again")
			return false, nil
		})
		o.Expect(metricsErr).NotTo(o.HaveOccurred(), "Fail to get metric openshift_unidle_events_total")

		g.By("create a service")
		otputils.CreateResourceFromFile(oc, ns, testSvcFile)
		serviceOutput, serviceErr := oc.WithoutNamespace().Run("get").Args("service", "-n", ns).Output()
		o.Expect(serviceErr).NotTo(o.HaveOccurred())
		o.Expect(serviceOutput).To(o.ContainSubstring("test-service"))

		g.By("create a test pod")
		otputils.CreateResourceFromFile(oc, ns, testPodFile)
		podErr := otputils.WaitForPodWithLabelReady(oc, ns, "name=hello-pod")
		o.Expect(podErr).NotTo(o.HaveOccurred(), "hello-pod is not running")

		g.By("get test service ip address")
		testServiceIP, _ := otputils.GetSvcIP(oc, ns, "test-service")
		dstURL := net.JoinHostPort(testServiceIP, "27017")

		g.By("test-pod can curl service ip address:port")
		_, svcerr1 := e2eoutput.RunHostCmd(ns, testPodName, "curl -connect-timeout 5 -s "+dstURL)
		o.Expect(svcerr1).NotTo(o.HaveOccurred())

		g.By("idle test-service")
		_, idleerr := oc.AsAdmin().WithoutNamespace().Run("idle").Args("-n", ns, "test-service").Output()
		o.Expect(idleerr).NotTo(o.HaveOccurred())

		g.By("test pod can curl service address:port again to unidle the svc")
		checkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 300*time.Second, false, func(ctx context.Context) (bool, error) {
			output, err := e2eoutput.RunHostCmd(ns, testPodName, "curl -connect-timeout 5 -s "+dstURL)
			if err != nil {
				e2e.Logf("curl to %s failed with error: %v\nOutput:\n%s\nRetrying...", dstURL, err, output)
				return false, nil
			}
			e2e.Logf("curl to %s succeeded. Output:\n%s", dstURL, output)
			return true, nil
		})
		o.Expect(checkErr).NotTo(o.HaveOccurred(), "Timed out waiting for curl to %s to succeed", dstURL)

		metricsOutput := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
			output := otputils.GetOVNMetrics(oc, prometheusURL)
			metricOutput, _ := exec.Command("bash", "-c", "cat "+output+" | grep openshift_unidle_events_total | awk 'NR==3{print $2}'").Output()
			metricValue := strings.TrimSpace(string(metricOutput))
			e2e.Logf("The output of openshift_unidle_events metrics is : %v", metricValue)
			if !strings.Contains(metricValue, metricNumber) {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics of openshift_unidle_events and try again")
			return false, nil
		})
		o.Expect(metricsOutput).NotTo(o.HaveOccurred(), "Fail to get updated metric openshift_unidle_events_total")
	})

	g.It("[OTP] 60539-Verify metrics ovs_vswitchd_interfaces_total", func() {
		var (
			namespace           = "openshift-ovn-kubernetes"
			metricName          = "ovs_vswitchd_interfaces_total"
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			delta               = 3
		)

		nodes, getNodeErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "node-role.kubernetes.io/worker,kubernetes.io/os=linux", "-o", "jsonpath='{.items[*].metadata.name}'").Output()
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		nodeName := strings.Split(strings.Trim(nodes, "'"), " ")[0]
		podName, getPodNameErr := otputils.GetOVNKPodOnNode(oc, namespace, "app=ovnkube-node", nodeName)
		o.Expect(getPodNameErr).NotTo(o.HaveOccurred())
		o.Expect(podName).NotTo(o.BeEmpty())

		g.By("1. Get the metrics of " + metricName + " before creating new pod on the node")
		prometheusURL := "localhost:29105/metrics"
		containerName := "kube-rbac-proxy-ovn-metrics"
		metricValue1 := otputils.GetOVNMetricsInSpecificContainer(oc, containerName, podName, prometheusURL, metricName)

		g.By("2. Create test pods and scale test pods to 10")
		ns := oc.Namespace()
		otputils.CreateResourceFromFile(oc, ns, testPodFile)
		podReadyErr := otputils.WaitForPodWithLabelReady(oc, ns, "name=test-pods")
		o.Expect(podReadyErr).NotTo(o.HaveOccurred(), "Waiting for pod with label name=test-pods become ready timeout")
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("rc/test-rc", "-n", ns, "-p", fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeName":"%s"}}}}`, nodeName), "--type=merge").Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		scaleErr := oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc/test-rc", "--replicas=0", "-n", ns).Execute()
		o.Expect(scaleErr).NotTo(o.HaveOccurred())
		scaleErr = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc/test-rc", "--replicas=10", "-n", ns).Execute()
		o.Expect(scaleErr).NotTo(o.HaveOccurred())
		podReadyErr = otputils.WaitForPodWithLabelReady(oc, ns, "name=test-pods")
		o.Expect(podReadyErr).NotTo(o.HaveOccurred(), "Waiting for pod with label name=test-pods become ready timeout after scale up")

		g.By("3. Get the metrics of " + metricName + " after creating new pod on the node")
		metricValue1Int, _ := strconv.Atoi(metricValue1)
		expectedIncFloor := metricValue1Int + 10 - delta
		expectedIncCeil := metricValue1Int + 10 + delta
		e2e.Logf("The expected value of the %s is : %v to %v", metricName, expectedIncFloor, expectedIncCeil)
		metricIncOutput := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
			metricValue2 := otputils.GetOVNMetricsInSpecificContainer(oc, containerName, podName, prometheusURL, metricName)
			metricValue2Int, _ := strconv.Atoi(metricValue2)
			if metricValue2Int >= expectedIncFloor && metricValue2Int <= expectedIncCeil {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s and try again", metricName)
			return false, nil
		})
		o.Expect(metricIncOutput).NotTo(o.HaveOccurred(), "Fail to get metric %s after scale up", metricName)

		g.By("4. Delete the pod on the node")
		scaleErr = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc/test-rc", "--replicas=0", "-n", ns).Execute()
		o.Expect(scaleErr).NotTo(o.HaveOccurred())
		delErr := otputils.WaitForPodWithLabelGone(oc, ns, "name=test-pods")
		o.Expect(delErr).NotTo(o.HaveOccurred())

		g.By("5. Get the metrics of " + metricName + " after deleting the pod on the node")
		expectedDecFloor := metricValue1Int - delta
		expectedDecCeil := metricValue1Int + delta
		e2e.Logf("The expected value of the %s is : %v to %v", metricName, expectedDecFloor, expectedDecCeil)
		metricDecOutput := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
			metricValue3 := otputils.GetOVNMetricsInSpecificContainer(oc, containerName, podName, prometheusURL, metricName)
			metricValue3Int, _ := strconv.Atoi(metricValue3)
			if metricValue3Int >= expectedDecFloor && metricValue3Int <= expectedDecCeil {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s and try again", metricName)
			return false, nil
		})
		o.Expect(metricDecOutput).NotTo(o.HaveOccurred(), "Fail to get metric %s after scale down", metricName)
	})

	g.It("[OTP] 60704-Verify metrics ovs_vswitchd_interface_up_wait_seconds_total", func() {
		var (
			namespace           = "openshift-ovn-kubernetes"
			metricName          = "ovs_vswitchd_interface_up_wait_seconds_total"
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
		)

		nodes, getNodeErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "node-role.kubernetes.io/worker,kubernetes.io/os=linux", "-o", "jsonpath='{.items[*].metadata.name}'").Output()
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		nodeName := strings.Split(strings.Trim(nodes, "'"), " ")[0]
		podName, getPodNameErr := otputils.GetOVNKPodOnNode(oc, namespace, "app=ovnkube-node", nodeName)
		o.Expect(getPodNameErr).NotTo(o.HaveOccurred())
		o.Expect(podName).NotTo(o.BeEmpty())

		g.By("1. Get the metrics of " + metricName + " before creating new pods on the node")
		prometheusURL := "localhost:29105/metrics"
		containerName := "kube-rbac-proxy-ovn-metrics"
		metricValue1 := otputils.GetOVNMetricsInSpecificContainer(oc, containerName, podName, prometheusURL, metricName)

		g.By("2. Create test pods and scale test pods to 30")
		ns := oc.Namespace()
		otputils.CreateResourceFromFile(oc, ns, testPodFile)
		podReadyErr1 := otputils.WaitForPodWithLabelReady(oc, ns, "name=test-pods")
		o.Expect(podReadyErr1).NotTo(o.HaveOccurred(), "pod with label name=test-pods not ready")
		_, scaleUpErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("replicationcontroller/test-rc", "-n", ns, "-p", fmt.Sprintf(`{"spec":{"replicas":30,"template":{"spec":{"nodeSelector":{"kubernetes.io/hostname":"%s"}}}}}`, nodeName), "--type=merge").Output()
		o.Expect(scaleUpErr).NotTo(o.HaveOccurred())
		podReadyErr2 := otputils.WaitForPodWithLabelReady(oc, ns, "name=test-pods")
		o.Expect(podReadyErr2).NotTo(o.HaveOccurred(), "pod with label name=test-pods not all ready")

		g.By("3. Get the metrics of " + metricName + " after creating new pods on the node")
		metricValue1Float, parseErr1 := strconv.ParseFloat(metricValue1, 64)
		o.Expect(parseErr1).NotTo(o.HaveOccurred())
		e2e.Logf("The expected value of the %s should be greater than %v", metricName, metricValue1)
		metricIncOutput := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
			metricValue2 := otputils.GetOVNMetricsInSpecificContainer(oc, containerName, podName, prometheusURL, metricName)
			metricValue2Float, parseErr2 := strconv.ParseFloat(metricValue2, 64)
			o.Expect(parseErr2).NotTo(o.HaveOccurred())
			if metricValue2Float > metricValue1Float {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s and try again", metricName)
			return false, nil
		})
		o.Expect(metricIncOutput).NotTo(o.HaveOccurred(), "Fail to get metric %s", metricName)
	})

	g.It("[OTP] 60708-Verify metrics ovnkube_resource_retry_failures_total", func() {
		var (
			namespace           = "openshift-ovn-kubernetes"
			metricName          = "ovnkube_resource_retry_failures_total"
			egressNodeLabel     = "k8s.ovn.org/egress-assignable"
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIPTemplate    = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		)

		g.By("1. Get the metrics of " + metricName + " before resource retry failure occur")
		prometheusURL := "localhost:29108/metrics"
		ovnMasterPodName := otputils.GetOVNKMasterPod(oc)
		containerName := "kube-rbac-proxy"
		metricValue1 := otputils.GetOVNMetricsInSpecificContainer(oc, containerName, ovnMasterPodName, prometheusURL, metricName)

		g.By("2. Configure egressip with invalid ip address to trigger resource retry")
		g.By("2.1 Label EgressIP node")
		nodeName, getNodeErr := otputils.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeName, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeName, egressNodeLabel, "true")

		g.By("2.2 Create new namespace and apply label")
		oc.SetupProject()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", oc.Namespace(), "name-").Output()
		_, labelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", oc.Namespace(), "name=test").Output()
		o.Expect(labelErr).NotTo(o.HaveOccurred())

		g.By("2.3 Create egressip object with invalid ip address")
		egressipName := "egressip-" + otputils.GetRandomString()
		egressip := otputils.EgressIPResource1{
			Name:     egressipName,
			Template: egressIPTemplate,
			EgressIP1: "a.b.c.d",
			EgressIP2: "a.b.0.1",
		}
		defer egressip.DeleteEgressIPObject1(oc)
		egressip.CreateEgressIPObject1(oc)

		g.By("3. Waiting for ovn resource retry failure")
		targetLog := egressipName + ": exceeded number of failed attempts"
		checkErr := wait.Poll(2*time.Minute, 16*time.Minute, func() (bool, error) {
			podLogs, logErr := otputils.GetSpecificPodLogs(oc, namespace, "ovnkube-cluster-manager", ovnMasterPodName, targetLog)
			if len(podLogs) == 0 || logErr != nil {
				e2e.Logf("did not get expected podLogs, or have err: %v, try again", logErr)
				return false, nil
			}
			return true, nil
		})
		o.Expect(checkErr).NotTo(o.HaveOccurred(), "fail to get expected log in pod %v", ovnMasterPodName)

		g.By("4. Get the metrics of " + metricName + " again when resource retry failure occur")
		metricValue1Int, _ := strconv.Atoi(metricValue1)
		expectedIncValue := strconv.Itoa(metricValue1Int + 1)
		e2e.Logf("The expected value of the %s is : %v", metricName, expectedIncValue)
		metricIncOutput := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
			metricValue2 := otputils.GetOVNMetricsInSpecificContainer(oc, containerName, ovnMasterPodName, prometheusURL, metricName)
			if metricValue2 == expectedIncValue {
				return true, nil
			}
			e2e.Logf("Can't get correct metrics value of %s and try again", metricName)
			return false, nil
		})
		o.Expect(metricIncOutput).NotTo(o.HaveOccurred(), "Fail to get metric %s", metricName)
	})
})
