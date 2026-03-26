package networking

import (
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[OTP][sig-networking] SDN alerts", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-alerts", compat_otp.KubeConfigPath())
	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("NonHyperShiftHOST-Author:weliang-Medium-51438-Upgrade NoRunningOvnControlPlane to critical severity and inclue runbook.", func() {
		alertName, NameErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[*].alert}").Output()
		o.Expect(NameErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertName is %v", alertName)
		o.Expect(alertName).To(o.ContainSubstring("NoRunningOvnControlPlane"))

		alertSeverity, severityErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"NoRunningOvnControlPlane\")].labels.severity}").Output()
		o.Expect(severityErr).NotTo(o.HaveOccurred())
		e2e.Logf("alertSeverity is %v", alertSeverity)
		o.Expect(alertSeverity).To(o.ContainSubstring("critical"))

		alertRunbook, runbookErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"NoRunningOvnControlPlane\")].annotations.runbook_url}").Output()
		o.Expect(runbookErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertRunbook is %v", alertRunbook)
		o.Expect(alertRunbook).To(o.ContainSubstring("https://github.com/openshift/runbooks/blob/master/alerts/cluster-network-operator/NoRunningOvnControlPlane.md"))

	})

	g.It("NonHyperShiftHOST-Author:weliang-Medium-51439-Upgrade NoOvnClusterManagerLeader to critical severity and inclue runbook.", func() {
		alertName, NameErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[*].alert}").Output()
		o.Expect(NameErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertName is %v", alertName)
		o.Expect(alertName).To(o.ContainSubstring("NoOvnClusterManagerLeader"))

		alertSeverity, severityErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"NoOvnClusterManagerLeader\")].labels.severity}").Output()
		o.Expect(severityErr).NotTo(o.HaveOccurred())
		e2e.Logf("alertSeverity is %v", alertSeverity)
		o.Expect(alertSeverity).To(o.ContainSubstring("critical"))

		alertRunbook, runbookErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"NoOvnClusterManagerLeader\")].annotations.runbook_url}").Output()
		o.Expect(runbookErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertRunbook is %v", alertRunbook)
		o.Expect(alertRunbook).To(o.ContainSubstring("https://github.com/openshift/runbooks/blob/master/alerts/cluster-network-operator/NoOvnClusterManagerLeader.md"))
	})

	g.It("NonHyperShiftHOST-Author:weliang-Medium-51722-Create runbook and link SOP for SouthboundStale alert", func() {
		alertName, NameErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[*].alert}").Output()
		o.Expect(NameErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertName is %v", alertName)
		o.Expect(alertName).To(o.ContainSubstring("SouthboundStale"))

		alertSeverity, severityErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"SouthboundStale\")].labels.severity}").Output()
		o.Expect(severityErr).NotTo(o.HaveOccurred())
		e2e.Logf("alertSeverity is %v", alertSeverity)
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))

		alertRunbook, runbookErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"SouthboundStale\")].annotations.runbook_url}").Output()
		o.Expect(runbookErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertRunbook is %v", alertRunbook)
		o.Expect(alertRunbook).To(o.ContainSubstring("https://github.com/openshift/runbooks/blob/master/alerts/cluster-network-operator/SouthboundStaleAlert.md"))
	})

	g.It("NonHyperShiftHOST-Author:weliang-Medium-51724-Create runbook and link SOP for V4SubnetAllocationThresholdExceeded alert", func() {
		alertName, NameErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[*].alert}").Output()
		o.Expect(NameErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertName is %v", alertName)
		o.Expect(alertName).To(o.ContainSubstring("V4SubnetAllocationThresholdExceeded"))

		alertSeverity, severityErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"V4SubnetAllocationThresholdExceeded\")].labels.severity}").Output()
		o.Expect(severityErr).NotTo(o.HaveOccurred())
		e2e.Logf("alertSeverity is %v", alertSeverity)
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))

		alertRunbook, runbookErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"V4SubnetAllocationThresholdExceeded\")].annotations.runbook_url}").Output()
		o.Expect(runbookErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertRunbook is %v", alertRunbook)
		o.Expect(alertRunbook).To(o.ContainSubstring("https://github.com/openshift/runbooks/blob/master/alerts/cluster-network-operator/V4SubnetAllocationThresholdExceeded.md"))
	})

	g.It("Author:weliang-Medium-51726-Create runbook and link SOP for NodeWithoutOVNKubeNodePodRunning alert", func() {
		alertName, NameErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[*].alert}").Output()
		o.Expect(NameErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertName is %v", alertName)
		o.Expect(alertName).To(o.ContainSubstring("NodeWithoutOVNKubeNodePodRunning"))

		alertSeverity, severityErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"NodeWithoutOVNKubeNodePodRunning\")].labels.severity}").Output()
		o.Expect(severityErr).NotTo(o.HaveOccurred())
		e2e.Logf("alertSeverity is %v", alertSeverity)
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))

		alertRunbook, runbookErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"NodeWithoutOVNKubeNodePodRunning\")].annotations.runbook_url}").Output()
		o.Expect(runbookErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertRunbook is %v", alertRunbook)
		o.Expect(alertRunbook).To(o.ContainSubstring("https://github.com/openshift/runbooks/blob/master/alerts/cluster-network-operator/NodeWithoutOVNKubeNodePodRunning.md"))
	})

	g.It("NonHyperShiftHOST-Author:weliang-Medium-51723-bug 2094068 Create runbook and link SOP for NorthboundStale alert", func() {
		alertName, NameErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[*].alert}").Output()
		o.Expect(NameErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertName is %v", alertName)
		o.Expect(alertName).To(o.ContainSubstring("NorthboundStale"))

		alertSeverity, severityErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"NorthboundStale\")].labels.severity}").Output()
		o.Expect(severityErr).NotTo(o.HaveOccurred())
		e2e.Logf("alertSeverity is %v", alertSeverity)
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))

		alertRunbook, runbookErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", "openshift-ovn-kubernetes", "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\"NorthboundStale\")].annotations.runbook_url}").Output()
		o.Expect(runbookErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alertRunbook is %v", alertRunbook)
		o.Expect(alertRunbook).To(o.ContainSubstring("https://github.com/openshift/runbooks/blob/master/alerts/cluster-network-operator/NorthboundStaleAlert.md"))
	})

	g.It("Author:qiowang-Medium-53999-OVN-K alerts for ovn controller disconnection", func() {
		alertSeverity, alertExpr, runBook := getOVNAlertNetworkingRules(oc, "OVNKubernetesControllerDisconnectedSouthboundDatabase")
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))
		o.Expect(alertExpr).To(o.ContainSubstring("max_over_time(ovn_controller_southbound_database_connected[5m]) == 0"))
		o.Expect(runBook).To(o.ContainSubstring("https://github.com/openshift/runbooks/blob/master/alerts/cluster-network-operator/OVNKubernetesControllerDisconnectedSouthboundDatabase.md"))
	})

	g.It("Author:qiowang-Medium-60705-Verify alert OVNKubernetesNodeOVSOverflowKernel", func() {
		alertSeverity, alertExpr, _ := getOVNAlertNetworkingRules(oc, "OVNKubernetesNodeOVSOverflowKernel")
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))
		o.Expect(alertExpr).To(o.ContainSubstring("increase(ovs_vswitchd_dp_flows_lookup_lost[5m]) > 0"))
	})

	g.It("Author:qiowang-Medium-60706-Verify alert OVNKubernetesNodeOVSOverflowUserspace", func() {
		alertSeverity, alertExpr, _ := getOVNAlertNetworkingRules(oc, "OVNKubernetesNodeOVSOverflowUserspace")
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))
		o.Expect(alertExpr).To(o.ContainSubstring("increase(ovs_vswitchd_netlink_overflow[5m]) > 0"))
	})

	g.It("Author:qiowang-Medium-60709-Verify alert OVNKubernetesResourceRetryFailure", func() {
		alertSeverity, alertExpr, _ := getOVNAlertNetworkingRules(oc, "OVNKubernetesResourceRetryFailure")
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))
		o.Expect(alertExpr).To(o.ContainSubstring("increase(ovnkube_resource_retry_failures_total[10m]) > 0"))
	})

	g.It("Author:qiowang-Medium-72328-Verify alert OVNKubernetesNodePodAddError and OVNKubernetesNodePodDeleteError", func() {
		alertSeverity1, alertExpr1, _ := getOVNAlertNetworkingRules(oc, "OVNKubernetesNodePodAddError")
		o.Expect(alertSeverity1).To(o.ContainSubstring("warning"))
		o.Expect(alertExpr1).To(o.ContainSubstring(`sum by(instance, namespace) (rate(ovnkube_node_cni_request_duration_seconds_count{command="ADD",err="true"}[5m]))`))

		alertSeverity2, alertExpr2, _ := getOVNAlertNetworkingRules(oc, "OVNKubernetesNodePodDeleteError")
		o.Expect(alertSeverity2).To(o.ContainSubstring("warning"))
		o.Expect(alertExpr2).To(o.ContainSubstring(`sum by(instance, namespace) (rate(ovnkube_node_cni_request_duration_seconds_count{command="DEL",err="true"}[5m]))`))
	})

	g.It("NonHyperShiftHOST-Author:qiowang-Medium-72329-Verify alert OVNKubernetesNorthboundDatabaseCPUUsagehigh and OVNKubernetesSouthboundDatabaseCPUUsagehigh", func() {
		alertSeverity1, alertExpr1, _ := getOVNAlertNetworkingRules(oc, "OVNKubernetesNorthboundDatabaseCPUUsageHigh")
		o.Expect(alertSeverity1).To(o.ContainSubstring("info"))
		o.Expect(alertExpr1).To(o.ContainSubstring(`(sum(rate(container_cpu_usage_seconds_total{container="nbdb"}[5m])) BY`))
		o.Expect(alertExpr1).To(o.ContainSubstring(`(instance, name, namespace)) > 0.8`))

		alertSeverity2, alertExpr2, _ := getOVNAlertNetworkingRules(oc, "OVNKubernetesSouthboundDatabaseCPUUsageHigh")
		o.Expect(alertSeverity2).To(o.ContainSubstring("info"))
		o.Expect(alertExpr2).To(o.ContainSubstring(`(sum(rate(container_cpu_usage_seconds_total{container="sbdb"}[5m])) BY`))
		o.Expect(alertExpr2).To(o.ContainSubstring(`(instance, name, namespace)) > 0.8`))
	})

	g.It("NonHyperShiftHOST-Author:qiowang-Medium-72330-Verify alert V6SubnetAllocationThresholdExceeded", func() {
		alertSeverity, alertExpr, _ := getOVNAlertMasterRules(oc, "V6SubnetAllocationThresholdExceeded")
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))
		o.Expect(alertExpr).To(o.ContainSubstring(`ovnkube_clustermanager_allocated_v6_host_subnets / ovnkube_clustermanager_num_v6_host_subnets`))
		o.Expect(alertExpr).To(o.ContainSubstring(`> 0.8`))
	})

	g.It("Author:qiowang-NonHyperShiftHOST-Medium-53926-OVN-K alerts for ovn northd inactivity", func() {
		alertSeverity, alertExpr, runBook := getOVNAlertNetworkingRules(oc, "OVNKubernetesNorthdInactive")
		o.Expect(alertSeverity).To(o.ContainSubstring("warning"))
		o.Expect(alertExpr).To(o.ContainSubstring(`count(ovn_northd_status != 1) BY (instance, name, namespace) > 0`))
		o.Expect(runBook).To(o.ContainSubstring(`https://github.com/openshift/runbooks/blob/master/alerts/cluster-network-operator/OVNKubernetesNorthdInactive.md`))
	})
})
