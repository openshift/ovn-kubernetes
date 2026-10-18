package otp

import (
	"fmt"
	"os/exec"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/otputils"
)

var _ = g.Describe("[OTP] SDN adminnetworkpolicy metrics", func() {
	defer g.GinkgoRecover()

	var (
		nsList []string
	)

	g.BeforeEach(func() {
		// Ensure OVN-K is present
		output, err := exec.Command("oc", "get", "network.config.openshift.io", "cluster", "-o", "jsonpath={.status.networkType}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if !strings.Contains(strings.ToLower(string(output)), "ovn") {
			g.Skip("AdminNetworkPolicy only supported on OVN clusters")
		}
	})

	g.AfterEach(func() {
		for _, ns := range nsList {
			exec.Command("oc", "delete", "ns", ns, "--ignore-not-found=true").Run()
		}
		nsList = nil
	})

	g.It("73331-BANP and ANP metrics are available [Serial]", func() {
		var (
			testID                   = "73331"
			banpCRTemplate           = otputils.FixturePath("adminnetworkpolicy", "banp-multi-pod-mixed-rule-template.yaml")
			anpCRTemplate            = otputils.FixturePath("adminnetworkpolicy", "anp-single-rule-me-template.yaml")
			anpNodeCRTemplate        = otputils.FixturePath("adminnetworkpolicy", "anp-single-rule-template-node.yaml")
			namespaceLabelKey        = "team"
			namespaceLabelVal        = "qe"
			podKey                   = "name"
			podVal                   = "hello-pod"
			expectedBANPMetricsValue = make(map[string]string)
			expectedANPMetricsValue  = make(map[string]string)
			banpEgress               = make(map[string]string)
			banpIngress              = make(map[string]string)
			anpEgress                = make(map[string]string)
			anpIngress               = make(map[string]string)
		)

		// Initialize variables
		banpMetricsList := []string{"ovnkube_controller_baseline_admin_network_policies", "ovnkube_controller_baseline_admin_network_policies_db_objects", "ovnkube_controller_baseline_admin_network_policies_rules"}
		anpMetricsList := []string{"ovnkube_controller_admin_network_policies", "ovnkube_controller_admin_network_policies_db_objects", "ovnkube_controller_admin_network_policies_rules"}
		actionList := []string{"Allow", "Deny", "Pass"}
		dbObjects := []string{"ACL", "Address_Set"}
		expectedBANPMetricsValue[banpMetricsList[0]] = "1"
		expectedBANPMetricsValue[dbObjects[0]] = "2"
		expectedANPMetricsValue[anpMetricsList[0]] = "1"
		expectedANPMetricsValue[dbObjects[0]] = "1"

		ipStackType := otputils.CheckIPStackType()
		o.Expect(ipStackType).NotTo(o.BeEmpty())

		g.By("1. Create a BANP with two rules with Allow action for Ingress and Deny action for Egress")
		banpCR := otputils.MultiPodMixedRuleBANPPolicyResource{
			Name:          "default",
			SubjectKey:    namespaceLabelKey,
			SubjectVal:    namespaceLabelVal,
			SubjectPodKey: podKey,
			SubjectPodVal: podVal,
			PolicyType1:   "ingress",
			Direction1:    "from",
			RuleName1:     "default-allow-ingress",
			RuleAction1:   "Allow",
			RuleKey1:      namespaceLabelKey,
			RuleVal1:      namespaceLabelVal,
			RulePodKey1:   podKey,
			RulePodVal1:   podVal,
			PolicyType2:   "egress",
			Direction2:    "to",
			RuleName2:     "default-deny-egress",
			RuleAction2:   "Deny",
			RuleKey2:      namespaceLabelVal,
			RuleVal2:      namespaceLabelVal,
			RulePodKey2:   podKey,
			RulePodVal2:   podVal,
			Template:      banpCRTemplate,
		}
		err := banpCR.Create()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer otputils.RemoveResource("banp", banpCR.Name)

		g.By(fmt.Sprintf("2.1 Validate %s metrics for BANP", banpMetricsList[0]))
		otputils.GetPolicyMetrics(banpMetricsList[0], expectedBANPMetricsValue[banpMetricsList[0]])
		
		// Address set
		if ipStackType == "dualstack" {
			expectedBANPMetricsValue[dbObjects[1]] = "4"
		} else {
			expectedBANPMetricsValue[dbObjects[1]] = "2"
		}
		for i := 0; i < 2; i++ {
			g.By(fmt.Sprintf("2.2.%d Validate %s - %s metrics for BANP", i, banpMetricsList[1], dbObjects[i]))
			otputils.GetPolicyMetrics(banpMetricsList[1], expectedBANPMetricsValue[dbObjects[i]], dbObjects[i])
		}

		banpEgress[actionList[1]] = "1"
		banpIngress[actionList[0]] = "1"
		ruleDirection := "Egress"
		g.By(fmt.Sprintf("3. Validate metrics %s for BANP, %s rule and %s action", banpMetricsList[2], ruleDirection, actionList[1]))
		otputils.GetPolicyMetrics(banpMetricsList[2], banpEgress[actionList[1]], ruleDirection, actionList[1])

		ruleDirection = "Ingress"
		g.By(fmt.Sprintf("4. Validate metrics %s for BANP, %s rule and %s action", banpMetricsList[2], ruleDirection, actionList[0]))
		otputils.GetPolicyMetrics(banpMetricsList[2], banpIngress[actionList[0]], ruleDirection, actionList[0])

		banpIngress[actionList[1]] = "1"
		g.By(fmt.Sprintf("5. Update BANP to add another ingress rule and validate metrics %s", banpMetricsList[2]))
		patchBANP := fmt.Sprintf("[{\"op\": \"add\", \"path\":\"/spec/ingress/1\", \"value\": {\"name\":\"deny ingress\", \"action\": \"Deny\", \"from\": [{\"pods\":  {\"namespaceSelector\": {\"matchLabels\": {%s: %s}}, \"podSelector\": {}}}]}}]", namespaceLabelKey, namespaceLabelVal)
		err = exec.Command("oc", "patch", "baselineadminnetworkpolicy", banpCR.Name, "--type=json", "-p", patchBANP).Run()
		o.Expect(err).NotTo(o.HaveOccurred())
		otputils.GetPolicyMetrics(banpMetricsList[2], banpIngress[actionList[1]], ruleDirection, actionList[1])

		g.By("6. Create a ANP with one ingress rule with deny action.")
		anpCR := otputils.SingleRuleANPMEPolicyResource{
			Name:            "anp-" + testID + "-0",
			SubjectKey:      namespaceLabelKey,
			SubjectOperator: "In",
			SubjectVal:      namespaceLabelVal,
			Priority:        25,
			PolicyType:      "ingress",
			Direction:       "from",
			RuleName:        "deny ingress",
			RuleAction:      "Deny",
			RuleKey:         namespaceLabelKey,
			RuleOperator:    "NotIn",
			RuleVal:         "ns" + testID,
			Template:        anpCRTemplate,
		}
		err = anpCR.Create()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer otputils.RemoveResource("anp", anpCR.Name)

		// Address set
		if ipStackType == "dualstack" {
			expectedANPMetricsValue[dbObjects[1]] = "2"
		} else {
			expectedANPMetricsValue[dbObjects[1]] = "1"
		}

		g.By(fmt.Sprintf("7.1 Validate %s metrics for ANP %s", anpMetricsList[0], anpCR.Name))
		otputils.GetPolicyMetrics(anpMetricsList[0], expectedANPMetricsValue[anpMetricsList[0]])
		for i := 0; i < 2; i++ {
			g.By(fmt.Sprintf("7.2.%d Validate %s - %s metrics  for ANP %s", i, anpMetricsList[1], dbObjects[i], anpCR.Name))
			otputils.GetPolicyMetrics(anpMetricsList[1], expectedANPMetricsValue[dbObjects[i]], dbObjects[i])
		}
		ruleDirection = "Ingress"
		anpIngress[actionList[1]] = "1"
		g.By(fmt.Sprintf("8. Validate metrics %s for ANP, %s rule and %s action", anpMetricsList[2], ruleDirection, actionList[1]))
		otputils.GetPolicyMetrics(anpMetricsList[2], anpIngress[actionList[1]], ruleDirection, actionList[1])

		g.By("9. Create another ANP with egress pass and allow rule.")
		anpNodeCR := otputils.SingleRuleANPPolicyResourceNode{
			Name:       "anp-" + testID + "-1",
			SubjectKey: namespaceLabelKey,
			SubjectVal: namespaceLabelVal,
			Priority:   40,
			PolicyType: "egress",
			Direction:  "to",
			RuleName:   "allow egress",
			RuleAction: "Allow",
			RuleKey:    "team",
			NodeKey:    "node-role.kubernetes.io/worker",
			RuleVal:    "worker-1",
			ActionName: "pass egress",
			ActionType: "Pass",
			Template:   anpNodeCRTemplate,
		}
		err = anpNodeCR.Create()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer otputils.RemoveResource("anp", anpNodeCR.Name)

		ruleDirection = "Egress"
		anpEgress[actionList[0]] = "1"
		anpEgress[actionList[2]] = "1"
		g.By(fmt.Sprintf("10. Validate metrics %s for ANP, %s rule and %s action", anpMetricsList[2], ruleDirection, actionList[0]))
		otputils.GetPolicyMetrics(anpMetricsList[2], anpEgress[actionList[0]], ruleDirection, actionList[0])

		g.By(fmt.Sprintf("11. Validate metrics %s for ANP, %s rule and %s action", anpMetricsList[2], ruleDirection, actionList[2]))
		otputils.GetPolicyMetrics(anpMetricsList[2], anpEgress[actionList[2]], ruleDirection, actionList[2])

		expectedANPMetricsValue[anpMetricsList[0]] = "2"
		expectedANPMetricsValue[dbObjects[0]] = "3"
		// Address set
		if ipStackType == "dualstack" {
			expectedANPMetricsValue[dbObjects[1]] = "6"
		} else {
			expectedANPMetricsValue[dbObjects[1]] = "3"
		}

		g.By(fmt.Sprintf("12.1 Validate %s metrics for both ANP policies", anpMetricsList[0]))
		otputils.GetPolicyMetrics(anpMetricsList[0], expectedANPMetricsValue[anpMetricsList[0]])
		for i := 0; i < 2; i++ {
			g.By(fmt.Sprintf("12.2.%d Validate %s - %s metrics for both ANP policies", i, anpMetricsList[1], dbObjects[i]))
			otputils.GetPolicyMetrics(anpMetricsList[1], expectedANPMetricsValue[dbObjects[i]], dbObjects[i])
		}
	})
})
