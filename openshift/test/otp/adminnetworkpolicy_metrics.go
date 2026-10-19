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
		output, err := exec.Command("oc", "get", "network.config.openshift.io", "cluster", "-o", "jsonpath={.status.networkType}").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "failed to check network type")
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
			testID           = "73331"
			banpCRTemplate   = otputils.FixturePath("adminnetworkpolicy", "banp-multi-pod-mixed-rule-template.yaml")
			anpCRTemplate    = otputils.FixturePath("adminnetworkpolicy", "anp-single-rule-me-template.yaml")
			anpNodeCRTemplate = otputils.FixturePath("adminnetworkpolicy", "anp-single-rule-template-node.yaml")
			namespaceLabelKey = "team"
			namespaceLabelVal = "qe"
			podKey           = "name"
			podVal           = "hello-pod"
			banpIngress      = make(map[string]string)
		)

		banpMetricsList := []string{"ovnkube_controller_baseline_admin_network_policies_rules"}
		anpMetricsList := []string{"ovnkube_controller_admin_network_policies_rules"}
		actionList := []string{"Allow", "Deny", "Pass"}

		ipStackType := otputils.CheckIPStackType()
		o.Expect(ipStackType).NotTo(o.BeEmpty(), "failed to determine cluster IP stack type")

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
		o.Expect(err).NotTo(o.HaveOccurred(), "failed to create BANP policy")
		defer otputils.RemoveResource("banp", banpCR.Name)

		g.By("2. Validate BANP rule metrics with Ingress Allow action")
		otputils.GetPolicyMetrics(banpMetricsList[0], "1", "Ingress", actionList[0])

		g.By("3. Validate BANP rule metrics with Egress Deny action")
		otputils.GetPolicyMetrics(banpMetricsList[0], "1", "Egress", actionList[1])

		banpIngress[actionList[1]] = "1"
		g.By("4. Update BANP to add another ingress rule and validate metrics")
		patchBANP := fmt.Sprintf("[{\"op\": \"add\", \"path\":\"/spec/ingress/1\", \"value\": {\"name\":\"deny ingress\", \"action\": \"Deny\", \"from\": [{\"pods\":  {\"namespaceSelector\": {\"matchLabels\": {%s: %s}}, \"podSelector\": {}}}]}}]", namespaceLabelKey, namespaceLabelVal)
		err = exec.Command("oc", "patch", "baselineadminnetworkpolicy", banpCR.Name, "--type=json", "-p", patchBANP).Run()
		o.Expect(err).NotTo(o.HaveOccurred(), "failed to patch BANP with additional ingress rule")
		otputils.GetPolicyMetrics(banpMetricsList[0], banpIngress[actionList[1]], "Ingress", actionList[1])

		g.By("5. Create a ANP with one ingress rule with deny action.")
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
		o.Expect(err).NotTo(o.HaveOccurred(), "failed to create ANP policy")
		defer otputils.RemoveResource("anp", anpCR.Name)

		g.By("6. Validate ANP rule metrics with Ingress Deny action")
		otputils.GetPolicyMetrics(anpMetricsList[0], "1", "Ingress", actionList[1])

		g.By("7. Create another ANP with egress pass and allow rule.")
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
		o.Expect(err).NotTo(o.HaveOccurred(), "failed to create second ANP policy")
		defer otputils.RemoveResource("anp", anpNodeCR.Name)

		g.By("8. Validate ANP rule metrics with Egress Allow action")
		otputils.GetPolicyMetrics(anpMetricsList[0], "1", "Egress", actionList[0])

		g.By("9. Validate ANP rule metrics with Egress Pass action")
		otputils.GetPolicyMetrics(anpMetricsList[0], "1", "Egress", actionList[2])
	})
})
