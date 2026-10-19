package otp

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/otputils"
)

var _ = g.Describe("[OTP] SDN adminnetworkpolicy", func() {
	defer g.GinkgoRecover()

	var (
		subjectNs string
		nsList    []string
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

	g.It("73189-BANP and ANP ACL audit log works [Serial]", func() {
		var (
			testID                   = "73189"
			banpCRTemplate           = otputils.FixturePath("adminnetworkpolicy", "banp-multi-pod-mixed-rule-template.yaml")
			anpMultiRuleCRTemplate   = otputils.FixturePath("adminnetworkpolicy", "anp-multi-pod-mixed-rule-template.yaml")
			rcPingPodTemplate        = otputils.FixturePath("rc-ping-for-pod-template.yaml")
			matchLabelKey            = "kubernetes.io/metadata.name"
			podKey                   = "color"
			podVal                   = "red"
			coloredPods              = make(map[string]string)
			unColoredPods            = make(map[string]string)
			ovnkubeNodeColoredPods   = make(map[string]string)
			ovnkubeNodeUnColoredPods = make(map[string]string)
		)

		g.By("1. Get the first namespace (subject) and create three peer namespaces")
		subjectNs = fmt.Sprintf("otp-%s-subject-%d", testID, time.Now().Unix())
		err := exec.Command("oc", "create", "ns", subjectNs).Run()
		o.Expect(err).NotTo(o.HaveOccurred())
		nsList = append(nsList, subjectNs)

		for i := 1; i <= 3; i++ {
			peerNs := fmt.Sprintf("otp-%s-peer-%d-%d", testID, i, time.Now().Unix())
			err := exec.Command("oc", "create", "ns", peerNs).Run()
			o.Expect(err).NotTo(o.HaveOccurred())
			err = exec.Command("oc", "label", "ns", peerNs, "team=qe").Run()
			o.Expect(err).NotTo(o.HaveOccurred())
			nsList = append(nsList, peerNs)
		}

		g.By("2. Create pods in all the namespaces, label one of the pod and obtain ovnkube-node pod for the scheduled pods in subject namespace.")
		for i, ns := range nsList {
			rcName := fmt.Sprintf("%s-test-pod-%d", testID, i)
			rc := otputils.ReplicationControllerPingPodResource{
				Name:      rcName,
				Replicas:  2,
				Namespace: ns,
				Template:  rcPingPodTemplate,
			}
			err := rc.Create(ns)
			o.Expect(err).NotTo(o.HaveOccurred())

			err = otputils.WaitForPodWithLabelReady(ns, "name="+rcName)
			o.Expect(err).NotTo(o.HaveOccurred())

			// Get pods
			output, err := exec.Command("oc", "get", "pods", "-n", ns, "-l", "name="+rcName, "-o", "jsonpath={.items[*].metadata.name}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			pods := strings.Fields(string(output))
			o.Expect(len(pods)).Should(o.Equal(2))

			// Label first pod
			err = exec.Command("oc", "label", "pod", pods[0], "-n", ns, podKey+"="+podVal).Run()
			o.Expect(err).NotTo(o.HaveOccurred())
			coloredPods[ns] = pods[0]
			unColoredPods[ns] = pods[1]

			if i == 0 {
				nodeName, err := otputils.GetPodNodeName(ns, pods[0])
				o.Expect(err).NotTo(o.HaveOccurred())
				ovnKubePod, err := otputils.GetPodName("openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
				o.Expect(err).NotTo(o.HaveOccurred())
				ovnkubeNodeColoredPods[ns] = ovnKubePod

				nodeName, err = otputils.GetPodNodeName(ns, pods[1])
				o.Expect(err).NotTo(o.HaveOccurred())
				ovnKubePod, err = otputils.GetPodName("openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
				o.Expect(err).NotTo(o.HaveOccurred())
				ovnkubeNodeUnColoredPods[ns] = ovnKubePod
			}
		}

		g.By("3. Create a BANP Policy with egress allow action and ingress deny action for subject namespace")
		banp := otputils.MultiPodMixedRuleBANPPolicyResource{
			Name:          "default",
			SubjectKey:    matchLabelKey,
			SubjectVal:    subjectNs,
			SubjectPodKey: podKey,
			SubjectPodVal: podVal,
			PolicyType1:   "egress",
			Direction1:    "to",
			RuleName1:     "default-allow-egress-to-colored-pods",
			RuleAction1:   "Allow",
			RuleKey1:      "team",
			RuleVal1:      "qe",
			RulePodKey1:   podKey,
			RulePodVal1:   podVal,
			PolicyType2:   "ingress",
			Direction2:    "from",
			RuleName2:     "default-deny-from-colored-pods",
			RuleAction2:   "Deny",
			RuleKey2:      "team",
			RuleVal2:      "qe",
			RulePodKey2:   podKey,
			RulePodVal2:   podVal,
			Template:      banpCRTemplate,
		}
		err = banp.Create()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer otputils.RemoveResource("banp", banp.Name)

		g.By("3.1 Update BANP subject pod selector.")
		patchBANP := `[{"op": "add", "path": "/spec/subject/pods/podSelector", "value": {}}]`
		err = exec.Command("oc", "patch", "baselineadminnetworkpolicy/default", "--type=json", "-p", patchBANP).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3.2 Update BANP to add another egress rule to BANP")
		patchBANP = `[{"op": "add", "path": "/spec/egress/1", "value": { "action": "Deny", "name": "default-deny-unlabelled-pods", "to": [{"pods": { "namespaceSelector": {"matchLabels": {"team": "qe"}}, "podSelector": {"matchExpressions": [{"key": "color", "operator": "DoesNotExist"}]}}}]} }]`
		err = exec.Command("oc", "patch", "baselineadminnetworkpolicy/default", "--type=json", "-p", patchBANP).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3.3 Update BANP to add another ingress rule to BANP")
		patchBANP = `[{"op": "add", "path": "/spec/ingress/1", "value": { "action": "Allow", "name": "default-allow-unlabelled-pods", "from": [{"pods": { "namespaceSelector": {"matchLabels": {"team": "qe"}}, "podSelector": {"matchExpressions": [{"key": "color", "operator": "DoesNotExist"}]}}}]} }]`
		err = exec.Command("oc", "patch", "baselineadminnetworkpolicy/default", "--type=json", "-p", patchBANP).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. BANP ACL audit logging verification for each rule")
		aclLogSearchString := "name=\"BANP:default:Egress:0\", verdict=allow, severity=alert"
		g.By(fmt.Sprintf("4.1 Verify ACL Logging for rule %s", aclLogSearchString))
		otputils.CheckACLLogs(subjectNs, coloredPods[subjectNs], nsList[1], coloredPods[nsList[1]], "pass", aclLogSearchString, ovnkubeNodeColoredPods[subjectNs], true)

		aclLogSearchString = "name=\"BANP:default:Egress:1\", verdict=drop, severity=alert"
		g.By(fmt.Sprintf("4.2 Verify ACL Logging for rule %s", aclLogSearchString))
		otputils.CheckACLLogs(subjectNs, coloredPods[subjectNs], nsList[1], unColoredPods[nsList[1]], "fail", aclLogSearchString, ovnkubeNodeColoredPods[subjectNs], true)

		aclLogSearchString = "name=\"BANP:default:Ingress:0\", verdict=drop, severity=alert"
		g.By(fmt.Sprintf("4.3 Verify ACL Logging for rule %s", aclLogSearchString))
		otputils.CheckACLLogs(nsList[2], coloredPods[nsList[2]], subjectNs, coloredPods[subjectNs], "fail", aclLogSearchString, ovnkubeNodeColoredPods[subjectNs], true)

		aclLogSearchString = "name=\"BANP:default:Ingress:1\", verdict=allow, severity=alert"
		g.By(fmt.Sprintf("4.4 Verify ACL Logging for rule %s", aclLogSearchString))
		otputils.CheckACLLogs(nsList[3], unColoredPods[nsList[3]], subjectNs, unColoredPods[subjectNs], "pass", aclLogSearchString, ovnkubeNodeUnColoredPods[subjectNs], true)

		g.By("5. Update BANP to change action on ingress from allow to deny")
		patchBANP = `[{"op": "add", "path": "/spec/egress/0/action", "value": "Deny"}]`
		err = exec.Command("oc", "patch", "baselineadminnetworkpolicy/default", "--type=json", "-p", patchBANP).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("6. Create Admin Network Policy with ingress deny from %s to %s and egress allow to %s and pass to %s from %s namespace", nsList[1], nsList[0], nsList[2], nsList[3], nsList[0]))
		anp := otputils.MultiPodMixedRuleANPPolicyResource{
			Name:          "anp-" + testID + "-1",
			SubjectKey:    matchLabelKey,
			SubjectVal:    subjectNs,
			SubjectPodKey: podKey,
			SubjectPodVal: podVal,
			Priority:      20,
			PolicyType1:   "ingress",
			Direction1:    "from",
			RuleName1:     "deny-from-" + nsList[1],
			RuleAction1:   "Deny",
			RuleKey1:      matchLabelKey,
			RuleVal1:      nsList[1],
			RulePodKey1:   podKey,
			RulePodVal1:   podVal,
			PolicyType2:   "egress",
			Direction2:    "to",
			RuleName2:     "allow-to-" + nsList[2],
			RuleAction2:   "Allow",
			RuleKey2:      matchLabelKey,
			RuleVal2:      nsList[2],
			RulePodKey2:   podKey,
			RulePodVal2:   podVal,
			RuleName3:     "pass-to-" + nsList[3],
			RuleAction3:   "Pass",
			RuleKey3:      matchLabelKey,
			RuleVal3:      nsList[3],
			RulePodKey3:   "color",
			RulePodVal3:   "red",
			Template:      anpMultiRuleCRTemplate,
		}
		err = anp.Create()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer otputils.RemoveResource("anp", anp.Name)

		aclLogSearchString = fmt.Sprintf("name=\"ANP:%s:Ingress:0\", verdict=drop, severity=alert", anp.Name)
		g.By(fmt.Sprintf("6.1 Verify ACL Logging for rule %s", aclLogSearchString))
		otputils.CheckACLLogs(nsList[1], coloredPods[nsList[1]], subjectNs, coloredPods[subjectNs], "fail", aclLogSearchString, ovnkubeNodeColoredPods[subjectNs], true)

		aclLogSearchString = fmt.Sprintf("name=\"ANP:%s:Egress:0\", verdict=allow, severity=warning", anp.Name)
		g.By(fmt.Sprintf("6.2 Verify ACL Logging for rule %s", aclLogSearchString))
		otputils.CheckACLLogs(subjectNs, coloredPods[subjectNs], nsList[2], coloredPods[nsList[2]], "pass", aclLogSearchString, ovnkubeNodeColoredPods[subjectNs], true)

		aclLogSearchString = fmt.Sprintf("name=\"ANP:%s:Egress:1\", verdict=pass, severity=info", anp.Name)
		g.By(fmt.Sprintf("6.3 Verify ACL Logging for rule %s", aclLogSearchString))
		otputils.CheckACLLogs(subjectNs, coloredPods[subjectNs], nsList[3], coloredPods[nsList[3]], "fail", aclLogSearchString, ovnkubeNodeColoredPods[subjectNs], true)

		g.By("7. Update BANP Policy annotation to see allow ACL is no longer audited")
		aclSettings := otputils.AclSettings{DenySetting: "", AllowSetting: "warning"}
		err = exec.Command("oc", "annotate", "--overwrite", "baselineadminnetworkpolicy", "default", aclSettings.GetJSONString()).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("8. Update ANP Policy ingress rule from allow to pass to verify BANP ACL logging change")
		patchANP := `[{"op": "replace", "path": "/spec/ingress/0/action", "value": "Pass" }]`
		err = exec.Command("oc", "patch", "anp", anp.Name, "--type=json", "-p", patchANP).Run()
		o.Expect(err).NotTo(o.HaveOccurred())

		aclLogSearchString = "name=\"BANP:default:Ingress:0\", verdict=drop, severity=alert"
		g.By(fmt.Sprintf("8.1 Verify ACL for rule %s in BANP is not logged", aclLogSearchString))
		otputils.CheckACLLogs(nsList[1], coloredPods[nsList[1]], subjectNs, coloredPods[subjectNs], "fail", aclLogSearchString, ovnkubeNodeColoredPods[subjectNs], false)
	})
})
