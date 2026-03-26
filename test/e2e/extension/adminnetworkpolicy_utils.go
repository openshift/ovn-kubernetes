package networking

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"github.com/tidwall/gjson"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"

	o "github.com/onsi/gomega"
)

// Struct to create BANP with either ingress or egress single rule
// Match Label selector
type singleRuleBANPPolicyResource struct {
	name       string
	subjectKey string
	subjectVal string
	policyType string
	direction  string
	ruleName   string
	ruleAction string
	ruleKey    string
	ruleVal    string
	template   string
}

// Struct to create BANP with either ingress or egress multiple rules
// Match Label selector
// egress to
// ingress from
type multiRuleBANPPolicyResource struct {
	name        string
	subjectKey  string
	subjectVal  string
	policyType  string
	direction   string
	ruleName1   string
	ruleAction1 string
	ruleKey1    string
	ruleVal1    string
	ruleName2   string
	ruleAction2 string
	ruleKey2    string
	ruleVal2    string
	ruleName3   string
	ruleAction3 string
	ruleKey3    string
	ruleVal3    string
	template    string
}

type singleRuleBANPPolicyResourceNode struct {
	name       string
	subjectKey string
	subjectVal string
	policyType string
	direction  string
	ruleName   string
	ruleAction string
	ruleKey    string
	template   string
}

// Rule using MatchExpressions
type singleRuleBANPMEPolicyResource struct {
	name            string
	subjectKey      string
	subjectOperator string
	subjectVal      string
	policyType      string
	direction       string
	ruleName        string
	ruleAction      string
	ruleKey         string
	ruleOperator    string
	ruleVal         string
	template        string
}

// Struct to create BANP multiple rules with mixed ingress or egress direction
// Match Label selector
// pod peer
type multiPodMixedRuleBANPPolicyResource struct {
	name          string
	subjectKey    string
	subjectVal    string
	subjectPodKey string
	subjectPodVal string
	policyType1   string
	direction1    string
	ruleName1     string
	ruleAction1   string
	ruleKey1      string
	ruleVal1      string
	rulePodKey1   string
	rulePodVal1   string
	policyType2   string
	direction2    string
	ruleName2     string
	ruleAction2   string
	ruleKey2      string
	ruleVal2      string
	rulePodKey2   string
	rulePodVal2   string
	template      string
}

// Struct to create ANP with either ingress or egress single rule
// Match Label selector
// egress to
// ingress from
type singleRuleANPPolicyResource struct {
	name       string
	subjectKey string
	subjectVal string
	priority   int32
	policyType string
	direction  string
	ruleName   string
	ruleAction string
	ruleKey    string
	ruleVal    string
	template   string
}

type singleRuleANPPolicyResourceNode struct {
	name       string
	subjectKey string
	subjectVal string
	priority   int32
	policyType string
	direction  string
	ruleName   string
	ruleAction string
	ruleKey    string
	nodeKey    string
	ruleVal    string
	actionname string
	actiontype string
	template   string
}

// Struct to create ANP with either ingress or egress multiple rules
// Match Label selector
// egress to
// ingress from
type multiRuleANPPolicyResource struct {
	name        string
	subjectKey  string
	subjectVal  string
	priority    int32
	policyType  string
	direction   string
	ruleName1   string
	ruleAction1 string
	ruleKey1    string
	ruleVal1    string
	ruleName2   string
	ruleAction2 string
	ruleKey2    string
	ruleVal2    string
	ruleName3   string
	ruleAction3 string
	ruleKey3    string
	ruleVal3    string
	template    string
}

// Struct to create ANP with multiple rules ingress or egress direction
// Match Label selector
// pods peer
// Two rules of the three will have same direction but action may vary
type multiPodMixedRuleANPPolicyResource struct {
	name          string
	subjectKey    string
	subjectVal    string
	subjectPodKey string
	subjectPodVal string
	priority      int32
	policyType1   string
	direction1    string
	ruleName1     string
	ruleAction1   string
	ruleKey1      string
	ruleVal1      string
	rulePodKey1   string
	rulePodVal1   string
	policyType2   string
	direction2    string
	ruleName2     string
	ruleAction2   string
	ruleKey2      string
	ruleVal2      string
	rulePodKey2   string
	rulePodVal2   string
	ruleName3     string
	ruleAction3   string
	ruleKey3      string
	ruleVal3      string
	rulePodKey3   string
	rulePodVal3   string
	template      string
}

// Struct to create ANP with single ingress or egress direction
// Match Label selector
// pods or namespace peer
type singlePodRuleANPPolicyResource struct {
	name          string
	subjectKey    string
	subjectVal    string
	subjectPodKey string
	subjectPodVal string
	priority      int32
	policyType    string
	direction     string
	ruleName      string
	ruleAction    string
	ruleKey       string
	ruleVal       string
	rulePodKey    string
	rulePodVal    string
	template      string
}

type networkPolicyResource struct {
	name             string
	namespace        string
	policy           string
	direction1       string
	namespaceSel1    string
	namespaceSelKey1 string
	namespaceSelVal1 string
	direction2       string `json:omitempty`
	namespaceSel2    string `json:omitempty`
	namespaceSelKey2 string `json:omitempty`
	namespaceSelVal2 string `json:omitempty`
	policyType       string
	template         string
}

// Resource to create a network policy with protocol
// Namespace and Pod Selector
// policy - egress or ingress
// policyType - Egress or Ingress
type networkPolicyProtocolResource struct {
	name            string
	namespace       string
	policy          string
	policyType      string
	direction       string
	namespaceSel    string
	namespaceSelKey string
	namespaceSelVal string
	podSel          string
	podSelKey       string
	podSelVal       string
	port            int
	protocol        string
	template        string
}
type replicationControllerPingPodResource struct {
	name      string
	replicas  int
	namespace string
	template  string
}

// Struct to create BANP with either ingress and egress rule
// Match cidr
type singleRuleCIDRBANPPolicyResource struct {
	name       string
	subjectKey string
	subjectVal string
	ruleName   string
	ruleAction string
	cidr       string
	template   string
}

// Struct to create ANP with either ingress or egress rule
// Match cidr
type singleRuleCIDRANPPolicyResource struct {
	name       string
	subjectKey string
	subjectVal string
	priority   int32
	ruleName   string
	ruleAction string
	cidr       string
	template   string
}

// Struct to create ANP with multiple rules either ingress or egress direction
// Match cidr
type MultiRuleCIDRANPPolicyResource struct {
	name        string
	subjectKey  string
	subjectVal  string
	priority    int32
	ruleName1   string
	ruleAction1 string
	cidr1       string
	ruleName2   string
	ruleAction2 string
	cidr2       string
	template    string
}

// Struct to create ANP with either ingress or egress single rule
// Match Expression selector
// egress to
// ingress from
type singleRuleANPMEPolicyResource struct {
	name            string
	subjectKey      string
	subjectOperator string
	subjectVal      string
	priority        int32
	policyType      string
	direction       string
	ruleName        string
	ruleAction      string
	ruleKey         string
	ruleOperator    string
	ruleVal         string
	template        string
}

func (banp *singleRuleBANPPolicyResource) createSingleRuleBANP(oc *exutil.CLI) {
	compat_otp.By("Creating single rule Baseline Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", banp.template, "-p", "NAME="+banp.name,
			"SUBJECTKEY="+banp.subjectKey, "SUBJECTVAL="+banp.subjectVal,
			"POLICYTYPE="+banp.policyType, "DIRECTION="+banp.direction,
			"RULENAME="+banp.ruleName, "RULEACTION="+banp.ruleAction, "RULEKEY="+banp.ruleKey, "RULEVAL="+banp.ruleVal)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Baseline Admin Network Policy CR %v", banp.name))
}

func (banp *singleRuleBANPPolicyResourceNode) createSingleRuleBANPNode(oc *exutil.CLI) {
	compat_otp.By("Creating single rule Baseline Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", banp.template, "-p", "NAME="+banp.name,
			"SUBJECTKEY="+banp.subjectKey, "SUBJECTVAL="+banp.subjectVal,
			"POLICYTYPE="+banp.policyType, "DIRECTION="+banp.direction,
			"RULENAME="+banp.ruleName, "RULEACTION="+banp.ruleAction, "RULEKEY="+banp.ruleKey)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Baseline Admin Network Policy CR %v", banp.name))
}

func (banp *multiRuleBANPPolicyResource) createMultiRuleBANP(oc *exutil.CLI) {
	compat_otp.By("Creating Multi rule Baseline Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", banp.template, "-p", "NAME="+banp.name,
			"SUBJECTKEY="+banp.subjectKey, "SUBJECTVAL="+banp.subjectVal,
			"POLICYTYPE="+banp.policyType, "DIRECTION="+banp.direction,
			"RULENAME1="+banp.ruleName1, "RULEACTION1="+banp.ruleAction1, "RULEKEY1="+banp.ruleKey1, "RULEVAL1="+banp.ruleVal1,
			"RULENAME2="+banp.ruleName2, "RULEACTION2="+banp.ruleAction2, "RULEKEY2="+banp.ruleKey2, "RULEVAL2="+banp.ruleVal2,
			"RULENAME3="+banp.ruleName3, "RULEACTION3="+banp.ruleAction3, "RULEKEY3="+banp.ruleKey3, "RULEVAL3="+banp.ruleVal3)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", banp.name))
}

func (banp *singleRuleBANPMEPolicyResource) createSingleRuleBANPMatchExp(oc *exutil.CLI) {
	compat_otp.By("Creating single rule Baseline Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", banp.template, "-p", "NAME="+banp.name,
			"SUBJECTKEY="+banp.subjectKey, "SUBJECTOPERATOR="+banp.subjectOperator, "SUBJECTVAL="+banp.subjectVal,
			"POLICYTYPE="+banp.policyType, "DIRECTION="+banp.direction,
			"RULENAME="+banp.ruleName, "RULEACTION="+banp.ruleAction,
			"RULEKEY="+banp.ruleKey, "RULEOPERATOR="+banp.ruleOperator, "RULEVAL="+banp.ruleVal)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Baseline Admin Network Policy CR %v", banp.name))
}

func (banp *multiPodMixedRuleBANPPolicyResource) createMultiPodMixedRuleBANP(oc *exutil.CLI) {
	compat_otp.By("Creating Multi rule Baseline Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", banp.template, "-p", "NAME="+banp.name,
			"SUBJECTKEY="+banp.subjectKey, "SUBJECTVAL="+banp.subjectVal, "SUBJECTPODKEY="+banp.subjectPodKey, "SUBJECTPODVAL="+banp.subjectPodVal,
			"POLICYTYPE1="+banp.policyType1, "DIRECTION1="+banp.direction1, "RULENAME1="+banp.ruleName1, "RULEACTION1="+banp.ruleAction1,
			"RULEKEY1="+banp.ruleKey1, "RULEVAL1="+banp.ruleVal1, "RULEPODKEY1="+banp.rulePodKey1, "RULEPODVAL1="+banp.rulePodVal1,
			"POLICYTYPE2="+banp.policyType2, "DIRECTION2="+banp.direction2, "RULENAME2="+banp.ruleName2, "RULEACTION2="+banp.ruleAction2,
			"RULEKEY2="+banp.ruleKey2, "RULEVAL2="+banp.ruleVal2, "RULEPODKEY2="+banp.rulePodKey2, "RULEPODVAL2="+banp.rulePodVal2)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", banp.name))
}

func (anp *singleRuleANPPolicyResource) createSingleRuleANP(oc *exutil.CLI) {
	compat_otp.By("Creating Single rule Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.template, "-p", "NAME="+anp.name,
			"POLICYTYPE="+anp.policyType, "DIRECTION="+anp.direction,
			"SUBJECTKEY="+anp.subjectKey, "SUBJECTVAL="+anp.subjectVal,
			"PRIORITY="+strconv.Itoa(int(anp.priority)), "RULENAME="+anp.ruleName, "RULEACTION="+anp.ruleAction, "RULEKEY="+anp.ruleKey, "RULEVAL="+anp.ruleVal)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.name))
}

func (anp *singleRuleANPPolicyResourceNode) createSingleRuleANPNode(oc *exutil.CLI) {
	compat_otp.By("Creating Single rule Admin Network Policy from template for Node")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.template, "-p", "NAME="+anp.name,
			"POLICYTYPE="+anp.policyType, "DIRECTION="+anp.direction,
			"SUBJECTKEY="+anp.subjectKey, "SUBJECTVAL="+anp.subjectVal,
			"PRIORITY="+strconv.Itoa(int(anp.priority)), "RULENAME="+anp.ruleName, "RULEACTION="+anp.ruleAction, "RULEKEY="+anp.ruleKey, "NODEKEY="+anp.nodeKey, "RULEVAL="+anp.ruleVal, "ACTIONNAME="+anp.actionname, "ACTIONTYPE="+anp.actiontype)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.name))
}

func (anp *multiRuleANPPolicyResource) createMultiRuleANP(oc *exutil.CLI) {
	compat_otp.By("Creating Multi rule Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.template, "-p", "NAME="+anp.name, "PRIORITY="+strconv.Itoa(int(anp.priority)),
			"SUBJECTKEY="+anp.subjectKey, "SUBJECTVAL="+anp.subjectVal,
			"POLICYTYPE="+anp.policyType, "DIRECTION="+anp.direction,
			"RULENAME1="+anp.ruleName1, "RULEACTION1="+anp.ruleAction1, "RULEKEY1="+anp.ruleKey1, "RULEVAL1="+anp.ruleVal1,
			"RULENAME2="+anp.ruleName2, "RULEACTION2="+anp.ruleAction2, "RULEKEY2="+anp.ruleKey2, "RULEVAL2="+anp.ruleVal2,
			"RULENAME3="+anp.ruleName3, "RULEACTION3="+anp.ruleAction3, "RULEKEY3="+anp.ruleKey2, "RULEVAL3="+anp.ruleVal3)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.name))
}

func (anp *singleRuleANPMEPolicyResource) createSingleRuleANPMatchExp(oc *exutil.CLI) {
	compat_otp.By("Creating Single rule Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.template, "-p", "NAME="+anp.name,
			"POLICYTYPE="+anp.policyType, "DIRECTION="+anp.direction,
			"SUBJECTKEY="+anp.subjectKey, "SUBJECTOPERATOR="+anp.subjectOperator, "SUBJECTVAL="+anp.subjectVal,
			"PRIORITY="+strconv.Itoa(int(anp.priority)), "RULENAME="+anp.ruleName, "RULEACTION="+anp.ruleAction,
			"RULEKEY="+anp.ruleKey, "RULEOPERATOR="+anp.ruleOperator, "RULEVAL="+anp.ruleVal)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.name))
}
func (anp *multiPodMixedRuleANPPolicyResource) createMultiPodMixedRuleANP(oc *exutil.CLI) {
	compat_otp.By("Creating Multi rule Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.template, "-p", "NAME="+anp.name, "PRIORITY="+strconv.Itoa(int(anp.priority)),
			"SUBJECTKEY="+anp.subjectKey, "SUBJECTVAL="+anp.subjectVal, "SUBJECTPODKEY="+anp.subjectPodKey, "SUBJECTPODVAL="+anp.subjectPodVal,
			"POLICYTYPE1="+anp.policyType1, "DIRECTION1="+anp.direction1, "RULENAME1="+anp.ruleName1, "RULEACTION1="+anp.ruleAction1,
			"RULEKEY1="+anp.ruleKey1, "RULEVAL1="+anp.ruleVal1, "RULEPODKEY1="+anp.rulePodKey1, "RULEPODVAL1="+anp.rulePodVal1,
			"POLICYTYPE2="+anp.policyType2, "DIRECTION2="+anp.direction2, "RULENAME2="+anp.ruleName2, "RULEACTION2="+anp.ruleAction2,
			"RULEKEY2="+anp.ruleKey2, "RULEVAL2="+anp.ruleVal2, "RULEPODKEY2="+anp.rulePodKey2, "RULEPODVAL2="+anp.rulePodVal2,
			"RULENAME3="+anp.ruleName3, "RULEACTION3="+anp.ruleAction3,
			"RULEKEY3="+anp.ruleKey2, "RULEVAL3="+anp.ruleVal3, "RULEPODKEY3="+anp.rulePodKey2, "RULEPODVAL3="+anp.rulePodVal3)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.name))
}

func (anp *singlePodRuleANPPolicyResource) createSinglePodRuleANP(oc *exutil.CLI) {
	compat_otp.By(fmt.Sprintf("Creating Single Rule Admin Network Policy from template %s", anp.template))
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.template, "-p", "NAME="+anp.name, "PRIORITY="+strconv.Itoa(int(anp.priority)),
			"SUBJECTKEY="+anp.subjectKey, "SUBJECTVAL="+anp.subjectVal, "SUBJECTPODKEY="+anp.subjectPodKey, "SUBJECTPODVAL="+anp.subjectPodVal,
			"POLICYTYPE="+anp.policyType, "DIRECTION="+anp.direction, "RULENAME="+anp.ruleName, "RULEACTION="+anp.ruleAction,
			"RULEKEY="+anp.ruleKey, "RULEVAL="+anp.ruleVal, "RULEPODKEY="+anp.rulePodKey, "RULEPODVAL="+anp.rulePodVal)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.name))
}
func (rcPingPod *replicationControllerPingPodResource) createReplicaController(oc *exutil.CLI) {
	compat_otp.By("Creating replication controller from template")
	replicasString := fmt.Sprintf("REPLICAS=%v", rcPingPod.replicas)
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", rcPingPod.template, "-p", "PODNAME="+rcPingPod.name,
			"NAMESPACE="+rcPingPod.namespace, replicasString)
		if err1 != nil {
			e2e.Logf("Error creating replication controller:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create replicationcontroller %v", rcPingPod.name))
}

func (netpol *networkPolicyResource) createNetworkPolicy(oc *exutil.CLI) {
	compat_otp.By("Creating networkpolicy from template")

	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", netpol.template, "-p", "NAME="+netpol.name,
			"NAMESPACE="+netpol.namespace, "POLICY="+netpol.policy,
			"DIRECTION1="+netpol.direction1,
			"NAMESPACESEL1="+netpol.namespaceSel1, "NAMESPACESELKEY1="+netpol.namespaceSelKey1, "NAMESPACESELVAL1="+netpol.namespaceSelVal1,
			"DIRECTION2="+netpol.direction2,
			"NAMESPACESEL2="+netpol.namespaceSel2, "NAMESPACESELKEY2="+netpol.namespaceSelKey2, "NAMESPACESELVAL2="+netpol.namespaceSelVal2,
			"POLICYTYPE="+netpol.policyType)
		if err1 != nil {
			e2e.Logf("Error creating networkpolicy :%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create networkpolicy %v", netpol.name))
}

func (netpol *networkPolicyProtocolResource) createProtocolNetworkPolicy(oc *exutil.CLI) {
	compat_otp.By("Creating protocol networkpolicy from template")
	portString := fmt.Sprintf("PORT=%v", netpol.port)

	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", netpol.template, "-p", "NAME="+netpol.name,
			"NAMESPACE="+netpol.namespace, "POLICY="+netpol.policy, "POLICYTYPE="+netpol.policyType,
			"DIRECTION="+netpol.direction,
			"NAMESPACESEL="+netpol.namespaceSel, "NAMESPACESELKEY="+netpol.namespaceSelKey, "NAMESPACESELVAL="+netpol.namespaceSelVal,
			"PODSEL="+netpol.podSel, "PODSELKEY="+netpol.podSelKey, "PODSELVAL="+netpol.podSelVal,
			"PROTOCOL="+netpol.protocol, portString)
		if err1 != nil {
			e2e.Logf("Error creating networkpolicy :%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create networkpolicy %v", netpol.name))
}

func (banp *singleRuleCIDRBANPPolicyResource) createSingleRuleCIDRBANP(oc *exutil.CLI) {
	compat_otp.By("Creating single rule Baseline Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", banp.template, "-p", "NAME="+banp.name,
			"SUBJECTKEY="+banp.subjectKey, "SUBJECTVAL="+banp.subjectVal,
			"RULENAME="+banp.ruleName, "RULEACTION="+banp.ruleAction, "CIDR="+banp.cidr)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Baseline Admin Network Policy CR %v", banp.name))
}

func (anp *singleRuleCIDRANPPolicyResource) createSingleRuleCIDRANP(oc *exutil.CLI) {
	compat_otp.By("Creating Single rule Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.template, "-p", "NAME="+anp.name,
			"SUBJECTKEY="+anp.subjectKey, "SUBJECTVAL="+anp.subjectVal,
			"PRIORITY="+strconv.Itoa(int(anp.priority)), "RULENAME="+anp.ruleName, "RULEACTION="+anp.ruleAction, "CIDR="+anp.cidr)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.name))
}

func (anp *MultiRuleCIDRANPPolicyResource) createMultiRuleCIDRANP(oc *exutil.CLI) {
	compat_otp.By("Creating multi-rules Admin Network Policy from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.template, "-p", "NAME="+anp.name,
			"SUBJECTKEY="+anp.subjectKey, "SUBJECTVAL="+anp.subjectVal,
			"PRIORITY="+strconv.Itoa(int(anp.priority)), "RULENAME1="+anp.ruleName1, "RULEACTION1="+anp.ruleAction1, "CIDR1="+anp.cidr1,
			"RULENAME2="+anp.ruleName2, "RULEACTION2="+anp.ruleAction2, "CIDR2="+anp.cidr2)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.name))
}

func checkUDPTraffic(oc *exutil.CLI, clientPodName string, clientPodNamespace string, serverPodName string, serverPodNamespace string, serverUdpPort string, resultPass bool) {
	e2e.Logf("Listening on pod %s at port %s", serverPodName, serverUdpPort)
	ipStackType := checkIPStackType(oc)
	var udpServerPodIPList []string
	switch ipStackType {
	case "ipv4single":
		udpServerPodIPList = append(udpServerPodIPList, getPodIPv4(oc, serverPodNamespace, serverPodName))
	case "ipv6single":
		udpServerPodIPList = append(udpServerPodIPList, getPodIPv6(oc, serverPodNamespace, serverPodName, ipStackType))
	case "dualstack":
		udpServerPodIPList = append(udpServerPodIPList, getPodIPv4(oc, serverPodNamespace, serverPodName))
		udpServerPodIPList = append(udpServerPodIPList, getPodIPv6(oc, serverPodNamespace, serverPodName, ipStackType))
	default:
		e2e.Logf("Stack type could not be determined")
	}
	udpServerCmd := fmt.Sprintf("timeout --preserve-status 60 ncat -u -l %s", serverUdpPort)
	for _, udpServerPodIP := range udpServerPodIPList {
		cmdNcat, cmdOutput, _, ncatCmdErr := oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", serverPodNamespace, serverPodName, "bash", "-c", udpServerCmd).Background()
		defer cmdNcat.Process.Kill()
		o.Expect(ncatCmdErr).NotTo(o.HaveOccurred())

		e2e.Logf("Sending UDP packets to pod %s", serverPodName)
		cmd := fmt.Sprintf("echo hello | ncat -v -u %s %s", udpServerPodIP, serverUdpPort)
		for i := 0; i < 2; i++ {
			output, ncatCmdErr := execCommandInSpecificPod(oc, clientPodNamespace, clientPodName, cmd)
			o.Expect(ncatCmdErr).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(string(output), "bytes sent")).To(o.BeTrue())
		}
		e2e.Logf("UDP pod server output %s", cmdOutput)
		if resultPass {
			o.Expect(strings.Contains(cmdOutput.String(), "hello")).To(o.BeTrue())
		} else {
			o.Expect(strings.Contains(cmdOutput.String(), "hello")).To(o.BeFalse())
		}
		cmdNcat.Process.Kill()
	}
}

func checkSCTPTraffic(oc *exutil.CLI, clientPodName string, clientPodNamespace string, serverPodName string, serverPodNamespace string, resultPass bool) {
	ipStackType := checkIPStackType(oc)
	var sctpServerPodIPList []string
	switch ipStackType {
	case "ipv4single":
		sctpServerPodIPList = append(sctpServerPodIPList, getPodIPv4(oc, serverPodNamespace, serverPodName))
	case "ipv6single":
		sctpServerPodIPList = append(sctpServerPodIPList, getPodIPv6(oc, serverPodNamespace, serverPodName, ipStackType))
	case "dualstack":
		sctpServerPodIPList = append(sctpServerPodIPList, getPodIPv4(oc, serverPodNamespace, serverPodName))
		sctpServerPodIPList = append(sctpServerPodIPList, getPodIPv6(oc, serverPodNamespace, serverPodName, ipStackType))
	default:
		e2e.Logf("Stack type could not be determined")
	}
	for _, sctpServerPodIP := range sctpServerPodIPList {
		e2e.Logf("SCTP server pod listening for sctp traffic")
		cmdNcat, _, _, err := oc.AsAdmin().Run("exec").Args("-n", serverPodNamespace, serverPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
		defer cmdNcat.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		e2e.Logf("Check SCTP process running in the SCTP server pod")
		o.Eventually(func() string {
			msg, err := e2eoutput.RunHostCmd(serverPodNamespace, serverPodName, "ps aux | grep sctp")
			o.Expect(err).NotTo(o.HaveOccurred())
			return msg
		}, "10s", "5s").Should(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "No SCTP process running on SCTP server pod")

		e2e.Logf("SCTP client pod sending SCTP traffic")
		_, err1 := e2eoutput.RunHostCmd(clientPodNamespace, clientPodName, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")
		if resultPass {
			o.Expect(err1).NotTo(o.HaveOccurred())
			compat_otp.By("Server SCTP process will end after receiving SCTP traffic from SCTP client")
			o.Eventually(func() string {
				msg, err := e2eoutput.RunHostCmd(serverPodNamespace, serverPodName, "ps aux | grep sctp")
				o.Expect(err).NotTo(o.HaveOccurred())
				return msg
			}, "10s", "5s").ShouldNot(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "SCTP process didn't end after getting SCTP traffic from SCTP client")
		} else {
			e2e.Logf("SCTP traffic is blocked")
			o.Expect(err1).To(o.HaveOccurred())
		}
		cmdNcat.Process.Kill()
	}
}

func checkACLLogs(oc *exutil.CLI, serverPodNs string, serverPodName string, clientPodNs string, clientPodName string, curlCmd string, aclLogSearchString string, ovnKNodePodName string, resultPass bool) {
	tailACLLog := "tail -f /var/log/ovn/acl-audit-log.log"
	tailACLLogCmd, cmdOutput, _, cmdErr := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-ovn-kubernetes", ovnKNodePodName, "-c", "ovn-controller", "--", "/bin/bash", "-c", tailACLLog).Background()
	defer tailACLLogCmd.Process.Kill()
	o.Expect(cmdErr).NotTo(o.HaveOccurred())
	if curlCmd == "pass" {
		CurlPod2PodPass(oc, serverPodNs, serverPodName, clientPodNs, clientPodName)
	} else {
		CurlPod2PodFail(oc, serverPodNs, serverPodName, clientPodNs, clientPodName)
	}
	e2e.Logf("Log output: \n %s", cmdOutput.String())
	if resultPass {
		o.Expect(strings.Contains(cmdOutput.String(), aclLogSearchString)).To(o.BeTrue())
		e2e.Logf("Found the expected string - %s", aclLogSearchString)
	} else {
		o.Expect(strings.Contains(cmdOutput.String(), aclLogSearchString)).To(o.BeFalse())
	}
	tailACLLogCmd.Process.Kill()

}

func checkSpecificPolicyStatus(oc *exutil.CLI, policyType string, policyName string, lookupStatusKey string, expectedStatusStr string) (result bool, resultMsg string) {
	e2e.Logf("Checking status of %s named %s for '%s' in '%s'", strings.ToUpper(policyType), policyName, expectedStatusStr, lookupStatusKey)
	result = true
	resultMsg = ""
	allNodes, err := compat_otp.GetAllNodes(oc)
	if err != nil {
		return false, fmt.Sprintf("%v", err)
	}
	statusOutput, messagesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args(policyType, policyName, `-ojsonpath={.status}`).Output()
	if messagesErr != nil {
		return false, fmt.Sprintf("%v", messagesErr)
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(statusOutput), &data)
	allConditions := data["conditions"].([]interface{})
	if len(allConditions) != len(allNodes) {
		resultMsg = "Failed to obtain status for all nodes in cluster"
		return false, resultMsg
	}
	for i := 0; i < len(allConditions); i++ {
		for statusKey, statusVal := range allConditions[i].(map[string]interface{}) {
			if statusKey == lookupStatusKey && !strings.Contains(statusVal.(string), expectedStatusStr) {
				resultMsg = fmt.Sprintf("Failed to find: %s", expectedStatusStr)
				return false, resultMsg
			}
		}

	}

	return result, resultMsg
}

func getPolicyMetrics(oc *exutil.CLI, metricsName string, expectedValue string, addArgs ...string) (bool, error) {
	metricsValue := ""
	switch argCount := len(addArgs); argCount {
	case 1:
		e2e.Logf("Obtaining metrics %s for DB Object - %s", metricsName, addArgs[0])
	case 2:
		e2e.Logf("Obtaining metrics %s for %s rule and %s action", metricsName, addArgs[0], addArgs[1])
	default:
		e2e.Logf("Obtaining metrics %s without any additional arguments", metricsName)
	}
	result := true
	olmToken, err := compat_otp.GetSAToken(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(olmToken).NotTo(o.BeEmpty())
	url := fmt.Sprintf("localhost:9090/api/v1/query?query=%s", metricsName)
	metricsErr := wait.Poll(5*time.Second, 30*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "-c", "prometheus", "prometheus-k8s-0", "--", "curl", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", olmToken), fmt.Sprintf("%s", url)).Output()
		if err != nil {
			e2e.Logf("Unable to get metrics and try again, the error is:%s", err)
			result = false
			return result, nil
		}
		metric := gjson.Get(output, "data.result.#.metric")
		for index, metricVal := range metric.Array() {
			metricMap := metricVal.Map()
			if strings.Contains((metricMap["__name__"]).String(), "rules") {
				if !(strings.Contains((metricMap["direction"]).String(), addArgs[0]) && strings.Contains((metricMap["action"]).String(), addArgs[1])) {
					continue
				}
			} else if strings.Contains((metricMap["__name__"]).String(), "db") {
				if !(strings.Contains((metricMap["table_name"]).String(), addArgs[0])) {
					continue
				}
			}
			val := gjson.Get(output, "data.result."+strconv.Itoa(index)+".value")
			metricsValue = strings.TrimSuffix(strings.Split(val.String(), ",")[1], "]")
		}
		if !strings.Contains(metricsValue, expectedValue) {
			result = false
			e2e.Logf("The value for %s is not %s as expected", metricsName, expectedValue)
			return result, nil
		} else {
			result = true
			e2e.Logf("The value for %s is %s as expected", metricsName, expectedValue)
			return result, nil
		}
	})
	compat_otp.AssertWaitPollNoErr(metricsErr, fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
	return result, nil
}

// Perform nslookup of the url provided with IP address of google DNS server
func verifyNslookup(oc *exutil.CLI, clientPodName string, clientPodNamespace string, urlToLookup string, resultPass bool) {

	var cmdList = []string{}
	ipStackType := checkIPStackType(oc)
	o.Expect(ipStackType).NotTo(o.BeEmpty())

	if ipStackType == "dualstack" {
		cmdList = append(cmdList, "nslookup "+urlToLookup+" 8.8.8.8")
		if checkIPv6PublicAccess(oc) {
			cmdList = append(cmdList, "nslookup "+urlToLookup+" 2001:4860:4860::8888")
		}
	} else {
		if ipStackType == "ipv6single" && checkIPv6PublicAccess(oc) {
			cmdList = append(cmdList, "nslookup "+urlToLookup+" 2001:4860:4860::8888")
		} else {
			cmdList = append(cmdList, "nslookup "+urlToLookup+" 8.8.8.8")
		}

	}
	for _, cmd := range cmdList {
		res, err := compat_otp.RemoteShPodWithBash(oc, clientPodNamespace, clientPodName, cmd)
		if resultPass {
			e2e.Logf("nslookup is allowed")
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(res, "www.facebook.com")).Should(o.BeTrue(), fmt.Sprintf("The nslookup did not succeed as expected:%s", res))
		} else {
			e2e.Logf("nslookup is blocked")
			o.Expect(err).To(o.HaveOccurred())
			o.Expect(strings.Contains(res, "connection timed out; no servers could be reached")).Should(o.BeTrue(), fmt.Sprintf("The nslookup did not fail as expected:%s", res))
		}
	}

}
