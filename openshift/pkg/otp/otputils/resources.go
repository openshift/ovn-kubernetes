package otputils

import (
	"fmt"
	"strconv"
)

type ReplicationControllerPingPodResource struct {
	Name      string
	Replicas  int
	Namespace string
	Template  string
}

func (rc *ReplicationControllerPingPodResource) Create(namespace string) error {
	return ApplyResourceFromTemplate(namespace, rc.Template,
		"-p", "PODNAME="+rc.Name,
		"-p", "REPLICAS="+strconv.Itoa(rc.Replicas))
}

type MultiPodMixedRuleBANPPolicyResource struct {
	Name          string
	SubjectKey    string
	SubjectVal    string
	SubjectPodKey string
	SubjectPodVal string
	PolicyType1   string
	Direction1    string
	RuleName1     string
	RuleAction1   string
	RuleKey1      string
	RuleVal1      string
	RulePodKey1   string
	RulePodVal1   string
	PolicyType2   string
	Direction2    string
	RuleName2     string
	RuleAction2   string
	RuleKey2      string
	RuleVal2      string
	RulePodKey2   string
	RulePodVal2   string
	Template      string
}

func (banp *MultiPodMixedRuleBANPPolicyResource) Create() error {
	return ApplyResourceFromTemplate("", banp.Template,
		"-p", "NAME="+banp.Name,
		"-p", "SUBJECTKEY="+banp.SubjectKey,
		"-p", "SUBJECTVAL="+banp.SubjectVal,
		"-p", "SUBJECTPODKEY="+banp.SubjectPodKey,
		"-p", "SUBJECTPODVAL="+banp.SubjectPodVal,
		"-p", "POLICYTYPE1="+banp.PolicyType1,
		"-p", "DIRECTION1="+banp.Direction1,
		"-p", "RULENAME1="+banp.RuleName1,
		"-p", "RULEACTION1="+banp.RuleAction1,
		"-p", "RULEKEY1="+banp.RuleKey1,
		"-p", "RULEVAL1="+banp.RuleVal1,
		"-p", "RULEPODKEY1="+banp.RulePodKey1,
		"-p", "RULEPODVAL1="+banp.RulePodVal1,
		"-p", "POLICYTYPE2="+banp.PolicyType2,
		"-p", "DIRECTION2="+banp.Direction2,
		"-p", "RULENAME2="+banp.RuleName2,
		"-p", "RULEACTION2="+banp.RuleAction2,
		"-p", "RULEKEY2="+banp.RuleKey2,
		"-p", "RULEVAL2="+banp.RuleVal2,
		"-p", "RULEPODKEY2="+banp.RulePodKey2,
		"-p", "RULEPODVAL2="+banp.RulePodVal2)
}

type MultiPodMixedRuleANPPolicyResource struct {
	Name          string
	SubjectKey    string
	SubjectVal    string
	SubjectPodKey string
	SubjectPodVal string
	Priority      int32
	PolicyType1   string
	Direction1    string
	RuleName1     string
	RuleAction1   string
	RuleKey1      string
	RuleVal1      string
	RulePodKey1   string
	RulePodVal1   string
	PolicyType2   string
	Direction2    string
	RuleName2     string
	RuleAction2   string
	RuleKey2      string
	RuleVal2      string
	RulePodKey2   string
	RulePodVal2   string
	RuleName3     string
	RuleAction3   string
	RuleKey3      string
	RuleVal3      string
	RulePodKey3   string
	RulePodVal3   string
	Template      string
}

func (anp *MultiPodMixedRuleANPPolicyResource) Create() error {
	return ApplyResourceFromTemplate("", anp.Template,
		"-p", "NAME="+anp.Name,
		"-p", "SUBJECTKEY="+anp.SubjectKey,
		"-p", "SUBJECTVAL="+anp.SubjectVal,
		"-p", "SUBJECTPODKEY="+anp.SubjectPodKey,
		"-p", "SUBJECTPODVAL="+anp.SubjectPodVal,
		"-p", "PRIORITY="+strconv.Itoa(int(anp.Priority)),
		"-p", "POLICYTYPE1="+anp.PolicyType1,
		"-p", "DIRECTION1="+anp.Direction1,
		"-p", "RULENAME1="+anp.RuleName1,
		"-p", "RULEACTION1="+anp.RuleAction1,
		"-p", "RULEKEY1="+anp.RuleKey1,
		"-p", "RULEVAL1="+anp.RuleVal1,
		"-p", "RULEPODKEY1="+anp.RulePodKey1,
		"-p", "RULEPODVAL1="+anp.RulePodVal1,
		"-p", "POLICYTYPE2="+anp.PolicyType2,
		"-p", "DIRECTION2="+anp.Direction2,
		"-p", "RULENAME2="+anp.RuleName2,
		"-p", "RULEACTION2="+anp.RuleAction2,
		"-p", "RULEKEY2="+anp.RuleKey2,
		"-p", "RULEVAL2="+anp.RuleVal2,
		"-p", "RULEPODKEY2="+anp.RulePodKey2,
		"-p", "RULEPODVAL2="+anp.RulePodVal2,
		"-p", "RULENAME3="+anp.RuleName3,
		"-p", "RULEACTION3="+anp.RuleAction3,
		"-p", "RULEKEY3="+anp.RuleKey3,
		"-p", "RULEVAL3="+anp.RuleVal3,
		"-p", "RULEPODKEY3="+anp.RulePodKey3,
		"-p", "RULEPODVAL3="+anp.RulePodVal3)
}

type SingleRuleANPMEPolicyResource struct {
	Name            string
	SubjectKey      string
	SubjectOperator string
	SubjectVal      string
	Priority        int32
	PolicyType      string
	Direction       string
	RuleName        string
	RuleAction      string
	RuleKey         string
	RuleOperator    string
	RuleVal         string
	Template        string
}

func (anp *SingleRuleANPMEPolicyResource) Create() error {
	return ApplyResourceFromTemplate("", anp.Template,
		"-p", "NAME="+anp.Name,
		"-p", "SUBJECTKEY="+anp.SubjectKey,
		"-p", "SUBJECTOPERATOR="+anp.SubjectOperator,
		"-p", "SUBJECTVAL="+anp.SubjectVal,
		"-p", "PRIORITY="+strconv.Itoa(int(anp.Priority)),
		"-p", "POLICYTYPE="+anp.PolicyType,
		"-p", "DIRECTION="+anp.Direction,
		"-p", "RULENAME="+anp.RuleName,
		"-p", "RULEACTION="+anp.RuleAction,
		"-p", "RULEKEY="+anp.RuleKey,
		"-p", "RULEOPERATOR="+anp.RuleOperator,
		"-p", "RULEVAL="+anp.RuleVal)
}

type SingleRuleANPPolicyResourceNode struct {
	Name       string
	SubjectKey string
	SubjectVal string
	Priority   int32
	PolicyType string
	Direction  string
	RuleName   string
	RuleAction string
	RuleKey    string
	NodeKey    string
	RuleVal    string
	ActionName string
	ActionType string
	Template   string
}

func (anp *SingleRuleANPPolicyResourceNode) Create() error {
	return ApplyResourceFromTemplate("", anp.Template,
		"-p", "NAME="+anp.Name,
		"-p", "SUBJECTKEY="+anp.SubjectKey,
		"-p", "SUBJECTVAL="+anp.SubjectVal,
		"-p", "PRIORITY="+strconv.Itoa(int(anp.Priority)),
		"-p", "POLICYTYPE="+anp.PolicyType,
		"-p", "DIRECTION="+anp.Direction,
		"-p", "RULENAME="+anp.RuleName,
		"-p", "RULEACTION="+anp.RuleAction,
		"-p", "RULEKEY="+anp.RuleKey,
		"-p", "NODEKEY="+anp.NodeKey,
		"-p", "RULEVAL="+anp.RuleVal,
		"-p", "ACTIONNAME="+anp.ActionName,
		"-p", "ACTIONTYPE="+anp.ActionType)
}

type AclSettings struct {
	DenySetting  string `json:"deny,omitempty"`
	AllowSetting string `json:"allow,omitempty"`
}

func (s *AclSettings) GetJSONString() string {
	return fmt.Sprintf("{\"k8s.ovn.org/acl-logging\": \"{\\\"deny\\\": \\\"%s\\\", \\\"allow\\\": \\\"%s\\\"}\"}", s.DenySetting, s.AllowSetting)
}

// GetAnnotationArg returns the acl-logging annotation as an `oc annotate` key=value argument.
func (s *AclSettings) GetAnnotationArg() string {
	return fmt.Sprintf(`k8s.ovn.org/acl-logging={"deny": "%s", "allow": "%s"}`, s.DenySetting, s.AllowSetting)
}
