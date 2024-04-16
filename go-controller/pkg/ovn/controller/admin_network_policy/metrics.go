package adminnetworkpolicy

import (
	"fmt"

	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/prometheus/client_golang/prometheus"
	anpapi "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

/*var metricANPRuleCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: metrics.MetricOvnkubeNamespace,
	Subsystem: metrics.MetricOvnkubeSubsystemController,
	Name:      "admin_network_policy_rules", // doing a sum across all ANPs will give the absolute count in the cluster
	Help:      "The total number of rules in a given admin network policy in the cluster"},
	[]string{
		"direction", // direction is either "ingress" or "egress"; so cardinality is max 2 for this label
		"action",    // action is either "Pass" or "Allow" or "Deny"; so cardinality is max 3 for this label
	},
)

var metricBANPRuleCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: metrics.MetricOvnkubeNamespace,
	Subsystem: metrics.MetricOvnkubeSubsystemController,
	Name:      "baseline_admin_network_policy_rules",
	Help:      "The total number of rules in a given baseline admin network policy in the cluster"},
	[]string{
		"direction", // direction is either "ingress" or "egress"; so cardinality is max 2 for this label
		"action",    // action is either "Allow" or "Deny"; so cardinality is max 2 for this label
	},
)*/

// Descriptors used by the ANPControllerCollector below.
var (
	anpRuleCountDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metrics.MetricOvnkubeNamespace, metrics.MetricOvnkubeSubsystemController, "admin_network_policy_rules"),
		"The total number of rules across all admin network policies in the cluster",
		[]string{"direction", "action"}, nil,
	)
)

func (c *Controller) initMetricsCollector() {
	prometheus.MustRegister(c)
}

// Describe is implemented with DescribeByCollect. That's possible because the
// Collect method will always return the same two metrics with the same two
// descriptors.
func (c *Controller) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func (c *Controller) fetchANPRuleCountMetric() map[string]map[string]int {
	c.RLock()
	defer c.RUnlock()
	ruleCount := map[string]map[string]int{
		string(libovsdbutil.ACLIngress): {
			string(anpapi.AdminNetworkPolicyRuleActionAllow): 0,
			string(anpapi.AdminNetworkPolicyRuleActionPass):  0,
			string(anpapi.AdminNetworkPolicyRuleActionDeny):  0,
		},
		string(libovsdbutil.ACLEgress): {
			string(anpapi.AdminNetworkPolicyRuleActionAllow): 0,
			string(anpapi.AdminNetworkPolicyRuleActionPass):  0,
			string(anpapi.AdminNetworkPolicyRuleActionDeny):  0,
		},
	}
	for _, state := range c.anpCache {
		allow, pass, deny := c.countRules(state.ingressRules)
		ruleCount[string(libovsdbutil.ACLIngress)][string(anpapi.AdminNetworkPolicyRuleActionAllow)] += allow
		ruleCount[string(libovsdbutil.ACLIngress)][string(anpapi.AdminNetworkPolicyRuleActionPass)] += pass
		ruleCount[string(libovsdbutil.ACLIngress)][string(anpapi.AdminNetworkPolicyRuleActionDeny)] += deny
		allow, pass, deny = c.countRules(state.egressRules)
		ruleCount[string(libovsdbutil.ACLEgress)][string(anpapi.AdminNetworkPolicyRuleActionAllow)] += allow
		ruleCount[string(libovsdbutil.ACLEgress)][string(anpapi.AdminNetworkPolicyRuleActionPass)] += pass
		ruleCount[string(libovsdbutil.ACLEgress)][string(anpapi.AdminNetworkPolicyRuleActionDeny)] += deny
	}
	return ruleCount
}

func (c *Controller) countRules(rules []*gressRule) (int, int, int) {
	var passCount, allowCount, denyCount int
	for _, rule := range rules {
		switch rule.action {
		case nbdb.ACLActionAllowRelated:
			allowCount++
		case nbdb.ACLActionDrop:
			denyCount++
		case nbdb.ACLActionPass:
			passCount++
		default:
			panic(fmt.Sprintf("Failed to count rule type: unknown acl action %s", rule.action))
		}
	}
	return allowCount, passCount, denyCount
}

// Collect first triggers the fetchANPRuleCountMetric. Then it
// creates constant metrics for each host on the fly based on the returned data.
//
// Note that Collect could be called concurrently, so we depend on
// fetchANPRuleCountMetric to be concurrency-safe.
func (c *Controller) Collect(ch chan<- prometheus.Metric) {
	ruleCount := c.fetchANPRuleCountMetric()
	for direction, actions := range ruleCount {
		for action, count := range actions {
			ch <- prometheus.MustNewConstMetric(
				anpRuleCountDesc,
				prometheus.CounterValue,
				float64(count),
				direction,
				action,
			)
		}
	}
}
