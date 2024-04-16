package adminnetworkpolicy

import (
	"fmt"

	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
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

// Descriptors used by the ClusterManagerCollector below.
var (
	anpRuleCountDesc = prometheus.NewDesc(
		"admin_network_policy_rules",
		"The total number of rules in a given admin network policy in the cluster",
		[]string{"direction", "action"}, nil,
	)
)


// ANPControllerCollector implements the Collector interface.
type ANPControllerCollector struct {
	ANPController *Controller
}

func (c *Controller) initMetricsCollector() {
	reg := prometheus.NewPedanticRegistry()
	cc := ANPControllerCollector{ANPController: c}
	prometheus.WrapRegistererWith(prometheus.Labels{"zone": c.zone}, reg).MustRegister(cc)
	// Add the standard process and Go metrics to the custom registry.
	reg.MustRegister(
		// expose process metrics like CPU, Memory, file descriptor usage etc.
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		// expose Go runtime metrics like GC stats, memory stats etc.
		collectors.NewGoCollector(),
	)
}

// Describe is implemented with DescribeByCollect. That's possible because the
// Collect method will always return the same two metrics with the same two
// descriptors.
func (cc ANPControllerCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(cc, ch)
}

func (cc ANPControllerCollector) updateANPRuleCountMetric(anpCache map[string]*adminNetworkPolicyState) int {
	for _, state := range anpCache {
		return cc.updateANPGressRuleCountMetric(string(libovsdbutil.ACLIngress), state.ingressRules, false)
		//updateANPGressRuleCountMetric(string(libovsdbutil.ACLEgress), state.egressRules, false)
	}
	return 0
}

func (cc ANPControllerCollector) updateANPGressRuleCountMetric(direction string, rules []*gressRule, isBanp bool) int {
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
	return allowCount+passCount+denyCount
	/*if isBanp {
		cc.UpdateBANPRuleCount(direction, string(anpapi.BaselineAdminNetworkPolicyRuleActionAllow), float64(allowCount))
		cc.UpdateBANPRuleCount(direction, string(anpapi.BaselineAdminNetworkPolicyRuleActionDeny), float64(denyCount))
	} else {
		cc.UpdateANPRuleCount(direction, string(anpapi.AdminNetworkPolicyRuleActionAllow), float64(allowCount))
		cc.UpdateANPRuleCount(direction, string(anpapi.AdminNetworkPolicyRuleActionDeny), float64(denyCount))
		cc.UpdateANPRuleCount(direction, string(anpapi.AdminNetworkPolicyRuleActionPass), float64(passCount))
	}*/
}

// UpdateANPRuleCount records the number of AdminNetworkPolicy rules.
/*func (cc ANPControllerCollector) UpdateANPRuleCount(direction, action string, count float64) {
	metricANPRuleCount.WithLabelValues(direction, action).Set(count)
}

// UpdateBANPRuleCount records the number of BaselineAdminNetworkPolicy rules.
func (cc ANPControllerCollector) UpdateBANPRuleCount(direction, action string, count float64) {
	metricBANPRuleCount.WithLabelValues(direction, action).Set(count)
}*/

// Collect first triggers the ReallyExpensiveAssessmentOfTheSystemState. Then it
// creates constant metrics for each host on the fly based on the returned data.
//
// Note that Collect could be called concurrently, so we depend on
// ReallyExpensiveAssessmentOfTheSystemState to be concurrency-safe.
func (cc ANPControllerCollector) Collect(ch chan<- prometheus.Metric) {
	ruleCount := cc.updateANPRuleCountMetric(cc.ANPController.anpCache)
	ch <- prometheus.MustNewConstMetric(
		anpRuleCountDesc,
		prometheus.CounterValue,
		float64(ruleCount),
		string(libovsdbutil.ACLIngress),
		"Allow",
	)
}
