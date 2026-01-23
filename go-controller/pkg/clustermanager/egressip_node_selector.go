package clustermanager

import (
	"os"
	"sync"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// OCP HACK: EgressIP node selector support
// This file contains downstream-only functionality for filtering EgressIP
// assignment based on node selector labels. When enabled via
// ENABLE_EGRESSIP_NODE_SELECTOR=true environment variable, the value of the
// egress-assignable label is parsed as a label selector that must match
// EgressIP object labels.
//
// Example:
//   Node label: k8s.ovn.org/egress-assignable=zone=east
//   EgressIP labels: zone=east
//   Result: EgressIP can be assigned to this node
//
// Limitations:
// - Changes to the label VALUE do not trigger re-reconciliation of existing
//   assignments. Only new assignments will respect the updated selector.
// END OCP HACK

var (
	egressIPNodeSelectorEnabled     bool
	egressIPNodeSelectorEnabledOnce sync.Once
)

// isEgressIPNodeSelectorEnabled checks if the feature is enabled via environment variable.
// The result is cached after the first call.
func isEgressIPNodeSelectorEnabled() bool {
	egressIPNodeSelectorEnabledOnce.Do(func() {
		egressIPNodeSelectorEnabled = os.Getenv("ENABLE_EGRESSIP_NODE_SELECTOR") == "true"
		if egressIPNodeSelectorEnabled {
			klog.Info("EgressIP node selector feature is enabled")
		}
	})
	return egressIPNodeSelectorEnabled
}

// filterEgressNodesForEgressIP filters the assignable nodes based on EgressIP labels.
// It looks up nodes from the watchFactory to get current label values, then filters
// based on selector matching. Returns the original slice if feature is disabled.
//
// Parameters:
//   - nodes: slice of egressNode pointers (from getSortedEgressData)
//   - egressIPName: name of the EgressIP object
//   - watchFactory: factory to look up Node and EgressIP objects
//
// Returns filtered slice of nodes that can accept the EgressIP.
func filterEgressNodesForEgressIP(nodes []*egressNode, egressIPName string, wf *factory.WatchFactory) []*egressNode {
	if !isEgressIPNodeSelectorEnabled() {
		return nodes
	}

	// Get the EgressIP object to retrieve its labels
	eip, err := wf.GetEgressIP(egressIPName)
	if err != nil {
		klog.Infof("Could not get EgressIP %s for node selector filtering: %v", egressIPName, err)
		return nodes
	}

	if len(eip.Labels) == 0 {
		// No labels on EgressIP, all nodes are eligible
		return nodes
	}

	egressIPLabels := labels.Set(eip.Labels)
	filtered := make([]*egressNode, 0, len(nodes))

	for _, eNode := range nodes {
		// Look up the actual Node object to get current label values
		node, err := wf.GetNode(eNode.name)
		if err != nil {
			klog.Infof("Could not get node %s for selector check: %v", eNode.name, err)
			continue
		}

		// Parse the selector from the node's egress-assignable label value
		nodeEgressLabel := util.GetNodeEgressLabel()
		labelValue := node.Labels[nodeEgressLabel]

		// Empty label value means accept all EgressIPs
		if labelValue == "" {
			filtered = append(filtered, eNode)
			continue
		}

		// Parse and match the selector
		selector, err := labels.Parse(labelValue)
		if err != nil {
			klog.Warningf("Failed to parse egress selector %q for node %s: %v, treating is as no value", labelValue, eNode.name, err)
			filtered = append(filtered, eNode)
			continue
		}

		if selector.Matches(egressIPLabels) {
			filtered = append(filtered, eNode)
		}
	}

	if len(filtered) < len(nodes) {
		klog.Infof("EgressIP %s: filtered %d/%d nodes based on selector matching", egressIPName, len(filtered), len(nodes))
	}

	return filtered
}
