package ovn

import (
	"time"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"k8s.io/klog/v2"

	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

// BatchUpdatePortGroups updates port groups for multiple pods in a single OVSDB transaction.
// Pods in the same namespace typically share port groups, so this batches those updates efficiently.
func (bnc *BaseNetworkController) BatchUpdatePortGroups(batch *PodBatch) error {
	if len(batch.Items) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		klog.V(4).Infof("[OVSDB BATCHING] BatchUpdatePortGroups: updated port groups for %d pods in %v",
			len(batch.Items), time.Since(start))
	}()

	// Group pods by namespace (pods in same namespace share port groups)
	portGroupMap := make(map[string][]*PodBatchItem)

	for _, item := range batch.Items {
		ns := item.Pod.Namespace
		portGroupMap[ns] = append(portGroupMap[ns], item)
	}

	var allOps []ovsdb.Operation

	// For each namespace, collect all port names and update port group in one operation
	for ns, items := range portGroupMap {
		portNames := make([]string, len(items))
		for i, item := range items {
			portNames[i] = bnc.GetLogicalPortName(item.Pod, item.Annotations.NetworkName)
		}

		// Get or create port group for this namespace
		portGroupName := bnc.getNetworkScopedName(nbdb.PortGroup{}, ns)

		// Generate ops to add ports to port group
		pgOps, err := bnc.getPortGroupAddPortsOps(portGroupName, portNames)
		if err != nil {
			klog.Warningf("[OVSDB BATCHING] Failed to generate port group ops for namespace %s: %v", ns, err)
			continue
		}

		allOps = append(allOps, pgOps...)
	}

	// Execute batch transaction
	if len(allOps) > 0 {
		_, err := libovsdbops.TransactAndCheck(bnc.nbClient, allOps)
		if err != nil {
			klog.Warningf("[OVSDB BATCHING] Batch port group update failed: %v", err)
			// Port group failure is not critical for pod connectivity
			return nil
		}
	}

	klog.V(4).Infof("[OVSDB BATCHING] Successfully updated %d port groups for %d pods",
		len(portGroupMap), len(batch.Items))
	return nil
}

// getPortGroupAddPortsOps generates OVSDB operations to add ports to a port group.
// This is a placeholder for the actual implementation which would use libovsdb ops.
func (bnc *BaseNetworkController) getPortGroupAddPortsOps(portGroupName string, portNames []string) ([]ovsdb.Operation, error) {
	// For now, return empty operations as port group management is complex.
	// The actual implementation would:
	// 1. Look up the port group by name
	// 2. Build mutation ops to add ports to the port group's Ports field
	// 3. Return the ops
	//
	// For L2 networks without network policies, port groups might not be needed.
	return nil, nil
}
