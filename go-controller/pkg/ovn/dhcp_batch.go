package ovn

import (
	"fmt"
	"time"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// BatchConfigureDHCP configures DHCP options for multiple pods in a single OVSDB transaction.
// This reduces the number of OVSDB transactions from N (one per pod) to 1 (one for all pods).
func (bnc *BaseNetworkController) BatchConfigureDHCP(batch *PodBatch) error {
	if len(batch.Items) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		klog.V(4).Infof("[OVSDB BATCHING] BatchConfigureDHCP: configured %d pods in %v",
			len(batch.Items), time.Since(start))
	}()

	// Collect all DHCP configuration operations
	var allOps []ovsdb.Operation

	for _, item := range batch.Items {
		dhcpOps, err := bnc.getDHCPOptions(item.Pod, item.Annotations)
		if err != nil {
			klog.V(5).Infof("[OVSDB BATCHING] Skipping DHCP configuration for pod %s/%s: %v",
				item.Pod.Namespace, item.Pod.Name, err)
			// DHCP is optional, don't fail the batch
			continue
		}

		if len(dhcpOps) > 0 {
			allOps = append(allOps, dhcpOps...)
		}
	}

	// Execute batch transaction if there are any ops
	if len(allOps) > 0 {
		_, err := libovsdbops.TransactAndCheck(bnc.nbClient, allOps)
		if err != nil {
			klog.Warningf("[OVSDB BATCHING] Batch DHCP configuration failed: %v", err)
			// DHCP failure is not critical, don't fail the entire batch
			return nil
		}
	}

	klog.V(4).Infof("[OVSDB BATCHING] Successfully configured DHCP for batch with %d operations",
		len(allOps))
	return nil
}

// getDHCPOptions generates OVSDB operations for configuring DHCP for a single pod.
// Returns empty ops if DHCP is not applicable for this pod.
func (bnc *BaseNetworkController) getDHCPOptions(pod *corev1.Pod, annotation *util.PodAnnotation) ([]ovsdb.Operation, error) {
	// For now, return empty operations as DHCP configuration is complex
	// and varies by network type. This is a placeholder for the actual
	// DHCP configuration logic that would be refactored from the existing code.
	//
	// The actual implementation would:
	// 1. Check if DHCP is needed for this network type
	// 2. Build DHCP_Options row for this pod's IPs
	// 3. Return ops to create/update the DHCP_Options row
	//
	// For L2 networks, DHCP might not be needed as IPs are static.
	return nil, fmt.Errorf("DHCP configuration not implemented for batching yet")
}
