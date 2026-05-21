package ovn

import (
	"context"
	"fmt"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"

	"k8s.io/klog/v2"
)

// checkSBDBLogicalFlows queries SBDB for logical flows corresponding to the SecondaryPods port group ACLs
// This verifies that NBDB ACL intent is correctly translated to SBDB logical flows
func (oc *DefaultNetworkController) checkSBDBLogicalFlows(pgName string) {
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== CHECKING SBDB LOGICAL FLOWS FOR PORT GROUP ========")

	// Find all logical flows that reference the port group
	// The port group is referenced as @<portGroupName> in flow match expressions
	pgRef := "@" + pgName

	logicalFlows := []sbdb.LogicalFlow{}
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()

	err := oc.sbClient.WhereCache(func(lf *sbdb.LogicalFlow) bool {
		return strings.Contains(lf.Match, pgRef)
	}).List(ctx, &logicalFlows)

	if err != nil {
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: CRITICAL - Failed to query SBDB logical flows: %v", err)
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: CANNOT VERIFY data plane flows - SBDB query failed")
		return
	}

	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: Found %d logical flows in SBDB referencing port group %s", len(logicalFlows), pgName)

	if len(logicalFlows) == 0 {
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: CRITICAL - NO logical flows found in SBDB for port group!")
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: SMOKING GUN: NBDB has ACLs but SBDB has NO flows - ACL translation failed!")
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: ROOT CAUSE: ovn-northd failed to translate NBDB ACLs to SBDB logical flows")
		return
	}

	// Count flow types to verify we have the expected isolation flows
	var egressDenyFlows, ingressDenyFlows, arpAllowFlows, mgmtAllowFlows int
	var otherFlows []string

	for i, lf := range logicalFlows {
		// Log first 10 flows in detail
		if i < 10 {
			klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: SBDB-FLOW[%d] table=%d priority=%d match=%q actions=%q",
				i, lf.TableID, lf.Priority, lf.Match, lf.Actions)
		}

		// Classify flow by action and match
		actions := lf.Actions
		match := lf.Match

		if strings.Contains(match, "inport == "+pgRef) && strings.Contains(actions, "drop") {
			egressDenyFlows++
		} else if strings.Contains(match, "outport == "+pgRef) && strings.Contains(actions, "drop") {
			ingressDenyFlows++
		} else if strings.Contains(match, "arp") || strings.Contains(match, "nd") {
			arpAllowFlows++
		} else if strings.Contains(match, "ip4.src") || strings.Contains(match, "ip6.src") {
			mgmtAllowFlows++
		} else {
			otherFlows = append(otherFlows, fmt.Sprintf("table=%d match=%q", lf.TableID, match))
		}
	}

	if len(logicalFlows) > 10 {
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ... and %d more flows (showing first 10)", len(logicalFlows)-10)
	}

	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: SBDB flow classification:")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK:   - Egress deny flows (inport==@pg && drop): %d", egressDenyFlows)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK:   - Ingress deny flows (outport==@pg && drop): %d", ingressDenyFlows)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK:   - ARP/ND allow flows: %d", arpAllowFlows)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK:   - Management port allow flows: %d", mgmtAllowFlows)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK:   - Other flows: %d", len(otherFlows))

	// Expected: at least 1 egress deny, 1 ingress deny, some ARP allows, some mgmt allows
	missingFlows := []string{}
	if egressDenyFlows == 0 {
		missingFlows = append(missingFlows, "egress deny (inport==@pg drop)")
	}
	if ingressDenyFlows == 0 {
		missingFlows = append(missingFlows, "ingress deny (outport==@pg drop)")
	}
	if arpAllowFlows == 0 {
		klog.Warningf("[UDN-DEBUG] PERIODIC-CHECK: WARNING - No ARP/ND allow flows found (expected at least 2)")
	}
	if mgmtAllowFlows == 0 {
		klog.Warningf("[UDN-DEBUG] PERIODIC-CHECK: WARNING - No management port allow flows found")
	}

	if len(missingFlows) > 0 {
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: CRITICAL - Missing required SBDB logical flows: %v", missingFlows)
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: SMOKING GUN: NBDB ACLs exist but corresponding SBDB flows are missing!")
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: ROOT CAUSE: Partial ACL translation - ovn-northd issue or timing race")
	} else {
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ✓ All expected SBDB flow types present (deny + ARP + mgmt)")
	}

	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== END SBDB LOGICAL FLOWS CHECK ========")
}

// logOVSFlowDiagnostics provides guidance for checking OVS flows on worker nodes
// Since ovnkube-controller runs on master, it cannot directly access worker OVS
func (oc *DefaultNetworkController) logOVSFlowDiagnostics(podName string, podIP string, nodeName string) {
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== OVS FLOW DIAGNOSTICS (MANUAL) ========")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: To verify OpenFlow rules on worker node %s:", nodeName)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 1. Check for drop flows matching pod IP %s:", podIP)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK:    oc debug node/%s -- chroot /host sh -c 'ovs-ofctl dump-flows br-int | grep %s'", nodeName, podIP)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 2. Check for port group flows (look for set actions with port group ID):")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK:    oc debug node/%s -- chroot /host sh -c 'ovs-ofctl dump-flows br-int | grep -i drop'", nodeName)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 3. Check microflow cache for active connections:")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK:    oc debug node/%s -- chroot /host sh -c 'ovs-appctl dpctl/dump-flows | grep %s'", nodeName, podIP)
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 4. Compare flow counts before and during connectivity test")
	klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== END OVS FLOW DIAGNOSTICS ========")
}
