package ovn

import (
	"fmt"
	"net"
	"strings"

	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	utilnet "k8s.io/utils/net"
)

type egressIPLocal struct {
	egressIPMode
}

func (e *egressIPLocal) addPodEgressIP(eIP *egressipv1.EgressIP, pod *kapi.Pod) error {
	podIPs := e.getPodIPs(pod)
	if podIPs == nil {
		e.podRetry.Store(getPodKey(pod), true)
		return nil
	}
	if e.needsRetry(pod) {
		e.podRetry.Delete(getPodKey(pod))
	}
	for _, status := range eIP.Status.Items {
		if err := e.createEgressReroutePolicy(podIPs, status, eIP.Name); err != nil {
			return fmt.Errorf("unable to create logical router policy for status: %v, err: %v", status, err)
		}
		mark := util.IPToUint32(status.EgressIP)
		if err := e.createEgressPacketMarkPolicy(podIPs, status, mark, eIP.Name); err != nil {
			return fmt.Errorf("unable to create logical router policy for packet mark on status: %v, err: %v", status, err)
		}
	}
	return nil
}

func (e *egressIPLocal) deletePodEgressIP(eIP *egressipv1.EgressIP, pod *kapi.Pod) error {
	podIPs := e.getPodIPs(pod)
	if podIPs == nil {
		return nil
	}
	for _, status := range eIP.Status.Items {
		if err := e.deleteEgressReroutePolicy(podIPs, status, eIP.Name); err != nil {
			return fmt.Errorf("unable to delete logical router policy for status: %v, err: %v", status, err)
		}
		mark := util.IPToUint32(status.EgressIP)
		if err := e.deleteEgressPacketMarkPolicy(podIPs, status, mark, eIP.Name); err != nil {
			return fmt.Errorf("unable to create logical router policy for packet mark on status: %v, err: %v", status, err)
		}
	}
	return nil
}

func (e *egressIPLocal) createEgressPacketMarkPolicy(podIps []net.IP, status egressipv1.EgressIPStatusItem, packetMark uint32, egressIPName string) error {
	isEgressIPv6 := utilnet.IsIPv6String(status.EgressIP)
	for _, podIP := range podIps {
		var err error
		var stderr, filterOption string
		if isEgressIPv6 && utilnet.IsIPv6(podIP) {
			filterOption = fmt.Sprintf("ip6.src == %s", podIP.String())
		} else if !isEgressIPv6 && !utilnet.IsIPv6(podIP) {
			filterOption = fmt.Sprintf("ip4.src == %s", podIP.String())
		}
		policyIDs, err := findPacketMarkPolicyIDs(filterOption, egressIPName, status, packetMark)
		if err != nil {
			return err
		}
		if policyIDs == nil {
			_, stderr, err = util.RunOVNNbctl(
				"--id=@lr-policy",
				"create",
				"logical_router_policy",
				"action=allow",
				fmt.Sprintf("match=\"%s\"", filterOption),
				fmt.Sprintf("priority=%v", egressIPReroutePriority),
				fmt.Sprintf("external_ids:name=%s", egressIPName),
				fmt.Sprintf("external_ids:node=%s", status.Node),
				fmt.Sprintf("options:pkt_mark=%v", packetMark),
				"--",
				"add",
				"logical_router",
				fmt.Sprintf("GR_%s", status.Node),
				"policies",
				"@lr-policy",
			)
			if err != nil {
				return fmt.Errorf("unable to create logical router policy: %s, stderr: %s, err: %v", status.EgressIP, stderr, err)
			}
		}
	}
	return nil
}

func (e *egressIPLocal) deleteEgressPacketMarkPolicy(podIps []net.IP, status egressipv1.EgressIPStatusItem, packetMark uint32, egressIPName string) error {
	for _, podIP := range podIps {
		var filterOption string
		if utilnet.IsIPv6(podIP) && utilnet.IsIPv6String(status.EgressIP) {
			filterOption = fmt.Sprintf("ip6.src == %s", podIP.String())
		} else if !utilnet.IsIPv6(podIP) && !utilnet.IsIPv6String(status.EgressIP) {
			filterOption = fmt.Sprintf("ip4.src == %s", podIP.String())
		}
		policyIDs, err := findPacketMarkPolicyIDs(filterOption, egressIPName, status, packetMark)
		if err != nil {
			return err
		}
		for _, policyID := range policyIDs {
			_, stderr, err := util.RunOVNNbctl(
				"remove",
				"logical_router",
				fmt.Sprintf("GR_%s", status.Node),
				"policies",
				policyID,
			)
			if err != nil {
				return fmt.Errorf("unable to remove logical router policy: %s, stderr: %s, err: %v", status.EgressIP, stderr, err)
			}
		}
	}
	return nil
}

func findPacketMarkPolicyIDs(filterOption, egressIPName string, status egressipv1.EgressIPStatusItem, packetMark uint32) ([]string, error) {
	policyIDs, stderr, err := util.RunOVNNbctl(
		"--format=csv",
		"--data=bare",
		"--no-heading",
		"--columns=_uuid",
		"find",
		"logical_router_policy",
		"action=allow",
		fmt.Sprintf("match=\"%s\"", filterOption),
		fmt.Sprintf("priority=%v", egressIPReroutePriority),
		fmt.Sprintf("external_ids:name=%s", egressIPName),
		fmt.Sprintf("external_ids:node=%s", status.Node),
		fmt.Sprintf("options:pkt_mark=%v", packetMark),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to find logical router policy for EgressIP: %s, stderr: %s, err: %v", egressIPName, stderr, err)
	}
	if policyIDs == "" {
		return nil, nil
	}
	return strings.Split(policyIDs, "\n"), nil
}
