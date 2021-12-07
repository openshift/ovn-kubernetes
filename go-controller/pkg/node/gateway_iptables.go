//go:build linux
// +build linux

package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/pkg/errors"
	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	iptableNodePortChain   = "OVN-KUBE-NODEPORT"
	iptableExternalIPChain = "OVN-KUBE-EXTERNALIP"
)

func clusterIPTablesProtocols() []iptables.Protocol {
	var protocols []iptables.Protocol
	if config.IPv4Mode {
		protocols = append(protocols, iptables.ProtocolIPv4)
	}
	if config.IPv6Mode {
		protocols = append(protocols, iptables.ProtocolIPv6)
	}
	return protocols
}

type iptRule struct {
	table    string
	chain    string
	args     []string
	protocol iptables.Protocol
}

func addIptRules(rules []iptRule) error {
	var addErrors error
	for _, r := range rules {
		klog.V(5).Infof("Adding rule in table: %s, chain: %s with args: \"%s\" for protocol: %v ", r.table, r.chain, strings.Join(r.args, " "), r.protocol)
		ipt, _ := util.GetIPTablesHelper(r.protocol)
		if err := ipt.NewChain(r.table, r.chain); err != nil {
			klog.V(5).Infof("Chain: \"%s\" in table: \"%s\" already exists, skipping creation", r.table, r.chain)
		}
		exists, err := ipt.Exists(r.table, r.chain, r.args...)
		if !exists && err == nil {
			err = ipt.Insert(r.table, r.chain, 1, r.args...)
		}
		if err != nil {
			addErrors = errors.Wrapf(addErrors, "failed to add iptables %s/%s rule %q: %v",
				r.table, r.chain, strings.Join(r.args, " "), err)
		}
	}
	return addErrors
}

func delIptRules(rules []iptRule) error {
	var delErrors error
	for _, r := range rules {
		klog.V(5).Infof("Deleting rule in table: %s, chain: %s with args: \"%s\" for protocol: %v ", r.table, r.chain, strings.Join(r.args, " "), r.protocol)
		ipt, _ := util.GetIPTablesHelper(r.protocol)
		if exists, err := ipt.Exists(r.table, r.chain, r.args...); err == nil && exists {
			err := ipt.Delete(r.table, r.chain, r.args...)
			if err != nil {
				delErrors = errors.Wrapf(delErrors, "failed to delete iptables %s/%s rule %q: %v",
					r.table, r.chain, strings.Join(r.args, " "), err)
			}
		}
	}
	return delErrors
}

func getGatewayInitRules(chain string, proto iptables.Protocol) []iptRule {
	return []iptRule{
		{
			table:    "nat",
			chain:    "PREROUTING",
			args:     []string{"-j", chain},
			protocol: proto,
		},
		{
			table:    "nat",
			chain:    "OUTPUT",
			args:     []string{"-j", chain},
			protocol: proto,
		},
	}
}

func getLegacyLocalGatewayInitRules(chain string, proto iptables.Protocol) []iptRule {
	return []iptRule{
		{
			table:    "filter",
			chain:    "FORWARD",
			args:     []string{"-j", chain},
			protocol: proto,
		},
	}
}

func getLegacySharedGatewayInitRules(chain string, proto iptables.Protocol) []iptRule {
	return []iptRule{
		{
			table:    "filter",
			chain:    "OUTPUT",
			args:     []string{"-j", chain},
			protocol: proto,
		},
		{
			table:    "filter",
			chain:    "FORWARD",
			args:     []string{"-j", chain},
			protocol: proto,
		},
	}
}

// getNodePortIPTRules returns the IPTable DNAT rules for a service of type nodePort
// `svcPort` corresponds to port details for this service as specified in the service object
// `targetIP` is clusterIP towards which the DNAT of nodePort service is to be added
// `targetPort` is the port towards which the DNAT of the nodePort service is to be added
//     case1: (applicable only in LGW mode where ETP=local) if svcDoesNotHaveLocalHostNetEndPnt=true, targetIP=types.HostETPLocalMasqueradeIP, targetPort=svcPort.NodePort
//     case2: if svcDoesNotHaveLocalHostNetEndPnt=false, targetIP=clusterIP, targetPort=svcPort.Port
func getNodePortIPTRules(svcPort kapi.ServicePort, targetIP string, targetPort int32, svcDoesNotHaveLocalHostNetEndPnt bool) []iptRule {
	var protocol iptables.Protocol
	if utilnet.IsIPv6String(targetIP) {
		protocol = iptables.ProtocolIPv6
		if svcDoesNotHaveLocalHostNetEndPnt {
			// DNAT it to the masqueradeIP:nodePort instead of clusterIP:targetPort
			targetIP = types.V6HostETPLocalMasqueradeIP
		}
	} else {
		protocol = iptables.ProtocolIPv4
		if svcDoesNotHaveLocalHostNetEndPnt {
			// DNAT it to the masqueradeIP:nodePort instead of clusterIP:targetPort
			targetIP = types.V4HostETPLocalMasqueradeIP
		}
	}
	return []iptRule{
		{
			table: "nat",
			chain: iptableNodePortChain,
			args: []string{
				"-p", string(svcPort.Protocol),
				"-m", "addrtype",
				"--dst-type", "LOCAL",
				"--dport", fmt.Sprintf("%d", svcPort.NodePort),
				"-j", "DNAT",
				"--to-destination", util.JoinHostPortInt32(targetIP, targetPort),
			},
			protocol: protocol,
		},
	}
}

// getNodePortETPLocalIPTRules returns the IPTable REDIRECT or RETURN rules for a service of type nodePort if ETP=local
// `svcPort` corresponds to port details for this service as specified in the service object
// `targetPort` is the svcPort.Port towards which the REDIRECT rule of the nodePort service is to be added i.e nodePort (redirected)->targetPort
//
//  case1: (applicable only in LGW mode) if svcDoesNotHaveLocalHostNetEndPnt=true, a RETURN rule is added to
//  iptableMgmPortChain to prevent SNAT of sourceIP
//
//  case2: if svcDoesNotHaveLocalHostNetEndPnt=false, a REJECT rule is added to iptableNodePortChain to redirect
//  traffic to the targetPort
func getNodePortETPLocalIPTRules(svcPort kapi.ServicePort, targetIP string, targetPort int32, svcDoesNotHaveLocalHostNetEndPnt bool) []iptRule {
	var protocol iptables.Protocol
	if utilnet.IsIPv6String(targetIP) {
		protocol = iptables.ProtocolIPv6
	} else {
		protocol = iptables.ProtocolIPv4
	}
	if svcDoesNotHaveLocalHostNetEndPnt {
		return []iptRule{
			{
				table: "nat",
				chain: iptableMgmPortChain,
				args: []string{
					"-p", string(svcPort.Protocol),
					"--dport", fmt.Sprintf("%d", svcPort.NodePort),
					"-j", "RETURN",
				},
				protocol: protocol,
			},
		}
	}
	return []iptRule{
		{
			table: "nat",
			chain: iptableNodePortChain,
			args: []string{
				"-p", string(svcPort.Protocol),
				"-m", "addrtype",
				"--dst-type", "LOCAL",
				"--dport", fmt.Sprintf("%d", svcPort.NodePort),
				"-j", "REDIRECT",
				"--to-port", fmt.Sprintf("%d", targetPort),
			},
			protocol: protocol,
		},
	}
}

// getExternalIPTRules returns the IPTable DNAT rules for a service of type LB or ExternalIP
// `svcPort` corresponds to port details for this service as specified in the service object
// `externalIP` can either be the externalIP or LB.status.ingressIP
// `dstIP` corresponds to the IP to which the provided externalIP needs to be DNAT-ed to
//     case1: (applicable only in LGW mode where ETP=local) if svcDoesNotHaveLocalHostNetEndPnt=true, dstIP=types.HostETPLocalMasqueradeIP
//     case2: if svcDoesNotHaveLocalHostNetEndPnt=false, dstIP=clusterIP
func getExternalIPTRules(svcPort kapi.ServicePort, externalIP, dstIP string, svcDoesNotHaveLocalHostNetEndPnt bool) []iptRule {
	var protocol iptables.Protocol
	targetPort := svcPort.Port
	if utilnet.IsIPv6String(externalIP) {
		protocol = iptables.ProtocolIPv6
		if svcDoesNotHaveLocalHostNetEndPnt {
			// DNAT it to the masqueradeIP:nodePort instead of clusterIP:Port
			dstIP = types.V6HostETPLocalMasqueradeIP
			targetPort = svcPort.NodePort
		}
	} else {
		protocol = iptables.ProtocolIPv4
		if svcDoesNotHaveLocalHostNetEndPnt {
			// DNAT it to the masqueradeIP:nodePort instead of clusterIP:Port
			dstIP = types.V4HostETPLocalMasqueradeIP
			targetPort = svcPort.NodePort
		}
	}
	return []iptRule{
		{
			table: "nat",
			chain: iptableExternalIPChain,
			args: []string{
				"-p", string(svcPort.Protocol),
				"-d", externalIP,
				"--dport", fmt.Sprintf("%v", svcPort.Port),
				"-j", "DNAT",
				"--to-destination", util.JoinHostPortInt32(dstIP, targetPort),
			},
			protocol: protocol,
		},
	}
}

func getExternalLocalIPTRules(svcPort kapi.ServicePort, externalIP string, targetPort int32) []iptRule {
	var protocol iptables.Protocol
	if utilnet.IsIPv6String(externalIP) {
		protocol = iptables.ProtocolIPv6
	} else {
		protocol = iptables.ProtocolIPv4
	}
	return []iptRule{
		{
			table: "nat",
			chain: iptableExternalIPChain,
			args: []string{
				"-p", string(svcPort.Protocol),
				"-d", externalIP,
				"--dport", fmt.Sprintf("%v", svcPort.Port),
				"-j", "REDIRECT",
				"--to-port", fmt.Sprintf("%v", targetPort),
			},
			protocol: protocol,
		},
	}
}

func getLocalGatewayNATRules(ifname string, cidr *net.IPNet) []iptRule {
	// Allow packets to/from the gateway interface in case defaults deny
	var protocol iptables.Protocol
	if utilnet.IsIPv6(cidr.IP) {
		protocol = iptables.ProtocolIPv6
	} else {
		protocol = iptables.ProtocolIPv4
	}
	return []iptRule{
		{
			table: "filter",
			chain: "FORWARD",
			args: []string{
				"-i", ifname,
				"-j", "ACCEPT",
			},
			protocol: protocol,
		},
		{
			table: "filter",
			chain: "FORWARD",
			args: []string{
				"-o", ifname,
				"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
				"-j", "ACCEPT",
			},
			protocol: protocol,
		},
		{
			table: "filter",
			chain: "INPUT",
			args: []string{
				"-i", ifname,
				"-m", "comment", "--comment", "from OVN to localhost",
				"-j", "ACCEPT",
			},
			protocol: protocol,
		},
		{
			table: "nat",
			chain: "POSTROUTING",
			args: []string{
				"-s", cidr.String(),
				"-j", "MASQUERADE",
			},
			protocol: protocol,
		},
	}
}

// initLocalGatewayNATRules sets up iptables rules for interfaces
func initLocalGatewayNATRules(ifname string, cidr *net.IPNet) error {
	return addIptRules(getLocalGatewayNATRules(ifname, cidr))
}

func handleGatewayIPTables(iptCallback func(rules []iptRule) error, genGatewayChainRules func(chain string, proto iptables.Protocol) []iptRule) error {
	rules := make([]iptRule, 0)
	for _, chain := range []string{iptableNodePortChain, iptableExternalIPChain} {
		for _, proto := range clusterIPTablesProtocols() {
			ipt, err := util.GetIPTablesHelper(proto)
			if err != nil {
				return err
			}
			if err := ipt.NewChain("nat", chain); err != nil {
				klog.V(5).Infof("Chain: \"%s\" in table: \"%s\" already exists, skipping creation", "nat", chain)
			}
			rules = append(rules, genGatewayChainRules(chain, proto)...)
		}
	}
	if err := iptCallback(rules); err != nil {
		return fmt.Errorf("failed to handle iptables rules %v: %v", rules, err)
	}
	return nil
}

func initSharedGatewayIPTables() error {
	if err := handleGatewayIPTables(addIptRules, getGatewayInitRules); err != nil {
		return err
	}
	if err := handleGatewayIPTables(delIptRules, getLegacySharedGatewayInitRules); err != nil {
		return err
	}
	return nil
}

func initLocalGatewayIPTables() error {
	if err := handleGatewayIPTables(addIptRules, getGatewayInitRules); err != nil {
		return err
	}
	if err := handleGatewayIPTables(delIptRules, getLegacyLocalGatewayInitRules); err != nil {
		return err
	}
	return nil
}

func cleanupSharedGatewayIPTChains() {
	for _, chain := range []string{iptableNodePortChain, iptableExternalIPChain} {
		// We clean up both IPv4 and IPv6, regardless of what is currently in use
		for _, proto := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
			ipt, err := util.GetIPTablesHelper(proto)
			if err != nil {
				return
			}
			_ = ipt.ClearChain("nat", chain)
			_ = ipt.DeleteChain("nat", chain)
		}
	}
}

func recreateIPTRules(table, chain string, keepIPTRules []iptRule) {
	for _, proto := range clusterIPTablesProtocols() {
		ipt, _ := util.GetIPTablesHelper(proto)
		if err := ipt.ClearChain(table, chain); err != nil {
			klog.Errorf("Error clearing chain: %s in table: %s, err: %v", chain, table, err)
		}
	}
	if err := addIptRules(keepIPTRules); err != nil {
		klog.Error(err)
	}
}

// getGatewayIPTRules returns NodePort, ExternalIP and LoadBalancer iptables rules for service.
// case1: If svcHasLocalHostNetEndPnt and svcTypeIsETPLocal, rule that redirects traffic to host targetPort is added.
//
// case2: (Only applicanle for LGW mode) If !svcHasLocalHostNetEndPnt and svcTypeIsETPLocal rules that redirect traffic
// to ovn-k8s-mp0 preserving sourceIP are added.
//
// case3: (default) In all other cases, DNAT rule towards clusterIP svc is added.
//        case3a: if externalTrafficPolicy=cluster, irrespective of gateway modes
//        case3b: if externalTrafficPolicy=local+!hasLocalHostNetworkEp+SGW mode
func getGatewayIPTRules(service *kapi.Service, svcHasLocalHostNetEndPnt bool) []iptRule {
	rules := make([]iptRule, 0)
	clusterIPs := util.GetClusterIPs(service)
	svcTypeIsETPLocal := util.ServiceExternalTrafficPolicyLocal(service)
	for _, svcPort := range service.Spec.Ports {
		if util.ServiceTypeHasNodePort(service) {
			err := util.ValidatePort(svcPort.Protocol, svcPort.NodePort)
			if err != nil {
				klog.Errorf("Skipping service: %s, invalid service NodePort: %v", svcPort.Name, err)
				continue
			}
			err = util.ValidatePort(svcPort.Protocol, svcPort.Port)
			if err != nil {
				klog.Errorf("Skipping service: %s, invalid service port %v", svcPort.Name, err)
				continue
			}
			if svcTypeIsETPLocal && svcHasLocalHostNetEndPnt {
				// case1 (see function description for details)
				// Port redirect host -> Nodeport -> host traffic directly to endpoint
				for _, clusterIP := range clusterIPs {
					rules = append(rules, getNodePortETPLocalIPTRules(svcPort, clusterIP, int32(svcPort.TargetPort.IntValue()), false)...)
				}
			} else if svcTypeIsETPLocal && !svcHasLocalHostNetEndPnt && config.Gateway.Mode == config.GatewayModeLocal {
				// case2 (see function description for details)
				// will hit this only if 1)gatewaymode=local & 2)svc.externaltrafficpolicy=local & 3)we don't have
				// any local-hostnetworked endpoints for this service (this includes 3a) endpoints.Subset is empty or
				// 3b) endpoints are host-networked but not local to this node or 3c) endpoints are ovn-podIPs).
				//
				// DNAT traffic to masqueradeIP instead of clusterIP.
				rules = append(rules, getNodePortIPTRules(svcPort, "", svcPort.NodePort, true)...)
				// add a skip SNAT rule to OVN-KUBE-SNAT-MGMTPORT to preserve sourceIP for etp=local traffic.
				rules = append(rules, getNodePortETPLocalIPTRules(svcPort, "", int32(svcPort.TargetPort.IntValue()), true)...)
			} else {
				// case3 (see function description for details)
				for _, clusterIP := range clusterIPs {
					rules = append(rules, getNodePortIPTRules(svcPort, clusterIP, svcPort.Port, false)...)
				}
			}
		}
		for _, externalIP := range service.Spec.ExternalIPs {
			err := util.ValidatePort(svcPort.Protocol, svcPort.Port)
			if err != nil {
				klog.Errorf("Skipping service: %s, invalid service port %v", svcPort.Name, err)
				continue
			}
			if clusterIP, err := util.MatchIPStringFamily(utilnet.IsIPv6String(externalIP), clusterIPs); err == nil {
				if svcTypeIsETPLocal && svcHasLocalHostNetEndPnt {
					// case1 (see function description for details)
					// Port redirect host -> ExternalIP -> host
					rules = append(rules, getExternalLocalIPTRules(svcPort, externalIP, int32(svcPort.TargetPort.IntValue()))...)
				} else if svcTypeIsETPLocal && !svcHasLocalHostNetEndPnt && config.Gateway.Mode == config.GatewayModeLocal {
					// case2 (see function description for details)
					// will hit this only if 1)gatewaymode=local & 2)svc.externaltrafficpolicy=local & 3)we don't have
					// any local-hostnetworked endpoints for this service (this includes 3a) endpoints.Subset is empty or
					// 3b) endpoints are host-networked but not local to this node or 3c) endpoints are ovn-podIPs).
					//
					// DNAT traffic to masqueradeIP:nodePort instead of clusterIP:Port. We are leveraging the existing rules for NODEPORT
					// service so no need to add skip SNAT rule to OVN-KUBE-SNAT-MGMTPORT since the corresponding nodePort svc would have one.
					rules = append(rules, getExternalIPTRules(svcPort, externalIP, "", true)...)
				} else {
					// case3 (see function description for details)
					rules = append(rules, getExternalIPTRules(svcPort, externalIP, clusterIP, false)...)
				}
			}
		}
	}
	return rules
}
