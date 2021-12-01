package services

import (
	"fmt"
	"reflect"
	"strings"

	globalconfig "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovnlb "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/loadbalancer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// magic string used in vips to indicate that the node's physical
// ips should be substituted in
const placeholderNodeIPs = "node"

// lbConfig is the abstract desired load balancer configuration.
// vips and endpoints are mixed families.
type lbConfig struct {
	vips     []string    // just ip or the special value "node" for the node's physical IPs (i.e. NodePort)
	protocol v1.Protocol // TCP, UDP, or SCTP
	inport   int32       // the incoming (virtual) port number
	eps      util.LbEndpoints

	// if true, then vips added on the router are in "local" mode
	// that means, skipSNAT, and remove any non-local endpoints.
	// (see below)
	externalTrafficLocal bool
}

// just used for consistent ordering
var protos = []v1.Protocol{
	v1.ProtocolTCP,
	v1.ProtocolUDP,
	v1.ProtocolSCTP,
}

// buildServiceLBConfigs generates the abstract load balancer(s) configurations for each service. The abstract configurations
// are then expanded in buildClusterLBs and buildPerNodeLBs to the full list of OVN LBs desired.
//
// It creates two lists of configurations:
// - the per-node configs, which are load balancers that, for some reason must be expanded per-node. (see below for why)
// - the cluster-wide configs, which are load balancers that can be the same across the whole cluster.
//
// For a "standard" ClusterIP service (possibly with ExternalIPS or external LoadBalancer Status IPs),
// a single cluster-wide LB will be created.
//
// Per-node LBs will be created for
// - services with NodePort set
// - services with host-network endpoints (for shared gateway mode)
// - services with ExternalTrafficPolicy=Local
func buildServiceLBConfigs(service *v1.Service, endpointSlices []*discovery.EndpointSlice) (perNodeConfigs []lbConfig, clusterConfigs []lbConfig) {
	// For each svcPort, determine if it will be applied per-node or cluster-wide
	for _, svcPort := range service.Spec.Ports {
		eps := util.GetLbEndpoints(endpointSlices, svcPort)

		// if ExternalTrafficPolicy is local, then we need to do things a bit differently
		externalTrafficLocal := globalconfig.Gateway.Mode == globalconfig.GatewayModeShared &&
			service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal

		// NodePort services get a per-node load balancer, but with the node's physical IP as the vip
		// Thus, the vip "node" will be expanded later.
		if svcPort.NodePort != 0 {
			nodePortLBConfig := lbConfig{
				protocol:             svcPort.Protocol,
				inport:               svcPort.NodePort,
				vips:                 []string{placeholderNodeIPs}, // shortcut for all-physical-ips
				eps:                  eps,
				externalTrafficLocal: externalTrafficLocal,
			}
			perNodeConfigs = append(perNodeConfigs, nodePortLBConfig)
		}

		// Build up list of vips
		vips := append([]string{}, service.Spec.ClusterIPs...)
		// Handle old clusters w/o v6 support
		if len(vips) == 0 {
			vips = []string{service.Spec.ClusterIP}
		}
		externalVips := []string{}
		// ExternalIP
		externalVips = append(externalVips, service.Spec.ExternalIPs...)
		// LoadBalancer status
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				externalVips = append(externalVips, ingress.IP)
			}
		}

		// if ETP=Local, then treat ExternalIPs and LoadBalancer IPs specially
		// otherwise, they're just cluster IPs
		if externalTrafficLocal && len(externalVips) > 0 {
			externalIPConfig := lbConfig{
				protocol:             svcPort.Protocol,
				inport:               svcPort.Port,
				vips:                 externalVips,
				eps:                  eps,
				externalTrafficLocal: true,
			}
			perNodeConfigs = append(perNodeConfigs, externalIPConfig)
		} else {
			vips = append(vips, externalVips...)
		}

		// Build the clusterIP config
		// This is NEVER influenced by ExternalTrafficPolicy
		clusterIPConfig := lbConfig{
			protocol:             svcPort.Protocol,
			inport:               svcPort.Port,
			vips:                 vips,
			eps:                  eps,
			externalTrafficLocal: false, // always false for ClusterIPs
		}

		// Normally, the ClusterIP LB is global (on all node switches and routers),
		// unless both of the following are true:
		// - We're in shared gateway mode, and
		// - Any of the endpoints are host-network
		//
		// In that case, we need to create per-node LBs.
		if globalconfig.Gateway.Mode == globalconfig.GatewayModeShared &&
			(hasHostEndpoints(eps.V4IPs) || hasHostEndpoints(eps.V6IPs)) {
			perNodeConfigs = append(perNodeConfigs, clusterIPConfig)
		} else {
			clusterConfigs = append(clusterConfigs, clusterIPConfig)
		}
	}

	return
}

// makeLBName creates the load balancer name - used to minimize churn
func makeLBName(service *v1.Service, proto v1.Protocol, scope string) string {
	return fmt.Sprintf("Service_%s/%s_%s_%s",
		service.Namespace, service.Name,
		proto, scope,
	)
}

// buildClusterLBs takes a list of lbConfigs and aggregates them
// in to one ovn LB per protocol.
//
// It takes a list of (proto:[vips]:port -> [endpoints]) configs and re-aggregates
// them to a list of (proto:[vip:port -> [endpoint:port]])
// This load balancer is attached to all node switches. In shared-GW mode, it is also on all routers
func buildClusterLBs(service *v1.Service, configs []lbConfig, nodeInfos []nodeInfo, useLBGroup bool) []ovnlb.LB {
	var nodeSwitches []string
	var nodeRouters []string
	var groups []string
	if useLBGroup {
		nodeSwitches = make([]string, 0)
		nodeRouters = make([]string, 0)
		groups = []string{types.ClusterLBGroupName}
	} else {
		nodeSwitches = make([]string, 0)
		nodeRouters = make([]string, 0)
		groups = make([]string, 0)

		for _, node := range nodeInfos {
			nodeSwitches = append(nodeSwitches, node.switchName)
			// For shared gateway, add to the node's GWR as well.
			// The node may not have a gateway router - it might be waiting initialization, or
			// might have disabled GWR creation via the k8s.ovn.org/l3-gateway-config annotation
			if globalconfig.Gateway.Mode == globalconfig.GatewayModeShared && node.gatewayRouterName != "" {
				nodeRouters = append(nodeRouters, node.gatewayRouterName)
			}
		}
	}

	cbp := configsByProto(configs)

	out := []ovnlb.LB{}
	for _, proto := range protos {
		cfgs, ok := cbp[proto]
		if !ok {
			continue
		}
		lb := ovnlb.LB{
			Name:        makeLBName(service, proto, "cluster"),
			Protocol:    string(proto),
			ExternalIDs: util.ExternalIDsForObject(service),
			Opts:        lbOpts(service),

			Switches: nodeSwitches,
			Routers:  nodeRouters,
			Groups:   groups,
		}

		for _, config := range cfgs {
			if config.externalTrafficLocal {
				klog.Errorf("BUG: service %s/%s has routerLocalMode=true for cluster-wide lbConfig",
					service.Namespace, service.Name)
			}

			v4targets := make([]ovnlb.Addr, 0, len(config.eps.V4IPs))
			for _, tgt := range config.eps.V4IPs {
				v4targets = append(v4targets, ovnlb.Addr{
					IP:   tgt,
					Port: config.eps.Port,
				})
			}

			v6targets := make([]ovnlb.Addr, 0, len(config.eps.V6IPs))
			for _, tgt := range config.eps.V6IPs {
				v6targets = append(v6targets, ovnlb.Addr{
					IP:   tgt,
					Port: config.eps.Port,
				})
			}

			rules := make([]ovnlb.LBRule, 0, len(config.vips))
			for _, vip := range config.vips {
				if vip == placeholderNodeIPs {
					klog.Errorf("BUG: service %s/%s has a \"node\" vip for a cluster-wide lbConfig",
						service.Namespace, service.Name)
					continue
				}
				targets := v4targets
				if utilnet.IsIPv6String(vip) {
					targets = v6targets
				}

				rules = append(rules, ovnlb.LBRule{
					Source: ovnlb.Addr{
						IP:   vip,
						Port: config.inport,
					},
					Targets: targets,
				})
			}
			lb.Rules = append(lb.Rules, rules...)
		}

		out = append(out, lb)
	}
	return out
}

// buildPerNodeLBs takes a list of lbConfigs and expands them to one LB per protocol per node
// This works differently based on whether or not we're in shared or local gateway mode.
//
// For local gateway, per-node lbs are created for:
// - nodePort services, attached to each node's switch, vips are node's physical IPs
//
// For shared gateway, per-node lbs are created for
// - clusterip services with host-network endpoints are attached to each node's gateway router + switch
// - nodeport services are attached to each node's gateway router + switch, vips are node's physical IPs
// - any services with host-network endpoints
// - services with external IPs / LoadBalancer Status IPs
//
// HOWEVER, we need to replace, on each nodes gateway router only, any host-network endpoints with a special loopback address
// see https://github.com/ovn-org/ovn-kubernetes/blob/master/docs/design/host_to_services_OpenFlow.md
// This is for host -> serviceip -> host hairpin
//
// For ExternalTrafficPolicy, all "External" IPs (NodePort, ExternalIPs, Loadbalancer Status) have:
// - targets filtered to only local targets
// - SkipSNAT enabled
// This results in the creation of an additional load balancer on the GatewayRouters.
func buildPerNodeLBs(service *v1.Service, configs []lbConfig, nodes []nodeInfo) []ovnlb.LB {
	cbp := configsByProto(configs)
	eids := util.ExternalIDsForObject(service)

	out := make([]ovnlb.LB, 0, len(nodes)*len(configs))

	// output is one LB per node per protocol
	// with one rule per vip
	for _, node := range nodes {
		for _, proto := range protos {
			configs, ok := cbp[proto]
			if !ok {
				continue
			}

			// local gateway mode - attach to switch only
			// shared gateway mode - attach to router & switch,
			// rules may or may not be different
			// localRouterRules are rules with no snat
			routerRules := make([]ovnlb.LBRule, 0, len(configs))
			noSNATRouterRules := make([]ovnlb.LBRule, 0)
			switchRules := make([]ovnlb.LBRule, 0, len(configs))

			for _, config := range configs {
				vips := config.vips

				routerV4targetips := config.eps.V4IPs
				routerV6targetips := config.eps.V6IPs

				// shared gateway needs to "massage" some of the targets
				if globalconfig.Gateway.Mode == "shared" {
					// for ExternalTrafficPolicy=Local, then remove non-local endpoints from the router targets
					if config.externalTrafficLocal {
						routerV4targetips = util.FilterIPsSlice(routerV4targetips, node.nodeSubnets(), true)
						routerV6targetips = util.FilterIPsSlice(routerV6targetips, node.nodeSubnets(), true)
					}

					// at this point, the targets may be empty

					// any targets local to the node need to have a special
					// harpin IP added, but only for the router LB
					routerV4targetips = util.UpdateIPsSlice(routerV4targetips, node.nodeIPs, []string{types.V4HostMasqueradeIP})
					routerV6targetips = util.UpdateIPsSlice(routerV6targetips, node.nodeIPs, []string{types.V6HostMasqueradeIP})
				}

				routerV4targets := ovnlb.JoinHostsPort(routerV4targetips, config.eps.Port)
				routerV6targets := ovnlb.JoinHostsPort(routerV6targetips, config.eps.Port)

				switchV4Targets := ovnlb.JoinHostsPort(config.eps.V4IPs, config.eps.Port)
				switchV6Targets := ovnlb.JoinHostsPort(config.eps.V6IPs, config.eps.Port)

				// Substitute the special vip "node" for the node's physical ips
				// This is used for nodeport
				vips = make([]string, 0, len(vips))
				for _, vip := range config.vips {
					if vip == placeholderNodeIPs {
						vips = append(vips, node.nodeIPs...)
					} else {
						vips = append(vips, vip)
					}
				}

				for _, vip := range vips {
					isv6 := utilnet.IsIPv6String((vip))
					// build switch rules
					targets := switchV4Targets
					if isv6 {
						targets = switchV6Targets
					}

					switchRules = append(switchRules, ovnlb.LBRule{
						Source:  ovnlb.Addr{IP: vip, Port: config.inport},
						Targets: targets,
					})

					// For shared gateway, there is also a per-router rule
					// with targets that *may* be different
					if globalconfig.Gateway.Mode == "shared" {
						targets := routerV4targets
						if isv6 {
							targets = routerV6targets
						}
						rule := ovnlb.LBRule{
							Source:  ovnlb.Addr{IP: vip, Port: config.inport},
							Targets: targets,
						}

						// in other words, is this ExternalTrafficPolicy=local?
						// if so, this gets a separate load balancer with SNAT disabled
						// (but there's no need to do this if the list of targets is empty)
						if config.externalTrafficLocal && len(targets) > 0 {
							noSNATRouterRules = append(noSNATRouterRules, rule)
						} else {
							routerRules = append(routerRules, rule)
						}
					}
				}
			}

			// If switch and router rules are identical, coalesce
			if reflect.DeepEqual(switchRules, routerRules) && len(switchRules) > 0 && node.gatewayRouterName != "" {
				out = append(out, ovnlb.LB{
					Name:        makeLBName(service, proto, "node_router+switch_"+node.name),
					Protocol:    string(proto),
					ExternalIDs: eids,
					Opts:        lbOpts(service),
					Routers:     []string{node.gatewayRouterName},
					Switches:    []string{node.switchName},
					Rules:       routerRules,
				})
			} else {
				if len(routerRules) > 0 && node.gatewayRouterName != "" {
					out = append(out, ovnlb.LB{
						Name:        makeLBName(service, proto, "node_router_"+node.name),
						Protocol:    string(proto),
						ExternalIDs: eids,
						Opts:        lbOpts(service),
						Routers:     []string{node.gatewayRouterName},
						Rules:       routerRules,
					})
				}
				if len(noSNATRouterRules) > 0 && node.gatewayRouterName != "" {
					lb := ovnlb.LB{
						Name:        makeLBName(service, proto, "node_local_router_"+node.name),
						Protocol:    string(proto),
						ExternalIDs: eids,
						Opts:        lbOpts(service),
						Routers:     []string{node.gatewayRouterName},
						Rules:       noSNATRouterRules,
					}
					lb.Opts.SkipSNAT = true
					out = append(out, lb)
				}

				if len(switchRules) > 0 {
					out = append(out, ovnlb.LB{
						Name:        makeLBName(service, proto, "node_switch_"+node.name),
						Protocol:    string(proto),
						ExternalIDs: eids,
						Opts:        lbOpts(service),
						Switches:    []string{node.switchName},
						Rules:       switchRules,
					})
				}
			}
		}
	}

	merged := mergeLBs(out)
	if len(merged) != len(out) {
		klog.V(5).Infof("Service %s/%s merged %d LBs to %d",
			service.Namespace, service.Name,
			len(out), len(merged))
	}

	return merged
}

// configsByProto buckets a list of configs by protocol (tcp, udp, sctp)
func configsByProto(configs []lbConfig) map[v1.Protocol][]lbConfig {
	out := map[v1.Protocol][]lbConfig{}
	for _, config := range configs {
		out[config.protocol] = append(out[config.protocol], config)
	}
	return out
}

// lbOpts generates the OVN load balancer options from the kubernetes Service.
func lbOpts(service *v1.Service) ovnlb.LBOpts {
	return ovnlb.LBOpts{
		Unidling: svcNeedsIdling(service.GetAnnotations()),
		Affinity: service.Spec.SessionAffinity == v1.ServiceAffinityClientIP,
		SkipSNAT: false, // never service-wide, ExternalTrafficPolicy-specific
	}
}

// mergeLBs joins two LBs together if it is safe to do so.
//
// an LB can be merged if the protocol, rules, and options are the same,
// and only the switches and routers are different.
func mergeLBs(lbs []ovnlb.LB) []ovnlb.LB {
	if len(lbs) == 1 {
		return lbs
	}
	out := make([]ovnlb.LB, 0, len(lbs))

outer:
	for _, lb := range lbs {
		for i := range out {
			// If mergeable, rather than inserting lb to out, just add switches and routers
			// and drop
			if canMergeLB(lb, out[i]) {
				out[i].Switches = append(out[i].Switches, lb.Switches...)
				out[i].Routers = append(out[i].Routers, lb.Routers...)

				if !strings.HasSuffix(out[i].Name, "_merged") {
					out[i].Name += "_merged"
				}
				continue outer
			}
		}
		out = append(out, lb)
	}

	return out
}

// canMergeLB returns true if two LBs are mergeable.
// We know that the ExternalIDs will be the same, so we don't need to compare them.
// All that matters is the protocol and rules are the same.
func canMergeLB(a, b ovnlb.LB) bool {
	if a.Protocol != b.Protocol {
		return false
	}

	if !reflect.DeepEqual(a.Opts, b.Opts) {
		return false
	}

	// While rules are actually a set, we generate all our lbConfigs from a single source
	// so the ordering will be the same. Thus, we can cheat and just reflect.DeepEqual
	return reflect.DeepEqual(a.Rules, b.Rules)
}
