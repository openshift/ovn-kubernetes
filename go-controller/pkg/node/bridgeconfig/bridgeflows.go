package bridgeconfig

import (
	"fmt"
	"net"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	nodetypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/types"
	nodeutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func (b *BridgeConfiguration) DefaultBridgeFlows(hostSubnets []*net.IPNet, extraIPs []net.IP) ([]string, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	dftFlows, err := b.flowsForDefaultBridge(extraIPs)
	if err != nil {
		return nil, err
	}
	dftCommonFlows, err := b.commonFlows(hostSubnets)
	if err != nil {
		return nil, err
	}
	return append(dftFlows, dftCommonFlows...), nil
}

func (b *BridgeConfiguration) ExternalBridgeFlows(hostSubnets []*net.IPNet) ([]string, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.commonFlows(hostSubnets)
}

// must be called with bridge.mutex held
func (b *BridgeConfiguration) flowsForDefaultBridge(extraIPs []net.IP) ([]string, error) {
	// CAUTION: when adding new flows where the in_port is ofPortPatch and the out_port is ofPortPhys, ensure
	// that dl_src is included in match criteria!

	ofPortPhys := b.ofPortPhys
	bridgeMacAddress := b.macAddress.String()
	ofPortHost := b.ofPortHost
	bridgeIPs := b.ips

	var dftFlows []string
	// 14 bytes of overhead for ethernet header (does not include VLAN)
	maxPktLength := getMaxFrameLength()

	strip_vlan := ""
	mod_vlan_id := ""
	match_vlan := ""
	if config.Gateway.VLANID != 0 {
		strip_vlan = "strip_vlan,"
		match_vlan = fmt.Sprintf("dl_vlan=%d,", config.Gateway.VLANID)
		mod_vlan_id = fmt.Sprintf("mod_vlan_vid:%d,", config.Gateway.VLANID)
	}

	if config.IPv4Mode {
		// table0, Geneve packets coming from external. Skip conntrack and go directly to host
		// if dest mac is the shared mac send directly to host.
		if ofPortPhys != "" {
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=205, in_port=%s, dl_dst=%s, udp, udp_dst=%d, "+
					"actions=output:%s", nodetypes.DefaultOpenFlowCookie, ofPortPhys, bridgeMacAddress, config.Default.EncapPort,
					ofPortHost))
			// perform NORMAL action otherwise.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=200, in_port=%s, udp, udp_dst=%d, "+
					"actions=NORMAL", nodetypes.DefaultOpenFlowCookie, ofPortPhys, config.Default.EncapPort))

			// table0, Geneve packets coming from LOCAL/Host OFPort. Skip conntrack and go directly to external
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=200, in_port=%s, udp, udp_dst=%d, "+
					"actions=output:%s", nodetypes.DefaultOpenFlowCookie, ofPortHost, config.Default.EncapPort, ofPortPhys))
		}
		physicalIP, err := util.MatchFirstIPNetFamily(false, bridgeIPs)
		if err != nil {
			return nil, fmt.Errorf("unable to determine IPv4 physical IP of host: %v", err)
		}
		for _, netConfig := range b.patchedNetConfigs() {
			// table 0, SVC Hairpin from OVN destined to local host, DNAT and go to table 4
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=500, in_port=%s, ip, ip_dst=%s, ip_src=%s,"+
					"actions=ct(commit,zone=%d,nat(dst=%s),table=4)",
					nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, config.Gateway.MasqueradeIPs.V4HostMasqueradeIP.String(), physicalIP.IP,
					config.Default.HostMasqConntrackZone, physicalIP.IP))
		}

		// table 0, hairpin from OVN destined to local host (but an additional node IP), send to table 4
		for _, ip := range extraIPs {
			if ip.To4() == nil {
				continue
			}
			// not needed for the physical IP
			if ip.Equal(physicalIP.IP) {
				continue
			}

			// not needed for special masquerade IP
			if ip.Equal(config.Gateway.MasqueradeIPs.V4HostMasqueradeIP) {
				continue
			}

			for _, netConfig := range b.patchedNetConfigs() {
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=500, in_port=%s, ip, ip_dst=%s, ip_src=%s,"+
						"actions=ct(commit,zone=%d,table=4)",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, ip.String(), physicalIP.IP,
						config.Default.HostMasqConntrackZone))
			}
		}

		// table 0, Reply SVC traffic from Host -> OVN, unSNAT and goto table 5
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=%s, ip, ip_dst=%s,"+
				"actions=ct(zone=%d,nat,table=5)",
				nodetypes.DefaultOpenFlowCookie, ofPortHost, config.Gateway.MasqueradeIPs.V4OVNMasqueradeIP.String(), config.Default.OVNMasqConntrackZone))
	}
	if config.IPv6Mode {
		if ofPortPhys != "" {
			// table0, Geneve packets coming from external. Skip conntrack and go directly to host
			// if dest mac is the shared mac send directly to host.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=205, in_port=%s, dl_dst=%s, udp6, udp_dst=%d, "+
					"actions=output:%s", nodetypes.DefaultOpenFlowCookie, ofPortPhys, bridgeMacAddress, config.Default.EncapPort,
					ofPortHost))
			// perform NORMAL action otherwise.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=200, in_port=%s, udp6, udp_dst=%d, "+
					"actions=NORMAL", nodetypes.DefaultOpenFlowCookie, ofPortPhys, config.Default.EncapPort))

			// table0, Geneve packets coming from LOCAL. Skip conntrack and send to external
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=200, in_port=%s, udp6, udp_dst=%d, "+
					"actions=output:%s", nodetypes.DefaultOpenFlowCookie, nodetypes.OvsLocalPort, config.Default.EncapPort, ofPortPhys))
		}

		physicalIP, err := util.MatchFirstIPNetFamily(true, bridgeIPs)
		if err != nil {
			return nil, fmt.Errorf("unable to determine IPv6 physical IP of host: %v", err)
		}
		// table 0, SVC Hairpin from OVN destined to local host, DNAT to host, send to table 4
		for _, netConfig := range b.patchedNetConfigs() {
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=500, in_port=%s, ipv6, ipv6_dst=%s, ipv6_src=%s,"+
					"actions=ct(commit,zone=%d,nat(dst=%s),table=4)",
					nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, config.Gateway.MasqueradeIPs.V6HostMasqueradeIP.String(), physicalIP.IP,
					config.Default.HostMasqConntrackZone, physicalIP.IP))
		}

		// table 0, hairpin from OVN destined to local host (but an additional node IP), send to table 4
		for _, ip := range extraIPs {
			if ip.To4() != nil {
				continue
			}
			// not needed for the physical IP
			if ip.Equal(physicalIP.IP) {
				continue
			}

			// not needed for special masquerade IP
			if ip.Equal(config.Gateway.MasqueradeIPs.V6HostMasqueradeIP) {
				continue
			}

			for _, netConfig := range b.patchedNetConfigs() {
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=500, in_port=%s, ipv6, ipv6_dst=%s, ipv6_src=%s,"+
						"actions=ct(commit,zone=%d,table=4)",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, ip.String(), physicalIP.IP,
						config.Default.HostMasqConntrackZone))
			}
		}

		// table 0, Reply SVC traffic from Host -> OVN, unSNAT and goto table 5
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=%s, ipv6, ipv6_dst=%s,"+
				"actions=ct(zone=%d,nat,table=5)",
				nodetypes.DefaultOpenFlowCookie, ofPortHost, config.Gateway.MasqueradeIPs.V6OVNMasqueradeIP.String(), config.Default.OVNMasqConntrackZone))
	}

	var protoPrefix, masqIP, masqSubnet string

	// table 0, packets coming from Host -> Service
	for _, svcCIDR := range config.Kubernetes.ServiceCIDRs {
		if utilnet.IsIPv4CIDR(svcCIDR) {
			protoPrefix = "ip"
			masqIP = config.Gateway.MasqueradeIPs.V4HostMasqueradeIP.String()
			masqSubnet = config.Gateway.V4MasqueradeSubnet
		} else {
			protoPrefix = "ipv6"
			masqIP = config.Gateway.MasqueradeIPs.V6HostMasqueradeIP.String()
			masqSubnet = config.Gateway.V6MasqueradeSubnet
		}

		// table 0, Host (default network) -> OVN towards SVC, SNAT to special IP.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=%s, %s, %s_dst=%s, "+
				"actions=ct(commit,zone=%d,nat(src=%s),table=2)",
				nodetypes.DefaultOpenFlowCookie, ofPortHost, protoPrefix, protoPrefix,
				svcCIDR, config.Default.HostMasqConntrackZone, masqIP))

		if util.IsNetworkSegmentationSupportEnabled() {
			// table 0, Host (UDNs) -> OVN towards SVC, SNAT to special IP.
			// For packets originating from UDN, commit without NATing, those
			// have already been SNATed to the masq IP of the UDN.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=550, in_port=%s, %s, %s_src=%s, %s_dst=%s, "+
					"actions=ct(commit,zone=%d,table=2)",
					nodetypes.DefaultOpenFlowCookie, ofPortHost, protoPrefix, protoPrefix,
					masqSubnet, protoPrefix, svcCIDR, config.Default.HostMasqConntrackZone))
			if util.IsRouteAdvertisementsEnabled() {
				// If the UDN is advertised then instead of matching on the masqSubnet
				// we match on the UDNPodSubnet itself and we also don't SNAT to 169.254.0.2
				// sample flow: cookie=0xdeff105, duration=1472.742s, table=0, n_packets=9, n_bytes=666, priority=550
				//              ip,in_port=LOCAL,nw_src=103.103.0.0/16,nw_dst=10.96.0.0/16 actions=ct(commit,table=2,zone=64001)
				for _, netConfig := range b.patchedNetConfigs() {
					if netConfig.IsDefaultNetwork() {
						continue
					}
					if netConfig.Advertised.Load() {
						var udnAdvertisedSubnets []*net.IPNet
						for _, clusterEntry := range netConfig.Subnets {
							udnAdvertisedSubnets = append(udnAdvertisedSubnets, clusterEntry.CIDR)
						}
						// Filter subnets based on the clusterIP service family
						// NOTE: We don't support more than 1 subnet CIDR of same family type; we only pick the first one
						matchingIPFamilySubnet, err := util.MatchFirstIPNetFamily(utilnet.IsIPv6CIDR(svcCIDR), udnAdvertisedSubnets)
						if err != nil {
							klog.Infof("Unable to determine UDN subnet for the provided family isIPV6: %t, %v", utilnet.IsIPv6CIDR(svcCIDR), err)
							continue
						}

						// Use the filtered subnet for the flow compute instead of the masqueradeIP
						dftFlows = append(dftFlows,
							fmt.Sprintf("cookie=%s, priority=550, in_port=%s, %s, %s_src=%s, %s_dst=%s, "+
								"actions=ct(commit,zone=%d,table=2)",
								nodetypes.DefaultOpenFlowCookie, ofPortHost, protoPrefix, protoPrefix,
								matchingIPFamilySubnet.String(), protoPrefix, svcCIDR, config.Default.HostMasqConntrackZone))
					}
				}
			}
		}

		masqDst := masqIP
		if util.IsNetworkSegmentationSupportEnabled() {
			// In UDN match on the whole masquerade subnet to handle replies from UDN enabled services
			masqDst = masqSubnet
		}
		for _, netConfig := range b.patchedNetConfigs() {
			// table 0, Reply hairpin traffic to host, coming from OVN, unSNAT
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=500, in_port=%s, %s, %s_src=%s, %s_dst=%s,"+
					"actions=ct(zone=%d,nat,table=3)",
					nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, protoPrefix, protoPrefix, svcCIDR,
					protoPrefix, masqDst, config.Default.HostMasqConntrackZone))
			// table 0, Reply traffic coming from OVN to outside, drop it if the DNAT wasn't done either
			// at the GR load balancer or switch load balancer. It means the correct port wasn't provided.
			// nodeCIDR->serviceCIDR traffic flow is internal and it shouldn't be carried to outside the cluster
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=115, in_port=%s, %s, %s_dst=%s,"+
					"actions=drop", nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, protoPrefix, protoPrefix, svcCIDR))
		}
	}

	// table 0, add IP fragment reassembly flows, only needed in SGW mode with
	// physical interface attached to bridge
	if config.Gateway.Mode == config.GatewayModeShared && ofPortPhys != "" {
		reassemblyFlows := generateIPFragmentReassemblyFlow(ofPortPhys)
		dftFlows = append(dftFlows, reassemblyFlows...)
	}
	if ofPortPhys != "" {
		for _, netConfig := range b.patchedNetConfigs() {
			var actions string
			if config.Gateway.Mode != config.GatewayModeLocal || config.Gateway.DisablePacketMTUCheck {
				actions = fmt.Sprintf("output:%s", netConfig.OfPortPatch)
			} else {
				// packets larger than known acceptable MTU need to go to kernel for
				// potential fragmentation
				// introduced specifically for replies to egress traffic not routed
				// through the host
				actions = fmt.Sprintf("check_pkt_larger(%d)->reg0[0],resubmit(,11)", maxPktLength)
			}

			if config.IPv4Mode {
				// table 1, established and related connections in zone 64000 with ct_mark CtMarkOVN go to OVN
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=100, table=1, ip, ct_state=+trk+est, ct_mark=%s, "+
						"actions=%s", nodetypes.DefaultOpenFlowCookie, netConfig.MasqCTMark, actions))

				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=100, table=1, ip, ct_state=+trk+rel, ct_mark=%s, "+
						"actions=%s", nodetypes.DefaultOpenFlowCookie, netConfig.MasqCTMark, actions))

			}

			if config.IPv6Mode {
				// table 1, established and related connections in zone 64000 with ct_mark CtMarkOVN go to OVN
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=100, table=1, ipv6, ct_state=+trk+est, ct_mark=%s, "+
						"actions=%s", nodetypes.DefaultOpenFlowCookie, netConfig.MasqCTMark, actions))

				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=100, table=1, ipv6, ct_state=+trk+rel, ct_mark=%s, "+
						"actions=%s", nodetypes.DefaultOpenFlowCookie, netConfig.MasqCTMark, actions))
			}
		}
		if config.IPv4Mode {
			// table 1, established and related connections in zone 64000 with ct_mark CtMarkHost go to host
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=100, table=1, %s ip, ct_state=+trk+est, ct_mark=%s, "+
					"actions=%soutput:%s",
					nodetypes.DefaultOpenFlowCookie, match_vlan, nodetypes.CtMarkHost, strip_vlan, ofPortHost))

			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=100, table=1, %s ip, ct_state=+trk+rel, ct_mark=%s, "+
					"actions=%soutput:%s",
					nodetypes.DefaultOpenFlowCookie, match_vlan, nodetypes.CtMarkHost, strip_vlan, ofPortHost))

		}
		if config.IPv6Mode {
			// table 1, established and related connections in zone 64000 with ct_mark CtMarkHost go to host
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=100, table=1, %s ip6, ct_state=+trk+est, ct_mark=%s, "+
					"actions=%soutput:%s",
					nodetypes.DefaultOpenFlowCookie, match_vlan, nodetypes.CtMarkHost, strip_vlan, ofPortHost))

			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=100, table=1, %s ip6, ct_state=+trk+rel, ct_mark=%s, "+
					"actions=%soutput:%s",
					nodetypes.DefaultOpenFlowCookie, match_vlan, nodetypes.CtMarkHost, strip_vlan, ofPortHost))

		}

		// table 1, we check to see if this dest mac is the shared mac, if so send to host
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=10, table=1, %s dl_dst=%s, actions=%soutput:%s",
				nodetypes.DefaultOpenFlowCookie, match_vlan, bridgeMacAddress, strip_vlan, ofPortHost))
	}

	defaultNetConfig := b.netConfig[types.DefaultNetworkName]

	// table 2, dispatch from Host -> OVN
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=100, table=2, "+
			"actions=set_field:%s->eth_dst,%soutput:%s", nodetypes.DefaultOpenFlowCookie,
			bridgeMacAddress, mod_vlan_id, defaultNetConfig.OfPortPatch))

	// table 2, priority 200, dispatch from UDN -> Host -> OVN. These packets have
	// already been SNATed to the UDN's masquerade IP or have been marked with the UDN's packet mark.
	if config.IPv4Mode {
		for _, netConfig := range b.patchedNetConfigs() {
			if netConfig.IsDefaultNetwork() {
				continue
			}
			if util.IsRouteAdvertisementsEnabled() && netConfig.Advertised.Load() {
				var udnAdvertisedSubnets []*net.IPNet
				for _, clusterEntry := range netConfig.Subnets {
					udnAdvertisedSubnets = append(udnAdvertisedSubnets, clusterEntry.CIDR)
				}
				// Filter subnets based on the clusterIP service family
				// NOTE: We don't support more than 1 subnet CIDR of same family type; we only pick the first one
				matchingIPFamilySubnet, err := util.MatchFirstIPNetFamily(false, udnAdvertisedSubnets)
				if err != nil {
					klog.Infof("Unable to determine IPV4 UDN subnet for the provided family isIPV6: %v", err)
					continue
				}
				// In addition to the masqueradeIP based flows, we also need the podsubnet based flows for
				// advertised networks since UDN pod to clusterIP is unSNATed and we need this traffic to be taken into
				// the correct patch port of it's own network where it's a deadend if the clusterIP is not part of
				// that UDN network and works if it is part of the UDN network.
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=200, table=2, ip, ip_src=%s, "+
						"actions=drop",
						nodetypes.DefaultOpenFlowCookie, matchingIPFamilySubnet.String()))
			}
			// Drop traffic coming from the masquerade IP or the UDN subnet(for advertised UDNs) to ensure that
			// isolation between networks is enforced. This handles the case where a pod on the UDN subnet is sending traffic to
			// a service in another UDN.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=200, table=2, ip, ip_src=%s, "+
					"actions=drop",
					nodetypes.DefaultOpenFlowCookie, netConfig.V4MasqIPs.ManagementPort.IP.String()))

			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=250, table=2, ip, pkt_mark=%s, "+
					"actions=set_field:%s->eth_dst,output:%s",
					nodetypes.DefaultOpenFlowCookie, netConfig.PktMark,
					bridgeMacAddress, netConfig.OfPortPatch))
		}
	}

	if config.IPv6Mode {
		for _, netConfig := range b.patchedNetConfigs() {
			if netConfig.IsDefaultNetwork() {
				continue
			}
			if util.IsRouteAdvertisementsEnabled() && netConfig.Advertised.Load() {
				var udnAdvertisedSubnets []*net.IPNet
				for _, clusterEntry := range netConfig.Subnets {
					udnAdvertisedSubnets = append(udnAdvertisedSubnets, clusterEntry.CIDR)
				}
				// Filter subnets based on the clusterIP service family
				// NOTE: We don't support more than 1 subnet CIDR of same family type; we only pick the first one
				matchingIPFamilySubnet, err := util.MatchFirstIPNetFamily(true, udnAdvertisedSubnets)
				if err != nil {
					klog.Infof("Unable to determine IPV6 UDN subnet for the provided family isIPV6: %v", err)
					continue
				}

				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=200, table=2, ip6, ipv6_src=%s, "+
						"actions=drop",
						nodetypes.DefaultOpenFlowCookie, matchingIPFamilySubnet.String()))
			}
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=200, table=2, ip6, ipv6_src=%s, "+
					"actions=drop",
					nodetypes.DefaultOpenFlowCookie, netConfig.V6MasqIPs.ManagementPort.IP.String()))
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=250, table=2, ip6, pkt_mark=%s, "+
					"actions=set_field:%s->eth_dst,output:%s",
					nodetypes.DefaultOpenFlowCookie, netConfig.PktMark,
					bridgeMacAddress, netConfig.OfPortPatch))
		}
	}

	// table 3, dispatch from OVN -> Host
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, table=3, %s "+
			"actions=move:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],set_field:%s->eth_dst,%soutput:%s",
			nodetypes.DefaultOpenFlowCookie, match_vlan, bridgeMacAddress, strip_vlan, ofPortHost))

	// table 4, hairpinned pkts that need to go from OVN -> Host
	// We need to SNAT and masquerade OVN GR IP, send to table 3 for dispatch to Host
	if config.IPv4Mode {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, table=4,ip,"+
				"actions=ct(commit,zone=%d,nat(src=%s),table=3)",
				nodetypes.DefaultOpenFlowCookie, config.Default.OVNMasqConntrackZone, config.Gateway.MasqueradeIPs.V4OVNMasqueradeIP.String()))
	}
	if config.IPv6Mode {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, table=4,ipv6, "+
				"actions=ct(commit,zone=%d,nat(src=%s),table=3)",
				nodetypes.DefaultOpenFlowCookie, config.Default.OVNMasqConntrackZone, config.Gateway.MasqueradeIPs.V6OVNMasqueradeIP.String()))
	}
	// table 5, Host Reply traffic to hairpinned svc, need to unDNAT, send to table 2
	if config.IPv4Mode {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, table=5, ip, "+
				"actions=ct(commit,zone=%d,nat,table=2)",
				nodetypes.DefaultOpenFlowCookie, config.Default.HostMasqConntrackZone))
	}
	if config.IPv6Mode {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, table=5, ipv6, "+
				"actions=ct(commit,zone=%d,nat,table=2)",
				nodetypes.DefaultOpenFlowCookie, config.Default.HostMasqConntrackZone))
	}
	return dftFlows, nil
}

// getMaxFrameLength returns the maximum frame size (ignoring VLAN header) that a gateway can handle
func getMaxFrameLength() int {
	return config.Default.MTU + 14
}

// generateIPFragmentReassemblyFlow adds flows in table 0 that send packets to a
// specific conntrack zone for reassembly with the same priority as node port
// flows that match on L4 fields. After reassembly packets are reinjected to
// table 0 again. This requires a conntrack immplementation that reassembles
// fragments. This reqreuiment is met for the kernel datapath with the netfilter
// module loaded. This reqreuiment is not met for the userspace datapath.
func generateIPFragmentReassemblyFlow(ofPortPhys string) []string {
	flows := make([]string, 0, 2)
	if config.IPv4Mode {
		flows = append(flows,
			fmt.Sprintf("cookie=%s, priority=110, table=0, in_port=%s, ip, nw_frag=yes, actions=ct(table=0,zone=%d)",
				nodetypes.DefaultOpenFlowCookie,
				ofPortPhys,
				config.Default.ReassemblyConntrackZone,
			),
		)
	}
	if config.IPv6Mode {
		flows = append(flows,
			fmt.Sprintf("cookie=%s, priority=110, table=0, in_port=%s, ipv6, nw_frag=yes, actions=ct(table=0,zone=%d)",
				nodetypes.DefaultOpenFlowCookie,
				ofPortPhys,
				config.Default.ReassemblyConntrackZone,
			),
		)
	}

	return flows
}

// must be called with bridge.mutex held
func (b *BridgeConfiguration) commonFlows(hostSubnets []*net.IPNet) ([]string, error) {
	// CAUTION: when adding new flows where the in_port is ofPortPatch and the out_port is ofPortPhys, ensure
	// that dl_src is included in match criteria!
	ofPortPhys := b.ofPortPhys
	bridgeMacAddress := b.macAddress.String()
	ofPortHost := b.ofPortHost
	bridgeIPs := b.ips

	var dftFlows []string

	strip_vlan := ""
	match_vlan := ""
	mod_vlan_id := ""
	if config.Gateway.VLANID != 0 {
		strip_vlan = "strip_vlan,"
		match_vlan = fmt.Sprintf("dl_vlan=%d,", config.Gateway.VLANID)
		mod_vlan_id = fmt.Sprintf("mod_vlan_vid:%d,", config.Gateway.VLANID)
	}

	if ofPortPhys != "" {
		// table 0, we check to see if this dest mac is the shared mac, if so flood to all ports
		actions := ""
		for _, netConfig := range b.patchedNetConfigs() {
			actions += "output:" + netConfig.OfPortPatch + ","
		}

		actions += strip_vlan + "output:" + ofPortHost
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=10, table=0, %s dl_dst=%s, actions=%s",
				nodetypes.DefaultOpenFlowCookie, match_vlan, bridgeMacAddress, actions))
	}

	// table 0, check packets coming from OVN have the correct mac address. Low priority flows that are a catch all
	// for non-IP packets that would normally be forwarded with NORMAL action (table 0, priority 0 flow).
	for _, netConfig := range b.patchedNetConfigs() {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=10, table=0, in_port=%s, dl_src=%s, actions=output:NORMAL",
				nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress))
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=9, table=0, in_port=%s, actions=drop",
				nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch))
	}

	if config.IPv4Mode {
		physicalIP, err := util.MatchFirstIPNetFamily(false, bridgeIPs)
		if err != nil {
			return nil, fmt.Errorf("unable to determine IPv4 physical IP of host: %v", err)
		}
		if ofPortPhys != "" {
			for _, netConfig := range b.patchedNetConfigs() {
				// table0, packets coming from egressIP pods that have mark 1008 on them
				// will be SNAT-ed a final time into nodeIP to maintain consistency in traffic even if the GR
				// SNATs these into egressIP prior to reaching external bridge.
				// egressService pods will also undergo this SNAT to nodeIP since these features are tied
				// together at the OVN policy level on the distributed router.
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=105, in_port=%s, dl_src=%s, ip, pkt_mark=%s "+
						"actions=ct(commit, zone=%d, nat(src=%s), exec(set_field:%s->ct_mark)),output:%s",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, nodetypes.OvnKubeNodeSNATMark,
						config.Default.ConntrackZone, physicalIP.IP, netConfig.MasqCTMark, ofPortPhys))

				// table 0, packets coming from egressIP pods only from user defined networks. If an egressIP is assigned to
				// this node, then all networks get a flow even if no pods on that network were selected for by this egressIP.
				if util.IsNetworkSegmentationSupportEnabled() && config.OVNKubernetesFeature.EnableInterconnect &&
					config.Gateway.Mode != config.GatewayModeDisabled && b.eipMarkIPs != nil {
					if netConfig.MasqCTMark != nodetypes.CtMarkOVN {
						for mark, eip := range b.eipMarkIPs.GetIPv4() {
							dftFlows = append(dftFlows,
								fmt.Sprintf("cookie=%s, priority=105, in_port=%s, dl_src=%s, ip, pkt_mark=%d, "+
									"actions=ct(commit, zone=%d, nat(src=%s), exec(set_field:%s->ct_mark)), output:%s",
									nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, mark,
									config.Default.ConntrackZone, eip, netConfig.MasqCTMark, ofPortPhys))
						}
					}
				}

				// table 0, packets coming from pods headed externally. Commit connections with ct_mark CtMarkOVN
				// so that reverse direction goes back to the pods.
				if netConfig.IsDefaultNetwork() {
					dftFlows = append(dftFlows,
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, dl_src=%s, ip, "+
							"actions=ct(commit, zone=%d, exec(set_field:%s->ct_mark)), output:%s",
							nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, config.Default.ConntrackZone,
							netConfig.MasqCTMark, ofPortPhys))

					// Allow (a) OVN->host traffic on the same node
					// (b) host->host traffic on the same node
					if config.Gateway.Mode == config.GatewayModeShared || config.Gateway.Mode == config.GatewayModeLocal {
						dftFlows = append(dftFlows, hostNetworkNormalActionFlows(netConfig, bridgeMacAddress, hostSubnets, false)...)
					}
				} else {
					//  for UDN we additionally SNAT the packet from masquerade IP -> node IP
					dftFlows = append(dftFlows,
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, dl_src=%s, ip, ip_src=%s, "+
							"actions=ct(commit, zone=%d, nat(src=%s), exec(set_field:%s->ct_mark)), output:%s",
							nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, netConfig.V4MasqIPs.GatewayRouter.IP, config.Default.ConntrackZone,
							physicalIP.IP, netConfig.MasqCTMark, ofPortPhys))
				}
			}

			// table 0, packets coming from host Commit connections with ct_mark CtMarkHost
			// so that reverse direction goes back to the host.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=100, in_port=%s, ip, "+
					"actions=ct(commit, zone=%d, exec(set_field:%s->ct_mark)), %soutput:%s",
					nodetypes.DefaultOpenFlowCookie, ofPortHost, config.Default.ConntrackZone, nodetypes.CtMarkHost, mod_vlan_id, ofPortPhys))
		}
		if config.Gateway.Mode == config.GatewayModeLocal {
			for _, netConfig := range b.patchedNetConfigs() {
				// table 0, any packet coming from OVN send to host in LGW mode, host will take care of sending it outside if needed.
				// exceptions are traffic for egressIP and egressGW features and ICMP related traffic which will hit the priority 100 flow instead of this.
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=175, in_port=%s, tcp, nw_src=%s, "+
						"actions=ct(table=4,zone=%d)",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, physicalIP.IP, config.Default.HostMasqConntrackZone))
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=175, in_port=%s, udp, nw_src=%s, "+
						"actions=ct(table=4,zone=%d)",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, physicalIP.IP, config.Default.HostMasqConntrackZone))
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=175, in_port=%s, sctp, nw_src=%s, "+
						"actions=ct(table=4,zone=%d)",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, physicalIP.IP, config.Default.HostMasqConntrackZone))
				// We send BFD traffic coming from OVN to outside directly using a higher priority flow
				if ofPortPhys != "" {
					dftFlows = append(dftFlows,
						fmt.Sprintf("cookie=%s, priority=650, table=0, in_port=%s, dl_src=%s, udp, tp_dst=3784, actions=output:%s",
							nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, ofPortPhys))
				}
			}
		}

		if ofPortPhys != "" {
			// table 0, packets coming from external or other localnet ports. Send it through conntrack and
			// resubmit to table 1 to know the state and mark of the connection.
			// Note, there are higher priority rules that take care of traffic coming from LOCAL and OVN ports.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=50, ip, actions=ct(zone=%d, nat, table=1)",
					nodetypes.DefaultOpenFlowCookie, config.Default.ConntrackZone))
		}
	}

	if config.IPv6Mode {
		physicalIP, err := util.MatchFirstIPNetFamily(true, bridgeIPs)
		if err != nil {
			return nil, fmt.Errorf("unable to determine IPv6 physical IP of host: %v", err)
		}
		if ofPortPhys != "" {
			for _, netConfig := range b.patchedNetConfigs() {
				// table0, packets coming from egressIP pods that have mark 1008 on them
				// will be DNAT-ed a final time into nodeIP to maintain consistency in traffic even if the GR
				// DNATs these into egressIP prior to reaching external bridge.
				// egressService pods will also undergo this SNAT to nodeIP since these features are tied
				// together at the OVN policy level on the distributed router.
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=105, in_port=%s, dl_src=%s, ipv6, pkt_mark=%s "+
						"actions=ct(commit, zone=%d, nat(src=%s), exec(set_field:%s->ct_mark)),output:%s",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, nodetypes.OvnKubeNodeSNATMark,
						config.Default.ConntrackZone, physicalIP.IP, netConfig.MasqCTMark, ofPortPhys))

				// table 0, packets coming from egressIP pods only from user defined networks. If an egressIP is assigned to
				// this node, then all networks get a flow even if no pods on that network were selected for by this egressIP.
				if util.IsNetworkSegmentationSupportEnabled() && config.OVNKubernetesFeature.EnableInterconnect &&
					config.Gateway.Mode != config.GatewayModeDisabled && b.eipMarkIPs != nil {
					if netConfig.MasqCTMark != nodetypes.CtMarkOVN {
						for mark, eip := range b.eipMarkIPs.GetIPv6() {
							dftFlows = append(dftFlows,
								fmt.Sprintf("cookie=%s, priority=105, in_port=%s, dl_src=%s, ipv6, pkt_mark=%d, "+
									"actions=ct(commit, zone=%d, nat(src=%s), exec(set_field:%s->ct_mark)), output:%s",
									nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, mark,
									config.Default.ConntrackZone, eip, netConfig.MasqCTMark, ofPortPhys))
						}
					}
				}

				// table 0, packets coming from pods headed externally. Commit connections with ct_mark CtMarkOVN
				// so that reverse direction goes back to the pods.
				if netConfig.IsDefaultNetwork() {
					dftFlows = append(dftFlows,
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, dl_src=%s, ipv6, "+
							"actions=ct(commit, zone=%d, exec(set_field:%s->ct_mark)), output:%s",
							nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, config.Default.ConntrackZone, netConfig.MasqCTMark, ofPortPhys))

					// Allow (a) OVN->host traffic on the same node
					// (b) host->host traffic on the same node
					if config.Gateway.Mode == config.GatewayModeShared || config.Gateway.Mode == config.GatewayModeLocal {
						dftFlows = append(dftFlows, hostNetworkNormalActionFlows(netConfig, bridgeMacAddress, hostSubnets, true)...)
					}
				} else {
					//  for UDN we additionally SNAT the packet from masquerade IP -> node IP
					dftFlows = append(dftFlows,
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, dl_src=%s, ipv6, ipv6_src=%s, "+
							"actions=ct(commit, zone=%d, nat(src=%s), exec(set_field:%s->ct_mark)), output:%s",
							nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, netConfig.V6MasqIPs.GatewayRouter.IP, config.Default.ConntrackZone,
							physicalIP.IP, netConfig.MasqCTMark, ofPortPhys))
				}
			}

			// table 0, packets coming from host. Commit connections with ct_mark CtMarkHost
			// so that reverse direction goes back to the host.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=100, in_port=%s, ipv6, "+
					"actions=ct(commit, zone=%d, exec(set_field:%s->ct_mark)), %soutput:%s",
					nodetypes.DefaultOpenFlowCookie, ofPortHost, config.Default.ConntrackZone, nodetypes.CtMarkHost, mod_vlan_id, ofPortPhys))

		}
		if config.Gateway.Mode == config.GatewayModeLocal {
			for _, netConfig := range b.patchedNetConfigs() {
				// table 0, any packet coming from OVN send to host in LGW mode, host will take care of sending it outside if needed.
				// exceptions are traffic for egressIP and egressGW features and ICMP related traffic which will hit the priority 100 flow instead of this.
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=175, in_port=%s, tcp6, ipv6_src=%s, "+
						"actions=ct(table=4,zone=%d)",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, physicalIP.IP, config.Default.HostMasqConntrackZone))
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=175, in_port=%s, udp6, ipv6_src=%s, "+
						"actions=ct(table=4,zone=%d)",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, physicalIP.IP, config.Default.HostMasqConntrackZone))
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=175, in_port=%s, sctp6, ipv6_src=%s, "+
						"actions=ct(table=4,zone=%d)",
						nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, physicalIP.IP, config.Default.HostMasqConntrackZone))
				if ofPortPhys != "" {
					// We send BFD traffic coming from OVN to outside directly using a higher priority flow
					dftFlows = append(dftFlows,
						fmt.Sprintf("cookie=%s, priority=650, table=0, in_port=%s, dl_src=%s, udp6, tp_dst=3784, actions=output:%s",
							nodetypes.DefaultOpenFlowCookie, netConfig.OfPortPatch, bridgeMacAddress, ofPortPhys))
				}
			}
		}
		if ofPortPhys != "" {
			// table 0, packets coming from external. Send it through conntrack and
			// resubmit to table 1 to know the state and mark of the connection.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=50, in_port=%s, ipv6, "+
					"actions=ct(zone=%d, nat, table=1)", nodetypes.DefaultOpenFlowCookie, ofPortPhys, config.Default.ConntrackZone))
		}
	}
	// Egress IP is often configured on a node different from the one hosting the affected pod.
	// Due to the fact that ovn-controllers on different nodes apply the changes independently,
	// there is a chance that the pod traffic will reach the egress node before it configures the SNAT flows.
	// Drop pod traffic that is not SNATed, excluding local pods(required for ICNIv2)
	defaultNetConfig := b.netConfig[types.DefaultNetworkName]
	if config.OVNKubernetesFeature.EnableEgressIP {
		for _, clusterEntry := range config.Default.ClusterSubnets {
			cidr := clusterEntry.CIDR
			ipv := getIPv(cidr)
			// table 0, drop packets coming from pods headed externally that were not SNATed.
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=104, in_port=%s, %s, %s_src=%s, actions=drop",
					nodetypes.DefaultOpenFlowCookie, defaultNetConfig.OfPortPatch, ipv, ipv, cidr))
		}
		for _, subnet := range defaultNetConfig.NodeSubnets {
			ipv := getIPv(subnet)
			if ofPortPhys != "" {
				// table 0, commit connections from local pods.
				// ICNIv2 requires that local pod traffic can leave the node without SNAT.
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=109, in_port=%s, dl_src=%s, %s, %s_src=%s"+
						"actions=ct(commit, zone=%d, exec(set_field:%s->ct_mark)), output:%s",
						nodetypes.DefaultOpenFlowCookie, defaultNetConfig.OfPortPatch, bridgeMacAddress, ipv, ipv, subnet,
						config.Default.ConntrackZone, nodetypes.CtMarkOVN, ofPortPhys))
			}
		}
	}

	if ofPortPhys != "" {
		for _, netConfig := range b.patchedNetConfigs() {
			isNetworkAdvertised := netConfig.Advertised.Load()
			// disableSNATMultipleGWs only applies to default network
			disableSNATMultipleGWs := netConfig.IsDefaultNetwork() && config.Gateway.DisableSNATMultipleGWs
			if !disableSNATMultipleGWs && !isNetworkAdvertised {
				continue
			}
			output := netConfig.OfPortPatch
			if isNetworkAdvertised && config.Gateway.Mode == config.GatewayModeLocal {
				// except if advertised through BGP, go to kernel
				// TODO: MEG enabled pods should still go through the patch port
				// but holding this until
				// https://issues.redhat.com/browse/FDP-646 is fixed, for now we
				// are assuming MEG & BGP are not used together
				output = nodetypes.OvsLocalPort
			}
			for _, clusterEntry := range netConfig.Subnets {
				cidr := clusterEntry.CIDR
				ipv := getIPv(cidr)
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=15, table=1, %s, %s_dst=%s, "+
						"actions=output:%s",
						nodetypes.DefaultOpenFlowCookie, ipv, ipv, cidr, output))
			}
			if output == netConfig.OfPortPatch {
				// except node management traffic
				for _, subnet := range netConfig.NodeSubnets {
					mgmtIP := util.GetNodeManagementIfAddr(subnet)
					ipv := getIPv(mgmtIP)
					dftFlows = append(dftFlows,
						fmt.Sprintf("cookie=%s, priority=16, table=1, %s, %s_dst=%s, "+
							"actions=output:%s",
							nodetypes.DefaultOpenFlowCookie, ipv, ipv, mgmtIP.IP, nodetypes.OvsLocalPort),
					)
				}
			}
		}

		// table 1, we check to see if this dest mac is the shared mac, if so send to host
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=10, table=1, %s dl_dst=%s, actions=%soutput:%s",
				nodetypes.DefaultOpenFlowCookie, match_vlan, bridgeMacAddress, strip_vlan, ofPortHost))

		if config.IPv6Mode {
			// REMOVEME(trozet) when https://bugzilla.kernel.org/show_bug.cgi?id=11797 is resolved
			// must flood icmpv6 Route Advertisement and Neighbor Advertisement traffic as it fails to create a CT entry
			for _, icmpType := range []int{types.RouteAdvertisementICMPType, types.NeighborAdvertisementICMPType} {
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=14, table=1,icmp6,icmpv6_type=%d actions=FLOOD",
						nodetypes.DefaultOpenFlowCookie, icmpType))
			}
			if ofPortPhys != "" {
				// We send BFD traffic both on the host and in ovn
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=13, table=1, in_port=%s, udp6, tp_dst=3784, actions=output:%s,output:%s",
						nodetypes.DefaultOpenFlowCookie, ofPortPhys, defaultNetConfig.OfPortPatch, ofPortHost))
			}
		}

		if config.IPv4Mode {
			if ofPortPhys != "" {
				// We send BFD traffic both on the host and in ovn
				dftFlows = append(dftFlows,
					fmt.Sprintf("cookie=%s, priority=13, table=1, in_port=%s, udp, tp_dst=3784, actions=output:%s,output:%s",
						nodetypes.DefaultOpenFlowCookie, ofPortPhys, defaultNetConfig.OfPortPatch, ofPortHost))
			}
		}

		// packets larger than known acceptable MTU need to go to kernel for
		// potential fragmentation
		// introduced specifically for replies to egress traffic not routed
		// through the host
		if config.Gateway.Mode == config.GatewayModeLocal && !config.Gateway.DisablePacketMTUCheck {
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=10, table=11, reg0=0x1, "+
					"actions=output:%s", nodetypes.DefaultOpenFlowCookie, ofPortHost))

			// Send UDN destined traffic to right patch port
			for _, netConfig := range b.patchedNetConfigs() {
				if netConfig.MasqCTMark != nodetypes.CtMarkOVN {
					dftFlows = append(dftFlows,
						fmt.Sprintf("cookie=%s, priority=5, table=11, ct_mark=%s, "+
							"actions=output:%s", nodetypes.DefaultOpenFlowCookie, netConfig.MasqCTMark, netConfig.OfPortPatch))
				}
			}

			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=1, table=11, "+
					"actions=output:%s", nodetypes.DefaultOpenFlowCookie, defaultNetConfig.OfPortPatch))
		}

		// table 1, all other connections do normal processing
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=0, table=1, actions=output:NORMAL", nodetypes.DefaultOpenFlowCookie))
	}

	return dftFlows, nil
}

func (b *BridgeConfiguration) PMTUDDropFlows(ipAddrs []string) []string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	var flows []string
	if config.Gateway.Mode != config.GatewayModeShared {
		return nil
	}
	for _, addr := range ipAddrs {
		for _, netConfig := range b.patchedNetConfigs() {
			flows = append(flows,
				nodeutil.GenerateICMPFragmentationFlow(addr, nodetypes.OutputPortDrop, netConfig.OfPortPatch, nodetypes.PmtudOpenFlowCookie, 700))
		}
	}

	return flows
}

func getIPv(ipnet *net.IPNet) string {
	prefix := "ip"
	if utilnet.IsIPv6CIDR(ipnet) {
		prefix = "ipv6"
	}
	return prefix
}

// hostNetworkNormalActionFlows returns the flows that allow IP{v4,v6} traffic:
// a. from pods in the OVN network to pods in a localnet network, on the same node
// b. from pods on the host to pods in a localnet network, on the same node
// when the localnet is mapped to breth0.
// The expected srcMAC is the MAC address of breth0 and the expected hostSubnets is the host subnets found on the node
// primary interface.
func hostNetworkNormalActionFlows(netConfig *BridgeUDNConfiguration, srcMAC string, hostSubnets []*net.IPNet, isV6 bool) []string {
	var flows []string
	var ipFamily, ipFamilyDest string

	if isV6 {
		ipFamily = "ipv6"
		ipFamilyDest = "ipv6_dst"
	} else {
		ipFamily = "ip"
		ipFamilyDest = "nw_dst"
	}

	formatFlow := func(inPort, destIP, ctMark string) string {
		// Matching IP traffic will be handled by the bridge instead of being output directly
		// to the NIC by the existing flow at prio=100.
		flowTemplate := "cookie=%s, priority=102, in_port=%s, dl_src=%s, %s, %s=%s, " +
			"actions=ct(commit, zone=%d, exec(set_field:%s->ct_mark)), output:NORMAL"
		return fmt.Sprintf(flowTemplate,
			nodetypes.DefaultOpenFlowCookie,
			inPort,
			srcMAC,
			ipFamily,
			ipFamilyDest,
			destIP,
			config.Default.ConntrackZone,
			ctMark)
	}

	// Traffic path (a): OVN->localnet for shared gw mode
	if config.Gateway.Mode == config.GatewayModeShared {
		for _, hostSubnet := range hostSubnets {
			if utilnet.IsIPv6(hostSubnet.IP) != isV6 {
				continue
			}
			flows = append(flows, formatFlow(netConfig.OfPortPatch, hostSubnet.String(), netConfig.MasqCTMark))
		}
	}

	// Traffic path (a): OVN->localnet for local gw mode
	// Traffic path (b): host->localnet for both gw modes
	for _, hostSubnet := range hostSubnets {
		if utilnet.IsIPv6(hostSubnet.IP) != isV6 {
			continue
		}
		flows = append(flows, formatFlow(nodetypes.OvsLocalPort, hostSubnet.String(), nodetypes.CtMarkHost))
	}

	if isV6 {
		// IPv6 neighbor discovery uses ICMPv6 messages sent to a special destination (ff02::1:ff00:0/104)
		// that is unrelated to the host subnets matched in the prio=102 flow above.
		// Allow neighbor discovery by matching against ICMP type and ingress port.
		formatICMPFlow := func(inPort, ctMark string, icmpType int) string {
			icmpFlowTemplate := "cookie=%s, priority=102, in_port=%s, dl_src=%s, icmp6, icmpv6_type=%d, " +
				"actions=ct(commit, zone=%d, exec(set_field:%s->ct_mark)), output:NORMAL"
			return fmt.Sprintf(icmpFlowTemplate,
				nodetypes.DefaultOpenFlowCookie,
				inPort,
				srcMAC,
				icmpType,
				config.Default.ConntrackZone,
				ctMark)
		}

		for _, icmpType := range []int{types.NeighborSolicitationICMPType, types.NeighborAdvertisementICMPType} {
			// Traffic path (a) for ICMP: OVN-> localnet for shared gw mode
			if config.Gateway.Mode == config.GatewayModeShared {
				flows = append(flows,
					formatICMPFlow(netConfig.OfPortPatch, netConfig.MasqCTMark, icmpType))
			}

			// Traffic path (a) for ICMP: OVN->localnet for local gw mode
			// Traffic path (b) for ICMP: host->localnet for both gw modes
			flows = append(flows, formatICMPFlow(nodetypes.OvsLocalPort, nodetypes.CtMarkHost, icmpType))
		}
	}
	return flows
}
