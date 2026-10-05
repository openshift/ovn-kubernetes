package node

import (
	"context"
	"fmt"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
	"sigs.k8s.io/knftables"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	nodenft "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/nftables"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

const nftPMTUDChain = "no-pmtud"
const nftEgressIPDropChain = "egressip-drop"

// setupRemoteNodeNFTSets sets up the NFT sets that contain remote Kubernetes node IPs
func setupRemoteNodeNFTSets() error {
	nft, err := nodenft.GetNFTablesHelper()
	if err != nil {
		return fmt.Errorf("failed to get nftables helper: %w", err)
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Set{
		Name:    types.NFTRemoteNodeIPsv4,
		Comment: knftables.PtrTo("Block egress ICMP needs frag to remote Kubernetes nodes"),
		Type:    "ipv4_addr",
	})
	tx.Add(&knftables.Set{
		Name:    types.NFTRemoteNodeIPsv6,
		Comment: knftables.PtrTo("Block egress ICMPv6 packet too big to remote Kubernetes nodes"),
		Type:    "ipv6_addr",
	})

	err = nft.Run(context.TODO(), tx)
	if err != nil {
		return fmt.Errorf("could not add nftables sets for pmtud blocking: %v", err)
	}
	return nil
}

// setupPMTUDNFTChain sets up the chain and rules to block PMTUD packets from being sent to k8s nodes
// Relies on the sets from setupPMTUDNFTSets.
func setupPMTUDNFTChain() error {
	counterIfDebug := ""
	if config.Logging.Level > 4 {
		counterIfDebug = "counter"
	}

	nft, err := nodenft.GetNFTablesHelper()
	if err != nil {
		return fmt.Errorf("failed to get nftables helper")
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Chain{
		Name:     nftPMTUDChain,
		Comment:  knftables.PtrTo("Block egress needs frag/packet too big to remote k8s nodes"),
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
	})

	tx.Flush(&knftables.Chain{
		Name: nftPMTUDChain,
	})
	if config.IPv4Mode {
		tx.Add(&knftables.Rule{
			Chain: nftPMTUDChain,
			Rule: knftables.Concat(
				"ip daddr @"+types.NFTRemoteNodeIPsv4,
				"meta l4proto icmp",
				"icmp type 3", // type 3 == Destination Unreachable
				"icmp code 4", // code 4 indicates fragmentation needed
				counterIfDebug,
				"drop",
			),
		})
	}

	if config.IPv6Mode {
		tx.Add(&knftables.Rule{
			Chain: nftPMTUDChain, // your egress chain for IPv6 traffic
			Rule: knftables.Concat(
				"meta l4proto icmpv6", // match on ICMPv6 packets
				"icmpv6 type 2",       // type 2 == Packet Too Big (PMTUD)
				"icmpv6 code 0",       // code 0 for that message
				"ip6 daddr @"+types.NFTRemoteNodeIPsv6,
				counterIfDebug,
				"drop", // drop the packet
			),
		})
	}

	err = nft.Run(context.TODO(), tx)
	if err != nil {
		return fmt.Errorf("could not update nftables rule for PMTUD: %v", err)
	}
	return nil
}

// SetupEgressIPARPBlockNFT sets up nftables for blocking ARP/NDP responses for egress IPs during
// graceful shutdown. Uses netdev family with ingress hook on the physical uplink interface to intercept
// packets before they reach the OVS bridge, preventing OVN from responding to ARP/NDP requests.
func SetupEgressIPARPBlockNFT(egressIPs []string, uplinkName string) error {
	if uplinkName == "" {
		return fmt.Errorf("uplink interface name is required for netdev nftables rules")
	}

	var ipv4Addrs, ipv6Addrs []string
	for _, ipStr := range egressIPs {
		if !utilnet.IsIPv6String(ipStr) {
			ipv4Addrs = append(ipv4Addrs, ipStr)
		} else {
			ipv6Addrs = append(ipv6Addrs, ipStr)
		}
	}

	// There are two entity which can reply to ARP broadcast messages:
	// - EgressIP attached to bridge interface
	// - SNAT rules at gateway router
	// netdev table family in nftables evaluates network packets very early and before reaches bridge interface. Any other
	// table family can cause ARP response until ovs-vswitchd is stopped on egressNode(before EIP migration) during node reboot.
	nft, err := nodenft.GetEgressIPNFTablesHelper()
	if err != nil {
		return fmt.Errorf("failed to get egress IP nftables helper: %w", err)
	}

	tx := nft.NewTransaction()

	tx.Add(&knftables.Table{})

	tx.Add(&knftables.Chain{
		Name:     nftEgressIPDropChain,
		Comment:  knftables.PtrTo("Block ARP/NDP for egress IPs during application restart"),
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.IngressHook),
		Device:   knftables.PtrTo(uplinkName),
		Priority: knftables.PtrTo(knftables.FilterPriority),
	})

	if config.IPv4Mode && len(ipv4Addrs) > 0 {
		tx.Add(&knftables.Set{
			Name:    types.NFTEgressIPARPBlockV4,
			Comment: knftables.PtrTo("IPv4 egress IPs"),
			Type:    "ipv4_addr",
		})

		for _, ipStr := range ipv4Addrs {
			tx.Add(&knftables.Element{
				Set: types.NFTEgressIPARPBlockV4,
				Key: []string{ipStr},
			})
		}

		tx.Add(&knftables.Rule{
			Chain: nftEgressIPDropChain,
			Rule: knftables.Concat(
				"arp daddr ip @"+types.NFTEgressIPARPBlockV4,
				"drop",
			),
		})
	}

	if config.IPv6Mode && len(ipv6Addrs) > 0 {
		tx.Add(&knftables.Set{
			Name:    types.NFTEgressIPNDPBlockV6,
			Comment: knftables.PtrTo("IPv6 egress IPs"),
			Type:    "ipv6_addr",
		})

		for _, ipStr := range ipv6Addrs {
			tx.Add(&knftables.Element{
				Set: types.NFTEgressIPNDPBlockV6,
				Key: []string{ipStr},
			})
		}

		tx.Add(&knftables.Rule{
			Chain: nftEgressIPDropChain,
			Rule: knftables.Concat(
				"icmpv6 type nd-neighbor-solicit",
				"icmpv6 taddr @"+types.NFTEgressIPNDPBlockV6,
				"drop",
			),
		})
	}

	if err = nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("could not setup egress IP nftables: %v", err)
	}

	return nil
}

// CleanupEgressIPARPBlockNFT deletes the dedicated nftable "ovn-kubernetes-egressip"  for egress IP ARP/NDP blocking.
// Called during startup to remove stale rules from previous container shutdown.
// On full node reboot, nftables state is cleared automatically, so this primarily handles container restarts.
func CleanupEgressIPARPBlockNFT(ctx context.Context) error {
	nft, err := nodenft.GetEgressIPNFTablesHelper()
	if err != nil {
		return fmt.Errorf("failed to get egress IP nftables helper: %w", err)
	}

	tx := nft.NewTransaction()
	tx.Delete(&knftables.Table{})

	if err = nft.Run(ctx, tx); err != nil && !knftables.IsNotFound(err) {
		return fmt.Errorf("could not delete egress IP nftables table %s: %v", nodenft.OVNKubernetesEgressIPNFTablesName, err)
	}

	klog.Infof("Cleaned up egress IP nftables table from previous shutdown : %s", nodenft.OVNKubernetesEgressIPNFTablesName)
	return nil
}
