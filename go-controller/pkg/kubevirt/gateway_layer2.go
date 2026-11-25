// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/generator/udn"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/ndp"
)

// Layer2GatewayAnnouncer is responsible for reconciling the default gateway
// configuration of a virtual machine's network interface after a live migration.
// It supports both IPv4 and IPv6 configurations.
type Layer2GatewayAnnouncer struct {
	watchFactory  *factory.WatchFactory
	netInfo       util.NetInfo
	interfaceName string
	unicastGARP   func(string, util.GARP, net.HardwareAddr) error
}

// NewLayer2GatewayAnnouncer creates a new instance of Layer2GatewayAnnouncer.
// It takes a WatchFactory for managing resource watches, a NetInfo object for network information,
// and the name of the network interface to send ARPs or RAs as parameters.
func NewLayer2GatewayAnnouncer(watchFactory *factory.WatchFactory, netInfo util.NetInfo, interfaceName string) *Layer2GatewayAnnouncer {
	return &Layer2GatewayAnnouncer{
		watchFactory:  watchFactory,
		netInfo:       netInfo,
		interfaceName: interfaceName,
		unicastGARP:   util.UnicastGARP,
	}
}

// AnnounceIPv4AfterLiveMigration sends unicast GARPs to the migrated VM to
// update its default gateway MAC address to that of the node where it is running.
func (r *Layer2GatewayAnnouncer) AnnounceIPv4AfterLiveMigration(liveMigrationStatus *LiveMigrationStatus) error {
	if liveMigrationStatus.State != LiveMigrationTargetDomainReady {
		return nil
	}

	targetPod := liveMigrationStatus.TargetPod
	nads := r.netInfo.GetNADs()
	if len(nads) != 1 {
		return fmt.Errorf("expected only one nad for network %q, got %d", r.netInfo.GetNetworkName(), len(nads))
	}
	targetPodAnnotation, err := util.UnmarshalPodAnnotation(targetPod.Annotations, nads[0])
	if err != nil {
		return ovntypes.NewSuppressedError(fmt.Errorf("failed parsing ovn pod annotation for pod '%s/%s' and network %q: %w", targetPod.Namespace, targetPod.Name, r.netInfo.GetNetworkName(), err))
	}

	targetNode, err := r.watchFactory.GetNode(targetPod.Spec.NodeName)
	if err != nil {
		return err
	}

	lrpJoinAddress, err := udn.GetGWRouterIPv4(targetNode, r.netInfo)
	if err != nil {
		return err
	}

	lrpMAC := util.IPAddrToHWAddr(lrpJoinAddress)
	var gateways []ipv4Gateway
	for _, subnet := range r.netInfo.Subnets() {
		gwIP := r.netInfo.GetNodeGatewayIP(subnet.CIDR).IP.To4()
		if gwIP == nil {
			continue
		}
		gateways = append(gateways, ipv4Gateway{ip: gwIP, mac: lrpMAC})
	}
	return sendGatewayGARPs(r.interfaceName, gateways, targetPodAnnotation.MAC, r.unicastGARP)
}

// AnnounceIPv6AfterLiveMigration will do two things at VM's:
// - Remove ipv6 default gw path from VM's node before live migration
// - Add ipv6 default gw path from VM's node after live migration
// This is done by sending a pair of unsolicited RA's one with lifetime=0
// (to remove the gateway path) another with lifetime=max to add the new
// default gateway path
func (r *Layer2GatewayAnnouncer) AnnounceIPv6AfterLiveMigration(liveMigration *LiveMigrationStatus) error {
	if !liveMigration.IsTargetDomainReady() {
		return nil
	}
	nodes, err := r.watchFactory.GetNodes()
	if err != nil {
		return err
	}

	targetPod := liveMigration.TargetPod
	if len(r.netInfo.GetNADs()) != 1 {
		return fmt.Errorf("expected only one nad for network %q, got %d", r.netInfo.GetNetworkName(), len(r.netInfo.GetNADs()))
	}

	targetPodAnnotation, err := util.UnmarshalPodAnnotation(targetPod.Annotations, r.netInfo.GetNADs()[0])
	if err != nil {
		return ovntypes.NewSuppressedError(fmt.Errorf("failed parsing ovn pod annotation for pod '%s/%s' and network %q: %w", targetPod.Namespace, targetPod.Name, r.netInfo.GetNetworkName(), err))
	}

	destinationIP, err := util.MatchFirstIPNetFamily(true /* ipv6 */, targetPodAnnotation.IPs)
	if err != nil {
		return err
	}
	destinationMAC := targetPodAnnotation.MAC

	ras := make([]ndp.RouterAdvertisement, 0, len(nodes))
	for _, node := range nodes {
		if node.Name == liveMigration.TargetPod.Spec.NodeName {
			// skip the target node since this is the proper gateway
			continue
		}
		nodeJoinAddrs, err := udn.GetGWRouterIPs(node, r.netInfo)
		if err != nil {
			return ovntypes.NewSuppressedError(fmt.Errorf("failed parsing join addresss from node %q and network %q to reconcile ipv6 gateway: %w", node.Name, r.netInfo.GetNetworkName(), err))
		}
		// During upgrades, nftables blocks Router Advertisements (RAs) from other nodes.
		// However, Virtual Machines (VMs) may still retain old default gateway paths.
		// To address this, we create a new Router Advertisement with a lifetime of 0
		// to signal the removal of the old default gateway.
		// NOTE: This is a workaround for the issue and may not be needed in the future, after
		//       upgrading to a version that supports the new behavior.
		ras = append(ras, newRouterAdvertisementFromJoinIPAndLifetime(nodeJoinAddrs[0].IP, destinationMAC, destinationIP.IP, 0))
	}
	targetNode, err := r.watchFactory.GetNode(liveMigration.TargetPod.Spec.NodeName)
	if err != nil {
		return fmt.Errorf("failed fetching node %q to reconcile ipv6 gateway: %w", liveMigration.TargetPod.Spec.NodeName, err)
	}
	targetNodeJoinAddrs, err := udn.GetGWRouterIPs(targetNode, r.netInfo)
	if err != nil {
		return ovntypes.NewSuppressedError(fmt.Errorf("failed parsing join addresss from live migration target node %q and network %q to reconcile ipv6 gateway: %w", targetNode.Name, r.netInfo.GetNetworkName(), err))
	}
	ras = append(ras, newRouterAdvertisementFromJoinIPAndLifetime(targetNodeJoinAddrs[0].IP, destinationMAC, destinationIP.IP, 65535))
	return ndp.SendRouterAdvertisements(r.interfaceName, ras...)
}

// newRouterAdvertisementFromJoinIPAndLifetime creates a new Router Advertisement (RA) message
// using the provided join IP address, destination MAC, destination IP, and lifetime.
//
// This function performs the following:
// - Derives the source MAC address from the given IP using util.IPAddrToHWAddr.
// - Calculates the link-local address (LLA) from the source MAC using util.HWAddrToIPv6LLA.
// - Configures the destination IP and MAC address to use the provided values.
// - Sets the RA message's lifetime to the specified value.
//
// Parameters:
// - ip: The join IP address used to derive the source MAC and LLA.
// - destinationMAC: The MAC address to which the RA message will be sent.
// - destinationIP: The IP address to which the RA message will be sent.
// - lifetime: The lifetime value for the RA message, in seconds.
//
// Returns:
// - An ndp.RouterAdvertisement object configured with the calculated source MAC, LLA, and the provided destination MAC, IP, and lifetime.
func newRouterAdvertisementFromJoinIPAndLifetime(ip net.IP, destinationMAC net.HardwareAddr, destinationIP net.IP, lifetime uint16) ndp.RouterAdvertisement {
	sourceMAC := util.IPAddrToHWAddr(ip)
	return ndp.RouterAdvertisement{
		SourceMAC:      sourceMAC,
		SourceIP:       util.HWAddrToIPv6LLA(sourceMAC),
		DestinationMAC: destinationMAC,
		DestinationIP:  destinationIP,
		Lifetime:       lifetime,
	}
}
