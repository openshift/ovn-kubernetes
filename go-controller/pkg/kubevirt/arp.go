package kubevirt

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/arp"
)

func sendGARP(interfaceName string, ip net.IP, mac net.HardwareAddr) error {
	addr := netip.AddrFrom4([4]byte(ip))
	p, err := arp.NewPacket(arp.OperationReply, mac, addr, net.HardwareAddr{0, 0, 0, 0, 0, 0}, addr)
	if err != nil {
		return fmt.Errorf("failed create GARP: %w", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed finding interface %s: %v", interfaceName, err)
	}

	c, err := arp.Dial(iface)
	if err != nil {
		return fmt.Errorf("failed dialing %q: %v", interfaceName, err)
	}
	defer c.Close()

	err = c.WriteTo(p, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return fmt.Errorf("failed sending GARP: %w", err)
	}

	return nil
}
