package util

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/arp"

	"k8s.io/klog/v2"
)

// GARP represents a gratuitous ARP request for an IPv4 address.
type GARP interface {
	// IP returns the IPv4 address as a net.IP
	IP() net.IP
	// IPv4 returns the raw 4-byte IPv4 address
	IPv4() [net.IPv4len]byte
	// MAC returns the MAC address to advertise (nil means use interface MAC)
	MAC() *net.HardwareAddr
}

// garp is the private implementation of GARP
type garp struct {
	ip  [4]byte
	mac *net.HardwareAddr
}

// NewGARP creates a new GARP with validation that the IP is IPv4.
// Returns error if the IP is not a valid IPv4 address.
// mac can be nil to use the interface's MAC address.
func NewGARP(ip net.IP, mac *net.HardwareAddr) (GARP, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("GARP only supports IPv4 addresses, got %s (len=%d bytes)", ip.String(), len(ip))
	}
	return &garp{
		ip:  [4]byte(ip4),
		mac: mac,
	}, nil
}

// IP returns the IPv4 address as a net.IP
func (g *garp) IP() net.IP {
	return net.IP(g.ip[:])
}

// IPv4 returns the raw 4-byte IPv4 address
func (g *garp) IPv4() [4]byte {
	return g.ip
}

// MAC returns the MAC address to advertise
func (g *garp) MAC() *net.HardwareAddr {
	return g.mac
}

// BroadcastGARP sends a pair of gratuitous ARP requests and replies to the
// Ethernet broadcast address. If garp.MAC() is nil, it advertises the interface MAC.
func BroadcastGARP(interfaceName string, garp GARP) error {
	return sendGARP(interfaceName, garp,
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		net.HardwareAddr{0, 0, 0, 0, 0, 0})
}

// UnicastGARP sends a pair of gratuitous ARP requests and replies to destinationMAC,
// using it for both the Ethernet destination and ARP target hardware address.
// If garp.MAC() is nil, it advertises the interface MAC.
func UnicastGARP(interfaceName string, garp GARP, destinationMAC net.HardwareAddr) error {
	return sendGARP(interfaceName, garp, destinationMAC, destinationMAC)
}

func sendGARP(interfaceName string, garp GARP, destinationMAC, targetMAC net.HardwareAddr) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed finding interface %s: %v", interfaceName, err)
	}

	srcIP := netip.AddrFrom4(garp.IPv4())
	mac := garp.MAC()
	if mac == nil {
		mac = &iface.HardwareAddr
	}

	c, err := arp.Dial(iface)
	if err != nil {
		return fmt.Errorf("failed dialing %q: %v", interfaceName, err)
	}
	defer c.Close()

	// Note that some devices will respond to the gratuitous request and some
	// will respond to the gratuitous reply. If one is trying to write
	// software for moving IP addresses around that works with all routers,
	// switches and IP stacks, it is best to send both the request and the reply.
	// These are documented by [RFC 2002](https://tools.ietf.org/html/rfc2002)
	// and [RFC 826](https://tools.ietf.org/html/rfc826). Software implementing
	// the gratuitious ARP function can be found
	// [in the Linux-HA source tree](http://hg.linux-ha.org/lha-2.1/file/1d5b54f0a2e0/heartbeat/libnet_util/send_arp.c).
	//
	// ref: https://wiki.wireshark.org/Gratuitous_ARP
	for _, op := range []arp.Operation{arp.OperationRequest, arp.OperationReply} {
		// The sender and target IP both identify the address being advertised.
		p, err := arp.NewPacket(op, *mac /* srcHw */, srcIP, targetMAC, srcIP)
		if err != nil {
			return fmt.Errorf("failed creating %q GARP %+v: %w", op, garp, err)
		}

		if err := c.WriteTo(p, destinationMAC); err != nil {
			return fmt.Errorf("failed sending %q GARP %+v:  %w", op, garp, err)
		}
	}

	klog.Infof("Sent GARP for IP %s on interface %s with MAC %s to %s", garp.IP().String(), interfaceName, mac.String(), destinationMAC.String())
	return nil
}
