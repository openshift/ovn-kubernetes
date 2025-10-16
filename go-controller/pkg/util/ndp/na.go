package ndp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/ndp"

	"k8s.io/klog/v2"
)

// NeighborAdvertisement represents a Neighbor Advertisement for an IPv6 address.
type NeighborAdvertisement interface {
	// IP returns the IPv6 address
	IP() net.IP
	// MAC returns the MAC address to advertise (nil means use interface MAC)
	MAC() *net.HardwareAddr
}

type neighborAdvertisement struct {
	ip  net.IP
	mac *net.HardwareAddr
}

// NewNeighborAdvertisement creates a new Unsolicited Neighbor Advertisement with validation that the IP is IPv6.
func NewNeighborAdvertisement(ip net.IP, mac *net.HardwareAddr) (NeighborAdvertisement, error) {
	// TODO: Can have v6 mapped v4?
	if ip.To4() != nil {
		return nil, fmt.Errorf("only IPv6 addresses can be used for NeighborAdvertisement, got IPv4 %s", ip.String())
	}
	if ip.To16() == nil {
		return nil, fmt.Errorf("only IPv6 addresses can be used for NeighborAdvertisement, got %s", ip.String())
	}

	return &neighborAdvertisement{
		ip:  ip.To16(),
		mac: mac,
	}, nil
}

// IP returns the IPv6 address
func (u *neighborAdvertisement) IP() net.IP {
	return u.ip
}

// MAC returns the MAC address to advertise
func (u *neighborAdvertisement) MAC() *net.HardwareAddr {
	return u.mac
}

// SendUnsolicitedNeighborAdvertisement sends an unsolicited neighbor advertisement for the given IPv6 address.
// If the mac address is not provided it will use the one from the interface.
func SendUnsolicitedNeighborAdvertisement(interfaceName string, na NeighborAdvertisement) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed finding interface %s: %v", interfaceName, err)
	}

	targetIP := na.IP()
	mac := na.MAC()
	if mac == nil {
		mac = &iface.HardwareAddr
	}

	targetAddr, ok := netip.AddrFromSlice(targetIP)
	if !ok {
		return fmt.Errorf("failed to convert IP %s to netip.Addr", targetIP.String())
	}

	allNodesMulticast := netip.MustParseAddr("ff02::1")

	// Use the target address as the source for the NA
	// This is required for gratuitous NAs to properly update neighbor caches
	c, _, err := ndp.Listen(iface, ndp.Addr(na.IP().String()))
	if err != nil {
		return fmt.Errorf("failed to create NDP connection on %s: %w", interfaceName, err)
	}
	defer c.Close()

	una := &ndp.NeighborAdvertisement{
		Router:        false,
		Solicited:     false,
		Override:      true,
		TargetAddress: targetAddr,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      *mac,
			},
		},
	}

	if err := c.WriteTo(una, nil, allNodesMulticast); err != nil {
		return fmt.Errorf("failed to send an unsolicited neighbor advertisement for IP %s over interface %s: %w", targetIP.String(), interfaceName, err)
	}

	klog.Infof("Sent an unsolicited neighbor advertisement for IP %s on interface %s with MAC: %s", targetIP.String(), interfaceName, mac.String())
	return nil
}
