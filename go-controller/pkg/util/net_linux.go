//go:build linux
// +build linux

package util

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/j-keck/arping"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

type NetLinkOps interface {
	LinkList() ([]netlink.Link, error)
	LinkByName(ifaceName string) (netlink.Link, error)
	LinkByIndex(index int) (netlink.Link, error)
	LinkSetDown(link netlink.Link) error
	LinkDelete(link netlink.Link) error
	LinkSetName(link netlink.Link, newName string) error
	LinkSetUp(link netlink.Link) error
	LinkSetNsFd(link netlink.Link, fd int) error
	LinkSetHardwareAddr(link netlink.Link, hwaddr net.HardwareAddr) error
	LinkSetMTU(link netlink.Link, mtu int) error
	LinkSetTxQLen(link netlink.Link, qlen int) error
	IsLinkNotFoundError(err error) bool
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	RouteDel(route *netlink.Route) error
	RouteAdd(route *netlink.Route) error
	RouteReplace(route *netlink.Route) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	NeighAdd(neigh *netlink.Neigh) error
	NeighDel(neigh *netlink.Neigh) error
	NeighList(linkIndex, family int) ([]netlink.Neigh, error)
	ConntrackDeleteFilter(table netlink.ConntrackTableType, family netlink.InetFamily, filter netlink.CustomConntrackFilter) (uint, error)
}

type defaultNetLinkOps struct {
}

var netLinkOps NetLinkOps = &defaultNetLinkOps{}

// SetNetLinkOpMockInst method would be used by unit tests in other packages
func SetNetLinkOpMockInst(mockInst NetLinkOps) {
	netLinkOps = mockInst
}

// ResetNetLinkOpMockInst resets the mock instance for netlink to the defaultNetLinkOps
func ResetNetLinkOpMockInst() {
	netLinkOps = &defaultNetLinkOps{}
}

// GetNetLinkOps will be invoked by functions in other packages that would need access to the netlink library methods.
func GetNetLinkOps() NetLinkOps {
	return netLinkOps
}

func (defaultNetLinkOps) LinkList() ([]netlink.Link, error) {
	return netlink.LinkList()
}

func (defaultNetLinkOps) LinkByName(ifaceName string) (netlink.Link, error) {
	return netlink.LinkByName(ifaceName)
}

func (defaultNetLinkOps) LinkByIndex(index int) (netlink.Link, error) {
	return netlink.LinkByIndex(index)
}

func (defaultNetLinkOps) LinkSetDown(link netlink.Link) error {
	return netlink.LinkSetDown(link)
}

func (defaultNetLinkOps) LinkDelete(link netlink.Link) error {
	return netlink.LinkDel(link)
}

func (defaultNetLinkOps) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (defaultNetLinkOps) LinkSetName(link netlink.Link, newName string) error {
	return netlink.LinkSetName(link, newName)
}

func (defaultNetLinkOps) LinkSetNsFd(link netlink.Link, fd int) error {
	return netlink.LinkSetNsFd(link, fd)
}

func (defaultNetLinkOps) LinkSetHardwareAddr(link netlink.Link, hwaddr net.HardwareAddr) error {
	return netlink.LinkSetHardwareAddr(link, hwaddr)
}

func (defaultNetLinkOps) LinkSetMTU(link netlink.Link, mtu int) error {
	return netlink.LinkSetMTU(link, mtu)
}

func (defaultNetLinkOps) LinkSetTxQLen(link netlink.Link, qlen int) error {
	return netlink.LinkSetTxQLen(link, qlen)
}

func (defaultNetLinkOps) IsLinkNotFoundError(err error) bool {
	return reflect.TypeOf(err) == reflect.TypeOf(netlink.LinkNotFoundError{})
}

func (defaultNetLinkOps) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return netlink.AddrList(link, family)
}

func (defaultNetLinkOps) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrDel(link, addr)
}

func (defaultNetLinkOps) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrAdd(link, addr)
}

func (defaultNetLinkOps) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}

func (defaultNetLinkOps) RouteDel(route *netlink.Route) error {
	return netlink.RouteDel(route)
}

func (defaultNetLinkOps) RouteAdd(route *netlink.Route) error {
	return netlink.RouteAdd(route)
}

func (defaultNetLinkOps) RouteReplace(route *netlink.Route) error {
	return netlink.RouteReplace(route)
}

func (defaultNetLinkOps) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, filter, filterMask)
}

func (defaultNetLinkOps) NeighAdd(neigh *netlink.Neigh) error {
	return netlink.NeighAdd(neigh)
}

func (defaultNetLinkOps) NeighDel(neigh *netlink.Neigh) error {
	return netlink.NeighDel(neigh)
}

func (defaultNetLinkOps) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return netlink.NeighList(linkIndex, family)
}

func (defaultNetLinkOps) ConntrackDeleteFilter(table netlink.ConntrackTableType, family netlink.InetFamily, filter netlink.CustomConntrackFilter) (uint, error) {
	return netlink.ConntrackDeleteFilter(table, family, filter)
}

func getFamily(ip net.IP) int {
	if utilnet.IsIPv6(ip) {
		return netlink.FAMILY_V6
	} else {
		return netlink.FAMILY_V4
	}
}

// LinkSetUp returns the netlink device with its state marked up
func LinkSetUp(interfaceName string) (netlink.Link, error) {
	link, err := netLinkOps.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup link %s: %v", interfaceName, err)
	}
	err = netLinkOps.LinkSetUp(link)
	if err != nil {
		return nil, fmt.Errorf("failed to set the link %s up: %v", interfaceName, err)
	}
	return link, nil
}

// LinkDelete removes an interface
func LinkDelete(interfaceName string) error {
	link, err := netLinkOps.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to lookup link %s: %v", interfaceName, err)
	}
	err = netLinkOps.LinkDelete(link)
	if err != nil {
		return fmt.Errorf("failed to remove link %s, error: %v", interfaceName, err)
	}
	return nil
}

// LinkAddrFlush flushes all the addresses on the given link, except IPv6 link-local addresses
func LinkAddrFlush(link netlink.Link) error {
	addrs, err := netLinkOps.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list addresses for the link %s: %v", link.Attrs().Name, err)
	}
	for _, addr := range addrs {
		if utilnet.IsIPv6(addr.IP) && addr.IP.IsLinkLocalUnicast() {
			continue
		}
		err = netLinkOps.AddrDel(link, &addr)
		if err != nil {
			return fmt.Errorf("failed to delete address %s on link %s: %v",
				addr.IP.String(), link.Attrs().Name, err)
		}
	}
	return nil
}

// LinkAddrExist returns true if the given address is present on the link
func LinkAddrExist(link netlink.Link, address *net.IPNet) (bool, error) {
	addrs, err := netLinkOps.AddrList(link, getFamily(address.IP))
	if err != nil {
		return false, fmt.Errorf("failed to list addresses for the link %s: %v",
			link.Attrs().Name, err)
	}
	for _, addr := range addrs {
		if addr.IPNet.String() == address.String() {
			return true, nil
		}
	}
	return false, nil
}

// LinkAddrAdd removes existing addresses on the link and adds the new address
func LinkAddrAdd(link netlink.Link, address *net.IPNet, flags int) error {
	err := netLinkOps.AddrAdd(link, &netlink.Addr{IPNet: address, Flags: flags})
	if err != nil {
		return fmt.Errorf("failed to add address %s on link %s: %v", address, link.Attrs().Name, err)
	}
	return nil
}

// LinkRoutesDel deletes all the routes for the given subnets via the link
// if subnets is empty, then all routes will be removed for a link
// if any item in subnets is nil the default route will be removed
func LinkRoutesDel(link netlink.Link, subnets []*net.IPNet) error {
	routes, err := netLinkOps.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get all the routes for link %s: %v",
			link.Attrs().Name, err)
	}
	for _, route := range routes {
		if len(subnets) == 0 {
			err = netLinkOps.RouteDel(&route)
			if err != nil {
				return fmt.Errorf("failed to delete route '%s via %s' for link %s : %v\n",
					route.Dst.String(), route.Gw.String(), link.Attrs().Name, err)
			}
			continue
		}
		for _, subnet := range subnets {
			deleteRoute := false

			if subnet == nil {
				deleteRoute = route.Dst == nil
			} else if route.Dst != nil {
				deleteRoute = route.Dst.String() == subnet.String()
			}

			if deleteRoute {
				err = netLinkOps.RouteDel(&route)
				if err != nil {
					net := "default"
					if route.Dst != nil {
						net = route.Dst.String()
					}
					return fmt.Errorf("failed to delete route '%s via %s' for link %s : %v\n",
						net, route.Gw.String(), link.Attrs().Name, err)
				}
				break
			}
		}
	}
	return nil
}

// LinkRoutesAdd adds a new route for given subnets through the gwIPstr
func LinkRoutesAdd(link netlink.Link, gwIP net.IP, subnets []*net.IPNet, mtu int, src net.IP) error {
	for _, subnet := range subnets {
		route := &netlink.Route{
			Dst:       subnet,
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Gw:        gwIP,
		}
		if len(src) > 0 {
			route.Src = src
		}
		if mtu != 0 {
			route.MTU = mtu
		}
		err := netLinkOps.RouteAdd(route)
		if err != nil {
			return fmt.Errorf("failed to add route for subnet %s via gateway %s with mtu %d and src: %s: %v",
				subnet.String(), gwIP.String(), mtu, src, err)
		}
	}
	return nil
}

// LinkRouteGetFilteredRoute gets a route for the given route filter.
// returns nil if route is not found
func LinkRouteGetFilteredRoute(routeFilter *netlink.Route, filterMask uint64) (*netlink.Route, error) {
	routes, err := netLinkOps.RouteListFiltered(getFamily(routeFilter.Dst.IP), routeFilter, filterMask)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get routes for filter %v with mask %d: %v", *routeFilter, filterMask, err)
	}
	if len(routes) == 0 {
		return nil, nil
	}
	return &routes[0], nil
}

// LinkRouteExists checks for existence of routes for the given subnet through gwIPStr
func LinkRouteExists(link netlink.Link, gwIP net.IP, subnet *net.IPNet) (bool, error) {
	route, err := LinkRouteGetFilteredRoute(filterRouteByDstAndGw(link, subnet, gwIP))
	return route != nil, err
}

// LinkNeighDel deletes an ip binding for a given link
func LinkNeighDel(link netlink.Link, neighIP net.IP) error {
	neigh := &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    getFamily(neighIP),
		IP:        neighIP,
	}
	err := netLinkOps.NeighDel(neigh)
	if err != nil {
		return fmt.Errorf("failed to delete neighbour entry %+v: %v", neigh, err)
	}
	return nil
}

// LinkNeighAdd adds MAC/IP bindings for the given link
func LinkNeighAdd(link netlink.Link, neighIP net.IP, neighMAC net.HardwareAddr) error {
	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       getFamily(neighIP),
		State:        netlink.NUD_PERMANENT,
		IP:           neighIP,
		HardwareAddr: neighMAC,
	}
	err := netLinkOps.NeighAdd(neigh)
	if err != nil {
		return fmt.Errorf("failed to add neighbour entry %+v: %v", neigh, err)
	}
	return nil
}

func SetARPTimeout() {
	arping.SetTimeout(50 * time.Millisecond) // hard-coded for now
}

func GetMACAddressFromARP(neighIP net.IP) (net.HardwareAddr, error) {
	hwAddr, _, err := arping.Ping(neighIP)
	if err != nil {
		return nil, err
	}
	return hwAddr, nil
}

// LinkNeighExists checks to see if the given MAC/IP bindings exists
func LinkNeighExists(link netlink.Link, neighIP net.IP, neighMAC net.HardwareAddr) (bool, error) {
	neighs, err := netLinkOps.NeighList(link.Attrs().Index, getFamily(neighIP))
	if err != nil {
		return false, fmt.Errorf("failed to get the list of neighbour entries for link %s",
			link.Attrs().Name)
	}

	for _, neigh := range neighs {
		if neigh.IP.Equal(neighIP) {
			if bytes.Equal(neigh.HardwareAddr, neighMAC) &&
				(neigh.State&netlink.NUD_PERMANENT) == netlink.NUD_PERMANENT {
				return true, nil
			}
		}
	}
	return false, nil
}

func DeleteConntrack(ip string, port int32, protocol kapi.Protocol, ipFilterType netlink.ConntrackFilterType, labels [][]byte) error {
	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return fmt.Errorf("value %q passed to DeleteConntrack is not an IP address", ipAddress)
	}

	filter := &netlink.ConntrackFilter{}
	if protocol == kapi.ProtocolUDP {
		// 17 = UDP protocol
		if err := filter.AddProtocol(17); err != nil {
			return fmt.Errorf("could not add Protocol UDP to conntrack filter %v", err)
		}
	} else if protocol == kapi.ProtocolSCTP {
		// 132 = SCTP protocol
		if err := filter.AddProtocol(132); err != nil {
			return fmt.Errorf("could not add Protocol SCTP to conntrack filter %v", err)
		}
	} else if protocol == kapi.ProtocolTCP {
		// 6 = TCP protocol
		if err := filter.AddProtocol(6); err != nil {
			return fmt.Errorf("could not add Protocol TCP to conntrack filter %v", err)
		}
	}
	if port > 0 {
		if err := filter.AddPort(netlink.ConntrackOrigDstPort, uint16(port)); err != nil {
			return fmt.Errorf("could not add port %d to conntrack filter: %v", port, err)
		}
	}
	if err := filter.AddIP(ipFilterType, ipAddress); err != nil {
		return fmt.Errorf("could not add IP: %s to conntrack filter: %v", ipAddress, err)
	}

	if len(labels) > 0 {
		// for now we only need unmatch label, we can add match label later if needed
		if err := filter.AddLabels(netlink.ConntrackUnmatchLabels, labels); err != nil {
			return fmt.Errorf("could not add label %s to conntrack filter: %v", labels, err)
		}
	}
	if ipAddress.To4() != nil {
		if _, err := netLinkOps.ConntrackDeleteFilter(netlink.ConntrackTable, netlink.FAMILY_V4, filter); err != nil {
			return err
		}
	} else {
		if _, err := netLinkOps.ConntrackDeleteFilter(netlink.ConntrackTable, netlink.FAMILY_V6, filter); err != nil {
			return err
		}
	}
	return nil
}

// GetNetworkInterfaceIPs returns the IP addresses for the network interface 'iface'.
// We filter out addresses that are link local, reserved for internal use or added by keepalived.
func GetNetworkInterfaceIPs(iface string) ([]*net.IPNet, error) {
	link, err := netLinkOps.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup link %s: %v", iface, err)
	}

	addrs, err := netLinkOps.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses for %q: %v", iface, err)
	}

	var ips []*net.IPNet
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() || IsAddressReservedForInternalUse(addr.IP) || IsAddressAddedByKeepAlived(addr) {
			continue
		}
		// Ignore addresses marked as secondary or deprecated since they may
		// disappear. (In bare metal clusters using MetalLB or similar, these
		// flags are used to mark load balancer IPs that aren't permanently owned
		// by the node).
		if (addr.Flags & (unix.IFA_F_SECONDARY | unix.IFA_F_DEPRECATED)) != 0 {
			continue
		}
		ips = append(ips, addr.IPNet)
	}
	return ips, nil
}

func IsAddressReservedForInternalUse(addr net.IP) bool {
	var subnetStr string
	if addr.To4() != nil {
		subnetStr = types.V4MasqueradeSubnet
	} else {
		subnetStr = types.V6MasqueradeSubnet
	}
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		klog.Errorf("Could not determine if %s is in reserved subnet %v: %v",
			addr, subnetStr, err)
		return false
	}
	return subnet.Contains(addr)
}

// IsAddressAddedByKeepAlived returns true if the input interface address obtained
// through netlink has a label that ends with ":vip", which is how keepalived
// marks the IP addresses it adds (https://github.com/openshift/machine-config-operator/pull/3683)
func IsAddressAddedByKeepAlived(addr netlink.Addr) bool {
	return strings.HasSuffix(addr.Label, ":vip")
}

// GetIPv6OnSubnet when given an IPv6 address with a 128 prefix for an interface,
// looks for possible broadest subnet on-link routes and returns the same address
// with the found subnet prefix. Otherwise it returns the provided address unchanged.
func GetIPv6OnSubnet(iface string, ip *net.IPNet) (*net.IPNet, error) {
	if s, _ := ip.Mask.Size(); s != 128 {
		return ip, nil
	}

	link, err := netLinkOps.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup link %s: %v", iface, err)
	}

	routeFilter := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        nil,
	}
	filterMask := netlink.RT_FILTER_GW | netlink.RT_FILTER_OIF
	routes, err := netLinkOps.RouteListFiltered(netlink.FAMILY_V6, routeFilter, filterMask)
	if err != nil {
		return nil, fmt.Errorf("failed to get on-link routes for ip %s and iface %s", ip.String(), iface)
	}

	dst := *ip
	for _, route := range routes {
		if route.Dst.Contains(dst.IP) && !dst.Contains(route.Dst.IP) {
			dst.Mask = route.Dst.Mask
		}
	}

	return &dst, nil
}

// GetIFNameAndMTUForAddress returns the interfaceName and MTU for the given network address
func GetIFNameAndMTUForAddress(ifAddress net.IP) (string, int, error) {
	// from the IP address arrive at the link
	addressFamily := getFamily(ifAddress)
	allAddresses, err := netLinkOps.AddrList(nil, addressFamily)
	if err != nil {
		return "", 0, fmt.Errorf("failed to list all the addresses for address family (%d): %v", addressFamily, err)

	}
	for _, address := range allAddresses {
		if address.IP.Equal(ifAddress) {
			link, err := netLinkOps.LinkByIndex(address.LinkIndex)
			if err != nil {
				return "", 0, fmt.Errorf("failed to lookup link with address(%s) and index(%d): %v",
					ifAddress, address.LinkIndex, err)
			}

			return link.Attrs().Name, link.Attrs().MTU, nil
		}
	}

	return "", 0, fmt.Errorf("couldn't not find a link associated with the given OVN Encap IP (%s)", ifAddress)
}

func filterRouteByDstAndGw(link netlink.Link, subnet *net.IPNet, gw net.IP) (*netlink.Route, uint64) {
	return &netlink.Route{
			Dst:       subnet,
			LinkIndex: link.Attrs().Index,
			Gw:        gw,
		},
		netlink.RT_FILTER_DST | netlink.RT_FILTER_OIF | netlink.RT_FILTER_GW
}
