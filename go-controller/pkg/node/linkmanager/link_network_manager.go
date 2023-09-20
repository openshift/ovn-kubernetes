package linkmanager

import (
	"fmt"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
)

// Gather all suitable interface address + network mask and offer this as a service.
// Also offer address assignment to interfaces and ensure the state we want is maintained through a sync func

type LinkAddress struct {
	Link      netlink.Link
	Addresses []netlink.Addr
}

type Controller struct {
	mu          *sync.Mutex
	name        string
	ipv4Enabled bool
	ipv6Enabled bool
	store       map[string][]netlink.Addr
}

// NewController creates a controller to manage linux network interfaces
func NewController(name string, v4, v6 bool) *Controller {
	return &Controller{
		mu:          &sync.Mutex{},
		name:        name,
		ipv4Enabled: v4,
		ipv6Enabled: v6,
		store:       make(map[string][]netlink.Addr, 0),
	}
}

// Run starts the controller and syncs at least every syncPeriod
func (c *Controller) Run(stopCh <-chan struct{}, syncPeriod time.Duration) {
	ticker := time.NewTicker(syncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			c.reconcile()
			c.mu.Unlock()
		}
	}

}

// AddAddress stores the address in a store and ensures its applied
func (c *Controller) AddAddress(address netlink.Addr) error {
	if !c.isAddressValid(address) {
		return fmt.Errorf("address (%s) is not valid", address.String())
	}
	link, err := util.GetNetLinkOps().LinkByIndex(address.LinkIndex)
	if err != nil {
		return fmt.Errorf("no valid link associated with addresses %s: %v", address.String(), err)
	}
	klog.Infof("Link manager: adding address %s to link %s", address.String(), link.Attrs().Name)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addAddressToStore(link.Attrs().Name, address)
	c.reconcile()
	return nil
}

// DelAddress removes the address from the store and ensure its removed from a link
func (c *Controller) DelAddress(address netlink.Addr) error {
	if !c.isAddressValid(address) {
		return fmt.Errorf("address (%s) is not valid", address.String())
	}
	link, err := util.GetNetLinkOps().LinkByIndex(address.LinkIndex)
	if err != nil && !util.GetNetLinkOps().IsLinkNotFoundError(err) {
		return fmt.Errorf("no valid link associated with addresses %s: %v", address.String(), err)
	}
	klog.Infof("Link manager: deleting address %s from link %s", address.String(), link.Attrs().Name)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := util.GetNetLinkOps().AddrDel(link, &address); err != nil {
		if !util.GetNetLinkOps().IsLinkNotFoundError(err) {
			return fmt.Errorf("failed to delete address %s: %v", address.String(), err)
		}
	}
	c.delAddressFromStore(link.Attrs().Name, address)
	return nil
}

func (c *Controller) reconcile() {
	// 1. get all the links on the node
	// 2. iterate over the links and get the addresses associated with it
	// 3. add addresses that are missing from a link that we manage
	links, err := util.GetNetLinkOps().LinkList()
	if err != nil {
		klog.Errorf("Link manager: failed to list links: %v", err)
		return
	}
	for _, link := range links {
		linkName := link.Attrs().Name
		// get all addresses associated with the link depending on which IP families we support
		foundAddresses, err := util.GetFilteredInterfaceAddrs(link, c.ipv4Enabled, c.ipv6Enabled)
		if err != nil {
			klog.Errorf("Link manager: failed to get address from link %q", linkName)
			continue
		}
		wantedAddresses, found := c.store[linkName]
		// we don't manage this link therefore we don't need to add any addresses
		if !found {
			continue
		}
		// add addresses we want that are not found on the link
		for _, addressWanted := range wantedAddresses {
			if containsAddress(foundAddresses, addressWanted) {
				continue
			}
			if err = util.GetNetLinkOps().AddrAdd(link, &addressWanted); err != nil {
				klog.Errorf("Link manager: failed to add address %q to link %q: %v", addressWanted.String(), linkName, err)
			}
			// For IPv4, use arping to try to update other hosts ARP caches, in case this IP was
			// previously active on another node
			if addressWanted.IP.To4() != nil {
				if err = arping.GratuitousArpOverIfaceByName(addressWanted.IP, linkName); err != nil {
					klog.Errorf("Failed to send a GARP for IP %s over interface %s: %v", addressWanted.IP.String(),
						linkName, err)
				}
			}
			klog.Infof("Link manager: completed adding address %s to link %s", addressWanted, linkName)
		}
	}
}

func (c *Controller) addAddressToStore(linkName string, newAddress netlink.Addr) {
	addressesSaved, found := c.store[linkName]
	if !found {
		c.store[linkName] = []netlink.Addr{newAddress}
		return
	}
	// check if the address already exists
	for _, addressSaved := range addressesSaved {
		if addressSaved.Equal(newAddress) {
			return
		}
	}
	// add it to store if not found
	c.store[linkName] = append(addressesSaved, newAddress)
}

func (c *Controller) delAddressFromStore(linkName string, address netlink.Addr) {
	addressesSaved, found := c.store[linkName]
	if !found {
		return
	}
	temp := addressesSaved[:0]
	for _, addressSaved := range addressesSaved {
		if !addressSaved.Equal(address) {
			temp = append(temp, addressSaved)
		}
	}
	c.store[linkName] = temp
}

func (c *Controller) isAddressValid(address netlink.Addr) bool {
	if address.LinkIndex == 0 {
		return false
	}
	if address.IPNet == nil {
		return false
	}
	if address.IPNet.IP.IsUnspecified() {
		return false
	}
	if utilnet.IsIPv4(address.IP) && !c.ipv4Enabled {
		return false
	}
	if utilnet.IsIPv6(address.IP) && !c.ipv6Enabled {
		return false
	}
	return true
}

// DeprecatedGetAssignedAddressLabel returns the label that must be assigned to each egress IP address bound to an interface
func DeprecatedGetAssignedAddressLabel(linkName string) string {
	return fmt.Sprintf("%sovn", linkName)
}

func containsAddress(addresses []netlink.Addr, candidate netlink.Addr) bool {
	for _, address := range addresses {
		if address.Equal(candidate) {
			return true
		}
	}
	return false
}
