package pool

import (
	"net"
	"sync"

	"k8s.io/klog/v2"
)

// pool tracks allocated MAC addresses for a specific UDN network
type pool struct {
	allocatedMACs map[string]string // MAC -> owner identifier
}

// NetworkPool manages MAC pools for all UDN networks
type NetworkPool struct {
	lock  sync.RWMutex
	pools map[string]*pool
}

// NewNetworkPool creates a new NetworkPool
func NewNetworkPool() *NetworkPool {
	return &NetworkPool{
		pools: make(map[string]*pool),
	}
}

// AddMACToPool adds a MAC address to the specified network pool with owner tracking
func (n *NetworkPool) AddMACToPool(networkName string, mac net.HardwareAddr, ownerID string) {
	if mac == nil {
		return
	}

	n.lock.Lock()
	defer n.lock.Unlock()

	pool := n.getOrCreatePool(networkName)
	pool.allocatedMACs[mac.String()] = ownerID

	klog.V(5).Infof("Added MAC %s to network %s for owner %s", mac.String(), networkName, ownerID)
}

// getOrCreatePool returns the pool for the given network, creating it if it doesn't exist
func (n *NetworkPool) getOrCreatePool(networkName string) *pool {
	if pool, exists := n.pools[networkName]; exists {
		return pool
	}

	klog.V(5).Infof("Creating new network pool for network: %s", networkName)
	n.pools[networkName] = &pool{
		allocatedMACs: make(map[string]string),
	}
	return n.pools[networkName]
}

// RemoveMACFromPool removes a MAC address from the specified network pool
func (n *NetworkPool) RemoveMACFromPool(networkName string, mac net.HardwareAddr) {
	if mac == nil {
		return
	}

	n.lock.Lock()
	defer n.lock.Unlock()

	if pool, exists := n.pools[networkName]; exists {
		delete(pool.allocatedMACs, mac.String())
		klog.V(5).Infof("Removed MAC %s from network %s", mac.String(), networkName)
	}
}

// IsMACConflict checks if the MAC address is already allocated in the network pool by a different owner
// Returns true only if the MAC is owned by someone other than the requester
func (n *NetworkPool) IsMACConflict(networkName string, mac net.HardwareAddr, ownerID string) bool {
	if mac == nil {
		return false
	}

	n.lock.RLock()
	defer n.lock.RUnlock()

	pool, exists := n.pools[networkName]
	if !exists {
		return false
	}

	currentOwner, isAllocated := pool.allocatedMACs[mac.String()]
	return isAllocated && currentOwner != ownerID
}

// GetMACPoolStats should be used in tests only, returns the number of allocated MACs for a network.
func (n *NetworkPool) GetMACPoolStats(networkName string) int {
	n.lock.RLock()
	defer n.lock.RUnlock()

	pool, exists := n.pools[networkName]
	if !exists {
		return 0
	}

	return len(pool.allocatedMACs)
}
