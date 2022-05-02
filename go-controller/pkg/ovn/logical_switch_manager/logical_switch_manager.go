package logicalswitchmanager

import (
	"fmt"
	"net"
	"reflect"
	"sync"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ipam "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator/allocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"k8s.io/klog/v2"
)

// logicalSwitchInfo contains information corresponding to the node. It holds the
// subnet allocations (v4 and v6) as well as the IPAM allocator instances for each
// subnet managed for this node
type logicalSwitchInfo struct {
	hostSubnets  []*net.IPNet
	ipams        []ipam.Interface
	noHostSubnet bool
	// the uuid of the logicalSwitch described by this struct
	uuid string
}

type ipamFactoryFunc func(*net.IPNet) (ipam.Interface, error)

// LogicalSwitchManager provides switch info management APIs including IPAM for the host subnets
type LogicalSwitchManager struct {
	cache map[string]logicalSwitchInfo
	// A RW mutex for LogicalSwitchManager which holds logicalSwitch information
	sync.RWMutex
	ipamFunc ipamFactoryFunc
}

// GetUUID returns the UUID for the given logical switch name if
func (manager *LogicalSwitchManager) GetUUID(name string) (string, bool) {
	manager.RLock()
	defer manager.RUnlock()
	if _, ok := manager.cache[name]; !ok {
		return "", ok
	}
	return manager.cache[name].uuid, true
}

// NewIPAMAllocator provides an ipam interface which can be used for IPAM
// allocations for a given cidr using a contiguous allocation strategy.
// It also pre-allocates certain special subnet IPs such as the .1, .2, and .3
// addresses as reserved.
func NewIPAMAllocator(cidr *net.IPNet) (ipam.Interface, error) {
	subnetRange, err := ipam.NewAllocatorCIDRRange(cidr, func(max int, rangeSpec string) (allocator.Interface, error) {
		return allocator.NewRoundRobinAllocationMap(max, rangeSpec), nil
	})
	if err != nil {
		return nil, err
	}
	if err := reserveIPs(cidr, subnetRange); err != nil {
		klog.Errorf("Failed reserving IPs for subnet %s, err: %v", cidr, err)
		return nil, err
	}
	return subnetRange, nil
}

// Helper function to reserve certain subnet IPs as special
// These are the .1, .2 and .3 addresses in particular
func reserveIPs(subnet *net.IPNet, ipam ipam.Interface) error {
	gwIfAddr := util.GetNodeGatewayIfAddr(subnet)
	err := ipam.Allocate(gwIfAddr.IP)
	if err != nil {
		klog.Errorf("Unable to allocate subnet's gateway IP: %s", gwIfAddr.IP)
		return err
	}
	mgmtIfAddr := util.GetNodeManagementIfAddr(subnet)
	err = ipam.Allocate(mgmtIfAddr.IP)
	if err != nil {
		klog.Errorf("Unable to allocate subnet's management IP: %s", mgmtIfAddr.IP)
		return err
	}
	if config.HybridOverlay.Enabled {
		hybridOverlayIfAddr := util.GetNodeHybridOverlayIfAddr(subnet)

		err = ipam.Allocate(hybridOverlayIfAddr.IP)
		if err != nil {
			klog.Errorf("Unable to allocate subnet's hybrid overlay interface IP: %s", hybridOverlayIfAddr.IP)
			return err
		}
	}

	return nil
}

// Initializes a new logical switch manager
func NewLogicalSwitchManager() *LogicalSwitchManager {
	return &LogicalSwitchManager{
		cache:    make(map[string]logicalSwitchInfo),
		RWMutex:  sync.RWMutex{},
		ipamFunc: NewIPAMAllocator,
	}
}

// AddNode adds/updates a node to the logical switch manager for subnet
// and IPAM management.
func (manager *LogicalSwitchManager) AddNode(nodeName, uuid string, hostSubnets []*net.IPNet) error {
	manager.Lock()
	defer manager.Unlock()
	if lsi, ok := manager.cache[nodeName]; ok && !reflect.DeepEqual(lsi.hostSubnets, hostSubnets) {
		klog.Warningf("Node %q logical switch already in cache with subnet %s; replacing with %s", nodeName,
			util.JoinIPNets(lsi.hostSubnets, ","), util.JoinIPNets(hostSubnets, ","))
	}
	var ipams []ipam.Interface
	for _, subnet := range hostSubnets {
		ipam, err := manager.ipamFunc(subnet)
		if err != nil {
			klog.Errorf("IPAM for subnet %s was not initialized for node %q", subnet, nodeName)
			return err
		}
		ipams = append(ipams, ipam)
	}
	manager.cache[nodeName] = logicalSwitchInfo{
		hostSubnets:  hostSubnets,
		ipams:        ipams,
		noHostSubnet: len(hostSubnets) == 0,
		uuid:         uuid,
	}

	return nil
}

// AddNoHostSubnetNode adds/updates a node without any host subnets
// to the logical switch manager
func (manager *LogicalSwitchManager) AddNoHostSubnetNode(nodeName string) error {
	// setting the hostSubnets slice argument to nil in the cache means an object
	// exists for the switch but it was not assigned a hostSubnet by ovn-kubernetes
	// this will be true for nodes that are marked as host-subnet only.
	return manager.AddNode(nodeName, "", nil)
}

// Remove a switch/node from the the logical switch manager
func (manager *LogicalSwitchManager) DeleteNode(nodeName string) {
	manager.Lock()
	defer manager.Unlock()
	delete(manager.cache, nodeName)
}

// Given a switch name, checks if the switch is a noHostSubnet switch
func (manager *LogicalSwitchManager) IsNonHostSubnetSwitch(nodeName string) bool {
	manager.RLock()
	defer manager.RUnlock()
	lsi, ok := manager.cache[nodeName]
	return ok && lsi.noHostSubnet
}

// Given a switch name, get all its host-subnets
func (manager *LogicalSwitchManager) GetSwitchSubnets(nodeName string) []*net.IPNet {
	manager.RLock()
	defer manager.RUnlock()
	lsi, ok := manager.cache[nodeName]
	// make a deep-copy of the underlying slice and return so that there is no
	// resource contention
	if ok && len(lsi.hostSubnets) > 0 {
		subnets := make([]*net.IPNet, len(lsi.hostSubnets))
		for i, hsn := range lsi.hostSubnets {
			subnet := *hsn
			subnets[i] = &subnet
		}
		return subnets
	}
	return nil
}

// AllocateUntilFull used for unit testing only, allocates the rest of the node subnet
func (manager *LogicalSwitchManager) AllocateUntilFull(nodeName string) error {
	manager.RLock()
	defer manager.RUnlock()
	lsi, ok := manager.cache[nodeName]
	if !ok {
		return fmt.Errorf("unable to allocate ips, node: %s does not exist in logical switch manager", nodeName)
	} else if len(lsi.ipams) == 0 {
		return fmt.Errorf("unable to allocate ips for node: %s. logical switch manager has no IPAM", nodeName)
	}
	var err error
	for err != ipam.ErrFull {
		for _, ipam := range lsi.ipams {
			_, err = ipam.AllocateNext()
		}
	}
	return nil
}

// AllocateIPs will block off IPs in the ipnets slice as already allocated
// for a given switch
func (manager *LogicalSwitchManager) AllocateIPs(nodeName string, ipnets []*net.IPNet) error {
	if len(ipnets) == 0 {
		return fmt.Errorf("unable to allocate empty IPs")
	}
	manager.RLock()
	defer manager.RUnlock()
	lsi, ok := manager.cache[nodeName]
	if !ok {
		return fmt.Errorf("unable to allocate ips: %v, node: %s does not exist in logical switch manager",
			ipnets, nodeName)
	} else if len(lsi.ipams) == 0 {
		return fmt.Errorf("unable to allocate ips %v for node: %s. logical switch manager has no IPAM",
			ipnets, nodeName)

	}

	var err error
	allocated := make(map[int]*net.IPNet)
	defer func() {
		if err != nil {
			// iterate over range of already allocated indices and release
			// ips allocated before the error occurred.
			for relIdx, relIPNet := range allocated {
				lsi.ipams[relIdx].Release(relIPNet.IP)
				if relIPNet.IP != nil {
					klog.Warningf("Reserved IP: %s was released", relIPNet.IP.String())
				}
			}
		}
	}()

	for _, ipnet := range ipnets {
		for idx, ipam := range lsi.ipams {
			cidr := ipam.CIDR()
			if cidr.Contains(ipnet.IP) {
				if _, ok = allocated[idx]; ok {
					err = fmt.Errorf("error attempting to reserve multiple IPs in the same IPAM instance")
					return err
				}
				if err = ipam.Allocate(ipnet.IP); err != nil {
					return err
				}
				allocated[idx] = ipnet
				break
			}
		}
	}
	return nil
}

// AllocateNextIPs allocates IP addresses from each of the host subnets
// for a given switch
func (manager *LogicalSwitchManager) AllocateNextIPs(nodeName string) ([]*net.IPNet, error) {
	manager.RLock()
	defer manager.RUnlock()
	var ipnets []*net.IPNet
	var ip net.IP
	var err error
	lsi, ok := manager.cache[nodeName]

	if !ok {
		return nil, fmt.Errorf("node %s not found in the logical switch manager cache", nodeName)
	}

	if len(lsi.ipams) == 0 {
		return nil, fmt.Errorf("failed to allocate IPs for node %s because there is no IPAM instance", nodeName)
	}

	if len(lsi.ipams) != len(lsi.hostSubnets) {
		return nil, fmt.Errorf("failed to allocate IPs for node %s because host subnet instances: %d"+
			" don't match ipam instances: %d", nodeName, len(lsi.hostSubnets), len(lsi.ipams))
	}

	defer func() {
		if err != nil {
			// iterate over range of already allocated indices and release
			// ips allocated before the error occurred.
			for relIdx, relIPNet := range ipnets {
				lsi.ipams[relIdx].Release(relIPNet.IP)
				if relIPNet.IP != nil {
					klog.Warningf("Reserved IP: %s was released", relIPNet.IP.String())
				}
			}
		}
	}()

	for idx, ipam := range lsi.ipams {
		ip, err = ipam.AllocateNext()
		if err != nil {
			return nil, err
		}
		ipnet := &net.IPNet{
			IP:   ip,
			Mask: lsi.hostSubnets[idx].Mask,
		}
		ipnets = append(ipnets, ipnet)
	}
	return ipnets, nil
}

// Mark the IPs in ipnets slice as available for allocation
// by releasing them from the IPAM pool of allocated IPs.
func (manager *LogicalSwitchManager) ReleaseIPs(nodeName string, ipnets []*net.IPNet) error {
	manager.RLock()
	defer manager.RUnlock()
	if ipnets == nil || nodeName == "" {
		klog.V(5).Infof("Node name is empty or ip slice to release is nil")
		return nil
	}
	lsi, ok := manager.cache[nodeName]
	if !ok {
		return fmt.Errorf("node %s not found in the logical switch manager cache",
			nodeName)
	}
	if len(lsi.ipams) == 0 {
		return fmt.Errorf("failed to release IPs for node %s because there is no IPAM instance", nodeName)
	}
	for _, ipnet := range ipnets {
		for _, ipam := range lsi.ipams {
			cidr := ipam.CIDR()
			if cidr.Contains(ipnet.IP) {
				ipam.Release(ipnet.IP)
				break
			}
		}
	}
	return nil
}

// ConditionalIPRelease determines if any IP is available to be released from an IPAM conditionally if func is true.
// It guarantees state of the allocator will not change while executing the predicate function
// TODO(trozet): add unit testing for this function
func (manager *LogicalSwitchManager) ConditionalIPRelease(nodeName string, ipnets []*net.IPNet, predicate func() (bool, error)) (bool, error) {
	manager.RLock()
	defer manager.RUnlock()
	if ipnets == nil || nodeName == "" {
		klog.V(5).Infof("Node name is empty or ip slice to release is nil")
		return false, nil
	}
	lsi, ok := manager.cache[nodeName]
	if !ok {
		return false, nil
	}
	if len(lsi.ipams) == 0 {
		return false, nil
	}

	// check if ipam has one of the ip addresses, and then execute the predicate function to determine
	// if this IP should be released or not
	for _, ipnet := range ipnets {
		for _, ipam := range lsi.ipams {
			cidr := ipam.CIDR()
			if cidr.Contains(ipnet.IP) {
				if ipam.Has(ipnet.IP) {
					return predicate()
				}
			}
		}
	}

	return false, nil
}

// IP allocator manager for join switch's IPv4 and IPv6 subnets.
type JoinSwitchIPManager struct {
	lsm            *LogicalSwitchManager
	nbClient       libovsdbclient.Client
	lrpIPCache     map[string][]*net.IPNet
	lrpIPCacheLock sync.Mutex
}

// NewJoinIPAMAllocator provides an ipam interface which can be used for join switch IPAM
// allocations for the specified cidr using a contiguous allocation strategy.
func NewJoinIPAMAllocator(cidr *net.IPNet) (ipam.Interface, error) {
	subnetRange, err := ipam.NewAllocatorCIDRRange(cidr, func(max int, rangeSpec string) (allocator.Interface, error) {
		return allocator.NewContiguousAllocationMap(max, rangeSpec), nil
	})
	if err != nil {
		return nil, err
	}
	return subnetRange, nil
}

// Initializes a new join switch logical switch manager.
// This IPmanager guaranteed to always have both IPv4 and IPv6 regardless of dual-stack
func NewJoinLogicalSwitchIPManager(nbClient libovsdbclient.Client, uuid string, existingNodeNames []string) (*JoinSwitchIPManager, error) {
	j := JoinSwitchIPManager{
		lsm: &LogicalSwitchManager{
			cache:    make(map[string]logicalSwitchInfo),
			ipamFunc: NewJoinIPAMAllocator,
		},
		nbClient:   nbClient,
		lrpIPCache: make(map[string][]*net.IPNet),
	}
	var joinSubnets []*net.IPNet
	joinSubnetsConfig := []string{}
	if config.IPv4Mode {
		joinSubnetsConfig = append(joinSubnetsConfig, config.Gateway.V4JoinSubnet)
	}
	if config.IPv6Mode {
		joinSubnetsConfig = append(joinSubnetsConfig, config.Gateway.V6JoinSubnet)
	}
	for _, joinSubnetString := range joinSubnetsConfig {
		_, joinSubnet, err := net.ParseCIDR(joinSubnetString)
		if err != nil {
			return nil, fmt.Errorf("error parsing join subnet string %s: %v", joinSubnetString, err)
		}
		joinSubnets = append(joinSubnets, joinSubnet)
	}
	err := j.lsm.AddNode(types.OVNJoinSwitch, uuid, joinSubnets)
	if err != nil {
		return nil, err
	}
	for _, nodeName := range existingNodeNames {
		gwLRPIPs := j.getJoinLRPAddresses(nodeName)
		if len(gwLRPIPs) > 0 {
			klog.Infof("Initializing and reserving the join switch IP for node: %s to: %v", nodeName, gwLRPIPs)
			if err := j.reserveJoinLRPIPs(nodeName, gwLRPIPs); err != nil {
				return nil, fmt.Errorf("error initiliazing and reserving the join switch IP for node: %s, err: %v", nodeName, err)
			}
		}
	}
	return &j, nil
}

func (jsIPManager *JoinSwitchIPManager) getJoinLRPCacheIPs(nodeName string) ([]*net.IPNet, bool) {
	gwLRPIPs, ok := jsIPManager.lrpIPCache[nodeName]
	return gwLRPIPs, ok
}

func sameIPs(a, b []*net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	for _, aip := range a {
		found := false
		for _, bip := range b {
			if aip.String() == bip.String() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (jsIPManager *JoinSwitchIPManager) setJoinLRPCacheIPs(nodeName string, gwLRPIPs []*net.IPNet) error {
	if oldIPs, ok := jsIPManager.lrpIPCache[nodeName]; ok && !sameIPs(oldIPs, gwLRPIPs) {
		return fmt.Errorf("join switch IPs %v already cached", oldIPs)
	}
	jsIPManager.lrpIPCache[nodeName] = gwLRPIPs
	return nil
}

func (jsIPManager *JoinSwitchIPManager) delJoinLRPCacheIPs(nodeName string) {
	delete(jsIPManager.lrpIPCache, nodeName)
}

// reserveJoinLRPIPs tries to add the LRP IPs to the joinSwitchIPManager, then they will be stored in the cache;
func (jsIPManager *JoinSwitchIPManager) reserveJoinLRPIPs(nodeName string, gwLRPIPs []*net.IPNet) error {
	// reserve the given IP in the allocator
	if err := jsIPManager.lsm.AllocateIPs(types.OVNJoinSwitch, gwLRPIPs); err != nil {
		return err
	}

	// store the allocated IPs in the cache if possible
	if err := jsIPManager.setJoinLRPCacheIPs(nodeName, gwLRPIPs); err != nil {
		// if storing the IPs to the cache fails, release the IPs again and return the error
		klog.Errorf("Failed to add node %s reserved IPs %v to the join switch IP cache: %s", nodeName, gwLRPIPs, err.Error())
		if relErr := jsIPManager.lsm.ReleaseIPs(types.OVNJoinSwitch, gwLRPIPs); relErr != nil {
			klog.Errorf("Failed to release logical router port IPs %v just reserved for node %s: %q",
				util.JoinIPNetIPs(gwLRPIPs, " "), nodeName, relErr)
		}
		return err
	}

	return nil
}

// ensureJoinLRPIPs tries to allocate the LRP IPs if it is not yet allocated, then they will be stored in the cache
func (jsIPManager *JoinSwitchIPManager) EnsureJoinLRPIPs(nodeName string) (gwLRPIPs []*net.IPNet, err error) {
	jsIPManager.lrpIPCacheLock.Lock()
	defer jsIPManager.lrpIPCacheLock.Unlock()
	// first check the IP cache, return if an entry already exists
	gwLRPIPs, ok := jsIPManager.getJoinLRPCacheIPs(nodeName)
	if ok {
		return gwLRPIPs, nil
	}
	// second check the running DB
	gwLRPIPs = jsIPManager.getJoinLRPAddresses(nodeName)
	if len(gwLRPIPs) > 0 {
		// Saving the hit in the cache
		err = jsIPManager.reserveJoinLRPIPs(nodeName, gwLRPIPs)
		if err != nil {
			klog.Errorf("Failed to add reserve IPs to the join switch IP cache: %s", err.Error())
			return nil, err
		}
		return gwLRPIPs, nil
	}
	gwLRPIPs, err = jsIPManager.lsm.AllocateNextIPs(types.OVNJoinSwitch)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			if relErr := jsIPManager.lsm.ReleaseIPs(types.OVNJoinSwitch, gwLRPIPs); relErr != nil {
				klog.Errorf("Failed to release logical router port IPs %v for node %s: %q",
					util.JoinIPNetIPs(gwLRPIPs, " "), nodeName, relErr)
			}
		}
	}()

	if err = jsIPManager.setJoinLRPCacheIPs(nodeName, gwLRPIPs); err != nil {
		klog.Errorf("Failed to add node %s reserved IPs %v to the join switch IP cache: %s", nodeName, gwLRPIPs, err.Error())
		return nil, err
	}

	return gwLRPIPs, nil
}

// getJoinLRPAddresses check if IPs of gateway logical router port are within the join switch IP range, and return them if true.
func (jsIPManager *JoinSwitchIPManager) getJoinLRPAddresses(nodeName string) []*net.IPNet {
	// try to get the IPs from the logical router port
	gwLRPIPs := []*net.IPNet{}
	gwLrpName := types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName
	joinSubnets := jsIPManager.lsm.GetSwitchSubnets(types.OVNJoinSwitch)
	ifAddrs, err := util.GetLRPAddrs(jsIPManager.nbClient, gwLrpName)
	if err == nil {
		for _, ifAddr := range ifAddrs {
			for _, subnet := range joinSubnets {
				if subnet.Contains(ifAddr.IP) {
					gwLRPIPs = append(gwLRPIPs, &net.IPNet{IP: ifAddr.IP, Mask: subnet.Mask})
					break
				}
			}
		}
	}

	if len(gwLRPIPs) != len(joinSubnets) {
		var errStr string
		if len(gwLRPIPs) == 0 {
			errStr = "Failed to get IPs"
		} else {
			errStr = fmt.Sprintf("Invalid IPs %s (possibly not in the range of subnet %s)",
				util.JoinIPNets(gwLRPIPs, " "), util.JoinIPNets(joinSubnets, " "))
		}
		klog.Warningf("%s for logical router port %s", errStr, gwLrpName)
		return []*net.IPNet{}
	}
	return gwLRPIPs
}

func (jsIPManager *JoinSwitchIPManager) ReleaseJoinLRPIPs(nodeName string) (err error) {
	jsIPManager.lrpIPCacheLock.Lock()
	defer jsIPManager.lrpIPCacheLock.Unlock()
	gwLRPIPs, ok := jsIPManager.getJoinLRPCacheIPs(nodeName)
	if ok {
		err = jsIPManager.lsm.ReleaseIPs(types.OVNJoinSwitch, gwLRPIPs)
		jsIPManager.delJoinLRPCacheIPs(nodeName)
	}
	return err
}
