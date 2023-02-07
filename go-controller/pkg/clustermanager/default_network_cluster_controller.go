package clustermanager

import (
	"fmt"
	"math/big"
	"net"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	cache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/clustermanager/subnetallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	bitmapallocator "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator/allocator"
	objretry "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	// Maximum node Ids that can be generated. Limited to maximum nodes supported by k8s.
	maxNodeIds = 5000
)

type networkClusterControllerBase struct {
	kube         kube.Interface
	watchFactory *factory.WatchFactory
	stopChan     chan struct{}
	wg           *sync.WaitGroup

	// node events factory handler
	nodeHandler *factory.Handler

	// retry framework for nodes
	retryNodes *objretry.RetryFramework
}

// defaultNetworkClusterController is the cluster controller for the default network
// for all the nodes. Listens to the node events and allocates subnet from the
// default cluster subnet pool.
type defaultNetworkClusterController struct {
	networkClusterControllerBase
	defaultNetworkController *NodeNetworkController

	hybridOverlaySubnetAllocator *subnetallocator.HostSubnetAllocator

	// Join switch subnet allocator for each zone.
	zoneJoinSubnetAllocator *subnetallocator.BaseSubnetAllocator
	zoneJoinSubnetCache     map[string]([]*net.IPNet)
	zoneJoinSubnetCacheLock sync.Mutex

	nodeIdBitmap    *bitmapallocator.AllocationBitmap
	nodeIdCache     map[string]int
	nodeIdCacheLock sync.Mutex

	transitSwitchv4Cidr   *net.IPNet
	transitSwitchBasev4Ip *big.Int

	transitSwitchv6Cidr   *net.IPNet
	transitSwitchBasev6Ip *big.Int
}

func newDefaultNetworkClusterController(ovnClient *util.OVNClusterManagerClientset, wf *factory.WatchFactory) *defaultNetworkClusterController {

	kube := &kube.Kube{
		KClient: ovnClient.KubeClient,
	}

	stopChan := make(chan struct{})
	wg := &sync.WaitGroup{}

	var hybridOverlaySubnetAllocator *subnetallocator.HostSubnetAllocator
	if config.HybridOverlay.Enabled {
		hybridOverlaySubnetAllocator = subnetallocator.NewHostSubnetAllocator()
	}

	nodeIdBitmap := bitmapallocator.NewContiguousAllocationMap(maxNodeIds, "nodeIds")
	_, _ = nodeIdBitmap.Allocate(0)

	var transitSwitchv4Cidr *net.IPNet
	var transitSwitchBasev4Ip *big.Int
	var transitSwitchv6Cidr *net.IPNet
	var transitSwitchBasev6Ip *big.Int

	if config.OVNKubernetesFeature.EnableInterconnect {
		_, transitSwitchv4Cidr, _ = net.ParseCIDR(config.ClusterManager.V4TransitSwitchSubnet)
		_, transitSwitchv6Cidr, _ = net.ParseCIDR(config.ClusterManager.V6TransitSwitchSubnet)

		transitSwitchBasev4Ip = utilnet.BigForIP(transitSwitchv4Cidr.IP)
		transitSwitchBasev6Ip = utilnet.BigForIP(transitSwitchv6Cidr.IP)
	}

	ncm := &defaultNetworkClusterController{
		networkClusterControllerBase: networkClusterControllerBase{
			kube:         kube,
			watchFactory: wf,
			stopChan:     stopChan,
			wg:           wg,
		},
		defaultNetworkController:     newNodeNetworkController(kube, wf, ovntypes.DefaultNetworkName),
		hybridOverlaySubnetAllocator: hybridOverlaySubnetAllocator,
		zoneJoinSubnetAllocator:      &subnetallocator.BaseSubnetAllocator{},
		nodeIdBitmap:                 nodeIdBitmap,
		nodeIdCache:                  make(map[string]int),
		zoneJoinSubnetCache:          make(map[string]([]*net.IPNet)),
		transitSwitchv4Cidr:          transitSwitchv4Cidr,
		transitSwitchBasev4Ip:        transitSwitchBasev4Ip,
		transitSwitchv6Cidr:          transitSwitchv6Cidr,
		transitSwitchBasev6Ip:        transitSwitchBasev6Ip,
	}

	ncm.initRetryFramework()
	return ncm
}

func (ncm *defaultNetworkClusterController) initRetryFramework() {
	ncm.retryNodes = ncm.newRetryFramework(factory.NodeType)
}

// Init initializes the default network subnet allocator ranges
// and hybrid network subnet allocator ranges if hybrid overlay is enabled.
func (ncm *defaultNetworkClusterController) Init() error {
	if err := ncm.defaultNetworkController.InitSubnetAllocatorRanges(config.Default.ClusterSubnets); err != nil {
		return fmt.Errorf("failed to initialize host subnet allocator ranges: %w", err)
	}

	if config.HybridOverlay.Enabled {
		if err := ncm.hybridOverlaySubnetAllocator.InitRanges(config.HybridOverlay.ClusterSubnets); err != nil {
			return fmt.Errorf("failed to initialize hybrid overlay subnet allocator ranges: %w", err)
		}
	}

	for _, entry := range config.ClusterManager.ZoneJoinSubnets {
		if err := ncm.zoneJoinSubnetAllocator.AddNetworkRange(entry.CIDR, entry.HostSubnetLength); err != nil {
			return err
		}
		klog.V(5).Infof("Added network range %s to zone subnet allocator", entry.CIDR)
	}

	return nil
}

func (ncm *defaultNetworkClusterController) Stop() {
	close(ncm.stopChan)
	ncm.wg.Wait()
}

// Run starts watching kubernetes nodes.
func (ncm *defaultNetworkClusterController) Run() error {
	return ncm.watchNodes()
}

// WatchNodes starts the watching of node resource and calls
// back the appropriate handler logic
func (ncm *defaultNetworkClusterController) watchNodes() error {
	if ncm.nodeHandler != nil {
		return nil
	}

	handler, err := ncm.retryNodes.WatchResource()
	if err != nil {
		return err
	}

	ncm.nodeHandler = handler
	return nil
}

// defaultNetworkClusterControllerEventHandler object handles the events
// from retry framework.
type defaultNetworkClusterControllerEventHandler struct {
	objretry.EventHandler

	objType  reflect.Type
	ncm      *defaultNetworkClusterController
	syncFunc func([]interface{}) error
}

func (ncm *defaultNetworkClusterController) newRetryFramework(objectType reflect.Type) *objretry.RetryFramework {
	resourceHandler := &objretry.ResourceHandler{
		HasUpdateFunc:          hasResourceAnUpdateFunc(objectType),
		NeedsUpdateDuringRetry: false,
		ObjType:                objectType,
		EventHandler: &defaultNetworkClusterControllerEventHandler{
			objType:  objectType,
			ncm:      ncm,
			syncFunc: nil,
		},
	}
	return objretry.NewRetryFramework(ncm.stopChan, ncm.wg, ncm.watchFactory, resourceHandler)
}

// hybridOverlayNodeEnsureSubnet allocates a subnet and sets the
// hybrid overlay subnet annotation. It returns any newly allocated subnet
// or an error. If an error occurs, the newly allocated subnet will be released.
func (ncm *defaultNetworkClusterController) hybridOverlayNodeEnsureSubnet(node *corev1.Node, annotator kube.Annotator) (*net.IPNet, error) {
	var existingSubnets []*net.IPNet
	// Do not allocate a subnet if the node already has one
	subnet, err := houtil.ParseHybridOverlayHostSubnet(node)
	if err != nil {
		// Log the error and try to allocate new subnets
		klog.Infof("Failed to get node %s hybrid overlay subnet annotation: %v", node.Name, err)
	} else if subnet != nil {
		existingSubnets = []*net.IPNet{subnet}
	}

	// Allocate a new host subnet for this node
	// FIXME: hybrid overlay is only IPv4 for now due to limitations on the Windows side
	hostSubnets, allocatedSubnets, err := ncm.hybridOverlaySubnetAllocator.AllocateNodeSubnets(node.Name, existingSubnets, true, false)
	if err != nil {
		return nil, fmt.Errorf("error allocating hybrid overlay HostSubnet for node %s: %v", node.Name, err)
	}

	if err := annotator.Set(hotypes.HybridOverlayNodeSubnet, hostSubnets[0].String()); err != nil {
		if e := ncm.hybridOverlaySubnetAllocator.ReleaseNodeSubnets(node.Name, allocatedSubnets...); e != nil {
			klog.Errorf("Failed to release hybrid over subnet for the node %s from the allocator : %w", node.Name, e)
		}
		return nil, fmt.Errorf("error setting hybrid overlay host subnet: %w", err)
	}

	return hostSubnets[0], nil
}

func (ncm *defaultNetworkClusterController) releaseHybridOverlayNodeSubnet(nodeName string) {
	ncm.hybridOverlaySubnetAllocator.ReleaseAllNodeSubnets(nodeName)
	klog.Infof("Deleted hybrid overlay HostSubnets for node %s", nodeName)
}

func (ncm *defaultNetworkClusterController) updateNodeAnnotationWithRetry(nodeName string, nodeId int,
	zoneJoinSubnets []*net.IPNet, nodeTransitSwitchPortIps []*net.IPNet) error {
	// Retry if it fails because of potential conflict which is transient. Return error in the
	// case of other errors (say temporary API server down), and it will be taken care of by the
	// retry mechanism.
	resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		node, err := ncm.watchFactory.GetNode(nodeName)
		if err != nil {
			return err
		}

		cnode := node.DeepCopy()
		if nodeId != -1 {
			cnode.Annotations = util.UpdateNodeIdAnnotation(cnode.Annotations, nodeId)
		}

		if zoneJoinSubnets != nil {
			cnode.Annotations, err = util.UpdateZoneJoinSubnetsAnnotation(cnode.Annotations, zoneJoinSubnets, ovntypes.DefaultNetworkName)
			if err != nil {
				return fmt.Errorf("failed to update node %q annotation subnet %s",
					node.Name, util.JoinIPNets(zoneJoinSubnets, ","))
			}
		}

		if nodeTransitSwitchPortIps != nil {
			cnode.Annotations, err = util.UpdateNodeTransitSwitchPortAddressesAnnotation(cnode.Annotations, nodeTransitSwitchPortIps)
			if err != nil {
				return fmt.Errorf("failed to update node %q annotation transit port ips %s",
					node.Name, util.JoinIPNets(nodeTransitSwitchPortIps, ","))
			}
		}
		return ncm.kube.UpdateNode(cnode)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update node %s annotation", nodeName)
	}

	return nil
}

func (ncm *defaultNetworkClusterController) addUpdateNodeEvent(node *corev1.Node) error {
	if util.NoHostSubnet(node) {
		if config.HybridOverlay.Enabled && houtil.IsHybridOverlayNode(node) {
			annotator := kube.NewNodeAnnotator(ncm.kube, node.Name)
			allocatedSubnet, err := ncm.hybridOverlayNodeEnsureSubnet(node, annotator)
			if err != nil {
				return fmt.Errorf("failed to update node %s hybrid overlay subnet annotation: %v", node.Name, err)
			}
			if err := annotator.Run(); err != nil {
				// Release allocated subnet if any errors occurred
				if allocatedSubnet != nil {
					ncm.releaseHybridOverlayNodeSubnet(node.Name)
				}
				return fmt.Errorf("failed to set hybrid overlay annotations for node %s: %v", node.Name, err)
			}
		}
		return nil
	}

	return ncm.addNode(node)
}

func (ncm *defaultNetworkClusterController) addNode(node *corev1.Node) error {
	var err error
	if err = ncm.defaultNetworkController.addUpdateNode(node); err != nil {
		return err
	}

	var allocatedNodeId int = -1
	// Release the allocation on error
	defer func() {
		if err != nil {
			ncm.removeNodeId(node.Name, allocatedNodeId)
		}
	}()

	allocatedNodeId, err = ncm.allocateNodeId(node)
	if err != nil {
		return err
	}

	updateNodeAnnotations := false
	zoneJoinSubnets, err := ncm.allocateZoneJoinSubnets(node)
	if err != nil {
		return err
	}

	if !ncm.isNodeJoinSubnetAnnotationOutOfSync(node, zoneJoinSubnets) {
		zoneJoinSubnets = nil
	} else {
		updateNodeAnnotations = true
	}

	var nodeTransitSwitchPortIps []*net.IPNet
	if config.OVNKubernetesFeature.EnableInterconnect {
		// Generate v4 and v6 transit switch port IPs for the node.
		nodeTransitSwitchPortIps = ncm.syncNodeTransitSwitchPortIps(node, allocatedNodeId)
		if nodeTransitSwitchPortIps != nil {
			updateNodeAnnotations = true
		}
	}

	if allocatedNodeId == util.GetNodeId(node) {
		// Set allocatedNodeId to -1, so that updateNodeAnnotationWithRetry() doesn't
		// update the node id annotation.
		allocatedNodeId = -1
	} else {
		updateNodeAnnotations = true
	}

	if updateNodeAnnotations {
		return ncm.updateNodeAnnotationWithRetry(node.Name, allocatedNodeId, zoneJoinSubnets, nodeTransitSwitchPortIps)
	}

	return nil
}

func (ncm *defaultNetworkClusterController) deleteNode(node *corev1.Node) error {
	if config.HybridOverlay.Enabled {
		ncm.releaseHybridOverlayNodeSubnet(node.Name)
	}

	nodeId := util.GetNodeId(node)
	ncm.removeNodeId(node.Name, nodeId)

	return ncm.defaultNetworkController.deleteNode(node)
}

func (ncm *defaultNetworkClusterController) syncNodes(nodes []interface{}) error {
	for _, tmp := range nodes {
		node, ok := tmp.(*corev1.Node)
		if !ok {
			return fmt.Errorf("spurious object in syncNodes: %v", tmp)
		}

		hostSubnets, _ := util.ParseNodeHostSubnetAnnotation(node, ovntypes.DefaultNetworkName)
		if config.HybridOverlay.Enabled && len(hostSubnets) == 0 && houtil.IsHybridOverlayNode(node) {
			// this is a hybrid overlay node so mark as allocated from the hybrid overlay subnet allocator
			hostSubnet, err := houtil.ParseHybridOverlayHostSubnet(node)
			if err != nil {
				klog.Errorf("Failed to parse hybrid overlay for node %s: %w", node.Name, err)
			} else if hostSubnet != nil {
				klog.V(5).Infof("Node %s contains subnets: %v", node.Name, hostSubnet)
				if err := ncm.hybridOverlaySubnetAllocator.MarkSubnetsAllocated(node.Name, hostSubnet); err != nil {
					klog.Errorf("Failed to mark the subnet %v as allocated in the hybrid subnet allocator for node %s: %w", hostSubnet, node.Name, err)
				}
			}
		}

		nodeZone := util.GetNodeZone(node)
		zoneSubnets, err := util.ParseZoneJoinSubnetsAnnotation(node, ovntypes.DefaultNetworkName)
		if err != nil {
			klog.Warning(err.Error())
		} else if zoneSubnets != nil {
			_, found := ncm.zoneJoinSubnetCache[nodeZone]
			if !found {
				ncm.zoneJoinSubnetCache[nodeZone] = zoneSubnets
				_ = ncm.zoneJoinSubnetAllocator.MarkAllocatedNetworks(ovntypes.DefaultNetworkName, zoneSubnets...)
			}
		}
	}

	err := ncm.syncNodeIds(nodes)
	if err != nil {
		return err
	}

	return ncm.defaultNetworkController.syncNodes(nodes)
}

func (ncm *defaultNetworkClusterController) syncNodeIds(nodes []interface{}) error {
	ncm.nodeIdCacheLock.Lock()
	defer ncm.nodeIdCacheLock.Unlock()

	duplicateIdNodes := []string{}

	for _, tmp := range nodes {
		node, ok := tmp.(*corev1.Node)
		if !ok {
			return fmt.Errorf("spurious object in syncNodes: %v", tmp)
		}

		nodeId := util.GetNodeId(node)
		if nodeId != -1 {
			klog.V(5).Infof("Node %s has the node id %d set", node.Name, nodeId)
			reserved, _ := ncm.nodeIdBitmap.Allocate(nodeId)
			if reserved {
				ncm.nodeIdCache[node.Name] = nodeId
			} else {
				// The id set on this node is duplicate.
				klog.V(5).Infof("Node %s has a duplicate node id %d set", node.Name, nodeId)
				duplicateIdNodes = append(duplicateIdNodes, node.Name)
			}
		}
	}

	for i := range duplicateIdNodes {
		newNodeId, allocated, _ := ncm.nodeIdBitmap.AllocateNext()
		klog.V(5).Infof("Allocated new node id  %d for node %q", newNodeId, duplicateIdNodes[i])
		if allocated {
			// Store the allocated new id in the cache.  addNode() will update the node annotation
			// with the new allocated id.
			ncm.nodeIdCache[duplicateIdNodes[i]] = newNodeId
		}
	}

	return nil
}

func (ncm *defaultNetworkClusterController) allocateNodeId(node *corev1.Node) (int, error) {
	ncm.nodeIdCacheLock.Lock()
	defer ncm.nodeIdCacheLock.Unlock()

	nodeId := util.GetNodeId(node)

	nodeIdInCache, ok := ncm.nodeIdCache[node.Name]
	if ok {
		klog.Infof("Allocate node id : found node id %d for node %q in the cache", nodeIdInCache, node.Name)
	} else {
		nodeIdInCache = -1
	}

	if nodeIdInCache != -1 && nodeId != nodeIdInCache {
		//  Use the cached node id.
		ncm.nodeIdCache[node.Name] = nodeIdInCache
		return nodeIdInCache, nil
	}

	if nodeIdInCache == -1 && nodeId != -1 {
		// Cache for this node is not set yet.  Cache the node id.
		ncm.nodeIdCache[node.Name] = nodeId
		return nodeId, nil
	}

	// We need to allocate the node id.
	if nodeIdInCache == -1 && nodeId == -1 {
		var allocated bool
		nodeId, allocated, _ = ncm.nodeIdBitmap.AllocateNext()
		klog.Infof("Allocate node id : Id allocated for node %q is %d", node.Name, nodeId)
		if allocated {
			ncm.nodeIdCache[node.Name] = nodeId
		} else {
			return -1, fmt.Errorf("failed to allocate id for the node %q", node.Name)
		}
	}

	return nodeId, nil
}

func (ncm *defaultNetworkClusterController) removeNodeId(nodeName string, nodeId int) {
	if nodeId != -1 {
		ncm.nodeIdBitmap.Release(nodeId)
	}
	delete(ncm.nodeIdCache, nodeName)
}

func (ncm *defaultNetworkClusterController) allocateZoneJoinSubnets(node *corev1.Node) ([]*net.IPNet, error) {
	ncm.zoneJoinSubnetCacheLock.Lock()
	defer ncm.zoneJoinSubnetCacheLock.Unlock()

	nodeZone := util.GetNodeZone(node)
	allocatedZoneSubnets, found := ncm.zoneJoinSubnetCache[nodeZone]
	if found {
		return allocatedZoneSubnets, nil
	}

	allocatedSubnets := []*net.IPNet{}
	if config.IPv4Mode {
		allocatedSubnet, err := ncm.zoneJoinSubnetAllocator.AllocateIPv4Network(ovntypes.DefaultNetworkName)
		if err != nil {
			return nil, fmt.Errorf("error allocating join IPv4 network for zone %s: %v", nodeZone, err)
		}

		allocatedSubnets = append(allocatedSubnets, allocatedSubnet)
	}

	if config.IPv6Mode {
		allocatedSubnet, err := ncm.zoneJoinSubnetAllocator.AllocateIPv6Network(ovntypes.DefaultNetworkName)
		if err != nil {
			return nil, fmt.Errorf("error allocating join IPv6 network for zone %s: %v", nodeZone, err)
		}

		allocatedSubnets = append(allocatedSubnets, allocatedSubnet)
	}

	ncm.zoneJoinSubnetCache[nodeZone] = allocatedSubnets
	return allocatedSubnets, nil
}

func (ncm *defaultNetworkClusterController) isNodeJoinSubnetAnnotationOutOfSync(node *corev1.Node,
	zoneJoinSubnets []*net.IPNet) bool {

	nodeZoneJoinSubnets, err := util.ParseZoneJoinSubnetsAnnotation(node, ovntypes.DefaultNetworkName)
	if err != nil {
		// Out of sync - Zone join subnet annotations not set for the node.
		return true
	}

	return !ncm.areIPNetsEqual(zoneJoinSubnets, nodeZoneJoinSubnets)
}

func (ncm *defaultNetworkClusterController) areIPNetsEqual(ipNet1 []*net.IPNet, ipNet2 []*net.IPNet) bool {
	if ipNet1 == nil || ipNet2 == nil {
		return false
	}

	if len(ipNet1) != len(ipNet2) {
		return false
	}

	ipNet1v4Ips := 0
	ipNet1v6Ips := 0
	ipNet2v4Ips := 0
	ipNet2v6Ips := 0

	for _, ip := range ipNet1 {
		if utilnet.IsIPv4(ip.IP) {
			ipNet1v4Ips++
		} else {
			ipNet1v6Ips++
		}
	}

	for _, ip := range ipNet2 {
		if utilnet.IsIPv4(ip.IP) {
			ipNet2v4Ips++
		} else {
			ipNet2v6Ips++
		}
	}

	if ipNet1v4Ips != ipNet2v4Ips || ipNet1v6Ips != ipNet2v6Ips {
		return false
	}

	for _, ip1 := range ipNet1 {
		found := false
		for _, ip2 := range ipNet2 {
			if ip1.String() == ip2.String() {
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

func (ncm *defaultNetworkClusterController) syncNodeTransitSwitchPortIps(node *corev1.Node, nodeId int) []*net.IPNet {
	var transitSwitchPortIps []*net.IPNet

	parsedTransitSwitchPortIps, _ := util.ParseNodeTransitSwitchPortAddresses(node)
	if config.IPv4Mode {
		nodeTransitSwitchPortv4Ip := utilnet.AddIPOffset(ncm.transitSwitchBasev4Ip, nodeId)
		transitSwitchPortIps = append(transitSwitchPortIps, &net.IPNet{IP: nodeTransitSwitchPortv4Ip, Mask: ncm.transitSwitchv4Cidr.Mask})
	}

	if config.IPv6Mode {
		nodeTransitSwitchPortv6Ip := utilnet.AddIPOffset(ncm.transitSwitchBasev6Ip, nodeId)
		transitSwitchPortIps = append(transitSwitchPortIps, &net.IPNet{IP: nodeTransitSwitchPortv6Ip, Mask: ncm.transitSwitchv6Cidr.Mask})
	}

	if !ncm.areIPNetsEqual(parsedTransitSwitchPortIps, transitSwitchPortIps) {
		return transitSwitchPortIps
	} else {
		// return nil if the parsed transit switch port ips from the node annotations
		// and the generated transit switch port ips are the same.
		return nil
	}
}

func (h *defaultNetworkClusterControllerEventHandler) AreResourcesEqual(obj1, obj2 interface{}) (bool, error) {
	// switch based on type
	switch h.objType {
	case factory.NodeType:
		node1, ok := obj1.(*corev1.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj1 of type %T to *corev1.Node", obj1)
		}
		node2, ok := obj2.(*corev1.Node)
		if !ok {
			return false, fmt.Errorf("could not cast obj2 of type %T to *corev1.Node", obj2)
		}

		// when shouldUpdateNode is false, the hostsubnet is not assigned by ovn-kubernetes
		shouldUpdate, err := util.ShouldUpdateNode(node2, node1)
		if err != nil {
			klog.Errorf(err.Error())
		}
		return !shouldUpdate, nil
	}

	return false, nil
}

// GetInternalCacheEntry returns the internal cache entry for this object
func (h *defaultNetworkClusterControllerEventHandler) GetInternalCacheEntry(obj interface{}) interface{} {
	return nil
}

// getResourceFromInformerCache returns the latest state of the object from the informers cache
// given an object key and its type,
func (h *defaultNetworkClusterControllerEventHandler) GetResourceFromInformerCache(key string) (interface{}, error) {
	var obj interface{}
	var name string
	var err error

	_, name, err = cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to split key %s: %v", key, err)
	}

	switch h.objType {
	case factory.NodeType,
		factory.EgressNodeType:
		obj, err = h.ncm.watchFactory.GetNode(name)

	default:
		err = fmt.Errorf("object type %s not supported, cannot retrieve it from informers cache",
			h.objType)
	}
	return obj, err
}

// RecordAddEvent records the add event on this object. Not used here.
func (h *defaultNetworkClusterControllerEventHandler) RecordAddEvent(obj interface{}) {
}

// RecordUpdateEvent records the update event on this object. Not used here.
func (h *defaultNetworkClusterControllerEventHandler) RecordUpdateEvent(obj interface{}) {
}

// RecordDeleteEvent records the delete event on this object. Not used here.
func (h *defaultNetworkClusterControllerEventHandler) RecordDeleteEvent(obj interface{}) {
}

func (h *defaultNetworkClusterControllerEventHandler) RecordSuccessEvent(obj interface{}) {
}

// RecordErrorEvent records an error event on this object. Not used here.
func (h *defaultNetworkClusterControllerEventHandler) RecordErrorEvent(obj interface{}, reason string, err error) {
}

// isResourceScheduled returns true if the object has been scheduled.  Always returns true.
func (h *defaultNetworkClusterControllerEventHandler) IsResourceScheduled(obj interface{}) bool {
	return true
}

// IsObjectInTerminalState returns true if the object is a in terminal state.  Always returns true.
func (h *defaultNetworkClusterControllerEventHandler) IsObjectInTerminalState(obj interface{}) bool {
	return false
}

// AddResource adds the specified object to the cluster according to its type and
// returns the error, if any, yielded during object creation.
func (h *defaultNetworkClusterControllerEventHandler) AddResource(obj interface{}, fromRetryLoop bool) error {
	var err error

	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Node", obj)
		}
		if err = h.ncm.addUpdateNodeEvent(node); err != nil {
			klog.Infof("Node add failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	default:
		return fmt.Errorf("no add function for object type %s", h.objType)
	}
	return nil
}

// UpdateResource updates the specified object in the cluster to its version in newObj according
// to its type and returns the error, if any, yielded during the object update.
// The inRetryCache boolean argument is to indicate if the given resource is in the retryCache or not.
func (h *defaultNetworkClusterControllerEventHandler) UpdateResource(oldObj, newObj interface{}, inRetryCache bool) error {
	var err error

	switch h.objType {
	case factory.NodeType:
		node, ok := newObj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *corev1.Node", newObj)
		}
		if err = h.ncm.addUpdateNodeEvent(node); err != nil {
			klog.Infof("Node update failed for %s, will try again later: %v",
				node.Name, err)
			return err
		}
	default:
		return fmt.Errorf("no update function for object type %s", h.objType)
	}
	return nil
}

// DeleteResource deletes the object from the cluster according to the delete logic of its resource type.
// cachedObj is the internal cache entry for this object, used for now for pods and network policies.
func (h *defaultNetworkClusterControllerEventHandler) DeleteResource(obj, cachedObj interface{}) error {
	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not cast obj of type %T to *knet.Node", obj)
		}
		return h.ncm.deleteNode(node)
	}
	return nil
}

func (h *defaultNetworkClusterControllerEventHandler) SyncFunc(objs []interface{}) error {
	var syncFunc func([]interface{}) error

	if h.syncFunc != nil {
		// syncFunc was provided explicitly
		syncFunc = h.syncFunc
	} else {
		switch h.objType {
		case factory.NodeType:
			syncFunc = h.ncm.syncNodes

		default:
			return fmt.Errorf("no sync function for object type %s", h.objType)
		}
	}
	if syncFunc == nil {
		return nil
	}
	return syncFunc(objs)
}
