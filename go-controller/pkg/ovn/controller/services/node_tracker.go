package services

import (
	"net"
	"reflect"
	"sort"
	"sync"

	globalconfig "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// nodeTracker watches all Node objects and maintains a cache of information relevant
// to service creation. If a new node is created, it requests a resync of all services,
// since need to apply those service's load balancers to the new node as well.
type nodeTracker struct {
	sync.Mutex

	// nodes is the list of nodes we know about
	// map of name -> info
	nodes map[string]nodeInfo

	// resyncFn is the function to call so that all service are resynced
	resyncFn func(nodes []nodeInfo)

	// zone in which this nodeTracker is tracking
	zone string
}

type nodeInfo struct {
	// the node's Name
	name string
	// The list of physical IPs reported by the gatewayconf annotation
	l3gatewayAddresses []net.IP
	// The list of physical IPs the node has, as reported by the host-address annotation
	hostAddresses []net.IP
	// The pod network subnet(s)
	podSubnets []net.IPNet
	// the name of the node's GatewayRouter, or "" of non-existent
	gatewayRouterName string
	// The name of the node's switch - never empty
	switchName string
	// The chassisID of the node (ovs.external-ids:system-id)
	chassisID string

	// The node's zone
	zone string
	/** HACK BEGIN **/
	// has the node migrated to remote?
	migrated bool
	/** HACK END **/
}

func (ni *nodeInfo) hostAddressesStr() []string {
	out := make([]string, 0, len(ni.hostAddresses))
	for _, ip := range ni.hostAddresses {
		out = append(out, ip.String())
	}
	return out
}

func (ni *nodeInfo) l3gatewayAddressesStr() []string {
	out := make([]string, 0, len(ni.l3gatewayAddresses))
	for _, ip := range ni.l3gatewayAddresses {
		out = append(out, ip.String())
	}
	return out
}

// returns a list of all ip blocks "assigned" to this node
// includes node IPs, still as a mask-1 net
func (ni *nodeInfo) nodeSubnets() []net.IPNet {
	out := append([]net.IPNet{}, ni.podSubnets...)
	for _, ip := range ni.hostAddresses {
		if ipv4 := ip.To4(); ipv4 != nil {
			out = append(out, net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(32, 32),
			})
		} else {
			out = append(out, net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(128, 128),
			})
		}
	}

	return out
}

func newNodeTracker(zone string, resyncFn func(nodes []nodeInfo)) *nodeTracker {
	return &nodeTracker{
		nodes:    map[string]nodeInfo{},
		zone:     zone,
		resyncFn: resyncFn,
	}
}

func (nt *nodeTracker) Start(nodeInformer coreinformers.NodeInformer) (cache.ResourceEventHandlerRegistration, error) {
	return nodeInformer.Informer().AddEventHandler(factory.WithUpdateHandlingForObjReplace(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node, ok := obj.(*v1.Node)
			if !ok {
				return
			}
			nt.updateNode(node)
		},
		UpdateFunc: func(old, new interface{}) {
			oldObj, ok := old.(*v1.Node)
			if !ok {
				return
			}
			newObj, ok := new.(*v1.Node)
			if !ok {
				return
			}
			// Make sure object was actually changed and not pending deletion
			if oldObj.GetResourceVersion() == newObj.GetResourceVersion() || !newObj.GetDeletionTimestamp().IsZero() {
				return
			}

			// updateNode needs to be called in the following cases:
			// - hostSubnet annotation has changed
			// - L3Gateway annotation's ip addresses have changed
			// - the name of the node (very rare) has changed
			// - the `host-addresses` annotation changed
			// - node changes its zone
			// . No need to trigger update for any other field change.
			if util.NodeSubnetAnnotationChanged(oldObj, newObj) ||
				util.NodeL3GatewayAnnotationChanged(oldObj, newObj) ||
				oldObj.Name != newObj.Name ||
				util.NodeHostAddressesAnnotationChanged(oldObj, newObj) ||
				util.NodeZoneAnnotationChanged(oldObj, newObj) ||
				util.NodeMigratedZoneAnnotationChanged(oldObj, newObj) {
				nt.updateNode(newObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*v1.Node)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.Errorf("Couldn't understand non-tombstone object")
					return
				}
				node, ok = tombstone.Obj.(*v1.Node)
				if !ok {
					klog.Errorf("Couldn't understand tombstone object")
					return
				}
			}
			nt.removeNodeWithServiceReSync(node.Name)
		},
	}))

}

// updateNodeInfo updates the node info cache, and syncs all services
// if it changed.
func (nt *nodeTracker) updateNodeInfo(nodeName, switchName, routerName, chassisID string, l3gatewayAddresses,
	hostAddresses []net.IP, podSubnets []*net.IPNet, zone string, migrated bool) {
	ni := nodeInfo{
		name:               nodeName,
		l3gatewayAddresses: l3gatewayAddresses,
		hostAddresses:      hostAddresses,
		podSubnets:         make([]net.IPNet, 0, len(podSubnets)),
		gatewayRouterName:  routerName,
		switchName:         switchName,
		chassisID:          chassisID,
		zone:               zone,
		migrated:           migrated,
	}
	for i := range podSubnets {
		ni.podSubnets = append(ni.podSubnets, *podSubnets[i]) // de-pointer
	}

	klog.Infof("Node %s switch + router changed, syncing services", nodeName)

	nt.Lock()
	defer nt.Unlock()
	if existing, ok := nt.nodes[nodeName]; ok {
		if reflect.DeepEqual(existing, ni) {
			return
		}
	}

	nt.nodes[nodeName] = ni

	// Resync all services
	nt.resyncFn(nt.getZoneNodes())
}

// removeNodeWithServiceReSync removes a node from the LB -> node mapper
// *and* forces full reconciliation of services.
func (nt *nodeTracker) removeNodeWithServiceReSync(nodeName string) {
	nt.removeNode(nodeName)
	nt.Lock()
	nt.resyncFn(nt.getZoneNodes())
	nt.Unlock()
}

// RemoveNode removes a node from the LB -> node mapper
// We don't need to re-sync here, because any stale LBs
// will eventually be cleaned up, and they don't have any cost.
func (nt *nodeTracker) removeNode(nodeName string) {
	nt.Lock()
	defer nt.Unlock()

	delete(nt.nodes, nodeName)
}

// UpdateNode is called when a node's gateway router / switch / IPs have changed
// The switch exists when the HostSubnet annotation is set.
// The gateway router will exist sometime after the L3Gateway annotation is set.
func (nt *nodeTracker) updateNode(node *v1.Node) {
	klog.V(2).Infof("Processing possible switch / router updates for node %s", node.Name)
	hsn, err := util.ParseNodeHostSubnetAnnotation(node, types.DefaultNetworkName)
	if err != nil || hsn == nil {
		// usually normal; means the node's gateway hasn't been initialized yet
		klog.Infof("Node %s has invalid / no HostSubnet annotations (probably waiting on initialization): %v", node.Name, err)
		nt.removeNode(node.Name)
		return
	}

	switchName := node.Name
	grName := ""
	l3gatewayAddresses := []net.IP{}
	chassisID := ""

	// if the node has a gateway config, it will soon have a gateway router
	// so, set the router name
	gwConf, err := util.ParseNodeL3GatewayAnnotation(node)
	if err != nil || gwConf == nil {
		klog.Infof("Node %s has invalid / no gateway config: %v", node.Name, err)
	} else if gwConf.Mode != globalconfig.GatewayModeDisabled {
		grName = util.GetGatewayRouterFromNode(node.Name)
		if gwConf.NodePortEnable {
			for _, ip := range gwConf.IPAddresses {
				l3gatewayAddresses = append(l3gatewayAddresses, ip.IP)
			}
		}
		chassisID = gwConf.ChassisID
	}

	hostAddresses, err := util.ParseNodeHostAddresses(node)
	if err != nil {
		klog.Warningf("Failed to get node host addresses for [%s]: %s", node.Name, err.Error())
		hostAddresses = sets.New[string]()
	}

	hostAddressesIPs := make([]net.IP, 0, len(hostAddresses))
	for _, ipStr := range hostAddresses.UnsortedList() {
		ip := net.ParseIP(ipStr)
		hostAddressesIPs = append(hostAddressesIPs, ip)
	}

	nt.updateNodeInfo(
		node.Name,
		switchName,
		grName,
		chassisID,
		l3gatewayAddresses,
		hostAddressesIPs,
		hsn,
		util.GetNodeZone(node),
		util.HasNodeMigratedZone(node),
	)
}

// getZoneNodes returns a list of all nodes (and their relevant information)
// which belong to the nodeTracker 'zone'
// MUST be called with nt locked
func (nt *nodeTracker) getZoneNodes() []nodeInfo {
	out := make([]nodeInfo, 0, len(nt.nodes))
	for _, node := range nt.nodes {
		/** HACK BEGIN **/
		// TODO(tssurya): Remove this HACK a few months from now. This has been added only to
		// minimize disruption for upgrades when moving to interconnect=true.
		// We want the legacy ovnkube-master to wait for remote ovnkube-node to
		// signal it using "k8s.ovn.org/remote-zone-migrated" annotation before
		// considering a node as remote when we upgrade from "global" (1 zone IC)
		// zone to multi-zone. This is so that network disruption for the existing workloads
		// is negligible and until the point where ovnkube-node flips the switch to connect
		// to the new SBDB, it would continue talking to the legacy RAFT ovnkube-sbdb to ensure
		// OVN/OVS flows are intact. Legacy ovnkube-master must not delete the service load
		// balancers for this node till it has finished migration
		if nt.zone == types.OvnDefaultZone {
			if !node.migrated {
				out = append(out, node)
			}
			continue
		}
		/** HACK END **/
		if node.zone == nt.zone {
			out = append(out, node)
		}
	}

	// Sort the returned list of nodes
	// so that other operations that consume this data can just do a DeepEquals of things
	// (e.g. LB routers + switches) without having to do set arithmetic
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}
