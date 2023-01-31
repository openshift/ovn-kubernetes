package clustermanager

import (
	"fmt"
	"net"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/clustermanager/subnetallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

// NodeNetworkController structure manages the network allocations for a 'network'
// for each node. Presently it only manages the subnet allocation.
type NodeNetworkController struct {
	kube         kube.Interface
	watchFactory *factory.WatchFactory

	networkName            string
	clusterSubnetAllocator *subnetallocator.HostSubnetAllocator

	subnetAllocatorLock sync.Mutex
}

func newNodeNetworkController(kube kube.Interface, wf *factory.WatchFactory,
	networkName string) *NodeNetworkController {
	return &NodeNetworkController{
		kube:                   kube,
		watchFactory:           wf,
		networkName:            networkName,
		clusterSubnetAllocator: subnetallocator.NewHostSubnetAllocator(),
	}
}

func (nnc *NodeNetworkController) InitSubnetAllocatorRanges(subnets []config.CIDRNetworkEntry) error {
	return nnc.clusterSubnetAllocator.InitRanges(subnets)
}

func (nnc *NodeNetworkController) syncNodes(nodes []interface{}) error {
	nnc.subnetAllocatorLock.Lock()
	defer func() {
		nnc.subnetAllocatorLock.Unlock()
	}()

	for _, tmp := range nodes {
		node, ok := tmp.(*kapi.Node)
		if !ok {
			return fmt.Errorf("spurious object in syncNodes: %v", tmp)
		}

		if util.NoHostSubnet(node) {
			continue
		}

		hostSubnets, _ := util.ParseNodeHostSubnetAnnotation(node, nnc.networkName)
		klog.V(5).Infof("Node %s contains subnets: %v for network : %s", node.Name, hostSubnets, nnc.networkName)
		if err := nnc.clusterSubnetAllocator.MarkSubnetsAllocated(node.Name, hostSubnets...); err != nil {
			utilruntime.HandleError(err)
		}
	}

	return nil
}

func (nnc *NodeNetworkController) addUpdateNode(node *kapi.Node) error {
	nnc.subnetAllocatorLock.Lock()
	defer func() {
		nnc.subnetAllocatorLock.Unlock()
	}()

	existingSubnets, err := util.ParseNodeHostSubnetAnnotation(node, nnc.networkName)
	if err != nil && !util.IsAnnotationNotSetError(err) {
		// Log the error and try to allocate new subnets
		klog.Infof("Failed to get node %s host subnets annotations for network %s : %v", node.Name, nnc.networkName, err)

	}

	hostSubnets, allocatedSubnets, err := nnc.clusterSubnetAllocator.AllocateNodeSubnets(node.Name, existingSubnets, config.IPv4Mode, config.IPv6Mode)
	if err != nil {
		return err
	}

	if len(allocatedSubnets) == 0 {
		return nil
	}

	// Release the allocation on error
	defer func() {
		if err != nil {
			if errR := nnc.clusterSubnetAllocator.ReleaseNodeSubnets(node.Name, allocatedSubnets...); errR != nil {
				klog.Warningf("Error releasing node %s subnets: %v", node.Name, errR)
			}
		}
	}()

	hostSubnetsMap := map[string][]*net.IPNet{nnc.networkName: hostSubnets}

	return nnc.updateNodeAnnotationWithRetry(node.Name, hostSubnetsMap)
}

func (nnc *NodeNetworkController) deleteNode(node *kapi.Node) error {
	nnc.subnetAllocatorLock.Lock()
	defer func() {
		nnc.subnetAllocatorLock.Unlock()
	}()
	nnc.clusterSubnetAllocator.ReleaseAllNodeSubnets(node.Name)
	return nil
}

func (nnc *NodeNetworkController) updateNodeAnnotationWithRetry(nodeName string, hostSubnetsMap map[string][]*net.IPNet) error {
	// Retry if it fails because of potential conflict which is transient. Return error in the
	// case of other errors (say temporary API server down), and it will be taken care of by the
	// retry mechanism.
	resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		node, err := nnc.watchFactory.GetNode(nodeName)
		if err != nil {
			return err
		}

		cnode := node.DeepCopy()
		for netName, hostSubnets := range hostSubnetsMap {
			cnode.Annotations, err = util.UpdateNodeHostSubnetAnnotation(cnode.Annotations, hostSubnets, netName)
			if err != nil {
				return fmt.Errorf("failed to update node %q annotation subnet %s",
					node.Name, util.JoinIPNets(hostSubnets, ","))
			}
		}
		return nnc.kube.UpdateNode(cnode)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update node %s annotation", nodeName)
	}

	return nil
}

func (nnc *NodeNetworkController) cleanup(networkName string) error {
	if nnc.networkName != networkName {
		return nil
	}

	// remove hostsubnet annotation for this network
	klog.Infof("Remove node-subnets annotation for network %s on all nodes", networkName)
	existingNodes, err := nnc.watchFactory.GetNodes()
	if err != nil {
		klog.Errorf("Error in getting the nodes: %v", err)
		return nil
	}

	for _, node := range existingNodes {
		if util.NoHostSubnet(node) {
			klog.V(5).Infof("Node %s is not managed by OVN", node.Name)
			continue
		}

		//updateFunc := func(nodeAnnotations map[string]string) (map[string]string, error) {
		//	return util.UpdateNodeHostSubnetAnnotation(nodeAnnotations, nil, nnc.networkName)
		//}

		hostSubnetsMap := map[string][]*net.IPNet{nnc.networkName: nil}
		err = nnc.updateNodeAnnotationWithRetry(node.Name, hostSubnetsMap)
		if err != nil {
			return fmt.Errorf("failed to clear node %q subnet annotation for network %s",
				node.Name, networkName)
		}

		nnc.clusterSubnetAllocator.ReleaseAllNodeSubnets(node.Name)
	}

	return nil
}
