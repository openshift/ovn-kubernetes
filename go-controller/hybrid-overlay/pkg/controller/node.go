package controller

import (
	"fmt"
	"net"
	"reflect"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

// The nodeController interface is implemented by the os-specific code
type nodeController interface {
	AddPod(*kapi.Pod) error
	DeletePod(*kapi.Pod) error
	AddNode(*kapi.Node) error
	DeleteNode(*kapi.Node) error
	RemoveStaleNodes([]*kapi.Node)
	RemoveStalePods([]*kapi.Pod)
}

// Node is a node controller and it's informers
type Node struct {
	controller       nodeController
	nodeEventHandler informer.EventHandler
	podEventHandler  informer.EventHandler
}

func nodeChanged(old, new interface{}) bool {
	oldNode := old.(*kapi.Node)
	newNode := new.(*kapi.Node)

	oldCidr, oldNodeIP, oldDrMAC, _ := getNodeDetails(oldNode)
	newCidr, newNodeIP, newDrMAC, _ := getNodeDetails(newNode)
	return !reflect.DeepEqual(oldCidr, newCidr) || !reflect.DeepEqual(oldNodeIP, newNodeIP) || !reflect.DeepEqual(oldDrMAC, newDrMAC)
}

// NewNode Returns a new Node
func NewNode(
	kube kube.Interface,
	nodeName string,
	nodeInformer cache.SharedIndexInformer,
	podInformer cache.SharedIndexInformer,
) (*Node, error) {
	controller, err := newNodeController(kube, nodeName)
	if err != nil {
		return nil, err
	}
	n := &Node{controller: controller}
	n.nodeEventHandler = informer.NewDefaultEventHandler("node", nodeInformer,
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return n.controller.AddNode(node)
		},
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return n.controller.DeleteNode(node)
		},
		nodeChanged,
	)
	n.podEventHandler = informer.NewDefaultEventHandler("pod", podInformer,
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("object is not a pod")
			}
			return n.controller.AddPod(pod)
		},
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("object is not a pod")
			}
			return n.controller.DeletePod(pod)
		},
		informer.DefaultUpdatePredicateFunction,
	)
	return n, nil
}

// Run starts the controller
func (n *Node) Run(stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	klog.Info("Starting Hybrid Overlay Node Controller")

	klog.Info("Starting workers")
	go func() {
		err := n.nodeEventHandler.Run(informer.DefaultNodeInformerThreadiness, stopCh)
		if err != nil {
			klog.Error(err)
		}
	}()
	go func() {
		err := n.podEventHandler.Run(informer.DefaultInformerThreadiness, stopCh)
		if err != nil {
			klog.Error(err)
		}
	}()

	nodeLister := listers.NewNodeLister(n.nodeEventHandler.GetIndexer())
	nodes, err := nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}
	go n.controller.RemoveStaleNodes(nodes)

	podLister := listers.NewPodLister(n.podEventHandler.GetIndexer())
	pods, err := podLister.List(labels.Everything())
	if err != nil {
		return err
	}
	go n.controller.RemoveStalePods(pods)

	klog.Info("Started workers")
	<-stopCh
	klog.Info("Shutting down workers")
	return nil
}

// getNodeSubnetAndIP returns the node's hybrid overlay subnet and the node's
// first InternalIP, or nil if the subnet or node IP is invalid
func getNodeSubnetAndIP(node *kapi.Node) (*net.IPNet, net.IP) {
	var cidr *net.IPNet

	// Parse Linux node OVN hostsubnet annotation first
	cidrs, _ := util.ParseNodeHostSubnetAnnotation(node)
	if cidrs != nil {
		// FIXME DUAL-STACK
		cidr = cidrs[0]
	} else {
		// Otherwise parse the hybrid overlay node subnet annotation
		subnet, ok := node.Annotations[types.HybridOverlayNodeSubnet]
		if !ok {

			klog.V(5).Infof("missing node %q node subnet annotation", node.Name)
			return nil, nil
		}
		var err error
		_, cidr, err = net.ParseCIDR(subnet)
		if err != nil {
			klog.Errorf("error parsing node %q subnet %q: %v", node.Name, subnet, err)
			return nil, nil
		}
	}

	nodeIP, err := houtil.GetNodeInternalIP(node)
	if err != nil {
		klog.Errorf("error getting node %q internal IP: %v", node.Name, err)
		return nil, nil
	}

	return cidr, net.ParseIP(nodeIP)
}

// getNodeDetails returns the node's hybrid overlay subnet, first InternalIP,
// and the distributed router MAC (DRMAC), or nil if any of the addresses are
// missing or invalid.
func getNodeDetails(node *kapi.Node) (*net.IPNet, net.IP, net.HardwareAddr, error) {
	cidr, ip := getNodeSubnetAndIP(node)
	if cidr == nil || ip == nil {
		return nil, nil, nil, fmt.Errorf("missing node subnet and/or node IP")
	}

	drMACString, ok := node.Annotations[types.HybridOverlayDRMAC]
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing distributed router MAC annotation")
	}
	drMAC, err := net.ParseMAC(drMACString)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid distributed router MAC %q: %v", drMACString, err)
	}

	return cidr, ip, drMAC, nil
}
