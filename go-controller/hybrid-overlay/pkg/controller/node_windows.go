package controller

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"

	"github.com/Microsoft/hcsshim/hcn"
)

const (
	// Hard-coded constants
	networkName = "OVNKubernetesHybridOverlayNetwork" // In practice, this is the virtual switch name
)

// NodeController is the node hybrid overlay controller
type NodeController struct {
	kube            kube.Interface
	machineID       string
	networkID       string
	localNodeCIDR   *net.IPNet
	localNodeIP     net.IP
	remoteSubnetMap map[string]string // Maps a remote node to its remote subnet
}

// NewNode returns a node handler that listens for node events
// so that Add/Update/Delete events are appropriately handled.
func NewNode(kube kube.Interface, nodeName string, stopChan <-chan struct{}) (*NodeController, error) {
	supportedFeatures := hcn.GetSupportedFeatures()
	if !supportedFeatures.HostRoute {
		return nil, fmt.Errorf("This version of windows does not support HostRoute " +
			"policies; network communication between this node and its pods " +
			"will not work. HostRoute policies are available as a KB update " +
			"for Windows Server 2019 version 1809 and out of the box in " +
			"Windows Server 2019 version 1903.")
	}

	node, err := kube.GetNode(nodeName)
	if err != nil {
		return nil, err
	}

	if err := ensureBaseNetwork(); err != nil {
		return nil, err
	}

	return &NodeController{
		kube:            kube,
		machineID:       node.Status.NodeInfo.MachineID,
		remoteSubnetMap: make(map[string]string),
	}, nil
}

func ensureBaseNetwork() error {
	// Host network connectivity is temporarily lost when the first
	// overlay network is created on Windows. This may cause disruption
	// to other services during boot time. Once the first overlay network
	// exists, any subsequent overlay network creation reuse the same
	// VMSwitch and therefore don't disrupt the traffic.
	//
	// Overlay networks have the ability to be persistent, which means
	// they are still present after node reboot. Endpoints and other
	// network resources on the other hand have to be cleaned up on
	// every reboot.
	//
	// In order to minimize traffic disruption but keep relying on
	// the HNS service to clean up the unnecessary resources, we create
	// a persistent base overlay network on top of which we create the
	// (non-persistent) Hybrid Overlay overlay network. Endpoints are
	// then attached to the Hybrid Overlay network. The Hybrid Overlay
	// network is re-created by Hybrid-Overlay after each node boot
	// while the base network remains across reboots.

	const (
		baseNetworkName = "BaseOVNKubernetesHybridOverlayNetwork"
		fakeSubnetVNI   = types.HybridOverlayVNI + 1
	)

	// Unused subnet and gateway IP required to create the base overlay network.
	// This subnet is actually invisible to the PODs/Nodes.
	_, fakeSubnetCIDR, _ := net.ParseCIDR("100.64.0.0/30")
	fakeSubnetGateway := net.ParseIP("100.64.0.2")

	baseNetwork := GetExistingNetwork(baseNetworkName, fakeSubnetCIDR.String(), fakeSubnetGateway.String())
	if baseNetwork != nil {
		// nothing to do
		return nil
	}

	baseNetworkInfo := NetworkInfo{
		AutomaticDNS: false,
		IsPersistent: true,
		Name:         baseNetworkName,
		Subnets: []SubnetInfo{{
			AddressPrefix:  fakeSubnetCIDR,
			GatewayAddress: fakeSubnetGateway,
			VSID:           fakeSubnetVNI,
		}},
	}

	klog.Infof("Creating the base overlay network '%s'.", baseNetworkName)

	// Retrieve the network schema object
	baseNetworkSchema, err := baseNetworkInfo.GetHostComputeNetworkConfig()
	if err != nil {
		return fmt.Errorf("Unable to generate a schema to create a base overlay network, error: %v", err)
	}

	klog.Infof("Base network creation may take up to a minute to complete...")
	// Create the base network from schema object
	if _, err = baseNetworkSchema.Create(); err != nil {
		return fmt.Errorf("Unable to create the base overlay network, error: %v", err)
	}

	// Workaround for a limitation in the Windows HNS service. We need
	// to manually duplicate persistent routes that used to be on the
	// physical network interface to the newly created host vNIC
	if err = DuplicatePersistentIPRoutes(); err != nil {
		return fmt.Errorf("Unable to refresh the persistent IP routes, error: %v", err)
	}

	return nil
}

// Start is the top level function to run hybrid-sdn in node mode
func (n *NodeController) Start(wf *factory.WatchFactory) error {
	return houtil.StartNodeWatch(n, wf)
}

// Add sets up VXLAN tunnels to other nodes
// For a windows node, this means watching for all nodes and programming the routing
func (n *NodeController) Add(node *kapi.Node) {
	if node.Status.NodeInfo.MachineID == n.machineID {
		// Initialize or the local node (or reconfigure it if the addresses
		// have changed) by creating the network object and setting up
		// all the VXLAN tunnels towards other nodes
		cidr, nodeIP := getNodeSubnetAndIP(node)
		if (cidr != nil && !houtil.SameIPNet(cidr, n.localNodeCIDR)) || (nodeIP != nil && nodeIP.Equal(n.localNodeIP)) {
			n.localNodeCIDR = cidr
			n.localNodeIP = nodeIP
			if err := n.initSelf(node, cidr); err != nil {
				klog.Errorf("failed to initialize node: %v", err)
			}
		}
		return
	}

	cidr, nodeIP, drMAC, err := getNodeDetails(node)
	if cidr == nil || nodeIP == nil || drMAC == nil {
		klog.V(5).Infof("cleaning up hybrid overlay resources for node %q because: %v", node.Name, err)
		n.Delete(node)
		return
	}

	// For remote nodes, just set up the VXLAN tunnel to it
	network, err := hcn.GetNetworkByID(n.networkID)
	if err != nil {
		klog.Error("error getting HCN network: %v", err)
		return
	}

	klog.Infof("Adding a remote subnet route for CIDR '%s' (remote node address: %s, distributed router MAC: %s, VNI: %v).",
		cidr.String(), nodeIP.String(), drMAC.String(), types.HybridOverlayVNI)
	networkPolicySettings := hcn.RemoteSubnetRoutePolicySetting{
		// VXLAN virtual network Identifier. Is expected to be 4097 or higher on Windows
		IsolationId: types.HybridOverlayVNI,
		// Distributed router/gateway MAC address
		DistributedRouterMacAddress: drMAC.String(),
		// Host IP address of the node
		ProviderAddress: nodeIP.String(),
		// Prefix used on the destination node
		DestinationPrefix: cidr.String(),
	}

	n.remoteSubnetMap[node.Status.NodeInfo.MachineID] = cidr.String()

	if err = AddRemoteSubnetPolicy(network, &networkPolicySettings); err != nil {
		klog.Error("error adding remote subnet policy: %v", err)
	}
}

// Update handles node updates
func (n *NodeController) Update(oldNode, newNode *kapi.Node) {
	// Only modify the node if relevant annotations have changed
	if nodeChanged(oldNode, newNode) {
		n.Delete(oldNode)
		n.Add(newNode)
	}
}

// Delete handles node deletions
func (n *NodeController) Delete(node *kapi.Node) {
	// Treat the local node differently than other nodes
	// If the local node is removed, we want to delete the network object
	// and remove all the VXLAN plumbing towards other existing nodes. If
	// a remote node is removed, we just want to remove the VXLAN tunnel
	// (i.e. the remote subnet) to it.

	if node.Status.NodeInfo.MachineID == n.machineID {
		if err := n.uninitSelf(node); err != nil {
			klog.Errorf("failed to uninitialize node: %v", err)
		}
		return
	}

	if n.networkID == "" {
		// Just silently return, no need to clean up a non-initialized network
		return
	}

	network, err := hcn.GetNetworkByID(n.networkID)
	if err != nil {
		if _, isNotExist := err.(hcn.NetworkNotFoundError); !isNotExist {
			klog.Errorf("Couldn't retrieve network with ID '%s' on node '%s'", n.networkID, node.Name)
		}
		return
	}

	nodeSubnet, ok := n.remoteSubnetMap[node.Status.NodeInfo.MachineID]
	if !ok {
		klog.Errorf("Can't retrieve the host subnet from the '%s' node's annotations", node.Name)
		return
	}

	if err := RemoveRemoteSubnetPolicy(network, nodeSubnet); err != nil {
		klog.Errorf("Error removing subnet policy '%s' node's annotations from network '%s' on node '%s'. Error: %v",
			nodeSubnet, n.networkID, node.Name, err)
		return
	}

	delete(n.remoteSubnetMap, node.Status.NodeInfo.MachineID)
}

// Sync handles synchronizing the initial node list
func (n *NodeController) Sync(nodes []*kapi.Node) {
}

// initSelf initializes the node it is currently running on. This means:
//  1. Setting up this node and its VXLAN extension for talking to other nodes
//  2. Setting back annotations about its VTEP and gateway MAC address to its own node object
//  3. Initializing every VXLAN tunnels toward other nodes
func (n *NodeController) initSelf(node *kapi.Node, nodeSubnet *net.IPNet) error {
	// The distributed router IP (i.e. the gateway, from a container perspective)
	// is hardcoded here to be the first IP on the subnet.
	// TODO: could be made configurable as Windows doesn't have any restrictions
	// as to what this gateway address should be.
	gatewayAddress := util.NextIP(nodeSubnet.IP)

	network := GetExistingNetwork(networkName, nodeSubnet.String(), gatewayAddress.String())
	if network == nil {
		// Create the overlay network
		networkInfo := NetworkInfo{
			AutomaticDNS: true,
			IsPersistent: false,
			Name:         networkName,
			Subnets: []SubnetInfo{{
				AddressPrefix:  nodeSubnet,
				GatewayAddress: gatewayAddress,
				VSID:           types.HybridOverlayVNI,
			}},
		}
		klog.Infof("Creating overlay network '%s' (address prefix %v) with gateway address: %v", networkName, nodeSubnet, gatewayAddress)

		// Retrieve the network schema object
		networkSchema, err := networkInfo.GetHostComputeNetworkConfig()
		if err != nil {
			return fmt.Errorf("Unable to generate a schema to create an overlay network, error: %v", err)
		}

		klog.Infof("Network creation may take up to a minute to complete...")
		// Create the actual network from schema object
		network, err = networkSchema.Create()
		if err != nil {
			return fmt.Errorf("Unable to create the overlay network, error: %v", err)
		}

		err = AddHostRoutePolicy(network)
		if err != nil {
			return fmt.Errorf("Unable to add host route policy, error: %v", err)
		}
	} else {
		klog.Infof("Reusing existing overlay network '%s' (address prefix %v) with gateway address: %v.",
			networkName, nodeSubnet, gatewayAddress)

		// TODO: there is a better approach than clearing all the remote
		// subnet policies, and then re-creating the ones still applicable.
		// we should instead take an update approach by removing the stale
		// policies and create the missing ones
		if err := ClearRemoteSubnetPolicies(network); err != nil {
			// Don't return here. We can still work with stale policies.
			// We will re-create the policies later in this function.
			klog.Errorf("Failed to clear the existing remote subnet policies. Some stale policies were left behind.: %v", err)
		}
	}

	n.networkID = network.Id

	// Set the HybridOverlayDrMac annotation on the node
	for _, policy := range network.Policies {
		if policy.Type == hcn.DrMacAddress {
			policySettings := hcn.DrMacAddressNetworkPolicySetting{}

			if err := json.Unmarshal(policy.Settings, &policySettings); err != nil {
				return fmt.Errorf("Unable to unmarshall the DRMAC policy setting, error: %v", err)
			}

			if len(policySettings.Address) == 0 {
				return fmt.Errorf("Error creating the network: no DRMAC address")
			}
			if err := n.kube.SetAnnotationsOnNode(node, map[string]interface{}{
				types.HybridOverlayDRMAC: policySettings.Address,
			}); err != nil {
				klog.Errorf("failed to set DRMAC annotation on node: %v", err)
			}
			break
		}
	}

	// Add existing nodes
	nodes, err := n.kube.GetNodes()
	if err != nil {
		return fmt.Errorf("Error in initializing/fetching nodes: %v", err)
	}

	for _, node := range nodes.Items {
		// Add VXLAN tunnel to the remote nodes
		if node.Status.NodeInfo.MachineID != n.machineID {
			n.Add(&node)
		}
	}

	return nil
}

// uninitSelf un-initializes the node it is currently running on. This means:
//  1. Cleaning up this node and its VXLAN extension for talking to other nodes
//  2. Cleaning up annotations about its VTEP and gateway MAC address to its own node object
//  3. Uninitializing every VXLAN tunnel toward other nodes
func (n *NodeController) uninitSelf(node *kapi.Node) error {
	klog.Infof("Removing overlay network '%s' (ID: %v) from local node '%s'",
		networkName, n.networkID, node.Name)

	// Remove existing nodes
	nodes, err := n.kube.GetNodes()
	if err != nil {
		return fmt.Errorf("failed to get nodes: %v", err)
	}

	// Delete VXLAN tunnel to the remote nodes
	for _, node := range nodes.Items {
		if node.Status.NodeInfo.MachineID != n.machineID {
			n.Delete(&node)
		}
	}

	// Find the network and remove it
	network, err := hcn.GetNetworkByID(n.networkID)
	if err != nil {
		return err
	}

	network.Delete()
	return nil
}
