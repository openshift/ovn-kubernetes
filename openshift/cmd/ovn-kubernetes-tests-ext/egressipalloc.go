package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/ipalloc"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kclientset "k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

const (
	// egressIPWindowSize is how many egress IP addresses one test process owns.
	egressIPWindowSize = 32
	// egressIPReservedHostCount is how far above the start of the subnet the
	// first window begins. It keeps the allocator away from the addresses the
	// cloud provider reserves at the bottom of a subnet.
	egressIPReservedHostCount = 512
	// egressIPWindowNamespace and egressIPWindowConfigMap identify the config
	// map that hands out a different window to every test process.
	egressIPWindowNamespace = "default"
	egressIPWindowConfigMap = "ovn-kubernetes-ote-egressip-windows"
	egressIPWindowKey       = "next"
	// egressIPWindowAttempts bounds the optimistic locking retries when
	// claiming a window.
	egressIPWindowAttempts = 30
)

// initEgressIPAllocator prepares the upstream egress IP allocator for this
// binary.
//
// Upstream initializes the allocator from the BeforeSuite in
// test/e2e/e2e_suite_test.go, which only runs under `go test`. The tests
// extension binary never runs it, so ipalloc.NewPrimaryIPv4 used to dereference
// a nil allocator and every EgressIP test panicked.
//
// Two OpenShift specific adjustments are needed on top of simply calling the
// upstream initializer:
//
//   - The allocator derives its address range from the first node it lists and
//     then requires that range to be inside the subnet of every other node. A
//     cloud cluster uses one subnet per availability zone, so that check fails
//     and, worse, the addresses it hands out belong to the wrong subnet and the
//     cloud network config controller cannot attach them to the egress node.
//     Report only the nodes that share a subnet with the node the EgressIP
//     tests make egress assignable.
//
//   - The suite runs in parallel test processes that each build their own
//     allocator. Without coordination they all hand out the same addresses and
//     the resulting EgressIP objects fight over one address. Give every process
//     its own window of addresses, claimed through a config map.
func initEgressIPAllocator(client kclientset.Interface) error {
	nodes, err := egressIPAllocatorNodes(client)
	if err != nil {
		return err
	}
	framework.Logf("Egress IP allocator scoped to %d node(s), deriving addresses from %s",
		len(nodes), nodes[0].Annotations[util.OvnNodeIfAddr])
	return ipalloc.InitPrimaryIPAllocator(scopedNodeInterface{
		NodeInterface: client.CoreV1().Nodes(),
		nodes:         nodes,
	})
}

// scopedNodeInterface reports a fixed set of nodes instead of every node in the
// cluster. The upstream allocator only uses List, both to pick its address
// range and to avoid handing out an address a node already owns.
type scopedNodeInterface struct {
	corev1client.NodeInterface
	nodes []corev1.Node
}

func (s scopedNodeInterface) List(_ context.Context, _ metav1.ListOptions) (*corev1.NodeList, error) {
	return &corev1.NodeList{Items: s.nodes}, nil
}

// egressIPAllocatorNodes returns the nodes the allocator may use. The first
// entry carries a rewritten primary interface address that places the allocator
// in this process' own window of the subnet.
func egressIPAllocatorNodes(client kclientset.Interface) ([]corev1.Node, error) {
	egressNode, err := egressAssignableNode(client)
	if err != nil {
		return nil, err
	}
	_, subnet, err := nodePrimaryIPv4(egressNode)
	if err != nil {
		return nil, err
	}
	all, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	var scoped []corev1.Node
	for i := range all.Items {
		ip, _, err := nodePrimaryIPv4(&all.Items[i])
		if err != nil {
			framework.Logf("Egress IP allocator skipping node %s: %v", all.Items[i].Name, err)
			continue
		}
		if subnet.Contains(ip) {
			scoped = append(scoped, all.Items[i])
		}
	}
	if len(scoped) == 0 {
		return nil, fmt.Errorf("no node found in subnet %s", subnet)
	}
	index, err := claimEgressIPWindow(client)
	if err != nil {
		return nil, err
	}
	base, err := egressIPWindowBase(subnet, index)
	if err != nil {
		return nil, err
	}
	// The allocator increments the second to last octet of the address it reads
	// and starts allocating from there, so hand it the window start minus one
	// octet step.
	first := scoped[0].DeepCopy()
	if err := setNodePrimaryIPv4(first, uint32ToIP(base-256), subnet.Mask); err != nil {
		return nil, err
	}
	return append([]corev1.Node{*first}, scoped...), nil
}

// egressAssignableNode returns the node the EgressIP tests make egress
// assignable. They take the second of at most three ready and schedulable
// nodes, see egress1Node in test/e2e/egressip.go.
func egressAssignableNode(client kclientset.Interface) (*corev1.Node, error) {
	nodes, err := e2enode.GetBoundedReadySchedulableNodes(context.Background(), client, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list schedulable nodes: %w", err)
	}
	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("no schedulable node found")
	}
	if len(nodes.Items) > 1 {
		return &nodes.Items[1], nil
	}
	return &nodes.Items[0], nil
}

// claimEgressIPWindow reserves a window index for this process. The config map
// is updated with optimistic locking so concurrent processes get distinct
// indexes.
func claimEgressIPWindow(client kclientset.Interface) (uint32, error) {
	configMaps := client.CoreV1().ConfigMaps(egressIPWindowNamespace)
	var lastErr error
	for attempt := 0; attempt < egressIPWindowAttempts; attempt++ {
		configMap, err := configMaps.Get(context.Background(), egressIPWindowConfigMap, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = configMaps.Create(context.Background(), &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      egressIPWindowConfigMap,
					Namespace: egressIPWindowNamespace,
				},
				Data: map[string]string{egressIPWindowKey: "0"},
			}, metav1.CreateOptions{})
			if err != nil && !apierrors.IsAlreadyExists(err) {
				return 0, fmt.Errorf("failed to create egress IP window config map: %w", err)
			}
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("failed to read egress IP window config map: %w", err)
		}
		if configMap.Data == nil {
			configMap.Data = map[string]string{}
		}
		index, err := strconv.ParseUint(configMap.Data[egressIPWindowKey], 10, 32)
		if err != nil {
			index = 0
		}
		configMap.Data[egressIPWindowKey] = strconv.FormatUint(index+1, 10)
		if _, err := configMaps.Update(context.Background(), configMap, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) {
				lastErr = err
				continue
			}
			return 0, fmt.Errorf("failed to claim an egress IP window: %w", err)
		}
		return uint32(index), nil
	}
	return 0, fmt.Errorf("gave up claiming an egress IP window: %v", lastErr)
}

// egressIPWindowBase returns the first address of the given window inside the
// subnet. Windows wrap around once the subnet runs out, which keeps a long run
// with many test processes inside the subnet at the cost of reusing addresses
// that earlier processes already released.
func egressIPWindowBase(subnet *net.IPNet, index uint32) (uint32, error) {
	ones, bits := subnet.Mask.Size()
	if bits != 32 {
		return 0, fmt.Errorf("subnet %s is not IPv4", subnet)
	}
	size := uint32(1) << uint(bits-ones)
	reserved := uint32(egressIPReservedHostCount)
	if size <= reserved+egressIPWindowSize {
		return 0, fmt.Errorf("subnet %s is too small for egress IP allocation", subnet)
	}
	windows := (size - reserved) / egressIPWindowSize
	start := binary.BigEndian.Uint32(subnet.IP.To4())
	base := start + reserved + (index%windows)*egressIPWindowSize
	// The allocator adds one to the second to last octet of the address it is
	// given, which overflows instead of carrying when that octet is 255. Shift
	// by a whole octet of windows when that would happen.
	if byte((base-256)>>8) == 255 {
		base = start + reserved + ((index+256/egressIPWindowSize)%windows)*egressIPWindowSize
	}
	return base, nil
}

// nodePrimaryIPv4 returns the IPv4 address and subnet of a node's primary
// interface.
func nodePrimaryIPv4(node *corev1.Node) (net.IP, *net.IPNet, error) {
	addresses, err := util.ParseNodePrimaryIfAddr(node)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse primary interface address of node %s: %w", node.Name, err)
	}
	if addresses.V4.IP == nil || addresses.V4.Net == nil {
		return nil, nil, fmt.Errorf("node %s has no IPv4 primary interface address", node.Name)
	}
	return addresses.V4.IP, addresses.V4.Net, nil
}

// setNodePrimaryIPv4 rewrites the IPv4 part of a node's primary interface
// address annotation, leaving any IPv6 part alone.
func setNodePrimaryIPv4(node *corev1.Node, ip net.IP, mask net.IPMask) error {
	annotation := map[string]string{}
	if raw, ok := node.Annotations[util.OvnNodeIfAddr]; ok {
		if err := json.Unmarshal([]byte(raw), &annotation); err != nil {
			return fmt.Errorf("failed to parse %s of node %s: %w", util.OvnNodeIfAddr, node.Name, err)
		}
	}
	ones, _ := mask.Size()
	annotation["ipv4"] = fmt.Sprintf("%s/%d", ip.String(), ones)
	raw, err := json.Marshal(annotation)
	if err != nil {
		return fmt.Errorf("failed to build %s for node %s: %w", util.OvnNodeIfAddr, node.Name, err)
	}
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}
	node.Annotations[util.OvnNodeIfAddr] = string(raw)
	return nil
}

func uint32ToIP(value uint32) net.IP {
	address := make([]byte, 4)
	binary.BigEndian.PutUint32(address, value)
	return net.IP(address)
}
