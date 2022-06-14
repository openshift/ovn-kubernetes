package util

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"sync"

	libovsdbclient "github.com/ovn-org/libovsdb/client"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	"github.com/urfave/cli/v2"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// StringArg gets the named command-line argument or returns an error if it is empty
func StringArg(context *cli.Context, name string) (string, error) {
	val := context.String(name)
	if val == "" {
		return "", fmt.Errorf("argument --%s should be non-null", name)
	}
	return val, nil
}

// GetIPFullMask returns /32 if ip is IPV4 family and /128 if ip is IPV6 family
func GetIPFullMask(ip string) string {
	const (
		// IPv4FullMask is the maximum prefix mask for an IPv4 address
		IPv4FullMask = "/32"
		// IPv6FullMask is the maxiumum prefix mask for an IPv6 address
		IPv6FullMask = "/128"
	)

	if utilnet.IsIPv6(net.ParseIP(ip)) {
		return IPv6FullMask
	}
	return IPv4FullMask
}

// GetLegacyK8sMgmtIntfName returns legacy management ovs-port name
func GetLegacyK8sMgmtIntfName(nodeName string) string {
	if len(nodeName) > 11 {
		return types.K8sPrefix + (nodeName[:11])
	}
	return types.K8sPrefix + nodeName
}

// GetWorkerFromGatewayRouter determines a node's corresponding worker switch name from a gateway router name
func GetWorkerFromGatewayRouter(gr string) string {
	return strings.TrimPrefix(gr, types.GWRouterPrefix)
}

// GetGatewayRouterFromNode determines a node's corresponding gateway router name
func GetGatewayRouterFromNode(node string) string {
	return types.GWRouterPrefix + node
}

// GetNodeChassisID returns the machine's OVN chassis ID
func GetNodeChassisID() (string, error) {
	chassisID, stderr, err := RunOVSVsctl("--if-exists", "get",
		"Open_vSwitch", ".", "external_ids:system-id")
	if err != nil {
		klog.Errorf("No system-id configured in the local host, "+
			"stderr: %q, error: %v", stderr, err)
		return "", err
	}
	if chassisID == "" {
		return "", fmt.Errorf("no system-id configured in the local host")
	}

	return chassisID, nil
}

// GetHybridOverlayPortName returns the name of the hybrid overlay switch port
// for a given node
func GetHybridOverlayPortName(nodeName string) string {
	return "int-" + nodeName
}

type annotationNotSetError struct {
	msg string
}

func (anse annotationNotSetError) Error() string {
	return anse.msg
}

// newAnnotationNotSetError returns an error for an annotation that is not set
func newAnnotationNotSetError(format string, args ...interface{}) error {
	return annotationNotSetError{msg: fmt.Sprintf(format, args...)}
}

// IsAnnotationNotSetError returns true if the error indicates that an annotation is not set
func IsAnnotationNotSetError(err error) bool {
	_, ok := err.(annotationNotSetError)
	return ok
}

// HashforOVN hashes the provided input to make it a valid addressSet or portGroup name.
func HashForOVN(s string) string {
	h := fnv.New64a()
	_, err := h.Write([]byte(s))
	if err != nil {
		klog.Errorf("Failed to hash %s", s)
		return ""
	}
	hashString := strconv.FormatUint(h.Sum64(), 10)
	return fmt.Sprintf("a%s", hashString)
}

// UpdateIPsSlice will search for values of oldIPs in the slice "s" and update it with newIPs values of same IP family
func UpdateIPsSlice(s, oldIPs, newIPs []string) []string {
	n := make([]string, len(s))
	copy(n, s)
	for i, entry := range s {
		for _, oldIP := range oldIPs {
			if entry == oldIP {
				for _, newIP := range newIPs {
					if utilnet.IsIPv6(net.ParseIP(oldIP)) {
						if utilnet.IsIPv6(net.ParseIP(newIP)) {
							n[i] = newIP
							break
						}
					} else {
						if !utilnet.IsIPv6(net.ParseIP(newIP)) {
							n[i] = newIP
							break
						}
					}
				}
				break
			}
		}
	}
	return n
}

// FilterIPsSlice will filter a list of IPs by a list of CIDRs. By default,
// it will *remove* all IPs that match filter, unless keep is true.
//
// It is dual-stack aware.
func FilterIPsSlice(s []string, filter []net.IPNet, keep bool) []string {
	out := make([]string, 0, len(s))
ipLoop:
	for _, ipStr := range s {
		ip := net.ParseIP(ipStr)
		is4 := ip.To4() != nil

		for _, cidr := range filter {
			if is4 && cidr.IP.To4() != nil && cidr.Contains(ip) {
				if keep {
					out = append(out, ipStr)
					continue ipLoop
				} else {
					continue ipLoop
				}
			}
			if !is4 && cidr.IP.To4() == nil && cidr.Contains(ip) {
				if keep {
					out = append(out, ipStr)
					continue ipLoop
				} else {
					continue ipLoop
				}
			}
		}
		if !keep { // discard mode, and nothing matched.
			out = append(out, ipStr)
		}
	}

	return out
}

func GetLogicalPortName(podNamespace, podName string) string {
	return composePortName(podNamespace, podName)
}

func GetIfaceId(podNamespace, podName string) string {
	return composePortName(podNamespace, podName)
}

// composePortName should be called both for LogicalPortName and iface-id
// because ovn-nb man says:
// Logical_Switch_Port.name must match external_ids:iface-id
// in the Open_vSwitch database’s Interface table,
// because hypervisors use external_ids:iface-id as a lookup key to
// identify the network interface of that entity.
func composePortName(podNamespace, podName string) string {
	return podNamespace + "_" + podName
}

func SliceHasStringItem(slice []string, item string) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}

var updateNodeSwitchLock sync.Mutex

// UpdateNodeSwitchExcludeIPs should be called after adding the management port
// and after adding the hybrid overlay port, and ensures that each port's IP
// is added to the logical switch's exclude_ips. This prevents ovn-northd log
// spam about duplicate IP addresses.
// See https://github.com/ovn-org/ovn-kubernetes/pull/779
func UpdateNodeSwitchExcludeIPs(nbClient libovsdbclient.Client, nodeName string, subnet *net.IPNet) error {
	if utilnet.IsIPv6CIDR(subnet) {
		// We don't exclude any IPs in IPv6
		return nil
	}

	updateNodeSwitchLock.Lock()
	defer updateNodeSwitchLock.Unlock()

	managmentPort := &nbdb.LogicalSwitchPort{Name: types.K8sPrefix + nodeName}
	HOPort := &nbdb.LogicalSwitchPort{Name: types.HybridOverlayPrefix + nodeName}
	haveManagementPort := true
	haveHybridOverlayPort := true
	// Only Query The cache for mp0 and HO LSPs
	ctx, cancel := context.WithTimeout(context.Background(), types.OVSDBTimeout)
	defer cancel()
	if err := nbClient.Get(ctx, managmentPort); err != nil {
		if err != libovsdbclient.ErrNotFound {
			return fmt.Errorf("failed to get management port for node %s error: %v", nodeName, err)
		}
		klog.V(5).Infof("Management port does not exist for node %s", nodeName)
		haveManagementPort = false
	}

	if err := nbClient.Get(ctx, HOPort); err != nil {
		if err != libovsdbclient.ErrNotFound {
			return fmt.Errorf("failed to get hybrid overlay port for node %s error: %v", nodeName, err)
		}
		klog.V(5).Infof("Hybridoverlay port does not exist for node %s", nodeName)
		haveHybridOverlayPort = false
	}

	mgmtIfAddr := GetNodeManagementIfAddr(subnet)
	hybridOverlayIfAddr := GetNodeHybridOverlayIfAddr(subnet)

	klog.V(5).Infof("haveMP %v haveHO %v ManagementPortAddress %v HybridOverlayAddressOA %v", haveManagementPort, haveHybridOverlayPort, mgmtIfAddr, hybridOverlayIfAddr)
	var excludeIPs string
	if config.HybridOverlay.Enabled {
		if haveHybridOverlayPort && haveManagementPort {
			// no excluded IPs required
		} else if !haveHybridOverlayPort && !haveManagementPort {
			// exclude both
			excludeIPs = mgmtIfAddr.IP.String() + ".." + hybridOverlayIfAddr.IP.String()
		} else if haveHybridOverlayPort {
			// exclude management port IP
			excludeIPs = mgmtIfAddr.IP.String()
		} else if haveManagementPort {
			// exclude hybrid overlay port IP
			excludeIPs = hybridOverlayIfAddr.IP.String()
		}
	} else if !haveManagementPort {
		// exclude management port IP
		excludeIPs = mgmtIfAddr.IP.String()
	}

	logicalSwitchDes := nbdb.LogicalSwitch{
		Name:        nodeName,
		OtherConfig: map[string]string{"exclude_ips": excludeIPs},
	}

	opModels := []libovsdbops.OperationModel{
		{
			Model:          &logicalSwitchDes,
			ModelPredicate: func(ls *nbdb.LogicalSwitch) bool { return ls.Name == nodeName },
			OnModelMutations: []interface{}{
				&logicalSwitchDes.OtherConfig,
			},
			ErrNotFound: true,
		},
	}

	m := libovsdbops.NewModelClient(nbClient)
	// If excludeIPs is empty ensure that we have no excludeIPs in the Switch's OtherConfig
	if len(excludeIPs) == 0 {
		if err := m.Delete(opModels...); err != nil {
			return fmt.Errorf("failed to delete otherConfig:exclude_ips from logical switch %s, error: %v", nodeName, err)
		}
	} else {
		if _, err := m.CreateOrUpdate(opModels...); err != nil {
			return fmt.Errorf("failed to configure otherConfig:exclude_ips from logical switch %s, error: %v", nodeName, err)
		}
	}

	return nil
}
