package e2e

import (
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/net"
)

// cudnGatewayRouterName returns the name of the OVN gateway router for the
// given ClusterUserDefinedNetwork on the given node. The format is:
//
//	GR_cluster_udn_<sanitized-cudn-name>_<node>
//
// where the sanitization (dashes/slashes -> dots, trailing underscore)
// matches what the production code uses in go-controller/pkg/util/multi_network.go
func cudnGatewayRouterName(cudnName, nodeName string) string {
	return types.GWRouterPrefix + util.GetUserDefinedNetworkPrefix(types.CUDNPrefix+cudnName) + nodeName
}

// podIPsForUserDefinedPrimaryNetwork returns the v4 or v6 IPs for a pod on the UDN
func getPodAnnotationIPsForPrimaryNetworkByIPFamily(k8sClient kubernetes.Interface, podNamespace string, podName string, networkName string, family net.IPFamily) (string, error) {
	if networkName != "default" {
		networkName = namespacedName(podNamespace, networkName)
	}
	ipnets, err := getPodAnnotationIPsForAttachment(k8sClient, podNamespace, podName, networkName)
	if err != nil {
		return "", err
	}
	ipnet := getFirstCIDROfFamily(family, ipnets)
	if ipnet == nil {
		return "", nil
	}
	return ipnet.IP.String(), nil
}
