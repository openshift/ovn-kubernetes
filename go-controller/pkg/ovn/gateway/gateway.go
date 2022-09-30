package gateway

import (
	"errors"
	"fmt"
	"strings"

	libovsdbclient "github.com/ovn-org/libovsdb/client"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	// OvnGatewayLoadBalancerIds represent the OVN loadbalancers used on nodes
	OvnGatewayLoadBalancerIds = "lb_gateway_router"
)

var (
	// It is perfectly normal to have OVN GW routers to not to have LB rules. This happens
	// when NodePort is disabled for that node.
	OVNGatewayLBIsEmpty = errors.New("load balancer item in OVN DB is an empty string")
)

// GetOvnGateways return all created gateways.
func GetOvnGateways(nbClient libovsdbclient.Client) ([]string, error) {
	p := func(item *nbdb.LogicalRouter) bool {
		return item.Options["chassis"] != "null"
	}
	logicalRouters, err := libovsdbops.FindLogicalRoutersWithPredicate(nbClient, p)
	if err != nil {
		return nil, err
	}

	result := []string{}
	for _, logicalRouter := range logicalRouters {
		result = append(result, logicalRouter.Name)
	}
	return result, nil
}

// GetGatewayPhysicalIPs return gateway physical IPs
func GetGatewayPhysicalIPs(nbClient libovsdbclient.Client, gatewayRouter string) ([]string, error) {
	logicalRouter := &nbdb.LogicalRouter{Name: gatewayRouter}
	logicalRouter, err := libovsdbops.GetLogicalRouter(nbClient, logicalRouter)
	if err != nil {
		return nil, fmt.Errorf("error getting router %s: %v", gatewayRouter, err)
	}

	if ips := logicalRouter.ExternalIDs["physical_ips"]; ips != "" {
		return strings.Split(ips, ","), nil
	}

	if ip := logicalRouter.ExternalIDs["physical_ip"]; ip != "" {
		return []string{ip}, nil
	}

	return nil, fmt.Errorf("no physical IPs found for gateway %s", gatewayRouter)
}

// CreateDummyGWMacBinding creates a mac binding for a fake next hop when a node has no default gateway
func CreateDummyGWMacBinding(sbClient libovsdbclient.Client, nodeName string) error {
	for _, nextHop := range node.DummyNextHopIPs() {
		dummyNextHopMAC := util.IPAddrToHWAddr(nextHop)
		nodeGWRouter := util.GetGatewayRouterFromNode(nodeName)
		logicalPort := ovntypes.GWRouterToExtSwitchPrefix + nodeGWRouter
		if err := util.CreateMACBinding(
			sbClient,
			logicalPort,
			nodeGWRouter,
			dummyNextHopMAC,
			nextHop,
		); err != nil {
			return fmt.Errorf(
				"failed to create MAC Binding for dummy nexthop %s: %v",
				nodeName,
				err)
		}
	}

	return nil
}
