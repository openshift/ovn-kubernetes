package ovn

import (
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/gateway"

	kapi "k8s.io/api/core/v1"
)

func (ovn *Controller) getGatewayPhysicalIPs(gatewayRouter string) ([]string, error) {
	return gateway.GetGatewayPhysicalIPs(gatewayRouter)
}

func (ovn *Controller) getGatewayLoadBalancer(gatewayRouter string, protocol kapi.Protocol) (string, error) {
	return gateway.GetGatewayLoadBalancer(gatewayRouter, protocol)
}

// getGatewayLoadBalancers find TCP, SCTP, UDP load-balancers from gateway router.
func getGatewayLoadBalancers(gatewayRouter string) (string, string, string, error) {
	return gateway.GetGatewayLoadBalancers(gatewayRouter)
}
