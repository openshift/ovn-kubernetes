package node

import (
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	utilnet "k8s.io/utils/net"
)

// forEachEligibleEndpoint iterates through each eligible endpoint in the given endpointslice and apply the input function fn to it.
// An endpoint is eligible if it is serving or if its corresponding service has Spec.PublishNotReadyAddresses set.
// When checking for a condition on the endpoints, returnWhenTrue should point to the boolean that fn sets, so that the iteration
// ends as soon as the boolean is set to true.
func forEachEligibleEndpoint(endpointSlice *discovery.EndpointSlice, service *kapi.Service, returnWhenTrue *bool, fn func(discovery.Endpoint)) {
	includeTerminating := service != nil && service.Spec.PublishNotReadyAddresses
	for _, endpoint := range endpointSlice.Endpoints {
		if util.IsEndpointEligible(endpoint, includeTerminating) {
			fn(endpoint)
			if returnWhenTrue != nil && *returnWhenTrue {
				// shortcircuit the whole iteration if given bool is true
				return
			}
		}
	}
}

// getEndpointAddresses returns a list of IP addresses of all eligible endpoints in the given endpoint slice.
func getEndpointAddresses(endpointSlice *discovery.EndpointSlice, service *kapi.Service) []string {
	endpointsAddress := make([]string, 0)
	forEachEligibleEndpoint(endpointSlice, service, nil, func(endpoint discovery.Endpoint) {
		for _, ip := range endpoint.Addresses {
			endpointsAddress = append(endpointsAddress, utilnet.ParseIPSloppy(ip).String())
		}
	})
	return endpointsAddress
}

// hasLocalHostNetworkEndpoints returns true if there is at least one host-networked endpoint
// in the provided list that is local to this node.
// It returns false if none of the endpoints are local host-networked endpoints or if ep.Subsets is nil.
func hasLocalHostNetworkEndpoints(endpointSlices []*discovery.EndpointSlice, nodeAddresses []net.IP, service *kapi.Service) bool {
	var res bool
	for _, endpointSlice := range endpointSlices {
		forEachEligibleEndpoint(endpointSlice, service, &res, func(endpoint discovery.Endpoint) {
			for _, ip := range endpoint.Addresses {
				for _, nodeIP := range nodeAddresses {
					if nodeIP.String() == utilnet.ParseIPSloppy(ip).String() {
						res = true
						return
					}
				}
			}
		})
	}
	return res
}

// getLocalEndpointAddresses returns a list of endpoints that are local to the specified node
func getLocalEndpointAddresses(endpointSlices []*discovery.EndpointSlice, service *kapi.Service, nodeName string) sets.String {
	localEndpoints := sets.NewString()
	for _, endpointSlice := range endpointSlices {
		forEachEligibleEndpoint(endpointSlice, service, nil, func(endpoint discovery.Endpoint) {
			if endpoint.NodeName != nil && *endpoint.NodeName == nodeName {
				localEndpoints.Insert(endpoint.Addresses...)
			}
		})
	}
	return localEndpoints
}

// doesEndpointSliceContainEndpoint returns true if the endpointslice
// contains an endpoint with the given IP/Port/Protocol and this endpoint is considered eligible
func doesEndpointSliceContainEndpoint(endpointSlice *discovery.EndpointSlice,
	epIP string, epPort int32, protocol kapi.Protocol, service *kapi.Service) bool {
	var res bool
	for _, port := range endpointSlice.Ports {
		forEachEligibleEndpoint(endpointSlice, service, &res, func(endpoint discovery.Endpoint) {
			for _, ip := range endpoint.Addresses {
				if utilnet.ParseIPSloppy(ip).String() == epIP && *port.Port == epPort && *port.Protocol == protocol {
					res = true
					return
				}
			}
		})
	}
	return res
}

// isHostEndpoint determines if the given endpoint ip belongs to a host networked pod
func isHostEndpoint(endpointIP string) bool {
	for _, clusterNet := range config.Default.ClusterSubnets {
		if clusterNet.CIDR.Contains(net.ParseIP(endpointIP)) {
			return false
		}
	}
	return true
}

// Returns the namespaced name of the service that corresponds to the given endpointSlice
func serviceNamespacedNameFromEndpointSlice(endpointSlice *discovery.EndpointSlice) (ktypes.NamespacedName, error) {
	var serviceNamespacedName ktypes.NamespacedName
	svcName := endpointSlice.Labels[discovery.LabelServiceName]
	if svcName == "" {
		// should not happen, since the informer already filters out endpoint slices with an empty service label
		return serviceNamespacedName,
			fmt.Errorf("endpointslice %s/%s: empty value for label %s",
				endpointSlice.Namespace, endpointSlice.Name, discovery.LabelServiceName)
	}
	return ktypes.NamespacedName{Namespace: endpointSlice.Namespace, Name: svcName}, nil
}
