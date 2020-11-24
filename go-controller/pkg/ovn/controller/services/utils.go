package services

import (
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/util/sets"

	"k8s.io/klog/v2"
)

// return the endpoints that belong to the IPFamily as a slice of IP:Port
func getLbEndpoints(slices []*discovery.EndpointSlice, protocol v1.Protocol, family v1.IPFamily) []string {
	// return an empty object so the caller don't have to check for nil and can use it as an iterator
	if len(slices) == 0 {
		return []string{}
	}
	// Endpoint Slices are allowed to have duplicate endpoints
	// we use a set to deduplicate endpoints
	lbEndpoints := sets.NewString()
	for _, slice := range slices {
		klog.V(4).Infof("Getting endpoints for slice %s", slice.Name)
		// Only return addresses that belong to the requested IP family
		if slice.AddressType != discovery.AddressType(family) {
			klog.V(4).Infof("Slice %s with different IP Family endpoints, requested: %s received: %s",
				slice.Name, slice.AddressType, family)
			continue
		}

		// build the list of endpoints in the slice
		for _, port := range slice.Ports {
			// Skip ports that doesn't match the protocol
			if *port.Protocol != protocol {
				klog.V(4).Infof("Slice %s with different Port protocol, requested: %s received: %s",
					slice.Name, protocol, *port.Protocol)
				continue
			}

			for _, endpoint := range slice.Endpoints {
				// Skip endpoints that are not ready
				if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
					klog.V(4).Infof("Slice endpoints Not Ready")
					continue
				}
				for _, ip := range endpoint.Addresses {
					klog.V(4).Infof("Adding slice %s endpoints: %s %d", slice.Name, ip, *port.Port)
					lbEndpoints.Insert(util.JoinHostPortInt32(ip, *port.Port))
				}
			}
		}
	}

	klog.V(4).Infof("LB Endpoints for %s are: %v", slices[0].Labels[discovery.LabelServiceName], lbEndpoints.List())
	return lbEndpoints.List()
}
