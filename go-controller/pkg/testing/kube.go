package testing

import (
	discovery "k8s.io/api/discovery/v1"
	utilpointer "k8s.io/utils/pointer"
)

// USED ONLY FOR TESTING

// makeReadyEndpointList returns a list of only one endpoint that carries the input addresses.
func MakeReadyEndpointList(node string, addresses ...string) []discovery.Endpoint {
	return []discovery.Endpoint{
		MakeReadyEndpoint(node, addresses...),
	}
}

func MakeReadyEndpoint(node string, addresses ...string) discovery.Endpoint {
	return discovery.Endpoint{
		Conditions: discovery.EndpointConditions{
			Ready:       utilpointer.Bool(true),
			Serving:     utilpointer.Bool(true),
			Terminating: utilpointer.Bool(false),
		},
		Addresses: addresses,
		NodeName:  &node,
	}
}

func MakeTerminatingServingEndpoint(node string, addresses ...string) discovery.Endpoint {
	return discovery.Endpoint{
		Conditions: discovery.EndpointConditions{
			Ready:       utilpointer.Bool(false),
			Serving:     utilpointer.Bool(true),
			Terminating: utilpointer.Bool(true),
		},
		Addresses: addresses,
		NodeName:  &node,
	}
}

func MakeTerminatingNonServingEndpoint(node string, addresses ...string) discovery.Endpoint {
	return discovery.Endpoint{
		Conditions: discovery.EndpointConditions{
			Ready:       utilpointer.Bool(false),
			Serving:     utilpointer.Bool(false),
			Terminating: utilpointer.Bool(true),
		},
		Addresses: addresses,
		NodeName:  &node,
	}
}
