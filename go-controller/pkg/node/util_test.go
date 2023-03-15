package node

import (
	"net"
	"reflect"
	"testing"

	kapi "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	testNode   string      = "testNode"
	ep1Address string      = "10.244.0.3"
	ep2Address string      = "10.244.0.4"
	ep3Address string      = "10.244.1.3"
	tcpv1      v1.Protocol = v1.ProtocolTCP
	udpv1      v1.Protocol = v1.ProtocolUDP

	httpsPortName   string = "https"
	httpsPortValue  int32  = int32(443)
	customPortName  string = "customApp"
	customPortValue int32  = int32(10600)
)

func getSampleService(publishNotReadyAddresses bool) *v1.Service {
	name := "service-test"
	namespace := "test"
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			UID:       k8stypes.UID(namespace),
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.ServiceSpec{
			PublishNotReadyAddresses: publishNotReadyAddresses,
		},
	}
}

// returns an endpoint slice with three endpoints, two of which belong to the expected local node
// and one belongs to "other-node"
func getSampleEndpointSlice(service *kapi.Service) *discovery.EndpointSlice {

	epPortHttps := discovery.EndpointPort{
		Name:     &httpsPortName,
		Port:     &httpsPortValue,
		Protocol: &tcpv1,
	}

	epPortCustom := discovery.EndpointPort{
		Name:     &customPortName,
		Port:     &customPortValue,
		Protocol: &udpv1,
	}

	ep1 := discovery.Endpoint{
		Addresses: []string{ep1Address},
		NodeName:  &testNode,
	}
	ep2 := discovery.Endpoint{
		Addresses: []string{ep2Address},
		NodeName:  &testNode,
	}
	otherNodeName := "other-node"
	nonLocalEndpoint := discovery.Endpoint{
		Addresses: []string{ep3Address},
		NodeName:  &otherNodeName,
	}
	return newEndpointSlice(
		service.Name,
		service.Namespace,
		[]discovery.Endpoint{ep1, ep2, nonLocalEndpoint},
		[]discovery.EndpointPort{epPortHttps, epPortCustom})
}

func newTrue() *bool {
	b := true
	return &b
}
func newFalse() *bool {
	b := false
	return &b
}

func setEndpointToReady(endpoint *discovery.Endpoint) {
	endpoint.Conditions.Ready = newTrue()
	endpoint.Conditions.Serving = newTrue()
	endpoint.Conditions.Terminating = newFalse()
}

func setEndpointToTerminatingAndServing(endpoint *discovery.Endpoint) {
	endpoint.Conditions.Ready = newFalse()
	endpoint.Conditions.Serving = newTrue()
	endpoint.Conditions.Terminating = newTrue()
}

func setEndpointToTerminatingAndNotServing(endpoint *discovery.Endpoint) {
	endpoint.Conditions.Ready = newFalse()
	endpoint.Conditions.Serving = newFalse()
	endpoint.Conditions.Terminating = newTrue()
}

func setAllEndpointsToTerminatingAndServing(endpointSlice *discovery.EndpointSlice) *discovery.EndpointSlice {
	for i := range endpointSlice.Endpoints {
		setEndpointToTerminatingAndServing(&endpointSlice.Endpoints[i])
	}
	return endpointSlice
}

func setAllEndpointsToTerminatingAndNotServing(endpointSlice *discovery.EndpointSlice) *discovery.EndpointSlice {
	for i := range endpointSlice.Endpoints {
		setEndpointToTerminatingAndNotServing(&endpointSlice.Endpoints[i])
	}
	return endpointSlice
}

func setAllEndpointsToReady(endpointSlice *discovery.EndpointSlice) *discovery.EndpointSlice {
	for i := range endpointSlice.Endpoints {
		setEndpointToReady(&endpointSlice.Endpoints[i])
	}
	return endpointSlice
}

func setEndpointsToAMixOfStatusConditions(endpointSlice *discovery.EndpointSlice) *discovery.EndpointSlice {
	setEndpointToReady(&endpointSlice.Endpoints[0])
	setEndpointToTerminatingAndServing(&endpointSlice.Endpoints[1])
	setEndpointToTerminatingAndNotServing(&endpointSlice.Endpoints[2])
	return endpointSlice
}

func TestGetEndpointAddresses(t *testing.T) {
	service := getSampleService(false)
	var tests = []struct {
		name          string
		endpointSlice *discovery.EndpointSlice
		want          []string
	}{
		{
			"Tests an endpointslice with all ready endpoints",
			setAllEndpointsToReady(getSampleEndpointSlice(service)),
			[]string{ep1Address, ep2Address, ep3Address},
		},
		{
			"Tests an endpointslice with all non-ready, serving, terminating endpoints",
			setAllEndpointsToTerminatingAndServing(getSampleEndpointSlice(service)),
			[]string{ep1Address, ep2Address, ep3Address},
		},
		{
			"Tests an endpointslice with all non-ready, non-serving, terminating endpoints",
			setAllEndpointsToTerminatingAndNotServing(getSampleEndpointSlice(service)),
			[]string{},
		},
		{
			"Tests an endpointslice with endpoints showing a mix of status conditions",
			setEndpointsToAMixOfStatusConditions(getSampleEndpointSlice(service)),
			[]string{ep1Address, ep2Address},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answer := getEndpointAddresses(tt.endpointSlice, service)
			if !reflect.DeepEqual(answer, tt.want) {
				t.Errorf("got %v, want %v", answer, tt.want)
			}
		})
	}
}

func TestHasLocalHostNetworkEndpoints(t *testing.T) {
	service := getSampleService(false)
	ep1IP := net.ParseIP(ep1Address)
	if ep1IP == nil {
		t.Errorf("error parsing ep1 address %s", ep1Address)
	}
	nodeAddresses := []net.IP{ep1IP}
	var tests = []struct {
		name          string
		endpointSlice *discovery.EndpointSlice
		want          bool
	}{
		{
			"Tests an endpointslice with all ready endpoints",
			setAllEndpointsToReady(getSampleEndpointSlice(service)),
			true,
		},
		{
			"Tests an endpointslice with all non-ready, serving, terminating endpoints",
			setAllEndpointsToTerminatingAndServing(getSampleEndpointSlice(service)),
			true,
		},
		{
			"Tests an endpointslice with all non-ready, non-serving, terminating endpoints",
			setAllEndpointsToTerminatingAndNotServing(getSampleEndpointSlice(service)),
			false,
		},
		{
			"Tests an endpointslice with endpoints showing a mix of status conditions",
			setEndpointsToAMixOfStatusConditions(getSampleEndpointSlice(service)),
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answer := hasLocalHostNetworkEndpoints([]*discovery.EndpointSlice{tt.endpointSlice}, nodeAddresses, service)
			if !reflect.DeepEqual(answer, tt.want) {
				t.Errorf("got %v, want %v", answer, tt.want)
			}
		})
	}
}

func TestGetLocalEndpointAddresses(t *testing.T) {
	service := getSampleService(false)
	var tests = []struct {
		name          string
		endpointSlice *discovery.EndpointSlice
		want          sets.String
	}{
		{
			"Tests an endpointslice with all ready endpoints",
			setAllEndpointsToReady(getSampleEndpointSlice(service)),
			sets.NewString(ep1Address, ep2Address),
		},
		{
			"Tests an endpointslice with all non-ready, serving, terminating endpoints",
			setAllEndpointsToTerminatingAndServing(getSampleEndpointSlice(service)),
			sets.NewString(ep1Address, ep2Address),
		},
		{
			"Tests an endpointslice with all non-ready, non-serving, terminating endpoints",
			setAllEndpointsToTerminatingAndNotServing(getSampleEndpointSlice(service)),
			sets.NewString(),
		},
		{
			"Tests an endpointslice with endpoints showing a mix of status conditions",
			setEndpointsToAMixOfStatusConditions(getSampleEndpointSlice(service)),
			sets.NewString(ep1Address, ep2Address),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answer := getLocalEndpointAddresses([]*discovery.EndpointSlice{tt.endpointSlice}, service, testNode)
			if !reflect.DeepEqual(answer, tt.want) {
				t.Errorf("got %v, want %v", answer, tt.want)
			}
		})
	}
}

func TestDoesEndpointSliceContainEndpoint(t *testing.T) {
	service := getSampleService(false)
	var tests = []struct {
		name          string
		endpointSlice *discovery.EndpointSlice
		epIP          string
		epPort        int32
		protocol      v1.Protocol
		want          bool
	}{
		{
			"Tests an endpointslice with all ready endpoints",
			setAllEndpointsToReady(getSampleEndpointSlice(service)),
			ep1Address, httpsPortValue, tcpv1,
			true,
		},
		{
			"Tests an endpointslice with all ready endpoints and a port that is not included",
			setAllEndpointsToReady(getSampleEndpointSlice(service)),
			ep1Address, int32(444), tcpv1,
			false,
		},

		{
			"Tests an endpointslice with all non-ready, serving, terminating endpoints",
			setAllEndpointsToTerminatingAndServing(getSampleEndpointSlice(service)),
			ep1Address, customPortValue, udpv1,
			true,
		},
		{
			"Tests an endpointslice with all non-ready, non-serving, terminating endpoints",
			setAllEndpointsToTerminatingAndNotServing(getSampleEndpointSlice(service)),
			ep1Address, customPortValue, udpv1,
			false,
		},
		{
			"Tests an endpointslice with endpoints showing a mix of status conditions",
			setEndpointsToAMixOfStatusConditions(getSampleEndpointSlice(service)),
			ep1Address, customPortValue, udpv1,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answer := doesEndpointSliceContainEndpoint(tt.endpointSlice, tt.epIP, tt.epPort, tt.protocol, service)
			if !reflect.DeepEqual(answer, tt.want) {
				t.Errorf("got %v, want %v", answer, tt.want)
			}
		})
	}
}
