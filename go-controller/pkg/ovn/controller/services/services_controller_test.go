/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	utilpointer "k8s.io/utils/pointer"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	loadbalancerTCP = "a08ea426-2288-11eb-a30b-a8a1590cda29"
)

var alwaysReady = func() bool { return true }

var (
	ipv4only = []v1.IPFamily{v1.IPv4Protocol}
	ipv6only = []v1.IPFamily{v1.IPv6Protocol}
	ipv4ipv6 = []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol}
	ipv6ipv4 = []v1.IPFamily{v1.IPv6Protocol, v1.IPv4Protocol}
)

type serviceController struct {
	*Controller
	serviceStore       cache.Store
	endpointSliceStore cache.Store
}

func newController() *serviceController {
	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	controller := NewController(client,
		informerFactory.Core().V1().Services(),
		informerFactory.Discovery().V1beta1().EndpointSlices(),
	)
	controller.servicesSynced = alwaysReady
	controller.endpointSlicesSynced = alwaysReady
	return &serviceController{
		controller,
		informerFactory.Core().V1().Services().Informer().GetStore(),
		informerFactory.Discovery().V1beta1().EndpointSlices().Informer().GetStore(),
	}
}

func TestSyncServices(t *testing.T) {
	ns := "testns"
	serviceName := "foo"

	tests := []struct {
		name          string
		slice         *discovery.EndpointSlice
		service       *v1.Service
		updateTracker bool
		ovnCmd        []ovntest.ExpectedCmd
	}{
		{
			name: "delete OVN LoadBalancer from deleted Single Stack Service",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports:       []discovery.EndpointPort{},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints:   []discovery.Endpoint{},
			},
			service:       &v1.Service{},
			updateTracker: true,
			ovnCmd: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
					Output: loadbalancerTCP,
				},
				{
					Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips \"192.168.1.1:80\"",
					Output: "",
				},
			},
		},
		{
			name: "create OVN LoadBalancer from Single Stack Service without endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports:       []discovery.EndpointPort{},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints:   []discovery.Endpoint{},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:     80,
						Protocol: v1.ProtocolTCP,
					}},
				},
			},
			updateTracker: true,
			ovnCmd: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
					Output: loadbalancerTCP,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:80"=""`,
					Output: "",
				},
			},
		},
		{
			name: "create OVN LoadBalancer from Single Stack Service with endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{
					{
						Name:     utilpointer.StringPtr("tcp-example"),
						Protocol: protoPtr(v1.ProtocolTCP),
						Port:     utilpointer.Int32Ptr(int32(3456)),
					},
				},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Conditions: discovery.EndpointConditions{
							Ready: utilpointer.BoolPtr(true),
						},
						Addresses: []string{"10.0.0.2"},
						Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
					},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:     80,
						Protocol: v1.ProtocolTCP,
					}},
				},
			},
			updateTracker: false,
			ovnCmd: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
					Output: loadbalancerTCP,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:80"="10.0.0.2:3456"`,
					Output: "",
				},
			},
		},
		{
			name: "create OVN LoadBalancer from Dual Stack Service with dual stack endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{
					{
						Name:     utilpointer.StringPtr("tcp-example"),
						Protocol: protoPtr(v1.ProtocolTCP),
						Port:     utilpointer.Int32Ptr(int32(3456)),
					},
				},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Conditions: discovery.EndpointConditions{
							Ready: utilpointer.BoolPtr(true),
						},
						Addresses: []string{"10.0.0.2"},
						Topology:  map[string]string{"kubernetes.io/hostname": "node-1"},
					},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:     80,
						Protocol: v1.ProtocolTCP,
					}},
				},
			},
			updateTracker: false,
			ovnCmd: []ovntest.ExpectedCmd{
				{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
					Output: loadbalancerTCP,
				},
				{
					Cmd:    `ovn-nbctl --timeout=15 set load_balancer a08ea426-2288-11eb-a30b-a8a1590cda29 vips:"192.168.1.1:80"="10.0.0.2:3456"`,
					Output: "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newController()
			// Add objects to the Store
			controller.endpointSliceStore.Add(tt.slice)
			controller.serviceStore.Add(tt.service)
			if tt.updateTracker {
				controller.serviceTracker.updateKubernetesService(tt.service)
			}

			// Expected OVN commands
			fexec := ovntest.NewFakeExec()
			for _, cmd := range tt.ovnCmd {
				cmd := cmd
				fexec.AddFakeCmd(&cmd)
			}
			err := util.SetExec(fexec)
			if err != nil {
				t.Errorf("fexec error: %v", err)
			}

			controller.syncServices(ns + "/" + serviceName)
		})
	}
}

// protoPtr takes a Protocol and returns a pointer to it.
func protoPtr(proto v1.Protocol) *v1.Protocol {
	return &proto
}
