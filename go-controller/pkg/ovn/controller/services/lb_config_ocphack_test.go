package services

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	globalconfig "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

// OCP hack begin

func Test_buildPerNodeLBs_OCPHackForDNS(t *testing.T) {
	oldClusterSubnet := globalconfig.Default.ClusterSubnets
	oldGwMode := globalconfig.Gateway.Mode
	oldIPv4Mode := globalconfig.IPv4Mode
	defer func() {
		globalconfig.Gateway.Mode = oldGwMode
		globalconfig.Default.ClusterSubnets = oldClusterSubnet
		globalconfig.IPv4Mode = oldIPv4Mode
	}()
	_, cidr4, _ := net.ParseCIDR("10.128.0.0/16")
	_, cidr6, _ := net.ParseCIDR("fe00::/64")
	globalconfig.Default.ClusterSubnets = []globalconfig.CIDRNetworkEntry{{CIDR: cidr4, HostSubnetLength: 26}, {CIDR: cidr6, HostSubnetLength: 26}}
	globalconfig.IPv4Mode = true

	name := "dns-default"
	namespace := "openshift-dns"

	UDNNetInfo, err := getSampleUDNNetInfo(namespace, types.Layer3Topology)
	if err != nil {
		panic(err)
	}

	defaultService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	defaultNodes := []nodeInfo{
		{
			name:              nodeA,
			hostAddresses:     []net.IP{net.ParseIP("10.0.0.1")},
			gatewayRouterName: "gr-node-a",
			switchName:        "switch-node-a",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("10.128.0.0"), Mask: net.CIDRMask(24, 32)}},
		},
		{
			name:              nodeB,
			hostAddresses:     []net.IP{net.ParseIP("10.0.0.2")},
			gatewayRouterName: "gr-node-b",
			switchName:        "switch-node-b",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("10.128.1.0"), Mask: net.CIDRMask(24, 32)}},
		},
	}

	defaultExternalIDs := map[string]string{
		"k8s.ovn.org/kind":  "Service",
		"k8s.ovn.org/owner": fmt.Sprintf("%s/%s", namespace, name),
	}

	UDNExternalIDs := loadBalancerExternalIDsForNetwork(namespacedServiceName(namespace, name), UDNNetInfo.GetNetworkName())

	//defaultRouters := []string{"gr-node-a", "gr-node-b"}
	//defaultSwitches := []string{"switch-node-a", "switch-node-b"}

	defaultOpts := LBOpts{Reject: true}

	tc := []struct {
		name     string
		service  *corev1.Service
		configs  []lbConfig
		expected []LB
	}{
		{
			name:    "clusterIP service, standard pods",
			service: defaultService,
			configs: []lbConfig{
				{
					vips:     []string{"192.168.1.1"},
					protocol: corev1.ProtocolTCP,
					inport:   80,
					clusterEndpoints: util.LBEndpoints{{
						V4IPs: []string{"10.128.0.2", "10.128.1.2"},
						Port:  8080,
					}},
				},
			},
			expected: []LB{
				{
					// Router and switch have same local-only target per node — merged into one LB.
					Name:        "Service_openshift-dns/dns-default_TCP_node_router+switch_node-a",
					ExternalIDs: defaultExternalIDs,
					Routers:     []string{"gr-node-a"},
					Switches:    []string{"switch-node-a"},
					Protocol:    "TCP",
					Rules: []LBRule{
						{
							Source:  Addr{"192.168.1.1", 80, nil},
							Targets: []Addr{{"10.128.0.2", 8080, nil}},
						},
					},
					Opts: defaultOpts,
				},
				{
					Name:        "Service_openshift-dns/dns-default_TCP_node_router+switch_node-b",
					ExternalIDs: defaultExternalIDs,
					Routers:     []string{"gr-node-b"},
					Switches:    []string{"switch-node-b"},
					Protocol:    "TCP",
					Rules: []LBRule{
						{
							Source:  Addr{"192.168.1.1", 80, nil},
							Targets: []Addr{{"10.128.1.2", 8080, nil}},
						},
					},
					Opts: defaultOpts,
				},
			},
		},
		{
			// dns-default with no local endpoint on node-a — uses two endpoints so node-a
			// and node-b produce genuinely different targets, proving fallback returns all
			// endpoints rather than empty. node-a has no local endpoint (neither is in
			// 10.128.0.0/24); node-b has 10.128.1.2 locally.
			name:    "dns-default service, no local endpoint on node-a, router fallback to all",
			service: defaultService,
			configs: []lbConfig{
				{
					vips:     []string{"192.168.1.1"},
					protocol: corev1.ProtocolTCP,
					inport:   80,
					clusterEndpoints: util.LBEndpoints{{
						V4IPs: []string{"10.128.1.2", "10.128.2.2"},
						Port:  8080,
					}},
				},
			},
			expected: []LB{
				{
					// node-a: no local endpoint for either router or switch → both fall back
					// to all endpoints and are merged into one router+switch LB.
					Name:        "Service_openshift-dns/dns-default_TCP_node_router+switch_node-a",
					ExternalIDs: defaultExternalIDs,
					Routers:     []string{"gr-node-a"},
					Switches:    []string{"switch-node-a"},
					Protocol:    "TCP",
					Rules: []LBRule{
						{
							Source:  Addr{"192.168.1.1", 80, nil},
							Targets: []Addr{{"10.128.1.2", 8080, nil}, {"10.128.2.2", 8080, nil}},
						},
					},
					Opts: defaultOpts,
				},
				{
					// node-b: 10.128.1.2 is local → router+switch both get local target only.
					Name:        "Service_openshift-dns/dns-default_TCP_node_router+switch_node-b",
					ExternalIDs: defaultExternalIDs,
					Routers:     []string{"gr-node-b"},
					Switches:    []string{"switch-node-b"},
					Protocol:    "TCP",
					Rules: []LBRule{
						{
							Source:  Addr{"192.168.1.1", 80, nil},
							Targets: []Addr{{"10.128.1.2", 8080, nil}},
						},
					},
					Opts: defaultOpts,
				},
			},
		},
	}

	for i, tt := range tc {
		t.Run(fmt.Sprintf("%d_%s", i, tt.name), func(t *testing.T) {

			globalconfig.Gateway.Mode = globalconfig.GatewayModeShared
			actual := buildPerNodeLBs(tt.service, tt.configs, defaultNodes, &util.DefaultNetInfo{})
			assert.Equal(t, tt.expected, actual, "shared gateway mode not as expected")

			globalconfig.Gateway.Mode = globalconfig.GatewayModeLocal
			actual = buildPerNodeLBs(tt.service, tt.configs, defaultNodes, &util.DefaultNetInfo{})
			assert.Equal(t, tt.expected, actual, "local gateway mode not as expected")

			// UDN
			for idx := range tt.expected {
				tt.expected[idx].ExternalIDs = UDNExternalIDs
				tt.expected[idx].Name = UDNNetInfo.GetNetworkScopedLoadBalancerName(tt.expected[idx].Name)

			}
			globalconfig.Gateway.Mode = globalconfig.GatewayModeShared
			actual = buildPerNodeLBs(tt.service, tt.configs, defaultNodes, UDNNetInfo)
			assert.Equal(t, tt.expected, actual, "shared gateway mode not as expected")

			globalconfig.Gateway.Mode = globalconfig.GatewayModeLocal
			actual = buildPerNodeLBs(tt.service, tt.configs, defaultNodes, UDNNetInfo)
			assert.Equal(t, tt.expected, actual, "local gateway mode not as expected")

		})
	}
}

func Test_buildPerNodeLBs_OCPHackForLocalWithFallback(t *testing.T) {
	oldClusterSubnet := globalconfig.Default.ClusterSubnets
	oldGwMode := globalconfig.Gateway.Mode
	oldIPv4Mode := globalconfig.IPv4Mode
	defer func() {
		globalconfig.Gateway.Mode = oldGwMode
		globalconfig.Default.ClusterSubnets = oldClusterSubnet
		globalconfig.IPv4Mode = oldIPv4Mode
	}()
	_, cidr4, _ := net.ParseCIDR("10.128.0.0/16")
	globalconfig.Default.ClusterSubnets = []globalconfig.CIDRNetworkEntry{{CIDR: cidr4, HostSubnetLength: 26}}
	globalconfig.IPv4Mode = true

	name := "router-default"
	namespace := "openshift-ingress"
	inport := int32(80)
	outport := int32(8080)

	UDNNetInfo, _ := getSampleUDNNetInfo(namespace, types.Layer3Topology)

	defaultService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{localWithFallbackAnnotation: ""}, // code checks for this annotation
		},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyTypeLocal,
			// add ingress IP
			ClusterIP:  "192.168.1.1",
			ClusterIPs: []string{"192.168.1.1"},
			Ports: []corev1.ServicePort{ // don't consider https for simplicity
				{
					Name:       "http",
					Port:       80,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(80),
					NodePort:   5,
				},
			},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{
					IP: "5.5.5.5",
				}},
			},
		},
	}

	defaultNodes := []nodeInfo{
		{
			name:              nodeA,
			hostAddresses:     []net.IP{net.ParseIP("10.0.0.1")},
			gatewayRouterName: "gr-node-a",
			switchName:        "switch-node-a",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("10.128.0.0"), Mask: net.CIDRMask(24, 32)}},
		},
		{
			name:              nodeB,
			hostAddresses:     []net.IP{net.ParseIP("10.0.0.2")},
			gatewayRouterName: "gr-node-b",
			switchName:        "switch-node-b",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("10.128.1.0"), Mask: net.CIDRMask(24, 32)}},
		},
	}

	defaultExternalIDs := map[string]string{
		"k8s.ovn.org/kind":  "Service",
		"k8s.ovn.org/owner": fmt.Sprintf("%s/%s", namespace, name),
	}

	UDNExternalIDs := loadBalancerExternalIDsForNetwork(namespacedServiceName(namespace, name), UDNNetInfo.GetNetworkName())

	defaultOpts := LBOpts{Reject: true}
	noSNATOpts := LBOpts{SkipSNAT: true, Reject: true}

	tc := []struct {
		name     string
		service  *corev1.Service
		configs  []lbConfig
		expected []LB
	}{
		{
			name:    "Load Balancer service with ETP local and local-with-fallback annotation, ovn-networked endpoints, all endpoints are up: no fallback",
			service: defaultService,
			configs: []lbConfig{
				{
					vips:                 []string{"node"}, //  placeholder for node IP
					protocol:             corev1.ProtocolTCP,
					inport:               5, // node port
					externalTrafficLocal: true,
					hasNodePort:          true,
					clusterEndpoints: []util.LBEndpointEntry{{
						V4IPs: []string{"10.128.0.2", "10.128.1.2"},
						Port:  outport,
					}},
					nodeEndpoints: map[string]util.LBEndpoints{
						nodeA: {{V4IPs: []string{"10.128.0.2"}, Port: outport}},
						nodeB: {{V4IPs: []string{"10.128.1.2"}, Port: outport}},
					},
				},
				{
					vips:                 []string{"5.5.5.5"}, // external VIP
					protocol:             corev1.ProtocolTCP,
					inport:               inport,
					externalTrafficLocal: true,
					clusterEndpoints: []util.LBEndpointEntry{
						{
							V4IPs: []string{"10.128.0.2", "10.128.1.2"},
							Port:  outport,
						},
					},
					nodeEndpoints: map[string]util.LBEndpoints{
						nodeA: {{V4IPs: []string{"10.128.0.2"}, Port: outport}},
						nodeB: {{V4IPs: []string{"10.128.1.2"}, Port: outport}},
					},
				},
			},
			expected: []LB{
				{
					Name:        "Service_openshift-ingress/router-default_TCP_node_local_router_node-a",
					Protocol:    "TCP",
					ExternalIDs: defaultExternalIDs,
					Opts:        noSNATOpts,
					Routers:     []string{"gr-node-a"},
					Rules: []LBRule{
						{
							Source:  Addr{IP: "10.0.0.1", Port: 5},
							Targets: []Addr{{IP: "10.128.0.2", Port: 8080}}},
						{
							Source:  Addr{IP: "5.5.5.5", Port: 80},
							Targets: []Addr{{IP: "10.128.0.2", Port: 8080}}}},
				},
				{
					Name:        "Service_openshift-ingress/router-default_TCP_node_switch_node-a",
					Protocol:    "TCP",
					ExternalIDs: defaultExternalIDs,
					Opts:        defaultOpts,
					Switches:    []string{"switch-node-a"},
					Rules: []LBRule{
						{
							Source:  Addr{IP: "169.254.169.3", Port: 5},
							Targets: []Addr{{IP: "10.128.0.2", Port: 8080}}},
						{
							Source:  Addr{IP: "10.0.0.1", Port: 5},
							Targets: []Addr{{IP: "10.128.0.2", Port: 8080}, {IP: "10.128.1.2", Port: 8080}}},
						{
							Source:  Addr{IP: "5.5.5.5", Port: 80},
							Targets: []Addr{{IP: "10.128.0.2", Port: 8080}, {IP: "10.128.1.2", Port: 8080}}}},
				},
				{
					Name:        "Service_openshift-ingress/router-default_TCP_node_local_router_node-b",
					Protocol:    "TCP",
					ExternalIDs: defaultExternalIDs,
					Opts:        noSNATOpts,
					Routers:     []string{"gr-node-b"},
					Rules: []LBRule{
						{
							Source:  Addr{IP: "10.0.0.2", Port: 5},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}},
						{
							Source:  Addr{IP: "5.5.5.5", Port: 80},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}}},
				},
				{
					Name:        "Service_openshift-ingress/router-default_TCP_node_switch_node-b",
					Protocol:    "TCP",
					ExternalIDs: defaultExternalIDs,
					Opts:        defaultOpts,
					Rules: []LBRule{
						{
							Source:  Addr{IP: "169.254.169.3", Port: 5},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}},
						{
							Source:  Addr{IP: "10.0.0.2", Port: 5},
							Targets: []Addr{{IP: "10.128.0.2", Port: 8080}, {IP: "10.128.1.2", Port: 8080}}},
						{
							Source:  Addr{IP: "5.5.5.5", Port: 80},
							Targets: []Addr{{IP: "10.128.0.2", Port: 8080}, {IP: "10.128.1.2", Port: 8080}}}},
					Switches: []string{"switch-node-b"},
				},
			},
		},
		{
			name:    "Load Balancer service with ETP local and local-with-fallback annotation, ovn-networked endpoints, endpoint on node-a is down: fallback to ETP Cluster",
			service: defaultService,
			configs: []lbConfig{
				{
					vips:                 []string{"node"}, //  placeholder for node IP
					protocol:             corev1.ProtocolTCP,
					inport:               5, // node port
					externalTrafficLocal: true,
					hasNodePort:          true,
					clusterEndpoints: util.LBEndpoints{{
						V4IPs: []string{"10.128.1.2"}, // only endpoint on node-b is running
						Port:  outport,
					}},
					nodeEndpoints: map[string]util.LBEndpoints{
						nodeB: {{V4IPs: []string{"10.128.1.2"}, Port: outport}},
					},
				},
				{
					vips:                 []string{"5.5.5.5"}, // external VIP
					protocol:             corev1.ProtocolTCP,
					inport:               inport,
					externalTrafficLocal: true,
					clusterEndpoints: util.LBEndpoints{{
						V4IPs: []string{"10.128.1.2"},
						Port:  outport,
					}},
					nodeEndpoints: map[string]util.LBEndpoints{
						nodeB: {{V4IPs: []string{"10.128.1.2"}, Port: outport}},
					},
				},
			},
			expected: []LB{
				{
					Name:        "Service_openshift-ingress/router-default_TCP_node_router_node-a", // fallback, because no local endpoints left
					Protocol:    "TCP",
					ExternalIDs: defaultExternalIDs,
					Opts:        defaultOpts,
					Routers:     []string{"gr-node-a"},
					Rules: []LBRule{
						{
							Source:  Addr{IP: "10.0.0.1", Port: 5},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}, // forwarding to endpoint on node-b, as if ETP=Cluster
						},
						{
							Source:  Addr{IP: "5.5.5.5", Port: 80},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}, // forwarding to endpoint on node-b, as if ETP=Cluster
						},
					},
				},
				{
					Name:        "Service_openshift-ingress/router-default_TCP_node_switch_node-a",
					Protocol:    "TCP",
					ExternalIDs: defaultExternalIDs,
					Opts:        defaultOpts,
					Switches:    []string{"switch-node-a"},
					Rules: []LBRule{
						{
							Source:  Addr{IP: "169.254.169.3", Port: 5},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}},
						{
							Source:  Addr{IP: "10.0.0.1", Port: 5},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}},
						{
							Source:  Addr{IP: "5.5.5.5", Port: 80},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}}},
				},

				{
					Name:        "Service_openshift-ingress/router-default_TCP_node_local_router_node-b",
					Protocol:    "TCP",
					ExternalIDs: defaultExternalIDs,
					Opts:        noSNATOpts,
					Rules: []LBRule{
						{
							Source:  Addr{IP: "10.0.0.2", Port: 5},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}}, // endpoint is on node-b, so eTP=local is respected
						{
							Source:  Addr{IP: "5.5.5.5", Port: 80},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}}}, // endpoint is on node-b, so eTP=local is respected
					Switches: []string(nil), Routers: []string{"gr-node-b"},
				},
				{
					Name:        "Service_openshift-ingress/router-default_TCP_node_switch_node-b",
					UUID:        "",
					Protocol:    "TCP",
					ExternalIDs: defaultExternalIDs,
					Opts:        defaultOpts,
					Rules: []LBRule{
						{
							Source:  Addr{IP: "169.254.169.3", Port: 5},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}},
						{
							Source:  Addr{IP: "10.0.0.2", Port: 5},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}},
						{
							Source:  Addr{IP: "5.5.5.5", Port: 80},
							Targets: []Addr{{IP: "10.128.1.2", Port: 8080}}}},
					Switches: []string{"switch-node-b"},
				},
			},
		},
	}

	for i, tt := range tc {
		t.Run(fmt.Sprintf("%d_%s", i, tt.name), func(t *testing.T) {

			globalconfig.Gateway.Mode = globalconfig.GatewayModeShared
			actual := buildPerNodeLBs(tt.service, tt.configs, defaultNodes, &util.DefaultNetInfo{})
			assert.Equal(t, tt.expected, actual, "shared gateway mode not as expected")

			globalconfig.Gateway.Mode = globalconfig.GatewayModeLocal
			actual = buildPerNodeLBs(tt.service, tt.configs, defaultNodes, &util.DefaultNetInfo{})
			assert.Equal(t, tt.expected, actual, "local gateway mode not as expected")

			// UDN
			for idx := range tt.expected {
				tt.expected[idx].ExternalIDs = UDNExternalIDs
				tt.expected[idx].Name = UDNNetInfo.GetNetworkScopedLoadBalancerName(tt.expected[idx].Name)

			}
			globalconfig.Gateway.Mode = globalconfig.GatewayModeShared
			actual = buildPerNodeLBs(tt.service, tt.configs, defaultNodes, UDNNetInfo)
			assert.Equal(t, tt.expected, actual, "shared gateway mode not as expected")

			globalconfig.Gateway.Mode = globalconfig.GatewayModeLocal
			actual = buildPerNodeLBs(tt.service, tt.configs, defaultNodes, UDNNetInfo)
			assert.Equal(t, tt.expected, actual, "local gateway mode not as expected")
		})
	}
}

// Test_buildPerNodeLBs_OCPHackForDNS_IPv6 verifies that the preferLocal router-target filtering
// works for IPv6: local IPv6 endpoint is preferred per node; fallback to all when no local endpoint.
func Test_buildPerNodeLBs_OCPHackForDNS_IPv6(t *testing.T) {
	oldClusterSubnet := globalconfig.Default.ClusterSubnets
	oldGwMode := globalconfig.Gateway.Mode
	oldIPv4Mode := globalconfig.IPv4Mode
	oldIPv6Mode := globalconfig.IPv6Mode
	defer func() {
		globalconfig.Gateway.Mode = oldGwMode
		globalconfig.Default.ClusterSubnets = oldClusterSubnet
		globalconfig.IPv4Mode = oldIPv4Mode
		globalconfig.IPv6Mode = oldIPv6Mode
	}()
	_, cidr6, _ := net.ParseCIDR("fd00::/48")
	globalconfig.Default.ClusterSubnets = []globalconfig.CIDRNetworkEntry{{CIDR: cidr6, HostSubnetLength: 64}}
	globalconfig.IPv4Mode = false
	globalconfig.IPv6Mode = true
	globalconfig.Gateway.Mode = globalconfig.GatewayModeShared

	nodes := []nodeInfo{
		{
			name:              nodeA,
			hostAddresses:     []net.IP{net.ParseIP("fd00::1")},
			gatewayRouterName: "gr-node-a",
			switchName:        "switch-node-a",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(64, 128)}},
		},
		{
			name:              nodeB,
			hostAddresses:     []net.IP{net.ParseIP("fd00:0:0:1::1")},
			gatewayRouterName: "gr-node-b",
			switchName:        "switch-node-b",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("fd00:0:0:1::"), Mask: net.CIDRMask(64, 128)}},
		},
		{
			// node-c has no endpoint in its subnet — exercises the fallback path.
			name:              "node-c",
			hostAddresses:     []net.IP{net.ParseIP("fd00:0:0:2::1")},
			gatewayRouterName: "gr-node-c",
			switchName:        "switch-node-c",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("fd00:0:0:2::"), Mask: net.CIDRMask(64, 128)}},
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "dns-default", Namespace: "openshift-dns"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
	}
	configs := []lbConfig{
		{
			vips:     []string{"fd10::10"},
			protocol: corev1.ProtocolTCP,
			inport:   53,
			clusterEndpoints: util.LBEndpoints{{
				V6IPs: []string{"fd00::2", "fd00:0:0:1::2"},
				Port:  5353,
			}},
		},
	}

	actual := buildPerNodeLBs(svc, configs, nodes, &util.DefaultNetInfo{})

	// 3 per-node LBs: node-a and node-b get local-only targets; node-c has no local
	// endpoint so both router and switch fall back to all endpoints.
	assert.Len(t, actual, 3)
	// node-a: local fd00::2 only.
	assert.Equal(t, []string{"gr-node-a"}, actual[0].Routers)
	assert.Equal(t, []Addr{{"fd00::2", 5353, nil}}, actual[0].Rules[0].Targets)
	// node-b: local fd00:0:0:1::2 only.
	assert.Equal(t, []string{"gr-node-b"}, actual[1].Routers)
	assert.Equal(t, []Addr{{"fd00:0:0:1::2", 5353, nil}}, actual[1].Rules[0].Targets)
	// node-c: no local endpoint — fallback returns all endpoints.
	assert.Equal(t, []string{"gr-node-c"}, actual[2].Routers)
	assert.ElementsMatch(t, []Addr{{"fd00::2", 5353, nil}, {"fd00:0:0:1::2", 5353, nil}}, actual[2].Rules[0].Targets)
}

// Test_buildPerNodeLBs_OCPHackForDNS_NonDNSService verifies that the router-target preferLocal
// logic is scoped strictly to the dns-default service and does not affect other services in the
// same namespace.
func Test_buildPerNodeLBs_OCPHackForDNS_NonDNSService(t *testing.T) {
	oldClusterSubnet := globalconfig.Default.ClusterSubnets
	oldGwMode := globalconfig.Gateway.Mode
	oldIPv4Mode := globalconfig.IPv4Mode
	defer func() {
		globalconfig.Gateway.Mode = oldGwMode
		globalconfig.Default.ClusterSubnets = oldClusterSubnet
		globalconfig.IPv4Mode = oldIPv4Mode
	}()
	_, cidr4, _ := net.ParseCIDR("10.128.0.0/16")
	globalconfig.Default.ClusterSubnets = []globalconfig.CIDRNetworkEntry{{CIDR: cidr4, HostSubnetLength: 26}}
	globalconfig.IPv4Mode = true
	globalconfig.Gateway.Mode = globalconfig.GatewayModeShared

	nodes := []nodeInfo{
		{
			name:              nodeA,
			hostAddresses:     []net.IP{net.ParseIP("10.0.0.1")},
			gatewayRouterName: "gr-node-a",
			switchName:        "switch-node-a",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("10.128.0.0"), Mask: net.CIDRMask(24, 32)}},
		},
		{
			name:              nodeB,
			hostAddresses:     []net.IP{net.ParseIP("10.0.0.2")},
			gatewayRouterName: "gr-node-b",
			switchName:        "switch-node-b",
			podSubnets:        []net.IPNet{{IP: net.ParseIP("10.128.1.0"), Mask: net.CIDRMask(24, 32)}},
		},
	}

	// A non-dns service in openshift-dns: router preferLocal must not apply.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "node-resolver", Namespace: "openshift-dns"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
	}
	configs := []lbConfig{
		{
			vips:     []string{"192.168.1.2"},
			protocol: corev1.ProtocolTCP,
			inport:   80,
			clusterEndpoints: util.LBEndpoints{{
				V4IPs: []string{"10.128.0.2", "10.128.1.2"},
				Port:  8080,
			}},
		},
	}

	actual := buildPerNodeLBs(svc, configs, nodes, &util.DefaultNetInfo{})

	// Expect one merged LB — router and switch both have all endpoints (no preferLocal).
	assert.Len(t, actual, 1)
	assert.Equal(t, []string{"gr-node-a", "gr-node-b"}, actual[0].Routers)
	assert.Equal(t, []string{"switch-node-a", "switch-node-b"}, actual[0].Switches)
	assert.Equal(t, []Addr{{"10.128.0.2", 8080, nil}, {"10.128.1.2", 8080, nil}}, actual[0].Rules[0].Targets)
}

// OCP hack end
