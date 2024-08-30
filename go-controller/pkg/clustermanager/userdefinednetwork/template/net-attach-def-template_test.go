package template

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	netv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	udnv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
)

var _ = Describe("NetAttachDefTemplate", func() {
	const udnTypeName = "UserDefinedNetwork"

	var udnApiVersion = udnv1.SchemeGroupVersion.String()

	DescribeTable("should fail given",
		func(spec *udnv1.UserDefinedNetworkSpec) {
			udn := &udnv1.UserDefinedNetwork{
				ObjectMeta: metav1.ObjectMeta{Namespace: "mynamespace", Name: "test-net", UID: "1"},
				Spec:       *spec,
			}
			_, err := RenderNetAttachDefManifest(udn)
			Expect(err).To(HaveOccurred())
		},
		Entry("invalid topology: topology layer2 & layer3 config",
			&udnv1.UserDefinedNetworkSpec{Topology: udnv1.NetworkTopologyLayer2, Layer3: &udnv1.Layer3Config{}},
		),
		Entry("invalid topology: topology layer3 & layer2 config",
			&udnv1.UserDefinedNetworkSpec{Topology: udnv1.NetworkTopologyLayer3, Layer2: &udnv1.Layer2Config{}},
		),
		Entry("invalid layer2 subnets",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Subnets: udnv1.DualStackCIDRs{"abc"},
				},
			},
		),
		Entry("invalid layer3 cluster-subnet",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer3,
				Layer3: &udnv1.Layer3Config{
					Subnets: []udnv1.Layer3Subnet{{CIDR: "!", HostSubnet: 16}},
				},
			},
		),
		Entry("invalid layer3 host-subnet mask",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer3,
				Layer3: &udnv1.Layer3Config{
					Subnets: []udnv1.Layer3Subnet{
						{CIDR: "10.10.0.0/24", HostSubnet: -1},
					},
				},
			},
		),
		Entry("layer3 host-subnet mask is smaller then cluster-subnet mask",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer3,
				Layer3: &udnv1.Layer3Config{
					Subnets: []udnv1.Layer3Subnet{
						{CIDR: "10.10.0.0/24", HostSubnet: 16},
					},
				},
			},
		),
		Entry("layer3 host-subnet mask equal to cluster-subnet mask",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer3,
				Layer3: &udnv1.Layer3Config{
					Subnets: []udnv1.Layer3Subnet{
						{CIDR: "10.10.0.0/24", HostSubnet: 24},
					},
				},
			},
		),
		Entry("layer3 host-subnet mask is smaller then cluster-subnet mask",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer3,
				Layer3: &udnv1.Layer3Config{
					Subnets: []udnv1.Layer3Subnet{
						{CIDR: "10.10.0.0/16", HostSubnet: 8},
					},
				},
			},
		),
		Entry("invalid layer3 host-subnet; IPv4 mask is bigger then 32",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer3,
				Layer3: &udnv1.Layer3Config{
					Subnets: []udnv1.Layer3Subnet{
						{CIDR: "10.10.0.0/24", HostSubnet: 33},
					},
				},
			},
		),
		Entry("invalid join subnets",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"abc"},
				},
			},
		),
		Entry("invalid dual-stack join subnets, invalid IPv4 CIDR",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"!", "fd50::0/125"},
				},
			},
		),
		Entry("invalid dual-stack join subnets, invalid IPv6 CIDR",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"10.10.0.0/24", "!"},
				},
			},
		),
		Entry("invalid dual-stack join subnets, multiple valid IPv4 CIDRs",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"10.10.0.0/24", "10.20.0.0/24", "10.30.0.0/24"},
				},
			},
		),
		Entry("invalid dual-stack join subnets, multiple valid IPv6 CIDRs",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"fd40::0/125", "fd10::0/125", "fd50::0/125"},
				},
			},
		),
		Entry("invalid dual-stack join subnets, multiple valid IPv4 & IPv6 CIDRs",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"fd40::0/125", "10.10.0.0/24", "fd50::0/125", "10.20.0.0/24"},
				},
			},
		),
		Entry("invalid join subnets, overlapping with cluster-default join-subnet, IPv4",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"100.64.10.0/24"},
				},
			},
		),
		Entry("invalid join subnets, overlapping with cluster-default join-subnet, IPv6",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"fd98::4/127"},
				},
			},
		),
		Entry("invalid join subnets, overlapping with cluster-default join-subnet, dual-stack",
			&udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:        udnv1.NetworkRolePrimary,
					JoinSubnets: udnv1.DualStackCIDRs{"100.64.10.0/24", "fd98::4/127"},
				},
			},
		),
	)

	It("should return nil given no NAD", func() {
		_, err := RenderNetAttachDefManifest(nil)
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("should create net attach from spec",
		func(testSpec udnv1.UserDefinedNetworkSpec, expectedNadNetConf string) {
			testUdn := &udnv1.UserDefinedNetwork{
				ObjectMeta: metav1.ObjectMeta{Namespace: "mynamespace", Name: "test-net", UID: "1"},
				Spec:       testSpec,
			}
			ownerRef := metav1.OwnerReference{
				APIVersion:         udnApiVersion,
				Kind:               udnTypeName,
				Name:               "test-net",
				UID:                "1",
				BlockOwnerDeletion: pointer.Bool(true),
				Controller:         pointer.Bool(true),
			}
			expectedNAD := &netv1.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "test-net",
					Labels:          map[string]string{"k8s.ovn.org/user-defined-network": ""},
					OwnerReferences: []metav1.OwnerReference{ownerRef},
					Finalizers:      []string{"k8s.ovn.org/user-defined-network-protection"},
				},
				Spec: netv1.NetworkAttachmentDefinitionSpec{Config: expectedNadNetConf},
			}

			nad, err := RenderNetAttachDefManifest(testUdn)
			Expect(err).NotTo(HaveOccurred())
			Expect(nad.TypeMeta).To(Equal(expectedNAD.TypeMeta))
			Expect(nad.ObjectMeta).To(Equal(expectedNAD.ObjectMeta))
			Expect(nad.Spec.Config).To(MatchJSON(expectedNAD.Spec.Config))
		},
		Entry("primary network, layer3",
			udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer3,
				Layer3: &udnv1.Layer3Config{
					Role: udnv1.NetworkRolePrimary,
					Subnets: []udnv1.Layer3Subnet{
						{CIDR: "192.168.100.0/16"},
						{CIDR: "2001:dbb::/60"},
					},
					MTU: 1500,
				},
			},
			`{
				"cniVersion": "1.0.0",
				"type": "ovn-k8s-cni-overlay",
				"name": "mynamespace.test-net",
				"netAttachDefName": "mynamespace/test-net",
				"role": "primary",
				"topology": "layer3",
				"joinSubnets": "100.65.0.0/16,fd99::/64",
				"subnets": "192.168.100.0/16,2001:dbb::/60",
				"mtu": 1500
			}`,
		),
		Entry("primary network, layer2",
			udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:          udnv1.NetworkRolePrimary,
					Subnets:       udnv1.DualStackCIDRs{"192.168.100.0/24", "2001:dbb::/64"},
					MTU:           1500,
					IPAMLifecycle: udnv1.IPAMLifecyclePersistent,
				},
			},
			`{
			  "cniVersion": "1.0.0",
			  "type": "ovn-k8s-cni-overlay",
			  "name": "mynamespace.test-net",
			  "netAttachDefName": "mynamespace/test-net",
			  "role": "primary",
			  "topology": "layer2",
			  "joinSubnets": "100.65.0.0/16,fd99::/64",
			  "subnets": "192.168.100.0/24,2001:dbb::/64",
			  "mtu": 1500,
			  "allowPersistentIPs": true
        	}`,
		),
		Entry("primary network, should override join-subnets when specified",
			udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:          udnv1.NetworkRolePrimary,
					Subnets:       udnv1.DualStackCIDRs{"192.168.100.0/24", "2001:dbb::/64"},
					JoinSubnets:   udnv1.DualStackCIDRs{"100.62.0.0/24", "fd92::/64"},
					MTU:           1500,
					IPAMLifecycle: udnv1.IPAMLifecyclePersistent,
				},
			},
			`{
			  "cniVersion": "1.0.0",
			  "type": "ovn-k8s-cni-overlay",
			  "name": "mynamespace.test-net",
			  "netAttachDefName": "mynamespace/test-net",
			  "role": "primary",
			  "topology": "layer2",
			  "joinSubnets": "100.62.0.0/24,fd92::/64",
			  "subnets": "192.168.100.0/24,2001:dbb::/64",
			  "mtu": 1500,
			  "allowPersistentIPs": true
			}`,
		),
		Entry("secondary network, no join-subnets should be set",
			udnv1.UserDefinedNetworkSpec{
				Topology: udnv1.NetworkTopologyLayer2,
				Layer2: &udnv1.Layer2Config{
					Role:          udnv1.NetworkRoleSecondary,
					Subnets:       udnv1.DualStackCIDRs{"192.168.100.0/24", "2001:dbb::/64"},
					MTU:           1500,
					IPAMLifecycle: udnv1.IPAMLifecyclePersistent,
				},
			},
			`{
			  "cniVersion": "1.0.0",
			  "type": "ovn-k8s-cni-overlay",
			  "name": "mynamespace.test-net",
			  "netAttachDefName": "mynamespace/test-net",
			  "role": "secondary",
			  "topology": "layer2",
			  "subnets": "192.168.100.0/24,2001:dbb::/64",
			  "mtu": 1500,
			  "allowPersistentIPs": true
			}`,
		),
	)
})
