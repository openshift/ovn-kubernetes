package kubevirt

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var _ = Describe("Kubevirt", func() {
	type dhcpTest struct {
		cidrs                             []string
		controllerName, namespace, vmName string
		dns                               *corev1.Service
		expectedDHCPConfigs               libovsdbops.DHCPConfigs
		expectedError                     string
	}
	var (
		svc = func(namespace string, name string, clusterIPs []string) *corev1.Service {
			return &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "kube-system",
					Name:      "kube-dns",
				},
				Spec: corev1.ServiceSpec{
					ClusterIPs: clusterIPs,
				},
			}
		}
		parseCIDR = func(cidr string) *net.IPNet {
			_, parsedCIDR, err := net.ParseCIDR(cidr)
			Expect(err).ToNot(HaveOccurred())
			return parsedCIDR
		}
	)
	DescribeTable("composing dhcp options should success", func(t dhcpTest) {
		svcs := []corev1.Service{}
		if t.dns != nil {
			svcs = append(svcs, *t.dns)
		}
		fakeClient := &util.OVNMasterClientset{
			KubeClient: fake.NewSimpleClientset(&corev1.ServiceList{
				Items: svcs,
			}),
		}
		watcher, err := factory.NewMasterWatchFactory(fakeClient)
		Expect(err).NotTo(HaveOccurred())
		Expect(watcher.Start()).To(Succeed())

		cidrs := []*net.IPNet{}
		for _, cidr := range t.cidrs {
			cidrs = append(cidrs, parseCIDR(cidr))
		}
		obtainedDHCPConfigs, err := ComposeDHCPConfigs(watcher, t.controllerName, t.namespace, t.vmName, cidrs)
		Expect(err).ToNot(HaveOccurred())
		Expect(t.expectedDHCPConfigs.V4).To(Equal(obtainedDHCPConfigs.V4))
		Expect(t.expectedDHCPConfigs.V6).To(Equal(obtainedDHCPConfigs.V6))
	},
		Entry("IPv4 Single stack and k8s dns", dhcpTest{
			cidrs:               []string{"192.168.25.0/24"},
			controllerName:      "defaultController",
			namespace:           "namespace1",
			vmName:              "foo1",
			dns:                 svc("kube-system", "kube-dns", []string{"192.167.23.44"}),
			expectedDHCPConfigs: libovsdbops.DHCPConfigs{V4: ComposeDHCPv4Config("192.168.25.0/24", "192.167.23.44", "defaultController", "namespace1", "foo1")},
		}),
		Entry("IPv6 Single stack and k8s dns", dhcpTest{
			cidrs:               []string{"2002:0:0:1234::/64"},
			controllerName:      "defaultController",
			namespace:           "namespace1",
			vmName:              "foo1",
			dns:                 svc("kube-system", "kube-dns", []string{"2001:1:2:3:4:5:6:7"}),
			expectedDHCPConfigs: libovsdbops.DHCPConfigs{V6: ComposeDHCPv6Config("2002:0:0:1234::/64", "2001:1:2:3:4:5:6:7", "defaultController", "namespace1", "foo1")},
		}),
		Entry("Dual stack and k8s dns", dhcpTest{
			cidrs:          []string{"192.168.25.0/24", "2002:0:0:1234::/64"},
			controllerName: "defaultController",
			namespace:      "namespace1",
			vmName:         "foo1",
			dns:            svc("kube-system", "kube-dns", []string{"192.167.23.44", "2001:1:2:3:4:5:6:7"}),
			expectedDHCPConfigs: libovsdbops.DHCPConfigs{
				V4: ComposeDHCPv4Config("192.168.25.0/24", "192.167.23.44", "defaultController", "namespace1", "foo1"),
				V6: ComposeDHCPv6Config("2002:0:0:1234::/64", "2001:1:2:3:4:5:6:7", "defaultController", "namespace1", "foo1"),
			},
		}),
		Entry("Dual stack and k8s dns with ipv4 only", dhcpTest{
			cidrs:          []string{"192.168.25.0/24", "2002:0:0:1234::/64"},
			controllerName: "defaultController",
			namespace:      "namespace1",
			vmName:         "foo1",
			dns:            svc("kube-system", "kube-dns", []string{"192.167.23.44", ""}),
			expectedDHCPConfigs: libovsdbops.DHCPConfigs{
				V4: ComposeDHCPv4Config("192.168.25.0/24", "192.167.23.44", "defaultController", "namespace1", "foo1"),
				V6: ComposeDHCPv6Config("2002:0:0:1234::/64", "", "defaultController", "namespace1", "foo1"),
			},
		}),
	)

	DescribeTable("composing dhcp options should fail", func(t dhcpTest) {
		svcs := []corev1.Service{}
		if t.dns != nil {
			svcs = append(svcs, *t.dns)
		}
		fakeClient := &util.OVNMasterClientset{
			KubeClient: fake.NewSimpleClientset(&corev1.ServiceList{
				Items: svcs,
			}),
		}
		watcher, err := factory.NewMasterWatchFactory(fakeClient)
		Expect(err).NotTo(HaveOccurred())
		Expect(watcher.Start()).To(Succeed())

		cidrs := []*net.IPNet{}
		for _, cidr := range t.cidrs {
			cidrs = append(cidrs, parseCIDR(cidr))
		}
		_, err = ComposeDHCPConfigs(watcher, t.controllerName, t.namespace, t.vmName, cidrs)
		Expect(err).To(MatchError(t.expectedError))
	},
		Entry("No cidr should fail", dhcpTest{
			expectedError: "missing ips to compose dhcp options",
		}),
		Entry("No dns should fail", dhcpTest{
			vmName:        "vm1",
			cidrs:         []string{"192.168.3.0/24"},
			expectedError: `failed retrieving dns service cluster ip: service "kube-dns" not found`,
		}),
		Entry("No hostname should fail", dhcpTest{
			vmName:        "",
			cidrs:         []string{"192.168.25.0/24"},
			dns:           svc("kube-system", "kube-dns", []string{"192.167.23.44"}),
			expectedError: "missing vmName to compose dhcp options",
		}),
	)

})
