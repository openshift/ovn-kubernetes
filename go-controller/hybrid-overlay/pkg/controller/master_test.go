package controller

import (
	"net"

	"github.com/urfave/cli"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func mustParseCIDR(cidr string) *net.IPNet {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("bad CIDR string constant " + cidr)
	}
	return net
}

var _ = Describe("Hybrid SDN Master Operations", func() {
	var app *cli.App

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.RestoreDefaultConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
	})

	const extIPNet string = "11.1.0.0"

	extCIDR := []config.CIDRNetworkEntry{
		{
			CIDR:             mustParseCIDR(extIPNet + "/16"),
			HostSubnetLength: 24,
		},
	}

	It("allocates and assigns an hybrid-overlay HostSubnet to a Windows node that doesn't have one", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName   string = "node1"
				nodeSubnet string = "11.1.0.0/24"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					{ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
						Labels: map[string]string{
							v1.LabelOSStable: "windows",
						},
					}},
				},
			})

			fexec := ovntest.NewFakeExec()
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			stopChan := make(chan struct{})
			f, err := factory.NewWatchFactory(fakeClient, stopChan)
			Expect(err).NotTo(HaveOccurred())
			defer f.Shutdown()

			m, err := NewMaster(fakeClient, extCIDR)
			Expect(err).NotTo(HaveOccurred())

			err = m.Start(f, stopChan)
			Expect(err).NotTo(HaveOccurred())

			// Windows node should be allocated a subnet
			updatedNode, err := fakeClient.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedNode.Annotations).To(HaveKeyWithValue(types.HybridOverlayHostSubnet, nodeSubnet))
			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})

	It("ignores a Linux node without an OVN hostsubnet annotation", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName string = "node1"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					{ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
						Labels: map[string]string{
							v1.LabelOSStable: "linux",
						},
					}},
				},
			})

			fexec := ovntest.NewFakeExec()
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			stopChan := make(chan struct{})
			f, err := factory.NewWatchFactory(fakeClient, stopChan)
			Expect(err).NotTo(HaveOccurred())
			defer f.Shutdown()

			m, err := NewMaster(fakeClient, extCIDR)
			Expect(err).NotTo(HaveOccurred())

			err = m.Start(f, stopChan)
			Expect(err).NotTo(HaveOccurred())

			// Linux node (without OVN subnet annotation) should not have an hybrid overlay subnet annotation
			updatedNode, err := fakeClient.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedNode.Annotations).NotTo(HaveKey(types.HybridOverlayHostSubnet))

			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})

	It("copies a Linux node's OVN hostsubnet annotation to the hybrid overlay hostsubnet annotation", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				node1Name   string = "node1"
				node1Subnet string = "10.1.2.0/24"
				node2Name   string = "node2"
				node2Subnet string = "10.1.3.0/24"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					{ObjectMeta: metav1.ObjectMeta{
						Name: node1Name,
						Labels: map[string]string{
							v1.LabelOSStable: "linux",
						},
						Annotations: map[string]string{
							"ovn_host_subnet": node1Subnet,
						},
					}},
					{ObjectMeta: metav1.ObjectMeta{
						Name: node2Name,
						Labels: map[string]string{
							v1.LabelOSStable: "linux",
						},
						Annotations: map[string]string{
							"ovn_host_subnet":             node2Subnet,
							types.HybridOverlayHostSubnet: "1.2.3.0/24",
						},
					}},
				},
			})

			fexec := ovntest.NewFakeExec()
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			stopChan := make(chan struct{})
			f, err := factory.NewWatchFactory(fakeClient, stopChan)
			Expect(err).NotTo(HaveOccurred())
			defer f.Shutdown()

			m, err := NewMaster(fakeClient, extCIDR)
			Expect(err).NotTo(HaveOccurred())

			err = m.Start(f, stopChan)
			Expect(err).NotTo(HaveOccurred())

			// Linux node #1 should have the same hybrid overlay subnet annotation
			updatedNode, err := fakeClient.CoreV1().Nodes().Get(node1Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedNode.Annotations).To(HaveKeyWithValue(types.HybridOverlayHostSubnet, node1Subnet))

			// Linux node #2 should have the same hybrid overlay subnet annotation
			updatedNode, err = fakeClient.CoreV1().Nodes().Get(node2Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedNode.Annotations).To(HaveKeyWithValue(types.HybridOverlayHostSubnet, node2Subnet))

			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})

	It("removes a Linux node's hybrid overlay hostsubnet annotation when the OVN hostsubnet annotation disappears", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName   string = "node1"
				nodeSubnet string = "10.1.2.0/24"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					{ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
						Labels: map[string]string{
							v1.LabelOSStable: "linux",
						},
						Annotations: map[string]string{
							types.HybridOverlayHostSubnet: nodeSubnet,
							"ovn_host_subnet":             nodeSubnet,
						},
					}},
				},
			})

			fexec := ovntest.NewFakeExec()
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			stopChan := make(chan struct{})
			f, err := factory.NewWatchFactory(fakeClient, stopChan)
			Expect(err).NotTo(HaveOccurred())
			defer f.Shutdown()

			m, err := NewMaster(fakeClient, extCIDR)
			Expect(err).NotTo(HaveOccurred())

			err = m.Start(f, stopChan)
			Expect(err).NotTo(HaveOccurred())

			kube := &kube.Kube{KClient: fakeClient}
			updatedNode, err := kube.GetNode(nodeName)
			Expect(err).NotTo(HaveOccurred())

			err = kube.DeleteAnnotationOnNode(updatedNode, "ovn_host_subnet")
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() map[string]string {
				updatedNode, err = kube.GetNode(nodeName)
				Expect(err).NotTo(HaveOccurred())
				return updatedNode.Annotations
			}, 5, 1).ShouldNot(HaveKey(types.HybridOverlayHostSubnet))

			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})
})
