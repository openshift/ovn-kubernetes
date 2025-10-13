package egressip

import (
	"fmt"
	"net"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/linkmanager"
	netlink_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/vishvananda/netlink"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
)

var _ = ginkgo.Describe("Gateway EgressIP", func() {

	const (
		nodeName        = "ovn-worker"
		bridgeName      = "breth0"
		bridgeLinkIndex = 10
		ipV4Addr        = "192.168.1.5"
		ipV4Addr2       = "192.168.1.6"
		ipV4Addr3       = "192.168.1.7"
		mark            = "50000"
		mark2           = "50001"
		mark3           = "50002"
		emptyAnnotation = ""
	)

	var (
		nlMock     *mocks.NetLinkOps
		nlLinkMock *netlink_mocks.Link
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		err := config.PrepareTestConfig()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		nlMock = new(mocks.NetLinkOps)
		nlLinkMock = new(netlink_mocks.Link)
		util.SetNetLinkOpMockInst(nlMock)
	})

	ginkgo.AfterEach(func() {
		util.ResetNetLinkOpMockInst()
	})

	ginkgo.Context("add EgressIP", func() {
		ginkgo.It("configures annotation and bridge when EIP assigned to node", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkByIndex", bridgeLinkIndex).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation)
			defer stopFn()
			eip := getEIPAssignedToNode(nodeName, mark, ipV4Addr)
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.ConsistOf(ipV4Addr))
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})

		ginkgo.It("doesn't configure or fail when annotation mark isn't found", func() {
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation)
			defer stopFn()
			eip := getEIPAssignedToNode(nodeName, "", ipV4Addr)
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeFalse())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).ShouldNot(gomega.ConsistOf(ipV4Addr))
			gomega.Expect(nlMock.AssertNotCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})

		ginkgo.It("fails when invalid annotation mark", func() {
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation)
			defer stopFn()
			eip := getEIPAssignedToNode(nodeName, "not-an-integer", ipV4Addr)
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).Should(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeFalse())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).ShouldNot(gomega.ConsistOf(ipV4Addr))
			gomega.Expect(nlMock.AssertNotCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})

		ginkgo.It("configures annotations with existing entries", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkByIndex", bridgeLinkIndex).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, generateAnnotFromIPs(ipV4Addr2))
			defer stopFn()
			eip := getEIPAssignedToNode(nodeName, mark, ipV4Addr)
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.ConsistOf(ipV4Addr, ipV4Addr2))
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})
	})

	ginkgo.Context("update EgressIP", func() {
		ginkgo.It("configures when EgressIP is not assigned to the node", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkByIndex", bridgeLinkIndex).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation)
			defer stopFn()
			assignedEIP := getEIPAssignedToNode(nodeName, mark, ipV4Addr)
			unassignedEIP := getEIPNotAssignedToNode(mark, ipV4Addr)
			isUpdated, err := addrMgr.UpdateEgressIP(unassignedEIP, assignedEIP)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.ConsistOf(ipV4Addr))
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})

		ginkgo.It("removes EgressIP previously assigned", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkByIndex", bridgeLinkIndex).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			nlMock.On("AddrDel", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation)
			defer stopFn()
			assignedEIP := getEIPAssignedToNode(nodeName, mark, ipV4Addr)
			unassignedEIP := getEIPNotAssignedToNode(mark, ipV4Addr)
			isUpdated, err := addrMgr.UpdateEgressIP(unassignedEIP, assignedEIP)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			isUpdated, err = addrMgr.UpdateEgressIP(assignedEIP, unassignedEIP)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).ShouldNot(gomega.ConsistOf(ipV4Addr))
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrDel", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})

		ginkgo.It("reconfigures from an old to a new IP", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkByIndex", bridgeLinkIndex).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr2), bridgeLinkIndex)).Return(nil)
			nlMock.On("AddrDel", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation)
			defer stopFn()
			unassignedEIP := getEIPNotAssignedToNode(mark, ipV4Addr)
			assignedEIP1 := getEIPAssignedToNode(nodeName, mark, ipV4Addr)
			assignedEIP2 := getEIPAssignedToNode(nodeName, mark2, ipV4Addr2)
			isUpdated, err := addrMgr.UpdateEgressIP(unassignedEIP, assignedEIP1)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			isUpdated, err = addrMgr.UpdateEgressIP(assignedEIP1, assignedEIP2)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.ConsistOf(ipV4Addr2))
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr2), bridgeLinkIndex))).Should(gomega.BeTrue())
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrDel", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})
	})

	ginkgo.Context("delete EgressIP", func() {
		ginkgo.It("removes configuration from annotation and bridge when EIP assigned to node is deleted", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkByIndex", bridgeLinkIndex).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			nlMock.On("AddrDel", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation)
			defer stopFn()
			eip := getEIPAssignedToNode(nodeName, mark, ipV4Addr)
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			isUpdated, err = addrMgr.DeleteEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeTrue())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).ShouldNot(gomega.ConsistOf(ipV4Addr))
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrDel", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})

		ginkgo.It("does not update when EIP is deleted that wasn't assigned to the node", func() {
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, generateAnnotFromIPs(ipV4Addr2))
			defer stopFn()
			eip := getEIPNotAssignedToNode(mark, ipV4Addr)
			isUpdated, err := addrMgr.DeleteEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process a valid EgressIP")
			gomega.Expect(isUpdated).Should(gomega.BeFalse())
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.ConsistOf(ipV4Addr2))
			gomega.Expect(nlMock.AssertNotCalled(ginkgo.GinkgoT(), "AddrDel", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
		})
	})

	ginkgo.Context("sync EgressIP", func() {
		ginkgo.It("configures multiple EgressIPs assigned to the node", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkByIndex", bridgeLinkIndex).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr2), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation)
			defer stopFn()
			eipAssigned1 := getEIPAssignedToNode(nodeName, mark, ipV4Addr)
			eipAssigned2 := getEIPAssignedToNode(nodeName, mark2, ipV4Addr2)
			eipUnassigned3 := getEIPNotAssignedToNode(mark3, ipV4Addr3)
			err := addrMgr.SyncEgressIP([]interface{}{eipAssigned1, eipAssigned2, eipUnassigned3})
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process valid EgressIPs")
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.ConsistOf(ipV4Addr, ipV4Addr2))
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr2), bridgeLinkIndex))).Should(gomega.BeTrue())
		})

		ginkgo.It("delete previous configuration", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkByIndex", bridgeLinkIndex).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr2), bridgeLinkIndex)).Return(nil)
			nlMock.On("AddrDel", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr3), bridgeLinkIndex)).Return(nil)
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, generateAnnotFromIPs(ipV4Addr3)) // previously configured IP
			defer stopFn()
			eipAssigned1 := getEIPAssignedToNode(nodeName, mark, ipV4Addr)
			eipAssigned2 := getEIPAssignedToNode(nodeName, mark2, ipV4Addr2)
			err := addrMgr.SyncEgressIP([]interface{}{eipAssigned1, eipAssigned2})
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process valid EgressIPs")
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.ConsistOf(ipV4Addr, ipV4Addr2))
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue())
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr2), bridgeLinkIndex))).Should(gomega.BeTrue())
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrDel", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr3), bridgeLinkIndex))).Should(gomega.BeTrue())
		})

		ginkgo.It("no update or failure when mark is not set", func() {
			addrMgr, stopFn := initBridgeEIPAddrManager(nodeName, bridgeName, emptyAnnotation) // previously configured IP
			defer stopFn()
			eipAssigned := getEIPAssignedToNode(nodeName, "", ipV4Addr)
			err := addrMgr.SyncEgressIP([]interface{}{eipAssigned})
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process valid EgressIPs")
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.BeEmpty())
		})
	})

	ginkgo.Context("bug fix validation", func() {
		ginkgo.It("should not add EgressIP to bridge when no matching pods exist", func() {
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)
			addrMgr, stopFn := initBridgeEIPAddrManagerWithPods(nodeName, bridgeName, emptyAnnotation, []*corev1.Namespace{}, []*corev1.Pod{})
			defer stopFn()
			eip := getEIPWithSelectors(nodeName, mark, ipV4Addr, map[string]string{"app": "test"}, map[string]string{"version": "v1"})
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process EgressIP without error")
			gomega.Expect(isUpdated).Should(gomega.BeFalse(), "should not update when no matching pods")
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.BeEmpty(), "no IPs should be added to node annotation")
			gomega.Expect(nlMock.AssertNotCalled(ginkgo.GinkgoT(), "AddrAdd")).Should(gomega.BeTrue(), "AddrAdd should not be called")
		})

		ginkgo.It("should add EgressIP to bridge only when matching pods exist and br-ex is correct interface", func() {
			// Setup network interface configuration for LPM
			bridgeAddr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)}}
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex, Flags: net.FlagUp}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{*bridgeAddr}, nil)
			nlMock.On("AddrAdd", nlLinkMock, getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex)).Return(nil)

			// Create matching namespace and pod
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"app": "test"}},
			}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns", Labels: map[string]string{"version": "v1"}},
				Status: corev1.PodStatus{
					Phase:  corev1.PodRunning,
					PodIPs: []corev1.PodIP{{IP: "10.244.0.1"}},
				},
			}

			addrMgr, stopFn := initBridgeEIPAddrManagerWithPods(nodeName, bridgeName, emptyAnnotation, []*corev1.Namespace{namespace}, []*corev1.Pod{pod})
			defer stopFn()
			eip := getEIPWithSelectors(nodeName, mark, ipV4Addr, map[string]string{"app": "test"}, map[string]string{"version": "v1"})
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process EgressIP without error")
			gomega.Expect(isUpdated).Should(gomega.BeTrue(), "should update when matching pods exist")
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.ConsistOf(ipV4Addr), "EgressIP should be added to node annotation")
			gomega.Expect(nlMock.AssertCalled(ginkgo.GinkgoT(), "AddrAdd", nlLinkMock,
				getEIPBridgeNetlinkAddressPtr(net.ParseIP(ipV4Addr), bridgeLinkIndex))).Should(gomega.BeTrue(), "AddrAdd should be called")
		})

		ginkgo.It("should not add EgressIP to bridge when br-ex is not the correct interface per LPM", func() {
			// Setup network interface configuration where br-ex doesn't match the EgressIP network
			secondaryLink := &netlink_mocks.Link{}
			secondaryAddr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)}}
			bridgeAddr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}}

			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex, Flags: net.FlagUp}, nil)
			secondaryLink.On("Attrs").Return(&netlink.LinkAttrs{Name: "eth1", Index: 11, Flags: net.FlagUp}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock, secondaryLink}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{*bridgeAddr}, nil)
			nlMock.On("AddrList", secondaryLink, 0).Return([]netlink.Addr{*secondaryAddr}, nil)

			// Create matching namespace and pod
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"app": "test"}},
			}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns", Labels: map[string]string{"version": "v1"}},
				Status: corev1.PodStatus{
					Phase:  corev1.PodRunning,
					PodIPs: []corev1.PodIP{{IP: "10.244.0.1"}},
				},
			}

			addrMgr, stopFn := initBridgeEIPAddrManagerWithPods(nodeName, bridgeName, emptyAnnotation, []*corev1.Namespace{namespace}, []*corev1.Pod{pod})
			defer stopFn()
			// EgressIP that should be assigned to eth1 (192.168.1.0/24), not br-ex (10.0.0.0/24)
			eip := getEIPWithSelectors(nodeName, mark, ipV4Addr, map[string]string{"app": "test"}, map[string]string{"version": "v1"})
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process EgressIP without error")
			gomega.Expect(isUpdated).Should(gomega.BeFalse(), "should not update when br-ex is not correct interface")
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.BeEmpty(), "no IPs should be added to node annotation")
			gomega.Expect(nlMock.AssertNotCalled(ginkgo.GinkgoT(), "AddrAdd")).Should(gomega.BeTrue(), "AddrAdd should not be called")
		})

		ginkgo.It("should handle pod selector matching correctly", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex, Flags: net.FlagUp}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)

			// Create namespace that matches, but pod that doesn't match
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"app": "test"}},
			}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns", Labels: map[string]string{"version": "v2"}}, // v2 instead of v1
				Status: corev1.PodStatus{
					Phase:  corev1.PodRunning,
					PodIPs: []corev1.PodIP{{IP: "10.244.0.1"}},
				},
			}

			addrMgr, stopFn := initBridgeEIPAddrManagerWithPods(nodeName, bridgeName, emptyAnnotation, []*corev1.Namespace{namespace}, []*corev1.Pod{pod})
			defer stopFn()
			eip := getEIPWithSelectors(nodeName, mark, ipV4Addr, map[string]string{"app": "test"}, map[string]string{"version": "v1"})
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process EgressIP without error")
			gomega.Expect(isUpdated).Should(gomega.BeFalse(), "should not update when pod doesn't match selector")
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.BeEmpty(), "no IPs should be added to node annotation")
			gomega.Expect(nlMock.AssertNotCalled(ginkgo.GinkgoT(), "AddrAdd")).Should(gomega.BeTrue(), "AddrAdd should not be called")
		})

		ginkgo.It("should skip pods that are completed or want host network", func() {
			nlLinkMock.On("Attrs").Return(&netlink.LinkAttrs{Name: bridgeName, Index: bridgeLinkIndex, Flags: net.FlagUp}, nil)
			nlMock.On("LinkByName", bridgeName).Return(nlLinkMock, nil)
			nlMock.On("LinkList").Return([]netlink.Link{nlLinkMock}, nil)
			nlMock.On("AddrList", nlLinkMock, 0).Return([]netlink.Addr{}, nil)

			// Create namespace that matches
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"app": "test"}},
			}
			// Create completed pod
			completedPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "completed-pod", Namespace: "test-ns", Labels: map[string]string{"version": "v1"}},
				Status: corev1.PodStatus{
					Phase:  corev1.PodSucceeded,
					PodIPs: []corev1.PodIP{{IP: "10.244.0.1"}},
				},
			}
			// Create host network pod
			hostNetPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "host-net-pod", Namespace: "test-ns", Labels: map[string]string{"version": "v1"}},
				Spec: corev1.PodSpec{
					HostNetwork: true,
				},
				Status: corev1.PodStatus{
					Phase:  corev1.PodRunning,
					PodIPs: []corev1.PodIP{{IP: "10.244.0.2"}},
				},
			}

			addrMgr, stopFn := initBridgeEIPAddrManagerWithPods(nodeName, bridgeName, emptyAnnotation, []*corev1.Namespace{namespace}, []*corev1.Pod{completedPod, hostNetPod})
			defer stopFn()
			eip := getEIPWithSelectors(nodeName, mark, ipV4Addr, map[string]string{"app": "test"}, map[string]string{"version": "v1"})
			isUpdated, err := addrMgr.addEgressIP(eip)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should process EgressIP without error")
			gomega.Expect(isUpdated).Should(gomega.BeFalse(), "should not update when no valid pods exist")
			node, err := addrMgr.nodeLister.Get(nodeName)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "node should be present within kapi")
			gomega.Expect(parseEIPsFromAnnotation(node)).Should(gomega.BeEmpty(), "no IPs should be added to node annotation")
			gomega.Expect(nlMock.AssertNotCalled(ginkgo.GinkgoT(), "AddrAdd")).Should(gomega.BeTrue(), "AddrAdd should not be called")
		})
	})
})

func initBridgeEIPAddrManager(nodeName, bridgeName string, bridgeEIPAnnot string) (*BridgeEIPAddrManager, func()) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, Annotations: map[string]string{}},
	}
	if bridgeEIPAnnot != "" {
		node.Annotations[util.OVNNodeBridgeEgressIPs] = bridgeEIPAnnot
	}
	client := fake.NewSimpleClientset(node)
	watchFactory, err := factory.NewNodeWatchFactory(&util.OVNNodeClientset{KubeClient: client}, nodeName)
	gomega.Expect(watchFactory.Start()).Should(gomega.Succeed(), "watch factory should start")
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "watch factory creation must succeed")
	linkManager := linkmanager.NewController(nodeName, true, true, nil)
	return newBridgeEIPAddrManager(nodeName, bridgeName, linkManager, &kube.Kube{KClient: client}, watchFactory.EgressIPInformer(), watchFactory.NodeCoreInformer(), watchFactory.PodCoreInformer(), watchFactory.NamespaceInformer()),
		watchFactory.Shutdown
}

func initBridgeEIPAddrManagerWithPods(nodeName, bridgeName string, bridgeEIPAnnot string, namespaces []*corev1.Namespace, pods []*corev1.Pod) (*BridgeEIPAddrManager, func()) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, Annotations: map[string]string{}},
	}
	if bridgeEIPAnnot != "" {
		node.Annotations[util.OVNNodeBridgeEgressIPs] = bridgeEIPAnnot
	}

	// Create objects slice with node, namespaces, and pods
	objs := []runtime.Object{node}
	for _, ns := range namespaces {
		objs = append(objs, ns)
	}
	for _, pod := range pods {
		objs = append(objs, pod)
	}

	client := fake.NewSimpleClientset(objs...)
	watchFactory, err := factory.NewNodeWatchFactory(&util.OVNNodeClientset{KubeClient: client}, nodeName)
	gomega.Expect(watchFactory.Start()).Should(gomega.Succeed(), "watch factory should start")
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "watch factory creation must succeed")
	linkManager := linkmanager.NewController(nodeName, true, true, nil)
	return newBridgeEIPAddrManager(nodeName, bridgeName, linkManager, &kube.Kube{KClient: client}, watchFactory.EgressIPInformer(), watchFactory.NodeCoreInformer(), watchFactory.PodCoreInformer(), watchFactory.NamespaceInformer()),
		watchFactory.Shutdown
}

func getEIPAssignedToNode(nodeName, mark, assignedIP string) *egressipv1.EgressIP {
	eip := &egressipv1.EgressIP{
		ObjectMeta: metav1.ObjectMeta{Name: "bridge-addr-mgr-test", Annotations: map[string]string{}},
		Spec: egressipv1.EgressIPSpec{
			EgressIPs: []string{assignedIP},
		},
		Status: egressipv1.EgressIPStatus{
			Items: []egressipv1.EgressIPStatusItem{
				{
					Node:     nodeName,
					EgressIP: assignedIP,
				},
			},
		},
	}
	if mark != "" {
		eip.Annotations[util.EgressIPMarkAnnotation] = mark
	}
	return eip
}

func getEIPNotAssignedToNode(mark, ip string) *egressipv1.EgressIP {
	eip := &egressipv1.EgressIP{
		ObjectMeta: metav1.ObjectMeta{Name: "bridge-addr-mgr-test", Annotations: map[string]string{}},
		Spec: egressipv1.EgressIPSpec{
			EgressIPs: []string{ip},
		},
		Status: egressipv1.EgressIPStatus{
			Items: []egressipv1.EgressIPStatusItem{
				{
					Node:     "different-node",
					EgressIP: ip,
				},
			},
		},
	}
	if mark != "" {
		eip.Annotations[util.EgressIPMarkAnnotation] = mark
	}
	return eip
}

func getEIPWithSelectors(nodeName, mark, assignedIP string, namespaceLabels, podLabels map[string]string) *egressipv1.EgressIP {
	eip := &egressipv1.EgressIP{
		ObjectMeta: metav1.ObjectMeta{Name: "bridge-addr-mgr-test", Annotations: map[string]string{}},
		Spec: egressipv1.EgressIPSpec{
			EgressIPs: []string{assignedIP},
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: namespaceLabels,
			},
			PodSelector: metav1.LabelSelector{
				MatchLabels: podLabels,
			},
		},
		Status: egressipv1.EgressIPStatus{
			Items: []egressipv1.EgressIPStatusItem{
				{
					Node:     nodeName,
					EgressIP: assignedIP,
				},
			},
		},
	}
	if mark != "" {
		eip.Annotations[util.EgressIPMarkAnnotation] = mark
	}
	return eip
}

func generateAnnotFromIPs(ips ...string) string {
	ipsWithQuotes := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			panic("invalid IP")
		}
		ipsWithQuotes = append(ipsWithQuotes, fmt.Sprintf("\"%s\"", ip))
	}
	return fmt.Sprintf("[%s]", strings.Join(ipsWithQuotes, ","))
}

func getEIPBridgeNetlinkAddressPtr(ip net.IP, ifindex int) *netlink.Addr {
	addr := getEIPBridgeNetlinkAddress(ip, ifindex)
	return &addr
}

func parseEIPsFromAnnotation(node *corev1.Node) []string {
	ips, err := util.ParseNodeBridgeEgressIPsAnnotation(node)
	if err != nil {
		if util.IsAnnotationNotSetError(err) {
			ips = make([]string, 0)
		} else {
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "should be able to detect if annotation is or not")
		}
	}
	return ips
}
