package node

import (
	"fmt"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/iprulemanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/routemanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/vrfmanager"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var _ = Describe("SecondaryNodeNetworkController", func() {
	var (
		nad = ovntest.GenerateNAD("bluenet", "rednad", "greenamespace",
			types.Layer3Topology, "100.128.0.0/16", types.NetworkRolePrimary)
		// netName                 = "bluenet"
		netID = 3
		// nodeName         string = "worker1"
		// mgtPortMAC       string = "00:00:00:55:66:77"
		fexec          *ovntest.FakeExec
		testNS         ns.NetNS
		vrf            *vrfmanager.Controller
		ipRulesManager *iprulemanager.Controller
		// v4NodeSubnet     = "10.128.0.0/24"
		// v6NodeSubnet     = "ae70::66/112"
		mgtPort          = fmt.Sprintf("%s%d", types.K8sMgmtIntfNamePrefix, netID)
		gatewayInterface = "eth0"
		gatewayBridge    = "breth0"
		stopCh           chan struct{}
		wg               *sync.WaitGroup
		// kubeMock         kubemocks.Interface
	)
	BeforeEach(func() {
		// Restore global default values before each testcase
		Expect(config.PrepareTestConfig()).To(Succeed())
		// Use a larger masq subnet to allow OF manager to allocate IPs for UDNs.
		config.Gateway.V6MasqueradeSubnet = "fd69::/112"
		config.Gateway.V4MasqueradeSubnet = "169.254.0.0/17"
		// Set up a fake vsctl command mock interface
		// kubeMock = kubemocks.Interface{}
		fexec = ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())
		// Set up a fake k8sMgmt interface
		testNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		err = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			ovntest.AddLink(gatewayInterface)
			link := ovntest.AddLink(gatewayBridge)
			ovntest.AddLink(mgtPort)
			addr, _ := netlink.ParseAddr("169.254.169.2/29")
			err = netlink.AddrAdd(link, addr)
			if err != nil {
				return err
			}
			addr, _ = netlink.ParseAddr("10.0.0.5/24")
			err = netlink.AddrAdd(link, addr)
			if err != nil {
				return err
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
		wg = &sync.WaitGroup{}
		stopCh = make(chan struct{})
		routeManager := routemanager.NewController()
		wg.Add(1)
		go testNS.Do(func(netNS ns.NetNS) error {
			defer wg.Done()
			routeManager.Run(stopCh, 2*time.Minute)
			return nil
		})
		ipRulesManager = iprulemanager.NewController(true, true)
		wg.Add(1)
		go testNS.Do(func(netNS ns.NetNS) error {
			defer wg.Done()
			ipRulesManager.Run(stopCh, 4*time.Minute)
			return nil
		})
		vrf = vrfmanager.NewController(routeManager)
		wg2 := &sync.WaitGroup{}
		defer func() {
			wg2.Wait()
		}()
		wg2.Add(1)
		go testNS.Do(func(netNS ns.NetNS) error {
			defer wg2.Done()
			defer GinkgoRecover()
			err = vrf.Run(stopCh, wg)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
	})
	AfterEach(func() {
		close(stopCh)
		wg.Wait()
		Expect(testNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(testNS)).To(Succeed())
	})

	It("should return networkID from one of the nodes in the cluster", func() {
		fakeClient := &util.OVNNodeClientset{
			KubeClient: fake.NewSimpleClientset(&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker1",
					Annotations: map[string]string{
						"k8s.ovn.org/network-ids": `{"bluenet": "3"}`,
					},
				},
			}),
		}
		controller := SecondaryNodeNetworkController{}
		var err error
		controller.watchFactory, err = factory.NewNodeWatchFactory(fakeClient, "worker1")
		Expect(err).NotTo(HaveOccurred())
		Expect(controller.watchFactory.Start()).To(Succeed())

		controller.NetInfo, err = util.ParseNADInfo(nad)
		Expect(err).NotTo(HaveOccurred())

		networkID, err := controller.getNetworkID()
		Expect(err).ToNot(HaveOccurred())
		Expect(networkID).To(Equal(3))
	})
})
