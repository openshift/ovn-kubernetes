package controller

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	testMgmtMAC string = "06:05:04:03:02:01"

	thisNodeSubnet string = "1.2.3.0/24"
	thisNodeDRIP   string = "1.2.3.3"
	thisNodeDRMAC  string = "22:33:44:55:66:77"
)

// returns if the two flowCaches are the same
func compareFlowCache(returnedFlowCache, expectedFlowCache map[string]*flowCacheEntry) error {
	if len(returnedFlowCache) != len(expectedFlowCache) {
		return fmt.Errorf("the number of expected flow cache entries (%d) does not equal the number returned (%d)", len(expectedFlowCache), len(returnedFlowCache))
	}

	for key, entry := range returnedFlowCache {
		expectedEntry, ok := expectedFlowCache[key]
		if !ok {
			return fmt.Errorf("unexpected entry %s in nodes flowCache", entry.flows)
		}
		if err := compareFlowCacheEntry(entry, expectedEntry); err != nil {
			return fmt.Errorf("returned flowCacheEntry[%s] does not equal expectedCacheEntry[%s]: %v", key, key, err)
		}
	}
	return nil

}

// compares two entries in the flow cache
func compareFlowCacheEntry(returnedEntry, expectedEntry *flowCacheEntry) error {
	if returnedEntry.learnedFlow != expectedEntry.learnedFlow {
		return fmt.Errorf("the number of flows in the flow cache entry is unexpected")
	}
	if returnedEntry.ignoreLearn != expectedEntry.ignoreLearn {
		return fmt.Errorf("the flowCacheEntry ignoreLearn field is not expected")
	}
	if len(returnedEntry.flows) != len(expectedEntry.flows) {
		return fmt.Errorf("the number of flows is not equal to the number of flows expected")
	}

	for key, returnedEntryFlow := range returnedEntry.flows {
		if returnedEntryFlow != expectedEntry.flows[key] {
			return fmt.Errorf("returnedflowCacheEntry[%d] = %s does not equal expectedFlowCacheEntry[%d] = %s", key, returnedEntryFlow, key, expectedEntry.flows[key])
		}

	}

	return nil
}

func generateInitialFlowCacheEntry(mgmtInterfaceAddr string) *flowCacheEntry {
	mgmtPortLink, err := netlink.LinkByName(types.K8sMgmtIntfName)
	Expect(err).NotTo(HaveOccurred())
	mgmtPortMAC := mgmtPortLink.Attrs().HardwareAddr
	_, ipNet, err := net.ParseCIDR(thisNodeSubnet)
	Expect(err).NotTo(HaveOccurred())
	gwIfAddr := util.GetNodeGatewayIfAddr(ipNet)
	gwPortMAC := util.IPAddrToHWAddr(gwIfAddr.IP)
	thisNodeDRMACRaw := strings.Replace(thisNodeDRMAC, ":", "", -1)
	return &flowCacheEntry{
		flows: []string{
			"table=0,priority=0,actions=drop",
			"table=1,priority=0,actions=drop",
			"table=2,priority=0,actions=drop",
			"table=10,priority=0,actions=drop",
			"table=20,priority=0,actions=drop",
			"table=0,priority=100,in_port=ext,arp_op=1,arp,arp_tpa=" + thisNodeDRIP + ",actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:" + thisNodeDRMAC + ",load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],load:0x" + thisNodeDRMACRaw + "->NXM_NX_ARP_SHA[],load:0x" + getIPAsHexString(net.ParseIP(thisNodeDRIP)) + "->NXM_OF_ARP_SPA[],IN_PORT,resubmit(,1)",
			"table=0,priority=100,in_port=ext-vxlan,ip,nw_dst=" + thisNodeSubnet + ",dl_dst=" + thisNodeDRMAC + ",actions=goto_table:10",
			"table=0,priority=10,arp,in_port=ext-vxlan,arp_op=1,arp_tpa=" + thisNodeSubnet + ",actions=resubmit(,2)",
			"table=2,priority=100,arp,in_port=ext-vxlan,arp_op=1,arp_tpa=" + thisNodeSubnet + ",actions=move:tun_src->tun_dst,load:4097->NXM_NX_TUN_ID[0..31],move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:" + thisNodeDRMAC + ",load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],load:0x" + thisNodeDRMACRaw + "->NXM_NX_ARP_SHA[],move:NXM_OF_ARP_TPA[]->NXM_NX_REG0[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],move:NXM_NX_REG0[]->NXM_OF_ARP_SPA[],IN_PORT",
			"table=10,priority=100,ip,nw_dst=" + mgmtInterfaceAddr + ",actions=mod_dl_src:" + thisNodeDRMAC + ",mod_dl_dst:" + mgmtPortMAC.String() + ",output:ext",
			"table=10,priority=100,ip,nw_dst=" + thisNodeDRIP + ",actions=mod_nw_dst:100.64.0.3,mod_dl_src:" + thisNodeDRMAC + ",mod_dl_dst:" + gwPortMAC.String() + ",output:ext",
		},
	}

}

// returns a fake node IP and DR MAC
func addNodeSetupCmds(fexec *ovntest.FakeExec, nodeName string) {
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 get logical_switch mynode other-config:subnet",
		Output: thisNodeSubnet,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovs-vsctl --timeout=15 --may-exist add-br br-ext -- set Bridge br-ext fail_mode=secure -- set Interface br-ext mtu_request=1400",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface br-ext mac_in_use",
		Output: thisNodeDRMAC,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovs-vsctl --timeout=15 set bridge br-ext other-config:hwaddr=" + thisNodeDRMAC,
		"ovs-vsctl --timeout=15 --may-exist add-port br-int int -- --may-exist add-port br-ext ext -- set Interface int type=patch options:peer=ext external-ids:iface-id=int-" + nodeName + " -- set Interface ext type=patch options:peer=int",
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		`ovs-vsctl --timeout=15 --may-exist add-port br-ext ext-vxlan -- set interface ext-vxlan type=vxlan options:remote_ip="flow" options:key="flow" options:dst_port=4789`,
	})
}

func createNode(name, os, ip string, annotations map[string]string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				v1.LabelOSStable: os,
			},
			Annotations: annotations,
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: ip},
			},
		},
	}
}

func createPod(namespace, name, node, podIP, podMAC string) *v1.Pod {
	annotations := map[string]string{}
	if podIP != "" || podMAC != "" {
		ipn := ovntest.MustParseIPNet(podIP)
		gatewayIP := util.NextIP(ipn.IP)
		annotations[util.OvnPodAnnotationName] = fmt.Sprintf(`{"default": {"ip_address":"` + podIP + `", "mac_address":"` + podMAC + `", "gateway_ip": "` + gatewayIP.String() + `"}}`)
	}

	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: annotations,
		},
		Spec: v1.PodSpec{
			NodeName: node,
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
		},
	}
}

func expectRouteForSubnet(routes []netlink.Route, subnet *net.IPNet, hoIfAddr net.IP) {
	found := false
	for _, route := range routes {
		if route.Dst.String() == subnet.String() && route.Gw.String() == hoIfAddr.String() {
			found = true
			break
		}
	}
	Expect(found).To(BeTrue(), fmt.Sprintf("failed to find hybrid overlay host route %s via %s", subnet, hoIfAddr))
}

func validateNetlinkState(nodeSubnet, hoDRIP string) {
	link, err := netlink.LinkByName(extBridgeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))

	link, err = netlink.LinkByName(types.K8sMgmtIntfName)
	Expect(err).NotTo(HaveOccurred())
	Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))

	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	Expect(err).NotTo(HaveOccurred())

	// Expect a route to the hybrid overlay CIDR via the given hoDRIP
	// through the management port
	Expect(err).NotTo(HaveOccurred())
	Expect(len(config.HybridOverlay.ClusterSubnets)).ToNot(BeZero())
	for _, hoSubnet := range config.HybridOverlay.ClusterSubnets {
		expectRouteForSubnet(routes, hoSubnet.CIDR, net.ParseIP(hoDRIP))
	}
}

func appRun(app *cli.App, netns ns.NetNS) {
	_ = netns.Do(func(ns.NetNS) error {
		defer GinkgoRecover()
		err := app.Run([]string{
			app.Name,
			"-enable-hybrid-overlay",
			"-no-hostsubnet-nodes=" + v1.LabelOSStable + "=windows",
			"-cluster-subnets=10.130.0.0/15/24",
		})
		Expect(err).NotTo(HaveOccurred())
		return nil
	})
}

func createNodeAnnotationsForSubnet(subnet string) map[string]string {
	subnetAnnotations, err := util.UpdateNodeHostSubnetAnnotation(nil, ovntest.MustParseIPNets(subnet), types.DefaultNetworkName)
	Expect(err).NotTo(HaveOccurred())
	annotations := make(map[string]string)
	for k, v := range subnetAnnotations {
		annotations[k] = fmt.Sprintf("%s", v)
	}
	return annotations
}

var _ = Describe("Hybrid Overlay Node Linux Operations", func() {
	var (
		app        *cli.App
		fexec      *ovntest.FakeExec
		netns      ns.NetNS
		stopChan   chan struct{}
		wg         *sync.WaitGroup
		mgmtIfAddr *net.IPNet
	)
	const (
		thisNode   string = "mynode"
		thisNodeIP string = "10.0.0.1"
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		stopChan = make(chan struct{})
		wg = &sync.WaitGroup{}

		fexec = ovntest.NewLooseCompareFakeExec()
		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		netns, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		// prepare br-ext and ovn-k8s-mp0 in original namespace
		_ = netns.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			ovntest.AddLink(extBridgeName)

			// Set up management interface with its address
			link := ovntest.AddLink(types.K8sMgmtIntfName)
			_, thisNet, err := net.ParseCIDR(thisNodeSubnet)
			Expect(err).NotTo(HaveOccurred())
			mgmtIfAddr = util.GetNodeManagementIfAddr(thisNet)
			err = netlink.AddrAdd(link, &netlink.Addr{IPNet: mgmtIfAddr})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
	})

	AfterEach(func() {
		close(stopChan)
		wg.Wait()
		Expect(netns.Close()).To(Succeed())
		Expect(testutils.UnmountNS(netns)).To(Succeed())
	})

	ovntest.OnSupportedPlatformsIt("does not set up tunnels for non-hybrid-overlay nodes without annotations", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				node1Name string = "node1"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					*createNode(node1Name, "linux", thisNodeIP, nil),
				},
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				n.nodeEventHandler.Run(1, stopChan)
			}()
			// don't add any commands the setup will fail because the master has not set the correct annotations
			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})

	ovntest.OnSupportedPlatformsIt("does not set up tunnels for non-hybrid-overlay nodes with subnet annotations", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				node1Name   string = "node1"
				node1Subnet string = "1.2.4.0/24"
				node1IP     string = "10.11.12.1"
			)

			annotations := createNodeAnnotationsForSubnet(node1Subnet)
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					*createNode(node1Name, "linux", node1IP, annotations),
				},
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				n.nodeEventHandler.Run(1, stopChan)
			}()

			// similarly to above no ovs commands will be issued to exec because the hybrid overlay setup will fail
			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})

	ovntest.OnSupportedPlatformsIt("sets up local node hybrid overlay bridge", func() {
		app.Action = func(ctx *cli.Context) error {

			annotations := createNodeAnnotationsForSubnet(thisNodeSubnet)
			annotations[hotypes.HybridOverlayDRMAC] = thisNodeDRMAC
			annotations["k8s.ovn.org/node-gateway-router-lrp-ifaddr"] = "{\"ipv4\":\"100.64.0.3/16\"}"
			annotations[hotypes.HybridOverlayDRIP] = thisNodeDRIP
			node := createNode(thisNode, "linux", thisNodeIP, annotations)
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{*node},
			})

			addNodeSetupCmds(fexec, thisNode)
			config.HybridOverlay.RawClusterSubnets = "10.0.0.1/16/23"
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			err = n.controller.EnsureHybridOverlayBridge(node)
			Expect(err).NotTo(HaveOccurred())

			linuxNode, okay := n.controller.(*NodeController)
			Expect(okay).To(BeTrue())
			Expect(linuxNode.initialized).To(BeTrue())

			// ovs commands generated by the initial sync
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
			})

			//  perform the requested cacheSync
			linuxNode.syncFlows()

			// the flow cache will be sync'ed to ovs from the above bundled command but there is not a good way using fexec to
			// get that data so I am comapring the flowcache to what it should be
			initialFlowCache := map[string]*flowCacheEntry{
				"0x0": generateInitialFlowCacheEntry(mgmtIfAddr.IP.String()),
			}
			Expect(compareFlowCache(linuxNode.flowCache, initialFlowCache)).NotTo(HaveOccurred())

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			validateNetlinkState(thisNodeSubnet, thisNodeDRIP)
			return nil
		}
		appRun(app, netns)
	})
	ovntest.OnSupportedPlatformsIt("sets up local linux pod", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				pod1IP   string = "1.2.3.5"
				pod1CIDR string = pod1IP + "/24"
				pod1MAC  string = "aa:bb:cc:dd:ee:ff"
			)

			annotations := createNodeAnnotationsForSubnet(thisNodeSubnet)
			annotations[hotypes.HybridOverlayDRMAC] = thisNodeDRMAC
			annotations["k8s.ovn.org/node-gateway-router-lrp-ifaddr"] = "{\"ipv4\":\"100.64.0.3/16\"}"
			annotations[hotypes.HybridOverlayDRIP] = thisNodeDRIP
			node := createNode(thisNode, "linux", thisNodeIP, annotations)
			testPod := createPod("test", "pod1", thisNode, pod1CIDR, pod1MAC)
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{*node},
			})

			// Node setup from initial node sync
			addNodeSetupCmds(fexec, thisNode)
			config.HybridOverlay.RawClusterSubnets = "10.0.0.1/16/23"
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			err = n.controller.EnsureHybridOverlayBridge(node)
			Expect(err).NotTo(HaveOccurred())
			linuxNode, okay := n.controller.(*NodeController)
			Expect(okay).To(BeTrue())
			Expect(linuxNode.initialized).To(BeTrue())
			// ovs commands generated by the initial sync
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
			})

			// perform the requested cacheSync
			linuxNode.syncFlows()
			initialFlowCache := map[string]*flowCacheEntry{
				"0x0": generateInitialFlowCacheEntry(mgmtIfAddr.IP.String()),
			}
			Expect(compareFlowCache(linuxNode.flowCache, initialFlowCache)).NotTo(HaveOccurred())

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			validateNetlinkState(thisNodeSubnet, thisNodeDRIP)
			err = n.controller.AddPod(testPod)
			Expect(err).NotTo(HaveOccurred())
			// ovs commands generated by second cacheSync
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
			})

			// perform the requested cacheSync
			linuxNode.syncFlows()
			// make sure that the flow that sends traffic to the windows pod is present
			initialFlowCache[podIPToCookie(net.ParseIP(pod1IP))] = &flowCacheEntry{
				flows:       []string{"table=10,cookie=0x" + podIPToCookie(net.ParseIP(pod1IP)) + ",priority=100,ip,nw_dst=" + pod1IP + ",actions=set_field:" + thisNodeDRMAC + "->eth_src,set_field:" + pod1MAC + "->eth_dst,output:ext"},
				ignoreLearn: true,
			}
			Expect(compareFlowCache(linuxNode.flowCache, initialFlowCache)).NotTo(HaveOccurred())
			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})

	ovntest.OnSupportedPlatformsIt("sets up tunnels for Windows nodes", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				node1Name   string = "node1"
				node1Subnet string = "10.11.12.0/24"
				node1DRMAC  string = "00:00:00:7f:af:03"
				node1IP     string = "10.11.12.1"
			)

			annotations := createNodeAnnotationsForSubnet(thisNodeSubnet)
			annotations[hotypes.HybridOverlayDRMAC] = thisNodeDRMAC
			annotations["k8s.ovn.org/node-gateway-router-lrp-ifaddr"] = "{\"ipv4\":\"100.64.0.3/16\"}"
			annotations[hotypes.HybridOverlayDRIP] = thisNodeDRIP
			node := createNode(thisNode, "linux", thisNodeIP, annotations)
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					*node,
				},
			})

			// Node setup from initial node sync
			addNodeSetupCmds(fexec, thisNode)
			config.HybridOverlay.RawClusterSubnets = "10.0.0.1/16/23"
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			err = n.controller.EnsureHybridOverlayBridge(node)
			Expect(err).NotTo(HaveOccurred())
			linuxNode, okay := n.controller.(*NodeController)
			Expect(okay).To(BeTrue())

			Expect(linuxNode.initialized).To(BeTrue())
			// ovs commands generated by the initial sync
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
			})

			// perform the requested cacheSync
			linuxNode.syncFlows()
			initialFlowCache := map[string]*flowCacheEntry{
				"0x0": generateInitialFlowCacheEntry(mgmtIfAddr.IP.String()),
			}
			Expect(compareFlowCache(linuxNode.flowCache, initialFlowCache)).NotTo(HaveOccurred())

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			validateNetlinkState(thisNodeSubnet, thisNodeDRIP)

			windowsAnnotation := createNodeAnnotationsForSubnet(node1Subnet)
			windowsAnnotation[hotypes.HybridOverlayDRMAC] = node1DRMAC
			n.controller.AddNode(createNode(node1Name, "windows", node1IP, windowsAnnotation))

			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
			})

			linuxNode.syncFlows()
			node1Cookie := nameToCookie(node1Name)
			initialFlowCache[node1Cookie] = &flowCacheEntry{
				flows: []string{
					"cookie=0x" + node1Cookie + ",table=0,priority=100,arp,in_port=ext,arp_tpa=" + node1Subnet + ",actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:" + node1DRMAC + ",load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],load:0x" + strings.ReplaceAll(node1DRMAC, ":", "") + "->NXM_NX_ARP_SHA[],move:NXM_OF_ARP_TPA[]->NXM_NX_REG0[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],move:NXM_NX_REG0[]->NXM_OF_ARP_SPA[],IN_PORT",
					"cookie=0x" + node1Cookie + ",table=0,priority=100,ip,nw_dst=" + node1Subnet + ",actions=load:4097->NXM_NX_TUN_ID[0..31],set_field:" + node1IP + "->tun_dst,set_field:" + node1DRMAC + "->eth_dst,output:ext-vxlan",
					"cookie=0x" + node1Cookie + ",table=0,priority=101,ip,nw_dst=" + node1Subnet + ",nw_src=100.64.0.3,actions=load:4097->NXM_NX_TUN_ID[0..31],set_field:" + thisNodeDRIP + "->nw_src,set_field:" + node1IP + "->tun_dst,set_field:" + node1DRMAC + "->eth_dst,output:ext-vxlan",
				},
			}
			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			Expect(compareFlowCache(linuxNode.flowCache, initialFlowCache)).NotTo(HaveOccurred())

			return nil
		}
		appRun(app, netns)
	})
})
