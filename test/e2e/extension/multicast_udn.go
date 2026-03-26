package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

var _ = g.Describe("[OTP][sig-networking] SDN udn/default multicast", func() {
	defer g.GinkgoRecover()

	var (
		oc               = exutil.NewCLI("networking-udn")
		testDataDirMcast = testdata.FixturePath("networking/multicast")
	)

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})
	g.It("[Level0] Author:yingwang-High-78447-udn pods should/should not receive multicast traffic when enable/disable multicast.", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns               string
			ipStackType      = checkIPStackType(oc)
			ipv4List         []string
			ipv6List         []string
			mcastipv4        = "232.43.211.234"
			mcastipv6        = "ff3e::4321:1234"
			port             = "4321"
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled. ")
		}
		//cover both udn and default network. when i ==0, test udn, when i ==1, test default
		for i := 0; i < 2; i++ {
			if i == 0 {
				compat_otp.By("############# test multicast on pods with udn primary interface")
				compat_otp.By("1. create udn namespace")
				oc.CreateNamespaceUDN()
				ns = oc.Namespace()

				compat_otp.By("2. Create CRD for UDN")
				var cidr, ipv4cidr, ipv6cidr string
				if ipStackType == "ipv4single" {
					cidr = "10.150.0.0/16"
				} else {
					if ipStackType == "ipv6single" {
						cidr = "2010:100:200::0/48"
					} else {
						ipv4cidr = "10.150.0.0/16"
						ipv6cidr = "2010:100:200::0/48"
					}
				}

				createGeneralUDNCRD(oc, ns, "udn-78447", ipv4cidr, ipv6cidr, cidr, "layer3")

			} else {
				compat_otp.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns = oc.Namespace()
			}
			compat_otp.By("3. Create 3 multicast testing pods")
			mcastPodRc := networkingRes{
				name:      "mcastpod-rc",
				namespace: ns,
				kind:      "ReplicationController",
				tempfile:  mcastPodTemplate,
			}

			defer removeResource(oc, true, true, mcastPodRc.kind, mcastPodRc.name, "-n", mcastPodRc.namespace)
			mcastPodRc.create(oc, "RCNAME="+mcastPodRc.name, "-n", mcastPodRc.namespace)

			err := waitForPodWithLabelReady(oc, ns, "name="+mcastPodRc.name)
			compat_otp.AssertWaitPollNoErr(err, "pod with label name="+mcastPodRc.name+" not ready")

			mcastPodList := getPodName(oc, ns, "name="+mcastPodRc.name)

			compat_otp.By("4. check multicast traffic without enable multicast in ns")
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv4List = getPodIPv4UDNList(oc, ns, mcastPodList)
				} else {
					ipv4List = getPodIPv4List(oc, ns, mcastPodList)
				}

				chkRes1 := chkMcastTraffic(oc, ns, mcastPodList, ipv4List, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeFalse())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv6List = getPodIPv6UDNList(oc, ns, mcastPodList)
				} else {
					ipv6List = getPodIPv6List(oc, ns, mcastPodList)
				}

				chkRes2 := chkMcastTraffic(oc, ns, mcastPodList, ipv6List, mcastipv6, port)
				o.Expect(chkRes2).Should(o.BeFalse())
			}

			compat_otp.By("5. enable multicast and check multicast traffic again")
			enableMulticast(oc, ns)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				chkRes1 := chkMcastTraffic(oc, ns, mcastPodList, ipv4List, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeTrue())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				chkRes2 := chkMcastTraffic(oc, ns, mcastPodList, ipv6List, mcastipv6, port)
				o.Expect(chkRes2).Should(o.BeTrue())
			}
			compat_otp.By("6. disable multicast and check multicast traffic again")
			disableMulticast(oc, ns)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				chkRes1 := chkMcastTraffic(oc, ns, mcastPodList, ipv4List, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeFalse())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				chkRes2 := chkMcastTraffic(oc, ns, mcastPodList, ipv6List, mcastipv6, port)
				o.Expect(chkRes2).Should(o.BeFalse())
			}
		}

	})

	/*** multicast layer2 cases failed due to bug OCPBUGS-48731, will recommit related cases once it fixed.

	g.It("Author:yingwang-High-78446-Delete/add udn pods should not affect other pods to receive multicast traffic (layer 2).", func() {
		var (
			udnCRDdualStack   = filepath.Join(testDataDirUDN, "udn_crd_layer2_dualstack_template.yaml")
			udnCRDSingleStack = filepath.Join(testDataDirUDN, "udn_crd_layer2_singlestack_template.yaml")
			mcastPodTemplate  = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns                string
			ipStackType       = checkIPStackType(oc)
			ipv4List          []string
			ipv6List          []string
			mcastipv4         = "232.43.211.234"
			mcastipv6         = "ff3e::4321:1234"
			intf              string
			port              = "4321"
		)
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled. ")
		}
		//cover both udn and default network. when i ==0, test udn, when i ==1, test default
		for i := 0; i < 2; i++ {
			if i == 0 {
				compat_otp.By("############# test multicast on pods with udn primary interface")
				compat_otp.By("###1. create udn namespace")
				oc.CreateNamespaceUDN()
				ns = oc.Namespace()
				intf = "ovn-udn1"

				compat_otp.By("###2. Create CRD for UDN")

				ipStackType := checkIPStackType(oc)
				var cidr, ipv4cidr, ipv6cidr string
				if ipStackType == "ipv4single" {
					cidr = "10.150.0.0/16"
				} else {
					if ipStackType == "ipv6single" {
						cidr = "2010:100:200::0/48"
					} else {
						ipv4cidr = "10.150.0.0/16"
						ipv6cidr = "2010:100:200::0/48"
					}
				}

				var udncrd udnCRDResource
				if ipStackType == "dualstack" {
					udncrd = udnCRDResource{
						crdname:   "udn-network-78446",
						namespace: ns,
						role:      "Primary",
						IPv4cidr:  ipv4cidr,
						IPv6cidr:  ipv6cidr,
						template:  udnCRDdualStack,
					}
					udncrd.createLayer2DualStackUDNCRD(oc)

				} else {
					udncrd = udnCRDResource{
						crdname:   "udn-network-78446",
						namespace: ns,
						role:      "Primary",
						cidr:      cidr,
						template:  udnCRDSingleStack,
					}
					udncrd.createLayer2SingleStackUDNCRD(oc)
				}
				err := waitUDNCRDApplied(oc, ns, udncrd.crdname)
				o.Expect(err).NotTo(o.HaveOccurred())

			} else {
				compat_otp.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns = oc.Namespace()
				intf = "eth0"
			}
			compat_otp.By("###3. Create 3 multicast testing pods")
			mcastPodRc := networkingRes{
				name:      "mcastpod-rc",
				namespace: ns,
				kind:      "ReplicationController",
				tempfile:  mcastPodTemplate,
			}

			defer removeResource(oc, true, true, mcastPodRc.kind, mcastPodRc.name, "-n", ns)
			mcastPodRc.create(oc, "RCNAME="+mcastPodRc.name, "-n", mcastPodRc.namespace)

			err := waitForPodWithLabelReady(oc, ns, "name="+mcastPodRc.name)
			compat_otp.AssertWaitPollNoErr(err, "pod with label name="+mcastPodRc.name+" not ready")

			mcastPodList := getPodName(oc, ns, "name="+mcastPodRc.name)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {

				if i == 0 {
					ipv4List = getPodIPv4UDNList(oc, ns, mcastPodList)
				} else {
					ipv4List = getPodIPv4List(oc, ns, mcastPodList)
				}
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {

				if i == 0 {
					ipv6List = getPodIPv6UDNList(oc, ns, mcastPodList)
				} else {
					ipv6List = getPodIPv6List(oc, ns, mcastPodList)
				}
			}

			compat_otp.By("###4. enable multicast and check multicast traffic")
			enableMulticast(oc, ns)
			//delete one pod druing sending traffic, and check the rest 2 pods still can receive mucast traffic
			pktFile1 := "/tmp/" + getRandomString() + ".txt"
			pktFile2 := "/tmp/" + getRandomString() + ".txt"
			pktFile3 := "/tmp/" + getRandomString() + ".txt"

			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				startMcastTrafficOnPod(oc, ns, mcastPodList[0], ipv4List, pktFile1, mcastipv4, port)
				startMcastTrafficOnPod(oc, ns, mcastPodList[1], ipv4List, pktFile2, mcastipv4, port)
				//add sleep time to make sure traffic started.
				time.Sleep(5 * time.Second)
				chkMcastAddress(oc, ns, mcastPodList[0], intf, mcastipv4)
				chkMcastAddress(oc, ns, mcastPodList[1], intf, mcastipv4)

				//startMcastTrafficOnPod(oc, ns, mcastPodList[2], ipv4List, pktFile3)
				removeResource(oc, true, true, "pod", mcastPodList[2], "-n", ns)
				//add sleep time to make sure traffic completed.
				time.Sleep(20 * time.Second)
				chkRes1 := chkMcatRcvOnPod(oc, ns, mcastPodList[0], ipv4List[0], ipv4List, mcastipv4, pktFile1)
				chkRes2 := chkMcatRcvOnPod(oc, ns, mcastPodList[1], ipv4List[1], ipv4List, mcastipv4, pktFile2)
				o.Expect(chkRes1).Should(o.BeTrue())
				o.Expect(chkRes2).Should(o.BeTrue())
			}
			if ipStackType == "dualstack" {
				//tested the new rc pod for ipv6
				mcastPodList = getPodName(oc, ns, "name="+mcastPodRc.name)
				if i == 0 {
					ipv6List = getPodIPv6UDNList(oc, ns, mcastPodList)
				} else {
					ipv6List = getPodIPv6List(oc, ns, mcastPodList)
				}
				startMcastTrafficOnPod(oc, ns, mcastPodList[0], ipv6List, pktFile1, mcastipv6, port)
				startMcastTrafficOnPod(oc, ns, mcastPodList[1], ipv6List, pktFile2, mcastipv6, port)
				startMcastTrafficOnPod(oc, ns, mcastPodList[2], ipv6List, pktFile3, mcastipv6, port)
				//add sleep time to make sure traffic started.
				time.Sleep(5 * time.Second)
				chkMcastAddress(oc, ns, mcastPodList[0], intf, mcastipv6)
				chkMcastAddress(oc, ns, mcastPodList[1], intf, mcastipv6)
				chkMcastAddress(oc, ns, mcastPodList[2], intf, mcastipv6)
				removeResource(oc, true, true, "pod", mcastPodList[2], "-n", ns)
				//add sleep time to make sure traffic completed.
				time.Sleep(20 * time.Second)
				chkRes1 := chkMcatRcvOnPod(oc, ns, mcastPodList[0], ipv6List[0], ipv6List, mcastipv6, pktFile1)
				chkRes2 := chkMcatRcvOnPod(oc, ns, mcastPodList[1], ipv6List[1], ipv6List, mcastipv6, pktFile2)
				chkRes3 := chkMcatRcvOnPod(oc, ns, mcastPodList[2], ipv6List[2], ipv6List, mcastipv6, pktFile3)
				o.Expect(chkRes1).Should(o.BeTrue())
				o.Expect(chkRes2).Should(o.BeTrue())
				o.Expect(chkRes3).Should(o.BeTrue())
			}

		}
	})
	g.It("Author:yingwang-High-78381-CUDN pods should be able to subscribe send and receive multicast traffic (layer 2).", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns               string
			key              = "test.cudn.layer2"
			ipStackType      = checkIPStackType(oc)
			ipv4List         []string
			ipv6List         []string
			mcastipv4        = "232.43.211.234"
			mcastipv6        = "ff3e::4321:1234"
			port             = "4321"

			crdName = "cudn-network-78381"
			values  = []string{"value-78381-1", "value-78381-2"}
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled. ")
		}
		//cover both udn and default network. when i ==0, test udn, when i ==1, test default
		for i := 0; i < 2; i++ {
			if i == 0 {
				compat_otp.By("1. create 2 namespaces for CUDN")
				oc.CreateNamespaceUDN()
				ns = oc.Namespace()

				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", key)).Execute()
				err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", key, values[0])).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())

				compat_otp.By("2. create CUDN in cudnNS")
				ipStackType := checkIPStackType(oc)
				var cidr, ipv4cidr, ipv6cidr string
				if ipStackType == "ipv4single" {
					cidr = "10.150.0.0/16"
				} else {
					if ipStackType == "ipv6single" {
						cidr = "2010:100:200::0/60"
					} else {
						ipv4cidr = "10.150.0.0/16"
						ipv6cidr = "2010:100:200::0/60"
					}
				}

				defer removeResource(oc, true, true, "clusteruserdefinednetwork", crdName)
				_, err = createCUDNCRD(oc, key, crdName, ipv4cidr, ipv6cidr, cidr, "layer2", values)
				o.Expect(err).NotTo(o.HaveOccurred())

			} else {
				compat_otp.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns = oc.Namespace()

			}
			compat_otp.By("3. Create 3 multicast testing pods")
			mcastPodRc := networkingRes{
				name:      "mcastpod-rc",
				namespace: ns,
				kind:      "ReplicationController",
				tempfile:  mcastPodTemplate,
			}

			defer removeResource(oc, true, true, mcastPodRc.kind, mcastPodRc.name, "-n", ns)
			mcastPodRc.create(oc, "RCNAME="+mcastPodRc.name, "-n", ns)

			err := waitForPodWithLabelReady(oc, ns, "name="+mcastPodRc.name)
			compat_otp.AssertWaitPollNoErr(err, "pod with label name="+mcastPodRc.name+" not ready")

			mcastPodList := getPodName(oc, ns, "name="+mcastPodRc.name)

			compat_otp.By("4. enable mulitcast and send multicast traffic")
			enableMulticast(oc, ns)

			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv4List = getPodIPv4UDNList(oc, ns, mcastPodList)
				} else {
					ipv4List = getPodIPv4List(oc, ns, mcastPodList)
				}

				chkRes := chkMcastTraffic(oc, ns, mcastPodList, ipv4List, mcastipv4, port)
				o.Expect(chkRes).Should(o.BeTrue())

			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv6List = getPodIPv6UDNList(oc, ns, mcastPodList)
				} else {
					ipv6List = getPodIPv6List(oc, ns, mcastPodList)
				}
				chkRes1 := chkMcastTraffic(oc, ns, mcastPodList, ipv6List, mcastipv6, port)
				o.Expect(chkRes1).Should(o.BeTrue())
			}
		}

	})
	***/
	g.It("Author:yingwang-High-78448-udn pods can join different multicast groups at same time.", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns               string
			ipStackType      = checkIPStackType(oc)
			ipv4List         []string
			ipv6List         []string
			mcastipv4        = []string{"232.43.211.234", "232.43.211.235", "232.43.211.236"}
			mcastipv6        = []string{"ff3e::4321:1234", "ff3e::4321:1235", "ff3e::4321:1236"}
			intf             string
			port             = []string{"4321", "4322", "4323"}
		)
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled. ")
		}
		//cover both udn and default network. when i ==0, test udn, when i ==1, test default
		for j := 0; j < 2; j++ {
			if j == 0 {
				compat_otp.By("############# test multicast on pods with udn primary interface")
				compat_otp.By("###1. create udn namespace")
				oc.CreateNamespaceUDN()
				ns = oc.Namespace()
				intf = "ovn-udn1"

				compat_otp.By("###2. Create CRD for UDN")

				var cidr, ipv4cidr, ipv6cidr string
				if ipStackType == "ipv4single" {
					cidr = "10.150.0.0/16"
				} else {
					if ipStackType == "ipv6single" {
						cidr = "2010:100:200::0/48"
					} else {
						ipv4cidr = "10.150.0.0/16"
						ipv6cidr = "2010:100:200::0/48"
					}
				}
				createGeneralUDNCRD(oc, ns, "udn-78448", ipv4cidr, ipv6cidr, cidr, "layer3")
			} else {
				compat_otp.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns = oc.Namespace()
				intf = "eth0"
			}
			compat_otp.By("###3. Create 3 multicast testing pods")
			mcastPodRc := networkingRes{
				name:      "mcastpod-rc",
				namespace: ns,
				kind:      "ReplicationController",
				tempfile:  mcastPodTemplate,
			}

			defer removeResource(oc, true, true, mcastPodRc.kind, mcastPodRc.name, "-n", ns)
			mcastPodRc.create(oc, "RCNAME="+mcastPodRc.name, "-n", mcastPodRc.namespace)

			err := waitForPodWithLabelReady(oc, ns, "name="+mcastPodRc.name)
			compat_otp.AssertWaitPollNoErr(err, "pod with label name="+mcastPodRc.name+" not ready")

			mcastPodList := getPodName(oc, ns, "name="+mcastPodRc.name)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if j == 0 {
					ipv4List = getPodIPv4UDNList(oc, ns, mcastPodList)
				} else {
					ipv4List = getPodIPv4List(oc, ns, mcastPodList)
				}
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if j == 0 {
					ipv6List = getPodIPv6UDNList(oc, ns, mcastPodList)
				} else {
					ipv6List = getPodIPv6List(oc, ns, mcastPodList)
				}
			}

			compat_otp.By("###4. enable multicast and check multicast traffic")
			enableMulticast(oc, ns)
			//send multicast traffic to join different multicast group at the same time
			pktFile1 := make([]string, len(mcastPodList))
			pktFile2 := make([]string, len(mcastPodList))
			pktFile3 := make([]string, len(mcastPodList))

			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				for i, podName := range mcastPodList {
					pktFile1[i] = "/tmp/" + getRandomString() + ".txt"
					pktFile2[i] = "/tmp/" + getRandomString() + ".txt"
					pktFile3[i] = "/tmp/" + getRandomString() + ".txt"
					startMcastTrafficOnPod(oc, ns, podName, ipv4List, pktFile1[i], mcastipv4[0], port[0])
					startMcastTrafficOnPod(oc, ns, podName, ipv4List, pktFile2[i], mcastipv4[1], port[1])
					startMcastTrafficOnPod(oc, ns, podName, ipv4List, pktFile3[i], mcastipv4[2], port[2])
				}
				//add sleep time to make sure traffic started
				time.Sleep(5 * time.Second)
				//choose one pod to check the multicast ip address
				chkMcastAddress(oc, ns, mcastPodList[0], intf, mcastipv4[0])
				chkMcastAddress(oc, ns, mcastPodList[0], intf, mcastipv4[1])
				chkMcastAddress(oc, ns, mcastPodList[0], intf, mcastipv4[2])
				//add sleep time to make sure traffic completed.
				time.Sleep(20 * time.Second)
				//choose one pod to check the received multicast pakets
				chkRes1 := chkMcatRcvOnPod(oc, ns, mcastPodList[1], ipv4List[1], ipv4List, mcastipv4[0], pktFile1[1])
				chkRes2 := chkMcatRcvOnPod(oc, ns, mcastPodList[1], ipv4List[1], ipv4List, mcastipv4[1], pktFile2[1])
				chkRes3 := chkMcatRcvOnPod(oc, ns, mcastPodList[1], ipv4List[1], ipv4List, mcastipv4[2], pktFile3[1])
				o.Expect(chkRes1).Should(o.BeTrue())
				o.Expect(chkRes2).Should(o.BeTrue())
				o.Expect(chkRes3).Should(o.BeTrue())

			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				for i, podName := range mcastPodList {
					pktFile1[i] = "/tmp/" + getRandomString() + ".txt"
					pktFile2[i] = "/tmp/" + getRandomString() + ".txt"
					pktFile3[i] = "/tmp/" + getRandomString() + ".txt"
					startMcastTrafficOnPod(oc, ns, podName, ipv6List, pktFile1[i], mcastipv6[0], port[0])
					startMcastTrafficOnPod(oc, ns, podName, ipv6List, pktFile2[i], mcastipv6[1], port[1])
					startMcastTrafficOnPod(oc, ns, podName, ipv6List, pktFile3[i], mcastipv6[2], port[2])
				}
				//add sleep time to make sure traffic started.
				time.Sleep(5 * time.Second)
				//choose one pod to check the multicast ipv6 address
				chkMcastAddress(oc, ns, mcastPodList[2], intf, mcastipv6[0])
				chkMcastAddress(oc, ns, mcastPodList[2], intf, mcastipv6[1])
				chkMcastAddress(oc, ns, mcastPodList[2], intf, mcastipv6[2])
				//add sleep time to make sure traffic completed.
				time.Sleep(20 * time.Second)

				//choose one pod to check the received multicast pakets
				chkRes1 := chkMcatRcvOnPod(oc, ns, mcastPodList[2], ipv6List[2], ipv6List, mcastipv6[0], pktFile1[2])
				chkRes2 := chkMcatRcvOnPod(oc, ns, mcastPodList[2], ipv6List[2], ipv6List, mcastipv6[1], pktFile2[2])
				chkRes3 := chkMcatRcvOnPod(oc, ns, mcastPodList[2], ipv6List[2], ipv6List, mcastipv6[2], pktFile3[2])
				o.Expect(chkRes1).Should(o.BeTrue())
				o.Expect(chkRes2).Should(o.BeTrue())
				o.Expect(chkRes3).Should(o.BeTrue())

			}

		}

	})

	g.It("Author:yingwang-High-78450-Same multicast groups can be created in multiple namespaces with udn configured.", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns1              string
			ns2              string
			ipStackType      = checkIPStackType(oc)
			ipv4List1        []string
			ipv6List1        []string
			ipv4List2        []string
			ipv6List2        []string
			mcastipv4        = "232.43.211.234"
			mcastipv6        = "ff3e::4321:1234"
			port             = "4321"
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled. ")
		}
		//cover both udn and default network. when i ==0, test udn, when i ==1, test default
		for i := 0; i < 2; i++ {
			if i == 0 {
				compat_otp.By("############# test multicast on pods with udn primary interface")
				compat_otp.By("1. create 2 udn namespaces")
				oc.CreateNamespaceUDN()
				ns1 = oc.Namespace()

				oc.CreateNamespaceUDN()
				ns2 = oc.Namespace()

				compat_otp.By("2. Create CRD for UDNs")

				var cidr, ipv4cidr, ipv6cidr string
				if ipStackType == "ipv4single" {
					cidr = "10.150.0.0/16"
				} else {
					if ipStackType == "ipv6single" {
						cidr = "2010:100:200::0/48"
					} else {
						ipv4cidr = "10.150.0.0/16"
						ipv6cidr = "2010:100:200::0/48"
					}
				}
				createGeneralUDNCRD(oc, ns1, "udn-78450-1", ipv4cidr, ipv6cidr, cidr, "layer3")
				createGeneralUDNCRD(oc, ns2, "udn-78450-2", ipv4cidr, ipv6cidr, cidr, "layer3")
			} else {
				compat_otp.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns1 = oc.Namespace()
				oc.SetupProject()
				ns2 = oc.Namespace()
			}
			compat_otp.By("3. Create 3 multicast testing pods")
			mcastPodRc1 := networkingRes{
				name:      "mcastpod-rc-1",
				namespace: ns1,
				kind:      "ReplicationController",
				tempfile:  mcastPodTemplate,
			}

			mcastPodRc2 := networkingRes{
				name:      "mcastpod-rc-2",
				namespace: ns2,
				kind:      "ReplicationController",
				tempfile:  mcastPodTemplate,
			}

			defer removeResource(oc, true, true, mcastPodRc1.kind, mcastPodRc1.name, "-n", ns1)
			mcastPodRc1.create(oc, "RCNAME="+mcastPodRc1.name, "-n", ns1)

			defer removeResource(oc, true, true, mcastPodRc2.kind, mcastPodRc2.name, "-n", ns2)
			mcastPodRc2.create(oc, "RCNAME="+mcastPodRc2.name, "-n", ns2)

			err := waitForPodWithLabelReady(oc, ns1, "name="+mcastPodRc1.name)
			compat_otp.AssertWaitPollNoErr(err, "pod with label name="+mcastPodRc1.name+" not ready")

			err = waitForPodWithLabelReady(oc, ns2, "name="+mcastPodRc2.name)
			compat_otp.AssertWaitPollNoErr(err, "pod with label name="+mcastPodRc2.name+" not ready")

			mcastPodList1 := getPodName(oc, ns1, "name="+mcastPodRc1.name)
			mcastPodList2 := getPodName(oc, ns2, "name="+mcastPodRc2.name)

			compat_otp.By("4. enable mulitcast and send multicast traffic in different ns to join a same multicast group")
			enableMulticast(oc, ns1)
			enableMulticast(oc, ns2)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv4List1 = getPodIPv4UDNList(oc, ns1, mcastPodList1)
					ipv4List2 = getPodIPv4UDNList(oc, ns2, mcastPodList2)
				} else {
					ipv4List1 = getPodIPv4List(oc, ns1, mcastPodList1)
					ipv4List2 = getPodIPv4List(oc, ns2, mcastPodList2)
				}

				chkRes1 := chkMcastTraffic(oc, ns1, mcastPodList1, ipv4List1, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeTrue())
				chkRes2 := chkMcastTraffic(oc, ns2, mcastPodList2, ipv4List2, mcastipv4, port)
				o.Expect(chkRes2).Should(o.BeTrue())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv6List1 = getPodIPv6UDNList(oc, ns1, mcastPodList1)
					ipv6List2 = getPodIPv6UDNList(oc, ns2, mcastPodList2)
				} else {
					ipv6List1 = getPodIPv6List(oc, ns1, mcastPodList1)
					ipv6List2 = getPodIPv6List(oc, ns2, mcastPodList2)
				}

				chkRes3 := chkMcastTraffic(oc, ns1, mcastPodList1, ipv6List1, mcastipv6, port)
				o.Expect(chkRes3).Should(o.BeTrue())
				chkRes4 := chkMcastTraffic(oc, ns2, mcastPodList2, ipv6List2, mcastipv6, port)
				o.Expect(chkRes4).Should(o.BeTrue())
			}

		}

	})

	g.It("Author:yingwang-High-78382-check CUDN pods should not be able to receive multicast traffic from other pods in different namespace which sharing a same CUDN (layer 3).", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns1              string
			ns2              string
			key              = "test.cudn.layer3"
			ipStackType      = checkIPStackType(oc)
			ipv4List1        []string
			ipv6List1        []string
			ipv4List2        []string
			ipv6List2        []string
			mcastipv4        = "232.43.211.234"
			mcastipv6        = "ff3e::4321:1234"
			port             = "4321"

			crdName = "cudn-network-78382"
			values  = []string{"value-78382-1", "value-78382-2"}
		)

		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This test requires at least 2 worker nodes which is not fulfilled. ")
		}
		//cover both udn and default network. when i ==0, test udn, when i ==1, test default
		for i := 0; i < 2; i++ {
			if i == 0 {
				compat_otp.By("###1. create 2 namespaces for CUDN")
				oc.CreateNamespaceUDN()
				ns1 = oc.Namespace()
				oc.CreateNamespaceUDN()
				ns2 = oc.Namespace()

				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s-", key)).Execute()
				err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, fmt.Sprintf("%s=%s", key, values[0])).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())

				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s-", key)).Execute()
				err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, fmt.Sprintf("%s=%s", key, values[1])).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())

				compat_otp.By("####2. create CUDN in cudnNS")
				ipStackType := checkIPStackType(oc)
				var cidr, ipv4cidr, ipv6cidr string
				if ipStackType == "ipv4single" {
					cidr = "10.150.0.0/16"
				} else {
					if ipStackType == "ipv6single" {
						cidr = "2010:100:200::0/60"
					} else {
						ipv4cidr = "10.150.0.0/16"
						ipv6cidr = "2010:100:200::0/60"
					}
				}

				defer removeResource(oc, true, true, "clusteruserdefinednetwork", crdName)
				_, err = createCUDNCRD(oc, key, crdName, ipv4cidr, ipv6cidr, cidr, "layer3", values)
				o.Expect(err).NotTo(o.HaveOccurred())

			} else {
				compat_otp.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns1 = oc.Namespace()
				oc.SetupProject()
				ns2 = oc.Namespace()
			}
			compat_otp.By("####3. Create 3 multicast testing pods")
			mcastPodRc1 := networkingRes{
				name:      "mcastpod-rc-1",
				namespace: ns1,
				kind:      "ReplicationController",
				tempfile:  mcastPodTemplate,
			}

			mcastPodRc2 := networkingRes{
				name:      "mcastpod-rc-2",
				namespace: ns2,
				kind:      "ReplicationController",
				tempfile:  mcastPodTemplate,
			}

			defer removeResource(oc, true, true, mcastPodRc1.kind, mcastPodRc1.name, "-n", ns1)
			mcastPodRc1.create(oc, "RCNAME="+mcastPodRc1.name, "-n", ns1)

			defer removeResource(oc, true, true, mcastPodRc2.kind, mcastPodRc2.name, "-n", ns2)
			mcastPodRc2.create(oc, "RCNAME="+mcastPodRc2.name, "-n", ns2)

			err := waitForPodWithLabelReady(oc, ns1, "name="+mcastPodRc1.name)
			compat_otp.AssertWaitPollNoErr(err, "pod with label name="+mcastPodRc1.name+" not ready")

			err = waitForPodWithLabelReady(oc, ns2, "name="+mcastPodRc2.name)
			compat_otp.AssertWaitPollNoErr(err, "pod with label name="+mcastPodRc2.name+" not ready")

			mcastPodList1 := getPodName(oc, ns1, "name="+mcastPodRc1.name)
			mcastPodList2 := getPodName(oc, ns2, "name="+mcastPodRc2.name)

			compat_otp.By("###4. enable mulitcast and send multicast traffic in different ns to join a same multicast group")
			enableMulticast(oc, ns1)
			enableMulticast(oc, ns2)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv4List1 = getPodIPv4UDNList(oc, ns1, mcastPodList1)
					ipv4List2 = getPodIPv4UDNList(oc, ns2, mcastPodList2)
				} else {
					ipv4List1 = getPodIPv4List(oc, ns1, mcastPodList1)
					ipv4List2 = getPodIPv4List(oc, ns2, mcastPodList2)
				}

				chkRes1 := chkMcastTraffic(oc, ns1, mcastPodList1, ipv4List1, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeTrue())
				chkRes2 := chkMcastTraffic(oc, ns2, mcastPodList2, ipv4List2, mcastipv4, port)
				o.Expect(chkRes2).Should(o.BeTrue())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv6List1 = getPodIPv6UDNList(oc, ns1, mcastPodList1)
					ipv6List2 = getPodIPv6UDNList(oc, ns2, mcastPodList2)
				} else {
					ipv6List1 = getPodIPv6List(oc, ns1, mcastPodList1)
					ipv6List2 = getPodIPv6List(oc, ns2, mcastPodList2)
				}

				chkRes3 := chkMcastTraffic(oc, ns1, mcastPodList1, ipv6List1, mcastipv6, port)
				o.Expect(chkRes3).Should(o.BeTrue())
				chkRes4 := chkMcastTraffic(oc, ns2, mcastPodList2, ipv6List2, mcastipv6, port)
				o.Expect(chkRes4).Should(o.BeTrue())
			}

			compat_otp.By("###5. send multicast traffic accross different ns to join a same multicast group")

			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				var podIPv4_1, podIPv4_2 string
				if i == 0 {
					podIPv4_1 = getPodIPUDNv4(oc, ns1, mcastPodList1[0], "ovn-udn1")
					podIPv4_2 = getPodIPUDNv4(oc, ns2, mcastPodList2[0], "ovn-udn1")
				} else {
					podIPv4_1 = getPodIPv4(oc, ns1, mcastPodList1[0])
					podIPv4_2 = getPodIPv4(oc, ns2, mcastPodList2[0])
				}
				ipv4List := []string{podIPv4_1, podIPv4_2}
				pktFile1 := "/tmp/" + getRandomString() + ".txt"
				pktFile2 := "/tmp/" + getRandomString() + ".txt"
				//send multicast traffic accrocss different ns
				startMcastTrafficOnPod(oc, ns1, mcastPodList1[0], ipv4List, pktFile1, mcastipv4, port)
				startMcastTrafficOnPod(oc, ns2, mcastPodList2[0], ipv4List, pktFile2, mcastipv4, port)
				//add sleep time to make sure traffic completed.
				time.Sleep(30 * time.Second)

				chkRes1 := chkMcatRcvOnPod(oc, ns1, mcastPodList1[0], podIPv4_1, ipv4List, mcastipv4, pktFile1)
				chkRes2 := chkMcatRcvOnPod(oc, ns2, mcastPodList2[0], podIPv4_2, ipv4List, mcastipv4, pktFile2)
				o.Expect(chkRes1).Should(o.BeFalse())
				o.Expect(chkRes2).Should(o.BeFalse())

			}
			if ipStackType == "dualstack" || ipStackType == "dualstack" {
				var podIPv6_1, podIPv6_2 string
				if i == 0 {
					podIPv6_1 = getPodIPUDNv6(oc, ns1, mcastPodList1[0], "ovn-udn1")
					podIPv6_2 = getPodIPUDNv6(oc, ns2, mcastPodList2[0], "ovn-udn1")
				} else {
					podIPv6_1 = getPodIPv6(oc, ns1, mcastPodList1[0], ipStackType)
					podIPv6_2 = getPodIPv6(oc, ns2, mcastPodList2[0], ipStackType)
				}
				ipv6List := []string{podIPv6_1, podIPv6_2}
				pktFile1 := "/tmp/" + getRandomString() + ".txt"
				pktFile2 := "/tmp/" + getRandomString() + ".txt"
				//send multicast traffic accrocss different ns
				startMcastTrafficOnPod(oc, ns1, mcastPodList1[0], ipv6List, pktFile1, mcastipv6, port)
				startMcastTrafficOnPod(oc, ns2, mcastPodList2[0], ipv6List, pktFile2, mcastipv6, port)
				//add sleep time to make sure traffic completed.
				time.Sleep(30 * time.Second)

				chkRes1 := chkMcatRcvOnPod(oc, ns1, mcastPodList1[0], podIPv6_1, ipv6List, mcastipv6, pktFile1)
				chkRes2 := chkMcatRcvOnPod(oc, ns2, mcastPodList2[0], podIPv6_2, ipv6List, mcastipv6, pktFile2)
				o.Expect(chkRes1).Should(o.BeFalse())
				o.Expect(chkRes2).Should(o.BeFalse())
			}
		}

	})

})
