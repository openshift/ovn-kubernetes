package otp

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"
	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/utils"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"

	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

var _ = g.Describe("[sig-network][Suite:openshift/conformance/serial] SDN network segmentation multicast", func() {

	var (
		oc               = exutil.NewCLI("networking-udn")
		testDataDirMcast = testdata.FixturePath("networking", "network_segmentation", "multicast")
	)

	g.It("[JIRA:Networking][OTP] 78447-udn pods should/should not receive multicast traffic when enable/disable multicast.", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns               string
			ipStackType      = otputils.CheckIPStackType(oc)
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
				g.By("############# test multicast on pods with udn primary interface")
				g.By("1. create udn namespace")
				oc.CreateNamespaceUDN()
				ns = oc.Namespace()

				g.By("2. Create CRD for UDN")
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

				otputils.CreateGeneralUDNCRD(oc, ns, "udn-78447", ipv4cidr, ipv6cidr, cidr, "layer3")

			} else {
				g.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns = oc.Namespace()
			}
			g.By("3. Create 3 multicast testing pods")

			defer otputils.RemoveResource(oc, true, true, "ReplicationController", "mcastpod-rc", "-n", ns)
			err := otputils.ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", mcastPodTemplate, "-p", "RCNAME=mcastpod-rc", "-n", ns)
			o.Expect(err).NotTo(o.HaveOccurred())

			err = otputils.WaitForPodWithLabelReady(oc, ns, "name=mcastpod-rc")
			o.Expect(err).NotTo(o.HaveOccurred())

			mcastPodList := otputils.GetPodName(oc, ns, "name=mcastpod-rc")

			g.By("4. check multicast traffic without enable multicast in ns")
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv4List = otputils.GetPodIPv4UDNList(oc, ns, mcastPodList)
				} else {
					ipv4List = otputils.GetPodIPv4List(oc, ns, mcastPodList)
				}

				chkRes1 := otputils.ChkMcastTraffic(oc, ns, mcastPodList, ipv4List, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeFalse())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv6List = otputils.GetPodIPv6UDNList(oc, ns, mcastPodList)
				} else {
					ipv6List = otputils.GetPodIPv6List(oc, ns, mcastPodList)
				}

				chkRes2 := otputils.ChkMcastTraffic(oc, ns, mcastPodList, ipv6List, mcastipv6, port)
				o.Expect(chkRes2).Should(o.BeFalse())
			}

			g.By("5. enable multicast and check multicast traffic again")
			otputils.EnableMulticast(oc, ns)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				chkRes1 := otputils.ChkMcastTraffic(oc, ns, mcastPodList, ipv4List, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeTrue())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				chkRes2 := otputils.ChkMcastTraffic(oc, ns, mcastPodList, ipv6List, mcastipv6, port)
				o.Expect(chkRes2).Should(o.BeTrue())
			}
			g.By("6. disable multicast and check multicast traffic again")
			otputils.DisableMulticast(oc, ns)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				chkRes1 := otputils.ChkMcastTraffic(oc, ns, mcastPodList, ipv4List, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeFalse())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				chkRes2 := otputils.ChkMcastTraffic(oc, ns, mcastPodList, ipv6List, mcastipv6, port)
				o.Expect(chkRes2).Should(o.BeFalse())
			}
		}

	})

	g.It("[JIRA:Networking][OTP] 78448-udn pods can join different multicast groups at same time.", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns               string
			ipStackType      = otputils.CheckIPStackType(oc)
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
		//cover both udn and default network. when j ==0, test udn, when j ==1, test default
		for j := 0; j < 2; j++ {
			if j == 0 {
				g.By("############# test multicast on pods with udn primary interface")
				g.By("###1. create udn namespace")
				oc.CreateNamespaceUDN()
				ns = oc.Namespace()
				intf = "ovn-udn1"

				g.By("###2. Create CRD for UDN")

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
				otputils.CreateGeneralUDNCRD(oc, ns, "udn-78448", ipv4cidr, ipv6cidr, cidr, "layer3")
			} else {
				g.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns = oc.Namespace()
				intf = "eth0"
			}
			g.By("###3. Create 3 multicast testing pods")

			defer otputils.RemoveResource(oc, true, true, "ReplicationController", "mcastpod-rc", "-n", ns)
			err := otputils.ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", mcastPodTemplate, "-p", "RCNAME=mcastpod-rc", "-n", ns)
			o.Expect(err).NotTo(o.HaveOccurred())

			err = otputils.WaitForPodWithLabelReady(oc, ns, "name=mcastpod-rc")
			o.Expect(err).NotTo(o.HaveOccurred())

			mcastPodList := otputils.GetPodName(oc, ns, "name=mcastpod-rc")
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if j == 0 {
					ipv4List = otputils.GetPodIPv4UDNList(oc, ns, mcastPodList)
				} else {
					ipv4List = otputils.GetPodIPv4List(oc, ns, mcastPodList)
				}
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if j == 0 {
					ipv6List = otputils.GetPodIPv6UDNList(oc, ns, mcastPodList)
				} else {
					ipv6List = otputils.GetPodIPv6List(oc, ns, mcastPodList)
				}
			}

			g.By("###4. enable multicast and check multicast traffic")
			otputils.EnableMulticast(oc, ns)
			//send multicast traffic to join different multicast group at the same time
			pktFile1 := make([]string, len(mcastPodList))
			pktFile2 := make([]string, len(mcastPodList))
			pktFile3 := make([]string, len(mcastPodList))

			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				for i, podName := range mcastPodList {
					pktFile1[i] = "/tmp/" + otputils.GetRandomString() + ".txt"
					pktFile2[i] = "/tmp/" + otputils.GetRandomString() + ".txt"
					pktFile3[i] = "/tmp/" + otputils.GetRandomString() + ".txt"
					otputils.StartMcastTrafficOnPod(oc, ns, podName, ipv4List, pktFile1[i], mcastipv4[0], port[0])
					otputils.StartMcastTrafficOnPod(oc, ns, podName, ipv4List, pktFile2[i], mcastipv4[1], port[1])
					otputils.StartMcastTrafficOnPod(oc, ns, podName, ipv4List, pktFile3[i], mcastipv4[2], port[2])
				}
				//add sleep time to make sure traffic started
				time.Sleep(5 * time.Second)
				//choose one pod to check the multicast ip address
				otputils.ChkMcastAddress(oc, ns, mcastPodList[0], intf, mcastipv4[0])
				otputils.ChkMcastAddress(oc, ns, mcastPodList[0], intf, mcastipv4[1])
				otputils.ChkMcastAddress(oc, ns, mcastPodList[0], intf, mcastipv4[2])
				//add sleep time to make sure traffic completed.
				time.Sleep(20 * time.Second)
				//choose one pod to check the received multicast packets
				chkRes1 := otputils.ChkMcatRcvOnPod(oc, ns, mcastPodList[1], ipv4List[1], ipv4List, mcastipv4[0], pktFile1[1])
				chkRes2 := otputils.ChkMcatRcvOnPod(oc, ns, mcastPodList[1], ipv4List[1], ipv4List, mcastipv4[1], pktFile2[1])
				chkRes3 := otputils.ChkMcatRcvOnPod(oc, ns, mcastPodList[1], ipv4List[1], ipv4List, mcastipv4[2], pktFile3[1])
				o.Expect(chkRes1).Should(o.BeTrue())
				o.Expect(chkRes2).Should(o.BeTrue())
				o.Expect(chkRes3).Should(o.BeTrue())

			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				for i, podName := range mcastPodList {
					pktFile1[i] = "/tmp/" + otputils.GetRandomString() + ".txt"
					pktFile2[i] = "/tmp/" + otputils.GetRandomString() + ".txt"
					pktFile3[i] = "/tmp/" + otputils.GetRandomString() + ".txt"
					otputils.StartMcastTrafficOnPod(oc, ns, podName, ipv6List, pktFile1[i], mcastipv6[0], port[0])
					otputils.StartMcastTrafficOnPod(oc, ns, podName, ipv6List, pktFile2[i], mcastipv6[1], port[1])
					otputils.StartMcastTrafficOnPod(oc, ns, podName, ipv6List, pktFile3[i], mcastipv6[2], port[2])
				}
				//add sleep time to make sure traffic started.
				time.Sleep(5 * time.Second)
				//choose one pod to check the multicast ipv6 address
				otputils.ChkMcastAddress(oc, ns, mcastPodList[2], intf, mcastipv6[0])
				otputils.ChkMcastAddress(oc, ns, mcastPodList[2], intf, mcastipv6[1])
				otputils.ChkMcastAddress(oc, ns, mcastPodList[2], intf, mcastipv6[2])
				//add sleep time to make sure traffic completed.
				time.Sleep(20 * time.Second)

				//choose one pod to check the received multicast packets
				chkRes1 := otputils.ChkMcatRcvOnPod(oc, ns, mcastPodList[2], ipv6List[2], ipv6List, mcastipv6[0], pktFile1[2])
				chkRes2 := otputils.ChkMcatRcvOnPod(oc, ns, mcastPodList[2], ipv6List[2], ipv6List, mcastipv6[1], pktFile2[2])
				chkRes3 := otputils.ChkMcatRcvOnPod(oc, ns, mcastPodList[2], ipv6List[2], ipv6List, mcastipv6[2], pktFile3[2])
				o.Expect(chkRes1).Should(o.BeTrue())
				o.Expect(chkRes2).Should(o.BeTrue())
				o.Expect(chkRes3).Should(o.BeTrue())

			}

		}

	})

	g.It("[JIRA:Networking][OTP] 78450-Same multicast groups can be created in multiple namespaces with udn configured.", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns1              string
			ns2              string
			ipStackType      = otputils.CheckIPStackType(oc)
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
				g.By("############# test multicast on pods with udn primary interface")
				g.By("1. create 2 udn namespaces")
				oc.CreateNamespaceUDN()
				ns1 = oc.Namespace()

				oc.CreateNamespaceUDN()
				ns2 = oc.Namespace()

				g.By("2. Create CRD for UDNs")

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
				otputils.CreateGeneralUDNCRD(oc, ns1, "udn-78450-1", ipv4cidr, ipv6cidr, cidr, "layer3")
				otputils.CreateGeneralUDNCRD(oc, ns2, "udn-78450-2", ipv4cidr, ipv6cidr, cidr, "layer3")
			} else {
				g.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns1 = oc.Namespace()
				oc.SetupProject()
				ns2 = oc.Namespace()
			}
			g.By("3. Create 3 multicast testing pods")

			defer otputils.RemoveResource(oc, true, true, "ReplicationController", "mcastpod-rc-1", "-n", ns1)
			err := otputils.ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", mcastPodTemplate, "-p", "RCNAME=mcastpod-rc-1", "-n", ns1)
			o.Expect(err).NotTo(o.HaveOccurred())

			defer otputils.RemoveResource(oc, true, true, "ReplicationController", "mcastpod-rc-2", "-n", ns2)
			err = otputils.ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", mcastPodTemplate, "-p", "RCNAME=mcastpod-rc-2", "-n", ns2)
			o.Expect(err).NotTo(o.HaveOccurred())

			err = otputils.WaitForPodWithLabelReady(oc, ns1, "name=mcastpod-rc-1")
			o.Expect(err).NotTo(o.HaveOccurred())

			err = otputils.WaitForPodWithLabelReady(oc, ns2, "name=mcastpod-rc-2")
			o.Expect(err).NotTo(o.HaveOccurred())

			mcastPodList1 := otputils.GetPodName(oc, ns1, "name=mcastpod-rc-1")
			mcastPodList2 := otputils.GetPodName(oc, ns2, "name=mcastpod-rc-2")

			g.By("4. enable multicast and send multicast traffic in different ns to join a same multicast group")
			otputils.EnableMulticast(oc, ns1)
			otputils.EnableMulticast(oc, ns2)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv4List1 = otputils.GetPodIPv4UDNList(oc, ns1, mcastPodList1)
					ipv4List2 = otputils.GetPodIPv4UDNList(oc, ns2, mcastPodList2)
				} else {
					ipv4List1 = otputils.GetPodIPv4List(oc, ns1, mcastPodList1)
					ipv4List2 = otputils.GetPodIPv4List(oc, ns2, mcastPodList2)
				}

				chkRes1 := otputils.ChkMcastTraffic(oc, ns1, mcastPodList1, ipv4List1, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeTrue())
				chkRes2 := otputils.ChkMcastTraffic(oc, ns2, mcastPodList2, ipv4List2, mcastipv4, port)
				o.Expect(chkRes2).Should(o.BeTrue())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv6List1 = otputils.GetPodIPv6UDNList(oc, ns1, mcastPodList1)
					ipv6List2 = otputils.GetPodIPv6UDNList(oc, ns2, mcastPodList2)
				} else {
					ipv6List1 = otputils.GetPodIPv6List(oc, ns1, mcastPodList1)
					ipv6List2 = otputils.GetPodIPv6List(oc, ns2, mcastPodList2)
				}

				chkRes3 := otputils.ChkMcastTraffic(oc, ns1, mcastPodList1, ipv6List1, mcastipv6, port)
				o.Expect(chkRes3).Should(o.BeTrue())
				chkRes4 := otputils.ChkMcastTraffic(oc, ns2, mcastPodList2, ipv6List2, mcastipv6, port)
				o.Expect(chkRes4).Should(o.BeTrue())
			}

		}

	})

	g.It("[JIRA:Networking][OTP] 78382-check CUDN pods should not be able to receive multicast traffic from other pods in different namespace which sharing a same CUDN (layer 3).", func() {
		var (
			mcastPodTemplate = filepath.Join(testDataDirMcast, "multicast-rc.json")
			ns1              string
			ns2              string
			key              = "test.cudn.layer3"
			ipStackType      = otputils.CheckIPStackType(oc)
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
				g.By("###1. create 2 namespaces for CUDN")
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

				g.By("####2. create CUDN in cudnNS")
				ipStackType := otputils.CheckIPStackType(oc)
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

				defer otputils.RemoveResource(oc, true, true, "clusteruserdefinednetwork", crdName)
				_, err = otputils.CreateCUDNCRD(oc, key, crdName, ipv4cidr, ipv6cidr, cidr, "layer3", values)
				o.Expect(err).NotTo(o.HaveOccurred())

			} else {
				g.By("############# test multicast on pods with default interface")
				oc.SetupProject()
				ns1 = oc.Namespace()
				oc.SetupProject()
				ns2 = oc.Namespace()
			}
			g.By("####3. Create 3 multicast testing pods")

			defer otputils.RemoveResource(oc, true, true, "ReplicationController", "mcastpod-rc-1", "-n", ns1)
			err := otputils.ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", mcastPodTemplate, "-p", "RCNAME=mcastpod-rc-1", "-n", ns1)
			o.Expect(err).NotTo(o.HaveOccurred())

			defer otputils.RemoveResource(oc, true, true, "ReplicationController", "mcastpod-rc-2", "-n", ns2)
			err = otputils.ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", mcastPodTemplate, "-p", "RCNAME=mcastpod-rc-2", "-n", ns2)
			o.Expect(err).NotTo(o.HaveOccurred())

			err = otputils.WaitForPodWithLabelReady(oc, ns1, "name=mcastpod-rc-1")
			o.Expect(err).NotTo(o.HaveOccurred())

			err = otputils.WaitForPodWithLabelReady(oc, ns2, "name=mcastpod-rc-2")
			o.Expect(err).NotTo(o.HaveOccurred())

			mcastPodList1 := otputils.GetPodName(oc, ns1, "name=mcastpod-rc-1")
			mcastPodList2 := otputils.GetPodName(oc, ns2, "name=mcastpod-rc-2")

			g.By("###4. enable multicast and send multicast traffic in different ns to join a same multicast group")
			otputils.EnableMulticast(oc, ns1)
			otputils.EnableMulticast(oc, ns2)
			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv4List1 = otputils.GetPodIPv4UDNList(oc, ns1, mcastPodList1)
					ipv4List2 = otputils.GetPodIPv4UDNList(oc, ns2, mcastPodList2)
				} else {
					ipv4List1 = otputils.GetPodIPv4List(oc, ns1, mcastPodList1)
					ipv4List2 = otputils.GetPodIPv4List(oc, ns2, mcastPodList2)
				}

				chkRes1 := otputils.ChkMcastTraffic(oc, ns1, mcastPodList1, ipv4List1, mcastipv4, port)
				o.Expect(chkRes1).Should(o.BeTrue())
				chkRes2 := otputils.ChkMcastTraffic(oc, ns2, mcastPodList2, ipv4List2, mcastipv4, port)
				o.Expect(chkRes2).Should(o.BeTrue())
			}
			if ipStackType == "ipv6single" || ipStackType == "dualstack" {
				if i == 0 {
					ipv6List1 = otputils.GetPodIPv6UDNList(oc, ns1, mcastPodList1)
					ipv6List2 = otputils.GetPodIPv6UDNList(oc, ns2, mcastPodList2)
				} else {
					ipv6List1 = otputils.GetPodIPv6List(oc, ns1, mcastPodList1)
					ipv6List2 = otputils.GetPodIPv6List(oc, ns2, mcastPodList2)
				}

				chkRes3 := otputils.ChkMcastTraffic(oc, ns1, mcastPodList1, ipv6List1, mcastipv6, port)
				o.Expect(chkRes3).Should(o.BeTrue())
				chkRes4 := otputils.ChkMcastTraffic(oc, ns2, mcastPodList2, ipv6List2, mcastipv6, port)
				o.Expect(chkRes4).Should(o.BeTrue())
			}

			g.By("###5. send multicast traffic across different ns to join a same multicast group")

			if ipStackType == "ipv4single" || ipStackType == "dualstack" {
				var podIPv4_1, podIPv4_2 string
				if i == 0 {
					podIPv4_1 = otputils.GetPodIPUDNv4(oc, ns1, mcastPodList1[0], "ovn-udn1")
					podIPv4_2 = otputils.GetPodIPUDNv4(oc, ns2, mcastPodList2[0], "ovn-udn1")
				} else {
					podIPv4_1 = otputils.GetPodIPv4(oc, ns1, mcastPodList1[0])
					podIPv4_2 = otputils.GetPodIPv4(oc, ns2, mcastPodList2[0])
				}
				ipv4List := []string{podIPv4_1, podIPv4_2}
				pktFile1 := "/tmp/" + otputils.GetRandomString() + ".txt"
				pktFile2 := "/tmp/" + otputils.GetRandomString() + ".txt"
				//send multicast traffic across different ns
				otputils.StartMcastTrafficOnPod(oc, ns1, mcastPodList1[0], ipv4List, pktFile1, mcastipv4, port)
				otputils.StartMcastTrafficOnPod(oc, ns2, mcastPodList2[0], ipv4List, pktFile2, mcastipv4, port)
				//add sleep time to make sure traffic completed.
				time.Sleep(30 * time.Second)

				chkRes1 := otputils.ChkMcatRcvOnPod(oc, ns1, mcastPodList1[0], podIPv4_1, ipv4List, mcastipv4, pktFile1)
				chkRes2 := otputils.ChkMcatRcvOnPod(oc, ns2, mcastPodList2[0], podIPv4_2, ipv4List, mcastipv4, pktFile2)
				o.Expect(chkRes1).Should(o.BeFalse())
				o.Expect(chkRes2).Should(o.BeFalse())

			}
			if ipStackType == "dualstack" || ipStackType == "ipv6single" {
				var podIPv6_1, podIPv6_2 string
				if i == 0 {
					podIPv6_1 = otputils.GetPodIPUDNv6(oc, ns1, mcastPodList1[0], "ovn-udn1")
					podIPv6_2 = otputils.GetPodIPUDNv6(oc, ns2, mcastPodList2[0], "ovn-udn1")
				} else {
					podIPv6_1 = otputils.GetPodIPv6(oc, ns1, mcastPodList1[0], ipStackType)
					podIPv6_2 = otputils.GetPodIPv6(oc, ns2, mcastPodList2[0], ipStackType)
				}
				ipv6List := []string{podIPv6_1, podIPv6_2}
				pktFile1 := "/tmp/" + otputils.GetRandomString() + ".txt"
				pktFile2 := "/tmp/" + otputils.GetRandomString() + ".txt"
				//send multicast traffic across different ns
				otputils.StartMcastTrafficOnPod(oc, ns1, mcastPodList1[0], ipv6List, pktFile1, mcastipv6, port)
				otputils.StartMcastTrafficOnPod(oc, ns2, mcastPodList2[0], ipv6List, pktFile2, mcastipv6, port)
				//add sleep time to make sure traffic completed.
				time.Sleep(30 * time.Second)

				chkRes1 := otputils.ChkMcatRcvOnPod(oc, ns1, mcastPodList1[0], podIPv6_1, ipv6List, mcastipv6, pktFile1)
				chkRes2 := otputils.ChkMcatRcvOnPod(oc, ns2, mcastPodList2[0], podIPv6_2, ipv6List, mcastipv6, pktFile2)
				o.Expect(chkRes1).Should(o.BeFalse())
				o.Expect(chkRes2).Should(o.BeFalse())
			}
		}

	})

})
