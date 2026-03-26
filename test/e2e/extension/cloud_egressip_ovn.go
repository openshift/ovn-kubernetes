package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	clusterinfra "github.com/openshift/origin/test/extended/util/compat_otp/clusterinfra"
	rosacli "github.com/openshift/origin/test/extended/util/compat_otp/rosacli"
	"github.com/vmware/govmomi"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	netutils "k8s.io/utils/net"
)

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP", func() {
	defer g.GinkgoRecover()

	var (
		ipEchoURL       string
		a               *compat_otp.AwsClient
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		flag            string
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
	)

	g.BeforeEach(func() {
		platform := compat_otp.CheckPlatform(oc)
		networkType := checkNetworkType(oc)
		e2e.Logf("\n\nThe platform is %v,  networkType is %v\n", platform, networkType)

		acceptedPlatform := strings.Contains(platform, "aws") || strings.Contains(platform, "gcp") || strings.Contains(platform, "openstack") || strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "none") || strings.Contains(platform, "nutanix") || strings.Contains(platform, "powervs")
		if !acceptedPlatform || !strings.Contains(networkType, "ovn") {
			g.Skip("Test cases should be run on AWS/GCP/Azure/Openstack/Vsphere/BareMetal/Nutanix/Powervs cluster with ovn network plugin, skip for other platforms or other non-OVN network plugin!!")
		}

		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv6single" {
			// Not able to run on IPv6 single cluster for now due to cluster disconnect limiation.
			g.Skip("Skip IPv6 Single cluster.")
		}

		if !(strings.Contains(platform, "none") || strings.Contains(platform, "powervs")) && (checkProxy(oc) || checkDisconnect(oc)) {
			g.Skip("This is proxy/disconnect cluster, skip the test.")
		}

		switch platform {
		case "aws":
			e2e.Logf("\n AWS is detected, running the case on AWS\n")
			if ipEchoURL == "" {
				creErr := getAwsCredentialFromCluster(oc)
				if creErr != nil {
					e2e.Logf("Cannot get AWS credential, will use tcpdump tool to verify egressIP,%v", creErr)
					flag = "tcpdump"
				} else {
					a = compat_otp.InitAwsSession()
					_, err := getAwsIntSvcInstanceID(a, oc)
					if err != nil {
						flag = "tcpdump"
						e2e.Logf("There is no int svc instance in this cluster: %v, try tcpdump way", err)
					} else {
						ipEchoURL, err = installIPEchoServiceOnAWS(a, oc)
						if ipEchoURL != "" && err == nil {
							flag = "ipecho"
							e2e.Logf("bastion host and ip-echo service instaled successfully, use ip-echo service to verify")
						} else {
							flag = "tcpdump"
							e2e.Logf("No ip-echo service installed on the bastion host, change to use tcpdump way %v", err)
						}
					}
				}
			}
		case "gcp":
			e2e.Logf("\n GCP is detected, running the case on GCP\n")
			if ipEchoURL == "" {
				// If an int-svc instance with external IP found, IpEcho service will be installed on the int-svc instance
				// otherwise, use tcpdump to verify egressIP
				infraID, err := compat_otp.GetInfraID(oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				host, err := getIntSvcExternalIPFromGcp(oc, infraID)
				if host == "" || err != nil {
					flag = "tcpdump"
					e2e.Logf("There is no int svc instance in this cluster: %v, try tcpdump way", err)
				} else {
					ipEchoURL, err = installIPEchoServiceOnGCP(oc, infraID, host)
					if ipEchoURL != "" && err == nil {
						flag = "ipecho"
						e2e.Logf("bastion host and ip-echo service instaled successfully, use ip-echo service to verify")
					} else {
						e2e.Logf("No ip-echo service installed on the bastion host, %v, change to use tcpdump to verify", err)
						flag = "tcpdump"
					}
				}
			}
		case "azure":
			e2e.Logf("\n Azure is detected, running the case on Azure\n")
			if isAzureStack(oc) {
				// Due to bug https://issues.redhat.com/browse/OCPBUGS-5860 and was closed as won't do, skip azure stack cluster.
				g.Skip("This is Azure Stack cluster,skip the tests!")
			}
			if ipEchoURL == "" {
				// If an int-svc instance with external IP found, IpEcho service will be installed on the int-svc instance
				// otherwise, use tcpdump to verify egressIP
				creErr := getAzureCredentialFromCluster(oc)
				if creErr != nil {
					e2e.Logf("Cannot get azure credential, will use tcpdump tool to verify egressIP,%v", creErr)
					flag = "tcpdump"
				} else {
					rg, azGroupErr := getAzureIntSvcResrouceGroup(oc)
					if azGroupErr != nil {
						e2e.Logf("Cannot get azure resource group, will use tcpdump tool to verify egressIP,%v", azGroupErr)
						flag = "tcpdump"
					} else {
						az, err := compat_otp.NewAzureSessionFromEnv()
						if err != nil {
							e2e.Logf("Cannot get new azure session, will use tcpdump tool to verify egressIP,%v", err)
							flag = "tcpdump"
						} else {
							_, intSvcErr := getAzureIntSvcVMPublicIP(oc, az, rg)
							if intSvcErr != nil {
								e2e.Logf("There is no int svc instance in this cluster, %v. Will use tcpdump tool to verify egressIP", intSvcErr)
								flag = "tcpdump"
							} else {
								ipEchoURL, intSvcErr = installIPEchoServiceOnAzure(oc, az, rg)
								if intSvcErr != nil && ipEchoURL != "" {
									e2e.Logf("No ip-echo service installed on the bastion host, %v. Will use tcpdump tool to verify egressIP", intSvcErr)
									flag = "tcpdump"
								} else {
									e2e.Logf("bastion host and ip-echo service instaled successfully, use ip-echo service to verify")
									flag = "ipecho"
								}
							}
						}
					}
				}
			}
			if isAzurePrivate(oc) && ipEchoURL == "" {
				//Due to bug https://issues.redhat.com/browse/OCPBUGS-5491 and fix limitation, if no ipecho installed on bastion host, need to skip the test.
				g.Skip("No ip-echo service installed on the bastion host in Azure private cluste,skip the tests.")
			}
		case "openstack":
			e2e.Logf("\n OpenStack is detected, running the case on OpenStack\n")
			flag = "tcpdump"
			e2e.Logf("Use tcpdump way to verify egressIP on OpenStack")
		case "vsphere":
			e2e.Logf("\n Vsphere is detected, running the case on Vsphere\n")
			flag = "tcpdump"
			e2e.Logf("Use tcpdump way to verify egressIP on Vsphere")
		case "baremetal":
			e2e.Logf("\n BareMetal is detected, running the case on BareMetal\n")
			flag = "tcpdump"
			e2e.Logf("Use tcpdump way to verify egressIP on BareMetal")
		case "none":
			e2e.Logf("\n UPI BareMetal is detected, running the case on UPI BareMetal\n")
			ipEchoURL = getIPechoURLFromUPIPrivateVlanBM(oc)
			e2e.Logf("IP echo URL is %s", ipEchoURL)
			if ipEchoURL == "" {
				g.Skip("This UPI Baremetal cluster did not fulfill the prequiste of testing egressIP cases, skip the test!!")
			}
			flag = "ipecho"
			e2e.Logf("Use IP echo way to verify egressIP on UPI BareMetal")
		case "nutanix":
			e2e.Logf("\n Nutanix is detected, running the case on Nutanix\n")
			flag = "tcpdump"
			e2e.Logf("Use tcpdump way to verify egressIP on Nutanix")
		case "powervs":
			e2e.Logf("\n Powervs is detected, running the case on Powervs\n")
			flag = "tcpdump"
			e2e.Logf("Use tcpdump way to verify egressIP on Powervs")
		default:
			e2e.Logf("Not support cloud provider for  egressip cases for now.")
			g.Skip("Not support cloud provider for  egressip cases for now.")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-ConnectedOnly-Medium-47272-[FdpOvnOvs] Pods will not be affected by the egressIP set on other netnamespace. [Serial]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1.1 Label EgressIP node")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		compat_otp.By("1.2 Apply EgressLabel Key to one node.")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, egressNodeLabel)

		compat_otp.By("2.1 Create first egressip object")
		freeIPs := findFreeIPs(oc, egressNode, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:          "egressip-47272-1",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("2.2 Create second egressip object")
		egressip2 := egressIPResource1{
			name:          "egressip-47272-2",
			template:      egressIP2Template,
			egressIP1:     freeIPs[1],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "blue",
		}
		egressip2.createEgressIPObject2(oc)
		defer egressip2.deleteEgressIPObject1(oc)
		egressIPMaps2 := getAssignedEIPInEIPObject(oc, egressip2.name)
		o.Expect(len(egressIPMaps2)).Should(o.Equal(1))

		compat_otp.By("3.1 create first namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		compat_otp.By("3.2 Apply a label to first namespace")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3.3 Create a pod in first namespace. ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1.name, "-n", pod1.namespace).Execute()
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("3.4 Apply label to pod in first namespace")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=pink")
		defer compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4.1 create second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns2)

		compat_otp.By("4.2 Apply a label to second namespace")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4.3 Create a pod in second namespace ")
		pod2 := pingPodResource{
			name:      "hello-pod",
			namespace: ns2,
			template:  pingPodTemplate,
		}
		pod2.createPingPod(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod2.name, "-n", pod2.namespace).Execute()
		waitPodReady(oc, pod2.namespace, pod2.name)

		compat_otp.By("4.4 Apply label to pod in second namespace")
		err = compat_otp.LabelPod(oc, ns2, pod2.name, "color=blue")
		defer compat_otp.LabelPod(oc, ns2, pod2.name, "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("5.1 Check source IP in first namespace using first egressip object")
		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			compat_otp.By(" Use IP-echo service to verify egressIP.")
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			verifyEgressIPWithIPEcho(oc, pod1.namespace, pod1.name, ipEchoURL, true, freeIPs[0])

			compat_otp.By("5.2 Check source IP in second namespace using second egressip object")
			verifyEgressIPWithIPEcho(oc, pod2.namespace, pod2.name, ipEchoURL, true, freeIPs[1])
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNode)
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-47272", ns2)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns2, "tcpdump-47272", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())
			compat_otp.By("Verify from tcpDump that source IP is EgressIP")
			egressErr := verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, freeIPs[0], dstHost, ns2, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
			compat_otp.By("5.2 Check source IP in second namespace using second egressip object")
			egressErr2 := verifyEgressIPinTCPDump(oc, pod2.name, pod2.namespace, freeIPs[1], dstHost, ns2, tcpdumpDS.name, true)
			o.Expect(egressErr2).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to get expected egressip:%s", freeIPs[1]))
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("Pods will not be affected by the egressIP set on other netnamespace.!!! ")
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-ConnectedOnly-Medium-47164-Medium-47025-[FdpOvnOvs] Be able to update egressip object,The pods removed matched labels will not use EgressIP [Serial]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1.1 Label EgressIP node")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		compat_otp.By("1.2 Apply EgressLabel Key to one node.")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, egressNodeLabel)

		compat_otp.By("2.1 Create first egressip object")
		freeIPs := findFreeIPs(oc, egressNode, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:          "egressip-47164",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("3.1 create first namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		compat_otp.By("3.2 Apply a label to first namespace")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3.3 Create a pod in first namespace. ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1.name, "-n", pod1.namespace).Execute()
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("3.4 Apply label to pod in first namespace")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=pink")
		defer compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Update the egressip in egressip object")
		updateEgressIPObject(oc, egressip1.name, freeIPs[1])

		compat_otp.By("5. Check source IP is updated IP")
		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			compat_otp.By(" Use IP-echo service to verify egressIP.")
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			verifyEgressIPWithIPEcho(oc, pod1.namespace, pod1.name, ipEchoURL, true, freeIPs[1])

			compat_otp.By("6. Remove labels from test pod.")
			err = compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By("7. Check source IP is not EgressIP")
			verifyEgressIPWithIPEcho(oc, pod1.namespace, pod1.name, ipEchoURL, false, freeIPs[1])
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNode)
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-47164", ns1)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-47164", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())
			compat_otp.By("Verify from tcpDump that source IP is EgressIP")
			egressErr := verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, freeIPs[1], dstHost, ns1, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to get expected egressip:%s", freeIPs[1]))

			compat_otp.By("6. Remove labels from test pod.")
			err = compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By("7. Check source IP is not EgressIP")
			egressErr = verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, freeIPs[1], dstHost, ns1, tcpdumpDS.name, false)
			o.Expect(egressErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Should not get egressip:%s", freeIPs[1]))

		default:
			g.Skip("Skip for not support scenarios!")
		}

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-ConnectedOnly-Medium-47030-[FdpOvnOvs] An EgressIP object can not have multiple egress IP assignments on the same node. [Serial]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("1. Get two worker nodes with same subnets")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("2. Apply EgressLabel Key for this test on one node.")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)

		compat_otp.By("3. Create an egressip object")
		freeIPs := findFreeIPs(oc, egressNodes[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-47030",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("4. Check only one EgressIP assigned in the object.")
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		compat_otp.By("5. Apply EgressLabel Key for this test on second node.")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)

		compat_otp.By("6. Check two EgressIP assigned in the object.")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-ConnectedOnly-Medium-47028-After remove EgressIP node tag, EgressIP will failover to other availabel egress nodes. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("1. Get list of nodes, get subnet from two worker nodes that have same subnet \n")
		var egressNode1, egressNode2 string
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}
		egressNode1 = egressNodes[0]
		egressNode2 = egressNodes[1]

		compat_otp.By("2. Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

		compat_otp.By("3.1 Create new namespace\n")
		oc.SetupProject()
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)
		compat_otp.By("3.2 Apply label to namespace\n")
		_, err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Output()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Create a pod in first namespace. \n")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("5. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNode1, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-47028",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("4. Check EgressIP assigned in the object.\n")
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		compat_otp.By("5. Update Egress node to egressNode2.\n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)

		compat_otp.By("6. Check the egress node was updated in the egressip object.\n")
		egressipErr := wait.Poll(10*time.Second, 350*time.Second, func() (bool, error) {
			egressIPMaps = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps) != 1 || egressIPMaps[0]["node"] == egressNode1 {
				e2e.Logf("Wait for new egress node applied,try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to update egress node:%s", egressipErr))
		o.Expect(egressIPMaps[0]["node"]).Should(o.ContainSubstring(egressNode2))

		compat_otp.By("7. Check the source ip.\n")
		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			compat_otp.By(" Use IP-echo service to verify egressIP.")
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			verifyEgressIPWithIPEcho(oc, pod1.namespace, pod1.name, ipEchoURL, true, egressIPMaps[0]["egressIP"])
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNode2)
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-47028", ns1)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-47028", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())
			compat_otp.By("Verify from tcpDump that source IP is EgressIP")
			egressErr := verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, egressIPMaps[0]["egressIP"], dstHost, ns1, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
		default:
			g.Skip("Skip for not support scenarios!")
		}

	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-High-47031-After reboot egress node EgressIP still work.  [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1.1 Label EgressIP node\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		compat_otp.By("1.2 Apply EgressLabel Key to one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("2.1 Create first egressip object\n")
		freeIPs := findFreeIPs(oc, nodeList.Items[0].Name, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-47031",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("3.1 create first namespace\n")
		oc.SetupProject()
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("3.2 Apply a label to test namespace.\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3.3 Create pods in test namespace. \n")
		createResourceFromFile(oc, ns1, testPodFile)
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		compat_otp.By("3.4 Apply label to one pod in test namespace\n")
		testPodName := getPodName(oc, ns1, "name=test-pods")
		err = compat_otp.LabelPod(oc, ns1, testPodName[0], "color=pink")
		defer compat_otp.LabelPod(oc, ns1, testPodName[0], "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Check only one EgressIP assigned in the object.\n")
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		compat_otp.By("5.Reboot egress node.\n")
		defer checkNodeStatus(oc, egressNode, "Ready")
		rebootNode(oc, egressNode)
		checkNodeStatus(oc, egressNode, "NotReady")
		checkNodeStatus(oc, egressNode, "Ready")
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName = getPodName(oc, ns1, "name=test-pods")
		_, err = compat_otp.AddLabelsToSpecificResource(oc, "pod/"+testPodName[0], ns1, "color=pink")
		defer compat_otp.LabelPod(oc, ns1, testPodName[0], "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("7. Check EgressIP assigned in the object.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("8. Check source IP is egressIP \n")
		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			compat_otp.By(" Use IP-echo service to verify egressIP.")
			e2e.Logf(" ipEchoURL is %v", ipEchoURL)
			verifyEgressIPWithIPEcho(oc, ns1, testPodName[0], ipEchoURL, true, freeIPs[0])
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNode)
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-47031", ns1)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-47031", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())
			compat_otp.By("Verify from tcpDump that source IP is EgressIP")
			egressErr := verifyEgressIPinTCPDump(oc, testPodName[0], ns1, freeIPs[0], dstHost, ns1, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
		default:
			g.Skip("Skip for not support scenarios!")
		}

	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-Critical-47032-High-47034-Traffic is load balanced between egress nodes,multiple EgressIP objects can have multiple egress IPs.[Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("create new namespace\n")
		oc.SetupProject()
		ns1 := oc.Namespace()

		compat_otp.By("Label EgressIP node\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)

		compat_otp.By("Apply label to namespace\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNodes[0], 4)
		o.Expect(len(freeIPs)).Should(o.Equal(4))
		egressip1 := egressIPResource1{
			name:      "egressip-47032",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		//Replce matchLabel with matchExpressions
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-47032", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchExpressions\":[{\"key\": \"name\", \"operator\": \"In\", \"values\": [\"test\"]}]}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-47032", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchLabels\":null}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		compat_otp.By("Create another egressip object\n")
		egressip2 := egressIPResource1{
			name:      "egressip-47034",
			template:  egressIPTemplate,
			egressIP1: freeIPs[2],
			egressIP2: freeIPs[3],
		}
		egressip2.createEgressIPObject1(oc)
		defer egressip2.deleteEgressIPObject1(oc)
		//Replce matchLabel with matchExpressions
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-47034", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchExpressions\":[{\"key\": \"name\", \"operator\": \"In\", \"values\": [\"qe\"]}]}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-47034", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchLabels\":null}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyExpectedEIPNumInEIPObject(oc, egressip2.name, 2)

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Create sencond namespace.")
		oc.SetupProject()
		ns2 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns2)

		compat_otp.By("Apply label to second namespace\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "name=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create a pod in second namespace")
		pod2 := pingPodResource{
			name:      "hello-pod",
			namespace: ns2,
			template:  pingPodTemplate,
		}
		pod2.createPingPod(oc)
		waitPodReady(oc, pod2.namespace, pod2.name)

		compat_otp.By("Check source IP is randomly one of egress ips.\n")
		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			sourceIP, err := execCommandInSpecificPod(oc, pod2.namespace, pod2.name, "for i in {1..10}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf(sourceIP)
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIPs[2]))
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIPs[3]))
			sourceIP, err = execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf(sourceIP)
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIPs[0]))
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIPs[1]))
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], "tcpdump", "true")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNodes[0])
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-47032", ns2)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns2, "tcpdump-47032", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())

			compat_otp.By("Check source IP is randomly one of egress ips for both namespaces.")
			egressipErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
				randomStr, url := getRequestURL(dstHost)
				_, err := execCommandInSpecificPod(oc, pod2.namespace, pod2.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
				o.Expect(err).NotTo(o.HaveOccurred())
				if checkMatchedIPs(oc, ns2, tcpdumpDS.name, randomStr, freeIPs[2], true) != nil || checkMatchedIPs(oc, ns2, tcpdumpDS.name, randomStr, freeIPs[3], true) != nil || err != nil {
					e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
					return false, nil
				}
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump", freeIPs[2], freeIPs[3]))

			egressipErr2 := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
				randomStr, url := getRequestURL(dstHost)
				_, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
				o.Expect(err).NotTo(o.HaveOccurred())
				if checkMatchedIPs(oc, ns2, tcpdumpDS.name, randomStr, freeIPs[0], true) != nil || checkMatchedIPs(oc, ns2, tcpdumpDS.name, randomStr, freeIPs[1], true) != nil || err != nil {
					e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
					return false, nil
				}
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr2, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump", freeIPs[0], freeIPs[1]))
		default:
			g.Skip("Skip for not support scenarios!")
		}

	})

	// author: huirwang@redhat.com
	g.It("[Level0] Author:huirwang-ConnectedOnly-High-47019-High-47023-[FdpOvnOvs] EgressIP works well with networkpolicy and egressFirewall. [Serial]", func() {
		//EgressFirewall case cannot run in proxy cluster, skip if proxy cluster.
		if checkProxy(oc) {
			g.Skip("This is proxy cluster, skip the test.")
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		networkPolicyFile := filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")

		compat_otp.By("1. Label EgressIP node\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		egressNode := nodeList.Items[0].Name
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2. Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("3. create new namespace\n")
		oc.SetupProject()
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("4. Apply label to namespace\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()

		compat_otp.By("5. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, nodeList.Items[0].Name, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-47019",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		compat_otp.By("6. Create test pods \n")
		createResourceFromFile(oc, ns1, testPodFile)
		err = waitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		compat_otp.By("7. Create default deny ingress type networkpolicy in test namespace\n")
		createResourceFromFile(oc, ns1, networkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-ingress"))

		compat_otp.By("8. Create an EgressFirewall object with rule deny.")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns1,
			ruletype:  "Deny",
			cidr:      "0.0.0.0/0",
			template:  egressFWTemplate,
		}
		egressFW2.createEgressFW2Object(oc)
		defer egressFW2.deleteEgressFW2Object(oc)

		compat_otp.By("9. Get test pods IP and test pod name in test namespace\n")
		testPodName := getPodName(oc, oc.Namespace(), "name=test-pods")

		compat_otp.By("10. Check network policy works. \n")
		CurlPod2PodFail(oc, ns1, testPodName[0], ns1, testPodName[1])

		compat_otp.By("11. Check EgressFirewall policy works. \n")
		_, err = e2eoutput.RunHostCmd(ns1, testPodName[0], "curl -s ifconfig.me --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		compat_otp.By("12.Update EgressFirewall to allow")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns1, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Allow\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}]}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			compat_otp.By("13. Check EgressFirewall Allow rule works and EgressIP works.\n")
			egressipErr := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
				sourceIP, err := e2eoutput.RunHostCmd(ns1, testPodName[0], "curl -s "+ipEchoURL+" --connect-timeout 5")
				if err != nil {
					e2e.Logf("Wait for EgressFirewall taking effect. %v", err)
					return false, nil
				}
				if !contains(freeIPs, sourceIP) {
					eip, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressip", "-o=jsonpath={.}").Output()
					e2e.Logf(eip)
					return false, nil
				}
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("The source Ip is not same as the egressIP expected!"))
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNode)
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-47023", ns1)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-47023", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())

			compat_otp.By("13. Verify from tcpdump that source IP is EgressIP")
			egressErr := verifyEgressIPinTCPDump(oc, testPodName[0], ns1, egressIPMaps[0]["egressIP"], dstHost, ns1, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())

		default:
			g.Skip("Skip for not support scenarios!")
		}

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-Medium-47018-Medium-47017-[FdpOvnOvs] Multiple projects use same EgressIP,EgressIP works for all pods in the namespace with matched namespaceSelector. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("1. Label EgressIP node\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		egressNode := nodeList.Items[0].Name
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2. Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("3. create first namespace\n")
		oc.SetupProject()
		ns1 := oc.Namespace()

		compat_otp.By("4. Create test pods in first namespace. \n")
		createResourceFromFile(oc, ns1, testPodFile)
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodNs1Name := getPodName(oc, ns1, "name=test-pods")

		compat_otp.By("5. Apply label to ns1 namespace\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()

		compat_otp.By("6. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNode, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-47018",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		compat_otp.By("7. create new namespace\n")
		oc.SetupProject()
		ns2 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns2)

		compat_otp.By("8. Apply label to namespace\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "name-").Execute()

		compat_otp.By("9. Create test pods in second namespace  \n")
		createResourceFromFile(oc, ns2, testPodFile)
		err = waitForPodWithLabelReady(oc, ns2, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodNs2Name := getPodName(oc, ns2, "name=test-pods")

		compat_otp.By("create new namespace\n")
		oc.SetupProject()
		ns3 := oc.Namespace()

		compat_otp.By("Create test pods in third namespace  \n")
		createResourceFromFile(oc, ns3, testPodFile)
		err = waitForPodWithLabelReady(oc, ns3, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodNs3Name := getPodName(oc, ns3, "name=test-pods")

		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			compat_otp.By("10. Check source IP from both namespace, should be egressip.  \n")
			verifyEgressIPWithIPEcho(oc, ns1, testPodNs1Name[0], ipEchoURL, true, freeIPs...)
			verifyEgressIPWithIPEcho(oc, ns1, testPodNs1Name[1], ipEchoURL, true, freeIPs...)
			verifyEgressIPWithIPEcho(oc, ns2, testPodNs2Name[0], ipEchoURL, true, freeIPs...)
			verifyEgressIPWithIPEcho(oc, ns2, testPodNs2Name[1], ipEchoURL, true, freeIPs...)
			verifyEgressIPWithIPEcho(oc, ns3, testPodNs3Name[0], ipEchoURL, false, freeIPs...)

			compat_otp.By("11. Remove matched labels from namespace ns1  \n")
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By("12.  Check source IP from namespace ns1, should not be egressip. \n")
			verifyEgressIPWithIPEcho(oc, ns1, testPodNs1Name[0], ipEchoURL, false, freeIPs...)
			verifyEgressIPWithIPEcho(oc, ns1, testPodNs1Name[1], ipEchoURL, false, freeIPs...)
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNode)
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-47017", ns2)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns2, "tcpdump-47017", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())

			compat_otp.By("10.Check source IP from both namespace, should be egressip. ")
			egressErr := verifyEgressIPinTCPDump(oc, testPodNs1Name[0], ns1, egressIPMaps[0]["egressIP"], dstHost, ns2, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
			egressErr = verifyEgressIPinTCPDump(oc, testPodNs1Name[1], ns1, egressIPMaps[0]["egressIP"], dstHost, ns2, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
			egressErr = verifyEgressIPinTCPDump(oc, testPodNs2Name[0], ns2, egressIPMaps[0]["egressIP"], dstHost, ns2, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
			egressErr = verifyEgressIPinTCPDump(oc, testPodNs2Name[1], ns2, egressIPMaps[0]["egressIP"], dstHost, ns2, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
			egressErr = verifyEgressIPinTCPDump(oc, testPodNs3Name[0], ns3, egressIPMaps[0]["egressIP"], dstHost, ns2, tcpdumpDS.name, false)
			o.Expect(egressErr).NotTo(o.HaveOccurred())

			compat_otp.By("11. Remove matched labels from namespace ns1  \n")
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By("12.  Check source IP from namespace ns1, should not be egressip. \n")
			egressErr = verifyEgressIPinTCPDump(oc, testPodNs1Name[0], ns1, egressIPMaps[0]["egressIP"], dstHost, ns2, tcpdumpDS.name, false)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
			egressErr = verifyEgressIPinTCPDump(oc, testPodNs1Name[1], ns1, egressIPMaps[0]["egressIP"], dstHost, ns2, tcpdumpDS.name, false)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
		default:
			g.Skip("Skip for not support scenarios!")
		}

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-Longduration-NonPreRelease-Medium-47033-If an egress node is NotReady traffic is still load balanced between available egress nodes. [Disruptive]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		timer := estimateTimeoutForEgressIP(oc) * 2

		// This test case is not supposed to run on some special AWS/GCP cluster with STS, use specialPlatformCheck function to identify such a cluster
		// For Azure cluster, if it has special credential type, this test case should be skipped as well
		isSpecialSTSorCredCluster := specialPlatformCheck(oc)
		if isSpecialSTSorCredCluster || clusterinfra.UseSpotInstanceWorkersCheck(oc) {
			g.Skip("Skipped: This test case is not suitable for special AWS/GCP STS cluster or Azure with special credential type or cluster uses spot instances!!")
		}

		compat_otp.By("1. create new namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("2. Label EgressIP node\n")
		// As in rdu1 cluster, sriov nodes have different primary NIC name from common node, we need uniq nic name for multiple tcpdump pods to capture packets, so filter out sriov nodes
		platform := compat_otp.CheckPlatform(oc)
		var workers []string
		if strings.Contains(platform, "baremetal") {
			workers = excludeSriovNodes(oc)
			if len(workers) < 3 {
				g.Skip("Not enough worker nodes for this test, skip the case!!")
			}
		} else {
			nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
			o.Expect(err).NotTo(o.HaveOccurred())
			if len(nodeList.Items) < 3 {
				g.Skip("Not enough worker nodes for this test, skip the case!!")
			}
			for _, node := range nodeList.Items {
				workers = append(workers, node.Name)
			}

		}

		compat_otp.By("3. Apply EgressLabel Key for this test on 3 nodes.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[2], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[2], egressNodeLabel)

		compat_otp.By("4. Apply label to namespace\n")
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()

		compat_otp.By("5. Create an egressip object\n")
		sub1 := getEgressCIDRsForNode(oc, workers[0])
		freeIP1 := findUnUsedIPsOnNode(oc, workers[0], sub1, 1)
		o.Expect(len(freeIP1) == 1).Should(o.BeTrue())
		sub2 := getEgressCIDRsForNode(oc, workers[1])
		freeIP2 := findUnUsedIPsOnNode(oc, workers[1], sub2, 1)
		o.Expect(len(freeIP2) == 1).Should(o.BeTrue())
		sub3 := getEgressCIDRsForNode(oc, workers[2])
		freeIP3 := findUnUsedIPsOnNode(oc, workers[2], sub3, 1)
		o.Expect(len(freeIP3) == 1).Should(o.BeTrue())

		egressip1 := egressIPResource1{
			name:      "egressip-47033",
			template:  egressIPTemplate,
			egressIP1: freeIP1[0],
			egressIP2: freeIP2[0],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("6. Update an egressip object with three egressips.\n")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-47033", "-p", "{\"spec\":{\"egressIPs\":[\""+freeIP1[0]+"\",\""+freeIP2[0]+"\",\""+freeIP3[0]+"\"]}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("7. Create a pod \n")
		pod1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns1,
			nodename:  workers[0],
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("8. Check source IP is randomly one of egress ips.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 3)

		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		errMsgFmt := "Any error in finding %v in tcpdump?: %v\n\n\n"
		switch flag {
		case "ipecho":
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			sourceIP, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..15}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf(sourceIP)
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIP1[0]))
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIP2[0]))
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIP3[0]))
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], "tcpdump", "true")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], "tcpdump", "true")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[2], "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[2], "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, workers[0])
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-47033", ns1)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-47033", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())

			compat_otp.By("Verify all egressIP is randomly used as sourceIP.")
			egressipErr := wait.Poll(30*time.Second, timer, func() (bool, error) {
				randomStr, url := getRequestURL(dstHost)
				_, cmdErr := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..30}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
				o.Expect(err).NotTo(o.HaveOccurred())
				egressIPCheck1 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIP1[0], true)
				e2e.Logf(errMsgFmt, freeIP1[0], egressIPCheck1)
				egressIPCheck2 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIP2[0], true)
				e2e.Logf(errMsgFmt, freeIP2[0], egressIPCheck2)
				egressIPCheck3 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIP3[0], true)
				e2e.Logf(errMsgFmt, freeIP3[0], egressIPCheck3)
				e2e.Logf("Any cmdErr when running curl?: %v\n\n\n", cmdErr)
				if egressIPCheck1 != nil || egressIPCheck2 != nil || egressIPCheck3 != nil || cmdErr != nil {
					e2e.Logf("Did not find egressIPs %s or %s or %s in tcpdump log, try next round.", freeIP1[0], freeIP2[0], freeIP3[0])
					return false, nil
				}
				e2e.Logf("Found all other 3 egressIP in tcpdump log as expected")
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get all EgressIPs %s,%s, %s in tcpdump", freeIP1[0], freeIP2[0], freeIP3[0]))
		default:
			g.Skip("Skip for not support scenarios!")
		}

		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)

		// Choose one egress node and shut it down
		nodeToBeShutdown := egressIPMaps1[2]["node"]
		e2e.Logf("\n\n\n the worker node to be shutdown is: %v\n\n\n", nodeToBeShutdown)
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeToBeShutdown, "tcpdump")

		compat_otp.By("9. Stop one egress node.\n")
		var instance []string
		var zone string
		var az *compat_otp.AzureSession
		var rg string
		var infraID string
		var ospObj compat_otp.Osp
		var vspObj *compat_otp.Vmware
		var vspClient *govmomi.Client
		var nutanixClient *compat_otp.NutanixClient
		var ibmPowerVsSession *compat_otp.IBMPowerVsSession
		var ibmPowerVsInstance *ibmPowerVsInstance
		switch compat_otp.CheckPlatform(oc) {
		case "aws":
			e2e.Logf("\n AWS is detected \n")
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			defer startInstanceOnAWS(a, nodeToBeShutdown)
			stopInstanceOnAWS(a, nodeToBeShutdown)
			checkNodeStatus(oc, nodeToBeShutdown, "NotReady")
		case "gcp":
			// for gcp, remove the postfix "c.openshift-qe.internal" to get its instance name
			instance = strings.Split(nodeToBeShutdown, ".")
			e2e.Logf("\n\n\n the worker node to be shutdown is: %v\n\n\n", instance[0])
			infraID, err = compat_otp.GetInfraID(oc)
			zone, err = getZoneOfInstanceFromGcp(oc, infraID, instance[0])
			o.Expect(err).NotTo(o.HaveOccurred())
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			defer startInstanceOnGcp(oc, instance[0], zone)
			err = stopInstanceOnGcp(oc, instance[0], zone)
			o.Expect(err).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "NotReady")
		case "azure":
			e2e.Logf("\n Azure is detected \n")
			err := getAzureCredentialFromCluster(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			rg, err = getAzureResourceGroup(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			az, err = compat_otp.NewAzureSessionFromEnv()
			o.Expect(err).NotTo(o.HaveOccurred())
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			defer startVMOnAzure(az, nodeToBeShutdown, rg)
			stopVMOnAzure(az, nodeToBeShutdown, rg)
			checkNodeStatus(oc, nodeToBeShutdown, "NotReady")
		case "openstack":
			e2e.Logf("\n OpenStack is detected, stop the instance %v on OSP now \n", nodeToBeShutdown)
			ospObj = compat_otp.Osp{}
			cred, err1 := compat_otp.GetOpenStackCredentials(oc)
			o.Expect(err1).NotTo(o.HaveOccurred())
			client := compat_otp.NewOpenStackClient(cred, "compute")
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			defer ospObj.GetStartOspInstance(client, nodeToBeShutdown)
			err = ospObj.GetStopOspInstance(client, nodeToBeShutdown)

			o.Expect(err).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "NotReady")
		case "vsphere":
			e2e.Logf("\n vSphere is detected, stop the instance %v on vSphere now \n", nodeToBeShutdown)
			vspObj, vspClient = VsphereCloudClient(oc)
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			defer vspObj.StartVsphereInstance(vspClient, nodeToBeShutdown)
			err = vspObj.StopVsphereInstance(vspClient, nodeToBeShutdown)
			o.Expect(err).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "NotReady")
		case "baremetal":
			e2e.Logf("\n IPI baremetal is detected \n")
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			defer startVMOnIPIBM(oc, nodeToBeShutdown)
			stopErr := stopVMOnIPIBM(oc, nodeToBeShutdown)
			o.Expect(stopErr).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "NotReady")
		case "nutanix":
			e2e.Logf("\n Nutanix is detected, stop the instance %v on nutanix now \n", nodeToBeShutdown)
			nutanixClient, err = compat_otp.InitNutanixClient(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			defer startInstanceOnNutanix(nutanixClient, nodeToBeShutdown)
			stopInstanceOnNutanix(nutanixClient, nodeToBeShutdown)
			checkNodeStatus(oc, nodeToBeShutdown, "NotReady")
		case "powervs":
			e2e.Logf("\n Powervs is detected, stop the instance %v on powervs now \n", nodeToBeShutdown)
			ibmApiKey, ibmRegion, ibmVpcName, credErr := compat_otp.GetIBMCredentialFromCluster(oc)
			o.Expect(credErr).NotTo(o.HaveOccurred())
			cloudID := compat_otp.GetIBMPowerVsCloudID(oc, nodeToBeShutdown)
			ibmPowerVsSession, err = compat_otp.LoginIBMPowerVsCloud(ibmApiKey, ibmRegion, ibmVpcName, cloudID)
			o.Expect(err).NotTo(o.HaveOccurred())
			ibmPowerVsInstance = newIBMPowerInstance(oc, ibmPowerVsSession, ibmRegion, ibmVpcName, nodeToBeShutdown)
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			defer ibmPowerVsInstance.Start()
			err = ibmPowerVsInstance.Stop()
			o.Expect(err).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "NotReady")
		default:
			e2e.Logf("Not support cloud provider for auto egressip cases for now.")
			g.Skip("Not support cloud provider for auto egressip cases for now.")
		}

		compat_otp.By("10. Check EgressIP updated in EIP object, sourceIP contains 2 IPs. \n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		switch flag {
		case "ipecho":
			egressipErr := wait.Poll(10*time.Second, 300*time.Second, func() (bool, error) {
				sourceIP, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..30}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
				e2e.Logf(sourceIP)
				if err != nil {
					e2e.Logf("Getting error: %v while curl %s from the pod.", err, ipEchoURL)
					return false, nil
				}
				if strings.Contains(sourceIP, egressIPMaps1[0]["egressIP"]) && strings.Contains(sourceIP, egressIPMaps1[1]["egressIP"]) {
					sourceIPSlice := findIP(sourceIP)
					if len(unique(sourceIPSlice)) == 2 {
						return true, nil
					}
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, "The source Ip is not same as the egressIP expected!")
		case "tcpdump":
			compat_otp.By("Verify other available egressIP is randomly used as sourceIP.")
			egressipErr := wait.Poll(30*time.Second, timer, func() (bool, error) {
				randomStr, url := getRequestURL(dstHost)
				_, cmdErr := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..30}; do curl -s "+url+" --connect-timeout 5 ; sleep 3;echo ;done")
				o.Expect(err).NotTo(o.HaveOccurred())

				egressIPCheck1 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, egressIPMaps1[0]["egressIP"], true)
				e2e.Logf(errMsgFmt, egressIPMaps1[0]["egressIP"], egressIPCheck1)
				egressIPCheck2 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, egressIPMaps1[1]["egressIP"], true)
				e2e.Logf(errMsgFmt, egressIPMaps1[1]["egressIP"], egressIPCheck2)
				egressIPCheck3 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, egressIPMaps1[2]["egressIP"], false)
				e2e.Logf("Any error in finding %v in tcpdump when it is not expected to be in tcpdump log?: %v\n\n\n", egressIPMaps1[2]["egressIP"], egressIPCheck3)
				e2e.Logf("Any cmdErr when running curl?: %v\n\n\n", cmdErr)
				if egressIPCheck1 != nil || egressIPCheck2 != nil || egressIPCheck3 != nil || cmdErr != nil {
					e2e.Logf("Did not find egressIPs %v or %v in tcpdump log, or found %v unexpected, try next round.", egressIPMaps1[0]["egressIP"], egressIPMaps1[1]["egressIP"], egressIPMaps1[2]["egressIP"])
					return false, nil
				}
				e2e.Logf("After the egress node is shut down, found all other 2 egressIP in tcpdump log!as expected")
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, "Failed to get all expected EgressIPs in tcpdump log")
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("11. Start the stopped egress node \n")
		switch compat_otp.CheckPlatform(oc) {
		case "aws":
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			startInstanceOnAWS(a, nodeToBeShutdown)
			checkNodeStatus(oc, nodeToBeShutdown, "Ready")
		case "gcp":
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			err = startInstanceOnGcp(oc, instance[0], zone)
			o.Expect(err).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "Ready")
		case "azure":
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			startVMOnAzure(az, nodeToBeShutdown, rg)
			checkNodeStatus(oc, nodeToBeShutdown, "Ready")
		case "openstack":
			cred, err1 := compat_otp.GetOpenStackCredentials(oc)
			o.Expect(err1).NotTo(o.HaveOccurred())
			client := compat_otp.NewOpenStackClient(cred, "compute")
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			err = ospObj.GetStartOspInstance(client, nodeToBeShutdown)
			o.Expect(err).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "Ready")
		case "vsphere":
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			err = vspObj.StartVsphereInstance(vspClient, nodeToBeShutdown)
			o.Expect(err).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "Ready")
		case "baremetal":
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			startErr := startVMOnIPIBM(oc, nodeToBeShutdown)
			o.Expect(startErr).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "Ready")
		case "nutanix":
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			startInstanceOnNutanix(nutanixClient, nodeToBeShutdown)
			checkNodeStatus(oc, nodeToBeShutdown, "Ready")
		case "powervs":
			defer checkNodeStatus(oc, nodeToBeShutdown, "Ready")
			err = ibmPowerVsInstance.Start()
			o.Expect(err).NotTo(o.HaveOccurred())
			checkNodeStatus(oc, nodeToBeShutdown, "Ready")
		default:
			e2e.Logf("Not support cloud provider for auto egressip cases for now.")
			g.Skip("Not support cloud provider for auto egressip cases for now.")
		}

		compat_otp.By("12. Check source IP is randomly one of 3 egress IPs.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 3)

		switch flag {
		case "ipecho":
			egressipErr := wait.Poll(5*time.Second, 180*time.Second, func() (bool, error) {
				sourceIP, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..30}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
				e2e.Logf(sourceIP)
				if err != nil {
					e2e.Logf("Getting error: %v while curl %s from the pod.", err, ipEchoURL)
					return false, nil
				}
				if strings.Contains(sourceIP, freeIP1[0]) && strings.Contains(sourceIP, freeIP2[0]) && strings.Contains(sourceIP, freeIP3[0]) {
					return true, nil
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, "The source Ip is not same as the egressIP expected!")
		case "tcpdump":
			e2e.Logf("\n Re-labelling the rebooted node %v to have tcpdump label\n", nodeToBeShutdown)
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeToBeShutdown, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeToBeShutdown, "tcpdump", "true")
			egressipErr := wait.Poll(30*time.Second, timer, func() (bool, error) {
				randomStr, url := getRequestURL(dstHost)
				_, cmdErr := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..30}; do curl -s "+url+" --connect-timeout 5 ; sleep 3;echo ;done")
				o.Expect(err).NotTo(o.HaveOccurred())
				egressIPCheck1 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIP1[0], true)
				e2e.Logf(errMsgFmt, freeIP1[0], egressIPCheck1)

				egressIPCheck2 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIP2[0], true)
				e2e.Logf(errMsgFmt, freeIP2[0], egressIPCheck2)

				egressIPCheck3 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIP3[0], true)
				e2e.Logf(errMsgFmt, freeIP3[0], egressIPCheck3)

				e2e.Logf("Any cmdErr when running curl?: %v\n\n\n", cmdErr)
				if egressIPCheck1 != nil || egressIPCheck2 != nil || egressIPCheck3 != nil || cmdErr != nil {
					e2e.Logf("Did not find egressIPs %s or %s or %s in tcpdump log, try next round.", freeIP1[0], freeIP2[0], freeIP3[0])
					return false, nil
				}
				e2e.Logf("After the egress node is brought back up, found all 3 egressIP in tcpdump log!as expected")
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get all EgressIPs %s,%s, %s in tcpdump", freeIP1[0], freeIP2[0], freeIP3[0]))
		default:
			g.Skip("Skip for not support scenarios!")
		}

	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-High-Longduration-NonPreRelease-53069-EgressIP should work for recreated same name pod. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("1. Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name

		compat_otp.By("2. Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("3.1 Get temp namespace\n")
		oc.SetupProject()
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("3.2 Apply label to namespace\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Create a pod in temp namespace. \n")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("5. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNode, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-53069",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("4. Check EgressIP assigned in the object.\n")
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			compat_otp.By("5. Check the source ip.\n")
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			verifyEgressIPWithIPEcho(oc, pod1.namespace, pod1.name, ipEchoURL, true, egressIPMaps[0]["egressIP"])

			compat_otp.By("6. Delete the test pod and recreate it. \n")
			// Add more times to delete pod and recreate pod. This is to cover bug https://bugzilla.redhat.com/show_bug.cgi?id=2117310
			compat_otp.By("6. Delete the test pod and recreate it. \n")
			for i := 0; i < 15; i++ {
				e2e.Logf("Delete and recreate pod for the %v time", i)
				pod1.deletePingPod(oc)
				pod1.createPingPod(oc)
				waitPodReady(oc, pod1.namespace, pod1.name)

				compat_otp.By("7. Check the source ip.\n")
				verifyEgressIPWithIPEcho(oc, pod1.namespace, pod1.name, ipEchoURL, true, egressIPMaps[0]["egressIP"])
			}
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNode)
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-53069", ns1)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-53069", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())

			compat_otp.By("5. Verify from tcpdump that source IP is EgressIP")
			egressErr := verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, egressIPMaps[0]["egressIP"], dstHost, ns1, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())

			compat_otp.By("6. Delete the test pod and recreate it for. \n")
			for i := 0; i < 15; i++ {
				e2e.Logf("Delete and recreate pod for the %v time", i)
				pod1.deletePingPod(oc)
				pod1.createPingPod(oc)
				waitPodReady(oc, pod1.namespace, pod1.name)

				compat_otp.By("7. Verify from tcpdump that source IP is EgressIP")
				egressErr = verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, egressIPMaps[0]["egressIP"], dstHost, ns1, tcpdumpDS.name, true)
				o.Expect(egressErr).NotTo(o.HaveOccurred())
			}

		default:
			g.Skip("Skip for not support scenarios!")
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-PreChkUpgrade-High-56875-High-77893-egressIP on default network and UDN if applicable should still be functional post upgrade (default network, UDN layer3/2 if applicable). [Disruptive]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		statefulSetHelloPod := filepath.Join(buildPruningBaseDir, "statefulset-hello.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		ns1 := "56875-upgrade-ns"
		allNS := []string{ns1}

		udnEnabled, _ := IsFeaturegateEnabled(oc, "NetworkSegmentation")

		// if NetworkSegmentation featuregate is enabled, define name for a second namespace that will be created in step 1
		var ns2, ns3 string
		if udnEnabled {
			ns2 = "77893-upgrade-ns2"
			ns3 = "77893-upgrade-ns3"
			allNS = append(allNS, ns2)
			allNS = append(allNS, ns3)
		}

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}
		egressNode1 := egressNodes[0]

		compat_otp.By("1. Create namespaces, label them with label that matches namespaceSelector defined in egressip object.")
		for i := 0; i < len(allNS); i++ {
			// first namespace is for default network
			if i == 0 {
				oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", allNS[i]).Execute()
			} else {
				oc.CreateSpecificNamespaceUDN(allNS[i])
			}
			compat_otp.SetNamespacePrivileged(oc, allNS[i])
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", allNS[i], "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		if udnEnabled {
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
			compat_otp.By("NetworkSegmentation featuregate is enabled, create CRD for layer3 UDN in namespace ns2")
			createGeneralUDNCRD(oc, ns2, "udn-network-layer3-"+ns2, ipv4cidr, ipv6cidr, cidr, "layer3")

			compat_otp.By("NetworkSegmentation featuregate is enabled, create CRD for layer2 UDN in namespace ns3")
			createGeneralUDNCRD(oc, ns3, "udn-network-layer2-"+ns3, ipv4cidr, ipv6cidr, "10.151.0.0/16", "layer2")
		}

		compat_otp.By("2. Choose a node as EgressIP node, label the node to be egress assignable")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")

		compat_otp.By("3. Create an egressip object, with pod label matches the label in stateful pod that will be created in step 4")
		freeIPs := findFreeIPs(oc, egressNode1, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-77893",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "app",
			podLabelValue: "hello",
		}
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("4. Create a stateful pod in each namespace.")
		var testpods []string
		for _, ns := range allNS {
			createResourceFromFile(oc, ns, statefulSetHelloPod)
			podErr := waitForPodWithLabelReady(oc, ns, "app=hello")
			compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
			helloPodname := getPodName(oc, ns, "app=hello")
			o.Expect(len(helloPodname)).Should(o.Equal(1))
			testpods = append(testpods, helloPodname[0])
		}

		compat_otp.By("5. Validate egressIP from each namespace")
		var dstHost, primaryInf string
		var infErr error
		compat_otp.By("5.1 Use tcpdump to verify egressIP.")
		e2e.Logf("Trying to get physical interface on the egressNode %s", egressNode1)
		primaryInf, infErr = getSnifPhyInf(oc, nodeList.Items[0].Name)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost = nslookDomainName("ifconfig.me")
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod := getRequestURL(dstHost)
		for i, ns := range allNS {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode1, tcpdumpCmd, ns, testpods[i], cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, freeIPs[0])).To(o.BeTrue())
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-PstChkUpgrade-High-56875-High-77893-egressIP on default network and UDN if applicable should still be functional post upgrade (default network, UDN layer3/2 if applicable). [Disruptive]", func() {

		compat_otp.By("0. Check upgrade namespace(s) from PreChkUpgrade still exist. \n")
		getNsCmd := `oc get ns | grep -E "56875|77893" | awk '{print $1}'`
		output, err := exec.Command("bash", "-c", getNsCmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		allNsString := strings.TrimRight(string(output), "\n")
		allNS := strings.Split(allNsString, "\n")
		if len(allNS) < 1 {
			g.Skip("Skip the PstChkUpgrade test as expected upgrade namespace(s) do not exist, PreChkUpgrade test did not run properly")
		}
		e2e.Logf("got upgrade namespaces:  %v", allNS)

		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("namespace", ns, "--ignore-not-found=true").Execute()
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "hello-", "-n", ns, "--ignore-not-found=true").Execute()
		}
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("egressip", "--all").Execute()

		egressNodeList := compat_otp.GetNodeListByLabel(oc, egressNodeLabel)
		for _, labelledEgressNode := range egressNodeList {
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, labelledEgressNode, egressNodeLabel)
		}

		nodeNum := 2
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < nodeNum {
			g.Skip("Not enough worker nodes for this test, skip the case!!")
		}

		compat_otp.By("1. Check EgressIP in EIP object, sourceIP contains one IP. \n")
		EIPObjects := getOVNEgressIPObject(oc)
		o.Expect(len(EIPObjects) == 1).Should(o.BeTrue())
		EIPObjectName := EIPObjects[0]
		egressIPMaps := getAssignedEIPInEIPObject(oc, EIPObjectName)
		o.Expect(len(egressIPMaps) == 1).Should(o.BeTrue())
		egressNode1 := egressIPMaps[0]["node"]
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

		compat_otp.By("2. Get test pod info from each namespace. \n")
		var testpods1 []string
		for _, ns := range allNS {
			e2e.Logf("\n namespace is: %s\n", ns)
			err := compat_otp.SetNamespacePrivileged(oc, ns)
			o.Expect(err).NotTo(o.HaveOccurred())
			helloPodname := getPodName(oc, ns, "app=hello")
			o.Expect(len(helloPodname)).Should(o.Equal(1))
			podErr := waitForPodWithLabelReady(oc, ns, "app=hello")
			compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
			testpods1 = append(testpods1, helloPodname[0])
		}

		compat_otp.By("3. Check source IP from the test pod of each namespace is the assigned egress IP address")
		var dstHost, primaryInf string
		var infErr error
		compat_otp.By("Use tcpdump to verify egressIP.")
		e2e.Logf("Trying to get physical interface on the egressNode %s", egressNode1)
		primaryInf, infErr = getSnifPhyInf(oc, egressNode1)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost = nslookDomainName("ifconfig.me")
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod := getRequestURL(dstHost)
		for i, ns := range allNS {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode1, tcpdumpCmd, ns, testpods1[i], cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, egressIPMaps[0]["egressIP"])).To(o.BeTrue())
		}

		compat_otp.By("4. Find another scheduleable node that is in the same subnet of first egress node, label it as the second egress node")
		var egressNode2 string
		platform := compat_otp.CheckPlatform(oc)
		if strings.Contains(platform, "aws") || strings.Contains(platform, "gcp") || strings.Contains(platform, "azure") || strings.Contains(platform, "openstack") {
			firstSub := getIfaddrFromNode(egressNode1, oc)
			for _, v := range nodeList.Items {
				secondSub := getIfaddrFromNode(v.Name, oc)
				if v.Name == egressNode1 || secondSub != firstSub {
					continue
				} else {
					egressNode2 = v.Name
					break
				}
			}
		} else { // On other BM, vSphere platforms, worker nodes are on same subnet
			for _, v := range nodeList.Items {
				if v.Name == egressNode1 {
					continue
				} else {
					egressNode2 = v.Name
					break
				}
			}
		}

		if egressNode2 == "" {
			g.Skip("Did not find a scheduleable second node that is on same subnet as the first egress node, skip the rest of the test!!")
		}
		e2e.Logf("\n secondEgressNode is %v\n", egressNode2)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")

		egressNodeList = compat_otp.GetNodeListByLabel(oc, egressNodeLabel)
		o.Expect(len(egressNodeList) == 2).Should(o.BeTrue())

		compat_otp.By("5. Unlabel the first egress node to cause egressIP failover to the second egress node")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

		// stateful test pods would be recreated during failover, wait for pods to be ready
		var testpods2 []string
		for _, ns := range allNS {
			podErr := waitForPodWithLabelReady(oc, ns, "app=hello")
			compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
			helloPodname := getPodName(oc, ns, "app=hello")
			testpods2 = append(testpods2, helloPodname[0])
		}

		compat_otp.By("5. Check EgressIP assigned to the second egress node.\n")
		o.Eventually(func() bool {
			egressIPMaps = getAssignedEIPInEIPObject(oc, EIPObjectName)
			return len(egressIPMaps) == 1 && egressIPMaps[0]["node"] == egressNode2
		}, "300s", "10s").Should(o.BeTrue(), "egressIP was not migrated to second egress node after unlabel first egress node!!")

		compat_otp.By("6. Check source IP from the test pod of each namespace is still the assigned egress IP address after failover")
		e2e.Logf("Trying to get physical interface on the egressNode %s", egressNode2)
		primaryInf, infErr = getSnifPhyInf(oc, egressNode2)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpCmd = fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", primaryInf, dstHost)
		_, cmdOnPod = getRequestURL(dstHost)
		for i, ns := range allNS {
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, egressNode2, tcpdumpCmd, ns, testpods2[i], cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, egressIPMaps[0]["egressIP"])).To(o.BeTrue())
		}

		compat_otp.By("7. Delete egressIP object, verify egressip is cleared\n")
		removeResource(oc, true, true, "egressip", EIPObjectName)
		waitCloudPrivateIPconfigUpdate(oc, egressIPMaps[0]["egressIP"], false)

		compat_otp.By("8. Verify that now node IP of the node where a stateful pod resides on is used as source IP for egress packets from the stateful pod\n")
		for i, ns := range allNS {
			// find the node that this stateful pod resides on
			podNodeName, nodeErr := compat_otp.GetPodNodeName(oc, ns, testpods2[i])
			o.Expect(nodeErr).NotTo(o.HaveOccurred())
			nodeIP := getNodeIPv4(oc, ns, podNodeName)

			//tcpdump should be captured on each pod's own node
			tcpdumOutput := getTcpdumpOnNodeCmdFromPod(oc, podNodeName, tcpdumpCmd, ns, testpods2[i], cmdOnPod)
			o.Expect(strings.Contains(tcpdumOutput, nodeIP)).To(o.BeTrue())
		}

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-NonPreRelease-High-68213-[FdpOvnOvs] Outgoing traffic sourced from same egressIP when only one egressIP is assigned even if the egressIP object has multiple egressIP addresses configured in it. [Serial]", func() {

		// Updated the case for OCPBUGS-19905

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		timer := estimateTimeoutForEgressIP(oc) * 2

		compat_otp.By("1. Get two worker nodes with same subnets")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("2. Apply EgressLabel Key for this test on one node.")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)

		compat_otp.By("3. Apply label to namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Create an egressip object")
		freeIPs := findFreeIPs(oc, egressNodes[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-68213",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("5. Check only one EgressIP assigned in the object.")
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		// Find out the other egressip address that is not assigned to egress node
		var unassignedIP []string
		for i, v := range freeIPs {
			if v == egressIPMaps[0]["egressIP"] {
				unassignedIP = append(freeIPs[:i], freeIPs[i+1:]...)
				break
			}
		}
		e2e.Logf("\n unassigned ip address: %v\n\n\n", unassignedIP)

		compat_otp.By("6. Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("7. Check only the egressIP that is assigned to egressNode is consistently used in outbounding traffic.")
		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		errMsgFmt := "Any error in finding %v in tcpdump?: %v\n\n\n"
		switch flag {
		case "ipecho":
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			sourceIP, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..15}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf(sourceIP)
			o.Expect(sourceIP).Should(o.ContainSubstring(egressIPMaps[0]["egressIP"]))
			o.Expect(sourceIP).ShouldNot(o.ContainSubstring(unassignedIP[0]))
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNodes[0])
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-68213", ns1)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-68213", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())

			compat_otp.By("Verify only one the assigned egressIP is used as sourceIP.")
			egressipErr := wait.Poll(30*time.Second, timer, func() (bool, error) {
				randomStr, url := getRequestURL(dstHost)
				_, cmdErr := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..30}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
				o.Expect(cmdErr).NotTo(o.HaveOccurred())
				egressIPCheck1 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, egressIPMaps[0]["egressIP"], true)
				e2e.Logf(errMsgFmt, egressIPMaps[0]["egressIP"], egressIPCheck1)
				egressIPCheck2 := checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, unassignedIP[0], false)
				e2e.Logf(errMsgFmt, unassignedIP[0], egressIPCheck2)
				if egressIPCheck1 != nil || egressIPCheck2 != nil {
					e2e.Logf("Did not find assigned egressIPs %s in tcpdump log, or found the unaisggned ip %s unexpectedly, try next round.", egressIPMaps[0]["egressIP"], unassignedIP[0])
					return false, nil
				}
				e2e.Logf("Found the egressIP in tcpdump log as expected")
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get EgressIPs %s in tcpdump", egressIPMaps[0]["egressIP"]))
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("8. Apply EgressLabel Key for this test on second node.")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)

		compat_otp.By("9. Check two EgressIP assigned in the object.")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		compat_otp.By("Check source IP is randomly one of egress ips.\n")
		switch flag {
		case "ipecho":
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			sourceIP, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf(sourceIP)
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIPs[0]))
			o.Expect(sourceIP).Should(o.ContainSubstring(freeIPs[1]))
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], "tcpdump", "true")
			dsReadyErr := waitDaemonSetReady(oc, ns1, tcpdumpDS.name)
			o.Expect(dsReadyErr).NotTo(o.HaveOccurred())

			compat_otp.By("Check source IP is randomly one of egress ips for both namespaces.")
			egressipErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
				randomStr, url := getRequestURL(dstHost)
				_, cmdErr := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
				o.Expect(cmdErr).NotTo(o.HaveOccurred())
				if checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[0], true) != nil || checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[1], true) != nil {
					e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
					return false, nil
				}
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump", freeIPs[0], freeIPs[1]))
		default:
			g.Skip("Skip for not support scenarios!")
		}

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-Longduration-NonPreRelease-High-70667-[FdpOvnOvs] After pods are deleted, SNAT and lr-policy-list for egressIP should be deleted correctly when egressIP uses podSelector with NotIn operator. [Disruptive]", func() {

		// This is for https://issues.redhat.com/browse/OCPBUGS-24055

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodeList.Items)).ShouldNot(o.Equal(0))
		egressNode := nodeList.Items[0].Name

		compat_otp.By("2 Apply EgressLabel Key to one node. \n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("3. Obtain the namespace, create a couple of test pods in it\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		pod2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, pod2.namespace, pod2.name)

		compat_otp.By("4. Apply label to namespace\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("5. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip1 := egressIPResource1{
			name:          "egressip-70667",
			template:      egressIPTemplate,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "purple",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("6. Patch change egressip object to use matchExpression for podSelector with NotIn operator\n")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-70667", "-p", "{\"spec\":{\"podSelector\":{\"matchExpressions\":[{\"key\": \"color\", \"operator\": \"NotIn\", \"values\": [\"pink\",\"blue\",\"yellow\",\"green\",\"orange\"]}],\"matchLabels\":null}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("7. Label two test pods in the way that ony hello-pod1 meets criteria to use egressip while hello-pod2 does not meet criteria to use egressip\n")
		defer compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=red")
		o.Expect(err).NotTo(o.HaveOccurred())

		defer compat_otp.LabelPod(oc, ns1, pod2.name, "color-")
		err = compat_otp.LabelPod(oc, ns1, pod2.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		helloPod1IP, _ := getPodIP(oc, ns1, pod1.name)
		e2e.Logf("hello-pod1's IP: %v", helloPod1IP)
		helloPod1Node, err := compat_otp.GetPodNodeName(oc, ns1, pod1.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("hello-pod1 %s is on node %s", pod1.name, helloPod1Node)

		helloPod2Node, err := compat_otp.GetPodNodeName(oc, ns1, pod2.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(helloPod2Node).NotTo(o.Equal(""))
		helloPod2NodeIP := getNodeIPv4(oc, ns1, helloPod2Node)

		compat_otp.By("8. Check SNAT in northdb of egress node, there should be only 1 entry that contains hello-pod1's pod IP. \n")
		snatIP, natErr := getSNATofEgressIP(oc, egressNode, freeIPs[0])
		o.Expect(natErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Before hello-pod1 is deleted, snat found: %v\n", snatIP)
		o.Expect(len(snatIP)).Should(o.Equal(1))
		o.Expect(snatIP[0]).To(o.ContainSubstring(helloPod1IP))

		compat_otp.By("9. Check lr-policy-list in 100 table of northdb on the node where hello-pod1 resides on, there should be an entry that contains hello-pod1's pod IP. \n")
		lrPolicyList, lrpErr := getlrPolicyList(oc, helloPod1Node, "100 ", true)
		o.Expect(lrpErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Before hello-pod1 is deleted, lrPolicyList found: %v\n", lrPolicyList)
		o.Expect(len(lrPolicyList)).Should(o.Equal(1))
		o.Expect(lrPolicyList[0]).To(o.ContainSubstring(helloPod1IP))

		compat_otp.By("10 Check the sourceIP of the two test pods, hello-pod1 should use egressip, while hello-pod2 should uses its node IP")
		var dstHost, primaryInf string
		var infErr, snifErr error
		var tcpdumpDS *tcpdumpDaemonSet
		switch flag {
		case "ipecho":
			compat_otp.By(" Use IP-echo service to verify egressIP for hello-pod1.")
			e2e.Logf("\n ipEchoURL is %v\n", ipEchoURL)
			verifyEgressIPWithIPEcho(oc, pod1.namespace, pod1.name, ipEchoURL, true, freeIPs[0])

			compat_otp.By("Verify hello-pod2 uses its node's IP as source IP")
			verifyEgressIPWithIPEcho(oc, pod2.namespace, pod2.name, ipEchoURL, true, helloPod2NodeIP)
		case "tcpdump":
			compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, helloPod2Node, "tcpdump")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, helloPod2Node, "tcpdump", "true")
			primaryInf, infErr = getSnifPhyInf(oc, egressNode)
			o.Expect(infErr).NotTo(o.HaveOccurred())
			dstHost = nslookDomainName("ifconfig.me")
			defer deleteTcpdumpDS(oc, "tcpdump-70667", ns1)
			tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-70667", "tcpdump", "true", dstHost, primaryInf, 80)
			o.Expect(snifErr).NotTo(o.HaveOccurred())
			compat_otp.By("Verify from tcpDump that source IP for hello-pod1 is the egressIP")
			egressErr := verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, freeIPs[0], dstHost, ns1, tcpdumpDS.name, true)
			o.Expect(egressErr).NotTo(o.HaveOccurred())
			compat_otp.By("Verify from tcpDump that source IP for hello-pod2 is its node's IP")
			egressErr2 := verifyEgressIPinTCPDump(oc, pod2.name, pod2.namespace, helloPod2NodeIP, dstHost, ns1, tcpdumpDS.name, true)
			o.Expect(egressErr2).NotTo(o.HaveOccurred())
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("11. Delete hello-pod1 that uses the egressip. \n")
		removeResource(oc, true, true, "pod", pod1.name, "-n", pod1.namespace)

		compat_otp.By("12. Check SNAT and lr-policy-list again after deleting hello-pod1 that uses the egressip, they should all be deleted. \n")
		// Because two tcpdump pods are created from step 10 in same namespace, they do not have label color, which make them meet criteria of egresssip podSelector
		// So there will be SNAT or lr-policy-list entry(or entries) for tcpdump pod(s), but we just need to verify there is no SNAT and lr-policy-list for hello-pod1
		o.Eventually(func() bool {
			snatIP, _ := getSNATofEgressIP(oc, egressNode, freeIPs[0])
			e2e.Logf("\n After hello-pod1 is deleted, snat found: %v\n", snatIP)
			return !isValueInList(freeIPs[0], snatIP)
		}, "300s", "10s").Should(o.BeTrue(), "SNAT for the egressip is not deleted!!")

		o.Eventually(func() bool {
			lrPolicyList, _ = getlrPolicyList(oc, helloPod1Node, "100 ", false)
			e2e.Logf("\n After hello-pod1 is deleted, lrPolicyList found: %v\n", lrPolicyList)
			return !isValueInList(helloPod1IP, lrPolicyList)
		}, "300s", "10s").Should(o.BeTrue(), "lr-policy-list for the egressip is not deleted!!")
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-Longduration-NonPreRelease-High-74241-Egress traffic works with ANP, BANP with Egress IP by nodeSelector.[Serial][Disruptive]", func() {
		var (
			buildPruningBaseDir       = testdata.FixturePath("networking")
			egressIP2Template         = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodNodeTemplate       = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			httpserverPodNodeTemplate = filepath.Join(buildPruningBaseDir, "httpserverPod-specific-node-template.yaml")
			banpTemplate              = filepath.Join(buildPruningBaseDir+"/adminnetworkpolicy", "banp-single-rule-template-node.yaml")
			anpTemplate               = filepath.Join(buildPruningBaseDir+"/adminnetworkpolicy", "anp-single-rule-template-node.yaml")
			matchLabelKey             = "kubernetes.io/metadata.name"
			hellopods                 []string
			containerport             int32 = 30001
			hostport                  int32 = 30003
		)

		compat_otp.By("\n 1. Get two worker nodes that are in same subnet, they will be used as egress-assignable nodes, get a third node as non-egress node\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		workers := egressNodes

		// find a non-egress node, append to workers list, so that first two nodes in workers list are egress nodes, third node in workers is non-egress node
		for _, node := range nodeList.Items {
			if !contains(egressNodes, node.Name) {
				workers = append(workers, node.Name)
				break
			}
		}

		// There is some strange behavior using tcpdump method to verify EIP with BANP/ANP node peer in place, use ipecho method to verify egressIP for now, will add tcpdump method when it is sorted out
		if !ok || egressNodes == nil || len(egressNodes) < 2 || len(workers) < 3 || flag != "ipecho" {
			g.Skip("Test requires 3 nodes, two of them are in same subnet, the prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("2. Set up egressIP.")
		compat_otp.By("2.1. Apply EgressLabel Key to first egress node.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")

		compat_otp.By("2.2. Create an egressip object")
		freeIPs := findFreeIPs(oc, egressNodes[0], 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip1 := egressIPResource1{
			name:          "egressip-74241",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "company",
			nsLabelValue:  "redhat",
			podLabelKey:   "color",
			podLabelValue: "green",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.Equal(workers[0]))
		o.Expect(egressIPMaps1[0]["egressIP"]).Should(o.Equal(freeIPs[0]))

		compat_otp.By("2.3. After egressIP is assigned to workers[0], apply EgressLabel Key to workers[1], prepare it to be used for egressIP failover in step 7.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel, "true")

		compat_otp.By("2.4 Obtain a namespace as subjectNS, label subjectNS to match namespaceSelector in egressIP object\n")
		subjectNS := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", subjectNS, "company-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", subjectNS, "company=redhat").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2.5 Create 4 ping pods in subjectNS, hello-pod0 on workers[0], hello-pod1 and hello-pod2 on workers[1], hello-pod3 on workers[2]\n")
		compat_otp.By("Only label hello-pod0 and hello-pod1 with label that matching podSelector in egressIP object\n")
		for i := 0; i < 2; i++ {
			pod := pingPodResourceNode{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: subjectNS,
				nodename:  workers[i], // create pod on egressnodes[0] and egressnodes[1]
				template:  pingPodNodeTemplate,
			}
			pod.createPingPodNode(oc)
			waitPodReady(oc, subjectNS, pod.name)
			defer compat_otp.LabelPod(oc, subjectNS, pod.name, "color-")
			err = compat_otp.LabelPod(oc, subjectNS, pod.name, "color=green")
			o.Expect(err).NotTo(o.HaveOccurred())
			hellopods = append(hellopods, pod.name)
		}
		for i := 2; i < 4; i++ {
			pod := pingPodResourceNode{
				name:      "hello-pod" + strconv.Itoa(i),
				namespace: subjectNS,
				nodename:  workers[i-1], // create pod on egressnodes[1] and non-egressnode
				template:  pingPodNodeTemplate,
			}
			pod.createPingPodNode(oc)
			waitPodReady(oc, subjectNS, pod.name)
			hellopods = append(hellopods, pod.name)
		}

		worker1NodeIP := getNodeIPv4(oc, subjectNS, workers[1])
		worker2NodeIP := getNodeIPv4(oc, subjectNS, workers[2])

		compat_otp.By("3.3 Verify egressIP works as expected from each hello-pod\n")
		switch flag {
		case "ipecho":
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[0], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[1], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[2], ipEchoURL, true, worker1NodeIP)
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[3], ipEchoURL, true, worker2NodeIP)
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("4 Create a targetNS, check healthiness of egress traffic to targeted nodes before applying BANP/ANP")
		compat_otp.By("4.1 Create a second namespace as targetNS, create 2 httpserverPods, one on each of workers[1] and workers[2]")
		oc.SetupProject()
		targetNS := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, targetNS)
		for i := 0; i < 2; i++ {
			httpserverPod := httpserverPodResourceNode{
				name:          "httpserverpod" + strconv.Itoa(i),
				namespace:     targetNS,
				containerport: containerport,
				hostport:      hostport,
				nodename:      workers[i+1], // create test pod on egressnode2 and non-egressnode
				template:      httpserverPodNodeTemplate,
			}
			httpserverPod.createHttpservePodNodeByAdmin(oc)
			waitPodReady(oc, targetNS, httpserverPod.name)
		}

		compat_otp.By("4.3 Verify egress traffic to target nodes from subjectNS to targetNS before applying BANP or ANP\n")
		for i := 0; i < 4; i++ {
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[1], strconv.Itoa(int(hostport)))
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[2], strconv.Itoa(int(hostport)))
		}

		compat_otp.By("5. Apply BANP with single rule to deny egress traffic to node\n")
		banp := singleRuleBANPPolicyResourceNode{
			name:       "default",
			subjectKey: matchLabelKey,
			subjectVal: subjectNS,
			policyType: "egress",
			direction:  "to",
			ruleName:   "default-egress",
			ruleAction: "Deny",
			ruleKey:    "department",
			template:   banpTemplate,
		}

		defer removeResource(oc, true, true, "banp", banp.name)
		banp.createSingleRuleBANPNode(oc)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("banp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, banp.name)).To(o.BeTrue())

		compat_otp.By("5.1. Patch change BANP to use matchExpression for nodeSelector with In operator and value: dev, so that workers[1] will be matched node, workers[2] is not\n")
		patchBANP := `[{"op": "replace", "path": "/spec/egress/0/to/0/nodes/matchExpressions/0/operator", "value": "In"},{"op": "add", "path": "/spec/egress/0/to/0/nodes/matchExpressions/0/values", "value": ["dev", "it"]}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("baselineadminnetworkpolicy/default", "--type=json", "-p", patchBANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		banpOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("baselineadminnetworkpolicy.policy.networking.k8s.io/default", "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\nBANP egress rule after step 5.1: %s\n", banpOutput)

		compat_otp.By("5.2. Apply workers[1] and workers[2] with different labels so that only workers[1] matches the nodeSelector in BANP\n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], "department")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], "department", "dev")

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[2], "department")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[2], "department", "qe")

		compat_otp.By("5.3. With BANP in place, verify egress traffic to external still works as expected\n")
		switch flag {
		case "ipecho":
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[0], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[1], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[2], ipEchoURL, true, worker1NodeIP)
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[3], ipEchoURL, true, worker2NodeIP)
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("5.4. With BANP in place, verify egress traffic from subjectNS to node peers as expected\n")
		for i := 0; i < 4; i++ {
			CurlPod2NodeFail(oc, subjectNS, hellopods[i], workers[1], strconv.Itoa(int(hostport)))
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[2], strconv.Itoa(int(hostport)))
		}

		compat_otp.By("6. Apply ANP with two rules for egress traffic to node peer\n")
		anp := singleRuleANPPolicyResourceNode{
			name:       "anp-74241",
			subjectKey: matchLabelKey,
			subjectVal: subjectNS,
			priority:   10,
			policyType: "egress",
			direction:  "to",
			ruleName:   "node-as-egress-peer-74241",
			ruleAction: "Allow",
			ruleKey:    "department",
			nodeKey:    "department",
			ruleVal:    "dev",
			actionname: "egress",
			actiontype: "Deny",
			template:   anpTemplate,
		}
		defer removeResource(oc, true, true, "anp", anp.name)
		anp.createSingleRuleANPNode(oc)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, anp.name)).To(o.BeTrue())
		patchANP := `[{"op": "replace", "path": "/spec/egress/1/to/0/nodes/matchExpressions/0/operator", "value": "In"},{"op": "add", "path": "/spec/egress/1/to/0/nodes/matchExpressions/0/values", "value": ["qe"]}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("adminnetworkpolicy/"+anp.name, "--type=json", "-p", patchANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		anpOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy.policy.networking.k8s.io/"+anp.name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP egress rule after step 6: %s\n", anpOutput)

		compat_otp.By("6.1. With BANP/ANP in place, verify egress traffic to external still works as expected\n")
		switch flag {
		case "ipecho":
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[0], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[1], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[2], ipEchoURL, true, worker1NodeIP)
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[3], ipEchoURL, true, worker2NodeIP)
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("6.2. With BANP/ANP in place, verify egress traffic from subjectNS to each node peer as expected\n")
		for i := 0; i < 4; i++ {
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[1], strconv.Itoa(int(hostport)))
			CurlPod2NodeFail(oc, subjectNS, hellopods[i], workers[2], strconv.Itoa(int(hostport)))
		}

		compat_otp.By("7. Unlabel egress-assignable label from current egressNode (workers[0]) to force egressIP failover to the 2nd egressNode (workers[1])\n")
		compat_otp.By("7.1. Verify egressIP failed over to 2nd egressNode which is workers[1] \n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)

		egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.Equal(workers[1]))
		o.Expect(egressIPMaps1[0]["egressIP"]).Should(o.Equal(freeIPs[0]))

		compat_otp.By("7.2. After egressIP failover, with BANP/ANP in place, Verify egress traffic to external works as expected \n")
		switch flag {
		case "ipecho":
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[0], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[1], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[2], ipEchoURL, true, worker1NodeIP)
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[3], ipEchoURL, true, worker2NodeIP)
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("7.3. After egressIP failover, and with BANP/ANP in place, Verify egress traffic from subjectNS to each node peer as expected \n")
		for i := 0; i < 4; i++ {
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[1], strconv.Itoa(int(hostport)))
			CurlPod2NodeFail(oc, subjectNS, hellopods[i], workers[2], strconv.Itoa(int(hostport)))
		}

		compat_otp.By("8. Patch change ANP 2nd rule so that egress traffic to workers[2] with NotIn operator and values:[qe, it]\n")
		patchANP = `[{"op": "replace", "path": "/spec/egress/1/to/0/nodes/matchExpressions/0/operator", "value": "NotIn"},{"op": "add", "path": "/spec/egress/1/to/0/nodes/matchExpressions/0/values", "value": ["qe", "it"]}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("adminnetworkpolicy/"+anp.name, "--type=json", "-p", patchANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		anpOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy.policy.networking.k8s.io/"+anp.name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP egress rule after step 8: %s\n", anpOutput)

		compat_otp.By("8.1. After egressIP failover, with BANP+ANP in place and ANP 2nd rule updated, Verify egress traffic to external works as expected \n")
		switch flag {
		case "ipecho":
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[0], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[1], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[2], ipEchoURL, true, worker1NodeIP)
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[3], ipEchoURL, true, worker2NodeIP)
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("8.2. After egressIP failover, with BANP+ANP in place, and ANP 2nd rule updated, Verify egress traffic from subjectNS to node peers work as expected \n")
		for i := 0; i < 4; i++ {
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[1], strconv.Itoa(int(hostport)))
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[2], strconv.Itoa(int(hostport)))
		}

		compat_otp.By("9. Flip action in 1st rule in ANP from Allow to Pass, flip action in 2nd rule in ANP from Deny to Allow\n")
		patchANP = `[{"op": "replace", "path": "/spec/egress/0/action", "value": "Pass"}, {"op": "replace", "path": "/spec/egress/1/action", "value": "Allow"}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("adminnetworkpolicy/"+anp.name, "--type=json", "-p", patchANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		anpOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy.policy.networking.k8s.io/"+anp.name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP egress rule after step 9: %s\n", anpOutput)

		compat_otp.By("9.1. Verify egress traffic to external works as expected after flipping actions in both ANP rules\n")
		switch flag {
		case "ipecho":
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[0], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[1], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[2], ipEchoURL, true, worker1NodeIP)
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[3], ipEchoURL, true, worker2NodeIP)
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("9.2. Verify egress traffic from subjectNS to node peers as expected after flipping actions in both ANP rules\n")
		for i := 0; i < 4; i++ {
			//Curl to nodeB should fail because of Deny rule in BANP after Pass rule in ANP
			CurlPod2NodeFail(oc, subjectNS, hellopods[i], workers[1], strconv.Itoa(int(hostport)))
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[2], strconv.Itoa(int(hostport)))
		}

		compat_otp.By("10. Delete ANP and update BANP to use NotIn operator with values:[qe,it]\n")
		removeResource(oc, true, true, "anp", anp.name)
		patchBANP = `[{"op": "replace", "path": "/spec/egress/0/to/0/nodes/matchExpressions/0/operator", "value": "NotIn"}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("baselineadminnetworkpolicy.policy.networking.k8s.io/default", "--type=json", "-p", patchBANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		banpOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("baselineadminnetworkpolicy.policy.networking.k8s.io/default", "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n BANP egress rule after step 10: %s\n", banpOutput)

		compat_otp.By("10.1. Verify egress traffic to external works as expected after update to BANP\n")
		switch flag {
		case "ipecho":
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[0], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[1], ipEchoURL, true, freeIPs[0])
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[2], ipEchoURL, true, worker1NodeIP)
			verifyEgressIPWithIPEcho(oc, subjectNS, hellopods[3], ipEchoURL, true, worker2NodeIP)
		default:
			g.Skip("Skip for not support scenarios!")
		}

		compat_otp.By("10.2. Verify egress traffic to node peers work as expected after update to BANP\n")
		for i := 0; i < 4; i++ {
			CurlPod2NodePass(oc, subjectNS, hellopods[i], workers[1], strconv.Itoa(int(hostport)))
			CurlPod2NodeFail(oc, subjectNS, hellopods[i], workers[2], strconv.Itoa(int(hostport)))
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-Longduration-NonPreRelease-High-67489-Egress traffic works with ANP, BANP and NP with Egress IP by cidrSelector.[Serial][Disruptive]", func() {
		var (
			buildPruningBaseDir         = testdata.FixturePath("networking")
			egressIP2Template           = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			pingPodTemplate             = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			testPodFile                 = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			banpTemplate                = filepath.Join(buildPruningBaseDir+"/adminnetworkpolicy", "banp-single-rule-cidr-template.yaml")
			anpTemplate                 = filepath.Join(buildPruningBaseDir+"/adminnetworkpolicy", "anp-multi-rule-cidr-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(buildPruningBaseDir+"/networkpolicy/ipblock", "ipBlock-egress-single-CIDR-template.yaml")
			matchLabelKey               = "kubernetes.io/metadata.name"
			cidrs                       []string
			dstHost                     = nslookDomainName("ifconfig.me")
		)

		// egressIP to two external CIDRs will be verified in this test, will use ipecho method to verify first one, tcpdump method to verify 2nd one, ipecho capability on the cluster is required
		if flag != "ipecho" {
			g.Skip("Test prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("0. Two external network CIDRs will be used to test egressIP, one is CIDR for ipecho server, another is the CIDR for test runner \n")
		ipechoServerNetwork := strings.Split(ipEchoURL, ":")[0] + "/32"
		cidrs = append(cidrs, ipechoServerNetwork)
		cidrs = append(cidrs, dstHost+"/32")
		e2e.Logf("\n external network CIDRs to be tested: %s\n", cidrs)

		compat_otp.By("1. Get schedulale nodes, label one node as egress assignable node\n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, egressNodeLabel, "true")

		compat_otp.By("2.1. Create an egressip object \n")
		freeIPs := findFreeIPs(oc, nodeList.Items[0].Name, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip1 := egressIPResource1{
			name:          "egressip-67489",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "company",
			nsLabelValue:  "redhat",
			podLabelKey:   "color",
			podLabelValue: "green",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.Equal(nodeList.Items[0].Name))
		o.Expect(egressIPMaps1[0]["egressIP"]).Should(o.Equal(freeIPs[0]))

		compat_otp.By("2.2 Obtain a namespace as subjectNS, label subjectNS to match namespaceSelector in egressIP object \n")
		subjectNS := oc.Namespace()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", subjectNS, "company-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", subjectNS, "company=redhat").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, subjectNS)

		compat_otp.By("2.3 Create a ping pod in subjectNS, label the pod to match podSelector in egressIP object \n")
		pingpod := pingPodResource{
			name:      "hello-pod",
			namespace: subjectNS,
			template:  pingPodTemplate,
		}
		pingpod.createPingPod(oc)
		waitPodReady(oc, pingpod.namespace, pingpod.name)
		defer compat_otp.LabelPod(oc, subjectNS, pingpod.name, "color-")
		err = compat_otp.LabelPod(oc, subjectNS, pingpod.name, "color=green")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3. Create a second namespace as targetNS, create a test pod in the targetNS \n")
		oc.SetupProject()
		targetNS := oc.Namespace()
		createResourceFromFile(oc, targetNS, testPodFile)
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=1", "-n", targetNS).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, targetNS, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "Test pod with label name=test-pods not ready")
		testpods := getPodName(oc, targetNS, "name=test-pods")

		compat_otp.By("Before applying BANP/NP/ANP, check healthiness of egress traffic to two external CIDRS, as well as to targetedNS on pod2pod and pod2svc \n")
		compat_otp.By("3.1 Verify egress traffic to external CIDR0 should be allowed \n")
		verifyEgressIPWithIPEcho(oc, subjectNS, pingpod.name, ipEchoURL, true, freeIPs[0])

		compat_otp.By("3.2 Verify egress traffic to external CIDR1 should be allowed \n")
		compat_otp.By("Create tcpdumpDS using external CIDR1 \n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, "tcpdump", "true")
		primaryInf, infErr := getSnifPhyInf(oc, nodeList.Items[0].Name)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		defer deleteTcpdumpDS(oc, "tcpdump-67489", subjectNS)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, subjectNS, "tcpdump-67489", "tcpdump", "true", dstHost, primaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())
		egressErr := verifyEgressIPinTCPDump(oc, pingpod.name, subjectNS, freeIPs[0], dstHost, subjectNS, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to get expected egressip:%s in tcpdump", freeIPs[0]))

		compat_otp.By("3.3. Verify pod2pod and pod2svc egress traffic to targetNS should be allowed \n")
		CurlPod2PodPass(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcPass(oc, subjectNS, targetNS, pingpod.name, "test-service")

		compat_otp.By("4. Apply BANP with single rule to deny egress traffic to cidr 0.0.0.0/0 \n")
		banp := singleRuleCIDRBANPPolicyResource{
			name:       "default",
			subjectKey: matchLabelKey,
			subjectVal: subjectNS,
			ruleName:   "egress-to-cidr",
			ruleAction: "Deny",
			cidr:       "0.0.0.0/0",
			template:   banpTemplate,
		}
		defer removeResource(oc, true, true, "banp", banp.name)
		banp.createSingleRuleCIDRBANP(oc)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("banp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, banp.name)).To(o.BeTrue())

		banpOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("baselineadminnetworkpolicy.policy.networking.k8s.io/default", "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\nBANP egress rule after step 4: %s\n", banpOutput)

		compat_otp.By("4.1. With BANP in place, verify egress traffic to external CIDR0 should be blocked \n")
		sourceIP, err := execCommandInSpecificPod(oc, subjectNS, pingpod.name, "for i in {1..2}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(sourceIP).To(o.BeEmpty())

		compat_otp.By("4.2. With BANP in place, Verify egress traffic to external CIDR1 should be blocked \n")
		egressipErr := wait.Poll(12*time.Second, 60*time.Second, func() (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, subjectNS, pingpod.name, "for i in {1..2}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, subjectNS, tcpdumpDS.name, randomStr, egressIPMaps1[0]["egressIP"], false) != nil {
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to verify egress traffic to external CIDR1 is blocked:%v", egressipErr))

		compat_otp.By("4.3. With BANP in place, verify pod2pod and pod2svc egress traffic to targetNS should be blocked \n")
		CurlPod2PodFail(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcFail(oc, subjectNS, targetNS, pingpod.name, "test-service")

		compat_otp.By("5. Update BANP rule to deny the network to external CIDR0 only\n")
		patchBANP := fmt.Sprintf("[{\"op\": \"replace\", \"path\": \"/spec/egress/0/to/0/networks/0\", \"value\": %s}]", cidrs[0])
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("baselineadminnetworkpolicy.policy.networking.k8s.io/default", "--type=json", "-p", patchBANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		banpOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("baselineadminnetworkpolicy.policy.networking.k8s.io/default", "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n BANP egress rule after update of step 5: %s\n", banpOutput)

		compat_otp.By("5.1. After BANP update, verify egress traffic to external CIDR0 should be blocked \n")
		sourceIP, err = execCommandInSpecificPod(oc, subjectNS, pingpod.name, "for i in {1..2}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(sourceIP).To(o.BeEmpty())

		compat_otp.By("5.2. After BANP update, verify egress traffic to external CIDR1 should be allowed \n")
		egressErr = verifyEgressIPinTCPDump(oc, pingpod.name, subjectNS, freeIPs[0], dstHost, subjectNS, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to get expected egressip:%s in tcpdump", freeIPs[0]))

		compat_otp.By("5.3. After BANP update, verify pod2pod and pod2svc egress traffic should be allowed \n")
		CurlPod2PodPass(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcPass(oc, subjectNS, targetNS, pingpod.name, "test-service")

		compat_otp.By("6. Create a NP to Allow to external CIDR0 \n")
		np := ipBlockCIDRsSingle{
			name:      "ipblock-single-cidr-egress",
			template:  ipBlockEgressTemplateSingle,
			cidr:      cidrs[0],
			namespace: subjectNS,
		}
		np.createipBlockCIDRObjectSingle(oc)
		output, err = oc.AsAdmin().Run("get").Args("networkpolicy", "-n", subjectNS).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress"))

		compat_otp.By("6.1. With BANP+NP in place, verify egress traffic to external CIDR0 should be allowed \n")
		verifyEgressIPWithIPEcho(oc, subjectNS, pingpod.name, ipEchoURL, true, freeIPs[0])

		compat_otp.By("6.2. With BANP+NP in place, verify egress traffic to external CIDR1 should be blocked \n")
		egressipErr = wait.Poll(12*time.Second, 60*time.Second, func() (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, subjectNS, pingpod.name, "for i in {1..2}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, subjectNS, tcpdumpDS.name, randomStr, egressIPMaps1[0]["egressIP"], false) != nil {
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to verify traffic to external CIDR1:%v", egressipErr))

		compat_otp.By("6.3. With BANP+NP in place, verify pod2pod and pod2svc egress traffic should be blocked \n")
		CurlPod2PodFail(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcFail(oc, subjectNS, targetNS, pingpod.name, "test-service")

		compat_otp.By("7. Apply ANP with 2 rules, first rule to deny egress to external CIDR0, 2nd rule to allow egress to external CIDR1 \n")
		anp := MultiRuleCIDRANPPolicyResource{
			name:        "anp-67489",
			subjectKey:  matchLabelKey,
			subjectVal:  subjectNS,
			priority:    10,
			ruleName1:   "egress-to-cidr0",
			ruleAction1: "Deny",
			cidr1:       cidrs[0],
			ruleName2:   "egress-to-cidr1",
			ruleAction2: "Allow",
			cidr2:       cidrs[1],
			template:    anpTemplate,
		}
		defer removeResource(oc, true, true, "anp", anp.name)
		anp.createMultiRuleCIDRANP(oc)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, anp.name)).To(o.BeTrue())

		anpOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy.policy.networking.k8s.io/"+anp.name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP egress rule after step 7: %s\n", anpOutput)

		compat_otp.By("7.1 With BANP+NP+ANP, verify egress traffic to external CIDR0 should be blocked \n")
		sourceIP, err = execCommandInSpecificPod(oc, subjectNS, pingpod.name, "for i in {1..2}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(sourceIP).To(o.BeEmpty())

		compat_otp.By("7.2. With BANP+NP+ANP, verify egress traffic to external CIDR1 should be allowed \n")
		egressErr = verifyEgressIPinTCPDump(oc, pingpod.name, subjectNS, freeIPs[0], dstHost, subjectNS, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to get expected egressip:%s in tcpdump", freeIPs[0]))

		compat_otp.By("7.3. With BANP+NP+ANP, verify pod2pod and pod2svc egress traffic should be blocked due to NP \n")
		CurlPod2PodFail(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcFail(oc, subjectNS, targetNS, pingpod.name, "test-service")

		compat_otp.By("8. Flip action for ANP 1st rule from Deny to Allow, flip action for ANP 2nd rule from Allow to Deny \n")
		patchANP := `[{"op": "replace", "path": "/spec/egress/0/action", "value": "Allow"},{"op": "replace", "path": "/spec/egress/1/action", "value": "Deny"}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("adminnetworkpolicy/"+anp.name, "--type=json", "-p", patchANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		anpOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy.policy.networking.k8s.io/"+anp.name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP egress rule after step 8: %s\n", anpOutput)

		compat_otp.By("8.1 After flipping ANP rules, verify egress traffic to external CIDR0 should be allowed \n")
		verifyEgressIPWithIPEcho(oc, subjectNS, pingpod.name, ipEchoURL, true, freeIPs[0])

		compat_otp.By("8.2. After flipping ANP rules, verify egress traffic to external CIDR1 should be blocked \n")
		egressipErr = wait.Poll(12*time.Second, 60*time.Second, func() (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, subjectNS, pingpod.name, "for i in {1..2}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, subjectNS, tcpdumpDS.name, randomStr, egressIPMaps1[0]["egressIP"], false) != nil {
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to verify egress traffic to external CIDR1 is blocked:%v", egressipErr))

		compat_otp.By("8.3. After flipping ANP rules, verify pod2pod and pod2svc egress traffic should be denied due to NP \n")
		CurlPod2PodFail(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcFail(oc, subjectNS, targetNS, pingpod.name, "test-service")

		compat_otp.By("9. Update ANP first rule to Allow 0.0.0.0/0 \n")
		patchANP = `[{"op": "replace", "path": "/spec/egress/0/to/0/networks/0", "value": "0.0.0.0/0"}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("adminnetworkpolicy/"+anp.name, "--type=json", "-p", patchANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		anpOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy.policy.networking.k8s.io/"+anp.name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP egress rule after step 9: %s\n", anpOutput)

		compat_otp.By("9.1. After ANP first rule cidr update, verify egress traffic to external CIDR0 should be allowed \n")
		verifyEgressIPWithIPEcho(oc, subjectNS, pingpod.name, ipEchoURL, true, freeIPs[0])

		compat_otp.By("9.2. After ANP first rule cidr update, verify egress traffic to external CIDR1 should be allowed \n")
		egressErr = verifyEgressIPinTCPDump(oc, pingpod.name, subjectNS, freeIPs[0], dstHost, subjectNS, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to get expected egressip:%s in tcpdump", freeIPs[0]))

		compat_otp.By("9.3. After ANP first rule cidr update, verify pod2pod and pod2svc egress traffic should be allowed \n")
		CurlPod2PodPass(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcPass(oc, subjectNS, targetNS, pingpod.name, "test-service")

		compat_otp.By("10. Flip action for ANP first rule from Allow to Pass\n")
		patchANP = `[{"op": "replace", "path": "/spec/egress/0/action", "value": "Pass"}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("adminnetworkpolicy/"+anp.name, "--type=json", "-p", patchANP).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		anpOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy.policy.networking.k8s.io/"+anp.name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP egress rule after step 10: %s\n", anpOutput)

		compat_otp.By("10.1. Verify egress traffic to external CIDR0 should be allowed because CIDR0 is in allowed ipvlock of NP \n")
		verifyEgressIPWithIPEcho(oc, subjectNS, pingpod.name, ipEchoURL, true, freeIPs[0])

		compat_otp.By("10.2. Verify egress traffic to external CIDR1 should be blocked because CIDR1 is not in allowed ipblock of NP \n")
		egressipErr = wait.Poll(12*time.Second, 60*time.Second, func() (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, subjectNS, pingpod.name, "for i in {1..2}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, subjectNS, tcpdumpDS.name, randomStr, egressIPMaps1[0]["egressIP"], false) != nil {
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to verify egress traffic to external CIDR1 is blocked:%v", egressipErr))

		compat_otp.By("10.3. Verify pod2pod and pod2svc egress traffic should be denied due to NP \n")
		CurlPod2PodFail(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcFail(oc, subjectNS, targetNS, pingpod.name, "test-service")

		compat_otp.By("11. Delete network policy created in step 6\n")
		removeResource(oc, true, true, "networkpolicy", np.name, "-n", np.namespace)

		compat_otp.By("11.1. After deleting NP, verify egress traffic to external CIDR0 should be blocked \n")
		sourceIP, err = execCommandInSpecificPod(oc, subjectNS, pingpod.name, "for i in {1..3}; do curl -s "+ipEchoURL+" --connect-timeout 5 ; sleep 2;echo ;done")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(sourceIP).To(o.BeEmpty())

		compat_otp.By("11.2. After deleting NP, verify egress traffic to external CIDR1 should be allowed \n")
		egressErr = verifyEgressIPinTCPDump(oc, pingpod.name, subjectNS, freeIPs[0], dstHost, subjectNS, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to get expected egressip:%s in tcpdump", freeIPs[0]))

		compat_otp.By("11.3. After deleting NP, verify pod2pod and pod2svc egress traffic should be allowed \n")
		CurlPod2PodPass(oc, subjectNS, pingpod.name, targetNS, testpods[0])
		CurlPod2SvcPass(oc, subjectNS, targetNS, pingpod.name, "test-service")

	})

})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP Basic", func() {
	//Cases in this function, do not need curl ip-echo
	defer g.GinkgoRecover()

	var (
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
	)

	g.BeforeEach(func() {
		platform := compat_otp.CheckPlatform(oc)
		networkType := checkNetworkType(oc)
		e2e.Logf("\n\nThe platform is %v,  networkType is %v\n", platform, networkType)

		acceptedPlatform := strings.Contains(platform, "aws") || strings.Contains(platform, "gcp") || strings.Contains(platform, "openstack") || strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "azure") || strings.Contains(platform, "none") || strings.Contains(platform, "nutanix") || strings.Contains(platform, "powervs")
		if !acceptedPlatform || !strings.Contains(networkType, "ovn") {
			g.Skip("Test cases should be run on AWS/GCP/Azure/Openstack/Vsphere/Baremetal/Nutanix/Powervs cluster with ovn network plugin, skip for other platforms or other non-OVN network plugin!!")
		}
		if strings.Contains(platform, "none") {
			// For UPI baremetal, egressIP cases only can be tested on clusters from upi-on-baremetal/versioned-installer-packet-http_proxy-private-vlan as some limitations on other clusters.
			e2e.Logf("\n UPI BareMetal is detected, running the case on UPI BareMetal\n")
			ipEchoURL := getIPechoURLFromUPIPrivateVlanBM(oc)
			e2e.Logf("IP echo URL is %s", ipEchoURL)
			if ipEchoURL == "" {
				g.Skip("This UPI Baremetal cluster did not fulfill the prequiste of testing egressIP cases, skip the test!!")
			}
		}

		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv6single" {
			// Not able to run on IPv6 single cluster for now due to cluster disconneect limiation.
			g.Skip("Skip IPv6 Single cluster.")
		}

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonPreRelease-Longduration-Medium-47029-Low-47024-Any egress IP can only be assigned to one node only. Warning event will be triggered if applying EgressIP object but no EgressIP nodes. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("2 Create first egressip object \n")
		freeIPs := findFreeIPs(oc, egressNodes[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:          "egressip-47029",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("3. Check warning event. \n")
		warnErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			warningEvent, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("event", "-n", "default").Output()
			if err != nil {
				e2e.Logf("Wait for waring event generated.%v", err)
				return false, nil
			}
			if !strings.Contains(warningEvent, "NoMatchingNodeFound") {
				e2e.Logf("Wait for waring event generated. ")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(warnErr, "Warning event doesn't conclude: NoMatchingNodeFound.")

		compat_otp.By("4 Apply EgressLabel Key to nodes. \n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)

		compat_otp.By("5. Check EgressIP assigned in the object.\n")
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1), "EgressIP object should get one applied item, but actually not.")

		compat_otp.By("6 Create second egressip object with same egressIP \n")
		egressip2 := egressIPResource1{
			name:          "egressip-47024",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip2.createEgressIPObject2(oc)
		defer egressip2.deleteEgressIPObject1(oc)

		compat_otp.By("7 Check the second egressIP object, no egressIP assigned  .\n")
		egressIPStatus, egressIPerr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressip", egressip2.name, "-ojsonpath={.status.items}").Output()
		o.Expect(egressIPerr).NotTo(o.HaveOccurred())
		o.Expect(egressIPStatus).To(o.Equal(""))

		compat_otp.By("8. Edit the second egressIP object to another IP\n")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/"+egressip2.name, "-p", "{\"spec\":{\"egressIPs\":[\""+freeIPs[1]+"\"]}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("9. Check egressIP assigned in the second object.\n")
		egressIPMaps2 := getAssignedEIPInEIPObject(oc, egressip2.name)

		o.Expect(len(egressIPMaps2)).Should(o.Equal(1), "EgressIP object should get one applied item, but actually not.")

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-High-47021-lr-policy-list and snat should be updated correctly after remove pods. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP1Template := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name

		compat_otp.By("2 Apply EgressLabel Key to one node. \n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		// For dual stack cluster, it needs two nodes holding IPv4 and IPv6 seperately.
		ipStackType := checkIPStackType(oc)
		var egressNode2 string
		if ipStackType == "dualstack" {
			if len(nodeList.Items) < 2 {
				g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
			}
			egressNode2 = nodeList.Items[1].Name
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		}

		compat_otp.By("3. create new namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("4. Apply label to namespace\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("5. Create test pods and scale test pods to 10 \n")
		createResourceFromFile(oc, ns1, testPodFile)
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=10", "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		compat_otp.By("6. Create an egressip object\n")

		var freeIPs []string
		switch ipStackType {
		case "ipv4single":
			freeIPs = findFreeIPs(oc, egressNode, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		case "dualstack":
			freeIPv6s := findFreeIPv6s(oc, egressNode2, 1)
			o.Expect(len(freeIPv6s)).Should(o.Equal(1))
			freeIPs = findFreeIPs(oc, egressNode, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPs = append(freeIPs, freeIPv6s[0])
		}
		egressip1 := egressIPResource1{
			name:      "egressip-47021",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		if ipStackType == "dualstack" {
			o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
		} else {
			o.Expect(len(egressIPMaps1) == 1).Should(o.BeTrue())
		}

		compat_otp.By("6. Restart ovnkube-node pod which is on egress node\n")
		ovnPod := ovnkubeNodePod(oc, egressNode)
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", ovnPod, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		compat_otp.By("9. Scale test pods to 1 \n")
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=1", "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		podsErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			podsOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", ns1).Output()
			e2e.Logf(podsOutput)
			o.Expect(err).NotTo(o.HaveOccurred())
			if strings.Count(podsOutput, "test") == 1 {
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(podsErr, fmt.Sprintf("The pods were not scaled to the expected number!"))
		testPodName := getPodName(oc, ns1, "name=test-pods")
		testPodIP1, testPodIP2 := getPodIP(oc, ns1, testPodName[0])
		e2e.Logf("testPodIP1: %v,testPodIP2: %v", testPodIP1, testPodIP2)
		testPodNode, err := compat_otp.GetPodNodeName(oc, ns1, testPodName[0])
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("test pod %s is on node %s", testPodName, testPodNode)

		compat_otp.By("11. Check lr-policy-list and snat in northdb. \n")
		ovnPod = ovnkubeNodePod(oc, testPodNode)
		o.Expect(ovnPod != "").Should(o.BeTrue())
		lspCmd := "ovn-nbctl lr-policy-list ovn_cluster_router | grep -v inport"
		checkLspErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
			lspOutput, lspErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lspCmd)
			if lspErr != nil {
				e2e.Logf("%v,Waiting for lr-policy-list to be synced, try next ...,", lspErr)
				return false, nil
			}
			e2e.Logf(lspOutput)
			if ipStackType == "dualstack" {
				if strings.Contains(lspOutput, testPodIP1) && strings.Contains(lspOutput, testPodIP2) && strings.Count(lspOutput, "100 ") == 2 {
					return true, nil
				}
			} else {
				if strings.Contains(lspOutput, testPodIP1) && strings.Count(lspOutput, "100 ") == 1 {
					return true, nil
				}
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(checkLspErr, fmt.Sprintf("lr-policy-list was not synced correctly!"))

		ovnPod = ovnkubeNodePod(oc, egressNode)
		var ovnPod2 string
		if ipStackType == "dualstack" {
			ovnPod2 = ovnkubeNodePod(oc, egressNode2)
		}
		snatCmd := "ovn-nbctl --format=csv --no-heading find nat | grep " + egressip1.name
		checkSnatErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			snatOutput, snatErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, snatCmd)
			e2e.Logf(snatOutput)
			filterStr := "EgressIP:" + egressip1.name
			if snatErr != nil {
				e2e.Logf("%v,Waiting for snat to be synced, try next ...,", snatErr)
				return false, nil
			}

			if ipStackType == "dualstack" {
				snatOutput2, snatErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod2, snatCmd)
				if snatErr != nil {
					e2e.Logf("%v,Waiting for snat to be synced, try next ...,", snatErr)
					return false, nil
				}
				snatOutput = snatOutput + "\n" + snatOutput2
				e2e.Logf(snatOutput)

				if strings.Contains(snatOutput, testPodIP1) && strings.Contains(snatOutput, testPodIP2) && strings.Count(snatOutput, filterStr) == 2 {
					e2e.Logf("The snat for egressip is as expected!")
					return true, nil
				}
			} else {
				if strings.Contains(snatOutput, testPodIP1) && strings.Count(snatOutput, filterStr) == 1 {
					e2e.Logf("The snat for egressip is as expected!")
					return true, nil
				}
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(checkSnatErr, fmt.Sprintf("snat was not synced correctly!"))

	})

	// author: qiowang@redhat.com
	g.It("Author:qiowang-Longduration-NonPreRelease-Medium-47208-High-86772-The configured EgressIPs exceeds IP capacity. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		check, nodes := findTwoNodesWithSameSubnet(oc, nodeList)
		var egressNode1, egressNode2, machinesetName string
		if check {
			egressNode1 = nodes[0]
			egressNode2 = nodes[1]
		} else {
			machinesetName = clusterinfra.GetRandomMachineSetName(oc)
			e2e.Logf("machinesetName is: %s", machinesetName)
			nodeNames := clusterinfra.GetNodeNamesFromMachineSet(oc, machinesetName)
			egressNode1 = nodeNames[0]
		}

		compat_otp.By("2 Apply EgressLabel Key to one node. \n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

		compat_otp.By("3 Get IP capacity of the node. \n")
		ipCapacity := getIPv4Capacity(oc, egressNode1)
		o.Expect(ipCapacity != "").Should(o.BeTrue())
		ipCap, _ := strconv.Atoi(ipCapacity)
		if ipCap > 14 {
			g.Skip("This is not the general IP capacity, will skip it.")
		}
		exceedNum := ipCap + 1

		compat_otp.By("4 Create egressip objects \n")
		sub1 := getIfaddrFromNode(egressNode1, oc)
		freeIPs := findUnUsedIPsOnNode(oc, egressNode1, sub1, exceedNum)
		o.Expect(len(freeIPs) == exceedNum).Should(o.BeTrue())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("egressip", "--all").Execute()
		egressIPConfig := make([]egressIPResource1, exceedNum)
		for i := 0; i <= ipCap; i++ {
			iVar := strconv.Itoa(i)
			egressIPConfig[i] = egressIPResource1{
				name:          "egressip-47208-" + iVar,
				template:      egressIP2Template,
				egressIP1:     freeIPs[i],
				nsLabelKey:    "org",
				nsLabelValue:  "qe",
				podLabelKey:   "color",
				podLabelValue: "pink",
			}
			egressIPConfig[i].createEgressIPObject2(oc)
		}

		compat_otp.By("5 Check ipCapacity+1 number egressIP created,but one is not assigned egress node \n")
		egressIPErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			egressIPOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressip").Output()
			e2e.Logf(egressIPOutput)
			if err != nil {
				e2e.Logf("Wait for egressip assigned.%v", err)
				return false, nil
			}
			if strings.Count(egressIPOutput, "egressip-47208") == exceedNum {
				e2e.Logf("The %v number egressIP object created.", exceedNum)
				if strings.Count(egressIPOutput, egressNode1) == ipCap {
					e2e.Logf("The %v number egressIPs were assigned.", ipCap)
					return true, nil
				}
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(egressIPErr, fmt.Sprintf(" Error at getting EgressIPs or EgressIPs were not assigned corrently."))

		compat_otp.By("6. Check warning event. \n")
		warnErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			warningEvent, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("event", "-n", "default").Output()
			if err != nil {
				e2e.Logf("Wait for warning event generated.%v", err)
				return false, nil
			}
			if !strings.Contains(warningEvent, "NoMatchingNodeFound") {
				e2e.Logf("Expected warning message is not found, try again ")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(warnErr, fmt.Sprintf("Warning event doesn't conclude: NoMatchingNodeFound."))

		platform := compat_otp.CheckPlatform(oc)
		creErr := getAwsCredentialFromCluster(oc)
		if strings.Contains(platform, "aws") && creErr == nil {
			compat_otp.By("Test OCP-86772 EgressIP not assigned when node capacity is full and assigned to new node with capacity\n\n")
			compat_otp.By("86772-1. Assign private IPs on node via console to fill up the capacity\n\n")
			delErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("egressip", "--all").Execute()
			o.Expect(delErr).NotTo(o.HaveOccurred())
			//It will take several seconds to delete all egressips
			o.Eventually(func() bool {
				output1, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressip").Output()
				output2, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("cloudprivateipconfig").Output()
				return strings.Contains(output1, "No resources found") && strings.Contains(output2, "No resources found")
			}, 20*time.Second, 2*time.Second).Should(o.BeTrue(), "fail to delete all egressips")
			a := compat_otp.InitAwsSession()
			// Get the instance ID for the egress node
			instanceID, err := a.GetAwsInstanceIDFromHostname(egressNode1)
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("Node %s has instance ID: %s", egressNode1, instanceID)
			// Get the network interface ID for the instance
			networkInterfaceID, err := getNetworkInterfaceID(a, instanceID)
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("Instance %s has network interface ID: %s", instanceID, networkInterfaceID)
			assignedIPs, err := assignPrivateIPsToENI(a, networkInterfaceID, ipCap)
			o.Expect(err).NotTo(o.HaveOccurred())
			defer restartCNCC(oc)
			defer func() {
				if len(assignedIPs) > 0 {
					unassignErr := unassignPrivateIPsFromENI(a, networkInterfaceID, assignedIPs)
					o.Expect(unassignErr).NotTo(o.HaveOccurred())
				}
			}()

			compat_otp.By("86772-2. Restart CNCC to sync the IP assignment, the IP capacity on the node should be 0\n\n")
			restartCNCC(oc)
			capacityErr := wait.Poll(10*time.Second, 120*time.Second, func() (bool, error) {
				ipCapacity := getIPv4Capacity(oc, egressNode1)
				o.Expect(ipCapacity != "").Should(o.BeTrue())
				e2e.Logf("Current IPv4 capacity on node %s: %s", egressNode1, ipCapacity)
				if ipCapacity == "0" {
					e2e.Logf("IPv4 capacity is 0 as expected")
					return true, nil
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(capacityErr, "IPv4 capacity did not become 0")

			compat_otp.By("86772-3. Create one EgressIP object, it should not be assigned to the node due to no capacity\n\n")
			freeIPs := findFreeIPs(oc, egressNode1, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			egressip := egressIPResource1{
				name:          "egressip-capacity-test",
				template:      egressIP2Template,
				egressIP1:     freeIPs[0],
				nsLabelKey:    "org",
				nsLabelValue:  "qe",
				podLabelKey:   "color",
				podLabelValue: "pink",
			}
			egressip.createEgressIPObject2(oc)
			egressIPStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressip", egressip.name, "-ojsonpath={.status.items}").Output()
			e2e.Logf("egressIPStatus: %v", egressIPStatus)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(egressIPStatus).To(o.Equal(""))

			compat_otp.By("86772-4. Check cloudprivateipconfigs, there should be no entry for the new created EIP\n\n")
			waitCloudPrivateIPconfigUpdate(oc, freeIPs[0], false)

			compat_otp.By("86772-5. Label another node which is in the same subnet as egress node\n\n")
			// Scale up machineset if there is no other node in the same subnet with egressnode1
			if egressNode2 == "" {
				originReplicas := clusterinfra.GetMachineSetReplicas(oc, machinesetName)
				defer clusterinfra.ScaleMachineSet(oc, machinesetName, originReplicas)
				clusterinfra.ScaleMachineSet(oc, machinesetName, originReplicas+1)
				machineName := clusterinfra.GetLatestMachineFromMachineSet(oc, machinesetName)
				o.Expect(machineName).NotTo(o.BeEmpty())
				defer clusterinfra.WaitForMachineDisappearByName(oc, machineName)
				defer clusterinfra.DeleteMachine(oc, machineName)
				egressNode2 = clusterinfra.GetNodeNameFromMachine(oc, machineName)
			}
			e2e.Logf("egressNode2 is: %s", egressNode2)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)

			compat_otp.By("86772-6. Check the EgressIP will be assigned to the new added node\n\n")
			egressIPMaps := getAssignedEIPInEIPObject(oc, egressip.name)
			o.Expect(len(egressIPMaps)).Should(o.Equal(1))
			egressipAssignedNode := egressIPMaps[0]["node"]
			e2e.Logf("egressip is assigned to : %v", egressipAssignedNode)
			o.Expect(egressipAssignedNode).To(o.ContainSubstring(egressNode2))

			compat_otp.By("86772-7. Verify cloudprivateipconfig status is CloudResponseSuccess\n\n")
			waitCloudPrivateIPconfigUpdate(oc, freeIPs[0], true)
		}
	})

	// author: jechen@redhat.com
	g.It("[Level0] Author:jechen-NonHyperShiftHOST-NonPreRelease-Longduration-ConnectedOnly-High-54045-EgressIP health check through monitoring port over GRPC on OCP OVN cluster. [Disruptive]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		ipStackType := checkIPStackType(oc)
		if ipStackType != "ipv4single" {
			g.Skip("This case requires IPv4 cluster only")
		}

		compat_otp.By("1 check ovnkube-config configmap if egressip-node-healthcheck-port=9107 is in it \n")
		configmapName := "ovnkube-config"
		envString := " egressip-node-healthcheck-port=9107"
		cmCheckErr := checkEnvInConfigMap(oc, "openshift-ovn-kubernetes", configmapName, envString)
		o.Expect(cmCheckErr).NotTo(o.HaveOccurred())

		compat_otp.By("2 get leader OVNK control plane pod and ovnkube-node pods \n")
		readyErr := waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-control-plane")
		compat_otp.AssertWaitPollNoErr(readyErr, "ovnkube-control-plane pods are not ready")
		OVNKCtrlPlaneLeadPodName := getOVNKMasterPod(oc)

		readyErr = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		compat_otp.AssertWaitPollNoErr(readyErr, "ovnkube-node pods are not ready")
		ovnkubeNodePods := getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		compat_otp.By("3 Check each ovnkube-node pod's log that health check server is started on it \n")
		expectedString := "Starting Egress IP Health Server on "
		for _, ovnkubeNodePod := range ovnkubeNodePods {
			podLogs, LogErr := checkLogMessageInPod(oc, "openshift-ovn-kubernetes", "ovnkube-controller", ovnkubeNodePod, "'egress ip'")
			o.Expect(LogErr).NotTo(o.HaveOccurred())
			o.Expect(podLogs).To(o.ContainSubstring(expectedString))
		}

		compat_otp.By("4 Get list of nodes, pick one as egressNode, apply EgressLabel Key to it \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		nodeOVNK8sMgmtIP := getOVNK8sNodeMgmtIPv4(oc, egressNode)

		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("5 Check leader OVNK control plane pod's log that health check connection has been made to the egressNode on port 9107 \n")
		expectedString = "Connected to " + egressNode + " (" + nodeOVNK8sMgmtIP + ":9107)"
		podLogs, LogErr := checkLogMessageInPod(oc, "openshift-ovn-kubernetes", "ovnkube-cluster-manager", OVNKCtrlPlaneLeadPodName, "'"+expectedString+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedString))

		compat_otp.By("6. Create an egressip object, verify egressIP is assigned to the egressNode")
		freeIPs := findFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-54045",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "red",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("7. Add iptables on to block port 9107 on egressNode, verify from log of ovnkube-control-plane pod that the health check connection is closed.\n")
		defer compat_otp.DebugNodeWithChroot(oc, egressNode, "iptables", "-D", "INPUT", "-p", "tcp", "--destination-port", "9107", "-j", "DROP")
		_, debugNodeErr := compat_otp.DebugNodeWithChroot(oc, egressNode, "iptables", "-I", "INPUT", "1", "-p", "tcp", "--destination-port", "9107", "-j", "DROP")
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())

		expectedString1 := "Closing connection with " + egressNode + " (" + nodeOVNK8sMgmtIP + ":9107)"
		podLogs, LogErr = checkLogMessageInPod(oc, "openshift-ovn-kubernetes", "ovnkube-cluster-manager", OVNKCtrlPlaneLeadPodName, "'"+expectedString1+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedString1))
		expectedString2 := "Could not connect to " + egressNode + " (" + nodeOVNK8sMgmtIP + ":9107)"
		podLogs, LogErr = checkLogMessageInPod(oc, "openshift-ovn-kubernetes", "ovnkube-cluster-manager", OVNKCtrlPlaneLeadPodName, "'"+expectedString2+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedString2))

		compat_otp.By("8. Verify egressIP is not assigned after blocking iptable rule on port 9170 is added.\n")
		o.Eventually(func() bool {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			return len(egressIPMaps1) == 0
		}, "300s", "10s").Should(o.BeTrue(), "egressIP is not unassigned after blocking iptable rule on port 9170 is added!!")

		compat_otp.By("9. Delete the iptables rule, verify from log of ovnkube-control-plane pod that the health check connection is re-established.\n")
		_, debugNodeErr = compat_otp.DebugNodeWithChroot(oc, egressNode, "iptables", "-D", "INPUT", "-p", "tcp", "--destination-port", "9107", "-j", "DROP")
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())

		expectedString = "Connected to " + egressNode + " (" + nodeOVNK8sMgmtIP + ":9107)"
		podLogs, LogErr = checkLogMessageInPod(oc, "openshift-ovn-kubernetes", "ovnkube-cluster-manager", OVNKCtrlPlaneLeadPodName, "'"+expectedString+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedString))

		compat_otp.By("10. Verify egressIP is re-applied after blocking iptable rule on port 9170 is deleted.\n")
		o.Eventually(func() bool {
			egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
			return len(egressIPMaps) == 1
		}, "60s", "10s").Should(o.BeTrue(), "egressIP failed to be re-applied after blocking iptable rule on port 9170 is deleted!!")

		compat_otp.By("11. Unlabel the egressNoe egressip-assignable, verify from log of ovnkube-control-plane pod that the health check connection is closed.\n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeList.Items[0].Name, egressNodeLabel)
		expectedString = "Closing connection with " + egressNode + " (" + nodeOVNK8sMgmtIP + ":9107)"

		podLogs, LogErr = checkLogMessageInPod(oc, "openshift-ovn-kubernetes", "ovnkube-cluster-manager", OVNKCtrlPlaneLeadPodName, "'"+expectedString+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedString))
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Author:huirwang-High-Longduration-NonPreRelease-55030-After reboot egress node, lr-policy-list and snat should keep correct. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP1Template := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("2 Apply EgressLabel Key to one node. \n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")

		compat_otp.By("3. create new namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("4. Apply label to namespace\n")
		worker1 := nodeList.Items[0].Name
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("5. Create test pods and scale test pods to 5 \n")
		createResourceFromFile(oc, ns1, testPodFile)
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("replicationcontroller/test-rc", "-n", ns1, "-p", "{\"spec\":{\"template\":{\"spec\":{\"nodeName\":\""+worker1+"\"}}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=0", "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=5", "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		compat_otp.By("6. Create an egressip object\n")
		ipStackType := checkIPStackType(oc)
		var freeIPs []string
		lspExpNum := 5
		switch ipStackType {
		case "ipv4single":
			freeIPs = findFreeIPs(oc, egressNodes[0], 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		case "dualstack":
			//Get one IPv6 address for second node
			freeIPv6s := findFreeIPv6s(oc, egressNodes[1], 1)
			o.Expect(len(freeIPv6s)).Should(o.Equal(1))
			//Get one IPv4 address
			freeIPs = findFreeIPs(oc, egressNodes[0], 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPs = append(freeIPs, freeIPv6s[0])
			lspExpNum = 10
		case "ipv6single":
			freeIPs = findFreeIPv6s(oc, egressNodes[0], 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		}
		egressip1 := egressIPResource1{
			name:      "egressip-55030",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		compat_otp.By("5.Reboot egress node.\n")
		defer checkNodeStatus(oc, egressNodes[0], "Ready")
		rebootNode(oc, egressNodes[0])
		checkNodeStatus(oc, egressNodes[0], "NotReady")
		checkNodeStatus(oc, egressNodes[0], "Ready")
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		compat_otp.By("6. Check lr-policy-list and snat in northdb. \n")
		ovnPod := ovnkubeNodePod(oc, worker1)
		o.Expect(ovnPod).ShouldNot(o.Equal(""))
		lspCmd := "ovn-nbctl lr-policy-list ovn_cluster_router | grep -v inport"
		o.Eventually(func() bool {
			output, cmdErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, lspCmd)
			e2e.Logf(output)
			return cmdErr == nil && strings.Count(output, "100 ") == lspExpNum
		}, "120s", "10s").Should(o.BeTrue(), "The command check result for lr-policy-list in ovndb is not expected!")
		ovnPod = ovnkubeNodePod(oc, egressNodes[0])
		snatCmd := "ovn-nbctl --format=csv --no-heading find nat | grep " + egressip1.name
		o.Eventually(func() bool {
			output, cmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnPod, "ovnkube-controller", snatCmd)
			e2e.Logf(output)
			return cmdErr == nil && strings.Count(output, "EgressIP:"+egressip1.name) == 5
		}, "120s", "10s").Should(o.BeTrue(), "The command check result for snat in ovndb is not expected!")
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-55632-[FdpOvnOvs] After enable egress node, egress node shouldn't generate broadcast ARP for service IPs. [Serial]", func() {
		e2e.Logf("This case is from customer bug: https://bugzilla.redhat.com/show_bug.cgi?id=2052975")
		compat_otp.By("1 Get list of nodes \n")
		nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		egessNode := nodeList.Items[0].Name

		compat_otp.By("2 Apply EgressLabel Key to one node. \n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egessNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egessNode, egressNodeLabel, "true")

		compat_otp.By("3. Check no ARP broadcast for service IPs\n")
		e2e.Logf("Trying to get physical interface on the node,%s", egessNode)
		phyInf, nicError := getSnifPhyInf(oc, egessNode)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 10 -nni %s arp", phyInf)
		outPut, _ := compat_otp.DebugNode(oc, egessNode, "bash", "-c", tcpdumpCmd)
		o.Expect(outPut).NotTo(o.ContainSubstring("172.30"), fmt.Sprintf("The output of tcpdump is %s", outPut))
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Author:huirwang-High-49161-High-43465-Service IP should be reachable when egressIP set to the namespace. [Serial]", func() {
		e2e.Logf("This case is from customer bug: https://bugzilla.redhat.com/show_bug.cgi?id=2014202")
		var (
			buildPruningBaseDir    = testdata.FixturePath("networking")
			pingPodTemplate        = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			genericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			egressIPTemplate       = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		)

		compat_otp.By(" Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Apply EgressLabel Key to one node. \n")
		egessNode := nodeList.Items[0].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egessNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egessNode, egressNodeLabel, "true")
		ipStackType := checkIPStackType(oc)
		// For dual stack cluster, it needs two nodes holding IPv4 and IPv6 seperately.
		if ipStackType == "dualstack" {
			if len(nodeList.Items) < 2 {
				g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
			}
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeList.Items[1].Name, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeList.Items[1].Name, egressNodeLabel, "true")
		}

		compat_otp.By("Get namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("create 1st hello pod in ns1")
		pod1 := pingPodResource{
			name:      "hello-pod1",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1.name, "-n", pod1.namespace).Execute()
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("Create a test service which is in front of the above pods")
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns1,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "ClusterIP",
			ipFamilyPolicy:        "",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "", //This no value parameter will be ignored
			template:              genericServiceTemplate,
		}
		if ipStackType == "dualstack" {
			svc.ipFamilyPolicy = "PreferDualStack"
		} else {
			svc.ipFamilyPolicy = "SingleStack"
		}
		svc.createServiceFromParams(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", svc.servicename, "-n", svc.namespace).Execute()

		compat_otp.By("Apply label to namespace\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6. Create an egressip object\n")
		var freeIPs []string
		switch ipStackType {
		case "ipv4single":
			freeIPs = findFreeIPs(oc, egessNode, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		case "dualstack":
			//Get one IPv6 address for second node
			freeIPv6s := findFreeIPv6s(oc, nodeList.Items[1].Name, 1)
			o.Expect(len(freeIPv6s)).Should(o.Equal(1))
			//Get one IPv4 address
			freeIPs = findFreeIPs(oc, egessNode, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPs = append(freeIPs, freeIPv6s[0])
		case "ipv6single":
			freeIPs = findFreeIPv6s(oc, egessNode, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		default:
			e2e.Logf("Get ipStackType as %s", ipStackType)
			g.Skip("Skip for not supported IP stack type!! ")
		}

		egressip1 := egressIPResource1{
			name:      "egressip-49161",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)

		//Get one non-egress node
		masterNode, errNode := compat_otp.GetFirstMasterNode(oc)
		o.Expect(errNode).NotTo(o.HaveOccurred())
		compat_otp.By("verify egressIP object was applied to egress node.")
		if ipStackType == "dualstack" {
			verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)
			// This is to cover case OCP-43465
			msg, errOutput := oc.WithoutNamespace().AsAdmin().Run("get").Args("egressip", egressip1.name, "-o=jsonpath={.status.items[*]}").Output()
			o.Expect(errOutput).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(msg, freeIPs[0]) && strings.Contains(msg, freeIPs[1])).To(o.BeTrue())
		} else {
			verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)
		}

		compat_otp.By("curl from egress node to service:port")
		CurlNode2SvcPass(oc, nodeList.Items[0].Name, ns1, svc.servicename)
		compat_otp.By("curl from non egress node to service:port")
		CurlNode2SvcPass(oc, masterNode, ns1, svc.servicename)
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Longduration-NonPreRelease-Author:huirwang-High-61344-EgressIP was migrated to correct workers after deleting machine it was assigned. [Disruptive]", func() {
		//This is from customer bug: https://bugzilla.redhat.com/show_bug.cgi?id=2079012
		platform := compat_otp.CheckPlatform(oc)
		if strings.Contains(platform, "baremetal") || strings.Contains(platform, "none") {
			g.Skip("Skip for non-supported auto scaling machineset platforms!!")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP1Template := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")

		compat_otp.By("Get an existing worker node.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Need at least 1 worker node, skip the test as the requirement was not fulfilled.")
		}
		workerNode := nodeList.Items[0].Name

		compat_otp.By("Get namespace")
		ns := oc.Namespace()
		compat_otp.By("Create a test pod on non-egress node\n")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns,
			nodename:  workerNode,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns, pod1.name)

		compat_otp.By("Apply egress label to namespace\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create a new machineset with 3 nodes")
		clusterinfra.SkipConditionally(oc)
		infrastructureName := clusterinfra.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-61344"
		ms := clusterinfra.MachineSetDescription{Name: machinesetName, Replicas: 3}
		defer clusterinfra.WaitForMachinesDisapper(oc, machinesetName)
		defer ms.DeleteMachineSet(oc)
		ms.CreateMachineSet(oc)

		clusterinfra.WaitForMachinesRunning(oc, 3, machinesetName)
		machineName := clusterinfra.GetMachineNamesFromMachineSet(oc, machinesetName)
		nodeName0 := clusterinfra.GetNodeNameFromMachine(oc, machineName[0])
		nodeName1 := clusterinfra.GetNodeNameFromMachine(oc, machineName[1])
		nodeName2 := clusterinfra.GetNodeNameFromMachine(oc, machineName[2])

		compat_otp.By("Apply EgressLabel Key to two nodes \n")
		// No defer here for  nodeName0, as this node will be deleted explicitly in the following step.
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeName0, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeName1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeName1, egressNodeLabel, "true")

		compat_otp.By("Create an egressip object\n")
		freeIPs := findFreeIPs(oc, nodeName0, 2)
		egressip1 := egressIPResource1{
			name:      "egressip-61344",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		compat_otp.By("Apply egess label to another worker node.\n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, nodeName2, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, nodeName2, egressNodeLabel, "true")

		compat_otp.By("Remove the first egress node.\n")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("machines.machine.openshift.io", machineName[0], "-n", "openshift-machine-api").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify egressIP was moved to second egress node.\n")
		o.Eventually(func() bool {
			egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
			return len(egressIPMaps) == 2 && egressIPMaps[0]["node"] != nodeName0 && egressIPMaps[1]["node"] != nodeName0
		}, "120s", "10s").Should(o.BeTrue(), "egressIP was not migrated to correct workers!!")

		compat_otp.By("Get ovn pod of the node where the test pod resides on\n")
		ovnPod := ovnkubeNodePod(oc, workerNode)

		compat_otp.By("Get lsp_addresses\n")
		lsp_address_cmd := `ovn-nbctl lsp-list transit_switch | while read guid name; do printf  "${name}"; ovn-nbctl lsp-get-addresses "${guid}"; done `
		lsp_address, err := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnPod, "northd", lsp_address_cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf(lsp_address)

		compat_otp.By("Get logical_router_policy for podIP\n")
		pod1IP := getPodIPv4(oc, ns, pod1.name)
		lrp_cmd := fmt.Sprintf(`ovn-nbctl --format=csv --data=bare --no-heading --columns=match,nexthops find logical_router_policy | grep  %s |awk -F, '{print $2}'`, pod1IP)
		lrp, err := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnPod, "northd", lrp_cmd)
		e2e.Logf("Nexthops for podIP:\n %s", lrp)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(lrp) > 0).To(o.BeTrue())

		re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
		nexthopIPs := re.FindAllString(lrp, -1)
		o.Expect(len(nexthopIPs) == 2).To(o.BeTrue())

		compat_otp.By("Verify nextHops are in lsp_addresses")
		o.Expect(strings.Contains(lsp_address, nexthopIPs[0])).To(o.BeTrue())
		o.Expect(strings.Contains(lsp_address, nexthopIPs[1])).To(o.BeTrue())

	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Critical-64293-[NETWORKCUSIM] EgressIP should not break access from a pod with EgressIP to other host networked pods on different nodes.[Disruptive]", func() {
		//This is from customer bug: https://bugzilla.redhat.com/show_bug.cgi?id=2070929
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP1Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")

		compat_otp.By("Verify there are two more worker nodes in the cluster.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		compat_otp.By("Get namespace")
		ns := oc.Namespace()

		compat_otp.By("Apply EgressLabel Key to one node. \n")
		egessNode := nodeList.Items[0].Name
		nonEgressNode := nodeList.Items[1].Name
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egessNode, egressNodeLabel)
			}
		}()
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egessNode, egressNodeLabel, "true")

		compat_otp.By("6. Create an egressip object\n")
		ipStackType := checkIPStackType(oc)
		var freeIPs []string
		if ipStackType == "ipv6single" {
			freeIPs = findFreeIPv6s(oc, egessNode, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
		} else {
			freeIPs = findFreeIPs(oc, egessNode, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
		}

		compat_otp.By("Create an egressip object\n")
		egressip1 := egressIPResource1{
			name:          "egressip-64293-1",
			template:      egressIP1Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				egressip1.deleteEgressIPObject1(oc)
			}
		}()
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Create a test pod on non-egress node\n")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns,
			nodename:  nonEgressNode,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns, pod1.name)

		compat_otp.By("patch label to namespace and pod")
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Execute()
			}
		}()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				compat_otp.LabelPod(oc, ns, pod1.name, "color-")
			}
		}()
		err = compat_otp.LabelPod(oc, ns, pod1.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Should be able to access the api service\n")
		//  The backend pod of api server are hostnetwork pod and located on master nodes.  That are different nodes from egress nodes as egress nodes are worker nodes here.
		svcIP, _ := getSvcIP(oc, "default", "kubernetes")
		curlCmd := fmt.Sprintf("curl -s %s --connect-timeout 5", net.JoinHostPort(svcIP, "443"))
		_, err = e2eoutput.RunHostCmd(ns, pod1.name, curlCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Author:huirwang-Critical-66512-pod2pod should work well when one is egress pod,another is located on egress node. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP1Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")

		compat_otp.By("Verify there are two more worker nodes in the cluster.")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		compat_otp.By("Get namespace")
		ns1 := oc.Namespace()

		compat_otp.By("Apply EgressLabel Key to one node. \n")
		egressNode := nodeList.Items[1].Name
		nonEgressNode := nodeList.Items[0].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-66512",
			template:      egressIP1Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Create a test pod on egress node\n")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  egressNode,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("Create a second namespace\n")
		oc.SetupProject()
		ns2 := oc.Namespace()

		compat_otp.By("Create a test pod on nonegress node under second namespace.\n")
		pod2 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns2,
			nodename:  nonEgressNode,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, ns2, pod2.name)

		compat_otp.By("patch label to second namespace and pod")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "org-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns2, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer compat_otp.LabelPod(oc, ns2, pod2.name, "color-")
		err = compat_otp.LabelPod(oc, ns2, pod2.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Should be able to access pod1 from pod2 and reverse works as well\n")
		CurlPod2PodPass(oc, ns1, pod1.name, ns2, pod2.name)
		CurlPod2PodPass(oc, ns2, pod2.name, ns1, pod1.name)
	})

})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP", func() {
	//Cases in this function, do not need curl ip-echo
	defer g.GinkgoRecover()

	var (
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
	)

	g.BeforeEach(func() {
		platform := compat_otp.CheckPlatform(oc)
		networkType := checkNetworkType(oc)
		e2e.Logf("\n\nThe platform is %v,  networkType is %v\n", platform, networkType)

		acceptedPlatform := strings.Contains(platform, "aws") || strings.Contains(platform, "gcp") || strings.Contains(platform, "openstack") || strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "nutanix") || strings.Contains(platform, "powervs")
		if !acceptedPlatform || !strings.Contains(networkType, "ovn") {
			g.Skip("Test cases should be run on AWS/GCP/Azure/Openstack/Vsphere/Baremetal/Nutanix/Powervs cluster with ovn network plugin, skip for other platforms or other non-OVN network plugin")
		}

		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv6single" {
			// Not able to run on IPv6 single cluster for now due to cluster disconnect limiation.
			g.Skip("Skip IPv6 Single cluster.")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-ConnectedOnly-High-47163-High-47026-Deleting EgressIP object and recreating it works,EgressIP was removed after delete egressIP object. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		if checkProxy(oc) || checkDisconnect(oc) {
			g.Skip("This is proxy/disconnect cluster, skip the test.")
		}

		if isAzurePrivate(oc) {
			g.Skip("Skip this test on azure private cluster.")
		}
		compat_otp.By("Get the temporary namespace")
		ns := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns)

		compat_otp.By("Get schedulable worker nodes")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")

		compat_otp.By("Create tcpdump sniffer Daemonset.")
		primaryInf, infErr := getSnifPhyInf(oc, egressNode)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost := nslookDomainName("ifconfig.me")
		defer deleteTcpdumpDS(oc, "tcpdump-47163", ns)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns, "tcpdump-47163", "tcpdump", "true", dstHost, primaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("Apply EgressLabel Key for this test on one node.")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("Apply label to namespace")
		_, err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", oc.Namespace(), "name=test").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", oc.Namespace(), "name-").Output()

		compat_otp.By("Create an egressip object")
		freeIPs := findFreeIPs(oc, egressNode, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-47163",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1) == 1).Should(o.BeTrue(), fmt.Sprintf("The egressIP was not assigned correctly!"))

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		defer pod1.deletePingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Check source IP is EgressIP")
		egressErr := verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, egressIPMaps1[0]["egressIP"], dstHost, ns, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())

		compat_otp.By("Deleting egressip object")
		egressip1.deleteEgressIPObject1(oc)
		waitCloudPrivateIPconfigUpdate(oc, egressIPMaps1[0]["egressIP"], false)
		egressipErr := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 100*time.Second, false, func(cxt context.Context) (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, url)
			if checkMatchedIPs(oc, ns, tcpdumpDS.name, randomStr, egressIPMaps1[0]["egressIP"], false) != nil {
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to clear egressip:%s", egressipErr))

		compat_otp.By("Recreating egressip object")
		egressip1.createEgressIPObject1(oc)
		egressIPMaps2 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps2) == 1).Should(o.BeTrue(), "The egressIP was not assigned correctly!")

		compat_otp.By("Check source IP is EgressIP")
		err = wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
			egressErr := verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, egressIPMaps2[0]["egressIP"], dstHost, ns, tcpdumpDS.name, true)

			if egressErr != nil {
				e2e.Logf("When verifying egressIP, getting err:%v, and try next round", egressErr)
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to verify egressIP %s after the egressIP object is re-created", egressIPMaps2[0]["egressIP"]))

		compat_otp.By("Deleting EgressIP object and recreating it works!!! ")

	})

	g.It("NonHyperShiftHOST-Longduration-NonPreRelease-ConnectedOnly-Author:jechen-High-54647-No stale or duplicated SNAT on gateway router after egressIP failover to new egress node. [Disruptive]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		statefulSetPodTemplate := filepath.Join(buildPruningBaseDir, "statefulset-hello.yaml")
		completedPodTemplate := filepath.Join(buildPruningBaseDir, "countdown-job-completed-pod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1. Get list of nodes, get two worker nodes that have same subnet, use them as egress nodes\n")
		var egressNode1, egressNode2 string
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}
		egressNode1 = egressNodes[0]
		egressNode2 = egressNodes[1]

		compat_otp.By("2. Apply EgressLabel Key to two egress nodes.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")

		compat_otp.By("3. Create an egressip object")
		freeIPs := findFreeIPs(oc, egressNode1, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip1 := egressIPResource1{
			name:          "egressip-54647",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "purple",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		// The egress node that currently hosts the egressIP will be the node to be rebooted to create egressIP failover
		nodeToBeRebooted := egressIPMaps1[0]["node"]
		e2e.Logf("egressNode to be rebooted is:%v", nodeToBeRebooted)

		var hostLeft []string
		for i, v := range egressNodes {
			if v == nodeToBeRebooted {
				hostLeft = append(egressNodes[:i], egressNodes[i+1:]...)
				break
			}
		}
		e2e.Logf("\n Get the egressNode that did not host egressIP address previously: %v\n", hostLeft)

		compat_otp.By("4. create a namespace, apply label to the namespace")
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		nsLabelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(nsLabelErr).NotTo(o.HaveOccurred())

		compat_otp.By("5.1 Create a statefulSet Hello pod in the namespace, apply pod label to it. ")
		createResourceFromFile(oc, ns1, statefulSetPodTemplate)
		podErr := waitForPodWithLabelReady(oc, ns1, "app=hello")
		compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
		statefulSetPodName := getPodName(oc, ns1, "app=hello")

		defer compat_otp.LabelPod(oc, ns1, statefulSetPodName[0], "color-")
		podLabelErr := compat_otp.LabelPod(oc, ns1, statefulSetPodName[0], "color=purple")
		compat_otp.AssertWaitPollNoErr(podLabelErr, "Was not able to apply pod label")

		compat_otp.By("5.2 Create a completed pod in the namespace, apply pod label to it. ")
		createResourceFromFile(oc, ns1, completedPodTemplate)
		completedPodName := getPodName(oc, ns1, "job-name=countdown")
		waitPodReady(oc, ns1, completedPodName[0])

		defer compat_otp.LabelPod(oc, ns1, completedPodName[0], "color-")
		podLabelErr = compat_otp.LabelPod(oc, ns1, completedPodName[0], "color=purple")
		compat_otp.AssertWaitPollNoErr(podLabelErr, "Was not able to apply pod label")

		ipStackType := checkIPStackType(oc)
		var helloPodIP, completedPodIP string
		if ipStackType == "dualstack" {
			_, helloPodIP = getPodIP(oc, ns1, statefulSetPodName[0])
			_, completedPodIP = getPodIP(oc, ns1, completedPodName[0])
		} else {
			helloPodIP, _ = getPodIP(oc, ns1, statefulSetPodName[0])
			completedPodIP, _ = getPodIP(oc, ns1, completedPodName[0])
		}
		e2e.Logf("Pod's IP for the statefulSet Hello Pod is:%v", helloPodIP)
		e2e.Logf("Pod's IP for the completed countdown pod is:%v", completedPodIP)

		compat_otp.By("6. Check SNATs of stateful pod and completed pod on the egressNode before rebooting it.\n")
		snatIP, snatErr := getSNATofEgressIP(oc, nodeToBeRebooted, freeIPs[0])
		e2e.Logf("snatIP:%v", snatIP)
		o.Expect(snatErr).NotTo(o.HaveOccurred())
		o.Expect(len(snatIP)).Should(o.Equal(1))
		e2e.Logf("the SNAT IP for the egressIP is:%v", snatIP[0])
		o.Expect(snatIP[0]).Should(o.Equal(helloPodIP))
		o.Expect(snatIP[0]).ShouldNot(o.Equal(completedPodIP))

		compat_otp.By("7. Reboot egress node.\n")
		defer checkNodeStatus(oc, nodeToBeRebooted, "Ready")
		rebootNode(oc, nodeToBeRebooted)
		checkNodeStatus(oc, nodeToBeRebooted, "NotReady")

		compat_otp.By("8. As soon as the rebooted node is in NotReady state, delete the statefulSet pod to force it be recreated while the node is rebooting.\n")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", statefulSetPodName[0], "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		podErr = waitForPodWithLabelReady(oc, ns1, "app=hello")
		compat_otp.AssertWaitPollNoErr(podErr, "this pod with label app=hello not ready")

		// Re-apply label for pod as pod is re-created with same pod name
		defer compat_otp.LabelPod(oc, ns1, statefulSetPodName[0], "color-")
		podLabelErr = compat_otp.LabelPod(oc, ns1, statefulSetPodName[0], "color=purple")
		compat_otp.AssertWaitPollNoErr(podLabelErr, "Was not able to apply pod label")

		// get completed pod name again, relabel it, get its IP address
		newCompletedPodName := getPodName(oc, ns1, "job-name=countdown")
		waitPodReady(oc, ns1, newCompletedPodName[0])
		defer compat_otp.LabelPod(oc, ns1, newCompletedPodName[0], "color-")
		podLabelErr = compat_otp.LabelPod(oc, ns1, newCompletedPodName[0], "color=purple")
		compat_otp.AssertWaitPollNoErr(podLabelErr, "Was not able to apply pod label")

		var newCompletedPodIP, newHelloPodIP string
		if ipStackType == "dualstack" {
			_, newCompletedPodIP = getPodIP(oc, ns1, newCompletedPodName[0])
			_, newHelloPodIP = getPodIP(oc, ns1, statefulSetPodName[0])
		} else {
			newCompletedPodIP, _ = getPodIP(oc, ns1, newCompletedPodName[0])
			newHelloPodIP, _ = getPodIP(oc, ns1, statefulSetPodName[0])
		}
		e2e.Logf("Pod's IP for the new completed countdown pod is:%v", newCompletedPodIP)
		e2e.Logf("Pod's IP for the newly created Hello Pod is:%v", newHelloPodIP)

		compat_otp.By("9. Check egress node in egress object again, egressIP should fail to the second egressNode.\n")
		egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
		newEgressIPHostNode := egressIPMaps1[0]["node"]
		e2e.Logf("new egressNode that hosts the egressIP is:%v", newEgressIPHostNode)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.Equal(hostLeft[0]))

		compat_otp.By("10. Check SNAT on the second egressNode\n")
		snatIP, snatErr = getSNATofEgressIP(oc, newEgressIPHostNode, freeIPs[0])
		o.Expect(snatErr).NotTo(o.HaveOccurred())
		o.Expect(len(snatIP)).Should(o.Equal(1))

		e2e.Logf("After egressIP failover, the SNAT IP for the egressIP on second router is:%v", snatIP)
		compat_otp.By("10.1 There should be the IP of the newly created statefulState hello pod, not the IP of old hello pod.\n")
		o.Expect(snatIP[0]).Should(o.Equal(newHelloPodIP))
		o.Expect(snatIP[0]).ShouldNot(o.Equal(helloPodIP))

		compat_otp.By("10.2 There should be no SNAT for old or new completed pod's IP.\n")
		o.Expect(snatIP[0]).ShouldNot(o.Equal(newEgressIPHostNode)) //there should be no SNAT for completed pod's old or new IP address
		o.Expect(snatIP[0]).ShouldNot(o.Equal(completedPodIP))      //there should be no SNAT for completed pod's old or new IP address

		// Make sure the rebooted node is back to Ready state
		checkNodeStatus(oc, egressIPMaps1[0]["node"], "Ready")

		compat_otp.By("11. Check SNAT on all other unassigned nodes, it should be no stale NAT on all other unassigned nodes.\n")
		var unassignedNodes []string
		for i := 0; i < len(nodeList.Items); i++ {
			if nodeList.Items[i].Name != newEgressIPHostNode {
				unassignedNodes = append(unassignedNodes, nodeList.Items[i].Name)
			}
		}
		e2e.Logf("unassigned nodes are:%v", unassignedNodes)

		for i := 0; i < len(unassignedNodes); i++ {
			snatIP, _ = getSNATofEgressIP(oc, unassignedNodes[i], freeIPs[0])
			o.Expect(len(snatIP)).Should(o.Equal(0))
			e2e.Logf("As expected, there is not stale NAT on the unassigned node:%v", unassignedNodes[i])
		}
	})

	g.It("NonHyperShiftHOST-Longduration-NonPreRelease-ConnectedOnly-Author:jechen-High-67091-Egressip status is synced with cloudprivateipconfig and egressip is assigned correctly after OVNK restart. [Disruptive]", func() {

		// This is for OCPBUGS-12747
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		// cloudprivateipconfig is a resource only available on cloud platforms like AWS, GCP and Azure that egressIP is supported, skip other platforms
		clusterinfra.SkipTestIfSupportedPlatformNotMatched(oc, clusterinfra.AWS, clusterinfra.GCP, clusterinfra.Azure)

		compat_otp.By("1. Get list of nodes, get two worker nodes that have same subnet, use them as egress nodes\n")
		var egressNode1, egressNode2 string
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}
		egressNode1 = egressNodes[0]
		egressNode2 = egressNodes[1]

		compat_otp.By("2. Apply EgressLabel Key to two egress nodes.\n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")

		compat_otp.By("3. Get two unused IP addresses from the egress node.\n")
		freeIPs := findFreeIPs(oc, egressNode1, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))

		compat_otp.By("4. Create an egressip object, verify egressip is assigned to an egress node.\n")
		egressip1 := egressIPResource1{
			name:          "egressip-67091",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "purple",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("5. Verify egressIP is in cloudprivateipconfig.\n")
		waitCloudPrivateIPconfigUpdate(oc, freeIPs[0], true)

		compat_otp.By("6. Restart OVNK, before OVNK is back up, delete cloudprivateipconfig and replace egressip in egressip object to another valid unused IP address\n")
		//Restart OVNK by deleting all ovnkube-node pods
		defer waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		delPodErr := oc.AsAdmin().Run("delete").Args("pod", "-l", "app=ovnkube-node", "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())

		delCloudPrivateIPConfigErr := oc.AsAdmin().Run("delete").Args("cloudprivateipconfig", egressIPMaps1[0]["egressIP"]).Execute()
		o.Expect(delCloudPrivateIPConfigErr).NotTo(o.HaveOccurred())

		// Update the egressip address in the egressip object with another unused ip address
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/"+egressip1.name, "-p", "{\"spec\":{\"egressIPs\":[\""+freeIPs[1]+"\"]}}", "--type=merge").Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		compat_otp.By("7. Wait for ovnkube-node back up.\n")
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		compat_otp.By("8. Verify cloudprivateipconfig is updated to new egressip address.\n")
		waitCloudPrivateIPconfigUpdate(oc, freeIPs[1], true)

		compat_otp.By("9. Verify egressIP object is updated with new egressIP address, and egressIP is assigned to an egressNode.\n")
		o.Eventually(func() bool {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			return len(egressIPMaps1) == 1 && egressIPMaps1[0]["egressIP"] == freeIPs[1]
		}, "300s", "10s").Should(o.BeTrue(), "egressIP was not updated to new ip address, or egressip was not assigned to an egressNode!!")
		currenAssignedEgressNode := egressIPMaps1[0]["node"]

		compat_otp.By("10. Unlabel current assigned egress node, verify that egressIP fails over to the other egressNode.\n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, currenAssignedEgressNode, egressNodeLabel)
		var newAssignedEgressNode string
		if currenAssignedEgressNode == egressNode1 {
			newAssignedEgressNode = egressNode2
		} else if currenAssignedEgressNode == egressNode2 {
			newAssignedEgressNode = egressNode1
		}
		o.Eventually(func() bool {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			return len(egressIPMaps1) == 1 && egressIPMaps1[0]["node"] == newAssignedEgressNode
		}, "300s", "10s").Should(o.BeTrue(), "egressIP was not migrated to second egress node after unlabel first egress node!!")
	})

	// author: huirwang@redhat.com
	g.It("ROSA-ConnectedOnly-Author:huirwang-High-68965-EgressIP works for podSelector and namespaceSelector.", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		egressLabel := "k8s.ovn.org/egress-assignable="

		workers, err := compat_otp.GetSchedulableLinuxWorkerNodes(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workers) < 1 {
			g.Skip("Worker nodes number is less than 1, skip the test!")
		}

		egressWorkers, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", egressLabel, "-o", "jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		nodes := strings.Split(egressWorkers, " ")
		var egressNodes []string
		for _, node := range nodes {
			if node != "" {
				egressNodes = append(egressNodes, node)
			}
		}

		if len(egressNodes) < 1 {
			e2e.Logf("This case is for ROSA which has egress label added to machinepool in Day 0 Setup.")
			g.Skip("Skip the tests as the environment doesn't fulfill the requirement.")
		}

		compat_otp.By("Get the temporary namespace")
		ns := oc.Namespace()

		compat_otp.By("Create an egressip object for namespaceSelector.")
		freeIPs := findFreeIPs(oc, egressNodes[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-68965-ns",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/"+egressip1.name, "-p", "{\"spec\":{\"egressIPs\":[\""+freeIPs[0]+"\"]}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)

		compat_otp.By("Create tcpdump sniffer Daemonset.")
		primaryInf, infErr := getSnifPhyInf(oc, egressNodes[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost := nslookDomainName("ifconfig.me")
		defer deleteTcpdumpDS(oc, "tcpdump-68965", ns)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns, "tcpdump-47163", "k8s.ovn.org/egress-assignable", "", dstHost, primaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("Apply label to namespace")
		_, err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", oc.Namespace(), "name=test").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", oc.Namespace(), "name-").Output()

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		defer pod1.deletePingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Check source IP is EgressIP")
		egressErr := verifyEgressIPinTCPDump(oc, pod1.name, pod1.namespace, egressIPMaps[0]["egressIP"], dstHost, ns, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())

		compat_otp.By("Setup second egressIP object.")
		egressip1.deleteEgressIPObject1(oc)
		egressip2 := egressIPResource1{
			name:          "egressip-68965-pod",
			template:      egressIP2Template,
			egressIP1:     freeIPs[1],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "purple",
		}
		egressip2.createEgressIPObject2(oc)
		defer egressip2.deleteEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip2.name, 1)

		compat_otp.By("Create second pod ")
		pod2 := pingPodResource{
			name:      "hello-pod-2",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod2.createPingPod(oc)
		defer pod2.deletePingPod(oc)
		waitPodReady(oc, pod2.namespace, pod2.name)

		compat_otp.By("Apply label to namespace")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Output()
		_, err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Apply label to pod")
		err = compat_otp.LabelPod(oc, ns, pod2.name, "color=purple")
		defer compat_otp.LabelPod(oc, ns, pod2.name, "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check source IP is EgressIP")
		egressErr = verifyEgressIPinTCPDump(oc, pod2.name, pod2.namespace, freeIPs[1], dstHost, ns, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-Medium-72336-Intra cluster traffic does not take egressIP path to reach ingressVIP when egressIP and ingressVIP located on same node. [Serial]", func() {

		// This is for customer bug: https://issues.redhat.com/browse/OCPBUGS-29851
		// IngressVIP is only for Baremetal or vSphere platform
		// Since for a dualstack egressIP object, its v6 egressIP and v6 egressIP would be assigned to two separate nodes by design, therefore
		// it is not possible to meet the test condition that the two egress nodes for a dualstack egressIP object co-locate with ingressVIP node at same time
		// Dualstack scenario will be skipped for this reason stated in last two lines
		// IP4v or IPv6 is tested in its singlestack mode.

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		platform := compat_otp.CheckPlatform(oc)
		ingressVIPs := GetVIPOnCluster(oc, platform, "ingressVIP")
		ipStackType := checkIPStackType(oc)
		e2e.Logf("\n\nThe platform is %v,   ingressVIP: %s\n\n", platform, ingressVIPs)
		acceptedPlatform := strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "none")
		if !acceptedPlatform || len(ingressVIPs) == 0 || ipStackType == "dualstack" {
			g.Skip("Test case should be run Vsphere/Baremetalcluster with ovn network plugin, skip for other platforms !!")
		}

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Does not have enough nodes for the test, skip the case")
		}

		compat_otp.By("1. Find the node that has ingressVIP address(es), get another node that is not egressIP/ingressVIP node.\n")
		ingressVIPNode := FindVIPNode(oc, ingressVIPs[0])
		o.Expect(ingressVIPNode).NotTo(o.Equal(""))

		_, ingressVIPNodeIP := getNodeIP(oc, ingressVIPNode)
		e2e.Logf("\nCluster's IPStack Type: %s, IngressVIP is on node %s, ingressVIP Node's IP address is: %v\n", ipStackType, ingressVIPNode, ingressVIPNodeIP)

		//  Get another node that is not egressIP/ingressVIP node
		var nonEgressNode string
		for _, node := range nodeList.Items {
			if node.Name != ingressVIPNode {
				nonEgressNode = node.Name
				break
			}
		}
		o.Expect(nonEgressNode).NotTo(o.Equal(""))
		_, nonEgressNodeIP := getNodeIP(oc, nonEgressNode)
		e2e.Logf("\n Cluster's IPStack Type: %s, use %s as nonEgressNode, its nodeIP address is: %v\n", ipStackType, nonEgressNode, nonEgressNodeIP)

		compat_otp.By("2 Apply EgressLabel Key to ingressVIP node to make ingressVIP and egressIP co-exist on the same node. \n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, ingressVIPNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, ingressVIPNode, egressNodeLabel, "true")

		compat_otp.By("3. Create an egressip object")
		var freeIPs []string
		var tcpdumpCmd, pingCurlCmds string
		if ipStackType == "ipv4single" {
			freeIPs = findFreeIPs(oc, ingressVIPNode, 1)
			tcpdumpCmd = "timeout 90s tcpdump -n -i any -nneep \"(src port 443 and  dst port 31459) or (src port 31459 and dst port 443)\""
			pingCurlCmds = fmt.Sprintf(" curl -4 --local-port 31459 %s:443 --connect-timeout  5", ingressVIPs[0])
		}
		if ipStackType == "ipv6single" {
			freeIPs = findFreeIPv6s(oc, ingressVIPNode, 1)
			tcpdumpCmd = "timeout 90s tcpdump -n -i any -nneep \"ip6 and (src port 443 and  dst port 31459) or (src port 31459 and dst port 443)\""
			pingCurlCmds = fmt.Sprintf(" curl -6 --local-port 31459 [%s]:443 --connect-timeout  5", ingressVIPs[0])
		}
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := egressIPResource1{
			name:          "egressip-72336",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip.createEgressIPObject2(oc)
		defer egressip.deleteEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip.name, 1)

		compat_otp.By("4.1. Obtain the namespace, create two test pods on egressIP/ingressVIP node, one on egressIP/ingressVIP node, the other one a non-egressIP Node\n")
		ns1 := oc.Namespace()

		// Pod1 is a remote pod because it is not on egressIP/ingressVIP node
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nonEgressNode,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		// Pods is a local pod because it is on egressIP/ingressVIP node
		pod2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns1,
			nodename:  ingressVIPNode,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, pod2.namespace, pod2.name)

		compat_otp.By("4.2 Apply label to test pods and namespace to match the label in egressIP object.\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer compat_otp.LabelPod(oc, ns1, pod2.name, "color-")
		err = compat_otp.LabelPod(oc, ns1, pod2.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4.3 Enable tcpdump on egressIP/ingressVIP node.\n")
		cmdTcpdump, tcpdumpOutput, _, err := oc.WithoutNamespace().AsAdmin().Run("debug").Args("-n", "default", "node/"+ingressVIPNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())
		// wait a little for tcpdump command to start
		time.Sleep(5 * time.Second)

		compat_otp.By("4.4 curl ingressVIP from test pod1 in ns1 namespace \n")
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, pingCurlCmds)
		o.Expect(fmt.Sprint(err)).To(o.ContainSubstring("Empty reply from server"))

		compat_otp.By("4.5 Check tcpdump, ingressVIP node's IP address should be captured instead of egressIP address \n")
		cmdTcpdump.Wait()
		e2e.Logf("tcpdumpOutput captured on EIP/VIP node: \n%s\n", tcpdumpOutput.String())

		// Remote pod uses its nodeIP to reach ingressVIP
		o.Expect(strings.Contains(tcpdumpOutput.String(), nonEgressNodeIP)).Should(o.BeTrue())

		// Does not take EIP path, so there should be no egressIP address in the tcpdump
		o.Expect(strings.Contains(tcpdumpOutput.String(), egressip.egressIP1)).Should(o.BeFalse())

		pod2IP, _ := getPodIP(oc, ns1, pod2.name)

		compat_otp.By("5.1 Enable tcpdump on egressIP/ingressVIP node again.\n")
		cmdTcpdump2, tcpdumpOutput2, _, err := oc.WithoutNamespace().AsAdmin().Run("debug").Args("-n", "default", "node/"+ingressVIPNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump2.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())
		time.Sleep(5 * time.Second)

		compat_otp.By("5.2 curl ingressVIP from test pod1 in ns1 namespace \n")
		_, err = e2eoutput.RunHostCmd(pod2.namespace, pod2.name, pingCurlCmds)
		o.Expect(fmt.Sprint(err)).To(o.ContainSubstring("Empty reply from server"))

		compat_otp.By("5.3 Check tcpdump, pod2's IP address should be captured instead of egressIP address \n")
		cmdTcpdump2.Wait()
		e2e.Logf("tcpdumpOutput captured on EIP/VIP node: \n%s\n", tcpdumpOutput2.String())

		// local pod uses its podIP to reach ingressVIP because there is no need to go through nodeIP
		o.Expect(strings.Contains(tcpdumpOutput2.String(), pod2IP)).Should(o.BeTrue())
		o.Expect(strings.Contains(tcpdumpOutput2.String(), egressip.egressIP1)).Should(o.BeFalse())
	})
})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP on hypershift", func() {
	defer g.GinkgoRecover()

	var (
		oc                                                          = compat_otp.NewCLIForKubeOpenShift("networking-" + getRandomString())
		egressNodeLabel                                             = "k8s.ovn.org/egress-assignable"
		hostedClusterName, hostedClusterKubeconfig, hostedclusterNS string
	)

	g.BeforeEach(func() {
		// Check the network plugin type
		networkType := compat_otp.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip case on cluster that has non-OVN network plugin!!")
		}
		hostedClusterName, hostedClusterKubeconfig, hostedclusterNS = compat_otp.ValidHypershiftAndGetGuestKubeConf(oc)
		oc.SetGuestKubeconf(hostedClusterKubeconfig)

	})
	g.It("ROSA-OSD_CCS-HyperShiftMGMT-NonPreRelease-Longduration-ConnectedOnly-Author:jechen-High-54741-EgressIP health check through monitoring port over GRPC on hypershift cluster. [Disruptive]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1. Check ovnkube-config configmap in hypershift mgmt NS if egressip-node-healthcheck-port=9107 is in it \n")

		configmapName := "ovnkube-config"
		envString := " egressip-node-healthcheck-port=9107"
		hyperShiftMgmtNS := hostedclusterNS + "-" + hostedClusterName
		cmCheckErr := checkEnvInConfigMap(oc, hyperShiftMgmtNS, configmapName, envString)
		o.Expect(cmCheckErr).NotTo(o.HaveOccurred())

		compat_otp.By("2. Check if ovnkube-control-plane is ready on hypershift cluster \n")
		readyErr := waitForPodWithLabelReady(oc, hyperShiftMgmtNS, "app=ovnkube-control-plane")
		compat_otp.AssertWaitPollNoErr(readyErr, "ovnkube-control-plane pods are not ready on the hypershift cluster")

		leaderOVNKCtrlPlanePodName := getOVNKCtrlPlanePodOnHostedCluster(oc, "openshift-ovn-kubernetes", "ovn-kubernetes-master", hyperShiftMgmtNS)
		e2e.Logf("\n\n leaderOVNKCtrlPlanePodName for the hosted cluster is: %s\n\n", leaderOVNKCtrlPlanePodName)

		readyErr = waitForPodWithLabelReadyOnHostedCluster(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		compat_otp.AssertWaitPollNoErr(readyErr, "ovnkube-node pods are not ready on hosted cluster")
		ovnkubeNodePods := getPodNameOnHostedCluster(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		compat_otp.By("3. Get list of scheduleable nodes on hosted cluster, pick one as egressNode, apply EgressLabel Key to it \n")
		scheduleableNodes, err := getReadySchedulableNodesOnHostedCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		// Pick first scheduleable node as egressNode
		egressNode := scheduleableNodes[0]

		defer compat_otp.DeleteLabelFromNode(oc.AsAdmin().AsGuestKubeconf(), egressNode, egressNodeLabel)
		labelValue := ""
		compat_otp.AddLabelToNode(oc.AsAdmin().AsGuestKubeconf(), egressNode, egressNodeLabel, labelValue)

		compat_otp.By("4. Check leader ovnkube-control-plane pod's log that health check connection has been made to the egressNode on port 9107 \n")
		// get the OVNK8s managementIP for the egressNode on hosted cluster
		nodeOVNK8sMgmtIP := getOVNK8sNodeMgmtIPv4OnHostedCluster(oc, egressNode)
		e2e.Logf("\n\n OVNK8s managementIP of the egressNode on hosted cluster is: %s\n\n", nodeOVNK8sMgmtIP)

		expectedConnectString := "Connected to " + egressNode + " (" + nodeOVNK8sMgmtIP + ":9107)"
		podLogs, LogErr := checkLogMessageInPod(oc, hyperShiftMgmtNS, "ovnkube-control-plane", leaderOVNKCtrlPlanePodName, "'"+expectedConnectString+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedConnectString))

		compat_otp.By("5. Check each ovnkube-node pod's log on hosted cluster that health check server is started on it \n")
		expectedSeverStartString := "Starting Egress IP Health Server on "
		for _, ovnkubeNodePod := range ovnkubeNodePods {
			podLogs, LogErr := checkLogMessageInPodOnHostedCluster(oc, "openshift-ovn-kubernetes", "ovnkube-controller", ovnkubeNodePod, "'egress ip'")
			o.Expect(LogErr).NotTo(o.HaveOccurred())
			o.Expect(podLogs).To(o.ContainSubstring(expectedSeverStartString))
		}

		compat_otp.By("6. Create an egressip object, verify egressIP is assigned to the egressNode")
		freeIPs := findFreeIPs(oc.AsAdmin().AsGuestKubeconf(), egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := egressIPResource1{
			name:          "egressip-54741",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "red",
		}
		defer egressip1.deleteEgressIPObject1(oc.AsAdmin().AsGuestKubeconf())
		egressip1.createEgressIPObject2(oc.AsAdmin().AsGuestKubeconf())
		egressIPMaps1 := getAssignedEIPInEIPObject(oc.AsAdmin().AsGuestKubeconf(), egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("7. Add iptables on to block port 9107 on egressNode, verify from log of ovnkube-control-plane pod that the health check connection is closed.\n")
		delCmdOptions := []string{"iptables", "-D", "INPUT", "-p", "tcp", "--destination-port", "9107", "-j", "DROP"}
		addCmdOptions := []string{"iptables", "-I", "INPUT", "1", "-p", "tcp", "--destination-port", "9107", "-j", "DROP"}
		defer execCmdOnDebugNodeOfHostedCluster(oc, egressNode, delCmdOptions)
		debugNodeErr := execCmdOnDebugNodeOfHostedCluster(oc, egressNode, addCmdOptions)
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())

		expectedCloseConnectString := "Closing connection with " + egressNode + " (" + nodeOVNK8sMgmtIP + ":9107)"
		podLogs, LogErr = checkLogMessageInPod(oc, hyperShiftMgmtNS, "ovnkube-control-plane", leaderOVNKCtrlPlanePodName, "'"+expectedCloseConnectString+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedCloseConnectString))
		expectedCouldNotConnectString := "Could not connect to " + egressNode + " (" + nodeOVNK8sMgmtIP + ":9107)"
		podLogs, LogErr = checkLogMessageInPod(oc, hyperShiftMgmtNS, "ovnkube-control-plane", leaderOVNKCtrlPlanePodName, "'"+expectedCouldNotConnectString+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedCouldNotConnectString))

		if compat_otp.IsKubernetesClusterFlag != "yes" {
			compat_otp.By("8. Verify egressIP is not in cloudprivateipconfig after blocking iptable rule on port 9170 is added.\n")
			waitCloudPrivateIPconfigUpdate(oc, freeIPs[0], false)
		}

		compat_otp.By("9. Delete the iptables rule, verify from log of lead ovnkube-control-plane pod that the health check connection is re-established.\n")
		debugNodeErr = execCmdOnDebugNodeOfHostedCluster(oc, egressNode, delCmdOptions)
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())

		podLogs, LogErr = checkLogMessageInPod(oc, hyperShiftMgmtNS, "ovnkube-control-plane", leaderOVNKCtrlPlanePodName, "'"+expectedConnectString+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedConnectString))

		compat_otp.By("10. Verify egressIP is re-applied after blocking iptable rule on port 9170 is deleted.\n")
		egressIPMaps := getAssignedEIPInEIPObject(oc.AsAdmin().AsGuestKubeconf(), egressip1.name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		compat_otp.By("11. Unlabel the egressNoe egressip-assignable, verify from log of lead ovnkube-control-plane pod that the health check connection is closed.\n")
		compat_otp.DeleteLabelFromNode(oc.AsAdmin().AsGuestKubeconf(), egressNode, egressNodeLabel)

		podLogs, LogErr = checkLogMessageInPod(oc, hyperShiftMgmtNS, "ovnkube-control-plane", leaderOVNKCtrlPlanePodName, "'"+expectedCloseConnectString+"'"+"| tail -1")
		o.Expect(LogErr).NotTo(o.HaveOccurred())
		o.Expect(podLogs).To(o.ContainSubstring(expectedCloseConnectString))
	})

})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP IPv6", func() {
	defer g.GinkgoRecover()

	var (
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		rduBastionHost  = "2620:52:0:800:3673:5aff:fe99:92f0"
	)

	g.BeforeEach(func() {
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com") || strings.Contains(msg, "offload.openshift-qe.sdn.com")) {
			g.Skip("This case will only run on rdu1 or rdu2 dual stack cluster. , skip for other envrionment!!!")
		}
		if strings.Contains(msg, "offload.openshift-qe.sdn.com") {
			rduBastionHost = "2620:52:0:800:3673:5aff:fe98:d2d0"
		}
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Author:huirwang-Medium-43466-EgressIP works well with ipv6 address. [Serial]", func() {
		ipStackType := checkIPStackType(oc)
		//We already have many egressIP cases cover ipv4 addresses on both ipv4 and dualstack clusters,so this case focuses on dualstack cluster for ipv6 addresses.
		if ipStackType != "dualstack" {
			g.Skip("Current env is not dualsatck cluster, skip this test!!!")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("create new namespace")
		ns := oc.Namespace()

		compat_otp.By("Label EgressIP node")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode1 := nodeList.Items[0].Name

		compat_otp.By("Apply EgressLabel Key for this test on one node.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")

		compat_otp.By("Apply label to namespace")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org-").Output()
		_, err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "org=qe").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create an egressip object")
		freeIPv6s := findFreeIPv6s(oc, egressNode1, 1)
		o.Expect(len(freeIPv6s)).Should(o.Equal(1))

		egressip1 := egressIPResource1{
			name:          "egressip-43466",
			template:      egressIP2Template,
			egressIP1:     freeIPv6s[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(1))

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: oc.Namespace(),
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Apply label to pod")
		err = compat_otp.LabelPod(oc, ns, pod1.name, "color=pink")
		defer compat_otp.LabelPod(oc, ns, pod1.name, "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Start tcpdump on node1")
		e2e.Logf("Trying to get physical interface on the node,%s", egressNode1)
		phyInf, nicError := getSnifPhyInf(oc, egressNode1)
		o.Expect(nicError).NotTo(o.HaveOccurred())
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s icmp6 and dst %s", phyInf, rduBastionHost)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+egressNode1, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check source IP is EgressIP")
		pingCmd := fmt.Sprintf("ping -c4 %s", rduBastionHost)
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmdErr := cmdTcpdump.Wait()
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		o.Expect(cmdOutput.String()).To(o.ContainSubstring(freeIPv6s[0]))

	})
})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP Multi-NIC", func() {
	defer g.GinkgoRecover()

	var (
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		dstHost         = "172.22.0.1"
		dstCIDR         = "172.22.0.0/24"
		secondaryInf    = "enp1s0"
		workers         []string
	)

	g.BeforeEach(func() {
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com") || strings.Contains(msg, "offload.openshift-qe.sdn.com")) {
			g.Skip("This case will only run on rdu1/rdu2 cluster , skip for other envrionment!!!")
		}

		//skip sriov nodes
		workers = excludeSriovNodes(oc)
		compat_otp.By("Enable IP forwarding 'Global' on all nodes\n")
		enableIPForwarding(oc, true)
	})

	g.AfterEach(func() {
		compat_otp.By("Restore IP forwarding default configuration on all nodes\n")
		enableIPForwarding(oc, false)
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-High-66294-[Multi-NIC] EgressIP can be load-balanced on secondary NICs. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("Label EgressIP node\n")
		if len(workers) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("Apply EgressLabel Key for this test on two nodes.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel)

		compat_otp.By("Apply label to namespace\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create an egressip object\n")
		freeIPs := findFreeIPsForCIDRs(oc, workers[0], dstCIDR, 2)
		egressip1 := egressIPResource1{
			name:      "egressip-66294",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		//Replce matchLabel with matchExpressions
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-66294", "-p", "{\"spec\":{\"namespaceSelector\":{\"matchExpressions\":[{\"key\": \"name\", \"operator\": \"In\", \"values\": [\"test\"]}],\"matchLabels\":null}}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], "tcpdump", "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], "tcpdump", "true")

		defer deleteTcpdumpDS(oc, "tcpdump-66294", ns1)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-66294", "tcpdump", "true", dstHost, secondaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("Check source IP is randomly one of egress ips")
		egressipErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[0], true) != nil || checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[1], true) != nil || err != nil {
				e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump", freeIPs[0], freeIPs[1]))
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-High-66336-[Multi-NIC] egressIP still works after egress node reboot for secondary nic assignment.[Disruptive]", func() {
		compat_otp.By("Get worker nodes\n")
		if len(workers) < 1 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By(" Label EgressIP node\n")
		egressNode := workers[0]
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("Create first egressip object\n")
		freeIPs := findFreeIPsForCIDRs(oc, egressNode, dstCIDR, 1)
		egressip1 := egressIPResource1{
			name:          "egressip-66336",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("Apply a label to test namespace.\n")
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create pods in test namespace. \n")
		createResourceFromFile(oc, ns1, testPodFile)
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		compat_otp.By("Apply label to one pod in test namespace\n")
		testPodName := getPodName(oc, ns1, "name=test-pods")
		err = compat_otp.LabelPod(oc, ns1, testPodName[0], "color=pink")
		defer compat_otp.LabelPod(oc, ns1, testPodName[0], "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check only one EgressIP assigned in the object.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Reboot egress node.\n")
		defer checkNodeStatus(oc, egressNode, "Ready")
		rebootNode(oc, egressNode)
		checkNodeStatus(oc, egressNode, "NotReady")
		checkNodeStatus(oc, egressNode, "Ready")
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName = getPodName(oc, ns1, "name=test-pods")
		_, err = compat_otp.AddLabelsToSpecificResource(oc, "pod/"+testPodName[0], ns1, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check EgressIP assigned in the object.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		egressIP := egressIPMaps1[0]["egressIP"]

		compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, "tcpdump", "true")
		defer deleteTcpdumpDS(oc, "tcpdump-66336", ns1)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-66336", "tcpdump", "true", dstHost, secondaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("Check source IP is as expected egressIP")
		egressErr := verifyEgressIPinTCPDump(oc, testPodName[0], ns1, egressIP, dstHost, ns1, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-Critical-66293-Medium-66349-[Multi-NIC] Egress traffic uses egressIP for secondary NIC,be able to access api server. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("Label EgressIP node\n")
		if len(workers) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}
		egressNode := workers[0]
		nonEgressNode := workers[1]

		compat_otp.By("Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("Apply label to namespace\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create an egressip object\n")
		freeIPs := findFreeIPsForCIDRs(oc, egressNode, dstCIDR, 1)
		egressip1 := egressIPResource1{
			name:          "egressip-66293",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Create a pod ")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  egressNode,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Create a second pod ")
		pod2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns1,
			nodename:  nonEgressNode,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod2.name)

		compat_otp.By("Apply a label to test namespace.\n")
		oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()

		compat_otp.By("Apply label to one pod in test namespace\n")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())
		err = compat_otp.LabelPod(oc, ns1, pod2.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], "tcpdump", "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], "tcpdump", "true")

		defer deleteTcpdumpDS(oc, "tcpdump-66293", ns1)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-66293", "tcpdump", "true", dstHost, secondaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("Check both pods located egress node and non-egress node will use egressIP\n")
		egressErr := verifyEgressIPinTCPDump(oc, pod1.name, ns1, freeIPs[0], dstHost, ns1, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())
		egressErr = verifyEgressIPinTCPDump(oc, pod2.name, ns1, freeIPs[0], dstHost, ns1, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify both pods can access api\n")
		_, err = e2eoutput.RunHostCmd(ns1, pod1.name, "curl -sk 172.30.0.1:443 --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(ns1, pod2.name, "curl -sk 172.30.0.1:443 --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Remove label from  pod1 in test namespace\n")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify pod2 still using egressIP\n")
		egressErr = verifyEgressIPinTCPDump(oc, pod2.name, ns1, freeIPs[0], dstHost, ns1, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify pod1 will use nodeIP\n")
		_, nodeIP := getNodeIP(oc, egressNode)
		deleteTcpdumpDS(oc, "tcpdump-66293", ns1)
		primaryInf, infErr := getSnifPhyInf(oc, egressNode)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		tcpdumpDS, snifErr = createSnifferDaemonset(oc, ns1, "tcpdump-66293", "tcpdump", "true", dstHost, primaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())
		egressErr = verifyEgressIPinTCPDump(oc, pod1.name, ns1, nodeIP, dstHost, ns1, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())

		compat_otp.By("Remove egressLabel from egress node\n")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		compat_otp.By("Verify pod2 used nodeIP \n")
		_, node2IP := getNodeIP(oc, nonEgressNode)
		egressErr = verifyEgressIPinTCPDump(oc, pod2.name, ns1, node2IP, dstHost, ns1, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-High-66330-[Multi-NIC] EgressIP will failover to second egress node if original egress node is unavailable. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("Label EgressIP node\n")
		if len(workers) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}
		egressNode1 := workers[0]
		egressNode2 := workers[1]

		compat_otp.By("Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

		compat_otp.By("Apply label to namespace\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create an egressip object\n")
		freeIPs := findFreeIPsForCIDRs(oc, egressNode1, dstCIDR, 1)
		egressip1 := egressIPResource1{
			name:          "egressip-66330",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Create a pod ")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  egressNode1,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Apply a label to test namespace.\n")
		oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()

		compat_otp.By("Apply label to one pod in test namespace\n")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Add iptables to block port 9107 on egressNode1\n")
		defer compat_otp.DebugNodeWithChroot(oc, egressNode1, "iptables", "-D", "INPUT", "-p", "tcp", "--destination-port", "9107", "-j", "DROP")
		_, debugNodeErr := compat_otp.DebugNodeWithChroot(oc, egressNode1, "iptables", "-I", "INPUT", "1", "-p", "tcp", "--destination-port", "9107", "-j", "DROP")
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())

		compat_otp.By("Apply EgressLabel Key for this test on second node.\n")
		// time sleep is a workaround for bug https://issues.redhat.com/browse/OCPBUGS-20209 , will remove it after bug fix
		time.Sleep(10 * time.Second)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)

		compat_otp.By(" Check the egress node was updated in the egressip object.\n")
		o.Eventually(func() bool {
			egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
			return len(egressIPMaps) == 1 && egressIPMaps[0]["node"] == egressNode2
		}, "300s", "10s").Should(o.BeTrue(), "egressIP was not migrated to second egress node after first egress node unavailable!!")

		compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, "tcpdump", "true")

		defer deleteTcpdumpDS(oc, "tcpdump-66330", ns1)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-66330", "tcpdump", "true", dstHost, secondaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify egressIP works\n")
		egressErr := verifyEgressIPinTCPDump(oc, pod1.name, ns1, freeIPs[0], dstHost, ns1, tcpdumpDS.name, true)
		o.Expect(egressErr).NotTo(o.HaveOccurred())
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-High-66296-[Multi-NIC] Mixing Egress IPs from ovn and non-ovn managed networks. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("Label EgressIP node\n")
		if len(workers) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("Apply EgressLabel Key for this test on two egress nodes.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel)

		compat_otp.By("Apply label to namespace\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create an egressip object\n")
		secondaryNICFreeIPs := findFreeIPsForCIDRs(oc, workers[0], dstCIDR, 1)
		primaryNICfreeIPs := findFreeIPs(oc, workers[1], 1)
		o.Expect(len(primaryNICfreeIPs)).Should(o.Equal(1))
		freeIPs := append(secondaryNICFreeIPs, primaryNICfreeIPs...)
		egressip1 := egressIPResource1{
			name:      "egressip-66296",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Get the node that has egressIP for primary interface assigned on it, and get the other node that hosts egressIP for secondary interface assigned on it.\n")
		egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
		var primaryInfNode, secInfNode string
		if egressIPMaps[0]["egressIP"] == freeIPs[0] {
			secInfNode = egressIPMaps[0]["node"]
			primaryInfNode = egressIPMaps[1]["node"]
		} else {
			secInfNode = egressIPMaps[1]["node"]
			primaryInfNode = egressIPMaps[0]["node"]
		}

		compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, primaryInfNode, "tcpdump", "primary")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], "tcpdump")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, secInfNode, "tcpdump", "secondary")

		primaryInf, infErr := getSnifPhyInf(oc, primaryInfNode)
		o.Expect(infErr).NotTo(o.HaveOccurred())
		defer deleteTcpdumpDS(oc, "tcpdump-66296-primary", ns1)
		tcpdumpDS1, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-66296-primary", "tcpdump", "primary", dstHost, primaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())
		defer deleteTcpdumpDS(oc, "tcpdump-66296-secondary", ns1)
		tcpdumpDS2, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-66296-secondary", "tcpdump", "secondary", dstHost, secondaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("Check source IP is randomly one of egress ips")
		egressipErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, ns1, tcpdumpDS1.name, randomStr, freeIPs[1], true) != nil || checkMatchedIPs(oc, ns1, tcpdumpDS2.name, randomStr, freeIPs[0], true) != nil || err != nil {
				e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get both EgressIPs %s,%s in tcpdump", freeIPs[0], freeIPs[1]))
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-High-68542-[Multi-NIC] EgressIP works for bonding interface as secondary NIC. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("Prepare bonding interface for egress node\n")
		e2e.Logf("Using node %s as egress node", workers[0])
		egressNode := workers[0]
		dummyNICName := "test-68542"
		compat_otp.By("Create one dummy interface on egress node\n")
		defer removeDummyInterface(oc, egressNode, dummyNICName)
		addDummyInferface(oc, egressNode, "120.10.0.100", dummyNICName)

		compat_otp.By("Get secondary NIC IP\n")
		secondNICIP, _ := getIPv4AndIPWithPrefixForNICOnNode(oc, egressNode, secondaryInf)

		compat_otp.By("Install nmstate operator and create nmstate CR")
		installNMstateOperator(oc)
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		compat_otp.By("Creating bonding interface by nmstate.\n")
		policyName := "bond-policy-68542"
		bondInfName := "bond01"
		bondPolicyTemplate := generateTemplateAbsolutePath("bonding-policy-template.yaml")
		bondPolicy := bondPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: egressNode,
			ifacename:  bondInfName,
			descr:      "create bond",
			port1:      secondaryInf,
			port2:      dummyNICName,
			state:      "up",
			ipaddrv4:   secondNICIP,
			template:   bondPolicyTemplate,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, egressNode, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, bondPolicy.ifacename) {
				compat_otp.DebugNodeWithChroot(oc, egressNode, "nmcli", "con", "delete", bondPolicy.ifacename)
			}
		}()

		configErr1 := configBondWithIP(oc, bondPolicy)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		compat_otp.By("Verify the policy is applied")
		nncpErr1 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		compat_otp.By("Apply EgressLabel Key to egress nodes.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Create one egressip object\n")
		freeIPs := findFreeIPsForCIDRs(oc, egressNode, dstCIDR, 1)
		egressip1 := egressIPResource1{
			name:          "egressip-68542",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("Apply a label to test namespace.\n")
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Apply label to one pod in test namespace\n")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=pink")
		defer compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check only one EgressIP assigned in the object.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Start tcpdump on egress node\n")
		compat_otp.SetNamespacePrivileged(oc, ns1)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", bondInfName, dstHost)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+egressNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Access exteranl IP from pod")
		//Wait 5 seconds to let the tcpdump ready for capturing traffic
		time.Sleep(5 * time.Second)
		pingCmd := fmt.Sprintf("ping -c4 %s", dstHost)
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Check captured packets including egressIP")
		cmdErr := cmdTcpdump.Wait()
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		e2e.Logf("The captured packet is %s", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), freeIPs[0])).To(o.BeTrue())
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Longduration-NonPreRelease-High-68541-[Multi-NIC] EgressIP works for vlan interface as secondary NIC. [Disruptive]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressIP2Template   = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			egressNode          = workers[0]
			ipVlanExternalHost  = "10.8.1.181"
			policyName1         = "vlan-policy-68541-worker0"
			policyName2         = "vlan-policy-68541-worker1"
			ipaddrv4Vlan1       = "192.168.118.30"
			ipaddrv6Vlan1       = "2600:52:7:94::30"
			ipaddrv4Vlan2       = "192.168.118.20"
			ipaddrv6Vlan2       = "2600:52:7:94::20"
			vlan1GWIPv4         = "192.168.118.1"
			vlan1GWIPv6         = "2600:52:7:94::1"
			addtionalNICName    = "nmstate1"
			vlanID              = 94
			vlanName            = addtionalNICName + "." + fmt.Sprintf("%d", vlanID)
			nodeBaseInf         = "enp3s0"
		)

		ipStackType := checkIPStackType(oc)
		if ipStackType == "ipv6single" {
			g.Skip("The case will be executed in ipv4single and dualstack only, skip for ipv6single")
		}

		compat_otp.By("get temp namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("Ensure the environment having addtional NIC for vlan testing")

		if !checkInterfaceExistsOnHypervisorHost(ipVlanExternalHost, addtionalNICName) {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("Create vlan interface on external host\n")
		defer func() {
			vlanCmd := "ip link show " + vlanName
			err := sshRunCmd(ipVlanExternalHost, "root", vlanCmd)
			if err == nil {
				vlanDelCmd := "ip link del " + vlanName
				errDel := sshRunCmd(ipVlanExternalHost, "root", vlanDelCmd)
				o.Expect(errDel).NotTo(o.HaveOccurred())
			}
		}()
		vlanCmd := fmt.Sprintf("ip link add link  %s name %s type vlan id %v && ip addr add %s/24 dev %s && ip addr add %s/64 dev %s && ip link set %s up", addtionalNICName, vlanName, vlanID, vlan1GWIPv4, vlanName, vlan1GWIPv6, vlanName, vlanName)
		err := sshRunCmd(ipVlanExternalHost, "root", vlanCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Install nmstate operator and create nmstate CR")
		installNMstateOperator(oc)
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		createNMstateCR(oc, nmstateCR)

		compat_otp.By("Creating vlan interface by nmstate.\n")
		vlanPolicyTemplate := generateTemplateAbsolutePath("vlan-policy-base-eth-template.yaml")
		vlanPolicyDualstackTemplate := generateTemplateAbsolutePath("vlan-policy-dualstack-template.yaml")
		var vlanPolicy1, vlanPolicy2 vlanPolicyResource
		vlanInf := "vlan" + fmt.Sprintf("%d", vlanID)
		if ipStackType == "dualstack" {
			vlanPolicy1 = vlanPolicyResource{
				name:        policyName1,
				nodelabel:   "kubernetes.io/hostname",
				labelvalue:  egressNode,
				ifacename:   vlanInf,
				descr:       "create vlan",
				baseiface:   nodeBaseInf,
				vlanid:      vlanID,
				state:       "up",
				ipaddrv4:    ipaddrv4Vlan1,
				ipaddrv6:    ipaddrv6Vlan1,
				gatewayipv4: vlan1GWIPv4,
				gatewayipv6: vlan1GWIPv6,
				template:    vlanPolicyDualstackTemplate,
			}
			vlanPolicy2 = vlanPolicyResource{
				name:        policyName2,
				nodelabel:   "kubernetes.io/hostname",
				labelvalue:  workers[1],
				ifacename:   vlanInf,
				descr:       "create vlan",
				baseiface:   nodeBaseInf,
				vlanid:      vlanID,
				state:       "up",
				ipaddrv4:    ipaddrv4Vlan2,
				ipaddrv6:    ipaddrv6Vlan2,
				gatewayipv4: vlan1GWIPv4,
				gatewayipv6: vlan1GWIPv6,
				template:    vlanPolicyDualstackTemplate,
			}
		} else if ipStackType == "ipv4single" {
			vlanPolicy1 = vlanPolicyResource{
				name:       policyName1,
				nodelabel:  "kubernetes.io/hostname",
				labelvalue: egressNode,
				ifacename:  vlanInf,
				descr:      "create vlan",
				baseiface:  nodeBaseInf,
				vlanid:     vlanID,
				state:      "up",
				ipaddrv4:   ipaddrv4Vlan1,
				template:   vlanPolicyTemplate,
			}
			vlanPolicy2 = vlanPolicyResource{
				name:       policyName2,
				nodelabel:  "kubernetes.io/hostname",
				labelvalue: workers[1],
				ifacename:  vlanInf,
				descr:      "create vlan",
				baseiface:  nodeBaseInf,
				vlanid:     vlanID,
				state:      "up",
				ipaddrv4:   ipaddrv4Vlan2,
				template:   vlanPolicyTemplate,
			}
		}

		defer deleteNNCP(oc, policyName1)
		defer deleteNNCP(oc, policyName2)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, egressNode, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, vlanPolicy1.ifacename) {
				compat_otp.DebugNodeWithChroot(oc, egressNode, "nmcli", "con", "delete", vlanPolicy1.ifacename)
			}
			ifaces, deferErr = compat_otp.DebugNodeWithChroot(oc, workers[1], "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, vlanPolicy2.ifacename) {
				compat_otp.DebugNodeWithChroot(oc, workers[1], "nmcli", "con", "delete", vlanPolicy2.ifacename)
			}
		}()

		if ipStackType == "dualstack" {
			configErr1 := vlanPolicy1.configNNCPWithDualstackIP(oc)
			o.Expect(configErr1).NotTo(o.HaveOccurred())
			configErr2 := vlanPolicy2.configNNCPWithDualstackIP(oc)
			o.Expect(configErr2).NotTo(o.HaveOccurred())
		} else if ipStackType == "ipv4single" {
			configErr1 := vlanPolicy1.configNNCPWithIP(oc)
			o.Expect(configErr1).NotTo(o.HaveOccurred())
			configErr2 := vlanPolicy2.configNNCPWithIP(oc)
			o.Expect(configErr2).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Verify the policy is applied")
		nncpErr := checkNNCPStatus(oc, policyName1, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr, "policy applied failed")
		nncpErr = checkNNCPStatus(oc, policyName2, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		compat_otp.By("Apply EgressLabel Key to egress nodes.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel)

		compat_otp.By("Create a pod ")
		pod1 := pingPodResourceNode{
			name:      "hello-pod",
			namespace: ns1,
			nodename:  workers[2],
			template:  pingPodTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Create one egressip object\n")
		egressIPv4 := "192.168.118.100"
		egressIPv6 := "2600:52:7:94::100"
		var egressip1 egressIPResource1
		egressip1 = egressIPResource1{
			name:      "egressip-68541",
			template:  egressIP2Template,
			egressIP1: egressIPv4,
			egressIP2: egressIPv6,
		}

		egressip1.createEgressIPObject1(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("Apply a label to test namespace.\n")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check only one EgressIP assigned in the object.\n")
		if ipStackType == "dualstack" {
			verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 2)
		} else {
			verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)
		}

		compat_otp.By("Start tcpdump on egress node\n")
		compat_otp.SetNamespacePrivileged(oc, ns1)
		// Create a temporary file on remote server to store tcpdump output
		tcpdumpOutputFile := fmt.Sprintf("/tmp/tcpdump_output_%d.txt", time.Now().Unix())
		defer func() {
			cleanupCmd := fmt.Sprintf("rm -f %s", tcpdumpOutputFile)
			_, err = sshRunCmdOutPut(ipVlanExternalHost, "root", cleanupCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
		}()
		// Start tcpdump in background and redirect output to file
		tcpdumpCmd := fmt.Sprintf("nohup timeout 60s tcpdump -nni %s host %s and tcp port 80 > %s 2>&1 & echo $!", vlanName, vlan1GWIPv4, tcpdumpOutputFile)
		_, err = sshRunCmdOutPut(ipVlanExternalHost, "root", tcpdumpCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Access exteranl IP from pod in a loop to generate traffic\n")
		//Wait 5 seconds to let the tcpdump ready for capturing traffic
		time.Sleep(5 * time.Second)

		compat_otp.By("Start a background ping process to continuously access the external host\n")
		curlCMD := fmt.Sprintf("for i in {1..30}; do date;curl http://%s --connect-timeout 2 ;   sleep 2; done", vlan1GWIPv4)
		cmdCurl, curlOutput, _, _ := oc.AsAdmin().Run("exec").Args("-n", ns1, pod1.name, "--", "bash", "-c", curlCMD).Background()
		defer cmdCurl.Process.Kill()
		egressNodeIPv4 := getNodeFromEIP(oc, egressIPv4, egressip1.name)
		o.Expect(egressNodeIPv4).NotTo(o.BeEmpty())
		originalEgressNodeIPv4 := egressNodeIPv4
		/*
			   // Test coverage for bug https://issues.redhat.com/browse/OCPBUGS-61524 which is still open
				output, debugNodeErr := compat_otp.DebugNode(oc, egressNodeIPv4, "ip", "addr", "show", "dev", "br-ex	")
				o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
				o.Expect(output).NotTo(o.ContainSubstring(egressIPv4))
		*/

		compat_otp.By("Reboot egress node to trigger EIP failover\n")
		defer checkNodeStatus(oc, egressNodeIPv4, "Ready")
		rebootNode(oc, egressNodeIPv4)
		checkNodeStatus(oc, egressNodeIPv4, "NotReady")
		checkNodeStatus(oc, egressNodeIPv4, "Ready")

		compat_otp.By("Verify egressIP has failed over to another node after node reboot\n")
		egressNodeIPv4 = getNodeFromEIP(oc, egressIPv4, egressip1.name)
		o.Expect(egressNodeIPv4).NotTo(o.BeEmpty())
		o.Expect(egressNodeIPv4).NotTo(o.Equal(originalEgressNodeIPv4), "EgressIP should have failed over to a different node after reboot")
		e2e.Logf("EgressIP failed over from node %s to node %s", originalEgressNodeIPv4, egressNodeIPv4)
		var ip4, ip6 string
		if ipStackType == "dualstack" {
			ip6, ip4 = getNodeIP(oc, egressNodeIPv4)
			e2e.Logf("The node's IPv4 IP is : %s, IPv6 IP is : %s", ip4, ip6)
		} else if ipStackType == "ipv4single" {
			_, ip4 = getNodeIP(oc, egressNodeIPv4)
			e2e.Logf("The node's IPv4 IP is : %s", ip4)
		}

		compat_otp.By("Verify traffic timeout is less than 12s during EIP failover \n")
		curlOutputStr := curlOutput.String()
		e2e.Logf("The curl output is : %s", curlOutputStr)
		o.Expect(strings.Contains(curlOutputStr, "404 Not Found")).Should(o.BeTrue())
		o.Expect(strings.Count(curlOutputStr, "Connection timeout")).Should(o.BeNumerically("<=", 6))

		// Stop tcpdump and retrieve output
		compat_otp.By("Stop tcpdump and check captured traffic\n")
		cmd := fmt.Sprintf(`
pkill tcpdump 2>/dev/null || true
sleep 1
cat %s
`, tcpdumpOutputFile)
		tcpdumpOutput, err := sshRunCmdOutPut(ipVlanExternalHost, "root", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("Verify tcpdump captured traffic and contains egress IP\n")
		o.Expect(tcpdumpOutput).NotTo(o.BeEmpty())
		o.Expect(tcpdumpOutput).To(o.ContainSubstring(egressIPv4))
		compat_otp.By("Verify tcpdump captured traffic and should not contains node IP\n")
		o.Expect(tcpdumpOutput).NotTo(o.ContainSubstring(ip4))
		if ipStackType == "dualstack" {
			tcpdumpCmd := fmt.Sprintf("nohup timeout 60s tcpdump -nni %s host %s and tcp port 80 > %s 2>&1 & echo $!", vlanName, vlan1GWIPv6, tcpdumpOutputFile)
			_, err = sshRunCmdOutPut(ipVlanExternalHost, "root", tcpdumpCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
			time.Sleep(5 * time.Second)

			compat_otp.By("Access exteranl IPv6 from pod in a loop to generate traffic\n")
			curlCMD := fmt.Sprintf("for i in {1..30}; do date;curl http://[%s] --connect-timeout 2 ; sleep 2; done", vlan1GWIPv6)
			//Start a background curl process to continuously access the external host
			_, curlOutput, _, _ := oc.AsAdmin().Run("exec").Args("-n", ns1, pod1.name, "--", "bash", "-c", curlCMD).Background()
			egressNodeIPv6 := getNodeFromEIP(oc, egressIPv6, egressip1.name)
			o.Expect(egressNodeIPv6).NotTo(o.BeEmpty())
			originalEgressNodeIPv6 := egressNodeIPv6

			compat_otp.By("Reboot egress node to trigger EIP failover for IPv6\n")
			defer checkNodeStatus(oc, egressNodeIPv6, "Ready")
			rebootNode(oc, egressNodeIPv6)
			checkNodeStatus(oc, egressNodeIPv6, "NotReady")
			checkNodeStatus(oc, egressNodeIPv6, "Ready")

			compat_otp.By("Verify egressIP has failed over to another node after node reboot\n")
			egressNodeIPv6 = getNodeFromEIP(oc, egressIPv6, egressip1.name)
			o.Expect(egressNodeIPv6).NotTo(o.BeEmpty())
			o.Expect(egressNodeIPv6).NotTo(o.Equal(egressNodeIPv6), "EgressIP should have failed over to a different node after reboot")
			e2e.Logf("EgressIP failed over from node %s to node %s", originalEgressNodeIPv6, egressNodeIPv6)
			output, debugNodeErr := compat_otp.DebugNode(oc, egressNodeIPv6, "ip", "addr", "show", "dev", vlanPolicy1.ifacename)
			o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("nodad"))

			compat_otp.By("Verify timeout is limited to a couple of seconds \n")
			curlOutputStr := curlOutput.String()
			o.Expect(strings.Contains(curlOutputStr, "404 Not Found")).Should(o.BeTrue())
			o.Expect(strings.Count(curlOutputStr, "Connection timeout")).Should(o.BeNumerically("<=", 6))

			// Stop tcpdump and retrieve output
			compat_otp.By("Stop tcpdump and check captured traffic\n")
			cmd := fmt.Sprintf(`
pkill tcpdump 2>/dev/null || true
sleep 1
cat %s
`, tcpdumpOutputFile)
			tcpdumpOutput, err := sshRunCmdOutPut(ipVlanExternalHost, "root", cmd)
			o.Expect(err).NotTo(o.HaveOccurred())
			compat_otp.By("Verify tcpdump captured traffic and contains egress IP\n")
			o.Expect(tcpdumpOutput).NotTo(o.BeEmpty())
			e2e.Logf("The tcpdump captured output is : %s", tcpdumpOutput)
			o.Expect(tcpdumpOutput).To(o.ContainSubstring(egressIPv6))
			compat_otp.By("Verify tcpdump captured traffic and should not contains node IPv6\n")
			o.Expect(tcpdumpOutput).NotTo(o.ContainSubstring(ip6))
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-High-75387-[rducluster] [Multi-NIC] Default Routes should be injected to Egress IP Routing Table for Secondary NIC. [Disruptive]", func() {
		// From bug https://issues.redhat.com/browse/OCPBUGS-31854
		compat_otp.By("Get worker nodes\n")
		if len(workers) < 1 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()

		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By(" Label EgressIP node\n")
		egressNode := workers[0]
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("Create first egressip object\n")
		dstCIDR := "192.168.221.0/24"
		freeIPs := findFreeIPsForCIDRs(oc, egressNode, dstCIDR, 1)
		egressip1 := egressIPResource1{
			name:          "egressip-75387",
			template:      egressIP2Template,
			egressIP1:     freeIPs[0],
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)

		compat_otp.By("Check only one EgressIP assigned in the object.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Apply a label to test namespace.\n")
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create pods in test namespace. \n")
		createResourceFromFile(oc, ns1, testPodFile)
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		compat_otp.By("Apply label to one pod in test namespace\n")
		testPodName := getPodName(oc, ns1, "name=test-pods")
		err = compat_otp.LabelPod(oc, ns1, testPodName[0], "color=pink")
		defer compat_otp.LabelPod(oc, ns1, testPodName[0], "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(" Use tcpdump to verify egressIP, create tcpdump sniffer Daemonset first.")
		// Access rdu2's host IP
		dstHost = "10.8.1.179"
		compat_otp.SetNamespacePrivileged(oc, ns1)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 4 -nni %s host %s", secondaryInf, dstHost)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+egressNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Access external IP from pod")
		//Wait 5 seconds to let the tcpdump ready for capturing traffic
		time.Sleep(5 * time.Second)
		pingCmd := fmt.Sprintf("ping -c4 %s", dstHost)
		_, err = e2eoutput.RunHostCmd(ns1, testPodName[0], pingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Check captured packets including egressIP")
		cmdErr := cmdTcpdump.Wait()
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		e2e.Logf("The captured packet is %s", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), freeIPs[0])).To(o.BeTrue())

		compat_otp.By("Verify IP route for secondary NIC includes default route.")
		testPodIP := getPodIPv4(oc, ns1, testPodName[0])
		ipRouteCmd := fmt.Sprintf("ip route show table $(ip rule | grep %s | awk '{print $5}')", testPodIP)
		output, debugNodeErr := compat_otp.DebugNode(oc, egressNode, "bash", "-c", ipRouteCmd)
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
		e2e.Logf(output)
		o.Expect(strings.Contains(output, "default ")).Should(o.BeTrue())

	})

	// author: jechen@redhat.com
	g.It("Author:jechen-ConnectedOnly-High-75830-[rducluster] [Multi-NIC] EgressIP should work in VRF mode. [Disruptive]", func() {

		// for customer bug: https://issues.redhat.com/browse/OCPBUGS-38267
		buildPruningBaseDir := testdata.FixturePath("networking")
		nmstateCRTemplate := filepath.Join(buildPruningBaseDir, "nmstate", "nmstate-cr-template.yaml")
		VRFTemplate := filepath.Join(buildPruningBaseDir, "nmstate", "nncp-vrf-template.yaml")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		if len(workers) < 1 {
			g.Skip("Need at least 1 worker for the test, when there is none, skip the case!!")
		}
		egressNode := workers[0]

		compat_otp.By("\n 1. Install nmstate operator and create nmstate CR \n")
		installNMstateOperator(oc)
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, "openshift-nmstate")
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("\n 2. Create VRF on egress node by nmstate \n")
		vrf := VRFResource{
			name:     "vrf-75830",
			intfname: "enp1s0",
			nodename: egressNode,
			tableid:  rand.Intn(999-256+1) + 256,
			template: VRFTemplate,
		}

		defer deleteNNCP(oc, vrf.name)
		vrf.createVRF(oc)
		compat_otp.By("\n 2.1 Verify VRF is created \n")
		nncpErr1 := checkNNCPStatus(oc, vrf.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "VRF creation failed")
		e2e.Logf("SUCCESS - VRF is created")

		compat_otp.By("3. Apply EgressLabel Key to egress node, create an egressIP object, verify egressIP is assigned \n")
		compat_otp.By("3.1. Apply EgressLabel Key to egress node \n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		compat_otp.By("3.2. Create one egressip object, verify egressIP is assigned\n")
		dstCIDR := "172.22.0.0/24"
		freeIPs := findFreeIPsForCIDRs(oc, egressNode, dstCIDR, 1)
		egressIP := freeIPs[0]
		egressip1 := egressIPResource1{
			name:          "egressip-75830",
			template:      egressIP2Template,
			egressIP1:     egressIP,
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		var egressIPMaps1 []map[string]string
		egressipErr := wait.PollUntilContextTimeout(context.Background(), 20*time.Second, 360*time.Second, false, func(cxt context.Context) (bool, error) {
			egressIPMaps1 = getAssignedEIPInEIPObject(oc, egressip1.name)
			if len(egressIPMaps1) != 1 || egressIPMaps1[0]["node"] != egressNode {
				e2e.Logf("Wait for egressIP be assigned to egress node,try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to assign egressIP to egress node:%v", egressipErr))
		o.Expect(egressIPMaps1[0]["node"]).Should(o.ContainSubstring(egressNode))

		compat_otp.By("4. Get the namespace, create a test pod in it, label namespace and test pod to match namespaceSelector and podSelector of egressIP object \n")
		ns1 := oc.Namespace()
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("4.1. Apply a label to the namespace \n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4.2. Apply label to test pod in the namespace\n")
		defer compat_otp.LabelPod(oc, ns1, pod1.name, "color-")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("5. Start tcpdump on egress node \n")
		compat_otp.SetNamespacePrivileged(oc, ns1)
		tcpdumpCmd := fmt.Sprintf("timeout 60s tcpdump -c 2 -nni %s icmp", vrf.intfname)
		cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+egressNode, "--", "bash", "-c", tcpdumpCmd).Background()
		defer cmdTcpdump.Process.Kill()
		compat_otp.AssertWaitPollNoErr(err, "FAILED to start tcmpdump on the egress node\n")

		//Wait 5 seconds to let the tcpdump ready for capturing traffic
		time.Sleep(5 * time.Second)

		compat_otp.By("6. Ping outside from the test pod \n")
		externalIP := "172.22.0.1"
		pingCmd := fmt.Sprintf("ping -c4 %s", externalIP)
		e2eoutput.RunHostCmd(pod1.namespace, pod1.name, pingCmd)

		compat_otp.By("7. Check if captured packets has egressIP as its sourceIP \n")
		cmdTcpdump.Wait()
		e2e.Logf(" \n\n\n The captured packet from tcpdump: \n %s \n\n\n", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), "IP "+egressIP+" > "+externalIP+": ICMP echo request")).To(o.BeTrue())
	})
})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP Multi-NIC Basic", func() {
	// In this describe function, will use dummy interfaces as non-ovn managed interfaces to test egressIP assignment to egress nodes.
	defer g.GinkgoRecover()

	var (
		oc              = compat_otp.NewCLI("networking-eip-multinic-"+getRandomString(), compat_otp.KubeConfigPath())
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		ipv4Addr1       = "10.10.0.10/24"
		ipv4Addr2       = "10.10.0.11/24"
		ipv6Addr1       = "2001::1/64"
		ipv6Addr2       = "2001::2/64"
		ipv4eip1        = "10.10.0.100"
		ipv6eip1        = "2001::100"
	)

	g.BeforeEach(func() {
		platform := compat_otp.CheckPlatform(oc)
		networkType := checkNetworkType(oc)
		e2e.Logf("\n\nThe platform is %v,  networkType is %v\n", platform, networkType)

		acceptedPlatform := strings.Contains(platform, "baremetal") || strings.Contains(platform, "none")
		if !acceptedPlatform || !strings.Contains(networkType, "ovn") {
			g.Skip("Test cases should be run on BareMetal cluster with ovn network plugin, skip for other platforms or other non-OVN network plugin!!")
		}
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Author:huirwang-Critical-66284-Medium-66286-Medium-66285-EgressIP can be applied on secondary NIC. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name

		compat_otp.By("Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		compat_otp.By("Create one dummy interface on egress node.\n")
		ipStackType := checkIPStackType(oc)
		var egressIP, dummyIP string
		dummyNICName := "dummy-66284"

		if ipStackType == "ipv6single" {
			dummyIP = ipv6Addr1
			egressIP = ipv6eip1
		} else {
			dummyIP = ipv4Addr1
			egressIP = ipv4eip1
		}
		defer removeDummyInterface(oc, egressNode, dummyNICName)
		addDummyInferface(oc, egressNode, dummyIP, dummyNICName)

		compat_otp.By("Create egressIP object.\n")
		egressip1 := egressIPResource1{
			name:          "egressip-66284",
			template:      egressIP2Template,
			egressIP1:     egressIP,
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("Verify egressIP was assigned to egress node.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		if ipStackType == "dualstack" {
			compat_otp.By("Verify egressIP was assigned to egress node with IPv6 in dualstack cluster.\n")
			removeDummyInterface(oc, egressNode, dummyNICName)
			addDummyInferface(oc, egressNode, ipv6Addr1, dummyNICName)
			egressip1.deleteEgressIPObject1(oc)
			egressip1.egressIP1 = ipv6eip1
			egressip1.createEgressIPObject2(oc)
			verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)
		}

		// Test case OCP-66285
		compat_otp.By("Remove IP address from dummy interface\n")
		if ipStackType == "ipv4single" {
			delIPFromInferface(oc, egressNode, ipv4Addr1, dummyNICName)
		} else {
			delIPFromInferface(oc, egressNode, ipv6Addr1, dummyNICName)
		}

		compat_otp.By("Verify egressIP was not assigned to egress node\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 0)

		compat_otp.By("Add IP back to dummy interface\n")
		if ipStackType == "ipv4single" {
			addIPtoInferface(oc, egressNode, ipv4Addr1, dummyNICName)
		} else {
			addIPtoInferface(oc, egressNode, ipv6Addr1, dummyNICName)
		}

		compat_otp.By("Verify egressIP was assigned back to egress node\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		// Test case OCP-66286
		compat_otp.By("Remove dummy interface from egress node. \n")
		removeDummyInterface(oc, egressNode, dummyNICName)

		compat_otp.By("Verify egressIP was not assigned to egress node\n\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 0)

	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Author:huirwang-High-66288-High-66287-egressIP will not failover to egress node which doesn't have the secodary nic. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Require 2 worker nodes for this test, no enough worker nodes, skip the test!")
		}
		egressNode1 := nodeList.Items[0].Name
		egressNode2 := nodeList.Items[1].Name

		compat_otp.By("Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

		compat_otp.By("Create one dummy interface on egress node.\n")
		ipStackType := checkIPStackType(oc)
		var egressIP, dummyIP string
		dummyNICName := "dummy-66288"

		if ipStackType == "ipv6single" {
			dummyIP = ipv6Addr1
			egressIP = ipv6eip1
		} else {
			dummyIP = ipv4Addr1
			egressIP = ipv4eip1
		}
		defer removeDummyInterface(oc, egressNode1, dummyNICName)
		addDummyInferface(oc, egressNode1, dummyIP, dummyNICName)

		compat_otp.By("Create egressIP object.\n")
		egressip1 := egressIPResource1{
			name:          "egressip-66288",
			template:      egressIP2Template,
			egressIP1:     egressIP,
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)

		compat_otp.By("Verify egressIP was assigned to egress node.\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Remove egress label from first egress node, add label to second node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

		compat_otp.By("Verify egressIP was not assigned to second egress node\n")
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 0)

		if ipStackType == "ipv6single" {
			addDummyInferface(oc, egressNode2, ipv6Addr2, dummyNICName)
		} else {
			addDummyInferface(oc, egressNode2, ipv4Addr2, dummyNICName)
		}
		defer removeDummyInterface(oc, egressNode2, dummyNICName)

		compat_otp.By("Verify egressIP was assigned to second egress node\n")
		o.Eventually(func() bool {
			egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
			return len(egressIPMaps) == 1 && egressIPMaps[0]["node"] == egressNode2
		}, "300s", "10s").Should(o.BeTrue(), "egressIP was not migrated to second egress node after unlabel first egress node!!")

		compat_otp.By("Remove egress label from second node, add label to first node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)

		compat_otp.By("Verify egressIP was assigned to first egress node again\n")
		o.Eventually(func() bool {
			egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
			return len(egressIPMaps) == 1 && egressIPMaps[0]["node"] == egressNode1
		}, "300s", "10s").Should(o.BeTrue(), "egressIP was not migrated back to first egress node after unlabel second egress node!!")

		if ipStackType == "dualstack" {
			compat_otp.By("Verify IPv6 in dualstack cluster.\n")
			addIPtoInferface(oc, egressNode1, ipv6Addr1, dummyNICName)
			egressip1.deleteEgressIPObject1(oc)
			egressip1.egressIP1 = ipv6eip1
			egressip1.createEgressIPObject2(oc)
			verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

			compat_otp.By("Remove egress label from first egress node, add label to second node.\n")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
			e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

			compat_otp.By("Verify egressIP was not assigned to second egress node\n")
			verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 0)

			compat_otp.By("Assign IPv6 address to the dummy interface on secondary NIC.\n")
			addIPtoInferface(oc, egressNode2, ipv6Addr2, dummyNICName)

			compat_otp.By("Verify egressIP was assigned to second egress node\n")
			o.Eventually(func() bool {
				egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
				return len(egressIPMaps) == 1 && egressIPMaps[0]["node"] == egressNode2
			}, "300s", "10s").Should(o.BeTrue(), "egressIP was not migrated to second egress node after unlabel first egress node!!")

		}
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-Author:huirwang-Medium-66297-EgressIP uses the longest prefix match for secondary NIC assignment. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Require 1 worker node for this test, no enough worker nodes, skip the test!")
		}
		egressNode1 := nodeList.Items[0].Name

		compat_otp.By("Apply EgressLabel Key for this test on one node.\n")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)

		compat_otp.By("Create two dummy interfaces on egress node.\n")
		ipStackType := checkIPStackType(oc)
		var egressIP, dummyIP1, dummyIP2 string

		dummyNICName1 := "dummy1-66297"
		dummyNICName2 := "dummy2-66297"

		if ipStackType == "ipv6single" {
			dummyIP1 = ipv6Addr1
			egressIP = ipv6eip1
			dummyIP2 = "2001::3/60"
		} else {
			dummyIP1 = ipv4Addr1
			egressIP = ipv4eip1
			dummyIP2 = "10.10.0.20/16"
		}
		addDummyInferface(oc, egressNode1, dummyIP1, dummyNICName1)
		defer removeDummyInterface(oc, egressNode1, dummyNICName1)
		addDummyInferface(oc, egressNode1, dummyIP2, dummyNICName2)
		defer removeDummyInterface(oc, egressNode1, dummyNICName2)

		compat_otp.By("Create an egressIP object.\n")
		egressip1 := egressIPResource1{
			name:          "egressip-66297",
			template:      egressIP2Template,
			egressIP1:     egressIP,
			nsLabelKey:    "org",
			nsLabelValue:  "qe",
			podLabelKey:   "color",
			podLabelValue: "pink",
		}
		egressip1.createEgressIPObject2(oc)
		defer egressip1.deleteEgressIPObject1(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		compat_otp.By("Get current namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)
		compat_otp.By("Apply a label to test namespace.\n")
		oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()

		compat_otp.By("Apply label to one pod in test namespace\n")
		err = compat_otp.LabelPod(oc, ns1, pod1.name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify egressIP was assigned to the interface which has longest prefix match!!\n")
		o.Eventually(func() bool {
			cmd := fmt.Sprintf("ip a show %s", dummyNICName1)
			output, debugNodeErr := compat_otp.DebugNode(oc, egressNode1, "bash", "-c", cmd)
			o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
			e2e.Logf("The egressIP was added to interface %s \n %s", dummyNICName1, output)
			return strings.Contains(output, egressIP)
		}, "120s", "20s").Should(o.BeTrue(), "The egressIP was not assigend to the interface with LPM")

		if ipStackType == "dualstack" {
			compat_otp.By("Verify IPv6 in dualstack cluster.\n")
			ipv6Addr2 := "2001::2/60"
			addIPtoInferface(oc, egressNode1, ipv6Addr1, dummyNICName1)
			addIPtoInferface(oc, egressNode1, ipv6Addr2, dummyNICName2)
			egressip1.deleteEgressIPObject1(oc)
			egressip1.egressIP1 = ipv6eip1
			egressip1.createEgressIPObject2(oc)
			verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

			compat_otp.By("Verify egressIP was assigned to the interface which has longest prefix match!!\n")
			o.Eventually(func() bool {
				cmd := fmt.Sprintf("ip a show %s", dummyNICName1)
				output, debugNodeErr := compat_otp.DebugNode(oc, egressNode1, "bash", "-c", cmd)
				o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
				e2e.Logf("The egressIP was added to interface %s \n %s", dummyNICName1, output)
				return strings.Contains(output, ipv6eip1)
			}, "120s", "20s").Should(o.BeTrue(), "The egressIP was not assigend to the interface with LPM")
		}

	})

})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP on rosa", func() {

	defer g.GinkgoRecover()

	var (
		clusterID       string
		rosaClient      *rosacli.Client
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
	)

	g.BeforeEach(func() {

		if !compat_otp.IsROSA() {
			g.Skip("The test cluster is not ROSA cluster.")
		}

		g.By("Get the cluster")
		clusterID = compat_otp.GetROSAClusterID()
		e2e.Logf("compat_otp is: %v", clusterID)

		// Initiate rosa client
		rosaClient = rosacli.NewClient()
	})

	// author: jechen@redhat.com
	g.It("ROSA-Longduration-NonPreRelease-ConnectedOnly-Author:jechen-High-61582-High-66112-New node with label can join ROSA cluster, EgressIP can be assigned to egress node that is labelled during ROSA machinepool creation and egressIP works. [Disruptive]", func() {

		compat_otp.By("This is for OCPBUGS-15731 and OCPBUGS-4969")

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIPTemplate := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		machinePoolName := "mp-61582"
		replicasNum := 2

		var origNodesName []string

		// Get original node list for ROSA hosted cluster for future use, do not need to do this for classic ROSA cluster
		if compat_otp.IsHypershiftHostedCluster(oc) {
			e2e.Logf("The test is running on ROSA Hypershift hosted cluster\n")

			// get existing nodes on the hosted cluster
			nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, node := range nodeList.Items {
				origNodesName = append(origNodesName, node.Name)
			}
			e2e.Logf("\n Original scheduleable nodes on the hosted cluster are: %v\n", origNodesName)
		}

		compat_otp.By("1. Create a new machinepool with egress-assignable label and set replicas.\n")
		machinePoolService := rosaClient.MachinePool

		output, err := machinePoolService.CreateMachinePool(clusterID, "--name="+machinePoolName, "--labels="+egressNodeLabel+"=true", "--replicas="+strconv.Itoa(replicasNum))
		o.Expect(err).To(o.BeNil())

		if compat_otp.IsHypershiftHostedCluster(oc) {
			o.Expect(output.String()).To(o.ContainSubstring("Machine pool '%s' created successfully on hosted cluster '%s'", machinePoolName, clusterID))
		} else {
			o.Expect(output.String()).To(o.ContainSubstring("Machine pool '%s' created successfully on cluster '%s'", machinePoolName, clusterID))
		}
		output, err = machinePoolService.ListMachinePool(clusterID)
		o.Expect(err).To(o.BeNil())
		o.Expect(output.String()).To(o.ContainSubstring(machinePoolName))

		// On ROSA hosted cluster, defer unlabel machinepool, defer deleting machinepool, defer checking nodes from the machinepool disappear
		// On classic ROSA cluster, defer unlabel machinepool, defer deleting machinepool, defer deleting machines from the machinepool
		if compat_otp.IsHypershiftHostedCluster(oc) {
			defer func() {
				machinePoolService.EditMachinePool(clusterID, machinePoolName, "--labels=")
				machinePoolService.DeleteMachinePool(clusterID, machinePoolName)

				// Make sure all nodes created from the machinepool disappear eventually after machinepool is deleted so the final node list is same as original node list
				o.Eventually(func() bool {
					finalNodesName, err := compat_otp.GetAllNodes(oc)
					o.Expect(err).NotTo(o.HaveOccurred())
					return len(finalNodesName) == len(origNodesName) && reflect.DeepEqual(finalNodesName, origNodesName)
				}, "600s", "10s").Should(o.BeTrue(), "Not all nodes created are deleted")
			}()
		} else {
			defer func() {
				machinePoolService.EditMachinePool(clusterID, machinePoolName, "--labels=")
				machinePoolService.DeleteMachinePool(clusterID, machinePoolName)

				// Make sure all machines created from the machinepool are deleted
				o.Eventually(func() bool {
					machineNames := getMachineNamesFromMachinePoolOnROSA(oc, machinePoolName, "openshift-machine-api")
					return len(machineNames) == 0
				}, "600s", "10s").Should(o.BeTrue(), "Machines from the machinepool %s are not all deleted", machinePoolName)
			}()
		}

		compat_otp.By("2. New nodes are created from the new machinepool, Verify they have egress-assignable label.\n")
		var newNodesName []string
		if compat_otp.IsHypershiftHostedCluster(oc) {
			e2e.Logf("The test is running on ROSA Hypershift hosted cluster\n")

			// Because there is no machine on ROSA hosted cluster to check, check if new nodes are created, need some wait time here before checking
			time.Sleep(60 * time.Second)
			o.Eventually(func() bool {
				newNodesName, err = compat_otp.GetAllNodes(oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				return len(newNodesName) == len(origNodesName)+replicasNum
			}, "600s", "10s").Should(o.BeTrue(), "Expected %d new nodes are not all created", replicasNum)
			e2e.Logf("\n Current nodes list on the ROSA hosted cluster are: %v\n", newNodesName)

			// Filter out existing nodes, only get new nodes created from the machineppol
			for _, oldNode := range origNodesName {
				for i, node := range newNodesName {
					if node == oldNode {
						newNodesName = append(newNodesName[:i], newNodesName[i+1:]...)
						break
					}
				}
			}
		} else {
			e2e.Logf("The test is running on classic ROSA (non-HCP) cluster\n")
			e2e.Logf("Check all machines are created from the machinepool and running\n")
			var machineNames []string
			o.Eventually(func() bool {
				machineNames = getMachineNamesFromMachinePoolOnROSA(oc, machinePoolName, "openshift-machine-api")
				return len(machineNames) == replicasNum
			}, "600s", "10s").Should(o.BeTrue(), fmt.Sprintf("Did not get expected %d of machines are created", replicasNum))
			e2e.Logf("\n machineNames created from the machinepool: %v\n", machineNames)

			for _, machineName := range machineNames {
				err := waitMachineOnROSAReady(oc, machineName, "openshift-machine-api")
				compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Machine %s is not in running state", machineName))
			}

			e2e.Logf("Get new nodes created from the machinepool\n")
			for _, machineName := range machineNames {
				newNode := clusterinfra.GetNodeNameFromMachine(oc, machineName)
				newNodesName = append(newNodesName, newNode)
			}
		}
		e2e.Logf("\n New nodes created from the machinepool on the classic ROSA or ROSA hosted cluster are: %v\n", newNodesName)

		compat_otp.By("3. Check and wait for new nodes to be ready, verify new nodes can join the cluster.\n")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("node", newNodesName[0], "--ignore-not-found=true").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("node", newNodesName[1], "--ignore-not-found=true").Execute()
		checkNodeStatus(oc, newNodesName[0], "Ready")
		checkNodeStatus(oc, newNodesName[1], "Ready")

		// Check all nodes created have egress-assignable label
		nodeList := compat_otp.GetNodeListByLabel(oc, egressNodeLabel)
		o.Expect(len(nodeList)).NotTo(o.And((o.Equal(0)), o.BeNumerically("<", 2)))
		o.Expect(contains(nodeList, newNodesName[0])).To(o.BeTrue())
		o.Expect(contains(nodeList, newNodesName[1])).To(o.BeTrue())

		compat_otp.By("Verify egressIP can be assigned to new nodes and egressIP works.\n")
		compat_otp.By("4. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, newNodesName[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-61582",
			template:  egressIPTemplate,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		o.Expect(len(egressIPMaps1)).Should(o.Equal(2))
		e2e.Logf("egressIPMaps1: %v", egressIPMaps1)

		compat_otp.By("5. Get a namespace, label the namespace\n")
		ns1 := oc.Namespace()
		compat_otp.By("Set namespace as privileged for Hostnetworked Sniffer Pods")
		compat_otp.SetNamespacePrivileged(oc, ns1)

		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Output()
		_, err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6. Create a test pod in the namespace. \n")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("7. Check source IP from the test pod is one of the two egressIP.\n")
		compat_otp.By("7.1 Use tcpdump to verify egressIP, add additional label tcpdump=true to the machinepool first.\n")
		defer machinePoolService.EditMachinePool(clusterID, machinePoolName, "--labels=")
		_, err = machinePoolService.EditMachinePool(clusterID, machinePoolName, "--labels=k8s.ovn.org/egress-assignable=true,tcpdump=true")
		o.Expect(err).To(o.BeNil())
		output, err = machinePoolService.ListMachinePool(clusterID)
		o.Expect(err).To(o.BeNil())
		o.Expect(output.String()).To(o.And(o.ContainSubstring("k8s.ovn.org/egress-assignable=true"), o.ContainSubstring("tcpdump=true")))

		compat_otp.By("7.2 Create tcpdump sniffer Daemonset.\n")
		primaryInf, infErr := getSnifPhyInf(oc, newNodesName[0])
		o.Expect(infErr).NotTo(o.HaveOccurred())
		dstHost := nslookDomainName("ifconfig.me")
		defer deleteTcpdumpDS(oc, "tcpdump-61582", ns1)
		tcpdumpDS, snifErr := createSnifferDaemonset(oc, ns1, "tcpdump-61582", "tcpdump", "true", dstHost, primaryInf, 80)
		o.Expect(snifErr).NotTo(o.HaveOccurred())

		compat_otp.By("7.3 Check source IP from the test pod is randomly one of egress ips.\n")
		egressipErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			randomStr, url := getRequestURL(dstHost)
			_, err := execCommandInSpecificPod(oc, pod1.namespace, pod1.name, "for i in {1..10}; do curl -s "+url+" --connect-timeout 5 ; sleep 2;echo ;done")
			o.Expect(err).NotTo(o.HaveOccurred())
			if checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[0], true) != nil || checkMatchedIPs(oc, ns1, tcpdumpDS.name, randomStr, freeIPs[1], true) != nil || err != nil {
				e2e.Logf("No matched egressIPs in tcpdump log, try next round.")
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to get either EgressIP %s or %s in tcpdump", freeIPs[0], freeIPs[1]))
	})

})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP StressTest ", func() {
	//This case will only be run in perf stress ci which can be deployed for scale number pods for stress testing.
	defer g.GinkgoRecover()

	var (
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		oc              = compat_otp.NewCLI("networking-egressip-stress-"+getRandomString(), compat_otp.KubeConfigPath())
	)
	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-Longduration-NonPreRelease-High-73694-No stale snat rules left after egressIP failover. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP1Template := filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")

		compat_otp.By("1 Get list of nodes \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		ok, egressNodes := getTwoNodesSameSubnet(oc, nodeList)
		if !ok || egressNodes == nil || len(egressNodes) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("2 Apply EgressLabel Key to one node. \n")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNodes[1], egressNodeLabel, "true")

		compat_otp.By("3. create new namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("4. Apply label to namespace\n")
		scalePodNum := "800"
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		compat_otp.By("5. Create test pods and scale test pods to 800 \n")
		createResourceFromFile(oc, ns1, testPodFile)
		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas="+scalePodNum, "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		compat_otp.By("6. Create an egressip object\n")
		freeIPs := findFreeIPs(oc, egressNodes[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip1 := egressIPResource1{
			name:      "egressip-73694",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressip/egressip-73694", "-p", "{\"spec\":{\"egressIPs\":[\""+freeIPs[0]+"\"]}}", "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		for i := 0; i < 2; i++ {
			//Reboot egress node for 2 times
			compat_otp.By("Get current egress node and failover node")
			egressIPMaps := getAssignedEIPInEIPObject(oc, egressip1.name)
			currentEgressNode := egressIPMaps[0]["node"]
			var nextEgressNode string
			if currentEgressNode == egressNodes[0] {
				nextEgressNode = egressNodes[1]
			} else {
				nextEgressNode = egressNodes[0]
			}

			compat_otp.By("5.Reboot egress node.\n")
			defer checkNodeStatus(oc, currentEgressNode, "Ready")
			rebootNode(oc, currentEgressNode)
			checkNodeStatus(oc, currentEgressNode, "NotReady")
			checkNodeStatus(oc, currentEgressNode, "Ready")
			err = waitForPodWithLabelReady(oc, ns1, "name=test-pods")
			compat_otp.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

			compat_otp.By("5. Check EgressIP assigned to the second egress node.\n")
			o.Eventually(func() bool {
				egressIPMaps = getAssignedEIPInEIPObject(oc, egressip1.name)
				return len(egressIPMaps) == 1 && egressIPMaps[0]["node"] == nextEgressNode
			}, "300s", "10s").Should(o.BeTrue(), "egressIP was not migrated to second egress node after unlabel first egress node!!")

			compat_otp.By("6. Check snat in northdb. \n")
			ovnPod := ovnkubeNodePod(oc, nextEgressNode)
			newSnatCmd := "ovn-nbctl --format=csv find nat external_ids:name=" + egressip1.name + " | grep " + nextEgressNode + " | wc -l"
			o.Eventually(func() bool {
				output, cmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnPod, "ovn-controller", newSnatCmd)
				e2e.Logf("The snat rules for egressIP related to %s number is %s", nextEgressNode, output)
				return cmdErr == nil && output == scalePodNum
			}, "120s", "10s").Should(o.BeTrue(), "The command check result in ovndb is not expected!")

			staleSnatCmd := "ovn-nbctl --format=csv find nat external_ids:name=" + egressip1.name + " | grep " + currentEgressNode + " | wc -l"
			o.Eventually(func() bool {
				output, cmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnPod, "ovn-controller", staleSnatCmd)
				e2e.Logf("The snat rules for egressIP related to %s number is %s", currentEgressNode, output)
				return cmdErr == nil && output == "0"
			}, "120s", "10s").Should(o.BeTrue(), "The command check result in ovndb is not expected!")
		}
	})

})

var _ = g.Describe("[OTP][sig-networking] SDN OVN EgressIP rdu1", func() {
	defer g.GinkgoRecover()

	var (
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		exteranlHost    = "10.8.1.181"
		exterGWIntf     = "sriovbm"
	)

	g.BeforeEach(func() {
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com")) {
			g.Skip("This case will only run on rdu1 cluster , skip for other envrionment!!!")
		}

	})

	// author: yingwang@redhat.com
	g.It("Author:yingwang-NonHyperShiftHOST-Medium-73641-[rducluster]external traffic direct to pod can work with EgressIP applied. [Disruptive]", func() {

		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodTmpFile      = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressIPTemplate    = filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
			testpodLable        = "hello-pod"
			podLabelKey         = "color"
			podLabelValue       = "blue"
			nsLabelKey          = "name"
			nsLabelValue        = "test"
		)

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("create 2 pods\n")
		workers := compat_otp.GetNodeListByLabel(oc, "node-role.kubernetes.io/worker")
		if len(workers) < 2 {
			g.Skip("The prerequirement was not fullfilled, skip the case!!")
		}

		//create pods on different worker nodes.
		testPod1 := networkingRes{
			name:      "testpod1",
			namespace: ns1,
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}

		testPod2 := networkingRes{
			name:      "testpod2",
			namespace: ns1,
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}

		defer removeResource(oc, true, true, "pod", testPod1.name, "-n", testPod1.namespace)
		testPod1.create(oc, "NAME="+testPod1.name, "NAMESPACE="+testPod1.namespace, "NODENAME="+workers[0])
		defer removeResource(oc, true, true, "pod", testPod2.name, "-n", testPod2.namespace)
		testPod2.create(oc, "NAME="+testPod2.name, "NAMESPACE="+testPod2.namespace, "NODENAME="+workers[1])

		errPodRdy := waitForPodWithLabelReady(oc, ns1, "name="+testpodLable)
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpodn isn't ready"))

		podLable := podLabelKey + "=" + podLabelValue
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("pod", testPod1.name, "-n", testPod1.namespace, podLable).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("pod", testPod2.name, "-n", testPod2.namespace, podLable).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		podIP1 := getPodIPv4(oc, ns1, testPod1.name)
		podIP2 := getPodIPv4(oc, ns1, testPod2.name)

		compat_otp.By("Apply label to namespace\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create an egressip object\n")

		compat_otp.By("1.2 Apply EgressLabel Key to one node.")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)

		freeIPs := findFreeIPs(oc, workers[0], 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip1 := egressIPResource1{
			name:          "egressip-66297",
			template:      egressIPTemplate,
			egressIP1:     freeIPs[0],
			nsLabelKey:    nsLabelKey,
			nsLabelValue:  nsLabelValue,
			podLabelKey:   podLabelKey,
			podLabelValue: podLabelValue,
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject2(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip1.name, 1)

		//config direct route to pod on external host
		defer rmRouteOnExternalHost(oc, exteranlHost, "root", testPod1.name, ns1)
		res1 := cfgRouteOnExternalHost(oc, exteranlHost, "root", testPod1.name, ns1, exterGWIntf)
		o.Expect(res1).To(o.BeTrue())
		defer rmRouteOnExternalHost(oc, exteranlHost, "root", testPod2.name, ns1)
		res2 := cfgRouteOnExternalHost(oc, exteranlHost, "root", testPod2.name, ns1, exterGWIntf)
		o.Expect(res2).To(o.BeTrue())

		externalHostCmd1 := "ping -c 5 " + podIP1
		externalHostCmd2 := "ping -c 5 " + podIP2

		outPut1, err1 := sshRunCmdOutPut(exteranlHost, "root", externalHostCmd1)
		e2e.Logf("traffic from external direct to pod1 result is %v", outPut1)
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(outPut1).To(o.ContainSubstring(`64 bytes from`))
		outPut2, err2 := sshRunCmdOutPut(exteranlHost, "root", externalHostCmd2)
		e2e.Logf("traffic from external direct to pod2 result is %v", outPut2)
		o.Expect(err2).NotTo(o.HaveOccurred())
		o.Expect(outPut2).To(o.ContainSubstring(`64 bytes from`))

	})

	// author: yingwang@redhat.com
	g.It("Author:yingwang-NonHyperShiftHOST-Medium-73625-[rducluster]external traffic can access MetalLB service when EgressIP is applied and service ETP=local. [Disruptive]", func() {
		var (
			networkBaseDir     = testdata.FixturePath("networking")
			testDataMetallbDir = testdata.FixturePath("networking/metallb")

			mlNSTemplate            = filepath.Join(testDataMetallbDir, "namespace-template.yaml")
			mlOperatorGroupTemplate = filepath.Join(testDataMetallbDir, "operatorgroup-template.yaml")
			mlSubscriptionTemplate  = filepath.Join(testDataMetallbDir, "subscription-template.yaml")
			mlNs                    = "metallb-system"
			exteranlHost            = "10.8.1.181"
			metalLBNodeSelKey       = "node-role.kubernetes.io/worker"
			metalLBNodeSelVal       = ""
			metalLBControllerSelKey = "node-role.kubernetes.io/worker"
			metalLBControllerSelVal = ""
			podLabelKey             string
			podLabelValue           string
			nsLabelKey              = "name"
			nsLabelValue            = "test"
		)

		workers := compat_otp.GetNodeListByLabel(oc, "node-role.kubernetes.io/worker")
		if len(workers) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		freeIPs := findFreeIPs(oc, workers[0], 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))

		compat_otp.By("create new namespace\n")
		ns1 := oc.Namespace()

		compat_otp.By("install Metallb operator\n")

		sub := subscriptionResource{
			name:             "metallb-operator-sub",
			namespace:        mlNs,
			operatorName:     "metallb-operator",
			channel:          "stable",
			catalog:          "qe-app-registry",
			catalogNamespace: "openshift-marketplace",
			template:         mlSubscriptionTemplate,
		}
		ns := namespaceResource{
			name:     mlNs,
			template: mlNSTemplate,
		}
		og := operatorGroupResource{
			name:             "metallb-operator",
			namespace:        mlNs,
			targetNamespaces: "metallb-system",
			template:         mlOperatorGroupTemplate,
		}
		catalogSource := getOperatorSource(oc, "openshift-marketplace")
		if catalogSource == "" {
			g.Skip("Skip testing as auto-release-app-registry/qe-app-registry not found")
		}
		sub.catalog = catalogSource
		operatorInstall(oc, sub, ns, og)
		g.By("Making sure CRDs are successfully installed")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		o.Expect(output).Should(
			o.And(
				o.ContainSubstring("bfdprofiles.metallb.io"),
				o.ContainSubstring("bgpadvertisements.metallb.io"),
				o.ContainSubstring("bgppeers.metallb.io"),
				o.ContainSubstring("communities.metallb.io"),
				o.ContainSubstring("ipaddresspools.metallb.io"),
				o.ContainSubstring("l2advertisements.metallb.io"),
				o.ContainSubstring("metallbs.metallb.io"),
			))

		compat_otp.By("1. Create MetalLB CR")
		metallbCRTemplate := filepath.Join(testDataMetallbDir, "metallb-cr-template.yaml")
		metallbCR := metalLBCRResource{
			name:                  "metallb",
			namespace:             mlNs,
			nodeSelectorKey:       metalLBNodeSelKey,
			nodeSelectorVal:       metalLBNodeSelVal,
			controllerSelectorKey: metalLBControllerSelKey,
			controllerSelectorVal: metalLBControllerSelVal,
			template:              metallbCRTemplate,
		}

		defer removeResource(oc, true, true, "metallb", metallbCR.name, "-n", metallbCR.namespace)
		result := createMetalLBCR(oc, metallbCR, metallbCRTemplate)
		o.Expect(result).To(o.BeTrue())
		compat_otp.By("SUCCESS - MetalLB CR Created")

		compat_otp.By("2. Create IP addresspool")
		ipAddresspoolTemplate := filepath.Join(networkBaseDir, "metallb-ipaddresspool-template.yaml")
		ipAddresspool := networkingRes{
			name:      "ippool-" + getRandomString(),
			namespace: mlNs,
			kind:      "ipddresspool",
			tempfile:  ipAddresspoolTemplate,
		}
		ipAddr := freeIPs[0] + "/32"
		defer removeResource(oc, true, true, "IPAddressPool", ipAddresspool.name, "-n", ipAddresspool.namespace)
		ipAddresspool.create(oc, "NAME="+ipAddresspool.name, "NAMESPACE="+ipAddresspool.namespace, "ADDRESS="+ipAddr)

		l2AdTemplate := filepath.Join(networkBaseDir, "metallb-l2advertisement-template.yaml")
		l2Ad := networkingRes{
			name:      "l2ad-" + getRandomString(),
			namespace: mlNs,
			kind:      "L2Advertisement",
			tempfile:  l2AdTemplate,
		}

		defer removeResource(oc, true, true, "L2Advertisement", l2Ad.name, "-n", l2Ad.namespace)
		l2Ad.create(oc, "NAME="+l2Ad.name, "NAMESPACE="+l2Ad.namespace, "IPADDRESSPOOL="+ipAddresspool.name)

		compat_otp.By("3. Create a service with annotation to obtain IP from first addresspool")
		loadBalancerServiceAnnotatedTemplate := filepath.Join(testDataMetallbDir, "loadbalancer-svc-annotated-template.yaml")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-73625",
			namespace:                     ns1,
			externaltrafficpolicy:         "Local",
			labelKey:                      "environ",
			labelValue:                    "Prod",
			annotationKey:                 "metallb.universe.tf/address-pool",
			annotationValue:               ipAddresspool.name,
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceAnnotatedTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP for OCP-73625 test case is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, freeIPs[0])).To(o.BeTrue())

		compat_otp.By("SUCCESS - Services created successfully")

		compat_otp.By("Apply label to namespace\n")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name-").Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "name=test").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4. Create an egressip object\n")

		compat_otp.By("Apply EgressLabel Key to one node.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")

		egressIPTemplate := filepath.Join(networkBaseDir, "egressip-config2-template.yaml")
		podLabelKey = "name"
		podLabelValue = svc.name
		egressip := egressIPResource1{
			name:          "egressip-" + getRandomString(),
			template:      egressIPTemplate,
			egressIP1:     freeIPs[1],
			nsLabelKey:    nsLabelKey,
			nsLabelValue:  nsLabelValue,
			podLabelKey:   podLabelKey,
			podLabelValue: podLabelValue,
		}
		defer egressip.deleteEgressIPObject1(oc)
		egressip.createEgressIPObject2(oc)
		verifyExpectedEIPNumInEIPObject(oc, egressip.name, 1)

		externalHostCmd := "curl -k " + freeIPs[0] + ":80"

		outPut, err := sshRunCmdOutPut(exteranlHost, "root", externalHostCmd)
		e2e.Logf("traffic from external direct to pod1 result is %v", outPut)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(outPut, "Hello OpenShift")).To(o.BeTrue())

	})

})

var _ = g.Describe("[OTP][sig-networking] SDN EgressIP generic", func() {
	//Test cases in this function do not need external bashion host, and can be run with any ipstack type
	defer g.GinkgoRecover()

	var (
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		oc              = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
	)

	g.BeforeEach(func() {

		platform := compat_otp.CheckPlatform(oc)
		networkType := checkNetworkType(oc)
		e2e.Logf("\n\nThe platform is %v,  networkType is %v\n", platform, networkType)

		acceptedPlatform := strings.Contains(platform, "aws") || strings.Contains(platform, "gcp") || strings.Contains(platform, "openstack") || strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "azure") || strings.Contains(platform, "none") || strings.Contains(platform, "nutanix") || strings.Contains(platform, "powervs")
		if !acceptedPlatform || !strings.Contains(networkType, "ovn") {
			g.Skip("Test cases should be run on AWS/GCP/Azure/Openstack/Vsphere/BareMetal/Nutanix/Powervs cluster with ovn network plugin, skip for other platforms or other non-OVN network plugin!!")
		}
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-NonPreRelease-High-78663-Pods on default network and UDNs if applicable can access k8s service when its node is egressIP node [Serial]", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressIP1Template   = filepath.Join(buildPruningBaseDir, "egressip-config1-template.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			allNS               []string
			udnNS               []string
		)

		compat_otp.By("1. Get node list")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		var egressNode1, egressNode2, nonEgressNode string
		var freeIPs []string
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" && len(nodeList.Items) < 3 {
			g.Skip("Need 3 nodes for the test on dualstack cluster, the prerequirement was not fullfilled, skip the case!!")
		} else if (ipStackType == "ipv4single" || ipStackType == "ipv6single") && len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test on singlev4 or singlev6 cluster, the prerequirement was not fullfilled, skip the case!!")
		}

		compat_otp.By("2.1 Get a namespace for default network.  If NetworkSegmentation featuregate is enabled, create four more namespaces for two overlapping layer3 UDNs and overlapping layer2 UDNs")
		ns1 := oc.Namespace()
		allNS = append(allNS, ns1)

		udnEnabled, _ := IsFeaturegateEnabled(oc, "NetworkSegmentation")

		// if NetworkSegmentation featuregate is enabled, create labelled UDN namespaces for UDNs
		if udnEnabled {
			for i := 0; i < 4; i++ {
				oc.CreateNamespaceUDN()
				ns := oc.Namespace()
				allNS = append(allNS, ns)
				udnNS = append(udnNS, ns)
			}
		}

		compat_otp.By("2.2 Apply a label to all namespaces that matches namespaceSelector defined in egressIP object")
		for _, ns := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name=test").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		if udnEnabled {
			compat_otp.By("2.2. Create two overlapping layer3 UDNs between ns2, ns3, create two overlapping layer2 UDN between ns4, ns5")
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
			for i := 0; i < 2; i++ {
				createGeneralUDNCRD(oc, udnNS[i], "udn-network-layer3-"+udnNS[i], ipv4cidr, ipv6cidr, cidr, "layer3")
				createGeneralUDNCRD(oc, udnNS[i+2], "udn-network-layer2-"+udnNS[i+2], ipv4cidr, ipv6cidr, cidr, "layer2")
			}
		}

		compat_otp.By("3. Apply EgressLabel Key to egressNode.  Two egress nodes are needed for dualstack egressIP object")
		if ipStackType == "dualstack" {
			egressNode1 = nodeList.Items[0].Name
			egressNode2 = nodeList.Items[1].Name
			nonEgressNode = nodeList.Items[2].Name
			freeIPs = findFreeIPs(oc, egressNode1, 1)
			o.Expect(len(freeIPs)).Should(o.Equal(1))
			freeIPv6s := findFreeIPv6s(oc, egressNode2, 1)
			o.Expect(len(freeIPv6s)).Should(o.Equal(1))
			freeIPs = append(freeIPs, freeIPv6s[0])
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		} else if ipStackType == "ipv6single" {
			egressNode1 = nodeList.Items[0].Name
			nonEgressNode = nodeList.Items[1].Name
			freeIPs = findFreeIPv6s(oc, egressNode1, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		} else if ipStackType == "ipv4single" {
			egressNode1 = nodeList.Items[0].Name
			nonEgressNode = nodeList.Items[1].Name
			freeIPs = findFreeIPs(oc, egressNode1, 2)
			o.Expect(len(freeIPs)).Should(o.Equal(2))
		}
		e2e.Logf("egressIPs to use: %s", freeIPs)
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")

		compat_otp.By("4. Create an egressip object")
		egressip1 := egressIPResource1{
			name:      "egressip-78663",
			template:  egressIP1Template,
			egressIP1: freeIPs[0],
			egressIP2: freeIPs[1],
		}
		defer egressip1.deleteEgressIPObject1(oc)
		egressip1.createEgressIPObject1(oc)

		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressip1.name)
		var assignedEIPNodev4, assignedEIPNodev6, assignedEIPNode string
		if ipStackType == "dualstack" {
			o.Expect(len(egressIPMaps1) == 2).Should(o.BeTrue())
			for _, eipMap := range egressIPMaps1 {
				if netutils.IsIPv4String(eipMap["egressIP"]) {
					assignedEIPNodev4 = eipMap["node"]
				}
				if netutils.IsIPv6String(eipMap["egressIP"]) {
					assignedEIPNodev6 = eipMap["node"]
				}
			}
			o.Expect(assignedEIPNodev4).NotTo(o.Equal(""))
			o.Expect(assignedEIPNodev6).NotTo(o.Equal(""))
			e2e.Logf("For the dualstack EIP,  v4 EIP is currently assigned to node: %s, v6 EIP is currently assigned to node: %s", assignedEIPNodev4, assignedEIPNodev6)
		} else {
			o.Expect(len(egressIPMaps1) == 1).Should(o.BeTrue())
			assignedEIPNode = egressNode1
		}

		compat_otp.By("5. On each of egress node(s) and nonEgressNode, create a test pod, curl k8s service from each pod")
		var nodeNames []string
		if ipStackType == "dualstack" {
			nodeNames = []string{assignedEIPNodev4, assignedEIPNodev6, nonEgressNode}
		} else {
			nodeNames = []string{assignedEIPNode, nonEgressNode}
		}
		e2e.Logf("nodeNames: %s , length of nodeName is: %d", nodeNames, len(nodeNames))

		var testpods [5][3]pingPodResourceNode
		for j := 0; j < len(allNS); j++ {
			for i := 0; i < len(nodeNames); i++ {
				testpods[j][i] = pingPodResourceNode{
					name:      "hello-pod" + strconv.Itoa(i) + "-" + allNS[j],
					namespace: allNS[j],
					nodename:  nodeNames[i],
					template:  pingPodNodeTemplate,
				}
				testpods[j][i].createPingPodNode(oc)
				waitPodReady(oc, allNS[j], testpods[j][i].name)
			}
		}

		svcIP1, svcIP2 := getSvcIP(oc, "default", "kubernetes")
		e2e.Logf("k8s service has IP(s) as svcIP1: %s, svcIP2: %s", svcIP1, svcIP2)

		var curlCmd string
		if svcIP2 != "" {
			curlCmdv6 := fmt.Sprintf("curl -I -k -v https://[%s]:443/api?timeout=32s", svcIP1)
			curlCmdv4 := fmt.Sprintf("curl -I -k -v https://%s:443/api?timeout=32s", svcIP2)
			for j := 0; j < len(allNS); j++ {
				for i := 0; i < len(nodeNames); i++ {
					_, curlErr := e2eoutput.RunHostCmd(testpods[j][i].namespace, testpods[j][i].name, curlCmdv6)
					o.Expect(curlErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to curl k8s service from pod %s", testpods[j][i].name))
					_, curlErr = e2eoutput.RunHostCmd(testpods[j][i].namespace, testpods[j][i].name, curlCmdv4)
					o.Expect(curlErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to curl k8s service from pod %s", testpods[j][i].name))
				}
			}
		} else {
			curlCmd = fmt.Sprintf("curl -I -k -v https://%s/api?timeout=32s", net.JoinHostPort(svcIP1, "443"))
			for j := 0; j < len(allNS); j++ {
				for i := 0; i < len(nodeNames); i++ {
					_, curlErr := e2eoutput.RunHostCmd(testpods[j][i].namespace, testpods[j][i].name, curlCmd)
					o.Expect(curlErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to curl k8s service from pod %s", testpods[j][i].name))
				}
			}
		}
	})

})
