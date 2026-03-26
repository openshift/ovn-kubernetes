package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"path/filepath"
	"strconv"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[OTP][sig-networking] SDN ovs hardware offload", func() {
	defer g.GinkgoRecover()

	var (
		oc = compat_otp.NewCLI("ovsoffload-"+getRandomString(), compat_otp.KubeConfigPath())
		//deviceID  = "101d"
		vendorID            = "15b3"
		sriovOpNs           = "openshift-sriov-network-operator"
		sriovPoolConfigName = "sriovnetworkpoolconfig-offload"

		networkBaseDir          string
		sriovBaseDir            string
		iperfServerTmp          string
		iperfClientTmp          string
		iperfNormalServerTmp    string
		iperfNormalClientTmp    string
		iperfSvcTmp             string
		iperfServerTmp_v6       string
		iperfNormalServerTmp_v6 string
		iperfSvcTmp_v6          string
		ipStackType             string
	)
	g.BeforeEach(func() {
		// for now skip sriov cases in temp in order to avoid cases always show failed in CI since sriov operator is not setup . will add install operator function after that
		_, err := oc.AdminKubeClient().CoreV1().Namespaces().Get(context.Background(), "openshift-sriov-network-operator", metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				g.Skip("the cluster does not install sriov operator")
			}
		}
		if !chkSriovPoolConfig(oc, sriovOpNs, sriovPoolConfigName) {
			g.Skip("the cluster does not configure sriovnetworkpoolconfigs. skip this testing!")
		}
		networkBaseDir = testdata.FixturePath("networking")
		sriovBaseDir = filepath.Join(networkBaseDir, "sriov")
		iperfServerTmp = filepath.Join(sriovBaseDir, "iperf-server-template.json")
		iperfClientTmp = filepath.Join(sriovBaseDir, "iperf-rc-template.json")
		iperfNormalServerTmp = filepath.Join(sriovBaseDir, "iperf-server-normal-template.json")
		iperfNormalClientTmp = filepath.Join(sriovBaseDir, "iperf-rc-normal-template.json")
		iperfSvcTmp = filepath.Join(sriovBaseDir, "iperf-service-template.json")

		iperfServerTmp_v6 = filepath.Join(sriovBaseDir, "iperf-server-ipv6-template.json")
		iperfNormalServerTmp_v6 = filepath.Join(sriovBaseDir, "iperf-server-ipv6-normal-template.json")
		iperfSvcTmp_v6 = filepath.Join(sriovBaseDir, "iperf-service-ipv6-template.json")
		ipStackType = checkIPStackType(oc)
		e2e.Logf("This cluster is %s OCP", ipStackType)

	})
	g.It("NonPreRelease-Longduration-Author:yingwang-Medium-45390-pod to pod traffic in different hosts can work well with ovs hw offload as default network [Disruptive]", func() {
		var (
			sriovNetPolicyName = "sriovoffloadpolicy"
			sriovNetDeviceName = "sriovoffloadnetattchdef"
			//pfName             = "ens1f0"
			workerNodeList = getOvsHWOffloadWokerNodes(oc)
			pfName         = getHWoffloadPF(oc, workerNodeList[0])
			hostnwPod0Name = "hostnw-pod-45390-worker0"
			hostnwPod1Name = "hostnw-pod-45390-worker1"
		)

		oc.SetupProject()
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())

		sriovNetPolicyTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadpolicy-template.yaml")
		sriovNetPolicy := sriovNetResource{
			name:      sriovNetPolicyName,
			namespace: sriovOpNs,
			kind:      "SriovNetworkNodePolicy",
			tempfile:  sriovNetPolicyTmpFile,
		}

		sriovNetworkAttachTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadnetattchdef-template.yaml")
		sriovNetwork := sriovNetResource{
			name:      sriovNetDeviceName,
			namespace: oc.Namespace(),
			tempfile:  sriovNetworkAttachTmpFile,
			kind:      "network-attachment-definitions",
		}

		defaultOffloadNet := oc.Namespace() + "/" + sriovNetwork.name
		offloadNetType := "v1.multus-cni.io/default-network"

		compat_otp.By("1) ####### Check openshift-sriov-network-operator is running well ##########")
		chkSriovOperatorStatus(oc, sriovOpNs)

		compat_otp.By("2) ####### Check sriov network policy ############")
		//check if sriov network policy is created or not. If not, create one.
		if !sriovNetPolicy.chkSriovPolicy(oc) {
			sriovNetPolicy.create(oc, "VENDOR="+vendorID, "PFNAME="+pfName, "SRIOVNETPOLICY="+sriovNetPolicy.name)
			defer rmSriovNetworkPolicy(oc, sriovNetPolicy.name, sriovNetPolicy.namespace)
		}
		waitForOffloadSriovPolicyReady(oc, sriovNetPolicy.namespace)

		compat_otp.By("3) ######### Create sriov network attachment ############")

		e2e.Logf("create sriov network attachment via template")
		sriovNetwork.create(oc, "NAMESPACE="+oc.Namespace(), "NETNAME="+sriovNetwork.name, "SRIOVNETPOLICY="+sriovNetPolicy.name)
		defer sriovNetwork.delete(oc)

		compat_otp.By("4) ########### Create iperf Server and client Pod on same host and attach sriov VF as default interface ##########")

		iperfServerPod := sriovNetResource{
			name:      "iperf-server",
			namespace: oc.Namespace(),
			tempfile:  iperfServerTmp,
			kind:      "pod",
		}
		//create iperf server pod with ovs hwoffload vf on worker0
		iperfServerPod.create(oc, "PODNAME="+iperfServerPod.name, "NAMESPACE="+iperfServerPod.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
		defer iperfServerPod.delete(oc)
		errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server")
		compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

		iperfServerIP := getPodIPv4(oc, oc.Namespace(), iperfServerPod.name)
		iperfServerVF := getPodVFPresentor(oc, iperfServerPod.namespace, iperfServerPod.name)

		iperfClientPod := sriovNetResource{
			name:      "iperf-rc",
			namespace: oc.Namespace(),
			tempfile:  iperfClientTmp,
			kind:      "pod",
		}
		//create iperf client pod with ovs hwoffload vf on worker1
		defer iperfClientPod.delete(oc)
		iperfClientPod.create(oc, "PODNAME="+iperfClientPod.name, "NAMESPACE="+iperfClientPod.namespace, "NETNAME="+defaultOffloadNet, "NODENAME="+workerNodeList[1],
			"NETTYPE="+offloadNetType)
		iperfClientName, err := compat_otp.GetPodName(oc, oc.Namespace(), "name=iperf-rc", workerNodeList[1])
		iperfClientPod.name = iperfClientName
		defer iperfClientPod.delete(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		errPodRdy2 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-rc")
		compat_otp.AssertWaitPollNoErr(errPodRdy2, fmt.Sprintf("iperf client pod isn't ready"))

		iperfClientIP := getPodIPv4(oc, oc.Namespace(), iperfClientPod.name)
		iperfClientVF := getPodVFPresentor(oc, iperfClientPod.namespace, iperfClientPod.name)

		compat_otp.By("5) ########### Create iperf Pods with normal default interface ##########")

		iperfServerPod1 := sriovNetResource{
			name:      "iperf-server-normal",
			namespace: oc.Namespace(),
			tempfile:  iperfNormalServerTmp,
			kind:      "pod",
		}
		//create iperf server pod with normal default interface on worker0
		iperfServerPod1.create(oc, "PODNAME="+iperfServerPod1.name, "NAMESPACE="+iperfServerPod1.namespace, "NODENAME="+workerNodeList[0])
		defer iperfServerPod1.delete(oc)
		errPodRdy3 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server-normal")
		compat_otp.AssertWaitPollNoErr(errPodRdy3, fmt.Sprintf("iperf server pod isn't ready"))

		iperfServerIP1 := getPodIPv4(oc, oc.Namespace(), iperfServerPod1.name)

		iperfClientPod1 := sriovNetResource{
			name:      "iperf-rc-normal",
			namespace: oc.Namespace(),
			tempfile:  iperfNormalClientTmp,
			kind:      "pod",
		}
		//create iperf client pod with normal default interface on worker1
		iperfClientPod1.create(oc, "PODNAME="+iperfClientPod1.name, "NAMESPACE="+iperfClientPod1.namespace, "NODENAME="+workerNodeList[1])
		defer iperfClientPod1.delete(oc)
		iperfClientName1, err := compat_otp.GetPodName(oc, oc.Namespace(), "name=iperf-rc-normal", workerNodeList[1])
		iperfClientPod1.name = iperfClientName1

		o.Expect(err).NotTo(o.HaveOccurred())
		errPodRdy4 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-rc-normal")
		compat_otp.AssertWaitPollNoErr(errPodRdy4, fmt.Sprintf("iperf client pod isn't ready"))

		compat_otp.By("6) ########### Create hostnetwork Pods to capture packets ##########")
		//create hostnetwork pod on worker0 and worker1 to capture packets
		hostnwPodTmp := filepath.Join(sriovBaseDir, "net-admin-cap-pod-template.yaml")
		hostnwPod0 := sriovNetResource{
			name:      hostnwPod0Name,
			namespace: oc.Namespace(),
			tempfile:  hostnwPodTmp,
			kind:      "pod",
		}

		hostnwPod1 := sriovNetResource{
			name:      hostnwPod1Name,
			namespace: oc.Namespace(),
			tempfile:  hostnwPodTmp,
			kind:      "pod",
		}
		//create hostnetwork pods on worker0 and worker1 to capture packets
		hostnwPod0.create(oc, "PODNAME="+hostnwPod0.name, "NODENAME="+workerNodeList[0])
		defer hostnwPod0.delete(oc)
		hostnwPod1.create(oc, "PODNAME="+hostnwPod1.name, "NODENAME="+workerNodeList[1])
		defer hostnwPod1.delete(oc)
		errPodRdy5 := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+hostnwPod0.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy5, fmt.Sprintf("hostnetwork pod isn't ready"))
		errPodRdy6 := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+hostnwPod1.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy6, fmt.Sprintf("hostnetwork pod isn't ready"))

		compat_otp.By("7) ########### Check Bandwidth between iperf client and iperf server pods ##########")
		// enable hardware offload should improve the performance
		// get throughput on pods which attached hardware offload enabled VF
		bandWithStr := startIperfTraffic(oc, iperfClientPod.namespace, iperfClientPod.name, iperfServerIP, "60s")
		bandWidth, paseFloatErr := strconv.ParseFloat(bandWithStr, 32)
		o.Expect(paseFloatErr).NotTo(o.HaveOccurred())
		// get throughput on pods with normal default interface
		bandWithStr1 := startIperfTraffic(oc, iperfClientPod1.namespace, iperfClientPod1.name, iperfServerIP1, "60s")
		bandWidth1, paseFloatErr1 := strconv.ParseFloat(bandWithStr1, 32)
		o.Expect(paseFloatErr1).NotTo(o.HaveOccurred())

		o.Expect(float64(bandWidth)).Should(o.BeNumerically(">", float64(bandWidth1)))

		compat_otp.By("8) ########### Capture packtes on hostnetwork pod ##########")
		//send traffic and capture traffic on iperf VF presentor on worker node and iperf server pod
		startIperfTrafficBackground(oc, iperfClientPod.namespace, iperfClientPod.name, iperfServerIP, "150s")
		// VF presentors should not be able to capture packets after hardware offload take effect（the begining packts can be captured.
		chkCapturePacketsOnIntf(oc, hostnwPod1.namespace, hostnwPod1.name, iperfClientVF, iperfClientIP, "0")
		chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfServerVF, iperfClientIP, "0")
		// iperf server pod should be able to capture packtes
		chkCapturePacketsOnIntf(oc, iperfServerPod.namespace, iperfServerPod.name, "eth0", iperfClientIP, "10")

		if ipStackType == "dualstack" {

			compat_otp.By("9) ########### Create ipv6 iperf Server and client Pod on same host and attach sriov VF as default interface ##########")
			iperfServerPodv6 := sriovNetResource{
				name:      "iperf-server-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfServerTmp_v6,
				kind:      "pod",
			}
			//create iperf server pod with ovs hwoffload vf on worker0
			iperfServerPodv6.create(oc, "PODNAME="+iperfServerPodv6.name, "NAMESPACE="+iperfServerPodv6.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
			defer iperfServerPodv6.delete(oc)
			errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server-ipv6")
			compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

			iperfServerIPv6 := getPodIPv6(oc, oc.Namespace(), iperfServerPodv6.name, "dualstack")
			iperfServerVF := getPodVFPresentor(oc, iperfServerPodv6.namespace, iperfServerPodv6.name)

			iperfClientIPv6 := getPodIPv6(oc, oc.Namespace(), iperfClientPod.name, "dualstack")

			compat_otp.By("10) ########### Create ipv6 iperf Pods with normal default interface ##########")
			iperfServerPodv6_1 := sriovNetResource{
				name:      "iperf-server-normal-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfNormalServerTmp_v6,
				kind:      "pod",
			}
			//create iperf server pod with normal default interface on worker0
			iperfServerPodv6_1.create(oc, "PODNAME="+iperfServerPodv6_1.name, "NAMESPACE="+iperfServerPodv6_1.namespace, "NODENAME="+workerNodeList[0])
			defer iperfServerPodv6_1.delete(oc)
			errPodRdy3 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server-normal-ipv6")
			compat_otp.AssertWaitPollNoErr(errPodRdy3, fmt.Sprintf("iperf server pod isn't ready"))

			iperfServerIPv6_1 := getPodIPv6(oc, oc.Namespace(), iperfServerPodv6_1.name, "dualstack")

			compat_otp.By("11) ########### Check ipv6 traffic Bandwidth between iperf client and iperf server pods ##########")
			// enable hardware offload should improve the performance
			// get throughput on pods which attached hardware offload enabled VF
			bandWithStr := startIperfTraffic(oc, iperfClientPod.namespace, iperfClientPod.name, iperfServerIPv6, "60s")
			bandWidth, paseFloatErr := strconv.ParseFloat(bandWithStr, 32)
			o.Expect(paseFloatErr).NotTo(o.HaveOccurred())
			// get throughput on pods with normal default interface
			bandWithStr1 := startIperfTraffic(oc, iperfClientPod1.namespace, iperfClientPod1.name, iperfServerIPv6_1, "60s")
			bandWidth1, paseFloatErr1 := strconv.ParseFloat(bandWithStr1, 32)
			o.Expect(paseFloatErr1).NotTo(o.HaveOccurred())
			o.Expect(float64(bandWidth)).Should(o.BeNumerically(">", float64(bandWidth1)))

			compat_otp.By("12) ########### Capture packtes on hostnetwork pod ##########")
			//send traffic and capture traffic on iperf VF presentor on worker node and iperf server pod
			startIperfTrafficBackground(oc, iperfClientPod.namespace, iperfClientPod.name, iperfServerIPv6, "150s")
			// VF presentors should not be able to capture packets after hardware offload take effect（the begining packts can be captured.
			chkCapturePacketsOnIntf(oc, hostnwPod1.namespace, hostnwPod1.name, iperfClientVF, iperfClientIPv6, "0")
			chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfServerVF, iperfClientIPv6, "0")
			// iperf server pod should be able to capture packtes
			chkCapturePacketsOnIntf(oc, iperfServerPodv6.namespace, iperfServerPodv6.name, "eth0", iperfClientIPv6, "10")
		}
	})

	g.It("NonPreRelease-Longduration-Author:yingwang-Medium-45388-pod to pod traffic in same host can work well with ovs hw offload as default network [Disruptive]", func() {
		var (
			networkBaseDir = testdata.FixturePath("networking")
			sriovBaseDir   = filepath.Join(networkBaseDir, "sriov")

			sriovNetPolicyName = "sriovoffloadpolicy"
			sriovNetDeviceName = "sriovoffloadnetattchdef"
			sriovOpNs          = "openshift-sriov-network-operator"
			//pfName             = "ens1f0"
			workerNodeList = getOvsHWOffloadWokerNodes(oc)
			hostnwPod0Name = "hostnw-pod-45388-worker0"
			pfName         = getHWoffloadPF(oc, workerNodeList[0])
		)

		oc.SetupProject()
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		sriovNetPolicyTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadpolicy-template.yaml")
		sriovNetPolicy := sriovNetResource{
			name:      sriovNetPolicyName,
			namespace: sriovOpNs,
			kind:      "SriovNetworkNodePolicy",
			tempfile:  sriovNetPolicyTmpFile,
		}

		sriovNetworkAttachTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadnetattchdef-template.yaml")
		sriovNetwork := sriovNetResource{
			name:      sriovNetDeviceName,
			namespace: oc.Namespace(),
			tempfile:  sriovNetworkAttachTmpFile,
			kind:      "network-attachment-definitions",
		}

		defaultOffloadNet := oc.Namespace() + "/" + sriovNetwork.name
		offloadNetType := "v1.multus-cni.io/default-network"

		compat_otp.By("1) ####### Check openshift-sriov-network-operator is running well ##########")
		chkSriovOperatorStatus(oc, sriovOpNs)

		compat_otp.By("2) ####### Check sriov network policy ############")
		//check if sriov network policy is created or not. If not, create one.
		if !sriovNetPolicy.chkSriovPolicy(oc) {
			sriovNetPolicy.create(oc, "VENDOR="+vendorID, "PFNAME="+pfName, "SRIOVNETPOLICY="+sriovNetPolicy.name)
			defer rmSriovNetworkPolicy(oc, sriovNetPolicy.name, sriovNetPolicy.namespace)
		}

		waitForOffloadSriovPolicyReady(oc, sriovNetPolicy.namespace)

		compat_otp.By("3) ######### Create sriov network attachment ############")

		e2e.Logf("create sriov network attachment via template")
		sriovNetwork.create(oc, "NAMESPACE="+oc.Namespace(), "NETNAME="+sriovNetwork.name, "SRIOVNETPOLICY="+sriovNetPolicy.name)
		defer sriovNetwork.delete(oc)

		compat_otp.By("4) ########### Create iperf Server and client Pod on same host and attach sriov VF as default interface ##########")
		iperfServerTmp := filepath.Join(sriovBaseDir, "iperf-server-template.json")
		iperfServerPod := sriovNetResource{
			name:      "iperf-server",
			namespace: oc.Namespace(),
			tempfile:  iperfServerTmp,
			kind:      "pod",
		}
		//create iperf server pod on worker0
		iperfServerPod.create(oc, "PODNAME="+iperfServerPod.name, "NAMESPACE="+iperfServerPod.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
		defer iperfServerPod.delete(oc)
		errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server")
		compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

		iperfServerIP := getPodIPv4(oc, oc.Namespace(), iperfServerPod.name)
		iperfServerVF := getPodVFPresentor(oc, iperfServerPod.namespace, iperfServerPod.name)

		iperfClientTmp := filepath.Join(sriovBaseDir, "iperf-rc-template.json")
		iperfClientPod := sriovNetResource{
			name:      "iperf-rc",
			namespace: oc.Namespace(),
			tempfile:  iperfClientTmp,
			kind:      "pod",
		}
		//create iperf client pod on worker0
		iperfClientPod.create(oc, "PODNAME="+iperfClientPod.name, "NAMESPACE="+iperfClientPod.namespace, "NETNAME="+defaultOffloadNet, "NODENAME="+workerNodeList[0],
			"NETTYPE="+offloadNetType)
		defer iperfClientPod.delete(oc)
		iperfClientName, err := compat_otp.GetPodName(oc, oc.Namespace(), "name=iperf-rc", workerNodeList[0])
		iperfClientPod.name = iperfClientName

		o.Expect(err).NotTo(o.HaveOccurred())
		errPodRdy2 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-rc")
		compat_otp.AssertWaitPollNoErr(errPodRdy2, fmt.Sprintf("iperf client pod isn't ready"))

		iperfClientIP := getPodIPv4(oc, oc.Namespace(), iperfClientPod.name)
		iperfClientVF := getPodVFPresentor(oc, iperfClientPod.namespace, iperfClientPod.name)

		compat_otp.By("5) ########### Create hostnetwork Pods to capture packets ##########")

		hostnwPodTmp := filepath.Join(sriovBaseDir, "net-admin-cap-pod-template.yaml")
		hostnwPod0 := sriovNetResource{
			name:      hostnwPod0Name,
			namespace: oc.Namespace(),
			tempfile:  hostnwPodTmp,
			kind:      "pod",
		}
		//create hostnetwork pod on worker0 to capture packets
		hostnwPod0.create(oc, "PODNAME="+hostnwPod0.name, "NODENAME="+workerNodeList[0])
		defer hostnwPod0.delete(oc)
		errPodRdy3 := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+hostnwPod0.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy3, fmt.Sprintf("hostnetwork pod isn't ready"))

		compat_otp.By("6) ########### Check Bandwidth between iperf client and iperf server pods ##########")
		bandWithStr := startIperfTraffic(oc, iperfClientPod.namespace, iperfClientPod.name, iperfServerIP, "20s")
		bandWidth, paseFloatErr := strconv.ParseFloat(bandWithStr, 32)
		o.Expect(paseFloatErr).NotTo(o.HaveOccurred())
		o.Expect(float64(bandWidth)).Should(o.BeNumerically(">", 0.0))

		compat_otp.By("7) ########### Capture packtes on hostnetwork pod ##########")
		//send traffic and capture traffic on iperf VF presentor on worker node and iperf server pod
		startIperfTrafficBackground(oc, iperfClientPod.namespace, iperfClientPod.name, iperfServerIP, "150s")
		// VF presentors should not be able to capture packets after hardware offload take effect（the begining packts can be captured.
		chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfClientVF, iperfClientIP, "0")
		chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfServerVF, iperfClientIP, "0")
		// iperf server pod should be able to capture packtes
		chkCapturePacketsOnIntf(oc, iperfServerPod.namespace, iperfServerPod.name, "eth0", iperfClientIP, "10")

		if ipStackType == "dualstack" {
			compat_otp.By("8) ########### Create ipv6 perf Server and client Pod on same host and attach sriov VF as default interface ##########")
			iperfServerPodv6 := sriovNetResource{
				name:      "iperf-server-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfServerTmp_v6,
				kind:      "pod",
			}
			//create iperf server pod with ovs hwoffload vf on worker0
			iperfServerPodv6.create(oc, "PODNAME="+iperfServerPodv6.name, "NAMESPACE="+iperfServerPodv6.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
			defer iperfServerPodv6.delete(oc)
			errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server-ipv6")
			compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

			iperfServerIPv6 := getPodIPv6(oc, oc.Namespace(), iperfServerPodv6.name, "dualstack")
			iperfServerVF := getPodVFPresentor(oc, iperfServerPodv6.namespace, iperfServerPodv6.name)

			iperfClientIPv6 := getPodIPv6(oc, oc.Namespace(), iperfClientPod.name, "dualstack")

			compat_otp.By("9) ########### Check ipv6 traffic Bandwidth between iperf client and iperf server pods ##########")
			// enable hardware offload should improve the performance
			// get throughput on pods which attached hardware offload enabled VF
			bandWithStr := startIperfTraffic(oc, iperfClientPod.namespace, iperfClientPod.name, iperfServerIPv6, "60s")
			bandWidth, paseFloatErr := strconv.ParseFloat(bandWithStr, 32)
			o.Expect(paseFloatErr).NotTo(o.HaveOccurred())
			o.Expect(float64(bandWidth)).Should(o.BeNumerically(">", 0.0))

			compat_otp.By("10) ########### Capture packtes on hostnetwork pod ##########")
			//send traffic and capture traffic on iperf VF presentor on worker node and iperf server pod
			startIperfTrafficBackground(oc, iperfClientPod.namespace, iperfClientPod.name, iperfServerIPv6, "150s")
			// VF presentors should not be able to capture packets after hardware offload take effect（the begining packts can be captured.
			chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfClientVF, iperfClientIPv6, "0")
			chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfServerVF, iperfClientIPv6, "0")
			// iperf server pod should be able to capture packtes
			chkCapturePacketsOnIntf(oc, iperfServerPodv6.namespace, iperfServerPodv6.name, "eth0", iperfClientIPv6, "10")
		}

	})

	g.It("NonPreRelease-Longduration-Author:yingwang-Medium-45396-pod to service traffic via cluster ip between diffrent hosts can work well with ovs hw offload as default network [Disruptive]", func() {
		var (
			networkBaseDir = testdata.FixturePath("networking")
			sriovBaseDir   = filepath.Join(networkBaseDir, "sriov")

			sriovNetPolicyName = "sriovoffloadpolicy"
			sriovNetDeviceName = "sriovoffloadnetattchdef"
			sriovOpNs          = "openshift-sriov-network-operator"
			//pfName             = "ens1f0"
			workerNodeList = getOvsHWOffloadWokerNodes(oc)
			hostnwPod0Name = "hostnw-pod-45396-worker0"
			hostnwPod1Name = "hostnw-pod-45396-worker1"
			pfName         = getHWoffloadPF(oc, workerNodeList[0])
		)

		oc.SetupProject()
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		sriovNetPolicyTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadpolicy-template.yaml")
		sriovNetPolicy := sriovNetResource{
			name:      sriovNetPolicyName,
			namespace: sriovOpNs,
			kind:      "SriovNetworkNodePolicy",
			tempfile:  sriovNetPolicyTmpFile,
		}

		sriovNetworkAttachTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadnetattchdef-template.yaml")
		sriovNetwork := sriovNetResource{
			name:      sriovNetDeviceName,
			namespace: oc.Namespace(),
			tempfile:  sriovNetworkAttachTmpFile,
			kind:      "network-attachment-definitions",
		}

		defaultOffloadNet := oc.Namespace() + "/" + sriovNetwork.name
		offloadNetType := "v1.multus-cni.io/default-network"

		compat_otp.By("1) ####### Check openshift-sriov-network-operator is running well ##########")
		chkSriovOperatorStatus(oc, sriovOpNs)

		compat_otp.By("2) ####### Check sriov network policy ############")
		//check if sriov network policy is created or not. If not, create one.
		if !sriovNetPolicy.chkSriovPolicy(oc) {
			sriovNetPolicy.create(oc, "VENDOR="+vendorID, "PFNAME="+pfName, "SRIOVNETPOLICY="+sriovNetPolicy.name)
			defer rmSriovNetworkPolicy(oc, sriovNetPolicy.name, sriovNetPolicy.namespace)
		}

		waitForOffloadSriovPolicyReady(oc, sriovNetPolicy.namespace)

		compat_otp.By("3) ######### Create sriov network attachment ############")

		e2e.Logf("create sriov network attachment via template")
		sriovNetwork.create(oc, "NAMESPACE="+oc.Namespace(), "NETNAME="+sriovNetwork.name, "SRIOVNETPOLICY="+sriovNetPolicy.name)
		defer sriovNetwork.delete(oc)

		compat_otp.By("4) ########### Create iperf Server clusterip service and client Pod on diffenrent hosts and attach sriov VF as default interface ##########")

		iperfSvc := sriovNetResource{
			name:      "iperf-clusterip-service",
			namespace: oc.Namespace(),
			tempfile:  iperfSvcTmp,
			kind:      "service",
		}
		iperfSvcPod := sriovNetResource{
			name:      "iperf-server",
			namespace: oc.Namespace(),
			tempfile:  iperfServerTmp,
			kind:      "pod",
		}
		//create iperf server pod with ovs hwoffload VF on worker0 and create clusterip service
		iperfSvcPod.create(oc, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvcPod.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
		defer iperfSvcPod.delete(oc)
		iperfSvc.create(oc, "SVCTYPE="+"ClusterIP", "SVCNAME="+iperfSvc.name, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvc.namespace)
		defer iperfSvc.delete(oc)
		errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server")
		compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

		iperfSvcIP := getSvcIPv4(oc, oc.Namespace(), iperfSvc.name)
		iperfServerVF := getPodVFPresentor(oc, iperfSvcPod.namespace, iperfSvcPod.name)

		iperfClientTmp := filepath.Join(sriovBaseDir, "iperf-rc-template.json")
		iperfClientPod := sriovNetResource{
			name:      "iperf-rc",
			namespace: oc.Namespace(),
			tempfile:  iperfClientTmp,
			kind:      "pod",
		}
		//create iperf client pod with ovs hw offload VF on worker1
		iperfClientPod.create(oc, "PODNAME="+iperfClientPod.name, "NAMESPACE="+iperfClientPod.namespace, "NETNAME="+defaultOffloadNet, "NODENAME="+workerNodeList[1],
			"NETTYPE="+offloadNetType)
		iperfClientName, err := compat_otp.GetPodName(oc, oc.Namespace(), "name=iperf-rc", workerNodeList[1])
		iperfClientPod.name = iperfClientName
		defer iperfClientPod.delete(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		errPodRdy2 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-rc")
		compat_otp.AssertWaitPollNoErr(errPodRdy2, fmt.Sprintf("iperf client pod isn't ready"))

		iperfClientVF := getPodVFPresentor(oc, iperfClientPod.namespace, iperfClientPod.name)
		iperfClientIP := getPodIPv4(oc, oc.Namespace(), iperfClientPod.name)

		compat_otp.By("5) ########### Create iperf clusterip service and iperf client pod with normal default interface ##########")
		iperfSvc1 := sriovNetResource{
			name:      "iperf-service-normal",
			namespace: oc.Namespace(),
			tempfile:  iperfSvcTmp,
			kind:      "service",
		}
		iperfSvcPod1 := sriovNetResource{
			name:      "iperf-server-normal",
			namespace: oc.Namespace(),
			tempfile:  iperfNormalServerTmp,
			kind:      "pod",
		}
		//create iperf server pod with normal default interface on worker0 and create clusterip service
		iperfSvcPod1.create(oc, "PODNAME="+iperfSvcPod1.name, "NAMESPACE="+iperfSvcPod1.namespace, "NODENAME="+workerNodeList[0])
		defer iperfSvcPod.delete(oc)
		iperfSvc1.create(oc, "SVCTYPE="+"ClusterIP", "SVCNAME="+iperfSvc1.name, "PODNAME="+iperfSvcPod1.name, "NAMESPACE="+iperfSvc1.namespace)
		defer iperfSvc1.delete(oc)
		errPodRdy3 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server-normal")
		compat_otp.AssertWaitPollNoErr(errPodRdy3, fmt.Sprintf("iperf server pod isn't ready"))

		iperfSvcIP1 := getSvcIPv4(oc, oc.Namespace(), iperfSvc1.name)

		iperfClientPod1 := sriovNetResource{
			name:      "iperf-rc-normal",
			namespace: oc.Namespace(),
			tempfile:  iperfNormalClientTmp,
			kind:      "pod",
		}
		//create iperf client pod with normal default interface on worker1
		iperfClientPod1.create(oc, "PODNAME="+iperfClientPod1.name, "NAMESPACE="+iperfClientPod1.namespace, "NODENAME="+workerNodeList[1])
		defer iperfClientPod1.delete(oc)
		iperfClientName1, err := compat_otp.GetPodName(oc, oc.Namespace(), "name=iperf-rc-normal", workerNodeList[1])
		iperfClientPod1.name = iperfClientName1

		o.Expect(err).NotTo(o.HaveOccurred())
		errPodRdy4 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-rc-normal")
		compat_otp.AssertWaitPollNoErr(errPodRdy4, fmt.Sprintf("iperf client pod isn't ready"))

		compat_otp.By("6) ########### Check Bandwidth between iperf client and iperf clusterip service ##########")
		// enable hardware offload should improve the performance
		// get bandwidth on iperf client which attached hardware offload enabled VF
		bandWithStr := startIperfTraffic(oc, iperfClientPod.namespace, iperfClientPod.name, iperfSvcIP, "60s")
		bandWidth, paseFloatErr := strconv.ParseFloat(bandWithStr, 32)
		o.Expect(paseFloatErr).NotTo(o.HaveOccurred())
		// get bandwidth on iperf client with normal default interface
		bandWithStr1 := startIperfTraffic(oc, iperfClientPod1.namespace, iperfClientPod1.name, iperfSvcIP1, "60s")
		bandWidth1, paseFloatErr1 := strconv.ParseFloat(bandWithStr1, 32)
		o.Expect(paseFloatErr1).NotTo(o.HaveOccurred())

		o.Expect(float64(bandWidth)).Should(o.BeNumerically(">", float64(bandWidth1)))

		compat_otp.By("7) ########### Create hostnetwork Pods to capture packets ##########")

		hostnwPodTmp := filepath.Join(sriovBaseDir, "net-admin-cap-pod-template.yaml")
		hostnwPod0 := sriovNetResource{
			name:      hostnwPod0Name,
			namespace: oc.Namespace(),
			tempfile:  hostnwPodTmp,
			kind:      "pod",
		}
		hostnwPod1 := sriovNetResource{
			name:      hostnwPod1Name,
			namespace: oc.Namespace(),
			tempfile:  hostnwPodTmp,
			kind:      "pod",
		}
		//create hostnetwork pods on worker0 and worker1 to capture packets
		hostnwPod0.create(oc, "PODNAME="+hostnwPod0.name, "NODENAME="+workerNodeList[0])
		defer hostnwPod0.delete(oc)
		hostnwPod1.create(oc, "PODNAME="+hostnwPod1.name, "NODENAME="+workerNodeList[1])
		defer hostnwPod1.delete(oc)
		errPodRdy5 := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+hostnwPod0.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy5, fmt.Sprintf("hostnetwork pod isn't ready"))
		errPodRdy6 := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+hostnwPod1.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy6, fmt.Sprintf("hostnetwork pod isn't ready"))

		compat_otp.By("8) ########### Capture packtes on hostnetwork pod ##########")
		//send traffic and capture traffic on iperf VF presentor on worker node and iperf server pod
		startIperfTrafficBackground(oc, iperfClientPod.namespace, iperfClientPod.name, iperfSvcIP, "150s")
		// VF presentors should not be able to capture packets after hardware offload take effect（the begining packts can be captured.
		chkCapturePacketsOnIntf(oc, hostnwPod1.namespace, hostnwPod1.name, iperfClientVF, iperfClientIP, "0")
		chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfServerVF, iperfClientIP, "0")
		// iperf server pod should be able to capture packtes
		chkCapturePacketsOnIntf(oc, iperfSvcPod.namespace, iperfSvcPod.name, "eth0", iperfClientIP, "10")

		if ipStackType == "dualstack" {
			compat_otp.By("4) ########### Create ipv6 iperf Server clusterip service and client Pod on diffenrent hosts and attach sriov VF as default interface ##########")
			iperfSvcv6 := sriovNetResource{
				name:      "iperf-clusterip-service-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfSvcTmp_v6,
				kind:      "service",
			}
			iperfSvcPodv6 := sriovNetResource{
				name:      "iperf-server-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfServerTmp_v6,
				kind:      "pod",
			}
			//create iperf server pod with ovs hwoffload VF on worker0 and create clusterip service
			iperfSvcPodv6.create(oc, "PODNAME="+iperfSvcPodv6.name, "NAMESPACE="+iperfSvcPodv6.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
			defer iperfSvcPodv6.delete(oc)
			iperfSvcv6.create(oc, "SVCTYPE="+"ClusterIP", "SVCNAME="+iperfSvcv6.name, "PODNAME="+iperfSvcPodv6.name, "NAMESPACE="+iperfSvcv6.namespace)
			defer iperfSvcv6.delete(oc)
			errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server-ipv6")
			compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

			iperfSvcIPv6 := getSvcIPv6(oc, oc.Namespace(), iperfSvcv6.name)
			iperfServerVF := getPodVFPresentor(oc, iperfSvcPodv6.namespace, iperfSvcPodv6.name)

			iperfClientIPv6 := getPodIPv6(oc, oc.Namespace(), iperfClientPod.name, "dualstack")

			compat_otp.By("5) ########### Create ipv6 iperf clusterip service and iperf client pod with normal default interface ##########")
			iperfSvcv6_1 := sriovNetResource{
				name:      "iperf-clusterip-service-normal-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfSvcTmp_v6,
				kind:      "service",
			}
			iperfSvcPodv6_1 := sriovNetResource{
				name:      "iperf-server-normal-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfNormalServerTmp_v6,
				kind:      "pod",
			}
			//create iperf server pod with normal default interface on worker0 and create clusterip service
			iperfSvcPodv6_1.create(oc, "PODNAME="+iperfSvcPodv6_1.name, "NAMESPACE="+iperfSvcPodv6_1.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
			defer iperfSvcPodv6_1.delete(oc)
			iperfSvcv6_1.create(oc, "SVCTYPE="+"ClusterIP", "SVCNAME="+iperfSvcv6_1.name, "PODNAME="+iperfSvcPodv6_1.name, "NAMESPACE="+iperfSvcv6_1.namespace)
			defer iperfSvcv6_1.delete(oc)
			errPodRdy3 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server-normal-ipv6")
			compat_otp.AssertWaitPollNoErr(errPodRdy3, fmt.Sprintf("iperf server pod isn't ready"))

			iperfSvcIPv6_1 := getSvcIPv6(oc, oc.Namespace(), iperfSvcv6_1.name)

			compat_otp.By("6) ########### Check ipv6 traffic Bandwidth between iperf client and iperf clusterip service ##########")
			// enable hardware offload should improve the performance
			// get bandwidth on iperf client which attached hardware offload enabled VF
			bandWithStr := startIperfTraffic(oc, iperfClientPod.namespace, iperfClientPod.name, iperfSvcIPv6, "60s")
			bandWidth, paseFloatErr := strconv.ParseFloat(bandWithStr, 32)
			o.Expect(paseFloatErr).NotTo(o.HaveOccurred())
			// get bandwidth on iperf client with normal default interface
			bandWithStr1 := startIperfTraffic(oc, iperfClientPod1.namespace, iperfClientPod1.name, iperfSvcIPv6_1, "60s")
			bandWidth1, paseFloatErr1 := strconv.ParseFloat(bandWithStr1, 32)
			o.Expect(paseFloatErr1).NotTo(o.HaveOccurred())

			o.Expect(float64(bandWidth)).Should(o.BeNumerically(">", float64(bandWidth1)))

			compat_otp.By("8) ########### Capture packtes on hostnetwork pod ##########")
			//send traffic and capture traffic on iperf VF presentor on worker node and iperf server pod
			startIperfTrafficBackground(oc, iperfClientPod.namespace, iperfClientPod.name, iperfSvcIPv6, "150s")
			// VF presentors should not be able to capture packets after hardware offload take effect（the begining packts can be captured.
			chkCapturePacketsOnIntf(oc, hostnwPod1.namespace, hostnwPod1.name, iperfClientVF, iperfClientIPv6, "0")
			chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfServerVF, iperfClientIPv6, "0")
			// iperf server pod should be able to capture packtes
			chkCapturePacketsOnIntf(oc, iperfSvcPodv6.namespace, iperfSvcPodv6.name, "eth0", iperfClientIPv6, "10")
		}

	})

	g.It("NonPreRelease-Longduration-Author:yingwang-Medium-45395-pod to service traffic via cluster ip in same host can work well with ovs hw offload as default network [Disruptive]", func() {
		var (
			networkBaseDir = testdata.FixturePath("networking")
			sriovBaseDir   = filepath.Join(networkBaseDir, "sriov")

			sriovNetPolicyName = "sriovoffloadpolicy"
			sriovNetDeviceName = "sriovoffloadnetattchdef"
			sriovOpNs          = "openshift-sriov-network-operator"
			//pfName             = "ens1f0"
			workerNodeList = getOvsHWOffloadWokerNodes(oc)
			hostnwPod0Name = "hostnw-pod-45388-worker0"
			pfName         = getHWoffloadPF(oc, workerNodeList[0])
		)

		oc.SetupProject()
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		sriovNetPolicyTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadpolicy-template.yaml")
		sriovNetPolicy := sriovNetResource{
			name:      sriovNetPolicyName,
			namespace: sriovOpNs,
			kind:      "SriovNetworkNodePolicy",
			tempfile:  sriovNetPolicyTmpFile,
		}

		sriovNetworkAttachTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadnetattchdef-template.yaml")
		sriovNetwork := sriovNetResource{
			name:      sriovNetDeviceName,
			namespace: oc.Namespace(),
			tempfile:  sriovNetworkAttachTmpFile,
			kind:      "network-attachment-definitions",
		}

		defaultOffloadNet := oc.Namespace() + "/" + sriovNetwork.name
		offloadNetType := "v1.multus-cni.io/default-network"

		compat_otp.By("1) ####### Check openshift-sriov-network-operator is running well ##########")
		chkSriovOperatorStatus(oc, sriovOpNs)

		compat_otp.By("2) ####### Check sriov network policy ############")
		//check if sriov network policy is created or not. If not, create one.
		if !sriovNetPolicy.chkSriovPolicy(oc) {
			sriovNetPolicy.create(oc, "VENDOR="+vendorID, "PFNAME="+pfName, "SRIOVNETPOLICY="+sriovNetPolicy.name)
			defer rmSriovNetworkPolicy(oc, sriovNetPolicy.name, sriovNetPolicy.namespace)
		}

		waitForOffloadSriovPolicyReady(oc, sriovNetPolicy.namespace)

		compat_otp.By("3) ######### Create sriov network attachment ############")

		e2e.Logf("create sriov network attachment via template")
		sriovNetwork.create(oc, "NAMESPACE="+oc.Namespace(), "NETNAME="+sriovNetwork.name, "SRIOVNETPOLICY="+sriovNetPolicy.name)
		defer sriovNetwork.delete(oc)

		compat_otp.By("4) ########### Create iperf clusterip service and client Pod on same host and attach sriov VF as default interface ##########")
		iperfSvcTmp := filepath.Join(sriovBaseDir, "iperf-service-template.json")
		iperfServerTmp := filepath.Join(sriovBaseDir, "iperf-server-template.json")
		iperfSvc := sriovNetResource{
			name:      "iperf-clusterip-service",
			namespace: oc.Namespace(),
			tempfile:  iperfSvcTmp,
			kind:      "service",
		}
		iperfSvcPod := sriovNetResource{
			name:      "iperf-server",
			namespace: oc.Namespace(),
			tempfile:  iperfServerTmp,
			kind:      "pod",
		}
		//create iperf server pod on worker0 and create clusterip service
		iperfSvcPod.create(oc, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvcPod.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
		defer iperfSvcPod.delete(oc)
		iperfSvc.create(oc, "SVCTYPE="+"ClusterIP", "SVCNAME="+iperfSvc.name, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvc.namespace)
		defer iperfSvc.delete(oc)
		errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server")
		compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

		iperfSvcIP := getSvcIPv4(oc, oc.Namespace(), iperfSvc.name)
		iperfServerVF := getPodVFPresentor(oc, iperfSvcPod.namespace, iperfSvcPod.name)

		iperfClientTmp := filepath.Join(sriovBaseDir, "iperf-rc-template.json")
		iperfClientPod := sriovNetResource{
			name:      "iperf-rc",
			namespace: oc.Namespace(),
			tempfile:  iperfClientTmp,
			kind:      "pod",
		}
		//create iperf client pod on worker0
		iperfClientPod.create(oc, "PODNAME="+iperfClientPod.name, "NAMESPACE="+iperfClientPod.namespace, "NETNAME="+defaultOffloadNet, "NODENAME="+workerNodeList[0],
			"NETTYPE="+offloadNetType)
		defer iperfClientPod.delete(oc)
		iperfClientName, err := compat_otp.GetPodName(oc, oc.Namespace(), "name=iperf-rc", workerNodeList[0])
		iperfClientPod.name = iperfClientName

		o.Expect(err).NotTo(o.HaveOccurred())
		errPodRdy2 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-rc")
		compat_otp.AssertWaitPollNoErr(errPodRdy2, fmt.Sprintf("iperf client pod isn't ready"))

		iperfClientIP := getPodIPv4(oc, oc.Namespace(), iperfClientPod.name)
		iperfClientVF := getPodVFPresentor(oc, iperfClientPod.namespace, iperfClientPod.name)

		compat_otp.By("5) ########### Create hostnetwork Pods to capture packets ##########")

		hostnwPodTmp := filepath.Join(sriovBaseDir, "net-admin-cap-pod-template.yaml")
		hostnwPod0 := sriovNetResource{
			name:      hostnwPod0Name,
			namespace: oc.Namespace(),
			tempfile:  hostnwPodTmp,
			kind:      "pod",
		}
		//create hostnetwork pod on worker0
		hostnwPod0.create(oc, "PODNAME="+hostnwPod0.name, "NODENAME="+workerNodeList[0])
		defer hostnwPod0.delete(oc)
		errPodRdy3 := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+hostnwPod0.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy3, fmt.Sprintf("hostnetwork pod isn't ready"))

		compat_otp.By("6) ########### Check Bandwidth between iperf client and iperf server pods ##########")
		bandWithStr := startIperfTraffic(oc, iperfClientPod.namespace, iperfClientPod.name, iperfSvcIP, "20s")
		bandWidth, paseFloatErr := strconv.ParseFloat(bandWithStr, 32)
		o.Expect(paseFloatErr).NotTo(o.HaveOccurred())
		o.Expect(float64(bandWidth)).Should(o.BeNumerically(">", 0.0))

		compat_otp.By("7) ########### Capture packtes on hostnetwork pod ##########")
		//send traffic and capture traffic on iperf VF presentor on worker node and iperf server pod
		startIperfTrafficBackground(oc, iperfClientPod.namespace, iperfClientPod.name, iperfSvcIP, "150s")
		// VF presentors should not be able to capture packets after hardware offload take effect（the begining packts can be captured.
		chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfClientVF, iperfClientIP, "0")
		chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfServerVF, iperfClientIP, "0")
		// iperf server pod should be able to capture packtes
		chkCapturePacketsOnIntf(oc, iperfSvcPod.namespace, iperfSvcPod.name, "eth0", iperfClientIP, "10")

		if ipStackType == "dualstack" {

			compat_otp.By("8) ########### Create ipv6 iperf Server and client Pod on same host and attach sriov VF as default interface ##########")
			iperfSvc := sriovNetResource{
				name:      "iperf-clusterip-service-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfSvcTmp_v6,
				kind:      "service",
			}
			iperfSvcPod := sriovNetResource{
				name:      "iperf-server-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfServerTmp_v6,
				kind:      "pod",
			}
			//create iperf server pod with ovs hwoffload VF on worker0 and create clusterip service
			iperfSvcPod.create(oc, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvcPod.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
			defer iperfSvcPod.delete(oc)
			iperfSvc.create(oc, "SVCTYPE="+"ClusterIP", "SVCNAME="+iperfSvc.name, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvc.namespace)
			defer iperfSvc.delete(oc)
			errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server-ipv6")
			compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

			iperfSvcIPv6 := getSvcIPv6(oc, oc.Namespace(), iperfSvc.name)
			iperfServerVF := getPodVFPresentor(oc, iperfSvcPod.namespace, iperfSvcPod.name)

			iperfClientIPv6 := getPodIPv6(oc, oc.Namespace(), iperfClientPod.name, "dualstack")

			compat_otp.By("9) ########### Check ipv6 traffic Bandwidth between iperf client and iperf server pods ##########")
			bandWithStr := startIperfTraffic(oc, iperfClientPod.namespace, iperfClientPod.name, iperfSvcIPv6, "20s")
			bandWidth, paseFloatErr := strconv.ParseFloat(bandWithStr, 32)
			o.Expect(paseFloatErr).NotTo(o.HaveOccurred())
			o.Expect(float64(bandWidth)).Should(o.BeNumerically(">", 0.0))

			compat_otp.By("10) ########### Capture packtes on hostnetwork pod ##########")
			//send traffic and capture traffic on iperf VF presentor on worker node and iperf server pod
			startIperfTrafficBackground(oc, iperfClientPod.namespace, iperfClientPod.name, iperfSvcIPv6, "150s")
			// VF presentors should not be able to capture packets after hardware offload take effect（the begining packts can be captured.
			chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfClientVF, iperfClientIPv6, "0")
			chkCapturePacketsOnIntf(oc, hostnwPod0.namespace, hostnwPod0.name, iperfServerVF, iperfClientIPv6, "0")
			// iperf server pod should be able to capture packtes
			chkCapturePacketsOnIntf(oc, iperfSvcPod.namespace, iperfSvcPod.name, "eth0", iperfClientIPv6, "10")
		}

	})

	g.It("NonPreRelease-Longduration-Author:yingwang-Medium-46018-test pod to service traffic via nodeport with ovs hw offload as default network [Disruptive]", func() {
		var (
			networkBaseDir = testdata.FixturePath("networking")
			sriovBaseDir   = filepath.Join(networkBaseDir, "sriov")

			sriovNetPolicyName = "sriovoffloadpolicy"
			sriovNetDeviceName = "sriovoffloadnetattchdef"
			sriovOpNs          = "openshift-sriov-network-operator"
			//pfName             = "ens1f0"
			workerNodeList = getOvsHWOffloadWokerNodes(oc)
			pfName         = getHWoffloadPF(oc, workerNodeList[0])
		)

		oc.SetupProject()
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		sriovNetPolicyTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadpolicy-template.yaml")
		sriovNetPolicy := sriovNetResource{
			name:      sriovNetPolicyName,
			namespace: sriovOpNs,
			kind:      "SriovNetworkNodePolicy",
			tempfile:  sriovNetPolicyTmpFile,
		}

		sriovNetworkAttachTmpFile := filepath.Join(sriovBaseDir, "sriovoffloadnetattchdef-template.yaml")
		sriovNetwork := sriovNetResource{
			name:      sriovNetDeviceName,
			namespace: oc.Namespace(),
			tempfile:  sriovNetworkAttachTmpFile,
			kind:      "network-attachment-definitions",
		}

		defaultOffloadNet := oc.Namespace() + "/" + sriovNetwork.name
		offloadNetType := "v1.multus-cni.io/default-network"

		compat_otp.By("1) ####### Check openshift-sriov-network-operator is running well ##########")
		chkSriovOperatorStatus(oc, sriovOpNs)

		compat_otp.By("2) ####### Check sriov network policy ############")
		//check if sriov network policy is created or not. If not, create one.
		if !sriovNetPolicy.chkSriovPolicy(oc) {
			sriovNetPolicy.create(oc, "VENDOR="+vendorID, "PFNAME="+pfName, "SRIOVNETPOLICY="+sriovNetPolicy.name)
			defer rmSriovNetworkPolicy(oc, sriovNetPolicy.name, sriovNetPolicy.namespace)
		}

		waitForOffloadSriovPolicyReady(oc, sriovNetPolicy.namespace)

		compat_otp.By("3) ######### Create sriov network attachment ############")

		e2e.Logf("create sriov network attachment via template")
		sriovNetwork.create(oc, "NAMESPACE="+oc.Namespace(), "NETNAME="+sriovNetwork.name, "SRIOVNETPOLICY="+sriovNetPolicy.name)
		defer sriovNetwork.delete(oc)

		compat_otp.By("4) ########### Create iperf nodeport service and create 2 client Pods on 2 hosts and attach sriov VF as default interface ##########")
		iperfSvcTmp := filepath.Join(sriovBaseDir, "iperf-service-template.json")
		iperfServerTmp := filepath.Join(sriovBaseDir, "iperf-server-template.json")
		iperfSvc := sriovNetResource{
			name:      "iperf-nodeport-service",
			namespace: oc.Namespace(),
			tempfile:  iperfSvcTmp,
			kind:      "service",
		}
		iperfSvcPod := sriovNetResource{
			name:      "iperf-server",
			namespace: oc.Namespace(),
			tempfile:  iperfServerTmp,
			kind:      "pod",
		}
		//create iperf server pod on worker0 and create nodeport service
		iperfSvcPod.create(oc, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvcPod.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
		defer iperfSvcPod.delete(oc)
		iperfSvc.create(oc, "SVCTYPE="+"NodePort", "SVCNAME="+iperfSvc.name, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvc.namespace)
		defer iperfSvc.delete(oc)
		errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server")
		compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

		iperfSvcIP := getSvcIPv4(oc, oc.Namespace(), iperfSvc.name)

		iperfClientTmp := filepath.Join(sriovBaseDir, "iperf-rc-template.json")
		iperfClientPod1 := sriovNetResource{
			name:      "iperf-rc-1",
			namespace: oc.Namespace(),
			tempfile:  iperfClientTmp,
			kind:      "pod",
		}

		iperfClientPod2 := sriovNetResource{
			name:      "iperf-rc-2",
			namespace: oc.Namespace(),
			tempfile:  iperfClientTmp,
			kind:      "pod",
		}
		//create iperf client pod on worker0
		iperfClientPod1.create(oc, "PODNAME="+iperfClientPod1.name, "NAMESPACE="+iperfClientPod1.namespace, "NETNAME="+defaultOffloadNet, "NODENAME="+workerNodeList[0],
			"NETTYPE="+offloadNetType)
		defer iperfClientPod1.delete(oc)
		iperfClientName1, err := compat_otp.GetPodName(oc, oc.Namespace(), "name=iperf-rc-1", workerNodeList[0])
		iperfClientPod1.name = iperfClientName1
		o.Expect(err).NotTo(o.HaveOccurred())
		//create iperf client pod on worker1
		iperfClientPod2.create(oc, "PODNAME="+iperfClientPod2.name, "NAMESPACE="+iperfClientPod2.namespace, "NETNAME="+defaultOffloadNet, "NODENAME="+workerNodeList[1],
			"NETTYPE="+offloadNetType)
		defer iperfClientPod2.delete(oc)
		iperfClientName2, err := compat_otp.GetPodName(oc, oc.Namespace(), "name=iperf-rc-2", workerNodeList[1])
		iperfClientPod2.name = iperfClientName2
		o.Expect(err).NotTo(o.HaveOccurred())

		errPodRdy2 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-rc-1")
		compat_otp.AssertWaitPollNoErr(errPodRdy2, fmt.Sprintf("iperf client pod isn't ready"))

		errPodRdy3 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-rc-2")
		compat_otp.AssertWaitPollNoErr(errPodRdy3, fmt.Sprintf("iperf client pod isn't ready"))

		compat_otp.By("5) ########### Check Bandwidth between iperf client and iperf server pods ##########")
		//traffic should pass
		bandWithStr1 := startIperfTraffic(oc, iperfClientPod1.namespace, iperfClientPod1.name, iperfSvcIP, "20s")
		bandWidth1, paseFloatErr1 := strconv.ParseFloat(bandWithStr1, 32)
		o.Expect(paseFloatErr1).NotTo(o.HaveOccurred())
		o.Expect(float64(bandWidth1)).Should(o.BeNumerically(">", 0.0))
		//traffic should pass
		bandWithStr2 := startIperfTraffic(oc, iperfClientPod2.namespace, iperfClientPod2.name, iperfSvcIP, "20s")
		bandWidth2, paseFloatErr2 := strconv.ParseFloat(bandWithStr2, 32)
		o.Expect(paseFloatErr2).NotTo(o.HaveOccurred())
		o.Expect(float64(bandWidth2)).Should(o.BeNumerically(">", 0.0))

		if ipStackType == "dualstack" {

			compat_otp.By("6) ########### Create ipv6 iperf nodeport service and create 2 client Pods on 2 hosts and attach sriov VF as default interface ##########")
			iperfSvc := sriovNetResource{
				name:      "iperf-nodeport-service-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfSvcTmp_v6,
				kind:      "service",
			}
			iperfSvcPod := sriovNetResource{
				name:      "iperf-server-ipv6",
				namespace: oc.Namespace(),
				tempfile:  iperfServerTmp_v6,
				kind:      "pod",
			}
			//create iperf server pod on worker0 and create nodeport service
			iperfSvcPod.create(oc, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvcPod.namespace, "NETNAME="+defaultOffloadNet, "NETTYPE="+offloadNetType, "NODENAME="+workerNodeList[0])
			defer iperfSvcPod.delete(oc)
			iperfSvc.create(oc, "SVCTYPE="+"NodePort", "SVCNAME="+iperfSvc.name, "PODNAME="+iperfSvcPod.name, "NAMESPACE="+iperfSvc.namespace)
			defer iperfSvc.delete(oc)
			//errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name=iperf-server")
			compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("iperf server pod isn't ready"))

			iperfSvcIPv6 := getSvcIPv6(oc, oc.Namespace(), iperfSvc.name)

			compat_otp.By("7) ########### Check ipv6 traffic Bandwidth between iperf client and iperf server pods ##########")
			//traffic should pass
			bandWithStr1 := startIperfTraffic(oc, iperfClientPod1.namespace, iperfClientPod1.name, iperfSvcIPv6, "20s")
			bandWidth1, paseFloatErr1 := strconv.ParseFloat(bandWithStr1, 32)
			o.Expect(paseFloatErr1).NotTo(o.HaveOccurred())
			o.Expect(float64(bandWidth1)).Should(o.BeNumerically(">", 0.0))
			//traffic should pass
			bandWithStr2 := startIperfTraffic(oc, iperfClientPod2.namespace, iperfClientPod2.name, iperfSvcIPv6, "20s")
			bandWidth2, paseFloatErr2 := strconv.ParseFloat(bandWithStr2, 32)
			o.Expect(paseFloatErr2).NotTo(o.HaveOccurred())
			o.Expect(float64(bandWidth2)).Should(o.BeNumerically(">", 0.0))
		}

	})

})
