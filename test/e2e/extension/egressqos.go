package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"fmt"
	"path/filepath"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	"github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

var _ = g.Describe("[OTP][sig-networking] SDN egressqos", func() {
	defer g.GinkgoRecover()
	var (
		dscpSvcIP         string
		externalPrivateIP string
		dscpSvcPort       = "9096"
		a                 *compat_otp.AwsClient
		oc                = compat_otp.NewCLI("networking-"+getRandomString(), compat_otp.KubeConfigPath())
	)

	g.BeforeEach(func() {

		platform := compat_otp.CheckPlatform(oc)
		networkType := checkNetworkType(oc)
		e2e.Logf("\n\nThe platform is %v,  networkType is %v\n", platform, networkType)

		acceptedPlatform := strings.Contains(platform, "aws")
		if !acceptedPlatform || !strings.Contains(networkType, "ovn") {
			g.Skip("Test cases should be run on AWS cluster with ovn network plugin, skip for other platforms or other non-OVN network plugin!!")
		}

		switch platform {
		case "aws":
			e2e.Logf("\n AWS is detected, running the case on AWS\n")
			if dscpSvcIP == "" {
				getAwsCredentialFromCluster(oc)
				a = compat_otp.InitAwsSession()
				_, err := getAwsIntSvcInstanceID(a, oc)
				if err != nil {
					e2e.Logf("There is no int svc instance in this cluster, %v", err)
					g.Skip("There is no int svc instance in this cluster, skip the cases!!")
				}
				ips := getAwsIntSvcIPs(a, oc)
				publicIP, ok := ips["publicIP"]
				if !ok {
					e2e.Logf("no public IP found for Int Svc instance")
				}
				privateIP, ok1 := ips["privateIP"]
				if !ok1 {
					e2e.Logf("no private IP found for Int Svc instance")
				}
				dscpSvcIP = publicIP
				externalPrivateIP = privateIP
				err = installDscpServiceOnAWS(a, oc, publicIP)
				if err != nil {
					e2e.Logf("No dscp-echo service installed on the bastion host, %v", err)
					g.Skip("No dscp-echo service installed on the bastion host, skip the cases!!")
				}
			}

		default:
			e2e.Logf("cloud provider %v is not supported for auto egressqos cases for now", platform)
			g.Skip("cloud provider %v is not supported for auto egressqos cases for now, skip the cases!")
		}

	})

	// author: yingwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:yingwang-Medium-51732-EgressQoS resource applies only to its namespace.", func() {
		var (
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-template.yaml")
			testPodTmpFile   = filepath.Join(egressBaseDir, "testpod-template.yaml")

			dscpValue1 = 40
			dscpValue2 = 30
			dstCIDR    = dscpSvcIP + "/" + "32"
			pktFile1   = getRandomString() + "pcap.txt"
			pktFile2   = getRandomString() + "pcap.txt"
		)

		compat_otp.By("1) ####### Create egressqos and testpod in one namespace  ##########")
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)
		e2e.Logf("create namespace %s", ns1)

		egressQos1 := egressQosResource{
			name:      "default",
			namespace: ns1,
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		testPod1 := egressQosResource{
			name:      "test-pod",
			namespace: ns1,
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}
		defer egressQos1.delete(oc)
		egressQos1.create(oc, "NAME="+egressQos1.name, "NAMESPACE="+egressQos1.namespace, "CIDR1="+dstCIDR, "CIDR2="+"1.1.1.1/32")

		defer testPod1.delete(oc)
		testPod1.create(oc, "NAME="+testPod1.name, "NAMESPACE="+testPod1.namespace)

		errPodRdy1 := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+testPod1.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy1, fmt.Sprintf("testpod isn't ready"))

		compat_otp.By("2) ####### Create egressqos and testpod in a new namespace  ##########")
		oc.SetupProject()
		ns2 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns2)
		e2e.Logf("create namespace %s", ns2)
		egressQos2 := egressQosResource{
			name:      "default",
			namespace: ns2,
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		testPod2 := egressQosResource{
			name:      "test-pod",
			namespace: ns2,
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}
		defer egressQos2.delete(oc)
		egressQos2.create(oc, "NAME="+egressQos2.name, "NAMESPACE="+egressQos2.namespace, "CIDR1="+"1.1.1.1/32", "CIDR2="+dstCIDR)

		defer testPod2.delete(oc)
		testPod2.create(oc, "NAME="+testPod2.name, "NAMESPACE="+testPod2.namespace)

		errPodRdy2 := waitForPodWithLabelReady(oc, ns2, "name="+testPod2.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy2, fmt.Sprintf("testpod isn't ready"))

		compat_otp.By("3) ####### Try to create a new egressqos in ns2  ##########")

		egressQos3 := egressQosResource{
			name:      "newegressqos",
			namespace: ns2,
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		output, _ := egressQos3.createWithOutput(oc, "NAME="+egressQos3.name, "NAMESPACE="+egressQos3.namespace, "CIDR1="+"1.1.1.1/32", "CIDR2="+dstCIDR)
		//Only one egressqos is permitted for one namespace
		o.Expect(output).Should(o.ContainSubstring("Invalid value"))

		compat_otp.By("4) ####### Check dscp value of egress traffic of ns1    ##########")

		defer rmPktsFile(a, oc, dscpSvcIP, pktFile1)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile1)

		startCurlTraffic(oc, testPod1.namespace, testPod1.name, dscpSvcIP, dscpSvcPort)

		chkRes1 := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile1, dscpValue1)
		o.Expect(chkRes1).Should(o.BeTrue())

		compat_otp.By("5 ####### Check dscp value of egress traffic of ns2    ##########")

		defer rmPktsFile(a, oc, dscpSvcIP, pktFile2)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile2)

		startCurlTraffic(oc, testPod2.namespace, testPod2.name, dscpSvcIP, dscpSvcPort)

		chkRes2 := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile2, dscpValue2)
		o.Expect(chkRes2).Should(o.BeTrue())

	})

	// author: yingwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:yingwang-Medium-51749-if ipv4 egress traffic matches multiple egressqos rules, the first one will take effect.", func() {
		compat_otp.By("1) ############## create egressqos and testpod #################")

		var (
			dscpValue        = 40
			dstCIDR          = dscpSvcIP + "/" + "32"
			pktFile          = getRandomString() + "pcap.txt"
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-template.yaml")
			testPodTmpFile   = filepath.Join(egressBaseDir, "testpod-template.yaml")
		)
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		egressQos := egressQosResource{
			name:      "default",
			namespace: oc.Namespace(),
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		testPod := egressQosResource{
			name:      "test-pod",
			namespace: oc.Namespace(),
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}
		//egressqos has two rules which can match egress traffic
		defer egressQos.delete(oc)
		egressQos.create(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1="+"0.0.0.0/0", "CIDR2="+dstCIDR)

		defer testPod.delete(oc)
		testPod.create(oc, "NAME="+testPod.name, "NAMESPACE="+testPod.namespace)

		errPodRdy := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+testPod.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpod isn't ready"))

		compat_otp.By("2) ####### Check dscp value of egress traffic   ##########")
		defer rmPktsFile(a, oc, dscpSvcIP, pktFile)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile)

		startCurlTraffic(oc, testPod.namespace, testPod.name, dscpSvcIP, dscpSvcPort)
		// the first matched egressqos rule can take effect
		chkRes := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile, dscpValue)
		o.Expect(chkRes).Should(o.BeTrue())

	})

	// author: yingwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:yingwang-Medium-51751-if egress traffic doesn't match egressqos rules, dscp value will not change.", func() {

		var (
			dscpValue1       = 40
			dscpValue2       = 30
			dscpValue        = 0
			pktFile          = getRandomString() + "pcap.txt"
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-template.yaml")
			testPodTmpFile   = filepath.Join(egressBaseDir, "testpod-template.yaml")
		)
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		egressQos := egressQosResource{
			name:      "default",
			namespace: oc.Namespace(),
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		testPod := egressQosResource{
			name:      "test-pod",
			namespace: oc.Namespace(),
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}
		compat_otp.By("1) ############## create egressqos and testpod #################")
		//egressqos has two rules which neither matches egress traffic
		defer egressQos.delete(oc)
		egressQos.create(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1="+"1.1.1.1/32", "CIDR2="+"2.2.2.2/32")

		defer testPod.delete(oc)
		testPod.create(oc, "NAME="+testPod.name, "NAMESPACE="+testPod.namespace)

		errPodRdy := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+testPod.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpod isn't ready"))

		compat_otp.By("2) ####### Check dscp value of egress traffic   ##########")
		defer rmPktsFile(a, oc, dscpSvcIP, pktFile)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile)

		startCurlTraffic(oc, testPod.namespace, testPod.name, dscpSvcIP, dscpSvcPort)
		// dscp value of egress traffic doesn't change
		chkRes1 := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile, dscpValue1)
		o.Expect(chkRes1).Should(o.Equal(false))
		chkRes2 := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile, dscpValue2)
		o.Expect(chkRes2).Should(o.Equal(false))
		chkRes := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile, dscpValue)
		o.Expect(chkRes).Should(o.BeTrue())

	})

	// author: yingwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:yingwang-Medium-51839-egressqos can work fine when new/update/delete matching pods.", func() {

		var (
			dscpValue1       = 40
			dscpValue2       = 30
			priorityValue    = "Critical"
			dstCIDR          = dscpSvcIP + "/" + "32"
			pktFile1         = getRandomString() + "pcap.txt"
			pktFile2         = getRandomString() + "pcap.txt"
			pktFile3         = getRandomString() + "pcap.txt"
			pktFile4         = getRandomString() + "pcap.txt"
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-podselector-template.yaml")
			testPodTmpFile   = filepath.Join(egressBaseDir, "testpod-template.yaml")
		)
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		egressQos := egressQosResource{
			name:      "default",
			namespace: oc.Namespace(),
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		testPod1 := egressQosResource{
			name:      "testpod1",
			namespace: oc.Namespace(),
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}

		testPod2 := egressQosResource{
			name:      "testpod2",
			namespace: oc.Namespace(),
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}

		compat_otp.By("1) ####### Create egressqos with podselector rules  ##########")
		defer egressQos.delete(oc)
		egressQos.create(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1="+"0.0.0.0/0", "PRIORITY="+priorityValue, "CIDR2="+dstCIDR, "LABELNAME="+testPod1.name)

		compat_otp.By("2) ####### Create testpod1 which match the second podselector  ##########")
		defer testPod1.delete(oc)
		testPod1.create(oc, "NAME="+testPod1.name, "NAMESPACE="+testPod1.namespace)
		errPodRdy := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+testPod1.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpod isn't ready"))

		compat_otp.By("3) ####### Check dscp value in egress traffic  ##########")
		defer rmPktsFile(a, oc, dscpSvcIP, pktFile1)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile1)

		startCurlTraffic(oc, testPod1.namespace, testPod1.name, dscpSvcIP, dscpSvcPort)

		chkRes1 := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile1, dscpValue2)
		o.Expect(chkRes1).Should(o.BeTrue())

		compat_otp.By("4) ####### Create testpod2 which match the second podselector  ##########")
		defer testPod2.delete(oc)
		testPod2.create(oc, "NAME="+testPod2.name, "NAMESPACE="+testPod2.namespace)
		errPodRdy = waitForPodWithLabelReady(oc, oc.Namespace(), "name="+testPod2.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpod isn't ready"))

		compat_otp.By("5) ####### Check dscp value in egress traffic  ##########")
		defer rmPktsFile(a, oc, dscpSvcIP, pktFile2)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile2)

		startCurlTraffic(oc, testPod2.namespace, testPod2.name, dscpSvcIP, dscpSvcPort)

		chkRes2 := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile1, dscpValue2)
		o.Expect(chkRes2).Should(o.BeTrue())

		compat_otp.By("6) ####### Update testpod2 label to match the first egressqos rule  ##########")
		defer compat_otp.LabelPod(oc, testPod2.namespace, testPod2.name, "priority-")
		err := compat_otp.LabelPod(oc, testPod2.namespace, testPod2.name, "priority="+priorityValue)
		o.Expect(err).NotTo(o.HaveOccurred())

		defer rmPktsFile(a, oc, dscpSvcIP, pktFile3)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile3)

		startCurlTraffic(oc, testPod2.namespace, testPod2.name, dscpSvcIP, dscpSvcPort)

		chkRes3 := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile3, dscpValue1)
		o.Expect(chkRes3).Should(o.BeTrue())

		compat_otp.By("7) ####### Remove testpod1 and check egress traffic ##########")
		testPod1.delete(oc)

		defer rmPktsFile(a, oc, dscpSvcIP, pktFile4)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile4)

		startCurlTraffic(oc, testPod2.namespace, testPod2.name, dscpSvcIP, dscpSvcPort)

		chkRes4 := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile4, dscpValue1)
		o.Expect(chkRes4).Should(o.BeTrue())

	})

	// author: yingwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:yingwang-Medium-51840-egressqos can work fine when new/update/delete egressqos rules", func() {
		var (
			dscpValue1       = 40
			dscpValue2       = 30
			dscpValue3       = 0
			dscpValue4       = 20
			priorityValue    = "Critical"
			dstCIDR          = dscpSvcIP + "/" + "32"
			pktFile1         = getRandomString() + "pcap.txt"
			pktFile2         = getRandomString() + "pcap.txt"
			pktFile3         = getRandomString() + "pcap.txt"
			pktFile4         = getRandomString() + "pcap.txt"
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-podselector-template.yaml")
			testPodTmpFile   = filepath.Join(egressBaseDir, "testpod-template.yaml")
		)
		compat_otp.SetNamespacePrivileged(oc, oc.Namespace())
		egressQos := egressQosResource{
			name:      "default",
			namespace: oc.Namespace(),
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		testPod := egressQosResource{
			name:      "testpod",
			namespace: oc.Namespace(),
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}

		compat_otp.By("1) ####### Create egressqos with podselector rules  ##########")
		defer egressQos.delete(oc)
		egressQos.create(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1="+"0.0.0.0/0", "PRIORITY="+priorityValue, "CIDR2="+dstCIDR, "LABELNAME="+testPod.name)

		compat_otp.By("2) ####### Create testpod1 which match the second podselector  ##########")
		defer testPod.delete(oc)
		testPod.create(oc, "NAME="+testPod.name, "NAMESPACE="+testPod.namespace)
		errPodRdy := waitForPodWithLabelReady(oc, oc.Namespace(), "name="+testPod.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpod isn't ready"))

		//label testpod with priority Critical
		err := compat_otp.LabelPod(oc, testPod.namespace, testPod.name, "priority="+priorityValue)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3) ####### Check dscp value in egress traffic  ##########")
		defer rmPktsFile(a, oc, dscpSvcIP, pktFile1)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile1)

		startCurlTraffic(oc, testPod.namespace, testPod.name, dscpSvcIP, dscpSvcPort)

		chkRes := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile1, dscpValue1)
		o.Expect(chkRes).Should(o.BeTrue())

		compat_otp.By("4) ####### Change egressqos rule and send traffic again ##########")
		patchYamlToRestore := `[{"op":"replace","path":"/spec/egress/0/podSelector/matchLabels/priority","value":"Low"}]`
		output, err1 := oc.AsAdmin().WithoutNamespace().Run("patch").Args(egressQos.kind, egressQos.name, "-n", egressQos.namespace, "--type=json", "-p", patchYamlToRestore).Output()
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("egressqos.k8s.ovn.org/default patched"))

		defer rmPktsFile(a, oc, dscpSvcIP, pktFile2)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile2)

		startCurlTraffic(oc, testPod.namespace, testPod.name, dscpSvcIP, dscpSvcPort)

		chkRes = chkDSCPinPkts(a, oc, dscpSvcIP, pktFile2, dscpValue2)
		o.Expect(chkRes).Should(o.BeTrue())

		compat_otp.By("5) ####### delete egressqos rule and send traffic again ##########")
		patchYamlToRestore = `[{"op":"remove","path":"/spec/egress/1"}]`
		output, err1 = oc.AsAdmin().WithoutNamespace().Run("patch").Args(egressQos.kind, egressQos.name, "-n", egressQos.namespace, "--type=json", "-p", patchYamlToRestore).Output()
		//output, err1 = oc.AsAdmin().WithoutNamespace().Run("patch").Args(egressQos.kind, egressQos.name, "-n", egressQos.namespace, "--type=json", "--patch-file", patchFile2).Output()
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("egressqos.k8s.ovn.org/default patched"))

		defer rmPktsFile(a, oc, dscpSvcIP, pktFile3)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile3)

		startCurlTraffic(oc, testPod.namespace, testPod.name, dscpSvcIP, dscpSvcPort)

		chkRes = chkDSCPinPkts(a, oc, dscpSvcIP, pktFile3, dscpValue3)
		o.Expect(chkRes).Should(o.BeTrue())

		compat_otp.By("6) ####### add new egressqos rule and send traffic again ##########")
		patchYamlToRestore = `[{"op": "add", "path": "/spec/egress/1", "value":{"dscp":20,"dstCIDR": "0.0.0.0/0"}}]`
		output, err1 = oc.AsAdmin().WithoutNamespace().Run("patch").Args(egressQos.kind, egressQos.name, "-n", egressQos.namespace, "--type=json", "-p", patchYamlToRestore).Output()
		//output, err1 = oc.AsAdmin().WithoutNamespace().Run("patch").Args(egressQos.kind, egressQos.name, "-n", egressQos.namespace, "--type=json", "--patch-file", patchFile3).Output()
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("egressqos.k8s.ovn.org/default patched"))

		defer rmPktsFile(a, oc, dscpSvcIP, pktFile4)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile4)

		startCurlTraffic(oc, testPod.namespace, testPod.name, dscpSvcIP, dscpSvcPort)

		chkRes = chkDSCPinPkts(a, oc, dscpSvcIP, pktFile4, dscpValue4)
		o.Expect(chkRes).Should(o.BeTrue())

	})

	// author: yingwang@redhat.com
	g.It("Author:yingwang-NonHyperShiftHOST-ConnectedOnly-Medium-74098-egressqos status is correct", func() {
		var (
			priorityValue    = "Critical"
			dstCIDR          = dscpSvcIP + "/" + "32"
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-podselector-template.yaml")
		)
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)

		egressQos := egressQosResource{
			name:      "default",
			namespace: ns,
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		compat_otp.By("1) ####### Create egressqos with podselector rules  ##########")
		defer egressQos.delete(oc)
		egressQos.create(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1="+"0.0.0.0/0", "PRIORITY="+priorityValue, "CIDR2="+dstCIDR, "LABELNAME="+"testPod")

		compat_otp.By("2) ####### check egressqos status info is correct ##########")
		statusInfo, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressqos", "default", "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(statusInfo, "STATUS")).To(o.BeTrue())
		o.Expect(strings.Contains(statusInfo, "EgressQoS Rules applied")).To(o.BeTrue())

		compat_otp.By("3) ####### check egressqos status detail info is correct ##########")
		chkEgressQosStatus(oc, ns)

	})

	g.It("Author:yingwang-NonHyperShiftHOST-ConnectedOnly-Medium-74204-egressqos addressset updated correctly", func() {
		var (
			priorityValue    = "Minor"
			dstCIDR          = dscpSvcIP + "/" + "32"
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-podselector-template.yaml")
			testPodTmpFile   = filepath.Join(networkBaseDir, "ping-for-pod-specific-node-template.yaml")
			podLable         = "egress-qos-pod"
		)
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		workerNodeList := compat_otp.GetNodeListByLabel(oc, "node-role.kubernetes.io/worker")
		if len(workerNodeList) < 2 {
			g.Skip("These cases can only be run for cluster that has at least two worker nodes")
		}

		compat_otp.By("1) ####### Create egressqos with podselector rules  ##########")
		egressQos := egressQosResource{
			name:      "default",
			namespace: ns,
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}
		defer egressQos.delete(oc)
		egressQos.create(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1="+"0.0.0.0/0", "PRIORITY="+priorityValue, "CIDR2="+dstCIDR, "LABELNAME="+podLable)

		compat_otp.By("2) ####### Create 2 testpods on different nodes which don't match the any egressqos rule  ##########")
		// create 2 testpods which located on different nodes
		testPod1 := egressQosResource{
			name:      "testpod1",
			namespace: ns,
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}
		defer testPod1.delete(oc)
		testPod1.create(oc, "NAME="+testPod1.name, "NAMESPACE="+testPod1.namespace, "NODENAME="+workerNodeList[0])
		testPod2 := egressQosResource{
			name:      "testpod2",
			namespace: ns,
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}
		defer testPod2.delete(oc)
		testPod2.create(oc, "NAME="+testPod2.name, "NAMESPACE="+testPod2.namespace, "NODENAME="+workerNodeList[1])

		errPodRdy := waitForPodWithLabelReady(oc, ns, "name=hello-pod")
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpod1 isn't ready"))

		compat_otp.By("4) ####### Check egressqos addresset.  ##########")

		addSet1 := getEgressQosAddSet(oc, workerNodeList[0], ns)
		addSet2 := getEgressQosAddSet(oc, workerNodeList[1], ns)

		chkAddSet(oc, testPod1.name, ns, addSet1, false)
		chkAddSet(oc, testPod2.name, ns, addSet1, false)
		chkAddSet(oc, testPod1.name, ns, addSet2, false)
		chkAddSet(oc, testPod2.name, ns, addSet2, false)

		compat_otp.By("5) ####### update testpod1 to match egressqos rule. Only addresset on worker0 updated  ##########")
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("pod", testPod1.name, "name="+podLable, "-n", testPod1.namespace, "--overwrite").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		addSet1 = getEgressQosAddSet(oc, workerNodeList[0], ns)
		addSet2 = getEgressQosAddSet(oc, workerNodeList[1], ns)

		chkAddSet(oc, testPod1.name, ns, addSet1, true)
		chkAddSet(oc, testPod2.name, ns, addSet1, false)
		chkAddSet(oc, testPod1.name, ns, addSet2, false)
		chkAddSet(oc, testPod2.name, ns, addSet2, false)

		compat_otp.By("6) ####### update testpod2 to match egressqos rule.  Only addresset on worker1 updated ##########")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("pod", testPod2.name, "priority="+priorityValue, "-n", testPod1.namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		addSet1 = getEgressQosAddSet(oc, workerNodeList[0], ns)
		addSet2 = getEgressQosAddSet(oc, workerNodeList[1], ns)

		chkAddSet(oc, testPod1.name, ns, addSet1, true)
		chkAddSet(oc, testPod2.name, ns, addSet1, false)
		chkAddSet(oc, testPod1.name, ns, addSet2, false)
		chkAddSet(oc, testPod2.name, ns, addSet2, true)

	})

	// author: yingwang@redhat.com
	g.It("Author:yingwang-NonHyperShiftHOST-ConnectedOnly-Medium-73642-Egress traffic with EgressIP and EgressQos applied can work fine.[Disruptive]", func() {
		compat_otp.By("1) ############## create egressqos and egressip #################")

		var (
			dstCIDR          = externalPrivateIP + "/" + "32"
			dscpValue        = 40
			pktFile          = getRandomString() + "pcap.txt"
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-template.yaml")
			testPodTmpFile   = filepath.Join(egressBaseDir, "testpod-template.yaml")
			egressIPTemplate = filepath.Join(networkBaseDir, "egressip-config2-template.yaml")
			egressNodeLabel  = "k8s.ovn.org/egress-assignable"
			podLabelKey      = "color"
			podLabelValue    = "blue"
			nodeLabelKey     = "name"
			nodeLabelValue   = "test"
		)
		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)

		workers := compat_otp.GetNodeListByLabel(oc, "node-role.kubernetes.io/worker")

		compat_otp.By("Apply label to namespace\n")
		nsLabel := nodeLabelKey + "=" + nodeLabelValue
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, "name-").Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, nsLabel).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Create an egressip object\n")

		compat_otp.By("Apply EgressLabel Key to one node.")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], egressNodeLabel, "true")

		freeIPs := findFreeIPs(oc, workers[0], 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))

		egressip := networkingRes{
			name:      "egressip-" + getRandomString(),
			namespace: ns,
			kind:      "egressip",
			tempfile:  egressIPTemplate,
		}

		defer removeResource(oc, true, true, "egressip", egressip.name)
		egressip.create(oc, "NAME="+egressip.name, "EGRESSIP1="+freeIPs[0], "NSLABELKEY="+nodeLabelKey, "NSLABELVALUE="+nodeLabelValue,
			"PODLABELKEY="+podLabelKey, "PODLABELVALUE="+podLabelValue)

		verifyExpectedEIPNumInEIPObject(oc, egressip.name, 1)

		egressQos := networkingRes{
			name:      "default",
			namespace: ns,
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		testPod := networkingRes{
			name:      "test-pod",
			namespace: ns,
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}
		//create egressqos
		defer removeResource(oc, true, true, "egressqos", egressQos.name, "-n", egressQos.namespace)
		egressQos.create(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1="+"0.0.0.0/0", "CIDR2="+dstCIDR)

		defer removeResource(oc, true, true, "pod", testPod.name, "-n", testPod.namespace)
		testPod.create(oc, "NAME="+testPod.name, "NAMESPACE="+testPod.namespace)

		errPodRdy := waitForPodWithLabelReady(oc, ns, "name="+testPod.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpod isn't ready"))

		podLable := podLabelKey + "=" + podLabelValue
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("pod", testPod.name, "-n", testPod.namespace, podLable).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2) ####### Check dscp value of egress traffic   ##########")
		defer rmPktsFile(a, oc, dscpSvcIP, pktFile)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile)

		startCurlTraffic(oc, testPod.namespace, testPod.name, externalPrivateIP, dscpSvcPort)
		// the first matched egressqos rule and egressip can take effect
		chkRes := chkDSCPandEIPinPkts(a, oc, dscpSvcIP, pktFile, dscpValue, freeIPs[0])
		o.Expect(chkRes).Should(o.BeTrue())

	})

	g.It("Author:yingwang-High-74054-Egress traffic works with ANP, BANP and NP with EgressQos. [Disruptive]", func() {
		var (
			dstCIDR          = externalPrivateIP + "/" + "32"
			dscpValue        = 40
			testDataDir      = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(testDataDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-template.yaml")
			testPodTmpFile   = filepath.Join(egressBaseDir, "testpod-template.yaml")
			pktFile1         = getRandomString() + "pcap.txt"
			pktFile2         = getRandomString() + "pcap.txt"

			banpCRTemplate = filepath.Join(testDataDir, "adminnetworkpolicy", "banp-single-rule-cidr-template.yaml")
			anpCRTemplate  = filepath.Join(testDataDir, "adminnetworkpolicy", "anp-single-rule-cidr-template.yaml")
			matchLabelKey  = "kubernetes.io/metadata.name"
			banpRuleName   = "banp-rule"
			anpRuleName    = "anp-rule"
		)

		ns := oc.Namespace()

		compat_otp.By("####### 1. Create pod and egressqos #############")

		egressQos := networkingRes{
			name:      "default",
			namespace: ns,
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		testPod := networkingRes{
			name:      "test-pod",
			namespace: ns,
			kind:      "pod",
			tempfile:  testPodTmpFile,
		}
		//create egressqos
		defer removeResource(oc, true, true, "egressqos", egressQos.name, "-n", egressQos.namespace)
		egressQos.create(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1="+"0.0.0.0/0", "CIDR2="+dstCIDR)

		defer removeResource(oc, true, true, "pod", testPod.name, "-n", testPod.namespace)
		testPod.create(oc, "NAME="+testPod.name, "NAMESPACE="+testPod.namespace)

		errPodRdy := waitForPodWithLabelReady(oc, ns, "name="+testPod.name)
		compat_otp.AssertWaitPollNoErr(errPodRdy, fmt.Sprintf("testpod isn't ready"))

		compat_otp.By("########### 2. Create a Admin Network Policy with deny action ############")

		anpCR := singleRuleCIDRANPPolicyResource{
			name:       "anp-74054",
			subjectKey: matchLabelKey,
			subjectVal: ns,
			priority:   10,
			ruleName:   anpRuleName,
			ruleAction: "Deny",
			cidr:       dstCIDR,
			template:   anpCRTemplate,
		}
		defer removeResource(oc, true, true, "anp", anpCR.name)
		anpCR.createSingleRuleCIDRANP(oc)

		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, anpCR.name)).To(o.BeTrue())

		compat_otp.By("############ 3. Verify ANP blocks matching egress traffic #############")
		CurlPod2HostFail(oc, ns, testPod.name, externalPrivateIP, dscpSvcPort)

		compat_otp.By("############## 4. edit ANP rule to allow egress traffic #############")
		patchYamlToRestore := `[{"op":"replace","path":"/spec/egress/0/action","value":"Allow"}]`
		output, err1 := oc.AsAdmin().WithoutNamespace().Run("patch").Args("adminnetworkpolicy", anpCR.name, "--type=json", "-p", patchYamlToRestore).Output()
		e2e.Logf("patch result is %v", output)
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "adminnetworkpolicy.policy.networking.k8s.io/anp-74054 patched")).To(o.BeTrue())

		compat_otp.By("############# 5. check egress traffic can pass and dscp value is correct ###########")
		defer rmPktsFile(a, oc, dscpSvcIP, pktFile1)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile1)

		startCurlTraffic(oc, testPod.namespace, testPod.name, dscpSvcIP, dscpSvcPort)

		chkRes := chkDSCPinPkts(a, oc, dscpSvcIP, pktFile1, dscpValue)
		o.Expect(chkRes).Should(o.BeTrue())

		compat_otp.By("############## 6. edit ANP rule to action pass  #############")
		patchYamlToRestore = `[{"op":"replace","path":"/spec/egress/0/action","value":"Pass"}]`
		output, err1 = oc.AsAdmin().WithoutNamespace().Run("patch").Args("adminnetworkpolicy", anpCR.name, "--type=json", "-p", patchYamlToRestore).Output()
		e2e.Logf("patch result is %v", output)
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "adminnetworkpolicy.policy.networking.k8s.io/anp-74054 patched")).To(o.BeTrue())

		compat_otp.By("############ 7. Create a Baseline Admin Network Policy with deny action ############")
		banpCR := singleRuleCIDRBANPPolicyResource{
			name:       "default",
			subjectKey: matchLabelKey,
			subjectVal: ns,
			ruleName:   banpRuleName,
			ruleAction: "Deny",
			cidr:       dstCIDR,
			template:   banpCRTemplate,
		}

		defer removeResource(oc, true, true, "banp", banpCR.name)
		banpCR.createSingleRuleCIDRBANP(oc)

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("banp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, banpCR.name)).To(o.BeTrue())

		compat_otp.By("############# 8. Verify BANP blocks matching egress traffic #########")
		CurlPod2HostFail(oc, ns, testPod.name, externalPrivateIP, dscpSvcPort)

		compat_otp.By("############ 9. edit BANP rule to allow egress traffic ###############")
		patchYamlToRestore = `[{"op":"replace","path":"/spec/egress/0/action","value":"Allow"}]`
		output, err1 = oc.AsAdmin().WithoutNamespace().Run("patch").Args("baselineadminnetworkpolicy", banpCR.name, "--type=json", "-p", patchYamlToRestore).Output()
		o.Expect(err1).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "baselineadminnetworkpolicy.policy.networking.k8s.io/default patched")).To(o.BeTrue())

		compat_otp.By("############# 10. check egress traffic can pass and dscp value is correct #############")
		defer rmPktsFile(a, oc, dscpSvcIP, pktFile2)
		startTcpdumpOnDscpService(a, oc, dscpSvcIP, pktFile2)

		startCurlTraffic(oc, testPod.namespace, testPod.name, dscpSvcIP, dscpSvcPort)

		chkRes = chkDSCPinPkts(a, oc, dscpSvcIP, pktFile2, dscpValue)
		o.Expect(chkRes).Should(o.BeTrue())

	})

})

var _ = g.Describe("[OTP][sig-networking] SDN egressqos negative test", func() {
	defer g.GinkgoRecover()
	var (
		oc = compat_otp.NewCLI("networking-egressqos", compat_otp.KubeConfigPath())
	)

	g.It("Author:qiowang-NonHyperShiftHOST-Medium-52365-negative validation for egressqos.", func() {
		var (
			networkBaseDir   = testdata.FixturePath("networking")
			egressBaseDir    = filepath.Join(networkBaseDir, "egressqos")
			egressQosTmpFile = filepath.Join(egressBaseDir, "egressqos-template.yaml")
			invalideDstCIDR  = []string{"abc/24", "$@#/132", "asd::/64", "1.2.3.4/58", "abc::/158"}
		)

		ns := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns)
		egressQos := egressQosResource{
			name:      "default",
			namespace: ns,
			kind:      "egressqos",
			tempfile:  egressQosTmpFile,
		}

		for _, cidr := range invalideDstCIDR {
			compat_otp.By("####### Create egressqos with wrong syntax/value CIDR rules " + cidr + " ##########")
			output, _ := egressQos.createWithOutput(oc, "NAME="+egressQos.name, "NAMESPACE="+egressQos.namespace, "CIDR1=1.1.1.1/32", "CIDR2="+cidr)
			o.Expect(output).Should(o.ContainSubstring("Invalid value"))
		}
	})
})
