package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[OTP][sig-networking] SDN sriov-nic", func() {
	defer g.GinkgoRecover()
	var (
		oc                  = exutil.NewCLI("sriov-" + getRandomString())
		buildPruningBaseDir = testdata.FixturePath("networking/sriov")
		sriovNeworkTemplate = filepath.Join(buildPruningBaseDir, "sriovnetwork-whereabouts-template.yaml")
		sriovOpNs           = "openshift-sriov-network-operator"
		vfNum               = 2
	)
	type testData = struct {
		Name          string
		DeviceID      string
		Vendor        string
		InterfaceName string
	}

	data := testData{
		Name:          "x710",
		DeviceID:      "1572",
		Vendor:        "8086",
		InterfaceName: "ens5f0",
	}

	g.BeforeEach(func() {
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com") || strings.Contains(msg, "offload.openshift-qe.sdn.com")) {
			g.Skip("This case will only run on rdu1/rdu2 cluster. , skip for other envrionment!!!")
		}

		compat_otp.By("check the sriov operator is running")
		chkSriovOperatorStatus(oc, sriovOpNs)

		sriovNodeList, nodeErr := compat_otp.GetClusterNodesBy(oc, "sriov")
		o.Expect(nodeErr).NotTo(o.HaveOccurred())

		if len(sriovNodeList) < 1 {
			g.Skip("Not enough SR-IOV nodes for this test, skip the test!")
		}

	})

	g.It("Author:yingwang-Medium-NonPreRelease-Longduration-69600-VF use and release testing [Disruptive]", func() {
		var caseID = "69600-"
		networkName := caseID + "net"
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)
		buildPruningBaseDir := testdata.FixturePath("networking/sriov")
		sriovTestPodTemplate := filepath.Join(buildPruningBaseDir, "sriov-netdevice-template.yaml")
		// Create VF on with given device
		defer rmSriovNetworkPolicy(oc, data.Name, sriovOpNs)
		result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
		// if the deviceid is not exist on the worker, skip this
		if !result {
			g.Skip("This nic which has deviceID is not found on this cluster!!!")
		}
		e2e.Logf("###############start to test %v sriov on nic %v ################", data.Name, data.InterfaceName)
		compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
		e2e.Logf("device ID is %v", data.DeviceID)
		e2e.Logf("device Name is %v", data.Name)
		sriovnetwork := sriovNetwork{
			name:             networkName,
			resourceName:     data.Name,
			networkNamespace: ns1,
			template:         sriovNeworkTemplate,
			namespace:        sriovOpNs,
			spoolchk:         "on",
			trust:            "on",
		}
		//defer
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)

		//create full number pods which use all of the VFs
		testpodPrex := "testpod"
		workerList := getWorkerNodesWithNic(oc, data.DeviceID, data.InterfaceName)
		o.Expect(workerList).NotTo(o.BeEmpty())
		numWorker := len(workerList)
		fullVFNum := vfNum * numWorker

		createNumPods(oc, sriovnetwork.name, ns1, testpodPrex, fullVFNum)

		//creating new pods will fail because all VFs are used.
		sriovTestNewPod := sriovTestPod{
			name:        "testpodnew",
			namespace:   ns1,
			networkName: sriovnetwork.name,
			template:    sriovTestPodTemplate,
		}
		sriovTestNewPod.createSriovTestPod(oc)
		e2e.Logf("creating new testpod should fail, because all VFs are used")
		o.Eventually(func() string {
			podStatus, _ := getPodStatus(oc, ns1, sriovTestNewPod.name)
			return podStatus
		}, 20*time.Second, 5*time.Second).Should(o.Equal("Pending"), fmt.Sprintf("Pod: %s should not be in Running state", sriovTestNewPod.name))

		//delete one pod and the testpodnew will be ready
		testpodName := testpodPrex + "0"
		sriovTestRmPod := sriovTestPod{
			name:        testpodName,
			namespace:   ns1,
			networkName: sriovnetwork.name,
			template:    sriovTestPodTemplate,
		}

		sriovTestRmPod.deleteSriovTestPod(oc)
		err := waitForPodWithLabelReady(oc, sriovTestNewPod.namespace, "app="+sriovTestNewPod.name)
		compat_otp.AssertWaitPollNoErr(err, "The new created pod is not ready after one VF is released")
	})

	g.It("Author:yingwang-Medium-NonPreRelease-Longduration-24780-NAD will be deleted too when sriovnetwork is deleted", func() {
		var caseID = "24780-"
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)
		networkName := caseID + "net"
		compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
		e2e.Logf("device ID is %v", data.DeviceID)
		e2e.Logf("device Name is %v", data.Name)
		sriovnetwork := sriovNetwork{
			name:             networkName,
			resourceName:     "none",
			networkNamespace: ns1,
			template:         sriovNeworkTemplate,
			namespace:        sriovOpNs,
			spoolchk:         "on",
			trust:            "on",
		}
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)
		errChk1 := chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk1, "Can't find NAD after sriovnetwork is created")
		//delete sriovnetwork
		rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		//NAD should be deleted too
		errChk2 := chkNAD(oc, ns1, sriovnetwork.name, false)
		compat_otp.AssertWaitPollNoErr(errChk2, "NAD was not removed after sriovnetwork is removed")

	})
	g.It("Author:yingwang-Medium-NonPreRelease-24713-NAD can be also updated when networknamespace is change", func() {
		var caseID = "24713-"
		ns1 := "e2e-" + caseID + data.Name
		ns2 := "e2e-" + caseID + data.Name + "-new"
		networkName := caseID + "net"
		err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns1, "--ignore-not-found").Execute()
		compat_otp.SetNamespacePrivileged(oc, ns1)
		err = oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns2).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", ns2, "--ignore-not-found").Execute()
		compat_otp.SetNamespacePrivileged(oc, ns2)

		compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
		e2e.Logf("device ID is %v", data.DeviceID)
		e2e.Logf("device Name is %v", data.Name)
		sriovnetwork := sriovNetwork{
			name:             networkName,
			resourceName:     "none",
			networkNamespace: ns1,
			template:         sriovNeworkTemplate,
			namespace:        sriovOpNs,
			spoolchk:         "on",
			trust:            "on",
		}
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)
		errChk1 := chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk1, fmt.Sprintf("Can find NAD in ns %v", ns1))
		errChk2 := chkNAD(oc, ns2, sriovnetwork.name, true)
		compat_otp.AssertWaitPollWithErr(errChk2, fmt.Sprintf("Can not find NAD in ns %v", ns2))

		//change networknamespace and check NAD
		patchYamlToRestore := `[{"op":"replace","path":"/spec/networkNamespace","value":"` + ns2 + `"}]`
		output, err1 := oc.AsAdmin().WithoutNamespace().Run("patch").Args("sriovnetwork", sriovnetwork.name, "-n", sriovOpNs,
			"--type=json", "-p", patchYamlToRestore).Output()
		e2e.Logf("patch result is %v", output)
		o.Expect(err1).NotTo(o.HaveOccurred())
		matchStr := sriovnetwork.name + " patched"
		o.Expect(output).Should(o.ContainSubstring(matchStr))

		errChk1 = chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollWithErr(errChk1, fmt.Sprintf("Can not find NAD in ns %v after networknamespace changed", ns1))
		errChk2 = chkNAD(oc, ns2, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk2, fmt.Sprintf("Can find NAD in ns %v after networknamespace changed", ns2))

	})

	g.It("Author:yingwang-Medium-NonPreRelease-Longduration-25287-NAD should be able to restore by sriov operator when it was deleted", func() {
		var caseID = "25287-"
		networkName := caseID + "net"
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)
		compat_otp.By("Create sriovNetwork to generate net-attach-def on the target namespace")
		e2e.Logf("device ID is %v", data.DeviceID)
		e2e.Logf("device Name is %v", data.Name)
		sriovnetwork := sriovNetwork{
			name:             networkName,
			resourceName:     "nonE",
			networkNamespace: ns1,
			template:         sriovNeworkTemplate,
			namespace:        sriovOpNs,
			spoolchk:         "on",
			trust:            "on",
		}
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)
		errChk1 := chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk1, fmt.Sprintf("Can find NAD in ns %v", ns1))
		//remove NAD and check again
		rmNAD(oc, ns1, sriovnetwork.name)
		errChk2 := chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk2, fmt.Sprintf("Can find NAD in ns %v as expected after NAD is removed", ns1))

	})

	g.It("Author:yingwang-Medium-NonPreRelease-Longduration-21364-Create pod with sriov-cni plugin and macvlan on the same interface [Disruptive]", func() {
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)
		var caseID = "21364-"
		networkName := caseID + "net"
		buildPruningBaseDir := testdata.FixturePath("networking/sriov")
		sriovTestPodTemplate := filepath.Join(buildPruningBaseDir, "sriov-multinet-template.yaml")
		netMacvlanTemplate := filepath.Join(buildPruningBaseDir, "nad-macvlan-template.yaml")
		netMacVlanName := "macvlannet"

		// Create VF on with given device
		defer rmSriovNetworkPolicy(oc, data.Name, sriovOpNs)
		result := initVF(oc, data.Name, data.DeviceID, data.InterfaceName, data.Vendor, sriovOpNs, vfNum)
		// if the deviceid is not exist on the worker, skip this
		if !result {
			g.Skip("This nic which has deviceID is not found on this cluster!!!")
		}
		e2e.Logf("###############start to test %v sriov on nic %v ################", data.Name, data.InterfaceName)
		compat_otp.By("Create sriovNetwork nad to generate net-attach-def on the target namespace")
		sriovnetwork := sriovNetwork{
			name:             networkName,
			resourceName:     data.Name,
			networkNamespace: ns1,
			template:         sriovNeworkTemplate,
			namespace:        sriovOpNs,
			linkState:        "enable",
		}

		networkMacvlan := sriovNetResource{
			name:      netMacVlanName,
			namespace: ns1,
			kind:      "NetworkAttachmentDefinition",
			tempfile:  netMacvlanTemplate,
		}

		//defer
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)

		defer networkMacvlan.delete(oc)
		networkMacvlan.create(oc, "NADNAME="+networkMacvlan.name, "NAMESPACE="+networkMacvlan.namespace)

		//create pods with both sriovnetwork and macvlan network
		for i := 0; i < 2; i++ {
			sriovTestPod := sriovNetResource{
				name:      "testpod" + strconv.Itoa(i),
				namespace: ns1,
				kind:      "pod",
				tempfile:  sriovTestPodTemplate,
			}
			defer sriovTestPod.delete(oc)
			sriovTestPod.create(oc, "PODNAME="+sriovTestPod.name, "NETWORKE1="+sriovnetwork.name, "NETWORKE2="+networkMacvlan.name, "NAMESPACE="+ns1)
			err := waitForPodWithLabelReady(oc, sriovTestPod.namespace, "name="+sriovTestPod.name)
			compat_otp.AssertWaitPollNoErr(err, "The new created pod is not ready")
		}
		chkPodsPassTraffic(oc, "testpod0", "testpod1", "net1", ns1)
		chkPodsPassTraffic(oc, "testpod0", "testpod1", "net2", ns1)

	})

	g.It("Author:yingwang-Medium-NonPreRelease-25847-SR-IOV operator-webhook can be disable by edit SR-IOV Operator Config [Serial]", func() {
		// check webhook pods are running
		chkPodsStatus(oc, sriovOpNs, "app=operator-webhook")
		//disable webhook
		defer chkSriovWebhookResource(oc, true)
		defer chkPodsStatus(oc, sriovOpNs, "app=operator-webhook")
		defer setSriovWebhook(oc, "true")
		setSriovWebhook(oc, "false")
		// webhook pods should be deleted
		o.Eventually(func() string {
			podStatus, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-l", "app=operator-webhook", "-n", sriovOpNs).Output()
			return podStatus
		}, 20*time.Second, 5*time.Second).Should(o.ContainSubstring("No resources found"), fmt.Sprintf("sriov webhook pods are removed"))
		chkSriovWebhookResource(oc, false)
		// set webhook true
		setSriovWebhook(oc, "true")
		// webhook pods should be recovered
		chkPodsStatus(oc, sriovOpNs, "app=operator-webhook")
		chkSriovWebhookResource(oc, true)

	})

	g.It("Author:yingwang-Medium-NonPreRelease-25814-SR-IOV resource injector can be disable by edit SR-IOV Operator Config [Serial]", func() {
		// check network-resources-injector pods are running
		chkPodsStatus(oc, sriovOpNs, "app=network-resources-injector")
		//disable network-resources-injector
		defer chkSriovInjectorResource(oc, true)
		defer chkPodsStatus(oc, sriovOpNs, "app=network-resources-injector")
		defer setSriovInjector(oc, "true")
		setSriovInjector(oc, "false")
		// network-resources-injector pods should be deleted
		o.Eventually(func() string {
			podStatus, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-l", "app=network-resources-injector", "-n", sriovOpNs).Output()
			return podStatus
		}, 20*time.Second, 5*time.Second).Should(o.ContainSubstring("No resources found"), fmt.Sprintf("sriov network-resources-injector pods are removed"))
		chkSriovInjectorResource(oc, false)
		// set network-resources-injector true
		setSriovInjector(oc, "true")
		// network-resources-injector pods should be recovered
		chkPodsStatus(oc, sriovOpNs, "app=network-resources-injector")
		chkSriovInjectorResource(oc, true)

	})
})

var _ = g.Describe("[OTP][sig-networking] SDN sriov externallyManaged", func() {
	defer g.GinkgoRecover()
	var (
		oc          = exutil.NewCLI("sriov-" + getRandomString())
		testDataDir = testdata.FixturePath("networking")
		sriovOpNs   = "openshift-sriov-network-operator"
	)
	type testData = struct {
		Name          string
		DeviceID      string
		Vendor        string
		InterfaceName string
	}

	data := testData{
		Name:          "x710",
		DeviceID:      "1572",
		Vendor:        "8086",
		InterfaceName: "ens5f0",
	}

	sriovDevices := make(map[string]testData)
	var node string
	var sriovNodeList []string
	var nodeErr error

	g.BeforeEach(func() {
		msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
		if err != nil || !(strings.Contains(msg, "sriov.openshift-qe.sdn.com") || strings.Contains(msg, "offload.openshift-qe.sdn.com")) {
			g.Skip("This case will only run on rdu1/rdu2 cluster. , skip for other envrionment!!!")
		}

		compat_otp.By("check the sriov operator is running")
		chkSriovOperatorStatus(oc, sriovOpNs)

		sriovNodeList, nodeErr = compat_otp.GetClusterNodesBy(oc, "sriov")
		o.Expect(nodeErr).NotTo(o.HaveOccurred())

		if len(sriovNodeList) < 1 {
			g.Skip("Not enough SR-IOV nodes for this test, skip the test!")
		}
		node = sriovNodeList[0]

		// Record SRIOV device data on each SR-IOV node of RDUs
		if err != nil || strings.Contains(msg, "sriov.openshift-qe.sdn.com") {
			e2e.Logf("Running the test on RDU1")
			data = testData{
				Name:          "e810xxv",
				DeviceID:      "159b",
				Vendor:        "8086",
				InterfaceName: "ens2f0",
			}
		}
		if err != nil || strings.Contains(msg, "offload.openshift-qe.sdn.com") {
			e2e.Logf("Running the test on RDU2")
			data = testData{
				Name:          "xl710",
				DeviceID:      "1583",
				Vendor:        "8086",
				InterfaceName: "ens2f1",
			}
		}

		g.By("0.0 Check if the deviceID exists on the cluster")
		if !checkDeviceIDExist(oc, sriovOpNs, data.DeviceID) {
			g.Skip("the cluster does not contain the sriov card. skip this testing!")
		}

		compat_otp.By("0.1 Get the node's name that has the device")
		for _, thisNode := range sriovNodeList {
			output, err := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, thisNode, []string{"--quiet=true", "--to-namespace=default"}, "bash", "-c", "nmcli", "con", "show")
			o.Expect(err).NotTo(o.HaveOccurred())
			if strings.Contains(output, data.InterfaceName) {
				node = thisNode
				break
			}
		}
		sriovDevices[node] = data
		e2e.Logf("\n what node is used for the test: %s\n", node)

		compat_otp.By("0.2 Check if the interface has carrier")
		if checkInterfaceNoCarrier(oc, node, sriovDevices[node].InterfaceName) {
			g.Skip("The interface on the device has NO-CARRIER, skip this testing!")
		}
	})

	g.It("Author:jechen-Longduration-NonPreRelease-High-63533-ExternallyManaged: Recreate VFs when SR-IOV policy is applied [Disruptive][Flaky]", func() {

		nmstateCRTemplate := filepath.Join(testDataDir, "nmstate", "nmstate-cr-template.yaml")
		nncpAddVFTemplate := filepath.Join(testDataDir, "nmstate", "nncp-vfs-specific-node-template.yaml")
		nncpDelVFTemplate := filepath.Join(testDataDir, "nmstate", "nncp-remove-vfs-specific-node-template.yaml")
		sriovNodeNetworkPolicyTemplate := filepath.Join(testDataDir, "sriov", "sriovnodepolicy-externallymanaged-template.yaml")
		sriovNeworkTemplate := filepath.Join(testDataDir, "sriov", "sriovnetwork2-template.yaml")
		sriovTestPodTemplate := filepath.Join(testDataDir, "sriov", "sriovtestpod2-with-mac-template.yaml")
		opNamespace := "openshift-nmstate"

		compat_otp.By("\n 1. Install nmstate operator and create nmstate CR \n")
		installNMstateOperator(oc)
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("\n 2. Apply policy to create VFs on SR-IOV node by nmstate \n")
		VFPolicy := VFPolicyResource{
			name:     "vf-policy-63533",
			intfname: sriovDevices[node].InterfaceName,
			nodename: node,
			totalvfs: 2,
			template: nncpAddVFTemplate,
		}

		// defer cleanup VFs by recreating VFPolicy with 0 VFs, then defer delete the VFPolicy
		defer deleteNNCP(oc, VFPolicy.name)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, VFPolicy.nodename, []string{"--quiet=true", "--to-namespace=default"}, "bash", "-c", "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			VFPolicy.totalvfs = 0
			if strings.Contains(ifaces, VFPolicy.intfname) {
				VFPolicy.createVFPolicy(oc)
				nncpErr1 := checkNNCPStatus(oc, VFPolicy.name, "Available")
				compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
				e2e.Logf("SUCCESS - NNCP policy to create VFs applied")
			}
		}()

		VFPolicy.createVFPolicy(oc)
		compat_otp.By("\n 2.1 Verify the policy is applied \n")
		nncpErr1 := checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to create VFs applied")

		compat_otp.By("\n 2.2 Verify the created VFs found in node network state \n")
		output, nnsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).Should(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
		), "Not all %d VFs are created.\n", VFPolicy.totalvfs)

		compat_otp.By("\n 3. Create SR-IOV policy on the node with ExternallyManaged set to true \n")
		sriovNNPolicy := sriovNetworkNodePolicySpecificNode{
			policyName:   "sriovnn",
			deviceType:   "netdevice",
			pfName:       sriovDevices[node].InterfaceName,
			numVfs:       2,
			resourceName: "sriovnn",
			nodename:     node,
			namespace:    sriovOpNs,
			template:     sriovNodeNetworkPolicyTemplate,
		}
		defer removeResource(oc, true, true, "SriovNetworkNodePolicy", sriovNNPolicy.policyName, "-n", sriovOpNs)
		sriovNNPolicy.createPolicySpecificNode(oc)
		waitForSriovPolicyReady(oc, sriovOpNs)

		compat_otp.By("\n 4. Create a target namespce, then create sriovNetwork to generate net-attach-def on the target namespace \n")
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)

		sriovnetwork := sriovNetwork{
			name:             sriovNNPolicy.policyName,
			resourceName:     sriovNNPolicy.resourceName,
			networkNamespace: ns1,
			template:         sriovNeworkTemplate,
			namespace:        sriovOpNs,
		}
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)

		e2e.Logf("\n expect to see NAD of %s in namespace : %s\n", sriovnetwork.name, ns1)
		errChk1 := chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk1, "Did not find NAD in the namespace")

		// compat_otp.By("\n 5. Create test pod1 with static MAC and test pod2 with dynamic MAC in target namespace\n")
		compat_otp.By("\n Create test pod1 on the target namespace \n")
		sriovTestPod1 := sriovTestPodMAC{
			name:         "sriov-63533-test-pod1",
			namespace:    ns1,
			ipaddr:       "192.168.10.1/24",
			macaddr:      "20:04:0f:f1:88:01",
			sriovnetname: sriovnetwork.name,
			tempfile:     sriovTestPodTemplate,
		}
		sriovTestPod1.createSriovTestPodMAC(oc)
		err := waitForPodWithLabelReady(oc, sriovTestPod1.namespace, "app="+sriovTestPod1.name)
		compat_otp.AssertWaitPollNoErr(err, "SRIOV client test pod is not ready")

		compat_otp.By("\n 5.2 Create test pod2 on the target namespace \n")
		sriovTestPod2 := sriovTestPodMAC{
			name:         "sriov-63533-test-pod2",
			namespace:    ns1,
			ipaddr:       "192.168.10.2/24",
			macaddr:      "",
			sriovnetname: sriovnetwork.name,
			tempfile:     sriovTestPodTemplate,
		}
		sriovTestPod2.createSriovTestPodMAC(oc)
		err = waitForPodWithLabelReady(oc, sriovTestPod2.namespace, "app="+sriovTestPod2.name)
		compat_otp.AssertWaitPollNoErr(err, "SRIOV server test pod is not ready")

		compat_otp.By("\n 5.3 Check traffic between two test pods \n")

		chkPodsPassTraffic(oc, sriovTestPod1.name, sriovTestPod2.name, "net1", ns1)
		chkPodsPassTraffic(oc, sriovTestPod2.name, sriovTestPod1.name, "net1", ns1)

		removeResource(oc, true, true, "pod", sriovTestPod1.name, "-n", sriovTestPod1.namespace)
		removeResource(oc, true, true, "pod", sriovTestPod2.name, "-n", sriovTestPod2.namespace)

		compat_otp.By("\n 6. Remove SR-IOV policy, wait for nns state to be stable, then verify VFs still remind \n")
		removeResource(oc, true, true, "SriovNetworkNodePolicy", sriovNNPolicy.policyName, "-n", sriovOpNs)
		waitForSriovPolicyReady(oc, sriovOpNs)

		output, nnsErr1 = oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).Should(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
		), "Not all %d VFs reminded!!!", VFPolicy.totalvfs)

		compat_otp.By("\n 7. Apply policy by nmstate to remove VFs then recreate VFs with one extra VF\n")
		compat_otp.By("\n 7.1. Apply policy by nmstate to remove VFs\n")
		VFPolicy.template = nncpDelVFTemplate

		VFPolicy.createVFPolicy(oc)
		nncpErr1 = checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to delete VFs applied")

		output, nnsErr1 = oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).ShouldNot(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
		), "Not all %d VFs are deleted correctly.\n", VFPolicy.totalvfs)

		compat_otp.By("\n 7.2. Apply policy by nmstate to add VFs with an extra VF\n")
		VFPolicy.template = nncpAddVFTemplate
		VFPolicy.totalvfs = 3

		VFPolicy.createVFPolicy(oc)
		nncpErr1 = checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to recreate VFs applied")

		output, nnsErr1 = oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).Should(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v2"),
		), "Not all %d VFs are added correctly.\n", VFPolicy.totalvfs)

		compat_otp.By("\n 8. Recreate test pods and verify connectivity betwen two pods\n")
		sriovTestPod1.createSriovTestPodMAC(oc)
		err = waitForPodWithLabelReady(oc, sriovTestPod1.namespace, "app="+sriovTestPod1.name)
		compat_otp.AssertWaitPollNoErr(err, "SRIOV client test pod is not ready")
		sriovTestPod2.createSriovTestPodMAC(oc)
		err = waitForPodWithLabelReady(oc, sriovTestPod2.namespace, "app="+sriovTestPod2.name)
		compat_otp.AssertWaitPollNoErr(err, "SRIOV server test pod is not ready")

		chkPodsPassTraffic(oc, sriovTestPod1.name, sriovTestPod2.name, "net1", ns1)
		chkPodsPassTraffic(oc, sriovTestPod2.name, sriovTestPod1.name, "net1", ns1)

		compat_otp.By("\n 9. Apply policy by nmstate to remove VFs\n")
		VFPolicy.template = nncpDelVFTemplate

		VFPolicy.createVFPolicy(oc)
		nncpErr1 = checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to delete VFs applied")

		output, nnsErr1 = oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).ShouldNot(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v2"),
		), "Not all %d VFs are deleted correctly.\n", VFPolicy.totalvfs)

	})

	g.It("Author:jechen-Longduration-NonPreRelease-Medium-63534-Verify ExternallyManaged SR-IOV network with options [Disruptive][Flaky]", func() {

		nmstateCRTemplate := filepath.Join(testDataDir, "nmstate", "nmstate-cr-template.yaml")
		nncpAddVFTemplate := filepath.Join(testDataDir, "nmstate", "nncp-vfs-opt-specific-node-template.yaml")
		nncpDelVFTemplate := filepath.Join(testDataDir, "nmstate", "nncp-remove-vfs-specific-node-template.yaml")
		sriovNodeNetworkPolicyTemplate := filepath.Join(testDataDir, "sriov", "sriovnodepolicy-externallymanaged-template.yaml")
		sriovNeworkTemplate := filepath.Join(testDataDir, "sriov", "sriovnetwork3-options-template.yaml")
		sriovTestPodTemplate := filepath.Join(testDataDir, "sriov", "sriovtestpod2-with-mac-template.yaml")
		opNamespace := "openshift-nmstate"

		compat_otp.By("\n 1. Install nmstate operator and create nmstate CR \n")
		installNMstateOperator(oc)
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("\n 2. Apply policy to create VFs on SR-IOV node by nmstate \n")
		VFPolicy := VFPolicyResource{
			name:     "vf-policy-63534",
			intfname: sriovDevices[node].InterfaceName,
			nodename: node,
			totalvfs: 2,
			template: nncpAddVFTemplate,
		}

		// defer cleanup VFs by recreating VFPolicy with 0 VFs, then defer delete the VFPolicy
		defer deleteNNCP(oc, VFPolicy.name)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, VFPolicy.nodename, []string{"--quiet=true", "--to-namespace=default"}, "bash", "-c", "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			VFPolicy.totalvfs = 0
			if strings.Contains(ifaces, VFPolicy.intfname) {
				VFPolicy.createVFPolicy(oc)
				nncpErr1 := checkNNCPStatus(oc, VFPolicy.name, "Available")
				compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
				e2e.Logf("SUCCESS - NNCP policy to create VFs applied")
			}
		}()

		VFPolicy.createVFPolicy(oc)
		compat_otp.By("\n 2.1 Verify the policy is applied \n")
		nncpErr1 := checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to create VFs applied")

		compat_otp.By("\n 2.2 Verify the created VFs found in node network state \n")
		output, nnsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).Should(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
		), "Not all %d VFs are created.\n", VFPolicy.totalvfs)

		compat_otp.By("\n 3. Create SR-IOV policy on the node with ExternallyManaged set to true \n")
		sriovNNPolicy := sriovNetworkNodePolicySpecificNode{
			policyName:   "sriovnn",
			deviceType:   "netdevice",
			pfName:       sriovDevices[node].InterfaceName,
			numVfs:       2,
			resourceName: "sriovnn",
			nodename:     node,
			namespace:    sriovOpNs,
			template:     sriovNodeNetworkPolicyTemplate,
		}
		defer removeResource(oc, true, true, "SriovNetworkNodePolicy", sriovNNPolicy.policyName, "-n", sriovOpNs)
		sriovNNPolicy.createPolicySpecificNode(oc)
		waitForSriovPolicyReady(oc, sriovOpNs)

		compat_otp.By("\n 4. Create a target namespce, then create sriovNetwork to generate net-attach-def on the target namespace \n")
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)

		sriovnetwork := sriovNetwork{
			name:             sriovNNPolicy.policyName,
			resourceName:     sriovNNPolicy.resourceName,
			networkNamespace: ns1,
			template:         sriovNeworkTemplate,
			namespace:        sriovOpNs,
		}
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)

		e2e.Logf("\n expect to see NAD of %s in namespace : %s\n", sriovnetwork.name, ns1)
		errChk1 := chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk1, "Did not find NAD in the namespace")

		compat_otp.By("\n 5. Create test pod1 with static MAC and test pod2 with dynamic MAC in target namespace\n")
		compat_otp.By("\n Test pods with IPv4, IPv6 and dualstack addresses will be tested in 3 iterations\n")
		addressPool1 := []string{"192.168.10.1/24", "2001:db8:abcd:0012::1/64", "192.168.10.1/24\", \"2001:db8:abcd:0012::1/64"}
		addressPool2 := []string{"192.168.10.2/24", "2001:db8:abcd:0012::2/64", "192.168.10.2/24\", \"2001:db8:abcd:0012::2/64"}

		for i := 0; i < 3; i++ {
			e2e.Logf("\n ************************* No %d set of test pods ******************\n", i+1)
			compat_otp.By("\n Create test pod1 on the target namespace \n")
			sriovTestPod1 := sriovTestPodMAC{
				name:         "sriov-63534-test-pod1",
				namespace:    ns1,
				ipaddr:       addressPool1[i],
				macaddr:      "20:04:0f:f1:88:01",
				sriovnetname: sriovnetwork.name,
				tempfile:     sriovTestPodTemplate,
			}
			sriovTestPod1.createSriovTestPodMAC(oc)
			err := waitForPodWithLabelReady(oc, sriovTestPod1.namespace, "app="+sriovTestPod1.name)
			compat_otp.AssertWaitPollNoErr(err, "SRIOV client test pod is not ready")

			compat_otp.By("\n 5.2 Create test pod2 on the target namespace \n")
			sriovTestPod2 := sriovTestPodMAC{
				name:         "sriov-63534-test-pod2",
				namespace:    ns1,
				ipaddr:       addressPool2[i],
				macaddr:      "",
				sriovnetname: sriovnetwork.name,
				tempfile:     sriovTestPodTemplate,
			}
			sriovTestPod2.createSriovTestPodMAC(oc)
			err = waitForPodWithLabelReady(oc, sriovTestPod2.namespace, "app="+sriovTestPod2.name)
			compat_otp.AssertWaitPollNoErr(err, "SRIOV server test pod is not ready")

			compat_otp.By("\n 5.3 Check traffic between two test pods \n")

			chkPodsPassTraffic(oc, sriovTestPod1.name, sriovTestPod2.name, "net1", ns1)
			chkPodsPassTraffic(oc, sriovTestPod2.name, sriovTestPod1.name, "net1", ns1)

			removeResource(oc, true, true, "pod", sriovTestPod1.name, "-n", sriovTestPod1.namespace)
			removeResource(oc, true, true, "pod", sriovTestPod2.name, "-n", sriovTestPod2.namespace)

			// wait a little before going to next iteration to recreate test pods with next set of addresses
			time.Sleep(3 * time.Second)
		}

		compat_otp.By("\n 6. Remove SR-IOV policy, wait for nns state to be stable, then verify VFs still remind \n")
		removeResource(oc, true, true, "SriovNetworkNodePolicy", sriovNNPolicy.policyName, "-n", sriovOpNs)
		waitForSriovPolicyReady(oc, sriovOpNs)

		output, nnsErr1 = oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).Should(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
		), "Not all %d VFs reminded!!!", VFPolicy.totalvfs)

		compat_otp.By("\n 7. Apply policy by nmstate to remove VFs\n")
		VFPolicy.template = nncpDelVFTemplate

		VFPolicy.createVFPolicy(oc)
		nncpErr1 = checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to delete VFs applied")

		output, nnsErr1 = oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).ShouldNot(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
		), "Not all %d VFs are deleted correctly.\n", VFPolicy.totalvfs)

	})

	g.It("Author:jechen-Longduration-NonPreRelease-High-63527-High-63537-High-46528-High-46530-High-46532-High-46533-Verify ExternallyManaged functionality with different IP protocols before and after SRIOV operator removal and re-installation [Disruptive]", func() {

		nmstateCRTemplate := filepath.Join(testDataDir, "nmstate", "nmstate-cr-template.yaml")
		nncpAddVFTemplate := filepath.Join(testDataDir, "nmstate", "nncp-vfs-specific-node-template.yaml")
		nncpDelVFTemplate := filepath.Join(testDataDir, "nmstate", "nncp-remove-vfs-specific-node-template.yaml")
		sriovNodeNetworkPolicyTemplate := filepath.Join(testDataDir, "sriov", "sriovnodepolicy-externallymanaged-template.yaml")
		sriovNeworkTemplate := filepath.Join(testDataDir, "sriov", "sriovnetwork2-template.yaml")
		sriovTestPodTemplate := filepath.Join(testDataDir, "sriov", "sriovtestpod2-with-mac-template.yaml")
		opNamespace := "openshift-nmstate"

		compat_otp.By("\n  **************** Before SRIOV un-installation: verify externallyManaged SRIOV functionality ***********************\n")
		compat_otp.By("\n 1. Before SRIOV un-stallation: install nmstate operator and create nmstate CR \n")
		installNMstateOperator(oc)
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("\n 2. Before SRIOV un-stallation: Apply policy to create VFs on SR-IOV node by nmstate \n")
		VFPolicy := VFPolicyResource{
			name:     "vf-policy-63537",
			intfname: sriovDevices[node].InterfaceName,
			nodename: node,
			totalvfs: 2,
			template: nncpAddVFTemplate,
		}

		// defer cleanup VFs by recreating VFPolicy with 0 VFs, then defer delete the VFPolicy
		defer deleteNNCP(oc, VFPolicy.name)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, VFPolicy.nodename, []string{"--quiet=true", "--to-namespace=default"}, "bash", "-c", "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			VFPolicy.totalvfs = 0
			if strings.Contains(ifaces, VFPolicy.intfname) {
				VFPolicy.createVFPolicy(oc)
				nncpErr1 := checkNNCPStatus(oc, VFPolicy.name, "Available")
				compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
				e2e.Logf("SUCCESS - NNCP policy to create VFs applied")
			}
		}()

		VFPolicy.createVFPolicy(oc)
		compat_otp.By("\n 2.1 Verify the policy is applied \n")
		nncpErr1 := checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to create VFs applied")

		compat_otp.By("\n 2.2 Verify the created VFs found in node network state \n")
		output, nnsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).Should(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
		), "Not all %d VFs are created.\n", VFPolicy.totalvfs)

		compat_otp.By("\n 3. Before SRIOV un-stallation: create SR-IOV policy on the node with ExternallyManaged set to true \n")
		sriovNNPolicy := sriovNetworkNodePolicySpecificNode{
			policyName:   "sriovnn",
			deviceType:   "netdevice",
			pfName:       sriovDevices[node].InterfaceName,
			numVfs:       2,
			resourceName: "sriovnn",
			nodename:     node,
			namespace:    sriovOpNs,
			template:     sriovNodeNetworkPolicyTemplate,
		}
		defer removeResource(oc, true, true, "SriovNetworkNodePolicy", sriovNNPolicy.policyName, "-n", sriovOpNs)
		sriovNNPolicy.createPolicySpecificNode(oc)
		waitForSriovPolicyReady(oc, sriovOpNs)

		compat_otp.By("\n 4. Before SRIOV un-stallation: create a target namespce, then create sriovNetwork to generate net-attach-def on the target namespace \n")
		ns1 := oc.Namespace()
		compat_otp.SetNamespacePrivileged(oc, ns1)

		sriovnetwork := sriovNetwork{
			name:             sriovNNPolicy.policyName,
			resourceName:     sriovNNPolicy.resourceName,
			networkNamespace: ns1,
			template:         sriovNeworkTemplate,
			namespace:        sriovOpNs,
		}
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)
		errChk1 := chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk1, "Did not find NAD in the namespace")

		compat_otp.By("\n 5. Before SRIOV un-stallation: create test pod1 with static MAC and test pod2 with dynamic MAC in target namespace\n")
		compat_otp.By("\n Test pods with IPv4, IPv6 and dualstack addresses will be tested in 3 iterations\n")
		addressPool1 := []string{"192.168.10.1/24", "2001:db8:abcd:0012::1/64", "192.168.10.1/24\", \"2001:db8:abcd:0012::1/64"}
		addressPool2 := []string{"192.168.10.2/24", "2001:db8:abcd:0012::2/64", "192.168.10.2/24\", \"2001:db8:abcd:0012::2/64"}

		var sriovTestPod1, sriovTestPod2 sriovTestPodMAC
		for i := 0; i < 3; i++ {
			e2e.Logf("\n ************************* No %d set of test pods ******************\n", i+1)
			compat_otp.By("\n 5.1 Create test pod1 on the target namespace \n")
			sriovTestPod1 = sriovTestPodMAC{
				name:         "sriov-test-pod1",
				namespace:    ns1,
				ipaddr:       addressPool1[i],
				macaddr:      "20:04:0f:f1:88:01",
				sriovnetname: sriovnetwork.name,
				tempfile:     sriovTestPodTemplate,
			}
			sriovTestPod1.createSriovTestPodMAC(oc)
			err := waitForPodWithLabelReady(oc, sriovTestPod1.namespace, "app="+sriovTestPod1.name)
			compat_otp.AssertWaitPollNoErr(err, "SRIOV client test pod is not ready")

			compat_otp.By("\n 5.2 Create test pod2 on the target namespace \n")
			sriovTestPod2 = sriovTestPodMAC{
				name:         "sriov-test-pod2",
				namespace:    ns1,
				ipaddr:       addressPool2[i],
				macaddr:      "",
				sriovnetname: sriovnetwork.name,
				tempfile:     sriovTestPodTemplate,
			}
			sriovTestPod2.createSriovTestPodMAC(oc)
			err = waitForPodWithLabelReady(oc, sriovTestPod2.namespace, "app="+sriovTestPod2.name)
			compat_otp.AssertWaitPollNoErr(err, "SRIOV server test pod is not ready")

			compat_otp.By("\n 5.3 Check traffic between two test pods \n")

			chkPodsPassTraffic(oc, sriovTestPod1.name, sriovTestPod2.name, "net1", ns1)
			chkPodsPassTraffic(oc, sriovTestPod2.name, sriovTestPod1.name, "net1", ns1)

			removeResource(oc, true, true, "pod", sriovTestPod1.name, "-n", sriovTestPod1.namespace)
			removeResource(oc, true, true, "pod", sriovTestPod2.name, "-n", sriovTestPod2.namespace)

			// wait a little before going to next iteration to recreate test pods with next set of addresses
			time.Sleep(3 * time.Second)
		}

		compat_otp.By("\n 6.1 Apply VF removal policy by nmstate to remove VFs\n")
		VFPolicy.template = nncpDelVFTemplate
		VFPolicy.createVFPolicy(oc)
		nncpErr1 = checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to delete VFs applied")

		compat_otp.By("\n 6.2 Delete the VFPolicy\n")
		deleteNNCP(oc, VFPolicy.name)
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("nncp", VFPolicy.name).Output()
		o.Expect(strings.Contains(output, "not found")).To(o.BeTrue())

		compat_otp.By("\n . ****************** SRIOV operator un-installation then re-installation ***********************\n")
		compat_otp.By("\n 7. Uninstall SRIOV operator \n")
		defer installSriovOperator(oc, sriovOpNs)
		uninstallSriovOperator(oc, sriovOpNs)

		compat_otp.By("\n 8. Re-install SRIOV operator")
		installSriovOperator(oc, sriovOpNs)

		// Due to https://bugzilla.redhat.com/show_bug.cgi?id=2033440, keep the placeholder but comment out the webhook failurePolicy check for now
		// compat_otp.By("\n 3. Check webhook failurePolicy after re-installation \n")
		// chkOutput, _ := exec.Command("bash", "-c", "oc get mutatingwebhookconfigurations network-resources-injector-config -oyaml | grep failurePolicy").Output()
		// e2e.Logf("\n failurePolicy for mutatingwebhookconfigurations network-resources-injector-config: %s\n", chkOutput)
		// o.Expect(strings.Contains(string(chkOutput), "Ignore")).To(o.BeTrue())
		// chkOutput, _ = exec.Command("bash", "-c", "oc get mutatingwebhookconfigurations sriov-operator-webhook-config -oyaml | grep failurePolicy").Output()
		// e2e.Logf("\n failurePolicy for mutatingwebhookconfigurations sriov-operator-webhook-config: %s\n", chkOutput)
		// o.Expect(strings.Contains(string(chkOutput), "Ignore")).To(o.BeTrue())
		// chkOutput, _ = exec.Command("bash", "-c", "oc get ValidatingWebhookConfiguration sriov-operator-webhook-config -oyaml | grep failurePolicy").Output()
		// e2e.Logf("\n failurePolicy for ValidatingWebhookConfiguration sriov-operator-webhook-config: %s\n", chkOutput)
		// o.Expect(strings.Contains(string(chkOutput), "Ignore")).To(o.BeTrue())

		compat_otp.By("\n  *********************** Post SRIOV re-installation: verify externallyManaged SRIOV functionality again ***********************\n")
		compat_otp.By("\n 9. Post sriov re-installation: re-apply policy to create VFs on SR-IOV node by nmstate \n")

		VFPolicy.template = nncpAddVFTemplate

		// defer cleanup VFs by recreating VFPolicy with 0 VFs, then defer delete the VFPolicy
		defer deleteNNCP(oc, VFPolicy.name)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, VFPolicy.nodename, []string{"--quiet=true", "--to-namespace=default"}, "bash", "-c", "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			VFPolicy.totalvfs = 0
			if strings.Contains(ifaces, VFPolicy.intfname) {
				VFPolicy.createVFPolicy(oc)
				nncpErr1 := checkNNCPStatus(oc, VFPolicy.name, "Available")
				compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
				e2e.Logf("SUCCESS - NNCP policy to create VFs applied")
			}
		}()

		VFPolicy.createVFPolicy(oc)
		compat_otp.By("\n 9.1 Verify the policy is applied \n")
		nncpErr1 = checkNNCPStatus(oc, VFPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - NNCP policy to create VFs applied")

		compat_otp.By("\n 9.2 Verify the created VFs found in node network state \n")
		output, nnsErr1 = oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", node, "-ojsonpath={.status.currentState.interfaces[?(@.name==\""+sriovDevices[node].InterfaceName+"\")].ethernet.sr-iov.vfs}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		e2e.Logf("\n output: %v\n", output)

		o.Expect(output).Should(o.And(
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v0"),
			o.ContainSubstring(sriovDevices[node].InterfaceName+"v1"),
		), "Not all %d VFs are created.\n", VFPolicy.totalvfs)

		compat_otp.By("\n 10. Post sriov re-installation: re-create SR-IOV policy on the node with ExternallyManaged set to true \n")
		defer removeResource(oc, true, true, "SriovNetworkNodePolicy", sriovNNPolicy.policyName, "-n", sriovOpNs)
		sriovNNPolicy.createPolicySpecificNode(oc)
		waitForSriovPolicyReady(oc, sriovOpNs)

		compat_otp.By("\n 11. Post sriov re-installation: re-create sriovNetwork to generate net-attach-def on the target namespace \n")
		defer rmSriovNetwork(oc, sriovnetwork.name, sriovOpNs)
		sriovnetwork.createSriovNetwork(oc)
		errChk1 = chkNAD(oc, ns1, sriovnetwork.name, true)
		compat_otp.AssertWaitPollNoErr(errChk1, "Did not find NAD in the namespace")

		compat_otp.By("\n 12. Post sriov re-installation: re-create test pod1 with static MAC and test pod2 with dynamic MAC in target namespace\n")
		compat_otp.By("\n Test pods with IPv4, IPv6 and dualstack addresses will be tested in 3 iterations\n")

		for i := 0; i < 3; i++ {
			e2e.Logf("\n ************************* No %d set of test pods ******************\n", i+1)
			compat_otp.By("\n 12.1 Create test pod1 on the target namespace \n")
			sriovTestPod1.ipaddr = addressPool1[i]
			sriovTestPod1.createSriovTestPodMAC(oc)
			err := waitForPodWithLabelReady(oc, sriovTestPod1.namespace, "app="+sriovTestPod1.name)
			compat_otp.AssertWaitPollNoErr(err, "SRIOV client test pod is not ready")

			compat_otp.By("\n 12.2 Create test pod2 on the target namespace \n")
			sriovTestPod2.ipaddr = addressPool2[i]
			sriovTestPod2.createSriovTestPodMAC(oc)
			err = waitForPodWithLabelReady(oc, sriovTestPod2.namespace, "app="+sriovTestPod2.name)
			compat_otp.AssertWaitPollNoErr(err, "SRIOV server test pod is not ready")

			compat_otp.By("\n 12.3 Check traffic between two test pods \n")
			chkPodsPassTraffic(oc, sriovTestPod1.name, sriovTestPod2.name, "net1", ns1)
			chkPodsPassTraffic(oc, sriovTestPod2.name, sriovTestPod1.name, "net1", ns1)

			removeResource(oc, true, true, "pod", sriovTestPod1.name, "-n", sriovTestPod1.namespace)
			removeResource(oc, true, true, "pod", sriovTestPod2.name, "-n", sriovTestPod2.namespace)

			// wait a little before going to next iteration to recreate test pods with next set of addresses
			time.Sleep(3 * time.Second)
		}
	})

})
