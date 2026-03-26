// Package networking NMState operator tests
package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[OTP][sig-networking] SDN nmstate-operator installation", func() {
	defer g.GinkgoRecover()

	var (
		oc = compat_otp.NewCLI("networking-nmstate", compat_otp.KubeConfigPath())
	)

	g.BeforeEach(func() {
		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}

		installNMstateOperator(oc)
	})

	g.It("[Level0] Author:qiowang-StagerunBoth-Critical-47088-NMState Operator installation ", func() {
		g.By("Checking nmstate operator installation")
		e2e.Logf("Operator install check successfull as part of setup !!!!!")
		e2e.Logf("SUCCESS - NMState operator installed")
	})
})

var _ = g.Describe("[OTP][sig-networking] SDN nmstate-operator functional", func() {
	defer g.GinkgoRecover()

	var (
		oc          = compat_otp.NewCLI("networking-nmstate", compat_otp.KubeConfigPath())
		opNamespace = "openshift-nmstate"
	)

	g.BeforeEach(func() {
		g.By("Check the platform and network plugin type if it is suitable for running the test")
		networkType := checkNetworkType(oc)
		if !(isPlatformSuitableForNMState(oc)) || !strings.Contains(networkType, "ovn") {
			g.Skip("Skipping for unsupported platform or non-OVN network plugin type!")
		}
		installNMstateOperator(oc)
	})

	g.It("Author:qiowang-NonPreRelease-Longduration-High-46380-High-46382-High-46379-Create/Disable/Remove interface on node [Disruptive] [Slow]", func() {
		g.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		g.By("2. OCP-46380-Creating interface on node")
		g.By("2.1 Configure NNCP for creating interface")
		policyName := "dummy-policy-46380"
		nodeList, getNodeErr := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		nodeName := nodeList[0]
		ifacePolicyTemplate := generateTemplateAbsolutePath("iface-policy-template.yaml")
		ifacePolicy := ifacePolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "dummy0",
			descr:      "create interface",
			ifacetype:  "dummy",
			state:      "up",
			template:   ifacePolicyTemplate,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, ifacePolicy.ifacename) {
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", ifacePolicy.ifacename)
			}
		}()
		result, configErr1 := configIface(oc, ifacePolicy)
		o.Expect(configErr1).NotTo(o.HaveOccurred())
		o.Expect(result).To(o.BeTrue())

		g.By("2.2 Verify the policy is applied")
		nncpErr1 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("2.3 Verify the status of enactments is updated")
		nnceName := nodeName + "." + policyName
		nnceErr1 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("2.4 Verify the created interface found in node network state")
		ifaceState, nnsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, "-ojsonpath={.status.currentState.interfaces[?(@.name==\"dummy0\")].state}").Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		o.Expect(ifaceState).Should(o.ContainSubstring("up"))
		e2e.Logf("SUCCESS - the created interface found in node network state")

		g.By("2.5 Verify the interface is up and active on the node")
		ifaceList1, ifaceErr1 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr1).NotTo(o.HaveOccurred())
		matched, matchErr1 := regexp.MatchString("dummy\\s+dummy0", ifaceList1)
		o.Expect(matchErr1).NotTo(o.HaveOccurred())
		o.Expect(matched).To(o.BeTrue())
		e2e.Logf("SUCCESS - interface is up and active on the node")

		g.By("3. OCP-46382-Disabling interface on node")
		g.By("3.1 Configure NNCP for disabling interface")
		ifacePolicy = ifacePolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "dummy0",
			descr:      "disable interface",
			ifacetype:  "dummy",
			state:      "down",
			template:   ifacePolicyTemplate,
		}
		result, configErr2 := configIface(oc, ifacePolicy)
		o.Expect(configErr2).NotTo(o.HaveOccurred())
		o.Expect(result).To(o.BeTrue())

		g.By("3.2 Verify the policy is applied")
		nncpErr2 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("3.3 Verify the status of enactments is updated")
		nnceErr2 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("3.4 Verify no disabled interface found in node network state")
		ifaceName1, nnsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, "-ojsonpath={.status.currentState.interfaces[*].name}").Output()
		o.Expect(nnsErr2).NotTo(o.HaveOccurred())
		o.Expect(ifaceName1).ShouldNot(o.ContainSubstring("dummy0"))
		e2e.Logf("SUCCESS - no disabled interface found in node network state")

		g.By("3.5 Verify the interface is down on the node")
		ifaceList2, ifaceErr2 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr2).NotTo(o.HaveOccurred())
		matched, matchErr2 := regexp.MatchString("dummy\\s+--", ifaceList2)
		o.Expect(matchErr2).NotTo(o.HaveOccurred())
		o.Expect(matched).To(o.BeTrue())
		e2e.Logf("SUCCESS - interface is down on the node")

		g.By("4. OCP-46379-Removing interface on node")
		g.By("4.1 Configure NNCP for removing interface")
		ifacePolicy = ifacePolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "dummy0",
			descr:      "remove interface",
			ifacetype:  "dummy",
			state:      "absent",
			template:   ifacePolicyTemplate,
		}
		result, configErr3 := configIface(oc, ifacePolicy)
		o.Expect(configErr3).NotTo(o.HaveOccurred())
		o.Expect(result).To(o.BeTrue())

		g.By("4.2 Verify the policy is applied")
		nncpErr3 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr3, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("4.3 Verify the status of enactments is updated")
		nnceErr3 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr3, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("4.4 Verify no removed interface found in node network state")
		ifaceName2, nnsErr3 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, "-ojsonpath={.status.currentState.interfaces[*].name}").Output()
		o.Expect(nnsErr3).NotTo(o.HaveOccurred())
		o.Expect(ifaceName2).ShouldNot(o.ContainSubstring("dummy0"))
		e2e.Logf("SUCCESS - no removed interface found in node network state")

		g.By("4.5 Verify the interface is removed from the node")
		ifaceList3, ifaceErr3 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr3).NotTo(o.HaveOccurred())
		matched, matchErr3 := regexp.MatchString("dummy0", ifaceList3)
		o.Expect(matchErr3).NotTo(o.HaveOccurred())
		o.Expect(matched).To(o.BeFalse())
		e2e.Logf("SUCCESS - interface is removed from the node")
	})

	g.It("[Level0] Author:qiowang-Critical-46329-Configure bond on node [Disruptive]", func() {
		g.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		g.By("2. Creating bond on node")
		g.By("2.1 Configure NNCP for creating bond")
		policyName := "bond-policy-46329"
		nodeList, getNodeErr := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		nodeName := nodeList[0]
		bondPolicyTemplate := generateTemplateAbsolutePath("bond-policy-template.yaml")
		bondPolicy := bondPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "bond01",
			descr:      "create bond",
			port1:      "dummy1",
			port2:      "dummy2",
			state:      "up",
			template:   bondPolicyTemplate,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, bondPolicy.ifacename) {
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", bondPolicy.port1)
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", bondPolicy.port2)
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", bondPolicy.ifacename)
			}
		}()
		configErr1 := configBond(oc, bondPolicy)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		g.By("2.2 Verify the policy is applied")
		nncpErr1 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("2.3 Verify the status of enactments is updated")
		nnceName := nodeName + "." + policyName
		nnceErr1 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("2.4 Verify the created bond found in node network state")
		ifaceState, nnsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="bond01")].state}`).Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		o.Expect(ifaceState).Should(o.ContainSubstring("up"))
		e2e.Logf("SUCCESS - the created bond found in node network state")

		g.By("2.5 Verify the bond is up and active on the node")
		ifaceList1, ifaceErr1 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr1).NotTo(o.HaveOccurred())
		matched, matchErr1 := regexp.MatchString("bond\\s+bond01", ifaceList1)
		o.Expect(matchErr1).NotTo(o.HaveOccurred())
		o.Expect(matched).To(o.BeTrue())
		e2e.Logf("SUCCESS - bond is up and active on the node")

		g.By("3. Remove bond on node")
		g.By("3.1 Configure NNCP for removing bond")
		bondPolicy = bondPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "bond01",
			descr:      "remove bond",
			port1:      "dummy1",
			port2:      "dummy2",
			state:      "absent",
			template:   bondPolicyTemplate,
		}
		configErr2 := configBond(oc, bondPolicy)
		o.Expect(configErr2).NotTo(o.HaveOccurred())

		g.By("3.2 Verify the policy is applied")
		nncpErr2 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("3.3 Verify the status of enactments is updated")
		nnceErr2 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("3.4 Verify no removed bond found in node network state")
		ifaceName1, nnsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, "-ojsonpath={.status.currentState.interfaces[*].name}").Output()
		o.Expect(nnsErr2).NotTo(o.HaveOccurred())
		o.Expect(ifaceName1).ShouldNot(o.ContainSubstring("bond01"))
		e2e.Logf("SUCCESS - no removed bond found in node network state")

		g.By("3.5 Verify the bond is removed from the node")
		ifaceList2, ifaceErr2 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr2).NotTo(o.HaveOccurred())
		matched, matchErr2 := regexp.MatchString("bond01", ifaceList2)
		o.Expect(matchErr2).NotTo(o.HaveOccurred())
		o.Expect(matched).To(o.BeFalse())
		e2e.Logf("SUCCESS - bond is removed from the node")
	})

	g.It("Author:qiowang-Medium-46383-VLAN [Disruptive]", func() {
		g.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		g.By("2. Creating vlan on node")
		g.By("2.1 Configure NNCP for creating vlan")
		policyName := "vlan-policy-46383"
		nodeList, getNodeErr := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		o.Expect(nodeList).NotTo(o.BeEmpty())
		nodeName := nodeList[0]
		vlanPolicyTemplate := generateTemplateAbsolutePath("vlan-policy-template.yaml")
		vlanPolicy := vlanPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "dummy3.101",
			descr:      "create vlan",
			baseiface:  "dummy3",
			vlanid:     101,
			state:      "up",
			template:   vlanPolicyTemplate,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, vlanPolicy.ifacename) {
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", vlanPolicy.ifacename)
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", vlanPolicy.baseiface)
			}
		}()
		configErr1 := vlanPolicy.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		g.By("2.2 Verify the policy is applied")
		nncpErr1 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("2.3 Verify the status of enactments is updated")
		nnceName := nodeName + "." + policyName
		nnceErr1 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("2.4 Verify the created vlan found in node network state")
		ifaceState, nnsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="`+vlanPolicy.ifacename+`")].state}`).Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		o.Expect(ifaceState).Should(o.ContainSubstring("up"))
		e2e.Logf("SUCCESS - the created vlan found in node network state")

		g.By("2.5 Verify the vlan is up and active on the node")
		ifaceList1, ifaceErr1 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr1).NotTo(o.HaveOccurred())
		matched, matchErr1 := regexp.MatchString("vlan\\s+"+vlanPolicy.ifacename, ifaceList1)
		o.Expect(matchErr1).NotTo(o.HaveOccurred())
		o.Expect(matched).To(o.BeTrue())
		e2e.Logf("SUCCESS - vlan is up and active on the node")

		g.By("3. Remove vlan on node")
		g.By("3.1 Configure NNCP for removing vlan")
		vlanPolicy = vlanPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "dummy3.101",
			descr:      "remove vlan",
			baseiface:  "dummy3",
			vlanid:     101,
			state:      "absent",
			template:   vlanPolicyTemplate,
		}
		configErr2 := vlanPolicy.configNNCP(oc)
		o.Expect(configErr2).NotTo(o.HaveOccurred())

		g.By("3.2 Verify the policy is applied")
		nncpErr2 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("3.3 Verify the status of enactments is updated")
		nnceErr2 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("3.4 Verify no removed vlan found in node network state")
		ifaceName1, nnsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, "-ojsonpath={.status.currentState.interfaces[*].name}").Output()
		o.Expect(nnsErr2).NotTo(o.HaveOccurred())
		o.Expect(ifaceName1).ShouldNot(o.ContainSubstring(vlanPolicy.ifacename))
		e2e.Logf("SUCCESS - no removed vlan found in node network state")

		g.By("3.5 Verify the vlan is removed from the node")
		ifaceList2, ifaceErr2 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr2).NotTo(o.HaveOccurred())
		o.Expect(ifaceList2).ShouldNot(o.ContainSubstring(vlanPolicy.ifacename))
		e2e.Logf("SUCCESS - vlan is removed from the node")
	})

	g.It("Author:qiowang-Medium-53346-Verify that it is able to reset linux-bridge vlan-filtering with vlan is empty [Disruptive]", func() {
		g.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		g.By("2. Creating linux-bridge with vlan-filtering")
		g.By("2.1 Configure NNCP for creating linux-bridge")
		policyName := "bridge-policy-53346"
		nodeList, getNodeErr := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		o.Expect(nodeList).NotTo(o.BeEmpty())
		nodeName := nodeList[0]
		bridgePolicyTemplate1 := generateTemplateAbsolutePath("bridge-policy-template.yaml")
		bridgePolicy := bridgevlanPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "linux-br0",
			descr:      "create linux-bridge with vlan-filtering",
			port:       "dummy4",
			state:      "up",
			template:   bridgePolicyTemplate1,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, bridgePolicy.ifacename) {
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", bridgePolicy.port)
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", bridgePolicy.ifacename)
			}
		}()
		configErr1 := bridgePolicy.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		g.By("2.2 Verify the policy is applied")
		nncpErr1 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("2.3 Verify the status of enactments is updated")
		nnceName := nodeName + "." + policyName
		nnceErr1 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("2.4 Verify the created bridge found in node network state")
		ifaceState, nnsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="linux-br0")].state}`).Output()
		bridgePort1, nnsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="linux-br0")].bridge.port[?(@.name=="dummy4")]}`).Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		o.Expect(nnsErr2).NotTo(o.HaveOccurred())
		o.Expect(ifaceState).Should(o.ContainSubstring("up"))
		o.Expect(bridgePort1).Should(o.ContainSubstring("vlan"))
		e2e.Logf("SUCCESS - the created bridge found in node network state")

		g.By("2.5 Verify the bridge is up and active, vlan-filtering is enabled")
		ifaceList1, ifaceErr1 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		vlanFilter1, vlanErr1 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show", bridgePolicy.ifacename)
		o.Expect(ifaceErr1).NotTo(o.HaveOccurred())
		o.Expect(vlanErr1).NotTo(o.HaveOccurred())
		matched1, matchErr1 := regexp.MatchString("bridge\\s+"+bridgePolicy.ifacename, ifaceList1)
		o.Expect(matchErr1).NotTo(o.HaveOccurred())
		o.Expect(matched1).To(o.BeTrue())
		matched2, matchErr2 := regexp.MatchString("bridge.vlan-filtering:\\s+yes", vlanFilter1)
		o.Expect(matchErr2).NotTo(o.HaveOccurred())
		o.Expect(matched2).To(o.BeTrue())
		e2e.Logf("SUCCESS - bridge is up and active, vlan-filtering is enabled")

		g.By("3. Reset linux-bridge vlan-filtering with vlan: {}")
		g.By("3.1 Configure NNCP for reset linux-bridge vlan-filtering")
		bridgePolicyTemplate2 := generateTemplateAbsolutePath("reset-bridge-vlan-policy-template.yaml")
		bridgePolicy = bridgevlanPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "linux-br0",
			descr:      "reset linux-bridge vlan-filtering",
			port:       "dummy4",
			state:      "up",
			template:   bridgePolicyTemplate2,
		}
		configErr2 := bridgePolicy.configNNCP(oc)
		o.Expect(configErr2).NotTo(o.HaveOccurred())

		g.By("3.2 Verify the policy is applied")
		nncpErr2 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("3.3 Verify the status of enactments is updated")
		nnceErr2 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("3.4 Verify no linux-bridge vlan-filtering found in node network state")
		bridgePort2, nnsErr3 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="linux-br0")].bridge.port[?(@.name=="dummy4")]}`).Output()
		o.Expect(nnsErr3).NotTo(o.HaveOccurred())
		o.Expect(bridgePort2).ShouldNot(o.ContainSubstring("vlan"))
		e2e.Logf("SUCCESS - no linux-bridge vlan-filtering found in node network state")

		g.By("3.5 Verify the linux-bridge vlan-filtering is disabled")
		vlanFilter2, vlanErr2 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show", bridgePolicy.ifacename)
		o.Expect(vlanErr2).NotTo(o.HaveOccurred())
		matched3, matchErr3 := regexp.MatchString("bridge.vlan-filtering:\\s+no", vlanFilter2)
		o.Expect(matchErr3).NotTo(o.HaveOccurred())
		o.Expect(matched3).To(o.BeTrue())
		e2e.Logf("SUCCESS - linux-bridge vlan-filtering is disabled")

		g.By("4. Remove linux-bridge on node")
		g.By("4.1 Configure NNCP for remove linux-bridge")
		bridgePolicy = bridgevlanPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "linux-br0",
			descr:      "remove linux-bridge",
			port:       "dummy4",
			state:      "absent",
			template:   bridgePolicyTemplate2,
		}
		configErr3 := bridgePolicy.configNNCP(oc)
		o.Expect(configErr3).NotTo(o.HaveOccurred())

		g.By("4.2 Verify the policy is applied")
		nncpErr3 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr3, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("4.3 Verify the status of enactments is updated")
		nnceErr3 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr3, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("4.4 Verify no removed linux-bridge found in node network state")
		ifaceName2, nnsErr4 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, "-ojsonpath={.status.currentState.interfaces[*].name}").Output()
		o.Expect(nnsErr4).NotTo(o.HaveOccurred())
		o.Expect(ifaceName2).ShouldNot(o.ContainSubstring(bridgePolicy.ifacename))
		e2e.Logf("SUCCESS - no removed linux-bridge found in node network state")

		g.By("4.5 Verify the linux-bridge is removed from the node")
		ifaceList2, ifaceErr3 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr3).NotTo(o.HaveOccurred())
		o.Expect(ifaceList2).ShouldNot(o.ContainSubstring(bridgePolicy.ifacename))
		e2e.Logf("SUCCESS - linux-bridge is removed from the node")
	})

	g.It("Author:qiowang-NonPreRelease-Medium-46327-Medium-46795-Medium-64854-Static IP and Route can be applied [Disruptive]", func() {
		var (
			ipAddrV4      = "192.0.2.251"
			destAddrV4    = "198.51.100.0/24"
			nextHopAddrV4 = "192.0.2.1"
			ipAddrV6      = "2001:db8::1:1"
			destAddrV6    = "2001:dc8::/64"
			nextHopAddrV6 = "2001:db8::1:2"
		)
		nodeName, getNodeErr := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())

		g.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		g.By("2. Apply static IP and Route on node")
		g.By("2.1 Configure NNCP for static IP and Route")
		policyName := "static-ip-route-46327"
		policyTemplate := generateTemplateAbsolutePath("apply-static-ip-route-template.yaml")
		stIPRoutePolicy := stIPRoutePolicyResource{
			name:          policyName,
			nodelabel:     "kubernetes.io/hostname",
			labelvalue:    nodeName,
			ifacename:     "dummyst",
			descr:         "apply static ip and route",
			state:         "up",
			ipaddrv4:      ipAddrV4,
			destaddrv4:    destAddrV4,
			nexthopaddrv4: nextHopAddrV4,
			ipaddrv6:      ipAddrV6,
			destaddrv6:    destAddrV6,
			nexthopaddrv6: nextHopAddrV6,
			template:      policyTemplate,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, stIPRoutePolicy.ifacename) {
				compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", stIPRoutePolicy.ifacename)
			}
		}()
		configErr := stIPRoutePolicy.configNNCP(oc)
		o.Expect(configErr).NotTo(o.HaveOccurred())

		g.By("2.2 Verify the policy is applied")
		nncpErr := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("2.3 Verify the status of enactments is updated")
		nnceName := nodeName + "." + policyName
		nnceErr := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("2.4 Verify the static ip and route found in node network state")
		iface, nnsIfaceErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="`+stIPRoutePolicy.ifacename+`")]}`).Output()
		o.Expect(nnsIfaceErr).NotTo(o.HaveOccurred())
		o.Expect(iface).Should(o.ContainSubstring(ipAddrV4))
		o.Expect(iface).Should(o.ContainSubstring(ipAddrV6))
		routes, nnsRoutesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.routes.config[?(@.next-hop-interface=="`+stIPRoutePolicy.ifacename+`")]}`).Output()
		o.Expect(nnsRoutesErr).NotTo(o.HaveOccurred())
		o.Expect(routes).Should(o.ContainSubstring(destAddrV4))
		o.Expect(routes).Should(o.ContainSubstring(nextHopAddrV4))
		o.Expect(routes).Should(o.ContainSubstring(destAddrV6))
		o.Expect(routes).Should(o.ContainSubstring(nextHopAddrV6))
		e2e.Logf("SUCCESS - the static ip and route found in node network state")

		g.By("2.5 Verify the static ip and route are shown on the node")
		ifaceInfo, ifaceErr := compat_otp.DebugNode(oc, nodeName, "ip", "addr", "show", stIPRoutePolicy.ifacename)
		o.Expect(ifaceErr).NotTo(o.HaveOccurred())
		o.Expect(ifaceInfo).Should(o.ContainSubstring(ipAddrV4))
		o.Expect(ifaceInfo).Should(o.ContainSubstring(ipAddrV6))
		v4Routes, routesV4Err := compat_otp.DebugNode(oc, nodeName, "ip", "-4", "route")
		o.Expect(routesV4Err).NotTo(o.HaveOccurred())
		o.Expect(v4Routes).Should(o.ContainSubstring(destAddrV4 + " via " + nextHopAddrV4 + " dev " + stIPRoutePolicy.ifacename))
		v6Routes, routesV6Err := compat_otp.DebugNode(oc, nodeName, "ip", "-6", "route")
		o.Expect(routesV6Err).NotTo(o.HaveOccurred())
		o.Expect(v6Routes).Should(o.ContainSubstring(destAddrV6 + " via " + nextHopAddrV6 + " dev " + stIPRoutePolicy.ifacename))

		e2e.Logf("SUCCESS - static ip and route are shown on the node")

		// Step3 is for https://issues.redhat.com/browse/OCPBUGS-8229
		g.By("3. Apply default gateway in non-default route table")
		g.By("3.1 Configure NNCP for default gateway")
		policyName2 := "default-route-64854"
		policyTemplate2 := generateTemplateAbsolutePath("apply-route-template.yaml")
		routePolicy := routePolicyResource{
			name:        policyName2,
			nodelabel:   "kubernetes.io/hostname",
			labelvalue:  nodeName,
			ifacename:   "dummyst",
			destaddr:    "0.0.0.0/0",
			nexthopaddr: nextHopAddrV4,
			tableid:     66,
			template:    policyTemplate2,
		}
		defer removeResource(oc, true, true, "nncp", policyName2, "-n", opNamespace)
		configErr2 := routePolicy.configNNCP(oc)
		o.Expect(configErr2).NotTo(o.HaveOccurred())

		g.By("3.2 Verify the policy is applied")
		nncpErr2 := checkNNCPStatus(oc, policyName2, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")

		g.By("3.3 Verify the status of enactments is updated")
		nnceName2 := nodeName + "." + policyName2
		nnceErr2 := checkNNCEStatus(oc, nnceName2, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")

		g.By("3.4 Verify the default gateway found in node network state")
		routes, nnsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.routes.config[?(@.table-id==66)]}`).Output()
		o.Expect(nnsErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(routes, "0.0.0.0/0")).Should(o.BeTrue())
		o.Expect(strings.Contains(routes, nextHopAddrV4)).Should(o.BeTrue())

		g.By("3.5 Verify the default gateway is shown on the node")
		defaultGW, gwErr := compat_otp.DebugNode(oc, nodeName, "ip", "-4", "route", "show", "default", "table", "66")
		o.Expect(gwErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(defaultGW, "default via "+nextHopAddrV4+" dev "+stIPRoutePolicy.ifacename)).Should(o.BeTrue())

		g.By("3.6 Verify there is no error logs for pinging default gateway shown in nmstate-handler pod")
		podName, getPodErr := compat_otp.GetPodName(oc, opNamespace, "component=kubernetes-nmstate-handler", nodeName)
		o.Expect(getPodErr).NotTo(o.HaveOccurred())
		o.Expect(podName).NotTo(o.BeEmpty())
		logs, logErr := compat_otp.GetSpecificPodLogs(oc, opNamespace, "", podName, "")
		o.Expect(logErr).ShouldNot(o.HaveOccurred())
		o.Expect(logs).NotTo(o.BeEmpty())
		o.Expect(strings.Contains(logs, "error pinging default gateway")).Should(o.BeFalse())

		g.By("4. Remove static ip and route on node")
		g.By("4.1 Configure NNCP for removing static ip and route")
		policyTemplate = generateTemplateAbsolutePath("remove-static-ip-route-template.yaml")
		stIPRoutePolicy = stIPRoutePolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "dummyst",
			descr:      "remove static ip and route",
			state:      "absent",
			ipaddrv4:   ipAddrV4,
			ipaddrv6:   ipAddrV6,
			template:   policyTemplate,
		}
		configErr1 := stIPRoutePolicy.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		g.By("4.2 Verify the policy is applied")
		nncpErr1 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("4.3 Verify the status of enactments is updated")
		nnceErr1 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("4.4 Verify static ip and route cannot be found in node network state")
		iface1, nnsIfaceErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, "-ojsonpath={.status.currentState.interfaces[*]}").Output()
		o.Expect(nnsIfaceErr1).NotTo(o.HaveOccurred())
		o.Expect(iface1).ShouldNot(o.ContainSubstring(stIPRoutePolicy.ifacename))
		o.Expect(iface1).ShouldNot(o.ContainSubstring(ipAddrV4))
		o.Expect(iface1).ShouldNot(o.ContainSubstring(ipAddrV6))
		routes1, nnsRoutesErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.routes}`).Output()
		o.Expect(nnsRoutesErr1).NotTo(o.HaveOccurred())
		o.Expect(routes1).ShouldNot(o.ContainSubstring(destAddrV4))
		o.Expect(routes1).ShouldNot(o.ContainSubstring(nextHopAddrV4))
		o.Expect(routes1).ShouldNot(o.ContainSubstring(destAddrV6))
		o.Expect(routes1).ShouldNot(o.ContainSubstring(nextHopAddrV6))

		g.By("4.5 Verify the static ip and route are removed from the node")
		ifaceInfo1, ifaceErr1 := compat_otp.DebugNode(oc, nodeName, "ip", "addr", "show")
		o.Expect(ifaceErr1).NotTo(o.HaveOccurred())
		o.Expect(ifaceInfo1).ShouldNot(o.ContainSubstring(stIPRoutePolicy.ifacename))
		o.Expect(ifaceInfo1).ShouldNot(o.ContainSubstring(ipAddrV4))
		o.Expect(ifaceInfo1).ShouldNot(o.ContainSubstring(ipAddrV6))
		v4Routes1, routesV4Err1 := compat_otp.DebugNode(oc, nodeName, "ip", "-4", "route")
		o.Expect(routesV4Err1).NotTo(o.HaveOccurred())
		o.Expect(v4Routes1).ShouldNot(o.ContainSubstring(destAddrV4 + " via " + nextHopAddrV4 + " dev " + stIPRoutePolicy.ifacename))
		v6Routes1, routesV6Err1 := compat_otp.DebugNode(oc, nodeName, "ip", "-6", "route")
		o.Expect(routesV6Err1).NotTo(o.HaveOccurred())
		o.Expect(v6Routes1).ShouldNot(o.ContainSubstring(destAddrV6 + " via " + nextHopAddrV6 + " dev " + stIPRoutePolicy.ifacename))
		e2e.Logf("SUCCESS - static ip and route are removed from the node")
	})

	g.It("Author:qiowang-NonPreRelease-Medium-66174-Verify knmstate operator support for IPv6 single stack - ipv6 default route [Disruptive]", func() {
		compat_otp.By("Check the platform if it is suitable for running the test")
		platform := checkPlatform(oc)
		ipStackType := checkIPStackType(oc)
		if ipStackType != "ipv6single" || !strings.Contains(platform, "baremetal") {
			g.Skip("Should be tested on IPv6 single stack platform(IPI BM), skipping!")
		}

		var (
			destAddr    = "::/0"
			nextHopAddr = "fd00:1101::1"
		)
		nodeName, getNodeErr := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		cmd := `nmcli dev | grep -v 'ovs' | egrep 'ethernet +connected' | awk '{print $1}'`
		ifNameInfo, ifNameErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", cmd)
		o.Expect(ifNameErr).NotTo(o.HaveOccurred())
		ifName := strings.Split(ifNameInfo, "\n")[0]

		compat_otp.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("2. Apply default routes on node")
		compat_otp.By("2.1 Configure NNCP for default route in main route table")
		policyTemplate := generateTemplateAbsolutePath("apply-route-template.yaml")
		policyName1 := "default-route-in-main-table-66174"
		routePolicy1 := routePolicyResource{
			name:        policyName1,
			nodelabel:   "kubernetes.io/hostname",
			labelvalue:  nodeName,
			ifacename:   ifName,
			destaddr:    destAddr,
			nexthopaddr: nextHopAddr,
			tableid:     254,
			template:    policyTemplate,
		}
		defer deleteNNCP(oc, policyName1)
		defer compat_otp.DebugNode(oc, nodeName, "ip", "-6", "route", "del", "default", "via", routePolicy1.nexthopaddr, "dev", routePolicy1.ifacename, "table", strconv.Itoa(routePolicy1.tableid))
		configErr1 := routePolicy1.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		compat_otp.By("2.2 Configure NNCP for default route in custom route table")
		policyName2 := "default-route-in-custom-table-66174"
		routePolicy2 := routePolicyResource{
			name:        policyName2,
			nodelabel:   "kubernetes.io/hostname",
			labelvalue:  nodeName,
			ifacename:   ifName,
			destaddr:    destAddr,
			nexthopaddr: nextHopAddr,
			tableid:     66,
			template:    policyTemplate,
		}
		defer deleteNNCP(oc, policyName2)
		defer compat_otp.DebugNode(oc, nodeName, "ip", "-6", "route", "del", "default", "via", routePolicy2.nexthopaddr, "dev", routePolicy2.ifacename, "table", strconv.Itoa(routePolicy2.tableid))
		configErr2 := routePolicy2.configNNCP(oc)
		o.Expect(configErr2).NotTo(o.HaveOccurred())

		compat_otp.By("2.3 Verify the policies are applied")
		nncpErr1 := checkNNCPStatus(oc, policyName1, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		nncpErr2 := checkNNCPStatus(oc, policyName2, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")
		e2e.Logf("SUCCESS - policies are applied")

		compat_otp.By("2.4 Verify the status of enactments are updated")
		nnceName1 := nodeName + "." + policyName1
		nnceErr1 := checkNNCEStatus(oc, nnceName1, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		nnceName2 := nodeName + "." + policyName2
		nnceErr2 := checkNNCEStatus(oc, nnceName2, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments are updated")

		compat_otp.By("2.5 Verify the default routes found in node network state")
		routes, nnsRoutesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.routes.config[?(@.destination=="`+destAddr+`")]}`).Output()
		o.Expect(nnsRoutesErr).NotTo(o.HaveOccurred())
		o.Expect(routes).Should(o.ContainSubstring(routePolicy1.nexthopaddr))
		o.Expect(routes).Should(o.ContainSubstring(routePolicy2.nexthopaddr))
		e2e.Logf("SUCCESS - the default routes found in node network state")

		compat_otp.By("2.6 Verify the default routes are shown on the node")
		route1, routeErr1 := compat_otp.DebugNode(oc, nodeName, "ip", "-6", "route", "show", "default", "table", strconv.Itoa(routePolicy1.tableid))
		o.Expect(routeErr1).NotTo(o.HaveOccurred())
		o.Expect(route1).Should(o.ContainSubstring("default via " + routePolicy1.nexthopaddr + " dev " + routePolicy1.ifacename))
		route2, routeErr2 := compat_otp.DebugNode(oc, nodeName, "ip", "-6", "route", "show", "default", "table", strconv.Itoa(routePolicy2.tableid))
		o.Expect(routeErr2).NotTo(o.HaveOccurred())
		o.Expect(route2).Should(o.ContainSubstring("default via " + routePolicy2.nexthopaddr + " dev " + routePolicy2.ifacename))
		e2e.Logf("SUCCESS - default routes are shown on the node")

		compat_otp.By("3. Remove default routes on node")
		compat_otp.By("3.1 Configure NNCP for removing default route in main route table")
		rmpolicyTemplate := generateTemplateAbsolutePath("remove-route-template.yaml")
		routePolicy1 = routePolicyResource{
			name:        policyName1,
			nodelabel:   "kubernetes.io/hostname",
			labelvalue:  nodeName,
			ifacename:   ifName,
			state:       "absent",
			destaddr:    destAddr,
			nexthopaddr: nextHopAddr,
			tableid:     254,
			template:    rmpolicyTemplate,
		}
		configErr1 = routePolicy1.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		compat_otp.By("3.2 Configure NNCP for removing default route in custom route table")
		routePolicy2 = routePolicyResource{
			name:        policyName2,
			nodelabel:   "kubernetes.io/hostname",
			labelvalue:  nodeName,
			ifacename:   ifName,
			state:       "absent",
			destaddr:    destAddr,
			nexthopaddr: nextHopAddr,
			tableid:     66,
			template:    rmpolicyTemplate,
		}
		configErr2 = routePolicy2.configNNCP(oc)
		o.Expect(configErr2).NotTo(o.HaveOccurred())

		compat_otp.By("3.3 Verify the policies are applied")
		nncpErr1 = checkNNCPStatus(oc, policyName1, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		nncpErr2 = checkNNCPStatus(oc, policyName2, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")
		e2e.Logf("SUCCESS - policies are applied")

		compat_otp.By("3.4 Verify the status of enactments are updated")
		nnceErr1 = checkNNCEStatus(oc, nnceName1, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		nnceErr2 = checkNNCEStatus(oc, nnceName2, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments are updated")

		compat_otp.By("3.5 Verify the removed default routes cannot be found in node network state")
		routes1, nnsRoutesErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.routes.config[?(@.destination=="`+destAddr+`")]}`).Output()
		o.Expect(nnsRoutesErr1).NotTo(o.HaveOccurred())
		o.Expect(routes1).ShouldNot(o.ContainSubstring(routePolicy1.nexthopaddr))
		o.Expect(routes1).ShouldNot(o.ContainSubstring(routePolicy2.nexthopaddr))
		e2e.Logf("SUCCESS - the default routes cannot be found in node network state")

		compat_otp.By("3.6 Verify the default routes are removed from the node")
		route1, routeErr1 = compat_otp.DebugNode(oc, nodeName, "ip", "-6", "route", "show", "default", "table", strconv.Itoa(routePolicy1.tableid))
		o.Expect(routeErr1).NotTo(o.HaveOccurred())
		o.Expect(route1).ShouldNot(o.ContainSubstring("default via " + routePolicy1.nexthopaddr + " dev " + routePolicy1.ifacename))
		route2, routeErr2 = compat_otp.DebugNode(oc, nodeName, "ip", "-6", "route", "show", "default", "table", strconv.Itoa(routePolicy2.tableid))
		o.Expect(routeErr2).NotTo(o.HaveOccurred())
		o.Expect(route2).ShouldNot(o.ContainSubstring("default via " + routePolicy2.nexthopaddr + " dev " + routePolicy2.ifacename))
		e2e.Logf("SUCCESS - default routes are removed from the node")
	})

	g.It("Author:qiowang-NonPreRelease-Medium-71145-configure bond interface and 70 vlans based on the bond then reboot node, check the boot time [Disruptive] [Slow]", func() {
		e2e.Logf("It is for OCPBUGS-22771, OCPBUGS-25753, OCPBUGS-26026")

		nodeName, getNodeErr := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		var ifacesAdded []string
		for i := 101; i <= 170; i++ {
			ifacesAdded = append(ifacesAdded, "bond12."+strconv.Itoa(i))
		}
		ifacesAdded = append(ifacesAdded, "bond12", "dummy1", "dummy2")

		compat_otp.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("2. Create bond interface and 70 vlans based on the bond")
		compat_otp.By("2.1 Configure NNCP for bond and vlans")
		policyName := "ocpbug-22771-25753-26026-bond-70vlans"
		bondPolicyTemplate := generateTemplateAbsolutePath("ocpbug-22771-25753-26026.yaml")
		bondPolicy := bondPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "bond12",
			descr:      "test bond-vlans",
			port1:      "dummy1",
			port2:      "dummy2",
			state:      "up",
			template:   bondPolicyTemplate,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			allIfaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			var deferCmd string
			for _, ifaceAdded := range ifacesAdded {
				if strings.Contains(allIfaces, ifaceAdded) {
					deferCmd = deferCmd + " nmcli con delete " + ifaceAdded + ";"
				}
			}
			if deferCmd != "" {
				compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", deferCmd)
			}
		}()
		configErr := configBond(oc, bondPolicy)
		o.Expect(configErr).NotTo(o.HaveOccurred())

		compat_otp.By("2.2 Verify the policy is applied")
		nncpErr := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		compat_otp.By("2.3 Verify the status of enactments is updated")
		nnceName := nodeName + "." + policyName
		nnceErr := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		compat_otp.By("2.4 Verify the bond and vlans found in node network state")
		iface, nnsIfaceErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[*].name}`).Output()
		o.Expect(nnsIfaceErr).NotTo(o.HaveOccurred())
		for _, ifaceAdded := range ifacesAdded {
			o.Expect(strings.Contains(iface, ifaceAdded)).Should(o.BeTrue())
		}
		e2e.Logf("SUCCESS - the bond and vlans found in node network state")

		compat_otp.By("2.5 Verify the bond and vlans are shown on the node")
		ifaceInfo, ifaceErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr).NotTo(o.HaveOccurred())
		for _, ifaceAdded := range ifacesAdded {
			o.Expect(strings.Contains(ifaceInfo, ifaceAdded)).Should(o.BeTrue())
		}
		e2e.Logf("SUCCESS - bond and vlans are shown on the node")

		compat_otp.By("3. Reboot the node")
		defer checkNodeStatus(oc, nodeName, "Ready")
		rebootNode(oc, nodeName)
		checkNodeStatus(oc, nodeName, "NotReady")
		checkNodeStatus(oc, nodeName, "Ready")

		compat_otp.By("4. Check the boot time")
		cmd := `systemd-analyze | head -1`
		analyzeOutput, analyzeErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", cmd)
		o.Expect(analyzeErr).NotTo(o.HaveOccurred())
		e2e.Logf("Expected boot time should be less than 3 minutes(180s)")
		reTime := regexp.MustCompile(`(\(initrd\) \+ ?)([\s\S]+)( \(userspace\)?)`)
		bootTime := reTime.FindStringSubmatch(analyzeOutput)[2]
		e2e.Logf("boot time(userspace) is: %v", bootTime)
		var totalSec int
		if strings.Contains(bootTime, "min") {
			reMin := regexp.MustCompile(`(\d+)min`)
			getMin := reMin.FindStringSubmatch(bootTime)[1]
			bootMin, _ := strconv.Atoi(getMin)
			totalSec = totalSec + bootMin*60
		}
		reSec := regexp.MustCompile(`(\d+)(\.\d+)?s`)
		getSec := reSec.FindStringSubmatch(bootTime)[1]
		bootSec, _ := strconv.Atoi(getSec)
		totalSec = totalSec + bootSec
		e2e.Logf("boot total seconds(userspace) is: %v", totalSec)
		o.Expect(totalSec < 180).To(o.BeTrue())

		compat_otp.By("5. Check the node logs")
		journalCmd := `journalctl -u ovs-configuration -b`
		logs, logsErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", journalCmd)
		o.Expect(logsErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(logs, "Cannot bring up connection br-ex after 10 attempts")).ShouldNot(o.BeTrue())
		o.Expect(strings.Contains(logs, "configure-ovs exited with error")).ShouldNot(o.BeTrue())
	})

	g.It("Author:qiowang-Medium-73027-Verify vlan of bond will get autoconnect when bond ports link revived [Disruptive]", func() {
		e2e.Logf("It is for OCPBUGS-11300, OCPBUGS-23023")

		var (
			ipAddr1V4 = "192.0.2.251"
			ipAddr2V4 = "192.0.2.252"
			ipAddr1V6 = "2001:db8::1:1"
			ipAddr2V6 = "2001:db8::1:2"
		)
		nodeName, getNodeErr := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())

		compat_otp.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("2. Create vlan over bond")
		compat_otp.By("2.1 Configure NNCP for vlan over bond")
		policyName := "ocpbug-11300-23023-vlan-over-bond"
		bondVlanPolicyTemplate := generateTemplateAbsolutePath("ocpbug-11300-23023.yaml")
		bondVlanPolicy := bondvlanPolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			descr:      "test bond-vlans",
			bondname:   "bond12",
			port1:      "dummy1",
			port1type:  "dummy",
			port2:      "dummy2",
			port2type:  "dummy",
			vlanifname: "bond12.101",
			vlanid:     101,
			ipaddrv4:   ipAddr1V4,
			ipaddrv6:   ipAddr1V6,
			state:      "up",
			template:   bondVlanPolicyTemplate,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			var ifacesAdded []string
			ifacesAdded = append(ifacesAdded, bondVlanPolicy.vlanifname, bondVlanPolicy.bondname, bondVlanPolicy.port1, bondVlanPolicy.port2)
			var deferCmd string
			for _, ifaceAdded := range ifacesAdded {
				if strings.Contains(ifaces, ifaceAdded) {
					deferCmd = deferCmd + " nmcli con delete " + ifaceAdded + ";"
				}
			}
			if deferCmd != "" {
				compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", deferCmd)
			}
		}()
		configErr1 := bondVlanPolicy.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		compat_otp.By("2.2 Verify the policy is applied")
		nncpErr1 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		compat_otp.By("2.3 Verify the status of enactments is updated")
		nnceName := nodeName + "." + policyName
		nnceErr1 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		compat_otp.By("2.4 Verify the vlan interface ip addresses are shown correctly")
		ipCmd := "ip address show " + bondVlanPolicy.vlanifname
		ifaceInfo1, ifaceErr1 := compat_otp.DebugNode(oc, nodeName, "bash", "-c", ipCmd)
		o.Expect(ifaceErr1).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceInfo1, ipAddr1V4)).Should(o.BeTrue())
		o.Expect(strings.Contains(ifaceInfo1, ipAddr1V6)).Should(o.BeTrue())
		e2e.Logf("SUCCESS - vlan interface ip addresses are shown on the node")

		compat_otp.By("3. edit nncp")
		compat_otp.By("3.1 update ip address")
		patchContent := `[{"op": "replace", "path": "/spec/desiredState/interfaces", "value": [{"name": "` + bondVlanPolicy.vlanifname + `", "type": "vlan", "state": "up", "vlan":{"base-iface": "` + bondVlanPolicy.bondname + `", "id": ` + strconv.Itoa(bondVlanPolicy.vlanid) + `}, "ipv4":{"address":[{"ip": "` + ipAddr2V4 + `", "prefix-length": 24}], "enabled":true}, "ipv6":{"address":[{"ip": "` + ipAddr2V6 + `", "prefix-length": 96}], "enabled":true}}]}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("nncp", policyName, "--type=json", "-p", patchContent).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		compat_otp.By("3.2 Verify the policy is applied")
		nncpErr2 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		compat_otp.By("3.3 Verify the status of enactments is updated")
		nnceErr2 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		compat_otp.By("3.4 Verify the vlan interface ip addresses are shown correctly")
		ifaceInfo2, ifaceErr2 := compat_otp.DebugNode(oc, nodeName, "bash", "-c", ipCmd)
		o.Expect(ifaceErr2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceInfo2, ipAddr2V4)).Should(o.BeTrue())
		o.Expect(strings.Contains(ifaceInfo2, ipAddr2V6)).Should(o.BeTrue())
		e2e.Logf("SUCCESS - vlan interface ip addresses are shown on the node")

		compat_otp.By("4. Bring all bond ports link down, wait for the vlan become inactive")
		downPortCmd := "ip link set " + bondVlanPolicy.port1 + " down; ip link set " + bondVlanPolicy.port2 + " down"
		_, downPortErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", downPortCmd)
		o.Expect(downPortErr).NotTo(o.HaveOccurred())
		vlanInfo1 := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
			ifaceInfo, ifaceErr := compat_otp.DebugNode(oc, nodeName, "bash", "-c", ipCmd)
			o.Expect(ifaceErr).NotTo(o.HaveOccurred())
			if !strings.Contains(ifaceInfo, "inet") {
				return true, nil
			}
			e2e.Logf("vlan still active and try again")
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(vlanInfo1, "Fail to inactive vlan")

		compat_otp.By("5. Bring all bond ports link up again, vlan will reactive with the original ip addresses")
		upPortCmd := "ip link set " + bondVlanPolicy.port1 + " up; ip link set " + bondVlanPolicy.port2 + " up"
		_, upPortErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", upPortCmd)
		o.Expect(upPortErr).NotTo(o.HaveOccurred())
		vlanInfo2 := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
			ifaceInfo, ifaceErr := compat_otp.DebugNode(oc, nodeName, "bash", "-c", ipCmd)
			o.Expect(ifaceErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaceInfo, ipAddr2V4) && strings.Contains(ifaceInfo, ipAddr2V6) {
				return true, nil
			}
			e2e.Logf("vlan still down and try again")
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(vlanInfo2, "Fail to reactive vlan with the original ip addresses")
	})

	g.It("Author:meinli-High-76212-Validate Metrics collection for kubernetes-nmstate [Disruptive]", func() {
		nodeName, getNodeErr := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		o.Expect(nodeName).NotTo(o.BeEmpty())

		compat_otp.By("1. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("2. Configure two NNCP for creating linux-bridge with hostname")
		policyName := "br-test"
		bridgePolicyTemplate1 := generateTemplateAbsolutePath("bridge-with-hostname-policy-template.yaml")
		bridgePolicy := bridgehostnamePolicyResource{
			name:       policyName,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  "linux-br0",
			state:      "up",
			template:   bridgePolicyTemplate1,
		}
		defer deleteNNCP(oc, policyName)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, bridgePolicy.ifacename) {
				_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", bridgePolicy.ifacename)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}()
		configErr1 := bridgePolicy.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())
		nncpErr1 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, fmt.Sprintf("%s policy applied failed", policyName))

		compat_otp.By("3. check the metrics value with proper gauge increased")
		featureNames := []string{"dhcpv4-custom-hostname"}
		expectedValues := []int{1}
		metricPod := getPodName(oc, opNamespace, "component=kubernetes-nmstate-metrics")
		o.Expect(metricPod).ShouldNot(o.BeEmpty())
		metricCmd := "curl http://127.0.0.1:8089/metrics | grep kubernetes_nmstate_features_applied"
		o.Eventually(func() bool {
			metricOutput, err := compat_otp.RemoteShPodWithBash(oc, opNamespace, metricPod[0], metricCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
			return extractMetricValue(metricOutput, featureNames, expectedValues)
		}, 10*time.Second, 2*time.Second).Should(o.BeTrue(), "Metric does not match the expected value!!")

		// validate the metrics value increased to 2 after applying again
		deleteNNCP(oc, policyName)
		configErr2 := bridgePolicy.configNNCP(oc)
		o.Expect(configErr2).NotTo(o.HaveOccurred())
		nncpErr2 := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, fmt.Sprintf("%s policy applied failed", policyName))
		expectedValues = []int{2}
		o.Eventually(func() bool {
			metricOutput, err := compat_otp.RemoteShPodWithBash(oc, opNamespace, metricPod[0], metricCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
			return extractMetricValue(metricOutput, featureNames, expectedValues)
		}, 10*time.Second, 2*time.Second).Should(o.BeTrue(), "Metric does not match the expected value!!")

		compat_otp.By("4. metrics value will decrease after update nncp with absent state")
		patchCmd := `[{"op": "replace", "path": "/spec/desiredState/interfaces/0/state", "value": "absent" }]`
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("nncp", policyName, "--type=json", "-p", patchCmd).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		checkErr := checkNNCPStatus(oc, policyName, "Available")
		compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("%s policy updated failed", policyName))

		// check the metrics value will decrease 1
		expectedValues = []int{1}
		o.Eventually(func() bool {
			metricOutput, err := compat_otp.RemoteShPodWithBash(oc, opNamespace, metricPod[0], metricCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
			return extractMetricValue(metricOutput, featureNames, expectedValues)
		}, 10*time.Second, 2*time.Second).Should(o.BeTrue(), "Metric does not match the expected value!!")
	})

	g.It("Author:meinli-High-76372-Check NMstate Features Metrics Value collection [Disruptive]", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking/nmstate")
			nmstateCRTemplate            = filepath.Join(buildPruningBaseDir, "nmstate-cr-template.yaml")
			dhcpHostnamePolicyTemplate   = filepath.Join(buildPruningBaseDir, "dhcp-hostname-policy-template.yaml")
			lldpPolicyTemplate           = filepath.Join(buildPruningBaseDir, "lldp-policy-template.yaml")
			ovnMappingPolicyTemplate     = filepath.Join(buildPruningBaseDir, "ovn-mapping-policy-template.yaml")
			ovsDBGlobalPolicyTemplate    = filepath.Join(buildPruningBaseDir, "ovs-db-global-policy-template.yaml")
			staticHostnamePolicyTemplate = filepath.Join(buildPruningBaseDir, "static-hostname-policy-template.yaml")
			staticDNSPolicyTemplate      = filepath.Join(buildPruningBaseDir, "global-dns-nncp-template.yaml")
			dnsClearNncpTemplate         = filepath.Join(buildPruningBaseDir, "global-dns-nncp-recover-template.yaml")
			nodeSelectLabel              = "kubernetes.io/hostname"
			featureNames                 = []string{"dhcpv4-custom-hostname", "dhcpv6-custom-hostname", "lldp", "ovn-mapping", "ovs-db-global",
				"static-hostname", "static-dns-name-server", "static-dns-search"}
			expectedValues = []int{1, 1, 1, 1, 1, 1, 1, 1}
			ipAddr         string
		)

		nodeName, getNodeErr := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		o.Expect(nodeName).NotTo(o.BeEmpty())

		compat_otp.By("1. Create NMState CR")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("2. Configure NNCPs for NMstate Features")
		compat_otp.By("2.1 Configure NNCP for creating DhcpCustomHostname NMstate Feature")
		dhcpHostnamePolicy := bridgehostnamePolicyResource{
			name:       "dhcphostname-test",
			nodelabel:  nodeSelectLabel,
			labelvalue: nodeName,
			ifacename:  "dummy_dhcp",
			state:      "up",
			template:   dhcpHostnamePolicyTemplate,
		}
		defer deleteNNCP(oc, dhcpHostnamePolicy.name)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, dhcpHostnamePolicy.ifacename) {
				_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", dhcpHostnamePolicy.ifacename)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}()
		configErr1 := dhcpHostnamePolicy.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())
		nncpErr1 := checkNNCPStatus(oc, dhcpHostnamePolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, fmt.Sprintf("%s policy applied failed", dhcpHostnamePolicy.name))

		compat_otp.By("2.2 Configure NNCP for creating Lldp NMstate Feature")
		lldpPolicy := bridgehostnamePolicyResource{
			name:       "lldp-test",
			nodelabel:  nodeSelectLabel,
			labelvalue: nodeName,
			ifacename:  "dummy_lldp",
			state:      "up",
			template:   lldpPolicyTemplate,
		}
		defer deleteNNCP(oc, lldpPolicy.name)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, lldpPolicy.ifacename) {
				_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "delete", lldpPolicy.ifacename)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}()
		configErr2 := lldpPolicy.configNNCP(oc)
		o.Expect(configErr2).NotTo(o.HaveOccurred())
		nncpErr2 := checkNNCPStatus(oc, lldpPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, fmt.Sprintf("%s policy applied failed", lldpPolicy.name))

		compat_otp.By("2.3 Configure NNCP for creating OvnMapping NMstate Feature")
		ovnMappingPolicy := ovnMappingPolicyResource{
			name:       "ovnmapping-test",
			nodelabel:  nodeSelectLabel,
			labelvalue: nodeName,
			localnet1:  "blue",
			bridge1:    "ovsbr1",
			template:   ovnMappingPolicyTemplate,
		}
		defer deleteNNCP(oc, ovnMappingPolicy.name)
		defer func() {
			ovnmapping, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "ovs-vsctl", "get", "Open_vSwitch", ".", "external_ids:ovn-bridge-mappings")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ovnmapping, ovnMappingPolicy.localnet1) {
				// ovs-vsctl can only use "set" to reserve some fields
				_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "ovs-vsctl", "set", "Open_vSwitch", ".", "external_ids:ovn-bridge-mappings=\"physnet:br-ex\"")
				o.Expect(err).NotTo(o.HaveOccurred())
			}
			ovsbr, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "ovs-vsctl", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ovsbr, ovnMappingPolicy.bridge1) {
				// delete ovs-bridge interface
				_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "ovs-vsctl", "del-br", ovnMappingPolicy.bridge1)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}()
		configErr3 := ovnMappingPolicy.configNNCP(oc)
		o.Expect(configErr3).NotTo(o.HaveOccurred())
		nncpErr3 := checkNNCPStatus(oc, ovnMappingPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr3, fmt.Sprintf("%s policy applied failed", ovnMappingPolicy.name))

		compat_otp.By("2.4 Configure NNCP for creating OvsDBGlobal NMstate Feature")
		ovsDBGlobalPolicy := ovsDBGlobalPolicyResource{
			name:       "ovsdbglobal-test",
			nodelabel:  nodeSelectLabel,
			labelvalue: nodeName,
			ovsconfig:  "n-handler-threads",
			ovsvalue:   "2",
			template:   ovsDBGlobalPolicyTemplate,
		}
		defer deleteNNCP(oc, ovsDBGlobalPolicy.name)
		defer func() {
			ovsdb, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "ovs-vsctl", "get", "Open_vSwitch", ".", "other_config")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ovsdb, ovsDBGlobalPolicy.ovsconfig) {
				_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "ovs-vsctl", "remove", "Open_vSwitch", ".", "other_config", ovsDBGlobalPolicy.ovsconfig)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}()
		configErr4 := ovsDBGlobalPolicy.configNNCP(oc)
		o.Expect(configErr4).NotTo(o.HaveOccurred())
		nncpErr4 := checkNNCPStatus(oc, ovsDBGlobalPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr4, fmt.Sprintf("%s policy applied failed", ovsDBGlobalPolicy.name))

		compat_otp.By("2.5 Configure NNCP for creating StaticHostname NMstate Feature")
		staticHostnamePolicy := staticHostnamePolicyResource{
			name:       "statichostname-test",
			nodelabel:  nodeSelectLabel,
			labelvalue: nodeName,
			hostdomain: nodeName,
			template:   staticHostnamePolicyTemplate,
		}
		defer deleteNNCP(oc, staticHostnamePolicy.name)
		defer func() {
			hostname, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "hostnamectl")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if !strings.Contains(hostname, nodeName) {
				_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "hostnamectl", "set-hostname", nodeName)
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}()
		configErr5 := staticHostnamePolicy.configNNCP(oc)
		o.Expect(configErr5).NotTo(o.HaveOccurred())
		ncpErr5 := checkNNCPStatus(oc, staticHostnamePolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(ncpErr5, fmt.Sprintf("%s policy applied failed", staticHostnamePolicy.name))

		compat_otp.By("2.6 Configure NNCP for creating StaticDNS NMstate Feature")
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" || ipStackType == "ipv6single" {
			ipAddr = "2003::3"
		}
		if ipStackType == "ipv4single" {
			ipAddr = "8.8.8.8"
		}

		dnsServerIP1 := getAvaliableNameServer(oc, nodeName)
		staticDNSPolicy := staticDNSPolicyResource{
			name:      "staticdns-test",
			nodeName:  nodeName,
			dnsdomain: "example.com",
			serverip1: dnsServerIP1,
			serverip2: ipAddr,
			template:  staticDNSPolicyTemplate,
		}
		defer deleteNNCP(oc, staticDNSPolicy.name)
		defer func() {
			//configure nncp with empty dns server to clear configuration
			nncpDns_clear := networkingRes{
				name:      "dns-" + getRandomString(),
				namespace: opNamespace,
				kind:      "NodeNetworkConfigurationPolicy",
				tempfile:  dnsClearNncpTemplate,
			}
			nncpDns_clear.create(oc, "NAME="+nncpDns_clear.name, "NAMESPACE="+nncpDns_clear.namespace, "NODE="+nodeName)
			nncpErr1 := checkNNCPStatus(oc, nncpDns_clear.name, "Available")
			compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
			e2e.Logf("SUCCESS - policy is applied")

			removeResource(oc, true, true, nncpDns_clear.kind, nncpDns_clear.name, "-n", nncpDns_clear.namespace)
		}()
		configErr6 := staticDNSPolicy.configNNCP(oc)
		o.Expect(configErr6).NotTo(o.HaveOccurred())
		ncpErr6 := checkNNCPStatus(oc, staticDNSPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(ncpErr6, fmt.Sprintf("%s policy applied failed", staticDNSPolicy.name))

		compat_otp.By("3. Check Metrics value for above NMstate Features")
		metricPod := getPodName(oc, opNamespace, "component=kubernetes-nmstate-metrics")
		o.Expect(metricPod).ShouldNot(o.BeEmpty())
		metricCmd := "curl http://127.0.0.1:8089/metrics | grep kubernetes_nmstate_features_applied"
		o.Eventually(func() bool {
			metricOutput, err := compat_otp.RemoteShPodWithBash(oc, opNamespace, metricPod[0], metricCmd)
			o.Expect(err).NotTo(o.HaveOccurred())
			return extractMetricValue(metricOutput, featureNames, expectedValues)
		}, 10*time.Second, 2*time.Second).Should(o.BeTrue(), "Metric does not match the expected value!!")
	})
})

var _ = g.Describe("[OTP][sig-networking] SDN nmstate-operator upgrade", func() {
	defer g.GinkgoRecover()

	var (
		oc                   = compat_otp.NewCLI("networking-nmstate", compat_otp.KubeConfigPath())
		opNamespace          = "openshift-nmstate"
		opName               = "kubernetes-nmstate-operator"
		policyNamePreUpgrade = "bond-policy-54077"
		policyNamePstUpgrade = "vlan-policy-54077"
		bondInfName          = "bond54077"
		bondPort1            = "dummy5"
		bondPort2            = "dummy6"
		vlanBaseInf          = "dummy7"
		bondPolicyTemplate   = generateTemplateAbsolutePath("bond-policy-template.yaml")
		vlanPolicyTemplate   = generateTemplateAbsolutePath("vlan-policy-template.yaml")
	)

	g.BeforeEach(func() {
		g.By("Check the platform if it is suitable for running the test")
		if !(isPlatformSuitableForNMState(oc)) {
			g.Skip("Skipping for unsupported platform!")
		}
	})

	g.It("Author:qiowang-PreChkUpgrade-NonPreRelease-Medium-54077-Verify that the knmstate operator works as expected after the cluster upgrade [Disruptive]", func() {
		nodeList, getNodeErr := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		nodeName := nodeList[0]

		compat_otp.By("1. install knmstate operator")
		installNMstateOperator(oc)

		compat_otp.By("2. Create NMState CR")
		nmstateCRTemplate := generateTemplateAbsolutePath("nmstate-cr-template.yaml")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("3. Creating bond on node")
		compat_otp.By("3.1 Configure NNCP for creating bond")
		bondPolicy := bondPolicyResource{
			name:       policyNamePreUpgrade,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  bondInfName,
			descr:      "create bond",
			port1:      bondPort1,
			port2:      bondPort2,
			state:      "up",
			template:   bondPolicyTemplate,
		}
		configErr := configBond(oc, bondPolicy)
		o.Expect(configErr).NotTo(o.HaveOccurred())

		compat_otp.By("3.2 Verify the policy is applied")
		nncpErr := checkNNCPStatus(oc, policyNamePreUpgrade, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr, "policy applied failed")

		compat_otp.By("3.3 Verify the status of enactments is updated")
		nnceName := nodeName + "." + policyNamePreUpgrade
		nnceErr := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr, "status of enactments updated failed")

		compat_otp.By("3.4 Verify the bond is up and active on the node")
		ifaceList, ifaceErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceList, bondPolicy.ifacename)).Should(o.BeTrue())

		compat_otp.By("3.5 Verify the created bond found in node network state")
		ifaceState, nnsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="`+bondPolicy.ifacename+`")].state}`).Output()
		o.Expect(nnsErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceState, "up")).Should(o.BeTrue())
	})

	g.It("Author:qiowang-PstChkUpgrade-NonPreRelease-Medium-54077-Verify that the knmstate operator works as expected after the cluster upgrade [Disruptive]", func() {
		nodeList, getNodeErr := compat_otp.GetClusterNodesBy(oc, "worker")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		nodeName := nodeList[0]
		defer removeResource(oc, true, true, "nmstate", "nmstate", "-n", opNamespace)
		defer deleteNNCP(oc, policyNamePreUpgrade)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, bondInfName) {
				cmd := "nmcli con delete " + bondInfName + "; nmcli con delete " + bondPort1 + "; nmcli con delete " + bondPort2
				compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", cmd)
			}
		}()

		compat_otp.By("1. Check NMState CSV is upgraded")
		majorVer, _, verErr := compat_otp.GetClusterVersion(oc)
		o.Expect(verErr).NotTo(o.HaveOccurred())
		e2e.Logf("ocp major version: %s", majorVer)
		csvOutput, csvErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("csv", "-n", opNamespace).Output()
		o.Expect(csvErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(csvOutput, opName+"."+majorVer)).Should(o.BeTrue())

		compat_otp.By("2. Check NMState CRs are running")
		result, crErr := checkNmstateCR(oc, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "check nmstate cr failed")
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("3. Check NNCP created before upgrade is still Available")
		compat_otp.By("3.1 Verify the policy is Available")
		nncpErr1 := checkNNCPStatus(oc, policyNamePreUpgrade, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")

		compat_otp.By("3.2 Verify the status of enactments is Available")
		nnceName1 := nodeName + "." + policyNamePreUpgrade
		nnceErr1 := checkNNCEStatus(oc, nnceName1, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")

		compat_otp.By("3.3 Verify the bond is up and active on the node")
		ifaceList1, ifaceErr1 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr1).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceList1, bondInfName)).Should(o.BeTrue())

		compat_otp.By("3.4 Verify the created bond found in node network state")
		ifaceState1, nnsErr1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="`+bondInfName+`")].state}`).Output()
		o.Expect(nnsErr1).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceState1, "up")).Should(o.BeTrue())

		compat_otp.By("4. Create new NNCP after upgrade")
		compat_otp.By("4.1 Configure NNCP for creating vlan")
		vlanPolicy := vlanPolicyResource{
			name:       policyNamePstUpgrade,
			nodelabel:  "kubernetes.io/hostname",
			labelvalue: nodeName,
			ifacename:  vlanBaseInf + ".101",
			descr:      "create vlan",
			baseiface:  vlanBaseInf,
			vlanid:     101,
			state:      "up",
			template:   vlanPolicyTemplate,
		}
		defer deleteNNCP(oc, policyNamePstUpgrade)
		defer func() {
			ifaces, deferErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
			o.Expect(deferErr).NotTo(o.HaveOccurred())
			if strings.Contains(ifaces, vlanPolicy.ifacename) {
				cmd := `nmcli con delete ` + vlanPolicy.ifacename + `; nmcli con delete ` + vlanPolicy.baseiface
				compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", cmd)
			}
		}()
		configErr1 := vlanPolicy.configNNCP(oc)
		o.Expect(configErr1).NotTo(o.HaveOccurred())

		compat_otp.By("4.2 Verify the policy is applied")
		nncpErr2 := checkNNCPStatus(oc, policyNamePstUpgrade, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr2, "policy applied failed")

		compat_otp.By("4.3 Verify the status of enactments is updated")
		nnceName2 := nodeName + "." + policyNamePstUpgrade
		nnceErr2 := checkNNCEStatus(oc, nnceName2, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr2, "status of enactments updated failed")

		compat_otp.By("4.4 Verify the vlan is up and active on the node")
		ifaceList2, ifaceErr2 := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		o.Expect(ifaceErr2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceList2, vlanPolicy.ifacename)).Should(o.BeTrue())

		compat_otp.By("4.5 Verify the created vlan found in node network state")
		ifaceState2, nnsErr2 := oc.AsAdmin().WithoutNamespace().Run("get").Args("nns", nodeName, `-ojsonpath={.status.currentState.interfaces[?(@.name=="`+vlanPolicy.ifacename+`")].state}`).Output()
		o.Expect(nnsErr2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(ifaceState2, "up")).Should(o.BeTrue())
	})
})

var _ = g.Describe("[OTP][sig-networking] SDN nmstate-operator testing on plateforms including Azure", func() {
	defer g.GinkgoRecover()
	var (
		oc          = compat_otp.NewCLI("networking-nmstate", compat_otp.KubeConfigPath())
		opNamespace = "openshift-nmstate"
		workers     = compat_otp.GetNodeListByLabel(oc, "node-role.kubernetes.io/worker")
	)

	g.BeforeEach(func() {
		g.By("Check the platform if it is suitable for running the test")
		platform := checkPlatform(oc)
		e2e.Logf("platform is %v", platform)
		if !(isPlatformSuitableForNMState(oc)) && !strings.Contains(platform, "azure") {
			g.Skip("It is not a suitable platform, it is not Azure either. Skip this testing!")
		}

		if len(workers) < 1 {
			g.Skip("These cases can only be run for cluster that has atleast one worker nodes. Skip this testing")
		}
		installNMstateOperator(oc)
	})

	g.It("Author:yingwang-NonPreRelease-Medium-75671-Verify global DNS via NMstate [Disruptive]", func() {
		var (
			nmstateCRTemplate = generateTemplateAbsolutePath("nmstate-cr-template.yaml")
			dnsNncpTemplate   = generateTemplateAbsolutePath("global-dns-nncp-template.yaml")
			dnsDomain         = "testglobal.com"
			ipAddr            string
		)

		ipStackType := checkIPStackType(oc)
		switch ipStackType {
		case "ipv4single":
			ipAddr = "8.8.8.8"
		case "dualstack":
			ipAddr = "2003::3"
		case "ipv6single":
			ipAddr = "2003::3"
		default:
			e2e.Logf("Get ipStackType as %s", ipStackType)
			g.Skip("Skip for not supported IP stack type!! ")
		}

		g.By("1. Create NMState CR")

		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		g.By("2. Create NNCP for Gloabal DNS")
		g.By("2.1 create policy")

		dnsServerIP1 := getAvaliableNameServer(oc, workers[0])
		dnsServerIP2 := ipAddr

		nncpDns := networkingRes{
			name:      "dns-" + getRandomString(),
			namespace: opNamespace,
			kind:      "NodeNetworkConfigurationPolicy",
			tempfile:  dnsNncpTemplate,
		}

		defer func() {
			removeResource(oc, true, true, nncpDns.kind, nncpDns.name, "-n", nncpDns.namespace)
			//configure nncp with empty dns server to clear configuration
			dnsClearNncpTemplate := generateTemplateAbsolutePath("global-dns-nncp-recover-template.yaml")
			nncpDns_clear := networkingRes{
				name:      "dns-" + getRandomString(),
				namespace: opNamespace,
				kind:      "NodeNetworkConfigurationPolicy",
				tempfile:  dnsClearNncpTemplate,
			}
			nncpDns_clear.create(oc, "NAME="+nncpDns_clear.name, "NAMESPACE="+nncpDns_clear.namespace, "NODE="+workers[0])
			nncpErr1 := checkNNCPStatus(oc, nncpDns_clear.name, "Available")
			compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
			e2e.Logf("SUCCESS - policy is applied")

			g.By("2.3 Verify the status of enactments is updated")
			nnceName_clear := workers[0] + "." + nncpDns_clear.name
			nnceErr1 := checkNNCEStatus(oc, nnceName_clear, "Available")
			compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
			e2e.Logf("SUCCESS - status of enactments is updated")

			removeResource(oc, true, true, nncpDns_clear.kind, nncpDns_clear.name, "-n", nncpDns_clear.namespace)

		}()
		nncpDns.create(oc, "NAME="+nncpDns.name, "NAMESPACE="+nncpDns.namespace, "NODE="+workers[0], "DNSDOMAIN="+dnsDomain,
			"SERVERIP1="+dnsServerIP1, "SERVERIP2="+dnsServerIP2)

		g.By("2.2 Verify the policy is applied")
		nncpErr1 := checkNNCPStatus(oc, nncpDns.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr1, "policy applied failed")
		e2e.Logf("SUCCESS - policy is applied")

		g.By("2.3 Verify the status of enactments is updated")
		nnceName := workers[0] + "." + nncpDns.name
		nnceErr1 := checkNNCEStatus(oc, nnceName, "Available")
		compat_otp.AssertWaitPollNoErr(nnceErr1, "status of enactments updated failed")
		e2e.Logf("SUCCESS - status of enactments is updated")

		g.By("2.4 Verify dns server record")
		dnsServerIP := make([]string, 2)
		dnsServerIP[0] = dnsServerIP1
		dnsServerIP[1] = dnsServerIP2
		checkDNSServer(oc, workers[0], dnsDomain, dnsServerIP)

	})
})
