// Package networking localnet tests
package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"fmt"
	"path/filepath"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[OTP][sig-networking] SDN localnet", func() {
	defer g.GinkgoRecover()

	var (
		oc                       = compat_otp.NewCLI("localnet", compat_otp.KubeConfigPath())
		opNamespace              = "openshift-nmstate"
		buildPruningBaseDir      = testdata.FixturePath("networking/nmstate")
		testDataDirUDN           = testdata.FixturePath("networking/udn")
		nmstateCRTemplate        = filepath.Join(buildPruningBaseDir, "nmstate-cr-template.yaml")
		ovnMappingPolicyTemplate = filepath.Join(buildPruningBaseDir, "ovn-mapping-policy-template.yaml")
	)

	g.BeforeEach(func() {

		g.By("Check the platform and network plugin type if it is suitable for running the test")
		networkType := checkNetworkType(oc)
		if !(isPlatformSuitableForNMState(oc)) || !strings.Contains(networkType, "ovn") {
			g.Skip("Skipping for unsupported platform or non-OVN network plugin type!")
		}
		installNMstateOperator(oc)
	})

	g.It("Author:aramesha-NonPreRelease-High-81186-Verify CUDN with single network Localnet topology with br-ex ovs-bridge on default interface without VLAN [Disruptive]", func() {
		var (
			matchLabelKey          = "test.io"
			matchValue             = "cudn-network-" + getRandomString()
			secondaryCUDNName      = "secondary-localnet-81186"
			nodeSelectLabel        = "node-role.kubernetes.io/worker"
			udnStatefulSetTemplate = filepath.Join(testDataDirUDN, "udn_statefulset_template.yaml")
		)

		nodeName, getNodeErr := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		o.Expect(nodeName).NotTo(o.BeEmpty())

		compat_otp.By("Create NMState CR")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("Configure NNCP for creating OvnMapping NMstate Feature")
		ovnMappingPolicy := ovnMappingPolicyResource{
			name:       "bridge-mapping-81186",
			nodelabel:  nodeSelectLabel,
			labelvalue: "",
			localnet1:  "mylocalnet",
			bridge1:    "br-ex",
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
		}()
		configErr3 := ovnMappingPolicy.configNNCP(oc)
		o.Expect(configErr3).NotTo(o.HaveOccurred())
		nncpErr3 := checkNNCPStatus(oc, ovnMappingPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr3, fmt.Sprintf("%s policy applied failed", ovnMappingPolicy.name))

		compat_otp.By("Create two namespaces and label them")
		allNS := []string{"test1-81186", "test2-81186"}
		for _, ns := range allNS {
			defer oc.DeleteSpecifiedNamespaceAsAdmin(ns)
			oc.CreateSpecifiedNamespaceAsAdmin(ns)
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Create secondary localnet CUDN")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", secondaryCUDNName)
		_, err := applyLocalnetCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, secondaryCUDNName, "mylocalnet", "192.168.100.0/24", "192.168.100.1/32", false)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Deploy statefulset in both cudnNS")
		for _, ns := range allNS {
			defer removeResource(oc, true, true, "statefulset", "hello", "-n", ns)
			compat_otp.ApplyNsResourceFromTemplate(oc, ns, "-f", udnStatefulSetTemplate, "NETWORK_NAME="+secondaryCUDNName)
			compat_otp.AssertAllPodsToBeReady(oc, ns)
		}

		compat_otp.By("Get all pods in both CUDN NS")
		allPodsNS0, err := compat_otp.GetAllPodsWithLabel(oc, allNS[0], "app=hello")
		o.Expect(err).NotTo(o.HaveOccurred())
		allPodsNS1, err := compat_otp.GetAllPodsWithLabel(oc, allNS[1], "app=hello")
		o.Expect(err).NotTo(o.HaveOccurred())

		//udn network connectivity should NOT be isolated
		CurlPod2PodPassUDN(oc, allNS[0], allPodsNS0[0], allNS[1], allPodsNS1[0])

		// TODO: External connectivity check needs to be added

		compat_otp.By("Create third namespace and label it too")
		allNS = append(allNS, "test3-81186")
		defer oc.DeleteSpecifiedNamespaceAsAdmin(allNS[2])
		oc.CreateSpecifiedNamespaceAsAdmin(allNS[2])
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", allNS[2], fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Deploy statefulset in third NS")
		defer removeResource(oc, true, true, "statefulset", "hello", "-n", allNS[2])
		compat_otp.ApplyNsResourceFromTemplate(oc, allNS[2], "-f", udnStatefulSetTemplate, "NETWORK_NAME="+secondaryCUDNName)

		compat_otp.By("Get all pods in third CUDN NS")
		compat_otp.AssertAllPodsToBeReady(oc, allNS[2])
		allPodsNS2, err := compat_otp.GetAllPodsWithLabel(oc, allNS[2], "app=hello")
		o.Expect(err).NotTo(o.HaveOccurred())

		//udn network connectivity should NOT be isolated
		CurlPod2PodPassUDN(oc, allNS[0], allPodsNS0[3], allNS[2], allPodsNS2[0])
	})

	g.It("Author:aramesha-NonPreRelease-High-81187-Verify CUDN with single network Localnet topology with br-ex ovs-bridge on default interface with VLAN [Disruptive]", func() {
		var (
			udnStatefulSetTemplate = filepath.Join(testDataDirUDN, "udn_statefulset_template.yaml")
			matchLabelKey          = "test.io"
			matchValue             = "cudn-network-" + getRandomString()
			secondaryCUDNName      = "secondary-localnet-81187"
			nodeSelectLabel        = "node-role.kubernetes.io/worker"
		)

		nodeName, getNodeErr := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		o.Expect(nodeName).NotTo(o.BeEmpty())

		compat_otp.By("Create NMState CR")
		nmstateCR := nmstateCRResource{
			name:     "nmstate",
			template: nmstateCRTemplate,
		}
		defer deleteNMStateCR(oc, nmstateCR)
		result, crErr := createNMStateCR(oc, nmstateCR, opNamespace)
		compat_otp.AssertWaitPollNoErr(crErr, "create nmstate cr failed")
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("SUCCESS - NMState CR Created")

		compat_otp.By("Configure NNCP for creating OvnMapping NMstate Feature")
		ovnMappingPolicy := ovnMappingPolicyResource{
			name:       "bridge-mapping-81187",
			nodelabel:  nodeSelectLabel,
			labelvalue: "",
			localnet1:  "mylocalnet",
			bridge1:    "br-ex",
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
		}()
		configErr3 := ovnMappingPolicy.configNNCP(oc)
		o.Expect(configErr3).NotTo(o.HaveOccurred())
		nncpErr3 := checkNNCPStatus(oc, ovnMappingPolicy.name, "Available")
		compat_otp.AssertWaitPollNoErr(nncpErr3, fmt.Sprintf("%s policy applied failed", ovnMappingPolicy.name))

		compat_otp.By("Create two namespaces and label them")
		allNS := []string{"test1-81187", "test2-81187"}
		for _, ns := range allNS {
			defer oc.DeleteSpecifiedNamespaceAsAdmin(ns)
			oc.CreateSpecifiedNamespaceAsAdmin(ns)
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		compat_otp.By("Create secondary localnet CUDN")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", secondaryCUDNName)
		_, err := applyLocalnetCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, secondaryCUDNName, "mylocalnet", "192.168.100.0/24", "192.168.100.1/32", true)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Deploy statefulset in both cudnNS")
		for _, ns := range allNS {
			defer removeResource(oc, true, true, "statefulset", "hello", "-n", ns)
			compat_otp.ApplyNsResourceFromTemplate(oc, ns, "-f", udnStatefulSetTemplate, "NETWORK_NAME="+secondaryCUDNName)
			compat_otp.AssertAllPodsToBeReady(oc, ns)
		}

		compat_otp.By("Get all pods in both CUDN NS")
		allPodsNS0, err := compat_otp.GetAllPodsWithLabel(oc, allNS[0], "app=hello")
		o.Expect(err).NotTo(o.HaveOccurred())
		allPodsNS1, err := compat_otp.GetAllPodsWithLabel(oc, allNS[1], "app=hello")
		o.Expect(err).NotTo(o.HaveOccurred())

		//udn network connectivity should NOT be isolated
		CurlPod2PodPassUDN(oc, allNS[0], allPodsNS0[0], allNS[1], allPodsNS1[0])

		// TODO: External connectivity check needs to be added

		compat_otp.By("Create third namespace and label it too")
		allNS = append(allNS, "test3-81187")
		defer oc.DeleteSpecifiedNamespaceAsAdmin(allNS[2])
		oc.CreateSpecifiedNamespaceAsAdmin(allNS[2])
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", allNS[2], fmt.Sprintf("%s=%s", matchLabelKey, matchValue)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Deploy statefulset in third NS")
		defer removeResource(oc, true, true, "statefulset", "hello", "-n", allNS[2])
		compat_otp.ApplyNsResourceFromTemplate(oc, allNS[2], "-f", udnStatefulSetTemplate, "NETWORK_NAME="+secondaryCUDNName)

		compat_otp.By("Get all pods in third CUDN NS")
		compat_otp.AssertAllPodsToBeReady(oc, allNS[2])
		allPodsNS2, err := compat_otp.GetAllPodsWithLabel(oc, allNS[2], "app=hello")
		o.Expect(err).NotTo(o.HaveOccurred())

		//udn network connectivity should NOT be isolated
		CurlPod2PodPassUDN(oc, allNS[0], allPodsNS0[3], allNS[2], allPodsNS2[0])
	})

	g.It("Author:aramesha-NonPreRelease-High-81192-Verify CUDN with localnet topology (physicalNetworkName, MTU, VLAN, excludeSubnets) is immutable", func() {
		var (
			matchLabelKey     = "test.io"
			matchValue        = "cudn-network-" + getRandomString()
			secondaryCUDNName = "secondary-localnet-81192"
		)

		compat_otp.By("Create secondary localnet CUDN")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", secondaryCUDNName)
		_, err := applyLocalnetCUDNtoMatchLabelNS(oc, matchLabelKey, matchValue, secondaryCUDNName, "mylocalnet", "192.168.100.0/24", "192.168.100.1/32", true)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify MTU patch is immutable")
		MTUPatchMsg, patchErr := oc.AsAdmin().Run("patch").Args("clusteruserdefinednetworks", secondaryCUDNName, "-p", `{"spec": {"network": {"localnet": {"mtu":2000}} }}`, "--type=merge").Output()
		o.Expect(patchErr).Should(o.HaveOccurred())
		o.Expect(MTUPatchMsg).Should(o.ContainSubstring(`Network spec is immutable`))

		compat_otp.By("Verify physicalNetworkName patch is immutable")
		PhysicalNetworkNamePatchMsg, patchErr := oc.AsAdmin().Run("patch").Args("clusteruserdefinednetworks", secondaryCUDNName, "-p", `{"spec": {"network": {"localnet": {"physicalNetworkName":"my-localnet"}} }}`, "--type=merge").Output()
		o.Expect(patchErr).Should(o.HaveOccurred())
		o.Expect(PhysicalNetworkNamePatchMsg).Should(o.ContainSubstring(`Network spec is immutable`))

		compat_otp.By("Verify excludeSubnet patch is immutable")
		excludeSubnetPatchMsg, patchErr := oc.AsAdmin().Run("patch").Args("clusteruserdefinednetworks", secondaryCUDNName, "-p", `{"spec": {"network": {"localnet": {"excludeSubnets":["192.168.100.2/32"]}} }}`, "--type=merge").Output()
		o.Expect(patchErr).Should(o.HaveOccurred())
		o.Expect(excludeSubnetPatchMsg).Should(o.ContainSubstring(`Network spec is immutable`))

		compat_otp.By("Verify VLAN patch is immutable")
		VLANPatchMsg, patchErr := oc.AsAdmin().Run("patch").Args("clusteruserdefinednetworks", secondaryCUDNName, "-p", `{"spec": {"network": {"localnet": {"vlan":{ "access": {"id":200}}}} }}`, "--type=merge").Output()
		o.Expect(patchErr).Should(o.HaveOccurred())
		o.Expect(VLANPatchMsg).Should(o.ContainSubstring(`Network spec is immutable`))
	})
})
