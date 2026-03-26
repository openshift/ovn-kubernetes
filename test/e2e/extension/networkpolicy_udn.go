package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN udn networkpolicy", func() {
	defer g.GinkgoRecover()

	var (
		oc             = exutil.NewCLI("networking-udn")
		testDataDirUDN = testdata.FixturePath("networking/udn")
	)

	g.BeforeEach(func() {

		SkipIfNoFeatureGate(oc, "NetworkSegmentation")

		networkType := checkNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("Author:asood-High-78292-Validate ingress allow-same-namespace and allow-all-namespaces network policies in Layer 3 NAD.", func() {
		var (
			testID                 = "78292"
			testDataDir            = testdata.FixturePath("networking")
			udnNADTemplate         = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			udnPodTemplate         = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			ingressDenyFile        = filepath.Join(testDataDir, "networkpolicy/default-deny-ingress.yaml")
			ingressAllowSameNSFile = filepath.Join(testDataDir, "networkpolicy/allow-from-same-namespace.yaml")
			ingressAllowAllNSFile  = filepath.Join(testDataDir, "networkpolicy/allow-from-all-namespaces.yaml")
			nsPodMap               = make(map[string][]string)
			nadResourcename        = "l3-network-"
			topology               = "layer3"
		)
		ipStackType := checkIPStackType(oc)
		var nadName string
		var nadNS []string = make([]string, 0, 4)
		nsDefaultNetwork := oc.Namespace()
		nadNetworkName := []string{"l3-network-test-1", "l3-network-test-2"}

		compat_otp.By("1.0 Create 4 UDN namespaces")
		for i := 0; i < 4; i++ {
			oc.CreateNamespaceUDN()
			nadNS = append(nadNS, oc.Namespace())
		}
		nadNS = append(nadNS, nsDefaultNetwork)
		var subnet []string
		if ipStackType == "ipv4single" {
			subnet = []string{"10.150.0.0/16/24", "10.152.0.0/16/24"}
		} else {
			if ipStackType == "ipv6single" {
				subnet = []string{"2010:100:200::0/60", "2012:100:200::0/60"}
			} else {
				subnet = []string{"10.150.0.0/16/24,2010:100:200::0/60", "10.152.0.0/16/24,2012:100:200::0/60"}
			}
		}
		compat_otp.By("2. Create Layer 3 NAD in first two namespaces")
		// Same network name in both namespaces
		nad := make([]udnNetDefResource, 4)
		for i := 0; i < 2; i++ {
			nadName = nadResourcename + strconv.Itoa(i) + "-" + testID
			if i == 1 {
				o.Expect(oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nadNS[i], "team=ocp").Execute()).NotTo(o.HaveOccurred())

			}
			compat_otp.By(fmt.Sprintf("Create NAD %s in namespace %s", nadName, nadNS[i]))
			nad[i] = udnNetDefResource{
				nadname:             nadName,
				namespace:           nadNS[i],
				nad_network_name:    nadNetworkName[0],
				topology:            topology,
				subnet:              subnet[0],
				net_attach_def_name: nadNS[i] + "/" + nadName,
				role:                "primary",
				template:            udnNADTemplate,
			}
			nad[i].createUdnNad(oc)

		}
		compat_otp.By("3. Create two pods in each namespace")
		pod := make([]udnPodResource, 4)
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				pod[j] = udnPodResource{
					name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					namespace: nadNS[i],
					label:     "hello-pod",
					template:  udnPodTemplate,
				}
				pod[j].createUdnPod(oc)
				waitPodReady(oc, pod[j].namespace, pod[j].name)
				nsPodMap[pod[j].namespace] = append(nsPodMap[pod[j].namespace], pod[j].name)
			}
		}
		CurlPod2PodPassUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][1], nadNS[0], nsPodMap[nadNS[0]][0])

		compat_otp.By("4. Create default deny ingress type networkpolicy in first namespace")
		createResourceFromFile(oc, nadNS[0], ingressDenyFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-ingress"))

		compat_otp.By("5. Validate traffic between pods in first namespace and from pods in second namespace")
		CurlPod2PodFailUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][1], nadNS[0], nsPodMap[nadNS[0]][0])

		compat_otp.By("6. Create allow same namespace ingress type networkpolicy in first namespace")
		createResourceFromFile(oc, nadNS[0], ingressAllowSameNSFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-from-same-namespace"))

		compat_otp.By("7. Validate traffic between pods in first namespace works but traffic from pod in second namespace is blocked")
		CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][1], nadNS[0], nsPodMap[nadNS[0]][0])
		CurlPod2PodFailUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])

		compat_otp.By("8. Create allow ingress from all namespaces networkpolicy in first namespace")
		createResourceFromFile(oc, nadNS[0], ingressAllowAllNSFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-from-all-namespaces"))

		compat_otp.By("9. Validate traffic from pods in second namespace")
		CurlPod2PodPassUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])

		compat_otp.By(fmt.Sprintf("10. Create NAD with same network %s in namespace %s as the first two namespaces and %s  (different network) in %s", nadNetworkName[0], nadNS[2], nadNetworkName[1], nadNS[3]))
		for i := 2; i < 4; i++ {
			nad[i] = udnNetDefResource{
				nadname:             nadResourcename + strconv.Itoa(i) + "-" + testID,
				namespace:           nadNS[i],
				nad_network_name:    nadNetworkName[i-2],
				topology:            topology,
				subnet:              subnet[i-2],
				net_attach_def_name: nadNS[i] + "/" + nadResourcename + strconv.Itoa(i) + "-" + testID,
				role:                "primary",
				template:            udnNADTemplate,
			}
			nad[i].createUdnNad(oc)
		}

		compat_otp.By("11. Create one pod each in last three namespaces, last one being without NAD")
		pod = make([]udnPodResource, 6)
		for i := 2; i < 5; i++ {
			for j := 0; j < 1; j++ {
				pod[j] = udnPodResource{
					name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					namespace: nadNS[i],
					label:     "hello-pod",
					template:  udnPodTemplate,
				}
				pod[j].createUdnPod(oc)
				waitPodReady(oc, pod[j].namespace, pod[j].name)
				nsPodMap[pod[j].namespace] = append(nsPodMap[pod[j].namespace], pod[j].name)
			}
		}
		compat_otp.By("12. Validate traffic from pods in third and fourth namespace works but not from pod in fifth namespace (default)")
		CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[2], nsPodMap[nadNS[2]][0])
		CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[3], nsPodMap[nadNS[3]][0])
		CurlPod2PodFail(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[4], nsPodMap[nadNS[4]][0])

		compat_otp.By("13. Update allow-all-namespaces policy with label to allow ingress traffic from pod in second namespace only")
		npPatch := `[{"op": "replace", "path": "/spec/ingress/0/from/0/namespaceSelector", "value": {"matchLabels": {"team": "ocp" }}}]`
		patchReplaceResourceAsAdmin(oc, "networkpolicy/allow-from-all-namespaces", npPatch, nadNS[0])
		npRules, npErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "allow-from-all-namespaces", "-n", nadNS[0], "-o=jsonpath={.spec}").Output()
		o.Expect(npErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Network policy after update: %s", npRules)

		compat_otp.By("14. Validate traffic from pods in second namespace works but fails from pod in third namespace")
		CurlPod2PodPassUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		CurlPod2PodFailUDN(oc, nadNS[2], nsPodMap[nadNS[2]][0], nadNS[0], nsPodMap[nadNS[0]][0])

	})

	g.It("Author:asood-High-79092-Validate egress allow-same-namespace and allow-all-namespaces network policies in Layer 2 NAD.", func() {
		var (
			testID                = "79092"
			testDataDir           = testdata.FixturePath("networking")
			udnNADTemplate        = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			udnPodTemplate        = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			egressDenyFile        = filepath.Join(testDataDir, "networkpolicy/default-deny-egress.yaml")
			egressAllowSameNSFile = filepath.Join(testDataDir, "networkpolicy/allow-to-same-namespace.yaml")
			egressAllowAllNSFile  = filepath.Join(testDataDir, "networkpolicy/allow-to-all-namespaces.yaml")
			nsPodMap              = make(map[string][]string)
			nadResourcename       = "l2-network-"
			topology              = "layer2"
		)
		ipStackType := checkIPStackType(oc)
		var nadName string
		var nadNS []string = make([]string, 0, 4)
		nadNetworkName := []string{"l2-network-test-1", "l2-network-test-2"}
		nsDefaultNetwork := oc.Namespace()

		compat_otp.By("1.0 Create 4 UDN namespaces")
		for i := 0; i < 4; i++ {
			oc.CreateNamespaceUDN()
			nadNS = append(nadNS, oc.Namespace())
		}
		nadNS = append(nadNS, nsDefaultNetwork)
		var subnet []string
		if ipStackType == "ipv4single" {
			subnet = []string{"10.150.0.0/16", "10.152.0.0/16"}
		} else {
			if ipStackType == "ipv6single" {
				subnet = []string{"2012:100:200::0/60"}
			} else {
				subnet = []string{"10.150.0.0/16,2010:100:200::0/60", "10.152.0.0/16,2012:100:200::0/60"}
			}
		}

		compat_otp.By("2. Create Layer 2 NAD in first two namespaces")
		nad := make([]udnNetDefResource, 4)
		for i := 0; i < 2; i++ {
			nadName = nadResourcename + strconv.Itoa(i) + "-" + testID
			if i == 1 {
				o.Expect(oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nadNS[i], "team=ocp").Execute()).NotTo(o.HaveOccurred())

			}
			compat_otp.By(fmt.Sprintf("Create NAD %s in namespace %s", nadName, nadNS[i]))
			nad[i] = udnNetDefResource{
				nadname:             nadName,
				namespace:           nadNS[i],
				nad_network_name:    nadNetworkName[0],
				topology:            topology,
				subnet:              subnet[0],
				net_attach_def_name: nadNS[i] + "/" + nadName,
				role:                "primary",
				template:            udnNADTemplate,
			}
			nad[i].createUdnNad(oc)
		}

		compat_otp.By("3. Create two pods in each namespace")
		pod := make([]udnPodResource, 4)
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				pod[j] = udnPodResource{
					name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					namespace: nadNS[i],
					label:     "hello-pod",
					template:  udnPodTemplate,
				}
				pod[j].createUdnPod(oc)
				waitPodReady(oc, pod[j].namespace, pod[j].name)
				nsPodMap[pod[j].namespace] = append(nsPodMap[pod[j].namespace], pod[j].name)
			}
		}
		CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])
		CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[0], nsPodMap[nadNS[0]][1])

		compat_otp.By("4. Create default deny egresss type networkpolicy in first namespace")
		createResourceFromFile(oc, nadNS[0], egressDenyFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-egress"))

		compat_otp.By("5. Validate traffic between pods in first namespace and from pods in second namespace")
		CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])
		CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[0], nsPodMap[nadNS[0]][1])

		compat_otp.By("6. Create allow egress to same namespace networkpolicy in first namespace")
		createResourceFromFile(oc, nadNS[0], egressAllowSameNSFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-same-namespace"))

		compat_otp.By("7. Validate traffic between pods in first namespace works but traffic from pod in second namespace is blocked")
		CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[0], nsPodMap[nadNS[0]][1])
		CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])

		compat_otp.By("8. Create allow all namespaces egress type networkpolicy in first namespace")
		createResourceFromFile(oc, nadNS[0], egressAllowAllNSFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-all-namespaces"))

		compat_otp.By("9. Validate traffic to pods in second namespace")
		CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])

		compat_otp.By(fmt.Sprintf("10. Create NAD with same network %s in namespace %s as the first two namespaces and %s  (different network) in %s", nadNetworkName[0], nadNS[2], nadNetworkName[1], nadNS[3]))
		for i := 2; i < 4; i++ {
			nad[i] = udnNetDefResource{
				nadname:             nadResourcename + strconv.Itoa(i) + "-" + testID,
				namespace:           nadNS[i],
				nad_network_name:    nadNetworkName[i-2],
				topology:            topology,
				subnet:              subnet[i-2],
				net_attach_def_name: nadNS[i] + "/" + nadResourcename + strconv.Itoa(i) + "-" + testID,
				role:                "primary",
				template:            udnNADTemplate,
			}
			nad[i].createUdnNad(oc)
		}

		compat_otp.By("11. Create one pod each in last three namespaces, last one being without NAD")
		pod = make([]udnPodResource, 6)
		for i := 2; i < 5; i++ {
			for j := 0; j < 1; j++ {
				pod[j] = udnPodResource{
					name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					namespace: nadNS[i],
					label:     "hello-pod",
					template:  udnPodTemplate,
				}
				pod[j].createUdnPod(oc)
				waitPodReady(oc, pod[j].namespace, pod[j].name)
				nsPodMap[pod[j].namespace] = append(nsPodMap[pod[j].namespace], pod[j].name)
			}
		}

		compat_otp.By("12. Validate traffic to pods in third and fourth namespace works but not to pod in fifth namespace (default)")
		CurlPod2PodPassUDN(oc, nadNS[2], nsPodMap[nadNS[2]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		CurlPod2PodFailUDN(oc, nadNS[3], nsPodMap[nadNS[3]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		CurlPod2PodFail(oc, nadNS[4], nsPodMap[nadNS[4]][0], nadNS[0], nsPodMap[nadNS[0]][0])

		compat_otp.By("13. Update allow-all-namespaces policy with label to allow ingress traffic to pod in second namespace only")
		npPatch := `[{"op": "replace", "path": "/spec/egress/0/to/0/namespaceSelector", "value": {"matchLabels": {"team": "ocp" }}}]`
		patchReplaceResourceAsAdmin(oc, "networkpolicy/allow-to-all-namespaces", npPatch, nadNS[0])
		npRules, npErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "allow-to-all-namespaces", "-n", nadNS[0], "-o=jsonpath={.spec}").Output()
		o.Expect(npErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Network policy after update: %s", npRules)

		compat_otp.By("14. Validate traffic to pods in second namespace works but fails to pod in third namespace")
		CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])
		CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[2], nsPodMap[nadNS[2]][0])

	})

	g.It("Author:asood-High-79093-Validate ingress CIDR block with and without except clause network policies in Layer 3 CUDN.", func() {
		var (
			testID                       = "79093"
			testDataDir                  = testdata.FixturePath("networking")
			udnPodTemplate               = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			udnPodNodeTemplate           = filepath.Join(testDataDirUDN, "udn_test_pod_template_node.yaml")
			ingressDenyFile              = filepath.Join(testDataDir, "networkpolicy/default-deny-ingress.yaml")
			ipBlockIngressTemplateDual   = filepath.Join(testDataDir, "networkpolicy/ipblock/ipBlock-ingress-dual-CIDRs-template.yaml")
			ipBlockIngressTemplateSingle = filepath.Join(testDataDir, "networkpolicy/ipblock/ipBlock-ingress-single-CIDR-template.yaml")
			nsPodMap                     = make(map[string][]string)
			topology                     = "layer3"
			matchLabelKey                = "test.io"
			matchLabelVal                = "ns-" + testID
			cudnCRDName                  = "cudn-l3-network-" + testID
			udnCRDName                   = "udn-l3-network-" + testID + "-0"
		)
		ipStackType := checkIPStackType(oc)
		var allNS []string = make([]string, 0, 3)
		var ipBlockPolicyName string
		var podCount int
		nsDefaultNetwork := oc.Namespace()

		compat_otp.By("1.0 Create 3 UDN namespaces")
		for i := 0; i < 3; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			allNS = append(allNS, ns)
			// Label first two for CUDN
			if i < 2 {
				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
				err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchLabelVal)).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}
		// Annotate first namespace for ACL logging
		aclSettings := aclSettings{DenySetting: "alert", AllowSetting: "alert"}
		err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", allNS[0], aclSettings.getJSONString()).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())

		allNS = append(allNS, nsDefaultNetwork)
		var cidr0, ipv4cidr0, ipv6cidr0, cidr1, ipv4cidr1, ipv6cidr1 string
		if ipStackType == "ipv4single" {
			cidr0 = "10.150.0.0/16"
			cidr1 = "10.152.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr0 = "2010:100:200::0/48"
				cidr1 = "2012:100:200::0/48"
			} else {
				ipv4cidr0 = "10.150.0.0/16"
				ipv4cidr1 = "10.152.0.0/16"
				ipv6cidr0 = "2010:100:200::0/48"
				ipv6cidr1 = "2012:100:200::0/48"

			}
		}

		compat_otp.By("2. Create default deny ingress type networkpolicy in first namespace before UDN is created")
		createResourceFromFile(oc, allNS[0], ingressDenyFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-ingress"))

		compat_otp.By("3. Create Layer 3 UDN in first two namespaces with CUDN resource and UDN in third")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnCRDName)
		_, cudnErr := applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchLabelVal, cudnCRDName, ipv4cidr0, ipv6cidr0, cidr0, topology)
		o.Expect(cudnErr).NotTo(o.HaveOccurred())
		defer removeResource(oc, true, true, "userdefinednetwork", udnCRDName)
		createGeneralUDNCRD(oc, allNS[2], udnCRDName, ipv4cidr1, ipv6cidr1, cidr1, topology)

		compat_otp.By("4. Create two pods in each namespace")
		podCount = 2
		pod := make([]udnPodResource, 4)
		for i := 0; i < len(allNS); i++ {
			if i == 2 {
				podCount = 1
			}
			for j := 0; j < podCount; j++ {
				pod[j] = udnPodResource{
					name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					namespace: allNS[i],
					label:     "hello-pod",
					template:  udnPodTemplate,
				}
				pod[j].createUdnPod(oc)
				defer removeResource(oc, true, true, "pod", pod[j].name, "-n", pod[j].namespace)
				waitPodReady(oc, pod[j].namespace, pod[j].name)
				nsPodMap[pod[j].namespace] = append(nsPodMap[pod[j].namespace], pod[j].name)
			}
		}

		compat_otp.By("5. Validate traffic between pods in first namespace and from pods in second namespace")
		CurlPod2PodFailUDN(oc, allNS[1], nsPodMap[allNS[1]][0], allNS[0], nsPodMap[allNS[0]][0])
		CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][1], allNS[0], nsPodMap[allNS[0]][0])

		compat_otp.By("6. Get node name and IPs of first pod in first namespace")
		podNodeName, podNodeNameErr := compat_otp.GetPodNodeName(oc, allNS[0], nsPodMap[allNS[0]][0])
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())

		compat_otp.By("7. Validate verdict=drop message")
		output, logErr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", podNodeName, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(logErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "verdict=drop")).To(o.BeTrue())

		compat_otp.By("8. Create IP Block ingress policy to allow traffic from first pod in second namespace to first pod in first")
		var cidrIpv4, cidrIpv6, cidr string
		if ipStackType == "dualstack" {
			compat_otp.By(fmt.Sprintf("Create ipBlock Ingress Dual CIDRs Policy in %s", allNS[0]))
			pod1ns1IPv6, pod1ns1IPv4 := getPodIPUDN(oc, allNS[1], nsPodMap[allNS[1]][0], "ovn-udn1")
			cidrIpv4 = pod1ns1IPv4 + "/32"
			cidrIpv6 = pod1ns1IPv6 + "/128"
			npIPBlockNS1 := ipBlockCIDRsDual{
				name:      "ipblock-dual-cidrs-ingress",
				template:  ipBlockIngressTemplateDual,
				cidrIpv4:  cidrIpv4,
				cidrIpv6:  cidrIpv6,
				namespace: allNS[0],
			}
			npIPBlockNS1.createipBlockCIDRObjectDual(oc)
			ipBlockPolicyName = npIPBlockNS1.name

		} else {
			pod1ns1, _ := getPodIPUDN(oc, allNS[1], nsPodMap[allNS[1]][0], "ovn-udn1")
			if ipStackType == "ipv6single" {
				cidr = pod1ns1 + "/128"
			} else {
				cidr = pod1ns1 + "/32"
			}
			npIPBlockNS1 := ipBlockCIDRsSingle{
				name:      "ipblock-single-cidr-ingress",
				template:  ipBlockIngressTemplateSingle,
				cidr:      cidr,
				namespace: allNS[0],
			}
			npIPBlockNS1.createipBlockCIDRObjectSingle(oc)
			ipBlockPolicyName = npIPBlockNS1.name

		}

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(ipBlockPolicyName))

		compat_otp.By("9. Validate traffic to first pod in first namespace is allowed from first pod in second namespace and verdict=allow in ACL audit log")
		CurlPod2PodPassUDN(oc, allNS[1], nsPodMap[allNS[1]][0], allNS[0], nsPodMap[allNS[0]][0])
		output, logErr = oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", podNodeName, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(logErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "verdict=allow")).To(o.BeTrue())

		compat_otp.By("10. Validate ingress traffic is not allowed from second pod in second namespace, pod in third namespace and pod in fourth (default network)")

		CurlPod2PodFailUDN(oc, allNS[1], nsPodMap[allNS[1]][1], allNS[0], nsPodMap[allNS[0]][0])
		CurlPod2PodFailUDN(oc, allNS[2], nsPodMap[allNS[2]][0], allNS[0], nsPodMap[allNS[0]][0])
		CurlPod2PodFailUDN(oc, allNS[3], nsPodMap[allNS[3]][0], allNS[0], nsPodMap[allNS[0]][0])

		compat_otp.By("11. Get node name of first pod in second namespace and schedule another pod on smae node")
		podNodeName, podNodeNameErr = compat_otp.GetPodNodeName(oc, allNS[1], nsPodMap[allNS[1]][0])
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())
		newPod := udnPodResourceNode{
			name:      "hello-pod-" + testID + "-1-2",
			namespace: allNS[1],
			label:     "hello-pod",
			nodename:  podNodeName,
			template:  udnPodNodeTemplate,
		}
		newPod.createUdnPodNode(oc)
		defer removeResource(oc, true, true, "pod", newPod.name, "-n", newPod.namespace)
		waitPodReady(oc, newPod.namespace, newPod.name)

		compat_otp.By(fmt.Sprintf("12. Update the %s policy to include except clause to block the ingress from the first pod in second", ipBlockPolicyName))
		var patchPayload string
		if ipStackType == "dualstack" {
			hostSubnetIPv4, hostSubnetIPv6 := getNodeSubnetDualStack(oc, podNodeName, "cluster_udn_"+cudnCRDName)
			patchPayload = fmt.Sprintf("[{\"op\": \"replace\", \"path\":\"/spec/ingress/0/from\", \"value\": [{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}},{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}}] }]", hostSubnetIPv4, cidrIpv4, hostSubnetIPv6, cidrIpv6)
		} else {
			hostSubnetCIDR := getNodeSubnet(oc, podNodeName, "cluster_udn_"+cudnCRDName)
			patchPayload = fmt.Sprintf("[{\"op\": \"replace\", \"path\":\"/spec/ingress/0/from\", \"value\": [{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}}] }]", hostSubnetCIDR, cidr)
		}
		patchReplaceResourceAsAdmin(oc, "networkpolicy/"+ipBlockPolicyName, patchPayload, allNS[0])
		npRules, npErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", ipBlockPolicyName, "-n", allNS[0], "-o=jsonpath={.spec}").Output()
		o.Expect(npErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Network policy after update: %s", npRules)

		CurlPod2PodFailUDN(oc, allNS[1], nsPodMap[allNS[1]][0], allNS[0], nsPodMap[allNS[0]][0])
		CurlPod2PodPassUDN(oc, allNS[1], newPod.name, allNS[0], nsPodMap[allNS[0]][0])

	})

	g.It("Author:asood-High-79094-Validate egress CIDR block with and without except clause network policies in Layer 3 CUDN.", func() {
		var (
			testID                      = "79094"
			testDataDir                 = testdata.FixturePath("networking")
			udnPodTemplate              = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			udnPodNodeTemplate          = filepath.Join(testDataDirUDN, "udn_test_pod_template_node.yaml")
			egressDenyFile              = filepath.Join(testDataDir, "networkpolicy/default-deny-egress.yaml")
			egressAllowFile             = filepath.Join(testDataDir, "networkpolicy/egress-allow-all.yaml")
			ipBlockEgressTemplateDual   = filepath.Join(testDataDir, "networkpolicy/ipblock/ipBlock-egress-dual-CIDRs-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(testDataDir, "networkpolicy/ipblock/ipBlock-egress-single-CIDR-template.yaml")
			nsPodMap                    = make(map[string][]string)
			topology                    = "layer3"
			matchLabelKey               = "test.io"
			matchLabelVal               = "ns-" + testID
			cudnCRDName                 = "cudn-l3-network-" + testID
			udnCRDName                  = "udn-l3-network-" + testID + "-0"
		)
		ipStackType := checkIPStackType(oc)
		var allNS []string = make([]string, 0, 3)
		var ipBlockPolicyName string
		var podCount int

		compat_otp.By("1. Create 3 UDN namespaces")
		for i := 0; i < 3; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			allNS = append(allNS, ns)
			// Label first two for CUDN
			if i < 2 {
				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s-", matchLabelKey)).Execute()
				err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns, fmt.Sprintf("%s=%s", matchLabelKey, matchLabelVal)).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}

		var cidr0, ipv4cidr0, ipv6cidr0, cidr1, ipv4cidr1, ipv6cidr1 string
		if ipStackType == "ipv4single" {
			cidr0 = "10.150.0.0/16"
			cidr1 = "10.152.0.0/16"
		} else {
			if ipStackType == "ipv6single" {
				cidr0 = "2010:100:200::0/48"
				cidr1 = "2012:100:200::0/48"
			} else {
				ipv4cidr0 = "10.150.0.0/16"
				ipv4cidr1 = "10.152.0.0/16"
				ipv6cidr0 = "2010:100:200::0/48"
				ipv6cidr1 = "2012:100:200::0/48"

			}
		}

		compat_otp.By("2. Create default deny egress type networkpolicy in first namespace before UDN is created")
		createResourceFromFile(oc, allNS[0], egressDenyFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-egress"))

		compat_otp.By("3. Create Layer 3 UDN in first two namespaces with CUDN resource and UDN in third")
		defer removeResource(oc, true, true, "clusteruserdefinednetwork", cudnCRDName)
		_, cudnErr := applyCUDNtoMatchLabelNS(oc, matchLabelKey, matchLabelVal, cudnCRDName, ipv4cidr0, ipv6cidr0, cidr0, topology)
		o.Expect(cudnErr).NotTo(o.HaveOccurred())
		defer removeResource(oc, true, true, "userdefinednetwork", udnCRDName)
		createGeneralUDNCRD(oc, allNS[2], udnCRDName, ipv4cidr1, ipv6cidr1, cidr1, topology)

		compat_otp.By("4. Create two pods in each namespace")
		podCount = 2
		pod := make([]udnPodResource, 4)
		for i := 0; i < len(allNS); i++ {
			if i == 2 {
				podCount = 1
			}
			for j := 0; j < podCount; j++ {
				pod[j] = udnPodResource{
					name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					namespace: allNS[i],
					label:     "test-pods",
					template:  udnPodTemplate,
				}
				pod[j].createUdnPod(oc)
				defer removeResource(oc, true, true, "pod", pod[j].name, "-n", pod[j].namespace)
				waitPodReady(oc, pod[j].namespace, pod[j].name)
				nsPodMap[pod[j].namespace] = append(nsPodMap[pod[j].namespace], pod[j].name)
			}
		}

		compat_otp.By("5. Validate traffic between pods in first namespace and from pods in second namespace")
		CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], nsPodMap[allNS[1]][0])
		CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[0], nsPodMap[allNS[0]][1])

		compat_otp.By("6. Create IP Block egress policy to allow traffic from first pod in first namespace to first pod in second namespace")
		var cidrIpv4, cidrIpv6, cidr string
		if ipStackType == "dualstack" {
			compat_otp.By(fmt.Sprintf("Create ipBlock Egress Dual CIDRs Policy in %s", allNS[0]))
			pod1ns1IPv6, pod1ns1IPv4 := getPodIPUDN(oc, allNS[1], nsPodMap[allNS[1]][0], "ovn-udn1")
			cidrIpv4 = pod1ns1IPv4 + "/32"
			cidrIpv6 = pod1ns1IPv6 + "/128"
			npIPBlockNS1 := ipBlockCIDRsDual{
				name:      "ipblock-dual-cidrs-egress",
				template:  ipBlockEgressTemplateDual,
				cidrIpv4:  cidrIpv4,
				cidrIpv6:  cidrIpv6,
				namespace: allNS[0],
			}
			npIPBlockNS1.createipBlockCIDRObjectDual(oc)
			ipBlockPolicyName = npIPBlockNS1.name

		} else {
			pod1ns1, _ := getPodIPUDN(oc, allNS[1], nsPodMap[allNS[1]][0], "ovn-udn1")
			if ipStackType == "ipv6single" {
				cidr = pod1ns1 + "/128"
			} else {
				cidr = pod1ns1 + "/32"
			}
			npIPBlockNS1 := ipBlockCIDRsSingle{
				name:      "ipblock-single-cidr-egress",
				template:  ipBlockEgressTemplateSingle,
				cidr:      cidr,
				namespace: allNS[0],
			}
			npIPBlockNS1.createipBlockCIDRObjectSingle(oc)
			ipBlockPolicyName = npIPBlockNS1.name

		}

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(ipBlockPolicyName))

		compat_otp.By("7. Validate ingress traffic is not allowed from second pod in second namespace, pod in third namespace and pod in fourth (default network)")
		CurlPod2PodPassUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], nsPodMap[allNS[1]][0])
		CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], nsPodMap[allNS[1]][1])
		CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[2], nsPodMap[allNS[2]][0])

		compat_otp.By("8. Get node name of first pod in second namespace and schedule another pod on smae node")
		podNodeName, podNodeNameErr := compat_otp.GetPodNodeName(oc, allNS[1], nsPodMap[allNS[1]][0])
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())
		newPodNS2 := udnPodResourceNode{
			name:      "hello-pod-" + testID + "-1-2",
			namespace: allNS[1],
			label:     "test-pods",
			nodename:  podNodeName,
			template:  udnPodNodeTemplate,
		}
		newPodNS2.createUdnPodNode(oc)
		defer removeResource(oc, true, true, "pod", newPodNS2.name, "-n", newPodNS2.namespace)
		waitPodReady(oc, newPodNS2.namespace, newPodNS2.name)

		compat_otp.By(fmt.Sprintf("9. Update the %s policy to include except clause to block the egress to the first pod in second namespace", ipBlockPolicyName))
		var patchPayload string
		if ipStackType == "dualstack" {
			hostSubnetIPv4, hostSubnetIPv6 := getNodeSubnetDualStack(oc, podNodeName, "cluster_udn_"+cudnCRDName)
			patchPayload = fmt.Sprintf("[{\"op\": \"replace\", \"path\":\"/spec/egress/0/to\", \"value\": [{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}},{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}}] }]", hostSubnetIPv4, cidrIpv4, hostSubnetIPv6, cidrIpv6)
		} else {
			hostSubnetCIDR := getNodeSubnet(oc, podNodeName, "cluster_udn_"+cudnCRDName)
			patchPayload = fmt.Sprintf("[{\"op\": \"replace\", \"path\":\"/spec/egress/0/to\", \"value\": [{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}}] }]", hostSubnetCIDR, cidr)
		}
		patchReplaceResourceAsAdmin(oc, "networkpolicy/"+ipBlockPolicyName, patchPayload, allNS[0])
		npRules, npErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", ipBlockPolicyName, "-n", allNS[0], "-o=jsonpath={.spec}").Output()
		o.Expect(npErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Network policy after update: %s", npRules)

		CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], nsPodMap[allNS[1]][0])
		CurlPod2PodPassUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], newPodNS2.name)

		compat_otp.By("10. Validate egress traffic from first namespace to DNS works with allow-all-egress policy only from pod labeled test-pods")
		newPodNS1 := udnPodResource{
			name:      "hello-pod-" + testID + "-0-2",
			namespace: allNS[0],
			label:     "hello-pod",
			template:  udnPodTemplate,
		}
		defer removeResource(oc, true, true, "pod", newPodNS1.name, "-n", newPodNS1.namespace)
		newPodNS1.createUdnPod(oc)
		waitPodReady(oc, newPodNS1.namespace, newPodNS1.name)

		digOutput, digErr := e2eoutput.RunHostCmd(allNS[0], nsPodMap[allNS[0]][0], "dig kubernetes.default")
		o.Expect(digErr).To(o.HaveOccurred())
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).Should(o.ContainSubstring("connection timed out"))

		createResourceFromFile(oc, allNS[0], egressAllowFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-egress"))

		digOutput, digErr = e2eoutput.RunHostCmd(allNS[0], nsPodMap[allNS[0]][0], "dig kubernetes.default")
		o.Expect(digErr).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("connection timed out"))

		digOutput, digErr = e2eoutput.RunHostCmd(allNS[0], newPodNS1.name, "dig kubernetes.default")
		o.Expect(digErr).To(o.HaveOccurred())
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).Should(o.ContainSubstring("connection timed out"))

	})

})
