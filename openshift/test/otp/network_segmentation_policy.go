package otp

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"
	otputils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/utils"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"

	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[sig-network][Suite:openshift/ovn-kubernetes][Suite:openshift/conformance/serial] SDN network segmentation policy", func() {
	var (
		oc = exutil.NewCLI("networking-netseg-policy")
	)

	g.It("[JIRA:Networking][OTP] 78292-Validate ingress allow-same-namespace and allow-all-namespaces network policies in Layer 3 NAD", func() {
		var (
			testID                 = "78292"
			testDataDir            = testdata.FixturePath("networking")
			testDataDirUDN         = testdata.FixturePath("networking/network_segmentation/udn")
			udnNADTemplate         = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			udnPodTemplate         = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			ingressDenyFile        = filepath.Join(testDataDir, "networkpolicy/default-deny-ingress.yaml")
			ingressAllowSameNSFile = filepath.Join(testDataDir, "networkpolicy/allow-from-same-namespace.yaml")
			ingressAllowAllNSFile  = filepath.Join(testDataDir, "networkpolicy/allow-from-all-namespaces.yaml")
			nsPodMap               = make(map[string][]string)
			nadResourcename        = "l3-network-"
			topology               = "layer3"
		)
		ipStackType := otputils.CheckIPStackType(oc)
		var nadName string
		var nadNS []string = make([]string, 0, 4)
		nsDefaultNetwork := oc.Namespace()
		nadNetworkName := []string{"l3-network-test-1", "l3-network-test-2"}

		g.By("1.0 Create 4 UDN namespaces")
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
		g.By("2. Create Layer 3 NAD in first two namespaces")
		// Same network name in both namespaces
		nad := make([]otputils.UdnNetDefResource, 4)
		for i := 0; i < 2; i++ {
			nadName = nadResourcename + strconv.Itoa(i) + "-" + testID
			if i == 1 {
				o.Expect(oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nadNS[i], "team=ocp").Execute()).NotTo(o.HaveOccurred())
			}
			g.By(fmt.Sprintf("Create NAD %s in namespace %s", nadName, nadNS[i]))
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadName,
				Namespace:        nadNS[i],
				NadNetworkName:   nadNetworkName[0],
				Topology:         topology,
				Subnet:           subnet[0],
				NetAttachDefName: nadNS[i] + "/" + nadName,
				Role:             "primary",
				Template:         udnNADTemplate,
			}
			nad[i].CreateUdnNad(oc)
		}
		g.By("3. Create two pods in each namespace")
		pod := make([]otputils.UdnPodResource, 4)
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				pod[j] = otputils.UdnPodResource{
					Name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					Namespace: nadNS[i],
					Label:     "hello-pod",
					Template:  udnPodTemplate,
				}
				pod[j].CreateUdnPod(oc)
				otputils.WaitPodReady(oc, pod[j].Namespace, pod[j].Name)
				nsPodMap[pod[j].Namespace] = append(nsPodMap[pod[j].Namespace], pod[j].Name)
			}
		}
		otputils.CurlPod2PodPassUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		otputils.CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][1], nadNS[0], nsPodMap[nadNS[0]][0])

		g.By("4. Create default deny ingress type networkpolicy in first namespace")
		otputils.CreateResourceFromFile(oc, nadNS[0], ingressDenyFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-ingress"))

		g.By("5. Validate traffic between pods in first namespace and from pods in second namespace")
		otputils.CurlPod2PodFailUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		otputils.CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][1], nadNS[0], nsPodMap[nadNS[0]][0])

		g.By("6. Create allow same namespace ingress type networkpolicy in first namespace")
		otputils.CreateResourceFromFile(oc, nadNS[0], ingressAllowSameNSFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-from-same-namespace"))

		g.By("7. Validate traffic between pods in first namespace works but traffic from pod in second namespace is blocked")
		otputils.CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][1], nadNS[0], nsPodMap[nadNS[0]][0])
		otputils.CurlPod2PodFailUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])

		g.By("8. Create allow ingress from all namespaces networkpolicy in first namespace")
		otputils.CreateResourceFromFile(oc, nadNS[0], ingressAllowAllNSFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-from-all-namespaces"))

		g.By("9. Validate traffic from pods in second namespace")
		otputils.CurlPod2PodPassUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])

		g.By(fmt.Sprintf("10. Create NAD with same network %s in namespace %s as the first two namespaces and %s (different network) in %s", nadNetworkName[0], nadNS[2], nadNetworkName[1], nadNS[3]))
		for i := 2; i < 4; i++ {
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadResourcename + strconv.Itoa(i) + "-" + testID,
				Namespace:        nadNS[i],
				NadNetworkName:   nadNetworkName[i-2],
				Topology:         topology,
				Subnet:           subnet[i-2],
				NetAttachDefName: nadNS[i] + "/" + nadResourcename + strconv.Itoa(i) + "-" + testID,
				Role:             "primary",
				Template:         udnNADTemplate,
			}
			nad[i].CreateUdnNad(oc)
		}

		g.By("11. Create one pod each in last three namespaces, last one being without NAD")
		pod = make([]otputils.UdnPodResource, 6)
		for i := 2; i < 5; i++ {
			for j := 0; j < 1; j++ {
				pod[j] = otputils.UdnPodResource{
					Name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					Namespace: nadNS[i],
					Label:     "hello-pod",
					Template:  udnPodTemplate,
				}
				pod[j].CreateUdnPod(oc)
				otputils.WaitPodReady(oc, pod[j].Namespace, pod[j].Name)
				nsPodMap[pod[j].Namespace] = append(nsPodMap[pod[j].Namespace], pod[j].Name)
			}
		}
		g.By("12. Validate traffic from pods in third and fourth namespace works but not from pod in fifth namespace (default)")
		otputils.CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[2], nsPodMap[nadNS[2]][0])
		otputils.CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[3], nsPodMap[nadNS[3]][0])
		otputils.CurlPod2PodFail(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[4], nsPodMap[nadNS[4]][0])

		g.By("13. Update allow-all-namespaces policy with label to allow ingress traffic from pod in second namespace only")
		npPatch := `[{"op": "replace", "path": "/spec/ingress/0/from/0/namespaceSelector", "value": {"matchLabels": {"team": "ocp" }}}]`
		otputils.PatchReplaceResourceAsAdmin(oc, "networkpolicy/allow-from-all-namespaces", npPatch, nadNS[0])
		npRules, npErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "allow-from-all-namespaces", "-n", nadNS[0], "-o=jsonpath={.spec}").Output()
		o.Expect(npErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Network policy after update: %s", npRules)

		g.By("14. Validate traffic from pods in second namespace works but fails from pod in third namespace")
		otputils.CurlPod2PodPassUDN(oc, nadNS[1], nsPodMap[nadNS[1]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		otputils.CurlPod2PodFailUDN(oc, nadNS[2], nsPodMap[nadNS[2]][0], nadNS[0], nsPodMap[nadNS[0]][0])
	})

	g.It("[JIRA:Networking][OTP] 79092-Validate egress allow-same-namespace and allow-all-namespaces network policies in Layer 2 NAD", func() {
		var (
			testID                = "79092"
			testDataDir           = testdata.FixturePath("networking")
			netsegDir             = testdata.FixturePath("networking/network_segmentation")
			testDataDirUDN        = testdata.FixturePath("networking/network_segmentation/udn")
			udnNADTemplate        = filepath.Join(testDataDirUDN, "udn_nad_template.yaml")
			udnPodTemplate        = filepath.Join(testDataDirUDN, "udn_test_pod_template.yaml")
			egressDenyFile        = filepath.Join(testDataDir, "networkpolicy/default-deny-egress.yaml")
			egressAllowSameNSFile = filepath.Join(testDataDir, "networkpolicy/allow-to-same-namespace.yaml")
			egressAllowAllNSFile  = filepath.Join(netsegDir, "networkpolicy/allow-to-all-namespaces.yaml")
			nsPodMap              = make(map[string][]string)
			nadResourcename       = "l2-network-"
			topology              = "layer2"
		)
		ipStackType := otputils.CheckIPStackType(oc)
		var nadName string
		var nadNS []string = make([]string, 0, 4)
		nadNetworkName := []string{"l2-network-test-1", "l2-network-test-2"}
		nsDefaultNetwork := oc.Namespace()

		g.By("1.0 Create 4 UDN namespaces")
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
				subnet = []string{"2010:100:200::0/60", "2012:100:200::0/60"}
			} else {
				subnet = []string{"10.150.0.0/16,2010:100:200::0/60", "10.152.0.0/16,2012:100:200::0/60"}
			}
		}

		g.By("2. Create Layer 2 NAD in first two namespaces")
		nad := make([]otputils.UdnNetDefResource, 4)
		for i := 0; i < 2; i++ {
			nadName = nadResourcename + strconv.Itoa(i) + "-" + testID
			if i == 1 {
				o.Expect(oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nadNS[i], "team=ocp").Execute()).NotTo(o.HaveOccurred())
			}
			g.By(fmt.Sprintf("Create NAD %s in namespace %s", nadName, nadNS[i]))
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadName,
				Namespace:        nadNS[i],
				NadNetworkName:   nadNetworkName[0],
				Topology:         topology,
				Subnet:           subnet[0],
				NetAttachDefName: nadNS[i] + "/" + nadName,
				Role:             "primary",
				Template:         udnNADTemplate,
			}
			nad[i].CreateUdnNad(oc)
		}

		g.By("3. Create two pods in each namespace")
		pod := make([]otputils.UdnPodResource, 4)
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				pod[j] = otputils.UdnPodResource{
					Name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					Namespace: nadNS[i],
					Label:     "hello-pod",
					Template:  udnPodTemplate,
				}
				pod[j].CreateUdnPod(oc)
				otputils.WaitPodReady(oc, pod[j].Namespace, pod[j].Name)
				nsPodMap[pod[j].Namespace] = append(nsPodMap[pod[j].Namespace], pod[j].Name)
			}
		}
		otputils.CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])
		otputils.CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[0], nsPodMap[nadNS[0]][1])

		g.By("4. Create default deny egress type networkpolicy in first namespace")
		otputils.CreateResourceFromFile(oc, nadNS[0], egressDenyFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-egress"))

		g.By("5. Validate traffic between pods in first namespace and from pods in second namespace")
		otputils.CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])
		otputils.CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[0], nsPodMap[nadNS[0]][1])

		g.By("6. Create allow egress to same namespace networkpolicy in first namespace")
		otputils.CreateResourceFromFile(oc, nadNS[0], egressAllowSameNSFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-same-namespace"))

		g.By("7. Validate traffic between pods in first namespace works but traffic from pod in second namespace is blocked")
		otputils.CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[0], nsPodMap[nadNS[0]][1])
		otputils.CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])

		g.By("8. Create allow all namespaces egress type networkpolicy in first namespace")
		otputils.CreateResourceFromFile(oc, nadNS[0], egressAllowAllNSFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", nadNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-all-namespaces"))

		g.By("9. Validate traffic to pods in second namespace")
		otputils.CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])

		g.By(fmt.Sprintf("10. Create NAD with same network %s in namespace %s as the first two namespaces and %s (different network) in %s", nadNetworkName[0], nadNS[2], nadNetworkName[1], nadNS[3]))
		for i := 2; i < 4; i++ {
			nad[i] = otputils.UdnNetDefResource{
				Nadname:          nadResourcename + strconv.Itoa(i) + "-" + testID,
				Namespace:        nadNS[i],
				NadNetworkName:   nadNetworkName[i-2],
				Topology:         topology,
				Subnet:           subnet[i-2],
				NetAttachDefName: nadNS[i] + "/" + nadResourcename + strconv.Itoa(i) + "-" + testID,
				Role:             "primary",
				Template:         udnNADTemplate,
			}
			nad[i].CreateUdnNad(oc)
		}

		g.By("11. Create one pod each in last three namespaces, last one being without NAD")
		pod = make([]otputils.UdnPodResource, 6)
		for i := 2; i < 5; i++ {
			for j := 0; j < 1; j++ {
				pod[j] = otputils.UdnPodResource{
					Name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					Namespace: nadNS[i],
					Label:     "hello-pod",
					Template:  udnPodTemplate,
				}
				pod[j].CreateUdnPod(oc)
				otputils.WaitPodReady(oc, pod[j].Namespace, pod[j].Name)
				nsPodMap[pod[j].Namespace] = append(nsPodMap[pod[j].Namespace], pod[j].Name)
			}
		}

		g.By("12. Validate traffic to pods in third and fourth namespace works but not to pod in fifth namespace (default)")
		otputils.CurlPod2PodPassUDN(oc, nadNS[2], nsPodMap[nadNS[2]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		otputils.CurlPod2PodFailUDN(oc, nadNS[3], nsPodMap[nadNS[3]][0], nadNS[0], nsPodMap[nadNS[0]][0])
		otputils.CurlPod2PodFail(oc, nadNS[4], nsPodMap[nadNS[4]][0], nadNS[0], nsPodMap[nadNS[0]][0])

		g.By("13. Update allow-all-namespaces policy with label to allow egress traffic to pod in second namespace only")
		npPatch := `[{"op": "replace", "path": "/spec/egress/0/to/0/namespaceSelector", "value": {"matchLabels": {"team": "ocp" }}}]`
		otputils.PatchReplaceResourceAsAdmin(oc, "networkpolicy/allow-to-all-namespaces", npPatch, nadNS[0])
		npRules, npErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "allow-to-all-namespaces", "-n", nadNS[0], "-o=jsonpath={.spec}").Output()
		o.Expect(npErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Network policy after update: %s", npRules)

		g.By("14. Validate traffic to pods in second namespace works but fails to pod in third namespace")
		otputils.CurlPod2PodPassUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[1], nsPodMap[nadNS[1]][0])
		otputils.CurlPod2PodFailUDN(oc, nadNS[0], nsPodMap[nadNS[0]][0], nadNS[2], nsPodMap[nadNS[2]][0])
	})

	g.It("[JIRA:Networking][OTP] 79093-Validate ingress CIDR block with and without except clause network policies in Layer 3 CUDN", func() {
		var (
			testID                       = "79093"
			testDataDir                  = testdata.FixturePath("networking")
			testDataDirUDN               = testdata.FixturePath("networking/network_segmentation/udn")
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
		ipStackType := otputils.CheckIPStackType(oc)
		var allNS []string = make([]string, 0, 3)
		var ipBlockPolicyName string
		var podCount int
		nsDefaultNetwork := oc.Namespace()

		g.By("1.0 Create 3 UDN namespaces")
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
		otputils.EnableACLOnNamespace(oc, allNS[0], "alert", "alert")

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

		g.By("2. Create default deny ingress type networkpolicy in first namespace before UDN is created")
		otputils.CreateResourceFromFile(oc, allNS[0], ingressDenyFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-ingress"))

		g.By("3. Create Layer 3 UDN in first two namespaces with CUDN resource and UDN in third")
		defer otputils.RemoveResource(oc, true, true, "clusteruserdefinednetwork", cudnCRDName)
		_, cudnErr := otputils.ApplyCUDNtoMatchLabelNS(oc, matchLabelKey, matchLabelVal, cudnCRDName, ipv4cidr0, ipv6cidr0, cidr0, topology)
		o.Expect(cudnErr).NotTo(o.HaveOccurred())
		defer otputils.RemoveResource(oc, true, true, "userdefinednetwork", udnCRDName)
		otputils.CreateGeneralUDNCRD(oc, allNS[2], udnCRDName, ipv4cidr1, ipv6cidr1, cidr1, topology)

		g.By("4. Create two pods in each namespace")
		podCount = 2
		pod := make([]otputils.UdnPodResource, 4)
		for i := 0; i < len(allNS); i++ {
			if i == 2 {
				podCount = 1
			}
			for j := 0; j < podCount; j++ {
				pod[j] = otputils.UdnPodResource{
					Name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					Namespace: allNS[i],
					Label:     "hello-pod",
					Template:  udnPodTemplate,
				}
				pod[j].CreateUdnPod(oc)
				defer otputils.RemoveResource(oc, true, true, "pod", pod[j].Name, "-n", pod[j].Namespace)
				otputils.WaitPodReady(oc, pod[j].Namespace, pod[j].Name)
				nsPodMap[pod[j].Namespace] = append(nsPodMap[pod[j].Namespace], pod[j].Name)
			}
		}

		g.By("5. Validate traffic between pods in first namespace and from pods in second namespace")
		otputils.CurlPod2PodFailUDN(oc, allNS[1], nsPodMap[allNS[1]][0], allNS[0], nsPodMap[allNS[0]][0])
		otputils.CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][1], allNS[0], nsPodMap[allNS[0]][0])

		g.By("6. Get node name and IPs of first pod in first namespace")
		podNodeName, podNodeNameErr := otputils.GetPodNodeName(oc, allNS[0], nsPodMap[allNS[0]][0])
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())

		g.By("7. Validate verdict=drop message")
		output, logErr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", podNodeName, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(logErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "verdict=drop")).To(o.BeTrue())

		g.By("8. Create IP Block ingress policy to allow traffic from first pod in second namespace to first pod in first")
		var cidrIpv4, cidrIpv6, cidr string
		if ipStackType == "dualstack" {
			g.By(fmt.Sprintf("Create ipBlock Ingress Dual CIDRs Policy in %s", allNS[0]))
			pod1ns1IPv6, pod1ns1IPv4 := otputils.GetPodIPUDN(oc, allNS[1], nsPodMap[allNS[1]][0], "ovn-udn1")
			cidrIpv4 = pod1ns1IPv4 + "/32"
			cidrIpv6 = pod1ns1IPv6 + "/128"
			npIPBlockNS1 := otputils.IpBlockCIDRsDual{
				Name:     "ipblock-dual-cidrs-ingress",
				Template: ipBlockIngressTemplateDual,
				CidrIpv4: cidrIpv4,
				CidrIpv6: cidrIpv6,
				Namespace: allNS[0],
			}
			npIPBlockNS1.CreateipBlockCIDRObjectDual(oc)
			ipBlockPolicyName = npIPBlockNS1.Name
		} else {
			pod1ns1, _ := otputils.GetPodIPUDN(oc, allNS[1], nsPodMap[allNS[1]][0], "ovn-udn1")
			if ipStackType == "ipv6single" {
				cidr = pod1ns1 + "/128"
			} else {
				cidr = pod1ns1 + "/32"
			}
			npIPBlockNS1 := otputils.IpBlockCIDRsSingle{
				Name:      "ipblock-single-cidr-ingress",
				Template:  ipBlockIngressTemplateSingle,
				Cidr:      cidr,
				Namespace: allNS[0],
			}
			npIPBlockNS1.CreateipBlockCIDRObjectSingle(oc)
			ipBlockPolicyName = npIPBlockNS1.Name
		}

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(ipBlockPolicyName))

		g.By("9. Validate traffic to first pod in first namespace is allowed from first pod in second namespace and verdict=allow in ACL audit log")
		otputils.CurlPod2PodPassUDN(oc, allNS[1], nsPodMap[allNS[1]][0], allNS[0], nsPodMap[allNS[0]][0])
		output, logErr = oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", podNodeName, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(logErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "verdict=allow")).To(o.BeTrue())

		g.By("10. Validate ingress traffic is not allowed from second pod in second namespace, pod in third namespace and pod in fourth (default network)")
		otputils.CurlPod2PodFailUDN(oc, allNS[1], nsPodMap[allNS[1]][1], allNS[0], nsPodMap[allNS[0]][0])
		otputils.CurlPod2PodFailUDN(oc, allNS[2], nsPodMap[allNS[2]][0], allNS[0], nsPodMap[allNS[0]][0])
		otputils.CurlPod2PodFailUDN(oc, allNS[3], nsPodMap[allNS[3]][0], allNS[0], nsPodMap[allNS[0]][0])

		g.By("11. Get node name of first pod in second namespace and schedule another pod on same node")
		podNodeName, podNodeNameErr = otputils.GetPodNodeName(oc, allNS[1], nsPodMap[allNS[1]][0])
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())
		newPod := otputils.UdnPodResourceNode{
			Name:      "hello-pod-" + testID + "-1-2",
			Namespace: allNS[1],
			Label:     "hello-pod",
			Nodename:  podNodeName,
			Template:  udnPodNodeTemplate,
		}
		newPod.CreateUdnPodNode(oc)
		defer otputils.RemoveResource(oc, true, true, "pod", newPod.Name, "-n", newPod.Namespace)
		otputils.WaitPodReady(oc, newPod.Namespace, newPod.Name)

		g.By(fmt.Sprintf("12. Update the %s policy to include except clause to block the ingress from the first pod in second", ipBlockPolicyName))
		var patchPayload string
		if ipStackType == "dualstack" {
			hostSubnetIPv4, hostSubnetIPv6 := otputils.GetNodeSubnetDualStack(oc, podNodeName, "cluster_udn_"+cudnCRDName)
			patchPayload = fmt.Sprintf("[{\"op\": \"replace\", \"path\":\"/spec/ingress/0/from\", \"value\": [{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}},{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}}] }]", hostSubnetIPv4, cidrIpv4, hostSubnetIPv6, cidrIpv6)
		} else {
			hostSubnetCIDR := otputils.GetNodeSubnet(oc, podNodeName, "cluster_udn_"+cudnCRDName)
			patchPayload = fmt.Sprintf("[{\"op\": \"replace\", \"path\":\"/spec/ingress/0/from\", \"value\": [{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}}] }]", hostSubnetCIDR, cidr)
		}
		otputils.PatchReplaceResourceAsAdmin(oc, "networkpolicy/"+ipBlockPolicyName, patchPayload, allNS[0])
		npRules, npErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", ipBlockPolicyName, "-n", allNS[0], "-o=jsonpath={.spec}").Output()
		o.Expect(npErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Network policy after update: %s", npRules)

		otputils.CurlPod2PodFailUDN(oc, allNS[1], nsPodMap[allNS[1]][0], allNS[0], nsPodMap[allNS[0]][0])
		otputils.CurlPod2PodPassUDN(oc, allNS[1], newPod.Name, allNS[0], nsPodMap[allNS[0]][0])
	})

	g.It("[JIRA:Networking][OTP] 79094-Validate egress CIDR block with and without except clause network policies in Layer 3 CUDN", func() {
		var (
			testID                      = "79094"
			testDataDir                 = testdata.FixturePath("networking")
			testDataDirUDN              = testdata.FixturePath("networking/network_segmentation/udn")
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
		ipStackType := otputils.CheckIPStackType(oc)
		var allNS []string = make([]string, 0, 3)
		var ipBlockPolicyName string
		var podCount int

		g.By("1. Create 3 UDN namespaces")
		for i := 0; i < 3; i++ {
			oc.CreateNamespaceUDN()
			ns := oc.Namespace()
			allNS = append(allNS, ns)
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
		} else if ipStackType == "ipv6single" {
			cidr0 = "2010:100:200::0/48"
			cidr1 = "2012:100:200::0/48"
		} else {
			ipv4cidr0 = "10.150.0.0/16"
			ipv4cidr1 = "10.152.0.0/16"
			ipv6cidr0 = "2010:100:200::0/48"
			ipv6cidr1 = "2012:100:200::0/48"
		}

		g.By("2. Create default deny egress type networkpolicy in first namespace before UDN is created")
		otputils.CreateResourceFromFile(oc, allNS[0], egressDenyFile)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("default-deny-egress"))

		g.By("3. Create Layer 3 UDN in first two namespaces with CUDN resource and UDN in third")
		defer otputils.RemoveResource(oc, true, true, "clusteruserdefinednetwork", cudnCRDName)
		_, cudnErr := otputils.ApplyCUDNtoMatchLabelNS(oc, matchLabelKey, matchLabelVal, cudnCRDName, ipv4cidr0, ipv6cidr0, cidr0, topology)
		o.Expect(cudnErr).NotTo(o.HaveOccurred())
		defer otputils.RemoveResource(oc, true, true, "userdefinednetwork", udnCRDName)
		otputils.CreateGeneralUDNCRD(oc, allNS[2], udnCRDName, ipv4cidr1, ipv6cidr1, cidr1, topology)

		g.By("4. Create two pods in each namespace")
		podCount = 2
		pod := make([]otputils.UdnPodResource, 4)
		for i := 0; i < len(allNS); i++ {
			if i == 2 {
				podCount = 1
			}
			for j := 0; j < podCount; j++ {
				pod[j] = otputils.UdnPodResource{
					Name:      "hello-pod-" + testID + "-" + strconv.Itoa(i) + "-" + strconv.Itoa(j),
					Namespace: allNS[i],
					Label:     "test-pods",
					Template:  udnPodTemplate,
				}
				pod[j].CreateUdnPod(oc)
				defer otputils.RemoveResource(oc, true, true, "pod", pod[j].Name, "-n", pod[j].Namespace)
				otputils.WaitPodReady(oc, pod[j].Namespace, pod[j].Name)
				nsPodMap[pod[j].Namespace] = append(nsPodMap[pod[j].Namespace], pod[j].Name)
			}
		}

		g.By("5. Validate traffic between pods in first namespace and from pods in second namespace")
		otputils.CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], nsPodMap[allNS[1]][0])
		otputils.CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[0], nsPodMap[allNS[0]][1])

		g.By("6. Create IP Block egress policy to allow traffic from first pod in first namespace to first pod in second namespace")
		var cidrIpv4, cidrIpv6, cidr string
		if ipStackType == "dualstack" {
			g.By(fmt.Sprintf("Create ipBlock Egress Dual CIDRs Policy in %s", allNS[0]))
			pod1ns1IPv6, pod1ns1IPv4 := otputils.GetPodIPUDN(oc, allNS[1], nsPodMap[allNS[1]][0], "ovn-udn1")
			cidrIpv4 = pod1ns1IPv4 + "/32"
			cidrIpv6 = pod1ns1IPv6 + "/128"
			npIPBlockNS1 := otputils.IpBlockCIDRsDual{
				Name:      "ipblock-dual-cidrs-egress",
				Template:  ipBlockEgressTemplateDual,
				CidrIpv4:  cidrIpv4,
				CidrIpv6:  cidrIpv6,
				Namespace: allNS[0],
			}
			npIPBlockNS1.CreateipBlockCIDRObjectDual(oc)
			ipBlockPolicyName = npIPBlockNS1.Name
		} else {
			pod1ns1, _ := otputils.GetPodIPUDN(oc, allNS[1], nsPodMap[allNS[1]][0], "ovn-udn1")
			if ipStackType == "ipv6single" {
				cidr = pod1ns1 + "/128"
			} else {
				cidr = pod1ns1 + "/32"
			}
			npIPBlockNS1 := otputils.IpBlockCIDRsSingle{
				Name:      "ipblock-single-cidr-egress",
				Template:  ipBlockEgressTemplateSingle,
				Cidr:      cidr,
				Namespace: allNS[0],
			}
			npIPBlockNS1.CreateipBlockCIDRObjectSingle(oc)
			ipBlockPolicyName = npIPBlockNS1.Name
		}

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(ipBlockPolicyName))

		g.By("7. Validate egress traffic is allowed to first pod in second namespace and not to others")
		otputils.CurlPod2PodPassUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], nsPodMap[allNS[1]][0])
		otputils.CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], nsPodMap[allNS[1]][1])
		otputils.CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[2], nsPodMap[allNS[2]][0])

		g.By("8. Get node name of first pod in second namespace and schedule another pod on same node")
		podNodeName, podNodeNameErr := otputils.GetPodNodeName(oc, allNS[1], nsPodMap[allNS[1]][0])
		o.Expect(podNodeNameErr).NotTo(o.HaveOccurred())
		o.Expect(podNodeName).NotTo(o.BeEmpty())
		newPodNS2 := otputils.UdnPodResourceNode{
			Name:      "hello-pod-" + testID + "-1-2",
			Namespace: allNS[1],
			Label:     "test-pods",
			Nodename:  podNodeName,
			Template:  udnPodNodeTemplate,
		}
		newPodNS2.CreateUdnPodNode(oc)
		defer otputils.RemoveResource(oc, true, true, "pod", newPodNS2.Name, "-n", newPodNS2.Namespace)
		otputils.WaitPodReady(oc, newPodNS2.Namespace, newPodNS2.Name)

		g.By(fmt.Sprintf("9. Update the %s policy to include except clause to block the egress to the first pod in second namespace", ipBlockPolicyName))
		var patchPayload string
		if ipStackType == "dualstack" {
			hostSubnetIPv4, hostSubnetIPv6 := otputils.GetNodeSubnetDualStack(oc, podNodeName, "cluster_udn_"+cudnCRDName)
			patchPayload = fmt.Sprintf("[{\"op\": \"replace\", \"path\":\"/spec/egress/0/to\", \"value\": [{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}},{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}}] }]", hostSubnetIPv4, cidrIpv4, hostSubnetIPv6, cidrIpv6)
		} else {
			hostSubnetCIDR := otputils.GetNodeSubnet(oc, podNodeName, "cluster_udn_"+cudnCRDName)
			patchPayload = fmt.Sprintf("[{\"op\": \"replace\", \"path\":\"/spec/egress/0/to\", \"value\": [{\"ipBlock\":{\"cidr\":%s,\"except\":[%s]}}] }]", hostSubnetCIDR, cidr)
		}
		otputils.PatchReplaceResourceAsAdmin(oc, "networkpolicy/"+ipBlockPolicyName, patchPayload, allNS[0])
		npRules, npErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", ipBlockPolicyName, "-n", allNS[0], "-o=jsonpath={.spec}").Output()
		o.Expect(npErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Network policy after update: %s", npRules)

		otputils.CurlPod2PodFailUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], nsPodMap[allNS[1]][0])
		otputils.CurlPod2PodPassUDN(oc, allNS[0], nsPodMap[allNS[0]][0], allNS[1], newPodNS2.Name)

		g.By("10. Validate egress traffic from first namespace to DNS works with allow-all-egress policy only from pod labeled test-pods")
		newPodNS1 := otputils.UdnPodResource{
			Name:      "hello-pod-" + testID + "-0-2",
			Namespace: allNS[0],
			Label:     "hello-pod",
			Template:  udnPodTemplate,
		}
		defer otputils.RemoveResource(oc, true, true, "pod", newPodNS1.Name, "-n", newPodNS1.Namespace)
		newPodNS1.CreateUdnPod(oc)
		otputils.WaitPodReady(oc, newPodNS1.Namespace, newPodNS1.Name)

		digOutput, digErr := e2eoutput.RunHostCmd(allNS[0], nsPodMap[allNS[0]][0], "dig kubernetes.default")
		o.Expect(digErr).To(o.HaveOccurred())
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).Should(o.ContainSubstring("connection timed out"))

		otputils.CreateResourceFromFile(oc, allNS[0], egressAllowFile)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("networkpolicy", "-n", allNS[0]).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-egress"))

		digOutput, digErr = e2eoutput.RunHostCmd(allNS[0], nsPodMap[allNS[0]][0], "dig kubernetes.default")
		o.Expect(digErr).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("connection timed out"))

		digOutput, digErr = e2eoutput.RunHostCmd(allNS[0], newPodNS1.Name, "dig kubernetes.default")
		o.Expect(digErr).To(o.HaveOccurred())
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("Got answer"))
		o.Expect(digOutput).Should(o.ContainSubstring("connection timed out"))
	})
})
