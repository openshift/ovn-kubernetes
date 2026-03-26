package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	"github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

// Test for staging pipeline
var _ = g.Describe("[OTP][sig-networking] SDN metallb", func() {
	defer g.GinkgoRecover()

	var (
		oc                       = compat_otp.NewCLI("networking-metallb", compat_otp.KubeConfigPath())
		opNamespace              = "metallb-system"
		opName                   = "metallb-operator"
		catalogNamespace         = "openshift-marketplace"
		catalogSourceName        = "metallb-operator-fbc-catalog"
		imageDigestMirrorSetName = "metallb-images-mirror-set"
		testDataDir              = testdata.FixturePath("networking/metallb")
	)

	g.BeforeEach(func() {

		networkType := compat_otp.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("This case requires OVNKubernetes as network plugin, skip the test as the cluster does not have OVN network plugin")
		}

		namespaceTemplate := filepath.Join(testDataDir, "namespace-template.yaml")
		operatorGroupTemplate := filepath.Join(testDataDir, "operatorgroup-template.yaml")
		subscriptionTemplate := filepath.Join(testDataDir, "subscription-template.yaml")
		catalogSourceTemplate := filepath.Join(testDataDir, "catalogsource-template.yaml")
		imageDigestMirrorSetFile := filepath.Join(testDataDir, "image-digest-mirrorset.yaml")
		sub := subscriptionResource{
			name:             "metallb-operator-sub",
			namespace:        opNamespace,
			operatorName:     opName,
			channel:          "stable",
			catalog:          catalogSourceName,
			catalogNamespace: catalogNamespace,
			template:         subscriptionTemplate,
		}
		ns := namespaceResource{
			name:     opNamespace,
			template: namespaceTemplate,
		}
		og := operatorGroupResource{
			name:             opName,
			namespace:        opNamespace,
			targetNamespaces: opNamespace,
			template:         operatorGroupTemplate,
		}
		catalogSourceName = setupOperatorCatalogSource(oc, "metallb", catalogSourceName, imageDigestMirrorSetName, catalogNamespace, imageDigestMirrorSetFile, catalogSourceTemplate)
		sub.catalog = catalogSourceName
		operatorInstall(oc, sub, ns, og)
		compat_otp.By("Making sure CRDs are successfully installed")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "bfdprofiles.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgpadvertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgppeers.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "communities.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "ipaddresspools.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "l2advertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "metallbs.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrconfigurations.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrnodestates.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "servicel2statuses.metallb.io")).To(o.BeTrue())

	})

	g.It("[Level0] Author:asood-NonHyperShiftHOST-StagerunBoth-High-43074-MetalLB-Operator installation [Serial]", func() {
		compat_otp.By("Checking metalLB operator installation")
		e2e.Logf("Operator install check successfull as part of setup !!!!!")
		compat_otp.By("SUCCESS - MetalLB operator installed")

	})

	g.It("Author:asood-NonHyperShiftHOST-Medium-50950-Verify community creation and webhook validation. [Serial]", func() {
		communityTemplate := filepath.Join(testDataDir, "community-template.yaml")
		communityCR := communityResource{
			name:          "community-50950",
			namespace:     opNamespace,
			communityName: "NO_ADVERTISE",
			value1:        "65535",
			value2:        "65282",
			template:      communityTemplate,
		}
		defer removeResource(oc, true, true, "community", communityCR.name, "-n", communityCR.namespace)
		result := createCommunityCR(oc, communityCR)
		o.Expect(result).To(o.BeTrue())

		patchCommunity := `[{"op": "add", "path": "/spec/communities/1", "value": {"name": "NO_ADVERTISE", "value":"65535:65282"}}]`
		patchOutput, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("community", communityCR.name, "-n", communityCR.namespace, "--type=json", "-p", patchCommunity).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "duplicate definition of community")).To(o.BeTrue())

	})

	g.It("Author:asood-NonHyperShiftHOST-Medium-50947-Medium-50948-Verify BGP and L2 Advertisement webhook validation. [Serial]", func() {
		workers := []string{"worker-1", "worker-2", "worker-3"}
		bgpCommunties := []string{"65001:65500"}
		ipaddrpools := []string{"ipaddresspool-0", "ipaddresspool-1"}
		bgpPeers := []string{"peer-64500", "peer-65000"}
		interfaces := []string{"br-ex", "eno1", "eno2"}
		crMap := make(map[string]string)

		bgpAdvertisementTemplate := filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
		l2AdvertisementTemplate := filepath.Join(testDataDir, "l2advertisement-template.yaml")

		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv-50948",
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        ipaddrpools[:],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}

		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv-50947",
			namespace:          opNamespace,
			ipAddressPools:     ipaddrpools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: workers[:],
			template:           l2AdvertisementTemplate,
		}

		compat_otp.By("Create BGP and L2 Advertisement")
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())
		crMap["bgpadvertisements"] = bgpAdvertisement.name

		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		o.Expect(createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)).To(o.BeTrue())
		crMap["l2advertisements"] = l2advertisement.name

		for crType, crName := range crMap {
			compat_otp.By(fmt.Sprintf("Validate duplicate ip address pool is rejected for %s", crType))
			ipaddrpools = append(ipaddrpools, "ipaddresspool-1")
			addrPoolList, err := json.Marshal(ipaddrpools)
			o.Expect(err).NotTo(o.HaveOccurred())
			patchAdvertisement := fmt.Sprintf("{\"spec\":{\"ipAddressPools\": %s}}", string(addrPoolList))
			patchOutput, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args(crType, crName, "-n", opNamespace, "--type=merge", "-p", patchAdvertisement).Output()
			o.Expect(patchErr).To(o.HaveOccurred())
			o.Expect(strings.Contains(patchOutput, "duplicate definition of ipAddressPools")).To(o.BeTrue())

			compat_otp.By(fmt.Sprintf("Validate duplicate node is rejected for %s", crType))
			workers = append(workers, "worker-1")
			workerList, err := json.Marshal(workers)
			o.Expect(err).NotTo(o.HaveOccurred())
			patchAdvertisement = fmt.Sprintf("{\"spec\":{\"nodeSelectors\":[{\"matchExpressions\":[{\"key\":\"kubernetes.io/hostname\",\"operator\":\"In\",\"values\":%s}]}]}}", string(workerList))
			patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args(crType, crName, "-n", opNamespace, "--type=merge", "-p", patchAdvertisement).Output()
			o.Expect(patchErr).To(o.HaveOccurred())
			o.Expect(strings.Contains(patchOutput, "duplicate definition of match expression value in label selector")).To(o.BeTrue())
		}
		compat_otp.By("Validate community strings is updated with community object for BGP Advertisements")
		bgpCommunties = []string{"65001:65500", "community1"}
		bgpCommStrList, err := json.Marshal(bgpCommunties)
		o.Expect(err).NotTo(o.HaveOccurred())
		patchBgpAdvertisement := fmt.Sprintf("{\"spec\":{\"communities\": %s}}", string(bgpCommStrList))
		_, patchErr1 := oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgpadvertisement", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace, "--type=merge", "-p", patchBgpAdvertisement).Output()
		o.Expect(patchErr1).NotTo(o.HaveOccurred())

		compat_otp.By("Validate duplicate community strings is rejected for BGP Advertisements")
		bgpCommunties = append(bgpCommunties, "65001:65500")
		bgpCommStrList, err = json.Marshal(bgpCommunties)
		o.Expect(err).NotTo(o.HaveOccurred())
		patchBgpAdvertisement = fmt.Sprintf("{\"spec\":{\"communities\": %s}}", string(bgpCommStrList))
		patchOutput, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgpadvertisement", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace, "--type=merge", "-p", patchBgpAdvertisement).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "duplicate definition of community")).To(o.BeTrue())

		compat_otp.By("Validate duplicate BGP Peer is rejected for BGP Advertisements")
		bgpPeers = append(bgpPeers, "peer-64500")
		bgpPeersList, err := json.Marshal(bgpPeers)
		o.Expect(err).NotTo(o.HaveOccurred())
		patchBgpAdvertisement = fmt.Sprintf("{\"spec\":{\"peers\": %s}}", string(bgpPeersList))
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgpadvertisement", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace, "--type=merge", "-p", patchBgpAdvertisement).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "duplicate definition of peers")).To(o.BeTrue())

		compat_otp.By("Validate invalid IPv4 aggregation length is rejected for BGP Advertisements")
		patchBgpAdvertisement = fmt.Sprintf("{\"spec\":{\"aggregationLength\": %d}}", 33)
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgpadvertisement", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace, "--type=merge", "-p", patchBgpAdvertisement).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "invalid aggregation length")).To(o.BeTrue())

		compat_otp.By("Validate invalid IPv6 aggregation length is rejected for BGP Advertisements")
		patchBgpAdvertisement = fmt.Sprintf("{\"spec\":{\"aggregationLengthV6\": %d}}", 129)
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgpadvertisement", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace, "--type=merge", "-p", patchBgpAdvertisement).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "invalid aggregation length")).To(o.BeTrue())

	})

	g.It("Author:qiowang-NonHyperShiftHOST-High-46124-Verify webhook validation for BGP peer [Serial]", func() {
		compat_otp.By("1. Create two BGPPeer")
		BGPPeerTemplate := filepath.Join(testDataDir, "bgppeer-template.yaml")
		for i := 1; i < 3; i++ {
			BGPPeerCR := bgpPeerResource{
				name:          "peer-46124-" + strconv.Itoa(i),
				namespace:     opNamespace,
				holdTime:      "30s",
				keepAliveTime: "10s",
				password:      "",
				myASN:         65501,
				peerASN:       65500 + i,
				peerAddress:   "10.10.10." + strconv.Itoa(i),
				peerPort:      6000,
				template:      BGPPeerTemplate,
			}
			defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
			o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())
		}

		compat_otp.By("2. Validate two BGPPeer with same peerASN and peerAddress is invalid")
		patchBGPPeer := `{"spec":{"peerASN":65501,"peerAddress": "10.10.10.1"}}`
		patchOutput, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "duplicate BGPPeers")).To(o.BeTrue())

		compat_otp.By("3. Validate two BGPPeer with different peerASN but same peerAddress is invalid")
		patchBGPPeer = `{"spec":{"peerAddress": "10.10.10.1"}}`
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "already exists")).To(o.BeTrue())

		compat_otp.By("4. Validate two BGPPeer with different myASN is invalid")
		patchBGPPeer = `{"spec":{"myASN": 65502}}`
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "all myAsn must be equal for the same VRF")).To(o.BeTrue())

		compat_otp.By("5. Validate BGPPeer with one of the ASN number more than 4294967296 is invalid")
		patchBGPPeer = `{"spec":{"myASN": 4294967297}}`
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "spec.myASN in body should be less than or equal to 4294967295")).To(o.BeTrue())

		compat_otp.By("6. Validate BGPPeer with invalid source address is invalid")
		patchBGPPeer = `{"spec":{"peerAddress": "10.10.10"}}`
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "invalid BGPPeer address")).To(o.BeTrue())

		compat_otp.By("7. Validate BGPPeer with port number greater than 16384 or less than 0 is invalid")
		patchBGPPeer = `{"spec":{"peerPort": 16385}}`
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "spec.peerPort in body should be less than or equal to 16384")).To(o.BeTrue())
		patchBGPPeer = `{"spec":{"peerPort": -1}}`
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "spec.peerPort in body should be greater than or equal to 1")).To(o.BeTrue())

		compat_otp.By("8. Validate hold timer and keepalive timer without unit is invalid")
		patchBGPPeer = `{"spec":{"holdTime": "30", "keepaliveTime": "10"}}`
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "missing unit")).To(o.BeTrue())

		compat_otp.By("9. Validate BGPPeer with keepalive timer greater than holdtime is invalid")
		patchBGPPeer = `{"spec":{"keepaliveTime": "40s"}}`
		patchOutput, patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", "peer-46124-2", "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Output()
		o.Expect(patchErr).To(o.HaveOccurred())
		o.Expect(strings.Contains(patchOutput, "must be lower than holdTime")).To(o.BeTrue())
	})

})

// Tests related to metallb install and CR creation that can be executed more frequently
var _ = g.Describe("[OTP][sig-networking] SDN metallb install", func() {
	defer g.GinkgoRecover()

	var (
		oc                       = compat_otp.NewCLI("networking-metallb", compat_otp.KubeConfigPath())
		opNamespace              = "metallb-system"
		opName                   = "metallb-operator"
		testDataDir              = testdata.FixturePath("networking/metallb")
		metalLBNodeSelKey        = "node-role.kubernetes.io/worker"
		metalLBNodeSelVal        = ""
		metalLBControllerSelKey  = "node-role.kubernetes.io/worker"
		metalLBControllerSelVal  = ""
		catalogNamespace         = "openshift-marketplace"
		catalogSourceName        = "metallb-operator-fbc-catalog"
		imageDigestMirrorSetName = "metallb-images-mirror-set"
	)

	g.BeforeEach(func() {
		// Install metallb on vSphere and baremetal but skip on all platforms
		compat_otp.By("Check the platform if it is suitable for running the test")
		platform := compat_otp.CheckPlatform(oc)
		networkType := compat_otp.CheckNetworkType(oc)
		if !(strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "none")) || !strings.Contains(networkType, "ovn") {
			g.Skip("These cases can only be run on networking team's private RDU BM cluster, vSphere and IPI/UPI BM, skip for other platforms or other non-OVN network plugin!!!")
		}

		namespaceTemplate := filepath.Join(testDataDir, "namespace-template.yaml")
		operatorGroupTemplate := filepath.Join(testDataDir, "operatorgroup-template.yaml")
		subscriptionTemplate := filepath.Join(testDataDir, "subscription-template.yaml")
		catalogSourceTemplate := filepath.Join(testDataDir, "catalogsource-template.yaml")
		imageDigestMirrorSetFile := filepath.Join(testDataDir, "image-digest-mirrorset.yaml")
		sub := subscriptionResource{
			name:             "metallb-operator-sub",
			namespace:        opNamespace,
			operatorName:     opName,
			channel:          "stable",
			catalog:          catalogSourceName,
			catalogNamespace: catalogNamespace,
			template:         subscriptionTemplate,
		}
		ns := namespaceResource{
			name:     opNamespace,
			template: namespaceTemplate,
		}
		og := operatorGroupResource{
			name:             opName,
			namespace:        opNamespace,
			targetNamespaces: opNamespace,
			template:         operatorGroupTemplate,
		}
		catalogSourceName = setupOperatorCatalogSource(oc, "metallb", catalogSourceName, imageDigestMirrorSetName, catalogNamespace, imageDigestMirrorSetFile, catalogSourceTemplate)
		sub.catalog = catalogSourceName
		operatorInstall(oc, sub, ns, og)
		compat_otp.By("Making sure CRDs are successfully installed")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "bfdprofiles.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgpadvertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgppeers.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "communities.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "ipaddresspools.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "l2advertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "metallbs.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrconfigurations.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrnodestates.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "servicel2statuses.metallb.io")).To(o.BeTrue())

		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("metallb", "-n", opNamespace).Output()
		if err == nil && strings.Contains(output, "metallb") {
			e2e.Logf("Deleting the existing metallb CR")
			removeResource(oc, true, true, "metallb", "metallb", "-n", opNamespace)
		}

	})

	g.It("Author:asood-NonHyperShiftHOST-High-46560-High-50944-MetalLB-CR All Workers Creation and Verify the logging level of MetalLB can be changed for debugging [Serial]", func() {

		compat_otp.By("Creating metalLB CR on all the worker nodes in cluster")
		metallbCRTemplate := filepath.Join(testDataDir, "metallb-cr-template.yaml")
		metallbCR := metalLBCRResource{
			name:                  "metallb",
			namespace:             opNamespace,
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
		compat_otp.By("Validate speaker  pods scheduled on worker nodes")
		result = validateAllWorkerNodeMCR(oc, opNamespace)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("50944-Verify the logging level of MetalLB can be changed for debugging")
		compat_otp.By("Validate log level is info")
		level := "info"
		components := [3]string{"controller", "speaker"}
		var err string
		for _, component := range components {
			result, err = checkLogLevelPod(oc, component, opNamespace, level)
			o.Expect(result).To(o.BeTrue())
			o.Expect(err).Should(o.BeEmpty())
			e2e.Logf("%s pod log level is %s", component, level)
		}

		compat_otp.By("Change the log level")
		//defer not needed because metallb CR is deleted at the end of the test
		patchResourceAsAdmin(oc, "metallb/"+metallbCR.name, "{\"spec\":{\"logLevel\": \"debug\"}}", opNamespace)

		compat_otp.By("Verify the deployment and daemon set have rolled out")
		dpStatus, dpStatusErr := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", opNamespace, "deployment", "controller", "--timeout", "5m").Output()
		o.Expect(dpStatusErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(dpStatus, "successfully rolled out")).To(o.BeTrue())

		dsStatus, dsStatusErr := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", opNamespace, "ds", "speaker", "--timeout", "5m").Output()
		o.Expect(dsStatusErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(dsStatus, "successfully rolled out")).To(o.BeTrue())

		level = "debug"
		for _, component := range components {
			result, err = checkLogLevelPod(oc, component, opNamespace, level)
			o.Expect(result).To(o.BeTrue())
			o.Expect(err).Should(o.BeEmpty())
			e2e.Logf("%s pod log level is %s", component, level)
		}

	})

	g.It("Author:asood-NonHyperShiftHOST-High-54857-Validate controller and pod can be scheduled based on node selectors.[Serial]", func() {
		var nodeSelKey = "kubernetes.io/hostname"
		compat_otp.By("Obtain the worker nodes in cluster")
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("This test can only be run for cluster that has atleast two worker nodes.")
		}

		compat_otp.By("Creating metalLB CR on specific worker nodes in cluster")

		metallbCRTemplate := filepath.Join(testDataDir, "metallb-cr-template.yaml")
		metallbCR := metalLBCRResource{
			name:                  "metallb",
			namespace:             opNamespace,
			nodeSelectorKey:       nodeSelKey,
			nodeSelectorVal:       workerList.Items[0].Name,
			controllerSelectorKey: nodeSelKey,
			controllerSelectorVal: workerList.Items[1].Name,
			template:              metallbCRTemplate,
		}
		defer removeResource(oc, true, true, "metallb", metallbCR.name, "-n", metallbCR.namespace)
		result := createMetalLBCR(oc, metallbCR, metallbCRTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By(fmt.Sprintf("Get the pod names for speaker and controller respectively scheduled on %s and %s", workerList.Items[0].Name, workerList.Items[1].Name))
		components := []string{"speaker", "controller"}
		for i, component := range components {
			podName, err := compat_otp.GetPodName(oc, opNamespace, "component="+component, workerList.Items[i].Name)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(podName).NotTo(o.BeEmpty())
		}

	})

	g.It("Author:asood-NonHyperShiftHOST-High-54822-Validate controller and speaker pods can be scheduled based on affinity - node affinity, pod affinity and pod anti affinity.[Serial]", func() {
		var (
			testDataBaseDir         = testdata.FixturePath("networking")
			nodeLabels              = []string{"east", "west"}
			nodeAffinityFile        = filepath.Join(testDataDir, "metallb-cr-node-affinity.yaml")
			nodeAffinityTemplate    = filepath.Join(testDataDir, "metallb-cr-node-affinity-template.yaml")
			podAffinityTemplate     = filepath.Join(testDataDir, "metallb-cr-pod-affinity-template.yaml")
			podAntiAffinityTemplate = filepath.Join(testDataDir, "metallb-cr-pod-antiaffinity-template.yaml")
			pingPodNodeTemplate     = filepath.Join(testDataBaseDir, "ping-for-pod-specific-node-template.yaml")
			components              = []string{"controller", "speaker"}
		)

		compat_otp.By("Obtain the worker nodes in cluster")
		workersList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workersList.Items) < 2 {
			g.Skip("This test can only be run for cluster that has atleast two worker nodes.")
		}

		compat_otp.By("Label two nodes of the cluster")
		for i := 0; i < 2; i++ {
			defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workersList.Items[i].Name, "zone")
			e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workersList.Items[i].Name, "zone", nodeLabels[i])
		}
		defer removeResource(oc, true, true, "metallb", "metallb", "-n", opNamespace)
		metallbCR := metalLBAffinityCRResource{
			name:      "metallb",
			namespace: opNamespace,
			param1:    "",
			param2:    "",
			template:  "",
		}
		// Node afinity
		for i := 0; i < 2; i++ {
			if i == 0 {
				compat_otp.By("Create meatllb CR with Node Affinity using node selector term - matchExpressions")
				createResourceFromFile(oc, opNamespace, nodeAffinityFile)

			} else {
				compat_otp.By("Create meatllb CR with Node Affinity using node selector term - matchFields")
				metallbCR.param1 = workersList.Items[0].Name
				metallbCR.param2 = workersList.Items[1].Name
				metallbCR.template = nodeAffinityTemplate
				o.Expect(createMetalLBAffinityCR(oc, metallbCR)).To(o.BeTrue())
			}

			compat_otp.By(fmt.Sprintf("Get the pod names for controller and speaker respectively scheduled on %s and %s", workersList.Items[0].Name, workersList.Items[1].Name))
			expectedPodNodeList := []string{workersList.Items[0].Name, workersList.Items[1].Name, workersList.Items[1].Name}
			for j, component := range components {
				if j == 0 {
					err := waitForPodWithLabelReady(oc, opNamespace, "component="+component)
					o.Expect(err).NotTo(o.HaveOccurred())
				} else {
					dsStatus, dsStatusErr := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", opNamespace, "ds", component, "--timeout", "5m").Output()
					o.Expect(dsStatusErr).NotTo(o.HaveOccurred())
					o.Expect(strings.Contains(dsStatus, "successfully rolled out")).To(o.BeTrue())
				}
				podName, err := compat_otp.GetPodName(oc, opNamespace, "component="+component, expectedPodNodeList[j])
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(podName).NotTo(o.BeEmpty())
			}
			removeResource(oc, true, true, "metallb", "metallb", "-n", opNamespace)
		}
		// Pod affinity and anti affinity
		compat_otp.By("Create a pod on one of the nodes")
		pod := pingPodResourceNode{
			name:      "hello-pod",
			namespace: oc.Namespace(),
			nodename:  workersList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod.createPingPodNode(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		metallbCR.param1 = pod.namespace
		metallbCR.param2 = pod.namespace

		metallbCRTemplateList := []string{podAffinityTemplate, podAntiAffinityTemplate}
		dsSearchStrList := []string{fmt.Sprintf("1 of %v updated pods are available", len(workersList.Items)), fmt.Sprintf("%v of %v updated pods are available", len(workersList.Items)-1, len(workersList.Items))}
		scenarioStrList := []string{"affinity", "anti affinity"}

		for index, scenario := range scenarioStrList {
			compat_otp.By(fmt.Sprintf("Create meatllb CR with pod %s", scenario))
			metallbCR.template = metallbCRTemplateList[index]
			o.Expect(createMetalLBAffinityCR(oc, metallbCR)).To(o.BeTrue())
			compat_otp.By(fmt.Sprintf("Validate roll out status of speaker daemonset for pod %s", scenario))
			o.Eventually(func() bool {
				dsStatus, dsStatusErr := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", opNamespace, "ds", components[1], "--timeout", "10s").Output()
				o.Expect(dsStatusErr).To(o.HaveOccurred())
				return strings.Contains(dsStatus, dsSearchStrList[index])
			}, "60s", "10s").Should(o.BeTrue(), "Pods did not reach running status")

			if index == 0 {
				compat_otp.By(fmt.Sprintf("Validate metallb pods are running only on %s", workersList.Items[0].Name))
				for i := 0; i < len(components); i++ {
					podName, err := compat_otp.GetPodName(oc, opNamespace, "component="+components[i], workersList.Items[0].Name)
					o.Expect(err).NotTo(o.HaveOccurred())
					o.Expect(podName).NotTo(o.BeEmpty())
				}
			} else {
				compat_otp.By(fmt.Sprintf("Validate metallb pods are not running on %s", workersList.Items[0].Name))
				for i := 0; i < len(components); i++ {
					podName, err := compat_otp.GetPodName(oc, opNamespace, "component="+components[i], workersList.Items[0].Name)
					o.Expect(err).NotTo(o.HaveOccurred())
					o.Expect(podName).To(o.BeEmpty())
				}
			}
			removeResource(oc, true, true, "metallb", "metallb", "-n", opNamespace)
		}

	})

	g.It("Author:asood-NonHyperShiftHOST-High-54823-Validate controller and speaker pods are scheduled on nodes based priority class. [Serial]", func() {
		var (
			metallbCRPriorityClassFile = filepath.Join(testDataDir, "metallb-cr-priority-class.yaml")
			metallbPriorityClassFile   = filepath.Join(testDataDir, "metallb-priority-class.yaml")
			components                 = []string{"controller", "speaker"}
		)

		compat_otp.By("Create meatllb CR with priority class")
		createResourceFromFile(oc, opNamespace, metallbCRPriorityClassFile)
		defer removeResource(oc, true, true, "metallb", "metallb", "-n", opNamespace)
		compat_otp.By("Validate metallb CR not created as priority class is not yet created")
		// just check the daemon sets as pods are not expected to be scheduled
		o.Eventually(func() bool {
			dsStatus, dsStatusErr := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", opNamespace, "ds", components[1], "--timeout", "10s").Output()
			o.Expect(dsStatusErr).To(o.HaveOccurred())
			return strings.Contains(dsStatus, "0 out of")
		}, "60s", "10s").Should(o.BeTrue(), "Pods did not reach running status")

		createResourceFromFile(oc, opNamespace, metallbPriorityClassFile)
		defer removeResource(oc, true, true, "priorityclass", "metallb-high-priority")
		compat_otp.By("Validate metallb CR is created after priority class is created")
		for j, component := range components {
			if j == 0 {
				err := waitForPodWithLabelReady(oc, opNamespace, "component="+component)
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				dsStatus, dsStatusErr := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", opNamespace, "ds", component, "--timeout", "60s").Output()
				o.Expect(dsStatusErr).NotTo(o.HaveOccurred())
				o.Expect(strings.Contains(dsStatus, "successfully rolled out")).To(o.BeTrue())
			}
		}

	})

})

// L2 tests
var _ = g.Describe("[OTP][sig-networking] SDN metallb l2", func() {
	defer g.GinkgoRecover()

	var (
		oc                        = compat_otp.NewCLI("networking-metallb", compat_otp.KubeConfigPath())
		opNamespace               = "metallb-system"
		opName                    = "metallb-operator"
		serviceLabelKey           = "environ"
		serviceLabelValue         = "Test"
		serviceNodePortAllocation = true
		testDataDir               = testdata.FixturePath("networking/metallb")
		l2Addresses               = [2][2]string{{"192.168.111.65-192.168.111.69", "192.168.111.70-192.168.111.74"}, {"192.168.111.75-192.168.111.79", "192.168.111.80-192.168.111.85"}}
		proxyHost                 = ""
		metalLBNodeSelKey         = "node-role.kubernetes.io/worker"
		metalLBNodeSelVal         = ""
		metalLBControllerSelKey   = "node-role.kubernetes.io/worker"
		metalLBControllerSelVal   = ""
		ipAddressPoolLabelKey     = "zone"
		ipAddressPoolLabelVal     = "east"
		annotationPrefix          = "metallb.io"
		catalogNamespace          = "openshift-marketplace"
		catalogSourceName         = "metallb-operator-fbc-catalog"
		imageDigestMirrorSetName  = "metallb-images-mirror-set"
	)

	g.BeforeEach(func() {
		compat_otp.By("Check the platform if it is suitable for running the test")
		networkType := compat_otp.CheckNetworkType(oc)
		if !(isRDUPlatformSuitable(oc)) || !strings.Contains(networkType, "ovn") {
			g.Skip("These cases can only be run on networking team's private RDU clusters , skip for other platforms or non-OVN network plugin!!!")
		}
		proxySetting := os.Getenv("http_proxy")
		if proxySetting == "" {
			g.Skip("Proxy settings to access the cluster are not found, please ensure they are set!!")
		}
		cmd := `echo "$http_proxy" | awk -F'[/:]' '{print $1}'`
		hostIP, awkErr := exec.Command("bash", "-c", cmd).Output()
		o.Expect(awkErr).NotTo(o.HaveOccurred())
		o.Expect(hostIP).NotTo(o.BeEmpty())
		proxyHost = strings.TrimSpace(string(hostIP))

		namespaceTemplate := filepath.Join(testDataDir, "namespace-template.yaml")
		operatorGroupTemplate := filepath.Join(testDataDir, "operatorgroup-template.yaml")
		subscriptionTemplate := filepath.Join(testDataDir, "subscription-template.yaml")
		catalogSourceTemplate := filepath.Join(testDataDir, "catalogsource-template.yaml")
		imageDigestMirrorSetFile := filepath.Join(testDataDir, "image-digest-mirrorset.yaml")
		sub := subscriptionResource{
			name:             "metallb-operator-sub",
			namespace:        opNamespace,
			operatorName:     opName,
			channel:          "stable",
			catalog:          catalogSourceName,
			catalogNamespace: catalogNamespace,
			template:         subscriptionTemplate,
		}
		ns := namespaceResource{
			name:     opNamespace,
			template: namespaceTemplate,
		}
		og := operatorGroupResource{
			name:             opName,
			namespace:        opNamespace,
			targetNamespaces: opNamespace,
			template:         operatorGroupTemplate,
		}
		catalogSourceName = setupOperatorCatalogSource(oc, "metallb", catalogSourceName, imageDigestMirrorSetName, catalogNamespace, imageDigestMirrorSetFile, catalogSourceTemplate)
		sub.catalog = catalogSourceName
		operatorInstall(oc, sub, ns, og)

		compat_otp.By("Making sure CRDs are successfully installed")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "bfdprofiles.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgpadvertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgppeers.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "communities.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "ipaddresspools.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "l2advertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "metallbs.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrconfigurations.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrnodestates.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "servicel2statuses.metallb.io")).To(o.BeTrue())

		compat_otp.By("Create MetalLB CR")
		metallbCRTemplate := filepath.Join(testDataDir, "metallb-cr-template.yaml")
		metallbCR := metalLBCRResource{
			name:                  "metallb",
			namespace:             opNamespace,
			nodeSelectorKey:       metalLBNodeSelKey,
			nodeSelectorVal:       metalLBNodeSelVal,
			controllerSelectorKey: metalLBControllerSelKey,
			controllerSelectorVal: metalLBControllerSelVal,
			template:              metallbCRTemplate,
		}
		result := createMetalLBCR(oc, metallbCR, metallbCRTemplate)
		o.Expect(result).To(o.BeTrue())
		compat_otp.By("SUCCESS - MetalLB CR Created")
	})

	g.It("Author:asood-High-43075-Create L2 LoadBalancer Service [Serial]", func() {
		var (
			ns                   string
			namespaces           []string
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			interfaces           = [3]string{"br-ex", "eno1", "eno2"}
			workers              []string
			ipaddresspools       []string
			testID               = "43075"
		)

		compat_otp.By("1. Obtain the masters, workers and namespace")
		//Two worker nodes needed to create l2advertisement object
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}
		masterNodeList, err1 := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(err1).NotTo(o.HaveOccurred())
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test"+testID)

		compat_otp.By("2. Create IP addresspool")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-l2",
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 l2Addresses[0][:],
			namespaces:                namespaces[:],
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)
		o.Expect(result).To(o.BeTrue())
		ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		compat_otp.By("SUCCESS - IP Addresspool")

		compat_otp.By("3. Create L2Advertisement")
		l2AdvertisementTemplate := filepath.Join(testDataDir, "l2advertisement-template.yaml")
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv",
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: workers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		result = createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("4. Create LoadBalancer services using Layer 2 addresses")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")

		compat_otp.By("4.1 Create a service with ExtenalTrafficPolicy Local")
		svc1 := loadBalancerServiceResource{
			name:                          "hello-world-local",
			namespace:                     ns,
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: serviceNodePortAllocation,
			externaltrafficpolicy:         "Local",
			template:                      loadBalancerServiceTemplate,
		}
		result = createLoadBalancerService(oc, svc1, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("4.2 Create a service with ExtenalTrafficPolicy Cluster")
		svc2 := loadBalancerServiceResource{
			name:                          "hello-world-cluster",
			namespace:                     ns,
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: serviceNodePortAllocation,
			externaltrafficpolicy:         "Cluster",
			template:                      loadBalancerServiceTemplate,
		}
		result = createLoadBalancerService(oc, svc2, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("SUCCESS - Services created successfully")

		compat_otp.By("4.3 Validate LoadBalancer services")
		err = checkLoadBalancerSvcStatus(oc, svc1.namespace, svc1.name)
		o.Expect(err).NotTo(o.HaveOccurred())

		svcIP := getLoadBalancerSvcIP(oc, svc1.namespace, svc1.name)
		e2e.Logf("The service %s External IP is %q", svc1.name, svcIP)
		result = validateService(oc, masterNodeList[0], svcIP)
		o.Expect(result).To(o.BeTrue())

		err = checkLoadBalancerSvcStatus(oc, svc2.namespace, svc2.name)
		o.Expect(err).NotTo(o.HaveOccurred())

		svcIP = getLoadBalancerSvcIP(oc, svc2.namespace, svc2.name)
		e2e.Logf("The service %s External IP is %q", svc2.name, svcIP)
		result = validateService(oc, masterNodeList[0], svcIP)
		o.Expect(result).To(o.BeTrue())

	})

	g.It("Author:asood-High-53333-High-49622-Verify for the service IP address of NodePort or LoadBalancer service ARP requests gets response from one interface only and prometheus metrics are updated when service is removed. [Serial]", func() {
		var (
			ns                   string
			namespaces           []string
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			interfaces           = [3]string{"br-ex", "eno1", "eno2"}
			workers              []string
			ipaddresspools       []string
			testID               = "53333"
		)
		compat_otp.By("Test case for bug ID 2054225")
		compat_otp.By("1.0 Obtain the masters, workers and namespace")
		//Two worker nodes needed to create l2advertisement object
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}
		masterNodeList, err1 := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(err1).NotTo(o.HaveOccurred())
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test"+testID)

		compat_otp.By(fmt.Sprintf("1.1 Add label to operator namespace %s to enable monitoring", opNamespace))
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", opNamespace, "openshift.io/cluster-monitoring-").Execute()
		labelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", opNamespace, "openshift.io/cluster-monitoring=true").Execute()
		o.Expect(labelErr).NotTo(o.HaveOccurred())

		compat_otp.By("2. Create IP addresspool")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-l2",
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 l2Addresses[0][:],
			namespaces:                namespaces[:],
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)
		o.Expect(result).To(o.BeTrue())
		ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		compat_otp.By("SUCCESS - IP Addresspool")

		compat_otp.By("3. Create L2Advertisement")
		l2AdvertisementTemplate := filepath.Join(testDataDir, "l2advertisement-template.yaml")
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv",
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: workers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		result = createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("4. Create LoadBalancer services using Layer 2 addresses")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")

		compat_otp.By("4.1 Create a service with ExtenalTrafficPolicy Cluster")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-cluster",
			namespace:                     ns,
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: serviceNodePortAllocation,
			externaltrafficpolicy:         "Cluster",
			template:                      loadBalancerServiceTemplate,
		}
		result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("SUCCESS - Services created successfully")

		compat_otp.By("4.2 Validate LoadBalancer services")
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())

		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %q", svc.name, svcIP)
		result = validateService(oc, masterNodeList[0], svcIP)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("5. Validate MAC Address assigned to service")
		compat_otp.By("5.1 Get the node announcing the service IP")
		nodeName := getNodeAnnouncingL2Service(oc, svc.name, svc.namespace)
		e2e.Logf("Node announcing the service IP %s ", nodeName)

		compat_otp.By("5.2 Obtain MAC address for  Load Balancer Service IP")
		macAddress, result := obtainMACAddressForIP(oc, masterNodeList[0], svcIP, 5)
		o.Expect(result).To(o.BeTrue())
		o.Expect(macAddress).NotTo(o.BeEmpty())
		e2e.Logf("MAC address by ARP Lookup %s ", macAddress)

		compat_otp.By("5.3 Get MAC address configured on the node interface announcing the service IP Address")
		macAddress1 := getNodeMacAddress(oc, nodeName)
		o.Expect(macAddress1).NotTo(o.BeEmpty())
		e2e.Logf("MAC address of announcing node %s ", macAddress1)
		o.Expect(strings.ToLower(macAddress)).Should(o.Equal(macAddress1))

		compat_otp.By("OCP-49622 LoadBalancer service prometheus metrics are updated when service is removed")
		l2Metrics := "metallb_speaker_announced"
		compat_otp.By(fmt.Sprintf("6.1 Get %s metrics for the service %s at %s IP Address", l2Metrics, svc.name, svcIP))
		o.Expect(checkPrometheusMetrics(oc, 10*time.Second, 200*time.Second, false, l2Metrics, true)).To(o.BeTrue())
		compat_otp.By("6.2 Delete the service and check meterics are removed")
		removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		o.Expect(checkPrometheusMetrics(oc, 5*time.Second, 30*time.Second, true, l2Metrics, false)).To(o.BeTrue())

	})

	g.It("Author:asood-High-60182-Verify the nodeport is not allocated to VIP based LoadBalancer service type [Disruptive]", func() {
		var (
			ns                   string
			namespaces           []string
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			interfaces           = [3]string{"br-ex", "eno1", "eno2"}
			workers              []string
			ipaddresspools       []string
			svc_names            = [2]string{"hello-world-cluster", "hello-world-local"}
			svc_etp              = [2]string{"Cluster", "Local"}
		)

		compat_otp.By("1. Determine suitability of worker nodes for the test")
		//Two worker nodes needed to create l2advertisement object
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}

		compat_otp.By("2. Create two namespace")
		for i := 0; i < 2; i++ {
			oc.SetupProject()
			ns = oc.Namespace()
			namespaces = append(namespaces, ns)
			compat_otp.By("Label the namespace")
			_, err := oc.AsAdmin().Run("label").Args("namespace", ns, namespaceLabelKey+"="+namespaceLabelValue[0], "--overwrite").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		compat_otp.By("3. Create IP addresspool")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-l2",
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 l2Addresses[0][:],
			namespaces:                namespaces[:],
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)
		o.Expect(result).To(o.BeTrue())
		ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		compat_otp.By("SUCCESS - IP Addresspool")

		compat_otp.By("4. Create L2Advertisement")
		l2AdvertisementTemplate := filepath.Join(testDataDir, "l2advertisement-template.yaml")
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv",
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: workers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		result = createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())

		masterNodeList, err1 := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(err1).NotTo(o.HaveOccurred())
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")

		for i := 0; i < 2; i++ {
			compat_otp.By("5.1 Create a service with extenaltrafficpolicy " + svc_etp[i])
			svc := loadBalancerServiceResource{
				name:                          svc_names[i],
				namespace:                     namespaces[i],
				externaltrafficpolicy:         svc_etp[i],
				labelKey:                      serviceLabelKey,
				labelValue:                    serviceLabelValue,
				allocateLoadBalancerNodePorts: false,
				template:                      loadBalancerServiceTemplate,
			}
			result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
			o.Expect(result).To(o.BeTrue())

			compat_otp.By("5.2 LoadBalancer service with name " + svc_names[i])
			compat_otp.By("5.2.1 Check LoadBalancer service is created")
			err := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
			o.Expect(err).NotTo(o.HaveOccurred())
			compat_otp.By("5.2.2 Get LoadBalancer service IP")
			svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
			compat_otp.By("5.2.3 Get LoadBalancer service IP announcing node")
			nodeName := getNodeAnnouncingL2Service(oc, svc.name, svc.namespace)
			e2e.Logf("%s is announcing the service %s with IP %s ", nodeName, svc.name, svcIP)
			compat_otp.By("5.2.4 Validate service")
			result = validateService(oc, masterNodeList[0], svcIP)
			o.Expect(result).To(o.BeTrue())
			compat_otp.By("5.2.5 Check nodePort is not assigned to service")
			nodePort := getLoadBalancerSvcNodePort(oc, svc.namespace, svc.name)
			o.Expect(nodePort).To(o.BeEmpty())

		}
		compat_otp.By("6. Change the shared gateway mode to local gateway mode")
		var desiredMode string
		origMode := getOVNGatewayMode(oc)
		if origMode == "local" {
			desiredMode = "shared"
		} else {
			desiredMode = "local"
		}
		e2e.Logf("Cluster is currently on gateway mode %s", origMode)
		e2e.Logf("Desired mode is %s", desiredMode)

		defer switchOVNGatewayMode(oc, origMode)
		switchOVNGatewayMode(oc, desiredMode)
		compat_otp.By("7. Validate services in modified gateway mode " + desiredMode)
		for i := 0; i < 2; i++ {
			compat_otp.By("7.1 Create a service with extenal traffic policy " + svc_etp[i])
			svc_names[i] = svc_names[i] + "-0"
			svc := loadBalancerServiceResource{
				name:                          svc_names[i],
				namespace:                     namespaces[i],
				externaltrafficpolicy:         svc_etp[i],
				labelKey:                      serviceLabelKey,
				labelValue:                    serviceLabelValue,
				allocateLoadBalancerNodePorts: false,
				template:                      loadBalancerServiceTemplate,
			}
			result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
			o.Expect(result).To(o.BeTrue())

			compat_otp.By("7.2 LoadBalancer service with name " + svc_names[i])
			compat_otp.By("7.2.1 Check LoadBalancer service is created")
			err := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
			o.Expect(err).NotTo(o.HaveOccurred())
			compat_otp.By("7.2.2 Get LoadBalancer service IP")
			svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
			compat_otp.By("7.2.3 Get LoadBalancer service IP announcing node")
			nodeName := getNodeAnnouncingL2Service(oc, svc.name, svc.namespace)
			e2e.Logf("%s is announcing the service %s with IP %s ", nodeName, svc.name, svcIP)
			compat_otp.By("7.2.4 Validate service")
			result = validateService(oc, masterNodeList[0], svcIP)
			o.Expect(result).To(o.BeTrue())
			compat_otp.By("7.2.5 Check nodePort is not assigned to service")
			nodePort := getLoadBalancerSvcNodePort(oc, svc.namespace, svc.name)
			o.Expect(nodePort).To(o.BeEmpty())

		}

	})

	// Test cases for CNF-6313 L2 interface selector productization
	g.It("Author:asood-Longduration-NonPreRelease-High-60513-High-60514-High-60515-High-60518-High-60519-Verify L2 service is reachable if service IP is advertised from specific interface on node using one or more L2 advertisements through the updates to L2 advetisements and gets indication if interface is not configured[Serial]", func() {
		var (
			ns                   string
			namespaces           []string
			testID               = "60513"
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			interfaces           = [3]string{"br-ex", "eno1", "eno2"}
			vmWorkers            []string
			workers              []string
			ipaddresspools       []string
		)

		//Two worker nodes needed to create l2advertisement object
		compat_otp.By("0. Determine suitability of worker nodes for the test")
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		for i := 0; i < len(workerList.Items); i++ {
			if strings.Contains(workerList.Items[i].Name, "worker") {
				vmWorkers = append(vmWorkers, workerList.Items[i].Name)
			} else {
				workers = append(workers, workerList.Items[i].Name)
			}
		}
		e2e.Logf("Virtual Nodes %s", vmWorkers)
		e2e.Logf("Real Nodes %s", workers)
		if len(workers) < 1 || len(vmWorkers) < 1 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes, virtual and real each.")
		}
		vmList, err := json.Marshal(workers)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("1. Get the namespace")
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test"+testID)

		compat_otp.By("2. Get the master nodes in the cluster for validating service")
		masterNodeList, err1 := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(err1).NotTo(o.HaveOccurred())

		compat_otp.By("3. Create IP addresspools")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")

		for i := 0; i < 2; i++ {
			ipAddresspool := ipAddressPoolResource{
				name:                      "ipaddresspool-l2-" + strconv.Itoa(i),
				namespace:                 opNamespace,
				label1:                    ipAddressPoolLabelKey,
				value1:                    ipAddressPoolLabelVal,
				addresses:                 l2Addresses[i][:],
				namespaces:                namespaces[:],
				priority:                  10,
				avoidBuggyIPs:             true,
				autoAssign:                true,
				serviceLabelKey:           serviceSelectorKey,
				serviceLabelValue:         serviceSelectorValue[0],
				serviceSelectorKey:        serviceSelectorKey,
				serviceSelectorOperator:   "In",
				serviceSelectorValue:      serviceSelectorValue[:],
				namespaceLabelKey:         namespaceLabelKey,
				namespaceLabelValue:       namespaceLabelValue[0],
				namespaceSelectorKey:      namespaceLabelKey,
				namespaceSelectorOperator: "In",
				namespaceSelectorValue:    namespaceLabelValue[:],
				template:                  ipAddresspoolTemplate,
			}
			defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
			result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)
			o.Expect(result).To(o.BeTrue())
			ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		}
		compat_otp.By(fmt.Sprintf("IP address pool %s created successfully", ipaddresspools[:]))
		//Ensure address is not assigned from address pool automatically by setting autoAssign to false
		addressList, err := json.Marshal(l2Addresses[1][:])
		o.Expect(err).NotTo(o.HaveOccurred())
		patchInfo := fmt.Sprintf("{\"spec\":{\"autoAssign\": false, \"addresses\": %s}}", string(addressList))
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddresspools[1], patchInfo, "metallb-system")

		compat_otp.By("4. Create L2 Advertisement")
		l2AdvertisementTemplate := filepath.Join(testDataDir, "l2advertisement-template.yaml")
		//Just assign one of the addresspool, use the second one for later
		ipaddrpools := []string{ipaddresspools[0], ""}
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv",
			namespace:          opNamespace,
			ipAddressPools:     ipaddrpools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: vmWorkers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		result := createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("5.0 60513 Verify L2 service with ETP Local or Cluster is reachable if service IP is advertised from specific interface on node.")
		compat_otp.By(fmt.Sprintf("5.1 Patch L2 Advertisement to ensure one interface that allows functionl services for test case %s", testID))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, "{\"spec\":{\"interfaces\": [\"br-ex\"]}}", "metallb-system")

		compat_otp.By("5.2 Create LoadBalancer services using Layer 2 addresses")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")

		svc := loadBalancerServiceResource{
			name:                          "hello-world-" + testID + "-0",
			namespace:                     ns,
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: serviceNodePortAllocation,
			externaltrafficpolicy:         "Cluster",
			template:                      loadBalancerServiceTemplate,
		}
		compat_otp.By(fmt.Sprintf("5.3. Create a service with ETP cluster with name %s", svc.name))
		defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("The %s service created successfully", svc.name)

		compat_otp.By("5.4 Validate LoadBalancer services")
		svcErr := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %s", svc.name, svcIP)
		checkSvcErr := wait.Poll(10*time.Second, 4*time.Minute, func() (bool, error) {
			result := validateService(oc, proxyHost, svcIP)
			if result {
				return true, nil
			}
			return false, nil

		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service %s at %s to be reachable but was unreachable", svc.name, svcIP))

		svc.name = "hello-world-" + testID + "-1"
		svc.externaltrafficpolicy = "Local"
		compat_otp.By(fmt.Sprintf("5.5 Create a service with ETP %s with name %s", svc.externaltrafficpolicy, svc.name))
		defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("The %s service created successfully", svc.name)

		compat_otp.By("5.6 Validate LoadBalancer services")
		svcErr = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %s", svc.name, svcIP)
		checkSvcErr = wait.Poll(10*time.Second, 4*time.Minute, func() (bool, error) {
			result := validateService(oc, masterNodeList[0], svcIP)
			if result {
				return true, nil
			}
			return false, nil

		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service %s at %s to be reachable but was unreachable", svc.name, svcIP))
		testID = "60514"
		compat_otp.By("6.0 60514 Verify user is given indication if specified interface does not exist on any of the selected node in L2 advertisement")
		compat_otp.By(fmt.Sprint("6.1 Patch L2 Advertisement to use interface that does not exist on nodes for test case", testID))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, "{\"spec\":{\"interfaces\": [\"eno1\"]}}", "metallb-system")
		compat_otp.By(fmt.Sprintf("6.2 Create service for test case %s", testID))
		svc.name = "hello-world-" + testID
		svc.externaltrafficpolicy = "Cluster"

		defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("The %s service created successfully", svc.name)
		svcErr = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())

		compat_otp.By("6.3 Check the event is generated for the interface")
		isEvent, _ := checkServiceEvents(oc, svc.name, svc.namespace, "announceFailed")
		o.Expect(isEvent).To(o.BeTrue())

		compat_otp.By("6.4 Validate LoadBalancer service is not reachable")
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %s", svc.name, svcIP)
		//There should not be any MAC address associated with service IP.
		_, macAddressResult := obtainMACAddressForIP(oc, masterNodeList[1], svcIP, 5)
		o.Expect(macAddressResult).To(o.BeFalse())

		compat_otp.By("6.5 Validate LoadBalancer service is reachable after L2 Advertisement is updated")
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, "{\"spec\":{\"interfaces\": [\"br-ex\"]}}", "metallb-system")
		checkSvcErr = wait.Poll(10*time.Second, 4*time.Minute, func() (bool, error) {
			result := validateService(oc, proxyHost, svcIP)
			if result {
				return true, nil
			}
			return false, nil

		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service %s at %s to be reachable but was unreachable", svc.name, svcIP))

		testID = "60515"
		compat_otp.By("7.0 60515 Verify service IP from IP addresspool for set of worker nodes is announced from a specific interface")
		compat_otp.By(fmt.Sprintf("8.1 Update interfaces and nodeSelector of %s", l2advertisement.name))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, "{\"spec\":{\"interfaces\": [\"eno1\", \"eno2\"]}}", "metallb-system")
		patchNodeSelector := fmt.Sprintf("{\"spec\":{\"nodeSelectors\": [{\"matchExpressions\": [{\"key\":\"kubernetes.io/hostname\", \"operator\": \"In\", \"values\": %s}]}]}}", string(vmList))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, patchNodeSelector, "metallb-system")

		compat_otp.By("7.2 Create L2 service that is unreachable")
		svc.name = "hello-world-" + testID
		svc.externaltrafficpolicy = "Cluster"
		defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("The %s service created successfully", svc.name)
		svcErr = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())

		compat_otp.By("7.3 Validate LoadBalancer service is not reachable")
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %s", svc.name, svcIP)
		_, macAddressResult = obtainMACAddressForIP(oc, masterNodeList[1], svcIP, 5)
		o.Expect(macAddressResult).To(o.BeFalse())

		compat_otp.By("7.4 Create another l2advertisement CR with same ip addresspool but different set of nodes and interface")
		l2advertisement1 := l2AdvertisementResource{
			name:               "l2-adv-" + testID,
			namespace:          opNamespace,
			ipAddressPools:     ipaddrpools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: vmWorkers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement1.name, "-n", l2advertisement1.namespace)
		result = createL2AdvertisementCR(oc, l2advertisement1, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement1.name, "{\"spec\":{\"interfaces\": [\"br-ex\"]}}", "metallb-system")
		patchNodeSelector = fmt.Sprintf("{\"spec\":{\"nodeSelectors\": [{\"matchExpressions\": [{\"key\":\"kubernetes.io/hostname\", \"operator\": \"In\", \"values\": %s}]}]}}", string(vmList))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement1.name, patchNodeSelector, "metallb-system")

		compat_otp.By("7.5 Check the event is not generated for the interface")
		isEvent, _ = checkServiceEvents(oc, svc.name, svc.namespace, "announceFailed")
		o.Expect(isEvent).To(o.BeFalse())

		compat_otp.By("7.6 Get LoadBalancer service IP announcing node")
		nodeName := getNodeAnnouncingL2Service(oc, svc.name, svc.namespace)
		e2e.Logf("%s is announcing the service %s with IP %s ", nodeName, svc.name, svcIP)

		compat_otp.By("7.7 Verify the service is functional as the another L2 advertisement is used for the ip addresspool")
		checkSvcErr = wait.Poll(10*time.Second, 4*time.Minute, func() (bool, error) {
			result := validateService(oc, proxyHost, svcIP)
			if result {
				return true, nil
			}
			return false, nil

		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service %s at %s to be reachable but was unreachable", svc.name, svcIP))

		testID = "60518"
		i := 0
		var svcIPs []string
		compat_otp.By("8.0 60518 Verify configuration changes like updating the L2 advertisement to add interface, removing L2advertisement and updating addresspool works.")
		removeResource(oc, true, true, "l2advertisements", l2advertisement1.name, "-n", l2advertisement1.namespace)

		compat_otp.By(fmt.Sprintf("8.1 Update interfaces and nodeSelector of %s", l2advertisement.name))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, "{\"spec\":{\"interfaces\": [\"br-ex\", \"eno2\"]}}", "metallb-system")
		patchNodeSelector = fmt.Sprintf("{\"spec\":{\"nodeSelectors\": [{\"matchExpressions\": [{\"key\":\"kubernetes.io/hostname\", \"operator\": \"In\", \"values\": %s}]}]}}", string(vmList))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, patchNodeSelector, "metallb-system")

		compat_otp.By("8.2 Create L2 service")
		svc.name = "hello-world-" + testID + "-" + strconv.Itoa(i)
		defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("The %s service created successfully", svc.name)
		svcErr = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())

		compat_otp.By("8.3 Validate LoadBalancer service is reachable")
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %s", svc.name, svcIP)

		checkSvcErr = wait.Poll(10*time.Second, 4*time.Minute, func() (bool, error) {
			result := validateService(oc, proxyHost, svcIP)
			if result {
				return true, nil
			}
			return false, nil

		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service %s at %s to be reachable but was unreachable", svc.name, svcIP))

		compat_otp.By(fmt.Sprintf("8.4 Delete the L2 advertisement resource named %s", l2advertisement.name))
		removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)

		compat_otp.By(fmt.Sprintf("8.5 Validate service with name %s is unreachable", svc.name))
		nodeName = getNodeAnnouncingL2Service(oc, svc.name, svc.namespace)
		e2e.Logf("%s is announcing the service %s with IP %s ", nodeName, svc.name, svcIP)
		_, macAddressResult = obtainMACAddressForIP(oc, masterNodeList[1], svcIP, 5)
		o.Expect(macAddressResult).To(o.BeFalse())

		svcIPs = append(svcIPs, svcIP)

		compat_otp.By("8.6 Create another service request IP address from second IP addresspool, so see it is unreachable")
		i = i + 1
		loadBalancerServiceAnnotatedTemplate := filepath.Join(testDataDir, "loadbalancer-svc-annotated-template.yaml")
		annotatedSvc := loadBalancerServiceResource{
			name:                          "hello-world-" + testID + "-" + strconv.Itoa(i),
			namespace:                     ns,
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceSelectorKey,
			labelValue:                    serviceSelectorValue[0],
			annotationKey:                 annotationPrefix + "/address-pool",
			annotationValue:               ipaddresspools[1],
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceAnnotatedTemplate,
		}
		defer removeResource(oc, true, true, "service", annotatedSvc.name, "-n", annotatedSvc.namespace)
		o.Expect(createLoadBalancerService(oc, annotatedSvc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, annotatedSvc.namespace, annotatedSvc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP = getLoadBalancerSvcIP(oc, annotatedSvc.namespace, annotatedSvc.name)
		e2e.Logf("The %s service created successfully with %s with annotation %s:%s", annotatedSvc.name, svcIP, annotatedSvc.annotationKey, annotatedSvc.annotationValue)
		svcIPs = append(svcIPs, svcIP)
		_, macAddressResult = obtainMACAddressForIP(oc, masterNodeList[1], svcIP, 5)
		o.Expect(macAddressResult).To(o.BeFalse())
		compat_otp.By("8.7 Create L2 Advertisements with both ip address pools")
		l2advertisement = l2AdvertisementResource{
			name:               "l2-adv-" + testID,
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: vmWorkers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		result = createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())
		addrPoolList, err := json.Marshal(ipaddresspools)
		o.Expect(err).NotTo(o.HaveOccurred())
		patchIPAddresspools := fmt.Sprintf("{\"spec\":{\"ipAddressPools\": %s}}", string(addrPoolList))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, patchIPAddresspools, "metallb-system")

		compat_otp.By("8.8 Both services are functional")
		for i = 0; i < 2; i++ {
			checkSvcErr = wait.Poll(10*time.Second, 4*time.Minute, func() (bool, error) {
				result := validateService(oc, proxyHost, svcIPs[i])
				if result {
					return true, nil
				}
				return false, nil

			})
			compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service at %s to be reachable but was unreachable", svcIPs[i]))

		}

		testID = "60519"
		compat_otp.By("9.0 60519 Verify interface can be selected across l2advertisements.")
		compat_otp.By(fmt.Sprintf("9.1 Update interface list of %s L2 Advertisement object to non functional", l2advertisement.name))
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement.name, "{\"spec\":{\"interfaces\": [\"eno1\", \"eno2\"]}}", "metallb-system")

		compat_otp.By("9.2 Create another L2 Advertisement")
		l2advertisement1 = l2AdvertisementResource{
			name:               "l2-adv-" + testID,
			namespace:          opNamespace,
			ipAddressPools:     ipaddrpools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: vmWorkers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement1.name, "-n", l2advertisement1.namespace)
		result = createL2AdvertisementCR(oc, l2advertisement1, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement1.name, "{\"spec\":{\"interfaces\": [\"br-ex\"]}}", "metallb-system")
		patchResourceAsAdmin(oc, "l2advertisements/"+l2advertisement1.name, "{\"spec\":{\"nodeSelectors\": []}}", "metallb-system")

		compat_otp.By("9.3 Create L2 Service")
		svc.name = "hello-world-" + testID
		defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())
		e2e.Logf("The %s service created successfully", svc.name)
		svcErr = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())

		compat_otp.By("9.4 Validate LoadBalancer service is reachable")
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %s", svc.name, svcIP)
		checkSvcErr = wait.Poll(10*time.Second, 4*time.Minute, func() (bool, error) {
			result := validateService(oc, proxyHost, svcIP)
			if result {
				return true, nil
			}
			return false, nil

		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service %s at %s to be reachable but was unreachable", svc.name, svcIP))
	})

	// Test cases service annotation
	g.It("Author:asood-High-43155-High-43156-High-43313-Verify static address is associated with LoadBalancer service specified in YAML, approriate messages are logged if it cannot be and services can share IP [Serial]", func() {
		var (
			ns                   string
			namespaces           []string
			testID               = "43155"
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			interfaces           = [3]string{"br-ex", "eno1", "eno2"}
			vmWorkers            []string
			ipaddresspools       []string
			requestedIp          = "192.168.111.65"
		)

		//Two worker nodes needed to create l2advertisement object
		compat_otp.By("1. Determine suitability of worker nodes for the test")
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes, virtual and real each.")
		}
		for i := 0; i < 2; i++ {
			vmWorkers = append(vmWorkers, workerList.Items[i].Name)
		}
		compat_otp.By("2. Get the namespace")
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test"+testID)

		compat_otp.By("3. Create IP addresspools")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")

		for i := 0; i < 2; i++ {
			ipAddresspool := ipAddressPoolResource{
				name:                      "ipaddresspool-l2-" + strconv.Itoa(i),
				namespace:                 opNamespace,
				label1:                    ipAddressPoolLabelKey,
				value1:                    ipAddressPoolLabelVal,
				addresses:                 l2Addresses[i][:],
				namespaces:                namespaces[:],
				priority:                  10,
				avoidBuggyIPs:             true,
				autoAssign:                true,
				serviceLabelKey:           serviceSelectorKey,
				serviceLabelValue:         serviceSelectorValue[0],
				serviceSelectorKey:        serviceSelectorKey,
				serviceSelectorOperator:   "In",
				serviceSelectorValue:      serviceSelectorValue[:],
				namespaceLabelKey:         namespaceLabelKey,
				namespaceLabelValue:       namespaceLabelValue[0],
				namespaceSelectorKey:      namespaceLabelKey,
				namespaceSelectorOperator: "In",
				namespaceSelectorValue:    namespaceLabelValue[:],
				template:                  ipAddresspoolTemplate,
			}
			defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
			result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)
			o.Expect(result).To(o.BeTrue())
			ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		}
		compat_otp.By(fmt.Sprintf("IP address pool %s created successfully", ipaddresspools[:]))
		//Ensure address is not assigned from address pool automatically by setting autoAssign to false
		addressList, err := json.Marshal(l2Addresses[1][:])
		o.Expect(err).NotTo(o.HaveOccurred())
		patchInfo := fmt.Sprintf("{\"spec\":{\"autoAssign\": false, \"addresses\": %s, \"serviceAllocation\":{\"serviceSelectors\":[], \"namespaces\":[\"%s\"], \"namespaceSelectors\":[] }}}", string(addressList), "test-"+testID)
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddresspools[1], patchInfo, "metallb-system")

		compat_otp.By("4. Create L2 Advertisement")
		l2AdvertisementTemplate := filepath.Join(testDataDir, "l2advertisement-template.yaml")
		//Just assign one of the addresspool, use the second one later
		ipaddrpools := []string{ipaddresspools[0], ""}
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv",
			namespace:          opNamespace,
			ipAddressPools:     ipaddrpools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: vmWorkers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		result := createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By(fmt.Sprintf("5.0 %s Verify L2 service requesting specific IP %s.", testID, requestedIp))
		compat_otp.By("5.1 Create L2 LoadBalancer service with annotated IP address")
		loadBalancerServiceAnnotatedTemplate := filepath.Join(testDataDir, "loadbalancer-svc-annotated-template.yaml")
		annotatedSvc := loadBalancerServiceResource{
			name:                          "hello-world-" + testID,
			namespace:                     namespaces[0],
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceSelectorKey,
			labelValue:                    serviceSelectorValue[0],
			annotationKey:                 annotationPrefix + "/loadBalancerIPs",
			annotationValue:               requestedIp,
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceAnnotatedTemplate,
		}
		compat_otp.By(fmt.Sprintf("5.2. Create a service with ETP Cluster with name %s", annotatedSvc.name))
		defer removeResource(oc, true, true, "service", annotatedSvc.name, "-n", annotatedSvc.namespace)
		o.Expect(createLoadBalancerService(oc, annotatedSvc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
		compat_otp.By("5.3 Validate LoadBalancer service")
		svcErr := checkLoadBalancerSvcStatus(oc, annotatedSvc.namespace, annotatedSvc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, annotatedSvc.namespace, annotatedSvc.name)
		e2e.Logf("The service %s External IP is %s", annotatedSvc.name, svcIP)
		checkSvcErr := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 4*time.Minute, false, func(ctx context.Context) (bool, error) {
			result := validateService(oc, proxyHost, svcIP)
			if result {
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service %s at %s to be reachable but was unreachable", annotatedSvc.name, svcIP))

		testID = "43156"
		compat_otp.By(fmt.Sprintf("6.0 %s Verify L2 service requesting IP from pool %s for AllocationFailed.", testID, ipaddresspools[1]))
		compat_otp.By("6.1 Create L2 LoadBalancer service with annotated IP address pool")
		annotatedSvc.name = "hello-world-" + testID + "-0"
		annotatedSvc.annotationKey = annotationPrefix + "/address-pool"
		annotatedSvc.annotationValue = ipaddresspools[1]
		defer removeResource(oc, true, true, "service", annotatedSvc.name, "-n", annotatedSvc.namespace)
		o.Expect(createLoadBalancerService(oc, annotatedSvc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())

		compat_otp.By("6.2 Validate LoadBalancer service")
		//Use interval and timeout as it is expected IP assignment will fail
		svcErr = checkLoadBalancerSvcStatus(oc, annotatedSvc.namespace, annotatedSvc.name, 5*time.Second, 30*time.Second)
		o.Expect(svcErr).To(o.HaveOccurred())

		compat_otp.By("6.3 Validate allocation failure reason")
		isEvent, msg := checkServiceEvents(oc, annotatedSvc.name, annotatedSvc.namespace, "AllocationFailed")
		o.Expect(isEvent).To(o.BeTrue())
		o.Expect(strings.Contains(msg, fmt.Sprintf("pool %s not compatible for ip assignment", ipaddresspools[1]))).To(o.BeTrue())

		compat_otp.By("6.4 Update IP address pool %s address range for already used IP address")
		patchInfo = fmt.Sprintf("{\"spec\":{\"addresses\":[\"%s-%s\"]}}", requestedIp, requestedIp)
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddresspools[0], patchInfo, "metallb-system")
		/* OCPBUGS-61210
		compat_otp.By("6.5 Create another service AllocationFailed reason ")
		annotatedSvc.name = "hello-world-" + testID + "-1"
		annotatedSvc.annotationKey = annotationPrefix + "/address-pool"
		annotatedSvc.annotationValue = ipaddresspools[0]
		defer removeResource(oc, true, true, "service", annotatedSvc.name, "-n", annotatedSvc.namespace)
		o.Expect(createLoadBalancerService(oc, annotatedSvc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())

		compat_otp.By("6.6 Validate LoadBalancer service")
		//Use interval and timeout as it is expected IP assignment will fail
		svcErr = checkLoadBalancerSvcStatus(oc, annotatedSvc.namespace, annotatedSvc.name, 5*time.Second, 30*time.Second)
		o.Expect(svcErr).To(o.HaveOccurred())

		compat_otp.By("6.7 Validate allocation failure reason")
		isEvent, msg = checkServiceEvents(oc, annotatedSvc.name, annotatedSvc.namespace, "AllocationFailed")
		o.Expect(isEvent).To(o.BeTrue())
		o.Expect(strings.Contains(msg, "no available IPs in pool "+ipaddresspools[0])).To(o.BeTrue())
		*/

		compat_otp.By("6.8 Create third service AllocationFailed reason ")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-" + testID + "-2",
			namespace:                     namespaces[0],
			labelKey:                      serviceSelectorKey,
			labelValue:                    serviceSelectorValue[0],
			allocateLoadBalancerNodePorts: false,
			externaltrafficpolicy:         "Cluster",
			template:                      loadBalancerServiceTemplate,
		}
		defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())

		compat_otp.By("6.9 Validate LoadBalancer service")
		//Use interval and timeout as it is expected IP assignment will fail
		svcErr = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name, 5*time.Second, 30*time.Second)
		o.Expect(svcErr).To(o.HaveOccurred())

		compat_otp.By("6.10 Validate allocation failure reason")
		isEvent, msg = checkServiceEvents(oc, svc.name, svc.namespace, "AllocationFailed")
		o.Expect(isEvent).To(o.BeTrue())
		o.Expect(strings.Contains(msg, "no available IPs")).To(o.BeTrue())

		testID = "43313"
		compat_otp.By(fmt.Sprintf("7.0 %s Verify one address can be associated with more than one service using annotation %s/allow-shared-ip", testID, annotationPrefix))
		compat_otp.By(fmt.Sprintf("7.1 Patch IP addresspool pool %s address range to original range", ipaddresspools[0]))
		addressList, err = json.Marshal(l2Addresses[0][:])
		o.Expect(err).NotTo(o.HaveOccurred())
		patchInfo = fmt.Sprintf("{\"spec\":{\"addresses\": %s}}", string(addressList))
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddresspools[0], patchInfo, "metallb-system")
		annotationForSvc := fmt.Sprintf("\"shared-ip-%s-svc\"", testID)

		compat_otp.By("7.2 Create first L2 LoadBalancer service with annotation")
		annotatedSvc.name = "hello-world-" + testID + "-tcp"
		annotatedSvc.annotationKey = annotationPrefix + "/allow-shared-ip"
		annotatedSvc.annotationValue = annotationForSvc

		defer removeResource(oc, true, true, "service", annotatedSvc.name, "-n", annotatedSvc.namespace)
		o.Expect(createLoadBalancerService(oc, annotatedSvc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())

		compat_otp.By("7.3 Validate LoadBalancer service is assigned an IP")
		svcErr = checkLoadBalancerSvcStatus(oc, annotatedSvc.namespace, annotatedSvc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())
		svcIP1 := getLoadBalancerSvcIP(oc, annotatedSvc.namespace, annotatedSvc.name)
		e2e.Logf("The service %s External IP is %s", annotatedSvc.name, svcIP1)

		compat_otp.By("7.4 Create second L2 LoadBalancer service with annotation")
		annotatedSvc.name = "hello-world-" + testID + "-udp"
		annotatedSvc.annotationKey = annotationPrefix + "/allow-shared-ip"
		annotatedSvc.annotationValue = annotationForSvc
		annotatedSvc.protocol = "UDP"
		defer removeResource(oc, true, true, "service", annotatedSvc.name, "-n", annotatedSvc.namespace)
		o.Expect(createLoadBalancerService(oc, annotatedSvc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())

		compat_otp.By("7.5 Validate LoadBalancer service is assigned an IP")
		svcErr = checkLoadBalancerSvcStatus(oc, annotatedSvc.namespace, annotatedSvc.name)
		o.Expect(svcErr).NotTo(o.HaveOccurred())

		svcIP2 := getLoadBalancerSvcIP(oc, annotatedSvc.namespace, annotatedSvc.name)
		e2e.Logf("The service %s External IP is %s", annotatedSvc.name, svcIP2)
		o.Expect(svcIP1).To(o.BeEquivalentTo(svcIP2))

		compat_otp.By(fmt.Sprintf("7.6 Validate LoadBalancer services sharing the IP address %s", svcIP1))
		compat_otp.By(fmt.Sprintf("7.6.1 LoadBalancer service at IP address %s configured with TCP", svcIP1))

		checkSvcErr = wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 4*time.Minute, false, func(ctx context.Context) (bool, error) {
			result := validateService(oc, proxyHost, svcIP1)
			if result {
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(checkSvcErr, fmt.Sprintf("Expected service %s at %s to be reachable but was unreachable", annotatedSvc.name, svcIP))
		compat_otp.By(fmt.Sprintf("7.6.2 LoadBalancer service at IP address %s configured with UDP", svcIP2))
		allUdpSvcPods, getPodsErr := compat_otp.GetAllPodsWithLabel(oc, ns, "name="+annotatedSvc.name)
		o.Expect(getPodsErr).NotTo(o.HaveOccurred())
		compat_otp.By("Listen on port 80 on a backend pod of UDP service")
		e2e.Logf("Listening on pod %s", allUdpSvcPods[0])
		cmdNcat, cmdOutput, _, ncatCmdErr := oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", ns, allUdpSvcPods[0], "bash", "-c", `timeout --preserve-status 60 ncat -u -l 8080`).Background()
		defer cmdNcat.Process.Kill()
		o.Expect(ncatCmdErr).NotTo(o.HaveOccurred())

		allTcpSvcPods, getPodsErr := compat_otp.GetAllPodsWithLabel(oc, ns, "name=hello-world-"+testID+"-tcp")
		o.Expect(getPodsErr).NotTo(o.HaveOccurred())
		e2e.Logf("Sending UDP packets from pod %s to service %s", allTcpSvcPods[0], annotatedSvc.name)
		cmd := fmt.Sprintf("echo hello | ncat -v -u %s 80", svcIP2)
		for i := 0; i < 5; i++ {
			output, ncatCmdErr := execCommandInSpecificPod(oc, ns, allTcpSvcPods[0], cmd)
			o.Expect(ncatCmdErr).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(string(output), "bytes sent")).To(o.BeTrue())
		}
		e2e.Logf("UDP pod server output %s", cmdOutput)
		o.Expect(strings.Contains(cmdOutput.String(), "hello")).To(o.BeTrue())

	})

	//https://issues.redhat.com/browse/OCPBUGS-14769
	g.It("Author:asood-High-64809-[NETWORKCUSIM] ovnkube-node sends netlink delete request deleting conntrack entries for API redirect iptables rule [Serial]", func() {
		var (
			ns                   string
			namespaces           []string
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			interfaces           = [3]string{"br-ex", "eno1", "eno2"}
			workers              []string
			ipaddresspools       []string
			testID               = "64809"
		)

		compat_otp.By("1. Get API VIP for cluster and Node hosting the VIP")
		apiVIP := GetAPIVIPOnCluster(oc)
		if apiVIP == "" {
			g.Skip("This case requires API VIP to configured on the cluster")
		}
		apiVIPNode := FindVIPNode(oc, apiVIP)
		if apiVIPNode == "" {
			g.Skip("This case requires API VIP to configured on the cluster on one of nodes, found none")
		}
		e2e.Logf("API VIP %s on the cluster is configured on %s", apiVIP, apiVIPNode)

		compat_otp.By("2. Obtain the masters, workers and namespace")
		//Two worker nodes needed to create l2advertisement object
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}
		masterNodeList, err1 := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(err1).NotTo(o.HaveOccurred())
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test"+testID)

		compat_otp.By("3. Create IP addresspool")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-l2",
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 l2Addresses[0][:],
			namespaces:                namespaces[:],
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
			}
		}()
		result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)
		o.Expect(result).To(o.BeTrue())
		ipaddresspools = append(ipaddresspools, ipAddresspool.name)

		compat_otp.By("4. Create L2 Advertisement")
		l2AdvertisementTemplate := filepath.Join(testDataDir, "l2advertisement-template.yaml")
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv",
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: workers[:],
			template:           l2AdvertisementTemplate,
		}
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
			}
		}()
		result = createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())
		conntrackRulesCmd := fmt.Sprintf("conntrack -E -o timestamp | grep %s | grep DESTROY | grep -v CLOSE | grep 6443 | grep ESTABL", apiVIP)
		cmdContrackRulesdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("node/"+apiVIPNode, "--", "chroot", "/host", "bash", "-c", conntrackRulesCmd).Background()
		defer cmdContrackRulesdump.Process.Kill()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("5. Create LoadBalancer services using Layer 2 addresses")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
		svc := loadBalancerServiceResource{
			name:                          "",
			namespace:                     ns,
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: false,
			externaltrafficpolicy:         "Cluster",
			template:                      loadBalancerServiceTemplate,
		}

		for i := 0; i < 10; i++ {
			svc.name = "hello-world-" + testID + "-" + strconv.Itoa(i)
			compat_otp.By(fmt.Sprintf("Create a service %s with ExtenalTrafficPolicy Cluster", svc.name))
			result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
			o.Expect(result).To(o.BeTrue())
			compat_otp.By(fmt.Sprintf("Validate LoadBalancer service %s", svc.name))
			err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
			o.Expect(err).NotTo(o.HaveOccurred())
			svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
			e2e.Logf("LB service created with IP %s", svcIP)
			result = validateService(oc, masterNodeList[0], svcIP)
			o.Expect(result).To(o.BeTrue())
			compat_otp.By(fmt.Sprintf("DeleteLoadBalancer service %s", svc.name))
			removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)

		}
		e2e.Logf("Conntrack rules output \n%s", cmdOutput.String())
		o.Expect(strings.Contains(cmdOutput.String(), "")).Should(o.BeTrue())

	})

	g.It("Author:qiowang-High-51186-High-54819-Validate ipAddressPoolSelector, ipAddressPool and nodeSelector are honored when advertising service IP address with L2 advertisement [Serial]", func() {
		var (
			ns                                   string
			namespaces                           []string
			serviceSelectorKey                   = "environ"
			serviceSelectorValue                 = [1]string{"Test"}
			namespaceLabelKey                    = "region"
			namespaceLabelValue                  = [1]string{"NA"}
			ipAddressPoolSelectorsKey            = "zone"
			ipAddressPoolSelectorsValues         = [2][2]string{{"east"}, {"west"}}
			interfaces                           = [3]string{"br-ex", "eno1", "eno2"}
			workers                              []string
			ipaddresspools                       []string
			testID                               = "51186"
			expectedAddress1                     = "192.168.111.65"
			expectedAddress2                     = "192.168.111.75"
			ipAddresspoolTemplate                = filepath.Join(testDataDir, "ipaddresspool-template.yaml")
			l2AdvertisementTemplate              = filepath.Join(testDataDir, "l2advertisement-template.yaml")
			loadBalancerServiceAnnotatedTemplate = filepath.Join(testDataDir, "loadbalancer-svc-annotated-template.yaml")
		)

		compat_otp.By("1. Obtain the masters, workers and namespace")
		//Two worker nodes needed to create l2advertisement object
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}
		masterNodeList, err1 := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(err1).NotTo(o.HaveOccurred())
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test"+testID)

		compat_otp.By("2. Create two IP addresspools with different labels")
		for i := 0; i < 2; i++ {
			ipAddresspool := ipAddressPoolResource{
				name:                      "ipaddresspool-l2-" + testID + "-" + strconv.Itoa(i),
				namespace:                 opNamespace,
				addresses:                 l2Addresses[i][:],
				namespaces:                namespaces,
				label1:                    ipAddressPoolSelectorsKey,
				value1:                    ipAddressPoolSelectorsValues[i][0],
				priority:                  10,
				avoidBuggyIPs:             true,
				autoAssign:                true,
				serviceLabelKey:           serviceSelectorKey,
				serviceLabelValue:         serviceSelectorValue[0],
				serviceSelectorKey:        serviceSelectorKey,
				serviceSelectorOperator:   "In",
				serviceSelectorValue:      serviceSelectorValue[:],
				namespaceLabelKey:         namespaceLabelKey,
				namespaceLabelValue:       namespaceLabelValue[0],
				namespaceSelectorKey:      namespaceLabelKey,
				namespaceSelectorOperator: "In",
				namespaceSelectorValue:    namespaceLabelValue[:],
				template:                  ipAddresspoolTemplate,
			}
			defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
			o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
			ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		}

		compat_otp.By("3. Create L2Advertisement with ipAddressPool and nodeSelectors")
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv" + testID,
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: workers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		o.Expect(createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)).To(o.BeTrue())

		compat_otp.By("4. Create LoadBalancer services using Layer 2 addresses")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-cluster",
			namespace:                     ns,
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			annotationKey:                 annotationPrefix + "/address-pool",
			annotationValue:               ipaddresspools[0],
			allocateLoadBalancerNodePorts: serviceNodePortAllocation,
			template:                      loadBalancerServiceAnnotatedTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
		statusErr := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(statusErr).NotTo(o.HaveOccurred())

		compat_otp.By("5. Check IP address assigned from addresspool, and advertised only on one of the node listed in l2advertisements")
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress1)).To(o.BeTrue())
		o.Expect(validateService(oc, masterNodeList[0], svcIP)).To(o.BeTrue())
		nodeName := getNodeAnnouncingL2Service(oc, svc.name, svc.namespace)
		e2e.Logf("Node %s announcing the service IP", nodeName)
		o.Expect(nodeName).Should(o.Or(o.Equal(workers[0]), o.Equal(workers[1])))

		compat_otp.By("6. Remove the previously created services")
		removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		removeResource(oc, true, true, "replicationcontroller", svc.name, "-n", svc.namespace)

		compat_otp.By("7. Update L2Advertisement, update ipAddressPool and nodeSelectors, add ipAddressPoolSelectors")
		patchL2Advertisement := `[{"op": "replace", "path": "/spec/ipAddressPools", "value": [""]}, {"op": "replace", "path": "/spec/nodeSelectors/0/matchExpressions/0/values", "value":["` + workers[1] + `"]}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", opNamespace, "l2advertisement", l2advertisement.name, "--type=json", "-p", patchL2Advertisement).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		patchIPAddrPoolSelectors := `{"spec":{"ipAddressPoolSelectors":[{"matchExpressions": [{"key": "` + ipAddressPoolSelectorsKey + `","operator": "In","values": ["` + ipAddressPoolSelectorsValues[1][0] + `"]}]}]}}`
		patchResourceAsAdmin(oc, "l2advertisement/"+l2advertisement.name, patchIPAddrPoolSelectors, "metallb-system")

		compat_otp.By("8. Create LoadBalancer services requesting address from the second ipaddresspools")
		svc.annotationValue = ipaddresspools[1]
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
		statusErr = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(statusErr).NotTo(o.HaveOccurred())

		compat_otp.By("9. Check IP address assigned from the second addresspool, and advertised only on one of the node listed in l2advertisements")
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress2)).To(o.BeTrue())
		o.Expect(validateService(oc, masterNodeList[0], svcIP)).To(o.BeTrue())
		nodeName = getNodeAnnouncingL2Service(oc, svc.name, svc.namespace)
		e2e.Logf("Node %s announcing the service IP", nodeName)
		o.Expect(nodeName).Should(o.Equal(workers[1]))

		compat_otp.By("10. OCP-54819-Add label to the first worker node")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[0], "zone")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[0], "zone", "east")

		compat_otp.By("11. OCP-54819-Edit the l2advertisement to modify the node selection")
		patchL2Advertisement = `[{"op": "replace", "path": "/spec/nodeSelectors/0/matchExpressions/0/key", "value":"zone"}, {"op": "replace", "path": "/spec/nodeSelectors/0/matchExpressions/0/values", "value":["east"]}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", opNamespace, "l2advertisement", l2advertisement.name, "--type=json", "-p", patchL2Advertisement).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		compat_otp.By("12. OCP-54819-Check the changes to nodeSelector in L2advertisements are reflected where the service IP is announced")
		nodeName = getNodeAnnouncingL2Service(oc, svc.name, svc.namespace)
		e2e.Logf("Node %s announcing the service IP", nodeName)
		o.Expect(nodeName).Should(o.Equal(workers[0]))
	})

	g.It("Author:meinli-High-43243-The L2 service with externalTrafficPolicy Local continues to service requests even when node announcing the service goes down. [Disruptive]", func() {
		var (
			buildPruningBaseDir     = testdata.FixturePath("networking")
			ipAddresspoolFile       = filepath.Join(testDataDir, "ipaddresspool-template.yaml")
			l2AdvertisementTemplate = filepath.Join(testDataDir, "l2advertisement-template.yaml")
			pingPodNodeTemplate     = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			genericServiceTemplate  = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			ipaddresspools          []string
			namespaces              []string
			serviceSelectorKey      = "name"
			serviceSelectorValue    = [1]string{"test-service"}
			namespaceLabelKey       = "region"
			namespaceLabelValue     = [1]string{"NA"}
			interfaces              = [3]string{"br-ex", "eno1", "eno2"}
		)

		compat_otp.By("1. Get the namespace, masters and workers")
		workerList := excludeSriovNodes(oc)
		if len(workerList) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than three nodes")
		}

		ns := oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test43243")

		compat_otp.By("2. create address pool with addresses from worker nodes")
		for i := 0; i < 2; i++ {
			ipAddresspool := ipAddressPoolResource{
				name:                      "ipaddresspool-l2-" + strconv.Itoa(i),
				namespace:                 opNamespace,
				label1:                    ipAddressPoolLabelKey,
				value1:                    ipAddressPoolLabelVal,
				addresses:                 l2Addresses[i][:],
				namespaces:                namespaces[:],
				priority:                  10,
				avoidBuggyIPs:             true,
				autoAssign:                true,
				serviceLabelKey:           serviceSelectorKey,
				serviceLabelValue:         serviceSelectorValue[0],
				serviceSelectorKey:        serviceSelectorKey,
				serviceSelectorOperator:   "In",
				serviceSelectorValue:      serviceSelectorValue[:],
				namespaceLabelKey:         namespaceLabelKey,
				namespaceLabelValue:       namespaceLabelValue[0],
				namespaceSelectorKey:      namespaceLabelKey,
				namespaceSelectorOperator: "In",
				namespaceSelectorValue:    namespaceLabelValue[:],
				template:                  ipAddresspoolFile,
			}
			defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
			result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolFile)
			o.Expect(result).To(o.BeTrue())
			ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		}
		e2e.Logf("IP address pools %s ", ipaddresspools)

		compat_otp.By("3. create a L2 advertisement using the above addresspool")
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv",
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[:],
			nodeSelectorValues: workerList[:],
			interfaces:         interfaces[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		result := createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("4. create a service with externalTrafficPolicy Local")
		for i := 0; i < 2; i++ {
			pod := pingPodResourceNode{
				name:      "hello-pod-" + strconv.Itoa(i),
				namespace: ns,
				nodename:  workerList[i],
				template:  pingPodNodeTemplate,
			}
			pod.createPingPodNode(oc)
			waitPodReady(oc, ns, pod.name)
		}
		svc := genericServiceResource{
			servicename:           "test-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "hello-pod",
			serviceType:           "LoadBalancer",
			ipFamilyPolicy:        "SingleStack",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "Local",
			template:              genericServiceTemplate,
		}
		svc.createServiceFromParams(oc)
		err := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.servicename)
		o.Expect(err).NotTo(o.HaveOccurred())

		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.servicename)
		e2e.Logf("The service %s External IP is %q", svc.servicename, svcIP)
		result = validateService(oc, proxyHost, svcIP+":27017")
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("5. Validate service IP announcement being taken over by another node")
		nodeName1 := getNodeAnnouncingL2Service(oc, svc.servicename, ns)
		defer checkNodeStatus(oc, nodeName1, "Ready")
		rebootNode(oc, nodeName1)
		checkNodeStatus(oc, nodeName1, "NotReady")
		nodeName2 := getNodeAnnouncingL2Service(oc, svc.servicename, ns)
		o.Expect(strings.Join(workerList, ",")).Should(o.ContainSubstring(nodeName2))
		if nodeName2 != nodeName1 {
			e2e.Logf("%s worker node taken over the service successfully!!!", nodeName2)
		} else {
			e2e.Fail("No worker node taken over the service after reboot")
		}
		// verify the service request after another worker nodeAssigned
		for i := 0; i < 2; i++ {
			o.Expect(validateService(oc, proxyHost, svcIP+":27017")).To(o.BeTrue())
		}
	})

	g.It("Author:meinli-High-43242-The L2 service with externalTrafficPolicy Cluster continues to service requests even when node announcing the service goes down. [Disruptive]", func() {
		var (
			ipAddresspoolFile           = filepath.Join(testDataDir, "ipaddresspool-template.yaml")
			loadBalancerServiceTemplate = filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
			l2AdvertisementTemplate     = filepath.Join(testDataDir, "l2advertisement-template.yaml")
			ipaddresspools              []string
			namespaces                  []string
			serviceSelectorKey          = "environ"
			serviceSelectorValue        = [1]string{"Test"}
			namespaceLabelKey           = "region"
			namespaceLabelValue         = [1]string{"NA"}
			interfaces                  = [3]string{"br-ex", "eno1", "eno2"}
		)

		compat_otp.By("1. Get the namespace, masters and workers")
		workerList := excludeSriovNodes(oc)
		if len(workerList) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		ns := oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test43242")

		compat_otp.By("2. create address pool with addresses from worker nodes")
		for i := 0; i < 2; i++ {
			ipAddresspool := ipAddressPoolResource{
				name:                      "ipaddresspool-l2-" + strconv.Itoa(i),
				namespace:                 opNamespace,
				label1:                    ipAddressPoolLabelKey,
				value1:                    ipAddressPoolLabelVal,
				addresses:                 l2Addresses[i][:],
				namespaces:                namespaces[:],
				priority:                  10,
				avoidBuggyIPs:             true,
				autoAssign:                true,
				serviceLabelKey:           serviceSelectorKey,
				serviceLabelValue:         serviceSelectorValue[0],
				serviceSelectorKey:        serviceSelectorKey,
				serviceSelectorOperator:   "In",
				serviceSelectorValue:      serviceSelectorValue[:],
				namespaceLabelKey:         namespaceLabelKey,
				namespaceLabelValue:       namespaceLabelValue[0],
				namespaceSelectorKey:      namespaceLabelKey,
				namespaceSelectorOperator: "In",
				namespaceSelectorValue:    namespaceLabelValue[:],
				template:                  ipAddresspoolFile,
			}
			defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
			result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolFile)
			o.Expect(result).To(o.BeTrue())
			ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		}
		e2e.Logf("IP address pools %s ", ipaddresspools)

		compat_otp.By("3. create a L2 advertisement using the above addresspool")
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv",
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[:],
			nodeSelectorValues: workerList[:],
			interfaces:         interfaces[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		result := createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("4. create a service with externalTrafficPolicy Cluster")
		svc := loadBalancerServiceResource{
			name:                          "test-rc",
			namespace:                     ns,
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			externaltrafficpolicy:         "Cluster",
			allocateLoadBalancerNodePorts: false,
			template:                      loadBalancerServiceTemplate,
		}
		result = createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)
		o.Expect(result).To(o.BeTrue())
		err := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())

		err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("rc", "test-rc", "--replicas=10", "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = waitForPodWithLabelReady(oc, ns, "name="+svc.name)
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("this pod with label name=%s not ready", svc.name))

		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %q", svc.name, svcIP)
		result = validateService(oc, proxyHost, svcIP+":80")
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("5. Validate service IP announcement being taken over by another node")
		nodeName1 := getNodeAnnouncingL2Service(oc, svc.name, ns)
		defer checkNodeStatus(oc, nodeName1, "Ready")
		rebootNode(oc, nodeName1)
		checkNodeStatus(oc, nodeName1, "NotReady")
		nodeName2 := getNodeAnnouncingL2Service(oc, svc.name, ns)
		o.Expect(strings.Join(workerList, ",")).Should(o.ContainSubstring(nodeName2))
		if nodeName2 != nodeName1 {
			e2e.Logf("%s worker node taker over the service successfully!!!", nodeName2)
		} else {
			e2e.Fail("No worker node taker over the service after reboot")
		}
		// verify the service request after another worker nodeAssigned
		for i := 0; i < 2; i++ {
			o.Expect(validateService(oc, proxyHost, svcIP+":80")).To(o.BeTrue())
		}
	})
})

// L3 Tests
var _ = g.Describe("[OTP][sig-networking] SDN metallb l3", func() {
	defer g.GinkgoRecover()

	var (
		oc                       = compat_otp.NewCLI("networking-metallb", compat_otp.KubeConfigPath())
		opNamespace              = "metallb-system"
		opName                   = "metallb-operator"
		catalogNamespace         = "openshift-marketplace"
		catalogSourceName        = "metallb-operator-fbc-catalog"
		imageDigestMirrorSetName = "metallb-images-mirror-set"
		serviceLabelKey          = "environ"
		serviceLabelValue        = "Test"
		testDataDir              = testdata.FixturePath("networking/metallb")
		bgpAddresses             = [2][2]string{{"10.10.10.0-10.10.10.10", "10.10.11.1-10.10.11.10"}, {"10.10.12.1-10.10.12.10", "10.10.13.1-10.10.13.10"}}
		myASN                    = 64512
		peerASN                  = 64500
		peerIPAddress            = "192.168.111.60"
		bgpCommunties            = [1]string{"65001:65500"}
		metalLBNodeSelKey        = "node-role.kubernetes.io/worker"
		metalLBNodeSelVal        = ""
		metalLBControllerSelKey  = "node-role.kubernetes.io/worker"
		metalLBControllerSelVal  = ""
		ipAddressPoolLabelKey    = "zone"
		ipAddressPoolLabelVal    = "east"
		annotationPrefix         = "metallb.io"
	)

	g.BeforeEach(func() {
		compat_otp.By("Check the platform if it is suitable for running the test")
		networkType := compat_otp.CheckNetworkType(oc)
		if !(isRDUPlatformSuitable(oc)) || !strings.Contains(networkType, "ovn") {
			g.Skip("These cases can only be run on networking team's private BM RDU clusters , skip for other platform or other non-OVN network plugin!!!")
		}

		namespaceTemplate := filepath.Join(testDataDir, "namespace-template.yaml")
		operatorGroupTemplate := filepath.Join(testDataDir, "operatorgroup-template.yaml")
		subscriptionTemplate := filepath.Join(testDataDir, "subscription-template.yaml")
		catalogSourceTemplate := filepath.Join(testDataDir, "catalogsource-template.yaml")
		imageDigestMirrorSetFile := filepath.Join(testDataDir, "image-digest-mirrorset.yaml")
		sub := subscriptionResource{
			name:             "metallb-operator-sub",
			namespace:        opNamespace,
			operatorName:     opName,
			channel:          "stable",
			catalog:          catalogSourceName,
			catalogNamespace: catalogNamespace,
			template:         subscriptionTemplate,
		}
		ns := namespaceResource{
			name:     opNamespace,
			template: namespaceTemplate,
		}
		og := operatorGroupResource{
			name:             opName,
			namespace:        opNamespace,
			targetNamespaces: opNamespace,
			template:         operatorGroupTemplate,
		}
		catalogSourceName = setupOperatorCatalogSource(oc, "metallb", catalogSourceName, imageDigestMirrorSetName, catalogNamespace, imageDigestMirrorSetFile, catalogSourceTemplate)
		sub.catalog = catalogSourceName
		operatorInstall(oc, sub, ns, og)
		compat_otp.By("Making sure CRDs are successfully installed")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "bfdprofiles.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgpadvertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgppeers.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "communities.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "ipaddresspools.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "l2advertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "metallbs.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrconfigurations.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrnodestates.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "servicel2statuses.metallb.io")).To(o.BeTrue())

		compat_otp.By("Create MetalLB CR")
		metallbCRTemplate := filepath.Join(testDataDir, "metallb-cr-template.yaml")
		metallbCR := metalLBCRResource{
			name:                  "metallb",
			namespace:             opNamespace,
			nodeSelectorKey:       metalLBNodeSelKey,
			nodeSelectorVal:       metalLBNodeSelVal,
			controllerSelectorKey: metalLBControllerSelKey,
			controllerSelectorVal: metalLBControllerSelVal,
			template:              metallbCRTemplate,
		}
		o.Expect(createMetalLBCR(oc, metallbCR, metallbCRTemplate)).To(o.BeTrue())
		compat_otp.By("SUCCESS - MetalLB CR Created")

	})

	g.It("Author:asood-High-60097-High-60098-High-60099-High-60159-Verify ip address is assigned from the ip address pool that has higher priority (lower value), matches namespace, service name or the annotated IP pool in service [Serial]", func() {
		var (
			ns                   string
			namespaces           []string
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			workers              []string
			ipaddrpools          []string
			bgpPeers             []string
			bgpPassword          string
			expectedAddress1     = "10.10.10.1"
			expectedAddress2     = "10.10.12.1"
		)

		//Two worker nodes needed to create BGP Advertisement object
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}
		compat_otp.By("1. Get the namespace")
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test60097")

		compat_otp.By("2. Set up upstream/external BGP router")
		suffix := getRandomString()
		bgpRouterNamespaceWithSuffix := bgpRouterNamespace + "-" + suffix
		defer oc.DeleteSpecifiedNamespaceAsAdmin(bgpRouterNamespaceWithSuffix)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", bgpRouterPodName, "-n", bgpRouterNamespaceWithSuffix).Execute()
		o.Expect(setUpExternalFRRRouter(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("3. Create BGP Peer")
		BGPPeerTemplate := filepath.Join(testDataDir, "bgppeer-template.yaml")
		BGPPeerCR := bgpPeerResource{
			name:          "peer-64500",
			namespace:     opNamespace,
			holdTime:      "30s",
			keepAliveTime: "10s",
			password:      bgpPassword,
			myASN:         myASN,
			peerASN:       peerASN,
			peerAddress:   peerIPAddress,
			template:      BGPPeerTemplate,
		}
		defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
		bgpPeers = append(bgpPeers, BGPPeerCR.name)
		o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())
		compat_otp.By("4. Check BGP Session between speakers and Router")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("5. Create IP addresspools with different priority")
		priority_val := 10
		for i := 0; i < 2; i++ {
			ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
			ipAddresspool := ipAddressPoolResource{
				name:                      "ipaddresspool-l3-" + strconv.Itoa(i),
				namespace:                 opNamespace,
				label1:                    ipAddressPoolLabelKey,
				value1:                    ipAddressPoolLabelVal,
				addresses:                 bgpAddresses[i][:],
				namespaces:                namespaces,
				priority:                  priority_val,
				avoidBuggyIPs:             true,
				autoAssign:                true,
				serviceLabelKey:           serviceSelectorKey,
				serviceLabelValue:         serviceSelectorValue[0],
				serviceSelectorKey:        serviceSelectorKey,
				serviceSelectorOperator:   "In",
				serviceSelectorValue:      serviceSelectorValue[:],
				namespaceLabelKey:         namespaceLabelKey,
				namespaceLabelValue:       namespaceLabelValue[0],
				namespaceSelectorKey:      namespaceLabelKey,
				namespaceSelectorOperator: "In",
				namespaceSelectorValue:    namespaceLabelValue[:],
				template:                  ipAddresspoolTemplate,
			}
			defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
			o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
			priority_val = priority_val + 10
			ipaddrpools = append(ipaddrpools, ipAddresspool.name)
		}

		compat_otp.By("6. Create BGP Advertisement")
		bgpAdvertisementTemplate := filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv",
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        ipaddrpools[:],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())
		addrPoolList, err := json.Marshal(ipaddrpools)
		o.Expect(err).NotTo(o.HaveOccurred())
		patchIPAddresspools := fmt.Sprintf("{\"spec\":{\"ipAddressPools\": %s}}", string(addrPoolList))
		patchResourceAsAdmin(oc, "bgpadvertisements/"+bgpAdvertisement.name, patchIPAddresspools, "metallb-system")

		compat_otp.By("7. Create a service to verify it is assigned address from the pool that has higher priority")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-60097",
			namespace:                     namespaces[0],
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP for OCP-60097 test case is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress1)).To(o.BeTrue())

		compat_otp.By("OCP-60098 Verify ip address from pool is assigned only to the service in project matching namespace or namespaceSelector in ip address pool.")
		compat_otp.By("8.0 Update first ipaddress pool's the match label and match expression for the namespace property")
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddrpools[0], "{\"spec\":{\"serviceAllocation\": {\"namespaceSelectors\": [{\"matchExpressions\": [{\"key\": \"region\", \"operator\": \"In\", \"values\": [\"SA\"]}]}, {\"matchLabels\": {\"environ\": \"Dev\"}}]}}}", "metallb-system")

		compat_otp.By("8.1 Update first ipaddress pool's priority")
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddrpools[0], "{\"spec\":{\"serviceAllocation\": {\"priority\": 20}}}", "metallb-system")

		compat_otp.By("8.2 Update first ipaddress pool's namespaces property")
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddrpools[0], "{\"spec\":{\"serviceAllocation\": {\"namespaces\": []}}}", "metallb-system")

		compat_otp.By("9. Label the namespace")
		_, errNs := oc.AsAdmin().Run("label").Args("namespace", ns, "environ=Test", "--overwrite").Output()
		o.Expect(errNs).NotTo(o.HaveOccurred())
		_, errNs = oc.AsAdmin().Run("label").Args("namespace", ns, "region=NA").Output()
		o.Expect(errNs).NotTo(o.HaveOccurred())

		compat_otp.By("10. Delete the service in namespace and recreate it to see the address assigned from the pool that matches namespace selector")
		removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		svc.name = "hello-world-60098"
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP for OCP-60098 test case is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress2)).To(o.BeTrue())

		compat_otp.By("OCP-60099 Verify ip address from pool is assigned only to the service matching serviceSelector in ip address pool")
		compat_otp.By("11.0 Update second ipaddress pool's the match label and match expression for the namespace property")
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddrpools[1], "{\"spec\":{\"serviceAllocation\": {\"namespaceSelectors\": [{\"matchExpressions\": [{\"key\": \"region\", \"operator\": \"In\", \"values\": [\"SA\"]}]}, {\"matchLabels\": {\"environ\": \"Dev\"}}]}}}", "metallb-system")

		compat_otp.By("11.1 Update second ipaddress pool's namesapces")
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddrpools[1], "{\"spec\":{\"serviceAllocation\": {\"namespaces\": []}}}", "metallb-system")

		compat_otp.By("11.2 Update second ipaddress pool's service selector")
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddrpools[1], "{\"spec\":{\"serviceAllocation\": {\"serviceSelectors\": [{\"matchExpressions\": [{\"key\": \"environ\", \"operator\": \"In\", \"values\": [\"Dev\"]}]}]}}}", "metallb-system")

		compat_otp.By("12. Delete the service in namespace and recreate it to see the address assigned from the pool that matches namespace selector")
		removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)

		svc.name = "hello-world-60099"
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP for OCP-60099 test case is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress1)).To(o.BeTrue())

		compat_otp.By(fmt.Sprintf("OCP-60159 Verify the ip address annotation in service %s/address-pool in namepace overrides the priority and service selectors in ip address pool.", annotationPrefix))
		compat_otp.By("13. Delete the service  created in namespace to ensure eligible IP address is released")
		removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)

		compat_otp.By("14. Update the priority on second address to be eligible for address assignment")
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipaddrpools[1], "{\"spec\":{\"serviceAllocation\": {\"priority\": 10}}}", "metallb-system")

		compat_otp.By("15. Label the namespace to ensure the both addresspools are eligible for address assignment")
		_, errNs = oc.AsAdmin().Run("label").Args("namespace", ns, "environ=Dev", "--overwrite").Output()
		o.Expect(errNs).NotTo(o.HaveOccurred())
		_, errNs = oc.AsAdmin().Run("label").Args("namespace", ns, "region=SA", "--overwrite").Output()
		o.Expect(errNs).NotTo(o.HaveOccurred())

		compat_otp.By("16. Create a service with annotation to obtain IP from first addresspool")
		loadBalancerServiceAnnotatedTemplate := filepath.Join(testDataDir, "loadbalancer-svc-annotated-template.yaml")
		svc = loadBalancerServiceResource{
			name:                          "hello-world-60159",
			namespace:                     namespaces[0],
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceSelectorKey,
			labelValue:                    serviceSelectorValue[0],
			annotationKey:                 annotationPrefix + "/address-pool",
			annotationValue:               ipaddrpools[0],
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceAnnotatedTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP for OCP-60159 test case is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress1)).To(o.BeTrue())

	})

	g.It("Author:asood-High-50946-Medium-69612-Verify .0 and .255 addresses in IPAddressPool are handled with avoidBuggIPs and MetalLB exposes password in clear text [Serial]", func() {
		var (
			ns                    string
			namespaces            []string
			serviceSelectorKey    = "environ"
			serviceSelectorValue  = [1]string{"Test"}
			namespaceLabelKey     = "region"
			namespaceLabelValue   = [1]string{"NA"}
			workers               []string
			ipaddrpools           []string
			bgpPeers              []string
			testID                = "50946"
			ipAddressList         = [3]string{"10.10.10.0-10.10.10.0", "10.10.10.255-10.10.10.255", "10.10.10.1-10.10.10.1"}
			expectedIPAddressList = [3]string{"10.10.10.0", "10.10.10.255", "10.10.10.1"}
			bgpPassword           string
		)

		//Two worker nodes needed to create BGP Advertisement object
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has at least two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}
		compat_otp.By("1. Get the namespace")
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test"+testID)
		compat_otp.By("Label the namespace")
		_, errNs := oc.AsAdmin().Run("label").Args("namespace", ns, namespaceLabelKey+"="+namespaceLabelValue[0], "--overwrite").Output()
		o.Expect(errNs).NotTo(o.HaveOccurred())

		compat_otp.By("2. Set up upstream/external BGP router")
		suffix := getRandomString()
		bgpRouterNamespaceWithSuffix := bgpRouterNamespace + "-" + suffix
		defer oc.DeleteSpecifiedNamespaceAsAdmin(bgpRouterNamespaceWithSuffix)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", bgpRouterPodName, "-n", bgpRouterNamespaceWithSuffix, "--ignore-not-found").Execute()
		bgpPassword = "bgp-test"
		o.Expect(setUpExternalFRRRouter(oc, bgpRouterNamespaceWithSuffix, bgpPassword)).To(o.BeTrue())

		compat_otp.By("3. Create BGP Peer")
		BGPPeerTemplate := filepath.Join(testDataDir, "bgppeer-template.yaml")
		BGPPeerCR := bgpPeerResource{
			name:          "peer-64500",
			namespace:     opNamespace,
			holdTime:      "30s",
			keepAliveTime: "10s",
			password:      bgpPassword,
			myASN:         myASN,
			peerASN:       peerASN,
			peerAddress:   peerIPAddress,
			template:      BGPPeerTemplate,
		}
		defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
		bgpPeers = append(bgpPeers, BGPPeerCR.name)
		o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())
		compat_otp.By("4. Check BGP Session between speakers and Router")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("5. Create IP addresspools with three addresses, including two buggy ones")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-l3-" + testID,
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 ipAddressList[:],
			namespaces:                namespaces[:],
			priority:                  0,
			avoidBuggyIPs:             false,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
		ipaddrpools = append(ipaddrpools, ipAddresspool.name)

		compat_otp.By("6. Create BGP Advertisement")
		bgpAdvertisementTemplate := filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv",
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        ipaddrpools[:],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())

		compat_otp.By("7. Create  services to verify it is assigned buggy IP addresses")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
		for i := 0; i < 2; i++ {
			svc := loadBalancerServiceResource{
				name:                          "hello-world-" + testID + "-" + strconv.Itoa(i),
				namespace:                     namespaces[0],
				externaltrafficpolicy:         "Cluster",
				labelKey:                      serviceLabelKey,
				labelValue:                    serviceLabelValue,
				allocateLoadBalancerNodePorts: true,
				template:                      loadBalancerServiceTemplate,
			}
			o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
			err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
			o.Expect(err).NotTo(o.HaveOccurred())
			svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
			e2e.Logf("The service %s External IP is %q", svc.name, svcIP)
			o.Expect(strings.Contains(svcIP, expectedIPAddressList[i])).To(o.BeTrue())
		}
		compat_otp.By("8. Delete the previously created services and set avoidBuggyIP to true in ip address pool")
		for i := 0; i < 2; i++ {
			removeResource(oc, true, true, "service", "hello-world-"+testID+"-"+strconv.Itoa(i), "-n", namespaces[0])
		}
		addressList, err := json.Marshal(ipAddressList)
		o.Expect(err).NotTo(o.HaveOccurred())
		patchInfo := fmt.Sprintf("{\"spec\":{\"avoidBuggyIPs\": true, \"addresses\": %s}}", string(addressList))
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipAddresspool.name, patchInfo, "metallb-system")

		compat_otp.By("9. Verify the service is created with ip address that is not a buggy")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-" + testID + "-3",
			namespace:                     namespaces[0],
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s External IP is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedIPAddressList[2])).To(o.BeTrue())

		compat_otp.By("10. OCPBUGS-3825 Check BGP password is not in clear text")
		frrExternalProviderNS := "openshift-frr-k8s"
		//https://issues.redhat.com/browse/OCPBUGS-3825
		podList, podListErr := compat_otp.GetAllPodsWithLabel(oc, frrExternalProviderNS, "component=frr-k8s")
		o.Expect(podListErr).NotTo(o.HaveOccurred())
		o.Expect(len(podList)).NotTo(o.Equal(0))
		searchString := fmt.Sprintf("neighbor '%s' password <retracted>", peerIPAddress)
		for _, pod := range podList {
			output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", frrExternalProviderNS, pod, "-c", "reloader").OutputToFile("podlog")
			o.Expect(err).NotTo(o.HaveOccurred())
			grepOutput, err := exec.Command("bash", "-c", "cat "+output+" | grep -i '"+searchString+"' | wc -l").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("Found %s occurences in logs of %s pod", grepOutput, pod)
			o.Expect(grepOutput).NotTo(o.Equal(0))

		}

	})

	g.It("Author:qiowang-High-46652-Verify LoadBalancer service can be created running at Layer 3 using BGP peering with BFD profile [Serial]", func() {
		var (
			workers                     []string
			ipaddresspools              []string
			bgpPeers                    []string
			namespaces                  []string
			expectedHostPrefixes        []string
			bgpPassword                 string
			expectedAddress1            = "10.10.10.1"
			bfdEnabled                  = "yes"
			serviceSelectorKey          = "environ"
			serviceSelectorValue        = [1]string{"Test"}
			namespaceLabelKey           = "region"
			namespaceLabelValue         = [1]string{"NA"}
			BFDProfileTemplate          = filepath.Join(testDataDir, "bfdprofile-template.yaml")
			ipAddresspoolTemplate       = filepath.Join(testDataDir, "ipaddresspool-template.yaml")
			BGPPeerTemplate             = filepath.Join(testDataDir, "bgppeer-template.yaml")
			bgpAdvertisementTemplate    = filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
			loadBalancerServiceTemplate = filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
		)

		//Two worker nodes needed to create BGP Advertisement object
		workerList, getWorkersErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(getWorkersErr).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run on cluster that has at least two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}

		compat_otp.By("1. Create BFD profile")
		BFDProfileCR := bfdProfileResource{
			name:                 "bfd-profile-46652",
			namespace:            opNamespace,
			detectMultiplier:     37,
			echoMode:             true,
			echoReceiveInterval:  38,
			echoTransmitInterval: 39,
			minimumTtl:           10,
			passiveMode:          true,
			receiveInterval:      35,
			transmitInterval:     35,
			template:             BFDProfileTemplate,
		}
		defer removeResource(oc, true, true, "bfdprofile", BFDProfileCR.name, "-n", BFDProfileCR.namespace)
		o.Expect(createBFDProfileCR(oc, BFDProfileCR)).To(o.BeTrue())

		compat_otp.By("2. Set up upstream/external BGP router, enable BFD")
		suffix := getRandomString()
		bgpRouterNamespaceWithSuffix := bgpRouterNamespace + "-" + suffix
		defer oc.DeleteSpecifiedNamespaceAsAdmin(bgpRouterNamespaceWithSuffix)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", bgpRouterPodName, "-n", bgpRouterNamespaceWithSuffix, "--ignore-not-found").Execute()
		bgpPassword = ""
		o.Expect(setUpExternalFRRRouter(oc, bgpRouterNamespaceWithSuffix, bgpPassword, bfdEnabled, BFDProfileCR.name)).To(o.BeTrue())

		compat_otp.By("3. Create IP addresspool")
		ns := oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test46652")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-bgp-46652",
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 bgpAddresses[0][:],
			namespaces:                namespaces,
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)
		o.Expect(result).To(o.BeTrue())
		ipaddresspools = append(ipaddresspools, ipAddresspool.name)

		compat_otp.By("4. Create BGP Peer")
		BGPPeerCR := bgpPeerResource{
			name:          "peer-64500",
			namespace:     opNamespace,
			holdTime:      "30s",
			keepAliveTime: "10s",
			password:      "",
			myASN:         myASN,
			peerASN:       peerASN,
			peerAddress:   peerIPAddress,
			template:      BGPPeerTemplate,
		}
		defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
		o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())
		bgpPeers = append(bgpPeers, BGPPeerCR.name)

		compat_otp.By("5. Patch the BGPPeer with BFD Profile")
		patchBFDProfile := fmt.Sprintf("{\"spec\":{\"bfdProfile\": \"%s\"}}", BFDProfileCR.name)
		patchResourceAsAdmin(oc, "bgppeer/"+BGPPeerCR.name, patchBFDProfile, "metallb-system")

		compat_otp.By("6. Create BGP Advertisement")
		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv-46652",
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        ipaddresspools[:],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())

		compat_otp.By("7. Check BGP Session between speakers and Router")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("8. Check BFD Session is up")
		o.Expect(checkBFDSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("9. Create a service")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-46652",
			namespace:                     ns,
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
		statusErr := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(statusErr).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP for OCP-46652 test case is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress1)).To(o.BeTrue())
		masterNodeList, getMastersErr := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(getMastersErr).NotTo(o.HaveOccurred())
		result = validateService(oc, masterNodeList[0], svcIP)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("10. Verify route is advertised")
		expectedHostPrefixes = append(expectedHostPrefixes, expectedAddress1+"/32")
		o.Expect(verifyHostPrefixAdvertised(oc, bgpRouterNamespaceWithSuffix, expectedHostPrefixes)).To(o.BeTrue())
	})

	g.It("Author:asood-High-50945-Verify the L2 and L3 IP address can be assigned to services respectively from the IP address pool based on the advertisement.[Serial]", func() {
		var (
			testID                               = "50945"
			workers                              []string
			bgpPeers                             []string
			namespaces                           []string
			ipaddresspools                       = make(map[int][]string)
			expectedHostPrefixes                 []string
			bgpPassword                          string
			serviceSelectorKey                   = "environ"
			serviceSelectorValue                 = [1]string{"Test"}
			namespaceLabelKey                    = "region"
			namespaceLabelValue                  = [1]string{"NA"}
			ipAddresspoolTemplate                = filepath.Join(testDataDir, "ipaddresspool-template.yaml")
			BGPPeerTemplate                      = filepath.Join(testDataDir, "bgppeer-template.yaml")
			bgpAdvertisementTemplate             = filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
			l2AdvertisementTemplate              = filepath.Join(testDataDir, "l2advertisement-template.yaml")
			loadBalancerServiceAnnotatedTemplate = filepath.Join(testDataDir, "loadbalancer-svc-annotated-template.yaml")
			loadBalancerServiceTemplate          = filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
			l2Addresses                          = [2][2]string{{"192.168.111.65-192.168.111.69", "192.168.111.70-192.168.111.74"}, {"192.168.111.75-192.168.111.79", "192.168.111.80-192.168.111.85"}}
			interfaces                           = [3]string{"br-ex", "eno1", "eno2"}
			expectedAddressList                  = [2]string{"10.10.10.1", "192.168.111.65"}
		)

		//Two worker nodes needed to create BGP Advertisement object
		workerList, getWorkersErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(getWorkersErr).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run on cluster that has at least two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
		}

		compat_otp.By("1. Get the namespace")
		ns := oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test"+testID)
		compat_otp.By("Label the namespace")
		_, errNsLabel := oc.AsAdmin().Run("label").Args("namespace", ns, namespaceLabelKey+"="+namespaceLabelValue[0], "--overwrite").Output()
		o.Expect(errNsLabel).NotTo(o.HaveOccurred())

		compat_otp.By("2. Set up upstream/external BGP router")
		suffix := getRandomString()
		bgpRouterNamespaceWithSuffix := bgpRouterNamespace + "-" + suffix
		defer oc.DeleteSpecifiedNamespaceAsAdmin(bgpRouterNamespaceWithSuffix)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", bgpRouterPodName, "-n", bgpRouterNamespaceWithSuffix, "--ignore-not-found").Execute()
		bgpPassword = "bgp-test"
		o.Expect(setUpExternalFRRRouter(oc, bgpRouterNamespaceWithSuffix, bgpPassword)).To(o.BeTrue())

		compat_otp.By("3. Create BGP Peer")
		BGPPeerCR := bgpPeerResource{
			name:          "peer-64500",
			namespace:     opNamespace,
			holdTime:      "30s",
			keepAliveTime: "10s",
			password:      bgpPassword,
			myASN:         myASN,
			peerASN:       peerASN,
			peerAddress:   peerIPAddress,
			template:      BGPPeerTemplate,
		}
		defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
		bgpPeers = append(bgpPeers, BGPPeerCR.name)
		o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())

		compat_otp.By("4. Check BGP Session between speakers and Router")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("5. Create L3 and L2 IP addresspools")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-bgp-" + testID,
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 bgpAddresses[0][:],
			namespaces:                namespaces,
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
		ipaddresspools[0] = append(ipaddresspools[0], ipAddresspool.name)

		ipAddresspool.name = "ipaddresspool-l2-" + testID
		ipAddresspool.addresses = l2Addresses[0][:]
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
		ipaddresspools[1] = append(ipaddresspools[1], ipAddresspool.name)

		compat_otp.By("6. Create BGP and L2 Advertisements")
		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv-" + testID,
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        ipaddresspools[0],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())

		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv-" + testID,
			namespace:          opNamespace,
			ipAddressPools:     ipaddresspools[1],
			interfaces:         interfaces[:],
			nodeSelectorValues: workers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		o.Expect(createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)).To(o.BeTrue())

		svcList := [2]string{"-l3-", "-l2-"}

		compat_otp.By("7. Create L2 and L3 service")
		annotatedSvc := loadBalancerServiceResource{
			name:                          "",
			namespace:                     ns,
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			annotationKey:                 annotationPrefix + "/address-pool",
			annotationValue:               "",
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceAnnotatedTemplate,
		}

		for i := 0; i < 2; i++ {
			annotatedSvc.name = "hello-world" + svcList[i] + testID
			annotatedSvc.annotationValue = ipaddresspools[i][0]

			o.Expect(createLoadBalancerService(oc, annotatedSvc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
			err := checkLoadBalancerSvcStatus(oc, annotatedSvc.namespace, annotatedSvc.name)
			o.Expect(err).NotTo(o.HaveOccurred())
			svcIP := getLoadBalancerSvcIP(oc, annotatedSvc.namespace, annotatedSvc.name)
			e2e.Logf("The %s service with annotation %s:%s created successfully, and assigned %s", annotatedSvc.name, annotatedSvc.annotationKey, annotatedSvc.annotationValue, svcIP)
			o.Expect(strings.Contains(svcIP, expectedAddressList[i])).To(o.BeTrue())
			masterNodeList, getMastersErr := compat_otp.GetClusterNodesBy(oc, "master")
			o.Expect(getMastersErr).NotTo(o.HaveOccurred())
			o.Expect(validateService(oc, masterNodeList[0], svcIP)).To(o.BeTrue())

		}
		compat_otp.By("8. Verify route is advertised")
		expectedHostPrefixes = append(expectedHostPrefixes, expectedAddressList[0]+"/32")
		o.Expect(verifyHostPrefixAdvertised(oc, bgpRouterNamespaceWithSuffix, expectedHostPrefixes)).To(o.BeTrue())

		compat_otp.By(fmt.Sprintf("9. Update the L2 IP Addresspool %s", ipaddresspools[1][0]))
		patchL2AddressPool := `[{"op": "replace", "path": "/spec/serviceAllocation/serviceSelectors/0/matchLabels", "value": {"environ": "Dev"}}, {"op": "replace", "path": "/spec/serviceAllocation/serviceSelectors/0/matchExpressions", "value":[{"key":"environ", "operator":"In", "values":["Dev"]}]} ]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", opNamespace, "ipaddresspools", ipaddresspools[1][0], "--type=json", "-p", patchL2AddressPool).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		compat_otp.By("10. Delete previously created services and create new ones without ip address pool annotation")
		for i := 0; i < 2; i++ {
			svcName := "hello-world" + svcList[i] + testID
			removeResource(oc, true, true, "service", svcName, "-n", ns)
		}

		svcLabelValList := [2]string{"Test", "Dev"}
		svc := loadBalancerServiceResource{
			name:                          "",
			namespace:                     ns,
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    "",
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceTemplate,
		}
		compat_otp.By("11. Create L3 and L2 services")
		for i := 0; i < 2; i++ {
			svc.name = "hello-world" + svcList[i] + testID
			svc.labelValue = svcLabelValList[i]
			defer removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
			o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
			err := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
			o.Expect(err).NotTo(o.HaveOccurred())
			svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
			e2e.Logf("The %s service created successfully IP %s assigned to it", svc.name, svcIP)
			o.Expect(strings.Contains(svcIP, expectedAddressList[i])).To(o.BeTrue())
			masterNodeList, getMastersErr := compat_otp.GetClusterNodesBy(oc, "master")
			o.Expect(getMastersErr).NotTo(o.HaveOccurred())
			o.Expect(validateService(oc, masterNodeList[0], svcIP)).To(o.BeTrue())

		}

	})

	g.It("Author:qiowang-High-51187-High-54820-Validate ipAddressPoolSelector, ipAddressPool and nodeSelector are honored when advertising service IP address via BGP advertisement [Serial]", func() {
		var (
			workers                              []string
			nodeIPs                              []string
			ipaddresspools                       []string
			bgpPeers                             []string
			namespaces                           []string
			expectedPaths1                       []string
			expectedPaths2                       []string
			expectedPaths3                       []string
			bgpPassword                          string
			expectedAddress1                     = "10.10.10.1"
			expectedAddress2                     = "10.10.12.1"
			serviceSelectorKey                   = "environ"
			serviceSelectorValue                 = [1]string{"Test"}
			namespaceLabelKey                    = "region"
			namespaceLabelValue                  = [1]string{"NA"}
			ipAddressPoolSelectorsKey            = "zone"
			ipAddressPoolSelectorsValues         = [2][2]string{{"east"}, {"west"}}
			ipAddresspoolTemplate                = filepath.Join(testDataDir, "ipaddresspool-template.yaml")
			BGPPeerTemplate                      = filepath.Join(testDataDir, "bgppeer-template.yaml")
			bgpAdvertisementTemplate             = filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
			loadBalancerServiceAnnotatedTemplate = filepath.Join(testDataDir, "loadbalancer-svc-annotated-template.yaml")
		)
		ns := oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test51187")

		//Two worker nodes needed to create BGP Advertisement object
		workerList, getWorkersErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(getWorkersErr).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run on cluster that has at least two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
			nodeIP := getNodeIPv4(oc, ns, workerList.Items[i].Name)
			nodeIPs = append(nodeIPs, nodeIP)
		}

		compat_otp.By("1. Set up upstream/external BGP router, enable BFD")
		suffix := getRandomString()
		bgpRouterNamespaceWithSuffix := bgpRouterNamespace + "-" + suffix
		defer oc.DeleteSpecifiedNamespaceAsAdmin(bgpRouterNamespaceWithSuffix)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", bgpRouterPodName, "-n", bgpRouterNamespaceWithSuffix, "--ignore-not-found").Execute()
		bgpPassword = ""
		o.Expect(setUpExternalFRRRouter(oc, bgpRouterNamespaceWithSuffix, bgpPassword)).To(o.BeTrue())

		compat_otp.By("2. Create two IP addresspools with different labels")
		for i := 0; i < 2; i++ {
			ipAddresspool := ipAddressPoolResource{
				name:                      "ipaddresspool-bgp-51187-" + strconv.Itoa(i),
				namespace:                 opNamespace,
				addresses:                 bgpAddresses[i][:],
				namespaces:                namespaces,
				label1:                    ipAddressPoolSelectorsKey,
				value1:                    ipAddressPoolSelectorsValues[i][0],
				priority:                  10,
				avoidBuggyIPs:             true,
				autoAssign:                true,
				serviceLabelKey:           serviceSelectorKey,
				serviceLabelValue:         serviceSelectorValue[0],
				serviceSelectorKey:        serviceSelectorKey,
				serviceSelectorOperator:   "In",
				serviceSelectorValue:      serviceSelectorValue[:],
				namespaceLabelKey:         namespaceLabelKey,
				namespaceLabelValue:       namespaceLabelValue[0],
				namespaceSelectorKey:      namespaceLabelKey,
				namespaceSelectorOperator: "In",
				namespaceSelectorValue:    namespaceLabelValue[:],
				template:                  ipAddresspoolTemplate,
			}
			defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
			o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
			ipaddresspools = append(ipaddresspools, ipAddresspool.name)
		}

		compat_otp.By("3. Create BGP Peer")
		BGPPeerCR := bgpPeerResource{
			name:          "peer-64500",
			namespace:     opNamespace,
			holdTime:      "30s",
			keepAliveTime: "10s",
			password:      "",
			myASN:         myASN,
			peerASN:       peerASN,
			peerAddress:   peerIPAddress,
			template:      BGPPeerTemplate,
		}
		defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
		o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())
		bgpPeers = append(bgpPeers, BGPPeerCR.name)

		compat_otp.By("4. Create BGP Advertisement with ipAddressPool and nodeSelectors")
		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv-51187",
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        ipaddresspools[:],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())

		compat_otp.By("5. Check BGP Session between speakers and Router")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("6. Create a service requesting address from the first ipaddresspools")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-51187",
			namespace:                     ns,
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			annotationKey:                 annotationPrefix + "/address-pool",
			annotationValue:               ipaddresspools[0],
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceAnnotatedTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
		statusErr := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(statusErr).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The service %s 's External IP for OCP-51187 test case is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress1)).To(o.BeTrue())
		masterNodeList, getMastersErr := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(getMastersErr).NotTo(o.HaveOccurred())
		result := validateService(oc, masterNodeList[0], svcIP)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("7. Verify route is advertised")
		expectedPaths1 = append(expectedPaths1, "2 available", nodeIPs[0], nodeIPs[1])
		o.Expect(checkBGPv4RouteTableEntry(oc, bgpRouterNamespaceWithSuffix, expectedAddress1, expectedPaths1)).To(o.BeTrue())

		compat_otp.By("8. Remove the previously created services")
		removeResource(oc, true, true, "service", svc.name, "-n", svc.namespace)
		removeResource(oc, true, true, "replicationcontroller", svc.name, "-n", svc.namespace)

		compat_otp.By("9. Update BGP Advertisement, update ipAddressPool and nodeSelectors, add ipAddressPoolSelectors")
		patchBgpAdvertisement := `[{"op": "replace", "path": "/spec/ipAddressPools", "value": [""]}, {"op": "replace", "path": "/spec/nodeSelectors/0/matchExpressions/0/values", "value":["` + workers[0] + `"]}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", opNamespace, "bgpadvertisement", bgpAdvertisement.name, "--type=json", "-p", patchBgpAdvertisement).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		patchIPAddrPoolSelectors := `{"spec":{"ipAddressPoolSelectors":[{"matchExpressions": [{"key": "` + ipAddressPoolSelectorsKey + `","operator": "In","values": ["` + ipAddressPoolSelectorsValues[1][0] + `"]}]}]}}`
		patchResourceAsAdmin(oc, "bgpadvertisement/"+bgpAdvertisement.name, patchIPAddrPoolSelectors, "metallb-system")

		compat_otp.By("10. Check BGP Session between speakers and Router")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("11. Create a service requesting address from the second ipaddresspools")
		svc.annotationValue = ipaddresspools[1]
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceAnnotatedTemplate)).To(o.BeTrue())
		statusErr = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(statusErr).NotTo(o.HaveOccurred())
		svcIP = getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		e2e.Logf("The recreated service %s 's External IP for OCP-51187 test case is %q", svc.name, svcIP)
		o.Expect(strings.Contains(svcIP, expectedAddress2)).To(o.BeTrue())
		result = validateService(oc, masterNodeList[0], svcIP)
		o.Expect(result).To(o.BeTrue())

		compat_otp.By("12. Verify route is advertised")
		expectedPaths2 = append(expectedPaths2, "1 available", nodeIPs[0])
		o.Expect(checkBGPv4RouteTableEntry(oc, bgpRouterNamespaceWithSuffix, expectedAddress2, expectedPaths2)).To(o.BeTrue())

		compat_otp.By("13. OCP-54820-Add label to the second worker node")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workers[1], "zone")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workers[1], "zone", "east")

		compat_otp.By("14. OCP-54820-Edit the BGPadvertisement to modify the node selection")
		patchBgpAdvertisement = `[{"op": "replace", "path": "/spec/nodeSelectors/0/matchExpressions/0/key", "value":"zone"}, {"op": "replace", "path": "/spec/nodeSelectors/0/matchExpressions/0/values", "value":["east"]}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", opNamespace, "bgpadvertisement", bgpAdvertisement.name, "--type=json", "-p", patchBgpAdvertisement).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		compat_otp.By("15. OCP-54820-Check the changes to nodeSelector in BGPadvertisements are reflected which node advertises the host prefix for service")
		expectedPaths3 = append(expectedPaths3, "1 available", nodeIPs[1])
		o.Expect(checkBGPv4RouteTableEntry(oc, bgpRouterNamespaceWithSuffix, expectedAddress2, expectedPaths3)).To(o.BeTrue())
	})

	g.It("Author:asood-Longduration-NonPreRelease-High-46110-Verify service is functional if BGP peer is modified to cause session to re establish. [Serial]", func() {
		var (
			testID               = "46110"
			ns                   string
			namespaces           []string
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			workers              []string
			ipaddrpools          []string
			bgpPeers             []string
			bgpPassword          string
			nodeIPs              []string
			expectedPath         []string
		)

		//Two worker nodes needed to create BGP Advertisement object
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		for i := 0; i < 2; i++ {
			workers = append(workers, workerList.Items[i].Name)
			nodeIP := getNodeIPv4(oc, ns, workerList.Items[i].Name)
			nodeIPs = append(nodeIPs, nodeIP)
		}
		masterNodeList, masterNodeErr := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(masterNodeErr).NotTo(o.HaveOccurred())

		compat_otp.By("1. Get the namespace")
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test46110")

		compat_otp.By("2. Set up upstream/external BGP router")
		suffix := getRandomString()
		bgpRouterNamespaceWithSuffix := bgpRouterNamespace + "-" + suffix
		defer oc.DeleteSpecifiedNamespaceAsAdmin(bgpRouterNamespaceWithSuffix)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", bgpRouterPodName, "-n", bgpRouterNamespaceWithSuffix).Execute()
		bgpPassword = ""
		o.Expect(setUpExternalFRRRouter(oc, bgpRouterNamespaceWithSuffix, bgpPassword)).To(o.BeTrue())

		compat_otp.By("3. Create BGP Peer")
		BGPPeerTemplate := filepath.Join(testDataDir, "bgppeer-template.yaml")
		BGPPeerCR := bgpPeerResource{
			name:          "peer-64500-" + testID,
			namespace:     opNamespace,
			holdTime:      "30s",
			keepAliveTime: "10s",
			password:      bgpPassword,
			myASN:         myASN,
			peerASN:       peerASN,
			peerAddress:   peerIPAddress,
			template:      BGPPeerTemplate,
		}
		defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
		bgpPeers = append(bgpPeers, BGPPeerCR.name)
		o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())
		compat_otp.By("4. Check BGP Session between speakers and Router is established")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("5. Create IP addresspool")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-l3-" + testID,
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 bgpAddresses[0][:],
			namespaces:                namespaces,
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
		ipaddrpools = append(ipaddrpools, ipAddresspool.name)

		compat_otp.By("6. Create BGP Advertisement")
		bgpAdvertisementTemplate := filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv",
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        ipaddrpools[:],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())

		compat_otp.By("7. Create a LB service and verify it is accessible ")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-" + testID,
			namespace:                     namespaces[0],
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		o.Expect(validateService(oc, masterNodeList[0], svcIP)).To(o.BeTrue())

		compat_otp.By("8. Verify route is advertised")
		expectedPath = append(expectedPath, "2 available", nodeIPs[0], nodeIPs[1])
		o.Expect(checkBGPv4RouteTableEntry(oc, bgpRouterNamespaceWithSuffix, svcIP, expectedPath)).To(o.BeTrue())

		compat_otp.By("9. Verify by setting password for BGP peer the session is no longer established")
		patchBGPPeer := `{"spec":{"password":"bgp-test"}}`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", BGPPeerCR.name, "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix, 60*time.Second)).To(o.BeFalse())

		compat_otp.By("10. Verify by unsetting password for BGP peer the session is re established")
		patchBGPPeer = `{"spec":{"password":""}}`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("bgppeer", BGPPeerCR.name, "-n", opNamespace, "--type=merge", "-p", patchBGPPeer).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("11. Verify route is advertised after the BGP session is re established")
		o.Expect(checkBGPv4RouteTableEntry(oc, bgpRouterNamespaceWithSuffix, svcIP, expectedPath)).To(o.BeTrue())

	})

	g.It("Author:asood-Longduration-NonPreRelease-High-46105-Verify only the specified node BGP peered advertise network prefixes. [Serial]", func() {
		var (
			testID               = "46105"
			ns                   string
			namespaces           []string
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [1]string{"Test"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			workers              []string
			ipaddrpools          []string
			bgpPeers             []string
			bgpPassword          string
			nodeIPs              []string
			expectedPath         []string
			newExpectedPath      []string
		)

		//Two worker nodes needed to create BGP Advertisement object
		workerList := excludeSriovNodes(oc)
		if len(workerList) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		for i := 0; i < 2; i++ {
			workers = append(workers, workerList[i])
			nodeIP := getNodeIPv4(oc, ns, workerList[i])
			nodeIPs = append(nodeIPs, nodeIP)
		}
		masterNodeList, masterNodeErr := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(masterNodeErr).NotTo(o.HaveOccurred())

		compat_otp.By("1. Get the namespace")
		ns = oc.Namespace()
		namespaces = append(namespaces, ns)
		namespaces = append(namespaces, "test46110")

		compat_otp.By("2. Set up upstream/external BGP router")
		suffix := getRandomString()
		bgpRouterNamespaceWithSuffix := bgpRouterNamespace + "-" + suffix
		defer oc.DeleteSpecifiedNamespaceAsAdmin(bgpRouterNamespaceWithSuffix)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", bgpRouterPodName, "-n", bgpRouterNamespaceWithSuffix).Execute()
		bgpPassword = ""
		o.Expect(setUpExternalFRRRouter(oc, bgpRouterNamespaceWithSuffix, bgpPassword)).To(o.BeTrue())

		compat_otp.By("3. Create BGP Peer")
		BGPPeerTemplate := filepath.Join(testDataDir, "bgppeer-template.yaml")
		BGPPeerCR := bgpPeerResource{
			name:          "peer-64500-" + testID,
			namespace:     opNamespace,
			holdTime:      "30s",
			keepAliveTime: "10s",
			password:      bgpPassword,
			myASN:         myASN,
			peerASN:       peerASN,
			peerAddress:   peerIPAddress,
			template:      BGPPeerTemplate,
		}
		defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
		bgpPeers = append(bgpPeers, BGPPeerCR.name)
		o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())
		compat_otp.By("4. Check BGP Session between speakers and Router is established")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())

		compat_otp.By("5. Create IP addresspool")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-l3-" + testID,
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 bgpAddresses[0][:],
			namespaces:                namespaces,
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      serviceSelectorValue[:],
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
		ipaddrpools = append(ipaddrpools, ipAddresspool.name)

		compat_otp.By("6. Create BGP Advertisement")
		bgpAdvertisementTemplate := filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv",
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        ipaddrpools[:],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())

		compat_otp.By("7. Update the BGP Peer with selected nodes ")
		bgppeerWorkersList, err := json.Marshal(workers)
		o.Expect(err).NotTo(o.HaveOccurred())
		patchBGPPeer := fmt.Sprintf("{\"spec\":{\"nodeSelectors\": [{\"matchExpressions\": [{\"key\":\"kubernetes.io/hostname\", \"operator\": \"In\", \"values\": %s}]}]}}", string(bgppeerWorkersList))
		patchResourceAsAdmin(oc, "bgppeer/"+BGPPeerCR.name, patchBGPPeer, opNamespace)

		compat_otp.By("8. Create a LB service and verify it is accessible ")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
		svc := loadBalancerServiceResource{
			name:                          "hello-world-" + testID,
			namespace:                     namespaces[0],
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceLabelKey,
			labelValue:                    serviceLabelValue,
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceTemplate,
		}
		o.Expect(createLoadBalancerService(oc, svc, loadBalancerServiceTemplate)).To(o.BeTrue())
		err = checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
		o.Expect(validateService(oc, masterNodeList[0], svcIP)).To(o.BeTrue())

		compat_otp.By("9. Verify route is advertised")
		expectedPath = append(expectedPath, "2 available", nodeIPs[0], nodeIPs[1])
		o.Expect(checkBGPv4RouteTableEntry(oc, bgpRouterNamespaceWithSuffix, svcIP, expectedPath)).To(o.BeTrue())

		compat_otp.By("10. Label one of the nodes")
		metalLBLabel := "feature.node.kubernetes.io/bgp.capable"
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, workerList[0], metalLBLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, workerList[0], metalLBLabel)

		compat_otp.By("11. Update BGP peer node selector with node that is labelled")
		patchBGPPeer = `[{"op": "replace", "path": "/spec/nodeSelectors", "value":[{"matchExpressions": [{"key": "` + metalLBLabel + `", "operator": "Exists"}]}]}]`
		patchReplaceResourceAsAdmin(oc, "bgppeer/"+BGPPeerCR.name, patchBGPPeer, opNamespace)

		compat_otp.By("12. Verify the advertised routes")
		newExpectedPath = append(newExpectedPath, "1 available", nodeIPs[0])
		o.Expect(checkBGPv4RouteTableEntry(oc, bgpRouterNamespaceWithSuffix, svcIP, newExpectedPath)).To(o.BeTrue())

	})

})

// Cross feature testing
var _ = g.Describe("[OTP][sig-networking] SDN udn metallb", func() {
	defer g.GinkgoRecover()

	var (
		oc                       = compat_otp.NewCLI("networking-metallb", compat_otp.KubeConfigPath())
		opNamespace              = "metallb-system"
		opName                   = "metallb-operator"
		catalogNamespace         = "openshift-marketplace"
		catalogSourceName        = "metallb-operator-fbc-catalog"
		imageDigestMirrorSetName = "metallb-images-mirror-set"
		testDataDir              = testdata.FixturePath("networking/metallb")
		l2Addresses              = [2][2]string{{"192.168.111.65-192.168.111.69", "192.168.111.70-192.168.111.74"}, {"192.168.111.75-192.168.111.79", "192.168.111.80-192.168.111.85"}}
		l3Addresses              = [2][2]string{{"10.10.10.0-10.10.10.10", "10.10.11.1-10.10.11.10"}, {"10.10.12.1-10.10.12.10", "10.10.13.1-10.10.13.10"}}
		myASN                    = 64512
		peerASN                  = 64500
		peerIPAddress            = "192.168.111.60"
		metalLBNodeSelKey        = "node-role.kubernetes.io/worker"
		metalLBNodeSelVal        = ""
		metalLBControllerSelKey  = "node-role.kubernetes.io/worker"
		metalLBControllerSelVal  = ""
		ipAddressPoolLabelKey    = "zone"
		ipAddressPoolLabelVal    = "east"
		proxyHost                = ""
	)

	g.BeforeEach(func() {
		SkipIfNoFeatureGate(oc, "NetworkSegmentation")

		compat_otp.By("Check the platform if it is suitable for running the test")
		networkType := compat_otp.CheckNetworkType(oc)
		if !(isRDUPlatformSuitable(oc)) || !strings.Contains(networkType, "ovn") {
			g.Skip("These cases can only be run on networking team's private RDU cluster, skipping for other platforms or non-OVN network plugin!!!")
		}
		proxySetting := os.Getenv("http_proxy")
		if proxySetting == "" {
			g.Skip("Proxy settings to access the cluster are not found, please ensure they are set!!")
		}
		cmd := `echo "$http_proxy" | awk -F'[/:]' '{print $1}'`
		hostIP, awkErr := exec.Command("bash", "-c", cmd).Output()
		o.Expect(awkErr).NotTo(o.HaveOccurred())
		o.Expect(hostIP).NotTo(o.BeEmpty())
		proxyHost = strings.TrimSpace(string(hostIP))

		namespaceTemplate := filepath.Join(testDataDir, "namespace-template.yaml")
		operatorGroupTemplate := filepath.Join(testDataDir, "operatorgroup-template.yaml")
		subscriptionTemplate := filepath.Join(testDataDir, "subscription-template.yaml")
		catalogSourceTemplate := filepath.Join(testDataDir, "catalogsource-template.yaml")
		imageDigestMirrorSetFile := filepath.Join(testDataDir, "image-digest-mirrorset.yaml")
		sub := subscriptionResource{
			name:             "metallb-operator-sub",
			namespace:        opNamespace,
			operatorName:     opName,
			channel:          "stable",
			catalog:          catalogSourceName,
			catalogNamespace: catalogNamespace,
			template:         subscriptionTemplate,
		}
		ns := namespaceResource{
			name:     opNamespace,
			template: namespaceTemplate,
		}
		og := operatorGroupResource{
			name:             opName,
			namespace:        opNamespace,
			targetNamespaces: opNamespace,
			template:         operatorGroupTemplate,
		}
		catalogSourceName = setupOperatorCatalogSource(oc, "metallb", catalogSourceName, imageDigestMirrorSetName, catalogNamespace, imageDigestMirrorSetFile, catalogSourceTemplate)
		sub.catalog = catalogSourceName
		operatorInstall(oc, sub, ns, og)

		compat_otp.By("Making sure CRDs are successfully installed")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "bfdprofiles.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgpadvertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "bgppeers.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "communities.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "ipaddresspools.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "l2advertisements.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "metallbs.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrconfigurations.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "frrnodestates.frrk8s.metallb.io")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "servicel2statuses.metallb.io")).To(o.BeTrue())

		compat_otp.By("Create MetalLB CR")
		metallbCRTemplate := filepath.Join(testDataDir, "metallb-cr-template.yaml")
		metallbCR := metalLBCRResource{
			name:                  "metallb",
			namespace:             opNamespace,
			nodeSelectorKey:       metalLBNodeSelKey,
			nodeSelectorVal:       metalLBNodeSelVal,
			controllerSelectorKey: metalLBControllerSelKey,
			controllerSelectorVal: metalLBControllerSelVal,
			template:              metallbCRTemplate,
		}
		result := createMetalLBCR(oc, metallbCR, metallbCRTemplate)
		o.Expect(result).To(o.BeTrue())
		compat_otp.By("SUCCESS - MetalLB CR Created")
	})

	g.It("Author:asood-High-76801-Validate LB services can be created in UDN with MetalLB operator on non cloud platform. [Serial]", func() {
		var (
			namespaces           []string
			serviceSelectorKey   = "environ"
			serviceSelectorValue = [2]string{"Test", "Dev"}
			namespaceLabelKey    = "region"
			namespaceLabelValue  = [1]string{"NA"}
			interfaces           = [3]string{"br-ex", "eno1", "eno2"}
			workers              []string
			l2IPAddressPool      []string
			l3IPAddressPool      []string
			bgpPeers             []string
			bgpPassword                = ""
			bgpCommunties              = []string{"65001:65500"}
			cidr                       = []string{"10.150.0.0/16", "10.151.0.0/16"}
			prefix               int32 = 24
			testID                     = "76801"
			routerNS                   = ""
			udnTestDataDir             = testdata.FixturePath("networking")
			udnCRDL2SingleStack        = filepath.Join(udnTestDataDir, "udn/udn_crd_layer2_singlestack_template.yaml")
			udnCRDL3SingleStack        = filepath.Join(udnTestDataDir, "udn/udn_crd_singlestack_template.yaml")
			udnNADTemplate             = filepath.Join(udnTestDataDir, "udn/udn_nad_template.yaml")
		)

		compat_otp.By("1. Obtain the workers")
		workerList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(workerList.Items) < 2 {
			g.Skip("These cases can only be run for cluster that has atleast two worker nodes")
		}
		for i := 0; i < len(workerList.Items); i++ {
			workers = append(workers, workerList.Items[i].Name)
		}

		compat_otp.By("2. Set up user defined network namespaces")
		for i := 0; i < 4; i++ {
			oc.CreateNamespaceUDN()
			namespaces = append(namespaces, oc.Namespace())
		}
		compat_otp.By("2.1. Create CRD for UDN in first two namespaces")
		udnResourceName := []string{"l2-network-udn", "l3-network-udn"}
		udnTemplate := []string{udnCRDL2SingleStack, udnCRDL3SingleStack}
		udnCRD := make([]udnCRDResource, 2)
		for i := 0; i < 2; i++ {
			udnCRD[i] = udnCRDResource{
				crdname:   udnResourceName[i],
				namespace: namespaces[i],
				role:      "Primary",
				cidr:      cidr[i],
				prefix:    prefix,
				template:  udnTemplate[i],
			}
			switch i {
			case 0:
				udnCRD[0].createLayer2SingleStackUDNCRD(oc)
			case 1:
				udnCRD[1].createUdnCRDSingleStack(oc)
			default:
				// Do nothing
			}
			err := waitUDNCRDApplied(oc, namespaces[i], udnCRD[i].crdname)
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		compat_otp.By("2.2 Create NAD for UDN in last two namespaces")
		udnNADResourceName := []string{"l2-network-nad", "l3-network-nad"}
		topology := []string{"layer2", "layer3"}
		udnNAD := make([]udnNetDefResource, 2)
		for i := 0; i < 2; i++ {
			udnNAD[i] = udnNetDefResource{
				nadname:             udnNADResourceName[i],
				namespace:           namespaces[i+2],
				nad_network_name:    udnNADResourceName[i],
				topology:            topology[i],
				subnet:              "",
				net_attach_def_name: fmt.Sprintf("%s/%s", namespaces[i+2], udnNADResourceName[i]),
				role:                "primary",
				template:            udnNADTemplate,
			}
			udnNAD[i].subnet = cidr[i]
			udnNAD[i].createUdnNad(oc)
		}

		compat_otp.By("3.1 Set up external BGP router")
		suffix := getRandomString()
		bgpRouterNamespaceWithSuffix := bgpRouterNamespace + "-" + suffix
		defer oc.DeleteSpecifiedNamespaceAsAdmin(bgpRouterNamespaceWithSuffix)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", bgpRouterPodName, "-n", bgpRouterNamespaceWithSuffix).Execute()
		o.Expect(setUpExternalFRRRouter(oc, bgpRouterNamespaceWithSuffix, bgpPassword)).To(o.BeTrue())
		compat_otp.By("3.2 Create BGP Peer")
		BGPPeerTemplate := filepath.Join(testDataDir, "bgppeer-template.yaml")
		BGPPeerCR := bgpPeerResource{
			name:          "peer-64500-" + testID,
			namespace:     opNamespace,
			holdTime:      "30s",
			keepAliveTime: "10s",
			password:      bgpPassword,
			myASN:         myASN,
			peerASN:       peerASN,
			peerAddress:   peerIPAddress,
			template:      BGPPeerTemplate,
		}
		defer removeResource(oc, true, true, "bgppeers", BGPPeerCR.name, "-n", BGPPeerCR.namespace)
		bgpPeers = append(bgpPeers, BGPPeerCR.name)
		o.Expect(createBGPPeerCR(oc, BGPPeerCR)).To(o.BeTrue())
		compat_otp.By("3.3 Check BGP Session between speakers and Router is established")
		o.Expect(checkBGPSessions(oc, bgpRouterNamespaceWithSuffix)).To(o.BeTrue())
		routerNS = getRouterPodNamespace(oc)
		o.Expect(routerNS).NotTo(o.BeEmpty())

		compat_otp.By("4. Create L2 and L3 IP addresspools")
		ipAddresspoolTemplate := filepath.Join(testDataDir, "ipaddresspool-template.yaml")
		ipAddresspool := ipAddressPoolResource{
			name:                      "ipaddresspool-l2-" + testID,
			namespace:                 opNamespace,
			label1:                    ipAddressPoolLabelKey,
			value1:                    ipAddressPoolLabelVal,
			addresses:                 l2Addresses[0][:],
			namespaces:                namespaces[:],
			priority:                  10,
			avoidBuggyIPs:             true,
			autoAssign:                true,
			serviceLabelKey:           serviceSelectorKey,
			serviceLabelValue:         serviceSelectorValue[0],
			serviceSelectorKey:        serviceSelectorKey,
			serviceSelectorOperator:   "In",
			serviceSelectorValue:      []string{serviceSelectorValue[0], "dummy"},
			namespaceLabelKey:         namespaceLabelKey,
			namespaceLabelValue:       namespaceLabelValue[0],
			namespaceSelectorKey:      namespaceLabelKey,
			namespaceSelectorOperator: "In",
			namespaceSelectorValue:    namespaceLabelValue[:],
			template:                  ipAddresspoolTemplate,
		}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		result := createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)
		o.Expect(result).To(o.BeTrue())
		l2IPAddressPool = append(l2IPAddressPool, ipAddresspool.name)
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipAddresspool.name, "{\"spec\":{\"serviceAllocation\": {\"namespaces\": []}}}", opNamespace)
		compat_otp.By("SUCCESS - L2 IP Addresspool created")

		ipAddresspool.name = "ipaddresspool-l3-" + testID
		ipAddresspool.addresses = l3Addresses[0][:]
		ipAddresspool.serviceLabelValue = serviceSelectorValue[1]
		ipAddresspool.serviceSelectorValue = []string{serviceSelectorValue[1], "dummy"}
		defer removeResource(oc, true, true, "ipaddresspools", ipAddresspool.name, "-n", ipAddresspool.namespace)
		o.Expect(createIPAddressPoolCR(oc, ipAddresspool, ipAddresspoolTemplate)).To(o.BeTrue())
		l3IPAddressPool = append(l3IPAddressPool, ipAddresspool.name)
		patchResourceAsAdmin(oc, "ipaddresspools/"+ipAddresspool.name, "{\"spec\":{\"serviceAllocation\": {\"namespaces\": []}}}", opNamespace)
		compat_otp.By("SUCCESS - L3 IP Addresspool created")

		compat_otp.By("5. Create L2 and BGP Advertisement")
		l2AdvertisementTemplate := filepath.Join(testDataDir, "l2advertisement-template.yaml")
		l2advertisement := l2AdvertisementResource{
			name:               "l2-adv-" + testID,
			namespace:          opNamespace,
			ipAddressPools:     l2IPAddressPool[:],
			interfaces:         interfaces[:],
			nodeSelectorValues: workers[:],
			template:           l2AdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "l2advertisements", l2advertisement.name, "-n", l2advertisement.namespace)
		o.Expect(createL2AdvertisementCR(oc, l2advertisement, l2AdvertisementTemplate)).To(o.BeTrue())
		l2AdvWorkersList, err := json.Marshal(workers)
		o.Expect(err).NotTo(o.HaveOccurred())

		patchL2Advertisement := fmt.Sprintf("[{\"op\": \"replace\", \"path\": \"/spec/nodeSelectors/0/matchExpressions/0/values\", \"value\":%s}]", l2AdvWorkersList)
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", opNamespace, "l2advertisement", l2advertisement.name, "--type=json", "-p", patchL2Advertisement).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		bgpAdvertisementTemplate := filepath.Join(testDataDir, "bgpadvertisement-template.yaml")
		bgpAdvertisement := bgpAdvertisementResource{
			name:                  "bgp-adv-" + testID,
			namespace:             opNamespace,
			aggregationLength:     32,
			aggregationLengthV6:   128,
			communities:           bgpCommunties[:],
			ipAddressPools:        l3IPAddressPool[:],
			nodeSelectorsKey:      "kubernetes.io/hostname",
			nodeSelectorsOperator: "In",
			nodeSelectorValues:    workers[:],
			peer:                  bgpPeers[:],
			template:              bgpAdvertisementTemplate,
		}
		defer removeResource(oc, true, true, "bgpadvertisements", bgpAdvertisement.name, "-n", bgpAdvertisement.namespace)
		o.Expect(createBGPAdvertisementCR(oc, bgpAdvertisement)).To(o.BeTrue())

		compat_otp.By("6. Create LoadBalancer services")
		loadBalancerServiceTemplate := filepath.Join(testDataDir, "loadbalancer-svc-template.yaml")
		svc := loadBalancerServiceResource{
			name:                          "",
			namespace:                     "",
			externaltrafficpolicy:         "Cluster",
			labelKey:                      serviceSelectorKey,
			labelValue:                    "",
			allocateLoadBalancerNodePorts: true,
			template:                      loadBalancerServiceTemplate,
		}

		for _, ns := range namespaces {
			for index, serviceSelector := range serviceSelectorValue {
				svc.name = "hello-world-" + testID + "-" + strconv.Itoa(index)
				svc.namespace = ns
				svc.labelValue = serviceSelector
				compat_otp.By(fmt.Sprintf("6.1 Create LoadBalancer service %s in %s", svc.name, svc.namespace))
				o.Expect(createLoadBalancerService(oc, svc, svc.template)).To(o.BeTrue())
				err := checkLoadBalancerSvcStatus(oc, svc.namespace, svc.name)
				o.Expect(err).NotTo(o.HaveOccurred())
				svcIP := getLoadBalancerSvcIP(oc, svc.namespace, svc.name)
				//svcClusterIP := getSvcIPv4(oc, svc.namespace, svc.name )
				compat_otp.By(fmt.Sprintf("6.2 Validating service %s using external IP %s", svc.name, svcIP))
				svcIPCmd := fmt.Sprintf("curl -s -I --connect-timeout 5 %s:80", svcIP)
				o.Eventually(func() bool {
					cmdOutput, _ := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, routerNS, "router-master1", "testcontainer", svcIPCmd)
					return strings.Contains(cmdOutput, "200 OK")
				}, "120s", "10s").Should(o.BeTrue(), "Service validation failed")
				// L3 addresses are not accessible outside cluster
				if index == 0 {
					compat_otp.By(fmt.Sprintf("6.3 Validating service %s using external IP %s", svc.name, svcIP))
					o.Eventually(func() bool {
						return validateService(oc, proxyHost, svcIP)
					}, "120s", "10s").Should(o.BeTrue(), "Service validation failed")
				}
			}
		}
	})

})
