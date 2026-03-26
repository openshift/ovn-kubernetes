package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"

	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN ovn-kubernetes egressrouter", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-egressrouter", compat_otp.KubeConfigPath())
	g.BeforeEach(func() {
		platform := compat_otp.CheckPlatform(oc)
		e2e.Logf("\n\nThe platform is %v\n", platform)
		networkType := checkNetworkType(oc)
		acceptedPlatform := strings.Contains(platform, "baremetal")
		if !acceptedPlatform || !strings.Contains(networkType, "ovn") {
			g.Skip("Test cases should be run on BareMetal cluster, skip for other platforms or other non-OVN network plugin!!")
		}
		if checkProxy(oc) {
			g.Skip("This is proxy cluster, skip the test.")
		}
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-High-42340-Egress router redirect mode with multiple destinations.", func() {
		ipStackType := checkIPStackType(oc)
		compat_otp.By("Skip testing on ipv6 single stack cluster")
		if ipStackType == "ipv6single" {
			g.Skip("Skip for single stack cluster!!!")
		}
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking")
			egressBaseDir                = filepath.Join(buildPruningBaseDir, "egressrouter")
			pingPodTemplate              = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			egressRouterTemplate         = filepath.Join(egressBaseDir, "egressrouter-multiple-destination-template.yaml")
			egressRouterService          = filepath.Join(egressBaseDir, "serive-egressrouter.yaml")
			egressRouterServiceDualStack = filepath.Join(egressBaseDir, "serive-egressrouter-dualstack.yaml")
			url                          = "www.google.com"
		)

		compat_otp.By("1. nslookup obtain dns server ip for url \n")
		destinationIP := nslookDomainName(url)
		e2e.Logf("ip address from nslookup for %v: %v", url, destinationIP)

		compat_otp.By("2. Get gateway for one worker node \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		gateway := getIPv4Gateway(oc, nodeList.Items[0].Name)
		o.Expect(gateway).ShouldNot(o.BeEmpty())
		freeIP := findFreeIPs(oc, nodeList.Items[0].Name, 1)
		o.Expect(len(freeIP)).Should(o.Equal(1))
		prefixIP := getInterfacePrefix(oc, nodeList.Items[0].Name)
		o.Expect(prefixIP).ShouldNot(o.BeEmpty())
		reservedIP := fmt.Sprintf("%s/%s", freeIP[0], prefixIP)

		compat_otp.By("3. Obtain the namespace \n")
		ns1 := oc.Namespace()

		compat_otp.By("4. Create egressrouter \n")
		egressrouter := egressrouterMultipleDst{
			name:           "egressrouter-42430",
			namespace:      ns1,
			reservedip:     reservedIP,
			gateway:        gateway,
			destinationip1: destinationIP,
			destinationip2: destinationIP,
			destinationip3: destinationIP,
			template:       egressRouterTemplate,
		}
		egressrouter.createEgressRouterMultipeDst(oc)
		err = waitForPodWithLabelReady(oc, ns1, "app=egress-router-cni")
		compat_otp.AssertWaitPollNoErr(err, "EgressRouter pod is not ready!")

		compat_otp.By("5. Schedule the worker \n")
		// In rdu1 and rdu2 clusters, there are two sriov nodes with mlx nic, by default, egressrouter case cannot run on it
		// So here exclude sriov nodes in rdu1 and rdu2 clusters, just use the other common worker nodes
		workers := excludeSriovNodes(oc)
		o.Expect(len(workers) > 0).Should(o.BeTrue(), fmt.Sprintf("The number of common worker nodes in the cluster is %v ", len(workers)))
		if len(workers) < nodeList.Size() {
			e2e.Logf("There are sriov workers in the cluster, will schedule the egress router pod to a common node.")
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns1, "deployment/egress-router-cni-deployment", "-p", "{\"spec\":{\"template\":{\"spec\":{\"nodeName\":\""+workers[0]+"\"}}}}", "--type=merge").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			output, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("-n", ns1, "status", "deployment/egress-router-cni-deployment").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("successfully rolled out"))
		}

		compat_otp.By("6. Create service for egress router pod! \n")
		if ipStackType == "dualstack" {
			createResourceFromFile(oc, ns1, egressRouterServiceDualStack)
		} else {
			createResourceFromFile(oc, ns1, egressRouterService)
		}

		compat_otp.By("7. create hello pod in ns1 \n")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("8. Get service IP \n")
		var svcIPv4 string
		if ipStackType == "dualstack" {
			_, svcIPv4 = getSvcIP(oc, ns1, "ovn-egressrouter-multidst-svc")
		} else {
			svcIPv4, _ = getSvcIP(oc, ns1, "ovn-egressrouter-multidst-svc")
		}

		compat_otp.By("9. Check result,the svc for egessrouter can be accessed \n")
		_, err = e2eoutput.RunHostCmdWithRetries(pod1.namespace, pod1.name, "curl -s "+svcIPv4+":5000 --connect-timeout 10", 5*time.Second, 30*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:5000 with error:%v", svcIPv4, err))
		_, err = e2eoutput.RunHostCmdWithRetries(pod1.namespace, pod1.name, "curl -s "+svcIPv4+":6000 --connect-timeout 10", 5*time.Second, 30*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:6000 with error:%v", svcIPv4, err))
		_, err = e2eoutput.RunHostCmdWithRetries(pod1.namespace, pod1.name, "curl -s "+svcIPv4+":80 --connect-timeout 10", 5*time.Second, 30*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:80 with error:%v", svcIPv4, err))
	})

	// author: jechen@redhat.com
	g.It("ConnectedOnly-NonPreRelease-PreChkUpgrade-Author:jechen-High-63155-Pre Egress router redirect mode with multiple destinations should still be functional after upgrade.", func() {
		ipStackType := checkIPStackType(oc)
		compat_otp.By("Skip testing on ipv6 single stack cluster")
		if ipStackType == "ipv6single" {
			g.Skip("Skip for single stack cluster!!!")
		}
		var (
			buildPruningBaseDir  = testdata.FixturePath("networking")
			egressBaseDir        = filepath.Join(buildPruningBaseDir, "egressrouter")
			statefulSetHelloPod  = filepath.Join(buildPruningBaseDir, "statefulset-hello.yaml")
			egressRouterTemplate = filepath.Join(egressBaseDir, "egressrouter-multiple-destination-template.yaml")
			egressRouterService  = filepath.Join(egressBaseDir, "serive-egressrouter.yaml")
			ns1                  = "63155-upgrade-ns"
			url                  = "www.google.com"
		)

		compat_otp.By("0. nslookup obtain dns server ip for url \n")
		destinationIP := nslookDomainName(url)
		e2e.Logf("ip address from nslookup for %v: %v", url, destinationIP)

		compat_otp.By("1.Get gateway for one worker node \n")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		gateway := getIPv4Gateway(oc, nodeList.Items[0].Name)
		o.Expect(gateway).ShouldNot(o.BeEmpty())
		freeIP := findFreeIPs(oc, nodeList.Items[0].Name, 1)
		o.Expect(len(freeIP)).Should(o.Equal(1))
		prefixIP := getInterfacePrefix(oc, nodeList.Items[0].Name)
		o.Expect(prefixIP).ShouldNot(o.BeEmpty())
		reservedIP := fmt.Sprintf("%s/%s", freeIP[0], prefixIP)

		compat_otp.By("2. Obtain the namespace \n")
		oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", ns1).Execute()
		compat_otp.SetNamespacePrivileged(oc, ns1)

		compat_otp.By("3 Create egressrouter \n")
		egressrouter := egressrouterMultipleDst{
			name:           "egressrouter-63155",
			namespace:      ns1,
			reservedip:     reservedIP,
			gateway:        gateway,
			destinationip1: destinationIP,
			destinationip2: destinationIP,
			destinationip3: destinationIP,
			template:       egressRouterTemplate,
		}
		egressrouter.createEgressRouterMultipeDst(oc)
		err = waitForPodWithLabelReady(oc, ns1, "app=egress-router-cni")
		compat_otp.AssertWaitPollNoErr(err, "EgressRouter pod is not ready!")

		compat_otp.By("4. Schedule the worker \n")
		// In rdu1 and rdu2 clusters, there are two sriov nodes with mlx nic, by default, egressrouter case cannot run on it
		// So here exclude sriov nodes in rdu1 and rdu2 clusters, just use the other common worker nodes
		workers := excludeSriovNodes(oc)
		o.Expect(len(workers) > 0).Should(o.BeTrue(), fmt.Sprintf("The number of common worker nodes in the cluster is %v ", len(workers)))
		if len(workers) < nodeList.Size() {
			e2e.Logf("There are sriov workers in the cluster, will schedule the egress router pod to a common node.")
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns1, "deployment/egress-router-cni-deployment", "-p", "{\"spec\":{\"template\":{\"spec\":{\"nodeName\":\""+workers[0]+"\"}}}}", "--type=merge").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			output, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("-n", ns1, "status", "deployment/egress-router-cni-deployment").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("successfully rolled out"))
		}

		compat_otp.By("5. Create serive for egress router pod! \n")
		createResourceFromFile(oc, ns1, egressRouterService)

		compat_otp.By("6. create hello pod in ns1 \n")
		createResourceFromFile(oc, ns1, statefulSetHelloPod)
		podErr := waitForPodWithLabelReady(oc, ns1, "app=hello")
		compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
		helloPodname := getPodName(oc, ns1, "app=hello")

		compat_otp.By("7. Get service IP \n")
		svcIPv4, _ := getSvcIP(oc, ns1, "ovn-egressrouter-multidst-svc")

		compat_otp.By("8. Check result,the svc for egessrouter can be accessed \n")
		_, err = e2eoutput.RunHostCmd(ns1, helloPodname[0], "curl -s "+svcIPv4+":5000 --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:5000 with error:%v", svcIPv4, err))
		_, err = e2eoutput.RunHostCmd(ns1, helloPodname[0], "curl -s "+svcIPv4+":6000 --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:6000 with error:%v", svcIPv4, err))
		_, err = e2eoutput.RunHostCmd(ns1, helloPodname[0], "curl -s "+svcIPv4+":80 --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:80 with error:%v", svcIPv4, err))
	})

	g.It("ConnectedOnly-NonPreRelease-PstChkUpgrade-Author:jechen-High-63155-Pst Egress router redirect mode with multiple destinations should still be funcitonal after upgrade.", func() {
		ipStackType := checkIPStackType(oc)
		compat_otp.By("Skip testing on ipv6 single stack cluster")
		if ipStackType == "ipv6single" {
			g.Skip("Skip for single stack cluster!!!")
		}

		ns1 := "63155-upgrade-ns"
		nsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", ns1).Execute()
		if nsErr != nil {
			g.Skip("Skip the PstChkUpgrade test as 63155-upgrade-ns namespace does not exist, PreChkUpgrade test did not run")
		}

		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", ns1, "--ignore-not-found=true").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "hello-pod1", "-n", ns1, "--ignore-not-found=true").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("egressrouters", "egressrouter-63155", "-n", ns1, "--ignore-not-found=true").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("Service", "ovn-egressrouter-multidst-svc", "-n", ns1, "--ignore-not-found=true").Execute()

		compat_otp.By("1. check egressrouter pod \n")
		err := waitForPodWithLabelReady(oc, ns1, "app=egress-router-cni")
		compat_otp.AssertWaitPollNoErr(err, "EgressRouter pod is not ready!")

		compat_otp.By("2. check egressrouter deployment \n")
		output, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("-n", ns1, "status", "deployment/egress-router-cni-deployment").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("successfully rolled out"))

		compat_otp.By("3. Get the hello pod in ns1 \n")
		helloPodname := getPodName(oc, ns1, "app=hello")
		o.Expect(len(helloPodname)).Should(o.Equal(1))

		compat_otp.By("4. Get egressrouter service IP \n")
		svcIPv4, _ := getSvcIP(oc, ns1, "ovn-egressrouter-multidst-svc")

		compat_otp.By("5. Check svc for egessrouter can be accessed \n")
		_, err = e2eoutput.RunHostCmd(ns1, helloPodname[0], "curl -s "+svcIPv4+":5000 --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:5000 with error:%v", svcIPv4, err))
		_, err = e2eoutput.RunHostCmd(ns1, helloPodname[0], "curl -s "+svcIPv4+":6000 --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:6000 with error:%v", svcIPv4, err))
		_, err = e2eoutput.RunHostCmd(ns1, helloPodname[0], "curl -s "+svcIPv4+":80 --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to access %s:80 with error:%v", svcIPv4, err))
	})

})
