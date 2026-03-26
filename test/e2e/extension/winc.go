package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"net"
	"path/filepath"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
)

var _ = g.Describe("[OTP][sig-networking] SDN winc", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-winc", compat_otp.KubeConfigPath())

	// author: anusaxen@redhat.com
	g.It("Author:anusaxen-High-51798-Check nodeport ETP Cluster and Local functionality wrt window node", func() {
		var (
			buildPruningBaseDir          = testdata.FixturePath("networking")
			pingPodWinNodeTemplate       = filepath.Join(buildPruningBaseDir, "ping-for-pod-window-template.yaml")
			windowGenericServiceTemplate = filepath.Join(buildPruningBaseDir, "service-generic-window-template.yaml")
		)

		linuxNodeList, err := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(err).NotTo(o.HaveOccurred())
		windowNodeList, err := compat_otp.GetAllNodesbyOSType(oc, "windows")
		o.Expect(err).NotTo(o.HaveOccurred())

		if len(linuxNodeList) < 2 || len(windowNodeList) < 1 {
			g.Skip("This case requires at least 1 window node, and 2 linux nodes")
		}

		g.By("Create a namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("create a window pod in ns")

		pod := pingPodResourceWinNode{
			name:      "win-webserver",
			namespace: ns,
			image:     "mcr.microsoft.com/powershell:lts-nanoserver-ltsc2022",
			nodename:  windowNodeList[0],
			template:  pingPodWinNodeTemplate,
		}
		pod.createPingPodWinNode(oc)
		testPodName := getPodName(oc, ns, "app=win-webserver")
		waitPodReady(oc, ns, testPodName[0])

		g.By("Create a cluster type nodeport test service for above window pod")
		svc := windowGenericServiceResource{
			servicename:           "win-nodeport-service",
			namespace:             ns,
			protocol:              "TCP",
			selector:              "win-webserver",
			serviceType:           "NodePort",
			ipFamilyPolicy:        "SingleStack",
			internalTrafficPolicy: "Cluster",
			externalTrafficPolicy: "Cluster",
			template:              windowGenericServiceTemplate,
		}
		svc.createWinServiceFromParams(oc)
		_, nodePort := getSvcIP(oc, ns, "win-nodeport-service")
		_, winNodeIP := getNodeIP(oc, windowNodeList[0])
		winNodeURL := net.JoinHostPort(winNodeIP, nodePort)
		_, err = compat_otp.DebugNode(oc, linuxNodeList[0], "curl", winNodeURL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())

		_, linuxNodeIP := getNodeIP(oc, linuxNodeList[0])
		linuxNodeURL := net.JoinHostPort(linuxNodeIP, nodePort)
		_, err = compat_otp.DebugNode(oc, linuxNodeList[0], "curl", linuxNodeURL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Delete nodeport svc from ns and recreate it with ETP Local")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("svc", "win-nodeport-service", "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		svc.externalTrafficPolicy = "Local"
		svc.createWinServiceFromParams(oc)
		_, nodePort = getSvcIP(oc, ns, "win-nodeport-service")
		//nodePort value might have changed so fetching new URLs for JoinHostPort
		winNodeURLnew := net.JoinHostPort(winNodeIP, nodePort)
		linuxNodeURLnew := net.JoinHostPort(linuxNodeIP, nodePort)

		g.By("linux worker 0 to window node should work because its external traffic from another node and destination window node has a backend pod on it, ETP=Local respected")
		_, err = compat_otp.DebugNode(oc, linuxNodeList[0], "curl", winNodeURLnew, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("linux Worker 0 to linux worker 0 should work like ETP=cluster because its not external traffic, its within the node. ETP=local shouldn't be respected and its like ETP=cluster behaviour")
		_, err = compat_otp.DebugNode(oc, linuxNodeList[0], "curl", linuxNodeURLnew, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	})
})
