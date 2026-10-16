package ote

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = g.Describe("[sig-network] SDN networkpolicy service access", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-networkpolicy-service")

	g.BeforeEach(func() {
		networkType := oteutils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs] 49076-service domain can be resolved when egress type is enabled", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			testPodFile         = filepath.Join(buildPruningBaseDir, "testpod.yaml")
			helloSdnFile        = filepath.Join(buildPruningBaseDir, "hellosdn.yaml")
			egressTypeFile      = filepath.Join(buildPruningBaseDir, "networkpolicy/egress-allow-all.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/ingress-allow-all.yaml")
		)
		g.By("create new namespace")
		oc.SetupProject()

		g.By("create test pods")
		oteutils.CreateResourceFromFile(oc, oc.Namespace(), testPodFile)
		oteutils.CreateResourceFromFile(oc, oc.Namespace(), helloSdnFile)
		err := oteutils.WaitForPodWithLabelReady(oc, oc.Namespace(), "name=test-pods")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=test-pods not ready")
		err = oteutils.WaitForPodWithLabelReady(oc, oc.Namespace(), "name=hellosdn")
		o.Expect(err).NotTo(o.HaveOccurred(), "this pod with label name=hellosdn not ready")

		g.By("create egress and ingress type networkpolicy")
		oteutils.CreateResourceFromFile(oc, oc.Namespace(), egressTypeFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-egress"))
		oteutils.CreateResourceFromFile(oc, oc.Namespace(), ingressTypeFile)
		output, err = oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-all-ingress"))

		g.By("check hellosdn pods can reolsve the dns after apply the networkplicy")
		helloSdnName := oteutils.GetPodName(oc, oc.Namespace(), "name=hellosdn")
		digOutput, err := e2eoutput.RunHostCmd(oc.Namespace(), helloSdnName[0], "dig kubernetes.default")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("status: NOERROR"), "DNS query for kubernetes.default should resolve successfully (NOERROR), not NXDOMAIN")
		o.Expect(digOutput).Should(o.ContainSubstring("ANSWER SECTION"), "DNS query for kubernetes.default should return an address record")
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("connection timed out"))

		g.By("check test-pods can reolsve the dns after apply the networkplicy")
		testPodName := oteutils.GetPodName(oc, oc.Namespace(), "name=test-pods")
		digOutput, err = e2eoutput.RunHostCmd(oc.Namespace(), testPodName[0], "dig kubernetes.default")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(digOutput).Should(o.ContainSubstring("status: NOERROR"), "DNS query for kubernetes.default should resolve successfully (NOERROR), not NXDOMAIN")
		o.Expect(digOutput).Should(o.ContainSubstring("ANSWER SECTION"), "DNS query for kubernetes.default should return an address record")
		o.Expect(digOutput).ShouldNot(o.ContainSubstring("connection timed out"))

	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs] 66085-Creating egress network policies for allowing to same namespace and openshift dns in namespace prevents the pod from reaching its own service", func() {
		var (
			buildPruningBaseDir        = testdata.FixturePath("networking")
			pingPodTemplate            = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			genericServiceTemplate     = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			allowToNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-to-same-namespace.yaml")
			allowToDNSNPolicyFile      = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-to-openshift-dns.yaml")
			podsInProject              = []string{"hello-pod-1", "other-pod"}
			svcURL                     string
		)

		g.By("Get first namespace and create another")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create set of pods with different labels")
		for _, podItem := range podsInProject {
			pod1 := oteutils.PingPodResource{
				Name:      podItem,
				Namespace: ns,
				Template:  pingPodTemplate,
			}
			pod1.CreatePingPod(oc)
			oteutils.WaitPodReady(oc, ns, pod1.Name)
		}
		g.By("Label the pods to ensure the pod does not serve the service")
		_, reLabelErr := oc.AsAdmin().WithoutNamespace().Run("label").Args("-n", ns, "--overwrite", "pod", podsInProject[1], "name=other-pod").Output()
		o.Expect(reLabelErr).NotTo(o.HaveOccurred())

		g.By("Create a service for one of the pods")
		svc := oteutils.GenericServiceResource{
			Servicename:           "test-service",
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        "PreferDualStack",
			InternalTrafficPolicy: "Cluster",
			ExternalTrafficPolicy: "", //This no value parameter will be ignored
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)
		g.By("Check service status")
		svcOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", ns, svc.Servicename).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(svcOutput).Should(o.ContainSubstring(svc.Servicename))

		g.By("Obtain the service URL")
		svcURL = fmt.Sprintf("http://%s.%s.svc:27017", svc.Servicename, svc.Namespace)
		e2e.Logf("Service URL %s", svcURL)
		g.By("Check the connectivity to service from the pods in the namespace")
		for _, podItem := range podsInProject {
			pod := podItem
			o.Eventually(func() error {
				output, err := e2eoutput.RunHostCmd(ns, pod, "curl --connect-timeout 5 -s "+svcURL)
				if err != nil {
					return fmt.Errorf("curl failed: %v", err)
				}
				if !strings.Contains(output, "Hello OpenShift!") {
					return fmt.Errorf("expected 'Hello OpenShift!' in output, got: %s", output)
				}
				return nil
			}, 30*time.Second, 2*time.Second).Should(o.Succeed(), "Service should be reachable from pod %s", pod)
		}

		g.By("Create the network policies in the namespace")
		g.By("Create the allow to same namespace policy in the namespace")
		oteutils.CreateResourceFromFile(oc, ns, allowToNSNetworkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-same-namespace"))
		g.By("Create the allow to DNS policy in the namespace")
		oteutils.CreateResourceFromFile(oc, ns, allowToDNSNPolicyFile)
		output, err = oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-to-openshift-dns"))

		g.By("Create another pod to serve the service")
		anotherPod := oteutils.PingPodResource{
			Name:      "hello-pod-2",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		anotherPod.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, ns, anotherPod.Name)
		podsInProject = append(podsInProject, anotherPod.Name)

		g.By("Check the connectivity to service again from the pods in the namespace")
		for _, eachPod := range podsInProject {
			pod := eachPod
			o.Eventually(func() error {
				output, err := e2eoutput.RunHostCmd(ns, pod, "curl --connect-timeout 5 -s "+svcURL)
				if err != nil {
					return fmt.Errorf("curl failed: %v", err)
				}
				if !strings.Contains(output, "Hello OpenShift!") {
					return fmt.Errorf("expected 'Hello OpenShift!' in output, got: %s", output)
				}
				return nil
			}, 30*time.Second, 2*time.Second).Should(o.Succeed(), "Service should be reachable from pod %s", pod)
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs] 68660-Exposed route of the service should be accessible when allowing inbound traffic from any namespace network policy is created.", func() {
		var (
			buildPruningBaseDir             = testdata.FixturePath("networking")
			allowFromAllNSNetworkPolicyFile = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-all-namespaces.yaml")
			pingPodTemplate                 = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			genericServiceTemplate          = filepath.Join(buildPruningBaseDir, "service-generic-template.yaml")
			serviceName                     = "test-service-68660"
		)

		g.By("Get namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		g.By("Create a hello pod in namspace")
		podns := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		podns.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, podns.Namespace, podns.Name)
		g.By("Create a test service which is in front of the above pod")
		svc := oteutils.GenericServiceResource{
			Servicename:           serviceName,
			Namespace:             ns,
			Protocol:              "TCP",
			Selector:              "hello-pod",
			ServiceType:           "ClusterIP",
			IpFamilyPolicy:        "PreferDualStack",
			InternalTrafficPolicy: "Local",
			ExternalTrafficPolicy: "",
			Template:              genericServiceTemplate,
		}
		svc.CreateServiceFromParams(oc)

		g.By("Expose the service through a route")
		err := oc.AsAdmin().WithoutNamespace().Run("expose").Args("svc", serviceName, "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		svcRoute, routeErr := oc.AsAdmin().Run("get").Args("route", serviceName, "-n", ns, "-o=jsonpath={.spec.host}").Output()
		o.Expect(routeErr).NotTo(o.HaveOccurred())
		o.Expect(svcRoute).ShouldNot(o.Equal(""))

		g.By("Access the route before network policy creation")
		var svcErr error
		var routeCurlOutput []byte
		o.Eventually(func() string {
			routeCurlOutput, svcErr = exec.Command("bash", "-c", "curl -sI "+svcRoute).Output()
			if svcErr != nil {
				e2e.Logf("Wait for service to be accessible through route, %v", svcErr)
			}
			return string(routeCurlOutput)
		}, "15s", "5s").Should(o.ContainSubstring("200 OK"), fmt.Sprintf("Service inaccessible through route %s", string(routeCurlOutput)))

		g.By("Create a network policy in namespace")
		oteutils.CreateResourceFromFile(oc, ns, allowFromAllNSNetworkPolicyFile)
		output, err := oc.Run("get").Args("networkpolicy").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("allow-from-all-namespaces"))

		g.By("Access the route after network policy creation")
		// CreateResourceFromFile returns once the NetworkPolicy object exists, not
		// once it is enforced, so poll the route until it is reachable again.
		o.Eventually(func() string {
			routeCurlOutput, svcErr = exec.Command("bash", "-c", "curl -sI "+svcRoute).Output()
			if svcErr != nil {
				e2e.Logf("Wait for service to be accessible through route, %v", svcErr)
			}
			return string(routeCurlOutput)
		}, "30s", "5s").Should(o.ContainSubstring("200 OK"), fmt.Sprintf("Service inaccessible through route %s", string(routeCurlOutput)))

	})

})
