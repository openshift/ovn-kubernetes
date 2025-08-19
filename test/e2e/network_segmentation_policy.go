package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	nadclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/feature"

	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
)

var _ = ginkgo.Describe("Network Segmentation: Network Policies", feature.NetworkSegmentation, func() {
	f := wrappedTestFramework("network-segmentation")
	f.SkipNamespaceCreation = true

	ginkgo.Context("on a user defined primary network", func() {
		const (
			nadName                      = "tenant-red"
			userDefinedNetworkIPv4Subnet = "10.128.0.0/16"
			userDefinedNetworkIPv6Subnet = "2014:100:200::0/60"
			nodeHostnameKey              = "kubernetes.io/hostname"
			workerOneNodeName            = "ovn-worker"
			workerTwoNodeName            = "ovn-worker2"
			port                         = 9000
			randomStringLength           = 5
			nameSpaceYellowSuffix        = "yellow"
			namespaceBlueSuffix          = "blue"
			namespaceRedSuffix           = "red"
			namespaceOrangeSuffix        = "orange"
		)

		var (
			cs                  clientset.Interface
			nadClient           nadclient.K8sCniCncfIoV1Interface
			allowServerPodLabel = map[string]string{"foo": "bar"}
			denyServerPodLabel  = map[string]string{"abc": "xyz"}
		)

		ginkgo.BeforeEach(func() {
			cs = f.ClientSet
			namespace, err := f.CreateNamespace(context.TODO(), f.BaseName, map[string]string{
				"e2e-framework":           f.BaseName,
				RequiredUDNNamespaceLabel: "",
			})
			f.Namespace = namespace
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			nadClient, err = nadclient.NewForConfig(f.ClientConfig())
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			namespaceYellow := getNamespaceName(f, nameSpaceYellowSuffix)
			namespaceBlue := getNamespaceName(f, namespaceBlueSuffix)
			namespaceRed := getNamespaceName(f, namespaceRedSuffix)
			namespaceOrange := getNamespaceName(f, namespaceOrangeSuffix)
			for _, namespace := range []string{namespaceYellow, namespaceBlue,
				namespaceRed, namespaceOrange} {
				ginkgo.By("Creating namespace " + namespace)
				ns, err := cs.CoreV1().Namespaces().Create(context.Background(), &v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name:   namespace,
						Labels: map[string]string{RequiredUDNNamespaceLabel: ""},
					},
				}, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				f.AddNamespacesToDelete(ns)
			}
		})

		ginkgo.DescribeTable(
			"pods within namespace should be isolated when deny policy is present",
			func(
				netConfigParams networkAttachmentConfigParams,
				clientPodConfig podConfiguration,
				serverPodConfig podConfiguration,
			) {
				ginkgo.By("Creating the attachment configuration")
				netConfig := newNetworkAttachmentConfig(netConfigParams)
				netConfig.namespace = f.Namespace.Name
				netConfig.cidr = filterCIDRsAndJoin(cs, netConfig.cidr)
				_, err := nadClient.NetworkAttachmentDefinitions(f.Namespace.Name).Create(
					context.Background(),
					generateNAD(netConfig),
					metav1.CreateOptions{},
				)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				ginkgo.By("creating client/server pods")
				serverPodConfig.namespace = f.Namespace.Name
				clientPodConfig.namespace = f.Namespace.Name
				runUDNPod(cs, f.Namespace.Name, serverPodConfig, nil)
				runUDNPod(cs, f.Namespace.Name, clientPodConfig, nil)

				var serverIP string
				for i, cidr := range strings.Split(netConfig.cidr, ",") {
					if cidr != "" {
						ginkgo.By("asserting the server pod has an IP from the configured range")
						serverIP, err = getPodAnnotationIPsForAttachmentByIndex(
							cs,
							f.Namespace.Name,
							serverPodConfig.name,
							namespacedName(f.Namespace.Name, netConfig.name),
							i,
						)
						gomega.Expect(err).NotTo(gomega.HaveOccurred())
						ginkgo.By(fmt.Sprintf("asserting the server pod IP %v is from the configured range %v", serverIP, cidr))
						subnet, err := getNetCIDRSubnet(cidr)
						gomega.Expect(err).NotTo(gomega.HaveOccurred())
						gomega.Expect(inRange(subnet, serverIP)).To(gomega.Succeed())
					}

					ginkgo.By("asserting the *client* pod can contact the server pod exposed endpoint")
					gomega.Eventually(func() error {
						return reachServerPodFromClient(cs, serverPodConfig, clientPodConfig, serverIP, port)
					}, 2*time.Minute, 6*time.Second).Should(gomega.Succeed())
				}

				ginkgo.By("creating a \"default deny\" network policy")
				_, err = makeDenyAllPolicy(f, f.Namespace.Name, "deny-all")
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				ginkgo.By("asserting the *client* pod can not contact the server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, serverPodConfig, clientPodConfig, serverIP, port)
				}, 1*time.Minute, 6*time.Second).ShouldNot(gomega.Succeed())

			},
			ginkgo.Entry(
				"in L2 dualstack primary UDN",
				networkAttachmentConfigParams{
					name:     nadName,
					topology: "layer2",
					cidr:     joinStrings(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet),
					role:     "primary",
				},
				*podConfig(
					"client-pod",
					withNodeSelector(map[string]string{nodeHostnameKey: workerOneNodeName}),
				),
				*podConfig(
					"server-pod",
					withCommand(func() []string {
						return httpServerContainerCmd(port)
					}),
					withNodeSelector(map[string]string{nodeHostnameKey: workerTwoNodeName}),
				),
			),
			ginkgo.Entry(
				"in L3 dualstack primary UDN",
				networkAttachmentConfigParams{
					name:     nadName,
					topology: "layer3",
					cidr:     joinStrings(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet),
					role:     "primary",
				},
				*podConfig(
					"client-pod",
					withNodeSelector(map[string]string{nodeHostnameKey: workerOneNodeName}),
				),
				*podConfig(
					"server-pod",
					withCommand(func() []string {
						return httpServerContainerCmd(port)
					}),
					withNodeSelector(map[string]string{nodeHostnameKey: workerTwoNodeName}),
				),
			),
		)

		ginkgo.DescribeTable(
			"allow ingress traffic to one pod from a particular namespace",
			func(
				topology string,
				clientPodConfig podConfiguration,
				allowServerPodConfig podConfiguration,
				denyServerPodConfig podConfiguration,
			) {

				namespaceYellow := getNamespaceName(f, nameSpaceYellowSuffix)
				namespaceBlue := getNamespaceName(f, namespaceBlueSuffix)
				namespaceRed := getNamespaceName(f, namespaceRedSuffix)
				namespaceOrange := getNamespaceName(f, namespaceOrangeSuffix)

				nad := networkAttachmentConfigParams{
					topology: topology,
					cidr:     filterCIDRsAndJoin(cs, joinStrings(userDefinedNetworkIPv4Subnet, userDefinedNetworkIPv6Subnet)),
					// The yellow, blue and red namespaces are going to served by green network.
					// Use random suffix for the network name to avoid race between tests.
					networkName: fmt.Sprintf("%s-%s", "green", rand.String(randomStringLength)),
					role:        "primary",
				}

				// Use random suffix in net conf name to avoid race between tests.
				netConfName := fmt.Sprintf("sharednet-%s", rand.String(randomStringLength))
				for _, namespace := range []string{namespaceYellow, namespaceBlue} {
					ginkgo.By("creating the attachment configuration for " + netConfName + " in namespace " + namespace)
					netConfig := newNetworkAttachmentConfig(nad)
					netConfig.cidr = filterCIDRsAndJoin(cs, netConfig.cidr)
					netConfig.namespace = namespace
					netConfig.name = netConfName

					_, err := nadClient.NetworkAttachmentDefinitions(namespace).Create(
						context.Background(),
						generateNAD(netConfig),
						metav1.CreateOptions{},
					)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
				}

				ginkgo.By("creating client/server pods")
				allowServerPodConfig.namespace = namespaceYellow
				denyServerPodConfig.namespace = namespaceYellow
				clientPodConfig.namespace = namespaceBlue
				runUDNPod(cs, namespaceYellow, allowServerPodConfig, nil)
				runUDNPod(cs, namespaceYellow, denyServerPodConfig, nil)
				runUDNPod(cs, namespaceBlue, clientPodConfig, nil)

				ginkgo.By("asserting the server pods have an IP from the configured range")
				var allowServerPodIP, denyServerPodIP string
				for i, cidr := range strings.Split(nad.cidr, ",") {
					if cidr == "" {
						continue
					}
					subnet, err := getNetCIDRSubnet(cidr)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					allowServerPodIP, err = getPodAnnotationIPsForAttachmentByIndex(cs, namespaceYellow, allowServerPodConfig.name,
						namespacedName(namespaceYellow, netConfName), i)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					ginkgo.By(fmt.Sprintf("asserting the allow server pod IP %v is from the configured range %v", allowServerPodIP, cidr))
					gomega.Expect(inRange(subnet, allowServerPodIP)).To(gomega.Succeed())
					denyServerPodIP, err = getPodAnnotationIPsForAttachmentByIndex(cs, namespaceYellow, denyServerPodConfig.name,
						namespacedName(namespaceYellow, netConfName), i)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					ginkgo.By(fmt.Sprintf("asserting the deny server pod IP %v is from the configured range %v", denyServerPodIP, cidr))
					gomega.Expect(inRange(subnet, denyServerPodIP)).To(gomega.Succeed())
				}

				ginkgo.By("asserting the *client* pod can contact the allow server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, allowServerPodConfig, clientPodConfig, allowServerPodIP, port)
				}, 2*time.Minute, 6*time.Second).Should(gomega.Succeed())

				ginkgo.By("asserting the *client* pod can contact the deny server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, denyServerPodConfig, clientPodConfig, denyServerPodIP, port)
				}, 2*time.Minute, 6*time.Second).Should(gomega.Succeed())

				ginkgo.By("creating a \"default deny\" network policy")
				_, err := makeDenyAllPolicy(f, namespaceYellow, "deny-all")
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				ginkgo.By("asserting the *client* pod can not contact the allow server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, allowServerPodConfig, clientPodConfig, allowServerPodIP, port)
				}, 1*time.Minute, 6*time.Second).ShouldNot(gomega.Succeed())

				ginkgo.By("asserting the *client* pod can not contact the deny server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, denyServerPodConfig, clientPodConfig, denyServerPodIP, port)
				}, 1*time.Minute, 6*time.Second).ShouldNot(gomega.Succeed())

				ginkgo.By("creating a \"allow-traffic-to-pod\" network policy for blue and red namespace")
				_, err = allowTrafficToPodFromNamespacePolicy(f, namespaceYellow, namespaceBlue, namespaceRed, "allow-traffic-to-pod", allowServerPodLabel)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				ginkgo.By("asserting the *client* pod can contact the allow server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, allowServerPodConfig, clientPodConfig, allowServerPodIP, port)
				}, 1*time.Minute, 6*time.Second).Should(gomega.Succeed())

				ginkgo.By("asserting the *client* pod can not contact deny server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, denyServerPodConfig, clientPodConfig, denyServerPodIP, port)
				}, 1*time.Minute, 6*time.Second).ShouldNot(gomega.Succeed())

				// Create client pod in red namespace and check network policy is working.
				ginkgo.By("creating client pod in red namespace and check if it is in pending state until NAD is created")
				clientPodConfig.namespace = namespaceRed
				podSpec := generatePodSpec(clientPodConfig)
				_, err = cs.CoreV1().Pods(clientPodConfig.namespace).Create(
					context.Background(),
					podSpec,
					metav1.CreateOptions{},
				)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Consistently(func() v1.PodPhase {
					updatedPod, err := cs.CoreV1().Pods(clientPodConfig.namespace).Get(context.Background(),
						clientPodConfig.name, metav1.GetOptions{})
					if err != nil {
						return v1.PodFailed
					}
					return updatedPod.Status.Phase
				}, 1*time.Minute, 6*time.Second).Should(gomega.Equal(v1.PodPending))

				// The pod won't run and the namespace address set won't be created until the NAD for the network is added
				// to the namespace and we test here that once that happens the policy is reconciled to account for it.
				ginkgo.By("creating NAD for red and orange namespaces and check pod moves into running state")
				for _, namespace := range []string{namespaceRed, namespaceOrange} {
					ginkgo.By("creating the attachment configuration for " + netConfName + " in namespace " + namespace)
					netConfig := newNetworkAttachmentConfig(nad)
					netConfig.namespace = namespace
					netConfig.name = netConfName

					_, err := nadClient.NetworkAttachmentDefinitions(namespace).Create(
						context.Background(),
						generateNAD(netConfig),
						metav1.CreateOptions{},
					)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
				}
				gomega.Eventually(func() v1.PodPhase {
					updatedPod, err := cs.CoreV1().Pods(clientPodConfig.namespace).Get(context.Background(),
						clientPodConfig.name, metav1.GetOptions{})
					if err != nil {
						return v1.PodFailed
					}
					return updatedPod.Status.Phase
				}, 1*time.Minute, 6*time.Second).Should(gomega.Equal(v1.PodRunning))

				ginkgo.By("asserting the *red client* pod can contact the allow server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, allowServerPodConfig, clientPodConfig, allowServerPodIP, port)
				}, 1*time.Minute, 6*time.Second).Should(gomega.Succeed())

				ginkgo.By("asserting the *red client* pod can not contact deny server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, denyServerPodConfig, clientPodConfig, denyServerPodIP, port)
				}, 1*time.Minute, 6*time.Second).ShouldNot(gomega.Succeed())

				// Create client pod in orange namespace now and check network policy is working.
				ginkgo.By("creating client pod in orange namespace")
				clientPodConfig.namespace = namespaceOrange
				runUDNPod(cs, namespaceOrange, clientPodConfig, nil)

				ginkgo.By("asserting the *orange client* pod can not contact the allow server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, allowServerPodConfig, clientPodConfig, allowServerPodIP, port)
				}, 1*time.Minute, 6*time.Second).ShouldNot(gomega.Succeed())

				ginkgo.By("asserting the *orange client* pod can not contact deny server pod exposed endpoint")
				gomega.Eventually(func() error {
					return reachServerPodFromClient(cs, denyServerPodConfig, clientPodConfig, denyServerPodIP, port)
				}, 1*time.Minute, 6*time.Second).ShouldNot(gomega.Succeed())
			},
			ginkgo.Entry(
				"in L2 primary UDN",
				"layer2",
				*podConfig(
					"client-pod",
					withNodeSelector(map[string]string{nodeHostnameKey: workerOneNodeName}),
				),
				*podConfig(
					"allow-server-pod",
					withCommand(func() []string {
						return httpServerContainerCmd(port)
					}),
					withNodeSelector(map[string]string{nodeHostnameKey: workerTwoNodeName}),
					withLabels(allowServerPodLabel),
				),
				*podConfig(
					"deny-server-pod",
					withCommand(func() []string {
						return httpServerContainerCmd(port)
					}),
					withNodeSelector(map[string]string{nodeHostnameKey: workerTwoNodeName}),
					withLabels(denyServerPodLabel),
				),
			),
			ginkgo.Entry(
				"in L3 primary UDN",
				"layer3",
				*podConfig(
					"client-pod",
					withNodeSelector(map[string]string{nodeHostnameKey: workerOneNodeName}),
				),
				*podConfig(
					"allow-server-pod",
					withCommand(func() []string {
						return httpServerContainerCmd(port)
					}),
					withNodeSelector(map[string]string{nodeHostnameKey: workerTwoNodeName}),
					withLabels(allowServerPodLabel),
				),
				*podConfig(
					"deny-server-pod",
					withCommand(func() []string {
						return httpServerContainerCmd(port)
					}),
					withNodeSelector(map[string]string{nodeHostnameKey: workerTwoNodeName}),
					withLabels(denyServerPodLabel),
				),
			))
	})
})

func getNamespaceName(f *framework.Framework, nsSuffix string) string {
	return fmt.Sprintf("%s-%s", f.Namespace.Name, nsSuffix)
}

func allowTrafficToPodFromNamespacePolicy(f *framework.Framework, namespace, fromNamespace1, fromNamespace2, policyName string, podLabel map[string]string) (*knet.NetworkPolicy, error) {
	policy := &knet.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyName,
		},
		Spec: knet.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabel},
			PolicyTypes: []knet.PolicyType{knet.PolicyTypeIngress},
			Ingress: []knet.NetworkPolicyIngressRule{{From: []knet.NetworkPolicyPeer{
				{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": fromNamespace1}}},
				{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": fromNamespace2}}}}}},
		},
	}
	return f.ClientSet.NetworkingV1().NetworkPolicies(namespace).Create(context.TODO(), policy, metav1.CreateOptions{})
}
