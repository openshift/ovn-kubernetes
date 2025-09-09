package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/feature"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	udnclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1/apis/clientset/versioned"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
)

var _ = Describe("Network Segmentation: Preconfigured Layer2 UDN", feature.NetworkSegmentation, func() {
	f := wrappedTestFramework("network-segmentation-preconfigured-l2udn")
	// disable automatic namespace creation, we need to add the required UDN label
	f.SkipNamespaceCreation = true

	var (
		cs        clientset.Interface
		udnClient udnclientset.Interface
	)

	type testConfig struct {
		netConfig          *networkAttachmentConfigParams
		expectedGatewayIPs []string
	}

	BeforeEach(func() {

		cs = f.ClientSet

		var err error
		udnClient, err = udnclientset.NewForConfig(f.ClientConfig())
		Expect(err).NotTo(HaveOccurred())

		namespace, err := f.CreateNamespace(context.TODO(), f.BaseName, map[string]string{
			"e2e-framework":           f.BaseName,
			RequiredUDNNamespaceLabel: "",
		})
		f.Namespace = namespace
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("should respect network configuration",
		func(config testConfig) {
			netConfig := config.netConfig

			By("creating the L2 network")

			netConfig.namespace = f.Namespace.Name
			udnManifest := generateUserDefinedNetworkManifest(netConfig, f.ClientSet)
			cleanup, err := createManifest(netConfig.namespace, udnManifest)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(cleanup)
			Eventually(userDefinedNetworkReadyFunc(f.DynamicClient, netConfig.namespace, netConfig.name), 5*time.Second, time.Second).Should(Succeed())

			By("creating a pod on the custom L2 network")
			podConfig := *podConfig("gateway-test-pod")
			podConfig.namespace = f.Namespace.Name
			pod := runUDNPod(cs, f.Namespace.Name, podConfig, nil)

			By("getting the created UDN object to validate against")
			udn, err := udnClient.K8sV1().UserDefinedNetworks(netConfig.namespace).Get(context.Background(), netConfig.name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By(fmt.Sprintf("validating gateway configuration for pod %s", pod.Name))
			podAnno, err := unmarshalPodAnnotation(pod.Annotations, pod.Namespace+"/"+netConfig.name)
			Expect(err).NotTo(HaveOccurred())

			if isPreConfiguredUdnAddressesEnabled() {
				var podGatewayIPs []string

				for _, gw := range podAnno.Gateways {
					podGatewayIPs = append(podGatewayIPs, gw.String())
				}
				expectedGatewayIPs := filterIPs(f.ClientSet, config.expectedGatewayIPs...)
				Expect(podGatewayIPs).To(ContainElements(expectedGatewayIPs), "Gateway IPs should be found in pod routes")
			}

			// Check that pod IP is not in reserved CIDRs (if any are configured)
			if isPreConfiguredUdnAddressesEnabled() && len(udn.Spec.Layer2.ReservedSubnets) > 0 {
				By(fmt.Sprintf("validating pod %s is not in reserved subnet", pod.Name))
				for _, ip := range podAnno.IPs {
					podIP := ip.IP.String()
					// Check against each reserved subnet
					for _, reservedSubnet := range udn.Spec.Layer2.ReservedSubnets {
						_, reservedNet, err := net.ParseCIDR(string(reservedSubnet))
						Expect(err).NotTo(HaveOccurred())
						Expect(reservedNet.Contains(net.ParseIP(podIP))).To(BeFalse(),
							fmt.Sprintf("Pod IP %s should not be in reserved subnet %s", podIP, reservedSubnet))
					}
				}
			}

		},
		Entry("Layer2 basic configuration", testConfig{
			netConfig: &networkAttachmentConfigParams{
				name:     "custom-l2-net",
				topology: "layer2",
				cidr:     joinStrings("10.128.0.0/16", "2014:100:200::0/60"),
				role:     "primary",
			},
			expectedGatewayIPs: []string{"10.128.0.1", "2014:100:200::1"},
		}),
		Entry("Layer2 with custom subnets", testConfig{
			netConfig: &networkAttachmentConfigParams{
				name:                "custom-l2-net",
				topology:            "layer2",
				cidr:                joinStrings("10.128.0.0/16", "2014:100:200::0/60"),
				role:                "primary",
				defaultGatewayIPs:   joinStrings("10.128.0.10", "2014:100:200::100"),
				reservedCIDRs:       joinStrings("10.128.1.0/24", "2014:100:200::/122"),
				infrastructureCIDRs: joinStrings("10.128.0.10/30", "2014:100:200::100/122"),
			},
			expectedGatewayIPs: []string{"10.128.0.10", "2014:100:200::100"},
		}),
		Entry("Layer2 with inverted gateway/management IPs", testConfig{
			netConfig: &networkAttachmentConfigParams{
				name:              "inv-gateway-net",
				topology:          "layer2",
				cidr:              joinStrings("10.128.0.0/16", "2014:100:200::0/60"),
				role:              "primary",
				defaultGatewayIPs: joinStrings("10.128.0.2", "2014:100:200::2"),
			},
			expectedGatewayIPs: []string{"10.128.0.2", "2014:100:200::2"},
		}),
	)

	Context("duplicate IP validation with primary UDN layer 2 pods", func() {
		const (
			duplicateIPv4 = "10.128.0.200/16"
			duplicateIPv6 = "2014:100:200::200/60"
		)

		type duplicateIPTestConfig struct {
			podIP string
		}

		createPodWithStaticIP := func(podName string, staticIPs []string) *v1.Pod {
			ips, err := json.Marshal(staticIPs)
			Expect(err).NotTo(HaveOccurred(), "Should marshal IPs for annotation")

			podConfig := *podConfig(podName,
				withCommand(func() []string {
					return []string{"pause"}
				}),
				withAnnotations(map[string]string{
					"v1.multus-cni.io/default-network": fmt.Sprintf(`[{"name":"default", "namespace":"ovn-kubernetes", "ips": %s}]`, string(ips)),
				}),
			)
			podConfig.namespace = f.Namespace.Name

			return runUDNPod(cs, f.Namespace.Name, podConfig, nil)
		}

		createPodWithStaticIPNoWait := func(podName string, staticIPs []string) *v1.Pod {
			ips, err := json.Marshal(staticIPs)
			Expect(err).NotTo(HaveOccurred(), "Should marshal IPs for annotation")

			podConfig := *podConfig(podName,
				withCommand(func() []string {
					return []string{"pause"}
				}),
				withAnnotations(map[string]string{
					"v1.multus-cni.io/default-network": fmt.Sprintf(`[{"name":"default", "namespace":"ovn-kubernetes", "ips": %s}]`, string(ips)),
				}),
			)
			podConfig.namespace = f.Namespace.Name

			// Create the pod but don't wait for it to be Running (since it will fail due to duplicate IP)
			podSpec := generatePodSpec(podConfig)
			createdPod, err := cs.CoreV1().Pods(f.Namespace.Name).Create(context.Background(), podSpec, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			return createdPod
		}

		waitForPodDuplicateIPFailure := func(podName string) {
			Eventually(func() []v1.Event {
				events, err := cs.CoreV1().Events(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{
					FieldSelector: fmt.Sprintf("involvedObject.name=%s", podName),
				})
				if err != nil {
					return nil
				}
				return events.Items
			}).
				WithTimeout(60*time.Second).
				WithPolling(2*time.Second).
				Should(ContainElement(SatisfyAll(
					HaveField("Type", Equal("Warning")),
					HaveField("Reason", Equal("ErrorAllocatingPod")),
					HaveField("Message", ContainSubstring("provided IP is already allocated")),
				)), fmt.Sprintf("Pod %s should fail with IP allocation error", podName))
		}

		BeforeEach(func() {
			if !isPreConfiguredUdnAddressesEnabled() {
				Skip("ENABLE_PRE_CONF_UDN_ADDR not configured")
			}

			namespace, err := f.CreateNamespace(context.TODO(), f.BaseName, map[string]string{
				"e2e-framework":           f.BaseName,
				RequiredUDNNamespaceLabel: "",
			})
			f.Namespace = namespace
			Expect(err).NotTo(HaveOccurred())
		})

		DescribeTable("should fail when creating second pod with duplicate static IP",
			func(config duplicateIPTestConfig) {
				podIPs := filterCIDRs(f.ClientSet, config.podIP)

				if len(podIPs) == 0 {
					Skip("IP family not supported in this environment")
				}

				By("Creating the L2 network")
				netConfig := &networkAttachmentConfigParams{
					name:      "duplicate-ip-test-net",
					topology:  "layer2",
					cidr:      joinStrings("10.128.0.0/16", "2014:100:200::0/60"),
					role:      "primary",
					namespace: f.Namespace.Name,
				}
				filterSupportedNetworkConfig(f.ClientSet, netConfig)
				udnManifest := generateUserDefinedNetworkManifest(netConfig, f.ClientSet)
				cleanup, err := createManifest(netConfig.namespace, udnManifest)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(cleanup)
				Eventually(userDefinedNetworkReadyFunc(f.DynamicClient, netConfig.namespace, netConfig.name), 5*time.Second, time.Second).Should(Succeed())

				By("Creating first pod with static IP")
				pod1 := createPodWithStaticIP("test-pod-1", podIPs)

				By("Verifying first pod gets the requested static IP")
				pod1, err = cs.CoreV1().Pods(f.Namespace.Name).Get(context.Background(), pod1.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				netStatus, err := podNetworkStatus(pod1, func(status nadapi.NetworkStatus) bool {
					return status.Default
				})
				Expect(err).NotTo(HaveOccurred(), "Should get network status from pod")
				Expect(netStatus).To(HaveLen(1), "Should have one network status for the default network")

				var expectedPodIPs []string
				for _, ip := range podIPs {
					expectedPodIPs = append(expectedPodIPs, strings.Split(ip, "/")[0])
				}
				Expect(netStatus[0].IPs).To(ConsistOf(expectedPodIPs), "Should have the IPs specified in the default network annotation")

				By("Creating second pod with duplicate IP - should fail")
				pod2 := createPodWithStaticIPNoWait("test-pod-2", podIPs)

				By("Verifying second pod fails with duplicate IP allocation error")
				waitForPodDuplicateIPFailure(pod2.Name)

				By("Verifying first pod is still running normally")
				Eventually(func() v1.PodPhase {
					updatedPod, err := cs.CoreV1().Pods(f.Namespace.Name).Get(context.Background(), pod1.Name, metav1.GetOptions{})
					if err != nil {
						return v1.PodFailed
					}
					return updatedPod.Status.Phase
				}, 30*time.Second, 5*time.Second).Should(Equal(v1.PodRunning))
			},
			Entry("IPv4 duplicate", duplicateIPTestConfig{
				podIP: duplicateIPv4,
			}),
			Entry("IPv6 duplicate", duplicateIPTestConfig{
				podIP: duplicateIPv6,
			}),
		)
	})
})
