package test

// EVPN disruptive e2e test cases for OpenShift clusters.
//
// Sets up 3 EVPN networks (L3 IP-VRF, L2 MAC-VRF, L2 MAC-VRF+IP-VRF) with
// random VTEP subnets, verifies connectivity and isolation, then performs
// disruptive actions — node restart, OVN-K restart, FRR-K8s restart,
// spine (external FRR) restart, then verifies EVPN sessions recover after each.

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	udnv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	e2e "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/feature"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	utilnet "k8s.io/utils/net"
)

// vpnTestState holds the per-network state needed across setup, verification,
// and disruption phases. It embeds EVPNDisruptiveState for the external FRR
// kernel state re-apply logic and adds pods and metadata for connectivity tests.
type vpnTestState struct {
	e2e.EVPNDisruptiveState // TestPod: pinned to targetWorkerNode

	otherPod    *corev1.Pod // on a different node (for pod-to-pod checks)
	vtepSubnets []string    // VTEP CIDRs for re-adding loopback IPs after node reboot
}

var _ = ginkgo.Describe("EVPN: disruptive actions with L3 IP-VRF, L2 MAC-VRF, and L2 MAC-VRF+IP-VRF",
	feature.EVPN, ginkgo.Serial, func() {
		const (
			bgpASN = 64512

			disruptiveBGPTimeout = 5 * time.Minute
			dsRolloutTimeout     = 5 * time.Minute
			nodeShutdownTimeout  = 5 * time.Minute
			nodeStartupTimeout   = 10 * time.Minute

			timeout    = 240 * time.Second
			polling    = 1 * time.Second
			timeoutNOK = 5 * time.Second
			pollingNOK = 2 * time.Second

			curlMaxTime    = 1
			curlMaxTimeStr = "1"
			netexecPortStr = "8080"

			testBaseName = "evpnd"
		)

		f := e2e.NewTestFramework(testBaseName)

		var (
			targetWorkerNode string
			otherWorkerNode  string
			ipFamilySet      sets.Set[utilnet.IPFamily]
			vpnStates        []vpnTestState
		)

		// -----------------------------------------------------------
		// Setup helpers
		// -----------------------------------------------------------

		// setupNetwork creates one EVPN network with external servers, test pods,
		// and returns the fully populated vpnTestState.
		setupNetwork := func(
			ictx infraapi.Context,
			networkName string,
			networkSpec *udnv1.NetworkSpec,
			vtepSubnets []string,
			frrVTEPIP string,
		) vpnTestState {
			ginkgo.GinkgoHelper()

			ginkgo.By("Setting up EVPN network: " + networkName)
			ns, servers, extIDs, err := e2e.SetupEVPNNetworkWithServers(
				f, ictx, testBaseName, ipFamilySet, networkName, networkSpec,
				vtepSubnets, bgpASN,
				"-", // skip FRRConfiguration; created once in BeforeEach
			)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			ginkgo.By("Creating test pod on " + targetWorkerNode + " for " + networkName)
			testPod := e2epod.CreateExecPodOrFail(
				context.Background(), f.ClientSet, ns.Name, ns.Name+"-pod",
				func(p *corev1.Pod) {
					p.Spec.Containers[0].Args = []string{"netexec"}
					p.Spec.NodeName = targetWorkerNode
				},
			)

			ginkgo.By("Creating other pod on " + otherWorkerNode + " for " + networkName)
			otherPod := e2epod.CreateExecPodOrFail(
				context.Background(), f.ClientSet, ns.Name, ns.Name+"-other-pod",
				func(p *corev1.Pod) {
					p.Spec.Containers[0].Args = []string{"netexec"}
					p.Spec.NodeName = otherWorkerNode
				},
			)

			state := vpnTestState{
				EVPNDisruptiveState: e2e.EVPNDisruptiveState{
					Namespace:       ns,
					TestPod:         testPod,
					NetworkName:     networkName,
					NetworkSpec:     networkSpec,
					ExternalServers: servers,
					BridgeName:      "br" + networkName,
					VxlanName:       "vx" + networkName,
					FrrVTEPIP:       frrVTEPIP,
				},
				otherPod:    otherPod,
				vtepSubnets: vtepSubnets,
			}

			if networkSpec.EVPN != nil && networkSpec.EVPN.IPVRF != nil {
				state.IpVRFName = fmt.Sprintf("vrf%d", networkSpec.EVPN.IPVRF.VNI)
				state.IpVRFVNI = int(networkSpec.EVPN.IPVRF.VNI)
			}
			if networkSpec.EVPN != nil && networkSpec.EVPN.MACVRF != nil {
				state.MacVRFVNI = int(networkSpec.EVPN.MACVRF.VNI)
			}
			// VLAN IDs / subnets actually programmed on external FRR (required for spine destroy/reapply).
			state.MacVRFVID = extIDs.MacVRFVID
			state.IpVRFVID = extIDs.IpVRFVID
			state.IpVRFSubnets = extIDs.IpVRFSubnets

			return state
		}

		// -----------------------------------------------------------
		// BeforeEach: set up 3 EVPN networks
		// -----------------------------------------------------------
		ginkgo.BeforeEach(func() {
			if !e2e.IsLocalGWModeEnabled() {
				ginkgo.Skip("EVPN tests require OVN local gateway mode (OVN_GATEWAY_MODE=local)")
			}

			ipFamilySet = sets.New(e2e.GetSupportedIPFamiliesSlice(f.ClientSet)...)

			// Pick two worker nodes: one for test pods, one for other pods.
			ginkgo.By("Selecting target and other worker nodes")
			allNodes, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			targetWorkerNode = ""
			otherWorkerNode = ""
			for _, node := range allNodes.Items {
				if e2e.IsControlPlaneNode(node) {
					continue
				}
				if targetWorkerNode == "" {
					targetWorkerNode = node.Name
				} else if otherWorkerNode == "" {
					otherWorkerNode = node.Name
				}
			}
			gomega.Expect(targetWorkerNode).NotTo(gomega.BeEmpty(), "must find at least one worker node")
			if otherWorkerNode == "" {
				ginkgo.Skip("EVPN disruptive tests require at least two worker nodes for cross-node pod checks")
			}
			ginkgo.GinkgoLogr.Info("Worker nodes", "target", targetWorkerNode, "other", otherWorkerNode)

			ictx := infraprovider.Get().NewTestContext()

			frrVTEPIP, err := e2e.GetExternalFRRIP(ipFamilySet)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Create a single shared FRRConfiguration before setting up networks.
			// This avoids repeated apply calls that could reset BGP sessions.
			ginkgo.By("Creating shared FRRConfiguration for all EVPN networks")
			frrConfigLabels := map[string]string{"network": testBaseName}
			gomega.Expect(
				e2e.CreateFRRConfiguration(ictx, testBaseName, deploymentconfig.Get().FRRK8sNamespace(), bgpASN, frrVTEPIP, frrConfigLabels),
			).To(gomega.Succeed())

			// Each network needs its own VTEP subnet to avoid CIDROverlap.
			// RandomVTEPSubnets returns (IPv4 /24, IPv6 /112). On dual-stack clusters both must be
			// passed through so the VTEP CR and per-node loopbacks include IPv6; otherwise after a
			// node reboot EnsureVTEPLoopbackIPs only restores IPv4 and IPv6 EVPN checks time out.
			l3VtepV4, l3VtepV6 := e2e.RandomVTEPSubnets()
			l2VtepV4, l2VtepV6 := e2e.RandomVTEPSubnets()
			l2l3VtepV4, l2l3VtepV6 := e2e.RandomVTEPSubnets()

			vtepSubnetsForCluster := func(v4, v6 string) []string {
				var s []string
				if ipFamilySet.Has(utilnet.IPv4) {
					gomega.Expect(v4).NotTo(gomega.BeEmpty())
					s = append(s, v4)
				}
				if ipFamilySet.Has(utilnet.IPv6) {
					gomega.Expect(v6).NotTo(gomega.BeEmpty())
					s = append(s, v6)
				}
				gomega.Expect(s).NotTo(gomega.BeEmpty(), "cluster must report at least one supported IP family")
				return s
			}

			// --- Network 1: L3 IP-VRF ---
			l3Name := testBaseName + "l3"
			l3Spec := e2e.NewL3IPVRFNetworkSpec(ipFamilySet)
			l3State := setupNetwork(ictx, l3Name, l3Spec, vtepSubnetsForCluster(l3VtepV4, l3VtepV6), frrVTEPIP)

			// --- Network 2: L2 MAC-VRF ---
			l2Name := testBaseName + "l2"
			l2Spec := e2e.NewL2MACVRFNetworkSpec(ipFamilySet)
			l2State := setupNetwork(ictx, l2Name, l2Spec, vtepSubnetsForCluster(l2VtepV4, l2VtepV6), frrVTEPIP)

			// --- Network 3: L2 MAC-VRF + IP-VRF ---
			l2l3Name := testBaseName + "ml"
			l2l3Spec := e2e.NewL2MACVRFIPVRFNetworkSpec(ipFamilySet)
			l2l3State := setupNetwork(ictx, l2l3Name, l2l3Spec, vtepSubnetsForCluster(l2l3VtepV4, l2l3VtepV6), frrVTEPIP)

			vpnStates = []vpnTestState{l3State, l2State, l2l3State}
		})

		// -----------------------------------------------------------
		// Connectivity and isolation verification
		// -----------------------------------------------------------

		// getServerIP returns an external server's IP for the given family.
		getServerIP := func(serverName string, family utilnet.IPFamily) string {
			ginkgo.GinkgoHelper()
			serverNetwork, err := infraprovider.Get().GetNetwork(serverName)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			iface, err := infraprovider.Get().GetExternalContainerNetworkInterface(
				infraapi.ExternalContainer{Name: serverName}, serverNetwork,
			)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			return e2e.GetFirstIPStringOfFamily(family, []string{iface.IPv4, iface.IPv6})
		}

		// getPodIP returns a pod's primary network IP for the given family.
		getPodIP := func(pod *corev1.Pod, networkName string, family utilnet.IPFamily) string {
			ginkgo.GinkgoHelper()
			ip, err := e2e.GetPodAnnotationIPsForPrimaryNetworkByIPFamily(
				f.ClientSet, pod.Namespace, pod.Name, networkName, family,
			)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(ip).NotTo(gomega.BeEmpty())
			return ip
		}

		// testPodToHostname verifies pod can reach dstIP and gets expected hostname.
		testPodToHostname := func(src *corev1.Pod, dstIP, expect string) {
			ginkgo.GinkgoHelper()
			e2e.EVPNPodConnectsToHostname(src, dstIP, expect)
		}

		// testContainerToClientIPAndExpect verifies external container can reach pod
		// and sees expected source IP.
		testContainerToClientIPAndExpect := func(src, dstIP, expect string) {
			ginkgo.GinkgoHelper()
			gomega.Eventually(func(g gomega.Gomega) {
				ip, err := infraprovider.Get().ExecExternalContainerCommand(
					infraapi.ExternalContainer{Name: src},
					[]string{"curl", "--max-time", curlMaxTimeStr, "-g", "-q", "-s",
						fmt.Sprintf("http://%s/clientip", net.JoinHostPort(dstIP, netexecPortStr))},
				)
				g.Expect(err).NotTo(gomega.HaveOccurred())
				host, _, err := net.SplitHostPort(ip)
				g.Expect(err).NotTo(gomega.HaveOccurred())
				g.Expect(host).To(gomega.Equal(expect))
			}).WithTimeout(timeout).WithPolling(polling).Should(gomega.Succeed())
		}

		// testPodCannotReach verifies pod consistently cannot reach dstIP (isolation).
		testPodCannotReach := func(src *corev1.Pod, dstIP string) {
			ginkgo.GinkgoHelper()
			e2e.EVPNPodCannotConnect(src, dstIP)
		}

		// testContainerCannotReach verifies external container consistently cannot reach dstIP.
		testContainerCannotReach := func(src, dstIP string) {
			ginkgo.GinkgoHelper()
			gomega.Consistently(func(g gomega.Gomega) {
				_, err := infraprovider.Get().ExecExternalContainerCommand(
					infraapi.ExternalContainer{Name: src},
					[]string{"curl", "--max-time", curlMaxTimeStr, "-g", "-q", "-s",
						fmt.Sprintf("http://%s/clientip", net.JoinHostPort(dstIP, netexecPortStr))},
				)
				g.Expect(err).To(gomega.HaveOccurred())
			}).WithTimeout(timeoutNOK).WithPolling(pollingNOK).Should(gomega.Succeed())
		}

		// testNodeCannotReach verifies cluster node consistently cannot reach dstIP.
		testNodeCannotReach := func(nodeName, dstIP string) {
			ginkgo.GinkgoHelper()
			gomega.Consistently(func(g gomega.Gomega) {
				_, err := infraprovider.Get().ExecK8NodeCommand(
					nodeName,
					[]string{"curl", "--max-time", curlMaxTimeStr, "-g", "-q", "-s",
						fmt.Sprintf("http://%s/clientip", net.JoinHostPort(dstIP, netexecPortStr))},
				)
				g.Expect(err).To(gomega.HaveOccurred())
			}).WithTimeout(timeoutNOK).WithPolling(pollingNOK).Should(gomega.Succeed())
		}

		// testPodToClientIP verifies pod can reach dstIP (pod-to-pod connectivity).
		testPodToClientIP := func(src *corev1.Pod, dstIP string) {
			ginkgo.GinkgoHelper()
			_, err := e2epodoutput.RunHostCmdWithRetries(
				src.Namespace,
				src.Name,
				fmt.Sprintf("curl --max-time %d -g -q -s http://%s/clientip",
					curlMaxTime, net.JoinHostPort(dstIP, netexecPortStr)),
				polling,
				timeout,
			)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		// testPodToClientIPAndExpect verifies that the server sees the pod's IP as source.
		testPodToClientIPAndExpect := func(src *corev1.Pod, dstIP, expect string) {
			ginkgo.GinkgoHelper()
			ip, err := e2epodoutput.RunHostCmdWithRetries(
				src.Namespace,
				src.Name,
				fmt.Sprintf("curl --max-time %d -g -q -s http://%s/clientip",
					curlMaxTime, net.JoinHostPort(dstIP, netexecPortStr)),
				polling,
				timeout,
			)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			host, _, err := net.SplitHostPort(ip)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(host).To(gomega.Equal(expect))
		}

		// verifyConnectivityAndIsolation runs the full suite of 7 check categories
		// across all 3 VPN networks. Called at baseline and after each disruption.
		verifyConnectivityAndIsolation := func(label string) {
			ginkgo.GinkgoHelper()

			ginkgo.By(fmt.Sprintf("[%s] Verifying BGP EVPN sessions", label))
			nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			bgpErr := e2e.WaitForExternalFRRBGPReady(len(nodeList.Items), disruptiveBGPTimeout)
			if bgpErr != nil {
				ginkgo.GinkgoLogr.Info("BGP EVPN sessions not established before assertions")
				ginkgo.GinkgoLogr.Info("Inspect with: oc get frrconfiguration -n openshift-frr-k8s -o yaml")
				ginkgo.GinkgoLogr.Info("Inspect with: podman exec frr vtysh -c 'show bgp l2vpn evpn summary'")
				if os.Getenv("EVPN_DEBUG_PAUSE_ON_FAILURE") == "true" {
					ginkgo.GinkgoLogr.Info("EVPN_DEBUG_PAUSE_ON_FAILURE=true — pausing 10 minutes for debugging")
					time.Sleep(10 * time.Minute)
				}
			}
			gomega.Expect(bgpErr).NotTo(gomega.HaveOccurred())

			ginkgo.By(fmt.Sprintf("[%s] Verifying EVPN VNIs are active", label))
			disruptiveStates := make([]e2e.EVPNDisruptiveState, len(vpnStates))
			for i := range vpnStates {
				disruptiveStates[i] = vpnStates[i].EVPNDisruptiveState
			}
			gomega.Expect(e2e.VerifyEVPNVNIsActive(disruptiveStates)).To(gomega.Succeed())

			ginkgo.By(fmt.Sprintf("[%s] Waiting for EVPN route convergence", label))
			gomega.Expect(e2e.WaitForEVPNRouteConvergence(len(nodeList.Items), disruptiveBGPTimeout)).To(gomega.Succeed())

			for i := range vpnStates {
				state := &vpnStates[i]
				for _, family := range []utilnet.IPFamily{utilnet.IPv4, utilnet.IPv6} {
					if !ipFamilySet.Has(family) {
						continue
					}

					// Check 1: Pod -> own external servers
					ginkgo.By(fmt.Sprintf("[%s] Check 1: %s pod reaches its own external servers (IPv%s)",
						label, state.NetworkName, familyStr(family)))
					for _, serverName := range state.ExternalServers {
						serverIP := getServerIP(serverName, family)
						if serverIP == "" {
							continue
						}
						testPodToHostname(state.TestPod, serverIP, serverName)

						podIP := getPodIP(state.TestPod, state.NetworkName, family)
						testPodToClientIPAndExpect(state.TestPod, serverIP, podIP)
					}

					// Check 2: External server -> pod
					ginkgo.By(fmt.Sprintf("[%s] Check 2: external servers reach %s pod (IPv%s)",
						label, state.NetworkName, familyStr(family)))
					for _, serverName := range state.ExternalServers {
						serverIP := getServerIP(serverName, family)
						if serverIP == "" {
							continue
						}
						podIP := getPodIP(state.TestPod, state.NetworkName, family)
						testContainerToClientIPAndExpect(serverName, podIP, serverIP)
					}

					// Check 4: Pod cannot reach other networks' external servers
					ginkgo.By(fmt.Sprintf("[%s] Check 4: %s pod cannot reach other VPNs' servers (IPv%s)",
						label, state.NetworkName, familyStr(family)))
					for j := range vpnStates {
						if i == j {
							continue
						}
						for _, serverName := range vpnStates[j].ExternalServers {
							serverIP := getServerIP(serverName, family)
							if serverIP == "" {
								continue
							}
							testPodCannotReach(state.TestPod, serverIP)
						}
					}

					// Check 5: Other networks' external servers cannot reach pod
					ginkgo.By(fmt.Sprintf("[%s] Check 5: other VPNs' servers cannot reach %s pod (IPv%s)",
						label, state.NetworkName, familyStr(family)))
					podIP := getPodIP(state.TestPod, state.NetworkName, family)
					for j := range vpnStates {
						if i == j {
							continue
						}
						for _, serverName := range vpnStates[j].ExternalServers {
							testContainerCannotReach(serverName, podIP)
						}
					}

					// Check 6: Cluster node cannot reach pod
					ginkgo.By(fmt.Sprintf("[%s] Check 6: cluster nodes cannot reach %s pod (IPv%s)",
						label, state.NetworkName, familyStr(family)))
					testNodeCannotReach(targetWorkerNode, podIP)
					if otherWorkerNode != targetWorkerNode {
						testNodeCannotReach(otherWorkerNode, podIP)
					}

					// Check 7: Pod-to-pod same network (different node)
					ginkgo.By(fmt.Sprintf("[%s] Check 7: pod-to-pod on %s (IPv%s)",
						label, state.NetworkName, familyStr(family)))
					otherPodIP := getPodIP(state.otherPod, state.NetworkName, family)
					testPodToClientIP(state.TestPod, otherPodIP)
					testPodToClientIP(state.otherPod, podIP)
				}

				// Check 3: Pod -> KAPI service
				ginkgo.By(fmt.Sprintf("[%s] Check 3: %s pod can reach KAPI", label, state.NetworkName))
				output, err := e2epodoutput.RunHostCmdWithRetries(
					state.TestPod.Namespace,
					state.TestPod.Name,
					fmt.Sprintf("curl --max-time %d -g -q -s -k https://kubernetes.default/healthz", curlMaxTime),
					polling,
					timeout,
				)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(output).To(gomega.Equal("ok"))
			}
		}

		// recreateTargetNodePods force-deletes pods on targetWorkerNode and recreates them.
		recreateTargetNodePods := func() {
			ginkgo.GinkgoHelper()
			ginkgo.By("Recreating test pods on " + targetWorkerNode)
			for i := range vpnStates {
				state := &vpnStates[i]
				podName := state.Namespace.Name + "-pod"
				_ = e2e.DeletePodWithWaitByName(context.Background(), f.ClientSet, podName, state.Namespace.Name)
				state.TestPod = e2epod.CreateExecPodOrFail(
					context.Background(), f.ClientSet, state.Namespace.Name, podName,
					func(p *corev1.Pod) {
						p.Spec.Containers[0].Args = []string{"netexec"}
						p.Spec.NodeName = targetWorkerNode
					},
				)
			}
		}

		// -----------------------------------------------------------
		// 4 separate disruptive test cases, each with baseline + disruption
		// -----------------------------------------------------------

		ginkgo.It("recovers after node restart", func() {
			verifyConnectivityAndIsolation("Baseline")

			ginkgo.By("Restarting worker node " + targetWorkerNode)
			gomega.Expect(infraprovider.Get().RebootNode(targetWorkerNode)).To(gomega.Succeed())

			ginkgo.By("Waiting for node to be NotReady")
			e2e.WaitForNodeReadyState(f, targetWorkerNode, nodeShutdownTimeout, false)

			ginkgo.By("Waiting for node to be Ready again")
			e2e.WaitForNodeReadyState(f, targetWorkerNode, nodeStartupTimeout, true)

			ginkgo.By("Waiting for ovnkube-node to be ready on " + targetWorkerNode)
			gomega.Expect(
				e2e.RestartOVNKubeNodePod(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), targetWorkerNode),
			).To(gomega.Succeed())

			ginkgo.By("Waiting for ovnkube-node DaemonSet rollout after node restart")
			gomega.Expect(
				e2e.WaitForDaemonSetReady(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), "ovnkube-node", dsRolloutTimeout),
			).To(gomega.Succeed())

			ginkgo.By("Waiting for FRR-K8s DaemonSet rollout after node restart")
			gomega.Expect(
				e2e.WaitForDaemonSetReady(f.ClientSet, deploymentconfig.Get().FRRK8sNamespace(), deploymentconfig.Get().FRRK8sDaemonSetName(), dsRolloutTimeout),
			).To(gomega.Succeed())

			ginkgo.By("Re-adding VTEP loopback IPs lost during node reboot")
			ictx := infraprovider.Get().NewTestContext()
			for _, state := range vpnStates {
				gomega.Expect(
					e2e.EnsureVTEPLoopbackIPs(f, ictx, state.vtepSubnets),
				).To(gomega.Succeed())
			}

			recreateTargetNodePods()
			verifyConnectivityAndIsolation("After node restart")
		})

		ginkgo.It("recovers after OVN-K restart", func() {
			verifyConnectivityAndIsolation("Baseline")

			ginkgo.By("Restarting ovnkube-node pods on all workers")
			nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			var workerNodeNames []string
			for _, node := range nodeList.Items {
				if !e2e.IsControlPlaneNode(node) {
					workerNodeNames = append(workerNodeNames, node.Name)
				}
			}
			gomega.Expect(
				e2e.RestartOVNKubeNodePodsInParallel(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), workerNodeNames...),
			).To(gomega.Succeed())

			ginkgo.By("Waiting for ovnkube-node DaemonSet rollout to complete")
			gomega.Expect(
				e2e.WaitForDaemonSetReady(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), "ovnkube-node", dsRolloutTimeout),
			).To(gomega.Succeed())

			verifyConnectivityAndIsolation("After OVN-K restart")
		})

		ginkgo.It("recovers after FRR-K8s restart", func() {
			verifyConnectivityAndIsolation("Baseline")

			frrk8sNS := deploymentconfig.Get().FRRK8sNamespace()
			ginkgo.By("Restarting FRR-K8s pods in " + frrk8sNS)
			gomega.Expect(
				e2e.RestartFRRK8sPods(f.ClientSet, frrk8sNS),
			).To(gomega.Succeed())

			ginkgo.By("Waiting for FRR-K8s DaemonSet rollout to complete")
			gomega.Expect(
				e2e.WaitForDaemonSetReady(f.ClientSet, frrk8sNS, deploymentconfig.Get().FRRK8sDaemonSetName(), dsRolloutTimeout),
			).To(gomega.Succeed())

			verifyConnectivityAndIsolation("After FRR-K8s restart")
		})

		ginkgo.It("recovers after spine restart", func() {
			verifyConnectivityAndIsolation("Baseline")

			disruptiveStates := make([]e2e.EVPNDisruptiveState, len(vpnStates))
			for i := range vpnStates {
				disruptiveStates[i] = vpnStates[i].EVPNDisruptiveState
			}

			ginkgo.By("Destroying kernel state on external FRR (simulating router power-off)")
			e2e.DestroyEVPNKernelStateOnFRR(disruptiveStates)

			ginkgo.By("Restarting FRR daemons (simulating router power-on)")
			gomega.Expect(e2e.RestartExternalFRRDaemons()).To(gomega.Succeed())

			ginkgo.By("Waiting for FRR process to be ready")
			gomega.Expect(e2e.WaitForExternalFRRProcessReady(2 * time.Minute)).To(gomega.Succeed())

			ginkgo.By("Re-applying transient kernel state on external FRR")
			ictx := infraprovider.Get().NewTestContext()
			gomega.Expect(e2e.ReapplyEVPNKernelStateOnFRR(ictx, ipFamilySet, disruptiveStates)).To(gomega.Succeed())

			ginkgo.By("Waiting for FRR/zebra after bulk ip-link changes from re-apply")
			gomega.Expect(e2e.WaitForExternalFRRProcessReady(time.Minute)).To(gomega.Succeed())

			verifyConnectivityAndIsolation("After spine restart")
		})
	})

// familyStr returns "4" or "6" for logging.
func familyStr(family utilnet.IPFamily) string {
	if family == utilnet.IPv6 {
		return "6"
	}
	return "4"
}
