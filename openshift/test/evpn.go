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
	"math/rand"
	"net"
	"os"
	"strings"
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
// and disruption phases for the OpenShift EVPN disruptive test suite.
type vpnTestState struct {
	// Kubernetes objects
	Namespace   *corev1.Namespace
	TestPod     *corev1.Pod // pinned to targetWorkerNode
	otherPod    *corev1.Pod // on a different node (for pod-to-pod checks)
	NetworkName string
	NetworkSpec *udnv1.NetworkSpec

	// External server names — Docker/Podman containers outside the cluster created by
	// setupMACVRFAgnhost / setupIPVRFAgnhost. Used in connectivity and isolation checks.
	ExternalServers []string

	// vtepSubnets are the VTEP CIDRs for re-adding loopback IPs after node reboot.
	vtepSubnets []string

	// Parameters for re-applying transient kernel state on the external FRR container
	// after a container restart (bridges and VXLANs are lost on stop/start).
	BridgeName string
	VxlanName  string
	FrrVTEPIP  string // FRR's IP on the provider specific primary network; used as VXLAN local IP
	MacVRFVNI  int
	MacVRFVID  int
	// MacVRFFrrInterface is the FRR-side interface attached to the MAC-VRF bridge,
	// recorded at setup time so re-apply does not need a post-VRF-deletion IPv6 lookup.
	MacVRFFrrInterface string
	IpVRFName          string
	IpVRFVNI           int
	IpVRFVID           int
	// IpVRFFrrInterface is the FRR-side interface enslaved to the IP-VRF,
	// recorded at setup time so re-apply does not need a post-VRF-deletion IPv6 lookup.
	IpVRFFrrInterface string
	// IpVRFFrrIPs are the FRR container's IPv4 and IPv6 addresses on the IP-VRF Docker
	// network, recorded at setup time for restoreFRRIPv6AfterVRFAssignment during re-apply.
	IpVRFFrrIPs  []string
	IpVRFSubnets []string // subnets advertised by the IP-VRF agnhost
}

var _ = ginkgo.Describe("EVPN: disruptive actions with L3 IP-VRF, L2 MAC-VRF, and L2 MAC-VRF+IP-VRF",
	feature.EVPN, ginkgo.Serial, func() {
		const (
			bgpASN = 64512

			disruptiveBGPTimeout = 5 * time.Minute
			dsRolloutTimeout     = 5 * time.Minute

			timeout    = 240 * time.Second
			polling    = 1 * time.Second
			timeoutNOK = 5 * time.Second
			pollingNOK = 2 * time.Second

			curlMaxTime    = 1
			curlMaxTimeStr = "1"
			netexecPortStr = "8080"

			testBaseName = "evpnd"
		)

		f := newTestFramework(testBaseName)

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
			// Delete pod before CUDN/namespace cleanup so the UDN controller can remove
			// its finalizer immediately, avoiding a burst of OVN reconciliation that
			// slows the API server and causes subsequent cleanup calls to time out.
			ictx.AddCleanUpFn(func() error {
				return e2epod.DeletePodWithWait(context.Background(), f.ClientSet, testPod)
			})

			ginkgo.By("Creating other pod on " + otherWorkerNode + " for " + networkName)
			otherPod := e2epod.CreateExecPodOrFail(
				context.Background(), f.ClientSet, ns.Name, ns.Name+"-other-pod",
				func(p *corev1.Pod) {
					p.Spec.Containers[0].Args = []string{"netexec"}
					p.Spec.NodeName = otherWorkerNode
				},
			)
			ictx.AddCleanUpFn(func() error {
				return e2epod.DeletePodWithWait(context.Background(), f.ClientSet, otherPod)
			})

			state := vpnTestState{
				Namespace:       ns,
				TestPod:         testPod,
				NetworkName:     networkName,
				NetworkSpec:     networkSpec,
				ExternalServers: servers,
				BridgeName:      evpnBridgeName(networkName),
				VxlanName:       evpnVxlanName(networkName),
				FrrVTEPIP:       frrVTEPIP,
				otherPod:        otherPod,
				vtepSubnets:     vtepSubnets,
			}

			if networkSpec.EVPN != nil && networkSpec.EVPN.IPVRF != nil {
				state.IpVRFName = evpnIPVRFName(networkSpec.EVPN.IPVRF.VNI)
				state.IpVRFVNI = int(networkSpec.EVPN.IPVRF.VNI)
			}
			if networkSpec.EVPN != nil && networkSpec.EVPN.MACVRF != nil {
				state.MacVRFVNI = int(networkSpec.EVPN.MACVRF.VNI)
			}
			// VLAN IDs / subnets actually programmed on external FRR (required for spine destroy/reapply).
			state.MacVRFVID = extIDs.MacVRFVID
			state.IpVRFVID = extIDs.IpVRFVID
			state.IpVRFSubnets = extIDs.IpVRFSubnets

			// Record the FRR-side interface names while both IPv4 and IPv6 are intact on the
			// interfaces (IPv6 global addresses drop after VRF deletion, which would cause a
			// re-lookup in reapplyEVPNKernelStateOnFRR to return an empty InfName).
			frr := infraapi.ExternalContainer{Name: externalFRRName}
			if networkSpec.EVPN != nil && networkSpec.EVPN.MACVRF != nil {
				macNet, err := infraprovider.Get().GetNetwork(evpnMACVRFAgnhostName(networkName))
				gomega.Expect(err).NotTo(gomega.HaveOccurred(), "get MAC-VRF docker network")
				macInf, err := infraprovider.Get().GetExternalContainerNetworkInterface(frr, macNet)
				gomega.Expect(err).NotTo(gomega.HaveOccurred(), "get FRR interface for MAC-VRF")
				state.MacVRFFrrInterface = macInf.InfName
			}
			if networkSpec.EVPN != nil && networkSpec.EVPN.IPVRF != nil {
				ipNet, err := infraprovider.Get().GetNetwork(evpnIPVRFAgnhostName(networkName))
				gomega.Expect(err).NotTo(gomega.HaveOccurred(), "get IP-VRF docker network")
				ipInf, err := infraprovider.Get().GetExternalContainerNetworkInterface(frr, ipNet)
				gomega.Expect(err).NotTo(gomega.HaveOccurred(), "get FRR interface for IP-VRF")
				state.IpVRFFrrInterface = ipInf.InfName
				state.IpVRFFrrIPs = []string{ipInf.IPv4, ipInf.IPv6}
			}

			return state
		}

		// -----------------------------------------------------------
		// BeforeEach: set up 3 EVPN networks
		// -----------------------------------------------------------
		ginkgo.BeforeEach(func() {
			if !isLocalGWModeEnabled() {
				ginkgo.Skip("EVPN tests require OVN local gateway mode (OVN_GATEWAY_MODE=local)")
			}

			ipFamilySet = sets.New(getSupportedIPFamiliesSlice(f.ClientSet)...)

			// Pick two worker nodes: one for test pods, one for other pods.
			ginkgo.By("Selecting target and other worker nodes")
			allNodes, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			targetWorkerNode = ""
			otherWorkerNode = ""
			for _, node := range allNodes.Items {
				if isControlPlaneNode(node) {
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

			frrVTEPIP, err := getExternalFRRIP(ipFamilySet)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Create a single shared FRRConfiguration before setting up networks.
			ginkgo.By("Creating shared FRRConfiguration for all EVPN networks")
			frrConfigLabels := map[string]string{"network": testBaseName}
			gomega.Expect(
				e2e.CreateFRRConfiguration(ictx, testBaseName, deploymentconfig.Get().FRRK8sNamespace(), bgpASN, frrVTEPIP, frrConfigLabels),
			).To(gomega.Succeed())

			// Each network needs its own VTEP subnet to avoid CIDROverlap.
			// Only IPv4 VTEP is supported; randomVTEPSubnets returns an IPv4 /24.
			l3VtepV4 := randomVTEPSubnets()
			gomega.Expect(l3VtepV4).NotTo(gomega.BeEmpty(), "randomVTEPSubnets IPv4 for L3 IP-VRF network")
			l2VtepV4 := randomVTEPSubnets()
			gomega.Expect(l2VtepV4).NotTo(gomega.BeEmpty(), "randomVTEPSubnets IPv4 for L2 MAC-VRF network")
			l2l3VtepV4 := randomVTEPSubnets()
			gomega.Expect(l2l3VtepV4).NotTo(gomega.BeEmpty(), "randomVTEPSubnets IPv4 for L2+L3 network")

			// Three independent randomCUDNSubnets() draws can collide on /20 IPv4; Podman then
			// rejects the second MAC-VRF bridge. Allocate disjoint CUDN pairs up front.
			cudnTriple, err := e2e.AllocDistinctEVPNCUDNSubnets(3)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// --- Network 1: L3 IP-VRF ---
			l3Name := testBaseName + "l3"
			l3Spec := newL3IPVRFNetworkSpec(ipFamilySet, cudnTriple[0][0], cudnTriple[0][1])
			l3State := setupNetwork(ictx, l3Name, l3Spec, []string{l3VtepV4}, frrVTEPIP)

			// --- Network 2: L2 MAC-VRF ---
			l2Name := testBaseName + "l2"
			l2Spec := newL2MACVRFNetworkSpec(ipFamilySet, cudnTriple[1][0], cudnTriple[1][1])
			l2State := setupNetwork(ictx, l2Name, l2Spec, []string{l2VtepV4}, frrVTEPIP)

			// --- Network 3: L2 MAC-VRF + IP-VRF ---
			l2l3Name := testBaseName + "ml"
			l2l3Spec := newL2MACVRFIPVRFNetworkSpec(ipFamilySet, cudnTriple[2][0], cudnTriple[2][1])
			l2l3State := setupNetwork(ictx, l2l3Name, l2l3Spec, []string{l2l3VtepV4}, frrVTEPIP)

			vpnStates = []vpnTestState{l3State, l2State, l2l3State}
		})

		// -----------------------------------------------------------
		// Connectivity and isolation verification
		// -----------------------------------------------------------

		// testPodToHostnameAndExpect verifies pod can reach dstIP and gets expected hostname.
		testPodToHostnameAndExpect := func(src *corev1.Pod, dstIP, expect string) {
			ginkgo.GinkgoHelper()
			hostname, err := e2epodoutput.RunHostCmdWithRetries(
				src.Namespace,
				src.Name,
				fmt.Sprintf("curl --max-time %d -g -q -s http://%s/hostname", curlMaxTime, net.JoinHostPort(dstIP, netexecPortStr)),
				polling,
				timeout,
			)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(hostname).To(gomega.Equal(expect))
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

		// testPodToClientIPNOK verifies pod consistently cannot reach dstIP (isolation).
		testPodToClientIPNOK := func(src *corev1.Pod, dstIP string) {
			ginkgo.GinkgoHelper()
			gomega.Consistently(func(g gomega.Gomega) {
				_, err := e2epodoutput.RunHostCmd(
					src.Namespace,
					src.Name,
					fmt.Sprintf("curl --max-time %d -g -q -s http://%s/clientip", curlMaxTime, net.JoinHostPort(dstIP, netexecPortStr)),
				)
				g.Expect(err).To(gomega.HaveOccurred())
			}).WithTimeout(timeoutNOK).WithPolling(pollingNOK).Should(gomega.Succeed())
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

			nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// waitForEVPNRouteConvergence polls "show bgp l2vpn evpn summary json" and
			// requires both peer.State=="Established" AND bidirectional route exchange, so it
			// covers both session establishment and convergence in one step.
			ginkgo.By(fmt.Sprintf("[%s] Waiting for BGP EVPN sessions and route convergence", label))
			convergenceErr := waitForEVPNRouteConvergence(len(nodeList.Items), disruptiveBGPTimeout)
			if convergenceErr != nil {
				ginkgo.GinkgoLogr.Info("BGP EVPN sessions or routes not converged")
				ginkgo.GinkgoLogr.Info("Inspect with: oc get frrconfiguration -n openshift-frr-k8s -o yaml")
				ginkgo.GinkgoLogr.Info("Inspect with: podman exec frr vtysh -c 'show bgp l2vpn evpn summary'")
				if os.Getenv("EVPN_DEBUG_PAUSE_ON_FAILURE") == "true" {
					ginkgo.GinkgoLogr.Info("EVPN_DEBUG_PAUSE_ON_FAILURE=true — pausing 10 minutes for debugging")
					time.Sleep(10 * time.Minute)
				}
			}
			gomega.Expect(convergenceErr).NotTo(gomega.HaveOccurred())

			for i := range vpnStates {
				state := &vpnStates[i]
				for _, family := range []utilnet.IPFamily{utilnet.IPv4, utilnet.IPv6} {
					if !ipFamilySet.Has(family) {
						continue
					}

					// Check 1: Pod -> own external servers
					ginkgo.By(fmt.Sprintf("[%s] Check 1: %s pod reaches its own external servers (%v)",
						label, state.NetworkName, family))
					for _, serverName := range state.ExternalServers {
						serverIP := getServerIP(serverName, family)
						if serverIP == "" {
							continue
						}
						testPodToHostnameAndExpect(state.TestPod, serverIP, serverName)

						podIP := getPodIP(f.ClientSet, state.TestPod, state.NetworkName, family)
						testPodToClientIPAndExpect(state.TestPod, serverIP, podIP)
					}

					// Check 2: External server -> pod
					ginkgo.By(fmt.Sprintf("[%s] Check 2: external servers reach %s pod (%v)",
						label, state.NetworkName, family))
					for _, serverName := range state.ExternalServers {
						serverIP := getServerIP(serverName, family)
						if serverIP == "" {
							continue
						}
						podIP := getPodIP(f.ClientSet, state.TestPod, state.NetworkName, family)
						testContainerToClientIPAndExpect(serverName, podIP, serverIP)
					}

					// Check 4: Pod cannot reach other networks' external servers
					ginkgo.By(fmt.Sprintf("[%s] Check 4: %s pod cannot reach other VPNs' servers (%v)",
						label, state.NetworkName, family))
					for j := range vpnStates {
						if i == j {
							continue
						}
						for _, serverName := range vpnStates[j].ExternalServers {
							serverIP := getServerIP(serverName, family)
							if serverIP == "" {
								continue
							}
							testPodToClientIPNOK(state.TestPod, serverIP)
						}
					}

				// Check 5: Other networks' external servers cannot reach pod
				ginkgo.By(fmt.Sprintf("[%s] Check 5: other VPNs' servers cannot reach %s pod (%v)",
					label, state.NetworkName, family))
				podIP := getPodIP(f.ClientSet, state.TestPod, state.NetworkName, family)
					for j := range vpnStates {
						if i == j {
							continue
						}
						for _, serverName := range vpnStates[j].ExternalServers {
							testContainerCannotReach(serverName, podIP)
						}
					}

					// Check 6: Cluster node cannot reach pod
					ginkgo.By(fmt.Sprintf("[%s] Check 6: cluster nodes cannot reach %s pod (%v)",
						label, state.NetworkName, family))
					testNodeCannotReach(targetWorkerNode, podIP)
					if otherWorkerNode != targetWorkerNode {
						testNodeCannotReach(otherWorkerNode, podIP)
					}

				// Check 7: Pod-to-pod same network (different node)
				ginkgo.By(fmt.Sprintf("[%s] Check 7: pod-to-pod on %s (%v)",
					label, state.NetworkName, family))
				otherPodIP := getPodIP(f.ClientSet, state.otherPod, state.NetworkName, family)
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
				_ = deletePodWithWaitByName(context.Background(), f.ClientSet, podName, state.Namespace.Name)
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

			ginkgo.By("Waiting for ovnkube-node to be ready on " + targetWorkerNode)
			gomega.Expect(
				restartOVNKubeNodePod(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), targetWorkerNode),
			).To(gomega.Succeed())

			ginkgo.By("Waiting for ovnkube-node DaemonSet rollout after node restart")
			gomega.Expect(
				waitForDaemonSetReady(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), "ovnkube-node", dsRolloutTimeout),
			).To(gomega.Succeed())

			ginkgo.By("Waiting for FRR-K8s DaemonSet rollout after node restart")
			gomega.Expect(
				waitForDaemonSetReady(f.ClientSet, deploymentconfig.Get().FRRK8sNamespace(), deploymentconfig.Get().FRRK8sDaemonSetName(), dsRolloutTimeout),
			).To(gomega.Succeed())

			ginkgo.By("Re-adding VTEP loopback IPs lost during node reboot")
			ictx := infraprovider.Get().NewTestContext()
			for _, state := range vpnStates {
				gomega.Expect(
					ensureVTEPLoopbackIPs(f, ictx, state.vtepSubnets),
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
				if !isControlPlaneNode(node) {
					workerNodeNames = append(workerNodeNames, node.Name)
				}
			}
			gomega.Expect(
				restartOVNKubeNodePodsInParallel(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), workerNodeNames...),
			).To(gomega.Succeed())

			ginkgo.By("Waiting for ovnkube-node DaemonSet rollout to complete")
			gomega.Expect(
				waitForDaemonSetReady(f.ClientSet, deploymentconfig.Get().OVNKubernetesNamespace(), "ovnkube-node", dsRolloutTimeout),
			).To(gomega.Succeed())

			verifyConnectivityAndIsolation("After OVN-K restart")
		})

		ginkgo.It("recovers after FRR-K8s restart", func() {
			verifyConnectivityAndIsolation("Baseline")

			frrk8sNS := deploymentconfig.Get().FRRK8sNamespace()
			ginkgo.By("Restarting FRR-K8s pods in " + frrk8sNS)
			gomega.Expect(
				restartFRRK8sPods(f.ClientSet, frrk8sNS),
			).To(gomega.Succeed())

			ginkgo.By("Waiting for FRR-K8s DaemonSet rollout to complete")
			gomega.Expect(
				waitForDaemonSetReady(f.ClientSet, frrk8sNS, deploymentconfig.Get().FRRK8sDaemonSetName(), dsRolloutTimeout),
			).To(gomega.Succeed())

			verifyConnectivityAndIsolation("After FRR-K8s restart")
		})

		ginkgo.It("recovers after spine restart", func() {
			verifyConnectivityAndIsolation("Baseline")

			ginkgo.By("Destroying kernel state on external FRR (simulating router power-off)")
			gomega.Expect(destroyEVPNKernelStateOnFRR(vpnStates)).To(gomega.Succeed())

			ginkgo.By("Restarting FRR daemons (simulating router power-on)")
			gomega.Expect(restartExternalFRRDaemons()).To(gomega.Succeed())

			ginkgo.By("Waiting for FRR daemons to be ready")
			gomega.Expect(waitForExternalFRRDaemonsReady(2 * time.Minute)).To(gomega.Succeed())

			ginkgo.By("Re-applying transient kernel state on external FRR")
			ictx := infraprovider.Get().NewTestContext()
			gomega.Expect(reapplyEVPNKernelStateOnFRR(ictx, vpnStates)).To(gomega.Succeed())

			ginkgo.By("Waiting for FRR/zebra after bulk ip-link changes from re-apply")
			gomega.Expect(waitForExternalFRRDaemonsReady(time.Minute)).To(gomega.Succeed())

			verifyConnectivityAndIsolation("After spine restart")
		})
	})

// =============================================================================
// EVPN Disruptive Test Helpers (OpenShift-specific)
// =============================================================================

// destroyEVPNKernelStateOnFRR removes transient kernel objects (bridges, VXLANs, VRFs, SVIs)
// from the external FRR container, simulating the loss of that state on a full container stop
// or power cycle. Call before reapplyEVPNKernelStateOnFRR when a real `docker stop`/restart of
// the FRR container is not used. Returns an error if any deletion fails for a reason other than
// the device already being absent (e.g. SSH/podman failure).
func destroyEVPNKernelStateOnFRR(states []vpnTestState) error {
	frr := infraapi.ExternalContainer{Name: externalFRRName}

	for _, state := range states {
		hasIPVRF := state.NetworkSpec.EVPN != nil && state.NetworkSpec.EVPN.IPVRF != nil

		type delCmd struct {
			label string
			args  []string
		}
		cmds := []delCmd{}
		if hasIPVRF {
			sviName := evpnSVIName(state.BridgeName, state.IpVRFVID)
			cmds = append(cmds,
				delCmd{"SVI", []string{"ip", "link", "del", sviName}},
				delCmd{"VRF", []string{"ip", "link", "del", state.IpVRFName}},
			)
		}
		cmds = append(cmds,
			delCmd{"VXLAN", []string{"ip", "link", "del", state.VxlanName}},
			delCmd{"bridge", []string{"ip", "link", "del", state.BridgeName}},
		)

		for _, cmd := range cmds {
			if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd.args); err != nil {
				if !strings.Contains(err.Error(), "Cannot find device") {
					return fmt.Errorf("destroyEVPNKernelState: failed to delete %s %s: %w",
						cmd.label, cmd.args[len(cmd.args)-1], err)
				}
				ginkgo.GinkgoLogr.Info("destroyEVPNKernelState: device already absent",
					"type", cmd.label, "device", cmd.args[len(cmd.args)-1])
			}
		}

		ginkgo.GinkgoLogr.Info("destroyEVPNKernelState: cleaned up kernel state", "network", state.NetworkName)
	}
	return nil
}

// reapplyEVPNKernelStateOnFRR re-creates all transient Linux kernel objects (bridge,
// VXLAN, VRF, MAC-VRF VLAN entries, IP-VRF SVI) on the external FRR container for
// every VPN in states.
//
// Background: docker restart destroys all kernel state inside the container's network
// namespace (bridges, VXLANs, VRFs). Docker does reconnect FRR to all its Docker
// networks on startup, so FRR's interfaces to the agnhost Docker networks are back
// automatically — but they are no longer attached to the bridge or VRF.
//
// FRR's BGP config is NOT re-applied here — it was persisted via "write memory" and
// is reloaded from /etc/frr/frr.conf on FRR startup.
//
// VIDs (VLAN IDs) are re-randomised on each re-apply. VID is a purely FRR-local tag;
// VXLAN encapsulation uses VNI (not VID), so a fresh VID is safe and correct.
func reapplyEVPNKernelStateOnFRR(ictx infraapi.Context, states []vpnTestState) error {
	frr := infraapi.ExternalContainer{Name: externalFRRName}

	for _, state := range states {
		hasMACVRF := state.NetworkSpec.EVPN != nil && state.NetworkSpec.EVPN.MACVRF != nil
		hasIPVRF := state.NetworkSpec.EVPN != nil && state.NetworkSpec.EVPN.IPVRF != nil

		ginkgo.GinkgoLogr.Info("Re-applying EVPN bridge/VXLAN on external FRR", "network", state.NetworkName)
		if err := setupEVPNBridgeOnExternalFRR(ictx, state.FrrVTEPIP, state.BridgeName, state.VxlanName); err != nil {
			return fmt.Errorf("failed to re-apply EVPN bridge for %q: %w", state.NetworkName, err)
		}

		if hasMACVRF {
			newMACVID := randomVID()
			ginkgo.GinkgoLogr.Info("Re-applying MAC-VRF on external FRR", "network", state.NetworkName, "vni", state.MacVRFVNI, "newVID", newMACVID)
			if err := setupMACVRFOnExternalFRR(ictx, state.MacVRFVNI, newMACVID, state.BridgeName, state.VxlanName); err != nil {
				return fmt.Errorf("failed to re-apply MAC-VRF for %q: %w", state.NetworkName, err)
			}

			vidStr := fmt.Sprintf("%d", newMACVID)
			frrCmds := [][]string{
				{"ip", "link", "set", state.MacVRFFrrInterface, "master", state.BridgeName},
				{"bridge", "vlan", "add", "dev", state.MacVRFFrrInterface, "vid", vidStr, "pvid", "untagged"},
				{"ip", "link", "set", state.MacVRFFrrInterface, "up"},
			}
			for _, cmd := range frrCmds {
				if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd); err != nil {
					return fmt.Errorf("failed to re-attach FRR interface %q to MAC-VRF bridge: %w", state.MacVRFFrrInterface, err)
				}
			}
		}

		if hasIPVRF {
			newIPVID := randomVID()
			ginkgo.GinkgoLogr.Info("Re-applying IP-VRF on external FRR", "network", state.NetworkName, "vni", state.IpVRFVNI, "newVID", newIPVID)
			if err := setupIPVRFOnExternalFRR(ictx, state.IpVRFName, state.IpVRFVNI, newIPVID, state.BridgeName, state.VxlanName); err != nil {
				return fmt.Errorf("failed to re-apply IP-VRF for %q: %w", state.NetworkName, err)
			}

			frrCmds := [][]string{
				{"ip", "link", "set", state.IpVRFFrrInterface, "master", state.IpVRFName},
				{"ip", "link", "set", state.IpVRFFrrInterface, "up"},
			}
			for _, cmd := range frrCmds {
				if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd); err != nil {
					return fmt.Errorf("failed to re-attach FRR interface %q to IP-VRF: %w", state.IpVRFFrrInterface, err)
				}
			}
			// Linux silently drops global IPv6 addresses from an interface when it is
			// enslaved to a VRF device, so we must re-add them after re-attachment.
			// IPv4 addresses are NOT affected by VRF enslavement and remain on the
			// interface throughout, so no equivalent restore is needed for IPv4.
			// On IPv4-only clusters there is nothing to restore
			for _, ip := range state.IpVRFFrrIPs {
				if utilnet.IsIPv6String(ip) {
					if err := restoreFRRIPv6AfterVRFAssignment(frr, state.IpVRFFrrInterface, state.IpVRFFrrIPs, state.IpVRFSubnets); err != nil {
						return fmt.Errorf("failed to restore IPv6 addresses on FRR after VRF re-attach for %q: %w", state.NetworkName, err)
					}
					break
				}
			}
		}
	}
	return nil
}

// randomVID generates a random VLAN ID in the valid range (2-4094).
// VIDs 0, 1, and 4095 are reserved and should not be used.
func randomVID() int {
	return rand.Intn(4093) + 2 // 2-4094
}

// externalFRRName is the name of the external FRR container used in EVPN tests.
const externalFRRName = "frr"
