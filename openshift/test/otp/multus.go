package otp

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

var _ = g.Describe("[JIRA:Networking][OTP][sig-network] OTP Multus", func() {
	var (
		clientset *kubernetes.Clientset
		config    *rest.Config
		ctx       context.Context
	)

	g.BeforeEach(func() {
		ctx = context.Background()

		// Load kubeconfig
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

		var err error
		config, err = kubeConfig.ClientConfig()
		o.Expect(err).NotTo(o.HaveOccurred())

		clientset, err = kubernetes.NewForConfig(config)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	// High-57589: Whereabouts CNI Timeout with Large Exclude Range
	g.It("[OTP][informing][57589] should handle large IPv6 exclude ranges without timeout", func() {
		const testNS = "test-whereabouts-57589"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "privileged",
					"pod-security.kubernetes.io/audit":   "privileged",
					"pod-security.kubernetes.io/warn":    "privileged",
				},
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			g.By("Cleaning up test namespace")
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Creating NetworkAttachmentDefinition with large exclude range")
		nadConfig := `{
      "cniVersion": "0.3.1",
      "name": "bridge-net",
      "type": "bridge",
      "bridge": "test-br0",
      "isGateway": false,
      "ipMasq": false,
      "ipam": {
         "type": "whereabouts",
         "range": "fd43:01f1:3daa:0baa::/64",
         "exclude": [ "fd43:01f1:3daa:0baa::/100" ],
         "log_file": "/tmp/whereabouts.log",
         "log_level" : "debug"
      }
    }`

		err = createNAD(ctx, config, testNS, "nad-w-excludes", nadConfig)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating pod with secondary network")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: testNS,
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/networks": "nad-w-excludes",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "test",
						Image:   "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}

		_, err = clientset.CoreV1().Pods(testNS).Create(ctx, pod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for pod to reach Running state (max 60s)")
		// Pod should be Running within 60 seconds (test validates no timeout)
		o.Eventually(func() corev1.PodPhase {
			p, err := clientset.CoreV1().Pods(testNS).Get(ctx, "test-pod", metav1.GetOptions{})
			if err != nil {
				return corev1.PodPending
			}
			return p.Status.Phase
		}, 60, 5).Should(o.Equal(corev1.PodRunning),
			"Pod did not reach Running state within 60s - Whereabouts may have timed out")

		g.By("Verifying secondary network attachment")
		p, err := clientset.CoreV1().Pods(testNS).Get(ctx, "test-pod", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		networkStatus, ok := p.Annotations["k8s.v1.cni.cncf.io/network-status"]
		o.Expect(ok).To(o.BeTrue(), "Pod missing network-status annotation")
		o.Expect(networkStatus).NotTo(o.BeEmpty())

		// Verify at least 2 networks (primary + secondary)
		networkCount := strings.Count(networkStatus, `"name"`)
		o.Expect(networkCount).To(o.BeNumerically(">=", 2),
			"Expected at least 2 networks, got %d", networkCount)
	})

	// Medium-76652: Dummy CNI Support
	g.It("[OTP][informing][76652] should support Dummy CNI plugin with Multus", func() {
		const testNS = "test-dummy-cni-76652"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "privileged",
					"pod-security.kubernetes.io/audit":   "privileged",
					"pod-security.kubernetes.io/warn":    "privileged",
				},
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			g.By("Cleaning up test namespace")
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Creating NetworkAttachmentDefinition with dummy CNI and static IPAM")
		dummyConfig := `{
      "cniVersion": "0.3.1",
      "name": "dummy-net",
      "type": "dummy",
      "ipam": {
        "type": "static",
        "addresses": [
          {
            "address": "10.10.10.2/24"
          }
        ]
      }
    }`

		err = createNAD(ctx, config, testNS, "dummy-net", dummyConfig)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating pod with dummy network attached")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-dummy-pod",
				Namespace: testNS,
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/networks": "dummy-net",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "test",
						Image:   "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"sleep", "3600"},
					},
				},
			},
		}

		_, err = clientset.CoreV1().Pods(testNS).Create(ctx, pod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for pod to reach Running state")
		o.Eventually(func() corev1.PodPhase {
			p, err := clientset.CoreV1().Pods(testNS).Get(ctx, "test-dummy-pod", metav1.GetOptions{})
			if err != nil {
				return corev1.PodPending
			}
			return p.Status.Phase
		}, 60, 5).Should(o.Equal(corev1.PodRunning),
			"Pod did not reach Running state within 60s")

		g.By("Verifying dummy network interface is created")
		p, err := clientset.CoreV1().Pods(testNS).Get(ctx, "test-dummy-pod", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		networkStatus, ok := p.Annotations["k8s.v1.cni.cncf.io/network-status"]
		o.Expect(ok).To(o.BeTrue(), "Pod missing network-status annotation")
		o.Expect(networkStatus).NotTo(o.BeEmpty())

		g.By("Validating dummy interface has correct IP and configuration")
		// Network status should contain 2 interfaces: ovn-kubernetes (primary) + dummy-net (secondary)
		o.Expect(networkStatus).To(o.ContainSubstring("ovn-kubernetes"), "Should have primary OVN network")
		o.Expect(networkStatus).To(o.ContainSubstring("dummy-net"), "Should have dummy network")
		o.Expect(networkStatus).To(o.ContainSubstring("10.10.10.2"), "Should have assigned dummy IP")

		// Verify we have at least 2 network interfaces
		networkCount := strings.Count(networkStatus, `"name"`)
		o.Expect(networkCount).To(o.BeNumerically(">=", 2),
			"Expected at least 2 networks (primary + dummy), got %d", networkCount)
	})

	// Medium-66876: Support Dual Stack IP assignment for whereabouts CNI/IPAM
	g.It("[OTP][informing][66876] should assign dual-stack IPs with Whereabouts IPAM", func() {
		const testNS = "test-whereabouts-dualstack-66876"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "privileged",
					"pod-security.kubernetes.io/audit":   "privileged",
					"pod-security.kubernetes.io/warn":    "privileged",
				},
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			g.By("Cleaning up test namespace")
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Creating NetworkAttachmentDefinition with dual-stack Whereabouts IPAM")
		dualStackConfig := `{
			"cniVersion": "0.3.1",
			"name": "whereabouts-dualstack",
			"type": "macvlan",
			"mode": "bridge",
			"ipam": {
				"type": "whereabouts",
				"ipRanges": [
					{
						"range": "192.168.10.0/24"
					},
					{
						"range": "fd00:dead:beef:10::/64"
					}
				]
			}
		}`

		err = createNAD(ctx, config, testNS, "whereabouts-dualstack", dualStackConfig)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating deployment with 2 pods using pod affinity for same-node placement")
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: testNS,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32Ptr(2),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-pod",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app": "test-pod",
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "whereabouts-dualstack",
						},
					},
					Spec: corev1.PodSpec{
						Affinity: &corev1.Affinity{
							PodAffinity: &corev1.PodAffinity{
								RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
									{
										LabelSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												"app": "test-pod",
											},
										},
										TopologyKey: "kubernetes.io/hostname",
									},
								},
							},
						},
						Containers: []corev1.Container{
							{
								Name:  "test-pod",
								Image: "registry.access.redhat.com/ubi9/python-39:latest",
								Command: []string{"/bin/bash", "-c"},
								Args: []string{
									`cat > /tmp/server.py <<'PYEOF'
import http.server
import socketserver
import socket
PORT = 8080
class DualStackTCPServer(socketserver.TCPServer):
    address_family = socket.AF_INET6
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=False)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        if bind_and_activate:
            self.server_bind()
            self.server_activate()
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'whereabouts-dualstack-test-pod\n')
with DualStackTCPServer(("::", PORT), Handler) as httpd:
    httpd.serve_forever()
PYEOF
python3 /tmp/server.py`,
								},
								Ports: []corev1.ContainerPort{
									{ContainerPort: 8080},
								},
							},
						},
					},
				},
			},
		}

		_, err = clientset.AppsV1().Deployments(testNS).Create(ctx, deployment, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for both pods to reach Running state")
		o.Eventually(func() int {
			pods, err := clientset.CoreV1().Pods(testNS).List(ctx, metav1.ListOptions{
				LabelSelector: "app=test-pod",
			})
			if err != nil {
				return 0
			}
			runningCount := 0
			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning {
					runningCount++
				}
			}
			return runningCount
		}, 120, 10).Should(o.Equal(2), "Both pods should reach Running state")

		g.By("Verifying pods have dual-stack IPs on secondary interface")
		pods, err := clientset.CoreV1().Pods(testNS).List(ctx, metav1.ListOptions{
			LabelSelector: "app=test-pod",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(pods.Items)).To(o.Equal(2), "Should have 2 pods")

		ipv4Assigned := 0
		ipv6Assigned := 0
		var podIPs []string

		for _, pod := range pods.Items {
			networkStatus, ok := pod.Annotations["k8s.v1.cni.cncf.io/network-status"]
			o.Expect(ok).To(o.BeTrue(), "Pod %s should have network-status annotation", pod.Name)

			// Check for dual-stack IPs in network status
			hasIPv4 := strings.Contains(networkStatus, "192.168.10.")
			hasIPv6 := strings.Contains(networkStatus, "fd00:dead:beef:10::")

			if hasIPv4 {
				ipv4Assigned++
			}
			if hasIPv6 {
				ipv6Assigned++
			}

			o.Expect(hasIPv4 && hasIPv6).To(o.BeTrue(),
				"Pod %s should have both IPv4 (192.168.10.x) and IPv6 (fd00:dead:beef:10::x) addresses", pod.Name)

			// Extract IPv4 for uniqueness check
			if hasIPv4 {
				ipv4Regex := regexp.MustCompile(`192\.168\.10\.\d+`)
				matches := ipv4Regex.FindString(networkStatus)
				if matches != "" {
					podIPs = append(podIPs, matches)
				}
			}
		}

		o.Expect(ipv4Assigned).To(o.Equal(2), "Both pods should have IPv4 addresses")
		o.Expect(ipv6Assigned).To(o.Equal(2), "Both pods should have IPv6 addresses")

		g.By("Verifying dual-stack IP uniqueness")
		o.Expect(len(podIPs)).To(o.BeNumerically(">=", 2), "Should have extracted at least 2 IPv4 addresses")

		if len(podIPs) >= 2 {
			o.Expect(podIPs[0]).NotTo(o.Equal(podIPs[1]), "Pods should have different IPv4 addresses")
		}

		g.By("Testing IPv4 connectivity between pods on the same node")
		// Both pods are guaranteed to be on the same node via pod affinity
		// Macvlan in bridge mode requires same-node for L2 connectivity
		o.Expect(len(pods.Items)).To(o.Equal(2), "Should have exactly 2 pods")

		ipv4Regex := regexp.MustCompile(`192\.168\.10\.\d+`)
		ipv6Regex := regexp.MustCompile(`fd00:dead:beef:10::[a-f0-9]+`)

		// Extract IPs from pod 0 and pod 1
		srcPod := pods.Items[0].Name
		networkStatus1 := pods.Items[1].Annotations["k8s.v1.cni.cncf.io/network-status"]

		dstIPv4 := ipv4Regex.FindString(networkStatus1)
		dstIPv6 := ipv6Regex.FindString(networkStatus1)

		o.Expect(dstIPv4).NotTo(o.BeEmpty(), "Pod 1 should have IPv4 address")
		o.Expect(dstIPv6).NotTo(o.BeEmpty(), "Pod 1 should have IPv6 address")

		// Verify both pods are on the same node (should always be true due to affinity)
		o.Expect(pods.Items[0].Spec.NodeName).To(o.Equal(pods.Items[1].Spec.NodeName),
			"Both pods should be on the same node due to pod affinity")

		scheme := runtime.NewScheme()
		err = corev1.AddToScheme(scheme)
		o.Expect(err).NotTo(o.HaveOccurred())

		// Test IPv4 connectivity
		curlCmd := []string{"curl", "-s", "--connect-timeout", "5", fmt.Sprintf("http://%s:8080", dstIPv4)}
		req := clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name(srcPod).
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "test-pod",
				Command:   curlCmd,
				Stdout:    true,
				Stderr:    true,
			}, runtime.NewParameterCodec(scheme))

		exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
		o.Expect(err).NotTo(o.HaveOccurred())

		var stdout, stderr bytes.Buffer
		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})
		o.Expect(err).NotTo(o.HaveOccurred(), "IPv4 connectivity test failed: %s", stderr.String())
		o.Expect(stdout.String()).To(o.ContainSubstring("whereabouts-dualstack-test-pod"),
			"IPv4 connectivity: Expected response from hello-sdn server")

		g.By("Testing IPv6 connectivity between pods on secondary network")
		// Test IPv6 connectivity - curl requires brackets around IPv6 and -g flag
		curlCmd = []string{"curl", "-s", "-6", "-g", "--connect-timeout", "5", fmt.Sprintf("http://[%s]:8080", dstIPv6)}
		req = clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name(srcPod).
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "test-pod",
				Command:   curlCmd,
				Stdout:    true,
				Stderr:    true,
			}, runtime.NewParameterCodec(scheme))

		exec, err = remotecommand.NewSPDYExecutor(config, "POST", req.URL())
		o.Expect(err).NotTo(o.HaveOccurred())

		stdout.Reset()
		stderr.Reset()
		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})
		o.Expect(err).NotTo(o.HaveOccurred(), "IPv6 connectivity test failed: %s", stderr.String())
		o.Expect(stdout.String()).To(o.ContainSubstring("whereabouts-dualstack-test-pod"),
			"IPv6 connectivity: Expected response from hello-sdn server")
	})

	// OCP-69947: Macvlan pods send Unsolicited Neighbor Advertisements
	// Note: Marked as informing due to timing sensitivity with tcpdump in automated environment
	g.It("[OTP][informing][69947] should send Unsolicited Neighbor Advertisements when macvlan pod is created", func() {
		testNS := "test-macvlan-na-69947"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "privileged",
					"pod-security.kubernetes.io/audit":   "privileged",
					"pod-security.kubernetes.io/warn":    "privileged",
				},
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Creating NetworkAttachmentDefinition with dual-stack whereabouts IPAM")
		nadConfig := `{
			"cniVersion": "0.3.1",
			"name": "whereabouts-dualstack",
			"type": "macvlan",
			"mode": "bridge",
			"ipam": {
				"type": "whereabouts",
				"ipRanges": [
					{
						"range": "192.168.10.0/24"
					},
					{
						"range": "fd00:dead:beef:10::/64"
					}
				]
			}
		}`

		err = createNAD(ctx, config, testNS, "whereabouts-dualstack", nadConfig)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating sniffer pod to capture ICMPv6 Neighbor Advertisements")
		snifferPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sniff-pod",
				Namespace: testNS,
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/networks": "whereabouts-dualstack",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "sniffer",
						Image: "quay.io/openshifttest/hello-sdn@sha256:c89445416459e7adea9a5a416b3365ed3d74f2491beb904d61dc8d1eb89a72a4",
						Command: []string{"/bin/sh", "-c"},
						Args: []string{
							// Start tcpdump to capture ICMPv6 Neighbor Advertisements on net1
							// Filter: icmp6 type 136 (Neighbor Advertisement)
							`tcpdump -i net1 -n 'icmp6 and icmp6[0] = 136' -w /tmp/capture.pcap &
							sleep 3600`,
						},
						SecurityContext: &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{"NET_RAW", "NET_ADMIN"},
							},
						},
					},
				},
			},
		}

		_, err = clientset.CoreV1().Pods(testNS).Create(ctx, snifferPod, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		// Wait for sniffer pod to be running
		o.Eventually(func() corev1.PodPhase {
			pod, err := clientset.CoreV1().Pods(testNS).Get(ctx, "sniff-pod", metav1.GetOptions{})
			if err != nil {
				return corev1.PodPending
			}
			return pod.Status.Phase
		}, 60, 5).Should(o.Equal(corev1.PodRunning), "Sniffer pod should be running")

		// Give tcpdump time to start capturing
		// tcpdump needs extra time after pod reaches Running to initialize and start listening
		time.Sleep(20 * time.Second)

		g.By("Creating 6 test pods with macvlan secondary network")
		rc := &corev1.ReplicationController{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: testNS,
			},
			Spec: corev1.ReplicationControllerSpec{
				Replicas: int32Ptr(6),
				Selector: map[string]string{
					"name": "test-pod",
				},
				Template: &corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"name": "test-pod",
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "whereabouts-dualstack",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-pod",
								Image: "quay.io/openshifttest/hello-sdn@sha256:c89445416459e7adea9a5a416b3365ed3d74f2491beb904d61dc8d1eb89a72a4",
								Env: []corev1.EnvVar{
									{
										Name:  "RESPONSE",
										Value: "Hello",
									},
								},
							},
						},
					},
				},
			},
		}

		_, err = clientset.CoreV1().ReplicationControllers(testNS).Create(ctx, rc, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for all 6 test pods to reach Running state")
		o.Eventually(func() int {
			pods, err := clientset.CoreV1().Pods(testNS).List(ctx, metav1.ListOptions{
				LabelSelector: "name=test-pod",
			})
			if err != nil {
				return 0
			}
			runningCount := 0
			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning {
					runningCount++
				}
			}
			return runningCount
		}, 120, 10).Should(o.Equal(6), "All 6 test pods should be running")

		// Wait additional time for Unsolicited Neighbor Advertisements to be sent
		time.Sleep(15 * time.Second)

		g.By("Analyzing captured ICMPv6 Neighbor Advertisements")
		// Stop tcpdump and read the capture file
		scheme := runtime.NewScheme()
		err = corev1.AddToScheme(scheme)
		o.Expect(err).NotTo(o.HaveOccurred())

		// Kill tcpdump process
		killCmd := []string{"/bin/sh", "-c", "pkill tcpdump"}
		req := clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name("sniff-pod").
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "sniffer",
				Command:   killCmd,
				Stdout:    true,
				Stderr:    true,
			}, runtime.NewParameterCodec(scheme))

		exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
		o.Expect(err).NotTo(o.HaveOccurred())

		var stdout, stderr bytes.Buffer
		_ = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})

		// Wait for tcpdump to flush pcap file to disk
		time.Sleep(5 * time.Second)

		// Read and analyze the pcap file using tcpdump
		// Check for ICMPv6 NA packets with solicited flag = 0 (Unsolicited)
		analyzeCmd := []string{"/bin/sh", "-c",
			`tcpdump -r /tmp/capture.pcap -n 'icmp6 and icmp6[0] = 136' -v 2>/dev/null | grep "Neighbor Advertisement" | wc -l`}

		req = clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name("sniff-pod").
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "sniffer",
				Command:   analyzeCmd,
				Stdout:    true,
				Stderr:    true,
			}, runtime.NewParameterCodec(scheme))

		exec, err = remotecommand.NewSPDYExecutor(config, "POST", req.URL())
		o.Expect(err).NotTo(o.HaveOccurred())

		stdout.Reset()
		stderr.Reset()
		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to analyze pcap: %s", stderr.String())

		naCount := strings.TrimSpace(stdout.String())
		o.Expect(naCount).NotTo(o.Equal("0"), "Should have captured at least one ICMPv6 Neighbor Advertisement")

		g.By("Verifying Neighbor Advertisements are Unsolicited (solicited flag = 0)")
		// Check that captured NAs have solicited flag = 0
		// In unsolicited NA, the destination is ff02::1 (all nodes multicast)
		verifyCmd := []string{"/bin/sh", "-c",
			`tcpdump -r /tmp/capture.pcap -n 'icmp6 and icmp6[0] = 136' 2>/dev/null | grep "ff02::1" | wc -l`}

		req = clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name("sniff-pod").
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "sniffer",
				Command:   verifyCmd,
				Stdout:    true,
				Stderr:    true,
			}, runtime.NewParameterCodec(scheme))

		exec, err = remotecommand.NewSPDYExecutor(config, "POST", req.URL())
		o.Expect(err).NotTo(o.HaveOccurred())

		stdout.Reset()
		stderr.Reset()
		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to verify unsolicited NAs: %s", stderr.String())

		unsolicitedCount := strings.TrimSpace(stdout.String())
		o.Expect(unsolicitedCount).NotTo(o.Equal("0"),
			"Should have captured Unsolicited Neighbor Advertisements (destination ff02::1)")
	})
})

// createNAD creates a NetworkAttachmentDefinition
func createNAD(ctx context.Context, config *rest.Config, namespace, name, nadConfig string) error {
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}

	nadGVR := schema.GroupVersionResource{
		Group:    "k8s.cni.cncf.io",
		Version:  "v1",
		Resource: "network-attachment-definitions",
	}

	nad := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "k8s.cni.cncf.io/v1",
			"kind":       "NetworkAttachmentDefinition",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"config": nadConfig,
			},
		},
	}

	_, err = dynamicClient.Resource(nadGVR).Namespace(namespace).Create(ctx, nad, metav1.CreateOptions{})
	return err
}

// int32Ptr returns a pointer to an int32
func int32Ptr(i int32) *int32 {
	return &i
}
