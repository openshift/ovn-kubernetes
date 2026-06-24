package otp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

var _ = g.Describe("[JIRA:Networking][OTP][sig-network] OTP Multus Port Isolation", func() {
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

	g.It("81757-should test port isolation with UDN and bridge CNI", func() {
		testNS := "test-udn-port-isolation-81757"

		g.By("Creating test namespace with UDN label")
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

		dynamicClient, err := dynamic.NewForConfig(config)
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			// Clean up UDN
			udnGVR := schema.GroupVersionResource{
				Group:    "k8s.ovn.org",
				Version:  "v1",
				Resource: "userdefinednetworks",
			}
			_ = dynamicClient.Resource(udnGVR).Namespace(testNS).Delete(ctx, "layer2-ipv4-pudn1", metav1.DeleteOptions{})
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Creating UserDefinedNetwork (Layer2 Primary)")
		udnGVR := schema.GroupVersionResource{
			Group:    "k8s.ovn.org",
			Version:  "v1",
			Resource: "userdefinednetworks",
		}

		udn := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "k8s.ovn.org/v1",
				"kind":       "UserDefinedNetwork",
				"metadata": map[string]interface{}{
					"name":      "layer2-ipv4-pudn1",
					"namespace": testNS,
				},
				"spec": map[string]interface{}{
					"topology": "Layer2",
					"layer2": map[string]interface{}{
						"role": "Primary",
						"subnets": []interface{}{
							"10.10.0.0/16",
							"FC00:10:10::0/64",
						},
					},
				},
			},
		}

		_, err = dynamicClient.Resource(udnGVR).Namespace(testNS).Create(ctx, udn, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		// Wait for UDN to be ready
		o.Eventually(func() bool {
			obj, err := dynamicClient.Resource(udnGVR).Namespace(testNS).Get(ctx, "layer2-ipv4-pudn1", metav1.GetOptions{})
			if err != nil {
				return false
			}
			status, found, _ := unstructured.NestedMap(obj.Object, "status")
			if !found {
				return false
			}
			conditions, found, _ := unstructured.NestedSlice(status, "conditions")
			if !found {
				return false
			}
			for _, cond := range conditions {
				condMap := cond.(map[string]interface{})
				if condMap["type"] == "NetworkReady" && condMap["status"] == "True" {
					return true
				}
			}
			return false
		}, 120, 5).Should(o.BeTrue(), "UDN should become ready")

		g.By("Creating NAD with portIsolation enabled")
		nadIsolated := `{
			"cniVersion": "0.4.0",
			"name": "bridge-isolated-ports",
			"type": "bridge",
			"portIsolation": true,
			"ipam": {
				"type": "host-local",
				"ranges": [
					[
						{
							"subnet": "192.168.10.0/24",
							"rangeStart": "192.168.10.1",
							"rangeEnd": "192.168.10.100"
						}
					],
					[
						{
							"subnet": "FD00:192:168:10::0/64",
							"rangeStart": "FD00:192:168:10::1",
							"rangeEnd": "FD00:192:168:10::100"
						}
					]
				]
			}
		}`

		err = createNAD(ctx, config, testNS, "bridge-isolated-ports", nadIsolated)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating NAD with portIsolation disabled")
		nadNonIsolated := `{
			"cniVersion": "0.4.0",
			"name": "bridge-isolated-false-ports",
			"type": "bridge",
			"portIsolation": false,
			"ipam": {
				"type": "host-local",
				"ranges": [
					[
						{
							"subnet": "192.168.11.0/24",
							"rangeStart": "192.168.11.1",
							"rangeEnd": "192.168.11.100"
						}
					],
					[
						{
							"subnet": "FD00:192:168:11::0/64",
							"rangeStart": "FD00:192:168:11::1",
							"rangeEnd": "FD00:192:168:11::100"
						}
					]
				]
			}
		}`

		err = createNAD(ctx, config, testNS, "bridge-isolated-false-ports", nadNonIsolated)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating ReplicationController with 2 pods using both NADs on the same node")
		nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{
			LabelSelector: "node-role.kubernetes.io/worker",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodes.Items)).To(o.BeNumerically(">", 0), "Should have at least one worker node")

		targetNode := nodes.Items[0].Name

		rc := &corev1.ReplicationController{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "green-test-pod",
				Namespace: testNS,
			},
			Spec: corev1.ReplicationControllerSpec{
				Replicas: int32Ptr(2),
				Selector: map[string]string{
					"name": "green",
				},
				Template: &corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"name": "green",
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "bridge-isolated-ports, bridge-isolated-false-ports",
						},
					},
					Spec: corev1.PodSpec{
						NodeName: targetNode,
						Containers: []corev1.Container{
							{
								Name:  "green-test-pod",
								Image: "quay.io/openshifttest/hello-sdn@sha256:c89445416459e7adea9a5a416b3365ed3d74f2491beb904d61dc8d1eb89a72a4",
								Ports: []corev1.ContainerPort{
									{ContainerPort: 8080},
									{ContainerPort: 443},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "RESPONSE",
										Value: "green-test-pod",
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

		g.By("Waiting for both pods to be Running")
		o.Eventually(func() int {
			pods, err := clientset.CoreV1().Pods(testNS).List(ctx, metav1.ListOptions{
				LabelSelector: "name=green",
			})
			if err != nil {
				return 0
			}
			runningCount := 0
			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning && pod.Spec.NodeName == targetNode {
					runningCount++
				}
			}
			return runningCount
		}, 120, 5).Should(o.Equal(2), "Both pods should be running on the same node")

		g.By("Getting pod IPs from both bridge networks")
		pods, err := clientset.CoreV1().Pods(testNS).List(ctx, metav1.ListOptions{
			LabelSelector: "name=green",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(pods.Items)).To(o.Equal(2), "Should have exactly 2 pods")

		pod1 := pods.Items[0]
		pod2 := pods.Items[1]

		// Parse network status to get IPs from both bridge networks
		var pod1IsolatedIP, pod1NonIsolatedIP, pod2IsolatedIP, pod2NonIsolatedIP string

		if netStatus, ok := pod1.Annotations["k8s.v1.cni.cncf.io/network-status"]; ok {
			var networks []map[string]interface{}
			err = json.Unmarshal([]byte(netStatus), &networks)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, net := range networks {
				if name, ok := net["name"].(string); ok {
					if name == testNS+"/bridge-isolated-ports" {
						if ips, ok := net["ips"].([]interface{}); ok && len(ips) > 0 {
							pod1IsolatedIP = ips[0].(string)
						}
					} else if name == testNS+"/bridge-isolated-false-ports" {
						if ips, ok := net["ips"].([]interface{}); ok && len(ips) > 0 {
							pod1NonIsolatedIP = ips[0].(string)
						}
					}
				}
			}
		}
		o.Expect(pod1IsolatedIP).NotTo(o.BeEmpty(), "Pod1 should have isolated network IP")
		o.Expect(pod1NonIsolatedIP).NotTo(o.BeEmpty(), "Pod1 should have non-isolated network IP")

		if netStatus, ok := pod2.Annotations["k8s.v1.cni.cncf.io/network-status"]; ok {
			var networks []map[string]interface{}
			err = json.Unmarshal([]byte(netStatus), &networks)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, net := range networks {
				if name, ok := net["name"].(string); ok {
					if name == testNS+"/bridge-isolated-ports" {
						if ips, ok := net["ips"].([]interface{}); ok && len(ips) > 0 {
							pod2IsolatedIP = ips[0].(string)
						}
					} else if name == testNS+"/bridge-isolated-false-ports" {
						if ips, ok := net["ips"].([]interface{}); ok && len(ips) > 0 {
							pod2NonIsolatedIP = ips[0].(string)
						}
					}
				}
			}
		}
		o.Expect(pod2IsolatedIP).NotTo(o.BeEmpty(), "Pod2 should have isolated network IP")
		o.Expect(pod2NonIsolatedIP).NotTo(o.BeEmpty(), "Pod2 should have non-isolated network IP")

		scheme := runtime.NewScheme()
		err = corev1.AddToScheme(scheme)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Verifying pods CANNOT communicate via isolated bridge network")
		pingIsolatedCmd := []string{"/bin/sh", "-c", fmt.Sprintf("ping -c 3 -W 2 %s", pod2IsolatedIP)}
		req := clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name(pod1.Name).
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "green-test-pod",
				Command:   pingIsolatedCmd,
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

		// Ping should FAIL on isolated network
		o.Expect(err).To(o.HaveOccurred(), "Ping should fail on isolated bridge network")
		isolatedOutput := stdout.String() + stderr.String()
		o.Expect(isolatedOutput).To(o.Or(
			o.ContainSubstring("100% packet loss"),
			o.ContainSubstring("Network is unreachable"),
		), "Should show network isolation on isolated bridge")

		g.By("Verifying pods CAN communicate via non-isolated bridge network")
		pingNonIsolatedCmd := []string{"/bin/sh", "-c", fmt.Sprintf("ping -c 3 -W 2 %s", pod2NonIsolatedIP)}
		req = clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name(pod1.Name).
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "green-test-pod",
				Command:   pingNonIsolatedCmd,
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

		// Ping should SUCCEED on non-isolated network
		o.Expect(err).NotTo(o.HaveOccurred(), "Ping should succeed on non-isolated bridge network")
		nonIsolatedOutput := stdout.String() + stderr.String()
		o.Expect(nonIsolatedOutput).To(o.ContainSubstring("0% packet loss"), "Should show successful ping on non-isolated bridge")
	})

	// OCP-80526: UDN Verify pods with isolated and non-isolated ports using bridge-cni
	// This test combines UDN (Layer2 Primary) with mixed port isolation from test 80525
	g.It("80526-should test UDN with mixed port isolation on bridge CNI", func() {
		testNS := "test-udn-mixed-isolation-80526"

		g.By("Creating test namespace with UDN")
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

		dynamicClient, err := dynamic.NewForConfig(config)
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			// Clean up UDN
			udnGVR := schema.GroupVersionResource{
				Group:    "k8s.ovn.org",
				Version:  "v1",
				Resource: "userdefinednetworks",
			}
			_ = dynamicClient.Resource(udnGVR).Namespace(testNS).Delete(ctx, "layer2-ipv4-pudn1", metav1.DeleteOptions{})
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Creating UserDefinedNetwork (Layer2 Primary)")
		udnGVR := schema.GroupVersionResource{
			Group:    "k8s.ovn.org",
			Version:  "v1",
			Resource: "userdefinednetworks",
		}

		udn := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "k8s.ovn.org/v1",
				"kind":       "UserDefinedNetwork",
				"metadata": map[string]interface{}{
					"name":      "layer2-ipv4-pudn1",
					"namespace": testNS,
				},
				"spec": map[string]interface{}{
					"topology": "Layer2",
					"layer2": map[string]interface{}{
						"role": "Primary",
						"subnets": []interface{}{
							"10.10.0.0/16",
							"FC00:10:10::0/64",
						},
					},
				},
			},
		}

		_, err = dynamicClient.Resource(udnGVR).Namespace(testNS).Create(ctx, udn, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		// Wait for UDN to be ready
		o.Eventually(func() bool {
			obj, err := dynamicClient.Resource(udnGVR).Namespace(testNS).Get(ctx, "layer2-ipv4-pudn1", metav1.GetOptions{})
			if err != nil {
				return false
			}
			status, found, _ := unstructured.NestedMap(obj.Object, "status")
			if !found {
				return false
			}
			conditions, found, _ := unstructured.NestedSlice(status, "conditions")
			if !found {
				return false
			}
			for _, cond := range conditions {
				condMap := cond.(map[string]interface{})
				if condMap["type"] == "NetworkReady" && condMap["status"] == "True" {
					return true
				}
			}
			return false
		}, 120, 5).Should(o.BeTrue(), "UDN should become ready")

		// Now run the same tests as 80525 (mixed port isolation) but in UDN namespace
		g.By("Creating NAD with portIsolation enabled")
		nadIsolated := `{
			"cniVersion": "0.4.0",
			"name": "bridge-isolated-ports",
			"type": "bridge",
			"portIsolation": true,
			"ipam": {
				"type": "host-local",
				"ranges": [
					[
						{
							"subnet": "192.168.10.0/24",
							"rangeStart": "192.168.10.1",
							"rangeEnd": "192.168.10.100"
						}
					],
					[
						{
							"subnet": "FD00:192:168:10::0/64",
							"rangeStart": "FD00:192:168:10::1",
							"rangeEnd": "FD00:192:168:10::100"
						}
					]
				]
			}
		}`

		err = createNAD(ctx, config, testNS, "bridge-isolated-ports", nadIsolated)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating NAD with portIsolation disabled")
		nadNonIsolated := `{
			"cniVersion": "0.4.0",
			"name": "bridge-whereabouts",
			"portIsolation": false,
			"type": "bridge",
			"ipam": {
				"type": "whereabouts",
				"ipRanges": [
					{
						"range": "192.168.14.0/24",
						"rangeStart": "192.168.14.1",
						"rangeEnd": "192.168.14.100"
					},
					{
						"range": "FD00:192:168:14::0/64",
						"rangeStart": "FD00:192:168:14::1",
						"rangeEnd": "FD00:192:168:14::100"
					}
				]
			}
		}`

		err = createNAD(ctx, config, testNS, "bridge-whereabouts", nadNonIsolated)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Creating ReplicationController with 2 pods using both NADs on the same node")
		nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{
			LabelSelector: "node-role.kubernetes.io/worker",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(nodes.Items)).To(o.BeNumerically(">", 0), "Should have at least one worker node")

		targetNode := nodes.Items[0].Name

		rc := &corev1.ReplicationController{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "green-test-pod",
				Namespace: testNS,
			},
			Spec: corev1.ReplicationControllerSpec{
				Replicas: int32Ptr(2),
				Selector: map[string]string{
					"name": "green",
				},
				Template: &corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"name": "green",
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "bridge-isolated-ports, bridge-whereabouts",
						},
					},
					Spec: corev1.PodSpec{
						NodeName: targetNode,
						Containers: []corev1.Container{
							{
								Name:  "green-test-pod",
								Image: "quay.io/openshifttest/hello-sdn@sha256:c89445416459e7adea9a5a416b3365ed3d74f2491beb904d61dc8d1eb89a72a4",
								Ports: []corev1.ContainerPort{
									{ContainerPort: 8080},
									{ContainerPort: 443},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "RESPONSE",
										Value: "green-test-pod",
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

		g.By("Waiting for both pods to be Running")
		o.Eventually(func() int {
			pods, err := clientset.CoreV1().Pods(testNS).List(ctx, metav1.ListOptions{
				LabelSelector: "name=green",
			})
			if err != nil {
				return 0
			}
			runningCount := 0
			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning && pod.Spec.NodeName == targetNode {
					runningCount++
				}
			}
			return runningCount
		}, 120, 5).Should(o.Equal(2), "Both pods should be running on the same node")

		g.By("Getting pod IPs from both networks")
		pods, err := clientset.CoreV1().Pods(testNS).List(ctx, metav1.ListOptions{
			LabelSelector: "name=green",
		})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(len(pods.Items)).To(o.Equal(2), "Should have exactly 2 pods")

		pod1 := pods.Items[0]
		pod2 := pods.Items[1]

		// Parse network status to get IPs from both networks
		var pod1IsolatedIP, pod1NonIsolatedIP, pod2IsolatedIP, pod2NonIsolatedIP string

		if netStatus, ok := pod1.Annotations["k8s.v1.cni.cncf.io/network-status"]; ok {
			var networks []map[string]interface{}
			err = json.Unmarshal([]byte(netStatus), &networks)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, net := range networks {
				if name, ok := net["name"].(string); ok {
					if name == testNS+"/bridge-isolated-ports" {
						if ips, ok := net["ips"].([]interface{}); ok && len(ips) > 0 {
							pod1IsolatedIP = ips[0].(string)
						}
					} else if name == testNS+"/bridge-whereabouts" {
						if ips, ok := net["ips"].([]interface{}); ok && len(ips) > 0 {
							pod1NonIsolatedIP = ips[0].(string)
						}
					}
				}
			}
		}
		o.Expect(pod1IsolatedIP).NotTo(o.BeEmpty(), "Pod1 should have isolated network IP")
		o.Expect(pod1NonIsolatedIP).NotTo(o.BeEmpty(), "Pod1 should have non-isolated network IP")

		if netStatus, ok := pod2.Annotations["k8s.v1.cni.cncf.io/network-status"]; ok {
			var networks []map[string]interface{}
			err = json.Unmarshal([]byte(netStatus), &networks)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, net := range networks {
				if name, ok := net["name"].(string); ok {
					if name == testNS+"/bridge-isolated-ports" {
						if ips, ok := net["ips"].([]interface{}); ok && len(ips) > 0 {
							pod2IsolatedIP = ips[0].(string)
						}
					} else if name == testNS+"/bridge-whereabouts" {
						if ips, ok := net["ips"].([]interface{}); ok && len(ips) > 0 {
							pod2NonIsolatedIP = ips[0].(string)
						}
					}
				}
			}
		}
		o.Expect(pod2IsolatedIP).NotTo(o.BeEmpty(), "Pod2 should have isolated network IP")
		o.Expect(pod2NonIsolatedIP).NotTo(o.BeEmpty(), "Pod2 should have non-isolated network IP")

		scheme := runtime.NewScheme()
		err = corev1.AddToScheme(scheme)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Verifying pods CANNOT communicate via isolated network")
		pingIsolatedCmd := []string{"/bin/sh", "-c", fmt.Sprintf("ping -c 3 -W 2 %s", pod2IsolatedIP)}
		req := clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name(pod1.Name).
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "green-test-pod",
				Command:   pingIsolatedCmd,
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

		// Ping should FAIL on isolated network
		o.Expect(err).To(o.HaveOccurred(), "Ping should fail on isolated network")
		isolatedOutput := stdout.String() + stderr.String()
		o.Expect(isolatedOutput).To(o.Or(
			o.ContainSubstring("100% packet loss"),
			o.ContainSubstring("Network is unreachable"),
		), "Should show network isolation on isolated network")

		g.By("Verifying pods CAN communicate via non-isolated network")
		pingNonIsolatedCmd := []string{"/bin/sh", "-c", fmt.Sprintf("ping -c 3 -W 2 %s", pod2NonIsolatedIP)}
		req = clientset.CoreV1().RESTClient().Post().
			Resource("pods").
			Name(pod1.Name).
			Namespace(testNS).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "green-test-pod",
				Command:   pingNonIsolatedCmd,
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

		// Ping should SUCCEED on non-isolated network
		o.Expect(err).NotTo(o.HaveOccurred(), "Ping should succeed on non-isolated network")
		nonIsolatedOutput := stdout.String() + stderr.String()
		o.Expect(nonIsolatedOutput).To(o.ContainSubstring("0% packet loss"), "Should show successful ping on non-isolated network")
	})
})
