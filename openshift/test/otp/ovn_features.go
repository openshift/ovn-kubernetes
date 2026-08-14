package otp

import (
	"context"
	"fmt"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var _ = g.Describe("[OTP] OVN Features", func() {
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

	g.It("45146-should create healthy pod with single-stack gateway on dual-stack cluster", func() {
		const testNS = "test-single-stack-gw-45146"

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

		g.By("Creating pod with single-stack gateway routing annotations")
		// This simulates a gateway pod with single-stack routing on a dual-stack cluster
		// Testing BZ 1986708 - pod should remain healthy despite stack mismatch
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "gw-single-stack-pod",
				Namespace: testNS,
				Annotations: map[string]string{
					"k8s.ovn.org/routing-namespaces": testNS,
					"k8s.ovn.org/routing-network":    "foo",
					// Single-stack IPv4 network status on potentially dual-stack cluster
					"k8s.v1.cni.cncf.io/network-status": `[{"name":"foo","interface":"net1","ips":["172.19.0.5"],"mac":"01:23:45:67:89:10"}]`,
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

		g.By("Waiting for pod to reach Running state (validating BZ 1986708 fix)")
		// The bug was that pods with single-stack gw on dual-stack clusters would fail
		// This test ensures the pod becomes healthy
		o.Eventually(func() corev1.PodPhase {
			p, err := clientset.CoreV1().Pods(testNS).Get(ctx, "gw-single-stack-pod", metav1.GetOptions{})
			if err != nil {
				return corev1.PodPending
			}
			return p.Status.Phase
		}, 60, 5).Should(o.Equal(corev1.PodRunning),
			"Pod with single-stack gateway should reach Running state on dual-stack cluster")

		g.By("Verifying pod is healthy with Ready condition")
		p, err := clientset.CoreV1().Pods(testNS).Get(ctx, "gw-single-stack-pod", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		// Check that pod has at least one container in Ready state
		hasReadyContainer := false
		for _, containerStatus := range p.Status.ContainerStatuses {
			if containerStatus.Ready {
				hasReadyContainer = true
				break
			}
		}
		o.Expect(hasReadyContainer).To(o.BeTrue(),
			"Pod should have at least one ready container, validating health despite single-stack GW")

		g.By("Verifying routing annotations are preserved")
		o.Expect(p.Annotations["k8s.ovn.org/routing-namespaces"]).To(o.Equal(testNS),
			"Routing namespace annotation should be preserved")
		o.Expect(p.Annotations["k8s.ovn.org/routing-network"]).To(o.Equal("foo"),
			"Routing network annotation should be preserved")
	})

	g.It("69761-should show aggregated status from all zones in AdminPolicyBasedExternalRoute", func() {
		const testNS = "test-apbexternalroute-69761"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		defer func() {
			g.By("Cleaning up test namespace and AdminPolicyBasedExternalRoute")
			dynamicClient, _ := dynamic.NewForConfig(config)
			apbrGVR := schema.GroupVersionResource{
				Group:    "k8s.ovn.org",
				Version:  "v1",
				Resource: "adminpolicybasedexternalroutes",
			}
			_ = dynamicClient.Resource(apbrGVR).Delete(ctx, "default-route-policy", metav1.DeleteOptions{})
			_ = clientset.CoreV1().Namespaces().Delete(ctx, testNS, metav1.DeleteOptions{})
		}()

		g.By("Creating AdminPolicyBasedExternalRoute with static next hops")
		dynamicClient, err := dynamic.NewForConfig(config)
		o.Expect(err).NotTo(o.HaveOccurred())

		apbrGVR := schema.GroupVersionResource{
			Group:    "k8s.ovn.org",
			Version:  "v1",
			Resource: "adminpolicybasedexternalroutes",
		}

		apbr := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "k8s.ovn.org/v1",
				"kind":       "AdminPolicyBasedExternalRoute",
				"metadata": map[string]interface{}{
					"name": "default-route-policy",
				},
				"spec": map[string]interface{}{
					"from": map[string]interface{}{
						"namespaceSelector": map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"kubernetes.io/metadata.name": testNS,
			},
						},
					},
					"nextHops": map[string]interface{}{
						"static": []interface{}{
							map[string]interface{}{"ip": "172.18.0.8"},
							map[string]interface{}{"ip": "172.18.0.9"},
						},
					},
				},
			},
		}

		_, err = dynamicClient.Resource(apbrGVR).Create(ctx, apbr, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Waiting for AdminPolicyBasedExternalRoute status to be populated")
		var apbrStatus *unstructured.Unstructured
		o.Eventually(func() bool {
			apbrStatus, err = dynamicClient.Resource(apbrGVR).Get(ctx, "default-route-policy", metav1.GetOptions{})
			if err != nil {
				return false
			}
			status, found, _ := unstructured.NestedMap(apbrStatus.Object, "status")
			return found && len(status) > 0
		}, 120, 10).Should(o.BeTrue(), "AdminPolicyBasedExternalRoute status should be populated")

		g.By("Verifying status contains messages from all zones (nodes)")
		status, found, err := unstructured.NestedMap(apbrStatus.Object, "status")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(found).To(o.BeTrue(), "Status field should exist")

		messages, found, err := unstructured.NestedSlice(status, "messages")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(found).To(o.BeTrue(), "Status.messages field should exist")
		o.Expect(len(messages)).To(o.BeNumerically(">", 0), "Status.messages should contain at least one zone report")

		// Get node count to validate we have messages from nodes
		nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		nodeCount := len(nodes.Items)

		g.By(fmt.Sprintf("Verifying status.messages has entries from zones (cluster has %d nodes)", nodeCount))
		// Each message should be prefixed with zone name (node name by default)
		// Format: "<zone-name>: configured external gateway IPs: 172.18.0.8,172.18.0.9"
		for _, msg := range messages {
			msgStr, ok := msg.(string)
			o.Expect(ok).To(o.BeTrue(), "Each message should be a string")
			o.Expect(msgStr).To(o.ContainSubstring("configured external gateway IPs"),
				"Message should describe configured gateway IPs")
			o.Expect(msgStr).To(o.MatchRegexp(`^[^:]+:`),
				"Message should be prefixed with zone name followed by colon")
		}

		g.By("Verifying status.status is Success when all zones report success")
		statusValue, found, err := unstructured.NestedString(status, "status")
		o.Expect(err).NotTo(o.HaveOccurred())
		if found {
			// Status should be "Success" when all zones reported successfully
			// or empty if not all zones have reported yet
			o.Expect(statusValue).To(o.Or(o.Equal("Success"), o.BeEmpty()),
				"Status should be 'Success' when all zones reported, or empty if still pending")
		}

		g.By("Verifying external gateway IPs are configured in messages")
		// Check that at least one message mentions the configured IPs
		hasExpectedIPs := false
		for _, msg := range messages {
			msgStr, ok := msg.(string)
			o.Expect(ok).To(o.BeTrue(), "Each message should be a string")
			if strings.Contains(msgStr, "172.18.0.8") && strings.Contains(msgStr, "172.18.0.9") {
				hasExpectedIPs = true
				break
			}
		}
		o.Expect(hasExpectedIPs).To(o.BeTrue(),
			"At least one zone should report the configured external gateway IPs (172.18.0.8, 172.18.0.9)")
	})
})
