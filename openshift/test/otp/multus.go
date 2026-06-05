package otp

import (
	"context"
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

var _ = g.Describe("[sig-networking] OTP Multus", func() {
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
	g.It("[OTP][blocking][case_id:57589] should handle large IPv6 exclude ranges without timeout", func() {
		const testNS = "test-whereabouts-57589"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
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
	g.It("[OTP][blocking][case_id:76652] should support Dummy CNI plugin with Multus", func() {
		const testNS = "test-dummy-cni-76652"

		g.By("Creating test namespace")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS,
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
