package deploymentconfig

import (
	"context"
	"fmt"
	"os"
	"time"

	imageclient "github.com/openshift/client-go/image/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
)

// FedoraContainerDiskImage matches Origin's approved live-migration test image.
const FedoraContainerDiskImage = "quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2"

func (m *openshift) GetImage(imageID api.ImageID) api.ImageConfig {
	return api.ImageConfig{ImageID: imageID, PullSpec: m.imagePullSpec(imageID)}
}

func (m *openshift) imagePullSpec(imageID api.ImageID) string {
	switch imageID {
	case api.Agnhost:
		if override := os.Getenv("AGNHOST_IMAGE"); override != "" {
			return override
		}
		return "registry.k8s.io/e2e-test-images/agnhost:2.40"
	case api.Netshoot:
		if override := os.Getenv("NETSHOOT_IMAGE"); override != "" {
			return override
		}
		image, err := m.getNetworkToolsImage()
		if err != nil {
			panic(err)
		}
		return image
	default:
		return imageConfigMap[imageID]
	}
}

func (m *openshift) getNetworkToolsImage() (string, error) {
	m.imageLock.Lock()
	defer m.imageLock.Unlock()
	if m.networkToolsImage != "" {
		return m.networkToolsImage, nil
	}
	if m.imageClient == nil {
		config, err := framework.LoadConfig()
		if err != nil {
			return "", err
		}
		client, err := imageclient.NewForConfig(config)
		if err != nil {
			return "", err
		}
		m.imageClient = client
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Match Origin's EgressIP helpers: use the latest imported tag's concrete
	// pullspec, including any cluster-specific mirror reference.
	stream, err := m.imageClient.ImageV1().ImageStreams("openshift").Get(ctx, "network-tools", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("resolve payload network-tools image: %w", err)
	}
	for _, tag := range stream.Status.Tags {
		if tag.Tag == "latest" && len(tag.Items) > 0 && tag.Items[0].DockerImageReference != "" {
			m.networkToolsImage = tag.Items[0].DockerImageReference
			return m.networkToolsImage, nil
		}
	}
	return "", fmt.Errorf("openshift/network-tools:latest has no imported Docker image reference")
}
