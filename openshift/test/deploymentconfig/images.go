// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package deploymentconfig

import (
	"fmt"
	"os"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

type ImageSource struct {
	K8SImageID imageutils.ImageID
	PullSpec   string
}

var (
	// Keep source pull specs for extension discovery; GetImage applies runtime mapping.
	ImageSourceMap = map[api.ImageID]ImageSource{
		api.Agnhost: {
			K8SImageID: imageutils.Agnhost,
		},
		api.FedoraKubevirtContainerDisk: {
			PullSpec: "quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2",
		},
	}
)

func originalPullSpec(imageSource ImageSource) string {
	if imageSource.K8SImageID != imageutils.None {
		return new(imageutils.GetOriginalImageConfigs()[imageSource.K8SImageID]).GetE2EImage()
	}
	return imageSource.PullSpec
}

func mappedPullSpec(imageSource ImageSource) (string, error) {
	if imageSource.K8SImageID != imageutils.None {
		return imageutils.GetE2EImage(imageSource.K8SImageID), nil
	}

	if imageSource.PullSpec != "" {
		if os.Getenv("KUBE_TEST_REPO") == "" {
			return imageSource.PullSpec, nil
		}
		return imageutils.ReplaceRegistryInImageURL(imageSource.PullSpec)
	}

	return "", fmt.Errorf("unexpected image source configuration")
}
