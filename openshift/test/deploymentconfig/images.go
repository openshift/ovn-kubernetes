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

// originalPullSpec returns the upstream source pull spec of an image, before
// any KUBE_TEST_REPO mirror mapping is applied. This is what the extension
// reports as a required image so that it can be mirrored by openshift-tests.
//
// For Kubernetes images it reads from imageutils.GetOriginalImageConfigs(),
// which always holds the source location (e.g. registry.k8s.io/e2e-test-images/agnhost:<tag>),
// unlike imageutils.GetE2EImage(id), which reads the configs already rewritten
// to the mirror repository when KUBE_TEST_REPO is set.
func originalPullSpec(imageSource ImageSource) string {
	if imageSource.K8SImageID != imageutils.None {
		return new(imageutils.GetOriginalImageConfigs()[imageSource.K8SImageID]).GetE2EImage()
	}
	return imageSource.PullSpec
}

// mappedPullSpec returns the pull spec the tests must use at runtime to pull
// an image. It is the same as originalPullSpec when KUBE_TEST_REPO is unset.
// When KUBE_TEST_REPO is set, as openshift-tests does to point at its mirror,
// it returns the location of the image in that repository instead of the
// source one: every image lives in the single KUBE_TEST_REPO repository under
// a tag derived from its source pull spec.
//
// Kubernetes images are resolved with imageutils.GetE2EImage(id), which
// already applies that mapping. Images identified only by PullSpec are not
// known to imageutils, so the same mapping is applied explicitly with
// imageutils.ReplaceRegistryInImageURL.
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
