// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	ocpdeploymentconfig "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	deploymentconfigapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	imageutils "k8s.io/kubernetes/test/utils/image"
)

func TestFedoraImageUsesConfiguredRepository(t *testing.T) {
	const tag = "e2e-quay-io-kubevirt-fedora-with-test-tooling-container-disk-v1-8-2-DmMayTpvDZVswLv0"
	const source = "quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2"

	for _, tc := range []struct {
		name string
		repo string
	}{
		{name: "source"},
		{name: "community mirror", repo: "quay.io/openshift/community-e2e-images"},
		{name: "custom repository", repo: "mirror.example.com:5000/e2e"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBE_TEST_REPO", tc.repo)
			ocpConfig, err := ocpdeploymentconfig.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			ocpConfig.AddRequiredImage(deploymentconfigapi.FedoraKubevirtContainerDisk)

			want := source
			if tc.repo != "" {
				want = tc.repo + ":" + tag
			}
			got := ocpConfig.GetImage(deploymentconfigapi.FedoraKubevirtContainerDisk).PullSpec
			if got != want {
				t.Fatalf("repo %q: got %q, want %q", tc.repo, got, want)
			}

			images := ocpConfig.GetRequiredImages()
			if len(images) != 1 || images[0].ImageID != deploymentconfigapi.FedoraKubevirtContainerDisk || images[0].PullSpec != source {
				t.Fatalf("required images must contain only the original Fedora image with its OVN ID, got %+v", images)
			}
		})
	}
}

func TestSplitImagePullSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		pullSpec         string
		wantRegistry     string
		wantName         string
		wantVersion      string
		wantErrSubstring string
	}{
		{
			name:         "k8s promoter image",
			pullSpec:     "registry.k8s.io/e2e-test-images/agnhost:2.40",
			wantRegistry: "registry.k8s.io",
			wantName:     "e2e-test-images/agnhost",
			wantVersion:  "2.40",
		},
		{
			name:         "quay image with org and repo",
			pullSpec:     "quay.io/sronanrh/iperf:latest",
			wantRegistry: "quay.io",
			wantName:     "sronanrh/iperf",
			wantVersion:  "latest",
		},
		{
			name:         "ghcr image",
			pullSpec:     "ghcr.io/nicolaka/netshoot:v0.16",
			wantRegistry: "ghcr.io",
			wantName:     "nicolaka/netshoot",
			wantVersion:  "v0.16",
		},
		{
			name:         "docker library short name",
			pullSpec:     "nginx:1",
			wantRegistry: "docker.io",
			wantName:     "library/nginx",
			wantVersion:  "1",
		},
		{
			name:         "image name contains colon in tag only",
			pullSpec:     "quay.io/itssurya/dev-images:metallb-lbservice",
			wantRegistry: "quay.io",
			wantName:     "itssurya/dev-images",
			wantVersion:  "metallb-lbservice",
		},
		{
			name:         "docker hub org image without tag defaults to latest",
			pullSpec:     "cloudflare/goflow",
			wantRegistry: "docker.io",
			wantName:     "cloudflare/goflow",
			wantVersion:  "latest",
		},
		{
			name:         "localhost registry with port",
			pullSpec:     "localhost:5000/ovn/test:v1",
			wantRegistry: "localhost:5000",
			wantName:     "ovn/test",
			wantVersion:  "v1",
		},
		{
			name:         "ip address registry with port",
			pullSpec:     "192.168.1.10:5000/ovn/test:v1",
			wantRegistry: "192.168.1.10:5000",
			wantName:     "ovn/test",
			wantVersion:  "v1",
		},
		{
			name:         "bare ip address registry",
			pullSpec:     "192.168.1.10/ovn/test:v1",
			wantRegistry: "192.168.1.10",
			wantName:     "ovn/test",
			wantVersion:  "v1",
		},
		{
			name:         "arbitrary dns registry",
			pullSpec:     "evil.example.com/ovn/test:v1",
			wantRegistry: "evil.example.com",
			wantName:     "ovn/test",
			wantVersion:  "v1",
		},
		{
			name:             "digest pullspec",
			pullSpec:         "quay.io/frrouting/frr@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErrSubstring: "digest image pullspecs are not supported",
		},
		{
			name:             "empty pullspec",
			pullSpec:         "",
			wantErrSubstring: "empty image pullspec",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			registry, name, version, err := splitImagePullSpec(tc.pullSpec)
			if tc.wantErrSubstring != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrSubstring)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstring) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrSubstring, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if registry != tc.wantRegistry {
				t.Errorf("registry: got %q, want %q", registry, tc.wantRegistry)
			}
			if name != tc.wantName {
				t.Errorf("name: got %q, want %q", name, tc.wantName)
			}
			if version != tc.wantVersion {
				t.Errorf("version: got %q, want %q", version, tc.wantVersion)
			}
		})
	}
}

func TestExtensionImageFromPullSpec(t *testing.T) {
	t.Parallel()

	img, err := extensionImageFromPullSpec("quay.io/frrouting/frr:10.5.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if img.Registry != "quay.io" {
		t.Errorf("Registry: got %q, want %q", img.Registry, "quay.io")
	}
	if img.Name != "frrouting/frr" {
		t.Errorf("Name: got %q, want %q", img.Name, "frrouting/frr")
	}
	if img.Version != "10.5.3" {
		t.Errorf("Version: got %q, want %q", img.Version, "10.5.3")
	}

	if _, err := extensionImageFromPullSpec(""); err == nil {
		t.Fatal("expected error for empty pullspec")
	}
}

func TestRegisterTestImages(t *testing.T) {
	for _, repo := range []string{"", "quay.io/openshift/community-e2e-images", "mirror.example.com:5000/e2e"} {
		t.Run(repo, func(t *testing.T) {
			t.Setenv("KUBE_TEST_REPO", repo)
			ocpConfig, err := ocpdeploymentconfig.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			deploymentconfig.Set(ocpConfig)
			ocpConfig.AddRequiredImage(deploymentconfigapi.Agnhost,
				deploymentconfigapi.FedoraKubevirtContainerDisk,
				deploymentconfigapi.Netshoot)
			ext := extension.NewExtension("openshift", "payload", "ovn-kubernetes")
			if err := registerTestImages(ext); err != nil {
				t.Fatalf("failed to register test images: %v", err)
			}
			images := ext.Images

			agnhost := imageutils.GetOriginalImageConfigs()[imageutils.Agnhost]
			want := map[string]int{
				agnhost.GetE2EImage(): int(imageutils.Agnhost),
				"quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2": int(imageutils.None),
				"ghcr.io/nicolaka/netshoot:v0.16":                                 int(imageutils.None),
			}
			if got := len(images); got != len(want) {
				t.Fatalf("returned %d images, want %d", got, len(want))
			}
			for _, img := range images {
				pullSpec := fmt.Sprintf("%s/%s:%s", img.Registry, img.Name, img.Version)
				expected, ok := want[pullSpec]
				if !ok {
					t.Errorf("unexpected source image %q", pullSpec)
					continue
				}
				if img.Index != expected {
					t.Errorf("image %q index: got %d, want %d", pullSpec, img.Index, expected)
				}
				if img.Mapped != nil {
					t.Errorf("source image %q must not have an explicit mirror mapping", pullSpec)
				}
				delete(want, pullSpec)
			}
			for pullSpec := range want {
				t.Errorf("missing image %q", pullSpec)
			}
		})
	}
}

func TestRegisterOnlyRequiredImages(t *testing.T) {
	t.Setenv("KUBE_TEST_REPO", "mirror.example.com:5000/e2e")
	ocpConfig, err := ocpdeploymentconfig.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	deploymentconfig.Set(ocpConfig)
	if images := ocpConfig.GetRequiredImages(); len(images) != 0 {
		t.Fatalf("new configuration must have no selected images, got %+v", images)
	}
	ocpConfig.AddRequiredImage(deploymentconfigapi.Agnhost, deploymentconfigapi.Agnhost)
	required := ocpConfig.GetRequiredImages()
	agnhost := imageutils.GetOriginalImageConfigs()[imageutils.Agnhost]
	if len(required) != 1 || required[0].ImageID != deploymentconfigapi.Agnhost || required[0].PullSpec != agnhost.GetE2EImage() {
		t.Fatalf("expected only the selected source Agnhost image with its OVN ID, got %+v", required)
	}
	ext := extension.NewExtension("openshift", "payload", "ovn-kubernetes")
	if err := registerTestImages(ext); err != nil {
		t.Fatal(err)
	}
	if len(ext.Images) != 1 || ext.Images[0].Index != int(imageutils.Agnhost) {
		t.Fatalf("expected only Agnhost with its Kubernetes index, got %+v", ext.Images)
	}
}

func TestAgnhostUsesKubernetesRuntimeImage(t *testing.T) {
	ocpConfig, err := ocpdeploymentconfig.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	ocpConfig.AddRequiredImage(deploymentconfigapi.Agnhost)
	image := ocpConfig.GetImage(deploymentconfigapi.Agnhost)
	if image.ImageID != deploymentconfigapi.Agnhost || image.PullSpec != imageutils.GetE2EImage(imageutils.Agnhost) {
		t.Fatalf("Agnhost must use the Kubernetes-configured runtime image, got %+v", image)
	}
	source := imageutils.GetOriginalImageConfigs()[imageutils.Agnhost]
	required := ocpConfig.GetRequiredImages()
	if len(required) != 1 || required[0].ImageID != deploymentconfigapi.Agnhost || required[0].PullSpec != source.GetE2EImage() {
		t.Fatalf("required images must retain the original Agnhost pull spec and OVN ID, got %+v", required)
	}
}

func TestNetshootUsesCommunityMirror(t *testing.T) {
	const source = "ghcr.io/nicolaka/netshoot:v0.16"
	const mirrored = "quay.io/openshift/community-e2e-images:e2e-ghcr-io-nicolaka-netshoot-v0-16-dJoD5NGEFxLwUP4n"

	for _, tc := range []struct {
		name string
		repo string
		want string
	}{
		{name: "source", want: source},
		{name: "community mirror", repo: "quay.io/openshift/community-e2e-images", want: mirrored},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBE_TEST_REPO", tc.repo)
			ocpConfig, err := ocpdeploymentconfig.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			ocpConfig.AddRequiredImage(deploymentconfigapi.Netshoot)

			image := ocpConfig.GetImage(deploymentconfigapi.Netshoot)
			if image.ImageID != deploymentconfigapi.Netshoot || image.PullSpec != tc.want {
				t.Fatalf("repo %q: got %+v, want pull spec %q", tc.repo, image, tc.want)
			}
			required := ocpConfig.GetRequiredImages()
			if len(required) != 1 || required[0].ImageID != deploymentconfigapi.Netshoot || required[0].PullSpec != source {
				t.Fatalf("required images must retain the original netshoot pull spec and OVN ID, got %+v", required)
			}
		})
	}
}
