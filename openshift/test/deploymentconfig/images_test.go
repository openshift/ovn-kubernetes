package deploymentconfig

import (
	"strings"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"
	imageutils "k8s.io/kubernetes/test/utils/image"

	imagev1 "github.com/openshift/api/image/v1"
	imagefake "github.com/openshift/client-go/image/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNetworkToolsImage(t *testing.T) {
	t.Setenv("NETSHOOT_IMAGE", "")
	const pullspec = "mirror.example.com/network-tools@sha256:abc"
	for _, tc := range []struct {
		name    string
		tags    []imagev1.NamedTagEventList
		wantErr bool
	}{
		{name: "latest imported image", tags: []imagev1.NamedTagEventList{
			{Tag: "old", Items: []imagev1.TagEvent{{DockerImageReference: "old-image"}}},
			{Tag: "latest", Items: []imagev1.TagEvent{{DockerImageReference: pullspec}, {DockerImageReference: "previous-image"}}},
		}},
		{name: "missing tag", wantErr: true},
		{name: "empty tag", tags: []imagev1.NamedTagEventList{{Tag: "latest"}}, wantErr: true},
		{name: "empty pullspec", tags: []imagev1.NamedTagEventList{{Tag: "latest", Items: []imagev1.TagEvent{{}}}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := imagefake.NewSimpleClientset(&imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "network-tools", Namespace: "openshift"},
				Status:     imagev1.ImageStreamStatus{Tags: tc.tags},
			})
			config := &openshift{imageClient: client}
			got, err := config.getNetworkToolsImage()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "no imported Docker image reference") {
					t.Fatalf("expected missing image error, got %v", err)
				}
				return
			}
			if err != nil || got != pullspec {
				t.Fatalf("got %q, %v; want %q", got, err, pullspec)
			}
			if got := config.GetImage(images.Netshoot); got != pullspec || len(client.Actions()) != 1 {
				t.Fatalf("expected cached image %q, got %q with %d API calls", pullspec, got, len(client.Actions()))
			}
		})
	}
	t.Run("API error", func(t *testing.T) {
		config := &openshift{imageClient: imagefake.NewSimpleClientset()}
		if _, err := config.getNetworkToolsImage(); err == nil || !strings.Contains(err.Error(), "resolve payload network-tools image") {
			t.Fatalf("expected image lookup error, got %v", err)
		}
	})
}

func TestRequiredImagesForVirtualization(t *testing.T) {
	t.Setenv("KUBE_TEST_REPO", "example.com/mirror")
	client := imagefake.NewSimpleClientset()
	config := &openshift{imageClient: client}
	foundFedora := false
	for _, image := range config.GetRequiredImages() {
		if image.PullSpec == FedoraContainerDiskImage {
			foundFedora = true
			if image.ImageID != api.ImageID(imageutils.None) {
				t.Fatalf("Fedora mirror index: got %d, want %d", image.ImageID, imageutils.None)
			}
		}
	}
	if !foundFedora {
		t.Fatal("Fedora must be advertised without KIND_INSTALL_KUBEVIRT")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("image discovery must not query the cluster")
	}
	t.Setenv("NETSHOOT_IMAGE", "example.com/tools:test")
	if got := config.GetImage(images.Netshoot); got != "example.com/tools:test" {
		t.Fatalf("Netshoot override ignored: %q", got)
	}
}
