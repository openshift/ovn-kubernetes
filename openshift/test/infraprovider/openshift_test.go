package infraprovider

import (
	"fmt"
	"testing"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	_ "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	deploymentconfigapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
)

func TestPreloadImages(t *testing.T) {
	deploymentconfig.Get().AddRequiredImage(deploymentconfigapi.Agnhost)
	if len(deploymentconfig.Get().GetRequiredImages()) == 0 {
		t.Fatal("requiredImages is empty")
	}

	ext := extension.NewExtension("openshift", "payload", "ovn-kubernetes")
	ocpInfra := &OpenshiftInfraProvider{
		ext: ext,
	}
	ocpInfra.PreloadImages(deploymentconfig.Get().GetRequiredImages())

	if got, want := len(ext.Images), len(deploymentconfig.Get().GetRequiredImages()); got != want {
		t.Fatalf("registered %d images, want %d from requiredImages", got, want)
	}

	type imageKey struct {
		imageID  deploymentconfigapi.ImageID
		pullSpec string
	}
	want := make(map[imageKey]int)
	for _, ri := range deploymentconfig.Get().GetRequiredImages() {
		want[imageKey{ri.ImageID, ri.PullSpec}]++
	}

	got := make(map[imageKey]int, len(ext.Images))
	for _, img := range ext.Images {
		got[imageKey{deploymentconfigapi.ImageID(img.Index), fmt.Sprintf("%s/%s:%s", img.Registry, img.Name, img.Version)}]++
	}

	if len(got) != len(want) {
		t.Fatalf("registered %d unique images, want %d", len(got), len(want))
	}
	for key, count := range want {
		if got[key] != count {
			t.Errorf("image %+v: got count %d, want %d", key, got[key], count)
		}
	}
}
