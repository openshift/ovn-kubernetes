package main

import (
	"fmt"
	"strings"

	imageutils "k8s.io/kubernetes/test/utils/image"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
)

// requiredImage associates an e2e image pullspec with an index used to generate
// the image tag so that it matches with the tag in quay.io/openshift/community-e2e-images.
type requiredImage struct {
	pullSpec string
	index    int
}

var requiredImages []requiredImage

func init() {
	agnhostImage := requiredImage{
		pullSpec: imageutils.GetE2EImage(imageutils.Agnhost),
		index:    int(imageutils.Agnhost),
	}
	requiredImages = append(requiredImages, agnhostImage)
}

// registerTestImages advertises OVN-Kubernetes e2e images to the openshift-tests
// extension so origin can list and mirror them (see "images" subcommand).
func registerTestImages(ext *extension.Extension) error {
	for _, ri := range requiredImages {
		img, err := extensionImageFromPullSpec(ri.pullSpec)
		if err != nil {
			return fmt.Errorf("failed to register test image %q: %v", ri.pullSpec, err)
		}
		img.Index = ri.index
		ext.RegisterImage(img)
	}
	return nil
}

// extensionImageFromPullSpec splits a pullspec into the registry/name/version
// layout expected by k8s.io/kubernetes/test/utils/image.Config.GetE2EImage
// (fmt.Sprintf("%s/%s:%s", registry, name, version)).
func extensionImageFromPullSpec(pullSpec string) (extension.Image, error) {
	registry, name, version, err := splitImagePullSpec(pullSpec)
	if err != nil {
		return extension.Image{}, err
	}
	return extension.Image{
		Registry: registry,
		Name:     name,
		Version:  version,
	}, nil
}

func splitImagePullSpec(pullSpec string) (registry, name, version string, err error) {
	if pullSpec == "" {
		return "", "", "", fmt.Errorf("empty image pullspec")
	}
	if strings.Contains(pullSpec, "@") {
		return "", "", "", fmt.Errorf("digest image pullspecs are not supported: %q", pullSpec)
	}

	remainder := pullSpec
	if tagIndex := strings.LastIndex(pullSpec, ":"); tagIndex > strings.LastIndex(pullSpec, "/") {
		version = pullSpec[tagIndex+1:]
		remainder = pullSpec[:tagIndex]
	}
	if version == "" {
		version = "latest"
	}

	first, rest, ok := strings.Cut(remainder, "/")
	if !ok {
		// Short docker-library name, e.g. "nginx" → docker.io/library/nginx
		return "docker.io", "library/" + remainder, version, nil
	}

	if strings.ContainsAny(first, ".:") || first == "localhost" {
		// Explicit registry, e.g. "quay.io/foo/bar", "registry.k8s.io/...",
		// or "localhost:5000/ovn/test"
		return first, rest, version, nil
	}

	// Docker Hub user/org image, e.g. "cloudflare/goflow"
	return "docker.io", remainder, version, nil
}
