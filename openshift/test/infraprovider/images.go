package infraprovider

import (
	"fmt"
	"strings"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
)

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
