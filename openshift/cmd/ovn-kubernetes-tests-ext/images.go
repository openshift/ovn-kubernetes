package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"
)

// registerTestImages advertises OVN-Kubernetes e2e images to the openshift-tests
// extension so origin can list and mirror them (see "images" subcommand).
func registerTestImages(ext *extension.Extension) {
	for _, pullSpec := range images.Required() {
		img, err := extensionImageFromPullSpec(pullSpec)
		if err != nil {
			panic(fmt.Sprintf("failed to register test image %q: %v", pullSpec, err))
		}
		ext.RegisterImage(img)
	}
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
		if err := validateRegistryHost(first, pullSpec); err != nil {
			return "", "", "", err
		}
		// Explicit registry, e.g. "quay.io/foo/bar" or "registry.k8s.io/e2e-test-images/agnhost"
		return first, rest, version, nil
	}

	// Docker Hub user/org image, e.g. "cloudflare/goflow"
	return "docker.io", remainder, version, nil
}

// validateRegistryHost rejects IP addresses and host:port forms. DNS registry
// names are allowed.
func validateRegistryHost(host, pullSpec string) error {
	if strings.Contains(host, ":") {
		return fmt.Errorf("registry host must not include a port: %q", pullSpec)
	}
	if host == "localhost" || net.ParseIP(host) != nil {
		return fmt.Errorf("registry host must be a DNS name, not an IP address or localhost: %q", pullSpec)
	}
	return nil
}
