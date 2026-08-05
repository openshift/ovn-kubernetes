package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
)

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
			pullSpec:     "ghcr.io/nicolaka/netshoot:v0.13",
			wantRegistry: "ghcr.io",
			wantName:     "nicolaka/netshoot",
			wantVersion:  "v0.13",
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
	if len(requiredImages) == 0 {
		t.Fatal("requiredImages is empty")
	}

	ext := extension.NewExtension("openshift", "payload", "ovn-kubernetes")
	err := registerTestImages(ext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(ext.Images), len(requiredImages); got != want {
		t.Fatalf("registered %d images, want %d from requiredImages", got, want)
	}

	type imageKey struct {
		index    int
		pullSpec string
	}
	want := make(map[imageKey]int)
	for _, ri := range requiredImages {
		want[imageKey{ri.index, ri.pullSpec}]++
	}

	got := make(map[imageKey]int, len(ext.Images))
	for _, img := range ext.Images {
		got[imageKey{img.Index, fmt.Sprintf("%s/%s:%s", img.Registry, img.Name, img.Version)}]++
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
