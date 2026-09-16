// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"reflect"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
)

type imageDeploymentConfig struct {
	api.DeploymentConfig
	netshootCalls int
}

func (c *imageDeploymentConfig) GetAgnHostContainerImage() string    { return "provider/agnhost" }
func (c *imageDeploymentConfig) GetFedoraContainerDiskImage() string { return "provider/fedora" }
func (c *imageDeploymentConfig) GetNetshootContainerImage() string {
	c.netshootCalls++
	return "provider/netshoot"
}

func TestProviderImages(t *testing.T) {
	originalAgnHost, originalNetshoot := agnHostOverride, netshootOverride
	originalExtra, originalDeferred := extraImages, deferredImages
	t.Cleanup(func() {
		agnHostOverride, netshootOverride = originalAgnHost, originalNetshoot
		extraImages, deferredImages = originalExtra, originalDeferred
		deploymentconfig.Set(nil)
	})
	agnHostOverride, netshootOverride = "", ""
	extraImages, deferredImages = nil, nil
	deploymentconfig.Set(nil)
	// Registration must work before the provider is installed, as in e2e init().
	AddDeferred(Netshoot)
	config := &imageDeploymentConfig{}
	deploymentconfig.Set(config)
	Add("provider/netshoot")
	if got, want := Required(), []string{"provider/agnhost", "provider/netshoot"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("required images: got %v, want %v", got, want)
	}
	if config.netshootCalls != 1 {
		t.Fatalf("expected deferred image resolution, got %d calls", config.netshootCalls)
	}
	if got := FedoraContainerDisk(); got != "provider/fedora" {
		t.Fatalf("Fedora image did not use provider: %q", got)
	}
	netshootOverride = "override/netshoot"
	if got := Netshoot(); got != netshootOverride || config.netshootCalls != 1 {
		t.Fatalf("override must bypass provider: image %q, calls %d", got, config.netshootCalls)
	}
}
