// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package infraprovider

import (
	"os"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	operv1 "github.com/openshift/api/operator/v1"
	ocpdeploymentconfig "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
)

func TestHasEVPNFeatureGate(t *testing.T) {
	tests := []struct {
		name string
		fg   *configv1.FeatureGate
		want bool
	}{
		{
			name: "nil FeatureGate",
			fg:   nil,
			want: false,
		},
		{
			name: "EVPN present",
			fg: &configv1.FeatureGate{
				Status: configv1.FeatureGateStatus{
					FeatureGates: []configv1.FeatureGateDetails{
						{
							Version: "4.18.0",
							Enabled: []configv1.FeatureGateAttributes{
								{Name: "SomeFeature"},
								{Name: "EVPN"},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "EVPN absent",
			fg: &configv1.FeatureGate{
				Status: configv1.FeatureGateStatus{
					FeatureGates: []configv1.FeatureGateDetails{
						{
							Version: "4.18.0",
							Enabled: []configv1.FeatureGateAttributes{
								{Name: "SomeOtherFeature"},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "empty feature list",
			fg: &configv1.FeatureGate{
				Status: configv1.FeatureGateStatus{
					FeatureGates: []configv1.FeatureGateDetails{
						{Version: "4.18.0"},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasFeatureGate(tt.fg, evpnFeatureGateName); got != tt.want {
				t.Errorf("hasFeatureGate(%s) = %v, want %v", evpnFeatureGateName, got, tt.want)
			}
		})
	}
}

func TestHasFRRRouteProvider(t *testing.T) {
	tests := []struct {
		name    string
		network *operv1.Network
		want    bool
	}{
		{
			name:    "nil AdditionalRoutingCapabilities",
			network: &operv1.Network{},
			want:    false,
		},
		{
			name: "FRR present",
			network: &operv1.Network{
				Spec: operv1.NetworkSpec{
					AdditionalRoutingCapabilities: &operv1.AdditionalRoutingCapabilities{
						Providers: []operv1.RoutingCapabilitiesProvider{
							operv1.RoutingCapabilitiesProviderFRR,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "FRR absent",
			network: &operv1.Network{
				Spec: operv1.NetworkSpec{
					AdditionalRoutingCapabilities: &operv1.AdditionalRoutingCapabilities{
						Providers: []operv1.RoutingCapabilitiesProvider{
							"SomeOther",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "empty providers list",
			network: &operv1.Network{
				Spec: operv1.NetworkSpec{
					AdditionalRoutingCapabilities: &operv1.AdditionalRoutingCapabilities{},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasFRRRouteProvider(tt.network); got != tt.want {
				t.Errorf("hasFRRRouteProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsLocalGatewayMode(t *testing.T) {
	tests := []struct {
		name    string
		network *operv1.Network
		want    bool
	}{
		{
			name:    "nil OVNKubernetesConfig",
			network: &operv1.Network{},
			want:    false,
		},
		{
			name: "nil GatewayConfig",
			network: &operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						OVNKubernetesConfig: &operv1.OVNKubernetesConfig{},
					},
				},
			},
			want: false,
		},
		{
			name: "RoutingViaHost true",
			network: &operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						OVNKubernetesConfig: &operv1.OVNKubernetesConfig{
							GatewayConfig: &operv1.GatewayConfig{
								RoutingViaHost: true,
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "RoutingViaHost false",
			network: &operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						OVNKubernetesConfig: &operv1.OVNKubernetesConfig{
							GatewayConfig: &operv1.GatewayConfig{
								RoutingViaHost: false,
							},
						},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalGatewayMode(tt.network); got != tt.want {
				t.Errorf("isLocalGatewayMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCloudPlatform(t *testing.T) {
	tests := []struct {
		name         string
		platformType configv1.PlatformType
		want         bool
	}{
		{name: "AWS", platformType: configv1.AWSPlatformType, want: true},
		{name: "Azure", platformType: configv1.AzurePlatformType, want: true},
		{name: "GCP", platformType: configv1.GCPPlatformType, want: true},
		{name: "BareMetal", platformType: configv1.BareMetalPlatformType, want: false},
		{name: "None", platformType: configv1.NonePlatformType, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OpenshiftInfraProvider{platformType: tt.platformType}
			if got := o.IsCloudPlatform(); got != tt.want {
				t.Errorf("IsCloudPlatform() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckForEVPN(t *testing.T) {
	fullNetwork := &operv1.Network{
		Spec: operv1.NetworkSpec{
			DefaultNetwork: operv1.DefaultNetworkDefinition{
				OVNKubernetesConfig: &operv1.OVNKubernetesConfig{
					GatewayConfig: &operv1.GatewayConfig{
						RoutingViaHost: true,
					},
				},
			},
			AdditionalRoutingCapabilities: &operv1.AdditionalRoutingCapabilities{
				Providers: []operv1.RoutingCapabilitiesProvider{
					operv1.RoutingCapabilitiesProviderFRR,
				},
			},
		},
	}

	fullFeatureGate := &configv1.FeatureGate{
		Status: configv1.FeatureGateStatus{
			FeatureGates: []configv1.FeatureGateDetails{
				{
					Version: "4.18.0",
					Enabled: []configv1.FeatureGateAttributes{
						{Name: "EVPN"},
					},
				},
			},
		},
	}

	tests := []struct {
		name string
		o    *OpenshiftInfraProvider
		want bool
	}{
		{
			name: "all prerequisites met",
			o: &OpenshiftInfraProvider{
				operNetwork:             fullNetwork,
				clusterFeatureGate:      fullFeatureGate,
				hasFRRExternalContainer: true,
			},
			want: true,
		},
		{
			name: "nil operNetwork",
			o: &OpenshiftInfraProvider{
				operNetwork:             nil,
				clusterFeatureGate:      fullFeatureGate,
				hasFRRExternalContainer: true,
			},
			want: false,
		},
		{
			name: "missing EVPN feature gate",
			o: &OpenshiftInfraProvider{
				operNetwork:             fullNetwork,
				clusterFeatureGate:      nil,
				hasFRRExternalContainer: true,
			},
			want: false,
		},
		{
			name: "missing FRR route provider",
			o: &OpenshiftInfraProvider{
				operNetwork: &operv1.Network{
					Spec: operv1.NetworkSpec{
						DefaultNetwork: operv1.DefaultNetworkDefinition{
							OVNKubernetesConfig: &operv1.OVNKubernetesConfig{
								GatewayConfig: &operv1.GatewayConfig{
									RoutingViaHost: true,
								},
							},
						},
					},
				},
				clusterFeatureGate:      fullFeatureGate,
				hasFRRExternalContainer: true,
			},
			want: false,
		},
		{
			name: "not local gateway mode",
			o: &OpenshiftInfraProvider{
				operNetwork: &operv1.Network{
					Spec: operv1.NetworkSpec{
						DefaultNetwork: operv1.DefaultNetworkDefinition{
							OVNKubernetesConfig: &operv1.OVNKubernetesConfig{
								GatewayConfig: &operv1.GatewayConfig{
									RoutingViaHost: false,
								},
							},
						},
						AdditionalRoutingCapabilities: &operv1.AdditionalRoutingCapabilities{
							Providers: []operv1.RoutingCapabilitiesProvider{
								operv1.RoutingCapabilitiesProviderFRR,
							},
						},
					},
				},
				clusterFeatureGate:      fullFeatureGate,
				hasFRRExternalContainer: true,
			},
			want: false,
		},
		{
			name: "no FRR external container",
			o: &OpenshiftInfraProvider{
				operNetwork:             fullNetwork,
				clusterFeatureGate:      fullFeatureGate,
				hasFRRExternalContainer: false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.o.CheckForEVPN(); got != tt.want {
				t.Errorf("CheckForEVPN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindNetworkInterfaceForSubnets(t *testing.T) {
	links := []linkInfo{
		{
			IfName: "lo",
			Mac:    "00:00:00:00:00:00",
			AddrInfo: []ipAddressInfo{
				{Family: "inet", Local: "127.0.0.1", PrefixLen: 8},
				{Family: "inet6", Local: "::1", PrefixLen: 128},
			},
		},
		{
			IfName: "enp0s3",
			Mac:    "02:00:00:00:00:01",
			AddrInfo: []ipAddressInfo{
				{Family: "inet", Local: "192.168.111.22", PrefixLen: 24},
				{Family: "inet6", Local: "fd2e:6f44:5dd8:c956::22", PrefixLen: 64},
			},
		},
	}

	t.Run("dual stack", func(t *testing.T) {
		got, err := findNetworkInterfaceForSubnets(links, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/64")
		if err != nil {
			t.Fatalf("findNetworkInterfaceForSubnets() error = %v", err)
		}
		if got.InfName != "enp0s3" {
			t.Errorf("InfName = %q, want %q", got.InfName, "enp0s3")
		}
		if got.MAC != "02:00:00:00:00:01" {
			t.Errorf("MAC = %q, want %q", got.MAC, "02:00:00:00:00:01")
		}
		if got.IPv4 != "192.168.111.22" {
			t.Errorf("IPv4 = %q, want %q", got.IPv4, "192.168.111.22")
		}
		if got.IPv4Prefix != "24" {
			t.Errorf("IPv4Prefix = %q, want %q", got.IPv4Prefix, "24")
		}
		if got.IPv6 != "fd2e:6f44:5dd8:c956::22" {
			t.Errorf("IPv6 = %q, want %q", got.IPv6, "fd2e:6f44:5dd8:c956::22")
		}
		if got.IPv6Prefix != "64" {
			t.Errorf("IPv6Prefix = %q, want %q", got.IPv6Prefix, "64")
		}
	})

	t.Run("IPv6 only", func(t *testing.T) {
		got, err := findNetworkInterfaceForSubnets(links, "", "fd2e:6f44:5dd8:c956::/64")
		if err != nil {
			t.Fatalf("findNetworkInterfaceForSubnets() error = %v", err)
		}
		if got.IPv4 != "" {
			t.Errorf("IPv4 = %q, want empty", got.IPv4)
		}
		if got.IPv6 != "fd2e:6f44:5dd8:c956::22" {
			t.Errorf("IPv6 = %q, want %q", got.IPv6, "fd2e:6f44:5dd8:c956::22")
		}
	})

	t.Run("no match", func(t *testing.T) {
		_, err := findNetworkInterfaceForSubnets(links, "10.0.0.0/24", "")
		if err == nil {
			t.Fatal("expected error for no match, got nil")
		}
	})
}

func boolPtr(b bool) *bool { return &b }

func TestConfigureTestEnvs(t *testing.T) {
	deploymentconfig.Set(ocpdeploymentconfig.New(nil))
	tests := []struct {
		name            string
		operNetwork     *operv1.Network
		wantGatewayMode string
		wantNetSegment  string
	}{
		{
			name:        "nil operNetwork",
			operNetwork: nil,
		},
		{
			name: "local gateway mode sets OVN_GATEWAY_MODE",
			operNetwork: &operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						OVNKubernetesConfig: &operv1.OVNKubernetesConfig{
							GatewayConfig: &operv1.GatewayConfig{
								RoutingViaHost: true,
							},
						},
					},
					DisableMultiNetwork: boolPtr(true),
				},
			},
			wantGatewayMode: "local",
		},
		{
			name: "shared gateway mode does not set OVN_GATEWAY_MODE",
			operNetwork: &operv1.Network{
				Spec: operv1.NetworkSpec{
					DefaultNetwork: operv1.DefaultNetworkDefinition{
						OVNKubernetesConfig: &operv1.OVNKubernetesConfig{
							GatewayConfig: &operv1.GatewayConfig{
								RoutingViaHost: false,
							},
						},
					},
					DisableMultiNetwork: boolPtr(true),
				},
			},
		},
		{
			name: "DisableMultiNetwork nil sets ENABLE_NETWORK_SEGMENTATION",
			operNetwork: &operv1.Network{
				Spec: operv1.NetworkSpec{
					DisableMultiNetwork: nil,
				},
			},
			wantNetSegment: "true",
		},
		{
			name: "DisableMultiNetwork false sets ENABLE_NETWORK_SEGMENTATION",
			operNetwork: &operv1.Network{
				Spec: operv1.NetworkSpec{
					DisableMultiNetwork: boolPtr(false),
				},
			},
			wantNetSegment: "true",
		},
		{
			name: "DisableMultiNetwork true does not set ENABLE_NETWORK_SEGMENTATION",
			operNetwork: &operv1.Network{
				Spec: operv1.NetworkSpec{
					DisableMultiNetwork: boolPtr(true),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean env before each subtest. t.Setenv registers
			// cleanup to restore the original value when the subtest ends.
			t.Setenv("OVN_GATEWAY_MODE", "")
			t.Setenv("ENABLE_NETWORK_SEGMENTATION", "")

			o := &OpenshiftInfraProvider{operNetwork: tt.operNetwork}
			o.configureTestEnvs()

			if got := os.Getenv("OVN_GATEWAY_MODE"); got != tt.wantGatewayMode {
				t.Errorf("OVN_GATEWAY_MODE = %q, want %q", got, tt.wantGatewayMode)
			}
			if got := os.Getenv("ENABLE_NETWORK_SEGMENTATION"); got != tt.wantNetSegment {
				t.Errorf("ENABLE_NETWORK_SEGMENTATION = %q, want %q", got, tt.wantNetSegment)
			}
		})
	}
}
