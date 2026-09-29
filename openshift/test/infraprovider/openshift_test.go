package infraprovider

import (
	"os"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	operv1 "github.com/openshift/api/operator/v1"
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
			if got := hasEVPNFeatureGate(tt.fg); got != tt.want {
				t.Errorf("hasEVPNFeatureGate() = %v, want %v", got, tt.want)
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

func TestIsGCPPlatform(t *testing.T) {
	tests := []struct {
		name         string
		platformType configv1.PlatformType
		want         bool
	}{
		{
			name:         "GCP platform",
			platformType: configv1.GCPPlatformType,
			want:         true,
		},
		{
			name:         "AWS platform",
			platformType: configv1.AWSPlatformType,
			want:         false,
		},
		{
			name:         "BareMetal platform",
			platformType: configv1.BareMetalPlatformType,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OpenshiftInfraProvider{platformType: tt.platformType}
			if got := o.IsGCPPlatform(); got != tt.want {
				t.Errorf("IsGCPPlatform() = %v, want %v", got, tt.want)
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

func TestHasPlatformInfra(t *testing.T) {
	tests := []struct {
		name  string
		infra platformInfra
		want  bool
	}{
		{
			name:  "nil clusterInfra",
			infra: nil,
			want:  false,
		},
		{
			name:  "non-nil clusterInfra",
			infra: &baseInfra{},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OpenshiftInfraProvider{clusterInfra: tt.infra}
			if got := o.HasPlatformInfra(); got != tt.want {
				t.Errorf("HasPlatformInfra() = %v, want %v", got, tt.want)
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

func boolPtr(b bool) *bool { return &b }

func TestConfigureTestEnvs(t *testing.T) {
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
