package main

import "k8s.io/apimachinery/pkg/util/sets"

// copied directly from https://github.com/openshift/origin/blob/main/pkg/clioptions/clusterdiscovery/cluster.go

// HypervisorConfig contains configuration for hypervisor-based recovery operations
type HypervisorConfig struct {
	HypervisorIP   string `json:"hypervisorIP"`
	SSHUser        string `json:"sshUser"`
	PrivateKeyPath string `json:"privateKeyPath"`
}

type ClusterConfiguration struct {
	ProviderName string `json:"type"`

	// These fields (and the "type" tag for ProviderName) chosen to match
	// upstream's e2e.CloudConfig.
	ProjectID   string
	Region      string
	Zone        string
	NumNodes    int
	MultiMaster bool
	MultiZone   bool
	Zones       []string
	ConfigFile  string

	// Disconnected is set for test jobs without external internet connectivity
	Disconnected bool

	// SingleReplicaTopology is set for disabling disruptive tests or tests
	// that require high availability
	SingleReplicaTopology bool

	// NetworkPlugin is the "official" plugin name
	NetworkPlugin string
	// NetworkPluginMode is an optional sub-identifier for the NetworkPlugin.
	// (Currently it is only used for OpenShiftSDN.)
	NetworkPluginMode string `json:",omitempty"`

	// HasIPv4 and HasIPv6 determine whether IPv4-specific, IPv6-specific,
	// and dual-stack-specific tests are run
	HasIPv4 bool
	HasIPv6 bool
	// IPFamily defines default IP stack of the cluster, replaces upstream getDefaultClusterIPFamily
	IPFamily string

	// HasSCTP determines whether SCTP connectivity tests can be run in the cluster
	HasSCTP bool

	// IsProxied determines whether we are accessing the cluster through an HTTP proxy
	IsProxied bool

	// IsIBMROKS determines whether the cluster is Managed IBM Cloud (ROKS)
	IsIBMROKS bool

	// IsNoOptionalCapabilities indicates the cluster has no optional capabilities enabled
	HasNoOptionalCapabilities bool

	// HypervisorConfig contains SSH configuration for hypervisor-based recovery operations
	HypervisorConfig *HypervisorConfig

	// APIGroups contains the set of API groups available in the cluster
	APIGroups sets.Set[string] `json:"-"`
	// EnabledFeatureGates contains the set of enabled feature gates in the cluster
	EnabledFeatureGates sets.Set[string] `json:"-"`
	// DisabledFeatureGates contains the set of disabled feature gates in the cluster
	DisabledFeatureGates sets.Set[string] `json:"-"`
}
