package types

import (
	"net"

	"github.com/containernetworking/cni/pkg/types"
)

// NetConf is CNI NetConf with DeviceID
type NetConf struct {
	types.NetConf

	// specifies the OVN topology for this network configuration
	// when not specified, by default it is Layer3AttachDefTopoType
	Topology string `json:"topology,omitempty"`
	// captures net-attach-def name in the form of namespace/name
	NADName string `json:"netAttachDefName,omitempty"`
	// Network MTU
	MTU int `json:"mtu,omitempty"`
	// comma-seperated subnet cidr
	// for secondary layer3 network, eg. 10.128.0.0/14/23
	// for layer2 and localnet network, eg. 10.1.130.0/24
	Subnets string `json:"subnets,omitempty"`
	// comma-seperated list of IPs, expressed in the form of subnets, to be excluded from being allocated for Pod
	// valid for layer2 and localnet network topology
	// eg. "10.1.130.0/27, 10.1.130.122/32"
	ExcludeSubnets string `json:"excludeSubnets,omitempty"`
	// VLANID, valid in localnet topology network only
	VLANID int `json:"vlanID,omitempty"`

	// PciAddrs in case of using sriov or Auxiliry device name in case of SF
	DeviceID string `json:"deviceID,omitempty"`
	// LogFile to log all the messages from cni shim binary to
	LogFile string `json:"logFile,omitempty"`
	// Level is the logging verbosity level
	LogLevel string `json:"logLevel,omitempty"`
	// LogFileMaxSize is the maximum size in bytes of the logfile
	// before it gets rolled.
	LogFileMaxSize int `json:"logfile-maxsize"`
	// LogFileMaxBackups represents the maximum number of
	// old log files to retain
	LogFileMaxBackups int `json:"logfile-maxbackups"`
	// LogFileMaxAge represents the maximum number
	// of days to retain old log files
	LogFileMaxAge int `json:"logfile-maxage"`
}

// NetworkSelectionElement represents one element of the JSON format
// Network Attachment Selection Annotation as described in section 4.1.2
// of the CRD specification.
type NetworkSelectionElement struct {
	// Name contains the name of the Network object this element selects
	Name string `json:"name"`
	// Namespace contains the optional namespace that the network referenced
	// by Name exists in
	Namespace string `json:"namespace,omitempty"`
	// MacRequest contains an optional requested MAC address for this
	// network attachment
	MacRequest string `json:"mac,omitempty"`
	// GatewayRequest contains default route IP address for the pod
	GatewayRequest []net.IP `json:"default-route,omitempty"`
}
