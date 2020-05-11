package types

import (
	"github.com/containernetworking/cni/pkg/types"
	"net"
)

// NetConf is CNI NetConf with DeviceID
type NetConf struct {
	types.NetConf
	// PciAddrs in case of using sriov
	DeviceID string `json:"deviceID,omitempty"`
	// LogFile to log all the messages from cni shim binary to
	LogFile string `json:"logFile,omitempty"`
	// Level is the logging verbosity level
	LogLevel string `json:"logLevel,omitempty"`
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
