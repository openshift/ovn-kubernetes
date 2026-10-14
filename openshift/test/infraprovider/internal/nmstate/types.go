package nmstate

type OVNBridgeMappingState string

const (
	OVNBridgeMappingStatePresent OVNBridgeMappingState = "present"
	OVNBridgeMappingStateAbsent  OVNBridgeMappingState = "absent"
)

type Configuration struct {
	OVN OVN `json:"ovn,omitempty"`
}

type OVN struct {
	BridgeMapping []OVNBridgeMapping `json:"bridge-mappings,omitempty"`
}

type OVNBridgeMapping struct {
	Localnet string                `json:"localnet,omitempty"`
	Bridge   string                `json:"bridge,omitempty"`
	State    OVNBridgeMappingState `json:"state,omitempty"`
}
