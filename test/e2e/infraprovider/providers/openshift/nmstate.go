package openshift

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type NodeNetworkState struct {
	DNSResolver DNSResolver `json:"dns-resolver"`
	Interfaces  []Interface `json:"interfaces"`
	OVN         OVN         `json:"ovn"`
	Routes      Routes      `json:"routes"`
}

type DNSResolver struct {
	Config  DNSConfig  `json:"config"`
	Running DNSRunning `json:"running"`
}

type DNSConfig struct {
	Search interface{} `json:"search"`
	Server interface{} `json:"server"`
}

type DNSRunning struct {
	Search []string `json:"search"`
	Server []string `json:"server"`
}

type Interface struct {
	AcceptAllMACAddresses bool      `json:"accept-all-mac-addresses,omitempty"`
	Controller            string    `json:"controller,omitempty"`
	Ethtool               *Ethtool  `json:"ethtool,omitempty"`
	Identifier            string    `json:"identifier,omitempty"`
	IPv4                  *IPConfig `json:"ipv4,omitempty"`
	IPv6                  *IPConfig `json:"ipv6,omitempty"`
	LLDP                  *LLDP     `json:"lldp,omitempty"`
	MACAddress            string    `json:"mac-address,omitempty"`
	MaxMTU                int       `json:"max-mtu,omitempty"`
	MinMTU                int       `json:"min-mtu,omitempty"`
	MPTCP                 *MPTCP    `json:"mptcp,omitempty"`
	MTU                   int       `json:"mtu,omitempty"`
	Name                  string    `json:"name"`
	ProfileName           string    `json:"profile-name,omitempty"`
	State                 string    `json:"state,omitempty"`
	Type                  string    `json:"type"`
	WaitIP                string    `json:"wait-ip,omitempty"`
	Driver                string    `json:"driver,omitempty"`
	Ethernet              *Ethernet `json:"ethernet,omitempty"`
	PermanentMACAddress   string    `json:"permanent-mac-address,omitempty"`
	OVSDB                 *OVSDB    `json:"ovs-db,omitempty"`
	Patch                 *Patch    `json:"patch,omitempty"`
}

type Ethtool struct {
	Feature  map[string]bool `json:"feature,omitempty"`
	Coalesce *Coalesce       `json:"coalesce,omitempty"`
	Ring     *Ring           `json:"ring,omitempty"`
}

type Coalesce struct {
	RXFrames int `json:"rx-frames"`
	RXUsecs  int `json:"rx-usecs"`
	TXFrames int `json:"tx-frames"`
	TXUsecs  int `json:"tx-usecs"`
}

type Ring struct {
	RX    int `json:"rx"`
	RXMax int `json:"rx-max"`
	TX    int `json:"tx"`
	TXMax int `json:"tx-max"`
}

type IPConfig struct {
	Address          []IPAddress `json:"address,omitempty"`
	AutoDNS          bool        `json:"auto-dns,omitempty"`
	AutoGateway      bool        `json:"auto-gateway,omitempty"`
	AutoRouteMetric  int         `json:"auto-route-metric,omitempty"`
	AutoRouteTableID int         `json:"auto-route-table-id,omitempty"`
	AutoRoutes       bool        `json:"auto-routes,omitempty"`
	DHCP             bool        `json:"dhcp,omitempty"`
	DHCPSendHostname bool        `json:"dhcp-send-hostname,omitempty"`
	Enabled          bool        `json:"enabled"`
	AddrGenMode      string      `json:"addr-gen-mode,omitempty"`
	Autoconf         bool        `json:"autoconf,omitempty"`
}

type IPAddress struct {
	IP                string `json:"ip"`
	PreferredLifeTime string `json:"preferred-life-time,omitempty"`
	PrefixLength      int    `json:"prefix-length"`
	ValidLifeTime     string `json:"valid-life-time,omitempty"`
}

type LLDP struct {
	Enabled bool `json:"enabled"`
}

type MPTCP struct {
	AddressFlags []string `json:"address-flags"`
}

type Ethernet struct {
	AutoNegotiation bool `json:"auto-negotiation,omitempty"`
}

type OVSDB struct {
	ExternalIDs map[string]string `json:"external_ids"`
	OtherConfig map[string]string `json:"other_config"`
}

type Patch struct {
	Peer string `json:"peer"`
}

type OVN struct {
	BridgeMappings []BridgeMapping `json:"bridge-mappings"`
}

type BridgeMapping struct {
	Bridge   string `json:"bridge"`
	Localnet string `json:"localnet"`
}

type Routes struct {
	Config  []Route `json:"config"`
	Running []Route `json:"running"`
}

type Route struct {
	Destination      string `json:"destination"`
	Metric           *int   `json:"metric,omitempty"`
	MTU              *int   `json:"mtu,omitempty"`
	NextHopAddress   string `json:"next-hop-address"`
	NextHopInterface string `json:"next-hop-interface"`
	Source           string `json:"source,omitempty"`
	TableID          int    `json:"table-id"`
}

func (nns *NodeNetworkState) FindInterfaceByMAC(mac string) *Interface {
	for _, iface := range nns.Interfaces {
		if strings.ToUpper(iface.MACAddress) == strings.ToUpper(mac) {
			return &iface
		}
	}
	return nil
}

func getNodeNetworkState(node string) (*NodeNetworkState, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("oc get nns %s -o jsonpath='{.status.currentState}'", node))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to get NodeNetworkState for node %s: %s: %w", node, stderr.String(), err)
	}
	nns := &NodeNetworkState{}
	if err := json.Unmarshal(stdout.Bytes(), nns); err != nil {
		return nil, fmt.Errorf("failed to umarshal NodeNetworkState %q: %w", stdout.String(), err)
	}
	return nns, nil
}
