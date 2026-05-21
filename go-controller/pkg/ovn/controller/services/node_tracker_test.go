package services

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

func TestGetZoneNodes_UDNFiltersByZone(t *testing.T) {
	oldIPv4Mode := config.IPv4Mode
	defer func() { config.IPv4Mode = oldIPv4Mode }()
	config.IPv4Mode = true

	udnNetInfo, err := getSampleUDNNetInfo("test-namespace", "layer3")
	require.NoError(t, err)

	nt := newNodeTracker("global", func(nodes []nodeInfo) {}, udnNetInfo)

	nt.nodes["node1"] = nodeInfo{
		name:       "node1",
		zone:       "global",
		mgmtIPs:    []net.IP{net.ParseIP("10.0.0.1")},
		switchName: "switch1",
	}
	nt.nodes["node2"] = nodeInfo{
		name:       "node2",
		zone:       "zone-a",
		mgmtIPs:    []net.IP{net.ParseIP("10.0.0.2")},
		switchName: "switch2",
	}
	nt.nodes["node3"] = nodeInfo{
		name:       "node3",
		zone:       "zone-b",
		mgmtIPs:    []net.IP{net.ParseIP("10.0.0.3")},
		switchName: "switch3",
	}

	nt.Lock()
	nodes := nt.getZoneNodes()
	nt.Unlock()

	// UDN should filter by zone like default network
	assert.Len(t, nodes, 1)
	assert.Equal(t, "node1", nodes[0].name)
}

func TestGetZoneNodes_DefaultNetwork(t *testing.T) {
	oldIPv4Mode := config.IPv4Mode
	defer func() { config.IPv4Mode = oldIPv4Mode }()
	config.IPv4Mode = true

	defaultNetInfo := &util.DefaultNetInfo{}

	nt := newNodeTracker("global", func(nodes []nodeInfo) {}, defaultNetInfo)

	nt.nodes["node1"] = nodeInfo{
		name:       "node1",
		zone:       "global",
		mgmtIPs:    []net.IP{net.ParseIP("10.0.0.1")},
		switchName: "switch1",
	}
	nt.nodes["node2"] = nodeInfo{
		name:       "node2",
		zone:       "zone-a",
		mgmtIPs:    []net.IP{net.ParseIP("10.0.0.2")},
		switchName: "switch2",
	}
	nt.nodes["node3"] = nodeInfo{
		name:       "node3",
		zone:       "global",
		mgmtIPs:    []net.IP{net.ParseIP("10.0.0.3")},
		switchName: "switch3",
	}

	nt.Lock()
	nodes := nt.getZoneNodes()
	nt.Unlock()

	// Default network should filter by zone
	assert.Len(t, nodes, 2)

	nodeNames := make([]string, len(nodes))
	for i, n := range nodes {
		nodeNames[i] = n.name
	}
	assert.Contains(t, nodeNames, "node1")
	assert.Contains(t, nodeNames, "node3")
	assert.NotContains(t, nodeNames, "node2")
}

func TestGetZoneNodes_Sorting(t *testing.T) {
	oldIPv4Mode := config.IPv4Mode
	defer func() { config.IPv4Mode = oldIPv4Mode }()
	config.IPv4Mode = true

	udnNetInfo, err := getSampleUDNNetInfo("test-namespace", "layer3")
	require.NoError(t, err)

	nt := newNodeTracker("global", func(nodes []nodeInfo) {}, udnNetInfo)

	nt.nodes["node-c"] = nodeInfo{name: "node-c", zone: "global"}
	nt.nodes["node-a"] = nodeInfo{name: "node-a", zone: "global"}
	nt.nodes["node-b"] = nodeInfo{name: "node-b", zone: "global"}

	nt.Lock()
	nodes := nt.getZoneNodes()
	nt.Unlock()

	assert.Len(t, nodes, 3)
	assert.Equal(t, "node-a", nodes[0].name)
	assert.Equal(t, "node-b", nodes[1].name)
	assert.Equal(t, "node-c", nodes[2].name)
}
