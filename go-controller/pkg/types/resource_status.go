package types

import (
	"fmt"
	"strings"
)

const (
	APBRouteErrorMsg       = "failed to apply policy"
	EgressFirewallErrorMsg = "EgressFirewall Rules not correctly applied"
	EgressQoSErrorMsg      = "EgressQoS Rules not correctly applied"
	NetworkQoSErrorMsg     = "NetworkQoS Destinations not correctly applied"
)

func GetZoneStatus(zoneID, message string) string {
	return fmt.Sprintf("%s: %s", zoneID, message)
}

func GetZoneFromStatus(status string) string {
	return strings.Split(status, ":")[0]
}
