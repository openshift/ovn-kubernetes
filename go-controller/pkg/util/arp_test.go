package util

import (
	"net"
	"testing"
)

// TestSendReleaseGARP_InterfaceNotFound verifies that SendReleaseGARP
// returns an error when the interface doesn't exist
func TestSendReleaseGARP_InterfaceNotFound(t *testing.T) {
	nonExistentInterface := "nonexistent-iface-xyz"
	garp := &garp{
		ip: [4]byte{192, 168, 1, 1},
	}

	err := SendReleaseGARP(nonExistentInterface, garp)
	if err == nil {
		t.Errorf("SendReleaseGARP() should return error for non-existent interface, got nil")
	}
}

// TestGARPStruct verifies the GARP interface implementation
func TestGARPStruct(t *testing.T) {
	expectedIP := net.IPv4(10, 0, 0, 1)
	expectedMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	g := &garp{
		ip:  [4]byte{10, 0, 0, 1},
		mac: &expectedMAC,
	}

	// Test IP() method
	if !g.IP().Equal(expectedIP) {
		t.Errorf("GARP.IP() = %v, want %v", g.IP(), expectedIP)
	}

	// Test IPv4() method
	ipv4 := g.IPv4()
	if ipv4[0] != 10 || ipv4[1] != 0 || ipv4[2] != 0 || ipv4[3] != 1 {
		t.Errorf("GARP.IPv4() = %v, want [10 0 0 1]", ipv4)
	}

	// Test MAC() method
	mac := g.MAC()
	if mac == nil {
		t.Error("GARP.MAC() returned nil, expected non-nil")
	} else if mac.String() != expectedMAC.String() {
		t.Errorf("GARP.MAC() = %v, want %v", mac, expectedMAC)
	}
}

// TestGARPWithNilMAC verifies GARP behavior when MAC is nil
func TestGARPWithNilMAC(t *testing.T) {
	g := &garp{
		ip:  [4]byte{10, 0, 0, 1},
		mac: nil,
	}

	mac := g.MAC()
	if mac != nil {
		t.Errorf("GARP.MAC() = %v, want nil when not set", mac)
	}
}
