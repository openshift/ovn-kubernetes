// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocator

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeCleanup is a test stub for ContextCleanUp interface
type fakeCleanup struct {
	cleanupFns []func() error
}

func (f *fakeCleanup) AddCleanUpFn(fn func() error) {
	f.cleanupFns = append(f.cleanupFns, fn)
}

func TestIndexToIP(t *testing.T) {
	tests := []struct {
		name     string
		baseIP   string
		index    int
		bits     int
		expected string
	}{
		{
			name:     "IPv4 first usable IP",
			baseIP:   "192.168.1.0",
			index:    1,
			bits:     32,
			expected: "192.168.1.1",
		},
		{
			name:     "IPv4 10th IP",
			baseIP:   "192.168.1.0",
			index:    10,
			bits:     32,
			expected: "192.168.1.10",
		},
		{
			name:     "IPv4 254th IP (last usable in /24)",
			baseIP:   "192.168.1.0",
			index:    254,
			bits:     32,
			expected: "192.168.1.254",
		},
		{
			name:     "IPv4 /16 subnet",
			baseIP:   "10.0.0.0",
			index:    256,
			bits:     32,
			expected: "10.0.1.0",
		},
		{
			name:     "IPv4 /16 subnet higher index",
			baseIP:   "10.0.0.0",
			index:    1000,
			bits:     32,
			expected: "10.0.3.232",
		},
		{
			name:     "IPv6 first usable IP",
			baseIP:   "fd00::",
			index:    1,
			bits:     128,
			expected: "fd00::1",
		},
		{
			name:     "IPv6 10th IP",
			baseIP:   "fd00::",
			index:    10,
			bits:     128,
			expected: "fd00::a",
		},
		{
			name:     "IPv6 256th IP",
			baseIP:   "fd00::",
			index:    256,
			bits:     128,
			expected: "fd00::100",
		},
		{
			name:     "IPv6 large index",
			baseIP:   "2001:db8::",
			index:    65536,
			bits:     128,
			expected: "2001:db8::1:0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseIP := net.ParseIP(tt.baseIP)
			require.NotNil(t, baseIP, "invalid base IP: %s", tt.baseIP)

			result := indexToIP(baseIP, tt.index, tt.bits)
			assert.Equal(t, tt.expected, result)

			// Verify the result is a valid IP
			resultIP := net.ParseIP(result)
			require.NotNil(t, resultIP, "result is not a valid IP: %s", result)
		})
	}
}

func TestAllocateIPValidation(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		isIPv6      bool
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "valid IPv4",
			cidr:        "192.168.1.0/24",
			isIPv6:      false,
			shouldError: false,
		},
		{
			name:        "valid IPv6",
			cidr:        "fd00::/120",
			isIPv6:      true,
			shouldError: false,
		},
		{
			name:        "invalid CIDR",
			cidr:        "not-a-cidr",
			isIPv6:      false,
			shouldError: true,
			errorMsg:    "failed to parse CIDR",
		},
		{
			name:        "IPv4 when expecting IPv6",
			cidr:        "192.168.1.0/24",
			isIPv6:      true,
			shouldError: true,
			errorMsg:    "expected IPv6 CIDR, got IPv4",
		},
		{
			name:        "IPv6 when expecting IPv4",
			cidr:        "fd00::/64",
			isIPv6:      false,
			shouldError: true,
			errorMsg:    "expected IPv4 CIDR, got IPv6",
		},
		{
			name:        "IPv4 /32 (no usable IPs)",
			cidr:        "192.168.1.1/32",
			isIPv6:      false,
			shouldError: true,
			errorMsg:    "no usable IPs",
		},
		{
			name:        "IPv4 /31 (1 usable after excluding network and broadcast)",
			cidr:        "192.168.1.0/31",
			isIPv6:      false,
			shouldError: true,
			errorMsg:    "no usable IPs",
		},
		{
			name:        "IPv4 /16 (large subnet, capped at 1024 IPs)",
			cidr:        "10.0.0.0/16",
			isIPv6:      false,
			shouldError: false,
		},
		{
			name:        "IPv6 /64 (large subnet, capped at 1024 IPs)",
			cidr:        "fd00::/64",
			isIPv6:      true,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the real allocateIPFromCIDR with test stubs
			fakeClient := fake.NewSimpleClientset()
			cleanup := &fakeCleanup{}

			ip, err := allocateIPFromCIDR(fakeClient, cleanup, tt.cidr, tt.isIPv6, nil)

			if tt.shouldError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				// Verify allocated IP is valid
				parsedIP := net.ParseIP(ip)
				require.NotNil(t, parsedIP, "allocated IP should be valid")

				// Verify cleanup function was registered
				assert.NotEmpty(t, cleanup.cleanupFns, "cleanup function should be registered")
			}
		})
	}
}

func TestIPAllocation(t *testing.T) {
	t.Run("IPv4 allocation math", func(t *testing.T) {
		// For 192.168.1.0/24:
		// - Total IPs: 256
		// - Usable IPs: 254 (excluding .0 and .255)
		// - Index 1 -> 192.168.1.1
		// - Index 254 -> 192.168.1.254

		_, ipNet, err := net.ParseCIDR("192.168.1.0/24")
		require.NoError(t, err)

		ones, bits := ipNet.Mask.Size()
		totalIPs := 1 << (bits - ones)
		usableIPs := totalIPs - 2 // IPv4 excludes network and broadcast

		assert.Equal(t, 256, totalIPs)
		assert.Equal(t, 254, usableIPs)

		// Verify first and last usable IPs
		firstIP := indexToIP(ipNet.IP, 1, 32)
		assert.Equal(t, "192.168.1.1", firstIP)

		lastIP := indexToIP(ipNet.IP, 254, 32)
		assert.Equal(t, "192.168.1.254", lastIP)
	})

	t.Run("IPv6 allocation math", func(t *testing.T) {
		// For fd00::/120:
		// - Total IPs: 256
		// - Usable IPs: 255 (excluding network address only)
		// - Index 1 -> fd00::1
		// - Index 255 -> fd00::ff

		_, ipNet, err := net.ParseCIDR("fd00::/120")
		require.NoError(t, err)

		ones, bits := ipNet.Mask.Size()
		totalIPs := 1 << (bits - ones)
		usableIPs := totalIPs - 1 // IPv6 excludes only network address

		assert.Equal(t, 256, totalIPs)
		assert.Equal(t, 255, usableIPs)

		// Verify first and last usable IPs
		firstIP := indexToIP(ipNet.IP, 1, 128)
		assert.Equal(t, "fd00::1", firstIP)

		lastIP := indexToIP(ipNet.IP, 255, 128)
		assert.Equal(t, "fd00::ff", lastIP)
	})
}

func TestIPToIndex(t *testing.T) {
	tests := []struct {
		name          string
		baseIP        string
		targetIP      string
		expectedIndex int
		shouldError   bool
	}{
		{
			name:          "IPv4 first usable IP",
			baseIP:        "192.168.1.0",
			targetIP:      "192.168.1.1",
			expectedIndex: 1,
		},
		{
			name:          "IPv4 10th IP",
			baseIP:        "192.168.1.0",
			targetIP:      "192.168.1.10",
			expectedIndex: 10,
		},
		{
			name:          "IPv4 network address",
			baseIP:        "192.168.1.0",
			targetIP:      "192.168.1.0",
			expectedIndex: 0,
		},
		{
			name:          "IPv4 broadcast",
			baseIP:        "192.168.1.0",
			targetIP:      "192.168.1.255",
			expectedIndex: 255,
		},
		{
			name:          "IPv6 first usable IP",
			baseIP:        "fd00::",
			targetIP:      "fd00::1",
			expectedIndex: 1,
		},
		{
			name:          "IPv6 256th IP",
			baseIP:        "fd00::",
			targetIP:      "fd00::100",
			expectedIndex: 256,
		},
		{
			name:          "IPv6 network address",
			baseIP:        "2001:db8::",
			targetIP:      "2001:db8::",
			expectedIndex: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseIP := net.ParseIP(tt.baseIP)
			require.NotNil(t, baseIP, "invalid base IP: %s", tt.baseIP)

			targetIP := net.ParseIP(tt.targetIP)
			require.NotNil(t, targetIP, "invalid target IP: %s", tt.targetIP)

			index, err := ipToIndex(baseIP, targetIP)

			if tt.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedIndex, index)

				// Verify round-trip: index -> IP should give us back the target
				// Use 32 bits for IPv4, 128 for IPv6
				bits := 32
				if baseIP.To4() == nil {
					bits = 128
				}
				resultIP := indexToIP(baseIP, index, bits)
				assert.Equal(t, tt.targetIP, resultIP)
			}
		})
	}
}

func TestReservedIPValidation(t *testing.T) {
	const testCIDR = "192.168.1.0/24"

	tests := []struct {
		name        string
		reservedIPs []string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "valid reserved IPs",
			reservedIPs: []string{"192.168.1.1", "192.168.1.10", "192.168.1.254"},
			shouldError: false,
		},
		{
			name:        "invalid IP format",
			reservedIPs: []string{"not-an-ip"},
			shouldError: true,
			errorMsg:    "invalid reserved IP",
		},
		{
			name:        "IP outside subnet",
			reservedIPs: []string{"192.168.2.1"},
			shouldError: true,
			errorMsg:    "not within subnet",
		},
		{
			name:        "empty reserved list",
			reservedIPs: []string{},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the real allocateIPFromCIDR with reserved IPs
			fakeClient := fake.NewSimpleClientset()
			cleanup := &fakeCleanup{}

			ip, err := allocateIPFromCIDR(fakeClient, cleanup, testCIDR, false, tt.reservedIPs)

			if tt.shouldError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				// Verify allocated IP is valid and not in reserved list
				parsedIP := net.ParseIP(ip)
				require.NotNil(t, parsedIP, "allocated IP should be valid")
				assert.NotContains(t, tt.reservedIPs, ip, "allocated IP should not be in reserved list")
			}
		})
	}
}
