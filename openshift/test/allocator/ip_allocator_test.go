// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocator

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			name:        "IPv4 /16 (too large, > 1024 IPs)",
			cidr:        "10.0.0.0/16",
			isIPv6:      false,
			shouldError: true,
			errorMsg:    "too large",
		},
		{
			name:        "IPv6 /64 (too large, > 1024 IPs)",
			cidr:        "fd00::/64",
			isIPv6:      true,
			shouldError: true,
			errorMsg:    "too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't actually call allocateIPFromCIDR without a framework and cleanup,
			// but we can test the CIDR parsing and validation logic
			ip, ipNet, err := net.ParseCIDR(tt.cidr)
			if tt.shouldError && tt.errorMsg == "failed to parse CIDR" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err, "failed to parse CIDR")

			// Validate IP family
			if tt.isIPv6 {
				if ip.To4() != nil {
					assert.Contains(t, "expected IPv6 CIDR, got IPv4", tt.errorMsg)
					return
				}
			} else {
				if ip.To4() == nil {
					assert.Contains(t, "expected IPv4 CIDR, got IPv6", tt.errorMsg)
					return
				}
			}

			// Calculate usable IPs
			ones, bits := ipNet.Mask.Size()
			hostBits := bits - ones

			// Check for "too large" error
			const maxHostBits = 10
			if tt.shouldError && tt.errorMsg == "too large" {
				assert.Greater(t, hostBits, maxHostBits)
				return
			}

			// Check that hostBits is within acceptable range
			if tt.shouldError && tt.errorMsg == "too large" {
				assert.Greater(t, hostBits, maxHostBits)
			} else if !tt.shouldError {
				assert.LessOrEqual(t, hostBits, maxHostBits)
			}

			// Skip overflow calculations for large subnets
			if hostBits > maxHostBits {
				return
			}

			totalIPs := 1 << hostBits
			usableIPs := totalIPs - 1
			if !tt.isIPv6 {
				usableIPs = totalIPs - 2
			}

			if tt.shouldError && tt.errorMsg == "no usable IPs" {
				assert.LessOrEqual(t, usableIPs, 0)
			} else if !tt.shouldError {
				assert.Greater(t, usableIPs, 0)
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
	_, ipNet, err := net.ParseCIDR("192.168.1.0/24")
	require.NoError(t, err)

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
			// Simulate the validation logic from allocateIPFromCIDR
			reservedIndices := make(map[int]bool)

			var validationErr error
			for _, reservedIP := range tt.reservedIPs {
				ip := net.ParseIP(reservedIP)
				if ip == nil {
					validationErr = fmt.Errorf("invalid reserved IP: %s", reservedIP)
					break
				}

				if !ipNet.Contains(ip) {
					validationErr = fmt.Errorf("reserved IP %s is not within subnet %s", reservedIP, ipNet)
					break
				}

				index, err := ipToIndex(ipNet.IP, ip)
				if err != nil {
					validationErr = fmt.Errorf("failed to convert reserved IP %s to index: %w", reservedIP, err)
					break
				}

				reservedIndices[index] = true
			}

			if tt.shouldError {
				require.Error(t, validationErr)
				if tt.errorMsg != "" {
					assert.Contains(t, validationErr.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, validationErr)
			}
		})
	}
}
