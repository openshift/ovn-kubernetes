// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/allocators"
	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	// ipAllocatorPrefix is used as the ConfigMap key prefix for IP allocations
	ipAllocatorPrefix = "ip-allocator"
)

// AllocateIP allocates a unique IP address from the given subnet CIDR for parallel
// test isolation. The allocation is backed by a ConfigMap using the AllocateInt API.
// The first usable IP (network address + 1) and broadcast address are excluded from
// allocation. Deallocation is registered as a cleanup function.
//
// Subnet size limits: The subnet must provide no more than 1024 IPs (e.g., /24 to /32 for IPv4,
// /120 to /128 for IPv6). This prevents excessive ConfigMap sizes in E2E tests.
//
// Example:
//
//	ip, err := AllocateIP(f, cleanup, "192.168.1.0/24")
//	// Returns an IP like "192.168.1.5" (skipping .0 and .255)
func AllocateIP(f *framework.Framework, cleanup infraapi.ContextCleanUp, cidr string) (string, error) {
	return allocateIPFromCIDR(f, cleanup, cidr, false)
}

// AllocateIPv6 allocates a unique IPv6 address from the given subnet CIDR.
// Subnet size limits: The subnet must provide no more than 1024 IPs (e.g., /120 to /128).
func AllocateIPv6(f *framework.Framework, cleanup infraapi.ContextCleanUp, cidr string) (string, error) {
	return allocateIPFromCIDR(f, cleanup, cidr, true)
}

// allocateIPFromCIDR allocates an IP address from the given CIDR using AllocateInt.
func allocateIPFromCIDR(f *framework.Framework, cleanup infraapi.ContextCleanUp, cidr string, isIPv6 bool) (string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("failed to parse CIDR %q: %w", cidr, err)
	}

	// Validate IP family
	if isIPv6 {
		if ip.To4() != nil {
			return "", fmt.Errorf("expected IPv6 CIDR, got IPv4: %s", cidr)
		}
	} else {
		if ip.To4() == nil {
			return "", fmt.Errorf("expected IPv4 CIDR, got IPv6: %s", cidr)
		}
	}

	// Calculate number of usable IPs in the subnet
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones

	// For E2E tests, we limit the subnet size to avoid allocating huge ConfigMaps.
	// maxHostBits of 10 allows up to 1024 IPs, which is more than enough for parallel tests.
	const maxHostBits = 10
	if hostBits > maxHostBits {
		minPrefix := bits - maxHostBits
		return "", fmt.Errorf("subnet %s is too large (/%d), use a smaller subnet with prefix >= /%d",
			cidr, ones, minPrefix)
	}

	totalIPs := 1 << hostBits

	// For IPv4, exclude network address (first IP) and broadcast (last IP)
	// For IPv6, exclude network address (first IP) only
	usableIPs := totalIPs - 1
	if !isIPv6 {
		usableIPs = totalIPs - 2 // Exclude both network and broadcast
	}

	if usableIPs <= 0 {
		return "", fmt.Errorf("no usable IPs in subnet %s", cidr)
	}

	// Use a canonical, Kubernetes-safe key so equivalent CIDRs share the same allocator state.
	normalizedCIDR := ipNet.String()
	sum := sha256.Sum256([]byte(normalizedCIDR))
	key := fmt.Sprintf("%s-%s", ipAllocatorPrefix, hex.EncodeToString(sum[:]))

	// Allocate a unique index within the usable range
	index, err := allocators.AllocateInt(f, key, usableIPs)
	if err != nil {
		return "", fmt.Errorf("failed to allocate IP index from subnet %s: %w", cidr, err)
	}

	// Register cleanup to deallocate
	cleanup.AddCleanUpFn(func() error {
		return allocators.DeallocateInt(f, key, index)
	})

	// Convert index to IP address
	// For IPv4: start from network address + 1 (skip .0)
	// For IPv6: start from network address + 1
	allocatedIP := indexToIP(ipNet.IP, index, bits)

	framework.Logf("AllocateIP: allocated %s from subnet %s (index %d)", allocatedIP, cidr, index)

	return allocatedIP, nil
}

// indexToIP converts an allocation index to an IP address within the subnet.
// index is 1-based (AllocateInt returns values starting from 1).
// The first usable IP corresponds to index 1.
func indexToIP(baseIP net.IP, index int, bits int) string {
	// Convert base IP to big.Int
	baseInt := new(big.Int).SetBytes(baseIP.To16())

	// Calculate offset: index is 1-based, so actual offset is index
	// (first usable IP is network + 1, which corresponds to index 1)
	offset := big.NewInt(int64(index))

	// Add offset to base IP
	resultInt := new(big.Int).Add(baseInt, offset)

	// Convert back to IP
	ipBytes := resultInt.Bytes()

	// Pad to 16 bytes for IPv6 or 4 bytes for IPv4
	var ip net.IP
	if bits == 32 {
		// IPv4
		ip = make(net.IP, 4)
		if len(ipBytes) > 4 {
			copy(ip, ipBytes[len(ipBytes)-4:])
		} else {
			copy(ip[4-len(ipBytes):], ipBytes)
		}
	} else {
		// IPv6
		ip = make(net.IP, 16)
		if len(ipBytes) > 16 {
			copy(ip, ipBytes[len(ipBytes)-16:])
		} else {
			copy(ip[16-len(ipBytes):], ipBytes)
		}
	}

	return ip.String()
}
