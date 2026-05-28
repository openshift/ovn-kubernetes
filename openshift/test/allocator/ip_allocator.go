// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/allocators"
	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
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
func AllocateIP(kubeClient kubernetes.Interface, cleanup infraapi.ContextCleanUp, cidr string) (string, error) {
	return allocateIPFromCIDR(kubeClient, cleanup, cidr, false, nil)
}

// AllocateIPv6 allocates a unique IPv6 address from the given subnet CIDR.
// Subnet size limits: The subnet must provide no more than 1024 IPs (e.g., /120 to /128).
func AllocateIPv6(kubeClient kubernetes.Interface, cleanup infraapi.ContextCleanUp, cidr string) (string, error) {
	return allocateIPFromCIDR(kubeClient, cleanup, cidr, true, nil)
}

// AllocateIPWithReserved allocates a unique IP address from the given subnet CIDR,
// excluding the specified reserved IPs from allocation. Reserved IPs are skipped
// during the allocation process and never allocated.
//
// Example:
//
//	reserved := []string{"192.168.1.1", "192.168.1.254"}
//	ip, err := AllocateIPWithReserved(f, cleanup, "192.168.1.0/24", reserved)
//	// Returns an IP like "192.168.1.5" (skipping .0, .1, .254, and .255)
func AllocateIPWithReserved(kubeClient kubernetes.Interface, cleanup infraapi.ContextCleanUp, cidr string, reservedIPs []string) (string, error) {
	return allocateIPFromCIDR(kubeClient, cleanup, cidr, false, reservedIPs)
}

// AllocateIPv6WithReserved allocates a unique IPv6 address from the given subnet CIDR,
// excluding the specified reserved IPs from allocation.
func AllocateIPv6WithReserved(kubeClient kubernetes.Interface, cleanup infraapi.ContextCleanUp, cidr string, reservedIPs []string) (string, error) {
	return allocateIPFromCIDR(kubeClient, cleanup, cidr, true, reservedIPs)
}

// AllocateSpecificIP allocates a specific IP address from the given subnet CIDR.
// The IP is validated to be within the subnet and then reserved through the allocator.
// Deallocation is registered as a cleanup function.
//
// Example:
//
//	ip, err := AllocateSpecificIP(f, cleanup, "192.168.1.0/24", "192.168.1.10")
//	// Reserves 192.168.1.10 if it's valid and not already allocated
func AllocateSpecificIP(kubeClient kubernetes.Interface, cleanup infraapi.ContextCleanUp, cidr string, requestedIP string) (string, error) {
	return allocateSpecificIPFromCIDR(kubeClient, cleanup, cidr, false, requestedIP)
}

// AllocateSpecificIPv6 allocates a specific IPv6 address from the given subnet CIDR.
// The IP is validated to be within the subnet and then reserved through the allocator.
func AllocateSpecificIPv6(kubeClient kubernetes.Interface, cleanup infraapi.ContextCleanUp, cidr string, requestedIP string) (string, error) {
	return allocateSpecificIPFromCIDR(kubeClient, cleanup, cidr, true, requestedIP)
}

// allocateSpecificInt attempts to allocate a specific integer index in the allocator ConfigMap.
// Returns nil on success, or an error if the index is already allocated or on other failures.
func allocateSpecificInt(kubeClient kubernetes.Interface, key string, index int) error {
	ctx := context.Background()

	const configMapNamespace = "ovn-kubernetes-e2e-allocators"

	// Ensure namespace exists
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: configMapNamespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to ensure allocator namespace: %w", err)
	}

	// Ensure ConfigMap exists
	cm := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: key}}
	client := kubeClient.CoreV1().ConfigMaps(configMapNamespace)
	_, err = client.Create(ctx, cm, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to ensure allocator config map: %w", err)
	}

	allocatorBackoff := wait.Backoff{
		Steps:    50,
		Duration: 100 * time.Millisecond,
	}

	return retry.RetryOnConflict(allocatorBackoff, func() error {
		cm, err := client.Get(ctx, key, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if cm.Data == nil {
			cm.Data = map[string]string{}
		}

		// Check if the specific index is already allocated
		idxStr := strconv.Itoa(index)
		if _, exists := cm.Data[idxStr]; exists {
			return fmt.Errorf("index %d already allocated", index)
		}

		// Allocate the specific index
		cm.Data[idxStr] = ""
		_, err = client.Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
}

// allocateIPFromCIDR allocates an IP address from the given CIDR.
// If reservedIPs is provided, those IPs are excluded from the allocation pool.
func allocateIPFromCIDR(kubeClient kubernetes.Interface, cleanup infraapi.ContextCleanUp, cidr string, isIPv6 bool, reservedIPs []string) (string, error) {
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

	// Cap allocation pool to avoid huge ConfigMaps and integer overflow.
	// For large subnets (e.g., /52), we allocate sparse IPs from the first 1024 addresses.
	// ConfigMap only tracks allocated IPs, not the entire address space.
	const maxAllocationPoolSize = 1024

	var usableIPs int
	if hostBits > 10 {
		// Large subnet: cap to 1024 IPs (sparse allocation from beginning of subnet)
		usableIPs = maxAllocationPoolSize
	} else {
		// Small subnet: use actual address space size
		totalIPs := 1 << hostBits
		// For IPv4, exclude network address (first IP) and broadcast (last IP)
		// For IPv6, exclude network address (first IP) only
		usableIPs = totalIPs - 1
		if !isIPv6 {
			usableIPs = totalIPs - 2 // Exclude both network and broadcast
		}
	}

	if usableIPs <= 0 {
		return "", fmt.Errorf("no usable IPs in subnet %s", cidr)
	}

	// Use a canonical, Kubernetes-safe key so equivalent CIDRs share the same allocator state.
	normalizedCIDR := ipNet.String()
	sum := sha256.Sum256([]byte(normalizedCIDR))
	key := fmt.Sprintf("%s-%s", ipAllocatorPrefix, hex.EncodeToString(sum[:]))

	// Build a map of reserved IP indices for quick lookup
	reservedIndices := make(map[int]bool)
	if len(reservedIPs) > 0 {
		for _, reservedIP := range reservedIPs {
			ip := net.ParseIP(reservedIP)
			if ip == nil {
				return "", fmt.Errorf("invalid reserved IP: %s", reservedIP)
			}

			// Verify the IP is within the subnet
			if !ipNet.Contains(ip) {
				return "", fmt.Errorf("reserved IP %s is not within subnet %s", reservedIP, ipNet)
			}

			// Convert IP to index
			index, err := ipToIndex(ipNet.IP, ip)
			if err != nil {
				return "", fmt.Errorf("failed to convert reserved IP %s to index: %w", reservedIP, err)
			}

			// Verify index is within usable range
			if index < 1 || index > usableIPs {
				return "", fmt.Errorf("reserved IP %s index %d is outside usable range [1, %d]", reservedIP, index, usableIPs)
			}

			reservedIndices[index] = true
			framework.Logf("Marked IP %s (index %d) as reserved in subnet %s", reservedIP, index, ipNet)
		}
	}

	// Allocate a unique index within the usable range, skipping reserved indices.
	// Try to allocate each non-reserved candidate index in order until one succeeds.
	var index int
	for candidate := 1; candidate <= usableIPs; candidate++ {
		// Skip reserved indices during selection
		if reservedIndices[candidate] {
			framework.Logf("Skipping reserved index %d in subnet %s", candidate, ipNet)
			continue
		}

		// Try to allocate this specific non-reserved index
		if err := allocateSpecificInt(kubeClient, key, candidate); err == nil {
			// Successfully allocated this index
			index = candidate
			break
		}
		// If already allocated by another test, try the next candidate
	}

	if index == 0 {
		return "", fmt.Errorf("failed to allocate any non-reserved IP from subnet %s (all %d usable IPs exhausted or reserved)", cidr, usableIPs)
	}

	// Register cleanup to deallocate the allocated index
	cleanup.AddCleanUpFn(func() error {
		if err := allocators.DeallocateInt(kubeClient, key, index); err != nil {
			return fmt.Errorf("failed to deallocate IP index %d: %w", index, err)
		}
		return nil
	})

	// Convert index to IP address
	// For IPv4: start from network address + 1 (skip .0)
	// For IPv6: start from network address + 1
	allocatedIP := indexToIP(ipNet.IP, index, bits)

	framework.Logf("AllocateIP: allocated %s from subnet %s (index %d)", allocatedIP, cidr, index)

	return allocatedIP, nil
}

// allocateSpecificIPFromCIDR allocates a specific IP address from the given CIDR.
// It validates the IP is within the subnet and reserves it through the allocator.
func allocateSpecificIPFromCIDR(kubeClient kubernetes.Interface, cleanup infraapi.ContextCleanUp, cidr string, isIPv6 bool, requestedIP string) (string, error) {
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

	// Parse and validate requested IP
	parsedIP := net.ParseIP(requestedIP)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid requested IP: %s", requestedIP)
	}

	// Validate IP family matches
	if isIPv6 {
		if parsedIP.To4() != nil {
			return "", fmt.Errorf("expected IPv6 address, got IPv4: %s", requestedIP)
		}
	} else {
		if parsedIP.To4() == nil {
			return "", fmt.Errorf("expected IPv4 address, got IPv6: %s", requestedIP)
		}
	}

	// Verify the IP is within the subnet
	if !ipNet.Contains(parsedIP) {
		return "", fmt.Errorf("requested IP %s is not within subnet %s", requestedIP, ipNet)
	}

	// Check subnet size and determine tracking limits
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones

	// For very large subnets (hostBits > 62), index calculation would overflow.
	// We only track allocations for the first 1024 IPs to avoid ConfigMap bloat.
	const maxTrackedIndex = 1024

	// Calculate index using big.Int to avoid overflow
	baseInt := new(big.Int).SetBytes(ipNet.IP.To16())
	targetInt := new(big.Int).SetBytes(parsedIP.To16())
	diff := new(big.Int).Sub(targetInt, baseInt)

	// Check if difference is negative (should not happen if ipNet.Contains passed)
	if diff.Sign() < 0 {
		return "", fmt.Errorf("requested IP %s is before subnet base %s", requestedIP, ipNet.IP)
	}

	// Check if difference is zero (network address itself)
	if diff.Sign() == 0 {
		return "", fmt.Errorf("requested IP %s is the network address (index 0)", requestedIP)
	}

	// For large subnets (> 1024 IPs tracked), check if requested IP is within tracked range
	if hostBits > 10 {
		// Large subnet: only track first 1024 IPs
		maxTracked := big.NewInt(int64(maxTrackedIndex))
		if diff.Cmp(maxTracked) > 0 {
			// Beyond tracking limit - skip ConfigMap, return IP without conflict detection
			framework.Logf("AllocateSpecificIP: allocated %s from subnet %s (beyond tracking limit %d, no ConfigMap tracking)",
				requestedIP, cidr, maxTrackedIndex)
			return requestedIP, nil
		}
	}

	// Convert to int now that we know it's within trackable range
	if !diff.IsInt64() {
		return "", fmt.Errorf("requested IP %s offset too large to track (index overflow)", requestedIP)
	}

	index := int(diff.Int64())

	// Validate index is within usable range (not broadcast for IPv4)
	if hostBits <= 10 {
		// Small subnet: validate against actual bounds
		totalIPs := 1 << hostBits
		maxUsableIndex := totalIPs - 1
		if !isIPv6 {
			maxUsableIndex = totalIPs - 2 // Exclude broadcast
		}
		if index > maxUsableIndex {
			return "", fmt.Errorf("requested IP %s (index %d) is outside usable range [1, %d]", requestedIP, index, maxUsableIndex)
		}
	}

	// Use a canonical, Kubernetes-safe key
	normalizedCIDR := ipNet.String()
	sum := sha256.Sum256([]byte(normalizedCIDR))
	key := fmt.Sprintf("%s-%s", ipAllocatorPrefix, hex.EncodeToString(sum[:]))

	// Allocate the specific index in ConfigMap
	if err := allocateSpecificInt(kubeClient, key, index); err != nil {
		return "", fmt.Errorf("failed to allocate specific IP %s from subnet %s: %w", requestedIP, cidr, err)
	}

	// Register cleanup to deallocate the allocated index
	cleanup.AddCleanUpFn(func() error {
		if err := allocators.DeallocateInt(kubeClient, key, index); err != nil {
			return fmt.Errorf("failed to deallocate IP index %d: %w", index, err)
		}
		return nil
	})

	framework.Logf("AllocateSpecificIP: allocated %s from subnet %s (index %d)", requestedIP, cidr, index)

	return requestedIP, nil
}

// ipToIndex converts an IP address to its index within the subnet.
// The network address corresponds to index 0, the first usable IP to index 1, etc.
func ipToIndex(baseIP, targetIP net.IP) (int, error) {
	baseInt := new(big.Int).SetBytes(baseIP.To16())
	targetInt := new(big.Int).SetBytes(targetIP.To16())

	// Calculate the difference
	diff := new(big.Int).Sub(targetInt, baseInt)

	// Convert to int64 and return as index
	index := diff.Int64()
	if index < 0 {
		return 0, fmt.Errorf("target IP is before base IP")
	}

	return int(index), nil
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
