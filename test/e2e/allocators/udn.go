// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocators

import (
	"sync"

	"k8s.io/kubernetes/test/e2e/framework"

	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

const udnSubnetsKey = "udn-subnets"

var (
	udnOnce      sync.Once
	udnV4, udnV6 subnetSpec
)

// AllocateUDNSubnets allocates non-overlapping IPv4 and IPv6 UDN subnets for
// parallel test isolation. The subnets are derived from a single integer
// allocated with AllocateInt, mapped to the nth non-excluded subnet within the
// ranges defined by udnSubnets and udnSubnets6. Deallocation is registered as
// a cleanup function.
func AllocateUDNSubnets(f *framework.Framework, cleanup infraapi.ContextCleanUp) (ipv4, ipv6 string, err error) {
	udnOnce.Do(func() {
		udnV4 = newSubnetSpec(udnSubnets, nil)
		udnV6 = newSubnetSpec(udnSubnets6, nil)
	})
	n, err := AllocateInt(f, udnSubnetsKey, min(udnV4.usable(), udnV6.usable()))
	if err != nil {
		return "", "", err
	}

	cleanup.AddCleanUpFn(func() error {
		return DeallocateInt(f, udnSubnetsKey, n)
	})

	udnV4Idx := udnV4.nthFree(n)
	udnV6Idx := udnV6.nthFree(n)
	return udnV4.cidr(udnV4Idx), udnV6.cidr(udnV6Idx), nil
}
