// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocators

import (
	"fmt"

	"k8s.io/kubernetes/test/e2e/framework"

	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

const (
	hostPortKey              = "host-port"
	externalContainerPortKey = "external-container-port"
)

// allocatePort reserves a port in [start, end] under key via ConfigMap-backed
// AllocateInt, so that parallel test processes cannot hand out the same port.
// Deallocation is registered as a cleanup function.
func allocatePort(f *framework.Framework, cleanup infraapi.ContextCleanUp, key string, start, end uint16) (uint16, error) {
	if end < start {
		return 0, fmt.Errorf("invalid port range [%d, %d]", start, end)
	}
	n, err := AllocateInt(f, key, int(end)-int(start)+1)
	if err != nil {
		return 0, err
	}
	cleanup.AddCleanUpFn(func() error {
		return DeallocateInt(f, key, n)
	})
	return start + uint16(n-1), nil
}

// AllocateHostPort returns a port in [start, end] for a pod or process to bind
// on a cluster node.
func AllocateHostPort(f *framework.Framework, cleanup infraapi.ContextCleanUp, start, end uint16) (uint16, error) {
	return allocatePort(f, cleanup, hostPortKey, start, end)
}

// AllocateExternalContainerPort returns a port in [start, end] for an external
// container to listen on. Host-networked external containers share the node's
// network namespace, so a per-process allocator hands the same port to several
// processes and the second container to start fails to bind it.
func AllocateExternalContainerPort(f *framework.Framework, cleanup infraapi.ContextCleanUp, start, end uint16) (uint16, error) {
	return allocatePort(f, cleanup, externalContainerPortKey, start, end)
}
