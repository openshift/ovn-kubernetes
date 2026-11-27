// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package portalloc

import (
	"math/rand"
	"sync"
)

type PortAllocator struct {
	start uint16
	end   uint16
	next  uint16
	count int
	max   int
	mu    sync.Mutex
}

// New creates an allocator for the given port range. Each test runs as its
// own process (see openshift-tests-extension's run-test command). A fixed
// start would hand the same first port to every concurrently-running
// process. That collides on external containers sharing a single network
// namespace, for example host-networked baremetal external containers. A
// random start makes that collision unlikely without checking the remote
// host for an already-used port.
func New(start, end uint16) *PortAllocator {
	max := int(end-start) + 1
	randomStart := start + uint16(rand.Intn(max))
	return &PortAllocator{start: start, end: end, next: randomStart, max: max}
}

// Allocate returns the next port, wrapping back to start after end. It
// panics once every port in the range has been handed out once.
func (pr *PortAllocator) Allocate() uint16 {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if pr.count >= pr.max {
		panic("port allocation limit reached")
	}
	val := pr.next
	pr.count++
	if pr.next == pr.end {
		pr.next = pr.start
	} else {
		pr.next++
	}
	return val
}
