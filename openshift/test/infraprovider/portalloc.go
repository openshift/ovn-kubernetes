package infraprovider

import (
	"math/rand"
	"sync"
)

// randPortAllocator hands out host ports uniformly at random, without
// replacement, from [start, end].
//
// The OTE harness runs every spec in its own process ("run-test"), so a
// sequential allocator makes all concurrently running tests fight over the
// same first few ports on the same nodes. A pre-shuffled permutation gives
// each process an independent sequence: retries within a process never repeat
// a port, and two processes that happen to collide diverge on their next
// allocation instead of advancing in lockstep.
type randPortAllocator struct {
	mu    sync.Mutex
	ports []uint16 // pre-shuffled, remaining
}

// newRandPortAllocator returns an allocator over [start, end] shuffled with
// the (randomly seeded, per process) global math/rand source.
func newRandPortAllocator(start, end uint16) *randPortAllocator {
	return newRandPortAllocatorWithRand(start, end, rand.New(rand.NewSource(rand.Int63())))
}

// newRandPortAllocatorWithRand is split out so tests can inject a
// deterministic *rand.Rand.
func newRandPortAllocatorWithRand(start, end uint16, r *rand.Rand) *randPortAllocator {
	if end < start {
		panic("invalid port range")
	}
	n := int(end) - int(start) + 1
	ports := make([]uint16, n)
	for i := range ports {
		ports[i] = start + uint16(i)
	}
	r.Shuffle(n, func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
	return &randPortAllocator{ports: ports}
}

// Allocate returns the next unused port. It panics when the range is
// exhausted, mirroring the upstream portalloc contract.
func (a *randPortAllocator) Allocate() uint16 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.ports) == 0 {
		panic("host port range exhausted")
	}
	p := a.ports[0]
	a.ports = a.ports[1:]
	return p
}
