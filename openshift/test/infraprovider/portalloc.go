package infraprovider

import (
	"math/rand"
	"sync"
)

// randPortAllocator hands out ports from [start, end] uniformly at random,
// without replacement. Every OTE spec runs in its own process, so a sequential
// allocator would make concurrent tests fight over the same first few ports.
type randPortAllocator struct {
	mu    sync.Mutex
	ports []uint16 // pre-shuffled, remaining
}

// newRandPortAllocator returns an allocator over [start, end], seeded per process.
func newRandPortAllocator(start, end uint16) *randPortAllocator {
	return newRandPortAllocatorWithRand(start, end, rand.New(rand.NewSource(rand.Int63())))
}

// newRandPortAllocatorWithRand lets tests inject a deterministic *rand.Rand.
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

// Allocate returns the next unused port, panicking when the range is exhausted
// (mirrors the upstream portalloc contract).
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
