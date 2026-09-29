package infraprovider

import (
	"math/rand"
	"sync"
	"testing"
)

func TestRandPortAllocatorBoundsAndNoReplacement(t *testing.T) {
	const start, end = 9000, 9999
	a := newRandPortAllocator(start, end)
	seen := make(map[uint16]struct{}, end-start+1)
	for i := 0; i < end-start+1; i++ {
		p := a.Allocate()
		if p < start || p > end {
			t.Fatalf("allocated port %d outside range [%d, %d]", p, start, end)
		}
		if _, dup := seen[p]; dup {
			t.Fatalf("port %d allocated twice", p)
		}
		seen[p] = struct{}{}
	}
	if len(seen) != end-start+1 {
		t.Fatalf("expected %d unique ports, got %d", end-start+1, len(seen))
	}
}

func TestRandPortAllocatorExhaustionPanics(t *testing.T) {
	a := newRandPortAllocator(9000, 9002)
	for i := 0; i < 3; i++ {
		a.Allocate()
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on exhausted range")
		}
	}()
	a.Allocate()
}

func TestRandPortAllocatorDeterministicWithSeed(t *testing.T) {
	const start, end = 9000, 9099
	seq := func(seed int64) []uint16 {
		a := newRandPortAllocatorWithRand(start, end, rand.New(rand.NewSource(seed)))
		out := make([]uint16, 0, end-start+1)
		for i := 0; i < end-start+1; i++ {
			out = append(out, a.Allocate())
		}
		return out
	}
	s1a, s1b, s2 := seq(1), seq(1), seq(2)
	for i := range s1a {
		if s1a[i] != s1b[i] {
			t.Fatalf("same seed produced different sequences at index %d: %d != %d", i, s1a[i], s1b[i])
		}
	}
	same := true
	for i := range s1a {
		if s1a[i] != s2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("distinct seeds produced identical sequences")
	}
}

func TestRandPortAllocatorConcurrentUniqueness(t *testing.T) {
	const start, end = 9000, 9999
	const workers = 10
	const perWorker = (end - start + 1) / workers
	a := newRandPortAllocator(start, end)
	var mu sync.Mutex
	seen := make(map[uint16]struct{}, end-start+1)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				p := a.Allocate()
				mu.Lock()
				if _, dup := seen[p]; dup {
					t.Errorf("port %d allocated twice", p)
				}
				seen[p] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != workers*perWorker {
		t.Fatalf("expected %d unique ports, got %d", workers*perWorker, len(seen))
	}
}
