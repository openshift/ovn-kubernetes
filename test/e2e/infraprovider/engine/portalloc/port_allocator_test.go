// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package portalloc

import "testing"

func TestNewRandomizesStart(t *testing.T) {
	// Not every call can differ from a fixed start. Checking that at
	// least one of many independent allocators differs catches the
	// case where randomization silently stops working.
	sawDifferentStart := false
	for i := 0; i < 20; i++ {
		pa := New(12000, 65535)
		if pa.next != 12000 {
			sawDifferentStart = true
			break
		}
	}
	if !sawDifferentStart {
		t.Fatalf("expected at least one of 20 allocators to start at a port other than 12000")
	}
}

func TestAllocateWrapsAroundWithinRange(t *testing.T) {
	pa := New(100, 102)
	seen := map[uint16]bool{}
	for i := 0; i < 3; i++ {
		port := pa.Allocate()
		if port < 100 || port > 102 {
			t.Fatalf("allocated port %d outside configured range [100, 102]", port)
		}
		if seen[port] {
			t.Fatalf("port %d allocated twice within one full lap", port)
		}
		seen[port] = true
	}
}

func TestAllocatePanicsWhenExhausted(t *testing.T) {
	pa := New(100, 100)
	pa.Allocate()
	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic when the port range is exhausted")
		}
	}()
	pa.Allocate()
}
