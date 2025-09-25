package id

import (
	"slices"
	"testing"
)

func TestIDsAllocator(t *testing.T) {
	// create allocator with range [3, 8]
	allocator := newIDsAllocator("test", 6, 3)
	ids, err := allocator.AllocateIDs("test1", 0)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expect 0 ids allocated, but got %v", ids)
	}
	// test reserve IDs
	err = allocator.ReserveIDs("test1", []int{4})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// ids: test1 = [4]
	// test offset and multiple IDs allocation skipping allocated ID
	ids, err = allocator.AllocateIDs("test2", 3)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{3, 5, 6}) {
		t.Errorf("expect ids [3,5,6] allocated, but got %v", ids)
	}
	// ids: test1 = [4]
	// ids: test2 = [3,5,6]
	// try to allocate more ids for test1
	ids, err = allocator.AllocateIDs("test1", 2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{4, 7}) {
		t.Errorf("expect ids [4,7] allocated, but got %v", ids)
	}
	// ids: test1 = [4,7]
	// ids: test2 = [3,5,6]
	// request already existing IDs
	ids, err = allocator.AllocateIDs("test1", 2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{4, 7}) {
		t.Errorf("expect ids [4,7] allocated, but got %v", ids)
	}
	// ids: test1 = [4,7]
	// ids: test2 = [3,5,6]
	// try to allocate more ids than available
	ids, err = allocator.AllocateIDs("test3", 2)
	if err == nil {
		t.Errorf("expect error allocating id for test3, but got ids %v", ids)
	}
	// try to reserve last available ID
	err = allocator.ReserveIDs("test3", []int{8})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// ids: test1 = [4,7]
	// ids: test2 = [3,5,6]
	// ids: test3 = [8]
	// try to reserve different IDs
	err = allocator.ReserveIDs("test3", []int{7, 8})
	if err == nil {
		t.Errorf("expect error reserving ids for test3")
	}
	// now release IDs for test1
	allocator.ReleaseIDs("test1")
	// ids: test2 = [3,5,6]
	// ids: test3 = [8]
	// try to allocate more ids than available
	ids, err = allocator.AllocateIDs("test3", 4)
	if err == nil {
		t.Errorf("expect error allocating id for test3, but got ids %v", ids)
	}
	ids, err = allocator.AllocateIDs("test3", 3)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{8, 4, 7}) {
		t.Errorf("expect ids [8,4,7] allocated, but got %v", ids)
	}
	// ids: test2 = [3,5,6]
	// ids: test3 = [8,4,7]
}

func TestTunnelKeysAllocator(t *testing.T) {
	allocator := NewTunnelKeyAllocator("test")
	transitSwitchBase := 16711683
	tunnelKeyBase := 16715779
	// allocate 1 key for networkID 1 (transit switch key is preserved)
	ids, err := allocator.AllocateKeys("net1", 1, 1)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{transitSwitchBase + 1}) {
		t.Errorf("expect ids %v allocated, but got %v", []int{transitSwitchBase + 1}, ids)
	}
	// now add one more key for networkID 1 (should return the same key)
	ids, err = allocator.AllocateKeys("net1", 1, 2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{transitSwitchBase + 1, tunnelKeyBase}) {
		t.Errorf("expect ids %v allocated, but got %v", []int{transitSwitchBase + 1, tunnelKeyBase}, ids)
	}
	// now ask for 1 key again for networkID 1 (reducing the number of requested keys is not expected and should return error)
	ids, err = allocator.AllocateKeys("net1", 1, 1)
	if err == nil {
		t.Errorf("expect error allocating id for net1, but got ids %v", ids)
	}
	// check the 0 also works
	ids, err = allocator.AllocateKeys("net1", 1, 0)
	if err == nil {
		t.Errorf("expect error allocating id for net1, but got ids %v", ids)
	}
	// same for reserve IDs
	err = allocator.ReserveKeys("net1", []int{transitSwitchBase + 1})
	if err == nil {
		t.Errorf("expect error reserving ids for net1")
	}
	// now reserve already allocated ids, should be ok
	err = allocator.ReserveKeys("net1", []int{transitSwitchBase + 1, tunnelKeyBase})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// allocate 3 keys for networkID 2 (transit switch key is preserved + 2 allocated keys)
	ids, err = allocator.AllocateKeys("net2", 2, 3)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{transitSwitchBase + 2, tunnelKeyBase + 1, tunnelKeyBase + 2}) {
		t.Errorf("expect ids %v allocated, but got %v", []int{transitSwitchBase + 1, tunnelKeyBase + 1, tunnelKeyBase + 2}, ids)
	}
	// reserve next 2 keys for networkID 3
	err = allocator.ReserveKeys("net3", []int{tunnelKeyBase + 3, tunnelKeyBase + 4})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// allocate 2 keys for networkID 4
	ids, err = allocator.AllocateKeys("net4", 4, 2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{transitSwitchBase + 4, tunnelKeyBase + 5}) {
		t.Errorf("expect ids %v allocated, but got %v", []int{transitSwitchBase + 4, tunnelKeyBase + 5}, ids)
	}
	// check network ID out of reserved range
	ids, err = allocator.AllocateKeys("net5", 5000, 1)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []int{tunnelKeyBase + 6}) {
		t.Errorf("expect ids %v allocated, but got %v", []int{tunnelKeyBase + 6}, ids)
	}

	totalKeys := 61437
	// we have already allocated 7 keys from the free range, request the rest of them + 1
	_, err = allocator.AllocateKeys("net6", 10000, totalKeys-7+1)
	if err == nil {
		t.Errorf("expect error allocating id for net5")
	}
	_, err = allocator.AllocateKeys("net6", 10000, totalKeys-7)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
