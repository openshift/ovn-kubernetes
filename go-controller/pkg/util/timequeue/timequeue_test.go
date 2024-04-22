package timequeue

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"
)

type testItem struct {
	time time.Time
}

func (i testItem) Time() time.Time {
	return i.time
}

func newTestItem(time time.Time) *testItem {
	return &testItem{time}
}

func sortTestItems(s []*testItem) []*testItem {
	c := make([]*testItem, len(s))
	copy(c, s)
	sort.Slice(c, func(i, j int) bool { return c[i].time.Before(c[j].time) })
	return c
}

func TestPop(t *testing.T) {
	tests := []struct {
		name   string
		items  int
		jitter int
	}{
		{
			name:   "Pop 100 random +- 500ms items",
			items:  100,
			jitter: 500,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := make([]*testItem, 0, tt.items)
			now := time.Now()
			start := now
			for i := 0; i < tt.items; i++ {
				t := start.Add(time.Duration(rand.Intn(tt.jitter*2)-tt.jitter) * time.Millisecond)
				items = append(items, newTestItem(t))
			}

			tq := New(items...)

			expected := make([]*testItem, 0, tt.items)
			var item *testItem

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(tt.jitter*2)*time.Millisecond)
			defer cancel()
			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					item = tq.Pop(ctx)
					now = time.Now()
					if item != nil && now.Before(item.time) {
						// we popped an item before it was due
						return
					}
					select {
					case <-ctx.Done():
						return
					default:
						expected = append(expected, item)
					}
				}
			}()
			wg.Wait()

			if item != nil {
				t.Fatalf("Expected last item to be nil but got %s added at %s and popped at %s", item.time, start, now)
			}

			if len(items) != len(expected) {
				t.Fatalf("Expected %d items but got %d", len(items), len(expected))
			}

			for i := 1; i < len(expected); i++ {
				if expected[i].time.Before(expected[i-1].time) {
					t.Fatalf("Expected %s to be less or equal to %s", expected[i].time, expected[i-1].time)
				}
			}
		})
	}
}

func TestConcurrentPopAndPush(t *testing.T) {
	tests := []struct {
		name      string
		items     int
		jitter    int
		consumers int
	}{
		{
			name:      "Inspect 5 consumers popping out of 100 pushed items concurrently",
			items:     100,
			jitter:    500,
			consumers: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := make([]*testItem, 0, tt.items)
			now := time.Now()
			start := now
			for i := 0; i < tt.items; i++ {
				t := start.Add(time.Duration(1000+rand.Intn(tt.jitter)) * time.Hour)
				items = append(items, newTestItem(t))
			}

			tq := New[*testItem]()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for i := 0; i < tt.consumers; i++ {
				go tq.Pop(ctx)
			}

			time.Sleep(time.Duration(100) * time.Millisecond)

			for _, item := range items {
				tq.Push(item)
			}

			time.Sleep(time.Duration(100) * time.Millisecond)

			tq.pop.Lock()
			defer tq.pop.Unlock()

			if len(tq.consumers) != tt.consumers {
				t.Fatalf("Expected %d consumers but got %d", tt.consumers, len(tq.consumers))
			}

			if len(tq.items) != tt.items-tt.consumers {
				t.Fatalf("Expected %d items in the backing slice but got %d", tt.items-tt.consumers, len(tq.items))
			}

			// as many old items as consumers should be tracked by them so they
			// should not be present on the backing slice
			sorted := sortTestItems(items)
			boundary := sorted[tt.consumers-1].time

			for _, item := range tq.items {
				if item.time.Before(boundary) {
					fmt.Printf("Inserted items: %d\n", len(items))
					for _, i := range items {
						fmt.Printf("%s\n", i.time)
					}

					fmt.Printf("Sorted items: %d\n", len(sorted))
					for _, i := range sorted {
						fmt.Printf("%s\n", i.time)
					}

					backing := sortTestItems(tq.items)
					fmt.Printf("Backing items: %d\n", len(backing))
					for _, i := range backing {
						fmt.Printf("%s\n", i.time)
					}

					t.Fatalf("Found non-popped item %s older than expected boundary %s", item.time, boundary)
				}
			}
		})
	}
}
