package timequeue

import (
	"container/heap"
	"context"
	"sync"
	"time"
)

// TimeItem is the type of item stored by TimeQueue. Each item has an associated
// time which is the earliest time they will become available for consumption
// from the queue.
type TimeItem interface {
	comparable
	Time() time.Time
}

// TimeQueue is a scheduler implemented as a thread safe priority queue where
// items with the oldest time have higher priority. It is not designed to store
// a large number of items as the backend storage is a slice.
type TimeQueue[T TimeItem] struct {
	pop       sync.Mutex
	push      sync.Mutex
	items     heapImpl[T]
	consumers map[chan struct{}]time.Time
}

// New TimeQueue initialized with the provided items
func New[T TimeItem](items ...T) *TimeQueue[T] {
	tq := TimeQueue[T]{
		pop:       sync.Mutex{},
		push:      sync.Mutex{},
		items:     items,
		consumers: make(map[chan struct{}]time.Time),
	}
	heap.Init(&tq.items)
	return &tq
}

// Pop the next item from the queue no earlier than its associated time. It
// blocks at least until that time is reached, the context expires or if there
// are no items in the queue. Timing precission is equivalent to that of
// time.Timer.
func (tq *TimeQueue[T]) Pop(ctx context.Context) T {
	// We make extensive use of channels and timers. Suposedly they are cheap,
	// but it might make sense to cache and reuse them.
	var zero T
	var itemTime time.Time
	var timer *time.Timer
	var timeout <-chan time.Time
	signal := make(chan struct{})

	pop := func() (T, bool) {
		tq.pop.Lock()
		defer tq.pop.Unlock()

		// if there are items pending to pop, pop the next one and track its
		// time
		var item T
		if tq.items.Len() > 0 {
			item = heap.Pop(&tq.items).(T)
			itemTime = item.Time()
			d := time.Until(itemTime)
			if d <= 0 {
				return item, true
			}
			if timer == nil {
				timer = time.NewTimer(d)
			} else {
				timer.Reset(d)
			}
			timeout = timer.C
		}

		// prepare to be signaled by producers when a new item arrives, either
		// when we are pending for an item to consume or when a new item has a
		// time earlier than the one we are tracking
		tq.consumers[signal] = itemTime
		return item, false
	}

	unpop := func(item T) {
		tq.pop.Lock()
		delete(tq.consumers, signal)
		tq.pop.Unlock()
		if item != zero {
			// use tq.Push rather than heap.Push so that we make sure this item
			// has a chance to be picked up by another consumer if it needs be
			tq.Push(item)
		}
		if timeout != nil && !timer.Stop() {
			// consume the pending timeout
			<-timeout
		}
	}

	for {
		item, due := pop()
		if due {
			unpop(zero)
			return item
		}
		select {
		case <-timeout:
			// timeout already consumed, flag it
			timeout = nil
			unpop(zero)
			return item
		case <-ctx.Done():
			unpop(item)
			return zero
		case <-signal:
			unpop(item)
		}
	}
}

// Push an item into the queue
func (tq *TimeQueue[T]) Push(item T) {
	// no concurrent push
	tq.push.Lock()
	defer tq.push.Unlock()

	// pop lock while we insert the item and evaluate consumers
	tq.pop.Lock()

	heap.Push(&tq.items, item)

	itemTime := item.Time()
	for {
		// find a free consumer or the one with the newest time than this item
		// and signal it so that this item can be picked up
		var signal chan<- struct{}
		var newest time.Time
		for s, t := range tq.consumers {
			if t.IsZero() {
				signal = s
				break
			}
			if t.After(itemTime) && t.After(newest) {
				signal = s
				newest = t
			}
		}

		// Unlock so that consumers can unregister themselves if they timed out
		// while we were checking on them, otherwise we might be in a loop
		// signaling an old consumer on a channel it will never receive on.
		// Any consumer might become free and pick up this item from this point
		// onwards, so the signal might end up being not needed and spurious,
		// but this should happen rarely and should have no functional
		// consequences.
		tq.pop.Unlock()

		// either there were no consumers or none of them were tracking an item
		// with an older time than the one pushed here
		if signal == nil {
			return
		}

		// signal the consumer if it is still receiving
		select {
		case signal <- struct{}{}:
			return
		default:
		}

		// rare but we might not be able to signal the consumer we intended if
		// it timed out at the same time, in which case that consumer might be
		// gone and not come back, so evaluate consumers again
		tq.pop.Lock()
	}
}

// heapImpl is a slice implementing the heap interface as a time based priority
// queue of items
type heapImpl[T TimeItem] []T

func (tq heapImpl[T]) Len() int {
	return len(tq)
}

func (tq heapImpl[T]) Less(i, j int) bool {
	// item with the oldest time has higher priority
	return tq[i].Time().Before(tq[j].Time())
}

func (tq heapImpl[T]) Swap(i, j int) {
	tq[i], tq[j] = tq[j], tq[i]
}

func (tq *heapImpl[T]) Push(x any) {
	*tq = append(*tq, x.(T))
}

func (tq *heapImpl[T]) Pop() any {
	old := *tq
	n := len(old)
	item := old[n-1]
	var zero T
	old[n-1] = zero // avoid memory leak
	*tq = old[0 : n-1]
	return item
}
