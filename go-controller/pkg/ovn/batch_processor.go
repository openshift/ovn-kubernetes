package ovn

import (
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// BatchProcessor collects items and processes them in batches to reduce overhead.
// Items are batched either when the batch reaches batchSize or after batchTimeout elapses.
type BatchProcessor struct {
	name         string
	batchSize    int
	batchTimeout time.Duration
	processFn    func([]interface{}) error

	mu     sync.Mutex
	batch  []interface{}
	timer  *time.Timer
	stopCh chan struct{}
}

// NewBatchProcessor creates a new batch processor with the given configuration.
// name: identifier for logging
// batchSize: maximum number of items per batch
// timeout: maximum time to wait before flushing a partial batch
// processFn: function to call with batched items
func NewBatchProcessor(name string, batchSize int, timeout time.Duration, processFn func([]interface{}) error) *BatchProcessor {
	return &BatchProcessor{
		name:         name,
		batchSize:    batchSize,
		batchTimeout: timeout,
		processFn:    processFn,
		batch:        make([]interface{}, 0, batchSize),
		stopCh:       make(chan struct{}),
	}
}

// Add adds an item to the batch. If the batch reaches batchSize, it is flushed immediately.
// Otherwise, a timer is set to flush the batch after batchTimeout.
// Returns true if the batch was flushed as a result of this add.
func (bp *BatchProcessor) Add(item interface{}) bool {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.batch = append(bp.batch, item)

	// Reset timeout timer
	if bp.timer != nil {
		bp.timer.Stop()
	}
	bp.timer = time.AfterFunc(bp.batchTimeout, func() {
		bp.flush()
	})

	// Flush if batch is full
	if len(bp.batch) >= bp.batchSize {
		return bp.flushLocked()
	}

	return false
}

// flush processes the current batch (public method with locking)
func (bp *BatchProcessor) flush() {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.flushLocked()
}

// flushLocked processes the current batch (caller must hold bp.mu)
func (bp *BatchProcessor) flushLocked() bool {
	if len(bp.batch) == 0 {
		return false
	}

	// Copy batch to process
	toProcess := make([]interface{}, len(bp.batch))
	copy(toProcess, bp.batch)

	// Clear current batch
	bp.batch = bp.batch[:0]

	// Stop timer
	if bp.timer != nil {
		bp.timer.Stop()
		bp.timer = nil
	}

	// Process batch asynchronously to avoid blocking Add() callers
	go func() {
		start := time.Now()
		klog.V(4).Infof("[OVSDB BATCHING][%s] Processing batch of %d items", bp.name, len(toProcess))

		if err := bp.processFn(toProcess); err != nil {
			klog.Errorf("[OVSDB BATCHING][%s] Batch processing failed: %v", bp.name, err)
		} else {
			klog.V(4).Infof("[OVSDB BATCHING][%s] Batch of %d items processed in %v",
				bp.name, len(toProcess), time.Since(start))
		}
	}()

	return true
}

// Shutdown flushes any remaining items and stops the processor
func (bp *BatchProcessor) Shutdown() {
	close(bp.stopCh)
	bp.flush()
}
