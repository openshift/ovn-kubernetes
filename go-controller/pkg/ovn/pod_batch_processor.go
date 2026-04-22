package ovn

import (
	"sync"
	"time"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/metrics"
)

// podBatchItem represents a single pod operation to be batched
type podBatchItem struct {
	pod     *corev1.Pod
	nadKey  string
	network *nadapi.NetworkSelectionElement
	errChan chan error
}

// PodBatchProcessor collects pod operations and processes them in batches
// to reduce OVN database transaction overhead during mass pod creation events
// such as node drains.
type PodBatchProcessor struct {
	batchWindow     time.Duration
	maxBatchSize    int
	parallelBatches int
	podQueue        chan *podBatchItem
	processBatch    func([]*podBatchItem) error
	stopCh          chan struct{}
	wg              sync.WaitGroup
	batchSemaphore  chan struct{}
}

// NewPodBatchProcessor creates a new batch processor for pod operations.
// batchWindow: time to wait before processing a partial batch
// maxBatchSize: maximum number of pods to process in a single batch
// parallelBatches: number of batches that can be processed concurrently
// processBatch: function to process a batch of pods
func NewPodBatchProcessor(batchWindow time.Duration, maxBatchSize int,
	parallelBatches int, processBatch func([]*podBatchItem) error) *PodBatchProcessor {

	if parallelBatches == 0 {
		parallelBatches = 4
	}

	return &PodBatchProcessor{
		batchWindow:     batchWindow,
		maxBatchSize:    maxBatchSize,
		parallelBatches: parallelBatches,
		podQueue:        make(chan *podBatchItem, 5000),
		processBatch:    processBatch,
		stopCh:          make(chan struct{}),
		batchSemaphore:  make(chan struct{}, parallelBatches),
	}
}

// Start begins the batch processing loop
func (p *PodBatchProcessor) Start() {
	p.wg.Add(1)
	go p.run()
}

// Stop stops the batch processor and waits for in-flight batches to complete
func (p *PodBatchProcessor) Stop() {
	close(p.stopCh)
	p.wg.Wait()
}

func (p *PodBatchProcessor) run() {
	defer p.wg.Done()

	batch := make([]*podBatchItem, 0, p.maxBatchSize)
	timer := time.NewTimer(p.batchWindow)
	timer.Stop()

	for {
		select {
		case <-p.stopCh:
			// Process remaining batch before stopping
			if len(batch) > 0 {
				p.processBatchAsync(batch)
			}
			// Wait for all in-flight batches to complete
			for i := 0; i < p.parallelBatches; i++ {
				p.batchSemaphore <- struct{}{}
			}
			return

		case item := <-p.podQueue:
			batch = append(batch, item)

			// Start timer on first item in batch
			if len(batch) == 1 {
				timer.Reset(p.batchWindow)
			}

			// Flush batch if it reaches maximum size
			if len(batch) >= p.maxBatchSize {
				timer.Stop()
				p.processBatchAsync(batch)
				batch = batch[:0]
			}

		case <-timer.C:
			// Flush batch on timeout
			if len(batch) > 0 {
				p.processBatchAsync(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatchAsync processes a batch in a separate goroutine with concurrency control
func (p *PodBatchProcessor) processBatchAsync(batch []*podBatchItem) {
	// Acquire semaphore (blocks if too many batches in flight)
	p.batchSemaphore <- struct{}{}

	// Copy batch to avoid race conditions
	batchCopy := make([]*podBatchItem, len(batch))
	copy(batchCopy, batch)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() { <-p.batchSemaphore }()

		p.processBatchWithMetrics(batchCopy)
	}()
}

func (p *PodBatchProcessor) processBatchWithMetrics(batch []*podBatchItem) {
	start := time.Now()
	batchSize := len(batch)

	klog.Infof("Processing batch of %d pods", batchSize)

	err := p.processBatch(batch)

	duration := time.Since(start)
	klog.Infof("Batch of %d pods processed in %v (%.2f pods/sec)",
		batchSize, duration, float64(batchSize)/duration.Seconds())

	// Record metrics
	metrics.RecordPodBatchSize(batchSize)
	metrics.RecordPodBatchDuration(duration.Seconds())

	// Send results back to all waiting callers
	for _, item := range batch {
		item.errChan <- err
		close(item.errChan)
	}
}

// AddPod adds a pod to the batch queue and waits for the result
func (p *PodBatchProcessor) AddPod(pod *corev1.Pod, nadKey string,
	network *nadapi.NetworkSelectionElement) error {
	item := &podBatchItem{
		pod:     pod,
		nadKey:  nadKey,
		network: network,
		errChan: make(chan error, 1),
	}

	p.podQueue <- item
	return <-item.errChan
}
