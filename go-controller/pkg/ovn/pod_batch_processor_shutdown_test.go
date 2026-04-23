package ovn

import (
	"sync"
	"testing"
	"time"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestPodBatchProcessorShutdownDrain verifies that all queued pods are processed during shutdown
// This test validates the fix for: "Drain queued pods before returning from Stop"
func TestPodBatchProcessorShutdownDrain(t *testing.T) {
	tests := []struct {
		name               string
		queuedPods         int
		batchSize          int
		expectedProcessed  int
		shutdownAfterEnqueue bool
	}{
		{
			name:               "drain single batch on shutdown",
			queuedPods:         10,
			batchSize:          50,
			expectedProcessed:  10,
			shutdownAfterEnqueue: true,
		},
		{
			name:               "drain multiple batches on shutdown",
			queuedPods:         150,
			batchSize:          50,
			expectedProcessed:  150,
			shutdownAfterEnqueue: true,
		},
		{
			name:               "drain partial batch on shutdown",
			queuedPods:         25,
			batchSize:          50,
			expectedProcessed:  25,
			shutdownAfterEnqueue: true,
		},
		{
			name:               "drain exactly one batch on shutdown",
			queuedPods:         50,
			batchSize:          50,
			expectedProcessed:  50,
			shutdownAfterEnqueue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var processedCount int
			var mu sync.Mutex
			var wg sync.WaitGroup

			// Track which pods were processed
			processedPods := make(map[string]bool)

			// Create processor with custom batch function
			processor := NewPodBatchProcessor(
				10*time.Millisecond,
				tt.batchSize,
				2, // parallel batches
				func(items []*podBatchItem) {
					mu.Lock()
					defer mu.Unlock()
					for _, item := range items {
						podKey := item.pod.Namespace + "/" + item.pod.Name
						processedPods[podKey] = true
						processedCount++
						item.result = nil // Success
					}
				},
			)

			processor.Start()

			// Enqueue pods
			for i := 0; i < tt.queuedPods; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-pod-" + string(rune('0'+idx)),
							Namespace: "default",
						},
					}
					err := processor.AddPod(pod, "default", nil)
					// During shutdown, some pods might get "processor stopped" error
					// but we're testing that queued pods are drained
					if err != nil {
						t.Logf("Pod %s/%s got error (expected during shutdown): %v", pod.Namespace, pod.Name, err)
					}
				}(i)
			}

			// Give pods time to queue
			time.Sleep(20 * time.Millisecond)

			// Stop processor - this should drain all queued pods
			processor.Stop()

			// Wait for all AddPod goroutines to complete
			wg.Wait()

			// Verify all queued pods were processed
			mu.Lock()
			finalCount := processedCount
			mu.Unlock()

			assert.GreaterOrEqual(t, finalCount, tt.expectedProcessed,
				"Should process at least %d pods, got %d", tt.expectedProcessed, finalCount)

			t.Logf("Successfully processed %d/%d pods during shutdown", finalCount, tt.queuedPods)
		})
	}
}

// TestPodBatchProcessorShutdownNoDeadlock verifies shutdown doesn't deadlock
func TestPodBatchProcessorShutdownNoDeadlock(t *testing.T) {
	processor := NewPodBatchProcessor(
		100*time.Millisecond,
		50,
		4,
		func(items []*podBatchItem) {
			// Simulate slow processing
			time.Sleep(50 * time.Millisecond)
			for _, item := range items {
				item.result = nil
			}
		},
	)

	processor.Start()

	// Enqueue some pods
	for i := 0; i < 10; i++ {
		go func(idx int) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-" + string(rune('0'+idx)),
					Namespace: "default",
				},
			}
			_ = processor.AddPod(pod, "default", nil)
		}(i)
	}

	// Stop should complete within reasonable time
	done := make(chan struct{})
	go func() {
		processor.Stop()
		close(done)
	}()

	select {
	case <-done:
		t.Log("Shutdown completed successfully without deadlock")
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown deadlocked - did not complete within 5 seconds")
	}
}

// TestPodBatchProcessorAddPodAfterStop verifies AddPod returns error after Stop
func TestPodBatchProcessorAddPodAfterStop(t *testing.T) {
	processor := NewPodBatchProcessor(
		100*time.Millisecond,
		50,
		4,
		func(items []*podBatchItem) {
			for _, item := range items {
				item.result = nil
			}
		},
	)

	processor.Start()
	processor.Stop()

	// Try to add pod after stop
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
	}

	err := processor.AddPod(pod, "default", nil)
	assert.Error(t, err, "AddPod should return error after Stop()")
	assert.Contains(t, err.Error(), "processor stopped", "Error should indicate processor is stopped")
}

// TestPodBatchProcessorResultDelivery verifies all pods get results via errChan
func TestPodBatchProcessorResultDelivery(t *testing.T) {
	const numPods = 100
	resultReceived := make(chan bool, numPods)

	processor := NewPodBatchProcessor(
		10*time.Millisecond,
		20,
		2,
		func(items []*podBatchItem) {
			for _, item := range items {
				item.result = nil // Success
			}
		},
	)

	processor.Start()
	defer processor.Stop()

	var wg sync.WaitGroup
	for i := 0; i < numPods; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-" + string(rune('0'+idx)),
					Namespace: "default",
				},
			}
			err := processor.AddPod(pod, "default", nil)
			if err == nil {
				resultReceived <- true
			} else {
				t.Logf("Pod %d got error: %v", idx, err)
			}
		}(i)
	}

	// Wait for all AddPod calls to complete
	go func() {
		wg.Wait()
		close(resultReceived)
	}()

	// Count received results
	receivedCount := 0
	for range resultReceived {
		receivedCount++
	}

	assert.Equal(t, numPods, receivedCount, "All pods should receive results")
	t.Logf("All %d pods received results successfully", receivedCount)
}

// TestPodBatchProcessorInFlightBatchesComplete verifies in-flight batches complete during shutdown
func TestPodBatchProcessorInFlightBatchesComplete(t *testing.T) {
	var processedCount int
	var mu sync.Mutex
	processingStarted := make(chan struct{})

	processor := NewPodBatchProcessor(
		10*time.Millisecond,
		10,
		2,
		func(items []*podBatchItem) {
			close(processingStarted)
			// Simulate long processing
			time.Sleep(200 * time.Millisecond)
			mu.Lock()
			processedCount += len(items)
			mu.Unlock()
			for _, item := range items {
				item.result = nil
			}
		},
	)

	processor.Start()

	// Enqueue enough pods to trigger processing
	for i := 0; i < 15; i++ {
		go func(idx int) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-" + string(rune('0'+idx)),
					Namespace: "default",
				},
			}
			_ = processor.AddPod(pod, "default", nil)
		}(i)
	}

	// Wait for processing to start
	<-processingStarted

	// Stop while batch is processing
	processor.Stop()

	// Verify in-flight batch completed
	mu.Lock()
	count := processedCount
	mu.Unlock()

	assert.GreaterOrEqual(t, count, 10, "In-flight batch should complete during shutdown")
	t.Logf("In-flight batch completed: processed %d pods", count)
}
