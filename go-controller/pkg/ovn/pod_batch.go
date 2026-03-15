package ovn

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// PodBatchItem represents a pod waiting to be processed in batch
type PodBatchItem struct {
	Pod         *corev1.Pod
	Annotations *util.PodAnnotation
	Network     string
	ResultCh    chan error // For returning result to caller
}

// PodBatch represents a batch of pods to process together
type PodBatch struct {
	Items []*PodBatchItem
}

// NewPodBatchItem creates a new batch item for a pod
func NewPodBatchItem(pod *corev1.Pod, annotations *util.PodAnnotation, network string) *PodBatchItem {
	return &PodBatchItem{
		Pod:         pod,
		Annotations: annotations,
		Network:     network,
		ResultCh:    make(chan error, 1), // Buffered channel to prevent blocking
	}
}

// Wait waits for batch processing result with timeout
func (item *PodBatchItem) Wait(timeout time.Duration) error {
	select {
	case err := <-item.ResultCh:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for batch processing of pod %s/%s",
			item.Pod.Namespace, item.Pod.Name)
	}
}

// Complete signals the result of processing this item
func (item *PodBatchItem) Complete(err error) {
	select {
	case item.ResultCh <- err:
		// Successfully sent result
	default:
		// Channel already has result, ignore
	}
}
