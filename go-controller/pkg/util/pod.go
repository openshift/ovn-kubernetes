package util

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/kube"
)

// AllocateToPodWithRollbackFunc is a function used to allocate a resource to a
// pod that depends on the current state of the pod, and possibly updating it.
// To be used with UpdatePodWithAllocationOrRollback. Implementations can return
// a nil pod if no update is warranted. Implementations can also return a
// rollback function that will be invoked if the pod update fails.
type AllocateToPodWithRollbackFunc func(pod *corev1.Pod) (*corev1.Pod, func(), error)

// UpdatePodWithRetryOrRollback updates the pod with the result of the
// allocate function. If the pod update fails, it applies the rollback provided by
// the allocate function.
func UpdatePodWithRetryOrRollback(podLister listers.PodLister, kube kube.Interface, pod *corev1.Pod, allocate AllocateToPodWithRollbackFunc) error {
	start := time.Now()
	var updated bool
	var retryCount int
	var totalGetTime, totalAllocTime, totalUpdateTime time.Duration

	err := retry.RetryOnConflict(OvnConflictBackoff, func() error {
		retryCount++

		// Measure pod get time
		t1 := time.Now()
		pod, err := podLister.Pods(pod.Namespace).Get(pod.Name)
		totalGetTime += time.Since(t1)
		if err != nil {
			return err
		}

		// Informer cache should not be mutated, so copy the object
		pod = pod.DeepCopy()

		// Measure allocation function time
		t2 := time.Now()
		pod, rollback, err := allocate(pod)
		totalAllocTime += time.Since(t2)
		if err != nil {
			return err
		}

		if pod == nil {
			return nil
		}

		updated = true

		// Measure API update time
		t3 := time.Now()
		// It is possible to update the pod annotations using status subresource
		// because changes to metadata via status subresource are not restricted pods.
		err = kube.UpdatePodStatus(pod)
		totalUpdateTime += time.Since(t3)

		if err != nil && rollback != nil {
			rollback()
		}

		return err
	})

	if err != nil {
		return fmt.Errorf("failed to update pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	if updated {
		totalTime := time.Since(start)
		retryWaitTime := totalTime - totalGetTime - totalAllocTime - totalUpdateTime

		// Log detailed timing at v=4 (same level as pod timing)
		klog.V(4).Infof("[K8s API %s/%s] pod update took %v (attempts=%d, get=%v, alloc=%v, apiUpdate=%v, retryWait=%v)",
			pod.Namespace, pod.Name, totalTime, retryCount,
			totalGetTime, totalAllocTime, totalUpdateTime, retryWaitTime)

		// Also keep the simple v=4 log for backward compatibility
		klog.V(4).Infof("[%s/%s] pod update took %v", pod.Namespace, pod.Name, totalTime)
	}

	return nil
}
