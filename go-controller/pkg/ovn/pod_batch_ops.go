package ovn

import (
	"fmt"
	"os"
	"strconv"
	"time"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

const (
	defaultPodBatchWindowMS  = 100
	defaultPodBatchSize      = 50
	defaultParallelBatches   = 4
	maxPodBatchWindowMS      = 1000
	maxPodBatchSize          = 200
	maxParallelBatches       = 16
)

// initPodBatching initializes the pod batch processor with configuration from environment variables
func (bnc *BaseNetworkController) initPodBatching() error {
	// Read config from environment
	batchWindow := defaultPodBatchWindowMS
	if val := os.Getenv("OVN_POD_BATCH_WINDOW_MS"); val != "" {
		if ms, err := strconv.Atoi(val); err == nil && ms >= 0 {
			if ms > maxPodBatchWindowMS {
				klog.Warningf("OVN_POD_BATCH_WINDOW_MS=%d exceeds max %d, using max", ms, maxPodBatchWindowMS)
				ms = maxPodBatchWindowMS
			}
			batchWindow = ms
		}
	}

	maxBatchSize := defaultPodBatchSize
	if val := os.Getenv("OVN_POD_BATCH_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil && size > 0 {
			if size > maxPodBatchSize {
				klog.Warningf("OVN_POD_BATCH_SIZE=%d exceeds max %d, using max", size, maxPodBatchSize)
				size = maxPodBatchSize
			}
			maxBatchSize = size
		}
	}

	parallelBatches := defaultParallelBatches
	if val := os.Getenv("OVN_POD_PARALLEL_BATCHES"); val != "" {
		if parallel, err := strconv.Atoi(val); err == nil && parallel > 0 {
			if parallel > maxParallelBatches {
				klog.Warningf("OVN_POD_PARALLEL_BATCHES=%d exceeds max %d, using max", parallel, maxParallelBatches)
				parallel = maxParallelBatches
			}
			parallelBatches = parallel
		}
	}

	// Disable batching if window is 0
	if batchWindow == 0 {
		klog.Infof("Pod batching disabled (OVN_POD_BATCH_WINDOW_MS=0)")
		bnc.podBatchingEnabled = false
		metrics.SetPodBatchConfigDisabled()
		return nil
	}

	klog.Infof("Initializing pod batch processor: window=%dms, maxSize=%d, parallel=%d",
		batchWindow, maxBatchSize, parallelBatches)

	bnc.podBatchProcessor = NewPodBatchProcessor(
		time.Duration(batchWindow)*time.Millisecond,
		maxBatchSize,
		parallelBatches,
		bnc.processPodBatch,
	)

	bnc.podBatchProcessor.Start()
	bnc.podBatchingEnabled = true

	// Log effective configuration for operational visibility
	klog.Infof("Pod batching ENABLED - effective config: window=%dms, batchSize=%d, parallelBatches=%d, queueSize=5000",
		batchWindow, maxBatchSize, parallelBatches)
	klog.Infof("Pod batching performance target: reduce OVN transaction count by 10-20x during high-volume pod operations")

	// Expose configuration as metrics for observability
	metrics.SetPodBatchConfig(float64(batchWindow), float64(maxBatchSize), float64(parallelBatches))

	return nil
}

// processPodBatch processes a batch of pod operations
func (bnc *BaseNetworkController) processPodBatch(items []*podBatchItem) error {
	klog.V(5).Infof("Processing batch of %d pods", len(items))

	// Group pods by namespace for efficient address set updates
	podsByNamespace := make(map[string][]*podBatchItem)
	for _, item := range items {
		podsByNamespace[item.pod.Namespace] = append(podsByNamespace[item.pod.Namespace], item)
	}

	// Process each namespace's pods
	for namespace, nsPods := range podsByNamespace {
		if err := bnc.processPodBatchForNamespace(namespace, nsPods); err != nil {
			klog.Errorf("Failed to process pod batch for namespace %s: %v, falling back to individual processing", namespace, err)

			// Fall back to individual processing - MUST be synchronous to avoid races
			// If async: caller gets error, retries while fallback running → duplicate OVN mutations
			for _, item := range nsPods {
				// Process each pod synchronously and capture actual result
				fallbackErr := bnc.addLogicalPortIndividual(item.pod, item.nadKey, item.network)

				// Send actual fallback result through pod's result channel
				item.errChan <- fallbackErr
				close(item.errChan)
			}

			// Don't return error - we've handled each pod individually
			// Returning would cause retry framework to retry pods we just processed
			continue
		}
	}

	return nil
}

// processPodBatchForNamespace processes a batch of pods in the same namespace
func (bnc *BaseNetworkController) processPodBatchForNamespace(namespace string, items []*podBatchItem) error {
	var allOps []ovsdb.Operation
	var podInfos []podBatchResult

	// Collect all IPs that need to be added to namespace address set
	allPodIPs := sets.NewString()

	// Build operations for all pods - track individual errors
	for _, item := range items {
		ops, lsp, podAnnotation, err := bnc.buildLogicalPortOps(item.pod, item.nadKey, item.network, nil)
		if err != nil {
			klog.Errorf("Failed to build ops for pod %s/%s: %v", item.pod.Namespace, item.pod.Name, err)
			// Track error for this specific pod
			podInfos = append(podInfos, podBatchResult{
				pod: item.pod,
				err: fmt.Errorf("build ops failed: %w", err),
			})
			continue
		}

		allOps = append(allOps, ops...)

		// Collect IPs for batch address set update
		for _, ip := range podAnnotation.IPs {
			allPodIPs.Insert(ip.IP.String())
		}

		switchName := item.pod.Spec.NodeName
		podInfos = append(podInfos, podBatchResult{
			pod:           item.pod,
			lsp:           lsp,
			podAnnotation: podAnnotation,
			switchName:    switchName,
			nadKey:        item.nadKey,
			err:           nil, // No error yet
		})
	}

	// If all pods failed during build phase, return error
	// Caller (processPodBatch) will handle fallback
	if len(allOps) == 0 {
		return fmt.Errorf("all %d pods in batch failed during build phase", len(podInfos))
	}

	// Add batch address set update for all pod IPs at once
	nsInfo, nsUnlock := bnc.getNamespaceLocked(namespace, false)
	var addrSetOps []ovsdb.Operation
	if nsInfo != nil && nsInfo.addressSet != nil {
		var err error
		addrSetOps, err = nsInfo.addressSet.AddAddressesReturnOps(allPodIPs.List())
		nsUnlock() // CRITICAL: Release lock BEFORE transaction to prevent deadlock
		if err != nil {
			// Address set build failed, return error
			// Caller (processPodBatch) will handle fallback
			return fmt.Errorf("failed to build address set ops: %v", err)
		}
		allOps = append(allOps, addrSetOps...)
	} else if nsInfo != nil {
		nsUnlock()
	}

	// Execute all operations in a single transaction
	klog.Infof("Executing batch transaction with %d operations for %d pods in namespace %s",
		len(allOps), len(items), namespace)

	start := time.Now()
	_, txnErr := libovsdbops.TransactAndCheck(bnc.nbClient, allOps)
	duration := time.Since(start)

	klog.Infof("Batch transaction for namespace %s completed in %v", namespace, duration)

	// If transaction failed, return error for fallback
	// Don't send results here - let processPodBatch decide fallback
	if txnErr != nil {
		return fmt.Errorf("batch transaction failed: %w", txnErr)
	}

	// Transaction succeeded - send success results and update caches
	for i, info := range podInfos {
		if info.err != nil {
			// Pod that failed during build phase - send its build error
			items[i].errChan <- info.err
			close(items[i].errChan)
			continue
		}

		// Success - update cache
		_ = bnc.logicalPortCache.add(info.pod, info.switchName, info.nadKey,
			info.lsp.UUID, info.podAnnotation.MAC, info.podAnnotation.IPs)

		if bnc.onLogicalPortCacheAdd != nil {
			bnc.onLogicalPortCacheAdd(info.pod, info.nadKey)
		}

		items[i].errChan <- nil
		close(items[i].errChan)
	}

	return nil
}

// buildLogicalPortOps builds OVN operations for a single pod without executing them
func (bnc *BaseNetworkController) buildLogicalPortOps(pod *corev1.Pod, nadKey string,
	network *nadapi.NetworkSelectionElement, enable *bool) (ops []ovsdb.Operation,
	lsp *nbdb.LogicalSwitchPort, podAnnotation *util.PodAnnotation, err error) {

	// Call existing addLogicalPortToNetwork but only collect ops
	ops, lsp, podAnnotation, _, err = bnc.addLogicalPortToNetwork(pod, nadKey, network, enable)
	if err != nil {
		return nil, nil, nil, err
	}

	// Note: We skip adding to namespace address set here as that will be done in batch
	// The namespace address set update is the main bottleneck we're optimizing

	return ops, lsp, podAnnotation, nil
}

// addLogicalPortIndividual processes a single pod using the traditional path
// This is used as fallback when batch processing fails
func (bnc *BaseNetworkController) addLogicalPortIndividual(pod *corev1.Pod, nadKey string,
	network *nadapi.NetworkSelectionElement) error {

	klog.Warningf("Processing pod %s/%s individually after batch failure", pod.Namespace, pod.Name)

	// Build operations for this single pod
	ops, lsp, podAnnotation, err := bnc.buildLogicalPortOps(pod, nadKey, network, nil)
	if err != nil {
		return fmt.Errorf("failed to build ops for pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	// Add namespace address set update
	nsInfo, nsUnlock := bnc.getNamespaceLocked(pod.Namespace, false)
	if nsInfo != nil && nsInfo.addressSet != nil {
		podIPs := make([]string, 0, len(podAnnotation.IPs))
		for _, ip := range podAnnotation.IPs {
			podIPs = append(podIPs, ip.IP.String())
		}
		addrSetOps, err := nsInfo.addressSet.AddAddressesReturnOps(podIPs)
		nsUnlock() // Release lock before transaction
		if err != nil {
			return fmt.Errorf("failed to build address set ops: %w", err)
		}
		ops = append(ops, addrSetOps...)
	} else if nsInfo != nil {
		nsUnlock()
	}

	// Execute transaction
	_, err = libovsdbops.TransactAndCheck(bnc.nbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to execute transaction for pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	// Update cache
	switchName := pod.Spec.NodeName
	_ = bnc.logicalPortCache.add(pod, switchName, nadKey, lsp.UUID, podAnnotation.MAC, podAnnotation.IPs)

	if bnc.onLogicalPortCacheAdd != nil {
		bnc.onLogicalPortCacheAdd(pod, nadKey)
	}

	return nil
}

type podBatchResult struct {
	pod           *corev1.Pod
	lsp           *nbdb.LogicalSwitchPort
	podAnnotation *util.PodAnnotation
	switchName    string
	nadKey        string
	err           error // Per-pod error tracking
}

// stopPodBatching stops the pod batch processor
func (bnc *BaseNetworkController) stopPodBatching() {
	if bnc.podBatchProcessor != nil {
		bnc.podBatchProcessor.Stop()
	}
}
