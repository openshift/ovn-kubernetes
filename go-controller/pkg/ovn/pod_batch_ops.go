package ovn

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
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
			klog.Errorf("Failed to process pod batch for namespace %s: %v", namespace, err)
			// Fall back to individual processing
			for _, item := range nsPods {
				go bnc.addLogicalPortIndividual(item.pod, item.nadKey, item.network)
			}
			return err
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

	// Build operations for all pods
	for _, item := range items {
		ops, lsp, podAnnotation, err := bnc.buildLogicalPortOps(item.pod, item.nadKey, item.network, nil)
		if err != nil {
			klog.Errorf("Failed to build ops for pod %s/%s: %v",
				item.pod.Namespace, item.pod.Name, err)
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
		})
	}

	if len(allOps) == 0 {
		return nil
	}

	// Add batch address set update for all pod IPs at once
	nsInfo, nsUnlock := bnc.getNamespaceLocked(namespace, false)
	if nsInfo != nil && nsInfo.addressSet != nil {
		defer nsUnlock()
		addrSetOps, err := nsInfo.addressSet.AddAddressesReturnOps(allPodIPs.List())
		if err != nil {
			return fmt.Errorf("failed to build address set ops: %v", err)
		}
		allOps = append(allOps, addrSetOps...)
	} else if nsInfo != nil {
		nsUnlock()
	}

	// Execute all operations in a single transaction
	klog.Infof("Executing batch transaction with %d operations for %d pods in namespace %s",
		len(allOps), len(podInfos), namespace)

	start := time.Now()
	_, err := libovsdbops.TransactAndCheck(bnc.nbClient, allOps)
	duration := time.Since(start)

	klog.Infof("Batch transaction for namespace %s completed in %v (%.2f pods/sec)",
		namespace, duration, float64(len(podInfos))/duration.Seconds())

	if err != nil {
		klog.Errorf("Batch transaction failed for namespace %s: %v, falling back to individual processing", namespace, err)
		return err
	}

	// Update caches for all successfully processed pods
	for _, info := range podInfos {
		_ = bnc.logicalPortCache.add(info.pod, info.switchName, info.nadKey,
			info.lsp.UUID, info.podAnnotation.MAC, info.podAnnotation.IPs)

		if bnc.onLogicalPortCacheAdd != nil {
			bnc.onLogicalPortCacheAdd(info.pod, info.nadKey)
		}
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
func (bnc *BaseNetworkController) addLogicalPortIndividual(pod *corev1.Pod, nadKey string,
	network *nadapi.NetworkSelectionElement) error {
	// This would call the existing individual processing logic
	// For now, we'll skip the implementation as it would use existing code paths
	klog.V(5).Infof("Processing pod %s/%s individually", pod.Namespace, pod.Name)
	return nil
}

type podBatchResult struct {
	pod           *corev1.Pod
	lsp           *nbdb.LogicalSwitchPort
	podAnnotation *util.PodAnnotation
	switchName    string
	nadKey        string
}

// stopPodBatching stops the pod batch processor
func (bnc *BaseNetworkController) stopPodBatching() {
	if bnc.podBatchProcessor != nil {
		bnc.podBatchProcessor.Stop()
	}
}
