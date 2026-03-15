package ovn

import (
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// PodAnnotationCache is a lightweight cache tracking which pods have annotations.
// It's updated immediately when annotations are added (Phase 1 watcher), avoiding
// informer cache lag that causes unnecessary retries.
//
// This solves the early exit effectiveness issue where the current 17% effectiveness
// is due to informer cache lag - the annotation exists in etcd but not yet visible
// in the informer cache when retry logic checks it.
type PodAnnotationCache struct {
	mu    sync.RWMutex
	cache map[string]annotationEntry // key: namespace/name
}

type annotationEntry struct {
	timestamp time.Time
	network   string // Which network allocated this annotation
}

// NewPodAnnotationCache creates a new pod annotation cache
func NewPodAnnotationCache() *PodAnnotationCache {
	return &PodAnnotationCache{
		cache: make(map[string]annotationEntry),
	}
}

// Set marks a pod as having annotation for a network
func (c *PodAnnotationCache) Set(podKey, network string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[podKey] = annotationEntry{
		timestamp: time.Now(),
		network:   network,
	}

	klog.V(5).Infof("Annotation cache: marked %s as annotated by %s", podKey, network)
}

// Has checks if a pod has annotation (fast, no API call)
func (c *PodAnnotationCache) Has(podKey string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.cache[podKey]
	return exists
}

// Delete removes a pod from cache (when pod deleted)
func (c *PodAnnotationCache) Delete(podKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, podKey)
	klog.V(5).Infof("Annotation cache: removed %s", podKey)
}

// Cleanup removes stale entries (pods deleted but we didn't get notification)
func (c *PodAnnotationCache) Cleanup(maxAge time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	cleaned := 0
	for key, entry := range c.cache {
		if now.Sub(entry.timestamp) > maxAge {
			delete(c.cache, key)
			cleaned++
		}
	}

	if cleaned > 0 {
		klog.V(5).Infof("Annotation cache: cleaned up %d stale entries", cleaned)
	}

	return cleaned
}

// StartCleanupRoutine runs periodic cleanup in the background
func (c *PodAnnotationCache) StartCleanupRoutine(stopCh <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.Cleanup(10 * time.Minute)
		case <-stopCh:
			klog.V(4).Info("Annotation cache cleanup routine stopped")
			return
		}
	}
}

// Size returns current cache size (for monitoring)
func (c *PodAnnotationCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}
