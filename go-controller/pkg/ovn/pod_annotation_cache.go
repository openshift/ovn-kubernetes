package ovn

import (
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// PodAnnotationCache is a lightweight cache tracking which pods have been successfully configured.
// It's populated AFTER AddResource() succeeds (when LSP is created in OVS), avoiding the timing
// bug where cache was populated when cluster manager annotation appeared (before LSP creation).
//
// This solves the early exit timing issue where pods exited retry before OVS port binding was ready,
// causing CNI timeouts waiting for ovn-installed annotation.
type PodAnnotationCache struct {
	mu    sync.RWMutex
	cache map[string]cacheEntry // key: namespace/name
}

type cacheEntry struct {
	timestamp time.Time
	network   string // Which network configured this pod
}

// NewPodAnnotationCache creates a new pod annotation cache
func NewPodAnnotationCache() *PodAnnotationCache {
	return &PodAnnotationCache{
		cache: make(map[string]cacheEntry),
	}
}

// Set marks a pod as successfully configured for a network.
// This should ONLY be called AFTER AddResource() succeeds (LSP created in OVS).
func (c *PodAnnotationCache) Set(podKey, network string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[podKey] = cacheEntry{
		timestamp: time.Now(),
		network:   network,
	}

	klog.V(4).Infof("Pod annotation cache: marked %s as configured by %s", podKey, network)
}

// Has checks if a pod has been successfully configured (fast, no API call)
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
	klog.V(5).Infof("Pod annotation cache: removed %s", podKey)
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
		klog.V(5).Infof("Pod annotation cache: cleaned up %d stale entries", cleaned)
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
			klog.V(4).Info("Pod annotation cache cleanup routine stopped")
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
