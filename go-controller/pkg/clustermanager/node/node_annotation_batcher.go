package node

import (
	"fmt"
	"net"
	"sync"
	"time"

	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	// minBatchDelay is the minimum delay before processing (0 = immediate)
	minBatchDelay = 1 * time.Millisecond
	// maxBatchDelay is the maximum delay when batching under high load
	maxBatchDelay = 100 * time.Millisecond
	// backoffMultiplier is how much to increase the delay when requests arrive in quick succession
	backoffMultiplier = 2
	// backoffThreshold is the time window to consider requests as "quick succession"
	backoffThreshold = 100 * time.Millisecond
)

// NodeAnnotationBatcher batches node annotation updates from multiple networks
// and applies them in a single API call with dynamic backoff. When idle, it processes
// immediately. When requests arrive in quick succession, it backs off to batch them.
// This significantly reduces API server load when multiple UDNs are being created
// or reconciled simultaneously while maintaining low latency for individual updates.
type NodeAnnotationBatcher struct {
	kube            kube.Interface
	nodeLister      listers.NodeLister
	annotationCache util.NodeAnnotationCache

	// Pending updates per node
	pendingUpdates map[string]*pendingNodeUpdate
	mutex          sync.Mutex

	// Dynamic backoff state
	currentDelay   time.Duration
	lastEnqueueTime time.Time
	timer          *time.Timer
	triggerChan    chan struct{}

	// Channels for lifecycle management
	stopChan chan struct{}
	wg       *sync.WaitGroup
}

// pendingNodeUpdate accumulates annotation updates for a single node
// from potentially multiple networks before batching them together
type pendingNodeUpdate struct {
	// Per-network updates - stored as network name -> value
	hostSubnets map[string][]*net.IPNet // network -> host subnets
	networkIDs  map[string]int          // network -> network ID (types.NoNetworkID means don't update)
	tunnelIDs   map[string]int          // network -> tunnel ID (types.NoTunnelID means don't update)
}

// NewNodeAnnotationBatcher creates a new batcher for node annotations
func NewNodeAnnotationBatcher(kube kube.Interface, nodeLister listers.NodeLister, cache util.NodeAnnotationCache, stopChan chan struct{}, wg *sync.WaitGroup) *NodeAnnotationBatcher {
	return &NodeAnnotationBatcher{
		kube:            kube,
		nodeLister:      nodeLister,
		annotationCache: cache,
		pendingUpdates:  make(map[string]*pendingNodeUpdate),
		currentDelay:    minBatchDelay,
		triggerChan:     make(chan struct{}, 1),
		stopChan:        stopChan,
		wg:              wg,
	}
}

// Start begins the background batch processing loop with dynamic backoff
func (b *NodeAnnotationBatcher) Start() {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		for {
			select {
			case <-b.triggerChan:
				// Calculate delay based on whether we're in quick succession
				b.mutex.Lock()
				delay := b.currentDelay
				b.mutex.Unlock()

				// Wait for the calculated delay
				if delay > 0 {
					timer := time.NewTimer(delay)
					select {
					case <-timer.C:
						// Delay complete, process batch
					case <-b.stopChan:
						timer.Stop()
						b.processBatch()
						klog.Info("Node annotation batcher stopped")
						return
					}
				}

				b.processBatch()

			case <-b.stopChan:
				// Process any remaining updates before exiting
				b.processBatch()
				klog.Info("Node annotation batcher stopped")
				return
			}
		}
	}()
	klog.Infof("Node annotation batcher started with dynamic backoff (min=%v, max=%v)", minBatchDelay, maxBatchDelay)
}

// EnqueueUpdate queues an annotation update for a node from a specific network.
// Multiple updates for the same node are merged and applied together.
// Uses dynamic backoff: processes immediately when idle, backs off when requests
// arrive in quick succession.
func (b *NodeAnnotationBatcher) EnqueueUpdate(nodeName, networkName string, hostSubnets []*net.IPNet, networkID, tunnelID int) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Get or create pending update for this node
	pending, ok := b.pendingUpdates[nodeName]
	if !ok {
		pending = &pendingNodeUpdate{
			hostSubnets: make(map[string][]*net.IPNet),
			networkIDs:  make(map[string]int),
			tunnelIDs:   make(map[string]int),
		}
		b.pendingUpdates[nodeName] = pending
	}

	// Store the updates for this network
	if len(hostSubnets) > 0 {
		pending.hostSubnets[networkName] = hostSubnets
	}
	if networkID != types.NoNetworkID {
		pending.networkIDs[networkName] = networkID
	}
	if tunnelID != types.NoTunnelID {
		pending.tunnelIDs[networkName] = tunnelID
	}

	// Update backoff based on request rate
	now := time.Now()
	timeSinceLastEnqueue := now.Sub(b.lastEnqueueTime)

	if timeSinceLastEnqueue < backoffThreshold && !b.lastEnqueueTime.IsZero() {
		// Requests are arriving in quick succession - increase delay
		b.currentDelay = b.currentDelay * backoffMultiplier
		if b.currentDelay > maxBatchDelay {
			b.currentDelay = maxBatchDelay
		}
		klog.V(5).Infof("Increased batch delay to %v due to quick succession (gap=%v)", b.currentDelay, timeSinceLastEnqueue)
	} else {
		// Requests have slowed down or this is the first request - reset to minimum
		b.currentDelay = minBatchDelay
		klog.V(5).Infof("Reset batch delay to %v (gap=%v)", b.currentDelay, timeSinceLastEnqueue)
	}
	b.lastEnqueueTime = now

	klog.V(5).Infof("Enqueued annotation update for node %s network %s (subnets=%v, netID=%v, tunnelID=%v, delay=%v)",
		nodeName, networkName, len(hostSubnets), networkID, tunnelID, b.currentDelay)

	// Trigger batch processing (non-blocking)
	select {
	case b.triggerChan <- struct{}{}:
	default:
		// Already triggered, no need to send again
	}
}

// processBatch processes all pending updates, merging updates for the same node
// and applying them in a single API call per node
func (b *NodeAnnotationBatcher) processBatch() {
	b.mutex.Lock()
	// Take ownership of pending updates and reset the map
	pendingUpdates := b.pendingUpdates
	b.pendingUpdates = make(map[string]*pendingNodeUpdate)
	b.mutex.Unlock()

	if len(pendingUpdates) == 0 {
		return
	}

	klog.V(4).Infof("Processing batch of %d node annotation updates", len(pendingUpdates))

	// Process each node's updates
	for nodeName, pending := range pendingUpdates {
		if err := b.updateNodeAnnotations(nodeName, pending); err != nil {
			klog.Errorf("Failed to update node %s annotations in batch: %v", nodeName, err)
			// Re-enqueue failed updates for retry
			b.requeueUpdate(nodeName, pending)
		}
	}
}

// updateNodeAnnotations applies all pending updates for a node using retry logic
func (b *NodeAnnotationBatcher) updateNodeAnnotations(nodeName string, pending *pendingNodeUpdate) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Get the latest node object
		node, err := b.nodeLister.Get(nodeName)
		if err != nil {
			return fmt.Errorf("failed to get node %s: %w", nodeName, err)
		}

		cnode := node.DeepCopy()

		// Parse existing annotations efficiently using the cache
		existingSubnets, err := util.ParseNodeHostSubnetAnnotationWithCache(cnode, b.annotationCache)
		if err != nil && !util.IsAnnotationNotSetError(err) {
			klog.Warningf("Failed to parse existing node-subnets for node %s: %v", nodeName, err)
			existingSubnets = make(map[string][]*net.IPNet)
		} else if existingSubnets == nil {
			existingSubnets = make(map[string][]*net.IPNet)
		}

		existingNetworkIDs, err := util.ParseNetworkIDAnnotationWithCache(cnode, b.annotationCache)
		if err != nil && !util.IsAnnotationNotSetError(err) {
			klog.Warningf("Failed to parse existing network-ids for node %s: %v", nodeName, err)
			existingNetworkIDs = make(map[string]int)
		} else if existingNetworkIDs == nil {
			existingNetworkIDs = make(map[string]int)
		}

		existingTunnelIDs, err := util.ParseUDNLayer2NodeGRLRPTunnelIDsAllWithCache(cnode, b.annotationCache)
		if err != nil && !util.IsAnnotationNotSetError(err) {
			klog.Warningf("Failed to parse existing tunnel-ids for node %s: %v", nodeName, err)
			existingTunnelIDs = make(map[string]int)
		} else if existingTunnelIDs == nil {
			existingTunnelIDs = make(map[string]int)
		}

		// Merge pending updates with existing values
		subnetsUpdated := false
		networkIDsUpdated := false
		tunnelIDsUpdated := false

		// Update host subnets
		for networkName, subnets := range pending.hostSubnets {
			existingSubnets[networkName] = subnets
			subnetsUpdated = true
		}
		if subnetsUpdated {
			cnode.Annotations, err = util.UpdateNodeHostSubnetAnnotationMap(cnode.Annotations, existingSubnets)
			if err != nil {
				return fmt.Errorf("failed to update node-subnets annotation for node %s: %w", nodeName, err)
			}
		}

		// Update network IDs
		for networkName, networkID := range pending.networkIDs {
			if networkID != types.NoNetworkID {
				existingNetworkIDs[networkName] = networkID
				networkIDsUpdated = true
			}
		}
		if networkIDsUpdated {
			cnode.Annotations, err = util.UpdateNetworkIDAnnotationMap(cnode.Annotations, existingNetworkIDs)
			if err != nil {
				return fmt.Errorf("failed to update network-ids annotation for node %s: %w", nodeName, err)
			}
		}

		// Update tunnel IDs
		for networkName, tunnelID := range pending.tunnelIDs {
			if tunnelID != types.NoTunnelID {
				existingTunnelIDs[networkName] = tunnelID
				tunnelIDsUpdated = true
			}
		}
		if tunnelIDsUpdated {
			cnode.Annotations, err = util.UpdateUDNLayer2NodeGRLRPTunnelIDsMap(cnode.Annotations, existingTunnelIDs)
			if err != nil {
				return fmt.Errorf("failed to update tunnel-ids annotation for node %s: %w", nodeName, err)
			}
		}

		// Apply all updates in a single API call
		klog.V(4).Infof("Updating node %s with batched annotations (%d networks)", nodeName, len(pending.hostSubnets)+len(pending.networkIDs)+len(pending.tunnelIDs))
		return b.kube.UpdateNodeStatus(cnode)
	})
}

// requeueUpdate re-enqueues a failed update for retry in the next batch
func (b *NodeAnnotationBatcher) requeueUpdate(nodeName string, pending *pendingNodeUpdate) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	existing, ok := b.pendingUpdates[nodeName]
	if !ok {
		b.pendingUpdates[nodeName] = pending
		return
	}

	// Merge with any new updates that came in while we were processing
	for networkName, subnets := range pending.hostSubnets {
		existing.hostSubnets[networkName] = subnets
	}
	for networkName, networkID := range pending.networkIDs {
		existing.networkIDs[networkName] = networkID
	}
	for networkName, tunnelID := range pending.tunnelIDs {
		existing.tunnelIDs[networkName] = tunnelID
	}
}
