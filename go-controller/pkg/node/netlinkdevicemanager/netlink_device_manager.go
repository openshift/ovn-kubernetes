package netlinkdevicemanager

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	nl "github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	utilerrors "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util/errors"
)

// Interface defines the contract for NetlinkDeviceManager Controller.
//
// # Design: Asynchronous API
//
// All mutating methods (EnsureLink, DeleteLink) are
// asynchronous: they store the desired state and return immediately. A single
// background worker goroutine performs all netlink I/O, serializing kernel
// operations and applying rate-limited retry on transient failures.
//
// This design was chosen over a synchronous "apply-and-return-error" approach
// for four reasons:
//
//  1. Cross-device dependencies. Unlike routes, devices depend on each other:
//     a VXLAN requires its master bridge, an SVI requires both a VLAN parent
//     (bridge) and a master (VRF, managed by a different controller). When a
//     dependency is missing, synchronous apply cannot return an actionable error
//     — the caller cannot resolve the dependency; a synchronous error would
//     only force the caller to implement retry/backoff (or poll/track
//     dependency readiness), often delaying convergence. The async model
//     classifies this as pending and retries promptly when the
//     dependency appears via a netlink event, without caller involvement.
//
//  2. Multi-step I/O. Each device reconciliation involves multiple netlink
//     calls (create, set alias, set master, apply bridge port settings, bring
//     up, sync addresses). A synchronous model must either hold a lock across
//     all of these (blocking all other callers and the event handler for the
//     full duration) or release the lock during I/O (duplicating the
//     reconciler's staleness-check logic and creating a second I/O path that
//     competes with the background worker). The async model avoids both:
//     a single worker goroutine owns all I/O, API methods never block on
//     kernel operations, and the workqueue deduplicates keys so bursty
//     netlink events collapse into fewer reconciles.
//
//  3. Single linearization point (policy + state machine in one place).
//     With a synchronous API, netlink events and periodic reconciliation,
//     multiple code paths would perform netlink I/O. To be correct, each
//     path must enforce the same invariants ("still desired?", "do we
//     own it?", current ifindex/kernel state, error classification/backoff,
//     state transitions). Any drift between paths creates subtle races
//     (e.g. resurrecting a deleted device or acting on stale state). The
//     async workqueue funnels all I/O and state transitions through one
//     reconciler goroutine, so these invariants are implemented once and
//     applied consistently. A "synchronous but centralized" design
//     would still need to serialize all entrypoints through that same
//     reconciler, which effectively converges on the workqueue pattern.
//
//  4. Netlink back-pressure control. Funneling all netlink I/O through a
//     single worker goroutine with a rate-limited workqueue gives the manager
//     direct control over how much pressure it puts on the kernel's netlink
//     subsystem.
//
// # Ownership
//
// Devices created through EnsureLink are marked with an IFLA_IFALIAS prefix
// ("ovn-k8s-ndm:"). Only devices with this alias are considered owned and may
// be modified or deleted. Devices without the alias (or with a foreign alias)
// are never touched — if a name collision occurs, the reconciler sets the
// device to a blocked state.
//
// # Supported Device Types
//
// The manager supports Bridge, Vxlan, Vlan, Vrf, and Dummy device types.
//
// # NOTE on Route Management
//
// NDM manages addresses but DOES NOT manage routes. When an address is added
// to a device, the kernel may automatically create a connected route for that
// subnet. If someone removes a kernel-created route, neither the kernel nor
// NDM will restore it. Route management, if needed, must be handled through a
// separate mechanism (e.g., route manager).
type Interface interface {
	// EnsureLink declares the desired configuration for a device.
	//
	// Behavior is asynchronous: the configuration is stored and a
	// reconciliation is enqueued. The method returns nil once the intent is
	// recorded; it does not wait for the device to be created or updated in
	// the kernel. Only validation errors (invalid name, unsupported type)
	// are returned synchronously.
	//
	// Updates are handled in-place: callers may call EnsureLink again with
	// a changed config for the same device name. There is no need to call
	// DeleteLink before re-calling EnsureLink. The reconciler
	// transparently chooses the least-disruptive strategy: mutable
	// attributes are patched on the existing device while immutable
	// attributes trigger an automatic delete+recreate.
	//
	// If the device already exists in the store with an identical config,
	// this is a no-op — no reconciliation is enqueued, except for Blocked
	// devices where the caller may know the external conflict was resolved.
	//
	// If a dependency (Master, VLANParent) does not exist in the kernel,
	// the device is marked pending and automatically retried
	// when the dependency appears via netlink event.
	//
	// The device is always brought UP after all configuration is applied,
	// regardless of the Flags field in Link.Attrs(). Callers cannot create
	// devices in a permanently DOWN state through this API.
	//
	// Full-state semantics: the provided config is the complete desired
	// state. Attributes not specified are treated as "use kernel default."
	// Addresses, if non-nil, are declarative — exactly the listed addresses
	// will exist on the device.
	EnsureLink(cfg DeviceConfig) error

	// DeleteLink removes a device from the desired state.
	//
	// Behavior is asynchronous: the device is removed from the store and
	// a reconciliation is enqueued to delete it from the kernel. The
	// method returns nil once the intent is recorded.
	//
	// Only devices with our ownership alias are deleted from the kernel.
	DeleteLink(name string) error
}

// deviceState represents the lifecycle state of a managed device.
type deviceState string

const (
	deviceStateReady   deviceState = "Ready"   // Device matches desired state in kernel
	deviceStatePending deviceState = "Pending" // Waiting for dependency (master, VLANParent)
	deviceStateFailed  deviceState = "Failed"  // Transient kernel error (will retry with backoff)
	deviceStateBlocked deviceState = "Blocked" // External device conflict (NotOwnedError)
)

// DeviceConfig represents the complete desired configuration for a network device.
// Controllers provide the FULL configuration; manager enforces EXACTLY what's provided.
type DeviceConfig struct {
	// Link is the netlink device. Supported types: Bridge, Vxlan, Vlan, Vrf, Dummy.
	//
	// Only specific fields per type are managed by NDM. Setting unsupported fields
	// to non-zero values will cause EnsureLink to return an error.
	//
	// Managed LinkAttrs fields (common to all types):
	//   - Name (device identity, required)
	//   - MTU (0 = kernel default / don't care)
	//   - TxQLen (-1 = unset from NewLinkAttrs, 0 = set to zero)
	//   - HardwareAddr (nil = don't care)
	//
	// Managed type-specific fields (see buildManagedLink for the canonical list):
	//   - Bridge:  VlanFiltering, VlanDefaultPVID
	//   - Vxlan:   VxlanId, SrcAddr, Port, FlowBased, VniFilter, Learning
	//   - Vlan:    VlanId, VlanProtocol
	//   - Vrf:     Table
	//   - Dummy:   (none)
	//
	// All other type-specific fields are unsupported and must remain at zero values.
	Link netlink.Link

	// Master is the name of the master device (e.g., bridge name for VXLAN, VRF name for SVI)
	// If the master doesn't exist yet, config is stored as pending and retried on netlink events.
	Master string

	// VLANParent is the name of the parent device for VLAN interfaces.
	// Required for *netlink.Vlan devices. The parent's current ifindex is
	// resolved at creation time, which is resilient to parent recreation
	// (ifindex changes).
	// If the parent doesn't exist yet, config is stored as pending and retried on netlink events.
	VLANParent string

	// BridgePortSettings configures bridge port-specific settings.
	// Only applicable when Master is set and is a bridge.
	// Settings are applied after the device is attached to the bridge.
	// Typically used for VXLAN ports that need vlan_tunnel=on, neigh_suppress=on, learning=off.
	BridgePortSettings *BridgePortSettings

	// Addresses specifies IP addresses to configure on the device.
	//
	// Semantics:
	//   - nil:           No address management. Existing addresses are preserved.
	//   - empty slice:   Declarative empty state. All addresses will be removed
	//                    (except link-local: IPv6 fe80::/10 and IPv4 169.254.0.0/16).
	//   - non-empty:     Declarative. Exactly these addresses will exist.
	//                    Missing addresses are added, extra addresses are removed
	//                    (except link-local).
	//
	// Address equality is based on IPNet (IP + prefix length) only.
	// Other Addr fields (Flags, Scope, Label, ValidLft, PreferredLft) are
	// applied when adding but not used for comparison.
	//
	// Link-local addresses (IPv6 fe80::/10 and IPv4 169.254.0.0/16) are
	// never auto-removed because they are kernel-managed and removing them
	// can break network functionality.
	Addresses []netlink.Addr

	// VIDVNIMappings specifies VID↔VNI tunnel mappings for VXLAN bridge ports.
	// Only valid when Link is *netlink.Vxlan and Master is set (bridge master).
	//
	// Semantics:
	//   - nil:           No mapping management. Existing mappings are preserved.
	//   - empty slice:   Declarative empty state. All stale mappings will be removed.
	//   - non-empty:     Declarative. Exactly these mappings will exist.
	//                    Missing mappings are added, stale mappings are removed.
	//
	// Each VID and each VNI must be unique within the slice.
	//
	// Architectural constraint (SVD model): VIDs must also be unique across all
	// devices sharing the same bridge master. Stale mappings are removed
	// including their bridge self VLAN, so a VID shared by two VXLAN devices
	// on the same bridge would cause removal of one mapping to disrupt the other.
	VIDVNIMappings []VIDVNIMapping
}

// VIDVNIMapping represents a single VID↔VNI mapping for bridge VXLAN configuration.
type VIDVNIMapping struct {
	VID uint16 // VLAN ID on the bridge (1-4094)
	VNI uint32 // VNI for VXLAN tunnel (1-16777215)
}

// BridgePortSettings configures bridge port-specific settings used for VXLAN port configuration.
type BridgePortSettings struct {
	VLANTunnel    bool // Enable VLAN tunnel mode (bridge link set dev X vlan_tunnel on)
	NeighSuppress bool // Enable neighbor suppression (bridge link set dev X neigh_suppress on)
	Learning      bool // Enable MAC learning
	Isolated      bool // Isolated ports cannot forward frames to each other (bridge link set dev X isolated on)
}

// managedAliasPrefix is the prefix used in IFLA_IFALIAS to mark devices managed by this controller.
// This allows safe cleanup: only delete devices with this prefix.
// Format: "ovn-k8s-ndm:<type>:<name>" for debugging and collision avoidance.
const managedAliasPrefix = "ovn-k8s-ndm:"

// maxInterfaceNameLength is the maximum length for Linux interface names.
// Linux's IFNAMSIZ is 16 (including null terminator), so max usable length is 15.
const maxInterfaceNameLength = 15

// NotOwnedError is returned when an operation is blocked because the device
// exists but is not owned by us (no alias or foreign alias).
// This is a permanent error - retrying won't help unless the external device is removed.
type NotOwnedError struct {
	DeviceName string
	Reason     string
}

func (e *NotOwnedError) Error() string {
	return fmt.Sprintf("device %s not owned by us: %s", e.DeviceName, e.Reason)
}

// IsNotOwnedError returns true if the error indicates a device ownership conflict.
func IsNotOwnedError(err error) bool {
	var notOwned *NotOwnedError
	return errors.As(err, &notOwned)
}

// defaultReconcilePeriod is the default interval for periodic sync as a safety net.
const defaultReconcilePeriod = 60 * time.Second

// defaultMaxSyncJitter is the maximum random delay added when enqueuing
// devices during periodic sync. Distributes reconciliation over time to
// avoid CPU spikes at scale.
const defaultMaxSyncJitter = 5 * time.Second

// Key prefixes for workqueue item type routing.
// Workqueue deduplicates by key, so rapid updates to the same device coalesce.
const (
	deviceKeyPrefix = "device/"  // e.g., "device/br-evpn"
	fullSyncKey     = "fullsync" // Channel recreation: orphan cleanup + re-enqueue all devices
	syncKey         = "sync"     // Periodic: re-enqueue VXLAN devices for VNI filter drift recovery
)

// managedDevice tracks a device with its config and status
type managedDevice struct {
	cfg           DeviceConfig // Complete desired config
	state         deviceState  // Lifecycle state (Ready, Pending, Failed, Blocked)
	ifindex       int          // Kernel ifindex, updated on successful reconciliation
	masterIfindex int          // Master's kernel ifindex at last successful reconciliation (0 = no master)
	lastError     error        // Last error from reconciliation (preserved for status/debug)
	generation    uint64       // Monotonic counter incremented by EnsureLink on config change; used by reconciler for staleness detection
}

// Controller manages Linux network device lifecycle using a workqueue-based reconciler.
// Public API methods store desired state and enqueue work; a single worker goroutine
// performs all netlink I/O. Self-heals via periodic sync (VNI filter drift),
// orphan cleanup, and netlink event-driven reconciliation (link events via
// address events).
type Controller struct {
	mu    sync.RWMutex
	store map[string]*managedDevice // device name -> managed device info

	reconciler controller.Reconciler // workqueue reconciler (single worker, all I/O)

	// ReconcilePeriod is the interval for periodic sync as a safety net.
	// Defaults to defaultReconcilePeriod. Can be overridden before calling Run().
	ReconcilePeriod time.Duration

	// MaxSyncJitter is the maximum random delay added per device when
	// enqueuing during periodic sync. Each device gets a delay in
	// [0, MaxSyncJitter) to spread reconciliation over time.
	// Defaults to defaultMaxSyncJitter. Can be overridden before calling Run().
	MaxSyncJitter time.Duration
}

// NewController creates a new NetlinkDeviceManager with default settings.
// The ReconcilePeriod can be overridden before calling Run() if needed.
func NewController() *Controller {
	c := &Controller{
		store:           make(map[string]*managedDevice),
		ReconcilePeriod: defaultReconcilePeriod,
		MaxSyncJitter:   defaultMaxSyncJitter,
	}

	c.reconciler = controller.NewReconciler("netlink-device-manager", &controller.ReconcilerConfig{
		RateLimiter: workqueue.DefaultTypedControllerRateLimiter[string](),
		Reconcile:   c.reconcileWorkqueue,
		Threadiness: 1,                           // Single worker — serializes all netlink I/O
		MaxAttempts: controller.InfiniteAttempts, // Self-healing: infinite retries
	})

	return c
}

// reconcileWorkqueue routes workqueue items to appropriate handlers based on key prefix.
// This is the single entry point for all I/O — called by the workqueue worker goroutine.
func (c *Controller) reconcileWorkqueue(key string) error {
	klog.V(5).Infof("NetlinkDeviceManager: reconciling %s", key)
	switch {
	case strings.HasPrefix(key, deviceKeyPrefix):
		return c.reconcileDeviceKey(strings.TrimPrefix(key, deviceKeyPrefix))
	case key == fullSyncKey:
		return c.reconcileFullSyncKey()
	case key == syncKey:
		return c.reconcileSyncKey()
	default:
		klog.Warningf("NetlinkDeviceManager: unknown reconcile key: %s", key)
		return nil
	}
}

// reconcileDeviceKey is the core device reconciler.
// Handles both create/update (device in store) and delete (device not in store).
// Pattern: Lock → copy config → Unlock → I/O outside lock → Lock → update state → Unlock.
func (c *Controller) reconcileDeviceKey(name string) error {
	start := time.Now()
	defer func() {
		klog.V(5).Infof("NetlinkDeviceManager: reconcile %s took %v", name, time.Since(start))
	}()

	// Read config under RLock
	c.mu.RLock()
	unlock := sync.OnceFunc(c.mu.RUnlock)
	defer unlock()

	device, exists := c.store[name]
	if !exists {
		unlock()
		// Not desired — delete from kernel if present.
		err := deleteDevice(name)
		if err != nil && !IsNotOwnedError(err) {
			return err // rate-limited retry
		}
		return nil
	}
	// Snapshot config for lock-free I/O. Deep-copy Link so downstream
	// functions (resolveDependencies, createLink) can mutate it freely.
	cfg := device.cfg
	cfg.Link = buildManagedLink(cfg.Link)
	gen := device.generation
	unlock()

	// All netlink I/O OUTSIDE lock
	ifindex, masterIfindex, err := applyDeviceConfig(&cfg)

	// Update state under Lock
	c.mu.Lock()
	defer c.mu.Unlock()

	device, stillExists := c.store[name]
	if !stillExists {
		return nil // Deleted during I/O — re-queued key will handle delete
	}

	// Staleness guard: if config was replaced during I/O (concurrent EnsureLink
	// incremented generation), skip state update. The replacement already
	// enqueued a fresh reconcile that will apply the current config.
	if device.generation != gen {
		return nil
	}

	var newState deviceState
	var reconcileErr error

	switch {
	case err == nil:
		newState = deviceStateReady
		device.ifindex = ifindex
		device.masterIfindex = masterIfindex
	case isDependencyError(err):
		newState = deviceStatePending
		// return nil: don't retry via rate-limited backoff
		// Will be re-triggered by netlink event when dependency appears
	case IsNotOwnedError(err):
		newState = deviceStateBlocked
		// return nil: permanent condition, no point retrying
		// Will be re-triggered by netlink event when external device removed
	default:
		newState = deviceStateFailed
		reconcileErr = err // return error → rate-limited retry via workqueue
	}

	device.lastError = err
	device.state = newState

	return reconcileErr
}

// cleanupOrphanedDevices scans kernel for devices with our alias that are NOT in the
// desired state store, and deletes them. Used during startup/resubscribe.
//
// Note: a device could be re-desired (via EnsureLink) between the scan and the delete.
// We don't re-check for this — if we delete a re-desired device, the worker will
// recreate it immediately since EnsureLink already enqueued the key.
func (c *Controller) cleanupOrphanedDevices() error {
	// Scan kernel — I/O, no lock needed
	links, err := util.GetNetLinkOps().LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links: %w", err)
	}

	// Find orphans — check store under RLock (read-only check)
	c.mu.RLock()
	var orphans []netlink.Link
	for _, link := range links {
		if isOurDevice(link) {
			name := link.Attrs().Name
			if _, desired := c.store[name]; !desired {
				orphans = append(orphans, link)
			}
		}
	}
	c.mu.RUnlock()

	// Delete orphans
	var deleted int
	for _, link := range orphans {
		name := link.Attrs().Name
		klog.V(5).Infof("NetlinkDeviceManager: deleting orphaned device %s", name)
		if err := util.GetNetLinkOps().LinkDelete(link); err != nil {
			klog.Errorf("NetlinkDeviceManager: failed to delete orphan %s: %v", name, err)
		} else {
			deleted++
		}
	}
	if deleted > 0 {
		klog.Infof("NetlinkDeviceManager: cleaned up %d orphaned devices", deleted)
	}
	return nil
}

// reconcileFullSyncKey runs orphan cleanup then re-enqueues ALL managed devices.
func (c *Controller) reconcileFullSyncKey() error {
	if err := c.cleanupOrphanedDevices(); err != nil {
		klog.Errorf("NetlinkDeviceManager: orphan cleanup failed: %v", err)
	}
	count := c.enqueueDevices(nil)
	klog.V(5).Infof("NetlinkDeviceManager: full sync enqueued %d device(s) (max jitter: %v)", count, c.MaxSyncJitter)
	return nil
}

// reconcileSyncKey re-enqueues VXLAN devices for VNI filter drift recovery.
// Only VXLAN devices need periodic sync because VNI filter changes emit
// RTNLGRP_TUNNEL events, which the netlink library has no subscription API for.
// Link and address attributes are covered by their respective event subscriptions.
func (c *Controller) reconcileSyncKey() error {
	isVxlan := func(d *managedDevice) bool {
		_, ok := d.cfg.Link.(*netlink.Vxlan)
		return ok
	}
	count := c.enqueueDevices(isVxlan)
	if count > 0 {
		klog.V(5).Infof("NetlinkDeviceManager: periodic sync enqueued %d VXLAN device(s) (max jitter: %v)", count, c.MaxSyncJitter)
	}
	return nil
}

// enqueueDevices iterates the store and enqueues matching devices for reconciliation
// with a random delay in [0, MaxSyncJitter). If filter is nil, all devices are enqueued.
// Returns the number of devices enqueued.
func (c *Controller) enqueueDevices(filter func(*managedDevice) bool) int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var count int
	for name, device := range c.store {
		if filter != nil && !filter(device) {
			continue
		}
		var jitter time.Duration
		if c.MaxSyncJitter > 0 {
			jitter = rand.N(c.MaxSyncJitter)
		}
		c.reconciler.ReconcileAfter(deviceKeyPrefix+name, jitter)
		count++
	}
	return count
}

// validateConfig checks that a DeviceConfig is well-formed.
func (cfg *DeviceConfig) validateConfig() error {
	name := cfg.deviceName()
	if err := validateInterfaceName(name, "device"); err != nil {
		return err
	}
	if err := validateLinkType(cfg.Link); err != nil {
		return fmt.Errorf("device %q: %w", name, err)
	}
	if cfg.Master != "" {
		if err := validateInterfaceName(cfg.Master, "master"); err != nil {
			return err
		}
	}
	if cfg.VLANParent != "" {
		if err := validateInterfaceName(cfg.VLANParent, "VLAN parent"); err != nil {
			return err
		}
	}
	if cfg.Link.Attrs().MasterIndex != 0 {
		return fmt.Errorf("device %q: set DeviceConfig.Master instead of LinkAttrs.MasterIndex (resolved internally)", name)
	}
	if vlan, ok := cfg.Link.(*netlink.Vlan); ok && vlan.ParentIndex != 0 {
		return fmt.Errorf("device %q: set DeviceConfig.VLANParent instead of LinkAttrs.ParentIndex (resolved internally)", name)
	}
	for _, addr := range cfg.Addresses {
		if addr.IPNet != nil && isLinkLocalAddress(addr.IPNet.IP) {
			return fmt.Errorf("device %q: link-local address %s cannot be managed (kernel-managed)", name, addr.IPNet)
		}
	}
	if cfg.VIDVNIMappings != nil {
		if _, ok := cfg.Link.(*netlink.Vxlan); !ok {
			return fmt.Errorf("device %q: VIDVNIMappings is only valid for VXLAN devices, got %T", name, cfg.Link)
		}
		if cfg.Master == "" {
			return fmt.Errorf("device %q: VIDVNIMappings requires a bridge master", name)
		}
		if err := validateMappings(cfg.VIDVNIMappings); err != nil {
			return fmt.Errorf("device %q: %w", name, err)
		}
	}
	if err := validateSupportedFields(cfg.Link); err != nil {
		return fmt.Errorf("device %q: %w", name, err)
	}
	return nil
}

// EnsureLink stores the desired device configuration and enqueues it for reconciliation.
//
// INVARIANT: This relies on MaxAttempts = InfiniteAttempts. If MaxAttempts
// were finite, a Failed device with unchanged config could be dropped from
// the workqueue and never retried (periodic sync would eventually catch it,
// but the gap could be up to ReconcilePeriod).
func (c *Controller) EnsureLink(cfg DeviceConfig) error {
	if err := cfg.validateConfig(); err != nil {
		return err
	}

	name := cfg.deviceName()

	// Defensive copy: prevent data race if caller mutates the slices/link after return.
	// buildManagedLink deep-copies reference types and strips unsupported fields,
	// so the stored config contains only managed fields and is fully independent.
	cfg.Addresses = slices.Clone(cfg.Addresses)
	cfg.VIDVNIMappings = slices.Clone(cfg.VIDVNIMappings)
	cfg.Link = buildManagedLink(cfg.Link)

	c.mu.Lock()
	unlock := sync.OnceFunc(c.mu.Unlock)
	defer unlock()

	var gen uint64
	state := deviceStatePending // default for new devices; existing devices preserve their state
	if existing := c.store[name]; existing != nil {
		if configsEqual(&existing.cfg, &cfg) {
			// Config unchanged. Re-enqueue only for Blocked devices — the caller
			// may know the external conflict was resolved and wants to force retry.
			// Don't re-enqueue Failed — the workqueue already has it in rate-limited
			// backoff. Reconcile() bypasses the rate limiter (queue.Add), so calling
			// it here would reset the backoff and cause rapid retries.
			if existing.state == deviceStateBlocked {
				unlock()
				c.reconciler.Reconcile(deviceKeyPrefix + name)
			}
			return nil
		}
		gen = existing.generation
		state = existing.state
	}

	// Store desired config, increment generation, and enqueue.
	c.store[name] = &managedDevice{cfg: cfg, state: state, generation: gen + 1}
	unlock()

	c.reconciler.Reconcile(deviceKeyPrefix + name)
	return nil
}

// DeleteLink removes a device from the desired state and enqueues reconciliation.
// The worker will see the device absent from store and delete it from the kernel.
func (c *Controller) DeleteLink(name string) error {
	c.mu.Lock()
	unlock := sync.OnceFunc(c.mu.Unlock)
	defer unlock()

	_, wasManaged := c.store[name]
	if !wasManaged {
		return nil
	}

	delete(c.store, name)
	unlock()

	c.reconciler.Reconcile(deviceKeyPrefix + name)
	return nil
}

// eventChanBufferSize is the buffer size for netlink event channels (link and addr).
// The buffer decouples the kernel socket drain rate from event processing,
// absorbing bursts (e.g., during startup or bulk reconfiguration) without
// tearing down the subscription.
const eventChanBufferSize = 100

// subscribeLinkEvents creates a buffered channel and subscribes to netlink link
// events. Returns the channel on success or nil on failure.
func subscribeLinkEvents(stopCh <-chan struct{}, onError func(error)) chan netlink.LinkUpdate {
	ch := make(chan netlink.LinkUpdate, eventChanBufferSize)
	options := netlink.LinkSubscribeOptions{
		ErrorCallback: onError,
	}
	if err := netlink.LinkSubscribeWithOptions(ch, stopCh, options); err != nil {
		onError(err)
		return nil
	}
	return ch
}

// subscribeAddrEvents creates a buffered channel and subscribes to netlink address
// events. Returns the channel on success or nil on failure.
func subscribeAddrEvents(stopCh <-chan struct{}, onError func(error)) chan netlink.AddrUpdate {
	ch := make(chan netlink.AddrUpdate, eventChanBufferSize)
	options := netlink.AddrSubscribeOptions{
		ErrorCallback: onError,
	}
	if err := netlink.AddrSubscribeWithOptions(ch, stopCh, options); err != nil {
		onError(err)
		return nil
	}
	return ch
}

// Run starts the background reconciler and netlink event listener.
//
// Callers MUST call EnsureLink for all previously-existing desired devices
// before calling Run. On startup, Run performs orphan cleanup: it scans the
// kernel for devices with our ownership alias that are not in the desired state
// store and deletes them. If the store is empty, all previously-managed devices
// will be removed.
func (c *Controller) Run(stopCh <-chan struct{}, doneWg *sync.WaitGroup) error {
	reconcilePeriod := c.ReconcilePeriod

	// Subscribe to netlink events BEFORE starting workers.
	// This ensures no events are missed between worker startup and subscription.
	onSubscribeError := func(err error) {
		klog.Errorf("NetlinkDeviceManager: netlink subscribe error: %v", err)
	}
	linkChan := subscribeLinkEvents(stopCh, onSubscribeError)
	addrChan := subscribeAddrEvents(stopCh, onSubscribeError)

	// Start reconciler with orphan cleanup as initial sync.
	if err := controller.StartWithInitialSync(
		c.cleanupOrphanedDevices,
		c.reconciler,
	); err != nil {
		return fmt.Errorf("failed to start reconciler: %w", err)
	}

	// Queue initial sync (not fullsync — orphan cleanup already ran via StartWithInitialSync)
	c.reconciler.Reconcile(syncKey)

	doneWg.Add(1)
	go func() {
		defer doneWg.Done()
		defer controller.Stop(c.reconciler)

		syncTimer := time.NewTicker(reconcilePeriod)
		defer syncTimer.Stop()

		for {
			// Exit immediately if stopCh is closed
			// Handle race condition between stopCh and events.
			select {
			case <-stopCh:
				klog.Info("NetlinkDeviceManager: stopping")
				return
			default:
			}

			select {
			case update, ok := <-linkChan:
				// Note: we do NOT reset the periodic sync timer on events.
				// Resetting would starve periodic sync on busy nodes with many
				// netlink events. The periodic sync is a hard safety net.
				if !ok {
					klog.Warning("NetlinkDeviceManager: link channel closed, resubscribing")
					linkChan = subscribeLinkEvents(stopCh, onSubscribeError)
					if linkChan != nil {
						c.reconciler.Reconcile(fullSyncKey)
					}
					continue
				}
				c.handleLinkUpdate(update)

			case update, ok := <-addrChan:
				if !ok {
					klog.Warning("NetlinkDeviceManager: addr channel closed, resubscribing")
					addrChan = subscribeAddrEvents(stopCh, onSubscribeError)
					if addrChan != nil {
						c.reconciler.Reconcile(fullSyncKey)
					}
					continue
				}
				c.handleAddrUpdate(update)

			case <-syncTimer.C:
				var resubscribed bool
				if linkChan == nil {
					linkChan = subscribeLinkEvents(stopCh, onSubscribeError)
					if linkChan != nil {
						resubscribed = true
					}
				}
				if addrChan == nil {
					addrChan = subscribeAddrEvents(stopCh, onSubscribeError)
					if addrChan != nil {
						resubscribed = true
					}
				}
				if resubscribed {
					c.reconciler.Reconcile(fullSyncKey)
				} else {
					c.reconciler.Reconcile(syncKey)
				}

			case <-stopCh:
				klog.Info("NetlinkDeviceManager: stopping")
				return
			}
		}
	}()

	klog.Info("NetlinkDeviceManager: running")
	return nil
}

// handleLinkUpdate enqueues reconciliation for devices affected by a netlink event.
// The update's Header.Type distinguishes create/update (unix.RTM_NEWLINK) from
// delete (unix.RTM_DELLINK), enabling two optimizations:
//   - Blocked devices are only re-queued on delete (the external conflict can only
//     resolve when the blocking device disappears).
//   - Ready devices whose event link already matches the desired state are skipped
//     (avoids redundant reconciliation after self-triggered changes).
func (c *Controller) handleLinkUpdate(update netlink.LinkUpdate) {
	linkName := update.Link.Attrs().Name
	klog.V(5).Infof("NetlinkDeviceManager: link event for %s (nlmsg_type=%d)", linkName, update.Header.Type)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if d, exists := c.store[linkName]; exists {
		needsReconcile := true
		if update.Header.Type != unix.RTM_DELLINK {
			switch d.state {
			case deviceStateBlocked:
				needsReconcile = false
				klog.V(5).Infof("NetlinkDeviceManager: skipping non-delete event for blocked device %s", linkName)
			case deviceStateReady:
				if eventLinkMatchesDesired(update.Link, d) {
					needsReconcile = false
					klog.V(5).Infof("NetlinkDeviceManager: skipping no-drift event for ready device %s", linkName)
				}
			}
		}
		if needsReconcile {
			c.reconciler.Reconcile(deviceKeyPrefix + linkName)
		}
	}

	// Queue devices that depend on this link.
	for name, device := range c.store {
		// Skip failed devices, they are already in rate-limited backoff.
		if device.state != deviceStateFailed {
			if device.cfg.Master == linkName || device.cfg.VLANParent == linkName {
				c.reconciler.Reconcile(deviceKeyPrefix + name)
			}
		}
	}
}

// eventLinkMatchesDesired performs a fast comparison of a netlink event's Link
// against the desired DeviceConfig, covering link-level attributes only.
//
// This function is intentionally composed from the same building blocks the
// reconciler uses so that adding a field to any building block automatically
// covers both paths.
// The remaining checks (FlagUp, master presence) are one-off checks unlikely to
// grow new fields.
func eventLinkMatchesDesired(event netlink.Link, d *managedDevice) bool {
	cfg := &d.cfg
	// needsLinkModify covers alias + linkMutableFieldsMatch — the same
	// check the reconciler uses to decide whether to call LinkModify.
	if needsLinkModify(event, cfg) {
		return false
	}
	if _, criticalMatch := fieldsMatch(event, cfg.Link); !criticalMatch {
		return false
	}
	if event.Attrs().Flags&net.FlagUp == 0 {
		return false
	}
	// Compare against the master's ifindex recorded at last successful
	// reconciliation.
	if event.Attrs().MasterIndex != d.masterIfindex {
		return false
	}
	// Bridge port setting changes include IFLA_PROTINFO in the RTM_NEWLINK
	// event. When present, compare against desired; when absent, the event
	// was about link-level attributes and bridge port settings were not
	// modified.
	if cfg.BridgePortSettings != nil {
		if pi := event.Attrs().Protinfo; pi != nil {
			if !bridgePortSettingsMatch(pi, cfg.BridgePortSettings) {
				return false
			}
		}
	}
	return true
}

// handleAddrUpdate enqueues reconciliation for a device affected by an address change.
//
// AddrUpdate only carries LinkIndex, so we match it against ifindexes tracked in
// the store (populated during reconciliation).
func (c *Controller) handleAddrUpdate(update netlink.AddrUpdate) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for name, device := range c.store {
		if device.ifindex > 0 && device.ifindex == update.LinkIndex {
			klog.V(5).Infof("NetlinkDeviceManager: addr update for %s (ifindex %d)", name, update.LinkIndex)
			c.reconciler.Reconcile(deviceKeyPrefix + name)
			return
		}
	}
}

// requireLink looks up a netlink device by name, returning a DependencyError if missing.
func requireLink(name string) (netlink.Link, error) {
	link, err := util.GetNetLinkOps().LinkByName(name)
	if err != nil {
		if util.GetNetLinkOps().IsLinkNotFoundError(err) {
			return nil, &DependencyError{Dependency: name, Reason: "not found"}
		}
		return nil, err
	}
	return link, nil
}

// resolveDependencies validates and resolves name-based dependencies to ifindices.
// Callers must ensure cfg.Link can be safely mutated.
// Returns DependencyError if a required dependency doesn't exist yet.
func resolveDependencies(cfg *DeviceConfig) error {
	vlan, isVlan := cfg.Link.(*netlink.Vlan)

	if !isVlan && cfg.VLANParent != "" {
		return fmt.Errorf("invalid DeviceConfig: VLANParent set but Link is %T, not *netlink.Vlan", cfg.Link)
	}
	if isVlan && cfg.VLANParent == "" {
		return fmt.Errorf("invalid DeviceConfig: VLAN %q requires VLANParent", cfg.deviceName())
	}

	if cfg.Master != "" {
		if _, err := requireLink(cfg.Master); err != nil {
			return fmt.Errorf("master: %w", err)
		}
	}

	if isVlan {
		parent, err := requireLink(cfg.VLANParent)
		if err != nil {
			return fmt.Errorf("VLAN parent: %w", err)
		}
		vlan.ParentIndex = parent.Attrs().Index
	}

	return nil
}

// applyDeviceConfig creates or updates a single device in the kernel.
// Returns (ifindex, masterIfindex, err):
//   - ifindex: kernel-assigned interface index (>0 on success, 0 on error)
//   - masterIfindex: master's kernel ifindex after reconciliation (0 if no master)
//
// Ownership rules:
//   - If device doesn't exist: create it with our alias
//   - If device exists with our alias: update or recreate as needed
//   - If device exists without our alias: return NotOwnedError (could be human-created)
func applyDeviceConfig(cfg *DeviceConfig) (int, int, error) {
	name := cfg.deviceName()
	// Resolve all dependencies first. For the delete-then-recreate path, this ensures
	// we never delete an existing device unless all dependencies are present to recreate it.
	// For new devices, early failure here is equivalent to failure in createDevice() -
	// both return DependencyError and mark the config pending. But for existing devices,
	// failing after delete would leave us in a worse state (device gone, can't recreate).
	if err := resolveDependencies(cfg); err != nil {
		return 0, 0, err
	}
	// Check if device already exists
	link, err := util.GetNetLinkOps().LinkByName(name)
	if err == nil {
		// Device exists - verify ownership before modifying
		if err := checkOwnership(link); err != nil {
			return 0, 0, err
		}

		// Check for critical mismatches (immutable attributes that require recreate)
		if _, criticalMatch := fieldsMatch(link, cfg.Link); !criticalMatch {
			klog.Warningf("NetlinkDeviceManager: device %s has critical config drift, recreating: existing=%+v desired=%+v",
				name, buildManagedLink(link), buildManagedLink(cfg.Link))
			if err := util.GetNetLinkOps().LinkDelete(link); err != nil {
				return 0, 0, fmt.Errorf("failed to delete mismatched device %s: %w", name, err)
			}
			// Fall through to create
		} else {
			// Device exists with correct critical attrs, update mutable attrs
			masterIfindex, err := updateDevice(link, cfg)
			return link.Attrs().Index, masterIfindex, err
		}
	} else if !util.GetNetLinkOps().IsLinkNotFoundError(err) {
		return 0, 0, fmt.Errorf("failed to check device %s: %w", name, err)
	}

	// Device doesn't exist (or was just deleted), create it
	return createDevice(cfg)
}

// createDevice creates a new netlink device.
// Returns (ifindex, masterIfindex, err) where ifindex is the kernel-assigned
// interface index and masterIfindex is the master's ifindex (0 if no master).
// Preconditions:
//   - Master (if specified) has been validated to exist
//   - VLANParent (if specified) has been resolved to ParentIndex
//     or alternatively ParentIndex (if specified) has been validated to exist
func createDevice(cfg *DeviceConfig) (int, int, error) {
	name := cfg.deviceName()
	masterIfindex := 0

	link, err := createLink(cfg)
	if err != nil {
		return 0, 0, err
	}

	// Set master if specified (Master existence already validated by resolveDependencies,
	// but it could be deleted between validation and now - treat as DependencyError for retry)
	if cfg.Master != "" {
		masterLink, err := util.GetNetLinkOps().LinkByName(cfg.Master)
		if err != nil {
			if util.GetNetLinkOps().IsLinkNotFoundError(err) {
				return 0, 0, &DependencyError{Dependency: cfg.Master, Reason: "master not found (deleted after validation)"}
			}
			return 0, 0, fmt.Errorf("failed to find master %s for device %s: %w", cfg.Master, name, err)
		}
		masterIfindex = masterLink.Attrs().Index
		if err := util.GetNetLinkOps().LinkSetMaster(link, masterLink); err != nil {
			return 0, 0, fmt.Errorf("failed to set master %s for device %s: %w", cfg.Master, name, err)
		}
		klog.V(5).Infof("NetlinkDeviceManager: set master %s for device %s", cfg.Master, name)

		// Apply bridge port settings after attaching to master (required for settings to take effect)
		if cfg.BridgePortSettings != nil {
			if err := applyBridgePortSettings(link, *cfg.BridgePortSettings); err != nil {
				return 0, 0, fmt.Errorf("failed to apply bridge port settings for %s: %w", name, err)
			}
			klog.V(5).Infof("NetlinkDeviceManager: applied bridge port settings for device %s", name)
		}
	}

	// Sync addresses if configured
	if err := syncAddresses(link, cfg); err != nil {
		return 0, 0, err
	}

	// Sync VID/VNI mappings (VXLAN bridge ports only)
	if err := syncVIDVNIMappings(link, cfg); err != nil {
		return 0, 0, err
	}

	// Bring the device up last: the device was created in DOWN state
	// so all configuration above is applied while no traffic can
	// flow through it. Bringing it up only after fully configured.
	if err := ensureDeviceUp(link); err != nil {
		return 0, 0, err
	}

	klog.V(5).Infof("NetlinkDeviceManager: created device %s", name)
	return link.Attrs().Index, masterIfindex, nil
}

// updateDevice updates an existing device to match config.
// Returns (modified, err) where modified indicates whether kernel state was
// actually changed.
//
// Preconditions:
//   - Caller has verified ownership (device has our alias)
//   - Master (if specified) has been validated to exist
//
// This function reconciles mutable attributes that can be updated in-place:
//   - LinkAttrs (Alias, MTU, TxQLen, HardwareAddr, etc.) via LinkModify
//   - Master via LinkSetMaster (not handled by LinkModify)
//   - BridgePortSettings via bridge API (not handled by LinkModify)
//   - Up state via LinkSetUp
//
// Immutable attributes (VNI, SrcAddr, VlanId, etc.) are handled by fieldsMatch
// (criticalMatch), which triggers delete+recreate instead.
func updateDevice(link netlink.Link, cfg *DeviceConfig) (int, error) {
	name := cfg.deviceName()
	currentAttrs := link.Attrs()
	masterIfindex := 0

	// Only call LinkModify if there are actual differences to apply.
	// This prevents unnecessary netlink events.
	if needsLinkModify(link, cfg) {
		modifiedLink := prepareLinkForModify(link, cfg)
		if err := util.GetNetLinkOps().LinkModify(modifiedLink); err != nil {
			return 0, fmt.Errorf("failed to modify link %s: %w", name, err)
		}
		klog.V(5).Infof("NetlinkDeviceManager: applied LinkModify for device %s", name)
	}

	// Check and update master (not handled by LinkModify).
	// Master existence already validated by preconditions, but it could be deleted
	// between validation and now - treat as DependencyError for retry.
	if cfg.Master != "" {
		masterLink, err := util.GetNetLinkOps().LinkByName(cfg.Master)
		if err != nil {
			if util.GetNetLinkOps().IsLinkNotFoundError(err) {
				return 0, &DependencyError{Dependency: cfg.Master, Reason: "master not found (deleted after validation)"}
			}
			return 0, fmt.Errorf("failed to find master %s: %w", cfg.Master, err)
		}
		masterIfindex = masterLink.Attrs().Index
		if currentAttrs.MasterIndex != masterIfindex {
			// Bring device down before master change to avoid having traffic flowing
			// through the device during intermediate states.
			if err := util.GetNetLinkOps().LinkSetDown(link); err != nil {
				return 0, fmt.Errorf("failed to set link %s down before master change: %w", name, err)
			}
			if err := util.GetNetLinkOps().LinkSetMaster(link, masterLink); err != nil {
				return 0, fmt.Errorf("failed to set master %s for device %s: %w", cfg.Master, name, err)
			}
			klog.V(5).Infof("NetlinkDeviceManager: updated master %s for device %s", cfg.Master, name)
		}
		// Apply bridge port settings if configured (not handled by LinkModify).
		if err := ensureBridgePortSettings(link, cfg); err != nil {
			return 0, err
		}
	} else if currentAttrs.MasterIndex != 0 {
		// Desired config has no master, but device is currently attached to one.
		// Detach to match the declarative "no master" intent.
		if err := util.GetNetLinkOps().LinkSetNoMaster(link); err != nil {
			return 0, fmt.Errorf("failed to detach %s from master: %w", name, err)
		}
		klog.V(5).Infof("NetlinkDeviceManager: detached device %s from master (ifindex %d)", name, currentAttrs.MasterIndex)
	}

	// Sync addresses if configured
	if err := syncAddresses(link, cfg); err != nil {
		return 0, err
	}

	// Sync VID/VNI mappings (VXLAN bridge ports only)
	if err := syncVIDVNIMappings(link, cfg); err != nil {
		return 0, err
	}

	// Bring device up.
	// For already-up devices (no master change) this is a no-op.
	if err := ensureDeviceUp(link); err != nil {
		return 0, err
	}

	return masterIfindex, nil
}

// needsLinkModify checks if any mutable attributes differ between current link and desired config.
// Returns true if LinkModify should be called to reconcile differences.
// This prevents unnecessary LinkModify calls that would trigger netlink events.
func needsLinkModify(current netlink.Link, cfg *DeviceConfig) bool {
	if current.Attrs().Alias != cfg.alias() {
		return true
	}
	return !linkMutableFieldsMatch(current, cfg.Link)
}

// prepareLinkForModify creates a Link object suitable for LinkModify.
// Delegates to buildManagedLink (all managed fields) and adds Index + Alias.
// Including immutable fields that match the existing device is safe,
// the kernel treats matching immutable fields as no-ops.
func prepareLinkForModify(existing netlink.Link, cfg *DeviceConfig) netlink.Link {
	result := buildManagedLink(cfg.Link)
	result.Attrs().Index = existing.Attrs().Index
	result.Attrs().Alias = cfg.alias()
	return result
}

// deleteDevice removes a device from the kernel.
// Only deletes devices that have our alias prefix (ownership check).
func deleteDevice(name string) error {
	link, err := util.GetNetLinkOps().LinkByName(name)
	if err != nil {
		if util.GetNetLinkOps().IsLinkNotFoundError(err) {
			return nil // Already gone
		}
		return fmt.Errorf("failed to find device %s for deletion: %w", name, err)
	}

	// Safety check - only delete if it's ours
	if err := checkOwnership(link); err != nil {
		return err
	}

	if err := util.GetNetLinkOps().LinkDelete(link); err != nil {
		return fmt.Errorf("failed to delete device %s: %w", name, err)
	}
	klog.V(5).Infof("NetlinkDeviceManager: deleted device %s", name)
	return nil
}

// createLink creates a netlink device with our ownership alias and returns
// the created link with kernel-assigned attributes (ifindex, etc.).
//
// The alias is set via a dedicated LinkSetAlias call after
// LinkAdd because the kernel's newlink does not process alias.
// See https://github.com/torvalds/linux/blob/v7.0-rc2/Documentation/netlink/specs/rt-link.yaml#L2384-L2412:
// ifalias is not listed as a valid newlink request attribute.
// If alias-setting fails, the device is rolled back (deleted) to avoid
// leaving an unowned device in the kernel.
func createLink(cfg *DeviceConfig) (netlink.Link, error) {
	name := cfg.deviceName()
	// Strip FlagUp so the device is always created in DOWN state.
	cfg.Link.Attrs().Flags &^= net.FlagUp
	if err := util.GetNetLinkOps().LinkAdd(cfg.Link); err != nil {
		return nil, fmt.Errorf("failed to create device %s: %w", name, err)
	}
	// Fetch the created device to get kernel-assigned attributes
	link, err := util.GetNetLinkOps().LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get created device %s: %w", name, err)
	}
	if err := util.GetNetLinkOps().LinkSetAlias(link, cfg.alias()); err != nil {
		klog.Errorf("NetlinkDeviceManager: failed to set alias on %s, rolling back: %v", name, err)
		if delErr := util.GetNetLinkOps().LinkDelete(link); delErr != nil {
			klog.Errorf("NetlinkDeviceManager: rollback failed, device %s may be orphaned: %v", name, delErr)
		}
		return nil, fmt.Errorf("failed to set alias on device %s: %w", name, err)
	}
	return link, nil
}

// ensureDeviceUp brings a device up. LinkSetUp is idempotent so no
// need to check current state first.
func ensureDeviceUp(link netlink.Link) error {
	if err := util.GetNetLinkOps().LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set link %s up: %w", link.Attrs().Name, err)
	}
	return nil
}

// syncAddresses ensures the device has exactly the desired addresses.
// If cfg.Addresses is nil, no address management is performed (existing addresses preserved).
// Link-local addresses (fe80::/10) are never removed automatically.
func syncAddresses(currentLink netlink.Link, cfg *DeviceConfig) error {
	if cfg.Addresses == nil {
		return nil // No address management requested
	}

	nlOps := util.GetNetLinkOps()
	name := currentLink.Attrs().Name

	current, err := nlOps.AddrList(currentLink, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list addresses on %s: %w", name, err)
	}

	// Build lookup maps (key = "IP/prefix") and compute diff using sets
	desiredMap := addrListToMap(cfg.Addresses)
	currentMap := addrListToMap(current)

	desiredKeys := sets.KeySet(desiredMap)
	currentKeys := sets.KeySet(currentMap)

	toAdd := desiredKeys.Difference(currentKeys)
	toRemove := currentKeys.Difference(desiredKeys)

	var errs []error

	for key := range toAdd {
		addr := desiredMap[key]
		if err := nlOps.AddrAdd(currentLink, addr); err != nil {
			// EEXIST is fine - address already exists (race or concurrent add)
			if !nlOps.IsAlreadyExistsError(err) {
				errs = append(errs, fmt.Errorf("failed to add address %s to %s: %w", key, name, err))
				continue
			}
		}
		klog.V(5).Infof("NetlinkDeviceManager: added address %s to %s", key, name)
	}

	for key := range toRemove {
		addr := currentMap[key]
		if isLinkLocalAddress(addr.IP) {
			continue // Never remove link-local addresses
		}
		if err := nlOps.AddrDel(currentLink, addr); err != nil {
			// EADDRNOTAVAIL/ENOENT is fine - address already gone
			if !nlOps.IsEntryNotFoundError(err) {
				errs = append(errs, fmt.Errorf("failed to remove address %s from %s: %w", key, name, err))
				continue
			}
		}
		klog.V(5).Infof("NetlinkDeviceManager: removed address %s from %s", key, name)
	}

	if len(errs) > 0 {
		return fmt.Errorf("address sync errors on %s: %w", name, utilerrors.Join(errs...))
	}
	return nil
}

// addrListToMap converts a slice of addresses to a map keyed by IPNet string.
func addrListToMap(addrs []netlink.Addr) map[string]*netlink.Addr {
	result := make(map[string]*netlink.Addr, len(addrs))
	for i := range addrs {
		addr := &addrs[i]
		if addr.IPNet != nil {
			result[addr.IPNet.String()] = addr
		}
	}
	return result
}

// isLinkLocalAddress returns true for link-local addresses (IPv6 fe80::/10 or IPv4 169.254.0.0/16).
// These addresses are kernel-managed and should not be removed automatically.
func isLinkLocalAddress(ip net.IP) bool {
	return ip != nil && ip.IsLinkLocalUnicast()
}

// syncVIDVNIMappings ensures the VXLAN device has exactly the desired VID/VNI mappings.
// If cfg.VIDVNIMappings is nil, no mapping management is performed.
//
// Each mapping requires four independent kernel entries:
//   - Bridge self VLAN — the bridge's own VLAN filter (on the bridge device)
//   - VXLAN VID membership — the port VLAN filter (on the VXLAN bridge port)
//   - VNI filter entry — allowed VNIs (on the VXLAN device)
//   - Tunnel info — the VID→VNI mapping (on the VXLAN bridge port)
//
// All four are queried to build a complete picture; only mappings with at least
// one missing entry are re-applied (addVIDVNIMapping handles EEXIST for the
// intact entries). This self-heals against external removal of any individual
// entry without redundantly re-applying fully intact mappings.
func syncVIDVNIMappings(link netlink.Link, cfg *DeviceConfig) error {
	if cfg.VIDVNIMappings == nil {
		return nil
	}
	if cfg.Master == "" {
		return nil
	}

	nlOps := util.GetNetLinkOps()
	name := link.Attrs().Name

	bridgeLink, err := nlOps.LinkByName(cfg.Master)
	if err != nil {
		if nlOps.IsLinkNotFoundError(err) {
			return &DependencyError{Dependency: cfg.Master, Reason: "bridge not found for VID/VNI mappings"}
		}
		return fmt.Errorf("failed to get bridge %s for mappings: %w", cfg.Master, err)
	}

	tunnelMappings, err := getVIDVNIMappings(link)
	if err != nil {
		return fmt.Errorf("failed to read tunnel info for %s: %w", name, err)
	}

	vlanList, err := nlOps.BridgeVlanList()
	if err != nil {
		return fmt.Errorf("failed to read bridge VLAN list: %w", err)
	}

	vniList, err := nlOps.BridgeVniList()
	if err != nil {
		return fmt.Errorf("failed to read VNI filter list: %w", err)
	}

	vxlanIdx := int32(link.Attrs().Index)
	toAdd, toRemove := diffVIDVNIMappings(
		cfg.VIDVNIMappings,
		tunnelMappings,
		extractVIDs(vlanList[int32(bridgeLink.Attrs().Index)]),
		extractVIDs(vlanList[vxlanIdx]),
		extractVNIs(vniList[vxlanIdx]),
	)

	var errs []error

	for _, mapping := range toRemove {
		if err := removeVIDVNIMapping(bridgeLink, link, mapping); err != nil {
			klog.Warningf("NetlinkDeviceManager: failed to remove mapping VID=%d VNI=%d from %s: %v",
				mapping.VID, mapping.VNI, name, err)
			errs = append(errs, err)
		}
	}

	for _, mapping := range toAdd {
		if err := addVIDVNIMapping(bridgeLink, link, mapping); err != nil {
			klog.Warningf("NetlinkDeviceManager: failed to add mapping VID=%d VNI=%d on %s: %v",
				mapping.VID, mapping.VNI, name, err)
			errs = append(errs, err)
		}
	}

	if len(toAdd) > 0 || len(toRemove) > 0 {
		klog.V(5).Infof("NetlinkDeviceManager: VID/VNI mappings synced for %s (added=%d, removed=%d, errors=%d)",
			name, len(toAdd), len(toRemove), len(errs))
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to apply %d mappings on %s: %w", len(errs), name, utilerrors.Join(errs...))
	}
	return nil
}

// getVIDVNIMappings retrieves current VID/VNI mappings for a VXLAN device.
func getVIDVNIMappings(link netlink.Link) ([]VIDVNIMapping, error) {
	nlOps := util.GetNetLinkOps()
	name := link.Attrs().Name

	tunnels, err := nlOps.BridgeVlanTunnelShowDev(link)
	if err != nil {
		klog.V(5).Infof("NetlinkDeviceManager: could not get tunnel info for %s: %v", name, err)
		return nil, err
	}

	var mappings []VIDVNIMapping
	for _, t := range tunnels {
		if t.TunId > 0 {
			mappings = append(mappings, VIDVNIMapping{
				VID: t.Vid,
				VNI: t.TunId,
			})
		}
	}

	klog.V(5).Infof("NetlinkDeviceManager: found %d existing VID/VNI mappings on %s", len(mappings), name)
	return mappings, nil
}

// extractVIDs returns the set of VIDs from a BridgeVlanInfo slice.
func extractVIDs(infos []*nl.BridgeVlanInfo) sets.Set[uint16] {
	s := sets.New[uint16]()
	for _, info := range infos {
		s.Insert(info.Vid)
	}
	return s
}

// extractVNIs returns the set of VNIs from a BridgeVniInfo slice.
// Handles both single entries and ranges (VniEnd > 0).
func extractVNIs(infos []*nl.BridgeVniInfo) sets.Set[uint32] {
	s := sets.New[uint32]()
	for _, info := range infos {
		end := max(info.VniEnd, info.Vni)
		for vni := info.Vni; vni <= end; vni++ {
			s.Insert(vni)
		}
	}
	return s
}

// diffVIDVNIMappings computes which mappings need to be added or removed.
// Returns two slices:
//   - toRemove: tunnel info entries not in desired (stale mappings).
//   - toAdd: desired mappings where any of the four kernel entries is missing.
//
// Known limitation: toRemove is derived solely from tunnel-info (the "current"
// parameter). If tunnel-info for a mapping is externally removed and that
// mapping is later removed from the desired set, the remaining three kernel
// entries (bridge self VLAN, VXLAN port VID, VNI filter) become orphaned.
// This is because the Linux kernel provides no ownership marker for
// bridge VLAN/VNI entries, so we cannot distinguish entries we created from
// entries added by other systems.
func diffVIDVNIMappings(desired, current []VIDVNIMapping,
	bridgeSelfVIDs, vxlanPortVIDs sets.Set[uint16],
	activeVNIs sets.Set[uint32]) (toAdd, toRemove []VIDVNIMapping) {

	currentSet := sets.New(current...)
	desiredSet := sets.New(desired...)
	toRemove = currentSet.Difference(desiredSet).UnsortedList()

	for _, m := range desired {
		if !isMappingFullyPresent(m, bridgeSelfVIDs, vxlanPortVIDs, activeVNIs, currentSet) {
			toAdd = append(toAdd, m)
		}
	}
	return toAdd, toRemove
}

func isMappingFullyPresent(m VIDVNIMapping, bridgeSelfVIDs, vxlanPortVIDs sets.Set[uint16], activeVNIs sets.Set[uint32], currentSet sets.Set[VIDVNIMapping]) bool {
	return bridgeSelfVIDs.Has(m.VID) &&
		vxlanPortVIDs.Has(m.VID) &&
		activeVNIs.Has(m.VNI) &&
		currentSet.Has(m)
}

// validateMappings checks VID/VNI ranges and uniqueness constraints.
// Range: VID [1, 4094], VNI [1, 16777215].
// Uniqueness is required because:
//   - Two VIDs mapping to the same VNI would cause removeVIDVNIMapping to delete the VNI filter
//     entry still needed by the other VID
//   - Duplicate VIDs would be ambiguous
const maxVNI = 1<<24 - 1 // 16777215

func validateMappings(mappings []VIDVNIMapping) error {
	seenVIDs := make(map[uint16]bool)
	seenVNIs := make(map[uint32]bool)

	for _, m := range mappings {
		if m.VID < 1 || m.VID > 4094 {
			return fmt.Errorf("VID %d out of valid range [1, 4094]", m.VID)
		}
		if m.VNI < 1 || m.VNI > maxVNI {
			return fmt.Errorf("VNI %d out of valid range [1, %d]", m.VNI, maxVNI)
		}
		if seenVIDs[m.VID] {
			return fmt.Errorf("duplicate VID %d", m.VID)
		}
		if seenVNIs[m.VNI] {
			return fmt.Errorf("duplicate VNI %d", m.VNI)
		}
		seenVIDs[m.VID] = true
		seenVNIs[m.VNI] = true
	}
	return nil
}

// addVIDVNIMapping adds a VID/VNI mapping to a VXLAN device.
// This function does NOT hold any locks - caller must ensure thread safety.
func addVIDVNIMapping(bridgeLink, vxlanLink netlink.Link, m VIDVNIMapping) error {
	nlOps := util.GetNetLinkOps()

	// 1. Add VID to bridge with 'self' flag
	// This is required for the bridge to recognize the VLAN
	if err := nlOps.BridgeVlanAdd(bridgeLink, m.VID, false, false, true, false); err != nil {
		if !nlOps.IsAlreadyExistsError(err) {
			return fmt.Errorf("failed to add VID %d to bridge self: %w", m.VID, err)
		}
	}

	// 2. Add VID to VXLAN with 'master' flag
	if err := nlOps.BridgeVlanAdd(vxlanLink, m.VID, false, false, false, true); err != nil {
		if !nlOps.IsAlreadyExistsError(err) {
			return fmt.Errorf("failed to add VID %d to VXLAN: %w", m.VID, err)
		}
	}

	// 3. Add VNI to VNI filter
	// IMPORTANT: VNI must be explicitly added when VNI filtering is enabled
	if err := nlOps.BridgeVniAdd(vxlanLink, m.VNI); err != nil {
		if !nlOps.IsAlreadyExistsError(err) {
			return fmt.Errorf("failed to add VNI %d: %w", m.VNI, err)
		}
	}

	// 4. Add tunnel info (VID -> VNI mapping)
	if err := nlOps.BridgeVlanAddTunnelInfo(vxlanLink, m.VID, m.VNI, false, true); err != nil {
		if !nlOps.IsAlreadyExistsError(err) {
			return fmt.Errorf("failed to add VID->VNI mapping: %w", err)
		}
	}

	return nil
}

// removeVIDVNIMapping removes a VID/VNI mapping from a VXLAN device.
// Symmetric with addVIDVNIMapping: removes all four kernel entries in
// reverse order (tunnel info, VNI filter, VXLAN VID, bridge self VLAN).
//
// The bridge self VLAN removal is safe because the SVD (Single VXLAN Device)
// architecture guarantees exactly one VXLAN per bridge, and each VID is
// unique per network — no sibling device can reference the same VID.
//
// This function does NOT hold any locks - caller must ensure thread safety.
func removeVIDVNIMapping(bridgeLink, vxlanLink netlink.Link, m VIDVNIMapping) error {
	nlOps := util.GetNetLinkOps()

	var errs []error

	// Remove tunnel_info mapping
	if err := nlOps.BridgeVlanDelTunnelInfo(vxlanLink, m.VID, m.VNI, false, true); err != nil {
		if !nlOps.IsEntryNotFoundError(err) {
			errs = append(errs, fmt.Errorf("tunnel_info VID=%d->VNI=%d: %w", m.VID, m.VNI, err))
		}
	}

	// Remove VNI from VNI filter
	if err := nlOps.BridgeVniDel(vxlanLink, m.VNI); err != nil {
		if !nlOps.IsEntryNotFoundError(err) {
			errs = append(errs, fmt.Errorf("VNI %d: %w", m.VNI, err))
		}
	}

	// Remove VID from VXLAN
	if err := nlOps.BridgeVlanDel(vxlanLink, m.VID, false, false, false, true); err != nil {
		if !nlOps.IsEntryNotFoundError(err) {
			errs = append(errs, fmt.Errorf("VXLAN VID %d: %w", m.VID, err))
		}
	}

	// Remove VID from bridge self
	if err := nlOps.BridgeVlanDel(bridgeLink, m.VID, false, false, true, false); err != nil {
		if !nlOps.IsEntryNotFoundError(err) {
			errs = append(errs, fmt.Errorf("bridge self VID %d: %w", m.VID, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to remove mapping from %s: %w", vxlanLink.Attrs().Name, utilerrors.Join(errs...))
	}
	return nil
}

// ensureBridgePortSettings applies bridge port settings if they differ from current.
//
// Compare-then-write is required because the kernel emits RTM_NEWLINK even
// for no-op writes (e.g. setting Learning=false when it is already false).
// Without the comparison, every reconciliation would trigger notifications
// which would trigger an infinite loop.
func ensureBridgePortSettings(link netlink.Link, cfg *DeviceConfig) error {
	if cfg.BridgePortSettings == nil {
		return nil
	}

	name := link.Attrs().Name

	// LinkGetProtinfo performs an AF_BRIDGE dump. link.Attrs().Protinfo is
	// not populated by LinkByName (only by event deserialization).
	protinfo, err := util.GetNetLinkOps().LinkGetProtinfo(link)
	if err != nil {
		return fmt.Errorf("failed to read bridge port settings for %s: %w", name, err)
	}

	if !bridgePortSettingsMatch(&protinfo, cfg.BridgePortSettings) {
		if err := applyBridgePortSettings(link, *cfg.BridgePortSettings); err != nil {
			return fmt.Errorf("failed to apply bridge port settings for %s: %w", name, err)
		}
		klog.V(5).Infof("NetlinkDeviceManager: applied bridge port settings for device %s", name)
	}

	return nil
}

// bridgePortSettingsMatch reports whether a kernel Protinfo matches the
// desired BridgePortSettings. This is the single source of truth for which
// Protinfo fields map to BridgePortSettings fields.
func bridgePortSettingsMatch(pi *netlink.Protinfo, desired *BridgePortSettings) bool {
	return pi.Learning == desired.Learning &&
		pi.NeighSuppress == desired.NeighSuppress &&
		pi.VlanTunnel == desired.VLANTunnel &&
		pi.Isolated == desired.Isolated
}

// applyBridgePortSettings sets bridge port settings.
func applyBridgePortSettings(link netlink.Link, settings BridgePortSettings) error {
	nlOps := util.GetNetLinkOps()
	name := link.Attrs().Name

	// Set VLAN tunnel mode
	if err := nlOps.LinkSetVlanTunnel(link, settings.VLANTunnel); err != nil {
		return fmt.Errorf("failed to set vlan_tunnel on %s: %w", name, err)
	}

	// Set neighbor suppress mode
	if err := nlOps.LinkSetBrNeighSuppress(link, settings.NeighSuppress); err != nil {
		return fmt.Errorf("failed to set neigh_suppress on %s: %w", name, err)
	}

	// Set learning mode
	if err := nlOps.LinkSetLearning(link, settings.Learning); err != nil {
		return fmt.Errorf("failed to set learning on %s: %w", name, err)
	}

	// Set isolated mode
	if err := nlOps.LinkSetIsolated(link, settings.Isolated); err != nil {
		return fmt.Errorf("failed to set isolated on %s: %w", name, err)
	}

	return nil
}

// deviceName extracts the device name from a DeviceConfig
func (cfg *DeviceConfig) deviceName() string {
	if cfg.Link == nil {
		return ""
	}
	return cfg.Link.Attrs().Name
}

// alias generates the ownership alias for this device.
// Format: "ovn-k8s-ndm:<type>:<name>" for debugging and collision avoidance.
func (cfg *DeviceConfig) alias() string {
	linkType := "unknown"
	if cfg.Link != nil {
		linkType = cfg.Link.Type()
	}
	return managedAliasPrefix + linkType + ":" + cfg.deviceName()
}

// fieldsMatch is the source of truth for comparing managed link fields.
// It classifies each managed field difference as mutable, critical, or both,
// returning two booleans in one pass.
//
// Directional: fieldsMatch(a, b) does NOT imply fieldsMatch(b, a).
// Zero-valued fields in desired are treated as "unspecified, don't care".

// eventLinkMatchesDesired and applyDeviceConfig call fieldsMatch directly
// for critical checks, so adding a field automatically covers both paths.
// Tests enforce these invariants.
func fieldsMatch(current, desired netlink.Link) (mutableMatch, criticalMatch bool) {
	mutableMatch = true
	criticalMatch = true

	if current.Type() != desired.Type() {
		criticalMatch = false
		return
	}

	curAttrs := current.Attrs()
	desAttrs := desired.Attrs()

	// Common mutable LinkAttrs
	if desAttrs.MTU != 0 && curAttrs.MTU != desAttrs.MTU {
		mutableMatch = false
	}
	if desAttrs.TxQLen >= 0 && curAttrs.TxQLen != desAttrs.TxQLen {
		mutableMatch = false
	}
	if len(desAttrs.HardwareAddr) > 0 && !bytes.Equal(curAttrs.HardwareAddr, desAttrs.HardwareAddr) {
		mutableMatch = false
	}

	switch des := desired.(type) {
	case *netlink.Vxlan:
		cur, ok := current.(*netlink.Vxlan)
		if !ok {
			return
		}
		if cur.Learning != des.Learning {
			mutableMatch = false
		}
		if cur.VxlanId != des.VxlanId {
			criticalMatch = false
		}
		if des.SrcAddr != nil && (cur.SrcAddr == nil || !cur.SrcAddr.Equal(des.SrcAddr)) {
			criticalMatch = false
		}
		if des.Port > 0 && cur.Port != des.Port {
			criticalMatch = false
		}
		if cur.FlowBased != des.FlowBased {
			criticalMatch = false
		}
		if cur.VniFilter != des.VniFilter {
			criticalMatch = false
		}

	case *netlink.Bridge:
		cur, ok := current.(*netlink.Bridge)
		if !ok {
			return
		}
		if des.VlanFiltering != nil && !ptr.Equal(cur.VlanFiltering, des.VlanFiltering) {
			mutableMatch = false
			criticalMatch = false
		}
		if des.VlanDefaultPVID != nil && !ptr.Equal(cur.VlanDefaultPVID, des.VlanDefaultPVID) {
			mutableMatch = false
			criticalMatch = false
		}

	case *netlink.Vrf:
		cur, ok := current.(*netlink.Vrf)
		if !ok {
			return
		}
		if cur.Table != des.Table {
			criticalMatch = false
		}

	case *netlink.Vlan:
		cur, ok := current.(*netlink.Vlan)
		if !ok {
			return
		}
		if cur.VlanId != des.VlanId {
			criticalMatch = false
		}
		if des.ParentIndex > 0 && cur.ParentIndex != des.ParentIndex {
			criticalMatch = false
		}
		if des.VlanProtocol != 0 && cur.VlanProtocol != des.VlanProtocol {
			criticalMatch = false
		}
		desMAC := des.Attrs().HardwareAddr
		if len(desMAC) > 0 && !bytes.Equal(cur.Attrs().HardwareAddr, desMAC) {
			criticalMatch = false
		}

	case *netlink.Dummy:
		// No type-specific fields

	default:
		panic(fmt.Sprintf("BUG: unsupported device type %T for fieldsMatch", desired))
	}

	return mutableMatch, criticalMatch
}

// linkMutableFieldsMatch reports whether current already satisfies desired for mutable
// link attributes. Directional: zero-valued fields in desired mean "don't care".
func linkMutableFieldsMatch(current, desired netlink.Link) bool {
	m, _ := fieldsMatch(current, desired)
	return m
}

// allFieldsEqual performs strict symmetric equality of all managed link fields
// (both mutable and critical). Returns false if the link types differ.
func allFieldsEqual(a, b netlink.Link) bool {
	mAB, cAB := fieldsMatch(a, b)
	mBA, cBA := fieldsMatch(b, a)
	return mAB && cAB && mBA && cBA
}

// configsEqual compares two DeviceConfigs for equality of all managed fields.
// Uses fieldsMatch bidirectionally for complete link field comparison, then
// checks DeviceConfig-level fields (name, master, vlanparent, bridgeport,
// addresses, mappings).
func configsEqual(a, b *DeviceConfig) bool {
	if a == nil || b == nil {
		return a == b
	}

	if (a.Link == nil) != (b.Link == nil) {
		return false
	}

	if a.deviceName() != b.deviceName() ||
		a.Master != b.Master ||
		a.VLANParent != b.VLANParent ||
		!ptr.Equal(a.BridgePortSettings, b.BridgePortSettings) {
		return false
	}

	if !allFieldsEqual(a.Link, b.Link) {
		return false
	}

	if !addressesEqual(a.Addresses, b.Addresses) {
		return false
	}

	if !vidVNIMappingsEqual(a.VIDVNIMappings, b.VIDVNIMappings) {
		return false
	}

	return true
}

// addressesEqual compares two address slices for equality.
// Two slices are equal if they have the same addresses (by IPNet string).
// nil and empty slice are treated as different (nil = no management, empty = want no addresses).
func addressesEqual(a, b []netlink.Addr) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return sets.KeySet(addrListToMap(a)).Equal(sets.KeySet(addrListToMap(b)))
}

// vidVNIMappingsEqual compares two VIDVNIMapping slices for equality (order-independent).
// nil and empty slice are treated as different (nil = no management, empty = want no mappings).
func vidVNIMappingsEqual(a, b []VIDVNIMapping) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return sets.New(a...).Equal(sets.New(b...))
}

// isDependencyError checks if the error is a dependency error
func isDependencyError(err error) bool {
	return errors.Is(err, ErrDependencyPending)
}

// ErrDependencyPending is a sentinel error indicating a dependency is not ready.
// Callers can check for this to distinguish "will auto-resolve" from real failures.
var ErrDependencyPending = errors.New("dependency pending")

// DependencyError indicates a device couldn't be created because a dependency is missing.
// Wraps ErrDependencyPending for errors.Is() compatibility.
type DependencyError struct {
	Dependency string
	Reason     string
}

func (e *DependencyError) Error() string {
	return fmt.Sprintf("dependency not ready: %s (%s)", e.Dependency, e.Reason)
}

// Unwrap allows errors.Is(err, ErrDependencyPending) to work
func (e *DependencyError) Unwrap() error {
	return ErrDependencyPending
}

// validateLinkType returns an error if the link type is not supported by the manager.
func validateLinkType(link netlink.Link) error {
	switch link.(type) {
	case *netlink.Bridge, *netlink.Vxlan, *netlink.Vlan, *netlink.Vrf, *netlink.Dummy:
		return nil
	default:
		return fmt.Errorf("unsupported link type %T; supported: Bridge, Vxlan, Vlan, Vrf, Dummy", link)
	}
}

// validateInterfaceName checks if an interface name is valid for Linux.
// Returns an error if the name is empty, exceeds IFNAMSIZ-1, contains
// characters rejected by the kernel (/, NUL, whitespace), or is reserved.
func validateInterfaceName(name, context string) error {
	if name == "" {
		return fmt.Errorf("%s name is empty", context)
	}
	if len(name) > maxInterfaceNameLength {
		return fmt.Errorf("%s name %q exceeds maximum length of %d characters (got %d)",
			context, name, maxInterfaceNameLength, len(name))
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%s name %q is reserved", context, name)
	}
	if strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("%s name %q contains invalid characters", context, name)
	}
	if strings.ContainsAny(name, " \t\n") {
		return fmt.Errorf("%s name %q contains whitespace", context, name)
	}
	return nil
}

// isOurDevice returns true only if the device has our alias prefix.
// This is the single source of truth for ownership:
//   - Empty alias = unknown ownership, NOT ours (could be human-created or other automation)
//   - Foreign alias = definitely NOT ours
//   - Our prefix = ours, safe to modify/delete
func isOurDevice(link netlink.Link) bool {
	return strings.HasPrefix(link.Attrs().Alias, managedAliasPrefix)
}

// checkOwnership returns nil if the device is ours, or a NotOwnedError explaining why not.
func checkOwnership(link netlink.Link) error {
	if isOurDevice(link) {
		return nil
	}
	return &NotOwnedError{
		DeviceName: link.Attrs().Name,
		Reason:     fmt.Sprintf("alias does not match managed prefix (alias=%q)", link.Attrs().Alias),
	}
}

// buildManagedLink constructs a new Link containing only the fields NDM manages.
// This is the source of truth for which fields are managed per link type.
//
// FIELD CONTRACT: Every field included here must also be covered by
// fieldsMatch.
func buildManagedLink(link netlink.Link) netlink.Link {
	a := link.Attrs()
	base := netlink.LinkAttrs{
		Name:         a.Name,
		MTU:          a.MTU,
		TxQLen:       a.TxQLen,
		HardwareAddr: slices.Clone(a.HardwareAddr),
	}
	switch v := link.(type) {
	case *netlink.Vxlan:
		return &netlink.Vxlan{
			LinkAttrs: base,
			VxlanId:   v.VxlanId,
			SrcAddr:   slices.Clone(v.SrcAddr),
			Port:      v.Port,
			FlowBased: v.FlowBased,
			VniFilter: v.VniFilter,
			Learning:  v.Learning,
		}
	case *netlink.Bridge:
		b := &netlink.Bridge{LinkAttrs: base}
		if v.VlanFiltering != nil {
			b.VlanFiltering = ptr.To(*v.VlanFiltering)
		}
		if v.VlanDefaultPVID != nil {
			b.VlanDefaultPVID = ptr.To(*v.VlanDefaultPVID)
		}
		return b
	case *netlink.Vlan:
		vlanBase := base
		vlanBase.ParentIndex = a.ParentIndex
		return &netlink.Vlan{
			LinkAttrs:    vlanBase,
			VlanId:       v.VlanId,
			VlanProtocol: v.VlanProtocol,
		}
	case *netlink.Vrf:
		return &netlink.Vrf{
			LinkAttrs: base,
			Table:     v.Table,
		}
	case *netlink.Dummy:
		return &netlink.Dummy{LinkAttrs: base}
	default:
		panic(fmt.Sprintf("BUG: unsupported device type %T for buildManagedLink", link))
	}
}

// validateSupportedFields checks that no unsupported fields are set to
// non-zero values.
//
// For LinkAttrs fields with non-zero netlink.NewLinkAttrs() defaults,
// both zero and the default are accepted.
func validateSupportedFields(link netlink.Link) error {
	var unsupported []string
	reject := func(name string, isSet bool) {
		if isSet {
			unsupported = append(unsupported, name)
		}
	}

	a := link.Attrs()
	d := netlink.NewLinkAttrs()
	reject("LinkAttrs.Index", a.Index != 0 && a.Index != d.Index)
	reject("LinkAttrs.Flags", a.Flags != 0 && a.Flags != d.Flags)
	reject("LinkAttrs.RawFlags", a.RawFlags != 0 && a.RawFlags != d.RawFlags)
	reject("LinkAttrs.Headroom", a.Headroom != 0 && a.Headroom != d.Headroom)
	reject("LinkAttrs.Tailroom", a.Tailroom != 0 && a.Tailroom != d.Tailroom)
	reject("LinkAttrs.Namespace", a.Namespace != nil && a.Namespace != d.Namespace)
	reject("LinkAttrs.Alias", a.Alias != "" && a.Alias != d.Alias)
	reject("LinkAttrs.AltNames", a.AltNames != nil)
	reject("LinkAttrs.Statistics", a.Statistics != nil)
	reject("LinkAttrs.Promisc", a.Promisc != 0 && a.Promisc != d.Promisc)
	reject("LinkAttrs.Allmulti", a.Allmulti != 0 && a.Allmulti != d.Allmulti)
	reject("LinkAttrs.Multi", a.Multi != 0 && a.Multi != d.Multi)
	reject("LinkAttrs.Xdp", a.Xdp != nil)
	reject("LinkAttrs.EncapType", a.EncapType != "" && a.EncapType != d.EncapType)
	reject("LinkAttrs.Protinfo", a.Protinfo != nil)
	reject("LinkAttrs.OperState", a.OperState != 0 && a.OperState != d.OperState)
	reject("LinkAttrs.PhysSwitchID", a.PhysSwitchID != 0 && a.PhysSwitchID != d.PhysSwitchID)
	reject("LinkAttrs.NetNsID", a.NetNsID != 0 && a.NetNsID != d.NetNsID)
	reject("LinkAttrs.NumTxQueues", a.NumTxQueues != 0 && a.NumTxQueues != d.NumTxQueues)
	reject("LinkAttrs.NumRxQueues", a.NumRxQueues != 0 && a.NumRxQueues != d.NumRxQueues)
	reject("LinkAttrs.TSOMaxSegs", a.TSOMaxSegs != 0 && a.TSOMaxSegs != d.TSOMaxSegs)
	reject("LinkAttrs.TSOMaxSize", a.TSOMaxSize != 0 && a.TSOMaxSize != d.TSOMaxSize)
	reject("LinkAttrs.GSOMaxSegs", a.GSOMaxSegs != 0 && a.GSOMaxSegs != d.GSOMaxSegs)
	reject("LinkAttrs.GSOMaxSize", a.GSOMaxSize != 0 && a.GSOMaxSize != d.GSOMaxSize)
	reject("LinkAttrs.GROMaxSize", a.GROMaxSize != 0 && a.GROMaxSize != d.GROMaxSize)
	reject("LinkAttrs.GSOIPv4MaxSize", a.GSOIPv4MaxSize != 0 && a.GSOIPv4MaxSize != d.GSOIPv4MaxSize)
	reject("LinkAttrs.GROIPv4MaxSize", a.GROIPv4MaxSize != 0 && a.GROIPv4MaxSize != d.GROIPv4MaxSize)
	reject("LinkAttrs.Vfs", a.Vfs != nil)
	reject("LinkAttrs.Group", a.Group != 0 && a.Group != d.Group)
	reject("LinkAttrs.PermHWAddr", a.PermHWAddr != nil)
	reject("LinkAttrs.ParentDev", a.ParentDev != "" && a.ParentDev != d.ParentDev)
	reject("LinkAttrs.ParentDevBus", a.ParentDevBus != "" && a.ParentDevBus != d.ParentDevBus)
	reject("LinkAttrs.Slave", a.Slave != nil)

	switch v := link.(type) {
	case *netlink.Vxlan:
		reject("VtepDevIndex", v.VtepDevIndex != 0)
		reject("Group", v.Group != nil)
		reject("TTL", v.TTL != 0)
		reject("TOS", v.TOS != 0)
		reject("Proxy", v.Proxy)
		reject("RSC", v.RSC)
		reject("L2miss", v.L2miss)
		reject("L3miss", v.L3miss)
		reject("UDPCSum", v.UDPCSum)
		reject("UDP6ZeroCSumTx", v.UDP6ZeroCSumTx)
		reject("UDP6ZeroCSumRx", v.UDP6ZeroCSumRx)
		reject("NoAge", v.NoAge)
		reject("GBP", v.GBP)
		reject("Age", v.Age != 0)
		reject("Limit", v.Limit != 0)
		reject("PortLow", v.PortLow != 0)
		reject("PortHigh", v.PortHigh != 0)
	case *netlink.Bridge:
		reject("MulticastSnooping", v.MulticastSnooping != nil)
		reject("AgeingTime", v.AgeingTime != nil)
		reject("HelloTime", v.HelloTime != nil)
		reject("GroupFwdMask", v.GroupFwdMask != nil)
	case *netlink.Vlan:
		reject("IngressQosMap", v.IngressQosMap != nil)
		reject("EgressQosMap", v.EgressQosMap != nil)
		reject("ReorderHdr", v.ReorderHdr != nil)
		reject("Gvrp", v.Gvrp != nil)
		reject("LooseBinding", v.LooseBinding != nil)
		reject("Mvrp", v.Mvrp != nil)
		reject("BridgeBinding", v.BridgeBinding != nil)
	case *netlink.Vrf:
		// All Vrf fields are managed (Table)
	case *netlink.Dummy:
		// No type-specific fields
	default:
		panic(fmt.Sprintf("BUG: unsupported device type %T for validateSupportedFields", link))
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("unsupported %T fields set to non-zero values: %s; "+
			"these fields are not managed by NDM and will not be reconciled",
			link, strings.Join(unsupported, ", "))
	}
	return nil
}
