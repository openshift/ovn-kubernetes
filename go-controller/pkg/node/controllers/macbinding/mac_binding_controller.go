// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package macbinding implements the MAC Binding controller for OKEP-6691
// (Scalable ARP and NDP Broadcast Handling for UDN).
//
// This controller watches host neighbor table entries and makes the resolved
// MAC addresses available to UDN (User Defined Network) Gateway Routers. This
// avoids the need for ARP replies/Neighbor Advertisements to be flooded to
// each UDN GR which does not scale as the number of UDNs grows.
//
// Two distinct sync actions are possible, abstracted behind the
// [macBindingSyncOps] interface:
//
//   - ARP responder flows: Program ARP responder flows on br-ex
//     via the openflowManager. This allows br-ex to send ARP replies
//     specifically to the port which the request came from. This mechanism
//     is primarily intended for IPv4 address family and not supported for
//     IPv6 address family.
//
//   - MAC_Binding mirroring: Mirror entries as MAC_Bindings to
//     UDN GR external ports in SBDB. This prevents UDN GRs from sending
//     ARP requests in the first place. This mechanism is primarily intended
//     for IPv6 address family but is also supported for the IPv4 address family.
//
// The controller uses a [sync.Map] as a local cache of MAC/IP binding entries,
// populated by an event handler that reacts to adds, deletes, and MAC changes
// notifications from a netlink subscription. Updates on the default bridge link
// index are tracked, secondary bridges are not supported.
//
// For entries using MAC_Binding mirroring, a periodic scan iterates the cache
// and enqueues any entry that may expire before the next scan in order to
// refresh its timestamp. To avoid timestamp refreshes clogging a single queue
// preventing new entries or mac updates from being synced, there are two
// reconcilers with two separate queues, a bootstrapReconciler handles new
// entries or mac updates at runtime and a refreshReconciler handles timestamp
// refreshes and deletes at runtime and initial sync. A separate [sync.Map]
// tracks known UDNs their datapath UUIDs re-syncing the appropriate entries on
// changes.
package macbinding

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbcache "github.com/ovn-kubernetes/libovsdb/cache"
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

// openFlowManager abstracts the openflow manager methods needed to
// program ARP responder flows on br-ex.
type openFlowManager interface {
	UpdateFlowCacheEntry(key string, flows []string)
	DeleteFlowsByKey(key string)
	RequestFlowSync()
	Flowskeys() []string
}

// portInfo identifies a UDN GR external port and its datapath.
type portInfo struct {
	LogicalPort  string
	DatapathUUID string
	Network      string
}

// macBindingSyncOps abstracts the operations used to propagate a CDN
// Gateway Router MAC_Binding entry to UDN Gateway Routers. A single
// implementation provides both ARP flow and MAC_Binding methods.
//
// The reconciler passes a fresh timestamp (time.Now) to MAC_Binding
// methods, not the CDN entry's timestamp, to avoid moving UDN
// timestamps backwards.
//
// There is no DeleteMACBinding: UDN entries age out naturally via
// OVN's mac_binding_age_threshold.
//
// The implementation must be safe for concurrent use from multiple
// reconciler workers.
type macBindingSyncOps interface {
	// EnsureARPFlow programs an OpenFlow ARP responder rule on br-ex via
	// the openflowManager for the given (IP, MAC) pair. When a UDN GR
	// sends an ARP request for this IP, br-ex replies directly with
	// the known MAC, avoiding broadcast.
	EnsureARPFlow(ip, mac string) error
	SyncARPFlows(iptomac map[string]string) error

	// DeleteARPFlow removes the ARP responder flow for the given IP.
	DeleteARPFlow(ip string) error

	// AddMACBinding inserts a MAC_Binding row in SBDB for each UDN GR
	// external port in ports. Used when syncedTimestamp == 0 (entry
	// never synced).
	AddMACBinding(ip, mac string, timestamp int, ports []portInfo) error

	// UpdateMACBinding conditionally updates existing MAC_Binding rows
	// for each UDN GR external port in ports. The OVSDB update must
	// include a timestamp < new_timestamp condition to handle the
	// residual race between computing time.Now and transaction commit:
	// the UDN GR's own statctrl may refresh the timestamp in that
	// window. A no-op update (0 rows, condition not met) is not an
	// error and must not trigger recovery.
	UpdateMACBinding(ip, mac string, timestamp int, ports []portInfo) error

	// DeleteAndAddMACBinding performs a conditional delete followed by
	// a create in a single OVSDB transaction. Used for error recovery
	// when the controller's cache has diverged from SBDB state (e.g.
	// AddMACBinding failed with duplicate, or UpdateMACBinding failed
	// with row missing). Like UpdateMACBinding, the delete must be
	// conditioned on timestamp < new_timestamp to avoid replacing an
	// entry that the UDN's own statctrl has already refreshed to a
	// newer value. A no-op (condition not met) is not an error.
	DeleteAndAddMACBinding(ip, mac string, timestamp int, ports []portInfo) error
}

// macBinding holds IP and MAC.
type macBinding struct {
	ip              string
	mac             atomic.Pointer[string]
	sourceTimestamp atomic.Int64
	// staleTimestamp is the absolute time (in milliseconds since epoch)
	// at which this entry should be considered stale and evicted.
	// Zero means unconditionally trusted (e.g. REACHABLE state).
	staleTimestamp int64
}

// getMAC returns the current MAC address.
func (e *macBinding) getMAC() string {
	return *e.mac.Load()
}

// setMAC atomically updates the MAC address.
func (e *macBinding) setMAC(mac *string) {
	e.mac.Store(mac)
}

func (e *macBinding) getSourceTime() time.Time {
	return time.UnixMilli(e.sourceTimestamp.Load())
}

func (e *macBinding) setSourceTime(t time.Time) {
	e.sourceTimestamp.Store(t.UnixMilli())
}

// getStaleTime returns the time at which this entry should be evicted.
// A zero time means the entry is unconditionally trusted.
func (e *macBinding) getStaleTime() time.Time {
	return time.UnixMilli(e.staleTimestamp)
}

// setStaleTime sets the time at which this entry should be evicted.
// A zero time means the entry is unconditionally trusted.
func (e *macBinding) setStaleTime(t time.Time) {
	e.staleTimestamp = t.UnixMilli()
}

func (e *macBinding) String() string {
	return fmt.Sprintf("ip[%s] mac[%s] source[%s] stale[%s]", e.ip, e.getMAC(), e.getSourceTime(), e.getStaleTime())
}

func newMacBinding(ip string, mac *string) *macBinding {
	mb := &macBinding{ip: ip}
	mb.setMAC(mac)
	var zeroTime time.Time
	mb.setSourceTime(zeroTime)
	mb.setStaleTime(zeroTime)
	return mb
}

// userHZ is the kernel's USER_HZ constant (fixed at 100 since Linux 2.4).
// Netlink neighbor Updated field is in clock ticks at this resolution.
const userHZ = 100

// maxAgeFresh is the maximum age in seconds of a mac binding entry (as measured
// either by the neighbor updated timestamp or CDN mac binding timestamp) for it
// to be considered valid to propagate to OVN mac binding table and is the
// maximum drift between the source and target timestamps.
const maxAgeFresh = 15

// scanPeriod returns the period by which we evist STALE neighbor/cache entries
// and corresponsding flows.
func scanPeriod() time.Duration {
	ageThreshold, _ := strconv.Atoi(types.GRMACBindingAgeThreshold)
	return time.Duration((3*ageThreshold)/16) * time.Second
}

// networkRefReconcilerFunc adapts a function to the
// networkmanager.NetworkRefReconciler interface.
type networkRefReconcilerFunc func(node, networkName string)

func (f networkRefReconcilerFunc) Reconcile(node, networkName string) { f(node, networkName) }

// MACBindingController propagates CDN Gateway Router MAC_Binding
// entries to UDN Gateway Routers. One instance per node.
type MACBindingController struct {
	sbClient       libovsdbclient.Client
	networkManager networkmanager.Interface
	syncOps        macBindingSyncOps

	// cache stores *cacheEntry (ARP flow) or *macBindingCacheEntry
	// (MAC_Binding mirroring) values keyed by IP. Pointer is swapped
	// atomically on bridge recreation; in-flight event handler
	// writes to the old map are harmless.
	cache atomic.Pointer[sync.Map]

	// ports tracks UDN GR external ports keyed by logical port name.
	// Add/remove is done by the network reconciler; the PortBinding
	// event handler only updates the datapath UUID. Cleanup of
	// MAC_Binding rows for deleted ports is handled by OVN via
	// strong-reference cascade from Datapath_Binding.
	ports sync.Map

	ipv4Enabled     bool
	ipv4UseARPFlows bool
	ipv6Enabled     bool
	hasCache        bool
	hostSource      bool

	cdnGatewayPort  string
	bridgeName      string
	bridgeLinkIndex atomic.Int32
	nodeName        string

	// macBindingReconciler handles new entries and MAC changes.
	macBindingReconciler controller.Reconciler
	nadReconciler        controller.Reconciler
}

func (c *MACBindingController) getBridgeLinkIndex() int {
	return int(c.bridgeLinkIndex.Load())
}

func (c *MACBindingController) setBridgeLinkIndex(index int) {
	c.bridgeLinkIndex.Store(int32(index))
}

func (c *MACBindingController) getCache() *sync.Map {
	return c.cache.Load()
}

// NewMACBindingController creates a new MACBindingController.
func NewMACBindingController(
	sbClient libovsdbclient.Client,
	networkManager networkmanager.Interface,
	ofm openFlowManager,
	nodeName string,
	bridgeName string,
	ipv4Enabled bool,
	ipv4UseARPFlows bool,
	ipv6Enabled bool,
	useHostAsSource bool,
	useCache bool,
) *MACBindingController {
	c := &MACBindingController{
		sbClient:        sbClient,
		networkManager:  networkManager,
		syncOps:         newMACBindingSyncOps(sbClient, ofm),
		nodeName:        nodeName,
		bridgeName:      bridgeName,
		ipv4Enabled:     ipv4Enabled,
		ipv4UseARPFlows: ipv4UseARPFlows,
		ipv6Enabled:     ipv6Enabled,
		cdnGatewayPort:  types.GWRouterToExtSwitchPrefix + (&util.DefaultNetInfo{}).GetNetworkScopedGWRouterName(nodeName),
	}
	c.cache.Store(&sync.Map{})
	c.macBindingReconciler = controller.NewReconciler(
		"mac-binding-reconciler",
		&controller.ReconcilerConfig{
			RateLimiter: controller.DefaultRateLimiter[string](),
			Reconcile:   c.reconcile,
			Threadiness: 1,
			MaxAttempts: 11, // with default rate limiter, retry during ~10s
		},
	)
	c.nadReconciler = controller.NewReconciler(
		"mac-binding-nad-reconciler",
		&controller.ReconcilerConfig{
			Reconcile:   c.reconcileNAD,
			Threadiness: 1,
			MaxAttempts: controller.InfiniteAttempts,
		},
	)

	// Set to mirror the host neighbor table instead of the CDN Mac_Binding table.
	c.hostSource = useHostAsSource

	// Set to cache host neighbor entries which reduces netlink queries on
	// kernel and allows to filter out transitions out of STALE for entries we
	// were already ignoring
	c.hasCache = useCache && c.hostSource

	return c
}

// Run starts the controller and blocks until stopCh is closed.
func (c *MACBindingController) Run(stopCh <-chan struct{}) error {
	klog.Info("Running MAC Binding controller...")
	if c.reconcilesMACBindings() {
		c.networkManager.RegisterNetworkRefReconciler(networkRefReconcilerFunc(func(node, networkName string) {
			c.reconcileNetwork(node, networkName)
		}))
		c.networkManager.RegisterNADReconciler(c.nadReconciler)
		c.registerPortEventHandler()
	}
	c.registerSourceEventHandler(stopCh)

	hasFlows := c.ipv4Enabled && c.ipv4UseARPFlows

	if !c.hostSource && hasFlows {
		// we can sync flows from CDN at startup
		c.enqueueFlowSync()
	}

	if err := controller.Start(
		c.macBindingReconciler,
		c.nadReconciler,
	); err != nil {
		return err
	}

	var tick <-chan time.Time
	if c.hostSource {
		period := scanPeriod()
		tick = time.Tick(period)
	}

	for {
		select {
		case <-tick:
			c.scan()
		case <-stopCh:
			klog.Info("Stopping MAC Binding controller...")
			controller.Stop(c.macBindingReconciler, c.nadReconciler)
			return nil
		}
	}
}

// scan evicts old STALE neighbor entries from cache, resyncs flows if needed,
// and re-enqueues REACHABLE MAC binding entries whose UDN timestamps may have
// aged out (REACHABLE entries generate no netlink events while they stay
// REACHABLE, so without periodic re-sync the UDN MAC_Binding would expire).
func (c *MACBindingController) scan() {
	hasFlows := c.ipv4Enabled && c.ipv4UseARPFlows
	hasMACBindings := c.ipv6Enabled || !hasFlows
	if !c.hasCache {
		if hasFlows {
			c.enqueueFlowSync()
		}
		if hasMACBindings {
			c.enqueueMACBindingsFromHost()
		}
		return
	}

	var deleteFlow bool
	now := time.Now()
	c.getCache().Range(func(key, value any) bool {
		ip := key.(string)
		needsMACBinding, hasFlow := c.ipNeeds(ip)
		if !needsMACBinding && !hasFlow {
			return true
		}
		mb := value.(*macBinding)
		staleTime := mb.getStaleTime()
		if needsMACBinding && staleTime.IsZero() {
			// sync REACHABLE entry to mac Binding
			c.enqueue(ip)
			return true
		}
		if !staleTime.IsZero() && now.After(staleTime) && c.getCache().CompareAndDelete(ip, value) {
			klog.V(5).Infof("Evicted stale neighbor %s from cache", ip)
			deleteFlow = deleteFlow || hasFlow
			return true
		}
		return true
	})
	if deleteFlow {
		c.enqueueFlowSync()
	}
}

func (c *MACBindingController) reconcileNAD(nad string) error {
	if !c.reconcilesMACBindings() {
		return nil
	}
	netInfo := c.networkManager.GetNetInfoForNADKey(nad)
	if netInfo == nil {
		// network might have been deleted, find out which and remove the port
		// from the cache
		c.ports.Range(func(key, value any) bool {
			portName := key.(string)
			pi := value.(portInfo)
			if len(c.networkManager.GetNADKeysForNetwork(pi.Network)) == 0 {
				klog.Infof("Removed UDN GR port %s as network %s is no longer available", portName, pi.Network)
				c.ports.Delete(portName)
			}
			return true
		})
		return nil
	}

	networkName := netInfo.GetNetworkName()
	var trackNetwork bool
	switch {
	case !netInfo.IsPrimaryNetwork():
		fallthrough
	case netInfo.TopologyType() != types.Layer2Topology && netInfo.TopologyType() != types.Layer3Topology:
		fallthrough
	case netInfo.Uplink() != "":
		fallthrough
	case !c.networkManager.NodeHasNetwork(c.nodeName, networkName):
		trackNetwork = false
	default:
		trackNetwork = true
	}

	portName := types.GWRouterToExtSwitchPrefix + netInfo.GetNetworkScopedGWRouterName(c.nodeName)
	if trackNetwork {
		pi := portInfo{LogicalPort: portName, Network: networkName}
		pb, _ := ops.GetPortBinding(c.sbClient, &sbdb.PortBinding{LogicalPort: portName})
		if pb != nil {
			pi.DatapathUUID = pb.Datapath
		}
		if _, loaded := c.ports.LoadOrStore(portName, pi); !loaded && pi.DatapathUUID != "" {
			klog.Infof("Added UDN GR port %s (datapath %s)", portName, pi.DatapathUUID)
			c.enqueueMACBindingsOnPort(portName)
		}
	} else if _, loaded := c.ports.LoadAndDelete(portName); loaded {
		klog.Infof("Removed UDN GR port %s as network %s is no longer available", portName, networkName)
	}

	return nil
}

func (c *MACBindingController) reconcileNetwork(node, networkName string) {
	if node != c.nodeName {
		return
	}
	if !c.reconcilesMACBindings() {
		return
	}
	nads := c.networkManager.GetNADKeysForNetwork(networkName)
	if len(nads) == 0 {
		return
	}
	c.nadReconciler.Reconcile(nads[0])
}

func (c *MACBindingController) registerSourceEventHandler(stopCh <-chan struct{}) {
	if c.hostSource {
		c.registerNeighEventHandler(stopCh)
		return
	}
	c.registerMACBindingEventHandler()
}

// registerMACBindingEventHandler registers libovsdb event handlers for
// the MAC_Binding table, filtered to this node's CDN GR port.
func (c *MACBindingController) registerMACBindingEventHandler() {
	handleUpdate := func(table string, current, previous model.Model) {
		if table != sbdb.MACBindingTable {
			return
		}
		cur := current.(*sbdb.MACBinding)
		if cur.LogicalPort != c.cdnGatewayPort {
			return
		}
		mb := newMacBinding(cur.IP, &cur.MAC)
		mb.setSourceTime(time.UnixMilli(int64(cur.Timestamp)))
		var old *macBinding
		if previous != nil {
			pre := previous.(*sbdb.MACBinding)
			old = newMacBinding(pre.IP, &pre.MAC)
			old.setSourceTime(time.UnixMilli(int64(pre.Timestamp)))
		}
		c.enqueueMaybe(mb.ip, mb, old)
	}
	c.sbClient.Cache().AddEventHandler(&libovsdbcache.EventHandlerFuncs{
		AddFunc: func(table string, m model.Model) {
			handleUpdate(table, m, nil)
		},
		UpdateFunc: func(table string, old model.Model, new model.Model) {
			handleUpdate(table, new, old)
		},
		DeleteFunc: func(table string, m model.Model) {
			handleUpdate(table, m, nil)
		},
	})
}

// registerPortEventHandler registers libovsdb event handlers for the
// PortBinding table to track datapath UUID changes.
func (c *MACBindingController) registerPortEventHandler() {
	updateDatapath := func(logicalPort, datapath string) {
		old, loaded := c.ports.Load(logicalPort)
		if !loaded {
			return
		}
		pi := old.(portInfo)
		if pi.DatapathUUID == datapath {
			return
		}
		oldDP := pi.DatapathUUID
		pi.DatapathUUID = datapath
		if c.ports.CompareAndSwap(logicalPort, old, pi) {
			klog.V(5).Infof("GR Datapath UUID changed: %s -> %s (was %s)", pi.Network, datapath, oldDP)
			c.enqueueMACBindingsOnPort(logicalPort)
		}
	}

	c.sbClient.Cache().AddEventHandler(&libovsdbcache.EventHandlerFuncs{
		AddFunc: func(table string, m model.Model) {
			if table == sbdb.PortBindingTable {
				pb := m.(*sbdb.PortBinding)
				updateDatapath(pb.LogicalPort, pb.Datapath)
			}
		},
		UpdateFunc: func(table string, _ model.Model, new model.Model) {
			if table == sbdb.PortBindingTable {
				pb := new.(*sbdb.PortBinding)
				updateDatapath(pb.LogicalPort, pb.Datapath)
			}
		},
		DeleteFunc: func(table string, m model.Model) {
			if table == sbdb.PortBindingTable {
				pb := m.(*sbdb.PortBinding)
				updateDatapath(pb.LogicalPort, "")
			}
		},
	})
}

// registerNeighEventHandler subscribes to netlink neighbor events on the
// default bridge. Resubscribes automatically on failure or unexpected
// channel close.
func (c *MACBindingController) registerNeighEventHandler(stopCh <-chan struct{}) {
	stopSubCh := make(chan struct{})
	neighCh, subscribedIndex := c.neighSubscribe(stopSubCh)
	subscribeTicker := time.NewTicker(1 * time.Second)

	resubscribe := func() {
		close(stopSubCh)
		stopSubCh = make(chan struct{})
		neighCh, subscribedIndex = c.neighSubscribe(stopSubCh)
	}

	go func() {
		defer subscribeTicker.Stop()
		for {
			select {
			case <-stopCh:
				close(stopSubCh)
				return
			case <-subscribeTicker.C:
				if neighCh == nil || c.getBridgeLinkIndex() != subscribedIndex {
					resubscribe()
				}
			case update, open := <-neighCh:
				if !open {
					klog.Warningf("Neighbor subscription closed, will resubscribe")
					resubscribe()
					continue
				}
				c.handleNeighUpdate(update)
			}
		}
	}()
}

// neighSubscribe creates a new netlink neighbor subscription and
// returns the channel and the bridge link index at subscription time.
func (c *MACBindingController) neighSubscribe(stopCh <-chan struct{}) (chan netlink.NeighUpdate, int) {
	nlOps := util.GetNetLinkOps()
	link, err := nlOps.LinkByName(c.bridgeName)
	if err != nil {
		klog.Errorf("Failed to get link %s: %v", c.bridgeName, err)
		return nil, 0
	}
	index := link.Attrs().Index

	err = util.SetAcceptUnsolicitedNeighborForInterface(c.bridgeName)
	if err != nil {
		klog.Errorf("Failed to configure bridge %s to accept unsolicited neighbor announcements: %v", c.bridgeName, err)
	}

	c.cache.Store(&sync.Map{})
	c.setBridgeLinkIndex(index)
	neighCh := make(chan netlink.NeighUpdate, 100)
	err = nlOps.NeighSubscribeWithOptions(
		neighCh,
		stopCh,
		netlink.NeighSubscribeOptions{
			ErrorCallback: func(err error) {
				klog.Warningf("Neighbor subscribe error: %v", err)
			},
			ListExisting: true,
		},
	)
	if err != nil {
		klog.Errorf("Failed to subscribe to neighbor events: %v", err)
		return nil, index
	}

	return neighCh, index
}

// HandleLinkEvent should be called from the linkManager callback when
// the external bridge link changes.
func (c *MACBindingController) HandleLinkEvent(link netlink.Link) {
	if link.Attrs().Name != c.bridgeName {
		return
	}
	new := link.Attrs().Index
	old := c.getBridgeLinkIndex()
	if old == 0 || old == new {
		return
	}

	// set to 0 to reset cache and resubscribe
	klog.V(5).Infof("Bridge %s link index changed %d -> %d, will resubscribe", link.Attrs().Name, old, new)
	c.setBridgeLinkIndex(0)
}

// handleNeighUpdate processes a single neighbor update event.
func (c *MACBindingController) handleNeighUpdate(update netlink.NeighUpdate) {
	if update.LinkIndex != c.getBridgeLinkIndex() {
		return
	}
	if len(update.IP) == 0 {
		return
	}

	klog.V(5).Infof("Processing neighbor update: %s %s", update.IP, update.HardwareAddr)
	ip := update.IP.String()
	var mb *macBinding
	if update.Type != unix.RTM_DELNEIGH && isValidNeigh(&update.Neigh) {
		mac := update.HardwareAddr.String()
		mb = newMacBinding(ip, &mac)
		if update.State&netlink.NUD_REACHABLE == 0 {
			// REACHABLE entries are trusted, other states depend on their
			// source and stale times
			sourceTime := time.Now().Add(-(time.Duration(update.Updated) / userHZ) * time.Second)
			mb.setSourceTime(sourceTime)
			ageThreshold, _ := strconv.Atoi(types.GRMACBindingAgeThreshold)
			staleTime := sourceTime.Add(time.Duration(ageThreshold) * time.Second)
			mb.setStaleTime(staleTime)
		}
	}

	if !c.hasCache {
		c.enqueueMaybe(ip, mb, nil)
		return
	}

	var previous *macBinding
	if pre, found := c.getCache().Load(ip); found {
		previous = pre.(*macBinding)
	}
	if previous == nil && update.State&(netlink.NUD_DELAY|netlink.NUD_PROBE) != 0 {
		// won't add new entries from DELAY or PROBE state, just update if
		// transitioning from STALE (can't do this without cache)
		return
	}
	c.cacheAndEnqueueMaybe(ip, mb, previous)
}

func (c *MACBindingController) shouldEnqueueKeys(ip string, current, previous *macBinding) []string {
	hasMACBinding, hasFlow := c.ipNeeds(ip)
	if !hasMACBinding && !hasFlow {
		// noop
		return nil
	}
	if current == nil && hasMACBinding {
		// source mac binding deleted, we don't remove mac bindings, let them age out
		return nil
	}
	if current == nil {
		// source mac binding deleted, full flow sync to remove the corresponding flow
		return []string{flowsKey}
	}
	if !current.getSourceTime().IsZero() && current.getSourceTime().Add(maxAgeFresh*time.Second).Before(time.Now()) {
		// ignore updates that are not recent (older than neighMaxAge)
		return nil
	}
	if previous != nil && current.getMAC() != previous.getMAC() && hasFlow {
		// full flow sync to update the flow mac and ip sync to update the mac binding mac
		return []string{flowsKey, ip}
	}
	if hasFlow {
		// full flow sync to ensure the flow
		return []string{flowsKey}
	}
	// ensure the mac binding
	return []string{ip}
}

func (c *MACBindingController) enqueueMaybe(ip string, current, previous *macBinding) {
	keys := c.shouldEnqueueKeys(ip, current, previous)
	c.enqueue(keys...)
}

func (c *MACBindingController) cacheAndEnqueueMaybe(ip string, current, previous *macBinding) {
	keys := c.shouldEnqueueKeys(ip, current, previous)
	if current == nil {
		if _, deleted := c.getCache().LoadAndDelete(ip); deleted {
			c.enqueue(keys...)
		}
		return
	}
	c.getCache().Store(ip, current)
	c.enqueue(keys...)
}

const (
	// flowsKey syncs all flows
	flowsKey = "*"

	// macBindingsKey sync to UDN mac bindings. By itself syncs all,
	// can be composed with IP and port to scope the sync
	macBindingsKey = "**"
)

func (c *MACBindingController) enqueueFlowSync() {
	c.enqueue(flowsKey)
}

func (c *MACBindingController) enqueueMACBindingsFromHost() {
	c.enqueue(macBindingsKey)
}

func (c *MACBindingController) enqueueMACBindingsOnPort(port string) {
	c.enqueue(macBindingsKey + "|" + port)
}

func (c *MACBindingController) enqueueMACBindingsForIPOnPort(ip, port string) {
	c.enqueue(macBindingsKey + "|" + port + "|" + ip)
}

func (c *MACBindingController) enqueue(keys ...string) {
	klog.V(5).Infof("Enqueuing key for reconciliation: %v", keys)
	for _, key := range keys {
		c.macBindingReconciler.Reconcile(key)
	}
}

func reconcileKeys(key string) (base, ip, port string) {
	if key == flowsKey {
		base = flowsKey
		return
	}
	if !strings.HasPrefix(key, macBindingsKey) {
		ip = key
		return
	}
	// macBindingsKey
	base = macBindingsKey
	tokens := strings.Split(key, "|")
	if len(tokens) >= 2 {
		port = tokens[1]
	}
	if len(tokens) >= 3 {
		ip = tokens[2]
	}
	return
}

// reconcile dispatches to the appropriate handler based on IP family
// and sentinel keys. Shared by both reconcilers.
func (c *MACBindingController) reconcile(key string) error {
	klog.V(5).Infof("Reconciling key %s", key)
	start := time.Now()
	defer func() {
		klog.V(5).Infof("Reconciling key %s done after %s", key, time.Since(start))
	}()

	base, ip, port := reconcileKeys(key)
	switch base {
	case flowsKey:
		return c.reconcileARPFlows()
	default:
		return c.reconcileMacBindings(ip, port)
	}
}

func (c *MACBindingController) reconcileARPFlows() error {
	if !c.ipv4Enabled || !c.ipv4UseARPFlows {
		return nil
	}
	switch {
	case c.hasCache:
		return c.reconcileARPFlowsFromCache()
	case c.hostSource:
		return c.reconcileARPFlowsFromHost()
	default:
		return c.reconcileARPFlowsFromCDN()
	}
}

func (c *MACBindingController) reconcileARPFlowsFromHost() error {
	linkIndex := c.getBridgeLinkIndex()
	if linkIndex == 0 {
		return nil
	}
	nlOps := util.GetNetLinkOps()
	neighs, err := nlOps.NeighList(linkIndex, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list neighbors for scan: %w", err)
	}
	bindings := make(map[string]string, len(neighs))
	for i := range neighs {
		neigh := &neighs[i]
		ip := neigh.IP.String()
		_, hasFlow := c.ipNeeds(ip)
		if !hasFlow {
			continue
		}
		if !isValidNeigh(neigh) {
			continue
		}
		bindings[neigh.IP.String()] = neigh.HardwareAddr.String()
	}
	return c.syncOps.SyncARPFlows(bindings)
}

func (c *MACBindingController) reconcileARPFlowsFromCDN() error {
	var mbs []*sbdb.MACBinding
	err := c.sbClient.WhereCache(func(mb *sbdb.MACBinding) bool {
		if mb.LogicalPort != c.cdnGatewayPort {
			return false
		}
		_, hasFlows := c.ipNeeds(mb.IP)
		return hasFlows
	}).List(context.Background(), &mbs)
	if err != nil {
		return err
	}

	if len(mbs) == 0 {
		return nil
	}

	bindings := make(map[string]string, len(mbs))
	for _, mb := range mbs {
		bindings[mb.IP] = mb.MAC
	}
	return c.syncOps.SyncARPFlows(bindings)
}

func (c *MACBindingController) reconcileARPFlowsFromCache() error {
	if !c.ipv4Enabled || !c.ipv4UseARPFlows {
		return nil
	}
	bindings := map[string]string{}
	c.getCache().Range(func(key, value any) bool {
		ip := key.(string)
		_, hasFlow := c.ipNeeds(ip)
		if !hasFlow {
			return true
		}
		mac := value.(*macBinding).getMAC()
		bindings[ip] = mac
		return true
	})
	return c.syncOps.SyncARPFlows(bindings)
}

func (c *MACBindingController) reconcileMacBindings(ip, port string) error {
	if !c.ipv6Enabled && (!c.ipv4Enabled || c.ipv4UseARPFlows) {
		return nil
	}
	switch {
	case ip != "" && port != "":
		return c.reconcileMACBindingForIPOnPort(ip, port)
	case port != "":
		return c.reconcileMACBindingsOnPort(port)
	case ip != "":
		return c.reconcileMACBindingForIP(ip)
	default:
		return c.reconcileAllMACBindings()
	}
}

func (c *MACBindingController) reconcileAllMACBindings() error {
	// only used to sync REACHABLE host neighbor entries with no cache
	if !c.hostSource || c.hasCache {
		return nil
	}
	return c.reconcileMACBindingsFromHost()
}

func (c *MACBindingController) reconcileMACBindingsFromHost() error {
	linkIndex := c.getBridgeLinkIndex()
	if linkIndex == 0 {
		return nil
	}
	nlOps := util.GetNetLinkOps()
	family := netlink.FAMILY_ALL
	if !c.ipv4Enabled || c.ipv4UseARPFlows {
		family = netlink.FAMILY_V6
	}
	neighs, err := nlOps.NeighList(linkIndex, family)
	if err != nil {
		return fmt.Errorf("failed to list neighbors: %w", err)
	}
	for i := range neighs {
		neigh := &neighs[i]
		if !isValidNeigh(neigh) || neigh.State&netlink.NUD_REACHABLE == 0 {
			continue
		}
		c.enqueue(neigh.IP.String())
	}
	return nil
}

func (c *MACBindingController) reconcileMACBindingForIP(ip string) error {
	var ports []portInfo
	c.ports.Range(func(_, value any) bool {
		pi := value.(portInfo)
		if pi.DatapathUUID != "" {
			ports = append(ports, pi)
		}
		return true
	})
	return c.reconcileMACBindings(ip, ports...)
}

func (c *MACBindingController) reconcileMACBindingForIPOnPort(ip string, portName string) error {
	var ports []portInfo
	c.ports.Range(func(_, value any) bool {
		pi := value.(portInfo)
		if pi.DatapathUUID != "" {
			ports = append(ports, pi)
		}
		return true
	})
	value, found := c.ports.Load(portName)
	if !found {
		return nil
	}
	return c.reconcileMACBindings(ip, value.(portInfo))
}

func (c *MACBindingController) reconcileMACBindingsOnPort(port string) error {
	switch {
	case c.hasCache:
		return c.reconcileMACBindingsOnPortFromCache(port)
	case c.hostSource:
		return c.reconcileMACBindingsOnPortFromHost(port)
	default:
		return c.reconcileMACBindingsOnPortFromCDN(port)
	}
}

func (c *MACBindingController) reconcileMACBindingsOnPortFromCache(port string) error {
	c.getCache().Range(func(key, value any) bool {
		ip := key.(string)
		hasMACBinding, _ := c.ipNeeds(ip)
		if !hasMACBinding {
			return true
		}
		staleTime := value.(*macBinding).getStaleTime()
		if !staleTime.IsZero() {
			// we only sync REACHABLE entries to new UDNs because with other
			// states we will get an event when UDN attempts to use an already
			// existing entry but with REACHABLE we will not get events
			return true
		}
		c.enqueueMACBindingsForIPOnPort(ip, port)
		return true
	})
	return nil
}

func (c *MACBindingController) reconcileMACBindingsOnPortFromHost(port string) error {
	linkIndex := c.getBridgeLinkIndex()
	if linkIndex == 0 {
		return nil
	}
	nlOps := util.GetNetLinkOps()
	family := netlink.FAMILY_ALL
	if !c.ipv4Enabled || c.ipv4UseARPFlows {
		family = netlink.FAMILY_V6
	}
	neighs, err := nlOps.NeighList(linkIndex, family)
	if err != nil {
		return fmt.Errorf("failed to list neighbors: %w", err)
	}

	for i := range neighs {
		neigh := &neighs[i]
		ip := neigh.IP.String()
		if !isValidNeigh(neigh) {
			continue
		}
		if neigh.State&netlink.NUD_REACHABLE == 0 {
			// we only sync REACHABLE entries to new UDNs because with other
			// states we will get an event when UDN attempts to use an already
			// existing entry but with REACHABLE we will not get events
			continue
		}
		c.enqueueMACBindingsForIPOnPort(ip, port)
	}
	return nil
}

func (c *MACBindingController) reconcileMACBindingsOnPortFromCDN(port string) error {
	var mbs []*sbdb.MACBinding
	err := c.sbClient.WhereCache(func(mb *sbdb.MACBinding) bool {
		if mb.LogicalPort != c.cdnGatewayPort {
			return false
		}
		hasMacBinding, _ := c.ipNeeds(mb.IP)
		if !hasMacBinding {
			return false
		}
		// FIXME: not getting tiemstamp updates when new UDN tries to use existing entry?
		//notFresh := time.UnixMilli(int64(mb.Timestamp)).Add(neighMaxAge * time.Second).Before(time.Now())
		//if notFresh {
		//	return "", nil
		//}
		c.enqueueMACBindingsForIPOnPort(mb.IP, port)
		return false
	}).List(context.Background(), &mbs)
	return err
}

// reconcileMACBindingNoCache looks up the current MAC from source and
// writes to all UDN GR ports with now(). No cache is used.
func (c *MACBindingController) reconcileMACBindings(ip string, ports ...portInfo) error {
	if len(ports) == 0 {
		return nil
	}

	mac, err := c.lookupMAC(ip)
	if err != nil {
		return err
	}
	if mac == "" {
		return nil
	}

	nowMs := int(time.Now().UnixMilli())
	klog.V(5).Infof("Setting MAC binding %s -> %s to %d ports", ip, mac, len(ports))
	return c.syncOps.DeleteAndAddMACBinding(ip, mac, nowMs, ports)
}

// lookupMAC looks up the current MAC for an IP from the neighbor
// table or SBDB MAC_Binding table.
func (c *MACBindingController) lookupMAC(ip string) (string, error) {
	if c.hasCache {
		entry, found := c.getCache().Load(ip)
		if !found {
			return "", nil
		}
		return entry.(*macBinding).getMAC(), nil
	}

	if !c.hostSource && c.sbClient != nil {
		mb := &sbdb.MACBinding{LogicalPort: c.cdnGatewayPort, IP: ip}
		err := c.sbClient.Get(context.Background(), mb)
		if err != nil {
			return "", err
		}
		// FIXME: not getting tiemstamp updates when new UDN tries to use existing entry?
		//notFresh := time.UnixMilli(int64(mb.Timestamp)).Add(neighMaxAge * time.Second).Before(time.Now())
		//if notFresh {
		//	return "", nil
		//}
		return mb.MAC, nil
	}

	linkIndex := c.getBridgeLinkIndex()
	nlOps := util.GetNetLinkOps()
	family := netlink.FAMILY_V4
	if utilnet.IsIPv6String(ip) {
		family = netlink.FAMILY_V6
	}
	neighs, err := nlOps.NeighList(linkIndex, family)
	if err != nil {
		return "", err
	}
	for i := range neighs {
		if neighs[i].IP.String() == ip && isValidNeigh(&neighs[i]) {
			return neighs[i].HardwareAddr.String(), nil
		}
	}

	return "", nil
}

func (c *MACBindingController) ipNeeds(ip string) (macBinding, flow bool) {
	isIPv6 := utilnet.IsIPv6String(ip)
	if isIPv6 && !c.ipv6Enabled {
		// IPv6 disabled
		return false, false
	}
	if !isIPv6 && !c.ipv4Enabled {
		// IPv4 disabled
		return false, false
	}
	hasFlow := !isIPv6 && c.ipv4UseARPFlows
	if hasFlow {
		return false, true
	}
	return true, false
}

func (c *MACBindingController) reconcilesMACBindings() bool {
	return c.ipv6Enabled || (c.ipv4Enabled && !c.ipv4UseARPFlows)
}

// isValidNeigh returns true if the neighbor entry is trusted: valid
// MAC, and either REACHABLE, or STALE/DELAY/PROBE with Updated ticks
// below the MAC aging threshold.
func isValidNeigh(neigh *netlink.Neigh) bool {
	if len(neigh.HardwareAddr) == 0 {
		return false
	}
	if neigh.State&netlink.NUD_REACHABLE != 0 {
		return true
	}
	if neigh.State&(netlink.NUD_STALE|netlink.NUD_DELAY|netlink.NUD_PROBE) == 0 {
		return false
	}
	ageThreshold, _ := strconv.Atoi(types.GRMACBindingAgeThreshold)
	return int(neigh.Updated)/userHZ < ageThreshold
}
