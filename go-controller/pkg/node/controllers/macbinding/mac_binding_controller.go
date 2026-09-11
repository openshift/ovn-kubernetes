// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package macbinding implements the MAC Binding mirror controller for OKEP-6691
// (Scalable ARP and NDP Broadcast Handling for UDN).
//
// Networks that share a physical uplink form a group. Within each group a
// single designated network ("source") resolves ARP/ND on the wire; OVN records
// the result in its Gateway Router's SB MAC_Binding rows. This controller
// mirrors those rows onto the SB MAC_Binding of every other ("target") Gateway
// Router in the group, so the targets never need to broadcast ARP/ND
// themselves.
//
//   - The default group (networks on the shared breth0, i.e. Uplink()=="")
//     always designates the CDN Gateway Router; its targets are the primary
//     L2/L3 UDNs and CUDNs present on the node.
//   - An uplink group (Uplink()!="") contains only CUDNs; openflow-manager
//     designates the source and informs the controller about it.
//
// The controller dynamically establishes SB MAC_Binding monitors for the
// sources. These monitors are only canceled when the datapath is deleted to
// ensure the related rows in the client cache have already been removed.
//
// Reconciliations happen on the following events:
// TODO: describe them
package macbinding

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

// --- type, construction, lifecycle --------------------------------------

// MACBindingController mirrors MAC bindings across networks.
type MACBindingController struct {
	sbClient             libovsdbclient.Client
	networkManager       networkmanager.Interface
	uplinkSourceProvider uplinkSourceProvider

	nodeName       string
	ipv4Enabled    bool
	ipv6Enabled    bool
	cdnGatewayPort string

	macBindingReconciler        controller.Reconciler
	macBindingRefreshReconciler controller.Reconciler
	networkReconciler           controller.Reconciler

	// macBindingSourceForUplinks
	macBindingSourceForUplinks atomic.Pointer[map[string]string]

	// lastBacklogWarningMs throttles the mirror-backlog warning (UnixMilli of
	// the last emission); see warnMirrorBacklog.
	lastBacklogWarningMs atomic.Int64

	// mutex for the following maps
	sync.RWMutex
	// followers maps sources to followers. They are external GW router port
	// names. The controller syncs mac bindings from the sources to the
	// corresponding followers. The source is the CDN for the default bridge or
	// a designated CUDN by openflow manager for uplink bridges. Designated CUDN
	// sources can change dynamically and followers might not have known sources
	// in which case they are tracked with "unknown" key. While there is an
	// unknown source the controller does full network reconciliations since it
	// needs the complete picture to re-allocate.
	followers map[string]sets.Set[string]
}

type uplinkSourceProvider interface {
	GetMacBindingSourceForUplinks() map[string]string
}

// NewMACBindingController creates a new MACBindingController.
func NewMACBindingController(
	sbClient libovsdbclient.Client,
	networkManager networkmanager.Interface,
	uplinkSourceProvider uplinkSourceProvider,
	nodeName string,
	ipv4Enabled bool,
	ipv6Enabled bool,
) *MACBindingController {
	c := &MACBindingController{
		sbClient:             sbClient,
		networkManager:       networkManager,
		uplinkSourceProvider: uplinkSourceProvider,
		nodeName:             nodeName,
		ipv4Enabled:          ipv4Enabled,
		ipv6Enabled:          ipv6Enabled,
		cdnGatewayPort:       util.GetNetworkScopedGWRouterExtPortName(types.DefaultNetworkName, nodeName),
		followers:            map[string]sets.Set[string]{},
	}

	c.macBindingReconciler = controller.NewReconciler(
		"mac-binding-reconciler",
		&controller.ReconcilerConfig{
			RateLimiter: controller.DefaultRateLimiter[string](),
			Reconcile:   c.reconcileMacBindingsUpdate,
			Threadiness: 1,
			MaxAttempts: 11, // with default rate limiter, retry during ~10s
		},
	)

	c.macBindingRefreshReconciler = controller.NewReconciler(
		"mac-binding-refresh-reconciler",
		&controller.ReconcilerConfig{
			RateLimiter: controller.DefaultRateLimiter[string](),
			Reconcile:   c.reconcileMacBindingsRefresh,
			Threadiness: 1,
			MaxAttempts: 11, // with default rate limiter, retry during ~1m
		},
	)

	c.networkReconciler = controller.NewReconciler(
		"mac-binding-network-reconciler",
		&controller.ReconcilerConfig{
			Reconcile:   c.reconcileNetwork,
			Threadiness: 1,
			MaxAttempts: controller.InfiniteAttempts,
		},
	)

	return c
}

// networkRefReconcilerFunc adapts a function to the
// networkmanager.NetworkRefReconciler interface.
type networkRefReconcilerFunc func(node, networkName string)

func (f networkRefReconcilerFunc) Reconcile(node, networkName string) { f(node, networkName) }

// Run starts the controller and blocks until stopCh is closed.
func (c *MACBindingController) Run(stopCh <-chan struct{}) error {
	klog.Info("Running MAC Binding controller...")

	// enqueue full network reconcile first
	c.enqueueAllNetworks()

	// register for events
	c.networkManager.RegisterNetworkRefReconciler(networkRefReconcilerFunc(func(node, networkName string) {
		if node != c.nodeName {
			return
		}
		c.enqueueNetwork(networkName)
	}))
	c.networkManager.RegisterNADReconciler(c.networkReconciler)
	c.registerSouthBoundEventHandlers()

	// start the reconcilers
	reconcilers := []controller.Reconciler{
		c.macBindingReconciler,
		c.macBindingRefreshReconciler,
		c.networkReconciler,
	}
	if err := controller.Start(reconcilers...); err != nil {
		return fmt.Errorf("failed to start MAC Binding controller: %w", err)
	}
	defer controller.Stop(reconcilers...)

	<-stopCh
	klog.Info("Stopping MAC Binding controller...")
	return nil
}

func (c *MACBindingController) ReconcileUplinkSource(network string) {
	port := util.GetNetworkScopedGWRouterExtPortName(network, c.nodeName)
	if c.tracksSource(port) {
		return
	}
	// Invalidate the memoized uplink->source designation. A nil cache doubles as
	// the "a full reconcile is due" signal (see hasUnknownSource), so the
	// enqueued reconcile won't be skipped and will relocate followers onto the
	// newly designated source.
	c.setMacBindingSourceForUplinks(nil)
	c.enqueueNetwork(network)
}

// --- event → enqueue plumbing -------------------------------------------

// keySep separates the designated port from the IP in a reconcile key.
// GR external port names never contain it.
const keySep = "|"

func (c *MACBindingController) enqueueNetwork(network string) {
	c.networkReconciler.Reconcile(network)
}

func (c *MACBindingController) enqueueAllNetworks() {
	c.networkReconciler.Reconcile("")
}

func (c *MACBindingController) enqueueFollower(follower string) {
	c.macBindingReconciler.Reconcile(follower)
}

func (c *MACBindingController) enqueueIP(source, ip string) {
	c.macBindingReconciler.Reconcile(source + keySep + ip)
}

func (c *MACBindingController) enqueueIPRefresh(source, ip string) {
	c.macBindingRefreshReconciler.Reconcile(source + keySep + ip)
}

// --- mac binding reconcilers --------------------------------------------

// reconcileMacBindingsUpdate handles the add/MAC-change path (macBindingReconciler):
// a source binding that is already stale by more than mirrorSourceStaleThresholdMs
// by the time we mirror it signals a backlog worth warning about.
func (c *MACBindingController) reconcileMacBindingsUpdate(key string) error {
	return c.reconcileMacBindings(key, updateWarnDelayThreshold)
}

// reconcileMacBindingsRefresh handles the timestamp-refresh path
// (macBindingRefreshReconciler), which is inherently less urgent: statctrl only
// refreshes a source periodically, so a source is not considered backlogged
// until it is stale by more than ovn_cooldown_period_ms.
func (c *MACBindingController) reconcileMacBindingsRefresh(key string) error {
	return c.reconcileMacBindings(key, refreshWarnDelayThreshold)
}

// reconcileMacBindings mirrors either a single (designated, ip) binding or, when no IP is
// given, all of a designated's bindings. warnDelayThresholdMs is the source
// staleness beyond which the single-IP mirror warns about a backlog.
func (c *MACBindingController) reconcileMacBindings(key string, warnDelayThresholdMs int) error {
	port, ip, _ := strings.Cut(key, keySep)
	if ip == "" {
		return c.reconcileMacBindingsForFollower(port)
	}
	return c.reconcileMacBindingsForIPFromSource(ip, port, warnDelayThresholdMs)
}

// reconcileMacBindingsForIPFromSource mirrors the designated's (ip, mac) onto every target port.
func (c *MACBindingController) reconcileMacBindingsForIPFromSource(ip, source string, warnDelayThresholdMs int) error {
	start := time.Now()
	followers := c.getFollowers(source)
	if len(followers) == 0 {
		return nil
	}

	err := c.setMacBindingsForIPFromSourceToTargets(ip, source, followers, warnDelayThresholdMs)
	if err != nil {
		return fmt.Errorf("failed to reconcile mac bindings for %s from source %s: %w", ip, source, err)
	}
	klog.V(5).Infof("Mirroring %s from %s to %d follower(s) took %s", ip, source, len(followers), time.Since(start))
	return nil
}

func (c *MACBindingController) reconcileMacBindingsForFollower(follower string) error {
	start := time.Now()
	source := c.getSourceForFollower(follower)
	if source == "" {
		return nil
	}

	err := c.setMacBindingsFromSourceToTarget(source, follower)
	if err != nil {
		return fmt.Errorf("failed to reconcile mac bindings for follower %s: %w", follower, err)
	}
	klog.V(5).Infof("Mirroring IPs from %s to follower %s took %s", source, follower, time.Since(start))
	return nil
}

// --- network reconcile + follower allocation engine ---------------------

// reconcileNetwork reacts to a NAD change. When the network still resolves, its
// uplink tells us which group to update; when it is gone we cannot tell, so a
// GC sweep re-checks every tracked network.
func (c *MACBindingController) reconcileNetwork(key string) error {
	if key == "" {
		// special key "" reconciles all
		return c.doReconcileAllNetworks()
	}

	// the key can be a NAD namespaced name or a network name
	var netInfo util.NetInfo
	namespace, _, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("failed to split meta namespace key %q: %w", key, err)
	}
	switch namespace {
	case "":
		netInfo = c.networkManager.GetNetwork(key)
	default:
		netInfo = c.networkManager.GetNetInfoForNADKey(key)
	}

	if netInfo == nil && namespace != "" {
		// deletes are handled with port binding events queueing networks, so
		// ignore NAD events
		return nil
	}

	// we can assume the key is the network name for our own cache lookups if it
	// doesn't exist
	networkName := key
	if netInfo != nil {
		networkName = netInfo.GetNetworkName()
	}
	portName := util.GetNetworkScopedGWRouterExtPortName(networkName, c.nodeName)

	// this might be a new source for our unknown source ports, full reconcile (enqueued
	// to dedup)
	if netInfo != nil && c.hasUnknownSource() {
		c.enqueueAllNetworks()
		return nil
	}

	// a port acting as source for followers might have been deleted (even if
	// network manager isn't aware yet), full reconcile to relocate its followers
	// (enqueued to dedup)
	if c.tracksSourceWithFollowers(portName) {
		c.enqueueAllNetworks()
		return nil
	}

	return c.doReconcileNetworks(networkName)
}

func (c *MACBindingController) doReconcileAllNetworks() error {
	return c.doReconcileNetworks()
}

func (c *MACBindingController) doReconcileNetworks(networks ...string) error {
	knownPorts := sets.New[string]()
	portToUplink := map[string]string{}
	var err error
	switch {
	case len(networks) == 0:
		// no network means reconcile all networks
		networks, err = c.getAllNetworkInfo(knownPorts, portToUplink)
	default:
		err = c.getNetworksInfo(networks, knownPorts, portToUplink)
	}
	if err != nil {
		return fmt.Errorf("faild to gather network info: %w", err)
	}

	// filter out ports that don't exist in the SB DB.
	validPorts, err := c.validatePorts(knownPorts)
	if err != nil {
		return err
	}

	addPorts := sets.New[string]()
	removePorts := sets.New[string]()
	trackedPorts := c.getAllPorts()
	for _, network := range networks {
		port := util.GetNetworkScopedGWRouterExtPortName(network, c.nodeName)
		switch {
		case trackedPorts.Has(port) && !validPorts.Has(port):
			removePorts.Insert(port)
		case !trackedPorts.Has(port) && validPorts.Has(port):
			addPorts.Insert(port)
		}
	}

	// skip on no additions or deletions and no unknown sources
	if addPorts.Len() == 0 && removePorts.Len() == 0 && !c.hasUnknownSource() {
		return nil
	}

	uplinkToSource := c.getMacBindingSourceForUplinks()
	newFollowers := c.updateFollowers(addPorts, removePorts, portToUplink, uplinkToSource)

	// sync mac bindings of new followers with an already known source
	for follower := range newFollowers {
		c.enqueueFollower(follower)
	}

	return nil
}

func (c *MACBindingController) getAllNetworkInfo(ports sets.Set[string], portToUplink map[string]string) ([]string, error) {
	// pre-fill default network info, network manager won't iterate through it
	networks := []string{types.DefaultNetworkName}
	ports.Insert(c.cdnGatewayPort)
	portToUplink[c.cdnGatewayPort] = ""

	err := c.networkManager.DoWithLock(func(network util.NetInfo) error {
		if !shouldTrackNetwork(network) {
			return nil
		}
		networks = append(networks, network.GetNetworkName())
		port := types.GWRouterToExtSwitchPrefix + network.GetNetworkScopedGWRouterName(c.nodeName)
		ports.Insert(port)
		portToUplink[port] = network.Uplink()
		return nil
	})

	return networks, err
}

func (c *MACBindingController) getNetworksInfo(networks []string, ports sets.Set[string], portToUplink map[string]string) error {
	for _, network := range networks {
		netInfo := c.networkManager.GetNetwork(network)
		if netInfo == nil || !shouldTrackNetwork(netInfo) {
			continue
		}
		port := util.GetNetworkScopedGWRouterExtPortName(network, c.nodeName)
		ports.Insert(port)
		portToUplink[port] = netInfo.Uplink()
	}
	return nil
}

func (c *MACBindingController) validatePorts(ports sets.Set[string]) (sets.Set[string], error) {
	validPorts := sets.New[string]()
	for port := range ports {
		_, err := ops.GetPortBinding(c.sbClient, &sbdb.PortBinding{LogicalPort: port})
		if errors.Is(err, libovsdbclient.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get port binding for port %q: %w", port, err)
		}
		validPorts.Insert(port)
	}
	return validPorts, nil
}

func (c *MACBindingController) updateFollowers(
	addPorts, removePorts sets.Set[string],
	portToUplink, uplinkToSource map[string]string,
) (newFollowers sets.Set[string]) {
	// prepare the inverse of uplinkToSource for convenience
	sourceToUplink := make(map[string]string, len(uplinkToSource))
	for uplink, source := range uplinkToSource {
		sourceToUplink[source] = uplink
	}

	// gather new ports by uplink, while also adding them to the ports map
	addPortsByUplink := map[string][]string{}
	for port := range addPorts {
		uplink := portToUplink[port]
		addPortsByUplink[uplink] = append(addPortsByUplink[uplink], port)
	}

	// track where ports land this round, for logging
	var logAddedBySource map[string][]string
	if klog.V(5).Enabled() {
		logAddedBySource = map[string][]string{}
	}

	c.Lock()
	defer c.Unlock()
	start := time.Now()

	newFollowers = sets.New[string]()
	removePortsList := removePorts.UnsortedList()
	followersWithNoSource := sets.New[string]()

	// big task: update followers map
	for source, followers := range c.followers {
		if source == "unknown" {
			// these are followers for which we don't know a source yet, handle
			// later
			continue
		}

		// remove followers
		followers.Delete(removePortsList...)

		// add followers on the same uplink as source
		uplink, isSource := sourceToUplink[source]
		if !isSource || removePorts.Has(source) {
			// source changed or removed, handle later
			followersWithNoSource.Insert(followers.UnsortedList()...)
			followersWithNoSource.Insert(source)
			delete(c.followers, source)
			continue
		}

		added := addPortsByUplink[uplink]
		followers.Insert(added...)
		followers.Delete(source)
		newFollowers.Insert(added...)
		newFollowers.Delete(source)
		delete(addPortsByUplink, uplink)

		if logAddedBySource != nil && len(added) > 0 {
			logAddedBySource[source] = sets.New(added...).Delete(source).UnsortedList()
		}
	}

	// Before handling new ports, treat followers with unknown source as if they
	// were new ports too. For the most part, the controller is only able to
	// relocate followers on full reconciliations where portToUplink has a
	// complete map of all networks.
	followersWithNoSource.Insert(c.followers["unknown"].UnsortedList()...)
	followersWithNoSource.Delete(removePortsList...)
	delete(c.followers, "unknown")
	for follower := range followersWithNoSource {
		uplink, knownUplink := portToUplink[follower]
		if !knownUplink {
			continue
		}
		addPortsByUplink[uplink] = append(addPortsByUplink[uplink], follower)
		delete(followersWithNoSource, follower)
	}

	// add new ports with known sources as followers
	for uplink, ports := range addPortsByUplink {
		source := uplinkToSource[uplink]
		portSet := sets.New(ports...)
		if source == "" || !portSet.Has(source) {
			// we don't have a source on the same uplink as this port
			followersWithNoSource.Insert(ports...)
			continue
		}

		c.followers[source] = portSet
		newFollowers.Insert(ports...)
		c.followers[source].Delete(source)
		newFollowers.Delete(source)

		if logAddedBySource != nil && len(ports) > 0 {
			logAddedBySource[source] = append(logAddedBySource[source], c.followers[source].UnsortedList()...)
		}
	}

	// if we still have ports with unknown sources, set them back as such
	if followersWithNoSource.Len() > 0 {
		c.followers["unknown"] = followersWithNoSource
		if logAddedBySource != nil {
			logAddedBySource["unknown"] = followersWithNoSource.UnsortedList()
		}
	}

	if logAddedBySource != nil {
		klog.V(5).Infof("Chaging follower allocation took %s: added ports: %v, removed ports: %v",
			time.Since(start),
			logAddedBySource,
			removePorts.UnsortedList(),
		)
	}

	return newFollowers
}

// --- stateless predicates -----------------------------------------------

func (c *MACBindingController) ipFamilyEnabled(ip string) bool {
	if utilnet.IsIPv6String(ip) {
		return c.ipv6Enabled
	}
	return c.ipv4Enabled
}

// shouldTrackNetwork reports whether a network takes part in MAC binding mirroring:
// a primary L2/L3 network present on this node.
func shouldTrackNetwork(netInfo util.NetInfo) bool {
	if netInfo == nil {
		return false
	}
	if !netInfo.IsPrimaryNetwork() && !netInfo.IsDefault() {
		return false
	}
	if !shouldTrackTopology(netInfo.TopologyType()) {
		return false
	}
	return true
}

func shouldTrackTopology(topology string) bool {
	return topology == types.Layer2Topology || topology == types.Layer3Topology
}

// --- locked state accessors ---------------------------------------------

// tracksSource reports whether source is a designated source, i.e. it is present
// in the follower map, even if it has no followers yet.
func (c *MACBindingController) tracksSource(source string) bool {
	c.RLock()
	defer c.RUnlock()
	_, ok := c.followers[source]
	return ok
}

// tracksSourceWithFollowers reports whether source is a designated source that
// currently has at least one follower to mirror MAC bindings onto.
func (c *MACBindingController) tracksSourceWithFollowers(source string) bool {
	c.RLock()
	defer c.RUnlock()
	return len(c.followers[source]) > 0
}

func (c *MACBindingController) getAllPorts() sets.Set[string] {
	c.RLock()
	defer c.RUnlock()
	ports := sets.New[string]()
	for source, followers := range c.followers {
		ports.Insert(source)
		ports.Insert(followers.UnsortedList()...)
	}
	return ports
}

func (c *MACBindingController) getFollowers(source string) []string {
	c.RLock()
	defer c.RUnlock()
	followers := c.followers[source]
	if followers == nil {
		return nil
	}
	return followers.UnsortedList()
}

func (c *MACBindingController) getSourceForFollower(follower string) string {
	c.RLock()
	defer c.RUnlock()
	for source, followers := range c.followers {
		if followers.Has(follower) {
			return source
		}
	}
	return ""
}

func (c *MACBindingController) hasUnknownSource() bool {
	c.RLock()
	defer c.RUnlock()
	if _, hasUnknown := c.followers["unknown"]; hasUnknown {
		return true
	}
	// A nil uplink->source cache means the designation was invalidated (at
	// startup, or by ReconcileUplinkSource on a re-designation) and a full
	// reconcile is due to recompute it.
	return c.macBindingSourceForUplinks.Load() == nil
}

func (c *MACBindingController) getMacBindingSourceForUplinks() map[string]string {
	macBindingSourceForUplinks := c.macBindingSourceForUplinks.Load()
	if macBindingSourceForUplinks != nil {
		return *macBindingSourceForUplinks
	}
	return c.setMacBindingSourceForUplinks(c.uplinkSourceProvider.GetMacBindingSourceForUplinks())
}

func (c *MACBindingController) setMacBindingSourceForUplinks(macBindingSourceForUplinks map[string]string) map[string]string {
	if macBindingSourceForUplinks == nil {
		c.macBindingSourceForUplinks.Store(nil)
		return nil
	}
	macBindingSourceForUplinks[""] = c.cdnGatewayPort
	c.macBindingSourceForUplinks.Store(&macBindingSourceForUplinks)
	return macBindingSourceForUplinks
}
