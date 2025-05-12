package routemanager

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// key of a managed route, only one route allowed with the same key
type key struct {
	dst      string
	table    int
	priority int
}

type Controller struct {
	*sync.Mutex
	store map[key]*netlink.Route
}

// NewController manages routes which include adding and deletion of routes. It
// also manages restoration of managed routes. Begin managing routes by calling
// Run() to start the manager. Routes should be added via Add(route) and
// deletion via Del(route) functions only. All other functions are used
// internally.
func NewController() *Controller {
	return &Controller{
		Mutex: &sync.Mutex{},
		store: make(map[key]*netlink.Route),
	}
}

// Run starts route manager and syncs at least every syncPeriod
func (c *Controller) Run(stopCh <-chan struct{}, syncPeriod time.Duration) {
	var err error
	var subscribed bool
	var routeEventCh chan netlink.RouteUpdate
	// netlink provides subscribing only to route events from the default table. Periodic sync will restore non-main table routes
	subscribed, routeEventCh = subscribeNetlinkRouteEvents(stopCh)
	ticker := time.NewTicker(syncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			// continue existing behaviour of not cleaning up routes upon exit
			return
		case newRouteEvent, ok := <-routeEventCh:
			if !ok {
				klog.Warning("Route Manager: netlink route events subscription lost, resubscribing...")
				subscribed, routeEventCh = subscribeNetlinkRouteEvents(stopCh)
				continue
			}
			if err = c.processNetlinkEvent(newRouteEvent); err != nil {
				// TODO: make util.GetNetLinkOps().IsLinkNotFoundError(err) smarter to unwrap error
				// and use it here to log errors that are not IsLinkNotFoundError
				klog.Errorf("Route Manager: failed to process route update event %v: %v", newRouteEvent, err)
			}
		case <-ticker.C:
			if !subscribed {
				klog.Warning("Route Manager: netlink route events subscription lost, resubscribing...")
				subscribed, routeEventCh = subscribeNetlinkRouteEvents(stopCh)
			}
			c.sync()
			ticker.Reset(syncPeriod)
		}
	}
}

// Add submits a request to add a route, instructing the kernel to replace a
// previously existing route. Route manager will periodically sync to ensure the
// provided route is installed and that no other routes with the same priority,
// prefix and table tuple exist. Thus note that if the provided route is not a
// replacement for an existing route, multiple routes with the same priority,
// prefix and table tuple may exist until sync happens.
func (c *Controller) Add(r netlink.Route) error {
	c.Lock()
	defer c.Unlock()
	return c.addRoute(&r)
}

// Del submits a request to delete and forget a route.
func (c *Controller) Del(r netlink.Route) error {
	c.Lock()
	defer c.Unlock()
	return c.delRoute(&r)
}

// addRoute attempts to add the route and returns with error
// if it fails to do so.
func (c *Controller) addRoute(r *netlink.Route) error {
	r, err := validateAndNormalizeRoute(r)
	if err != nil {
		return err
	}
	if c.hasRouteInStore(r) {
		// already managed - nothing to do
		return nil
	}
	err = c.netlinkAddRoute(r)
	if err != nil {
		return err
	}
	c.addRouteToStore(r)
	return nil
}

// delRoute attempts to remove the route and returns with error
// if it fails to do so.
func (c *Controller) delRoute(r *netlink.Route) error {
	r, err := validateAndNormalizeRoute(r)
	if err != nil {
		return err
	}
	err = c.netlinkDelRoute(r)
	if err != nil {
		return err
	}
	// also remove the route we had in store if different
	o := c.store[keyFromNetlink(r)]
	if o != nil && !util.RouteEqual(r, o) {
		err = c.netlinkDelRoute(o)
		if err != nil {
			return err
		}
	}
	c.removeRouteFromStore(r)
	return nil
}

// processNetlinkEvent will check if a deleted route is managed by route manager and if so, determine if a sync is needed
// to restore any managed routes.
func (c *Controller) processNetlinkEvent(ru netlink.RouteUpdate) error {
	c.Lock()
	defer c.Unlock()
	r := c.store[keyFromNetlink(&ru.Route)]
	if r == nil {
		return nil
	}
	if ru.Type == unix.RTM_DELROUTE || !routePartiallyEqualWantedToExisting(r, &ru.Route) {
		return c.netlinkAddRoute(r)
	}
	return nil
}

func (c *Controller) netlinkAddRoute(r *netlink.Route) error {
	err := util.GetNetLinkOps().RouteReplace(r)
	if err != nil {
		return fmt.Errorf("failed to add route %s: %w", r, err)
	}
	klog.V(5).Infof("Route Manager: added route %s", r)
	return nil
}

func (c *Controller) netlinkDelRoute(r *netlink.Route) error {
	err := util.GetNetLinkOps().RouteDel(r)
	if err != nil && !isRouteNotFoundError(err) {
		return fmt.Errorf("failed to delete route %s: %w", r, err)
	}
	klog.V(5).Infof("Route Manager: deleted route %s", r)
	return nil
}

// addRouteToStore adds routes to the internal cache
// Must be called with the controller locked
func (c *Controller) addRouteToStore(r *netlink.Route) {
	route := keyFromNetlink(r)
	c.store[route] = r
}

// removeRouteFromStore removes route from the internal cache
// Must be called with the controller locked
func (c *Controller) removeRouteFromStore(r *netlink.Route) {
	delete(c.store, keyFromNetlink(r))
}

// hasRouteInStore checks if a route with the same key is stored in the
// internal cache as requested. Must be called with the controller locked
func (c *Controller) hasRouteInStore(r *netlink.Route) bool {
	route := c.store[keyFromNetlink(r)]
	return route != nil && util.RouteEqual(r, route)
}

func validateAndNormalizeRoute(r *netlink.Route) (*netlink.Route, error) {
	if r == nil {
		return nil, fmt.Errorf("nil route provided")
	}
	if r.Table == unix.RT_TABLE_UNSPEC {
		r.Table = unix.RT_TABLE_MAIN
	}
	return r, nil
}

func keyFromNetlink(r *netlink.Route) key {
	return key{
		dst:      r.Dst.String(),
		table:    r.Table,
		priority: r.Priority,
	}
}

// sync will iterate through all routes seen on a node and ensure any route
// manager managed routes are applied. Any conflicting additional routes are
// removed. Other routes are preserved.
func (c *Controller) sync() {
	c.Lock()
	defer c.Unlock()

	var read, added, deleted int
	start := time.Now()
	defer func() {
		klog.V(5).Infof("Route Manager: synced routes: stored[%d] read[%d] added[%d] deleted[%d], took %s",
			len(c.store),
			read,
			added,
			deleted,
			time.Since(start),
		)
	}()

	// there can be many routes on the system so make sure we list them as few
	// times as possible
	// note that RouteListFiltered dumps ALL routes, filtering happens on the
	// client side
	// we need to filter by table without specifying any table to get routes
	// form all tables
	filter := &netlink.Route{}
	mask := netlink.RT_FILTER_TABLE
	existing, err := util.GetNetLinkOps().RouteListFiltered(netlink.FAMILY_ALL, filter, mask)
	if err != nil {
		klog.Errorf("Route Manager: failed to list routes: %v", err)
		return
	}
	read = len(existing)

	existingAndTracked := map[key][]*netlink.Route{}
	for _, r := range existing {
		key := keyFromNetlink(&r)
		wants := c.store[key]
		if wants == nil {
			continue
		}
		existingAndTracked[key] = append(existingAndTracked[key], &r)
	}

	for key, wants := range c.store {
		existing := existingAndTracked[key]
		if len(existing) == 1 && routePartiallyEqualWantedToExisting(wants, existing[0]) {
			continue
		}
		// take the safe approach to delete routes before adding ours to make
		// sure we don't end up deleting what we shouldn't
		// deleting now may cause network blips until we add our route but
		// nobody should be manipulating conflicting routes anyway
		for _, r := range existing {
			err := c.netlinkDelRoute(r)
			if err != nil {
				klog.Errorf("Route Manager: failed while syncing: %v", err)
				continue
			}
			klog.Warningf("Route Manager: removed unexpected route %s", r)
			deleted++
		}
		err := c.netlinkAddRoute(wants)
		if err != nil {
			klog.Errorf("Route Manager: failed while syncing: %v", err)
			continue
		}
		added++
	}
}

func subscribeNetlinkRouteEvents(stopCh <-chan struct{}) (bool, chan netlink.RouteUpdate) {
	routeEventCh := make(chan netlink.RouteUpdate, 20)
	if err := netlink.RouteSubscribe(routeEventCh, stopCh); err != nil {
		klog.Errorf("Route Manager: failed to subscribe to netlink route events: %v", err)
		return false, routeEventCh
	}
	return true, routeEventCh
}

func equalOrLeftZero[T comparable](l, r, z T) bool {
	return l == z || l == r
}

func equalOrLeftZeroFunc[T any](eq func(l, r T) bool, l, r, z T) bool {
	return eq(l, z) || eq(l, r)
}

// routePartiallyEqualWantedToExisting compares non zero values of left wanted route with the
// right existing route. The reason for not using the Equal method associated
// with type netlink.Route is because a user will only specify a limited subset
// of fields but when we introspect routes seen on the system, other fields are
// populated by default and therefore won't be equal anymore with user defined
// routes. Also, netlink.Routes Equal method doesn't compare MTU.
func routePartiallyEqualWantedToExisting(w, e *netlink.Route) bool {
	if (w == nil) != (e == nil) {
		return false
	}
	if w == e {
		return true
	}
	// this compares dst, table and priority which must be equal for us
	if keyFromNetlink(w) != keyFromNetlink(e) {
		return false
	}
	var z netlink.Route
	return equalOrLeftZero(w.LinkIndex, e.LinkIndex, z.LinkIndex) &&
		equalOrLeftZero(w.ILinkIndex, e.ILinkIndex, z.ILinkIndex) &&
		equalOrLeftZero(w.Scope, e.Scope, z.Scope) &&
		equalOrLeftZeroFunc(func(l, r net.IP) bool { return l.Equal(r) }, w.Src, e.Src, z.Src) &&
		equalOrLeftZeroFunc(func(l, r net.IP) bool { return l.Equal(r) }, w.Gw, e.Gw, z.Gw) &&
		equalOrLeftZeroFunc(
			func(l, r []*netlink.NexthopInfo) bool {
				return slices.EqualFunc(l, r,
					func(l, r *netlink.NexthopInfo) bool { return l == r || (l != nil && r != nil && l.Equal(*r)) },
				)
			}, w.MultiPath, e.MultiPath, z.MultiPath) &&
		equalOrLeftZero(w.Protocol, e.Protocol, z.Protocol) &&
		equalOrLeftZero(w.Family, e.Family, z.Family) &&
		equalOrLeftZero(w.Type, e.Type, z.Type) &&
		equalOrLeftZero(w.Tos, e.Tos, z.Tos) &&
		equalOrLeftZero(w.Flags, e.Flags, z.Flags) &&
		equalOrLeftZeroFunc(func(l, r *int) bool { return l == r || (l != nil && r != nil && *l == *r) }, w.MPLSDst, e.MPLSDst, z.MPLSDst) &&
		equalOrLeftZeroFunc(func(l, r netlink.Destination) bool { return l == r || (l != nil && r != nil && l.Equal(r)) }, w.NewDst, e.NewDst, z.NewDst) &&
		equalOrLeftZeroFunc(func(l, r netlink.Encap) bool { return l == r || (l != nil && r != nil && l.Equal(r)) }, w.Encap, e.Encap, z.Encap) &&
		equalOrLeftZeroFunc(func(l, r netlink.Destination) bool { return l == r || (l != nil && r != nil && l.Equal(r)) }, w.Via, e.Via, z.Via) &&
		equalOrLeftZero(w.Realm, e.Realm, z.Realm) &&
		equalOrLeftZero(w.MTU, e.MTU, z.MTU) &&
		equalOrLeftZero(w.Window, e.Window, z.Window) &&
		equalOrLeftZero(w.Rtt, e.Rtt, z.Rtt) &&
		equalOrLeftZero(w.RttVar, e.RttVar, z.RttVar) &&
		equalOrLeftZero(w.Ssthresh, e.Ssthresh, z.Ssthresh) &&
		equalOrLeftZero(w.Cwnd, e.Cwnd, z.Cwnd) &&
		equalOrLeftZero(w.AdvMSS, e.AdvMSS, z.AdvMSS) &&
		equalOrLeftZero(w.Reordering, e.Reordering, z.Reordering) &&
		equalOrLeftZero(w.Hoplimit, e.Hoplimit, z.Hoplimit) &&
		equalOrLeftZero(w.InitCwnd, e.InitCwnd, z.InitCwnd) &&
		equalOrLeftZero(w.Features, e.Features, z.Features) &&
		equalOrLeftZero(w.RtoMin, e.RtoMin, z.RtoMin) &&
		equalOrLeftZero(w.InitRwnd, e.InitRwnd, z.InitRwnd) &&
		equalOrLeftZero(w.QuickACK, e.QuickACK, z.QuickACK) &&
		equalOrLeftZero(w.Congctl, e.Congctl, z.Congctl) &&
		equalOrLeftZero(w.FastOpenNoCookie, e.FastOpenNoCookie, z.FastOpenNoCookie)
}

func isRouteNotFoundError(err error) bool {
	return strings.Contains(err.Error(), "no such process")
}
