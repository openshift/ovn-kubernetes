// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/klog/v2"

	libovsdbcache "github.com/ovn-kubernetes/libovsdb/cache"
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
)

const (
	ovn_cooldown_period_ms  = int((3.0 / 16) * types.GRMACBindingAgeThresholdInt * 1000)
	ovnk_cooldown_period_ms = ovn_cooldown_period_ms * 4

	updateWarnDelayThreshold    = 1000
	refreshWarnDelayThreshold   = ovn_cooldown_period_ms
	warnDelayThrottleIntervalMs = int64(time.Minute / time.Millisecond)
)

// setMacBindingsForIPFromSourceToTargets reads the source's (ip, mac) binding
// and mirrors it onto every target port. warnDelayThresholdMs is the source
// staleness beyond which a backlog warning is emitted; the caller sets it lower
// for the add/MAC-change path than for the periodic refresh path.
func (c *MACBindingController) setMacBindingsForIPFromSourceToTargets(ip, source string, targets []string, warnDelayThresholdMs int) error {
	mb := &sbdb.MACBinding{LogicalPort: source, IP: ip}
	ctx, cancel := context.WithTimeout(context.Background(), config.Default.OVSDBTxnTimeout)
	defer cancel()
	err := c.sbClient.Get(ctx, mb)
	if errors.Is(err, libovsdbclient.ErrNotFound) {
		c.throttleBacklogWarning("MAC_Binding for %s on source port %s missing", ip, source)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get MAC_Binding for port %q IP %q: %w", source, ip, err)
	}
	if delay := int(time.Now().UnixMilli()) - mb.Timestamp; delay > warnDelayThresholdMs {
		c.throttleBacklogWarning("MAC_Binding for %s on source port %s is being refreshed with %dms delay (over %dms warning threshold)",
			source,
			ip,
			delay,
			warnDelayThresholdMs,
		)
	}

	return c.setMacBindingsFromSourceToTargets(map[string]string{mb.IP: mb.MAC}, source, targets)
}

func (c *MACBindingController) setMacBindingsFromSourceToTarget(source, target string) error {
	// using logical port as secondary index to find its mac bindings
	mb := &sbdb.MACBinding{LogicalPort: source}
	mbs := []*sbdb.MACBinding{}
	ctx, cancel := context.WithTimeout(context.Background(), config.Default.OVSDBTxnTimeout)
	defer cancel()
	err := c.sbClient.Where(mb).List(ctx, &mbs)
	if err != nil {
		return fmt.Errorf("failed to list MAC_Bindings for port %q: %w", source, err)
	}
	if len(mbs) == 0 {
		return nil
	}
	macBindings := map[string]string{}
	for _, mb := range mbs {
		if !c.ipFamilyEnabled(mb.IP) {
			continue
		}
		macBindings[mb.IP] = mb.MAC
	}

	return c.setMacBindingsFromSourceToTargets(macBindings, source, []string{target})
}

func (c *MACBindingController) setMacBindingsFromSourceToTargets(macBindings map[string]string, source string, followers []string) error {
	portToDatapath := map[string]string{}
	for _, follower := range followers {
		if source == follower {
			continue
		}
		pb, err := ops.GetPortBinding(c.sbClient, &sbdb.PortBinding{LogicalPort: follower})
		if errors.Is(err, libovsdbclient.ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get port binding for port %q: %w", follower, err)
		}
		if pb.Datapath == "" {
			continue
		}
		portToDatapath[follower] = pb.Datapath
	}
	if len(portToDatapath) == 0 {
		return nil
	}
	nowMs := int(time.Now().UnixMilli())
	return c.setMacBindings(macBindings, nowMs, portToDatapath)
}

// setMacBindings mirrors (ip, mac) as a MAC_Binding row for each target port
// in a single transaction. A row that does not yet exist is created; an existing
// row is updated only once its timestamp is older than the cooldown period, so
// mirrored writes don't churn a row that a target's own statctrl is still
// refreshing. The caller passes a fresh timestamp (time.Now). portToDatapath
// maps each target logical port to its datapath UUID.
func (c *MACBindingController) setMacBindings(macBindings map[string]string, timestamp int, portToDatapath map[string]string) error {
	allOps := make([]ovsdb.Operation, 0, len(portToDatapath)*len(macBindings))
	var cooldownSkipsCount, addCount, updateCount int
	for port, datapath := range portToDatapath {
		for ip, mac := range macBindings {
			mb := &sbdb.MACBinding{LogicalPort: port, IP: ip}
			var op []ovsdb.Operation
			ctx, cancel := context.WithTimeout(context.Background(), config.Default.OVSDBTxnTimeout)
			defer cancel()
			err := c.sbClient.Get(ctx, mb)
			switch {
			case errors.Is(err, libovsdbclient.ErrNotFound):
				addCount++
				op, err = c.sbClient.Create(&sbdb.MACBinding{
					LogicalPort: port,
					IP:          ip,
					MAC:         mac,
					Datapath:    datapath,
					Timestamp:   timestamp,
				})
			case err == nil:
				dt := timestamp - mb.Timestamp
				// The cooldown only throttles timestamp refreshes on an
				// otherwise-unchanged row (the target's own statctrl may still be
				// keeping it fresh). A changed MAC must be written immediately, or
				// the target keeps forwarding to a stale MAC until the cooldown
				// elapses.
				if mb.MAC == mac && dt < ovnk_cooldown_period_ms {
					cooldownSkipsCount++
					continue
				}
				updateCount++
				op, err = c.sbClient.Where(mb).Update(&sbdb.MACBinding{
					LogicalPort: port,
					IP:          ip,
					MAC:         mac,
					Timestamp:   timestamp,
				})
			}
			if err != nil {
				return err
			}
			allOps = append(allOps, op...)
		}
	}
	if len(allOps) == 0 {
		return nil
	}
	start := time.Now()
	_, err := ops.TransactAndCheck(c.sbClient, allOps)
	if err != nil {
		return err
	}
	klog.V(5).Infof("Took %s to execute a %d op(s) transaction to set %d mac bindings on %d ports with %d adds, %d updates and %d skips due to cooldown",
		time.Since(start),
		len(allOps),
		len(macBindings),
		len(portToDatapath),
		addCount,
		updateCount,
		cooldownSkipsCount,
	)
	return nil
}

func (c *MACBindingController) registerSouthBoundEventHandlers() {
	handleMacBinding := func(m, o model.Model) {
		mb := m.(*sbdb.MACBinding)
		if !c.ipFamilyEnabled(mb.IP) {
			return
		}
		if !strings.HasPrefix(mb.LogicalPort, types.GWRouterToExtSwitchPrefix) {
			return
		}
		if !c.tracksSourceWithFollowers(mb.LogicalPort) {
			return
		}
		var oldMAC string
		if o != nil {
			oldMAC = o.(*sbdb.MACBinding).MAC
		}
		switch mb.MAC {
		case oldMAC:
			c.enqueueIPRefresh(mb.LogicalPort, mb.IP)
		default:
			c.enqueueIP(mb.LogicalPort, mb.IP)
		}
	}
	handlePortBinding := func(m model.Model) {
		pb := m.(*sbdb.PortBinding)
		if !strings.HasPrefix(pb.LogicalPort, types.GWRouterToExtSwitchPrefix) {
			return
		}
		network := pb.ExternalIDs[types.NetworkExternalID]
		topology := pb.ExternalIDs[types.TopologyExternalID]
		if network != "" && !shouldTrackTopology(topology) {
			return
		}
		if pb.LogicalPort == c.cdnGatewayPort {
			network = types.DefaultNetworkName
		}
		if network == "" {
			return
		}
		c.enqueueNetwork(network)
	}
	handle := func(op, table string, m, o model.Model) {
		switch {
		case table == sbdb.MACBindingTable && op != "d":
			handleMacBinding(m, o)
		case table == sbdb.PortBindingTable && op != "u":
			handlePortBinding(m)
		}
	}
	c.sbClient.Cache().AddEventHandler(&libovsdbcache.EventHandlerFuncs{
		AddFunc:    func(table string, model model.Model) { handle("a", table, model, nil) },
		UpdateFunc: func(table string, old, new model.Model) { handle("u", table, new, old) },
		DeleteFunc: func(table string, model model.Model) { handle("d", table, model, nil) },
	})
}

// throttleBacklogWarning emits a throttled warning that a mirror source is stale or
// missing. Both hint that the controller is backlogged, which risks a target
// (UDN/CUDN) Gateway Router not having a MAC binding when it needs it. To avoid
// flooding the log while a backlog persists, at most one warning is emitted per
// backlogWarningIntervalMs regardless of how many sources or IPs are affected.
func (c *MACBindingController) throttleBacklogWarning(format string, args ...any) {
	if !c.allowBacklogWarning(time.Now().UnixMilli()) {
		return
	}
	klog.Warningf("Excessive delay mirroring MAC bindings (muted for the next %dms): "+format,
		append([]any{warnDelayThrottleIntervalMs}, args...)...,
	)
}

// allowBacklogWarning reports whether enough time has elapsed since the last
// backlog warning to emit another, recording nowMs as the new emission time when
// it returns true. It is safe for concurrent callers.
func (c *MACBindingController) allowBacklogWarning(nowMs int64) bool {
	last := c.lastBacklogWarningMs.Load()
	if nowMs-last < warnDelayThrottleIntervalMs {
		return false
	}
	// If a concurrent caller won the race and already recorded a newer emission,
	// let it own this interval's warning.
	return c.lastBacklogWarningMs.CompareAndSwap(last, nowMs)
}
