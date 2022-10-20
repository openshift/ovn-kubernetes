package node

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/healthcheck"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/pkg/errors"

	kapi "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

// initLoadBalancerHealthChecker initializes the health check server for
// ServiceTypeLoadBalancer services

type loadBalancerHealthChecker struct {
	sync.Mutex
	nodeName      string
	server        healthcheck.Server
	services      map[ktypes.NamespacedName]uint16
	endpoints     map[ktypes.NamespacedName]int
	endpoints_dry map[ktypes.NamespacedName]int
	watchFactory  factory.NodeWatchFactory
}

func newLoadBalancerHealthChecker(nodeName string, watchFactory factory.NodeWatchFactory) *loadBalancerHealthChecker {
	return &loadBalancerHealthChecker{
		nodeName:      nodeName,
		server:        healthcheck.NewServer(nodeName, nil, nil, nil),
		services:      make(map[ktypes.NamespacedName]uint16),
		endpoints:     make(map[ktypes.NamespacedName]int),
		endpoints_dry: make(map[ktypes.NamespacedName]int),
		watchFactory:  watchFactory,
	}
}

func (l *loadBalancerHealthChecker) AddService(svc *kapi.Service) {
	klog.Infof("[AddService] riccardo:  %s/%s, svc=%v", svc.Namespace, svc.Name, svc)

	// TODO aren't we hitting this code at all?
	// Why is the l.services[name] entry never created??
	if svc.Spec.HealthCheckNodePort != 0 {
		l.Lock()
		defer l.Unlock()
		name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
		l.services[name] = uint16(svc.Spec.HealthCheckNodePort)
		klog.Infof("[AddService] riccardo:  %s/%s calling l.server.SyncServices on %v",
			svc.Namespace, svc.Name, l.services)
		_ = l.server.SyncServices(l.services)
	} else {
		klog.Infof("[AddService] riccardo:  %s/%s, "+
			"svc.Spec.HealthCheckNodePort == 0 (%v), SKIP",
			svc.Namespace, svc.Name, svc.Spec.HealthCheckNodePort)
	}
}

func (l *loadBalancerHealthChecker) UpdateService(old, new *kapi.Service) {
	// if the ETP values have changed between local and cluster,
	// we need to update health checks accordingly
	// HealthCheckNodePort is used only in ETP=local mode
	if old.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeCluster &&
		new.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeLocal {
		l.AddService(new)
		epSlices, err := l.watchFactory.GetEndpointSlices(new.Namespace, new.Name)
		if err != nil {
			klog.V(4).Infof("Could not fetch endpointslices for service %s/%s during health check update service", new.Namespace, new.Name)
		}
		namespacedName := ktypes.NamespacedName{Namespace: new.Namespace, Name: new.Name}
		l.Lock()
		l.endpoints[namespacedName] = l.CountLocalEndpointAddresses(epSlices)
		_ = l.server.SyncEndpoints(l.endpoints)
		l.Unlock()
	}
	if old.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeLocal &&
		new.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeCluster {
		l.DeleteService(old)
	}
}

func (l *loadBalancerHealthChecker) DeleteService(svc *kapi.Service) {
	klog.Infof("[DeleteService] riccardo:  %s/%s, svc=%v", svc.Namespace, svc.Name, svc)

	if svc.Spec.HealthCheckNodePort != 0 {
		l.Lock()
		defer l.Unlock()
		name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
		delete(l.services, name)
		delete(l.endpoints, name)
		delete(l.endpoints_dry, name)
		klog.Infof("[DeleteService] riccardo:  %s/%s calling l.server.SyncServices on %v",
			svc.Namespace, svc.Name, l.services)
		_ = l.server.SyncServices(l.services)
	} else {
		klog.Infof("[DeleteService] riccardo:  %s/%s, "+
			"svc.Spec.HealthCheckNodePort == 0 (%v), SKIP",
			svc.Namespace, svc.Name, svc.Spec.HealthCheckNodePort)
	}
}

func (l *loadBalancerHealthChecker) SyncServices(svcs []interface{}) error {
	return nil
}

func (l *loadBalancerHealthChecker) AddEndpoints(ep *kapi.Endpoints) {
	// Real run for add operation on endpoints
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	l.Lock()
	defer l.Unlock()
	if _, exists := l.services[name]; exists {
		l.endpoints_dry[name] = countLocalEndpoints(ep, l.nodeName)
		klog.Infof("[AddEndpoints, REAL RUN] riccardo: for %s, local endpoints: %d, calling SyncEndpoints on l.endpoints_dry=%v",
			name, l.endpoints_dry[name], l.endpoints_dry)
		_ = l.server.SyncEndpoints(l.endpoints_dry)
	} else {
		klog.Infof("[AddEndpoints, REAL RUN] riccardo: SKIP %s, not in l.services: %v",
			name.String(), l.services)
	}
}

func (l *loadBalancerHealthChecker) UpdateEndpoints(old, new *kapi.Endpoints) {
	// DRY run for update operation on endpoints
	name := ktypes.NamespacedName{Namespace: new.Namespace, Name: new.Name}
	l.Lock()
	defer l.Unlock()
	if _, exists := l.services[name]; exists {
		l.endpoints_dry[name] = countLocalEndpoints(new, l.nodeName)
		klog.Infof("[UpdateEndpoints, DRY RUN] riccardo: for %s, local endpoints: %d,"+
			" calling SyncEndpoints on l.endpoints_dry=%v, old endpoints=%v, new endpoints=%v",
			name, l.endpoints_dry[name], l.endpoints_dry, old, new)
		// _ = l.server.SyncEndpoints(l.endpoints_dry)
	} else {
		klog.Infof("[UpdateEndpoints, DRY RUN] riccardo: SKIP %s, not in l.services: %v,"+
			" old endpoints: %v, new endpoints: %v",
			name.String(), l.services, old, new)
	}

}

func (l *loadBalancerHealthChecker) DeleteEndpoints(ep *kapi.Endpoints) {
	// Real run for delete operation on endpoints
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	l.Lock()
	defer l.Unlock()
	delete(l.endpoints_dry, name)
	klog.Infof("[DeleteEndpoints, REAL RUN] riccardo: for %s, calling SyncEndpoints on l.endpoints_dry=%v, deleted ep=%v",
		name, l.endpoints_dry, ep)
	_ = l.server.SyncEndpoints(l.endpoints_dry)
}

func countLocalEndpoints(ep *kapi.Endpoints, nodeName string) int { // TODO call it countLocalEndpointAddresses
	num := 0
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Addresses {
			addr := &ss.Addresses[i]
			if addr.NodeName != nil && *addr.NodeName == nodeName {
				num++
			}
		}
	}
	klog.Infof("[countLocalEndpoints] riccardo: ep=%v, nodeName=%s, num=%d", ep, nodeName, num)
	return num
}

func (l *loadBalancerHealthChecker) SyncEndPointSlices(epSlice *discovery.EndpointSlice, dryRun bool) {
	// Get all endpointslices for the service that corresponds to this epSlice
	// Count the # of local endpoints for these endpoint slices
	// Call SyncEndpoints on all endpoints stored in cache l.endpoints
	namespacedName, err := namespacedNameFromEPSlice(epSlice)
	if err != nil {
		klog.Errorf("[SyncEndPointSlices] riccardo: SKIP no service for this endpoint slice: %v", err)
		return
	}
	epSlices, err := l.watchFactory.GetEndpointSlices(epSlice.Namespace, epSlice.Labels[discovery.LabelServiceName])
	if err != nil {
		// should be a rare occurence
		klog.V(4).Infof("Could not fetch endpointslices for %s during health check", namespacedName.String())
	}

	localEndpointAddressCount := l.CountLocalEndpointAddresses(epSlices)
	if len(epSlices) == 0 {
		// let's delete it from cache and wait for the next update; this will show as 0 endpoints for health checks
		delete(l.endpoints, namespacedName)
	} else {
		l.endpoints[namespacedName] = localEndpointAddressCount
	}
	klog.Infof("[SyncEndPointSlices] riccardo: epSlice=%s/%s, service %s, local=%v, all epSlices: %v",
		epSlice.Namespace, epSlice.Name, namespacedName.String(), localEndpointAddressCount, epSlices)

	if !dryRun {
		klog.Infof("[SyncEndPointSlices, REAL RUN] riccardo:  epSlice=%s/%s, for svc %s, calling SyncEndpoints on l.endpoints=%v",
			epSlice.Namespace, epSlice.Name, namespacedName.String(), l.endpoints)
		_ = l.server.SyncEndpoints(l.endpoints)
	} else {
		klog.Infof("[SyncEndPointSlices, DRY RUN] riccardo: epSlice=%s/%s, for svc %s, calling SyncEndpoints on l.endpoints=%v",
			epSlice.Namespace, epSlice.Name, namespacedName.String(), l.endpoints)
	}
}

func (l *loadBalancerHealthChecker) AddEndpointSlice(epSlice *discovery.EndpointSlice) {
	// DRY run for the ADD operation on endpointslice events
	namespacedName, err := namespacedNameFromEPSlice(epSlice)
	if err != nil {
		klog.Errorf("[AddEndpointSlice, DRY RUN] riccardo: no service label for epslice, SKIP: %v", err)
		return
	}
	l.Lock()
	defer l.Unlock()
	if _, exists := l.services[namespacedName]; exists {
		klog.Infof("[AddEndpointSlice, DRY RUN] riccardo: %s/%v, calling SyncEndpointSlices",
			epSlice.Namespace, epSlice.Name)
		l.SyncEndPointSlices(epSlice, true) // dryRun=True
	} else {
		klog.Infof("[AddEndpointSlice, DRY RUN] riccardo: SKIP %s, not in l.services: %v",
			namespacedName.String(), l.services)
	}
}

func (l *loadBalancerHealthChecker) UpdateEndpointSlice(oldEpSlice, newEpSlice *discovery.EndpointSlice) {
	// Real RUN for the update operation on endpointslice events
	namespacedName, err := namespacedNameFromEPSlice(newEpSlice)
	if err != nil {
		klog.Errorf("[UpdateEndpointSlice, REAL RUN] riccardo: no service label for new epslice, SKIP: %v", err)
		return
	}
	oldNamespacedName, err := namespacedNameFromEPSlice(oldEpSlice)
	if err != nil {
		klog.Errorf("[UpdateEndpointSlice, REAL RUN] riccardo: no service label for old epslice, SKIP: %v", err)
		return
	}
	klog.Infof("[UpdateEndpointSlice, REAL RUN] riccardo: old=%s/%s, new=%s/%s, oldSvc=%s, newSvc=%s; l.services=%v, old=%v, new=%v",
		oldEpSlice.Namespace, oldEpSlice.Name, newEpSlice.Namespace, newEpSlice.Name,
		oldNamespacedName.String(), namespacedName.String(), l.services, oldEpSlice, newEpSlice)

	l.Lock()
	defer l.Unlock()

	// if _, exists := l.services[oldNamespacedName]; exists {
	// 	klog.Infof("[UpdateEndpointSlice, REAL RUN, old] riccardo: old=%s/%s, new=%s/%s, oldSvc=%s, newSvc=%s; calling SyncEndpointSlices on oldEpSlice",
	// 		oldEpSlice.Namespace, oldEpSlice.Name,
	// 		newEpSlice.Namespace, newEpSlice.Name,
	// 		oldNamespacedName.String(), namespacedName.String())
	// 	l.SyncEndPointSlices(oldEpSlice, false) // dryRun=false

	// } else {
	// 	klog.Infof("[UpdateEndpointSlice, REAL RUN, old] riccardo: SKIP %s, not in l.services: %v",
	// 		oldNamespacedName.String(), l.services)
	// }

	if _, exists := l.services[namespacedName]; exists {
		klog.Infof("[UpdateEndpointSlice, REAL RUN, new] riccardo: old=%s/%s, new=%s/%s, oldSvc=%s, newSvc=%s; calling SyncEndpointSlices on newEpSlice",
			oldEpSlice.Namespace, oldEpSlice.Name,
			newEpSlice.Namespace, newEpSlice.Name,
			oldNamespacedName.String(), namespacedName.String())
		l.SyncEndPointSlices(newEpSlice, false) // dryRun=false

	} else {
		klog.Infof("[UpdateEndpointSlice, REAL RUN, new] riccardo: SKIP %s, not in l.services: %v",
			namespacedName.String(), l.services)
	}

}

func (l *loadBalancerHealthChecker) DeleteEndpointSlice(epSlice *discovery.EndpointSlice) {
	// DRY RUN for the delete operation on endpointslice events
	_, err := namespacedNameFromEPSlice(epSlice)
	if err != nil {
		klog.Errorf("[DeleteEndpointSlice, DRY RUN] riccardo: no service label for epslice, SKIP: %v", err)
		return
	}
	l.Lock()
	defer l.Unlock()
	klog.Infof("[DeleteEndpointSlice, DRY RUN] riccardo: %s/%v, calling SyncEndpointSlices",
		epSlice.Namespace, epSlice.Name)
	l.SyncEndPointSlices(epSlice, true) // dryRun=true
}

// GetLocalEndpointAddresses returns the number of IP addresses from ready endpoints that are local
// to the node for a service
func (l *loadBalancerHealthChecker) CountLocalEndpointAddresses(endpointSlices []*discovery.EndpointSlice) int {
	localEndpointAddresses := sets.NewString()
	for _, endpointSlice := range endpointSlices {
		for _, endpoint := range endpointSlice.Endpoints {
			isLocal := endpoint.NodeName != nil && *endpoint.NodeName == l.nodeName
			if isEndpointReady(endpoint) && isLocal {
				localEndpointAddresses.Insert(endpoint.Addresses...)
			}
		}
	}
	klog.Infof("[CountLocalEndpointAddresses, epslice riccardo: len(localEndpointAddresses)=%d for endpointSlices=%v",
		len(localEndpointAddresses), endpointSlices)
	return len(localEndpointAddresses)
}

// // GetLocalEndpointAddresses returns the number of endpoints that are local to the node for a service
// func (l *loadBalancerHealthChecker) GetLocalEndpointAddressesCount(endpointSlices []*discovery.EndpointSlice) int {
// 	localEndpoints := sets.NewString()
// 	for _, endpointSlice := range endpointSlices {
// 		for _, endpoint := range endpointSlice.Endpoints {
// 			// Skip endpoints that are not ready
// 			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
// 				klog.Infof("[GetLocalEndpointAddressesCount, epslice ] SKIP non-ready endpoint %v", endpoint)
// 				continue
// 			}

// 			if endpoint.NodeName != nil && *endpoint.NodeName == l.nodeName {
// 				klog.Infof("[GetLocalEndpointAddressesCount, epslice] riccardo: found local endpoint %v (node=%s)",
// 					endpoint, l.nodeName)
// 				localEndpoints.Insert(endpoint.Addresses...)
// 			}
// 		}
// 	}
// 	klog.Infof("[GetLocalEndpointAddressesCount, epslice riccardo: res=%d for endpointSlices=%v",
// 		len(localEndpoints), endpointSlices)
// 	return len(localEndpoints)
// }

// hasLocalHostNetworkEndpoints_old returns true if there is at least one host-networked endpoint
// in the provided list that is local to this node.
// It returns false if none of the endpoints are local host-networked endpoints or if ep.Subsets is nil.
func hasLocalHostNetworkEndpoints_old(ep *kapi.Endpoints, nodeAddresses []net.IP) bool {
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Addresses {
			addr := &ss.Addresses[i]
			for _, nodeIP := range nodeAddresses {
				if nodeIP.String() == addr.IP {
					klog.Infof("[hasLocalHostNetworkEndpoints_old] riccardo: %v : true, ep=%v, nodeAddresses=%v",
						addr.IP, ep, nodeAddresses)
					return true
				}
			}
		}
	}
	klog.Infof("[hasLocalHostNetworkEndpoints_old] riccardo: false (ep=%v, nodeAddresses=%v)",
		ep, nodeAddresses)

	return false
}

// hasLocalHostNetworkEndpoints returns true if there is at least one host-networked endpoint
// in the provided list that is local to this node.
// It returns false if none of the endpoints are local host-networked endpoints or if ep.Subsets is nil.
func hasLocalHostNetworkEndpoints(epSlices []*discovery.EndpointSlice, nodeAddresses []net.IP) bool {
	for _, epSlice := range epSlices {
		for _, endpoint := range epSlice.Endpoints {
			if !isEndpointReady(endpoint) {
				// skip endpoints that are not ready
				klog.Infof("[hasLocalHostNetworkEndpoints] %s/%s skipping non-ready endpoint %v",
					epSlice.Namespace, epSlice.Name, endpoint)
				continue
			}
			for _, ip := range endpoint.Addresses {
				for _, nodeIP := range nodeAddresses {
					if nodeIP.String() == ip {
						klog.Infof("[hasLocalHostNetworkEndpoints] %s/%s %v : true, epslice=%v",
							epSlice.Namespace, epSlice.Name, ip, epSlice)
						return true
					}
				}
			}
		}
	}
	klog.Infof("[hasLocalHostNetworkEndpoints] riccardo: false (epSlices=%v, nodeAddresses=%v)",
		epSlices, nodeAddresses)

	return false
}

// discovery.EndpointSlice reports in the same slice all endpoints along with their status.
// isEndpointReady takes an endpoint from an endpoint slice and returns true if the endpoint is
// to be considered ready.
func isEndpointReady(endpoint discovery.Endpoint) bool {
	return endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready
}

// checkForStaleOVSInternalPorts checks for OVS internal ports without any ofport assigned,
// they are stale ports that must be deleted
func checkForStaleOVSInternalPorts() {
	// Track how long scrubbing stale interfaces takes
	start := time.Now()
	defer func() {
		klog.V(5).Infof("CheckForStaleOVSInternalPorts took %v", time.Since(start))
	}()

	stdout, _, err := util.RunOVSVsctl("--data=bare", "--no-headings", "--columns=name", "find",
		"interface", "ofport=-1")
	if err != nil {
		klog.Errorf("Failed to list OVS interfaces with ofport set to -1")
		return
	}
	if len(stdout) == 0 {
		return
	}
	// Batched command length overload shouldn't be a worry here since the number
	// of interfaces per node should never be very large
	// TODO: change this to use libovsdb
	staleInterfaceArgs := []string{}
	values := strings.Split(stdout, "\n\n")
	for _, val := range values {
		klog.Warningf("Found stale interface %s, so queuing it to be deleted", val)
		if len(staleInterfaceArgs) > 0 {
			staleInterfaceArgs = append(staleInterfaceArgs, "--")
		}

		staleInterfaceArgs = append(staleInterfaceArgs, "--if-exists", "--with-iface", "del-port", val)
	}

	_, stderr, err := util.RunOVSVsctl(staleInterfaceArgs...)
	if err != nil {
		klog.Errorf("Failed to delete OVS port/interfaces: stderr: %s (%v)",
			stderr, err)
	}
}

// checkForStaleOVSRepresentorInterfaces checks for stale OVS ports backed by Repreresentor interfaces,
// derive iface-id from pod name and namespace then remove any interfaces assoicated with a sandbox that are
// not scheduled to the node.
func checkForStaleOVSRepresentorInterfaces(nodeName string, wf factory.ObjectCacheInterface) {
	// Get all ovn-kuberntes Pod interfaces. these are OVS interfaces that have their external_ids:sandbox set.
	out, stderr, err := util.RunOVSVsctl("--columns=name,external_ids", "--data=bare", "--no-headings",
		"--format=csv", "find", "Interface", "external_ids:sandbox!=\"\"", "external_ids:vf-netdev-name!=\"\"")
	if err != nil {
		klog.Errorf("Failed to list ovn-k8s OVS interfaces:, stderr: %q, error: %v", stderr, err)
		return
	}

	// parse this data into local struct
	type interfaceInfo struct {
		Name       string
		Attributes map[string]string
	}

	lines := strings.Split(out, "\n")
	interfaceInfos := make([]*interfaceInfo, 0, len(lines))
	for _, line := range lines {
		cols := strings.Split(line, ",")
		// Note: There are exactly 2 column entries as requested in the ovs query
		// Col 0: interface name
		// Col 1: space separated key=val pairs of external_ids attributes
		if len(cols) < 2 {
			// unlikely to happen
			continue
		}
		ifcInfo := interfaceInfo{Name: strings.TrimSpace(cols[0]), Attributes: make(map[string]string)}
		for _, attr := range strings.Split(cols[1], " ") {
			keyVal := strings.SplitN(attr, "=", 2)
			if len(keyVal) != 2 {
				// unlikely to happen
				continue
			}
			ifcInfo.Attributes[keyVal[0]] = keyVal[1]
		}
		interfaceInfos = append(interfaceInfos, &ifcInfo)
	}

	if len(interfaceInfos) == 0 {
		return
	}

	// list Pods and calculate the expected iface-ids.
	// Note: we do this after scanning ovs interfaces to avoid deleting ports of pods that where just scheduled
	// on the node.
	pods, err := wf.GetPods("")
	if err != nil {
		klog.Errorf("Failed to list pods. %v", err)
		return
	}
	expectedIfaceIds := make(map[string]bool)
	for _, pod := range pods {
		if pod.Spec.NodeName == nodeName {
			// Note: wf (WatchFactory) *usually* returns pods assigned to this node, however we dont rely on it
			// and add this check to filter out pods assigned to other nodes. (e.g when ovnkube master and node
			// share the same process)
			expectedIfaceIds[util.GetIfaceId(pod.Namespace, pod.Name)] = true
		}
	}

	// Remove any stale representor ports
	for _, ifaceInfo := range interfaceInfos {
		ifaceId, ok := ifaceInfo.Attributes["iface-id"]
		if !ok {
			klog.Warningf("iface-id attribute was not found for OVS interface %s. "+
				"skipping cleanup check for interface", ifaceInfo.Name)
			continue
		}
		if _, ok := expectedIfaceIds[ifaceId]; !ok {
			klog.Warningf("Found stale OVS Interface, deleting OVS Port with interface %s", ifaceInfo.Name)
			_, stderr, err := util.RunOVSVsctl("--if-exists", "--with-iface", "del-port", ifaceInfo.Name)
			if err != nil {
				klog.Errorf("Failed to delete interface %q . stderr: %q, error: %v",
					ifaceInfo.Name, stderr, err)
				continue
			}
		}
	}
}

// checkForStaleOVSInterfaces periodically checks for stale OVS interfaces
func checkForStaleOVSInterfaces(nodeName string, wf factory.ObjectCacheInterface) {
	checkForStaleOVSInternalPorts()
	checkForStaleOVSRepresentorInterfaces(nodeName, wf)
}

type openflowManager struct {
	defaultBridge         *bridgeConfiguration
	externalGatewayBridge *bridgeConfiguration
	// flow cache, use map instead of array for readability when debugging
	flowCache     map[string][]string
	flowMutex     sync.Mutex
	exGWFlowCache map[string][]string
	exGWFlowMutex sync.Mutex
	// channel to indicate we need to update flows immediately
	flowChan chan struct{}
}

func (c *openflowManager) updateFlowCacheEntry(key string, flows []string) {
	c.flowMutex.Lock()
	defer c.flowMutex.Unlock()
	c.flowCache[key] = flows
}

func (c *openflowManager) deleteFlowsByKey(key string) {
	c.flowMutex.Lock()
	defer c.flowMutex.Unlock()
	delete(c.flowCache, key)
}

func (c *openflowManager) updateExBridgeFlowCacheEntry(key string, flows []string) {
	c.exGWFlowMutex.Lock()
	defer c.exGWFlowMutex.Unlock()
	c.exGWFlowCache[key] = flows
}

func (c *openflowManager) requestFlowSync() {
	select {
	case c.flowChan <- struct{}{}:
		klog.V(5).Infof("Gateway OpenFlow sync requested")
	default:
		klog.V(5).Infof("Gateway OpenFlow sync already requested")
	}
}

func (c *openflowManager) syncFlows() {
	c.flowMutex.Lock()
	defer c.flowMutex.Unlock()

	flows := []string{}
	for _, entry := range c.flowCache {
		flows = append(flows, entry...)
	}

	_, stderr, err := util.ReplaceOFFlows(c.defaultBridge.bridgeName, flows)
	if err != nil {
		klog.Errorf("Failed to add flows, error: %v, stderr, %s, flows: %s", err, stderr, c.flowCache)
	}

	if c.externalGatewayBridge != nil {
		c.exGWFlowMutex.Lock()
		defer c.exGWFlowMutex.Unlock()

		flows := []string{}
		for _, entry := range c.exGWFlowCache {
			flows = append(flows, entry...)
		}

		_, stderr, err := util.ReplaceOFFlows(c.externalGatewayBridge.bridgeName, flows)
		if err != nil {
			klog.Errorf("Failed to add flows, error: %v, stderr, %s, flows: %s", err, stderr, c.exGWFlowCache)
		}
	}
}

// checkDefaultOpenFlow checks for the existence of default OpenFlow rules and
// exits if the output is not as expected
func (c *openflowManager) Run(stopChan <-chan struct{}, doneWg *sync.WaitGroup) {
	doneWg.Add(1)
	go func() {
		defer doneWg.Done()
		syncPeriod := 15 * time.Second
		timer := time.NewTicker(syncPeriod)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				if err := checkPorts(c.defaultBridge.patchPort, c.defaultBridge.ofPortPatch,
					c.defaultBridge.uplinkName, c.defaultBridge.ofPortPhys); err != nil {
					klog.Errorf("Checkports failed %v", err)
					continue
				}
				if c.externalGatewayBridge != nil {
					if err := checkPorts(
						c.externalGatewayBridge.patchPort, c.externalGatewayBridge.ofPortPatch,
						c.externalGatewayBridge.uplinkName, c.externalGatewayBridge.ofPortPhys); err != nil {
						klog.Errorf("Checkports failed %v", err)
						continue
					}
				}
				c.syncFlows()
			case <-c.flowChan:
				c.syncFlows()
				timer.Reset(syncPeriod)
			case <-stopChan:
				return
			}
		}
	}()
}

func checkPorts(patchIntf, ofPortPatch, physIntf, ofPortPhys string) error {
	// it could be that the ovn-controller recreated the patch between the host OVS bridge and
	// the integration bridge, as a result the ofport number changed for that patch interface
	curOfportPatch, stderr, err := util.GetOVSOfPort("--if-exists", "get", "Interface", patchIntf, "ofport")
	if err != nil {
		return errors.Wrapf(err, "Failed to get ofport of %s, stderr: %q", patchIntf, stderr)

	}
	if ofPortPatch != curOfportPatch {
		klog.Errorf("Fatal error: patch port %s ofport changed from %s to %s",
			patchIntf, ofPortPatch, curOfportPatch)
		os.Exit(1)
	}

	// it could be that someone removed the physical interface and added it back on the OVS host
	// bridge, as a result the ofport number changed for that physical interface
	curOfportPhys, stderr, err := util.GetOVSOfPort("--if-exists", "get", "interface", physIntf, "ofport")
	if err != nil {
		return errors.Wrapf(err, "Failed to get ofport of %s, stderr: %q", physIntf, stderr)
	}
	if ofPortPhys != curOfportPhys {
		klog.Errorf("Fatal error: phys port %s ofport changed from %s to %s",
			physIntf, ofPortPhys, curOfportPhys)
		os.Exit(1)
	}
	return nil
}

func namespacedNameFromEPSlice(epSlice *discovery.EndpointSlice) (ktypes.NamespacedName, error) {
	// Return the namespaced name of the corresponding service
	var serviceNamespacedName ktypes.NamespacedName
	svcName := epSlice.Labels[discovery.LabelServiceName]
	if svcName == "" {
		// should not happen, since the informer already filters out endpoint slices with an empty service label
		return serviceNamespacedName,
			fmt.Errorf("endpointslice %s/%s: empty value for label %s",
				epSlice.Namespace, epSlice.Name, discovery.LabelServiceName)
	}
	return ktypes.NamespacedName{Namespace: epSlice.Namespace, Name: svcName}, nil
}
