package egressservice

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/services"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const EgressServiceServedPodsAddrSetName = "egresssvc-served-pods"

func GetEgressServiceAddrSetDbIDs(controller string) *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetEgressService, controller, map[libovsdbops.ExternalIDKey]string{
		// egressService has 1 cluster-wide address set
		libovsdbops.ObjectNameKey: EgressServiceServedPodsAddrSetName,
	})
}

func (c *Controller) onServiceAdd(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}

	service := obj.(*corev1.Service)
	// We only care about new LoadBalancer services that have an EgressService
	if !util.ServiceTypeHasLoadBalancer(service) || len(service.Status.LoadBalancer.Ingress) == 0 {
		return
	}

	es, err := c.egressServiceLister.EgressServices(service.Namespace).Get(service.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		// This shouldn't happen, but we queue the service in case we got an unrelated
		// error when the EgressService exists
		c.egressServiceQueue.Add(key)
		return
	}

	// There is no EgressService resource for this service so we don't queue it
	if es == nil {
		return
	}

	klog.V(4).Infof("Adding egress service %s", key)
	c.egressServiceQueue.Add(key)
}

func (c *Controller) onServiceUpdate(oldObj, newObj interface{}) {
	oldService := oldObj.(*corev1.Service)
	newService := newObj.(*corev1.Service)

	// don't process resync or objects that are marked for deletion
	if oldService.ResourceVersion == newService.ResourceVersion ||
		!newService.GetDeletionTimestamp().IsZero() {
		return
	}

	// We only care about LoadBalancer service updates that enable/disable egress service functionality
	if !util.ServiceTypeHasLoadBalancer(oldService) && !util.ServiceTypeHasLoadBalancer(newService) {
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", newObj, err))
		return
	}

	es, err := c.egressServiceLister.EgressServices(newService.Namespace).Get(newService.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		// This shouldn't happen, but we queue the service in case we got an unrelated
		// error when the EgressService exists
		c.egressServiceQueue.Add(key)
		return
	}

	// There is no EgressService resource for this service so we don't queue it
	if es == nil {
		return
	}

	c.egressServiceQueue.Add(key)
}

func (c *Controller) onServiceDelete(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}

	service := obj.(*corev1.Service)
	// We only care about deletions of LoadBalancer services
	if !util.ServiceTypeHasLoadBalancer(service) {
		return
	}

	klog.V(4).Infof("Deleting egress service %s", key)
	es, err := c.egressServiceLister.EgressServices(service.Namespace).Get(service.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		// This shouldn't happen, but we queue the service in case we got an unrelated
		// error when the EgressService exists
		c.egressServiceQueue.Add(key)
		return
	}

	// There is no EgressService resource for this service so we don't queue it
	if es == nil {
		return
	}

	c.egressServiceQueue.Add(key)
}

// Returns cluster-networked endpoints for the given service grouped by IPv4/IPv6.
// When IC is disabled v[4|6]LocalEndpoints contains all service endpoints and v[4|6]RemoteEndpoints is not set
// When IC is enabled v[4|6]LocalEndpoints contains endpoints hosted in the local zone and
// v[4|6]RemoteEndpoints contains endpoints hosted in remote zones
func (c *Controller) allEndpointsFor(svc *corev1.Service) (
	v4LocalEndpoints, v6LocalEndpoints, v4RemoteEndpoints, v6RemoteEndpoints sets.Set[string],
	err error) {
	// Get the endpoint slices associated to the Service
	esLabelSelector := labels.Set(map[string]string{
		discovery.LabelServiceName: svc.Name,
	}).AsSelectorPreValidated()

	endpointSlices, err := c.endpointSliceLister.EndpointSlices(svc.Namespace).List(esLabelSelector)
	if err != nil {
		return
	}

	v4LocalEndpoints = sets.Set[string]{}
	v6LocalEndpoints = sets.Set[string]{}
	v4RemoteEndpoints = sets.Set[string]{}
	v6RemoteEndpoints = sets.Set[string]{}

	for _, eps := range endpointSlices {
		if eps.AddressType == discovery.AddressTypeFQDN {
			continue
		}

		localEndpoints := v4LocalEndpoints
		remoteEndpoints := v4RemoteEndpoints
		if eps.AddressType == discovery.AddressTypeIPv6 {
			localEndpoints = v6LocalEndpoints
			remoteEndpoints = v6RemoteEndpoints
		}

		for _, ep := range eps.Endpoints {
			if ep.NodeName == nil {
				// ignore endpoints without a node
				continue
			}
			isEpLocal := true
			if config.OVNKubernetesFeature.EnableInterconnect {
				var zoneKnown bool
				isEpLocal, zoneKnown = c.nodesZoneState[*ep.NodeName]
				if !zoneKnown {
					klog.Errorf("Failed to get the zone for %v", ep)
					continue
				}
			}
			for _, ip := range ep.Addresses {
				ipStr := utilnet.ParseIPSloppy(ip).String()
				if !services.IsHostEndpoint(ipStr) {
					if isEpLocal {
						localEndpoints.Insert(ipStr)
					} else {
						remoteEndpoints.Insert(ipStr)
					}

				}
			}
		}
	}
	return
}

func createIPAddressStringSlice(v4ips, v6ips []string) []string {
	return append(v4ips, v6ips...)
}

func (c *Controller) addPodIPsToAddressSetOps(addrSetIPs []string) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	dbIDs := GetEgressServiceAddrSetDbIDs(c.controllerName)
	as, err := c.addressSetFactory.GetAddressSet(dbIDs)
	if err != nil {
		return nil, fmt.Errorf("cannot ensure that addressSet %s exists: %v", EgressServiceServedPodsAddrSetName, err)
	}
	if ops, err = as.AddAddressesReturnOps(addrSetIPs); err != nil {
		return nil, fmt.Errorf("cannot add egressPodIPs %v from the address set %v: err: %v", addrSetIPs, EgressServiceServedPodsAddrSetName, err)
	}
	return ops, nil
}

func (c *Controller) deletePodIPsFromAddressSetOps(addrSetIPs []string) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	dbIDs := GetEgressServiceAddrSetDbIDs(c.controllerName)
	as, err := c.addressSetFactory.GetAddressSet(dbIDs)
	if err != nil {
		return nil, fmt.Errorf("cannot ensure that addressSet %s exists: %v", EgressServiceServedPodsAddrSetName, err)
	}
	if ops, err = as.DeleteAddressesReturnOps(addrSetIPs); err != nil {
		return nil, fmt.Errorf("cannot delete egressPodIPs %v from the address set %v: err: %v", addrSetIPs, EgressServiceServedPodsAddrSetName, err)
	}
	return ops, nil
}

func (c *Controller) setPodIPsInAddressSet(addrSetIPs []string) error {
	dbIDs := GetEgressServiceAddrSetDbIDs(c.controllerName)
	as, err := c.addressSetFactory.GetAddressSet(dbIDs)
	if err != nil {
		return fmt.Errorf("cannot ensure that addressSet %s exists: %v", EgressServiceServedPodsAddrSetName, err)
	}
	return as.SetAddresses(addrSetIPs)
}

// Returns the libovsdb operations to create or updates the logical router policies for the service,
// given its key, the nexthops (mgmt ips) and endpoints to add.
func (c *Controller) createOrUpdateLogicalRouterPoliciesOps(key, v4MgmtIP, v6MgmtIP string, v4Endpoints, v6Endpoints []string) ([]ovsdb.Operation, error) {
	allOps := []ovsdb.Operation{}
	var err error

	for _, addr := range v4Endpoints {
		lrp := &nbdb.LogicalRouterPolicy{
			Match:    fmt.Sprintf("ip4.src == %s", addr),
			Priority: ovntypes.EgressSVCReroutePriority,
			Nexthops: []string{v4MgmtIP},
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			ExternalIDs: map[string]string{
				svcExternalIDKey: key,
			},
		}
		p := func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Match == lrp.Match && item.Priority == lrp.Priority && item.ExternalIDs[svcExternalIDKey] == key
		}

		allOps, err = libovsdbops.CreateOrUpdateLogicalRouterPolicyWithPredicateOps(c.nbClient, allOps, c.GetNetworkScopedClusterRouterName(), lrp, p)
		if err != nil {
			return nil, err
		}
	}

	for _, addr := range v6Endpoints {
		lrp := &nbdb.LogicalRouterPolicy{
			Match:    fmt.Sprintf("ip6.src == %s", addr),
			Priority: ovntypes.EgressSVCReroutePriority,
			Nexthops: []string{v6MgmtIP},
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			ExternalIDs: map[string]string{
				svcExternalIDKey: key,
			},
		}
		p := func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Match == lrp.Match && item.Priority == lrp.Priority && item.ExternalIDs[svcExternalIDKey] == key
		}

		allOps, err = libovsdbops.CreateOrUpdateLogicalRouterPolicyWithPredicateOps(c.nbClient, allOps, c.GetNetworkScopedClusterRouterName(), lrp, p)
		if err != nil {
			return nil, err
		}
	}

	return allOps, nil
}

// Returns the libovsdb operations to delete the logical router policies for the service,
// given its key and endpoints to delete.
func (c *Controller) deleteLogicalRouterPoliciesOps(key string, v4Endpoints, v6Endpoints []string) ([]ovsdb.Operation, error) {
	allOps := []ovsdb.Operation{}
	var err error

	for _, addr := range v4Endpoints {
		match := fmt.Sprintf("ip4.src == %s", addr)
		p := func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Match == match && item.Priority == ovntypes.EgressSVCReroutePriority && item.ExternalIDs[svcExternalIDKey] == key
		}

		allOps, err = libovsdbops.DeleteLogicalRouterPolicyWithPredicateOps(c.nbClient, allOps, c.GetNetworkScopedClusterRouterName(), p)
		if err != nil {
			return nil, err
		}
	}

	for _, addr := range v6Endpoints {
		match := fmt.Sprintf("ip6.src == %s", addr)
		p := func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Match == match && item.Priority == ovntypes.EgressSVCReroutePriority && item.ExternalIDs[svcExternalIDKey] == key
		}

		allOps, err = libovsdbops.DeleteLogicalRouterPolicyWithPredicateOps(c.nbClient, allOps, c.GetNetworkScopedClusterRouterName(), p)
		if err != nil {
			return nil, err
		}
	}

	return allOps, nil
}
