package services

import (
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

// loadBalancer represents an OVN LoadBalancer entry using the VirtualIP (IP:Port) as key
type loadBalancer map[string]v1.Protocol

// serviceTrackerKey returns a string using for the index.
func serviceTrackerKey(name, namespace string) string { return name + "/" + namespace }

// serviceTracker tracks the services VIPs to map the OVN LoadBalancers to the Kubernetes services
// we need the tracker because on Service deletion we need to be able to know which OVN Loadbalancer
// we need to delete.
// We don't need to track endpoints because we can obtain them from the cache
// and for deleting service we don't need them, we just delete everything corresponding to the VIP
type serviceTracker struct {
	sync.Mutex
	loadBalancerByService map[string]loadBalancer
}

// newServiceTracker creates and initializes a new serviceTracker.
func newServiceTracker() *serviceTracker {
	return &serviceTracker{
		loadBalancerByService: map[string]loadBalancer{},
	}
}

// updateService adds or updates the vips and endpoints
func (st *serviceTracker) updateService(name, namespace, vip string, proto v1.Protocol) {
	st.Lock()
	defer st.Unlock()
	serviceNN := serviceTrackerKey(name, namespace)

	// check if the service already exists and create a new entry if it does not
	lb, ok := st.loadBalancerByService[serviceNN]
	if !ok {
		lb := map[string]v1.Protocol{vip: proto}
		st.loadBalancerByService[serviceNN] = lb
		return
	}
	// Update the service VIP with the new endpoints
	lb[vip] = proto
	klog.V(5).Infof("Updated service %s VIP %s %s on Service Tracker", serviceNN, vip, proto)
}

// DeleteService removes the set of resource versions tracked for the Service.
func (st *serviceTracker) deleteService(name, namespace string) {
	st.Lock()
	defer st.Unlock()

	serviceNN := serviceTrackerKey(name, namespace)
	delete(st.loadBalancerByService, serviceNN)
	klog.V(5).Infof("Deleted service %s from Service Tracker", serviceNN)
}

// DeleteService removes the set of resource versions tracked for the Service.
func (st *serviceTracker) deleteServiceVIP(name, namespace, vip string, proto v1.Protocol) {
	st.Lock()
	defer st.Unlock()
	serviceNN := serviceTrackerKey(name, namespace)
	lb := st.loadBalancerByService[serviceNN]
	delete(lb, vip)
	klog.V(5).Infof("Deleted service %s VIP %s %s from Service Tracker", serviceNN, vip, proto)
}

// hasService return true if the service exist
func (st *serviceTracker) hasService(name, namespace string) bool {
	st.Lock()
	defer st.Unlock()
	serviceNN := serviceTrackerKey(name, namespace)
	_, ok := st.loadBalancerByService[serviceNN]
	return ok
}

// hasServiceVIP return true if the VIP exists in the service
func (st *serviceTracker) hasServiceVIP(name, namespace, vip string, proto v1.Protocol) bool {
	st.Lock()
	defer st.Unlock()
	serviceNN := serviceTrackerKey(name, namespace)
	if lb, ok := st.loadBalancerByService[serviceNN]; ok {
		_, ok := lb[vip]
		return ok
	}
	return false
}

// getService return the service VIPs and endpoints
func (st *serviceTracker) getService(name, namespace string) loadBalancer {
	st.Lock()
	defer st.Unlock()
	serviceNN := serviceTrackerKey(name, namespace)
	if lb, ok := st.loadBalancerByService[serviceNN]; ok {
		klog.V(5).Infof("Obtained service %s on Service Tracker: %v", serviceNN, lb)
		return lb
	}
	return loadBalancer{}
}

// updateKubernetesService adds or updates the tracker from a Kubernetes service
// added for testing purposes
func (st *serviceTracker) updateKubernetesService(service *v1.Service) {
	for _, ip := range service.Spec.ClusterIPs {
		for _, svcPort := range service.Spec.Ports {
			vip := util.JoinHostPortInt32(ip, svcPort.Port)
			st.updateService(service.Name, service.Namespace, vip, svcPort.Protocol)
		}
	}
}
