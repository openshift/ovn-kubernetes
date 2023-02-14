package node

import (
	"net"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/healthcheck"

	kapi "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// initLoadBalancerHealthChecker initializes the health check server for
// ServiceTypeLoadBalancer services

type loadBalancerHealthChecker struct {
	sync.Mutex
	nodeName     string
	server       healthcheck.Server
	services     map[ktypes.NamespacedName]uint16
	endpoints    map[ktypes.NamespacedName]int
	watchFactory factory.NodeWatchFactory
}

func newLoadBalancerHealthChecker(nodeName string, watchFactory factory.NodeWatchFactory) *loadBalancerHealthChecker {
	return &loadBalancerHealthChecker{
		nodeName:     nodeName,
		server:       healthcheck.NewServer(nodeName, nil, nil, nil),
		services:     make(map[ktypes.NamespacedName]uint16),
		endpoints:    make(map[ktypes.NamespacedName]int),
		watchFactory: watchFactory,
	}
}

func (l *loadBalancerHealthChecker) AddService(svc *kapi.Service) {
	if svc.Spec.HealthCheckNodePort != 0 {
		l.Lock()
		defer l.Unlock()
		name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
		l.services[name] = uint16(svc.Spec.HealthCheckNodePort)
		_ = l.server.SyncServices(l.services)
	}
}

func (l *loadBalancerHealthChecker) UpdateService(old, new *kapi.Service) {
	// if the ETP values have changed between local and cluster,
	// we need to update health checks accordingly
	// HealthCheckNodePort is used only in ETP=local mode
	if old.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeCluster &&
		new.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeLocal {
		l.AddService(new)
		ep, err := l.watchFactory.GetEndpoint(new.Namespace, new.Name)
		if err != nil {
			klog.V(4).Infof("Could not fetch endpoint for service %s/%s during health check update service", new.Namespace, new.Name)
		}
		namespacedName := ktypes.NamespacedName{Namespace: new.Namespace, Name: new.Name}
		l.Lock()
		l.endpoints[namespacedName] = countLocalEndpoints(ep, l.nodeName)
		_ = l.server.SyncEndpoints(l.endpoints)
		l.Unlock()
	}
	if old.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeLocal &&
		new.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeCluster {
		l.DeleteService(old)
	}
}

func (l *loadBalancerHealthChecker) DeleteService(svc *kapi.Service) {
	if svc.Spec.HealthCheckNodePort != 0 {
		l.Lock()
		defer l.Unlock()
		name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
		delete(l.services, name)
		delete(l.endpoints, name)
		_ = l.server.SyncServices(l.services)
	}
}

func (l *loadBalancerHealthChecker) SyncServices(svcs []interface{}) error {
	return nil
}

func (l *loadBalancerHealthChecker) AddEndpoints(ep *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	l.Lock()
	defer l.Unlock()
	if _, exists := l.services[name]; exists {
		l.endpoints[name] = countLocalEndpoints(ep, l.nodeName)
		_ = l.server.SyncEndpoints(l.endpoints)
	}
}

func (l *loadBalancerHealthChecker) UpdateEndpoints(old, new *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: new.Namespace, Name: new.Name}
	l.Lock()
	defer l.Unlock()
	if _, exists := l.services[name]; exists {
		l.endpoints[name] = countLocalEndpoints(new, l.nodeName)
		_ = l.server.SyncEndpoints(l.endpoints)
	}

}

func (l *loadBalancerHealthChecker) DeleteEndpoints(ep *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	l.Lock()
	defer l.Unlock()
	delete(l.endpoints, name)
	_ = l.server.SyncEndpoints(l.endpoints)
}

func countLocalEndpoints(ep *kapi.Endpoints, nodeName string) int {
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
	return num
}

// hasLocalHostNetworkEndpoints returns true if there is at least one host-networked endpoint
// in the provided list that is local to this node.
// It returns false if none of the endpoints are local host-networked endpoints or if ep.Subsets is nil.
func hasLocalHostNetworkEndpoints(ep *kapi.Endpoints, nodeAddresses []net.IP) bool {
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Addresses {
			addr := &ss.Addresses[i]
			for _, nodeIP := range nodeAddresses {
				if nodeIP.String() == utilnet.ParseIPSloppy(addr.IP).String() {
					return true
				}
			}
		}
	}
	return false
}
