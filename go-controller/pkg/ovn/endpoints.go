package ovn

import (
	"fmt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/loadbalancer"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

type lbEndpoints struct {
	IPs  []string
	Port int32
}

func (ovn *Controller) getLbEndpoints(ep *kapi.Endpoints) map[kapi.Protocol]map[string]lbEndpoints {
	protoPortMap := map[kapi.Protocol]map[string]lbEndpoints{
		kapi.ProtocolTCP:  make(map[string]lbEndpoints),
		kapi.ProtocolUDP:  make(map[string]lbEndpoints),
		kapi.ProtocolSCTP: make(map[string]lbEndpoints),
	}
	for _, s := range ep.Subsets {
		for _, ip := range s.Addresses {
			for _, port := range s.Ports {
				var ips []string
				if err := util.ValidatePort(port.Protocol, port.Port); err != nil {
					klog.Errorf("Invalid endpoint port: %s: %v", port.Name, err)
					continue
				}
				if lbEps, ok := protoPortMap[port.Protocol][port.Name]; ok {
					ips = append(lbEps.IPs, ip.IP)
				} else {
					ips = []string{ip.IP}
				}
				protoPortMap[port.Protocol][port.Name] = lbEndpoints{IPs: ips, Port: port.Port}
			}
		}
	}
	klog.V(5).Infof("Endpoint Protocol Map is: %v", protoPortMap)
	return protoPortMap
}

// AddEndpoints adds endpoints and creates corresponding resources in OVN
func (ovn *Controller) AddEndpoints(ep *kapi.Endpoints, addClusterLBs bool) error {
	klog.Infof("Adding endpoints: %s for namespace: %s", ep.Name, ep.Namespace)
	// get service
	// TODO: cache the service
	svc, err := ovn.watchFactory.GetService(ep.Namespace, ep.Name)
	if err != nil {
		// This is not necessarily an error. For e.g when there are endpoints
		// without a corresponding service.
		klog.V(5).Infof("No service found for endpoint %s in namespace %s", ep.Name, ep.Namespace)
		return nil
	}
	if !util.IsClusterIPSet(svc) {
		klog.V(5).Infof("Skipping service %s due to clusterIP = %q", svc.Name, svc.Spec.ClusterIP)
		return nil
	}

	klog.V(5).Infof("Matching service %s found for ep: %s, with cluster IP: %s", svc.Name, ep.Name, svc.Spec.ClusterIP)

	protoPortMap := ovn.getLbEndpoints(ep)
	klog.V(5).Infof("Matching service %s ports: %v", svc.Name, svc.Spec.Ports)
	for _, svcPort := range svc.Spec.Ports {
		lbEps, isFound := protoPortMap[svcPort.Protocol][svcPort.Name]
		if !isFound {
			continue
		}
		if !ovn.SCTPSupport && svcPort.Protocol == kapi.ProtocolSCTP {
			klog.Errorf("Rejecting endpoint creation for unsupported SCTP protocol: %s, %s", ep.Namespace, ep.Name)
			continue
		}
		if util.ServiceTypeHasNodePort(svc) {
			if err := ovn.createPerNodeVIPs(nil, svcPort.Protocol, svcPort.NodePort, lbEps.IPs, lbEps.Port); err != nil {
				klog.Errorf("Error in creating Node Port for svc %s, node port: %d - %v\n", svc.Name, svcPort.NodePort, err)
				continue
			}
		}

		if util.ServiceTypeHasClusterIP(svc) {
			var loadBalancer string
			loadBalancer, err = ovn.getLoadBalancer(svcPort.Protocol)
			if err != nil {
				klog.Errorf("Failed to get load balancer for %s (%v)", svcPort.Protocol, err)
				continue
			}

			// If any of the lbEps contain the a host IP we add to worker/GR LB separately, and not to cluster LB
			if hasHostEndpoints(lbEps.IPs) && config.Gateway.Mode == config.GatewayModeShared {
				if err := ovn.createPerNodeVIPs([]string{svc.Spec.ClusterIP}, svcPort.Protocol, svcPort.Port, lbEps.IPs, lbEps.Port); err != nil {
					klog.Errorf("Error in creating Cluster IP for svc %s, target port: %d - %v\n", svc.Name, lbEps.Port, err)
					continue
				}
				// Need to ensure that if vip exists on cluster LB we remove it
				// This can happen if endpoints originally had cluster only ips but now have host ips
				vip := util.JoinHostPortInt32(svc.Spec.ClusterIP, svcPort.Port)
				if err := ovn.deleteLoadBalancerVIP(loadBalancer, vip); err != nil {
					klog.Error(err)
				}
			} else if addClusterLBs {
				if err = ovn.createLoadBalancerVIPs(loadBalancer, []string{svc.Spec.ClusterIP}, svcPort.Port, lbEps.IPs, lbEps.Port); err != nil {
					klog.Errorf("Error in creating Cluster IP for svc %s, target port: %d - %v\n", svc.Name, lbEps.Port, err)
					continue
				}
				// Need to ensure if this vip exists in the worker LBs that we remove it
				// This can happen if the endpoints originally had host eps but now have cluster only ips
				ovn.deleteNodeVIPs([]string{svc.Spec.ClusterIP}, svcPort.Protocol, svcPort.Port)
			}
			if len(svc.Spec.ExternalIPs) > 0 {
				if err := ovn.createPerNodeVIPs(svc.Spec.ExternalIPs, svcPort.Protocol, svcPort.Port, lbEps.IPs, lbEps.Port); err != nil {
					klog.Errorf("Error in creating ExternalIP for svc %s, target port: %d - %v\n", svc.Name, lbEps.Port, err)
				}
			}
			// Cloud load balancers: directly load balance that traffic from pods
			// Apply to gateway load-balancers to handle ingress traffic to the GR as well as worker switches
			for _, ing := range svc.Status.LoadBalancer.Ingress {
				if ing.IP == "" {
					continue
				}
				if err := ovn.createPerNodeVIPs([]string{ing.IP}, svcPort.Protocol, svcPort.Port, lbEps.IPs, lbEps.Port); err != nil {
					klog.Errorf("Error in creating Ingress LB IP for svc %s, target port: %d - %v\n", svc.Name, lbEps.Port, err)
				}
			}
		}
	}
	return nil
}

func (ovn *Controller) handleNodePortLB(node *kapi.Node) error {
	gatewayRouter := types.GWRouterPrefix + node.Name
	var physicalIPs []string
	if physicalIPs, _ = ovn.getGatewayPhysicalIPs(gatewayRouter); physicalIPs == nil {
		return fmt.Errorf("gateway physical IP for node %q does not yet exist", node.Name)
	}
	namespaces, err := ovn.watchFactory.GetNamespaces()
	if err != nil {
		return fmt.Errorf("failed to get k8s namespaces: %v", err)
	}
	for _, ns := range namespaces {
		endpoints, err := ovn.watchFactory.GetEndpoints(ns.Name)
		if err != nil {
			klog.Errorf("Failed to get k8s endpoints: %v", err)
			continue
		}
		for _, ep := range endpoints {
			if err := ovn.AddEndpoints(ep, false); err != nil {
				return fmt.Errorf("unable to handle adding endpoints for new node: %s, error: %v",
					node.Name, err)
			}

		}
	}
	return nil
}

func (ovn *Controller) deleteEndpoints(ep *kapi.Endpoints) error {
	klog.Infof("Deleting endpoints: %s for namespace: %s", ep.Name, ep.Namespace)
	svc, err := ovn.watchFactory.GetService(ep.Namespace, ep.Name)
	if err != nil {
		// This is not necessarily an error. For e.g when a service is deleted,
		// you will get endpoint delete event and the call to fetch service
		// will fail.
		klog.V(5).Infof("No service found for endpoint %s in namespace %s", ep.Name, ep.Namespace)
		return nil
	}
	if !util.IsClusterIPSet(svc) {
		return nil
	}
	gateways, _, err := ovn.getOvnGateways()
	if err != nil {
		klog.Error(err)
	}

	for _, svcPort := range svc.Spec.Ports {
		clusterLB, err := ovn.getLoadBalancer(svcPort.Protocol)
		if err != nil {
			klog.Errorf("Failed to get load balancer for %s (%v)", clusterLB, err)
			continue
		}
		// Cluster IP service
		ovn.clearVIPsAddRejectACL(svc, clusterLB, svc.Spec.ClusterIP, svcPort.Port, svcPort.Protocol)

		for _, gateway := range gateways {
			gatewayLB, err := ovn.getGatewayLoadBalancer(gateway, svcPort.Protocol)
			if err != nil {
				klog.Errorf("Gateway router %s does not have load balancer (%v)", gateway, err)
				continue
			}
			// ClusterIP may be on gateway or worker LBs, so need to remove here as well
			if config.Gateway.Mode == config.GatewayModeShared {
				ovn.clearVIPsAddRejectACL(svc, gatewayLB, svc.Spec.ClusterIP, svcPort.Port, svcPort.Protocol)
			}
			workerNode := strings.TrimPrefix(gateway, "GR_")
			workerLB, err := loadbalancer.GetWorkerLoadBalancer(workerNode, svcPort.Protocol)
			if err != nil {
				klog.Errorf("Worker switch %s does not have load balancer (%v)", workerNode, err)
				continue
			}
			if config.Gateway.Mode == config.GatewayModeShared {
				ovn.clearVIPsAddRejectACL(svc, workerLB, svc.Spec.ClusterIP, svcPort.Port, svcPort.Protocol)
			}

			// Cloud load balancers: directly reject traffic from pods
			for _, ing := range svc.Status.LoadBalancer.Ingress {
				if ing.IP == "" {
					continue
				}
				ovn.clearVIPsAddRejectACL(svc, gatewayLB, ing.IP, svcPort.Port, svcPort.Protocol)
				ovn.clearVIPsAddRejectACL(svc, workerLB, ing.IP, svcPort.Port, svcPort.Protocol)
			}
			// Node Port services
			if util.ServiceTypeHasNodePort(svc) {
				physicalIPs, err := ovn.getGatewayPhysicalIPs(gateway)
				if err != nil {
					klog.Errorf("Gateway router %s does not have physical ip (%v)", gateway, err)
					continue
				}
				for _, physicalIP := range physicalIPs {
					ovn.clearVIPsAddRejectACL(svc, gatewayLB, physicalIP, svcPort.NodePort, svcPort.Protocol)
					ovn.clearVIPsAddRejectACL(svc, workerLB, physicalIP, svcPort.NodePort, svcPort.Protocol)
				}
			}
			// External IP services
			for _, extIP := range svc.Spec.ExternalIPs {
				ovn.clearVIPsAddRejectACL(svc, gatewayLB, extIP, svcPort.Port, svcPort.Protocol)
				ovn.clearVIPsAddRejectACL(svc, workerLB, extIP, svcPort.NodePort, svcPort.Protocol)
			}
		}
	}
	return nil
}

func (ovn *Controller) clearVIPsAddRejectACL(svc *kapi.Service, lb, ip string, port int32, proto kapi.Protocol) {
	aclLogging := ovn.GetNetworkPolicyACLLogging(svc.Namespace).Deny
	if svcQualifiesForReject(svc) {
		aclUUID, err := ovn.createLoadBalancerRejectACL(lb, ip, port, proto, aclLogging)
		if err != nil {
			klog.Errorf("Failed to create reject ACL for VIP: %s:%d, load balancer: %s, error: %v",
				ip, port, lb, err)
		} else {
			klog.Infof("Reject ACL created for VIP: %s:%d, load balancer: %s, %s", ip, port, lb, aclUUID)
		}
	}
	err := ovn.configureLoadBalancer(lb, ip, port, nil)
	if err != nil {
		klog.Errorf("Error in clearing endpoints for lb %s: %v", lb, err)
	}
}

// hasHostEndpoints determines if a slice of endpoints contains a host networked pod
func hasHostEndpoints(endpointIPs []string) bool {
	for _, endpointIP := range endpointIPs {
		found := false
		for _, clusterNet := range config.Default.ClusterSubnets {
			if clusterNet.CIDR.Contains(net.ParseIP(endpointIP)) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}
