package ovn

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"
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
				if _, err := util.ValidateProtocol(port.Protocol); err != nil {
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
func (ovn *Controller) AddEndpoints(ep *kapi.Endpoints) error {
	klog.V(5).Infof("Adding endpoints: %s for namespace: %s", ep.Name, ep.Namespace)
	// get service
	// TODO: cache the service
	svc, err := ovn.watchFactory.GetService(ep.Namespace, ep.Name)
	if err != nil {
		// This is not necessarily an error. For e.g when there are endpoints
		// without a corresponding service.
		klog.V(5).Infof("no service found for endpoint %s in namespace %s",
			ep.Name, ep.Namespace)
		return nil
	}
	if !util.IsClusterIPSet(svc) {
		klog.V(5).Infof("Skipping service %s due to clusterIP = %q",
			svc.Name, svc.Spec.ClusterIP)
		return nil
	}
	klog.V(5).Infof("Matching service %s found for ep: %s, with cluster IP: %s", svc.Name, ep.Name,
		svc.Spec.ClusterIP)

	protoPortMap := ovn.getLbEndpoints(ep)
	klog.V(5).Infof("Matching service %s ports: %v", svc.Name, svc.Spec.Ports)
	for proto, portMap := range protoPortMap {
		for svcPortName, lbEps := range portMap {
			ips := lbEps.IPs
			targetPort := lbEps.Port
			for _, svcPort := range svc.Spec.Ports {
				if svcPort.Protocol == proto && svcPort.Name == svcPortName {
					if !ovn.SCTPSupport && proto == kapi.ProtocolSCTP {
						klog.Errorf("Rejecting endpoint creation for unsupported SCTP protocol: %s, %s", ep.Namespace, ep.Name)
						continue
					}
					if util.ServiceTypeHasNodePort(svc) {
						klog.V(5).Infof("Creating Gateways IP for NodePort: %d, %v", svcPort.NodePort, ips)
						err = ovn.createGatewayVIPs(svcPort.Protocol, svcPort.NodePort, ips, targetPort)
						if err != nil {
							klog.Errorf("Error in creating Node Port for svc %s, node port: %d - %v\n", svc.Name, svcPort.NodePort, err)
							continue
						}
					}
					if util.ServiceTypeHasClusterIP(svc) {
						var loadBalancer string
						loadBalancer, err = ovn.getLoadBalancer(svcPort.Protocol)
						if err != nil {
							klog.Errorf("Failed to get loadbalancer for %s (%v)",
								svcPort.Protocol, err)
							continue
						}
						err = ovn.createLoadBalancerVIPs(loadBalancer,
							[]string{svc.Spec.ClusterIP},
							svcPort.Port, ips, targetPort)
						if err != nil {
							klog.Errorf("Error in creating Cluster IP for svc %s, target port: %d - %v\n", svc.Name, targetPort, err)
							continue
						}
						vip := util.JoinHostPortInt32(svc.Spec.ClusterIP, svcPort.Port)
						ovn.AddServiceVIPToName(vip, svcPort.Protocol, svc.Namespace, svc.Name)
						ovn.handleExternalIPs(svc, svcPort, ips, targetPort, false)
					}
				}
			}
		}
	}
	return nil
}

func (ovn *Controller) handleNodePortLB(node *kapi.Node) error {
	physicalGateway := gwRouterPrefix + node.Name
	var physicalIPs []string
	if physicalIPs, _ = ovn.getGatewayPhysicalIPs(physicalGateway); physicalIPs == nil {
		return fmt.Errorf("gateway physical IP for node %q does not yet exist", node.Name)
	}
	namespaces, err := ovn.watchFactory.GetNamespaces()
	if err != nil {
		return fmt.Errorf("failed to get k8s namespaces: %v", err)
	}
	for _, ns := range namespaces {
		endpoints, err := ovn.watchFactory.GetEndpoints(ns.Name)
		if err != nil {
			klog.Errorf("failed to get k8s endpoints: %v", err)
			continue
		}
		for _, ep := range endpoints {
			svc, err := ovn.watchFactory.GetService(ep.Namespace, ep.Name)
			if err != nil {
				continue
			}
			if !util.ServiceTypeHasNodePort(svc) {
				continue
			}
			protoPortMap := ovn.getLbEndpoints(ep)
			for proto, portMap := range protoPortMap {
				for svcPortName, lbEps := range portMap {
					ips := lbEps.IPs
					targetPort := lbEps.Port
					for _, svcPort := range svc.Spec.Ports {
						if svcPort.Protocol == proto && svcPort.Name == svcPortName {
							k8sNSLb, _ := ovn.getGatewayLoadBalancer(physicalGateway, proto)
							if k8sNSLb == "" {
								return fmt.Errorf("%s load balancer for node %q does not yet exist",
									proto, node.Name)
							}
							err = ovn.createLoadBalancerVIPs(k8sNSLb, physicalIPs, svcPort.NodePort, ips, targetPort)
							if err != nil {
								klog.Errorf("failed to create VIP in load balancer %s - %v", k8sNSLb, err)
								continue
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// updateExternalIPsLB is used to handle the case where a node is deleted, and the external IP needs to be moved
// to another GW node
func (ovn *Controller) updateExternalIPsLB() {
	namespaces, err := ovn.watchFactory.GetNamespaces()
	if err != nil {
		klog.Errorf("failed to get k8s namespaces: %v", err)
		return
	}
	for _, ns := range namespaces {
		endpoints, err := ovn.watchFactory.GetEndpoints(ns.Name)
		if err != nil {
			klog.Errorf("failed to get k8s endpoints: %v", err)
			continue
		}
		for _, ep := range endpoints {
			svc, err := ovn.watchFactory.GetService(ep.Namespace, ep.Name)
			if err != nil {
				continue
			}
			if len(svc.Spec.ExternalIPs) == 0 {
				continue
			}
			tcpPortMap := make(map[string]lbEndpoints)
			udpPortMap := make(map[string]lbEndpoints)
			sctpPortMap := make(map[string]lbEndpoints)
			protoPortMap := map[kapi.Protocol]map[string]lbEndpoints{
				kapi.ProtocolTCP:  tcpPortMap,
				kapi.ProtocolUDP:  udpPortMap,
				kapi.ProtocolSCTP: sctpPortMap,
			}
			for proto, portMap := range protoPortMap {
				for svcPortName, lbEps := range portMap {
					ips := lbEps.IPs
					targetPort := lbEps.Port
					for _, svcPort := range svc.Spec.Ports {
						if svcPort.Protocol == proto && svcPort.Name == svcPortName {
							ovn.handleExternalIPs(svc, svcPort, ips, targetPort, false)
						}
					}
				}
			}
		}
	}
}

// handleExternalIPs will take care of updating/adding GW load balancers. If removeLoadBalancerVIP is true,
// the behavior changes to remove the load balancer VIP for services with external ips
func (ovn *Controller) handleExternalIPs(svc *kapi.Service, svcPort kapi.ServicePort, ips []string, targetPort int32,
	removeLoadBalancerVIP bool) {
	klog.V(5).Infof("handling external IPs for svc %v", svc.Name)
	if len(svc.Spec.ExternalIPs) == 0 {
		return
	}
	lb := ovn.getDefaultGatewayLoadBalancer(svcPort.Protocol)
	if lb == "" {
		klog.Warningf("No default gateway found for protocol %s\n\tNote: 'nodeport' flag needs to be enabled for default gateway", svcPort.Protocol)
		return
	}

	if removeLoadBalancerVIP {
		for _, extIP := range svc.Spec.ExternalIPs {
			vip := util.JoinHostPortInt32(extIP, svcPort.Port)
			klog.V(5).Infof("Removing external VIP: %s from load balancer: %s", vip, lb)
			ovn.deleteLoadBalancerVIP(lb, vip)
		}
	} else {
		err := ovn.createLoadBalancerVIPs(lb, svc.Spec.ExternalIPs, svcPort.Port, ips, targetPort)
		if err != nil {
			klog.Errorf("Error in creating external IPs for service: %s", svc.Name)
		}
	}
}

func (ovn *Controller) deleteEndpoints(ep *kapi.Endpoints) error {
	klog.V(5).Infof("Deleting endpoints: %s for namespace: %s", ep.Name, ep.Namespace)
	svc, err := ovn.watchFactory.GetService(ep.Namespace, ep.Name)
	if err != nil {
		// This is not necessarily an error. For e.g when a service is deleted,
		// you will get endpoint delete event and the call to fetch service
		// will fail.
		klog.V(5).Infof("no service found for endpoint %s in namespace %s", ep.Name, ep.Namespace)
		return nil
	}
	if !util.IsClusterIPSet(svc) {
		return nil
	}
	for _, svcPort := range svc.Spec.Ports {
		var lb string
		lb, err = ovn.getLoadBalancer(svcPort.Protocol)
		if err != nil {
			klog.Errorf("Failed to get load-balancer for %s (%v)", lb, err)
			continue
		}

		// apply reject ACL if necessary before deleting endpoints (avoids unwanted traffic events hitting OVN/OVS)
		if ovn.svcQualifiesForReject(svc) {
			aclUUID, err := ovn.createLoadBalancerRejectACL(lb, svc.Spec.ClusterIP, svcPort.Port, svcPort.Protocol)
			if err != nil {
				klog.Errorf("Failed to create reject ACL for load balancer: %s, error: %v", lb, err)
			}
			klog.V(5).Infof("Reject ACL created for load balancer: %s, %s", lb, aclUUID)
		}

		// clear endpoints from the LB
		err := ovn.configureLoadBalancer(lb, svc.Spec.ClusterIP, svcPort.Port, nil)
		if err != nil {
			klog.Errorf("Error in deleting endpoints for lb %s: %v", lb, err)
		}
		vip := util.JoinHostPortInt32(svc.Spec.ClusterIP, svcPort.Port)
		ovn.removeServiceEndpoints(lb, vip)
	}
	return nil
}
