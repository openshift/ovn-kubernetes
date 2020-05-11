package ovn

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

func (ovn *Controller) getLoadBalancer(protocol kapi.Protocol) (string, error) {
	if outStr, ok := ovn.loadbalancerClusterCache[protocol]; ok {
		return outStr, nil
	}

	var out string
	var err error
	if protocol == kapi.ProtocolTCP {
		out, _, err = util.RunOVNNbctl("--data=bare",
			"--no-heading", "--columns=_uuid", "find", "load_balancer",
			"external_ids:k8s-cluster-lb-tcp=yes")
	} else if protocol == kapi.ProtocolUDP {
		out, _, err = util.RunOVNNbctl("--data=bare", "--no-heading",
			"--columns=_uuid", "find", "load_balancer",
			"external_ids:k8s-cluster-lb-udp=yes")
	} else if protocol == kapi.ProtocolSCTP {
		out, _, err = util.RunOVNNbctl("--data=bare", "--no-heading",
			"--columns=_uuid", "find", "load_balancer",
			"external_ids:k8s-cluster-lb-sctp=yes")
	}
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("no load-balancer found in the database")
	}
	ovn.loadbalancerClusterCache[protocol] = out
	return out, nil
}

// getDefaultGatewayLoadBalancer returns the load balancer for the node with the lowest gateway IP.
// This is used in the implementation of ExternalIPs
func (ovn *Controller) getDefaultGatewayLoadBalancer(protocol kapi.Protocol) string {
	if outStr, ok := ovn.loadbalancerGWCache[protocol]; ok {
		return outStr
	}

	gw, _, err := getDefaultGatewayRouterIP()
	if err != nil {
		klog.Errorf(err.Error())
		return ""
	}

	externalIDKey := string(protocol) + "_lb_gateway_router"
	lb, _, _ := util.RunOVNNbctl("--data=bare",
		"--no-heading", "--columns=_uuid", "find", "load_balancer",
		"external_ids:"+externalIDKey+"="+gw)
	if len(lb) != 0 {
		ovn.loadbalancerGWCache[protocol] = lb
		ovn.defGatewayRouter = gw
	}
	return lb
}

// getLoadBalancerVIPs returns a map whose keys are VIPs (IP:port) on loadBalancer
func (ovn *Controller) getLoadBalancerVIPs(loadBalancer string) (map[string]interface{}, error) {
	outStr, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"get", "load_balancer", loadBalancer, "vips")
	if err != nil {
		return nil, err
	}
	if outStr == "" {
		return nil, nil
	}
	// sample outStr:
	// - {"192.168.0.1:80"="10.1.1.1:80,10.2.2.2:80"}
	// - {"[fd01::]:80"="[fd02::]:80,[fd03::]:80"}
	outStrMap := strings.Replace(outStr, "=", ":", -1)

	var raw map[string]interface{}
	err = json.Unmarshal([]byte(outStrMap), &raw)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// deleteLoadBalancerVIP removes the VIP as well as any reject ACLs associated to the LB
func (ovn *Controller) deleteLoadBalancerVIP(loadBalancer, vip string) {
	vipQuotes := fmt.Sprintf("\"%s\"", vip)
	stdout, stderr, err := util.RunOVNNbctl("--if-exists", "remove", "load_balancer", loadBalancer, "vips", vipQuotes)
	if err != nil {
		klog.Errorf("Error in deleting load balancer vip %s for %s"+
			"stdout: %q, stderr: %q, error: %v",
			vip, loadBalancer, stdout, stderr, err)
		// if we hit an error and fail to remove load balancer, we skip removing the rejectACL
		return
	}
	ovn.removeServiceEndpoints(loadBalancer, vip)
	ovn.deleteLoadBalancerRejectACL(loadBalancer, vip)
	ovn.removeServiceLB(loadBalancer, vip)
}

// configureLoadBalancer updates the VIP for sourceIP:sourcePort to point to targets (an
// array of IP:port strings)
func (ovn *Controller) configureLoadBalancer(lb, sourceIP string, sourcePort int32, targets []string) error {
	ovn.serviceLBLock.Lock()
	defer ovn.serviceLBLock.Unlock()

	vip := util.JoinHostPortInt32(sourceIP, sourcePort)
	lbTarget := fmt.Sprintf(`vips:"%s"="%s"`, vip, strings.Join(targets, ","))

	out, stderr, err := util.RunOVNNbctl("set", "load_balancer", lb, lbTarget)
	if err != nil {
		return fmt.Errorf("error in configuring load balancer: %s "+
			"stdout: %q, stderr: %q, error: %v", lb, out, stderr, err)
	}
	ovn.setServiceEndpointsToLB(lb, vip, targets)
	klog.V(5).Infof("lb entry set for %s, %s, %v", lb, lbTarget,
		ovn.serviceLBMap[lb][vip])
	return nil
}

// createLoadBalancerVIPs either creates or updates a set of load balancer VIPs mapping
// from sourcePort on each IP of a given address family in sourceIPs, to targetPort on
// each IP of the same address family in targetIPs, removing the reject ACL for any
// source IP that is now in use.
func (ovn *Controller) createLoadBalancerVIPs(lb string,
	sourceIPs []string, sourcePort int32,
	targetIPs []string, targetPort int32) error {
	klog.V(5).Infof("Creating lb with %s, [%v], %d, [%v], %d", lb, sourceIPs, sourcePort, targetIPs, targetPort)

	for _, sourceIP := range sourceIPs {
		isIPv6 := utilnet.IsIPv6String(sourceIP)

		var targets []string
		for _, targetIP := range targetIPs {
			if utilnet.IsIPv6String(targetIP) == isIPv6 {
				targets = append(targets, util.JoinHostPortInt32(targetIP, targetPort))
			}
		}
		err := ovn.configureLoadBalancer(lb, sourceIP, sourcePort, targets)
		if len(targets) > 0 {
			// ensure the ACL is removed if it exists
			ovn.deleteLoadBalancerRejectACL(lb, util.JoinHostPortInt32(sourceIP, sourcePort))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (ovn *Controller) getLogicalSwitchesForLoadBalancer(lb string) ([]string, error) {
	out, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find",
		"logical_switch", fmt.Sprintf("load_balancer{>=}%s", lb))
	if err != nil {
		return nil, err
	}
	if len(strings.Fields(out)) > 0 {
		return strings.Fields(out), nil
	}
	// if load balancer was not on a switch, then it may be on a router
	out, _, err = util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=name", "find",
		"logical_router", fmt.Sprintf("load_balancer{>=}%s", lb))
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	// if this is a GR we know the corresponding join and external switches, otherwise this is an unhandled
	// case
	if strings.HasPrefix(out, gwRouterPrefix) {
		routerName := strings.TrimPrefix(out, gwRouterPrefix)
		return []string{joinSwitchPrefix + routerName, externalSwitchPrefix + routerName}, nil
	}
	return nil, fmt.Errorf("router detected with load balancer that is not a GR")
}

func (ovn *Controller) createLoadBalancerRejectACL(lb string, sourceIP string, sourcePort int32, proto kapi.Protocol) (string, error) {
	ovn.serviceLBLock.Lock()
	defer ovn.serviceLBLock.Unlock()
	switches, err := ovn.getLogicalSwitchesForLoadBalancer(lb)
	if err != nil {
		return "", fmt.Errorf("error finding logical switch that contains load balancer %s: %v", lb, err)
	}

	if len(switches) == 0 {
		klog.V(5).Infof("Ignoring creating reject ACL for load balancer %s. It has no logical switches", lb)
		return "", nil
	}

	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return "", fmt.Errorf("cannot create reject ACL, invalid source IP: %s", sourceIP)
	}
	var aclMatch string
	var l3Prefix string
	if utilnet.IsIPv6(ip) {
		l3Prefix = "ip6"
	} else {
		l3Prefix = "ip4"
	}
	vip := util.JoinHostPortInt32(sourceIP, sourcePort)
	// NOTE: doesn't use vip, to avoid having brackets in the name with IPv6
	aclName := fmt.Sprintf("%s-%s:%d", lb, sourceIP, sourcePort)
	// If ovn-k8s was restarted, we lost the cache, and an ACL may already exist in OVN. In that case we need to check
	// using ACL name
	aclUUID, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "acl",
		fmt.Sprintf("name=%s", strings.ReplaceAll(aclName, ":", "\\:")))
	if err != nil {
		klog.Errorf("Error while querying ACLs by name: %s, %v", stderr, err)
	} else if len(aclUUID) > 0 {
		klog.Infof("Existing Service Reject ACL found: %s for %s", aclUUID, aclName)
		// If we found the ACL exists we need to ensure it applies to all logical switches
		for _, ls := range switches {
			_, _, err := util.RunOVNNbctl("add", "logical_switch", ls, "acls", aclUUID)
			if err != nil {
				klog.Warningf("Unable to add reject ACL: %s for switch: %s", aclUUID, ls)
			}
		}
		ovn.setServiceACLToLB(lb, vip, aclUUID)
		return aclUUID, nil
	}

	aclMatch = fmt.Sprintf("match=\"%s.dst==%s && %s && %s.dst==%d\"", l3Prefix, sourceIP,
		strings.ToLower(string(proto)), strings.ToLower(string(proto)), sourcePort)

	cmd := []string{"--id=@acl", "create", "acl", "direction=from-lport", "priority=1000", aclMatch, "action=reject",
		fmt.Sprintf("name=%s", strings.ReplaceAll(aclName, ":", "\\:"))}
	for _, ls := range switches {
		cmd = append(cmd, "--", "add", "logical_switch", ls, "acls", "@acl")
	}

	aclUUID, stderr, err = util.RunOVNNbctl(cmd...)
	if err != nil {
		return "", fmt.Errorf("error creating ACL reject rule: %s for load balancer %s: %s, %s", cmd, lb, stderr,
			err)
	} else {
		// Associate ACL UUID with load balancer and ip+port so we can remove this ACL if
		// backends are re-added.
		ovn.setServiceACLToLB(lb, vip, aclUUID)
	}
	return aclUUID, nil
}

func (ovn *Controller) deleteLoadBalancerRejectACL(lb, vip string) {
	acl, _ := ovn.getServiceLBInfo(lb, vip)
	if acl == "" {
		klog.V(5).Infof("No reject ACL found to remove for load balancer: %s, vip: %s", lb, vip)
		return
	}

	switches, err := ovn.getLogicalSwitchesForLoadBalancer(lb)
	if err != nil {
		klog.Errorf("Could not retrieve logical switches associated with load balancer %s", lb)
		return
	}
	for _, ls := range switches {
		_, _, err := util.RunOVNNbctl("--if-exists", "remove", "logical_switch", ls, "acl", acl)
		if err != nil {
			klog.Errorf("Error while removing ACL: %s, from switch %s, error: %v", acl, ls, err)
		} else {
			klog.V(5).Infof("ACL: %s, removed from switch: %s", acl, ls)
		}
	}

	ovn.removeServiceACL(lb, vip)
}
