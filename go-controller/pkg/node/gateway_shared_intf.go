package node

import (
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

const (
	// defaultOpenFlowCookie identifies default open flow rules added to the host OVS bridge.
	// The hex number 0xdeff105, aka defflos, is meant to sound like default flows.
	defaultOpenFlowCookie = "0xdeff105"
)

func addService(service *kapi.Service, inport, outport, gwBridge string) {
	if !util.ServiceTypeHasNodePort(service) {
		return
	}

	for _, svcPort := range service.Spec.Ports {
		_, err := util.ValidateProtocol(svcPort.Protocol)
		if err != nil {
			klog.Errorf("Skipping service add. Invalid service port %s: %v", svcPort.Name, err)
			continue
		}
		protocol := strings.ToLower(string(svcPort.Protocol))

		_, stderr, err := util.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("priority=100, in_port=%s, %s, tp_dst=%d, actions=%s",
				inport, protocol, svcPort.NodePort, outport))
		if err != nil {
			klog.Errorf("Failed to add openflow flow on %s for nodePort "+
				"%d, stderr: %q, error: %v", gwBridge,
				svcPort.NodePort, stderr, err)
		}
	}
}

func deleteService(service *kapi.Service, inport, gwBridge string) {
	if !util.ServiceTypeHasNodePort(service) {
		return
	}

	for _, svcPort := range service.Spec.Ports {
		_, err := util.ValidateProtocol(svcPort.Protocol)
		if err != nil {
			klog.Errorf("Skipping service delete. Invalid service port %s: %v", svcPort.Name, err)
			continue
		}

		protocol := strings.ToLower(string(svcPort.Protocol))

		_, stderr, err := util.RunOVSOfctl("del-flows", gwBridge,
			fmt.Sprintf("in_port=%s, %s, tp_dst=%d",
				inport, protocol, svcPort.NodePort))
		if err != nil {
			klog.Errorf("Failed to delete openflow flow on %s for nodePort "+
				"%d, stderr: %q, error: %v", gwBridge,
				svcPort.NodePort, stderr, err)
		}
	}
}

func syncServices(services []interface{}, inport, gwBridge string) {
	nodePorts := make(map[string]bool)
	for _, serviceInterface := range services {
		service, ok := serviceInterface.(*kapi.Service)
		if !ok {
			klog.Errorf("Spurious object in syncServices: %v",
				serviceInterface)
			continue
		}

		if !util.ServiceTypeHasNodePort(service) ||
			len(service.Spec.Ports) == 0 {
			continue
		}

		for _, svcPort := range service.Spec.Ports {
			port := svcPort.NodePort
			if port == 0 {
				continue
			}

			proto, err := util.ValidateProtocol(svcPort.Protocol)
			if err != nil {
				klog.Errorf("syncServices error for service port %s: %v", svcPort.Name, err)
				continue
			}
			protocol := strings.ToLower(string(proto))
			nodePortKey := fmt.Sprintf("%s_%d", protocol, port)
			nodePorts[nodePortKey] = true
		}
	}

	stdout, stderr, err := util.RunOVSOfctl("dump-flows",
		gwBridge)
	if err != nil {
		klog.Errorf("dump-flows failed: %q (%v)", stderr, err)
		return
	}
	flows := strings.Split(stdout, "\n")

	re, err := regexp.Compile(`tp_dst=(.*?)[, ]`)
	if err != nil {
		klog.Errorf("regexp compile failed: %v", err)
		return
	}

	for _, flow := range flows {
		group := re.FindStringSubmatch(flow)
		if group == nil {
			continue
		}

		var key string
		if strings.Contains(flow, "tcp") {
			key = fmt.Sprintf("tcp_%s", group[1])
		} else if strings.Contains(flow, "udp") {
			key = fmt.Sprintf("udp_%s", group[1])
		} else if strings.Contains(flow, "sctp") {
			key = fmt.Sprintf("sctp_%s", group[1])
		} else {
			continue
		}

		if _, ok := nodePorts[key]; !ok {
			pair := strings.Split(key, "_")
			protocol, port := pair[0], pair[1]

			stdout, _, err := util.RunOVSOfctl(
				"del-flows", gwBridge,
				fmt.Sprintf("in_port=%s, %s, tp_dst=%s",
					inport, protocol, port))
			if err != nil {
				klog.Errorf("del-flows of %s failed: %q",
					gwBridge, stdout)
			}
		}
	}
}

func nodePortWatcher(nodeName, gwBridge, gwIntf string, wf *factory.WatchFactory) error {
	// the name of the patch port created by ovn-controller is of the form
	// patch-<logical_port_name_of_localnet_port>-to-br-int
	patchPort := "patch-" + gwBridge + "_" + nodeName + "-to-br-int"
	// Get ofport of patchPort
	ofportPatch, stderr, err := util.RunOVSVsctl("--if-exists", "get",
		"interface", patchPort, "ofport")
	if err != nil {
		return fmt.Errorf("Failed to get ofport of %s, stderr: %q, error: %v",
			patchPort, stderr, err)
	}

	// Get ofport of physical interface
	ofportPhys, stderr, err := util.RunOVSVsctl("--if-exists", "get",
		"interface", gwIntf, "ofport")
	if err != nil {
		return fmt.Errorf("Failed to get ofport of %s, stderr: %q, error: %v",
			gwIntf, stderr, err)
	}

	_, err = wf.AddServiceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service := obj.(*kapi.Service)
			addService(service, ofportPhys, ofportPatch, gwBridge)
		},
		UpdateFunc: func(old, new interface{}) {
			svcNew := new.(*kapi.Service)
			svcOld := old.(*kapi.Service)
			if reflect.DeepEqual(svcNew.Spec, svcOld.Spec) {
				return
			}
			deleteService(svcOld, ofportPhys, gwBridge)
			addService(svcNew, ofportPhys, ofportPatch, gwBridge)
		},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*kapi.Service)
			deleteService(service, ofportPhys, gwBridge)
		},
	}, func(services []interface{}) {
		syncServices(services, ofportPhys, gwBridge)
	})

	return err
}

// since we share the host's k8s node IP, add OpenFlow flows
// -- to steer the NodePort traffic arriving on the host to the OVN logical topology and
// -- to also connection track the outbound north-south traffic through l3 gateway so that
//    the return traffic can be steered back to OVN logical topology
func addDefaultConntrackRules(nodeName, gwBridge, gwIntf string, stopChan chan struct{}) error {
	// the name of the patch port created by ovn-controller is of the form
	// patch-<logical_port_name_of_localnet_port>-to-br-int
	localnetLpName := gwBridge + "_" + nodeName
	patchPort := "patch-" + localnetLpName + "-to-br-int"
	// Get ofport of patchPort, but before that make sure ovn-controller created
	// one for us (waits for about ovsCommandTimeout seconds)
	ofportPatch, stderr, err := util.RunOVSVsctl("wait-until", "Interface", patchPort, "ofport>0",
		"--", "get", "Interface", patchPort, "ofport")
	if err != nil {
		return fmt.Errorf("Failed while waiting on patch port %q to be created by ovn-controller and "+
			"while getting ofport. stderr: %q, error: %v", patchPort, stderr, err)
	}

	// Get ofport of physical interface
	ofportPhys, stderr, err := util.RunOVSVsctl("--if-exists", "get",
		"interface", gwIntf, "ofport")
	if err != nil {
		return fmt.Errorf("Failed to get ofport of %s, stderr: %q, error: %v",
			gwIntf, stderr, err)
	}

	// replace the left over OpenFlow flows with the NORMAL action flow
	_, stderr, err = util.AddNormalActionOFFlow(gwBridge)
	if err != nil {
		return fmt.Errorf("failed to replace-flows on bridge %q stderr:%s (%v)", gwBridge, stderr, err)
	}

	nFlows := 0
	// table 0, packets coming from pods headed externally. Commit connections
	// so that reverse direction goes back to the pods.
	_, stderr, err = util.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=100, in_port=%s, ip, "+
			"actions=ct(commit, zone=%d), output:%s",
			defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))
	if err != nil {
		return fmt.Errorf("Failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// table 0, packets coming from external. Send it through conntrack and
	// resubmit to table 1 to know the state of the connection.
	_, stderr, err = util.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=50, in_port=%s, ip, "+
			"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
	if err != nil {
		return fmt.Errorf("Failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// table 1, established and related connections go to pod
	_, stderr, err = util.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=100, table=1, ct_state=+trk+est, "+
			"actions=output:%s", defaultOpenFlowCookie, ofportPatch))
	if err != nil {
		return fmt.Errorf("Failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	_, stderr, err = util.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=100, table=1, ct_state=+trk+rel, "+
			"actions=output:%s", defaultOpenFlowCookie, ofportPatch))
	if err != nil {
		return fmt.Errorf("Failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// table 1, all other connections do normal processing
	_, stderr, err = util.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=0, table=1, actions=output:NORMAL", defaultOpenFlowCookie))
	if err != nil {
		return fmt.Errorf("Failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// add health check function to check default OpenFlow flows are on the shared gateway bridge
	go checkDefaultConntrackRules(gwBridge, gwIntf, patchPort, ofportPhys, ofportPatch, nFlows, stopChan)
	return nil
}

func (n *OvnNode) initSharedGateway(subnet *net.IPNet, gwNextHop net.IP, gwIntf string,
	nodeAnnotator kube.Annotator) (postWaitFunc, error) {
	var bridgeName string
	var uplinkName string
	var brCreated bool
	var err error

	if bridgeName, _, err = util.RunOVSVsctl("--", "port-to-br", gwIntf); err == nil {
		// This is an OVS bridge's internal port
		uplinkName, err = util.GetNicName(bridgeName)
		if err != nil {
			return nil, err
		}
	} else if _, _, err := util.RunOVSVsctl("--", "br-exists", gwIntf); err != nil {
		// This is not a OVS bridge. We need to create a OVS bridge
		// and add cluster.GatewayIntf as a port of that bridge.
		bridgeName, err = util.NicToBridge(gwIntf)
		if err != nil {
			return nil, fmt.Errorf("failed to convert %s to OVS bridge: %v",
				gwIntf, err)
		}
		uplinkName = gwIntf
		gwIntf = bridgeName
		brCreated = true
	} else {
		// gateway interface is an OVS bridge
		uplinkName, err = getIntfName(gwIntf)
		if err != nil {
			return nil, err
		}
		bridgeName = gwIntf
	}

	// Now, we get IP address from OVS bridge. If IP does not exist,
	// error out.
	ipAddress, err := getIPv4Address(gwIntf)
	if err != nil {
		return nil, fmt.Errorf("Failed to get interface details for %s (%v)",
			gwIntf, err)
	}
	if ipAddress == nil {
		return nil, fmt.Errorf("%s does not have a ipv4 address", gwIntf)
	}

	ifaceID, macAddress, err := bridgedGatewayNodeSetup(n.name, bridgeName, gwIntf, brCreated)
	if err != nil {
		return nil, fmt.Errorf("failed to set up shared interface gateway: %v", err)
	}

	chassisID, err := util.GetNodeChassisID()
	if err != nil {
		return nil, err
	}

	err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{
		Mode:           config.GatewayModeShared,
		ChassisID:      chassisID,
		InterfaceID:    ifaceID,
		MACAddress:     macAddress,
		IPAddresses:    []*net.IPNet{ipAddress},
		NextHops:       []net.IP{gwNextHop},
		NodePortEnable: config.Gateway.NodeportEnable,
		VLANID:         &config.Gateway.VLANID,
	})
	if err != nil {
		return nil, err
	}

	return func() error {
		// Program cluster.GatewayIntf to let non-pod traffic to go to host
		// stack
		if err := addDefaultConntrackRules(n.name, bridgeName, uplinkName, n.stopChan); err != nil {
			return err
		}

		if config.Gateway.NodeportEnable {
			// Program cluster.GatewayIntf to let nodePort traffic to go to pods.
			if err := nodePortWatcher(n.name, bridgeName, uplinkName, n.watchFactory); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func cleanupSharedGateway() error {
	// NicToBridge() may be created before-hand, only delete the patch port here
	stdout, stderr, err := util.RunOVSVsctl("--columns=name", "--no-heading", "find", "port",
		"external_ids:ovn-localnet-port!=_")
	if err != nil {
		return fmt.Errorf("Failed to get ovn-localnet-port port stderr:%s (%v)", stderr, err)
	}
	ports := strings.Fields(strings.Trim(stdout, "\""))
	for _, port := range ports {
		_, stderr, err := util.RunOVSVsctl("--if-exists", "del-port", strings.Trim(port, "\""))
		if err != nil {
			return fmt.Errorf("Failed to delete port %s stderr:%s (%v)", port, stderr, err)
		}
	}

	// Get the OVS bridge name from ovn-bridge-mappings
	stdout, stderr, err = util.RunOVSVsctl("--if-exists", "get", "Open_vSwitch", ".",
		"external_ids:ovn-bridge-mappings")
	if err != nil {
		return fmt.Errorf("Failed to get ovn-bridge-mappings stderr:%s (%v)", stderr, err)
	}
	// skip the existing mapping setting for the specified physicalNetworkName
	bridgeName := ""
	bridgeMappings := strings.Split(stdout, ",")
	for _, bridgeMapping := range bridgeMappings {
		m := strings.Split(bridgeMapping, ":")
		if network := m[0]; network == util.PhysicalNetworkName {
			bridgeName = m[1]
			break
		}
	}
	if len(bridgeName) == 0 {
		return nil
	}

	_, stderr, err = util.AddNormalActionOFFlow(bridgeName)
	if err != nil {
		return fmt.Errorf("Failed to replace-flows on bridge %q stderr:%s (%v)", bridgeName, stderr, err)
	}
	return nil
}
