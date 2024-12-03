package ovn

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	v1 "k8s.io/api/core/v1"

	kubevirtv1 "kubevirt.io/api/core/v1"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func (p testPod) addNetwork(
	netName, nadName, nodeSubnet, nodeMgtIP, nodeGWIP, podIP, podMAC, role string,
	tunnelID int,
	routes []util.PodRoute,
) {
	podInfo, ok := p.secondaryPodInfos[netName]
	if !ok {
		podInfo = &secondaryPodInfo{
			nodeSubnet:  nodeSubnet,
			nodeMgtIP:   nodeMgtIP,
			nodeGWIP:    nodeGWIP,
			routes:      routes,
			allportInfo: map[string]portInfo{},
		}
		p.secondaryPodInfos[netName] = podInfo
	}

	prefixLen, ip := splitPodIPMaskLength(podIP)

	portName := util.GetSecondaryNetworkLogicalPortName(p.namespace, p.podName, nadName)
	podInfo.allportInfo[nadName] = portInfo{
		portUUID:  portName + "-UUID",
		podIP:     ip,
		podMAC:    podMAC,
		portName:  portName,
		tunnelID:  tunnelID,
		prefixLen: prefixLen,
	}
}

func (p testPod) getNetworkPortInfo(netName, nadName string) *portInfo {
	podInfo, ok := p.secondaryPodInfos[netName]
	if !ok {
		return nil
	}
	info, ok := podInfo.allportInfo[nadName]
	if !ok {
		return nil
	}

	return &info
}

func splitPodIPMaskLength(podIP string) (int, string) {
	var prefixLen int
	ip, ipNet, err := net.ParseCIDR(podIP)
	if err != nil || ipNet == nil {
		return 0, podIP // falling back to the test's default - e.g. 24 for v4 / 64 for v6
	}
	prefixLen, _ = ipNet.Mask.Size()
	return prefixLen, ip.String()
}

type option func(machine *secondaryNetworkExpectationMachine)

type secondaryNetworkExpectationMachine struct {
	fakeOvn               *FakeOVN
	pods                  []testPod
	isInterconnectCluster bool
}

func newSecondaryNetworkExpectationMachine(fakeOvn *FakeOVN, pods []testPod, opts ...option) *secondaryNetworkExpectationMachine {
	machine := &secondaryNetworkExpectationMachine{
		fakeOvn: fakeOvn,
		pods:    pods,
	}

	for _, opt := range opts {
		opt(machine)
	}
	return machine
}

func withInterconnectCluster() option {
	return func(machine *secondaryNetworkExpectationMachine) {
		machine.isInterconnectCluster = true
	}
}

func (em *secondaryNetworkExpectationMachine) expectedLogicalSwitchesAndPorts() []libovsdbtest.TestData {
	return em.expectedLogicalSwitchesAndPortsWithLspEnabled(nil)
}

func (em *secondaryNetworkExpectationMachine) expectedLogicalSwitchesAndPortsWithLspEnabled(expectedPodLspEnabled map[string]*bool) []libovsdbtest.TestData {
	data := []libovsdbtest.TestData{}
	for _, ocInfo := range em.fakeOvn.secondaryControllers {
		nodeslsps := make(map[string][]string)
		acls := make(map[string][]string)
		var switchName string
		switchNodeMap := make(map[string]*nbdb.LogicalSwitch)
		alreadyAddedManagementElements := make(map[string]struct{})
		for _, pod := range em.pods {
			podInfo, ok := pod.secondaryPodInfos[ocInfo.bnc.GetNetworkName()]
			if !ok {
				continue
			}
			subnets := podInfo.nodeSubnet
			var (
				subnet     *net.IPNet
				hasSubnets bool
			)
			if len(subnets) > 0 {
				subnet = ovntest.MustParseIPNet(subnets)
				hasSubnets = true
			}

			for nad, portInfo := range podInfo.allportInfo {
				portName := portInfo.portName
				var lspUUID string
				if len(portInfo.portUUID) == 0 {
					lspUUID = portName + "-UUID"
				} else {
					lspUUID = portInfo.portUUID
				}
				podAddr := fmt.Sprintf("%s %s", portInfo.podMAC, portInfo.podIP)
				lsp := newExpectedSwitchPort(lspUUID, portName, podAddr, pod, ocInfo.bnc, nad)
				if expectedPodLspEnabled != nil {
					lsp.Enabled = expectedPodLspEnabled[pod.podName]
				}

				if pod.noIfaceIdVer {
					delete(lsp.Options, "iface-id-ver")
				}
				if ocInfo.bnc.isLayer2Interconnect() {
					lsp.Options["requested-tnl-key"] = "1" // hardcode this for now.
				}
				data = append(data, lsp)

				switch ocInfo.bnc.TopologyType() {
				case ovntypes.Layer3Topology:
					switchName = ocInfo.bnc.GetNetworkScopedName(pod.nodeName)

					switchToRouterPortName := "stor-" + switchName
					switchToRouterPortUUID := switchToRouterPortName + "-UUID"
					data = append(data, newExpectedSwitchToRouterPort(switchToRouterPortUUID, switchToRouterPortName, pod, ocInfo.bnc, nad))
					nodeslsps[switchName] = append(nodeslsps[switchName], switchToRouterPortUUID)

				case ovntypes.Layer2Topology:
					switchName = ocInfo.bnc.GetNetworkScopedName(ovntypes.OVNLayer2Switch)

				case ovntypes.LocalnetTopology:
					switchName = ocInfo.bnc.GetNetworkScopedName(ovntypes.OVNLocalnetSwitch)
				}
				nodeslsps[switchName] = append(nodeslsps[switchName], lspUUID)
			}

			var otherConfig map[string]string
			if hasSubnets {
				otherConfig = map[string]string{
					"exclude_ips": managementPortIP(subnet).String(),
					"subnet":      subnet.String(),
				}
			}

			// TODO: once we start the "full" SecondaryLayer2NetworkController (instead of just Base)
			// we can drop this, and compare all objects created by the controller (right now we're
			// missing all the meters, and the COPP)
			if ocInfo.bnc.TopologyType() == ovntypes.Layer2Topology {
				otherConfig = nil
			}

			switchNodeMap[switchName] = &nbdb.LogicalSwitch{
				UUID:  switchName + "-UUID",
				Name:  switchName,
				Ports: nodeslsps[switchName],
				ExternalIDs: map[string]string{
					ovntypes.NetworkExternalID: ocInfo.bnc.GetNetworkName(),
				},
				OtherConfig: otherConfig,
				ACLs:        acls[switchName],
			}

			if _, alreadyAdded := alreadyAddedManagementElements[pod.nodeName]; !alreadyAdded &&
				em.isInterconnectCluster && ocInfo.bnc.TopologyType() == ovntypes.Layer3Topology {
				transitSwitchName := ocInfo.bnc.GetNetworkName() + "_transit_switch"
				data = append(data, &nbdb.LogicalSwitch{
					UUID: transitSwitchName + "-UUID",
					Name: transitSwitchName,
					OtherConfig: map[string]string{
						"mcast_querier":            "false",
						"mcast_flood_unregistered": "true",
						"interconn-ts":             transitSwitchName,
						"requested-tnl-key":        "16711685",
						"mcast_snoop":              "true",
					},
				})
			}
			alreadyAddedManagementElements[pod.nodeName] = struct{}{}
		}
		for _, logicalSwitch := range switchNodeMap {
			data = append(data, logicalSwitch)
		}
	}

	return data
}

func newExpectedSwitchPort(lspUUID string, portName string, podAddr string, pod testPod, netInfo util.NetInfo, nad string) *nbdb.LogicalSwitchPort {
	return &nbdb.LogicalSwitchPort{
		UUID:      lspUUID,
		Name:      portName,
		Addresses: []string{podAddr},
		ExternalIDs: map[string]string{
			"pod":                       "true",
			"namespace":                 pod.namespace,
			ovntypes.NetworkExternalID:  netInfo.GetNetworkName(),
			ovntypes.NADExternalID:      nad,
			ovntypes.TopologyExternalID: netInfo.TopologyType(),
		},
		Options: map[string]string{
			"requested-chassis": pod.nodeName,
			"iface-id-ver":      pod.podName,
		},
		PortSecurity: []string{podAddr},
	}
}

func newExpectedSwitchToRouterPort(lspUUID string, portName string, pod testPod, netInfo util.NetInfo, nad string) *nbdb.LogicalSwitchPort {
	lrp := newExpectedSwitchPort(lspUUID, portName, "router", pod, netInfo, nad)
	lrp.ExternalIDs = nil
	lrp.Options = map[string]string{
		"router-port": "rtos-isolatednet_test-node",
		"arp_proxy":   "0a:58:a9:fe:01:01 169.254.1.1 fe80::1 10.128.0.0/14",
	}
	lrp.PortSecurity = nil
	lrp.Type = "router"
	return lrp
}

func managementPortIP(subnet *net.IPNet) net.IP {
	return util.GetNodeManagementIfAddr(subnet).IP
}

func minimalFeatureConfig() *config.OVNKubernetesFeatureConfig {
	return &config.OVNKubernetesFeatureConfig{
		EnableMultiNetwork: true,
	}
}

func enableICFeatureConfig() *config.OVNKubernetesFeatureConfig {
	featConfig := minimalFeatureConfig()
	featConfig.EnableInterconnect = true
	return featConfig
}

func icClusterTestConfiguration() testConfiguration {
	return testConfiguration{
		configToOverride:   enableICFeatureConfig(),
		expectationOptions: []option{withInterconnectCluster()},
	}
}

func nonICClusterTestConfiguration() testConfiguration {
	return testConfiguration{}
}

func newMultiHomedKubevirtPod(vmName string, liveMigrationInfo liveMigrationPodInfo, testPod testPod, multiHomingConfigs ...secondaryNetInfo) *v1.Pod {
	pod := newMultiHomedPod(testPod, multiHomingConfigs...)
	pod.Labels[kubevirtv1.VirtualMachineNameLabel] = vmName
	pod.Status.Phase = liveMigrationInfo.podPhase
	for key, val := range liveMigrationInfo.annotation {
		pod.Annotations[key] = val
	}
	pod.CreationTimestamp = liveMigrationInfo.creationTimestamp
	return pod
}

func newMultiHomedPod(testPod testPod, multiHomingConfigs ...secondaryNetInfo) *v1.Pod {
	pod := newPod(testPod.namespace, testPod.podName, testPod.nodeName, testPod.podIP)
	var secondaryNetworks []nadapi.NetworkSelectionElement
	for _, multiHomingConf := range multiHomingConfigs {
		nadNamePair := strings.Split(multiHomingConf.nadName, "/")
		ns := pod.Namespace
		attachmentName := multiHomingConf.nadName
		if len(nadNamePair) > 1 {
			ns = nadNamePair[0]
			attachmentName = nadNamePair[1]
		}
		nse := nadapi.NetworkSelectionElement{
			Name:      attachmentName,
			Namespace: ns,
		}
		secondaryNetworks = append(secondaryNetworks, nse)
	}
	serializedNetworkSelectionElements, _ := json.Marshal(secondaryNetworks)
	pod.Annotations = map[string]string{nadapi.NetworkAttachmentAnnot: string(serializedNetworkSelectionElements)}
	if config.OVNKubernetesFeature.EnableInterconnect {
		dummyOVNNetAnnotations := dummyOVNPodNetworkAnnotations(testPod.secondaryPodInfos, multiHomingConfigs)
		if dummyOVNNetAnnotations != "{}" {
			pod.Annotations["k8s.ovn.org/pod-networks"] = dummyOVNNetAnnotations
		}
	}
	return pod
}

func dummyOVNPodNetworkAnnotations(secondaryPodInfos map[string]*secondaryPodInfo, multiHomingConfigs []secondaryNetInfo) string {
	var ovnPodNetworksAnnotations []byte
	podAnnotations := map[string]podAnnotation{}
	for i, netConfig := range multiHomingConfigs {
		// we need to inject a dummy OVN annotation into the pods for each multihoming config
		// for layer2 topology since allocating the annotation for this cluster configuration
		// is performed by cluster manager - which doesn't exist in the unit tests.
		if netConfig.topology == ovntypes.Layer2Topology {
			portInfo := secondaryPodInfos[netConfig.netName].allportInfo[netConfig.nadName]
			podAnnotations[netConfig.nadName] = dummyOVNPodNetworkAnnotationForNetwork(portInfo, netConfig, i+1)
		}
	}

	var err error
	ovnPodNetworksAnnotations, err = json.Marshal(podAnnotations)
	if err != nil {
		panic(fmt.Errorf("failed to marshal the pod annotations: %w", err))
	}
	return string(ovnPodNetworksAnnotations)
}

func dummyOVNPodNetworkAnnotationForNetwork(portInfo portInfo, netConfig secondaryNetInfo, tunnelID int) podAnnotation {
	var gateways []string
	for _, subnetStr := range strings.Split(netConfig.subnets, ",") {
		subnet := ovntest.MustParseIPNet(subnetStr)
		gateways = append(gateways, util.GetNodeGatewayIfAddr(subnet).IP.String())
	}
	ip := ovntest.MustParseIP(portInfo.podIP)
	_, maskSize := util.GetIPFullMask(ip).Size()
	ipNet := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(portInfo.prefixLen, maskSize),
	}
	return podAnnotation{
		IPs:      []string{ipNet.String()},
		MAC:      util.IPAddrToHWAddr(ip).String(),
		Gateways: gateways,
		Routes:   nil, // TODO: must add here the expected routes.
		TunnelID: tunnelID,
	}
}

// Internal struct used to marshal PodAnnotation to the pod annotationç
// Copied from pkg/util/pod_annotation.go
type podAnnotation struct {
	IPs      []string   `json:"ip_addresses"`
	MAC      string     `json:"mac_address"`
	Gateways []string   `json:"gateway_ips,omitempty"`
	Routes   []podRoute `json:"routes,omitempty"`

	IP      string `json:"ip_address,omitempty"`
	Gateway string `json:"gateway_ip,omitempty"`

	TunnelID int    `json:"tunnel_id,omitempty"`
	Role     string `json:"role,omitempty"`
}

// Internal struct used to marshal PodRoute to the pod annotation
// Copied from pkg/util/pod_annotation.go
type podRoute struct {
	Dest    string `json:"dest"`
	NextHop string `json:"nextHop"`
}
