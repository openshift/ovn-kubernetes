package services

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	nadlister "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/listers/k8s.cni.cncf.io/v1"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	ovncnitypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	globalconfig "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	kubetest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"golang.org/x/exp/maps"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	utilnet "k8s.io/utils/net"
	utilpointer "k8s.io/utils/pointer"
)

var (
	nodeA = "node-a"
	nodeB = "node-b"

	tcp = v1.ProtocolTCP
	udp = v1.ProtocolUDP
)

type serviceController struct {
	*Controller
	serviceStore       cache.Store
	endpointSliceStore cache.Store
	libovsdbCleanup    *libovsdbtest.Context
}

func newControllerWithDBSetupForNetwork(dbSetup libovsdbtest.TestSetup, netInfo util.NetInfo, testUDN bool, nadNamespace, nadNetworkName string) (*serviceController, error) {
	nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(dbSetup, nil)

	if err != nil {
		return nil, err
	}

	config.OVNKubernetesFeature.EnableInterconnect = true
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableNetworkSegmentation = true

	client := util.GetOVNClientset().GetOVNKubeControllerClientset()

	factoryMock, err := factory.NewOVNKubeControllerWatchFactory(client)
	if err != nil {
		return nil, err
	}

	if err = factoryMock.Start(); err != nil {
		return nil, err
	}
	recorder := record.NewFakeRecorder(10)

	nbZoneFailed := false
	// Try to get the NBZone.  If there is an error, create NB_Global record.
	// Otherwise NewController() will return error since it
	// calls libovsdbutil.GetNBZone().
	_, err = libovsdbutil.GetNBZone(nbClient)
	if err != nil {
		nbZoneFailed = true
		if err = createTestNBGlobal(nbClient, "global"); err != nil {
			return nil, err
		}
	}
	var nadLister nadlister.NetworkAttachmentDefinitionLister
	if testUDN {
		nadLister = factoryMock.NADInformer().Lister()
	}

	controller, err := NewController(client.KubeClient,
		nbClient,
		factoryMock.ServiceCoreInformer(),
		factoryMock.EndpointSliceCoreInformer(),
		factoryMock.NodeCoreInformer(),
		nadLister,
		recorder,
		netInfo,
	)
	if err != nil {
		return nil, err
	}

	if nbZoneFailed {
		// Delete the NBGlobal row as this function created it.  Otherwise many tests would fail while
		// checking the expectedData in the NBDB.
		if err = deleteTestNBGlobal(nbClient, "global"); err != nil {
			return nil, err
		}
	}

	if err = controller.initTopLevelCache(); err != nil {
		return nil, err
	}
	controller.useLBGroups = true
	controller.useTemplates = true

	// When testing services on UDN, add a NAD in the same namespace associated to the service
	if testUDN {
		if err = addSampleNAD(client, nadNamespace, nadNetworkName); err != nil {
			return nil, err
		}
	}

	return &serviceController{
		controller,
		factoryMock.ServiceCoreInformer().Informer().GetStore(),
		factoryMock.EndpointSliceInformer().GetStore(),
		cleanup,
	}, nil
}

func (c *serviceController) close() {
	c.libovsdbCleanup.Cleanup()
}

func getSampleUDNNetInfo(namespace string) util.NetInfo {
	netInfo, _ := util.NewNetInfo(&ovncnitypes.NetConf{
		Topology:   "layer3",
		NADName:    fmt.Sprintf("%s/nad1", namespace),
		MTU:        1400,
		Role:       "primary",
		Subnets:    "192.168.200.0/16",
		NetConf:    cnitypes.NetConf{Name: "tenant-red", Type: "ovn-k8s-cni-overlay"},
		JoinSubnet: "100.66.0.0/16",
	})
	return netInfo
}

func addSampleNAD(client *util.OVNKubeControllerClientset, namespace, networkName string) error {
	_, err := client.NetworkAttchDefClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Create(
		context.TODO(),
		kubetest.GenerateNAD(networkName, networkName, namespace, types.Layer3Topology, "10.128.0.0/16/24", types.NetworkRolePrimary),
		metav1.CreateOptions{})
	return err
}

// TestSyncServices - an end-to-end test for the services controller.
func TestSyncServices(t *testing.T) {
	// setup gomega parameters
	initialMaxLength := format.MaxLength
	temporarilyEnableGomegaMaxLengthFormat()
	t.Cleanup(func() {
		restoreGomegaMaxLengthFormat(initialMaxLength)
	})

	// define test constants
	const (
		nodeAEndpoint    = "10.128.0.2"
		nodeAEndpoint2   = "10.128.0.3"
		nodeAEndpointV6  = "fe00::5555:0:0:2"
		nodeAEndpoint2V6 = "fe00::5555:0:0:3"

		nodeBEndpointIP = "10.128.1.2"

		nodeAHostAddress = "10.0.0.1"
		nodeBHostAddress = "10.0.0.2"

		nodePort = 8989

		// the IPs below are only used in one test
		nodeAHostAddress2   = "10.2.2.2"
		nodeAHostAddress3   = "10.3.3.3"
		nodeAHostAddressV6  = "fd00::1:0:0:1"
		nodeAHostAddress2V6 = "fd00::2:0:0:2"
	)

	var (
		ns          = "testns"
		serviceName = "foo"

		serviceClusterIP   = "192.168.1.1"
		serviceClusterIPv6 = "fd00::7777:0:0:1"
		servicePort        = int32(80)
		outPort            = int32(3456)

		initialLsGroups = []string{types.ClusterLBGroupName, types.ClusterSwitchLBGroupName}
		initialLrGroups = []string{types.ClusterLBGroupName, types.ClusterRouterLBGroupName}

		udnNetworkName = "tenant-red"
		udnNetInfo     = getSampleUDNNetInfo(ns)
	)
	// setup global config
	oldGateway := globalconfig.Gateway.Mode
	oldClusterSubnet := globalconfig.Default.ClusterSubnets
	globalconfig.Kubernetes.OVNEmptyLbEvents = true
	globalconfig.IPv4Mode = true
	defer func() {
		globalconfig.Kubernetes.OVNEmptyLbEvents = false
		globalconfig.IPv4Mode = false
		globalconfig.Gateway.Mode = oldGateway
		globalconfig.Default.ClusterSubnets = oldClusterSubnet
	}()
	_, cidr4, _ := net.ParseCIDR("10.128.0.0/16")
	_, cidr6, _ := net.ParseCIDR("fe00:0:0:0:5555::0/64")
	globalconfig.Default.ClusterSubnets = []globalconfig.CIDRNetworkEntry{{cidr4, 26}, {cidr6, 26}}

	// define node configs
	nodeAInfo := getNodeInfo(nodeA, []string{nodeAHostAddress}, nil)
	nodeBInfo := getNodeInfo(nodeB, []string{nodeBHostAddress}, nil)

	nodeAMultiAddressesV4 := []string{nodeAHostAddress, nodeAHostAddress2, nodeAHostAddress3}
	nodeAMultiAddressesV6 := []string{nodeAHostAddressV6, nodeAHostAddress2V6}

	nodeAInfoMultiIP := getNodeInfo(nodeA, nodeAMultiAddressesV4, nodeAMultiAddressesV6)

	// Each test structure is filled in with the initial and expect OVN DB for the scenario where the services controller
	// runs in the default cluster network (initialDb, expectedDb) and for the scenario where it runs in a UDN (initialDbUDN, expectedDbUDN).
	// In the UDN scenario, the expectation is that the OVN DB still contains the default objects for the default cluster network,
	// even though they're left empty for simplicity, and all OVNK logic applies to the UDN-specific OVN objects.
	tests := []struct {
		name                    string
		nodeAInfo               *nodeInfo
		nodeBInfo               *nodeInfo
		enableIPv6              bool
		slices                  []discovery.EndpointSlice
		service                 *v1.Service
		initialDb               []libovsdbtest.TestData
		expectedDb              []libovsdbtest.TestData
		initialDbUDN            []libovsdbtest.TestData
		expectedDbUDN           []libovsdbtest.TestData
		gatewayMode             string
		nodeToDelete            string
		dbStateAfterDeleting    []libovsdbtest.TestData
		dbStateAfterDeletingUDN []libovsdbtest.TestData
	}{

		{
			name:      "create service from Single Stack Service without endpoints",
			nodeAInfo: nodeAInfo,
			nodeBInfo: nodeBInfo,
			slices: []discovery.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serviceName + "ab23",
						Namespace: ns,
						Labels:    map[string]string{discovery.LabelServiceName: serviceName},
					},
					Ports:       []discovery.EndpointPort{},
					AddressType: discovery.AddressTypeIPv4,
					Endpoints:   []discovery.Endpoint{},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  serviceClusterIP,
					ClusterIPs: []string{serviceClusterIP},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       servicePort,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt32(outPort),
					}},
				},
			},
			initialDb: []libovsdbtest.TestData{
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
			},
			expectedDb: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): "",
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				lbGroup(types.ClusterLBGroupName, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
			initialDbUDN: []libovsdbtest.TestData{
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo),
			},
			expectedDbUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): "",
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetInfo.GetNetworkName()),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo),

				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
		},
		{
			name:      "update service without endpoints",
			nodeAInfo: nodeAInfo,
			nodeBInfo: nodeBInfo,
			slices: []discovery.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serviceName + "ab23",
						Namespace: ns,
						Labels:    map[string]string{discovery.LabelServiceName: serviceName},
					},
					Ports:       []discovery.EndpointPort{},
					AddressType: discovery.AddressTypeIPv4,
					Endpoints:   []discovery.Endpoint{},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  serviceClusterIP,
					ClusterIPs: []string{serviceClusterIP},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       servicePort,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt32(outPort),
					}},
				},
			},
			initialDb: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"192.168.0.1:6443": "",
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitch("wrong-switch", []string{}, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				nodeLogicalRouter(nodeA, initialLrGroups, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				nodeLogicalRouter(nodeB, initialLrGroups, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				nodeLogicalRouter("node-c", []string{}, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
			},
			initialDbUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"192.168.0.1:6443": "",
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork("wrong-switch", []string{}, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				nodeLogicalRouterForNetwork("node-c", []string{}, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo),
			},
			expectedDb: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): "",
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitch("wrong-switch", []string{}),
				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouter("node-c", []string{}),
				lbGroup(types.ClusterLBGroupName, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
			expectedDbUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): "",
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork("wrong-switch", []string{}, udnNetInfo),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo),
				nodeLogicalRouterForNetwork("node-c", []string{}, udnNetInfo),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo),

				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
		},
		{
			name:      "transition to endpoints, create nodeport",
			nodeAInfo: nodeAInfo,
			nodeBInfo: nodeBInfo,
			slices: []discovery.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serviceName + "ab1",
						Namespace: ns,
						Labels:    map[string]string{discovery.LabelServiceName: serviceName},
					},
					Ports: []discovery.EndpointPort{
						{
							Protocol: &tcp,
							Port:     &outPort,
						},
					},
					AddressType: discovery.AddressTypeIPv4,
					Endpoints: []discovery.Endpoint{
						{
							Conditions: discovery.EndpointConditions{
								Ready: utilpointer.Bool(true),
							},
							Addresses: []string{nodeAEndpoint},
							NodeName:  &nodeA,
						},
						{
							Conditions: discovery.EndpointConditions{
								Ready: utilpointer.Bool(true),
							},
							Addresses: []string{nodeBEndpointIP},
							NodeName:  &nodeB,
						},
					},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  serviceClusterIP,
					ClusterIPs: []string{serviceClusterIP},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       servicePort,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt32(outPort),
						NodePort:   nodePort,
					}},
				},
			},
			initialDb: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"192.168.0.1:6443": "",
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				nodeLogicalSwitch(nodeB, initialLsGroups, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				nodeLogicalRouter(nodeA, initialLrGroups, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				nodeLogicalRouter(nodeB, initialLrGroups, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
			},
			initialDbUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"192.168.0.1:6443": "",
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo),
			},
			expectedDb: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): formatEndpoints(outPort, nodeAEndpoint, nodeBEndpointIP),
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeMergedTemplateLoadBalancer(nodePort, serviceName, ns, outPort, nodeAEndpoint, nodeBEndpointIP),
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				lbGroup(types.ClusterLBGroupName, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterSwitchLBGroupName, nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol)),
				lbGroup(types.ClusterRouterLBGroupName, nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol)),
				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
			expectedDbUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): formatEndpoints(outPort, nodeAEndpoint, nodeBEndpointIP),
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				nodeMergedTemplateLoadBalancerForNetwork(nodePort, serviceName, ns, outPort, udnNetInfo, nodeAEndpoint, nodeBEndpointIP),

				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo, nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo)),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo, nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo)),

				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
		},
		{
			name:      "deleting a node should not leave stale load balancers",
			nodeAInfo: nodeAInfo,
			nodeBInfo: nodeBInfo,
			slices: []discovery.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serviceName + "ab1",
						Namespace: ns,
						Labels:    map[string]string{discovery.LabelServiceName: serviceName},
					},
					Ports: []discovery.EndpointPort{
						{
							Protocol: &tcp,
							Port:     &outPort,
						},
					},
					AddressType: discovery.AddressTypeIPv4,
					Endpoints: []discovery.Endpoint{
						{
							Conditions: discovery.EndpointConditions{
								Ready: utilpointer.Bool(true),
							},
							Addresses: []string{nodeAEndpoint},
							NodeName:  &nodeA,
						},
						{
							Conditions: discovery.EndpointConditions{
								Ready: utilpointer.Bool(true),
							},
							Addresses: []string{nodeBEndpointIP},
							NodeName:  &nodeB,
						},
					},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  serviceClusterIP,
					ClusterIPs: []string{serviceClusterIP},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       servicePort,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt32(outPort),
						NodePort:   nodePort,
					}},
				},
			},
			initialDb: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"192.168.0.1:6443": "",
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				lbGroup(types.ClusterLBGroupName, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
			},
			initialDbUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"192.168.0.1:6443": "",
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo),
			},
			expectedDb: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): formatEndpoints(outPort, nodeAEndpoint, nodeBEndpointIP),
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeMergedTemplateLoadBalancer(nodePort, serviceName, ns, outPort, nodeAEndpoint, nodeBEndpointIP),
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				lbGroup(types.ClusterLBGroupName, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterSwitchLBGroupName, nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol)),
				lbGroup(types.ClusterRouterLBGroupName, nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol)),
				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
			expectedDbUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): formatEndpoints(outPort, nodeAEndpoint, nodeBEndpointIP),
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				nodeMergedTemplateLoadBalancerForNetwork(nodePort, serviceName, ns, outPort, udnNetInfo, nodeAEndpoint, nodeBEndpointIP),
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo, nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo)),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo, nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo)),

				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
			nodeToDelete: nodeA,

			dbStateAfterDeleting: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): formatEndpoints(outPort, nodeAEndpoint, nodeBEndpointIP),
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeMergedTemplateLoadBalancer(nodePort, serviceName, ns, outPort, nodeAEndpoint, nodeBEndpointIP),
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				lbGroup(types.ClusterLBGroupName, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterSwitchLBGroupName, nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol)),
				lbGroup(types.ClusterRouterLBGroupName, nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol)),
				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
			dbStateAfterDeletingUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort): formatEndpoints(outPort, nodeAEndpoint, nodeBEndpointIP),
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				nodeMergedTemplateLoadBalancerForNetwork(nodePort, serviceName, ns, outPort, udnNetInfo, nodeAEndpoint, nodeBEndpointIP),
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitch(nodeB, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),
				nodeLogicalSwitchForNetwork(nodeB, initialLsGroups, udnNetInfo),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouter(nodeB, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo),
				nodeLogicalRouterForNetwork(nodeB, initialLrGroups, udnNetInfo),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo, nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo)),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo, nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo)),

				nodeIPTemplate(nodeAInfo),
				nodeIPTemplate(nodeBInfo),
			},
		},
		{
			// Test for multiple IP support in Template LBs (https://github.com/ovn-org/ovn-kubernetes/pull/3557)
			name:       "NodePort service, multiple IP addresses, ETP=cluster",
			enableIPv6: true,
			nodeAInfo:  nodeAInfoMultiIP,
			nodeBInfo:  nil,
			slices: []discovery.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serviceName + "ipv4",
						Namespace: ns,
						Labels:    map[string]string{discovery.LabelServiceName: serviceName},
					},
					Ports:       []discovery.EndpointPort{{Protocol: &tcp, Port: &outPort}},
					AddressType: discovery.AddressTypeIPv4,
					Endpoints:   kubetest.MakeReadyEndpointList(nodeA, nodeAEndpoint, nodeAEndpoint2),
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serviceName + "ipv6",
						Namespace: ns,
						Labels:    map[string]string{discovery.LabelServiceName: serviceName},
					},
					Ports:       []discovery.EndpointPort{{Protocol: &tcp, Port: &outPort}},
					AddressType: discovery.AddressTypeIPv6,
					Endpoints:   kubetest.MakeReadyEndpointList(nodeA, nodeAEndpointV6, nodeAEndpoint2V6),
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:                  v1.ServiceTypeNodePort,
					ClusterIP:             serviceClusterIP,
					ClusterIPs:            []string{serviceClusterIP, serviceClusterIPv6},
					IPFamilies:            []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol},
					Selector:              map[string]string{"foo": "bar"},
					ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
					Ports: []v1.ServicePort{{
						Port:       servicePort,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt32(outPort),
						NodePort:   30123,
					}},
				},
			},
			initialDb: []libovsdbtest.TestData{
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalRouter(nodeA, initialLrGroups),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
			},
			expectedDb: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Name:     clusterWideTCPServiceLoadBalancerName(ns, serviceName),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort):   formatEndpoints(outPort, nodeAEndpoint, nodeAEndpoint2),
						IPAndPort(serviceClusterIPv6, servicePort): formatEndpoints(outPort, nodeAEndpointV6, nodeAEndpoint2V6),
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				&nbdb.LoadBalancer{
					UUID:     nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol),
					Name:     nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol),
					Options:  templateServicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"^NODEIP_IPv4_1:30123": formatEndpoints(outPort, nodeAEndpoint, nodeAEndpoint2),
						"^NODEIP_IPv4_2:30123": formatEndpoints(outPort, nodeAEndpoint, nodeAEndpoint2),
						"^NODEIP_IPv4_0:30123": formatEndpoints(outPort, nodeAEndpoint, nodeAEndpoint2),
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				&nbdb.LoadBalancer{
					UUID:     nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv6Protocol),
					Name:     nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv6Protocol),
					Options:  templateServicesOptionsV6(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"^NODEIP_IPv6_1:30123": formatEndpoints(outPort, nodeAEndpointV6, nodeAEndpoint2V6),
						"^NODEIP_IPv6_0:30123": formatEndpoints(outPort, nodeAEndpointV6, nodeAEndpoint2V6),
					},
					ExternalIDs: loadBalancerExternalIDs(namespacedServiceName(ns, serviceName)),
				},
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalRouter(nodeA, initialLrGroups),
				lbGroup(types.ClusterLBGroupName, clusterWideTCPServiceLoadBalancerName(ns, serviceName)),
				lbGroup(types.ClusterSwitchLBGroupName,
					nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol),
					nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv6Protocol)),
				lbGroup(types.ClusterRouterLBGroupName,
					nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv4Protocol),
					nodeMergedTemplateLoadBalancerName(ns, serviceName, v1.IPv6Protocol)),

				&nbdb.ChassisTemplateVar{
					UUID: nodeA, Chassis: nodeA,
					Variables: map[string]string{
						makeLBNodeIPTemplateNamePrefix(v1.IPv4Protocol) + "0": nodeAMultiAddressesV4[0],
						makeLBNodeIPTemplateNamePrefix(v1.IPv4Protocol) + "1": nodeAMultiAddressesV4[1],
						makeLBNodeIPTemplateNamePrefix(v1.IPv4Protocol) + "2": nodeAMultiAddressesV4[2],

						makeLBNodeIPTemplateNamePrefix(v1.IPv6Protocol) + "0": nodeAMultiAddressesV6[0],
						makeLBNodeIPTemplateNamePrefix(v1.IPv6Protocol) + "1": nodeAMultiAddressesV6[1],
					},
				},
			},
			initialDbUDN: []libovsdbtest.TestData{
				nodeLogicalSwitch(nodeA, initialLsGroups),
				nodeLogicalSwitchForNetwork(nodeA, initialLsGroups, udnNetInfo),

				nodeLogicalRouter(nodeA, initialLrGroups),
				nodeLogicalRouterForNetwork(nodeA, initialLrGroups, udnNetInfo),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),
				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName, udnNetInfo),
				lbGroupForNetwork(types.ClusterRouterLBGroupName, udnNetInfo),
			},

			expectedDbUDN: []libovsdbtest.TestData{
				&nbdb.LoadBalancer{
					UUID:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Name:     clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo),
					Options:  servicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						IPAndPort(serviceClusterIP, servicePort):   formatEndpoints(outPort, nodeAEndpoint, nodeAEndpoint2),
						IPAndPort(serviceClusterIPv6, servicePort): formatEndpoints(outPort, nodeAEndpointV6, nodeAEndpoint2V6),
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				&nbdb.LoadBalancer{
					UUID:     nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo),
					Name:     nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo),
					Options:  templateServicesOptions(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"^NODEIP_IPv4_1:30123": formatEndpoints(outPort, nodeAEndpoint, nodeAEndpoint2),
						"^NODEIP_IPv4_2:30123": formatEndpoints(outPort, nodeAEndpoint, nodeAEndpoint2),
						"^NODEIP_IPv4_0:30123": formatEndpoints(outPort, nodeAEndpoint, nodeAEndpoint2),
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},
				&nbdb.LoadBalancer{
					UUID:     nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv6Protocol, udnNetInfo),
					Name:     nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv6Protocol, udnNetInfo),
					Options:  templateServicesOptionsV6(),
					Protocol: &nbdb.LoadBalancerProtocolTCP,
					Vips: map[string]string{
						"^NODEIP_IPv6_1:30123": formatEndpoints(outPort, nodeAEndpointV6, nodeAEndpoint2V6),
						"^NODEIP_IPv6_0:30123": formatEndpoints(outPort, nodeAEndpointV6, nodeAEndpoint2V6),
					},
					ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(ns, serviceName), udnNetworkName),
				},

				nodeLogicalSwitchForNetwork(nodeAInfo.name, initialLsGroups, udnNetInfo),
				nodeLogicalRouterForNetwork(nodeAInfo.name, initialLrGroups, udnNetInfo),

				nodeLogicalSwitch(nodeAInfo.name, initialLsGroups),
				nodeLogicalRouter(nodeAInfo.name, initialLrGroups),

				lbGroup(types.ClusterLBGroupName),
				lbGroup(types.ClusterSwitchLBGroupName),
				lbGroup(types.ClusterRouterLBGroupName),

				lbGroupForNetwork(types.ClusterLBGroupName, udnNetInfo, clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, udnNetInfo)),
				lbGroupForNetwork(types.ClusterSwitchLBGroupName,
					udnNetInfo,
					nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo),
					nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv6Protocol, udnNetInfo)),
				lbGroupForNetwork(types.ClusterRouterLBGroupName,
					udnNetInfo,
					nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv4Protocol, udnNetInfo),
					nodeMergedTemplateLoadBalancerNameForNetwork(ns, serviceName, v1.IPv6Protocol, udnNetInfo)),

				&nbdb.ChassisTemplateVar{
					UUID: nodeAInfo.chassisID, Chassis: nodeAInfo.chassisID,
					Variables: map[string]string{
						makeLBNodeIPTemplateNamePrefix(v1.IPv4Protocol) + "0": nodeAMultiAddressesV4[0],
						makeLBNodeIPTemplateNamePrefix(v1.IPv4Protocol) + "1": nodeAMultiAddressesV4[1],
						makeLBNodeIPTemplateNamePrefix(v1.IPv4Protocol) + "2": nodeAMultiAddressesV4[2],

						makeLBNodeIPTemplateNamePrefix(v1.IPv6Protocol) + "0": nodeAMultiAddressesV6[0],
						makeLBNodeIPTemplateNamePrefix(v1.IPv6Protocol) + "1": nodeAMultiAddressesV6[1],
					},
				},
			},
		},
	}

	for i, tt := range tests {
		for _, testUDN := range []bool{false, true} {
			udnString := ""
			if testUDN {
				udnString = "_UDN"
			}
			t.Run(fmt.Sprintf("%d_%s%s", i, tt.name, udnString), func(t *testing.T) {

				g := gomega.NewGomegaWithT(t)

				var netInfo util.NetInfo

				// Setup test-dependent parameters (default network vs UDN)
				netInfo = &util.DefaultNetInfo{}
				initialDb := tt.initialDb
				expectedDb := tt.expectedDb
				dbStateAfterDeleting := tt.dbStateAfterDeleting
				if testUDN {
					netInfo = udnNetInfo
					initialDb = tt.initialDbUDN
					expectedDb = tt.expectedDbUDN
					dbStateAfterDeleting = tt.dbStateAfterDeletingUDN
					nodeAInfo.gatewayRouterName = udnNetInfo.GetNetworkScopedGWRouterName(nodeAInfo.gatewayRouterName)
					nodeAInfo.switchName = udnNetInfo.GetNetworkScopedGWRouterName(nodeAInfo.switchName)
					nodeBInfo.gatewayRouterName = udnNetInfo.GetNetworkScopedGWRouterName(nodeBInfo.gatewayRouterName)
					nodeBInfo.switchName = udnNetInfo.GetNetworkScopedGWRouterName(nodeBInfo.switchName)

				}

				if tt.gatewayMode != "" {
					globalconfig.Gateway.Mode = globalconfig.GatewayMode(tt.gatewayMode)
				} else {
					globalconfig.Gateway.Mode = globalconfig.GatewayModeShared
				}

				if tt.enableIPv6 {
					globalconfig.IPv6Mode = true
					defer func() { globalconfig.IPv6Mode = false }()
				}

				// Create services controller
				var controller *serviceController
				var err error

				controller, err = newControllerWithDBSetupForNetwork(libovsdbtest.TestSetup{NBData: initialDb}, netInfo, testUDN, ns, udnNetworkName)
				if err != nil {
					t.Fatalf("Error creating controller: %v", err)
				}
				defer controller.close()

				// Add k8s objects
				for _, slice := range tt.slices {
					controller.endpointSliceStore.Add(&slice)
				}
				controller.serviceStore.Add(tt.service)

				// Setup node tracker
				controller.nodeTracker.nodes = map[string]nodeInfo{}
				if tt.nodeAInfo != nil {
					controller.nodeTracker.nodes[nodeA] = *tt.nodeAInfo
				}
				if tt.nodeBInfo != nil {
					controller.nodeTracker.nodes[nodeB] = *tt.nodeBInfo
				}

				// Add mirrored endpoint slices when the controller runs on a UDN
				if testUDN {
					for _, slice := range tt.slices {
						controller.endpointSliceStore.Add(kubetest.MirrorEndpointSlice(&slice, udnNetInfo.GetNetworkName(), true))
					}
				}

				// Trigger services controller
				controller.RequestFullSync(controller.nodeTracker.getZoneNodes())

				err = controller.syncService(namespacedServiceName(ns, serviceName))
				if err != nil {
					t.Fatalf("syncServices error: %v", err)
				}

				// Check OVN DB
				g.Expect(controller.nbClient).To(libovsdbtest.HaveData(expectedDb))

				// If the test requires a node to be deleted, remove it from the node tracker,
				// sync the service controller and check the OVN DB
				if tt.nodeToDelete != "" {
					controller.nodeTracker.removeNode(tt.nodeToDelete)

					g.Expect(controller.syncService(namespacedServiceName(ns, serviceName))).To(gomega.Succeed())

					g.Expect(controller.nbClient).To(libovsdbtest.HaveData(dbStateAfterDeleting))
				}
			})
		}

	}
}

func nodeLogicalSwitch(nodeName string, lbGroups []string, namespacedServiceNames ...string) *nbdb.LogicalSwitch {
	return nodeLogicalSwitchForNetwork(nodeName, lbGroups, &util.DefaultNetInfo{}, namespacedServiceNames...)
}

func nodeLogicalSwitchForNetwork(nodeName string, lbGroups []string, netInfo util.NetInfo, namespacedServiceNames ...string) *nbdb.LogicalSwitch {
	var externalIDs map[string]string
	lbGroupsForNetwork := lbGroups

	switchName := nodeSwitchNameForNetwork(nodeName, netInfo)

	if netInfo.IsPrimaryNetwork() {
		for _, lbGroup := range lbGroups {
			lbGroupsForNetwork = append(lbGroupsForNetwork, netInfo.GetNetworkScopedLoadBalancerGroupName(lbGroup))
		}
		externalIDs = getExternalIDsForNetwork(netInfo.GetNetworkName())
	}
	ls := &nbdb.LogicalSwitch{
		UUID:              switchName,
		Name:              switchName,
		LoadBalancerGroup: lbGroupsForNetwork,
		ExternalIDs:       externalIDs,
	}

	if len(namespacedServiceNames) > 0 {
		ls.LoadBalancer = namespacedServiceNames
	}
	return ls
}

func nodeLogicalRouter(nodeName string, lbGroups []string, namespacedServiceNames ...string) *nbdb.LogicalRouter {
	return nodeLogicalRouterForNetwork(nodeName, lbGroups, &util.DefaultNetInfo{}, namespacedServiceNames...)
}

func nodeLogicalRouterForNetwork(nodeName string, lbGroups []string, netInfo util.NetInfo, namespacedServiceNames ...string) *nbdb.LogicalRouter {
	var externalIDs map[string]string
	lbGroupsForNetwork := lbGroups

	routerName := nodeGWRouterNameForNetwork(nodeName, netInfo)

	if netInfo.IsPrimaryNetwork() {
		for _, lbGroup := range lbGroups {
			lbGroupsForNetwork = append(lbGroupsForNetwork, netInfo.GetNetworkScopedLoadBalancerGroupName(lbGroup))
		}
		externalIDs = getExternalIDsForNetwork(netInfo.GetNetworkName())
	}

	lr := &nbdb.LogicalRouter{
		UUID:              routerName,
		Name:              routerName,
		LoadBalancerGroup: lbGroups,
		ExternalIDs:       externalIDs,
	}

	if len(namespacedServiceNames) > 0 {
		lr.LoadBalancer = namespacedServiceNames
	}

	return lr
}

func nodeSwitchName(nodeName string) string {
	return nodeSwitchNameForNetwork(nodeName, &util.DefaultNetInfo{})
}

func nodeSwitchNameForNetwork(nodeName string, netInfo util.NetInfo) string {
	return netInfo.GetNetworkScopedSwitchName(fmt.Sprintf("switch-%s", nodeName))
}

func nodeGWRouterName(nodeName string) string {
	return nodeGWRouterNameForNetwork(nodeName, &util.DefaultNetInfo{})
}

func nodeGWRouterNameForNetwork(nodeName string, netInfo util.NetInfo) string {
	return netInfo.GetNetworkScopedGWRouterName(fmt.Sprintf("gr-%s", nodeName))
}

func lbGroup(name string, namespacedServiceNames ...string) *nbdb.LoadBalancerGroup {
	return lbGroupForNetwork(name, &util.DefaultNetInfo{}, namespacedServiceNames...)
}

func lbGroupForNetwork(name string, netInfo util.NetInfo, namespacedServiceNames ...string) *nbdb.LoadBalancerGroup {
	LBGroupName := netInfo.GetNetworkScopedLoadBalancerGroupName(name)
	lbg := &nbdb.LoadBalancerGroup{
		UUID: LBGroupName,
		Name: LBGroupName,
	}
	if len(namespacedServiceNames) > 0 {
		lbg.LoadBalancer = namespacedServiceNames
	}
	return lbg
}

func namespacedServiceName(ns string, name string) string {
	return fmt.Sprintf("%s/%s", ns, name)
}

func clusterWideTCPServiceLoadBalancerName(ns string, serviceName string) string {
	return clusterWideTCPServiceLoadBalancerNameForNetwork(ns, serviceName, &util.DefaultNetInfo{})
}

func clusterWideTCPServiceLoadBalancerNameForNetwork(ns string, serviceName string, netInfo util.NetInfo) string {
	baseName := fmt.Sprintf("Service_%s_TCP_cluster", namespacedServiceName(ns, serviceName))
	return netInfo.GetNetworkScopedLoadBalancerName(baseName)
}

func nodeSwitchRouterLoadBalancerNameForNetwork(nodeName string, serviceNamespace string, serviceName string, netInfo util.NetInfo) string {
	baseName := fmt.Sprintf(
		"Service_%s/%s_TCP_node_router+switch_%s",
		serviceNamespace,
		serviceName,
		nodeName)
	return netInfo.GetNetworkScopedLoadBalancerName(baseName)
}

func nodeSwitchTemplateLoadBalancerNameForNetwork(serviceNamespace string, serviceName string, addressFamily v1.IPFamily, netInfo util.NetInfo) string {
	baseName := fmt.Sprintf(
		"Service_%s/%s_TCP_node_switch_template_%s",
		serviceNamespace,
		serviceName,
		addressFamily)
	return netInfo.GetNetworkScopedLoadBalancerName(baseName)
}

func nodeRouterTemplateLoadBalancerNameForNetwork(serviceNamespace string, serviceName string, addressFamily v1.IPFamily, netInfo util.NetInfo) string {
	baseName := fmt.Sprintf(
		"Service_%s/%s_TCP_node_router_template_%s",
		serviceNamespace,
		serviceName,
		addressFamily)
	return netInfo.GetNetworkScopedLoadBalancerName(baseName)
}

func nodeMergedTemplateLoadBalancerName(serviceNamespace string, serviceName string, addressFamily v1.IPFamily) string {
	return nodeMergedTemplateLoadBalancerNameForNetwork(serviceNamespace, serviceName, addressFamily, &util.DefaultNetInfo{})
}

func nodeMergedTemplateLoadBalancerNameForNetwork(serviceNamespace string, serviceName string, addressFamily v1.IPFamily, netInfo util.NetInfo) string {
	baseName := fmt.Sprintf(
		"Service_%s/%s_TCP_node_switch_template_%s_merged",
		serviceNamespace,
		serviceName,
		addressFamily)
	return netInfo.GetNetworkScopedLoadBalancerName(baseName)
}

func servicesOptions() map[string]string {
	return map[string]string{
		"event":              "false",
		"reject":             "true",
		"skip_snat":          "false",
		"neighbor_responder": "none",
		"hairpin_snat_ip":    "169.254.169.5 fd69::5",
	}
}

func servicesOptionsWithAffinityTimeout() map[string]string {
	options := servicesOptions()
	options["affinity_timeout"] = "10800"
	return options
}

func templateServicesOptions() map[string]string {
	// Template LBs need "options:template=true" and "options:address-family" set.
	opts := servicesOptions()
	opts["template"] = "true"
	opts["address-family"] = "ipv4"
	return opts
}

func templateServicesOptionsV6() map[string]string {
	// Template LBs need "options:template=true" and "options:address-family" set.
	opts := servicesOptions()
	opts["template"] = "true"
	opts["address-family"] = "ipv6"
	return opts
}

func tcpGatewayRouterExternalIDs() map[string]string {
	return map[string]string{
		"TCP_lb_gateway_router": "",
	}
}

func getExternalIDsForNetwork(network string) map[string]string {
	if network == types.DefaultNetworkName {
		return map[string]string{}
	}

	return map[string]string{
		types.NetworkRoleExternalID: types.NetworkRolePrimary,
		types.NetworkExternalID:     network,
	}
}

func loadBalancerExternalIDs(namespacedServiceName string) map[string]string {
	return loadBalancerExternalIDsForNetwork(namespacedServiceName, types.DefaultNetworkName)
}

func loadBalancerExternalIDsForNetwork(namespacedServiceName string, network string) map[string]string {
	externalIDs := map[string]string{
		types.LoadBalancerKindExternalID:  "Service",
		types.LoadBalancerOwnerExternalID: namespacedServiceName,
	}
	maps.Copy(externalIDs, getExternalIDsForNetwork(network))
	return externalIDs

}

func nodeIPTemplate(node *nodeInfo) *nbdb.ChassisTemplateVar {
	return &nbdb.ChassisTemplateVar{
		UUID:    node.chassisID,
		Chassis: node.chassisID,
		Variables: map[string]string{
			makeLBNodeIPTemplateNamePrefix(v1.IPv4Protocol) + "0": node.hostAddresses[0].String(),
		},
	}
}

func nodeMergedTemplateLoadBalancer(nodePort int32, serviceName string, serviceNamespace string, outputPort int32, endpointIPs ...string) *nbdb.LoadBalancer {
	return nodeMergedTemplateLoadBalancerForNetwork(nodePort, serviceName, serviceNamespace, outputPort, &util.DefaultNetInfo{}, endpointIPs...)
}

func nodeMergedTemplateLoadBalancerForNetwork(nodePort int32, serviceName string, serviceNamespace string, outputPort int32, netInfo util.NetInfo, endpointIPs ...string) *nbdb.LoadBalancer {
	nodeTemplateIP := makeTemplate(makeLBNodeIPTemplateNamePrefix(v1.IPv4Protocol) + "0")
	return &nbdb.LoadBalancer{
		UUID:     nodeMergedTemplateLoadBalancerNameForNetwork(serviceNamespace, serviceName, v1.IPv4Protocol, netInfo),
		Name:     nodeMergedTemplateLoadBalancerNameForNetwork(serviceNamespace, serviceName, v1.IPv4Protocol, netInfo),
		Options:  templateServicesOptions(),
		Protocol: &nbdb.LoadBalancerProtocolTCP,
		Vips: map[string]string{
			IPAndPort(refTemplate(nodeTemplateIP.Name), nodePort): formatEndpoints(outputPort, endpointIPs...),
		},
		ExternalIDs: loadBalancerExternalIDsForNetwork(namespacedServiceName(serviceNamespace, serviceName), netInfo.GetNetworkName()),
	}
}

func refTemplate(template string) string {
	return "^" + template
}

func formatEndpoints(outputPort int32, ips ...string) string {
	var endpoints []string
	for _, ip := range ips {
		endpoints = append(endpoints, IPAndPort(ip, outputPort))
	}
	return strings.Join(endpoints, ",")
}

func IPAndPort(ip string, port int32) string {
	ipStr := ip
	if utilnet.IsIPv6String(ip) {
		ipStr = "[" + ip + "]"
	}

	return fmt.Sprintf("%s:%d", ipStr, port)
}

func getNodeInfo(nodeName string, nodeIPsV4 []string, nodeIPsV6 []string) *nodeInfo {
	var gwAddresses []net.IP
	ips := []net.IP{}

	if len(nodeIPsV4) > 0 {
		gwAddresses = append(gwAddresses, net.ParseIP(nodeIPsV4[0]))
		for _, ip := range nodeIPsV4 {
			ips = append(ips, net.ParseIP(ip))
		}
	}
	if len(nodeIPsV6) > 0 {
		gwAddresses = append(gwAddresses, net.ParseIP(nodeIPsV6[0]))
		for _, ip := range nodeIPsV6 {
			ips = append(ips, net.ParseIP(ip))
		}
	}

	return &nodeInfo{
		name:               nodeName,
		l3gatewayAddresses: gwAddresses,
		hostAddresses:      ips,
		gatewayRouterName:  nodeGWRouterName(nodeName),
		switchName:         nodeSwitchName(nodeName),
		chassisID:          nodeName,
		zone:               types.OvnDefaultZone,
	}
}

func temporarilyEnableGomegaMaxLengthFormat() {
	format.MaxLength = 0
}

func restoreGomegaMaxLengthFormat(originalLength int) {
	format.MaxLength = originalLength
}

func createTestNBGlobal(nbClient libovsdbclient.Client, zone string) error {
	nbGlobal := &nbdb.NBGlobal{Name: zone}
	ops, err := nbClient.Create(nbGlobal)
	if err != nil {
		return err
	}

	_, err = nbClient.Transact(context.Background(), ops...)
	if err != nil {
		return err
	}

	return nil
}

func deleteTestNBGlobal(nbClient libovsdbclient.Client, zone string) error {
	p := func(nbGlobal *nbdb.NBGlobal) bool {
		return true
	}

	ops, err := nbClient.WhereCache(p).Delete()
	if err != nil {
		return err
	}

	_, err = nbClient.Transact(context.Background(), ops...)
	if err != nil {
		return err
	}

	return nil
}
