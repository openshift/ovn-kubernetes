package node

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	kapi "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/containernetworking/plugins/pkg/ip"
	honode "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/controllers/upgrade"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/healthcheck"
	retry "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/util/errors"
)

type CommonNodeNetworkControllerInfo struct {
	client       clientset.Interface
	Kube         kube.Interface
	watchFactory factory.NodeWatchFactory
	recorder     record.EventRecorder
	name         string

	// atomic integer value to indicate if PortBinding.up is supported
	atomicOvnUpEnabled int32
}

// BaseNodeNetworkController structure per-network fields and network specific configuration
type BaseNodeNetworkController struct {
	CommonNodeNetworkControllerInfo
	// per controller nad/netconf name information
	util.NetInfo
	util.NetConfInfo

	// stopChan and WaitGroup per controller
	stopChan chan struct{}
	wg       *sync.WaitGroup
}

func newCommonNodeNetworkControllerInfo(kubeClient clientset.Interface, kube kube.Interface,
	wf factory.NodeWatchFactory, eventRecorder record.EventRecorder, name string,
	isOvnUpEnabled bool) *CommonNodeNetworkControllerInfo {
	var atomicOvnUpEnabled int32
	if isOvnUpEnabled {
		atomicOvnUpEnabled = 1
	}

	return &CommonNodeNetworkControllerInfo{
		client:             kubeClient,
		Kube:               kube,
		watchFactory:       wf,
		name:               name,
		recorder:           eventRecorder,
		atomicOvnUpEnabled: atomicOvnUpEnabled,
	}
}

// NewCommonNodeNetworkControllerInfo creates and returns the base node network controller info
func NewCommonNodeNetworkControllerInfo(kubeClient clientset.Interface, wf factory.NodeWatchFactory,
	eventRecorder record.EventRecorder, name string, isOvnUpEnabled bool) *CommonNodeNetworkControllerInfo {
	return newCommonNodeNetworkControllerInfo(kubeClient, &kube.Kube{KClient: kubeClient}, wf, eventRecorder, name, isOvnUpEnabled)
}

// DefaultNodeNetworkController is the object holder for utilities meant for node management of default network
type DefaultNodeNetworkController struct {
	BaseNodeNetworkController

	gateway Gateway

	// Node healthcheck server for cloud load balancers
	healthzServer *proxierHealthUpdater

	// retry framework for namespaces, used for the removal of stale conntrack entries for external gateways
	retryNamespaces *retry.RetryFramework
	// retry framework for endpoint slices, used for the removal of stale conntrack entries for services
	retryEndpointSlices *retry.RetryFramework
}

func newDefaultNodeNetworkController(cnnci *CommonNodeNetworkControllerInfo, stopChan chan struct{},
	wg *sync.WaitGroup) *DefaultNodeNetworkController {
	return &DefaultNodeNetworkController{
		BaseNodeNetworkController: BaseNodeNetworkController{
			CommonNodeNetworkControllerInfo: *cnnci,
			NetConfInfo:                     &util.DefaultNetConfInfo{},
			NetInfo:                         &util.DefaultNetInfo{},
			stopChan:                        stopChan,
			wg:                              wg,
		},
	}
}

// NewDefaultNodeNetworkController creates a new network controller for node management of the default network
func NewDefaultNodeNetworkController(cnnci *CommonNodeNetworkControllerInfo) (*DefaultNodeNetworkController, error) {
	stopChan := make(chan struct{})
	wg := &sync.WaitGroup{}
	nc := newDefaultNodeNetworkController(cnnci, stopChan, wg)

	if len(config.Kubernetes.HealthzBindAddress) != 0 {
		klog.Infof("Enable node proxy healthz server on %s", config.Kubernetes.HealthzBindAddress)
		var err error
		nc.healthzServer, err = newNodeProxyHealthzServer(
			nc.name, config.Kubernetes.HealthzBindAddress, nc.recorder, nc.watchFactory)
		if err != nil {
			return nil, fmt.Errorf("could not create node proxy healthz server: %w", err)
		}
	}

	nc.initRetryFrameworkForNode()
	return nc, nil
}

func (nc *DefaultNodeNetworkController) initRetryFrameworkForNode() {
	nc.retryNamespaces = nc.newRetryFrameworkNode(factory.NamespaceExGwType)
	nc.retryEndpointSlices = nc.newRetryFrameworkNode(factory.EndpointSliceForStaleConntrackRemovalType)
}

func clearOVSFlowTargets() error {
	_, _, err := util.RunOVSVsctl(
		"--",
		"clear", "bridge", "br-int", "netflow",
		"--",
		"clear", "bridge", "br-int", "sflow",
		"--",
		"clear", "bridge", "br-int", "ipfix",
	)
	if err != nil {
		return err
	}
	return nil
}

// collectorsString joins all HostPort entry into a string that is acceptable as
// target by the ovs-vsctl command. If an entry has an empty host, it uses the Node IP
func collectorsString(node *kapi.Node, targets []config.HostPort) (string, error) {
	if len(targets) == 0 {
		return "", errors.New("collector targets can't be empty")
	}
	var joined strings.Builder
	for n, v := range targets {
		if n == 0 {
			joined.WriteByte('"')
		} else {
			joined.WriteString(`","`)
		}
		var host string
		if v.Host != nil && len(*v.Host) != 0 {
			host = v.Host.String()
		} else {
			var err error
			if host, err = util.GetNodePrimaryIP(node); err != nil {
				return "", fmt.Errorf("composing flow collectors' IPs: %w", err)
			}
		}
		joined.WriteString(util.JoinHostPortInt32(host, v.Port))
	}
	joined.WriteByte('"')
	return joined.String(), nil
}

func setOVSFlowTargets(node *kapi.Node) error {
	if len(config.Monitoring.NetFlowTargets) != 0 {
		collectors, err := collectorsString(node, config.Monitoring.NetFlowTargets)
		if err != nil {
			return fmt.Errorf("error joining NetFlow targets: %w", err)
		}

		_, stderr, err := util.RunOVSVsctl(
			"--",
			"--id=@netflow",
			"create",
			"netflow",
			fmt.Sprintf("targets=[%s]", collectors),
			"active_timeout=60",
			"--",
			"set", "bridge", "br-int", "netflow=@netflow",
		)
		if err != nil {
			return fmt.Errorf("error setting NetFlow: %v\n  %q", err, stderr)
		}
	}
	if len(config.Monitoring.SFlowTargets) != 0 {
		collectors, err := collectorsString(node, config.Monitoring.SFlowTargets)
		if err != nil {
			return fmt.Errorf("error joining SFlow targets: %w", err)
		}

		_, stderr, err := util.RunOVSVsctl(
			"--",
			"--id=@sflow",
			"create",
			"sflow",
			"agent="+types.SFlowAgent,
			fmt.Sprintf("targets=[%s]", collectors),
			"--",
			"set", "bridge", "br-int", "sflow=@sflow",
		)
		if err != nil {
			return fmt.Errorf("error setting SFlow: %v\n  %q", err, stderr)
		}
	}
	if len(config.Monitoring.IPFIXTargets) != 0 {
		collectors, err := collectorsString(node, config.Monitoring.IPFIXTargets)
		if err != nil {
			return fmt.Errorf("error joining IPFIX targets: %w", err)
		}

		args := []string{
			"--",
			"--id=@ipfix",
			"create",
			"ipfix",
			fmt.Sprintf("targets=[%s]", collectors),
			fmt.Sprintf("cache_active_timeout=%d", config.IPFIX.CacheActiveTimeout),
		}
		if config.IPFIX.CacheMaxFlows != 0 {
			args = append(args, fmt.Sprintf("cache_max_flows=%d", config.IPFIX.CacheMaxFlows))
		}
		if config.IPFIX.Sampling != 0 {
			args = append(args, fmt.Sprintf("sampling=%d", config.IPFIX.Sampling))
		}
		args = append(args, "--", "set", "bridge", "br-int", "ipfix=@ipfix")
		_, stderr, err := util.RunOVSVsctl(args...)
		if err != nil {
			return fmt.Errorf("error setting IPFIX: %v\n  %q", err, stderr)
		}
	}
	return nil
}

func setupOVNNode(node *kapi.Node) error {
	var err error

	encapIP := config.Default.EncapIP
	if encapIP == "" {
		encapIP, err = util.GetNodePrimaryIP(node)
		if err != nil {
			return fmt.Errorf("failed to obtain local IP from node %q: %v", node.Name, err)
		}
		config.Default.EncapIP = encapIP
	} else {
		if ip := net.ParseIP(encapIP); ip == nil {
			return fmt.Errorf("invalid encapsulation IP provided %q", encapIP)
		}
	}

	setExternalIdsCmd := []string{
		"set",
		"Open_vSwitch",
		".",
		fmt.Sprintf("external_ids:ovn-encap-type=%s", config.Default.EncapType),
		fmt.Sprintf("external_ids:ovn-encap-ip=%s", encapIP),
		fmt.Sprintf("external_ids:ovn-remote-probe-interval=%d",
			config.Default.InactivityProbe),
		fmt.Sprintf("external_ids:ovn-openflow-probe-interval=%d",
			config.Default.OpenFlowProbe),
		// bundle-idle-timeout default value is 10s, it should be set
		// as high as the ovn-openflow-probe-interval to allow ovn-controller
		// to finish computation specially with complex acl configuration with port range.
		fmt.Sprintf("other_config:bundle-idle-timeout=%d",
			config.Default.OpenFlowProbe),
		fmt.Sprintf("external_ids:hostname=\"%s\"", node.Name),
		fmt.Sprintf("external_ids:ovn-monitor-all=%t", config.Default.MonitorAll),
		fmt.Sprintf("external_ids:ovn-ofctrl-wait-before-clear=%d", config.Default.OfctrlWaitBeforeClear),
		fmt.Sprintf("external_ids:ovn-enable-lflow-cache=%t", config.Default.LFlowCacheEnable),
	}

	if config.Default.LFlowCacheLimit > 0 {
		setExternalIdsCmd = append(setExternalIdsCmd,
			fmt.Sprintf("external_ids:ovn-limit-lflow-cache=%d", config.Default.LFlowCacheLimit),
		)
	}

	if config.Default.LFlowCacheLimitKb > 0 {
		setExternalIdsCmd = append(setExternalIdsCmd,
			fmt.Sprintf("external_ids:ovn-memlimit-lflow-cache-kb=%d", config.Default.LFlowCacheLimitKb),
		)
	}

	_, stderr, err := util.RunOVSVsctl(setExternalIdsCmd...)
	if err != nil {
		return fmt.Errorf("error setting OVS external IDs: %v\n  %q", err, stderr)
	}
	// If EncapPort is not the default tell sbdb to use specified port.
	if config.Default.EncapPort != config.DefaultEncapPort {
		systemID, err := util.GetNodeChassisID()
		if err != nil {
			return err
		}
		uuid, _, err := util.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "Encap",
			fmt.Sprintf("chassis_name=%s", systemID))
		if err != nil {
			return err
		}
		if len(uuid) == 0 {
			return fmt.Errorf("unable to find encap uuid to set geneve port for chassis %s", systemID)
		}
		_, stderr, errSet := util.RunOVNSbctl("set", "encap", uuid,
			fmt.Sprintf("options:dst_port=%d", config.Default.EncapPort),
		)
		if errSet != nil {
			return fmt.Errorf("error setting OVS encap-port: %v\n  %q", errSet, stderr)
		}
	}

	// clear stale ovs flow targets if needed
	err = clearOVSFlowTargets()
	if err != nil {
		return fmt.Errorf("error clearing stale ovs flow targets: %q", err)
	}
	// set new ovs flow targets if needed
	err = setOVSFlowTargets(node)
	if err != nil {
		return fmt.Errorf("error setting ovs flow targets: %q", err)
	}

	return nil
}

func isOVNControllerReady() (bool, error) {
	// check node's connection status
	runDir := util.GetOvnRunDir()
	pid, err := ioutil.ReadFile(runDir + "ovn-controller.pid")
	if err != nil {
		return false, fmt.Errorf("unknown pid for ovn-controller process: %v", err)
	}
	ctlFile := runDir + fmt.Sprintf("ovn-controller.%s.ctl", strings.TrimSuffix(string(pid), "\n"))
	ret, _, err := util.RunOVSAppctl("-t", ctlFile, "connection-status")
	if err != nil {
		return false, fmt.Errorf("could not get connection status: %w", err)
	}
	klog.Infof("Node connection status = %s", ret)
	if ret != "connected" {
		return false, nil
	}

	// check whether br-int exists on node
	_, _, err = util.RunOVSVsctl("--", "br-exists", "br-int")
	if err != nil {
		return false, nil
	}

	// check by dumping br-int flow entries
	stdout, _, err := util.RunOVSOfctl("dump-aggregate", "br-int")
	if err != nil {
		klog.V(5).Infof("Error dumping aggregate flows: %v", err)
		return false, nil
	}
	hasFlowCountZero := strings.Contains(stdout, "flow_count=0")
	if hasFlowCountZero {
		klog.V(5).Info("Got a flow count of 0 when dumping flows for node")
		return false, nil
	}

	return true, nil
}

type managementPortEntry struct {
	port   ManagementPort
	config *managementPortConfig
}

func createNodeManagementPorts(name string, nodeAnnotator kube.Annotator, waiter *startupWaiter,
	subnets []*net.IPNet) ([]managementPortEntry, *managementPortConfig, error) {
	// If netdevice name is not provided in the full mode then management port backed by OVS internal port.
	// If it is provided then it is backed by VF or SF and need to determine its representor name to plug
	// into OVS integrational bridge
	if config.OvnKubeNode.Mode == types.NodeModeFull && config.OvnKubeNode.MgmtPortNetdev != "" {
		deviceID, err := util.GetDeviceIDFromNetdevice(config.OvnKubeNode.MgmtPortNetdev)
		if err != nil {
			// Device might had been already renamed to types.K8sMgmtIntfName
			config.OvnKubeNode.MgmtPortNetdev = types.K8sMgmtIntfName
			if deviceID, err = util.GetDeviceIDFromNetdevice(config.OvnKubeNode.MgmtPortNetdev); err != nil {
				return nil, nil, fmt.Errorf("failed to get device id for %s or %s: %v",
					config.OvnKubeNode.MgmtPortNetdev, types.K8sMgmtIntfName, err)
			}
		}
		rep, err := util.GetFunctionRepresentorName(deviceID)
		if err != nil {
			return nil, nil, err
		}
		config.OvnKubeNode.MgmtPortRepresentor = rep
	}
	ports := NewManagementPorts(name, subnets)

	var mgmtPortConfig *managementPortConfig
	mgmtPorts := make([]managementPortEntry, 0)
	for _, port := range ports {
		config, err := port.Create(nodeAnnotator, waiter)
		if err != nil {
			return nil, nil, err
		}
		mgmtPorts = append(mgmtPorts, managementPortEntry{port: port, config: config})
		// Save this management port config for later usage.
		// Since only one OVS internal port / Representor config may exist it is fine just to overwrite it
		if _, ok := port.(*managementPortNetdev); !ok {
			mgmtPortConfig = config
		}
	}

	return mgmtPorts, mgmtPortConfig, nil
}

// Start learns the subnets assigned to it by the master controller
// and calls the SetupNode script which establishes the logical switch
func (nc *DefaultNodeNetworkController) Start(ctx context.Context) error {
	klog.Infof("Starting the default node network controller")

	var err error
	var node *kapi.Node
	var subnets []*net.IPNet
	var cniServer *cni.Server

	// Setting debug log level during node bring up to expose bring up process.
	// Log level is returned to configured value when bring up is complete.
	var level klog.Level
	if err := level.Set("5"); err != nil {
		klog.Errorf("Setting klog \"loglevel\" to 5 failed, err: %v", err)
	}

	if node, err = nc.Kube.GetNode(nc.name); err != nil {
		return fmt.Errorf("error retrieving node %s: %v", nc.name, err)
	}

	nodeAddrStr, err := util.GetNodePrimaryIP(node)
	if err != nil {
		return err
	}
	nodeAddr := net.ParseIP(nodeAddrStr)
	if nodeAddr == nil {
		return fmt.Errorf("failed to parse kubernetes node IP address. %v", err)
	}

	if config.OvnKubeNode.Mode != types.NodeModeDPUHost {
		for _, auth := range []config.OvnAuthConfig{config.OvnNorth, config.OvnSouth} {
			if err := auth.SetDBAuth(); err != nil {
				return err
			}
		}

		err = setupOVNNode(node)
		if err != nil {
			return err
		}
	}

	// First wait for the node logical switch to be created by the Master, timeout is 300s.
	err = wait.PollImmediate(500*time.Millisecond, 300*time.Second, func() (bool, error) {
		if node, err = nc.Kube.GetNode(nc.name); err != nil {
			klog.Infof("Waiting to retrieve node %s: %v", nc.name, err)
			return false, nil
		}
		subnets, err = util.ParseNodeHostSubnetAnnotation(node, types.DefaultNetworkName)
		if err != nil {
			klog.Infof("Waiting for node %s to start, no annotation found on node for subnet: %v", nc.name, err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for node's: %q logical switch: %v", nc.name, err)
	}
	klog.Infof("Node %s ready for ovn initialization with subnet %s", nc.name, util.JoinIPNets(subnets, ","))

	// Create CNI Server
	isOvnUpEnabled := atomic.LoadInt32(&nc.atomicOvnUpEnabled) > 0
	if config.OvnKubeNode.Mode != types.NodeModeDPU {
		kclient, ok := nc.Kube.(*kube.Kube)
		if !ok {
			return fmt.Errorf("cannot get kubeclient for starting CNI server")
		}
		cniServer, err = cni.NewCNIServer(isOvnUpEnabled, nc.watchFactory, kclient.KClient)
		if err != nil {
			return err
		}
	}

	nodeAnnotator := kube.NewNodeAnnotator(nc.Kube, node.Name)
	waiter := newStartupWaiter()

	// Setup management ports
	mgmtPorts, mgmtPortConfig, err := createNodeManagementPorts(nc.name, nodeAnnotator, waiter, subnets)
	if err != nil {
		return err
	}

	// Initialize gateway
	if config.OvnKubeNode.Mode == types.NodeModeDPUHost {
		err = nc.initGatewayDPUHost(nodeAddr)
		if err != nil {
			return err
		}
	} else {
		// Initialize gateway for OVS internal port or representor management port
		if err := nc.initGateway(subnets, nodeAnnotator, waiter, mgmtPortConfig, nodeAddr); err != nil {
			return err
		}
	}

	if err := nodeAnnotator.Run(); err != nil {
		return fmt.Errorf("failed to set node %s annotations: %v", nc.name, err)
	}

	// Wait for management port and gateway resources to be created by the master
	klog.Infof("Waiting for gateway and management port readiness...")
	start := time.Now()
	if err := waiter.Wait(); err != nil {
		return err
	}
	nc.gateway.Start()
	klog.Infof("Gateway and management port readiness took %v", time.Since(start))

	// Note(adrianc): DPU deployments are expected to support the new shared gateway changes, upgrade flow
	// is not needed. Future upgrade flows will need to take DPUs into account.
	if config.OvnKubeNode.Mode != types.NodeModeDPUHost {
		// Upgrade for Node. If we upgrade workers before masters, then we need to keep service routing via
		// mgmt port until masters have been updated and modified OVN config. Run a goroutine to handle this case
		upgradeController := upgrade.NewController(nc.client, nc.watchFactory)
		initialTopoVersion, err := upgradeController.GetTopologyVersion(ctx)
		if err != nil {
			return fmt.Errorf("failed to get initial topology version: %w", err)
		}
		klog.Infof("Current control-plane topology version is %d", initialTopoVersion)

		bridgeName := ""
		if config.OvnKubeNode.Mode == types.NodeModeFull {
			bridgeName = nc.gateway.GetGatewayBridgeIface()

			needLegacySvcRoute := true
			if (initialTopoVersion >= types.OvnHostToSvcOFTopoVersion && config.GatewayModeShared == config.Gateway.Mode) ||
				(initialTopoVersion >= types.OvnRoutingViaHostTopoVersion) {
				// Configure route for svc towards shared gw bridge
				// Have to have the route to bridge for multi-NIC mode, where the default gateway may go to a non-OVS interface
				if err := configureSvcRouteViaBridge(bridgeName); err != nil {
					return err
				}
				needLegacySvcRoute = false
			}

			// Determine if we need to run upgrade checks
			if initialTopoVersion != types.OvnCurrentTopologyVersion {
				if needLegacySvcRoute {
					klog.Info("System may be upgrading, falling back to legacy K8S Service via management port")
					// add back legacy route for service via management port
					link, err := util.LinkSetUp(types.K8sMgmtIntfName)
					if err != nil {
						return fmt.Errorf("unable to get link for %s, error: %v", types.K8sMgmtIntfName, err)
					}
					var gwIP net.IP
					for _, subnet := range config.Kubernetes.ServiceCIDRs {
						if utilnet.IsIPv4CIDR(subnet) {
							gwIP = mgmtPortConfig.ipv4.gwIP
						} else {
							gwIP = mgmtPortConfig.ipv6.gwIP
						}
						err := util.LinkRoutesApply(link, gwIP, []*net.IPNet{subnet}, config.Default.RoutableMTU, nil)
						if err != nil {
							return fmt.Errorf("unable to add legacy route for services via mp0, error: %v", err)
						}
					}
				}
			}
		}

		// need to run upgrade controller
		go func() {
			if err := upgradeController.WaitForTopologyVersion(ctx, types.OvnCurrentTopologyVersion, 30*time.Minute); err != nil {
				klog.Fatalf("Error while waiting for Topology Version to be updated: %v", err)
			}
			// upgrade complete now see what needs upgrading
			if config.OvnKubeNode.Mode == types.NodeModeFull {
				// migrate service route from ovn-k8s-mp0 to shared gw bridge
				if (initialTopoVersion < types.OvnHostToSvcOFTopoVersion && config.GatewayModeShared == config.Gateway.Mode) ||
					(initialTopoVersion < types.OvnRoutingViaHostTopoVersion) {
					if err := upgradeServiceRoute(bridgeName); err != nil {
						klog.Fatalf("Failed to upgrade service route for node, error: %v", err)
					}
				}
			}

			// ensure CNI support for port binding built into OVN, as masters have been upgraded
			if initialTopoVersion < types.OvnPortBindingTopoVersion && !isOvnUpEnabled && !config.OvnKubeNode.DisableOVNIfaceIdVer {
				isOvnUpEnabled, err := util.GetOVNIfUpCheckMode()
				if err != nil {
					klog.Errorf("%v", err)
				} else if isOvnUpEnabled {
					klog.Infof("Detected support for port binding with external IDs")
					if cniServer != nil {
						cniServer.EnableOVNPortUpSupport()
					}
					atomic.StoreInt32(&nc.atomicOvnUpEnabled, 1)
				}
			}
		}()
	}

	if config.HybridOverlay.Enabled {
		// Not supported with DPUs, enforced in config
		// TODO(adrianc): Revisit above comment
		nodeController, err := honode.NewNode(
			nc.Kube,
			nc.name,
			nc.watchFactory.NodeInformer(),
			nc.watchFactory.LocalPodInformer(),
			informer.NewDefaultEventHandler,
		)
		if err != nil {
			return err
		}
		nc.wg.Add(1)
		go func() {
			defer nc.wg.Done()
			nodeController.Run(nc.stopChan)
		}()
	} else {
		// attempt to cleanup the possibly stale bridge
		_, stderr, err := util.RunOVSVsctl("--if-exists", "del-br", "br-ext")
		if err != nil {
			klog.Errorf("Deletion of bridge br-ext failed: %v (%v)", err, stderr)
		}
		_, stderr, err = util.RunOVSVsctl("--if-exists", "del-port", "br-int", "int")
		if err != nil {
			klog.Errorf("Deletion of port int on  br-int failed: %v (%v)", err, stderr)
		}
	}

	if err := level.Set(strconv.Itoa(config.Logging.Level)); err != nil {
		klog.Errorf("Reset of initial klog \"loglevel\" failed, err: %v", err)
	}

	// start management ports health check
	for _, mgmtPort := range mgmtPorts {
		mgmtPort.port.CheckManagementPortHealth(mgmtPort.config, nc.stopChan)
		// Start the health checking server used by egressip, if EgressIPNodeHealthCheckPort is specified
		if err := nc.startEgressIPHealthCheckingServer(mgmtPort); err != nil {
			return err
		}
	}

	if config.OvnKubeNode.Mode != types.NodeModeDPUHost {
		util.SetARPTimeout()
		err := nc.WatchNamespaces()
		if err != nil {
			return fmt.Errorf("failed to watch namespaces: %w", err)
		}
		// every minute cleanup stale conntrack entries if any
		go wait.Until(func() {
			nc.checkAndDeleteStaleConntrackEntries()
		}, time.Minute*1, nc.stopChan)
		err = nc.WatchEndpointSlices()
		if err != nil {
			return fmt.Errorf("failed to watch endpointSlices: %w", err)
		}
	}

	if nc.healthzServer != nil {
		nc.healthzServer.Start(nc.stopChan, nc.wg)
	}

	if config.OvnKubeNode.Mode == types.NodeModeDPU {
		if err := nc.watchPodsDPU(); err != nil {
			return err
		}
	} else {
		// start the cni server
		if err := cniServer.Start(cni.ServerRunDir); err != nil {
			return err
		}

		// Write CNI config file if it doesn't already exist
		if err := config.WriteCNIConfig(); err != nil {
			return err
		}
	}

	klog.Infof("Default node network controller initialized and ready.")
	return nil
}

// Stop gracefully stops the controller
// deleteLogicalEntities will never be true for default network
func (nc *DefaultNodeNetworkController) Stop() {
	close(nc.stopChan)
	nc.wg.Wait()
}

func (nc *DefaultNodeNetworkController) startEgressIPHealthCheckingServer(mgmtPortEntry managementPortEntry) error {
	healthCheckPort := config.OVNKubernetesFeature.EgressIPNodeHealthCheckPort
	if healthCheckPort == 0 {
		klog.Infof("Egress IP health check server skipped: no port specified")
		return nil
	}

	var nodeMgmtIP net.IP
	var mgmtPortConfig *managementPortConfig = mgmtPortEntry.config
	// Not all management port interfaces can have IP addresses assignable to them.
	if mgmtPortEntry.port.HasIpAddr() {
		if mgmtPortConfig.ipv4 != nil {
			nodeMgmtIP = mgmtPortConfig.ipv4.ifAddr.IP
		} else if mgmtPortConfig.ipv6 != nil {
			nodeMgmtIP = mgmtPortConfig.ipv6.ifAddr.IP
			// Wait for IPv6 address to become usable.
			if err := ip.SettleAddresses(mgmtPortConfig.ifName, 10); err != nil {
				return fmt.Errorf("failed to start Egress IP health checking server due to unsettled IPv6: %w on interface %s", err, mgmtPortConfig.ifName)
			}
		} else {
			return fmt.Errorf("unable to start Egress IP health checking server on interface %s: no mgmt ip", mgmtPortConfig.ifName)
		}
	} else {
		klog.Infof("Skipping interface %s as it does not have an IP address", mgmtPortConfig.ifName)
		return nil
	}

	healthServer, err := healthcheck.NewEgressIPHealthServer(nodeMgmtIP, healthCheckPort)
	if err != nil {
		return fmt.Errorf("unable to allocate health checking server: %v", err)
	}

	nc.wg.Add(1)
	go func() {
		defer nc.wg.Done()
		healthServer.Run(nc.stopChan)
	}()
	return nil
}

func (nc *DefaultNodeNetworkController) reconcileConntrackUponEndpointSliceEvents(oldEndpointSlice, newEndpointSlice *discovery.EndpointSlice) error {
	var errors []error
	if oldEndpointSlice == nil {
		// nothing to do upon an add event
		return nil
	}
	namespacedName, err := util.ServiceNamespacedNameFromEndpointSlice(oldEndpointSlice)
	if err != nil {
		return fmt.Errorf("cannot reconcile conntrack: %v", err)
	}
	svc, err := nc.watchFactory.GetService(namespacedName.Namespace, namespacedName.Name)
	if err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("error while retrieving service for endpointslice %s/%s when reconciling conntrack: %v",
			newEndpointSlice.Namespace, newEndpointSlice.Name, err)
	}
	for _, oldPort := range oldEndpointSlice.Ports {
		if *oldPort.Protocol != kapi.ProtocolUDP { // flush conntrack only for UDP
			continue
		}
		for _, oldEndpoint := range oldEndpointSlice.Endpoints {
			for _, oldIP := range oldEndpoint.Addresses {
				oldIPStr := utilnet.ParseIPSloppy(oldIP).String()
				// upon an update event, remove conntrack entries for IP addresses that are no longer
				// in the endpointslice, skip otherwise
				if newEndpointSlice != nil && util.DoesEndpointSliceContainEligibleEndpoint(newEndpointSlice, oldIPStr, *oldPort.Port, *oldPort.Protocol, svc) {
					continue
				}
				// upon update and delete events, flush conntrack only for UDP
				if err := util.DeleteConntrackServicePort(oldIPStr, *oldPort.Port, *oldPort.Protocol,
					netlink.ConntrackReplyAnyIP, nil); err != nil {
					klog.Errorf("Failed to delete conntrack entry for %s: %v", oldIPStr, err)
				}
			}
		}
	}
	return apierrors.NewAggregate(errors)

}
func (nc *DefaultNodeNetworkController) WatchEndpointSlices() error {
	_, err := nc.retryEndpointSlices.WatchResource()
	return err
}

func exGatewayPodsAnnotationsChanged(oldNs, newNs *kapi.Namespace) bool {
	// In reality we only care about exgw pod deletions, however since the list of IPs is not expected to change
	// that often, let's check for *any* changes to these annotations compared to their previous state and trigger
	// the logic for checking if we need to delete any conntrack entries
	return (oldNs.Annotations[util.ExternalGatewayPodIPsAnnotation] != newNs.Annotations[util.ExternalGatewayPodIPsAnnotation]) ||
		(oldNs.Annotations[util.RoutingExternalGWsAnnotation] != newNs.Annotations[util.RoutingExternalGWsAnnotation])
}

func (nc *DefaultNodeNetworkController) checkAndDeleteStaleConntrackEntries() {
	namespaces, err := nc.watchFactory.GetNamespaces()
	if err != nil {
		klog.Errorf("Unable to get pods from informer: %v", err)
	}
	for _, namespace := range namespaces {
		_, foundRoutingExternalGWsAnnotation := namespace.Annotations[util.RoutingExternalGWsAnnotation]
		_, foundExternalGatewayPodIPsAnnotation := namespace.Annotations[util.ExternalGatewayPodIPsAnnotation]
		if foundRoutingExternalGWsAnnotation || foundExternalGatewayPodIPsAnnotation {
			pods, err := nc.watchFactory.GetPods(namespace.Name)
			if err != nil {
				klog.Warningf("Unable to get pods from informer for namespace %s: %v", namespace.Name, err)
			}
			if len(pods) > 0 || err != nil {
				// we only need to proceed if there is at least one pod in this namespace on this node
				// OR if we couldn't fetch the pods for some reason at this juncture
				_ = nc.syncConntrackForExternalGateways(namespace)
			}
		}
	}
}

func (nc *DefaultNodeNetworkController) syncConntrackForExternalGateways(newNs *kapi.Namespace) error {
	// loop through all the IPs on the annotations; ARP for their MACs and form an allowlist
	gatewayIPs := strings.Split(newNs.Annotations[util.ExternalGatewayPodIPsAnnotation], ",")
	gatewayIPs = append(gatewayIPs, strings.Split(newNs.Annotations[util.RoutingExternalGWsAnnotation], ",")...)
	var wg sync.WaitGroup
	wg.Add(len(gatewayIPs))
	validMACs := sync.Map{}
	for _, gwIP := range gatewayIPs {
		go func(gwIP string) {
			defer wg.Done()
			if len(gwIP) > 0 && !utilnet.IsIPv6String(gwIP) {
				// TODO: Add support for IPv6 external gateways
				if hwAddr, err := util.GetMACAddressFromARP(net.ParseIP(gwIP)); err != nil {
					klog.Errorf("Failed to lookup hardware address for gatewayIP %s: %v", gwIP, err)
				} else if len(hwAddr) > 0 {
					// we need to reverse the mac before passing it to the conntrack filter since OVN saves the MAC in the following format
					// +------------------------------------------------------------ +
					// | 128 ...  112 ... 96 ... 80 ... 64 ... 48 ... 32 ... 16 ... 0|
					// +------------------+-------+--------------------+-------------|
					// |                  | UNUSED|    MAC ADDRESS     |   UNUSED    |
					// +------------------+-------+--------------------+-------------+
					for i, j := 0, len(hwAddr)-1; i < j; i, j = i+1, j-1 {
						hwAddr[i], hwAddr[j] = hwAddr[j], hwAddr[i]
					}
					validMACs.Store(gwIP, []byte(hwAddr))
				}
			}
		}(gwIP)
	}
	wg.Wait()

	validNextHopMACs := [][]byte{}
	validMACs.Range(func(key interface{}, value interface{}) bool {
		validNextHopMACs = append(validNextHopMACs, value.([]byte))
		return true
	})
	// Handle corner case where there are 0 IPs on the annotations OR none of the ARPs were successful; i.e allowMACList={empty}.
	// This means we *need to* pass a label > 128 bits that will not match on any conntrack entry labels for these pods.
	// That way any remaining entries with labels having MACs set will get purged.
	if len(validNextHopMACs) == 0 {
		validNextHopMACs = append(validNextHopMACs, []byte("does-not-contain-anything"))
	}

	pods, err := nc.watchFactory.GetPods(newNs.Name)
	if err != nil {
		return fmt.Errorf("unable to get pods from informer: %v", err)
	}

	var errors []error
	for _, pod := range pods {
		pod := pod
		podIPs, err := util.GetPodIPsOfNetwork(pod, &util.DefaultNetInfo{})
		if err != nil {
			errors = append(errors, fmt.Errorf("unable to fetch IP for pod %s/%s: %v", pod.Namespace, pod.Name, err))
		}
		for _, podIP := range podIPs { // flush conntrack only for UDP
			// for this pod, we check if the conntrack entry has a label that is not in the provided allowlist of MACs
			// only caveat here is we assume egressGW served pods shouldn't have conntrack entries with other labels set
			err := util.DeleteConntrack(podIP.String(), 0, kapi.ProtocolUDP, netlink.ConntrackOrigDstIP, validNextHopMACs)
			if err != nil {
				errors = append(errors, fmt.Errorf("failed to delete conntrack entry for pod %s: %v", podIP.String(), err))
			}
		}
	}
	return apierrors.NewAggregate(errors)
}

func (nc *DefaultNodeNetworkController) WatchNamespaces() error {
	_, err := nc.retryNamespaces.WatchResource()
	return err
}

// validateVTEPInterfaceMTU checks if the MTU of the interface that has ovn-encap-ip is big
// enough to carry the `config.Default.MTU` and the Geneve header. If the MTU is not big
// enough, it will return an error
func (nc *DefaultNodeNetworkController) validateVTEPInterfaceMTU() error {
	ovnEncapIP := net.ParseIP(config.Default.EncapIP)
	if ovnEncapIP == nil {
		return fmt.Errorf("the set OVN Encap IP is invalid: (%s)", config.Default.EncapIP)
	}
	interfaceName, mtu, err := util.GetIFNameAndMTUForAddress(ovnEncapIP)
	if err != nil {
		return fmt.Errorf("could not get MTU for the interface with address %s: %w", ovnEncapIP, err)
	}

	// calc required MTU
	var requiredMTU int
	if config.Gateway.SingleNode {
		requiredMTU = config.Default.MTU
	} else {
		if config.IPv4Mode && !config.IPv6Mode {
			// we run in single-stack IPv4 only
			requiredMTU = config.Default.MTU + types.GeneveHeaderLengthIPv4
		} else {
			// we run in single-stack IPv6 or dual-stack mode
			requiredMTU = config.Default.MTU + types.GeneveHeaderLengthIPv6
		}
	}

	if mtu < requiredMTU {
		return fmt.Errorf("interface MTU (%d) is too small for specified overlay MTU (%d)", mtu, requiredMTU)
	}
	klog.V(2).Infof("MTU (%d) of network interface %s is big enough to deal with Geneve header overhead (sum %d). ",
		mtu, interfaceName, requiredMTU)
	return nil
}

func configureSvcRouteViaBridge(bridge string) error {
	return configureSvcRouteViaInterface(bridge, DummyNextHopIPs())
}

func upgradeServiceRoute(bridgeName string) error {
	klog.Info("Updating K8S Service route")
	// Flush old routes
	link, err := util.LinkSetUp(types.K8sMgmtIntfName)
	if err != nil {
		return fmt.Errorf("unable to get link: %s, error: %v", types.K8sMgmtIntfName, err)
	}
	if err := util.LinkRoutesDel(link, config.Kubernetes.ServiceCIDRs); err != nil {
		return fmt.Errorf("unable to delete routes on upgrade, error: %v", err)
	}
	// add route via OVS bridge
	if err := configureSvcRouteViaBridge(bridgeName); err != nil {
		return fmt.Errorf("unable to add svc route via OVS bridge interface, error: %v", err)
	}
	klog.Info("Successfully updated Kubernetes service route towards OVS")
	// Clean up gw0 and local ovs bridge as best effort
	if err := deleteLocalNodeAccessBridge(); err != nil {
		klog.Warningf("Error while removing Local Node Access Bridge, error: %v", err)
	}
	// Clean up gw0 related IPTable rules as best effort.
	for _, ip := range []string{types.V4NodeLocalNATSubnet, types.V6NodeLocalNATSubnet} {
		_, IPNet, err := net.ParseCIDR(ip)
		if err != nil {
			klog.Errorf("Failed to LocalGatewayNATRules: %v", err)
		}
		rules := getLocalGatewayNATRules(types.LocalnetGatewayNextHopPort, IPNet)
		if err := delIptRules(rules); err != nil {
			klog.Errorf("Failed to LocalGatewayNATRules: %v", err)
		}
	}
	return nil
}

// DummyNextHopIPs returns the fake next hops used for service traffic routing.
// It is used in:
// - br-ex, where we don't really care about the next hop GW in use as traffic is always routed to OVN
// - OVN, only when there is no default GW as it wouldn't matter since there is no external traffic
func DummyNextHopIPs() []net.IP {
	var nextHops []net.IP
	if config.IPv4Mode {
		nextHops = append(nextHops, net.ParseIP(types.V4DummyNextHopMasqueradeIP))
	}
	if config.IPv6Mode {
		nextHops = append(nextHops, net.ParseIP(types.V6DummyNextHopMasqueradeIP))
	}
	return nextHops
}
