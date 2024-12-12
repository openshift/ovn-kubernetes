package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/iprulemanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/vrfmanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

// SecondaryNodeNetworkController structure is the object which holds the controls for starting
// and reacting upon the watched resources (e.g. pods, endpoints) for secondary network
type SecondaryNodeNetworkController struct {
	BaseNodeNetworkController
	// pod events factory handler
	podHandler *factory.Handler
	// stores the networkID of this network
	networkID *int
	// responsible for programing gateway elements for this network
	gateway *UserDefinedNetworkGateway
}

// NewSecondaryNodeNetworkController creates a new OVN controller for creating logical network
// infrastructure and policy for the given secondary network. It supports layer3, layer2 and
// localnet topology types.
func NewSecondaryNodeNetworkController(cnnci *CommonNodeNetworkControllerInfo, netInfo util.NetInfo,
	vrfManager *vrfmanager.Controller, ruleManager *iprulemanager.Controller, defaultNetworkGateway Gateway) (*SecondaryNodeNetworkController, error) {
	snnc := &SecondaryNodeNetworkController{
		BaseNodeNetworkController: BaseNodeNetworkController{
			CommonNodeNetworkControllerInfo: *cnnci,
			NetInfo:                         netInfo,
			stopChan:                        make(chan struct{}),
			wg:                              &sync.WaitGroup{},
		},
	}
	if util.IsNetworkSegmentationSupportEnabled() && snnc.IsPrimaryNetwork() {
		node, err := snnc.watchFactory.GetNode(snnc.name)
		if err != nil {
			return nil, fmt.Errorf("error retrieving node %s while creating node network controller for network %s: %v",
				snnc.name, netInfo.GetNetworkName(), err)
		}
		networkID, err := snnc.getNetworkID()
		if err != nil {
			return nil, fmt.Errorf("error retrieving network id for network %s: %v", netInfo.GetNetworkName(), err)
		}

		snnc.gateway, err = NewUserDefinedNetworkGateway(snnc.NetInfo, networkID, node,
			snnc.watchFactory.NodeCoreInformer().Lister(), snnc.Kube, vrfManager, ruleManager, defaultNetworkGateway)
		if err != nil {
			return nil, fmt.Errorf("error creating UDN gateway for network %s: %v", netInfo.GetNetworkName(), err)
		}
	}
	return snnc, nil
}

type PerfEntry struct {
	name string
	time time.Duration
}
type CtrlPerf struct {
	sync.Mutex
	Startups      int
	Name          string
	LastStartTime time.Time
	Entries       []PerfEntry
}

func (r *CtrlPerf) AddEntry(name string, startTime time.Time) {
	r.Lock()
	defer r.Unlock()
	r.Entries = append(r.Entries, PerfEntry{
		name: fmt.Sprintf("%s[%d]", name, r.Startups),
		time: time.Since(startTime),
	})
}

func (r *CtrlPerf) String() string {
	res := fmt.Sprintf("Name: %s, LastStartTime: %s, Startups: %d", r.Name, r.LastStartTime, r.Startups)
	for _, e := range r.Entries {
		res += fmt.Sprintf(", %s:%s", e.name, e.time)
	}
	return res
}

var perfNode = make(map[string]*CtrlPerf, 100)

// Start starts the default controller; handles all events and creates all needed logical entities
func (nc *SecondaryNodeNetworkController) Start(ctx context.Context) error {
	klog.Infof("Start secondary node network controller of network %s", nc.GetNetworkName())

	var ctrlPerf *CtrlPerf
	var exists bool
	if ctrlPerf, exists = perfNode[nc.GetNetworkName()]; !exists {
		ctrlPerf = &CtrlPerf{Name: nc.GetNetworkName()}
		perfNode[nc.GetNetworkName()] = ctrlPerf
	}
	ctrlPerf.Startups += 1
	ctrlPerf.LastStartTime = time.Now()

	// enable adding ovs ports for dpu pods in both primary and secondary user defined networks
	if (config.OVNKubernetesFeature.EnableMultiNetwork || util.IsNetworkSegmentationSupportEnabled()) && config.OvnKubeNode.Mode == types.NodeModeDPU {
		handler, err := nc.watchPodsDPU()
		if err != nil {
			return err
		}
		nc.podHandler = handler
	}
	if util.IsNetworkSegmentationSupportEnabled() && nc.IsPrimaryNetwork() {
		if err := nc.gateway.AddNetwork(); err != nil {
			return fmt.Errorf("failed to add network to node gateway for network %s at node %s: %w",
				nc.GetNetworkName(), nc.name, err)
		}
		ctrlPerf.AddEntry("gateway_AddNetwork", ctrlPerf.LastStartTime)
	}
	return nil
}

// Stop gracefully stops the controller
func (nc *SecondaryNodeNetworkController) Stop() {
	klog.Infof("Node performance numbers: %s", perfNode[nc.GetNetworkName()])
	
	klog.Infof("Stop secondary node network controller of network %s", nc.GetNetworkName())
	close(nc.stopChan)
	nc.wg.Wait()

	if nc.podHandler != nil {
		nc.watchFactory.RemovePodHandler(nc.podHandler)
	}
}

// Cleanup cleans up node entities for the given secondary network
func (nc *SecondaryNodeNetworkController) Cleanup() error {
	if nc.gateway != nil {
		return nc.gateway.DelNetwork()
	}
	return nil
}

func (oc *SecondaryNodeNetworkController) getNetworkID() (int, error) {
	if oc.networkID == nil || *oc.networkID == util.InvalidID {
		oc.networkID = ptr.To(util.InvalidID)
		nodes, err := oc.watchFactory.GetNodes()
		if err != nil {
			return util.InvalidID, err
		}
		*oc.networkID, err = util.GetNetworkID(nodes, oc.NetInfo)
		if err != nil {
			return util.InvalidID, err
		}
	}
	return *oc.networkID, nil
}
