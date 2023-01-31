package clustermanager

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"

	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	nad "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/network-attach-def-controller"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// ovnkubeClusterManagerLeaderMetrics object is used for the cluster manager
// leader election metrics
type ovnkubeClusterManagerLeaderMetrics struct{}

func (ovnkubeClusterManagerLeaderMetrics) On(string) {
	metrics.MetricClusterManagerLeader.Set(1)
}

func (ovnkubeClusterManagerLeaderMetrics) Off(string) {
	metrics.MetricClusterManagerLeader.Set(0)
}

type ovnkubeClusterManagerLeaderMetricsProvider struct{}

func (_ ovnkubeClusterManagerLeaderMetricsProvider) NewLeaderMetric() leaderelection.SwitchMetric {
	return ovnkubeClusterManagerLeaderMetrics{}
}

// ClusterManager structure is the object which manages the cluster nodes.
// It creates a default network controller for the default network and a
// secondary network cluster controller manager to manage the multi networks.
type ClusterManager struct {
	client                               clientset.Interface
	defaultNetClusterController          *defaultNetworkClusterController
	wf                                   *factory.WatchFactory
	wg                                   *sync.WaitGroup
	stopChan                             chan struct{}
	secondaryNetClusterControllerManager *secondaryNetworkClusterControllerManager
	// event recorder used to post events to k8s
	recorder record.EventRecorder

	// unique identity for clusterManager running on different ovnkube-cluster-manager instance,
	// used for leader election
	identity string
}

// NewClusterManager creates a new Cluster Manager for managing the
// cluster nodes.
func NewClusterManager(ovnClient *util.OVNClusterManagerClientset, wf *factory.WatchFactory,
	identity string, wg *sync.WaitGroup, recorder record.EventRecorder) *ClusterManager {
	cm := &ClusterManager{
		client:                      ovnClient.KubeClient,
		defaultNetClusterController: newDefaultNetworkClusterController(ovnClient, wf),
		wg:                          wg,
		wf:                          wf,
		stopChan:                    make(chan struct{}),
		recorder:                    recorder,
		identity:                    identity,
	}

	if config.OVNKubernetesFeature.EnableMultiNetwork {
		cm.secondaryNetClusterControllerManager = newSecondaryNetworkClusterControllerManager(ovnClient, wf, recorder)
	}
	return cm
}

// Start waits until this process is the leader before starting master functions
func (cm *ClusterManager) Start(ctx context.Context) error {
	metrics.RegisterClusterManagerBase()

	// Set up leader election process first.
	// User lease resource lock as configmap and endpoint lock support is removed from leader election library.
	rl, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		config.Kubernetes.OVNConfigNamespace,
		"ovn-kubernetes-cluster-manager",
		cm.client.CoreV1(),
		cm.client.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity:      cm.identity,
			EventRecorder: cm.recorder,
		},
	)
	if err != nil {
		return err
	}

	lec := leaderelection.LeaderElectionConfig{
		Lock:            rl,
		LeaseDuration:   time.Duration(config.ClusterMgrHA.ElectionLeaseDuration) * time.Second,
		RenewDeadline:   time.Duration(config.ClusterMgrHA.ElectionRenewDeadline) * time.Second,
		RetryPeriod:     time.Duration(config.ClusterMgrHA.ElectionRetryPeriod) * time.Second,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				klog.Infof("Won leader election; in active mode")
				// run the cluster controller to init the cluster manager
				start := time.Now()
				defer func() {
					end := time.Since(start)
					metrics.MetricClusterManagerReadyDuration.Set(end.Seconds())
				}()

				// run only on the active master node.
				if err := cm.Run(); err != nil {
					panic(err.Error())
				}
			},
			OnStoppedLeading: func() {
				// This node was leader and it lost the election.
				// Whenever the node transitions from leader to follower,
				// we need to handle the transition properly like clearing
				// the cache. It is better to exit for now.
				// kube will restart and this will become a follower.
				klog.Infof("No longer leader; exiting")
				os.Exit(0)
			},
			OnNewLeader: func(newLeaderName string) {
				if newLeaderName != cm.identity {
					klog.Infof("Lost the election to %s; in standby mode", newLeaderName)
				}
			},
		},
	}

	leaderelection.SetProvider(ovnkubeClusterManagerLeaderMetricsProvider{})
	leaderElector, err := leaderelection.NewLeaderElector(lec)
	if err != nil {
		return err
	}

	cm.wg.Add(1)
	go func() {
		leaderElector.Run(ctx)
		klog.Infof("Stopped leader election")
		cm.wg.Done()
	}()

	return nil
}

// Run starts the watch factory, inits and runs the default network cluster controller
func (cm *ClusterManager) Run() error {
	metrics.RegisterClusterManagerFunctional()
	if err := cm.defaultNetClusterController.Init(); err != nil {
		return err
	}

	if cm.secondaryNetClusterControllerManager != nil {
		if err := cm.secondaryNetClusterControllerManager.Start(); err != nil {
			return err
		}
	}

	// Start and sync the watch factory to begin listening for events
	if err := cm.wf.Start(); err != nil {
		return err
	}

	if err := cm.defaultNetClusterController.Run(); err != nil {
		return err
	}

	if cm.secondaryNetClusterControllerManager != nil {
		klog.Infof("Starting multi network attach manager")
		return cm.secondaryNetClusterControllerManager.Run(cm.stopChan)
	}

	return nil
}

func (cm *ClusterManager) Stop() {
	close(cm.stopChan)
	cm.defaultNetClusterController.Stop()

	if cm.secondaryNetClusterControllerManager != nil {
		cm.secondaryNetClusterControllerManager.Stop()
	}
}

// secondaryNetworkClusterControllerManager object manages the multi net-attach-def controllers.
// It implements networkAttachDefController.NetworkControllerManager and can be used
// by NetAttachDefinitionController to add and delete NADs.
type secondaryNetworkClusterControllerManager struct {
	// net-attach-def controller handle net-attach-def and create/delete network controllers
	nadController *nad.NetAttachDefinitionController
	client        clientset.Interface
	ovnClient     *util.OVNClusterManagerClientset
	kube          kube.Interface
	watchFactory  *factory.WatchFactory
}

func newSecondaryNetworkClusterControllerManager(ovnClient *util.OVNClusterManagerClientset,
	wf *factory.WatchFactory, recorder record.EventRecorder) *secondaryNetworkClusterControllerManager {
	klog.Infof("Creating new multi network cluster manager")
	kube := &kube.Kube{
		KClient: ovnClient.KubeClient,
	}
	sncm := &secondaryNetworkClusterControllerManager{
		ovnClient:    ovnClient,
		client:       ovnClient.KubeClient,
		kube:         kube,
		watchFactory: wf,
	}
	sncm.nadController = nad.NewNetAttachDefinitionController(
		sncm, ovnClient.NetworkAttchDefClient, recorder)
	return sncm
}

func (sncm *secondaryNetworkClusterControllerManager) Run(stopChan <-chan struct{}) error {
	klog.Infof("Starting net-attach-def controller")
	return sncm.nadController.Run(stopChan)
}

// Start starts the secondary layer3 controller, handles all events and creates all needed logical entities
func (sncm *secondaryNetworkClusterControllerManager) Start() error {
	klog.Infof("Start secondary network controller of network")
	return nil
}

func (sncm *secondaryNetworkClusterControllerManager) Stop() {
	// stops each network controller associated with net-attach-def; it is ok
	// to call GetAllControllers here as net-attach-def controller has been stopped,
	// and no more change of network controllers
	klog.Infof("Stops net-attach-def controller")
	for _, oc := range sncm.nadController.GetAllNetworkControllers() {
		oc.Stop()
	}
}

func (sncm *secondaryNetworkClusterControllerManager) NewNetworkController(nInfo util.NetInfo,
	netConfInfo util.NetConfInfo) (nad.NetworkController, error) {
	klog.Infof("New net-attach-def controller for network %s called", nInfo.GetNetworkName())
	topoType := netConfInfo.TopologyType()
	if topoType == ovntypes.Layer3Topology {
		stopChan := make(chan struct{})
		sncc := newSecondaryNetworkClusterController(sncm.ovnClient, sncm.watchFactory,
			stopChan, &sync.WaitGroup{}, nInfo, netConfInfo, nInfo.GetNetworkName())

		sncc.initRetryFramework()
		return sncc, nil
	}
	return nil, fmt.Errorf("topology type %s not supported", topoType)
}

func (sncm *secondaryNetworkClusterControllerManager) CleanupDeletedNetworks(allControllers []nad.NetworkController) error {
	// Nothing need to be done here
	return nil
}

// hasResourceAnUpdateFunc returns true if the given resource type has a dedicated update function.
// It returns false if, upon an update event on this resource type, we instead need to first delete the old
// object and then add the new one.
func hasResourceAnUpdateFunc(objType reflect.Type) bool {
	switch objType {
	case factory.NodeType:
		return true
	}
	return false
}
