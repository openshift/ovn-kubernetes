package clustermanager

import (
	"context"
	"os"
	"reflect"
	"sync"
	"time"

	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	clientset "k8s.io/client-go/kubernetes"
)

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
// It creates a default network controller for the default network.
type ClusterManager struct {
	client                      clientset.Interface
	defaultNetClusterController *defaultNetworkClusterController
	wf                          *factory.WatchFactory
	// event recorder used to post events to k8s
	recorder record.EventRecorder
}

// NewClusterManager creates a new Cluster Manager for managing the
// cluster nodes.
func NewClusterManager(ovnClient *util.OVNClientset, wf *factory.WatchFactory,
	wg *sync.WaitGroup, recorder record.EventRecorder) *ClusterManager {
	cm := &ClusterManager{
		client:                      ovnClient.KubeClient,
		defaultNetClusterController: newDefaultNetworkClusterController(ovnClient, wf),
		wf:                          wf,
		recorder:                    recorder,
	}

	return cm
}

// Start waits until this process is the leader before starting master functions
func (cm *ClusterManager) Start(nodeName string, wg *sync.WaitGroup, ctx context.Context) error {
	klog.Infof("Cluster manager Started.")
	// Set up leader election process first.
	// User lease resource lock as configmap and endpoint lock support is removed from leaderelection library.
	rl, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		config.Kubernetes.OVNConfigNamespace,
		"ovn-kubernetes-cluster-manager",
		cm.client.CoreV1(),
		cm.client.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity:      nodeName,
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
					metrics.MetriClusterManagerReadyDuration.Set(end.Seconds())
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
				if newLeaderName != nodeName {
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

	wg.Add(1)
	go func() {
		leaderElector.Run(ctx)
		klog.Infof("Stopped leader election")
		wg.Done()
	}()

	return nil
}

func (cm *ClusterManager) Stop() {
	metrics.UnRegisterClusterManagerFunctional()
	cm.defaultNetClusterController.Stop()
}

// Run starts the actual watching.
func (cm *ClusterManager) Run() error {
	metrics.RegisterClusterManagerFunctional()
	if err := cm.defaultNetClusterController.Start(); err != nil {
		return err
	}

	// Start and sync the watch factory to begin listening for events
	if err := cm.wf.Start(); err != nil {
		return err
	}

	return cm.defaultNetClusterController.Run()
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
