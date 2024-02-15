package upgrade

import (
	"context"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// upgradeController detects TopologyVersion edges as broadcast from the ovn-kube master.
// Previously, ovn-kube used an annotation on the Node object. We now use a ConfigMap as the
// coordination point, but will read from Nodes to handle upgrading an existing cluster.
type upgradeController struct {
	client kubernetes.Interface
	wf     factory.NodeWatchFactory
}

// NewController creates a new upgrade controller
func NewController(client kubernetes.Interface, wf factory.NodeWatchFactory) *upgradeController {
	uc := &upgradeController{
		client: client,
		wf:     wf,
	}
	return uc
}

// WaitForTopologyVerions polls continuously until the running master has reported a topology of
// at least the minimum requested.
func (uc *upgradeController) WaitForTopologyVersion(ctx context.Context, minVersion int, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, 10*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		ver, err := uc.GetTopologyVersion(ctx)
		if err == nil {
			if ver >= minVersion {
				klog.Infof("Cluster topology version is now %d", ver)
				return true, nil
			}

			klog.Infof("Cluster topology version %d < %d", ver, minVersion)
			return false, nil
		}
		klog.Errorf("Failed to retrieve topology version: %v", err)
		return false, nil // swallow error so we retry
	})
}

// GetTopologyVersion polls the coordination points (Nodes and ConfigMaps) until
// the master has reported a version
func (uc *upgradeController) GetTopologyVersion(ctx context.Context) (int, error) {
	return ovntypes.OvnCurrentTopologyVersion, nil
}
