package ovn

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

// ensureNetworkInfoForVM will at live migration extract the ovn pod
// annotations and original switch name from the source vm pod and copy it
// to the target vm pod so ip address follow vm during migration. This has to
// done before creating the LSP to be sure that Address field get configured
// correctly at the target VM pod LSP.
func ensureNetworkInfoForVM(watchFactory *factory.WatchFactory, kube *kube.KubeOVN, pod *corev1.Pod) error {
	if !kubevirt.IsPodLiveMigratable(pod) {
		return nil
	}
	vmNetworkInfo, err := kubevirt.FindNetworkInfo(watchFactory, pod)
	if err != nil {
		return err
	}
	resultErr := retry.RetryOnConflict(util.OvnConflictBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return err
		}

		cpod := pod.DeepCopy()
		_, ok := cpod.Labels[kubevirt.OriginalSwitchNameLabel]
		if !ok {
			cpod.Labels[kubevirt.OriginalSwitchNameLabel] = vmNetworkInfo.OriginalSwitchName
		}
		if vmNetworkInfo.Status != "" {
			cpod.Annotations[util.OvnPodAnnotationName] = vmNetworkInfo.Status
		}
		return kube.UpdatePod(cpod)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update labels and annotations on pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
	}

	// There is nothing to check
	if vmNetworkInfo.Status == "" {
		return nil
	}
	// Wait until informers cache get updated so we don't depend on conflict
	// mechanism at next pod annotations update
	return wait.ExponentialBackoff(util.OvnConflictBackoff, func() (bool, error) {
		pod, err := watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return false, err
		}
		currentNetworkInfoStatus, ok := pod.Annotations[util.OvnPodAnnotationName]
		if !ok || currentNetworkInfoStatus != vmNetworkInfo.Status {
			return false, err
		}
		originalSwitchName, ok := pod.Labels[kubevirt.OriginalSwitchNameLabel]
		if !ok || originalSwitchName != vmNetworkInfo.OriginalSwitchName {
			return false, err
		}
		return true, nil
	})
}
