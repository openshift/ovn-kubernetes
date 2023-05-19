package cni

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/retry"
)

// updatePodDPUConnDetailsWithRetry update the pod annotation with the given connection details for the NAD in
// the PodRequest. If the dpuConnDetails argument is nil, delete the NAD's DPU connection details annotation instead.
func (pr *PodRequest) updatePodDPUConnDetailsWithRetry(kube kube.Interface, podLister corev1listers.PodLister, dpuConnDetails *util.DPUConnectionDetails) error {
	resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := podLister.Pods(pr.PodNamespace).Get(pr.PodName)
		if err != nil {
			return err
		}

		cpod := pod.DeepCopy()
		cpod.Annotations, err = util.MarshalPodDPUConnDetails(cpod.Annotations, dpuConnDetails, pr.nadName)
		if err != nil {
			if util.IsAnnotationAlreadySetError(err) {
				return nil
			}
			return err
		}
		return kube.UpdatePod(cpod)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update %s annotation dpuConnDetails %+v on pod %s/%s for NAD %s: %v",
			util.DPUConnectionDetailsAnnot, dpuConnDetails, pr.PodNamespace, pr.PodName, pr.nadName, resultErr)
	}
	return nil
}

func (pr *PodRequest) addDPUConnectionDetailsAnnot(k kube.Interface, podLister corev1listers.PodLister, vfNetdevName string) error {
	if pr.CNIConf.DeviceID == "" {
		return fmt.Errorf("DeviceID must be set for Pod request with DPU")
	}
	pciAddress := pr.CNIConf.DeviceID

	vfindex, err := util.GetSriovnetOps().GetVfIndexByPciAddress(pciAddress)
	if err != nil {
		return err
	}
	pfindex, err := util.GetSriovnetOps().GetPfIndexByVfPciAddress(pciAddress)
	if err != nil {
		return err
	}

	dpuConnDetails := util.DPUConnectionDetails{
		PfId:         fmt.Sprint(pfindex),
		VfId:         fmt.Sprint(vfindex),
		SandboxId:    pr.SandboxID,
		VfNetdevName: vfNetdevName,
	}

	return pr.updatePodDPUConnDetailsWithRetry(k, podLister, &dpuConnDetails)
}
