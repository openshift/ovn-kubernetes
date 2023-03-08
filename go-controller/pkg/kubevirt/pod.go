package kubevirt

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// PodIsLiveMigratable will return true if the pod belongs
// to kubevirt and should use the live migration features
func PodIsLiveMigratable(pod *corev1.Pod) bool {
	_, ok := pod.Annotations[kubevirtv1.AllowPodBridgeNetworkLiveMigrationAnnotation]
	return ok
}

// FindVMRelatedPods will return pods belong to the same vm annotated at pod
func FindVMRelatedPods(client *factory.WatchFactory, pod *corev1.Pod) ([]*corev1.Pod, error) {
	vmName, ok := pod.Labels[kubevirtv1.VirtualMachineNameLabel]
	if !ok {
		return []*corev1.Pod{}, nil
	}
	vmPods, err := client.GetPodsBySelector(pod.Namespace, metav1.LabelSelector{MatchLabels: map[string]string{kubevirtv1.VirtualMachineNameLabel: vmName}})
	if err != nil {
		return []*corev1.Pod{}, err
	}
	return vmPods, nil
}

// FindNetworkInfo will return the original switch name and the OVN pod
// annotation from any other pod annotated with the same VM as pod
func FindNetworkInfo(client *factory.WatchFactory, pod *corev1.Pod) (NetworkInfo, error) {
	vmPods, err := FindVMRelatedPods(client, pod)
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("failed finding related pods for pod %s/%s when looking for network info: %v", pod.Namespace, pod.Name, err)
	}
	networkInfo := NetworkInfo{
		OriginalSwitchName: pod.Spec.NodeName,
	}
	if len(vmPods) == 0 || vmPods[0].Name == pod.Name {
		return networkInfo, nil
	}
	firstVMPod := vmPods[0]
	originalSwitchName, ok := firstVMPod.Labels[OriginalSwitchNameLabel]
	if !ok {
		return networkInfo, fmt.Errorf("missing %s label at vm related pod", OriginalSwitchNameLabel)
	}
	networkInfo.OriginalSwitchName = originalSwitchName

	status, ok := firstVMPod.Annotations[util.OvnPodAnnotationName]
	if !ok {
		return networkInfo, fmt.Errorf("missing %s annotation at vm related pod", util.OvnPodAnnotationName)
	}
	networkInfo.Status = status
	return networkInfo, nil
}
