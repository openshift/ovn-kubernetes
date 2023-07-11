package pod

import (
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/ip"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/ip/subnet"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// PodAnnotationAllocator is an utility to handle allocation of the PodAnnotation to Pods.
type PodAnnotationAllocator struct {
	podLister listers.PodLister
	kube      kube.Interface

	netInfo util.NetInfo
}

func NewPodAnnotationAllocator(netInfo util.NetInfo, podLister listers.PodLister, kube kube.Interface) *PodAnnotationAllocator {
	return &PodAnnotationAllocator{
		podLister: podLister,
		kube:      kube,
		netInfo:   netInfo,
	}
}

// AllocatePodAnnotation allocates the PodAnnotation which includes IPs, a mac
// address, routes and gateways. Returns the allocated pod annotation and the
// updated pod. Returns a nil pod and the existing PodAnnotation if no updates
// are warranted to the pod.
//
// The allocation can be requested through the network selection element or
// derived from the allocator provided IPs. If the requested IPs cannot be
// honored, a new set of IPs will be allocated unless reallocateIP is set to
// false.
func (allocator *PodAnnotationAllocator) AllocatePodAnnotation(
	ipAllocator subnet.NamedAllocator,
	pod *v1.Pod,
	network *nadapi.NetworkSelectionElement,
	reallocateIP bool) (
	*v1.Pod,
	*util.PodAnnotation,
	error) {

	return allocatePodAnnotation(
		allocator.podLister,
		allocator.kube,
		ipAllocator,
		allocator.netInfo,
		pod,
		network,
		reallocateIP,
	)

}

func allocatePodAnnotation(
	podLister listers.PodLister,
	kube kube.Interface,
	ipAllocator subnet.NamedAllocator,
	netInfo util.NetInfo,
	pod *v1.Pod,
	network *nadapi.NetworkSelectionElement,
	reallocateIP bool) (
	updatedPod *v1.Pod,
	podAnnotation *util.PodAnnotation,
	err error) {

	allocateToPodWithRollback := func(pod *v1.Pod) (*v1.Pod, func(), error) {
		var rollback func()
		pod, podAnnotation, rollback, err = allocatePodAnnotationWithRollback(
			ipAllocator,
			netInfo,
			pod,
			network,
			reallocateIP)
		return pod, rollback, err
	}

	err = util.UpdatePodWithRetryOrRollback(
		podLister,
		kube,
		pod,
		allocateToPodWithRollback,
	)

	if err != nil {
		return nil, nil, err
	}

	return pod, podAnnotation, nil
}

// allocatePodAnnotationWithRollback allocates the PodAnnotation which includes
// IPs, a mac address, routes and gateways. Returns the allocated pod annotation
// and a pod with that annotation set. Returns a nil pod and the existing
// PodAnnotation if no updates are warranted to the pod.

// The allocation can be requested through the network selection element or
// derived from the allocator provided IPs. If no IP allocation is required, set
// allocateIP to false. If the requested IPs cannot be honored, a new set of IPs
// will be allocated unless reallocateIP is set to false.

// A rollback function is returned to rollback the IP allocation if there was
// any.

// This function is designed to be used in AllocateToPodWithRollbackFunc
// implementations. Use an inlined implementation if you want to extract
// information from it as a side-effect.
func allocatePodAnnotationWithRollback(
	ipAllocator subnet.NamedAllocator,
	netInfo util.NetInfo,
	pod *v1.Pod,
	network *nadapi.NetworkSelectionElement,
	reallocateIP bool) (
	updatedPod *v1.Pod,
	podAnnotation *util.PodAnnotation,
	rollback func(),
	err error) {

	nadName := types.DefaultNetworkName
	if netInfo.IsSecondary() {
		nadName = util.GetNADName(network.Namespace, network.Name)
	}
	podDesc := fmt.Sprintf("%s/%s/%s", nadName, pod.Namespace, pod.Name)

	// the IPs we allocate in this function need to be released back to the IPAM
	// pool if there is some error in any step past the point the IPs were
	// assigned via the IPAM manager. Note we are using a named return variable
	// for defer to work correctly.
	var releaseIPs []*net.IPNet
	rollback = func() {
		if len(releaseIPs) == 0 {
			return
		}
		err := ipAllocator.ReleaseIPs(releaseIPs)
		if err != nil {
			klog.Errorf("Error when releasing IPs %v: %w", util.StringSlice(releaseIPs), err)
			releaseIPs = nil
			return
		}
		klog.V(5).Infof("Released IPs %v", util.StringSlice(releaseIPs))
		releaseIPs = nil
	}
	defer func() {
		if err != nil {
			rollback()
		}
	}()

	hasIPAM := util.DoesNetworkRequireIPAM(netInfo)
	hasIPRequest := network != nil && len(network.IPRequest) > 0
	hasStaticIPRequest := hasIPRequest && !reallocateIP

	if hasIPAM && hasStaticIPRequest {
		// for now we can't tell apart already allocated IPs from IPs excluded
		// from allocation so we can't really honor static IP requests when
		// there is IPAM as we don't really know if the requested IP should not
		// be allocated or was already allocated by the same pod
		err = fmt.Errorf("cannot allocate a static IP request with IPAM for pod %s", podDesc)
		return
	}

	podAnnotation, _ = util.UnmarshalPodAnnotation(pod.Annotations, nadName)
	if podAnnotation == nil {
		podAnnotation = &util.PodAnnotation{}
	}

	// work on a tentative pod annotation based on the existing one
	tentative := &util.PodAnnotation{
		IPs: podAnnotation.IPs,
		MAC: podAnnotation.MAC,
	}

	// we need to update the annotation if it is missing IPs or MAC
	needsAnnotationUpdate := len(tentative.IPs) == 0 && (hasIPAM || hasIPRequest)
	needsAnnotationUpdate = needsAnnotationUpdate || len(tentative.MAC) == 0
	reallocateOnNonStaticIPRequest := len(tentative.IPs) == 0 && hasIPRequest && !hasStaticIPRequest

	if len(tentative.IPs) == 0 {
		if hasIPRequest {
			tentative.IPs, err = util.ParseIPNets(network.IPRequest)
			if err != nil {
				return
			}
		}
	}

	if hasIPAM {
		if len(tentative.IPs) > 0 {
			if err = ipAllocator.AllocateIPs(tentative.IPs); err != nil && !ip.IsErrAllocated(err) {
				err = fmt.Errorf("failed to ensure requested or annotated IPs %v for pod %s: %w",
					util.StringSlice(tentative.IPs), podDesc, err)
				if !reallocateOnNonStaticIPRequest {
					return
				}
				klog.Warning(err.Error())
				needsAnnotationUpdate = true
				tentative.IPs = nil
			}

			if err == nil {
				// copy the IPs that would need to be released
				releaseIPs = util.CopyIPNets(tentative.IPs)
			}

			// IPs allocated or we will allocate a new set of IPs, reset the error
			err = nil
		}

		if len(tentative.IPs) == 0 {
			tentative.IPs, err = ipAllocator.AllocateNextIPs()
			if err != nil {
				err = fmt.Errorf("failed to assign pod addresses for pod %s: %w", podDesc, err)
				return
			}

			// copy the IPs that would need to be released
			releaseIPs = util.CopyIPNets(tentative.IPs)
		}
	}

	if needsAnnotationUpdate {
		// handle mac address
		if network != nil && network.MacRequest != "" {
			tentative.MAC, err = net.ParseMAC(network.MacRequest)
		} else if len(tentative.IPs) > 0 {
			tentative.MAC = util.IPAddrToHWAddr(tentative.IPs[0].IP)
		} else {
			tentative.MAC, err = util.GenerateRandMAC()
		}
		if err != nil {
			return
		}

		// handle routes & gateways
		err = util.AddRoutesGatewayIP(netInfo, pod, tentative, network)
		if err != nil {
			return
		}

		updatedPod = pod
		updatedPod.Annotations, err = util.MarshalPodAnnotation(updatedPod.Annotations, tentative, nadName)
		podAnnotation = tentative
	}

	return
}
