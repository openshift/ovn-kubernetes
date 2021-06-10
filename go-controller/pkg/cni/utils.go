package cni

import (
	"errors"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// PodAnnotation2PodInfo creates PodInterfaceInfo from Pod annotations and additional attributes
func PodAnnotation2PodInfo(podAnnotation map[string]string) (*PodInterfaceInfo, error) {
	podAnnotSt, err := util.UnmarshalPodAnnotation(podAnnotation)
	if err != nil {
		return nil, err
	}
	ingress, err := extractPodBandwidth(podAnnotation, Ingress)
	if err != nil && !errors.Is(err, BandwidthNotFound) {
		return nil, err
	}
	egress, err := extractPodBandwidth(podAnnotation, Egress)
	if err != nil && !errors.Is(err, BandwidthNotFound) {
		return nil, err
	}

	podInterfaceInfo := &PodInterfaceInfo{
		PodAnnotation: *podAnnotSt,
		MTU:           config.Default.MTU,
		Ingress:       ingress,
		Egress:        egress,
	}
	return podInterfaceInfo, nil
}
