package cni

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

// wait on a certain pod annotation related condition
type podAnnotWaitCond func(podAnnotation map[string]string) bool

// isOvnReady is a wait condition for OVN master to set pod-networks annotation
func isOvnReady(podAnnotation map[string]string) bool {
	if _, ok := podAnnotation[util.OvnPodAnnotationName]; ok {
		return true
	}
	return false
}

// isSmartNICReady is a wait condition smart-NIC: wait for OVN master to set pod-networks annotation and
// ovnkube running on Smart-NIC to set connection-status pod annotation and its status is Ready
func isSmartNICReady(podAnnotation map[string]string) bool {
	if isOvnReady(podAnnotation) {
		// check Smart-NIC connection status
		status := util.SmartNICConnectionStatus{}
		if err := status.FromPodAnnotation(podAnnotation); err == nil {
			if status.Status == util.SmartNicConnectionStatusReady {
				return true
			}
		}
	}
	return false
}

// GetPodAnnotations obtains the pod annotation from the cache
func GetPodAnnotations(ctx context.Context, podLister corev1listers.PodLister, namespace, name string, annotCond podAnnotWaitCond) (map[string]string, error) {
	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("canceled waiting for annotations")
		case <-timeout:
			return nil, fmt.Errorf("timed out waiting for annotations")
		default:
			pod, err := podLister.Pods(namespace).Get(name)
			if err != nil {
				return nil, fmt.Errorf("failed to get annotations: %v", err)
			}
			annotations := pod.ObjectMeta.Annotations
			if annotCond(annotations) {
				return annotations, nil
			}
			// try again later
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func GetPodAnnotationsFallback(ctx context.Context, podLister corev1listers.PodLister, namespace, name string, annotCond podAnnotWaitCond, kclient kubernetes.Interface) (map[string]string, error) {
	annotations, err := GetPodAnnotations(ctx, podLister, namespace, name, annotCond)
	if err != nil {
		klog.Warningf("Getting annotations for pod %s/%s via the SharedInformer failed, falling back to a direct request: %v", namespace, name, err)
		pod, err2 := kclient.CoreV1().Pods(namespace).Get(ctx, name, v1.GetOptions{})
		if err2 != nil {
			klog.Warningf("Fallback failed when getting annotations for pod %s/%s: %v", namespace, name, err2)
			return nil, err // return original error
		}

		annotations = pod.ObjectMeta.Annotations
		if annotCond(annotations) {
			klog.Warningf("Fallback succeded for fetching annotations for pod %s/%s -- possible informer hang? Dumping stack.", namespace, name)
			pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)

			return annotations, nil
		}

		// Fallback succeded, but annotations don't meet condition, return original error
		return nil, err
	}
	return annotations, nil
}

// PodAnnotation2PodInfo creates PodInterfaceInfo from Pod annotations and additional attributes
func PodAnnotation2PodInfo(podAnnotation map[string]string, checkExtIDs bool, isSmartNic bool) (
	*PodInterfaceInfo, error) {
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
		CheckExtIDs:   checkExtIDs,
		IsSmartNic:    isSmartNic,
	}
	return podInterfaceInfo, nil
}
