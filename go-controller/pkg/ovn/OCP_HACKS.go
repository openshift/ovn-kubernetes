package ovn

import (
	"fmt"
	"net"

	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

// ICNIv1 legacy code

// addPodICNIv1 ensures that hybrid overlay annotations are copied to a
// pod when it's created. This allows the nodes to set up the appropriate
// flows
func (oc *Controller) addPodICNIv1(pod *kapi.Pod) error {
	namespace, err := oc.watchFactory.GetNamespace(pod.Namespace)
	if err != nil {
		return err
	}

	namespaceExternalGw := namespace.Annotations[hotypes.HybridOverlayExternalGw]
	namespaceVTEP := namespace.Annotations[hotypes.HybridOverlayVTEP]

	podExternalGw := pod.Annotations[hotypes.HybridOverlayExternalGw]
	podVTEP := pod.Annotations[hotypes.HybridOverlayVTEP]

	if namespaceExternalGw != podExternalGw || namespaceVTEP != podVTEP {
		// copy namespace annotations to the pod and return
		return houtil.CopyNamespaceAnnotationsToPod(oc.kube, namespace, pod)
	}
	return nil
}

// addNamespaceICNIv1 copies namespace annotations to all pods in the namespace
func (oc *Controller) addNamespaceICNIv1(ns *kapi.Namespace) error {
	pods, err := oc.watchFactory.GetPods(ns.Name)
	if err != nil {
		return err
	}
	for _, pod := range pods {
		if err := houtil.CopyNamespaceAnnotationsToPod(oc.kube, ns, pod); err != nil {
			klog.Errorf("Unable to copy hybrid-overlay namespace annotations to pod %s", pod.Name)
		}
	}
	return nil
}

// nsHybridAnnotationChanged returns true if any relevant NS attributes changed
func nsHybridAnnotationChanged(oldNs, newNs *kapi.Namespace) bool {
	nsExGwOld := oldNs.GetAnnotations()[hotypes.HybridOverlayExternalGw]
	nsVTEPOld := oldNs.GetAnnotations()[hotypes.HybridOverlayVTEP]
	nsExGwNew := newNs.GetAnnotations()[hotypes.HybridOverlayExternalGw]
	nsVTEPNew := newNs.GetAnnotations()[hotypes.HybridOverlayVTEP]
	if nsExGwOld != nsExGwNew || nsVTEPOld != nsVTEPNew {
		return true
	}
	return false
}

// hasHybridAnnotation returns true if namespace has ICNIv1 annotations
func hasHybridAnnotation(obj v1.ObjectMeta) bool {
	nsExGw := obj.GetAnnotations()[hotypes.HybridOverlayExternalGw]
	nsVTEP := obj.GetAnnotations()[hotypes.HybridOverlayVTEP]

	if len(nsExGw) > 0 || len(nsVTEP) > 0 {
		return true
	}
	return false
}

// getNodeHybridOverlayIfAddr gets the hybrid overlay address from the HybridOverlayDRIP annotation given a nodes name
func (oc *Controller) getNodeHybridOverlayIfAddr(nodeName string) (net.IP, error) {
	node, err := oc.watchFactory.GetNode(nodeName)
	if err != nil {
		return nil, fmt.Errorf("cannot find node %s: %v", nodeName, err)
	}

	hybridOverlayDRIP, ok := node.Annotations[hotypes.HybridOverlayDRIP]
	if !ok {
		return nil, fmt.Errorf("hybrid overlay not initialized on node %s", nodeName)
	}

	hybridOverlayNodeIFAddr := net.ParseIP(hybridOverlayDRIP)
	if hybridOverlayNodeIFAddr == nil {
		return nil, fmt.Errorf("hybrid overlay distributed router ip for node %s is invalid annotation is %s", nodeName, hybridOverlayDRIP)
	}

	return hybridOverlayNodeIFAddr, nil
}
