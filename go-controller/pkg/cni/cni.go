package cni

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
)

var (
	minRsrc           = resource.MustParse("1k")
	maxRsrc           = resource.MustParse("1P")
	BandwidthNotFound = &notFoundError{}
)

type direction int

func (d direction) String() string {
	if d == Egress {
		return "egress"
	}
	return "ingress"
}

const (
	Egress direction = iota
	Ingress
)

type notFoundError struct{}

func (*notFoundError) Error() string {
	return "not found"
}

func validateBandwidthIsReasonable(rsrc *resource.Quantity) error {
	if rsrc.Value() < minRsrc.Value() {
		return fmt.Errorf("resource is unreasonably small (< 1kbit)")
	}
	if rsrc.Value() > maxRsrc.Value() {
		return fmt.Errorf("resoruce is unreasonably large (> 1Pbit)")
	}
	return nil
}

func extractPodBandwidth(podAnnotations map[string]string, dir direction) (int64, error) {
	annotation := "kubernetes.io/ingress-bandwidth"
	if dir == Egress {
		annotation = "kubernetes.io/egress-bandwidth"
	}

	str, found := podAnnotations[annotation]
	if !found {
		return 0, BandwidthNotFound
	}
	bwVal, err := resource.ParseQuantity(str)
	if err != nil {
		return 0, err
	}
	if err := validateBandwidthIsReasonable(&bwVal); err != nil {
		return 0, err
	}
	return bwVal.Value(), nil
}

func (pr *PodRequest) String() string {
	return fmt.Sprintf("[%s/%s %s]", pr.PodNamespace, pr.PodName, pr.SandboxID)
}

// checkOrUpdatePodUID validates the given pod UID against the request's existing
// pod UID. If the existing UID is empty the runtime did not support passing UIDs
// and the best we can do is use the given UID for the duration of the request.
// But if the existing UID is valid and does not match the given UID then the
// sandbox request is for a different pod instance and should be terminated.
func (pr *PodRequest) checkOrUpdatePodUID(podUID string) error {
	if pr.PodUID == "" {
		// Runtime didn't pass UID, use the one we got from the pod object
		pr.PodUID = podUID
	} else if podUID != pr.PodUID {
		// Exit early if the pod was deleted and recreated already
		return fmt.Errorf("pod deleted before sandbox %v operation began", pr.Command)
	}
	return nil
}

func (pr *PodRequest) cmdAdd(kubeAuth *KubeAPIAuth, podLister corev1listers.PodLister, useOVSExternalIDs bool, kclient kubernetes.Interface) ([]byte, error) {
	namespace := pr.PodNamespace
	podName := pr.PodName
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("required CNI variable missing")
	}

	kubecli := &kube.Kube{KClient: kclient}
	annotCondFn := isOvnReady

	if pr.IsSmartNIC {
		// Add Smart-NIC connection-details annotation so ovnkube-node running on smart-NIC
		// performs the needed network plumbing.
		if err := pr.addSmartNICConnectionDetailsAnnot(kubecli); err != nil {
			return nil, err
		}
		annotCondFn = isSmartNICReady
	}
	// Get the IP address and MAC address of the pod
	// for Smart-Nic, ensure connection-details is present
	podUID, annotations, err := GetPodAnnotations(pr.ctx, podLister, kclient, namespace, podName, annotCondFn)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod annotation: %v", err)
	}
	if err := pr.checkOrUpdatePodUID(podUID); err != nil {
		return nil, err
	}

	podInterfaceInfo, err := PodAnnotation2PodInfo(annotations, useOVSExternalIDs, pr.IsSmartNIC)
	if err != nil {
		return nil, err
	}

	response := &Response{KubeAuth: kubeAuth}
	if !config.UnprivilegedMode {
		response.Result, err = pr.getCNIResult(podLister, kclient, podInterfaceInfo)
		if err != nil {
			return nil, err
		}
	} else {
		response.PodIFInfo = podInterfaceInfo
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod request response: %v", err)
	}

	return responseBytes, nil
}

func (pr *PodRequest) cmdDel() ([]byte, error) {
	if pr.IsSmartNIC {
		// nothing to do
		return []byte{}, nil
	}

	if err := pr.PlatformSpecificCleanup(); err != nil {
		return nil, err
	}
	return []byte{}, nil
}

func (pr *PodRequest) cmdCheck(podLister corev1listers.PodLister, useOVSExternalIDs bool, kclient kubernetes.Interface) ([]byte, error) {
	namespace := pr.PodNamespace
	podName := pr.PodName
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("required CNI variable missing")
	}

	// Get the IP address and MAC address of the pod
	annotCondFn := isOvnReady
	if pr.IsSmartNIC {
		annotCondFn = isSmartNICReady
	}
	podUID, annotations, err := GetPodAnnotations(pr.ctx, podLister, kclient, pr.PodNamespace, pr.PodName, annotCondFn)
	if err != nil {
		return nil, err
	}
	if err := pr.checkOrUpdatePodUID(podUID); err != nil {
		return nil, err
	}

	if pr.CNIConf.PrevResult != nil {
		result, err := current.NewResultFromResult(pr.CNIConf.PrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
		hostIfaceName := ""
		for _, interf := range result.Interfaces {
			if len(interf.Sandbox) == 0 {
				hostIfaceName = interf.Name
				break
			}
		}
		if len(hostIfaceName) == 0 {
			return nil, fmt.Errorf("could not find host interface in the prevResult: %v", result)
		}
		ifaceID := fmt.Sprintf("%s_%s", namespace, podName)
		ofPort, err := getIfaceOFPort(hostIfaceName)
		if err != nil {
			return nil, err
		}
		for _, ip := range result.IPs {
			if err = waitForPodInterface(pr.ctx, result.Interfaces[*ip.Interface].Mac, []*net.IPNet{&ip.Address},
				hostIfaceName, ifaceID, ofPort, useOVSExternalIDs, podLister, kclient, pr.PodNamespace, pr.PodName,
				pr.PodUID); err != nil {
				return nil, fmt.Errorf("error while waiting on OVN pod interface: %s ip: %v, error: %v", ifaceID, ip, err)
			}
		}

		for _, direction := range []direction{Ingress, Egress} {
			annotationBandwith, annotationErr := extractPodBandwidth(annotations, direction)
			ovnBandwith, ovnErr := getOvsPortBandwidth(hostIfaceName, direction)
			if errors.Is(annotationErr, BandwidthNotFound) && errors.Is(ovnErr, BandwidthNotFound) {
				continue
			}
			if annotationErr != nil {
				return nil, errors.Wrapf(err, "Failed to get bandwith from annotations of pod %s %s", podName, direction)
			}
			if ovnErr != nil {
				return nil, errors.Wrapf(err, "Failed to get pod %s %s bandwith from ovn", direction, podName)
			}
			if annotationBandwith != ovnBandwith {
				return nil, fmt.Errorf("defined %s bandwith restriction %d is not equal to the set one %d", direction, annotationBandwith, ovnBandwith)
			}
		}
	}
	return []byte{}, nil
}

// HandleCNIRequest is the callback for all the requests
// coming to the cniserver after being processed into PodRequest objects
// Argument '*PodRequest' encapsulates all the necessary information
// kclient is passed in so that clientset can be reused from the server
// Return value is the actual bytes to be sent back without further processing.
func HandleCNIRequest(request *PodRequest, podLister corev1listers.PodLister, useOVSExternalIDs bool, kclient kubernetes.Interface, kubeAuth *KubeAPIAuth) ([]byte, error) {
	var result []byte
	var err error

	klog.Infof("%s %s starting CNI request %+v", request, request.Command, request)
	switch request.Command {
	case CNIAdd:
		result, err = request.cmdAdd(kubeAuth, podLister, useOVSExternalIDs, kclient)
	case CNIDel:
		result, err = request.cmdDel()
	case CNICheck:
		result, err = request.cmdCheck(podLister, useOVSExternalIDs, kclient)
	default:
	}
	klog.Infof("%s %s finished CNI request %+v, result %q, err %v",
		request, request.Command, request, string(formatResponseForLogging(result, request)), err)

	if err != nil {
		// Prefix errors with request info for easier failure debugging
		return nil, fmt.Errorf("%s %v", request, err)
	}
	return result, nil
}

// getCNIResult get result from pod interface info.
func (pr *PodRequest) getCNIResult(podLister corev1listers.PodLister, kclient kubernetes.Interface, podInterfaceInfo *PodInterfaceInfo) (*current.Result, error) {
	interfacesArray, err := pr.ConfigureInterface(podLister, kclient, podInterfaceInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to configure pod interface: %v", err)
	}

	gateways := map[string]net.IP{}
	for _, gw := range podInterfaceInfo.Gateways {
		if gw.To4() != nil && gateways["4"] == nil {
			gateways["4"] = gw
		} else if gw.To4() == nil && gateways["6"] == nil {
			gateways["6"] = gw
		}
	}

	// Build the result structure to pass back to the runtime
	ips := []*current.IPConfig{}
	for _, ipcidr := range podInterfaceInfo.IPs {
		ip := &current.IPConfig{
			Interface: current.Int(1),
			Address:   *ipcidr,
		}
		if utilnet.IsIPv6CIDR(ipcidr) {
			ip.Version = "6"
		} else {
			ip.Version = "4"
		}
		ip.Gateway = gateways[ip.Version]
		ips = append(ips, ip)
	}

	return &current.Result{
		Interfaces: interfacesArray,
		IPs:        ips,
	}, nil
}

// Filter out kubeAuth from response, since it might contain sensitive information.
func formatResponseForLogging(response []byte, request *PodRequest) []byte {
	var noAuthJSON []byte
	var err error

	if response == nil {
		return nil
	}
	if len(response) == 0 {
		return []byte{}
	}

	noAuth := struct {
		Result    *current.Result
		PodIFInfo *PodInterfaceInfo
	}{}
	if err = json.Unmarshal(response, &noAuth); err != nil {
		klog.Errorf("Could not extract Response from %s %s CNI request %+v, : %v",
			request, request.Command, request, err)
		return nil
	}

	if noAuthJSON, err = json.Marshal(noAuth); err != nil {
		klog.Errorf("Could not JSON-encode the extracted Response from %s %s "+
			"CNI request %+v: %v", request, request.Command, request, err)
		return nil
	}

	return noAuthJSON
}
