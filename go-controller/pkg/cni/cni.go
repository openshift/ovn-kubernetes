package cni

import (
	"fmt"
	"net"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var (
	minRsrc           = resource.MustParse("1k")
	maxRsrc           = resource.MustParse("1P")
	BandwidthNotFound = &notFoundError{}
)

type direction int

type durationMap map[string]time.Duration

func addDuration(durationMap *durationMap, tag string, since time.Time) {
	if durationMap != nil {
		(*durationMap)[tag] = time.Since(since)
	}
}

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

func (pr *PodRequest) getVFNetdevName() (string, error) {
	// Get the vf device Name
	vfNetdevices, err := util.GetSriovnetOps().GetNetDevicesFromPci(pr.CNIConf.DeviceID)
	if err != nil {
		return "", err

	}
	// Make sure we have 1 netdevice per pci address
	if len(vfNetdevices) != 1 {
		return "", fmt.Errorf("failed to get one netdevice interface per %s", pr.CNIConf.DeviceID)
	}
	return vfNetdevices[0], nil
}

func (pr *PodRequest) cmdAdd(kubeAuth *KubeAPIAuth, podLister corev1listers.PodLister, useOVSExternalIDs bool, kclient kubernetes.Interface) (*Response, error) {
	durationMap := durationMap{}
	start := time.Now()
	defer func() {
		durationMap["cmdAdd"] = time.Since(start)
		klog.Infof("SCALE TIMING cmdAdd [%s/%s/%s]: %+v", pr.PodNamespace, pr.PodName, pr.PodUID, durationMap)
	}()

	kubecli := &kube.Kube{KClient: kclient}
	annotCondFn := isOvnReady

	vfNetdevName := ""
	if pr.CNIConf.DeviceID != "" {
		var err error

		vfNetdevName, err = pr.getVFNetdevName()
		if err != nil {
			return nil, fmt.Errorf("failed in cmdAdd while getting VF Netdevice name: %v", err)
		}
		if config.OvnKubeNode.Mode == types.NodeModeDPUHost {
			// Add DPU connection-details annotation so ovnkube-node running on DPU
			// performs the needed network plumbing.
			if err = pr.addDPUConnectionDetailsAnnot(kubecli, vfNetdevName); err != nil {
				return nil, err
			}
			annotCondFn = isDPUReady
		}
		// In the case of SmartNIC (CX5), we store the VFNetdevname in the VF representor's
		// OVS interface's external_id column. This is done in ConfigureInterface().
	}
	// Get the IP address and MAC address of the pod
	// for DPU, ensure connection-details is present
	podUID, annotations, err := GetPodAnnotations(pr.ctx, podLister, kclient, pr.PodNamespace, pr.PodName, annotCondFn, &durationMap)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod annotation: %v", err)
	}
	if err := pr.checkOrUpdatePodUID(podUID); err != nil {
		return nil, err
	}

	podInterfaceInfo, err := PodAnnotation2PodInfo(annotations, useOVSExternalIDs, pr.PodUID, vfNetdevName, &durationMap)
	if err != nil {
		return nil, err
	}

	response := &Response{KubeAuth: kubeAuth}
	if !config.UnprivilegedMode {
		response.Result, err = pr.getCNIResult(podLister, kclient, podInterfaceInfo, &durationMap)
		if err != nil {
			return nil, err
		}
	} else {
		response.PodIFInfo = podInterfaceInfo
	}

	return response, nil
}

func (pr *PodRequest) cmdDel(podLister corev1listers.PodLister, kclient kubernetes.Interface) (*Response, error) {
	// assume success case, return an empty Result
	response := &Response{}
	response.Result = &current.Result{}

	vfNetdevName := ""
	if pr.CNIConf.DeviceID != "" {
		if config.OvnKubeNode.Mode == types.NodeModeDPUHost {
			pod, err := getPod(podLister, kclient, pr.PodNamespace, pr.PodName)
			if err != nil {
				klog.Warningf("Failed to get pod %s/%s: %v", pr.PodNamespace, pr.PodName, err)
				return response, nil
			}
			dpuCD := util.DPUConnectionDetails{}
			if err := dpuCD.FromPodAnnotation(pod.Annotations); err != nil {
				klog.Warningf("Failed to get DPU connection details annotation for pod %s/%s: %v", pr.PodNamespace,
					pr.PodName, err)
				return response, nil
			}
			vfNetdevName = dpuCD.VfNetdevName
		} else {
			ovsIfName := pr.SandboxID[:15]
			out, err := ovsGet("interface", ovsIfName, "external_ids", "vf-netdev-name")
			if err != nil {
				klog.Warningf("Couldn't find the original VF Netdev name from OVS interface %s for pod %s/%s: %v",
					ovsIfName, pr.PodNamespace, pr.PodName, err)
			} else {
				vfNetdevName = out
			}
		}
	}

	podInterfaceInfo := &PodInterfaceInfo{
		IsDPUHostMode: config.OvnKubeNode.Mode == types.NodeModeDPUHost,
		VfNetdevName:  vfNetdevName,
	}
	if !config.UnprivilegedMode {
		err := pr.UnconfigureInterface(podInterfaceInfo)
		if err != nil {
			return nil, err
		}
	} else {
		// pass the isDPU flag and vfNetdevName back to cniShim
		response.Result = nil
		response.PodIFInfo = podInterfaceInfo
	}
	return response, nil
}

func (pr *PodRequest) cmdCheck(podLister corev1listers.PodLister, useOVSExternalIDs bool, kclient kubernetes.Interface) error {
	// noop...CMD check is not considered useful, and has a considerable performance impact
	// to pod bring up times with CRIO. This is due to the fact that CRIO currently calls check
	// after CNI ADD before it finishes bringing the container up
	return nil
}

// HandleCNIRequest is the callback for all the requests
// coming to the cniserver after being processed into PodRequest objects
// Argument '*PodRequest' encapsulates all the necessary information
// kclient is passed in so that clientset can be reused from the server
// Return value is the actual bytes to be sent back without further processing.
func HandleCNIRequest(request *PodRequest, podLister corev1listers.PodLister, useOVSExternalIDs bool, kclient kubernetes.Interface, kubeAuth *KubeAPIAuth) ([]byte, error) {
	var result, resultForLogging []byte
	var response *Response
	var err, err1 error

	klog.Infof("%s %s starting CNI request %+v", request, request.Command, request)
	switch request.Command {
	case CNIAdd:
		response, err = request.cmdAdd(kubeAuth, podLister, useOVSExternalIDs, kclient)
	case CNIDel:
		response, err = request.cmdDel(podLister, kclient)
	case CNICheck:
		err = request.cmdCheck(podLister, useOVSExternalIDs, kclient)
	default:
	}

	if response != nil {
		if result, err1 = response.Marshal(); err1 != nil {
			return nil, fmt.Errorf("%s %s CNI request %+v failed to marshal result: %v",
				request, request.Command, request, err1)
		}
		if resultForLogging, err1 = response.MarshalForLogging(); err1 != nil {
			klog.Errorf("%s %s CNI request %+v, %v", request, request.Command, request, err1)
		}
	}

	klog.Infof("%s %s finished CNI request %+v, result %q, err %v",
		request, request.Command, request, string(resultForLogging), err)

	if err != nil {
		// Prefix errors with request info for easier failure debugging
		return nil, fmt.Errorf("%s %v", request, err)
	}
	return result, nil
}

// getCNIResult get result from pod interface info.
func (pr *PodRequest) getCNIResult(podLister corev1listers.PodLister, kclient kubernetes.Interface, podInterfaceInfo *PodInterfaceInfo, durationMap *durationMap) (*current.Result, error) {
	interfacesArray, err := pr.ConfigureInterface(podLister, kclient, podInterfaceInfo, durationMap)
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
