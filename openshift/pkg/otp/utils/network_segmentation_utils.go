package otputils

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	netutils "k8s.io/utils/net"
)

// UDN pod resource types

type UdnPodResource struct {
	Name      string
	Namespace string
	Label     string
	Template  string
}

type UdnPodResourceNode struct {
	Name      string
	Namespace string
	Label     string
	Nodename  string
	Template  string
}

type UdnPodSecNADResource struct {
	Name       string
	Namespace  string
	Label      string
	Annotation string
	Template   string
}

type UdnPodSecNADResourceNode struct {
	Name      string
	Namespace string
	Label     string
	Nadname   string
	Nodename  string
	Template  string
}

type UdnNetDefResource struct {
	Nadname         string
	Namespace       string
	NadNetworkName  string
	Topology        string
	Subnet          string
	NetAttachDefName string
	Role            string
	Template        string
}

type UdnCRDResource struct {
	Crdname    string
	Namespace  string
	IPv4cidr   string
	IPv4prefix int32
	IPv6cidr   string
	IPv6prefix int32
	Cidr       string
	Prefix     int32
	Role       string
	Template   string
}

type CudnCRDResource struct {
	Crdname             string
	Labelvalue          string
	Labelkey            string
	Key                 string
	Operator            string
	Values              []string
	IPv4cidr            string
	IPv4prefix          int32
	IPv6cidr            string
	IPv6prefix          int32
	Cidr                string
	Prefix              int32
	Role                string
	Physicalnetworkname string
	Subnet              string
	Excludesubnet       string
	Template            string
}

type UdnPodWithProbeResource struct {
	Name             string
	Namespace        string
	Label            string
	Port             int
	Failurethreshold int
	Periodseconds    int
	Template         string
}

type ReplicationControllerPingPodResource struct {
	Name      string
	Replicas  int
	Namespace string
	Template  string
}

// RunOcWithRetry runs an oc command with retry on i/o timeout errors
func RunOcWithRetry(oc *exutil.CLI, cmd string, args ...string) (string, error) {
	var err error
	var output string
	maxRetries := 5

	for numRetries := 0; numRetries < maxRetries; numRetries++ {
		if numRetries > 0 {
			e2e.Logf("Retrying oc command (retry count=%v/%v)", numRetries+1, maxRetries)
		}

		output, err = oc.Run(cmd).Args(args...).Output()
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "i/o timeout") {
				e2e.Logf("Warning: oc command encountered i/o timeout.\nerr=%v\n)", err)
				continue
			}
			return output, err
		}
		break
	}
	return output, err
}

func (pod *UdnPodResource) CreateUdnPod(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace, "LABEL="+pod.Label)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
}

func (pod *UdnPodResourceNode) CreateUdnPodNode(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace, "LABEL="+pod.Label, "NODENAME="+pod.Nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
}

func (pod *UdnPodWithProbeResource) CreateUdnPodWithProbe(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace, "LABEL="+pod.Label, "PORT="+strconv.Itoa(pod.Port), "FAILURETHRESHOLD="+strconv.Itoa(pod.Failurethreshold), "PERIODSECONDS="+strconv.Itoa(pod.Periodseconds))
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
}

func (pod *UdnPodSecNADResource) CreateUdnPodWithSecNAD(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace, "LABEL="+pod.Label, "ANNOTATION="+pod.Annotation)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
}

func (pod *UdnPodSecNADResourceNode) CreateUdnPodWithSecNADNode(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace, "LABEL="+pod.Label, "NADNAME="+pod.Nadname, "NODENAME="+pod.Nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
}

func (nad *UdnNetDefResource) CreateUdnNad(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", nad.Template, "-p", "NADNAME="+nad.Nadname, "NAMESPACE="+nad.Namespace, "NAD_NETWORK_NAME="+nad.NadNetworkName, "TOPOLOGY="+nad.Topology, "SUBNET="+nad.Subnet, "NET_ATTACH_DEF_NAME="+nad.NetAttachDefName, "ROLE="+nad.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create nad %v", nad.Nadname))
}

func (nad *UdnNetDefResource) DeleteUdnNetDef(oc *exutil.CLI) {
	RemoveResource(oc, false, true, "net-attach-def", nad.Nadname, "-n", nad.Namespace)
}

// GetPodIPUDN returns IPv6 and IPv4 in vars in order on dual stack respectively and main IP in case of single stack (v4 or v6) in 1st var, and nil in 2nd var
func GetPodIPUDN(oc *exutil.CLI, namespace string, podName string, netName string) (string, string) {
	ipStack := CheckIPStackType(oc)
	cmdIPv4 := "ip a sho " + netName + " | awk 'NR==3{print $2}' |grep -Eo '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'"
	cmdIPv6 := "ip -o -6 addr show dev " + netName + " | awk '$3 == \"inet6\" && $6 == \"global\" {print $4}' | cut -d'/' -f1"
	switch ipStack {
	case "ipv4single":
		podIPv4, err := ExecCommandInSpecificPod(oc, namespace, podName, cmdIPv4)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The UDN pod %s IPv4 in namespace %s is %q", podName, namespace, podIPv4)
		return podIPv4, ""
	case "ipv6single":
		podIPv6, err := ExecCommandInSpecificPod(oc, namespace, podName, cmdIPv6)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The UDN pod %s IPv6 in namespace %s is %q", podName, namespace, podIPv6)
		return podIPv6, ""
	default:
		podIPv4, err := ExecCommandInSpecificPod(oc, namespace, podName, cmdIPv4)
		o.Expect(err).NotTo(o.HaveOccurred())
		podIPv6, err := ExecCommandInSpecificPod(oc, namespace, podName, cmdIPv6)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The UDN pod's %s IPv6 and IPv4 IP in namespace %s is %q %q", podName, namespace, podIPv6, podIPv4)
		return podIPv6, podIPv4
	}
}

// CurlPod2PodPassUDN checks connectivity across udn pods regardless of network addressing type on cluster
func CurlPod2PodPassUDN(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := GetPodIPUDN(oc, namespaceDst, podNameDst, "ovn-udn1")
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 2 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 2 -s "+net.JoinHostPort(podIP2, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 2 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlPod2PodFailUDN ensures no connectivity from a udn pod to pod regardless of network addressing type on cluster
func CurlPod2PodFailUDN(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := GetPodIPUDN(oc, namespaceDst, podNameDst, "ovn-udn1")
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 2 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 2 -s "+net.JoinHostPort(podIP2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 2 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	}
}

func CurlNode2PodFailUDN(oc *exutil.CLI, nodeName string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := GetPodIPUDN(oc, namespaceDst, podNameDst, "ovn-udn1")
	if podIP2 != "" {
		podv4URL := net.JoinHostPort(podIP2, "8080")
		_, err := DebugNode(oc, nodeName, "curl", podv4URL, "-s", "--connect-timeout", "2")
		o.Expect(err).To(o.HaveOccurred())
	}
	podURL := net.JoinHostPort(podIP1, "8080")
	_, err := DebugNode(oc, nodeName, "curl", podURL, "-s", "--connect-timeout", "2")
	o.Expect(err).To(o.HaveOccurred())
}

func CurlUDNPod2PodPassMultiNetwork(oc *exutil.CLI, namespaceSrc string, namespaceDst string, podNameSrc string, netNameInterface string, podNameDst string, netNameDst string) {
	podIP1, podIP2 := GetPodIPUDN(oc, namespaceDst, podNameDst, netNameDst)
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --interface "+netNameInterface+" --connect-timeout 2 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --interface "+netNameInterface+" --connect-timeout 2 -s "+net.JoinHostPort(podIP2, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --interface "+netNameInterface+" --connect-timeout 2 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

func CurlUDNPod2PodFailMultiNetwork(oc *exutil.CLI, namespaceSrc string, namespaceDst string, podNameSrc string, netNameInterface string, podNameDst string, netNameDst string) {
	podIP1, podIP2 := GetPodIPUDN(oc, namespaceDst, podNameDst, netNameDst)
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --interface "+netNameInterface+" --connect-timeout 2 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --interface "+netNameInterface+" --connect-timeout 2 -s "+net.JoinHostPort(podIP2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --interface "+netNameInterface+" --connect-timeout 2 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	}
}

func (udncrd *UdnCRDResource) CreateUdnCRDSingleStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", udncrd.Template, "-p", "CRDNAME="+udncrd.Crdname, "NAMESPACE="+udncrd.Namespace, "CIDR="+udncrd.Cidr, "PREFIX="+strconv.Itoa(int(udncrd.Prefix)), "ROLE="+udncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create udn CRD %s", udncrd.Crdname))
}

func (udncrd *UdnCRDResource) CreateUdnCRDDualStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", udncrd.Template, "-p", "CRDNAME="+udncrd.Crdname, "NAMESPACE="+udncrd.Namespace, "IPv4CIDR="+udncrd.IPv4cidr, "IPv4PREFIX="+strconv.Itoa(int(udncrd.IPv4prefix)), "IPv6CIDR="+udncrd.IPv6cidr, "IPv6PREFIX="+strconv.Itoa(int(udncrd.IPv6prefix)), "ROLE="+udncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create udn CRD %s", udncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateCUDNCRDSingleStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "LABELKEY="+cudncrd.Labelkey, "LABELVALUE="+cudncrd.Labelvalue,
			"CIDR="+cudncrd.Cidr, "PREFIX="+strconv.Itoa(int(cudncrd.Prefix)), "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateCUDNCRDDualStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "LABELKEY="+cudncrd.Labelkey, "LABELVALUE="+cudncrd.Labelvalue,
			"IPv4CIDR="+cudncrd.IPv4cidr, "IPv4PREFIX="+strconv.Itoa(int(cudncrd.IPv4prefix)), "IPv6CIDR="+cudncrd.IPv6cidr, "IPv6PREFIX="+strconv.Itoa(int(cudncrd.IPv6prefix)), "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateCUDNCRDMatchExpSingleStack(oc *exutil.CLI) {
	o.Expect(len(cudncrd.Values)).To(o.BeNumerically(">=", 2), fmt.Sprintf("CUDN %q requires at least 2 match-expression values", cudncrd.Crdname))
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "KEY="+cudncrd.Key, "OPERATOR="+cudncrd.Operator, "VALUE1="+cudncrd.Values[0], "VALUE2="+cudncrd.Values[1],
			"CIDR="+cudncrd.Cidr, "PREFIX="+strconv.Itoa(int(cudncrd.Prefix)), "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateCUDNCRDMatchExpDualStack(oc *exutil.CLI) {
	o.Expect(len(cudncrd.Values)).To(o.BeNumerically(">=", 2), fmt.Sprintf("CUDN %q requires at least 2 match-expression values", cudncrd.Crdname))
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "KEY="+cudncrd.Key, "OPERATOR="+cudncrd.Operator, "VALUE1="+cudncrd.Values[0], "VALUE2="+cudncrd.Values[1],
			"IPv4CIDR="+cudncrd.IPv4cidr, "IPv4PREFIX="+strconv.Itoa(int(cudncrd.IPv4prefix)), "IPv6CIDR="+cudncrd.IPv6cidr, "IPv6PREFIX="+strconv.Itoa(int(cudncrd.IPv6prefix)), "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func (udncrd *UdnCRDResource) DeleteUdnCRDDef(oc *exutil.CLI) {
	RemoveResource(oc, true, true, "UserDefinedNetwork", udncrd.Crdname, "-n", udncrd.Namespace)
}

func WaitUDNCRDApplied(oc *exutil.CLI, ns, crdName string) error {
	checkErr := wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, 60*time.Second, false, func(ctx context.Context) (bool, error) {
		output, efErr := oc.AsAdmin().WithoutNamespace().Run("wait").Args("UserDefinedNetwork/"+crdName, "-n", ns, "--for", "condition=NetworkAllocationSucceeded=True").Output()
		if efErr != nil {
			e2e.Logf("Failed to get UDN %v, error: %s. Trying again", crdName, efErr)
			return false, nil
		}
		if !strings.Contains(output, fmt.Sprintf("userdefinednetwork.k8s.ovn.org/%s condition met", crdName)) {
			e2e.Logf("UDN CRD was not applied yet, trying again. \n %s", output)
			return false, nil
		}
		return true, nil
	})
	return checkErr
}

func WaitCUDNCRDApplied(oc *exutil.CLI, crdName string) error {
	checkErr := wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		output, efErr := oc.AsAdmin().WithoutNamespace().Run("wait").Args("ClusterUserDefinedNetwork/"+crdName, "--for", "condition=NetworkCreated=True").Output()
		if efErr != nil {
			e2e.Logf("Failed to get CUDN %v, error: %s. Trying again", crdName, efErr)
			return false, nil
		}
		if !strings.Contains(output, fmt.Sprintf("clusteruserdefinednetwork.k8s.ovn.org/%s condition met", crdName)) {
			e2e.Logf("CUDN CRD was not applied yet, trying again. \n %s", output)
			return false, nil
		}
		return true, nil
	})
	return checkErr
}

func (udncrd *UdnCRDResource) CreateLayer2DualStackUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", udncrd.Template, "-p", "CRDNAME="+udncrd.Crdname, "NAMESPACE="+udncrd.Namespace, "IPv4CIDR="+udncrd.IPv4cidr, "IPv6CIDR="+udncrd.IPv6cidr, "ROLE="+udncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create udn CRD %s", udncrd.Crdname))
}

func (udncrd *UdnCRDResource) CreateLayer2SingleStackUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", udncrd.Template, "-p", "CRDNAME="+udncrd.Crdname, "NAMESPACE="+udncrd.Namespace, "CIDR="+udncrd.Cidr, "ROLE="+udncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create udn CRD %s", udncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateLayer2SingleStackCUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "LABELKEY="+cudncrd.Labelkey, "LABELVALUE="+cudncrd.Labelvalue,
			"CIDR="+cudncrd.Cidr, "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateLayer2DualStackCUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "LABELKEY="+cudncrd.Labelkey, "LABELVALUE="+cudncrd.Labelvalue,
			"IPv4CIDR="+cudncrd.IPv4cidr, "IPv6CIDR="+cudncrd.IPv6cidr, "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateLayer2CUDNCRDMatchExpSingleStack(oc *exutil.CLI) {
	o.Expect(len(cudncrd.Values)).To(o.BeNumerically(">=", 2), fmt.Sprintf("CUDN %q requires at least 2 match-expression values", cudncrd.Crdname))
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "KEY="+cudncrd.Key, "OPERATOR="+cudncrd.Operator, "VALUE1="+cudncrd.Values[0], "VALUE2="+cudncrd.Values[1],
			"CIDR="+cudncrd.Cidr, "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateLayer2CUDNCRDMatchExpDualStack(oc *exutil.CLI) {
	o.Expect(len(cudncrd.Values)).To(o.BeNumerically(">=", 2), fmt.Sprintf("CUDN %q requires at least 2 match-expression values", cudncrd.Crdname))
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "KEY="+cudncrd.Key, "OPERATOR="+cudncrd.Operator, "VALUE1="+cudncrd.Values[0], "VALUE2="+cudncrd.Values[1],
			"IPv4CIDR="+cudncrd.IPv4cidr, "IPv6CIDR="+cudncrd.IPv6cidr, "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func (cudncrd *CudnCRDResource) CreateLayer3LocalnetCUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.Template, "-p", "CRDNAME="+cudncrd.Crdname, "LABELKEY="+cudncrd.Labelkey, "LABELVALUE="+cudncrd.Labelvalue, "PHYSICALNETWORK="+cudncrd.Physicalnetworkname, "SUBNET="+cudncrd.Subnet, "EXCLUDESUBNET="+cudncrd.Excludesubnet, "ROLE="+cudncrd.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create cudn CRD %s", cudncrd.Crdname))
}

func CheckPodCIDRsOverlap(oc *exutil.CLI, namespace string, ipStack string, Pods []string, netName string) bool {
	var subnetsIPv4 []*net.IPNet
	var subnetsIPv6 []*net.IPNet
	var subnets []*net.IPNet
	cmdIPv4 := "ip a sho " + netName + " | awk 'NR==3{print $2}'"
	cmdIPv6 := "ip -o -6 addr show dev " + netName + " | awk '$3 == \"inet6\" && $6 == \"global\" {print $4}'"
	for _, pod := range Pods {
		if ipStack == "dualstack" {
			podIPv4, ipv4Err := ExecCommandInSpecificPod(oc, namespace, pod, cmdIPv4)
			o.Expect(ipv4Err).NotTo(o.HaveOccurred())
			podIPv6, ipv6Err := ExecCommandInSpecificPod(oc, namespace, pod, cmdIPv6)
			o.Expect(ipv6Err).NotTo(o.HaveOccurred())
			_, subnetIPv4, err := net.ParseCIDR(strings.TrimSpace(podIPv4))
			o.Expect(err).NotTo(o.HaveOccurred())
			subnetsIPv4 = append(subnetsIPv4, subnetIPv4)
			_, subnetIPv6, err := net.ParseCIDR(strings.TrimSpace(podIPv6))
			o.Expect(err).NotTo(o.HaveOccurred())
			subnetsIPv6 = append(subnetsIPv6, subnetIPv6)
		} else {
			if ipStack == "ipv6single" {
				podIPv6, ipv6Err := ExecCommandInSpecificPod(oc, namespace, pod, cmdIPv6)
				o.Expect(ipv6Err).NotTo(o.HaveOccurred())
				_, subnet, err := net.ParseCIDR(strings.TrimSpace(podIPv6))
				o.Expect(err).NotTo(o.HaveOccurred())
				subnets = append(subnets, subnet)
			} else {
				podIPv4, ipv4Err := ExecCommandInSpecificPod(oc, namespace, pod, cmdIPv4)
				o.Expect(ipv4Err).NotTo(o.HaveOccurred())
				_, subnet, err := net.ParseCIDR(strings.TrimSpace(podIPv4))
				o.Expect(err).NotTo(o.HaveOccurred())
				subnets = append(subnets, subnet)
			}
		}
	}
	if ipStack == "dualstack" {
		return subnetsIPv4[0].Contains(subnetsIPv4[1].IP) || subnetsIPv4[1].Contains(subnetsIPv4[0].IP) ||
			subnetsIPv6[0].Contains(subnetsIPv6[1].IP) || subnetsIPv6[1].Contains(subnetsIPv6[0].IP)
	}
	return subnets[0].Contains(subnets[1].IP) || subnets[1].Contains(subnets[0].IP)
}

func ApplyL3UDNtoNamespace(oc *exutil.CLI, namespace string, udnSelector int) error {
	udnCRDSingleStack := testdata.FixturePath("networking", "network_segmentation", "udn", "udn_crd_singlestack_template.yaml")
	udnCRDdualStack := testdata.FixturePath("networking", "network_segmentation", "udn", "udn_crd_dualstack2_template.yaml")

	SkipIfNoFeatureGate(oc, "NetworkSegmentation")

	ipStackType := CheckIPStackType(oc)
	var cidr, ipv4cidr, ipv6cidr []string
	var prefix, ipv4prefix, ipv6prefix int32
	if ipStackType == "ipv4single" {
		cidr = []string{"10.150.0.0/16", "10.151.0.0/16", "10.151.0.0/16"}
		prefix = 24
	} else {
		if ipStackType == "ipv6single" {
			cidr = []string{"2010:100:200::0/60", "2011:100:200::0/60", "2011:100:200::0/60"}
			prefix = 64
		} else {
			ipv4cidr = []string{"10.150.0.0/16", "10.151.0.0/16", "10.151.0.0/16"}
			ipv4prefix = 24
			ipv6cidr = []string{"2010:100:200::0/60", "2011:100:200::0/60", "2011:100:200::0/60"}
			ipv6prefix = 64
		}
	}

	var udncrd UdnCRDResource
	if ipStackType == "dualstack" {
		udncrd = UdnCRDResource{
			Crdname:    "l3-network-" + namespace,
			Namespace:  namespace,
			Role:       "Primary",
			IPv4cidr:   ipv4cidr[udnSelector],
			IPv4prefix: ipv4prefix,
			IPv6cidr:   ipv6cidr[udnSelector],
			IPv6prefix: ipv6prefix,
			Template:   udnCRDdualStack,
		}
		udncrd.CreateUdnCRDDualStack(oc)
	} else {
		udncrd = UdnCRDResource{
			Crdname:   "l3-network-" + namespace,
			Namespace: namespace,
			Role:      "Primary",
			Cidr:      cidr[udnSelector],
			Prefix:    prefix,
			Template:  udnCRDSingleStack,
		}
		udncrd.CreateUdnCRDSingleStack(oc)
	}
	err := WaitUDNCRDApplied(oc, namespace, udncrd.Crdname)
	return err
}

func ApplyCUDNtoMatchLabelNS(oc *exutil.CLI, matchLabelKey, matchValue, crdName, ipv4cidr, ipv6cidr, cidr, topology string) (CudnCRDResource, error) {
	var (
		testDataDirUDN       = testdata.FixturePath("networking/network_segmentation/udn")
		cudnCRDSingleStack   = filepath.Join(testDataDirUDN, "cudn_crd_singlestack_template.yaml")
		cudnCRDdualStack     = filepath.Join(testDataDirUDN, "cudn_crd_dualstack_template.yaml")
		cudnCRDL2dualStack   = filepath.Join(testDataDirUDN, "cudn_crd_layer2_dualstack_template.yaml")
		cudnCRDL2SingleStack = filepath.Join(testDataDirUDN, "cudn_crd_layer2_singlestack_template.yaml")
	)

	ipStackType := CheckIPStackType(oc)
	cudncrd := CudnCRDResource{
		Crdname:    crdName,
		Labelkey:   matchLabelKey,
		Labelvalue: matchValue,
		Role:       "Primary",
		Template:   cudnCRDSingleStack,
	}

	switch topology {
	case "layer3":
		switch ipStackType {
		case "dualstack":
			cudncrd.IPv4cidr = ipv4cidr
			cudncrd.IPv4prefix = 24
			cudncrd.IPv6cidr = ipv6cidr
			cudncrd.IPv6prefix = 64
			cudncrd.Template = cudnCRDdualStack
			cudncrd.CreateCUDNCRDDualStack(oc)
		case "ipv6single":
			cudncrd.Prefix = 64
			cudncrd.Cidr = cidr
			cudncrd.Template = cudnCRDSingleStack
			cudncrd.CreateCUDNCRDSingleStack(oc)
		case "ipv4single":
			cudncrd.Prefix = 24
			cudncrd.Cidr = cidr
			cudncrd.Template = cudnCRDSingleStack
			cudncrd.CreateCUDNCRDSingleStack(oc)
		}
	case "layer2":
		switch ipStackType {
		case "dualstack":
			cudncrd.IPv4cidr = ipv4cidr
			cudncrd.IPv6cidr = ipv6cidr
			cudncrd.Template = cudnCRDL2dualStack
			cudncrd.CreateLayer2DualStackCUDNCRD(oc)
		default:
			cudncrd.Cidr = cidr
			cudncrd.Template = cudnCRDL2SingleStack
			cudncrd.CreateLayer2SingleStackCUDNCRD(oc)
		}
	}
	err := WaitCUDNCRDApplied(oc, cudncrd.Crdname)
	if err != nil {
		return cudncrd, err
	}
	return cudncrd, nil
}

func ApplyLocalnetCUDNtoMatchLabelNS(oc *exutil.CLI, matchLabelKey, matchValue, crdName, physicalNetworkName, subnet, excludeSubnet string, vlan bool) (CudnCRDResource, error) {
	var (
		testDataDirUDN                     = testdata.FixturePath("networking/network_segmentation/udn")
		cudnCRDLocalnetSingleStack         = filepath.Join(testDataDirUDN, "cudn_crd_localnet_singlestack_template.yaml")
		cudnCRDLocalnetSingleStackWithVlan = filepath.Join(testDataDirUDN, "cudn_crd_localnet_singlestack_with_vlan_template.yaml")
	)

	cudncrd := CudnCRDResource{
		Crdname:             crdName,
		Labelkey:            matchLabelKey,
		Labelvalue:          matchValue,
		Physicalnetworkname: physicalNetworkName,
		Subnet:              subnet,
		Excludesubnet:       excludeSubnet,
		Role:                "Secondary",
	}

	if vlan {
		cudncrd.Template = cudnCRDLocalnetSingleStackWithVlan
	} else {
		cudncrd.Template = cudnCRDLocalnetSingleStack
	}

	cudncrd.CreateLayer3LocalnetCUDNCRD(oc)
	err := WaitCUDNCRDApplied(oc, cudncrd.Crdname)
	if err != nil {
		return cudncrd, err
	}
	return cudncrd, nil
}

func PingPod2PodPass(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := GetPodIP(oc, namespaceDst, podNameDst)
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "ping6 -c4 "+podIP1)
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "ping -c4 "+podIP2)
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		if netutils.IsIPv6String(podIP1) {
			_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "ping6 -c4 "+podIP1)
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "ping -c4 "+podIP1)
			o.Expect(err).NotTo(o.HaveOccurred())
		}
	}
}

func PingPod2PodFail(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := GetPodIP(oc, namespaceDst, podNameDst)
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "ping6 -c4 "+podIP1)
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "ping -c4 "+podIP2)
		o.Expect(err).To(o.HaveOccurred())
	} else {
		if netutils.IsIPv6String(podIP1) {
			_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "ping6 -c4 "+podIP1)
			o.Expect(err).To(o.HaveOccurred())
		} else {
			_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "ping -c4 "+podIP1)
			o.Expect(err).To(o.HaveOccurred())
		}
	}
}

func VerifyConnPod2Pod(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string, protocol string, port int, pass bool) {
	e2e.Logf("==== Check %s traffic ====", protocol)
	// kill socat process before sending/listen traffic
	for _, nsPod := range [][]string{{namespaceSrc, podNameSrc}, {namespaceDst, podNameDst}} {
		e2eoutput.RunHostCmd(nsPod[0], nsPod[1], "killall socat")
	}
	var clientOpt, serverOpt string
	switch protocol {
	case "UDP":
		clientOpt = "udp-connect"
		serverOpt = "udp6-listen"
	case "SCTP":
		clientOpt = "sctp-connect"
		serverOpt = "sctp6-listen"
	default:
		e2e.Failf("protocol is not specified")
	}

	e2e.Logf("Listening on port %s on dst pod %s", strconv.Itoa(port), podNameDst)
	serverCmd, serverCmdOutput, _, serverCmdErr := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", namespaceDst, podNameDst, "--", "socat", "-", serverOpt+":"+strconv.Itoa(port)+",fork").Background()
	o.Expect(serverCmdErr).NotTo(o.HaveOccurred())
	defer func() {
		if serverCmd != nil && serverCmd.Process != nil {
			_ = serverCmd.Process.Kill()
		}
	}()

	e2e.Logf("Check %s process enabled in the dst pod %s", protocol, podNameDst)
	o.Eventually(func() string {
		msg, err := e2eoutput.RunHostCmd(namespaceDst, podNameDst, "ps aux | grep socat")
		o.Expect(err).NotTo(o.HaveOccurred())
		return msg
	}, "30s", "5s").Should(o.ContainSubstring(serverOpt), "No expected process running on dst pod")

	e2e.Logf("Sending %s packets from src pod %s to dst pod %s", protocol, podNameSrc, podNameDst)
	podIP1, podIP2 := GetPodIP(oc, namespaceDst, podNameDst)
	if pass {
		if podIP2 != "" {
			clientCmd := fmt.Sprintf("echo hello | socat - %s:%s", clientOpt, net.JoinHostPort(podIP1, strconv.Itoa(port)))
			_, clientCmdErr := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, clientCmd)
			o.Expect(clientCmdErr).NotTo(o.HaveOccurred())
			clientCmd = fmt.Sprintf("echo hello | socat - %s:%s", clientOpt, net.JoinHostPort(podIP2, strconv.Itoa(port)))
			_, clientCmdErr = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, clientCmd)
			o.Expect(clientCmdErr).NotTo(o.HaveOccurred())
			e2e.Logf("output on server side: %s", serverCmdOutput.String())
			o.Expect(strings.Count(serverCmdOutput.String(), "hello") == 2).To(o.BeTrue())
		} else {
			clientCmd := fmt.Sprintf("timeout 10 sh -c 'echo hello | socat - %s:%s'", clientOpt, net.JoinHostPort(podIP1, strconv.Itoa(port)))
			_, clientCmdErr := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, clientCmd)
			o.Expect(clientCmdErr).NotTo(o.HaveOccurred())
			e2e.Logf("output on server side: %s", serverCmdOutput.String())
			o.Expect(strings.Contains(serverCmdOutput.String(), "hello")).To(o.BeTrue())
		}
	} else {
		if podIP2 != "" {
			clientCmd := fmt.Sprintf("timeout 10 sh -c 'echo hello | socat - %s:%s'", clientOpt, net.JoinHostPort(podIP1, strconv.Itoa(port)))
			e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, clientCmd)
			clientCmd = fmt.Sprintf("timeout 10 sh -c 'echo hello | socat - %s:%s'", clientOpt, net.JoinHostPort(podIP2, strconv.Itoa(port)))
			e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, clientCmd)
			e2e.Logf("output on server side: %s", serverCmdOutput.String())
			o.Expect(strings.Contains(serverCmdOutput.String(), "hello")).To(o.BeFalse())
		} else {
			clientCmd := fmt.Sprintf("timeout 10 sh -c 'echo hello | socat - %s:%s'", clientOpt, net.JoinHostPort(podIP1, strconv.Itoa(port)))
			e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, clientCmd)
			e2e.Logf("output on server side: %s", serverCmdOutput.String())
			o.Expect(strings.Contains(serverCmdOutput.String(), "hello")).To(o.BeFalse())
		}
	}
}

func CreateGeneralUDNCRD(oc *exutil.CLI, namespace, crdName, ipv4cidr, ipv6cidr, cidr, layer string) {
	var (
		testDataDirUDN          = testdata.FixturePath("networking/network_segmentation/udn")
		udnCRDdualStack         = filepath.Join(testDataDirUDN, "udn_crd_dualstack2_template.yaml")
		udnCRDSingleStack       = filepath.Join(testDataDirUDN, "udn_crd_singlestack_template.yaml")
		udnCRDLayer2dualStack   = filepath.Join(testDataDirUDN, "udn_crd_layer2_dualstack_template.yaml")
		udnCRDLayer2SingleStack = filepath.Join(testDataDirUDN, "udn_crd_layer2_singlestack_template.yaml")
	)

	ipStackType := CheckIPStackType(oc)
	var udncrd UdnCRDResource
	switch layer {
	case "layer3":
		switch ipStackType {
		case "dualstack":
			udncrd = UdnCRDResource{
				Crdname:    crdName,
				Namespace:  namespace,
				Role:       "Primary",
				IPv4cidr:   ipv4cidr,
				IPv4prefix: 24,
				IPv6cidr:   ipv6cidr,
				IPv6prefix: 64,
				Template:   udnCRDdualStack,
			}
			udncrd.CreateUdnCRDDualStack(oc)
		case "ipv6single":
			udncrd = UdnCRDResource{
				Crdname:   crdName,
				Namespace: namespace,
				Role:      "Primary",
				Cidr:      cidr,
				Prefix:    64,
				Template:  udnCRDSingleStack,
			}
			udncrd.CreateUdnCRDSingleStack(oc)
		default:
			udncrd = UdnCRDResource{
				Crdname:   crdName,
				Namespace: namespace,
				Role:      "Primary",
				Cidr:      cidr,
				Prefix:    24,
				Template:  udnCRDSingleStack,
			}
			udncrd.CreateUdnCRDSingleStack(oc)
		}
		err := WaitUDNCRDApplied(oc, namespace, udncrd.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

	case "layer2":
		switch ipStackType {
		case "dualstack":
			udncrd = UdnCRDResource{
				Crdname:   crdName,
				Namespace: namespace,
				Role:      "Primary",
				IPv4cidr:  ipv4cidr,
				IPv6cidr:  ipv6cidr,
				Template:  udnCRDLayer2dualStack,
			}
			udncrd.CreateLayer2DualStackUDNCRD(oc)

		default:
			udncrd = UdnCRDResource{
				Crdname:   crdName,
				Namespace: namespace,
				Role:      "Primary",
				Cidr:      cidr,
				Template:  udnCRDLayer2SingleStack,
			}
			udncrd.CreateLayer2SingleStackUDNCRD(oc)
		}
		err := WaitUDNCRDApplied(oc, namespace, udncrd.Crdname)
		o.Expect(err).NotTo(o.HaveOccurred())
	default:
		e2e.Logf("Not surpport UDN type for now.")
	}
}

func CreateCUDNCRD(oc *exutil.CLI, key, crdName, ipv4cidr, ipv6cidr, cidr, layer string, values []string) (CudnCRDResource, error) {
	var (
		testDataDirUDN           = testdata.FixturePath("networking/network_segmentation/udn")
		cudnCRDL3dualStack       = filepath.Join(testDataDirUDN, "cudn_crd_matchexp_dualstack_template.yaml")
		cudnCRDL3SingleStack     = filepath.Join(testDataDirUDN, "cudn_crd_matchexp_singlestack_template.yaml")
		cudnCRDLayer2dualStack   = filepath.Join(testDataDirUDN, "cudn_crd_matchexp_layer2_dualstack_template.yaml")
		cudnCRDLayer2SingleStack = filepath.Join(testDataDirUDN, "cudn_crd_matchexp_layer2_singlestack_template.yaml")
	)

	ipStackType := CheckIPStackType(oc)
	cudncrd := CudnCRDResource{
		Crdname:  crdName,
		Key:      key,
		Operator: "In",
		Values:   values,
		Role:     "Primary",
		Template: cudnCRDL3dualStack,
	}

	switch layer {
	case "layer3":
		switch ipStackType {
		case "dualstack":
			cudncrd.IPv4cidr = ipv4cidr
			cudncrd.IPv4prefix = 24
			cudncrd.IPv6cidr = ipv6cidr
			cudncrd.IPv6prefix = 64
			cudncrd.Template = cudnCRDL3dualStack
			cudncrd.CreateCUDNCRDMatchExpDualStack(oc)
		case "ipv6single":
			cudncrd.Prefix = 64
			cudncrd.Cidr = cidr
			cudncrd.Template = cudnCRDL3SingleStack
			cudncrd.CreateCUDNCRDMatchExpSingleStack(oc)
		default:
			cudncrd.Prefix = 24
			cudncrd.Cidr = cidr
			cudncrd.Template = cudnCRDL3SingleStack
			cudncrd.CreateCUDNCRDMatchExpSingleStack(oc)
		}
	case "layer2":
		switch ipStackType {
		case "dualstack":
			cudncrd.IPv4cidr = ipv4cidr
			cudncrd.IPv6cidr = ipv6cidr
			cudncrd.Template = cudnCRDLayer2dualStack
			cudncrd.CreateLayer2CUDNCRDMatchExpDualStack(oc)
		default:
			cudncrd.Cidr = cidr
			cudncrd.Template = cudnCRDLayer2SingleStack
			cudncrd.CreateLayer2CUDNCRDMatchExpSingleStack(oc)
		}

	default:
		e2e.Logf("Not supported UDN type for now.")
	}
	err := WaitCUDNCRDApplied(oc, cudncrd.Crdname)
	if err != nil {
		return cudncrd, err
	}
	return cudncrd, nil
}

// Multicast utility functions

// DisableMulticast disables multicast on specific namespace
func DisableMulticast(oc *exutil.CLI, ns string) {
	_, err := RunOcWithRetry(oc.AsAdmin().WithoutNamespace(), "annotate", "namespace", ns, "k8s.ovn.org/multicast-enabled-")
	o.Expect(err).NotTo(o.HaveOccurred())
}

// ChkMcastTraffic sends omping traffic on all multicast pods
func ChkMcastTraffic(oc *exutil.CLI, namespace string, podList []string, ipList []string, mcastip string, port string) bool {
	pktFile := make([]string, len(podList))
	for i, podName := range podList {
		pktFile[i] = "/tmp/" + GetRandomString() + ".txt"
		StartMcastTrafficOnPod(oc, namespace, podName, ipList, pktFile[i], mcastip, port)
	}
	// wait for omping packets send and receive
	time.Sleep(30 * time.Second)
	for i, podName := range podList {
		if !ChkMcatRcvOnPod(oc, namespace, podName, ipList[i], ipList, mcastip, pktFile[i]) {
			return false
		}
	}
	return true
}

// StartMcastTrafficOnPod sends multicast traffic via omping in a goroutine so
// all pods start omping concurrently — omping requires all peers running simultaneously.
func StartMcastTrafficOnPod(oc *exutil.CLI, ns string, pod string, ipList []string, pktfile string, mcastip string, port string) {
	ipStr := strings.Join(ipList, " ")
	if port == "" {
		port = "4321"
	}
	go func() {
		ompingCmd := "omping " + "-q " + "-p " + port + " -c 20 -T 20 -m " + mcastip + " " + ipStr + " > " + fmt.Sprintf("%s", pktfile) + " &"
		_, err := e2eoutput.RunHostCmd(ns, pod, ompingCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
	}()
}

// ChkMcatRcvOnPod checks omping send/receive results on a pod
func ChkMcatRcvOnPod(oc *exutil.CLI, ns string, pod string, podip string, iplist []string, mcastip string, pktfile string) bool {
	catCmd := "cat " + fmt.Sprintf("%s", pktfile)
	outPut, err := e2eoutput.RunHostCmd(ns, pod, catCmd)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(outPut).NotTo(o.BeEmpty())
	for _, neighborip := range iplist {
		if neighborip != podip {
			reg1 := regexp.MustCompile(regexp.QuoteMeta(neighborip) + `.*joined \(S,G\) = \(\*,\s*` + regexp.QuoteMeta(mcastip) + `\), pinging`)
			reg2 := regexp.MustCompile(regexp.QuoteMeta(neighborip) + `.*multicast, xmt/rcv/%loss = \d+/(\d+)/\d+%`)

			match1 := reg1.MatchString(outPut)
			match2 := reg2.FindStringSubmatch(outPut)
			o.Expect(match2).ShouldNot(o.BeNil())
			pktNum, _ := strconv.Atoi(match2[1])
			e2e.Logf("Received packets on pod %v from ip %v is %v", pod, neighborip, pktNum)
			if pktNum == 0 || !match1 {
				return false
			}
		}
	}
	return true
}

// GetPodIPv4UDNList gets ipv4 addresses of udn pods
func GetPodIPv4UDNList(oc *exutil.CLI, namespace string, podList []string) []string {
	var ipList []string
	ipStackType := CheckIPStackType(oc)
	o.Expect(ipStackType).ShouldNot(o.Equal("ipv6single"))
	for _, podName := range podList {
		podIP1, podIP2 := GetPodIPUDN(oc, namespace, podName, "ovn-udn1")
		if ipStackType == "dualstack" {
			ipList = append(ipList, podIP2)
		} else {
			ipList = append(ipList, podIP1)
		}
	}
	e2e.Logf("The ipv4list for pods is %v", ipList)
	return ipList
}

// GetPodIPv6UDNList gets ipv6 addresses of udn pods
func GetPodIPv6UDNList(oc *exutil.CLI, namespace string, podList []string) []string {
	var ipList []string
	ipStackType := CheckIPStackType(oc)
	o.Expect(ipStackType).ShouldNot(o.Equal("ipv4single"))
	for _, podName := range podList {
		podIP1, _ := GetPodIPUDN(oc, namespace, podName, "ovn-udn1")
		ipList = append(ipList, podIP1)
	}
	e2e.Logf("The ipv6list for pods is %v", ipList)
	return ipList
}

// GetPodIPv4List gets ipv4 addresses of default pods
func GetPodIPv4List(oc *exutil.CLI, namespace string, podList []string) []string {
	var ipList []string
	ipStackType := CheckIPStackType(oc)
	o.Expect(ipStackType).ShouldNot(o.Equal("ipv6single"))
	for _, podName := range podList {
		podIP := GetPodIPv4(oc, namespace, podName)
		ipList = append(ipList, podIP)
	}
	e2e.Logf("The ipv4list for pods is %v", ipList)
	return ipList
}

// GetPodIPv6List gets ipv6 addresses of default pods
func GetPodIPv6List(oc *exutil.CLI, namespace string, podList []string) []string {
	var ipList []string
	ipStackType := CheckIPStackType(oc)
	o.Expect(ipStackType).ShouldNot(o.Equal("ipv4single"))
	for _, podName := range podList {
		podIP := GetPodIPv6(oc, namespace, podName, ipStackType)
		ipList = append(ipList, podIP)
	}
	e2e.Logf("The ipv6list for pods is %v", ipList)
	return ipList
}

// ChkMcastAddress checks netstat during sending multicast traffic
func ChkMcastAddress(oc *exutil.CLI, ns string, pod string, intf string, mcastip string) {
	netstatCmd := "netstat -ng"
	outPut, err := e2eoutput.RunHostCmd(ns, pod, netstatCmd)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("netstat result is %v: /n", outPut)
	reg := regexp.MustCompile(regexp.QuoteMeta(intf) + `\s+\d+\s+` + regexp.QuoteMeta(mcastip))
	matchRes := reg.MatchString(outPut)
	o.Expect(matchRes).Should(o.BeTrue())
}

// GetPodIPUDNv4 returns IPv4 address of specific interface
func GetPodIPUDNv4(oc *exutil.CLI, namespace string, podName string, netName string) string {
	ipStack := CheckIPStackType(oc)
	ip1, ip2 := GetPodIPUDN(oc, namespace, podName, netName)
	if ipStack == "ipv4single" {
		return ip1
	} else if ipStack == "dualstack" {
		return ip2
	}
	return ""
}

// GetPodIPUDNv6 returns IPv6 address of specific interface
func GetPodIPUDNv6(oc *exutil.CLI, namespace string, podName string, netName string) string {
	ipStack := CheckIPStackType(oc)
	ip1, _ := GetPodIPUDN(oc, namespace, podName, netName)
	if ipStack == "ipv6single" || ipStack == "dualstack" {
		return ip1
	}
	return ""
}

// ReplicationControllerPingPodResource methods

func (rcPingPod *ReplicationControllerPingPodResource) CreateReplicaController(oc *exutil.CLI) {
	e2e.Logf("Creating replication controller from template")
	replicasString := fmt.Sprintf("REPLICAS=%v", rcPingPod.Replicas)
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", rcPingPod.Template, "-p", "PODNAME="+rcPingPod.Name,
			"NAMESPACE="+rcPingPod.Namespace, replicasString)
		if err1 != nil {
			e2e.Logf("Error creating replication controller:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("Failed to create replicationcontroller %v", rcPingPod.Name))
}
