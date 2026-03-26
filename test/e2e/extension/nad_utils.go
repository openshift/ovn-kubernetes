package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	netutils "k8s.io/utils/net"
)

type udnPodResource struct {
	name      string
	namespace string
	label     string
	template  string
}

type udnPodResourceNode struct {
	name      string
	namespace string
	label     string
	nodename  string
	template  string
}

type udnPodSecNADResource struct {
	name       string
	namespace  string
	label      string
	annotation string
	template   string
}

type udnPodSecNADResourceNode struct {
	name      string
	namespace string
	label     string
	nadname   string
	nodename  string
	template  string
}

type udnNetDefResource struct {
	nadname             string
	namespace           string
	nad_network_name    string
	topology            string
	subnet              string
	net_attach_def_name string
	role                string
	template            string
}

type udnCRDResource struct {
	crdname    string
	namespace  string
	IPv4cidr   string
	IPv4prefix int32
	IPv6cidr   string
	IPv6prefix int32
	cidr       string
	prefix     int32
	role       string
	template   string
}

type cudnCRDResource struct {
	crdname             string
	labelvalue          string
	labelkey            string
	key                 string
	operator            string
	values              []string
	IPv4cidr            string
	IPv4prefix          int32
	IPv6cidr            string
	IPv6prefix          int32
	cidr                string
	prefix              int32
	role                string
	physicalnetworkname string
	subnet              string
	excludesubnet       string
	template            string
}

type udnPodWithProbeResource struct {
	name             string
	namespace        string
	label            string
	port             int
	failurethreshold int
	periodseconds    int
	template         string
}

func (pod *udnPodResource) createUdnPod(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "LABEL="+pod.label)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (pod *udnPodResourceNode) createUdnPodNode(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "LABEL="+pod.label, "NODENAME="+pod.nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (pod *udnPodWithProbeResource) createUdnPodWithProbe(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "LABEL="+pod.label, "PORT="+strconv.Itoa(int(pod.port)), "FAILURETHRESHOLD="+strconv.Itoa(int(pod.failurethreshold)), "PERIODSECONDS="+strconv.Itoa(int(pod.periodseconds)))
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (pod *udnPodSecNADResource) createUdnPodWithSecNAD(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "LABEL="+pod.label, "ANNOTATION="+pod.annotation)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (pod *udnPodSecNADResourceNode) createUdnPodWithSecNADNode(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "LABEL="+pod.label, "NADNAME="+pod.nadname, "NODENAME="+pod.nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (nad *udnNetDefResource) createUdnNad(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", nad.template, "-p", "NADNAME="+nad.nadname, "NAMESPACE="+nad.namespace, "NAD_NETWORK_NAME="+nad.nad_network_name, "TOPOLOGY="+nad.topology, "SUBNET="+nad.subnet, "NET_ATTACH_DEF_NAME="+nad.net_attach_def_name, "ROLE="+nad.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", nad.nadname))
}

func (nad *udnNetDefResource) deleteUdnNetDef(oc *exutil.CLI) {
	removeResource(oc, false, true, "net-attach-def", nad.nadname, "-n", nad.namespace)
}

// getPodIPUDN returns IPv6 and IPv4 in vars in order on dual stack respectively and main IP in case of single stack (v4 or v6) in 1st var, and nil in 2nd var
func getPodIPUDN(oc *exutil.CLI, namespace string, podName string, netName string) (string, string) {
	ipStack := checkIPStackType(oc)
	cmdIPv4 := "ip a sho " + netName + " | awk 'NR==3{print $2}' |grep -Eo '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'"
	cmdIPv6 := "ip -o -6 addr show dev " + netName + " | awk '$3 == \"inet6\" && $6 == \"global\" {print $4}' | cut -d'/' -f1"
	switch ipStack {
	case "ipv4single":
		podIPv4, err := execCommandInSpecificPod(oc, namespace, podName, cmdIPv4)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The UDN pod %s IPv4 in namespace %s is %q", podName, namespace, podIPv4)
		return podIPv4, ""
	case "ipv6single":
		podIPv6, err := execCommandInSpecificPod(oc, namespace, podName, cmdIPv6)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The UDN pod %s IPv6 in namespace %s is %q", podName, namespace, podIPv6)
		return podIPv6, ""
	default:
		podIPv4, err := execCommandInSpecificPod(oc, namespace, podName, cmdIPv4)
		o.Expect(err).NotTo(o.HaveOccurred())
		podIPv6, err := execCommandInSpecificPod(oc, namespace, podName, cmdIPv6)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The UDN pod's %s IPv6 and IPv4 IP in namespace %s is %q %q", podName, namespace, podIPv6, podIPv4)
		return podIPv6, podIPv4
	}
}

// CurlPod2PodPass checks connectivity across udn pods regardless of network addressing type on cluster
func CurlPod2PodPassUDN(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	// getPodIPUDN will returns IPv6 and IPv4 in vars in order on dual stack respectively and main IP in case of single stack (v4 or v6) in 1st var, and nil in 2nd var
	podIP1, podIP2 := getPodIPUDN(oc, namespaceDst, podNameDst, "ovn-udn1")
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
	// getPodIPUDN will returns IPv6 and IPv4 in vars in order on dual stack respectively and main IP in case of single stack (v4 or v6) in 1st var, and nil in 2nd var
	podIP1, podIP2 := getPodIPUDN(oc, namespaceDst, podNameDst, "ovn-udn1")
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
	//getPodIPUDN returns IPv6 and IPv4 in order on dual stack in PodIP1 and PodIP2 respectively and main IP in case of single stack (v4 or v6) in PodIP1, and nil in PodIP2
	podIP1, podIP2 := getPodIPUDN(oc, namespaceDst, podNameDst, "ovn-udn1")
	if podIP2 != "" {
		podv4URL := net.JoinHostPort(podIP2, "8080")
		_, err := compat_otp.DebugNode(oc, nodeName, "curl", podv4URL, "-s", "--connect-timeout", "2")
		o.Expect(err).To(o.HaveOccurred())
	}
	podURL := net.JoinHostPort(podIP1, "8080")
	_, err := compat_otp.DebugNode(oc, nodeName, "curl", podURL, "-s", "--connect-timeout", "2")
	o.Expect(err).To(o.HaveOccurred())
}

func CurlUDNPod2PodPassMultiNetwork(oc *exutil.CLI, namespaceSrc string, namespaceDst string, podNameSrc string, netNameInterface string, podNameDst string, netNameDst string) {
	podIP1, podIP2 := getPodIPUDN(oc, namespaceDst, podNameDst, netNameDst)
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
	podIP1, podIP2 := getPodIPUDN(oc, namespaceDst, podNameDst, netNameDst)
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

func (udncrd *udnCRDResource) createUdnCRDSingleStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", udncrd.template, "-p", "CRDNAME="+udncrd.crdname, "NAMESPACE="+udncrd.namespace, "CIDR="+udncrd.cidr, "PREFIX="+strconv.Itoa(int(udncrd.prefix)), "ROLE="+udncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create udn CRD %s due to %v", udncrd.crdname, err))
}

func (udncrd *udnCRDResource) createUdnCRDDualStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", udncrd.template, "-p", "CRDNAME="+udncrd.crdname, "NAMESPACE="+udncrd.namespace, "IPv4CIDR="+udncrd.IPv4cidr, "IPv4PREFIX="+strconv.Itoa(int(udncrd.IPv4prefix)), "IPv6CIDR="+udncrd.IPv6cidr, "IPv6PREFIX="+strconv.Itoa(int(udncrd.IPv6prefix)), "ROLE="+udncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create udn CRD %s due to %v", udncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createCUDNCRDSingleStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "LABELKEY="+cudncrd.labelkey, "LABELVALUE="+cudncrd.labelvalue,
			"CIDR="+cudncrd.cidr, "PREFIX="+strconv.Itoa(int(cudncrd.prefix)), "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createCUDNCRDDualStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "LABELKEY="+cudncrd.labelkey, "LABELVALUE="+cudncrd.labelvalue,
			"IPv4CIDR="+cudncrd.IPv4cidr, "IPv4PREFIX="+strconv.Itoa(int(cudncrd.IPv4prefix)), "IPv6CIDR="+cudncrd.IPv6cidr, "IPv6PREFIX="+strconv.Itoa(int(cudncrd.IPv6prefix)), "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createCUDNCRDMatchExpSingleStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "KEY="+cudncrd.key, "OPERATOR="+cudncrd.operator, "VALUE1="+cudncrd.values[0], "VALUE2="+cudncrd.values[1],
			"CIDR="+cudncrd.cidr, "PREFIX="+strconv.Itoa(int(cudncrd.prefix)), "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createCUDNCRDMatchExpDualStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "KEY="+cudncrd.key, "OPERATOR="+cudncrd.operator, "VALUE1="+cudncrd.values[0], "VALUE2="+cudncrd.values[1],
			"IPv4CIDR="+cudncrd.IPv4cidr, "IPv4PREFIX="+strconv.Itoa(int(cudncrd.IPv4prefix)), "IPv6CIDR="+cudncrd.IPv6cidr, "IPv6PREFIX="+strconv.Itoa(int(cudncrd.IPv6prefix)), "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func (udncrd *udnCRDResource) deleteUdnCRDDef(oc *exutil.CLI) {
	removeResource(oc, true, true, "UserDefinedNetwork", udncrd.crdname, "-n", udncrd.namespace)
}

func waitUDNCRDApplied(oc *exutil.CLI, ns, crdName string) error {
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

func waitCUDNCRDApplied(oc *exutil.CLI, crdName string) error {
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

func (udncrd *udnCRDResource) createLayer2DualStackUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", udncrd.template, "-p", "CRDNAME="+udncrd.crdname, "NAMESPACE="+udncrd.namespace, "IPv4CIDR="+udncrd.IPv4cidr, "IPv6CIDR="+udncrd.IPv6cidr, "ROLE="+udncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create udn CRD %s due to %v", udncrd.crdname, err))
}

func (udncrd *udnCRDResource) createLayer2SingleStackUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", udncrd.template, "-p", "CRDNAME="+udncrd.crdname, "NAMESPACE="+udncrd.namespace, "CIDR="+udncrd.cidr, "ROLE="+udncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create udn CRD %s due to %v", udncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createLayer2SingleStackCUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "LABELKEY="+cudncrd.labelkey, "LABELVALUE="+cudncrd.labelvalue,
			"CIDR="+cudncrd.cidr, "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createLayer2DualStackCUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "LABELKEY="+cudncrd.labelkey, "LABELVALUE="+cudncrd.labelvalue,
			"IPv4CIDR="+cudncrd.IPv4cidr, "IPv6CIDR="+cudncrd.IPv6cidr, "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createLayer2CUDNCRDMatchExpSingleStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "KEY="+cudncrd.key, "OPERATOR="+cudncrd.operator, "VALUE1="+cudncrd.values[0], "VALUE2="+cudncrd.values[1],
			"CIDR="+cudncrd.cidr, "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createLayer2CUDNCRDMatchExpDualStack(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "KEY="+cudncrd.key, "OPERATOR="+cudncrd.operator, "VALUE1="+cudncrd.values[0], "VALUE2="+cudncrd.values[1],
			"IPv4CIDR="+cudncrd.IPv4cidr, "IPv6CIDR="+cudncrd.IPv6cidr, "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func (cudncrd *cudnCRDResource) createLayer3LocalnetCUDNCRD(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 20*time.Second, false, func(ctx context.Context) (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", cudncrd.template, "-p", "CRDNAME="+cudncrd.crdname, "LABELKEY="+cudncrd.labelkey, "LABELVALUE="+cudncrd.labelvalue, "PHYSICALNETWORK="+cudncrd.physicalnetworkname, "SUBNET="+cudncrd.subnet, "EXCLUDESUBNET="+cudncrd.excludesubnet, "ROLE="+cudncrd.role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create cudn CRD %s due to %v", cudncrd.crdname, err))
}

func checkPodCIDRsOverlap(oc *exutil.CLI, namespace string, ipStack string, Pods []string, netName string) bool {
	var subnetsIPv4 []*net.IPNet
	var subnetsIPv6 []*net.IPNet
	var subnets []*net.IPNet
	cmdIPv4 := "ip a sho " + netName + " | awk 'NR==3{print $2}'"
	cmdIPv6 := "ip -o -6 addr show dev " + netName + " | awk '$3 == \"inet6\" && $6 == \"global\" {print $4}'"
	for _, pod := range Pods {
		if ipStack == "dualstack" {
			podIPv4, ipv4Err := execCommandInSpecificPod(oc, namespace, pod, cmdIPv4)
			o.Expect(ipv4Err).NotTo(o.HaveOccurred())
			podIPv6, ipv6Err := execCommandInSpecificPod(oc, namespace, pod, cmdIPv6)
			o.Expect(ipv6Err).NotTo(o.HaveOccurred())
			_, subnetIPv4, err := net.ParseCIDR(strings.TrimSpace(podIPv4))
			o.Expect(err).NotTo(o.HaveOccurred())
			subnetsIPv4 = append(subnetsIPv4, subnetIPv4)
			_, subnetIPv6, err := net.ParseCIDR(strings.TrimSpace(podIPv6))
			o.Expect(err).NotTo(o.HaveOccurred())
			subnetsIPv6 = append(subnetsIPv6, subnetIPv6)
		} else {
			if ipStack == "ipv6single" {
				podIPv6, ipv6Err := execCommandInSpecificPod(oc, namespace, pod, cmdIPv6)
				o.Expect(ipv6Err).NotTo(o.HaveOccurred())
				_, subnet, err := net.ParseCIDR(strings.TrimSpace(podIPv6))
				o.Expect(err).NotTo(o.HaveOccurred())
				subnets = append(subnets, subnet)
			} else {
				podIPv4, ipv4Err := execCommandInSpecificPod(oc, namespace, pod, cmdIPv4)
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
	} else {
		return subnets[0].Contains(subnets[1].IP) || subnets[1].Contains(subnets[0].IP)
	}
}

func applyL3UDNtoNamespace(oc *exutil.CLI, namespace string, udnSelector int) error {

	udnCRDSingleStack := testdata.FixturePath("networking", "udn", "udn_crd_singlestack_template.yaml")
	udnCRDdualStack := testdata.FixturePath("networking", "udn", "udn_crd_dualstack2_template.yaml")

	SkipIfNoFeatureGate(oc, "NetworkSegmentation")

	ipStackType := checkIPStackType(oc)
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

	var udncrd udnCRDResource
	if ipStackType == "dualstack" {
		udncrd = udnCRDResource{
			crdname:    "l3-network-" + namespace,
			namespace:  namespace,
			role:       "Primary",
			IPv4cidr:   ipv4cidr[udnSelector],
			IPv4prefix: ipv4prefix,
			IPv6cidr:   ipv6cidr[udnSelector],
			IPv6prefix: ipv6prefix,
			template:   udnCRDdualStack,
		}
		udncrd.createUdnCRDDualStack(oc)
	} else {
		udncrd = udnCRDResource{
			crdname:   "l3-network-" + namespace,
			namespace: namespace,
			role:      "Primary",
			cidr:      cidr[udnSelector],
			prefix:    prefix,
			template:  udnCRDSingleStack,
		}
		udncrd.createUdnCRDSingleStack(oc)
	}
	err := waitUDNCRDApplied(oc, namespace, udncrd.crdname)
	return err

}

func applyCUDNtoMatchLabelNS(oc *exutil.CLI, matchLabelKey, matchValue, crdName, ipv4cidr, ipv6cidr, cidr, topology string) (cudnCRDResource, error) {

	var (
		testDataDirUDN       = testdata.FixturePath("networking/udn")
		cudnCRDSingleStack   = filepath.Join(testDataDirUDN, "cudn_crd_singlestack_template.yaml")
		cudnCRDdualStack     = filepath.Join(testDataDirUDN, "cudn_crd_dualstack_template.yaml")
		cudnCRDL2dualStack   = filepath.Join(testDataDirUDN, "cudn_crd_layer2_dualstack_template.yaml")
		cudnCRDL2SingleStack = filepath.Join(testDataDirUDN, "cudn_crd_layer2_singlestack_template.yaml")
	)

	ipStackType := checkIPStackType(oc)
	cudncrd := cudnCRDResource{
		crdname:    crdName,
		labelkey:   matchLabelKey,
		labelvalue: matchValue,
		role:       "Primary",
		template:   cudnCRDSingleStack,
	}

	switch topology {
	case "layer3":
		switch ipStackType {
		case "dualstack":
			cudncrd.IPv4cidr = ipv4cidr
			cudncrd.IPv4prefix = 24
			cudncrd.IPv6cidr = ipv6cidr
			cudncrd.IPv6prefix = 64
			cudncrd.template = cudnCRDdualStack
			cudncrd.createCUDNCRDDualStack(oc)
		case "ipv6single":
			cudncrd.prefix = 64
			cudncrd.cidr = cidr
			cudncrd.template = cudnCRDSingleStack
			cudncrd.createCUDNCRDSingleStack(oc)
		case "ipv4single":
			cudncrd.prefix = 24
			cudncrd.cidr = cidr
			cudncrd.template = cudnCRDSingleStack
			cudncrd.createCUDNCRDSingleStack(oc)
		}
	case "layer2":
		switch ipStackType {
		case "dualstack":
			cudncrd.IPv4cidr = ipv4cidr
			cudncrd.IPv6cidr = ipv6cidr
			cudncrd.template = cudnCRDL2dualStack
			cudncrd.createLayer2DualStackCUDNCRD(oc)
		default:
			cudncrd.cidr = cidr
			cudncrd.template = cudnCRDL2SingleStack
			cudncrd.createLayer2SingleStackCUDNCRD(oc)
		}
	}
	err := waitCUDNCRDApplied(oc, cudncrd.crdname)
	if err != nil {
		return cudncrd, err
	}
	return cudncrd, nil
}

func applyLocalnetCUDNtoMatchLabelNS(oc *exutil.CLI, matchLabelKey, matchValue, crdName, physicalNetworkName, subnet, excludeSubnet string, vlan bool) (cudnCRDResource, error) {
	var (
		testDataDirUDN                     = testdata.FixturePath("networking/udn")
		cudnCRDLocalnetSingleStack         = filepath.Join(testDataDirUDN, "cudn_crd_localnet_singlestack_template.yaml")
		cudnCRDLocalnetSingleStackWithVlan = filepath.Join(testDataDirUDN, "cudn_crd_localnet_singlestack_with_vlan_template.yaml")
	)

	cudncrd := cudnCRDResource{
		crdname:             crdName,
		labelkey:            matchLabelKey,
		labelvalue:          matchValue,
		physicalnetworkname: physicalNetworkName,
		subnet:              subnet,
		excludesubnet:       excludeSubnet,
		role:                "Secondary",
	}

	if vlan {
		cudncrd.template = cudnCRDLocalnetSingleStackWithVlan
	} else {
		cudncrd.template = cudnCRDLocalnetSingleStack
	}

	cudncrd.createLayer3LocalnetCUDNCRD(oc)
	err := waitCUDNCRDApplied(oc, cudncrd.crdname)
	if err != nil {
		return cudncrd, err
	}
	return cudncrd, nil
}

func PingPod2PodPass(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := getPodIP(oc, namespaceDst, podNameDst)
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
	podIP1, podIP2 := getPodIP(oc, namespaceDst, podNameDst)
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

func verifyConnPod2Pod(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string, protocol string, port int, pass bool) {
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
	defer serverCmd.Process.Kill()
	o.Expect(serverCmdErr).NotTo(o.HaveOccurred())

	e2e.Logf("Check %s process enabled in the dst pod %s", protocol, podNameDst)
	o.Eventually(func() string {
		msg, err := e2eoutput.RunHostCmd(namespaceDst, podNameDst, "ps aux | grep socat")
		o.Expect(err).NotTo(o.HaveOccurred())
		return msg
	}, "30s", "5s").Should(o.ContainSubstring(serverOpt), "No expected process running on dst pod")

	e2e.Logf("Sending %s packets from src pod %s to dst pod %s", protocol, podNameSrc, podNameDst)
	podIP1, podIP2 := getPodIP(oc, namespaceDst, podNameDst)
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
			clientCmd = fmt.Sprintf("timeout 10 sh -c 'echo hello | socat %s:%s'", clientOpt, net.JoinHostPort(podIP2, strconv.Itoa(port)))
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

func createGeneralUDNCRD(oc *exutil.CLI, namespace, crdName, ipv4cidr, ipv6cidr, cidr, layer string) {
	// This is a function for common CRD creation without special requirement for parameters which is can be used for common cases and to reduce code lines in case level.
	var (
		testDataDirUDN          = testdata.FixturePath("networking/udn")
		udnCRDdualStack         = filepath.Join(testDataDirUDN, "udn_crd_dualstack2_template.yaml")
		udnCRDSingleStack       = filepath.Join(testDataDirUDN, "udn_crd_singlestack_template.yaml")
		udnCRDLayer2dualStack   = filepath.Join(testDataDirUDN, "udn_crd_layer2_dualstack_template.yaml")
		udnCRDLayer2SingleStack = filepath.Join(testDataDirUDN, "udn_crd_layer2_singlestack_template.yaml")
	)

	ipStackType := checkIPStackType(oc)
	var udncrd udnCRDResource
	switch layer {
	case "layer3":
		switch ipStackType {
		case "dualstack":
			udncrd = udnCRDResource{
				crdname:    crdName,
				namespace:  namespace,
				role:       "Primary",
				IPv4cidr:   ipv4cidr,
				IPv4prefix: 24,
				IPv6cidr:   ipv6cidr,
				IPv6prefix: 64,
				template:   udnCRDdualStack,
			}
			udncrd.createUdnCRDDualStack(oc)
		case "ipv6single":
			udncrd = udnCRDResource{
				crdname:   crdName,
				namespace: namespace,
				role:      "Primary",
				cidr:      cidr,
				prefix:    64,
				template:  udnCRDSingleStack,
			}
			udncrd.createUdnCRDSingleStack(oc)
		default:
			udncrd = udnCRDResource{
				crdname:   crdName,
				namespace: namespace,
				role:      "Primary",
				cidr:      cidr,
				prefix:    24,
				template:  udnCRDSingleStack,
			}
			udncrd.createUdnCRDSingleStack(oc)
		}
		err := waitUDNCRDApplied(oc, namespace, udncrd.crdname)
		o.Expect(err).NotTo(o.HaveOccurred())

	case "layer2":
		switch ipStackType {
		case "dualstack":
			udncrd = udnCRDResource{
				crdname:   crdName,
				namespace: namespace,
				role:      "Primary",
				IPv4cidr:  ipv4cidr,
				IPv6cidr:  ipv6cidr,
				template:  udnCRDLayer2dualStack,
			}
			udncrd.createLayer2DualStackUDNCRD(oc)

		default:
			udncrd = udnCRDResource{
				crdname:   crdName,
				namespace: namespace,
				role:      "Primary",
				cidr:      cidr,
				template:  udnCRDLayer2SingleStack,
			}
			udncrd.createLayer2SingleStackUDNCRD(oc)
			err := waitUDNCRDApplied(oc, namespace, udncrd.crdname)
			o.Expect(err).NotTo(o.HaveOccurred())
		}
	default:
		e2e.Logf("Not surpport UDN type for now.")
	}
}

func createCUDNCRD(oc *exutil.CLI, key, crdName, ipv4cidr, ipv6cidr, cidr, layer string, values []string) (cudnCRDResource, error) {
	// This is a function for common CUDN CRD creation without special requirement for parameters which is can be used for common cases and to reduce code lines in case level.
	var (
		testDataDirUDN           = testdata.FixturePath("networking/udn")
		cudnCRDL3dualStack       = filepath.Join(testDataDirUDN, "cudn_crd_matchexp_dualstack_template.yaml")
		cudnCRDL3SingleStack     = filepath.Join(testDataDirUDN, "cudn_crd_matchexp_singlestack_template.yaml")
		cudnCRDLayer2dualStack   = filepath.Join(testDataDirUDN, "cudn_crd_matchexp_layer2_dualstack_template.yaml")
		cudnCRDLayer2SingleStack = filepath.Join(testDataDirUDN, "cudn_crd_matchexp_layer2_singlestack_template.yaml")
	)

	ipStackType := checkIPStackType(oc)
	cudncrd := cudnCRDResource{
		crdname:  crdName,
		key:      key,
		operator: "In",
		values:   values,
		role:     "Primary",
		template: cudnCRDL3dualStack,
	}

	switch layer {
	case "layer3":
		switch ipStackType {
		case "dualstack":
			cudncrd.IPv4cidr = ipv4cidr
			cudncrd.IPv4prefix = 24
			cudncrd.IPv6cidr = ipv6cidr
			cudncrd.IPv6prefix = 64
			cudncrd.template = cudnCRDL3dualStack
			cudncrd.createCUDNCRDMatchExpDualStack(oc)
		case "ipv6single":
			cudncrd.prefix = 64
			cudncrd.cidr = cidr
			cudncrd.template = cudnCRDL3SingleStack
			cudncrd.createCUDNCRDMatchExpSingleStack(oc)
		default:
			cudncrd.prefix = 24
			cudncrd.cidr = cidr
			cudncrd.template = cudnCRDL3SingleStack
			cudncrd.createCUDNCRDMatchExpSingleStack(oc)
		}
	case "layer2":
		switch ipStackType {
		case "dualstack":
			cudncrd.IPv4cidr = ipv4cidr
			cudncrd.IPv6cidr = ipv6cidr
			cudncrd.template = cudnCRDLayer2dualStack
			cudncrd.createLayer2CUDNCRDMatchExpDualStack(oc)
		default:
			cudncrd.cidr = cidr
			cudncrd.template = cudnCRDLayer2SingleStack
			cudncrd.createLayer2CUDNCRDMatchExpSingleStack(oc)
		}

	default:
		e2e.Logf("Not supported UDN type for now.")
	}
	err := waitCUDNCRDApplied(oc, cudncrd.crdname)
	if err != nil {
		return cudncrd, err
	}
	return cudncrd, nil
}
