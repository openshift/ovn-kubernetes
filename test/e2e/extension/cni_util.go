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

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

type multihomingNAD struct {
	namespace      string
	nadname        string
	subnets        string
	nswithnadname  string
	excludeSubnets string
	topology       string
	template       string
}

type multihomingSharenetNAD struct {
	namespace      string
	nadname        string
	subnets        string
	nswithnadname  string
	excludeSubnets string
	topology       string
	sharenetname   string
	template       string
}

type testMultihomingPod struct {
	name       string
	namespace  string
	podlabel   string
	nadname    string
	podenvname string
	nodename   string
	template   string
}

type testMultihomingStaticPod struct {
	name       string
	namespace  string
	podlabel   string
	nadname    string
	podenvname string
	nodename   string
	macaddress string
	ipaddress  string
	template   string
}

type multihomingIPBlock struct {
	name      string
	namespace string
	cidr      string
	policyfor string
	template  string
}

type dualstackNAD struct {
	nadname        string
	namespace      string
	plugintype     string
	mode           string
	ipamtype       string
	ipv4range      string
	ipv6range      string
	ipv4rangestart string
	ipv4rangeend   string
	ipv6rangestart string
	ipv6rangeend   string
	template       string
}

type whereaboutsoverlappingIPNAD struct {
	nadname           string
	namespace         string
	plugintype        string
	mode              string
	ipamtype          string
	ipv4range         string
	enableoverlapping bool
	networkname       string
	template          string
}

type testMultusPod struct {
	name       string
	namespace  string
	podlabel   string
	nadname    string
	podenvname string
	nodename   string
	replicas   string
	template   string
}

type multinetworkipBlockCIDRsDual struct {
	name      string
	namespace string
	cidrIpv4  string
	cidrIpv6  string
	policyfor string
	template  string
}

type nadInfo struct {
	name     string
	filePath string
}

type bridgeCNINAD struct {
	nadname        string
	namespace      string
	plugintype     string
	ipamtype       string
	ipv4range      string
	ipv6range      string
	ipv4rangestart string
	ipv4rangeend   string
	ipv6rangestart string
	ipv6rangeend   string
	portisolation  string
	template       string
}

func (nad *multihomingNAD) createMultihomingNAD(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", nad.template, "-p", "NAMESPACE="+nad.namespace, "NADNAME="+nad.nadname, "SUBNETS="+nad.subnets, "NSWITHNADNAME="+nad.nswithnadname, "EXCLUDESUBNETS="+nad.excludeSubnets, "TOPOLOGY="+nad.topology)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to net attach definition %v", nad.nadname))
}

func (nad *multihomingSharenetNAD) createMultihomingSharenetNAD(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", nad.template, "-p", "NAMESPACE="+nad.namespace, "NADNAME="+nad.nadname, "SUBNETS="+nad.subnets, "NSWITHNADNAME="+nad.nswithnadname, "EXCLUDESUBNETS="+nad.excludeSubnets, "TOPOLOGY="+nad.topology, "SHARENETNAME="+nad.sharenetname)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to net attach definition %v", nad.nadname))
}

func (pod *testMultihomingPod) createTestMultihomingPod(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplate(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "PODLABEL="+pod.podlabel, "NADNAME="+pod.nadname, "PODENVNAME="+pod.podenvname, "NODENAME="+pod.nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (pod *testMultihomingStaticPod) createTestMultihomingStaticPod(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplate(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "PODLABEL="+pod.podlabel, "NADNAME="+pod.nadname, "PODENVNAME="+pod.podenvname, "NODENAME="+pod.nodename, "MACADDRESS="+pod.macaddress, "IPADDRESS="+pod.ipaddress)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (ipBlock_ingress_policy *multihomingIPBlock) createMultihomingipBlockIngressObject(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_ingress_policy.template, "-p", "NAME="+ipBlock_ingress_policy.name, "NAMESPACE="+ipBlock_ingress_policy.namespace, "CIDR="+ipBlock_ingress_policy.cidr, "POLICYFOR="+ipBlock_ingress_policy.policyfor)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network policy %v", ipBlock_ingress_policy.name))
}

func checkOVNSwitch(oc *exutil.CLI, nad string, leaderPod string) bool {
	listSWCmd := "ovn-nbctl show | grep switch"
	listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", leaderPod, listSWCmd)
	o.Expect(listErr).NotTo(o.HaveOccurred())
	return strings.Contains(listOutput, nad)
}

func checkOVNRouter(oc *exutil.CLI, nad string, leaderPod string) bool {
	listSWCmd := "ovn-nbctl show | grep router"
	listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", leaderPod, listSWCmd)
	o.Expect(listErr).NotTo(o.HaveOccurred())
	return strings.Contains(listOutput, nad)
}

func checkNAD(oc *exutil.CLI, ns string, nad string) bool {
	nadOutput, nadOutputErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("net-attach-def", "-n", ns).Output()
	o.Expect(nadOutputErr).NotTo(o.HaveOccurred())
	return strings.Contains(nadOutput, nad)
}

func checkOVNswitchPorts(podName []string, outPut string) bool {
	result := true
	for _, pod := range podName {
		if !strings.Contains(outPut, pod) {
			result = false
		}
	}
	return result
}

func CurlMultusPod2PodPass(oc *exutil.CLI, namespaceSrc string, podNameSrc string, podIPDst string, outputInt string, podEnvName string) {
	output, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --interface "+outputInt+" --connect-timeout 5 -s "+net.JoinHostPort(podIPDst, "8080"))
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(strings.Contains(output, podEnvName)).To(o.BeTrue())
}

func CurlMultusPod2PodFail(oc *exutil.CLI, namespaceSrc string, podNameSrc string, podIPDst string, outputInt string, podEnvName string) {
	output, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --interface "+outputInt+" --connect-timeout 5 -s "+net.JoinHostPort(podIPDst, "8080"))
	o.Expect(err).To(o.HaveOccurred())
	o.Expect(strings.Contains(output, podEnvName)).NotTo(o.BeTrue())
}

// Using getPodMultiNetworks when pods consume multiple NADs
// Using getPodMultiNetwork when pods consume single NAD
func getPodMultiNetworks(oc *exutil.CLI, namespace string, podName string, netName string) (string, string) {
	cmd1 := "ip a sho " + netName + " | awk 'NR==3{print $2}' |grep -Eo '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'"
	cmd2 := "ip a sho " + netName + " | awk 'NR==5{print $2}' |grep -Eo '([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}'"
	podv4Output, err := e2eoutput.RunHostCmd(namespace, podName, cmd1)
	o.Expect(err).NotTo(o.HaveOccurred())
	podIPv4 := strings.TrimSpace(podv4Output)
	podv6Output, err1 := e2eoutput.RunHostCmd(namespace, podName, cmd2)
	o.Expect(err1).NotTo(o.HaveOccurred())
	podIPv6 := strings.TrimSpace(podv6Output)
	return podIPv4, podIPv6
}

func multihomingBeforeCheck(oc *exutil.CLI, topology string) ([]string, []string, []string, []string, string, string, string) {
	var (
		buildPruningBaseDir    = testdata.FixturePath("networking/multihoming")
		multihomingNADTemplate = filepath.Join(buildPruningBaseDir, "multihoming-NAD-template.yaml")
		multihomingPodTemplate = filepath.Join(buildPruningBaseDir, "multihoming-pod-template.yaml")
	)

	compat_otp.By("Get the ready-schedulable worker nodes")
	nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
	o.Expect(nodeErr).NotTo(o.HaveOccurred())
	if len(nodeList.Items) < 2 {
		g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
	}

	compat_otp.By("Create a test namespace")
	ns1 := oc.Namespace()

	nadName := "layer2dualstacknetwork"
	nsWithnad := ns1 + "/" + nadName

	compat_otp.By("Create a custom resource network-attach-defintion in tested namespace")
	nad1ns1 := multihomingNAD{
		namespace:      ns1,
		nadname:        nadName,
		subnets:        "192.168.100.0/24,fd00:dead:beef::0/64",
		nswithnadname:  nsWithnad,
		excludeSubnets: "",
		topology:       topology,
		template:       multihomingNADTemplate,
	}
	nad1ns1.createMultihomingNAD(oc)

	compat_otp.By("Create 1st pod consuming above network-attach-defintion in ns1")
	pod1 := testMultihomingPod{
		name:       "multihoming-pod-1",
		namespace:  ns1,
		podlabel:   "multihoming-pod1",
		nadname:    nadName,
		nodename:   nodeList.Items[0].Name,
		podenvname: "Hello multihoming-pod-1",
		template:   multihomingPodTemplate,
	}
	pod1.createTestMultihomingPod(oc)
	o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod1")).NotTo(o.HaveOccurred())

	compat_otp.By("Create 2nd pod consuming above network-attach-defintion in ns1")
	pod2 := testMultihomingPod{
		name:       "multihoming-pod-2",
		namespace:  ns1,
		podlabel:   "multihoming-pod2",
		nadname:    nadName,
		nodename:   nodeList.Items[0].Name,
		podenvname: "Hello multihoming-pod-2",
		template:   multihomingPodTemplate,
	}
	pod2.createTestMultihomingPod(oc)
	o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod2")).NotTo(o.HaveOccurred())

	compat_otp.By("Create 3rd pod consuming above network-attach-defintion in ns1")
	pod3 := testMultihomingPod{
		name:       "multihoming-pod-3",
		namespace:  ns1,
		podlabel:   "multihoming-pod3",
		nadname:    nadName,
		nodename:   nodeList.Items[1].Name,
		podenvname: "Hello multihoming-pod-3",
		template:   multihomingPodTemplate,
	}
	pod3.createTestMultihomingPod(oc)
	o.Expect(waitForPodWithLabelReady(oc, ns1, "name=multihoming-pod3")).NotTo(o.HaveOccurred())

	compat_otp.By("Get IPs from the pod1's secondary interface")
	pod1Name := getPodName(oc, ns1, "name=multihoming-pod1")
	pod1IPv4, pod1IPv6 := getPodMultiNetwork(ns1, pod1Name[0])
	e2e.Logf("The v4 address of pod1 is: %v", pod1IPv4, "net1", pod1.podenvname)
	e2e.Logf("The v6 address of pod1 is: %v", pod1IPv6, "net1", pod1.podenvname)

	compat_otp.By("Get IPs from the pod2's secondary interface")
	pod2Name := getPodName(oc, ns1, "name=multihoming-pod2")
	pod2IPv4, pod2IPv6 := getPodMultiNetwork(ns1, pod2Name[0])
	e2e.Logf("The v4 address of pod2 is: %v", pod2IPv4, "net1", pod2.podenvname)
	e2e.Logf("The v6 address of pod2 is: %v", pod2IPv6, "net1", pod2.podenvname)

	compat_otp.By("Get IPs from the pod3's secondary interface")
	pod3Name := getPodName(oc, ns1, "name=multihoming-pod3")
	pod3IPv4, pod3IPv6 := getPodMultiNetwork(ns1, pod3Name[0])
	e2e.Logf("The v4 address of pod3 is: %v", pod3IPv4, "net1", pod3.podenvname)
	e2e.Logf("The v6 address of pod3 is: %v", pod3IPv6, "net1", pod3.podenvname)

	ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
	o.Expect(ovnMasterPodName).ShouldNot(o.Equal(""))
	podName := []string{pod1Name[0], pod2Name[0], pod3Name[0]}

	compat_otp.By("Checking connectivity from pod1 to pod2")
	CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2IPv4, "net1", pod2.podenvname)
	CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod2IPv6, "net1", pod2.podenvname)

	compat_otp.By("Checking connectivity from pod1 to pod3")
	CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3IPv4, "net1", pod3.podenvname)
	CurlMultusPod2PodPass(oc, ns1, pod1Name[0], pod3IPv6, "net1", pod3.podenvname)

	compat_otp.By("Checking connectivity from pod2 to pod1")
	CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1IPv4, "net1", pod1.podenvname)
	CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod1IPv6, "net1", pod1.podenvname)

	compat_otp.By("Checking connectivity from pod2 to pod3")
	CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3IPv4, "net1", pod3.podenvname)
	CurlMultusPod2PodPass(oc, ns1, pod2Name[0], pod3IPv6, "net1", pod3.podenvname)

	compat_otp.By("Checking connectivity from pod3 to pod1")
	CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1IPv4, "net1", pod1.podenvname)
	CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod1IPv6, "net1", pod1.podenvname)

	compat_otp.By("Checking connectivity from pod3 to pod2")
	CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2IPv4, "net1", pod2.podenvname)
	CurlMultusPod2PodPass(oc, ns1, pod3Name[0], pod2IPv6, "net1", pod2.podenvname)

	podEnvName := []string{pod1.podenvname, pod2.podenvname, pod3.podenvname}
	podIPv4 := []string{pod1IPv4, pod2IPv4, pod3IPv4}
	podIPv6 := []string{pod1IPv6, pod2IPv6, pod3IPv6}
	return podName, podEnvName, podIPv4, podIPv6, ovnMasterPodName, ns1, nadName
}

func multihomingAfterCheck(oc *exutil.CLI, podName []string, podEnvName []string, podIPv4 []string, podIPv6 []string, ovnMasterPodName string, ns string, nadName string) {
	pod1Name := podName[0]
	pod2Name := podName[1]
	pod3Name := podName[2]
	pod1envname := podEnvName[0]
	pod2envname := podEnvName[1]
	pod3envname := podEnvName[2]
	pod1IPv4 := podIPv4[0]
	pod2IPv4 := podIPv4[1]
	pod3IPv4 := podIPv4[2]
	pod1IPv6 := podIPv6[0]
	pod2IPv6 := podIPv6[1]
	pod3IPv6 := podIPv6[2]

	compat_otp.By("Checking connectivity from pod to pod after deleting")
	CurlMultusPod2PodPass(oc, ns, pod1Name, pod2IPv4, "net1", pod2envname)
	CurlMultusPod2PodPass(oc, ns, pod1Name, pod2IPv6, "net1", pod2envname)
	CurlMultusPod2PodPass(oc, ns, pod1Name, pod3IPv4, "net1", pod3envname)
	CurlMultusPod2PodPass(oc, ns, pod1Name, pod3IPv6, "net1", pod3envname)
	CurlMultusPod2PodPass(oc, ns, pod2Name, pod1IPv4, "net1", pod1envname)
	CurlMultusPod2PodPass(oc, ns, pod2Name, pod1IPv6, "net1", pod1envname)
	CurlMultusPod2PodPass(oc, ns, pod2Name, pod3IPv4, "net1", pod3envname)
	CurlMultusPod2PodPass(oc, ns, pod2Name, pod3IPv6, "net1", pod3envname)
	CurlMultusPod2PodPass(oc, ns, pod3Name, pod1IPv4, "net1", pod1envname)
	CurlMultusPod2PodPass(oc, ns, pod3Name, pod1IPv6, "net1", pod1envname)
	CurlMultusPod2PodPass(oc, ns, pod3Name, pod2IPv4, "net1", pod2envname)
	CurlMultusPod2PodPass(oc, ns, pod3Name, pod2IPv6, "net1", pod2envname)
}

// This is for a negtive case which the pods can't be running using the wrong NAD
func getPodMultiNetworkFail(oc *exutil.CLI, namespace string, podName string) {
	cmd1 := "ip a sho net1 | awk 'NR==3{print $2}' |grep -Eo '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'"
	cmd2 := "ip a sho net1 | awk 'NR==5{print $2}' |grep -Eo '([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}'"
	_, ipv4Err := e2eoutput.RunHostCmd(namespace, podName, cmd1)
	o.Expect(ipv4Err).To(o.HaveOccurred())
	_, ipv6Err := e2eoutput.RunHostCmd(namespace, podName, cmd2)
	o.Expect(ipv6Err).To(o.HaveOccurred())
}

func (nad *dualstackNAD) createDualstackNAD(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", nad.template, "-p", "NADNAME="+nad.nadname, "NAMESPACE="+nad.namespace, "PLUGINTYPE="+nad.plugintype, "MODE="+nad.mode, "IPAMTYPE="+nad.ipamtype, "IPV4RANGE="+nad.ipv4range, "IPV6RANGE="+nad.ipv6range, "IPV4RANGESTART="+nad.ipv4rangestart, "IPV4RANGEEND="+nad.ipv4rangeend, "IPV6RANGESTART="+nad.ipv6rangestart, "IPV6RANGEEND="+nad.ipv6rangeend)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to net attach definition %v", nad.nadname))
}

func (nad *whereaboutsoverlappingIPNAD) createWhereaboutsoverlappingIPNAD(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", nad.template, "-p", "NADNAME="+nad.nadname, "NAMESPACE="+nad.namespace, "PLUGINTYPE="+nad.plugintype, "MODE="+nad.mode, "IPAMTYPE="+nad.ipamtype, "IPV4RANGE="+nad.ipv4range, "ENABLEOVERLAPPING="+strconv.FormatBool(nad.enableoverlapping), "NETWORKNAME="+nad.networkname)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create the net-attach-definition %v", nad.nadname))
}

func (pod *testMultusPod) createTestMultusPod(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplate(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "PODLABEL="+pod.podlabel, "NADNAME="+pod.nadname, "PODENVNAME="+pod.podenvname, "NODENAME="+pod.nodename, "REPLICAS="+pod.replicas)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (multinetworkipBlock_policy *multinetworkipBlockCIDRsDual) createMultinetworkipBlockCIDRDual(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", multinetworkipBlock_policy.template, "-p", "NAME="+multinetworkipBlock_policy.name, "NAMESPACE="+multinetworkipBlock_policy.namespace, "CIDRIPV6="+multinetworkipBlock_policy.cidrIpv6, "CIDRIPV4="+multinetworkipBlock_policy.cidrIpv4, "POLICYFOR="+multinetworkipBlock_policy.policyfor)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network policy %v", multinetworkipBlock_policy.name))
}

func createAndVerifyNAD(oc *exutil.CLI, ns string, nads []nadInfo) {
	for _, nad := range nads {
		compat_otp.By("Creating network-attachment-definition in the test namespace")
		err := oc.AsAdmin().Run("create").Args("-f", nad.filePath, "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verifying the configured network-attachment-definition")
		verifyNAD(oc, ns, nad.name)
	}
}

func (nad *bridgeCNINAD) createBridgeCNINAD(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(
			oc,
			"--ignore-unknown-parameters=true",
			"-f", nad.template,
			"-p", "NADNAME="+nad.nadname,
			"NAMESPACE="+nad.namespace,
			"PLUGINTYPE="+nad.plugintype,
			"IPAMTYPE="+nad.ipamtype,
			"IPV4RANGE="+nad.ipv4range,
			"IPV6RANGE="+nad.ipv6range,
			"IPV4RANGESTART="+nad.ipv4rangestart,
			"IPV4RANGEEND="+nad.ipv4rangeend,
			"IPV6RANGESTART="+nad.ipv6rangestart,
			"IPV6RANGEEND="+nad.ipv6rangeend,
			"PORTISOLATION="+nad.portisolation,
		)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network attachment definition %v", nad.nadname))
}

func verifyNAD(oc *exutil.CLI, ns string, nadname string) {
	compat_otp.By("Verifying the configured network-attachment-definition")
	verifyErr := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		if checkNAD(oc, ns, nadname) {
			return true, nil
		}
		e2e.Logf("Waiting for network-attachment-definition %s to be available...", nadname)
		return false, nil
	})
	if verifyErr != nil {
		e2e.Failf("The correct network-attachment-definition %v was not created due to %v!", nadname, verifyErr)
	}
	e2e.Logf("The correct network-attachment-definition: %v has been created due to %v!", nadname, verifyErr)
}
