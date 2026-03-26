package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

// struct for sriovnetworknodepolicy and sriovnetwork
type sriovNetResource struct {
	name      string
	namespace string
	tempfile  string
	kind      string
	ip        string
}

type sriovNetworkNodePolicy struct {
	policyName   string
	deviceType   string
	pfName       string
	deviceID     string
	vendor       string
	numVfs       int
	resourceName string
	template     string
	namespace    string
}

type sriovNetwork struct {
	name             string
	resourceName     string
	networkNamespace string
	template         string
	namespace        string
	spoolchk         string
	trust            string
	vlanId           int
	linkState        string
	minTxRate        int
	maxTxRate        int
	vlanQoS          int
}

type sriovTestPod struct {
	name        string
	namespace   string
	networkName string
	template    string
}

// struct for sriov pod
type sriovPod struct {
	name         string
	tempfile     string
	namespace    string
	ipv4addr     string
	ipv6addr     string
	intfname     string
	intfresource string
	pingip       string
}

// struct for using nncp to create VF on sriov node
type VFPolicyResource struct {
	name     string
	intfname string
	nodename string
	totalvfs int
	template string
}

type sriovNetworkNodePolicySpecificNode struct {
	policyName   string
	deviceType   string
	pfName       string
	numVfs       int
	resourceName string
	nodename     string
	namespace    string
	template     string
}

// struct for sriov pod with static or dynamic MAC address
type sriovTestPodMAC struct {
	name         string
	namespace    string
	ipaddr       string
	macaddr      string
	sriovnetname string
	tempfile     string
}

// delete sriov resource
func (rs *sriovNetResource) delete(oc *exutil.CLI) {
	e2e.Logf("delete %s %s in namespace %s", rs.kind, rs.name, rs.namespace)
	oc.AsAdmin().WithoutNamespace().Run("delete").Args(rs.kind, rs.name, "-n", rs.namespace).Execute()
}

// create sriov resource
func (rs *sriovNetResource) create(oc *exutil.CLI, parameters ...string) {
	var configFile string
	cmd := []string{"-f", rs.tempfile, "--ignore-unknown-parameters=true", "-p"}
	for _, para := range parameters {
		cmd = append(cmd, para)
	}
	e2e.Logf("parameters list is %s\n", cmd)
	err := wait.Poll(3*time.Second, 15*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().Run("process").Args(cmd...).OutputToFile(getRandomString() + "config.json")
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		configFile = output
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to process sriov resource %v", cmd))
	e2e.Logf("the file of resource is %s\n", configFile)

	_, err1 := oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", configFile, "-n", rs.namespace).Output()
	o.Expect(err1).NotTo(o.HaveOccurred())
}

// porcess sriov pod template and get a configuration file
func (pod *sriovPod) processPodTemplate(oc *exutil.CLI) string {
	var configFile string
	err := wait.Poll(3*time.Second, 15*time.Second, func() (bool, error) {
		parameters := fmt.Sprintf("-p PODNAME=%s, SRIOVNETNAME=%s, IPV4_ADDR=%s, IPV6_ADDR=%s", pod.name, pod.intfresource, pod.ipv4addr, pod.ipv6addr)

		if pod.pingip != "" {
			parameters += pod.pingip
		}

		output, err := oc.AsAdmin().Run("process").Args("-f", pod.tempfile, "--ignore-unknown-parameters=true", parameters, "-o=jsonpath={.items[0]}").OutputToFile(getRandomString() + "config.json")
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		configFile = output
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to process pod resource %v", pod.name))
	e2e.Logf("the file of resource is %s\n", configFile)
	return configFile
}

// create pod
func (pod *sriovPod) createPod(oc *exutil.CLI) string {
	configFile := pod.processPodTemplate(oc)
	podsLog, err1 := oc.AsAdmin().WithoutNamespace().Run("create").Args("--loglevel=10", "-f", configFile, "-n", pod.namespace).Output()
	o.Expect(err1).NotTo(o.HaveOccurred())
	return podsLog
}

// delete pod
func (pod *sriovPod) deletePod(oc *exutil.CLI) {
	e2e.Logf("delete pod %s in namespace %s", pod.name, pod.namespace)
	oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod.name, "-n", pod.namespace).Execute()
}

// check pods of openshift-sriov-network-operator are running
func chkSriovOperatorStatus(oc *exutil.CLI, ns string) {
	e2e.Logf("check if openshift-sriov-network-operator pods are running properly")
	chkPodsStatus(oc, ns, "app=network-resources-injector")
	chkPodsStatus(oc, ns, "app=operator-webhook")
	chkPodsStatus(oc, ns, "app=sriov-network-config-daemon")
	chkPodsStatus(oc, ns, "name=sriov-network-operator")

}

// check specified pods are running
func chkPodsStatus(oc *exutil.CLI, ns, lable string) {
	err := wait.Poll(10*time.Second, 5*time.Minute, func() (bool, error) {
		podsStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", ns, "-l", lable, "-o=jsonpath={.items[*].status.phase}").Output()
		if err != nil {
			return false, err
		}
		podsStatus = strings.TrimSpace(podsStatus)
		statusList := strings.Split(podsStatus, " ")
		for _, podStat := range statusList {
			if strings.Compare(podStat, "Running") != 0 {
				return false, nil
			}
		}
		e2e.Logf("All pods with lable %s in namespace %s are Running", lable, ns)
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("pod with label %s in namespace %v does not running", lable, ns))

}

// clear specified sriovnetworknodepolicy
func rmSriovNetworkPolicy(oc *exutil.CLI, policyname, ns string) {
	_, err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("SriovNetworkNodePolicy", policyname, "-n", ns, "--ignore-not-found").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("remove sriovnetworknodepolicy %s", policyname)
	waitForSriovPolicyReady(oc, ns)
}

// clear specified sriovnetwork
func rmSriovNetwork(oc *exutil.CLI, netname, ns string) {
	sriovNetList, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("SriovNetwork", "-n", ns).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(sriovNetList, netname) {
		_, err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("SriovNetwork", netname, "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// Wait for Pod ready
func (pod *sriovPod) waitForPodReady(oc *exutil.CLI) {
	res := false
	err := wait.Poll(5*time.Second, 15*time.Minute, func() (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod.name, "-n", pod.namespace, "-o=jsonpath={.status.phase}").Output()
		e2e.Logf("the status of pod is %s", status)
		if strings.Contains(status, "NotFound") {
			e2e.Logf("the pod was created fail.")
			res = false
			return true, nil
		}
		if err != nil {
			e2e.Logf("failed to get pod status: %v, retrying...", err)
			return false, nil
		}
		if strings.Contains(status, "Running") {
			e2e.Logf("the pod is Ready.")
			res = true
			return true, nil
		}
		return false, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("sriov pod %v is not ready", pod.name))
	o.Expect(res).To(o.Equal(true))
}

// Wait for sriov network policy ready
func waitForSriovPolicyReady(oc *exutil.CLI, ns string) {
	err := wait.Poll(10*time.Second, 30*time.Minute, func() (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("sriovnetworknodestates", "-n", ns, "-o=jsonpath={.items[*].status.syncStatus}").Output()
		e2e.Logf("the status of sriov policy is %v", status)
		if err != nil {
			e2e.Logf("failed to get sriov policy status: %v, retrying...", err)
			return false, nil
		}
		nodesStatus := strings.TrimSpace(status)
		statusList := strings.Split(nodesStatus, " ")
		for _, nodeStat := range statusList {
			if nodeStat != "Succeeded" {
				e2e.Logf("nodes sync up not ready yet: %v, retrying...", err)
				return false, nil
			}
		}
		e2e.Logf("nodes sync up ready now")
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, "sriovnetworknodestates is not ready")
}

// check interface on pod
func (pod *sriovPod) getSriovIntfonPod(oc *exutil.CLI) string {
	msg, err := oc.WithoutNamespace().AsAdmin().Run("exec").Args(pod.name, "-n", pod.namespace, "-i", "--", "ip", "address").Output()
	if err != nil {
		e2e.Logf("Execute ip address command failed with  err:%v .", err)
	}
	e2e.Logf("Get ip address info as:%v", msg)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(msg).NotTo(o.BeEmpty())
	return msg
}

// create pod via HTTP request
func (pod *sriovPod) sendHTTPRequest(oc *exutil.CLI, user, cmd string) {
	//generate token for service acount
	testToken, err := oc.AsAdmin().WithoutNamespace().Run("sa").Args("get-token", user, "-n", pod.namespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(testToken).NotTo(o.BeEmpty())

	configFile := pod.processPodTemplate(oc)

	curlCmd := cmd + " -k " + " -H " + fmt.Sprintf("\"Authorization: Bearer %v\"", testToken) + " -d " + "@" + configFile

	e2e.Logf("Send curl request to create new pod: %s\n", curlCmd)

	res, err := exec.Command("bash", "-c", curlCmd).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(res).NotTo(o.BeEmpty())

}
func (sriovPolicy *sriovNetworkNodePolicy) createPolicy(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", sriovPolicy.template, "-p", "NAMESPACE="+sriovPolicy.namespace, "DEVICEID="+sriovPolicy.deviceID, "SRIOVNETPOLICY="+sriovPolicy.policyName, "DEVICETYPE="+sriovPolicy.deviceType, "PFNAME="+sriovPolicy.pfName, "VENDOR="+sriovPolicy.vendor, "NUMVFS="+strconv.Itoa(sriovPolicy.numVfs), "RESOURCENAME="+sriovPolicy.resourceName)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create sriovnetworknodePolicy %v", sriovPolicy.policyName))
}

func (sriovNetwork *sriovNetwork) createSriovNetwork(oc *exutil.CLI) {
	err := wait.Poll(2*time.Second, 20*time.Second, func() (bool, error) {
		if sriovNetwork.spoolchk == "" {
			sriovNetwork.spoolchk = "off"
		}
		if sriovNetwork.trust == "" {
			sriovNetwork.trust = "on"
		}
		if sriovNetwork.linkState == "" {
			sriovNetwork.linkState = "auto"
		}
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", sriovNetwork.template, "-p", "NAMESPACE="+sriovNetwork.namespace, "SRIOVNETNAME="+sriovNetwork.name, "TARGETNS="+sriovNetwork.networkNamespace, "SRIOVNETPOLICY="+sriovNetwork.resourceName, "SPOOFCHK="+sriovNetwork.spoolchk, "TRUST="+sriovNetwork.trust, "LINKSTATE="+sriovNetwork.linkState, "MINTXRATE="+strconv.Itoa(sriovNetwork.minTxRate), "MAXTXRATE="+strconv.Itoa(sriovNetwork.maxTxRate), "VLANID="+strconv.Itoa(sriovNetwork.vlanId), "VLANQOS="+strconv.Itoa(sriovNetwork.vlanQoS))
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create sriovnetwork %v", sriovNetwork.name))
}

func (sriovTestPod *sriovTestPod) createSriovTestPod(oc *exutil.CLI) {
	err := wait.Poll(2*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", sriovTestPod.template, "-p", "PODNAME="+sriovTestPod.name, "SRIOVNETNAME="+sriovTestPod.networkName, "NAMESPACE="+sriovTestPod.namespace)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create test pod %v", sriovTestPod.name))
}

// get the pciAddress pod is used
func getPciAddress(namespace string, podName string, policyName string) string {
	pciAddress, err := e2eoutput.RunHostCmdWithRetries(namespace, podName, "printenv PCIDEVICE_OPENSHIFT_IO_"+strings.ToUpper(policyName), 3*time.Second, 30*time.Second)
	e2e.Logf("Get the pci address env is: %s", pciAddress)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(pciAddress).NotTo(o.BeEmpty())
	return strings.TrimSuffix(pciAddress, "\n")
}

// Get the sriov worker which the policy is used
func getSriovNode(oc *exutil.CLI, namespace string, label string) string {
	sriovNodeName := ""
	nodeNamesAll, err := oc.AsAdmin().Run("get").Args("-n", namespace, "node", "-l", label, "-ojsonpath={.items..metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	nodeNames := strings.Split(nodeNamesAll, " ")
	for _, nodeName := range nodeNames {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("sriovnetworknodestates", nodeName, "-n", namespace, "-ojsonpath={.spec.interfaces}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if output != "" {
			sriovNodeName = nodeName
			break
		}
	}
	e2e.Logf("The sriov node is  %v ", sriovNodeName)
	o.Expect(sriovNodeName).NotTo(o.BeEmpty())
	return sriovNodeName
}

// checkDeviceIDExist will check the worker node contain the network card according to deviceID
func checkDeviceIDExist(oc *exutil.CLI, namespace string, deviceID string) bool {
	allDeviceID, err := oc.AsAdmin().Run("get").Args("sriovnetworknodestates", "-n", namespace, "-ojsonpath={.items[*].status.interfaces[*].deviceID}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("tested deviceID is %v and all supported deviceID on node are %v ", deviceID, allDeviceID)
	return strings.Contains(allDeviceID, deviceID)
}

// Wait for sriov network policy ready
func (rs *sriovNetResource) chkSriovPolicy(oc *exutil.CLI) bool {
	sriovPolicyList, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("SriovNetworkNodePolicy", "-n", rs.namespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if !strings.Contains(sriovPolicyList, rs.name) {
		return false
	}
	return true
}

// Wait for nodes starting to sync up for sriov policy
func waitForSriovPolicySyncUpStart(oc *exutil.CLI, ns string) {
	err := wait.Poll(5*time.Second, 3*time.Minute, func() (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("sriovnetworknodestates", "-n", ns, "-o=jsonpath={.items[*].status.syncStatus}").Output()
		e2e.Logf("the status of sriov policy is %s", status)
		if err != nil {
			e2e.Logf("failed to get sriov policy status: %v, retrying...", err)
			return false, nil
		}
		nodesStatus := strings.TrimSpace(status)
		statusList := strings.Split(nodesStatus, " ")
		for _, nodeStat := range statusList {
			if nodeStat == "InProgress" {
				e2e.Logf("nodes start to sync up ...", err)
				return true, nil
			}
		}
		e2e.Logf("nodes sync up hasn't started yet ...")
		return false, nil
	})
	compat_otp.AssertWaitPollNoErr(err, "sriovnetworknodestates sync up is in progress")
}

func getOperatorVersion(oc *exutil.CLI, subname string, ns string) string {
	csvName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("sub", subname, "-n", ns, "-o=jsonpath={.status.currentCSV}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(csvName).NotTo(o.BeEmpty())
	e2e.Logf("operator version is %s", csvName)
	return csvName
}

// find the node name which is in scheduleDisableNode
func findSchedulingDisabledNode(oc *exutil.CLI, interval, timeout time.Duration, label string) string {
	scheduleDisableNodeName := ""
	errNode := wait.PollUntilContextTimeout(context.TODO(), interval, timeout, false, func(ctx context.Context) (bool, error) {
		nodeNamesAll, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", label, "-ojsonpath={.items..metadata.name}").Output()
		if err != nil {
			return false, nil
		}
		nodeNames := strings.Split(nodeNamesAll, " ")
		for _, nodeName := range nodeNames {
			nodeOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName).Output()
			if err == nil {
				if strings.Contains(nodeOutput, "NotReady") || strings.Contains(nodeOutput, "SchedulingDisabled") {
					scheduleDisableNodeName = nodeName
					break
				}
			}
		}
		if scheduleDisableNodeName == "" {
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(errNode, fmt.Sprintf("no node become SchedulingDisabled or Notready!"))
	return scheduleDisableNodeName
}

func chkVFStatusMatch(oc *exutil.CLI, nodeName, nicName, macAddress, expectVaule string) {
	cmd := fmt.Sprintf("ip link show %s | grep %s", nicName, macAddress)
	output, debugNodeErr := compat_otp.DebugNode(oc, nodeName, "bash", "-c", cmd)
	e2e.Logf("The ip link show. \n %v", output)
	o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
	o.Expect(strings.Contains(output, expectVaule)).To(o.BeTrue())
}

func initVF(oc *exutil.CLI, name, deviceID, interfaceName, vendor, ns string, vfNum int) bool {
	buildPruningBaseDir := testdata.FixturePath("networking/sriov")
	sriovNetworkNodePolicyTemplate := filepath.Join(buildPruningBaseDir, "sriovnetworkpolicy-template.yaml")
	sriovPolicy := sriovNetworkNodePolicy{
		policyName:   name,
		deviceType:   "netdevice",
		deviceID:     deviceID,
		pfName:       interfaceName,
		vendor:       vendor,
		numVfs:       vfNum,
		resourceName: name,
		template:     sriovNetworkNodePolicyTemplate,
		namespace:    ns,
	}

	compat_otp.By("Check the deviceID if exist on the cluster worker")
	e2e.Logf("Create VF on name: %s, deviceID: %s, interfacename: %s, vendor: %s", name, deviceID, interfaceName, vendor)
	if !chkPfExist(oc, deviceID, interfaceName) {
		e2e.Logf("the cluster do not contain the sriov card. skip this testing!")
		return false
	}
	//defer rmSriovNetworkPolicy(oc, sriovPolicy.policyName, sriovOpNs)
	sriovPolicy.createPolicy(oc)
	waitForSriovPolicyReady(oc, ns)
	return true
}

func initDpdkVF(oc *exutil.CLI, name, deviceID, interfaceName, vendor, ns string, vfNum int) bool {
	deviceType := "vfio-pci"
	buildPruningBaseDir := testdata.FixturePath("networking/sriov")
	sriovNetworkNodePolicyTemplate := filepath.Join(buildPruningBaseDir, "sriovnetworkpolicy-template.yaml")
	if vendor == "15b3" {
		deviceType = "netdevice"
		sriovNetworkNodePolicyTemplate = filepath.Join(buildPruningBaseDir, "sriovnetworkpolicy-mlx-dpdk-template.yaml")
	}
	sriovPolicy := sriovNetworkNodePolicy{
		policyName:   name,
		deviceType:   deviceType,
		deviceID:     deviceID,
		pfName:       interfaceName,
		vendor:       vendor,
		numVfs:       vfNum,
		resourceName: name,
		template:     sriovNetworkNodePolicyTemplate,
		namespace:    ns,
	}

	compat_otp.By("Check the deviceID if exist on the cluster worker")
	e2e.Logf("Create VF on name: %s, deviceID: %s, interfacename: %s, vendor: %s", name, deviceID, interfaceName, vendor)
	if !chkPfExist(oc, deviceID, interfaceName) {
		e2e.Logf("the cluster do not contain the sriov card. skip this testing!")
		return false
	}
	// create dpdk policy
	sriovPolicy.createPolicy(oc)
	waitForSriovPolicyReady(oc, ns)
	return true
}

func chkVFStatusWithPassTraffic(oc *exutil.CLI, nadName, nicName, ns, expectVaule string) {
	buildPruningBaseDir := testdata.FixturePath("networking/sriov")
	sriovTestPodTemplate := filepath.Join(buildPruningBaseDir, "sriov-netdevice-template.yaml")
	compat_otp.By("Create test pod on the target namespace")
	for i := 0; i < 2; i++ {
		sriovTestPod := sriovTestPod{
			name:        "testpod" + strconv.Itoa(i),
			namespace:   ns,
			networkName: nadName,
			template:    sriovTestPodTemplate,
		}
		sriovTestPod.createSriovTestPod(oc)
		err := waitForPodWithLabelReady(oc, ns, "name=sriov-netdevice")
		compat_otp.AssertWaitPollNoErr(err, "this pod with label name=sriov-netdevice not ready")
		if strings.Contains(expectVaule, "mtu") {
			mtucheck, err := e2eoutput.RunHostCmdWithRetries(ns, sriovTestPod.name, "ip addr show net1", 3*time.Second, 30*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(mtucheck, expectVaule)).To(o.BeTrue())
		} else {
			nodeName, nodeNameErr := compat_otp.GetPodNodeName(oc, ns, sriovTestPod.name)
			o.Expect(nodeNameErr).NotTo(o.HaveOccurred())
			podMac := getInterfaceMac(ns, sriovTestPod.name, "net1")
			chkVFStatusMatch(oc, nodeName, nicName, podMac, expectVaule)
		}
	}
	chkPodsPassTraffic(oc, "testpod0", "testpod1", "net1", ns)
}

func chkPodsPassTraffic(oc *exutil.CLI, pod1name string, pod2name string, infName string, ns string) {
	compat_otp.By("Check the interface is connected, if not skip the connect testing")
	cmd := "ip addr show " + infName
	podConnectStatus1, err1 := e2eoutput.RunHostCmdWithRetries(ns, pod1name, cmd, 3*time.Second, 30*time.Second)
	o.Expect(err1).NotTo(o.HaveOccurred())
	podConnectStatus2, err2 := e2eoutput.RunHostCmdWithRetries(ns, pod2name, cmd, 3*time.Second, 30*time.Second)
	o.Expect(err2).NotTo(o.HaveOccurred())

	e2e.Logf("The ip connection of %v show: \n %v", pod1name, podConnectStatus1)
	e2e.Logf("The ip connection of %v show: \n %v", pod2name, podConnectStatus2)
	//if podConnectStatus including NO-CARRIER, then skip the connection testing
	if !strings.Contains(podConnectStatus1, "NO-CARRIER") && !strings.Contains(podConnectStatus2, "NO-CARRIER") {
		compat_otp.By("Get destination Pod's IP on secondary interface")
		cmd = "ip addr show dev " + infName + " | grep global"
		net1Output, _ := e2eoutput.RunHostCmdWithRetries(ns, pod2name, cmd, 3*time.Second, 30*time.Second)
		net1Output = strings.TrimSpace(net1Output)

		// Match our IPv4 and IPv6 address on net1 ip address output
		rev4 := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
		ipv4Addresses := rev4.FindAllString(net1Output, -1)
		rev6 := regexp.MustCompile(`inet6\s+([0-9a-fA-F:]{2,39})(?:/\d{1,3})?`)
		ipv6Addresses := rev6.FindAllStringSubmatch(net1Output, -1)
		for _, match := range ipv6Addresses {
			if len(match) > 1 {
				ipv6Address := match[1]
				e2e.Logf("\n destination pod %s net1 IPv6 address: %s\n", pod2name, ipv6Address)
				CurlMultusPod2PodPass(oc, ns, pod1name, ipv6Address, infName, "Hello")
			}
		}

		e2e.Logf("\n destination pod %s net1 IPv4 address: %s\n", pod2name, ipv4Addresses)
		if len(ipv4Addresses) != 0 {
			CurlMultusPod2PodPass(oc, ns, pod1name, ipv4Addresses[0], infName, "Hello")
		}

	}

}

func (sriovTestPod *sriovTestPod) deleteSriovTestPod(oc *exutil.CLI) {
	e2e.Logf("delete pod %s in namespace %s", sriovTestPod.name, sriovTestPod.namespace)
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", sriovTestPod.name, "-n", sriovTestPod.namespace).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())

}

func createNumPods(oc *exutil.CLI, nadName, ns, podPrex string, numPods int) {
	buildPruningBaseDir := testdata.FixturePath("networking/sriov")
	sriovTestPodTemplate := filepath.Join(buildPruningBaseDir, "sriov-netdevice-template.yaml")
	compat_otp.By("Create test pod on the target namespace")
	for i := 0; i < numPods; i++ {
		sriovTestPod := sriovTestPod{
			name:        podPrex + strconv.Itoa(i),
			namespace:   ns,
			networkName: nadName,
			template:    sriovTestPodTemplate,
		}
		sriovTestPod.createSriovTestPod(oc)
	}
	err := waitForPodWithLabelReady(oc, ns, "name=sriov-netdevice")
	compat_otp.AssertWaitPollNoErr(err, "pods with label name=sriov-netdevice not ready")

	e2e.Logf("Have successfully created %v pods", numPods)
}

// get worker nodes which have sriov enabled.
func getSriovWokerNodes(oc *exutil.CLI) []string {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "feature.node.kubernetes.io/sriov-capable=true",
		"-o=jsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	nodeNameList := strings.Fields(output)
	return nodeNameList
}

// get worker node which has required PF
func getWorkerNodesWithNic(oc *exutil.CLI, deviceid string, pfname string) []string {
	workerWithNicList := []string{}
	nodeNameList := getSriovWokerNodes(oc)
	e2e.Logf("print all worker nodes %v", nodeNameList)
	for _, workerNode := range nodeNameList {
		output, checkNicErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("sriovnetworknodestates.sriovnetwork.openshift.io", workerNode,
			"-n", "openshift-sriov-network-operator", "-o=jsonpath={.status.interfaces}").Output()
		o.Expect(checkNicErr).NotTo(o.HaveOccurred())
		nicList := strings.Split(output, "}")
		for _, nicInfo := range nicList {
			// at least one worker node should have required PF.
			re1 := regexp.MustCompile(`\"` + pfname + `\"`)
			re2 := regexp.MustCompile(`\"deviceID\":\"` + deviceid + `\"`)
			if re1.MatchString(nicInfo) && re2.MatchString(nicInfo) {
				e2e.Logf("on worker node %v, find PF %v!!", workerNode, pfname)
				workerWithNicList = append(workerWithNicList, workerNode)
			}
		}
		e2e.Logf("The worker list which has device id %v, pfname %v is %v", deviceid, pfname, workerWithNicList)
	}
	return workerWithNicList
}

// check if required pf exist on workers
func chkPfExist(oc *exutil.CLI, deviceid string, pfname string) bool {
	res := true
	workerList := getWorkerNodesWithNic(oc, deviceid, pfname)
	if len(workerList) == 0 {
		e2e.Logf("The worker nodes don't have the required PF %v with DeviceID %v", pfname, deviceid)
		res = false
	}
	return res
}

func chkNAD(oc *exutil.CLI, ns string, name string, expected bool) error {
	return wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("net-attach-def", "-n", ns, "-o=jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("the NAD list in ns %v is %v", ns, output)
		if expected && !strings.Contains(output, name) {
			e2e.Logf("Can not get NAD, got err:%v, and try next round", err)
			return false, nil
		}
		if !expected && strings.Contains(output, name) {
			e2e.Logf("NAD has not beem removed, try again")
			return false, nil
		}
		return true, nil
	})
}

func rmNAD(oc *exutil.CLI, ns string, name string) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("net-attach-def", "-n", ns, name).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.BeEmpty())
	e2e.Logf("the NAD %v is removed", name)
}

func setSriovWebhook(oc *exutil.CLI, status string) {
	//enable webhook
	var patchYamlToRestore string
	if status == "true" {
		patchYamlToRestore = `[{"op":"replace","path":"/spec/enableOperatorWebhook","value": true}]`
	} else if status == "false" {
		patchYamlToRestore = `[{"op":"replace","path":"/spec/enableOperatorWebhook","value": false}]`
	}

	output, err1 := oc.AsAdmin().WithoutNamespace().Run("patch").Args("sriovoperatorconfigs", "default", "-n", "openshift-sriov-network-operator",
		"--type=json", "-p", patchYamlToRestore).Output()
	e2e.Logf("patch result is %v", output)
	o.Expect(err1).NotTo(o.HaveOccurred())
	matchStr := "sriovoperatorconfig.sriovnetwork.openshift.io/default patched"
	o.Expect(output).Should(o.ContainSubstring(matchStr))

	// check webhook is set correctly
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("sriovoperatorconfigs", "default", "-n", "openshift-sriov-network-operator", "-o=jsonpath={.spec.enableOperatorWebhook}").Output()
	e2e.Logf("the status of sriov webhook is %v", output)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).Should(o.ContainSubstring(status))

}

func chkSriovWebhookResource(oc *exutil.CLI, status bool) {

	output1, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", "operator-webhook", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output1)
	output2, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("sa", "operator-webhook-sa", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output2)
	output3, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("svc", "operator-webhook-service", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output3)
	output4, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterrole", "operator-webhook", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output4)
	output5, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("MutatingWebhookConfiguration", "sriov-operator-webhook-config", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output5)
	output6, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterrolebinding", "operator-webhook-role-binding ", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output6)

	if status == true {
		o.Expect(output1).Should(o.ContainSubstring("operator-webhook"))
		o.Expect(output2).Should(o.ContainSubstring("operator-webhook"))
		o.Expect(output3).Should(o.ContainSubstring("operator-webhook"))
		o.Expect(output4).Should(o.ContainSubstring("operator-webhook"))
		o.Expect(output5).Should(o.ContainSubstring("operator-webhook"))
		o.Expect(output6).Should(o.ContainSubstring("operator-webhook"))
	} else {
		o.Expect(output1).Should(o.ContainSubstring("not found"))
		o.Expect(output2).Should(o.ContainSubstring("not found"))
		o.Expect(output3).Should(o.ContainSubstring("not found"))
		o.Expect(output4).Should(o.ContainSubstring("not found"))
		o.Expect(output5).Should(o.ContainSubstring("not found"))
		o.Expect(output6).Should(o.ContainSubstring("not found"))
	}

}

func setSriovInjector(oc *exutil.CLI, status string) {
	//enable sriov resource injector
	var patchYamlToRestore string
	if status == "true" {
		patchYamlToRestore = `[{"op":"replace","path":"/spec/enableInjector","value": true}]`
	} else if status == "false" {
		patchYamlToRestore = `[{"op":"replace","path":"/spec/enableInjector","value": false}]`
	}

	output, err1 := oc.AsAdmin().WithoutNamespace().Run("patch").Args("sriovoperatorconfigs", "default", "-n", "openshift-sriov-network-operator",
		"--type=json", "-p", patchYamlToRestore).Output()
	e2e.Logf("patch result is %v", output)
	o.Expect(err1).NotTo(o.HaveOccurred())
	matchStr := "sriovoperatorconfig.sriovnetwork.openshift.io/default patched"
	o.Expect(output).Should(o.ContainSubstring(matchStr))

	// check injector is set correctly
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("sriovoperatorconfigs", "default", "-n", "openshift-sriov-network-operator", "-o=jsonpath={.spec.enableInjector}").Output()
	e2e.Logf("the status of sriov resource injector is %v", output)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).Should(o.ContainSubstring(status))

}

func chkSriovInjectorResource(oc *exutil.CLI, status bool) {
	output1, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", "network-resources-injector", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output1)
	output2, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("sa", "network-resources-injector-sa", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output2)
	output3, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("svc", "network-resources-injector-service", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output3)
	output4, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterrole", "network-resources-injector", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output4)
	output5, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("MutatingWebhookConfiguration", "network-resources-injector-config", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output5)
	output6, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterrolebinding", "network-resources-injector-role-binding", "-n", "openshift-sriov-network-operator").Output()
	e2e.Logf("the result of output is %v", output6)

	if status == true {
		o.Expect(output1).Should(o.ContainSubstring("network-resources-injector"))
		o.Expect(output2).Should(o.ContainSubstring("network-resources-injector"))
		o.Expect(output3).Should(o.ContainSubstring("network-resources-injector"))
		o.Expect(output4).Should(o.ContainSubstring("network-resources-injector"))
		o.Expect(output5).Should(o.ContainSubstring("network-resources-injector"))
		o.Expect(output6).Should(o.ContainSubstring("network-resources-injector"))
	} else {
		o.Expect(output1).Should(o.ContainSubstring("not found"))
		o.Expect(output2).Should(o.ContainSubstring("not found"))
		o.Expect(output3).Should(o.ContainSubstring("not found"))
		o.Expect(output4).Should(o.ContainSubstring("not found"))
		o.Expect(output5).Should(o.ContainSubstring("not found"))
		o.Expect(output6).Should(o.ContainSubstring("not found"))
	}

}

func pingPassWithNet1(ns1, pod1, pod2 string) {
	pod1IPv4, _ := getPodMultiNetwork(ns1, pod1)
	e2e.Logf("The second interface v4 address of pod1 is: %v", pod1IPv4)
	command := fmt.Sprintf("ping -c 3 %s", pod1IPv4)
	pingOutput, err := e2eoutput.RunHostCmdWithRetries(ns1, pod2, command, 3*time.Second, 12*time.Second)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("ping output: %v", pingOutput)
	o.Expect(strings.Count(pingOutput, "3 received")).To(o.Equal(1))
}

// get the Mac address from one pod interface
func getInterfaceMac(namespace, podName, interfaceName string) string {
	command := fmt.Sprintf("ip link show %s | awk '/link\\/ether/ {print $2}'", interfaceName)
	podInterfaceMac, err := e2eoutput.RunHostCmdWithRetries(namespace, podName, command, 3*time.Second, 30*time.Second)
	o.Expect(err).NotTo(o.HaveOccurred())
	podInterfaceMac = strings.TrimSpace(podInterfaceMac)
	return podInterfaceMac
}

// get the catlogsource name
func getOperatorSource(oc *exutil.CLI, namespace string) string {
	if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "OperatorLifecycleManager")) {
		g.Skip("Skipping the test as baselinecaps have been set and OperatorLifecycleManager capability is not enabled!")
	}
	catalogSourceNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("catalogsource", "-n", namespace, "-o=jsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(catalogSourceNames, "qe-app-registry") {
		return "qe-app-registry"
	} else if strings.Contains(catalogSourceNames, "redhat-operators") {
		return "redhat-operators"
	} else {
		return ""
	}
}

// check if interface is not connected with CARRIER
func checkInterfaceNoCarrier(oc *exutil.CLI, nodeName string, interfaceName string) bool {
	var output string
	var err error
	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		output, err = compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", "/usr/sbin/ip address show dev "+interfaceName)
		if output == "" || err != nil {
			e2e.Logf("Did not get node's management interface, errors: %v, try again", err)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("fail to check if interface %s on node %s has carrier, err: %v", interfaceName, nodeName, checkErr))
	return strings.Contains(output, "NO-CARRIER")
}

// Create VF policy through NMstate
func (vfpolicy *VFPolicyResource) createVFPolicy(oc *exutil.CLI) error {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", vfpolicy.template, "-p", "NAME="+vfpolicy.name, "INTFNAME="+vfpolicy.intfname, "NODENAME="+vfpolicy.nodename, "TOTALVFS="+strconv.Itoa(int(vfpolicy.totalvfs)))
		if err1 != nil {
			e2e.Logf("Creating VF on sriov node failed :%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("fail to VF on sriov node %v", vfpolicy.name)
	}
	return nil
}

// Create SRIOVNetworkNodePolicy on specific node
func (sriovNNPolicy *sriovNetworkNodePolicySpecificNode) createPolicySpecificNode(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", sriovNNPolicy.template, "-p", "NAMESPACE="+sriovNNPolicy.namespace, "SRIOVNETPOLICY="+sriovNNPolicy.policyName, "DEVICETYPE="+sriovNNPolicy.deviceType, "PFNAME="+sriovNNPolicy.pfName, "NUMVFS="+strconv.Itoa(sriovNNPolicy.numVfs), "RESOURCENAME="+sriovNNPolicy.resourceName, "NODENAME="+sriovNNPolicy.nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create sriovnetworknodePolicy %v", sriovNNPolicy.policyName))
}

// Create SRIOV test pod with MAC address
func (sriovTestPod *sriovTestPodMAC) createSriovTestPodMAC(oc *exutil.CLI) {
	err := wait.Poll(2*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", sriovTestPod.tempfile, "-p", "PODNAME="+sriovTestPod.name, "SRIOVNETNAME="+sriovTestPod.sriovnetname, "TARGETNS="+sriovTestPod.namespace, "IP_ADDR="+sriovTestPod.ipaddr, "MAC_ADDR="+sriovTestPod.macaddr)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create test pod %v", sriovTestPod.name))
}

// uninstall SRIOV operator, but leave SriovNetworkPoolConfig and openshift-sriov-network-operator namespace behind so offload cases are not impacted
func uninstallSriovOperator(oc *exutil.CLI, namespace string) {

	// Delete SRIOV network related config except SriovNetworkPoolConfig, subscription, CSV, and DS under openshift-sriov-network-operator namespace
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("sriovnetwork", "--all", "-n", namespace, "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting sirovnetwork")
	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("sriovnetworknodepolicy", "--all", "-n", namespace, "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting sirovnetworknodepolicy")

	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("subscription", "--all", "-n", namespace, "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting subscription under openshift-sriov-network-operator namespace")
	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("csv", "--all", "-n", namespace).Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting CSV under openshift-sriov-network-operator namespace")
	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("ds", "--all", "-n", namespace, "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting DS under openshift-sriov-network-operator namespace")
	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("deployment", "sriov-network-operator", "-n", namespace, "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting deployment/sriov-network-operator under openshift-sriov-network-operator namespace")

	// Verify SRIOV network related config, subscription, CSV, and DS under openshift-sriov-network-operator namespace are removed
	sriovconfigs := [6]string{"sriovnetwork", "sriovnetworknodepolicy", "subscription", "csv", "ds", "deployment"}
	for _, config := range sriovconfigs {
		sriovChkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 90*time.Second, false, func(cxt context.Context) (bool, error) {
			output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args(config, "-n", namespace).Output()
			e2e.Logf("\n output after deleting %s: %s\n", config, output)
			if strings.Contains(output, "not found") || strings.Contains(output, "No resources found") {
				e2e.Logf("mutatingwebhookconfigs %s is delete successfully", config)
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(sriovChkErr, fmt.Sprintf("Failed to delete resource %s", config))
	}

	// Delete SRIOV related CRD under openshift-sriov-network-operator namespace
	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("crd", "sriovibnetworks.sriovnetwork.openshift.io "+
		"sriovnetworknodepolicies.sriovnetwork.openshift.io "+
		"sriovnetworknodestates.sriovnetwork.openshift.io "+
		"sriovnetworkpoolconfigs.sriovnetwork.openshift.io "+
		"sriovnetworks.sriovnetwork.openshift.io "+
		"sriovoperatorconfigs.sriovnetwork.openshift.io", "-n", namespace, "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting SRIOV related CRD")

	// Verify SRIOV related CRD under openshift-sriov-network-operator namespace are removed
	chkOutput, _ := exec.Command("bash", "-c", "oc crd | grep sriov").Output()
	o.Expect(string(chkOutput)).Should(o.BeEmpty(), "Not all SRIOV CRD were removed")

	// Delete webhook related configurations
	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("mutatingwebhookconfigurations", "network-resources-injector-config", "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting network-resources-injector-config")
	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("MutatingWebhookConfiguration", "sriov-operator-webhook-config", "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting MutatingWebhookConfiguration sriov-operator-webhook-config")
	err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("ValidatingWebhookConfiguration", "sriov-operator-webhook-config", "--ignore-not-found").Execute()
	compat_otp.AssertWaitPollNoErr(err, "Got error when deleting ValidatingWebhookConfiguration sriov-operator-webhook-config")

	// Verify webhook related configurations are removed
	mutatingwebhookconfigs := [2]string{"network-resources-injector-config", "sriov-operator-webhook-config"}
	for _, config := range mutatingwebhookconfigs {
		sriovChkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 90*time.Second, false, func(cxt context.Context) (bool, error) {
			output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("mutatingwebhookconfigurations", config).Output()
			e2e.Logf("\n output after deleting %s: %s\n", config, output)
			if strings.Contains(output, "not found") || strings.Contains(output, "No resources found") {
				e2e.Logf("mutatingwebhookconfigs %s is delete successfully", config)
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(sriovChkErr, fmt.Sprintf("Failed to delete resource %s", config))
	}

	sriovChkErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 90*time.Second, false, func(cxt context.Context) (bool, error) {
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("ValidatingWebhookConfiguration", "sriov-operator-webhook-config").Output()
		e2e.Logf("\n\n\n output after deleting ValidatingWebhookConfiguration sriov-operator-webhook-config: %s\n\n\n", output)
		if strings.Contains(output, "not found") || strings.Contains(output, "No resources found") {
			e2e.Logf("ValidatingWebhookConfiguration sriov-operator-webhook-config is delete successfully")
			return true, nil
		}
		return false, nil
	})
	compat_otp.AssertWaitPollNoErr(sriovChkErr, "Failed to delete ValidatingWebhookConfiguration sriov-operator-webhook-config")
}

func installSriovOperator(oc *exutil.CLI, opNamespace string) {
	var (
		buildPruningBaseDir   = testdata.FixturePath("networking/sriov")
		namespaceTemplate     = filepath.Join(buildPruningBaseDir, "namespace-template.yaml")
		operatorGroupTemplate = filepath.Join(buildPruningBaseDir, "operatorgroup-template.yaml")
		subscriptionTemplate  = filepath.Join(buildPruningBaseDir, "subscription-template.yaml")
		sriovOperatorconfig   = filepath.Join(buildPruningBaseDir, "sriovoperatorconfig.yaml")
		opName                = "sriov-network-operators"
	)
	sub := subscriptionResource{
		name:             "sriov-network-operator-subsription",
		namespace:        opNamespace,
		operatorName:     opName,
		channel:          "stable",
		catalog:          "qe-app-registry",
		catalogNamespace: "openshift-marketplace",
		template:         subscriptionTemplate,
	}
	ns := namespaceResource{
		name:     opNamespace,
		template: namespaceTemplate,
	}
	og := operatorGroupResource{
		name:             opName,
		namespace:        opNamespace,
		targetNamespaces: opNamespace,
		template:         operatorGroupTemplate,
	}
	catalogSource := getOperatorSource(oc, "openshift-marketplace")
	if catalogSource == "" {
		g.Skip("Skip testing as auto-release-app-registry/qe-app-registry not found")
	}
	sub.catalog = catalogSource
	operatorInstall(oc, sub, ns, og)
	e2e.Logf("Operator install check successfull as part of setup !!!!!")
	compat_otp.By("SUCCESS - sriov operator installed")
	compat_otp.By("check sriov version if match the ocp version")
	operatorVersion := getOperatorVersion(oc, sub.name, sub.namespace)
	ocpversion, _, err := compat_otp.GetClusterVersion(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(operatorVersion).Should(o.MatchRegexp(ocpversion))
	err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", sriovOperatorconfig, "-n", opNamespace).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
	compat_otp.By("Check all pods in sriov namespace are running")
	chkSriovOperatorStatus(oc, sub.namespace)

}
