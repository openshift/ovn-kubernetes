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

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

// NslookDomainName resolves a domain name to its IPv4 address
func NslookDomainName(domainName string) string {
	ips, err := net.LookupIP(domainName)
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	e2e.Logf("There is no IPv4 address for destination domain %s", domainName)
	return ""
}

// GetPrimaryIfaddrFromBMNode returns the primary interface IPv4 and IPv6 addresses from a baremetal node
func GetPrimaryIfaddrFromBMNode(oc *exutil.CLI, nodeName string) (string, string) {
	primaryIfaddr, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.k8s\\.ovn\\.org/node-primary-ifaddr}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The primaryIfaddr is %v for node %s", primaryIfaddr, nodeName)
	var ipv4Ifaddr, ipv6Ifaddr string
	tempSlice := strings.Split(primaryIfaddr, "\"")
	ipStackType := CheckIPStackType(oc)
	switch ipStackType {
	case "ipv4single":
		o.Expect(len(tempSlice) > 3).Should(o.BeTrue())
		ipv4Ifaddr = tempSlice[3]
	case "dualstack":
		o.Expect(len(tempSlice) > 7).Should(o.BeTrue())
		ipv4Ifaddr = tempSlice[3]
		ipv6Ifaddr = tempSlice[7]
	case "ipv6single":
		o.Expect(len(tempSlice) > 3).Should(o.BeTrue())
		ipv6Ifaddr = tempSlice[3]
	default:
		g.Skip("Skip for not supported IP stack type!! ")
	}
	return ipv4Ifaddr, ipv6Ifaddr
}

// FindFreeIPs finds unused IPs on a node, handling different platform types
func FindFreeIPs(oc *exutil.CLI, nodeName string, number int) []string {
	var freeIPs []string
	platform := CheckPlatform(oc)
	if strings.Contains(platform, "vsphere") {
		sub1, err := GetDefaultSubnet(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		freeIPs = FindUnUsedIPs(oc, sub1, number)
	} else if strings.Contains(platform, "baremetal") || strings.Contains(platform, "none") || strings.Contains(platform, "nutanix") || strings.Contains(platform, "kubevirt") || strings.Contains(platform, "powervs") {
		ipv4Sub, _ := GetPrimaryIfaddrFromBMNode(oc, nodeName)
		tempSlice := strings.Split(ipv4Sub, "/")
		o.Expect(len(tempSlice) > 1).Should(o.BeTrue())
		preFix, err := strconv.Atoi(tempSlice[1])
		o.Expect(err).NotTo(o.HaveOccurred())
		if preFix > 29 {
			g.Skip("There might be no enough free IPs in current subnet, skip the test!!")
		}
		freeIPs = FindUnUsedIPsOnNode(oc, nodeName, ipv4Sub, number)
	} else {
		sub1 := GetIfaddrFromNode(nodeName, oc)
		if len(sub1) == 0 && strings.Contains(platform, "gcp") {
			g.Skip("Skip the tests as no egressIP annoatation on this platform nodes!!")
		}
		o.Expect(len(sub1) == 0).NotTo(o.BeTrue())
		freeIPs = FindUnUsedIPsOnNode(oc, nodeName, sub1, number)
	}
	return freeIPs
}

// CreateNamespaceUDN creates a namespace with the UDN label and returns its name
func CreateNamespaceUDN(oc *exutil.CLI, baseName string) string {
	nsName := fmt.Sprintf("e2e-test-udn-%s-%s", baseName, GetRandomString())
	labelKey := "k8s.ovn.org/primary-user-defined-network"
	labelValue := "null"
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   nsName,
			Labels: map[string]string{labelKey: labelValue},
		},
	}
	_, err := oc.AdminKubeClient().CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("Namespace %q with UDN label has been created", nsName)
	return nsName
}

// ApplyNsResourceFromTemplate processes an OCP template and applies the result in a specific namespace
func ApplyNsResourceFromTemplate(oc *exutil.CLI, namespace string, parameters ...string) {
	var configFile string
	err := wait.Poll(3*time.Second, 15*time.Second, func() (bool, error) {
		args := append([]string{"-n", namespace}, parameters...)
		output, oerr := oc.AsAdmin().Run("process").Args(args...).OutputToFile(GetRandomString() + "config.json")
		if oerr != nil {
			e2e.Logf("the err:%v, and try next round", oerr)
			return false, nil
		}
		configFile = output
		return true, nil
	})
	AssertWaitPollNoErr(err, fmt.Sprintf("fail to process %v resource", parameters))
	applyErr := oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", configFile, "-n", namespace).Execute()
	o.Expect(applyErr).NotTo(o.HaveOccurred())
}

// GetAllNodes returns the names of all nodes in the cluster
func GetAllNodes(oc *exutil.CLI) ([]string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-o=jsonpath={.items[*].metadata.name}").Output()
	if err != nil {
		return nil, err
	}
	if output == "" {
		return []string{}, nil
	}
	return strings.Split(output, " "), nil
}

// --- EgressQoS helpers ---

type EgressQosResource struct {
	Name      string
	Namespace string
	Tempfile  string
	Kind      string
}

type NetworkingRes struct {
	Name      string
	Namespace string
	Tempfile  string
	Kind      string
}

func (rs *NetworkingRes) Create(oc *exutil.CLI, parameters ...string) {
	paras := []string{"-f", rs.Tempfile, "--ignore-unknown-parameters=true", "-p"}
	paras = append(paras, parameters...)
	ApplyNsResourceFromTemplate(oc, rs.Namespace, paras...)
}

func (rs *EgressQosResource) Create(oc *exutil.CLI, parameters ...string) {
	paras := []string{"-f", rs.Tempfile, "--ignore-unknown-parameters=true", "-p"}
	paras = append(paras, parameters...)
	ApplyNsResourceFromTemplate(oc, rs.Namespace, paras...)
}

func (rs *EgressQosResource) Delete(oc *exutil.CLI) {
	e2e.Logf("delete %s %s in namespace %s", rs.Kind, rs.Name, rs.Namespace)
	oc.AsAdmin().WithoutNamespace().Run("delete").Args(rs.Kind, rs.Name, "-n", rs.Namespace, "--ignore-not-found=true").Execute()
}

func ChkEgressQosStatus(oc *exutil.CLI, ns string) {
	nodeList, err := GetAllNodes(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	outPut, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressqos", "default", "-n", ns, "-o", "yaml").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, nodeName := range nodeList {
		subString := "Ready-In-Zone-" + nodeName
		o.Expect(strings.Contains(outPut, subString)).To(o.BeTrue())
	}
}

func GetEgressQosAddSet(oc *exutil.CLI, node string, ns string) []string {
	podName, err := GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", node)
	o.Expect(err).NotTo(o.HaveOccurred())
	nsFilter := "external-ids:k8s.ovn.org/name=" + ns
	output, err := oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", "openshift-ovn-kubernetes", podName, "ovn-nbctl", "find", "address_set",
		"external-ids:k8s.ovn.org/owner-type=EgressQoS", nsFilter).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.BeEmpty())
	re := regexp.MustCompile(`\"(\d+\.\d+\.\d+\.\d+)\"`)
	addrList := re.FindAllString(output, -1)
	return addrList
}

func ChkAddSet(oc *exutil.CLI, podname string, ns string, iplist []string, expect bool) {
	podIP := GetPodIPv4(oc, ns, podname)
	ipStr := strings.Join(iplist, " ")
	matchRes := strings.Contains(ipStr, podIP)
	if expect {
		o.Expect(matchRes).To(o.BeTrue())
	} else {
		o.Expect(matchRes).To(o.BeFalse())
	}
}

// --- ANP/BANP policy helpers ---

type SingleRuleBANPPolicyResource struct {
	Name       string
	SubjectKey string
	SubjectVal string
	PolicyType string
	Direction  string
	RuleName   string
	RuleAction string
	RuleKey    string
	RuleVal    string
	Template   string
}

func (banp *SingleRuleBANPPolicyResource) CreateSingleRuleBANP(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", banp.Template, "-p", "NAME="+banp.Name,
			"SUBJECTKEY="+banp.SubjectKey, "SUBJECTVAL="+banp.SubjectVal,
			"POLICYTYPE="+banp.PolicyType, "DIRECTION="+banp.Direction,
			"RULENAME="+banp.RuleName, "RULEACTION="+banp.RuleAction, "RULEKEY="+banp.RuleKey, "RULEVAL="+banp.RuleVal)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Baseline Admin Network Policy CR %v", banp.Name))
}

type SingleRuleCIDRBANPPolicyResource struct {
	Name       string
	SubjectKey string
	SubjectVal string
	RuleName   string
	RuleAction string
	Cidr       string
	Template   string
}

func (banp *SingleRuleCIDRBANPPolicyResource) CreateSingleRuleCIDRBANP(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", banp.Template, "-p", "NAME="+banp.Name,
			"SUBJECTKEY="+banp.SubjectKey, "SUBJECTVAL="+banp.SubjectVal,
			"RULENAME="+banp.RuleName, "RULEACTION="+banp.RuleAction, "CIDR="+banp.Cidr)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Baseline Admin Network Policy CR %v", banp.Name))
}

type SingleRuleCIDRANPPolicyResource struct {
	Name       string
	SubjectKey string
	SubjectVal string
	Priority   int32
	RuleName   string
	RuleAction string
	Cidr       string
	Template   string
}

func (anp *SingleRuleCIDRANPPolicyResource) CreateSingleRuleCIDRANP(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.Template, "-p", "NAME="+anp.Name,
			"SUBJECTKEY="+anp.SubjectKey, "SUBJECTVAL="+anp.SubjectVal,
			"PRIORITY="+strconv.Itoa(int(anp.Priority)), "RULENAME="+anp.RuleName, "RULEACTION="+anp.RuleAction, "CIDR="+anp.Cidr)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.Name))
}

type SingleRuleANPPolicyResource struct {
	Name       string
	SubjectKey string
	SubjectVal string
	Priority   int32
	PolicyType string
	Direction  string
	RuleName   string
	RuleAction string
	RuleKey    string
	RuleVal    string
	Template   string
}

func (anp *SingleRuleANPPolicyResource) CreateSingleRuleANP(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.Template, "-p", "NAME="+anp.Name,
			"SUBJECTKEY="+anp.SubjectKey, "SUBJECTVAL="+anp.SubjectVal,
			"PRIORITY="+strconv.Itoa(int(anp.Priority)),
			"POLICYTYPE="+anp.PolicyType, "DIRECTION="+anp.Direction,
			"RULENAME="+anp.RuleName, "RULEACTION="+anp.RuleAction, "RULEKEY="+anp.RuleKey, "RULEVAL="+anp.RuleVal)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.Name))
}

type SinglePodRuleANPPolicyResource struct {
	Name          string
	SubjectKey    string
	SubjectVal    string
	SubjectPodKey string
	SubjectPodVal string
	Priority      int32
	PolicyType    string
	Direction     string
	RuleName      string
	RuleAction    string
	RuleKey       string
	RuleVal       string
	RulePodKey    string
	RulePodVal    string
	Template      string
}

func (anp *SinglePodRuleANPPolicyResource) CreateSinglePodRuleANP(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", anp.Template, "-p", "NAME="+anp.Name, "PRIORITY="+strconv.Itoa(int(anp.Priority)),
			"SUBJECTKEY="+anp.SubjectKey, "SUBJECTVAL="+anp.SubjectVal, "SUBJECTPODKEY="+anp.SubjectPodKey, "SUBJECTPODVAL="+anp.SubjectPodVal,
			"POLICYTYPE="+anp.PolicyType, "DIRECTION="+anp.Direction, "RULENAME="+anp.RuleName, "RULEACTION="+anp.RuleAction,
			"RULEKEY="+anp.RuleKey, "RULEVAL="+anp.RuleVal, "RULEPODKEY="+anp.RulePodKey, "RULEPODVAL="+anp.RulePodVal)
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create Admin Network Policy CR %v", anp.Name))
}

// DeleteNamespace deletes a namespace by name
func DeleteNamespace(oc *exutil.CLI, ns string) {
	err := oc.AdminKubeClient().CoreV1().Namespaces().Delete(context.TODO(), ns, metav1.DeleteOptions{})
	if err != nil {
		e2e.Logf("Error deleting namespace %s: %v", ns, err)
	}
}

// --- Tcpdump sniffer daemonset helpers ---

type TcpdumpDaemonSet struct {
	Name         string
	Namespace    string
	NodeLabel    string
	LabelKey     string
	PhyInterface string
	DstPort      int
	DstHost      string
	Template     string
}

func (ds *TcpdumpDaemonSet) CreateTcpdumpDS(oc *exutil.CLI) error {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ds.Template, "-p", "NAME="+ds.Name, "NAMESPACE="+ds.Namespace, "NODELABEL="+ds.NodeLabel, "LABELKEY="+ds.LabelKey, "INF="+ds.PhyInterface, "DSTPORT="+strconv.Itoa(ds.DstPort), "HOST="+ds.DstHost)
		if err1 != nil {
			e2e.Logf("Tcpdump daemonset created failed :%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("fail to create Tcpdump daemonset %v", ds.Name)
	}
	return nil
}

func DeleteTcpdumpDS(oc *exutil.CLI, dsName, dsNS string) {
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("ds", dsName, "-n", dsNS, "--ignore-not-found=true").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func WaitDaemonSetReady(oc *exutil.CLI, ns, dsName string) error {
	desiredNumStr, scheduledErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", dsName, "-n", ns, "-ojsonpath={.status.desiredNumberScheduled}").Output()
	if scheduledErr != nil {
		return fmt.Errorf("Cannot get DesiredNumberScheduled for daemonset :%s", dsName)
	}
	desiredNum, convertErr := strconv.Atoi(desiredNumStr)
	o.Expect(convertErr).NotTo(o.HaveOccurred())

	dsErr := wait.Poll(10*time.Second, 5*time.Minute, func() (bool, error) {
		readyNumStr, readyErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", dsName, "-n", ns, "-ojsonpath={.status.numberReady}").Output()
		o.Expect(readyErr).NotTo(o.HaveOccurred())
		readyNum, convertErr := strconv.Atoi(readyNumStr)
		o.Expect(convertErr).NotTo(o.HaveOccurred())
		if desiredNum != readyNum || readyErr != nil || readyNum == 0 || desiredNum == 0 {
			e2e.Logf("The DesiredNumberScheduled for daemonset :%v, ready number is %v, wait for next try.", desiredNum, readyNum)
			return false, nil
		}
		e2e.Logf("The DesiredNumberScheduled for daemonset :%v, ready number is %v.", desiredNum, readyNum)
		return true, nil
	})
	if dsErr != nil {
		return fmt.Errorf("The daemonset :%s is not ready", dsName)
	}
	return nil
}

func CreateSnifferDaemonset(oc *exutil.CLI, ns, dsName, nodeLabel, labelKey, dstHost, phyInf string, dstPort int) (*TcpdumpDaemonSet, error) {
	buildPruningBaseDir := testdata.FixturePath("networking")
	tcpdumpDSTemplate := filepath.Join(buildPruningBaseDir, "tcpdump-daemonset-template.yaml")

	_, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-scc-to-user", "privileged", fmt.Sprintf("system:serviceaccount:%s:default", ns)).Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	tcpdumpDS := TcpdumpDaemonSet{
		Name:         dsName,
		Template:     tcpdumpDSTemplate,
		Namespace:    ns,
		NodeLabel:    nodeLabel,
		LabelKey:     labelKey,
		PhyInterface: phyInf,
		DstPort:      dstPort,
		DstHost:      dstHost,
	}

	dsErr := tcpdumpDS.CreateTcpdumpDS(oc)
	if dsErr != nil {
		return &tcpdumpDS, dsErr
	}

	platform := CheckPlatform(oc)
	if platform == "openstack" {
		time.Sleep(30 * time.Second)
	}
	dsReadyErr := WaitDaemonSetReady(oc, ns, tcpdumpDS.Name)
	if dsReadyErr != nil {
		return &tcpdumpDS, dsReadyErr
	}
	return &tcpdumpDS, nil
}

func GetSnifferLogs(oc *exutil.CLI, ns, dsName, searchString string) (map[string]int, error) {
	snifferPods := GetPodName(oc, ns, "name="+dsName)
	var snifLogs string
	for _, pod := range snifferPods {
		log, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args(pod, "-n", ns).Output()
		if err != nil {
			return nil, err
		}
		snifLogs += "\n" + log
	}
	var ip string
	snifferLogs := strings.Split(snifLogs, "\n")
	matchedIPs := make(map[string]int)
	if len(snifferLogs) > 0 {
		for _, line := range snifferLogs {
			if !strings.Contains(line, searchString) {
				continue
			}
			e2e.Logf("Try to find source ip in this log line:\n %v", line)
			matchLineSlice := strings.Fields(line)
			if len(matchLineSlice) < 10 {
				e2e.Logf("Skipping log line with insufficient fields: %v", line)
				continue
			}
			ipPortSlice := strings.Split(matchLineSlice[9], ".")
			e2e.Logf("%s", matchLineSlice[9])
			ip = strings.Join(ipPortSlice[:len(ipPortSlice)-1], ".")
			e2e.Logf("Found source ip %s in this log line.", ip)
			matchedIPs[ip]++
		}
	} else {
		e2e.Logf("No new log generated!")
	}
	return matchedIPs, nil
}

func CheckMatchedIPs(oc *exutil.CLI, ns, dsName string, searchString, expectedIP string, match bool) error {
	e2e.Logf("Expected egressIP hit egress node logs : %v", match)
	matchErr := wait.Poll(10*time.Second, 30*time.Second, func() (bool, error) {
		foundIPs, searchErr := GetSnifferLogs(oc, ns, dsName, searchString)
		o.Expect(searchErr).NotTo(o.HaveOccurred())

		_, ok := foundIPs[expectedIP]
		if match && !ok {
			e2e.Logf("Waiting for the logs to be synced, try next round.")
			return false, nil
		}
		if !match && ok {
			e2e.Logf("Waiting for the logs to be synced, try next round.")
			return false, nil
		}
		return true, nil
	})
	e2e.Logf("Checking expected result in tcpdump log got error message as: %v.", matchErr)
	return matchErr
}

func GetRequestURL(domainName string) (string, string) {
	randomStr := GetRandomString()
	url := fmt.Sprintf("curl -s http://%s/?request=%s --connect-timeout 5", domainName, randomStr)
	return randomStr, url
}

func GetSnifPhyInf(oc *exutil.CLI, nodeName string) (string, error) {
	var phyInf string
	ifaceErr := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 15*time.Second, false, func(cxt context.Context) (bool, error) {
		ifaceList, ifaceErr := DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		if ifaceErr != nil {
			e2e.Logf("Debug node Error: %v", ifaceErr)
			return false, nil
		}
		e2e.Logf("%s", ifaceList)
		infList := strings.Split(ifaceList, "\n")
		for _, inf := range infList {
			if strings.Contains(inf, "ovs-if-phys0") {
				fields := strings.Fields(inf)
				if len(fields) > 3 {
					phyInf = fields[3]
				}
			}
		}
		return true, nil
	})
	return phyInf, ifaceErr
}

func VerifyEgressIPInTCPDump(oc *exutil.CLI, pod, podNS, expectedEgressIP, dstHost, tcpdumpNS, tcpdumpName string, expectedOrNot bool) error {
	egressipErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
		randomStr, url := GetRequestURL(dstHost)
		_, err := e2eoutput.RunHostCmd(podNS, pod, url)
		if CheckMatchedIPs(oc, tcpdumpNS, tcpdumpName, randomStr, expectedEgressIP, expectedOrNot) != nil || err != nil {
			e2e.Logf("Expected to find egressIP in tcpdump is: %v, did not get expected result in tcpdump log, try next round.", expectedOrNot)
			return false, nil
		}
		return true, nil
	})
	return egressipErr
}

func VerifyExpectedEIPNumInEIPObject(oc *exutil.CLI, egressIPObject string, expectedNumber int) {
	timeout := EstimateTimeoutForEgressIP(oc)
	egressErr := wait.Poll(5*time.Second, timeout, func() (bool, error) {
		egressIPMaps1 := GetAssignedEIPInEIPObject(oc, egressIPObject)
		if len(egressIPMaps1) != expectedNumber {
			e2e.Logf("Current EgressIP object length is %v,but expected is %v \n", len(egressIPMaps1), expectedNumber)
			return false, nil
		}
		return true, nil
	})
	AssertWaitPollNoErr(egressErr, fmt.Sprintf("Failed to get expected number egressIPs %v", expectedNumber))
}
