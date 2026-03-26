package networking

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

// send omping traffic on all multicast pods
func chkMcastTraffic(oc *exutil.CLI, namespace string, podList []string, ipList []string, mcastip string, port string) bool {
	pktFile := make([]string, len(podList))
	//omping on each mulitcast pod in parallel
	for i, podName := range podList {
		pktFile[i] = "/tmp/" + getRandomString() + ".txt"
		startMcastTrafficOnPod(oc, namespace, podName, ipList, pktFile[i], mcastip, port)
	}
	// wait for omping packtes send and receive.
	time.Sleep(30 * time.Second)
	// check omping send/receive results
	for i, podName := range podList {
		if !chkMcatRcvOnPod(oc, namespace, podName, ipList[i], ipList, mcastip, pktFile[i]) {
			return false
		}
	}
	return true
}

// send multicast traffic via omping
func startMcastTrafficOnPod(oc *exutil.CLI, ns string, pod string, ipList []string, pktfile string, mcastip string, port string) {
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

func chkMcatRcvOnPod(oc *exutil.CLI, ns string, pod string, podip string, iplist []string, mcastip string, pktfile string) bool {
	catCmd := "cat " + fmt.Sprintf("%s", pktfile)
	outPut, err := e2eoutput.RunHostCmd(ns, pod, catCmd)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(outPut).NotTo(o.BeEmpty())
	for _, neighborip := range iplist {
		if neighborip != podip {
			reg1 := regexp.MustCompile(neighborip + `.*joined \(S,G\) = \(\*,\s*` + mcastip + `\), pinging`)
			reg2 := regexp.MustCompile(neighborip + `.*multicast, xmt/rcv/%loss = \d+/(\d+)/\d+%`)

			match1 := reg1.MatchString(outPut)
			match2 := reg2.FindStringSubmatch(outPut)
			o.Expect(match2).ShouldNot(o.Equal(nil))
			pktNum, _ := strconv.Atoi(match2[1])
			e2e.Logf("Received packets on pod %v from ip %v is %v", pod, neighborip, pktNum)
			if pktNum == 0 || !match1 {
				return false
			}
		}
	}
	return true
}

// get ipv4 addresses of udn pods
func getPodIPv4UDNList(oc *exutil.CLI, namespace string, podList []string) []string {
	var ipList []string
	ipStackType := checkIPStackType(oc)
	o.Expect(ipStackType).ShouldNot(o.Equal("ipv6single"))
	for _, podName := range podList {
		podIP1, podIP2 := getPodIPUDN(oc, namespace, podName, "ovn-udn1")
		if ipStackType == "dualstack" {
			ipList = append(ipList, podIP2)
		} else {
			ipList = append(ipList, podIP1)
		}
	}
	e2e.Logf("The ipv4list for pods is %v", ipList)
	return ipList
}

// get ipv6 addresses of udn pods
func getPodIPv6UDNList(oc *exutil.CLI, namespace string, podList []string) []string {
	var ipList []string
	ipStackType := checkIPStackType(oc)
	o.Expect(ipStackType).ShouldNot(o.Equal("ipv4single"))
	for _, podName := range podList {
		podIP1, _ := getPodIPUDN(oc, namespace, podName, "ovn-udn1")
		ipList = append(ipList, podIP1)
	}
	e2e.Logf("The ipv6list for pods is %v", ipList)
	return ipList
}

// get ipv4 addresses of default pods
func getPodIPv4List(oc *exutil.CLI, namespace string, podList []string) []string {
	var ipList []string
	ipStackType := checkIPStackType(oc)
	o.Expect(ipStackType).ShouldNot(o.Equal("ipv6single"))
	for _, podName := range podList {
		podIP := getPodIPv4(oc, namespace, podName)
		ipList = append(ipList, podIP)
	}
	e2e.Logf("The ipv4list for pods is %v", ipList)
	return ipList
}

// get ipv6 addresses of default pods
func getPodIPv6List(oc *exutil.CLI, namespace string, podList []string) []string {
	var ipList []string
	ipStackType := checkIPStackType(oc)
	o.Expect(ipStackType).ShouldNot(o.Equal("ipv4single"))
	for _, podName := range podList {
		podIP := getPodIPv6(oc, namespace, podName, ipStackType)
		ipList = append(ipList, podIP)
	}
	e2e.Logf("The ipv6list for pods is %v", ipList)
	return ipList
}

// check netstat during sending multicast traffic
func chkMcastAddress(oc *exutil.CLI, ns string, pod string, intf string, mcastip string) {
	netstatCmd := "netstat -ng"
	outPut, err := e2eoutput.RunHostCmd(ns, pod, netstatCmd)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("netstat result is %v: /n", outPut)
	reg := regexp.MustCompile(intf + `\s+\d+\s+` + mcastip)
	matchRes := reg.MatchString(outPut)
	o.Expect(matchRes).Should(o.BeTrue())
}

// disable multicast on specific namespace
func disableMulticast(oc *exutil.CLI, ns string) {
	_, err := runOcWithRetry(oc.AsAdmin().WithoutNamespace(), "annotate", "namespace", ns, "k8s.ovn.org/multicast-enabled-")
	o.Expect(err).NotTo(o.HaveOccurred())
}

// getPodIPUDNv4 returns IPv4 address of specific interface
func getPodIPUDNv4(oc *exutil.CLI, namespace string, podName string, netName string) string {
	ipStack := checkIPStackType(oc)
	ip_1, ip_2 := getPodIPUDN(oc, namespace, podName, netName)
	if ipStack == "ipv4single" {
		return ip_1
	} else if ipStack == "dualstack" {
		return ip_2
	} else {
		return ""
	}
}

// getPodIPUDNv6 returns IPv6 address of specific interface
func getPodIPUDNv6(oc *exutil.CLI, namespace string, podName string, netName string) string {
	ipStack := checkIPStackType(oc)
	ip_1, _ := getPodIPUDN(oc, namespace, podName, netName)
	if ipStack == "ipv6single" || ipStack == "dualstack" {
		return ip_1
	} else {
		return ""
	}
}
