package networking

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

func getHWoffloadPF(oc *exutil.CLI, nodename string) string {
	pfName := "ens1f0"
	nmConnection, checkLogFileErr := compat_otp.DebugNodeWithOptionsAndChroot(oc, nodename, []string{"-q"}, "nmcli", "-g", "connection.interface-name", "c", "show", "ovs-if-phys0")
	o.Expect(checkLogFileErr).NotTo(o.HaveOccurred())

	if !strings.Contains(nmConnection, "no such connection profile") {
		re := regexp.MustCompile(`(ens\w+)`)
		match := re.FindStringSubmatch(nmConnection)
		e2e.Logf("The match result is %v", match)
		pfName = match[1]
		e2e.Logf("The PF of Offload worker nodes is %v", pfName)
	}
	return pfName
}

func getOvsHWOffloadWokerNodes(oc *exutil.CLI) []string {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/sriov", "-o=jsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	nodeNameList := strings.Fields(output)
	return nodeNameList
}

func capturePacktes(oc *exutil.CLI, ns string, pod string, intf string, srcip string) string {
	var output string
	var err error
	if strings.Contains(srcip, ":") {
		// if ipv6 address
		e2e.Logf("start to capture packetes on pod %s using command 'tcpdump tcp -c 10 -vvv -i %s and src net %s/128`", pod, intf, srcip)
		output, err = oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", ns, pod, "bash", "-c",
			`timeout --preserve-status 10 tcpdump tcp -c 10 -vvv -i `+fmt.Sprintf("%s", intf)+` and src net `+fmt.Sprintf("%s", srcip)+`/128`).Output()

	} else {
		e2e.Logf("start to capture packetes on pod %s using command tcpdump tcp -c 10 -vvv -i %s and src net %s/32", pod, intf, srcip)
		output, err = oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", ns, pod, "bash", "-c",
			`timeout --preserve-status 10 tcpdump tcp -c 10 -vvv -i `+fmt.Sprintf("%s", intf)+` and src net `+fmt.Sprintf("%s", srcip)+`/32`).Output()
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.BeEmpty())
	return output
}

func chkCapturePacketsOnIntf(oc *exutil.CLI, ns string, pod string, intf string, srcip string, expectnum string) {
	errCheck := wait.Poll(10*time.Second, 30*time.Second, func() (bool, error) {
		capResOnIntf := capturePacktes(oc, ns, pod, intf, srcip)
		//e2e.Logf("The capture packtes result is %v", capResOnIntf)
		reg := regexp.MustCompile(`(\d+) packets captured`)
		match := reg.FindStringSubmatch(capResOnIntf)
		pktNum := match[1]
		e2e.Logf("captured %s packtes on this interface", pktNum)
		if pktNum != expectnum {
			e2e.Logf("doesn't capture the expected number packets, trying next round ... ")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(errCheck, "can not capture expected number packets, please check")
}

func getPodVFPresentor(oc *exutil.CLI, ns string, pod string) string {
	nodename, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, "-o=jsonpath={.spec.nodeName}", "-n", ns).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	// example:
	// #ovs-vsctl --columns=name find interface external_ids:iface-id=z1_hello-rc-1-w56tg
	//  name                : eth1
	command := fmt.Sprintf("ovs-vsctl --columns=name find interface external_ids:iface-id=%s_%s", ns, pod)
	output, err := compat_otp.DebugNodeWithChroot(oc, nodename, "/bin/bash", "-c", command)
	e2e.Logf("ovs-vsctl --columns=name find interface external_ids:iface-id=%s_%s", ns, pod)
	e2e.Logf("The output is %v", output)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).Should(o.ContainSubstring("name"))
	// find the match string with "name     : eth1"
	matchvalue := regexp.MustCompile(`name\s*:\s*(\S+)`).FindStringSubmatch(output)
	e2e.Logf("The VF Presentor is %s just test", matchvalue[1])
	o.Expect(matchvalue[1]).ShouldNot(o.BeNil())
	return matchvalue[1]
}

func startIperfTraffic(oc *exutil.CLI, ns string, pod string, svrip string, duration string) string {
	var output string
	var err error
	if strings.Contains(svrip, ":") {
		output, err = oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", ns, pod, "iperf3", "-V", "-c", svrip, "-t", duration).Output()
	} else {
		output, err = oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", ns, pod, "iperf3", "-c", svrip, "-t", duration).Output()
	}
	if err != nil {
		e2e.Logf("start iperf traffic failed, the error message is %s", output)
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.BeEmpty())
	re := regexp.MustCompile(`(\d+.\d+)\s+Gbits/sec\s+receiver`)
	match := re.FindStringSubmatch(output)
	bandWidth := match[1]
	e2e.Logf("iperf bandwidth %s", bandWidth)
	return bandWidth
}

func startIperfTrafficBackground(oc *exutil.CLI, ns string, pod string, svrip string, duration string) {
	var err error
	e2e.Logf("start iperf traffic in background")
	if strings.Contains(svrip, ":") {
		// if ipv6 address
		_, _, _, err = oc.Run("exec").Args("-n", ns, pod, "-q", "--", "iperf3", "-V", "-c", svrip, "-t", duration).Background()
	} else {
		_, _, _, err = oc.Run("exec").Args("-n", ns, pod, "-q", "--", "iperf3", "-c", svrip, "-t", duration).Background()
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	//wait for 5 seconds for iperf starting.
	time.Sleep(5 * time.Second)
}

// Wait for sriov network policy ready
func waitForOffloadSriovPolicyReady(oc *exutil.CLI, ns string) {
	workerNodeList := getOvsHWOffloadWokerNodes(oc)
	err := wait.Poll(30*time.Second, 30*time.Minute, func() (bool, error) {
		for _, workerNode := range workerNodeList {
			nodestatus, err1 := oc.AsAdmin().WithoutNamespace().Run("get").Args("sriovnetworknodestates", workerNode, "-n", ns, "-o=jsonpath={.status.syncStatus}").Output()
			if err1 != nil {
				e2e.Logf("failed to get node %v sriov policy status: %v, retrying...", workerNode, err1)
				return false, nil
			}

			if nodestatus != "Succeeded" {
				e2e.Logf("nodes %v sync up not ready yet: %v, retrying...", workerNode, nodestatus)
				return false, nil
			}
			e2e.Logf("nodes %v sync up ready now", workerNode)
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, "sriovnetworknodestates is not ready")
}

func chkSriovPoolConfig(oc *exutil.CLI, ns string, sriovpoolname string) bool {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("sriovnetworkpoolconfigs.sriovnetwork.openshift.io", "-n", ns).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if !strings.Contains(output, sriovpoolname) {
		e2e.Logf("sriovnetworkpoolconfigs is not configured")
		return false
	}
	return true
}
