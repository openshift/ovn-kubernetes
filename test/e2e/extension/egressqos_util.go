package networking

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

type egressQosResource struct {
	name      string
	namespace string
	tempfile  string
	kind      string
}
type networkingRes struct {
	name      string
	namespace string
	tempfile  string
	kind      string
}

// create networking resource
func (rs *networkingRes) create(oc *exutil.CLI, parameters ...string) {

	paras := []string{"-f", rs.tempfile, "--ignore-unknown-parameters=true", "-p"}
	for _, para := range parameters {
		paras = append(paras, para)
	}
	compat_otp.ApplyNsResourceFromTemplate(oc, rs.namespace, paras...)
}

// delete egressqos resource
func (rs *egressQosResource) delete(oc *exutil.CLI) {
	e2e.Logf("delete %s %s in namespace %s", rs.kind, rs.name, rs.namespace)
	oc.AsAdmin().WithoutNamespace().Run("delete").Args(rs.kind, rs.name, "-n", rs.namespace, "--ignore-not-found=true").Execute()
}

// create egressqos resource
func (rs *egressQosResource) create(oc *exutil.CLI, parameters ...string) {

	paras := []string{"-f", rs.tempfile, "--ignore-unknown-parameters=true", "-p"}
	for _, para := range parameters {
		paras = append(paras, para)
	}
	compat_otp.ApplyNsResourceFromTemplate(oc, rs.namespace, paras...)
}

// create egressqos resource with output
func (rs *egressQosResource) createWithOutput(oc *exutil.CLI, parameters ...string) (string, error) {
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
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to process %v resource: %v", rs.kind, cmd))
	e2e.Logf("the file of resource is %s\n", configFile)

	output, err1 := oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", configFile, "-n", rs.namespace).Output()
	return output, err1
}

func runSSHCmdOnAWS(host string, cmd string) (string, error) {
	user := os.Getenv("SSH_CLOUD_PRIV_AWS_USER")
	if user == "" {
		user = "core"
	}
	sshkey, err := compat_otp.GetPrivateKey()
	o.Expect(err).NotTo(o.HaveOccurred())

	sshClient := compat_otp.SshClient{User: user, Host: host, Port: 22, PrivateKey: sshkey}
	return sshClient.RunOutput(cmd)
}

func installDscpServiceOnAWS(a *compat_otp.AwsClient, oc *exutil.CLI, publicIP string) error {

	command := "sudo netstat -ntlp | grep 9096 || sudo podman run --name dscpecho -d -p 9096:8080 quay.io/openshifttest/hello-sdn@sha256:2af5b5ec480f05fda7e9b278023ba04724a3dd53a296afcd8c13f220dec52197"
	e2e.Logf("Run command %s", command)

	outPut, err := runSSHCmdOnAWS(publicIP, command)
	if err != nil {
		e2e.Logf("Failed to run %v: %v", command, outPut)
		return err
	}

	updateAwsIntSvcSecurityRule(a, oc, 9096)

	return nil
}

func startTcpdumpOnDscpService(a *compat_otp.AwsClient, oc *exutil.CLI, publicIP string, pktfile string) {
	//start tcpdump
	tcpdumpCmd := "'tcpdump tcp -c 5 -vvv -i eth0 -n and dst port 8080 > '" + fmt.Sprintf("%s", pktfile)
	command := "sudo podman exec -d dscpecho bash -c  " + tcpdumpCmd
	e2e.Logf("Run command %s", command)

	outPut, err := runSSHCmdOnAWS(publicIP, command)
	if err != nil {
		e2e.Logf("Failed to run %v: %v", command, outPut)
	}
	o.Expect(err).NotTo(o.HaveOccurred())
}

func chkDSCPinPkts(a *compat_otp.AwsClient, oc *exutil.CLI, publicIP string, pktfile string, dscp int) bool {
	command := "sudo podman exec -- dscpecho cat " + fmt.Sprintf("%s", pktfile)
	outPut, err := runSSHCmdOnAWS(publicIP, command)

	if err != nil {
		e2e.Logf("Failed to run %v: %v", command, outPut)
		return false
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("Captured packets are %s", outPut)
	tosHex := dscpDecConvertToHex(dscp)
	dscpString := "tos 0x" + tosHex

	if !strings.Contains(outPut, dscpString) {
		e2e.Logf("Captured packets doesn't contain dscp value %s", dscpString)
		return false
	}
	e2e.Logf("Captured packets contains dscp value %s", dscpString)
	return true
}

func chkDSCPandEIPinPkts(a *compat_otp.AwsClient, oc *exutil.CLI, publicIP string, pktfile string, dscp int, egressip string) bool {
	command := "sudo podman exec -- dscpecho cat " + fmt.Sprintf("%s", pktfile)
	outPut, err := runSSHCmdOnAWS(publicIP, command)

	if err != nil {
		e2e.Logf("Failed to run %v: %v", command, outPut)
		return false
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("Captured packets are %s", outPut)
	tosHex := dscpDecConvertToHex(dscp)
	dscpString := "tos 0x" + tosHex

	if !strings.Contains(outPut, dscpString) {
		e2e.Logf("Captured packets doesn't contain dscp value %s", dscpString)
		return false
	}

	if !strings.Contains(outPut, egressip) {
		e2e.Logf("Captured packets doesn't contain egressip %s", egressip)
		return false
	}
	e2e.Logf("Captured packets contains dscp value %s or egressip %v", dscpString, egressip)
	return true
}

func rmPktsFile(a *compat_otp.AwsClient, oc *exutil.CLI, publicIP string, pktfile string) {
	command := "sudo podman exec -- dscpecho rm " + fmt.Sprintf("%s", pktfile)
	outPut, err := runSSHCmdOnAWS(publicIP, command)
	if err != nil {
		e2e.Logf("Failed to run %v: %v", command, outPut)
	}
	o.Expect(err).NotTo(o.HaveOccurred())
}

func dscpDecConvertToHex(dscp int) string {
	tosInt := dscp * 4
	tosHex := fmt.Sprintf("%x", tosInt)
	e2e.Logf("The dscp hex value is %v", tosHex)
	return tosHex
}

func startCurlTraffic(oc *exutil.CLI, ns string, pod string, dstip string, dstport string) {
	e2e.Logf("start curl traffic")
	dstURL := net.JoinHostPort(dstip, dstport)
	cmd := "curl -k " + dstURL
	outPut, err := compat_otp.RemoteShPodWithBash(oc, ns, pod, cmd)

	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(outPut).Should(o.ContainSubstring("Hello OpenShift"))

}

func chkEgressQosStatus(oc *exutil.CLI, ns string) {
	nodeList, err := compat_otp.GetAllNodes(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	outPut, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressqos", "default", "-n", ns, "-o", "yaml").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, nodeName := range nodeList {
		subString := "Ready-In-Zone-" + nodeName
		o.Expect(strings.Contains(outPut, subString)).To(o.BeTrue())
	}
}

func getEgressQosAddSet(oc *exutil.CLI, node string, ns string) []string {
	//get ovnkube pod of this node
	podName, err := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", node)

	o.Expect(err).NotTo(o.HaveOccurred())
	nsFilter := "external-ids:k8s.ovn.org/name=" + ns
	output, err := oc.AsAdmin().WithoutNamespace().Run("rsh").Args("-n", "openshift-ovn-kubernetes", podName, "ovn-nbctl", "find", "address_set",
		"external-ids:k8s.ovn.org/owner-type=EgressQoS", nsFilter).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.BeEmpty())
	e2e.Logf("The egressqos addresset output is %v", output)

	re := regexp.MustCompile(`\"(\d+.\d+.\d+.\d+)\"`)
	addrList := re.FindAllString(output, -1)
	e2e.Logf("The ip addresses which matched egressqos rules are %v", addrList)
	return addrList
}

func chkAddSet(oc *exutil.CLI, podname string, ns string, iplist []string, expect bool) {
	podIP := getPodIPv4(oc, ns, podname)
	re := regexp.MustCompile(podIP)
	ipStr := strings.Join(iplist, " ")
	matchRes := re.MatchString(ipStr)
	if expect {
		o.Expect(matchRes).To(o.BeTrue())
	} else {
		o.Expect(matchRes).To(o.BeFalse())
	}

}
