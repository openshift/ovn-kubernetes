package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	netutils "k8s.io/utils/net"
)

// get file contents to be modified for Ushift
func getFileContentforUshift(baseDir string, name string) (fileContent string) {
	filePath := filepath.Join(testdata.FixturePath("networking", baseDir), name)
	fileOpen, err := os.Open(filePath)
	defer fileOpen.Close()
	if err != nil {
		e2e.Failf("Failed to open file: %s", filePath)
	}
	fileRead, _ := io.ReadAll(fileOpen)
	if err != nil {
		e2e.Failf("Failed to read file: %s", filePath)
	}
	return string(fileRead)
}

// get service yaml file, replace variables as per requirements in ushift and create service post that
func createServiceforUshift(oc *exutil.CLI, svc_pmtrs map[string]string) (err error) {
	e2e.Logf("Getting filecontent")
	ServiceGenericYaml := getFileContentforUshift("microshift", "service-generic.yaml")
	//replace all variables as per createServiceforUshift() arguements
	for rep, value := range svc_pmtrs {
		ServiceGenericYaml = strings.ReplaceAll(ServiceGenericYaml, rep, value)
	}
	svcFileName := "temp-service-" + getRandomString() + ".yaml"
	defer os.Remove(svcFileName)
	os.WriteFile(svcFileName, []byte(ServiceGenericYaml), 0644)
	// create service for Microshift
	_, err = oc.WithoutNamespace().Run("create").Args("-f", svcFileName).Output()
	return err
}

// get generic pod yaml file, replace varibles as per requirements in ushift and create pod post that
func createPingPodforUshift(oc *exutil.CLI, pod_pmtrs map[string]string) (err error) {
	PodGenericYaml := getFileContentforUshift("microshift", "ping-for-pod-generic.yaml")
	//replace all variables as per createPodforUshift() arguements
	for rep, value := range pod_pmtrs {
		PodGenericYaml = strings.ReplaceAll(PodGenericYaml, rep, value)
	}
	podFileName := "temp-ping-pod-" + getRandomString() + ".yaml"
	defer os.Remove(podFileName)
	os.WriteFile(podFileName, []byte(PodGenericYaml), 0644)
	// create ping pod for Microshift
	_, err = oc.WithoutNamespace().Run("create").Args("-f", podFileName).Output()
	return err
}

// get pod yaml file, replace varibles as per requirements in ushift and create pod on host network
func createHostNetworkedPodforUshift(oc *exutil.CLI, pod_pmtrs map[string]string) (err error) {
	PodHostYaml := getFileContentforUshift("microshift", "pod-specific-host.yaml")
	//replace all variables as per createPodforUshift() arguements
	for rep, value := range pod_pmtrs {
		PodHostYaml = strings.ReplaceAll(PodHostYaml, rep, value)
	}
	podFileName := "temp-pod-host" + getRandomString() + ".yaml"
	defer os.Remove(podFileName)
	os.WriteFile(podFileName, []byte(PodHostYaml), 0644)
	// create ping pod on the host network for Microshift
	_, err = oc.WithoutNamespace().Run("create").Args("-f", podFileName).Output()
	return err
}

func rebootUshiftNode(oc *exutil.CLI, nodeName string) {
	rebootNode(oc, nodeName)
	exec.Command("bash", "-c", "sleep 120").Output()
	checkNodeStatus(oc, nodeName, "Ready")
}
func setMTU(oc *exutil.CLI, nodeName string, mtu string) {
	_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", "cd /etc/microshift && cp ovn.yaml.default ovn.yaml && echo mtu: "+mtu+" >> ovn.yaml")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("reboot node")
	rebootUshiftNode(oc, nodeName)
}

func rollbackMTU(oc *exutil.CLI, nodeName string) {
	_, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", "rm -f /etc/microshift/ovn.yaml")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("reboot node")
	rebootUshiftNode(oc, nodeName)
}

func removeIPRules(oc *exutil.CLI, nodePort, nodeIP, nodeName string) {
	ipRuleList := fmt.Sprintf("nft -a list chain ip nat PREROUTING")
	rulesOutput, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", ipRuleList)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The iprules out put is :\n%s", rulesOutput)
	if checkIPrules(oc, nodePort, nodeIP, rulesOutput) {
		regexText := fmt.Sprintf("tcp dport %v ip daddr %v drop # handle (\\d+)", nodePort, nodeIP)
		re := regexp.MustCompile(regexText)
		match := re.FindStringSubmatch(rulesOutput)
		o.Expect(len(match) > 1).To(o.BeTrue())
		handleNumber := match[1]
		removeRuleCmd := fmt.Sprintf("nft -a delete rule ip nat PREROUTING handle %v", handleNumber)
		e2e.Logf("The remove rule command: %s\n", removeRuleCmd)
		_, err = compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", removeRuleCmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		rulesOutput, err = compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", ipRuleList)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(checkIPrules(oc, nodePort, nodeIP, rulesOutput)).Should(o.BeFalse())
	}

}

func checkIPrules(oc *exutil.CLI, nodePort, nodeIP, iprules string) bool {
	regexText := fmt.Sprintf("tcp dport %v ip daddr %v drop", nodePort, nodeIP)
	re := regexp.MustCompile(regexText)
	found := re.MatchString(iprules)
	if found {
		e2e.Logf("%s --Line found.", regexText)
		return true
	} else {
		e2e.Logf("%s --Line not found.", regexText)
		return false
	}

}
func checkIPv6rules(oc *exutil.CLI, nodePort, nodeIP, iprules string) bool {
	regexText := fmt.Sprintf("tcp dport %v ip6 daddr %v drop", nodePort, nodeIP)
	re := regexp.MustCompile(regexText)
	found := re.MatchString(iprules)
	if found {
		e2e.Logf("%s --Line found.", regexText)
		return true
	} else {
		e2e.Logf("%s --Line not found.", regexText)
		return false
	}

}

func restartMicroshiftService(oc *exutil.CLI, nodeName string) {
	// As restart the microshift service, the debug node pod will quit with error
	compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", "systemctl restart microshift")
	exec.Command("bash", "-c", "sleep 60").Output()
	checkNodeStatus(oc, nodeName, "Ready")
}

func getSecondaryNICip(oc *exutil.CLI) string {
	masterPodName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", "openshift-ovn-kubernetes", "-l", "app=ovnkube-master", "-o=jsonpath={.items[0].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	//primary nic will have lowest metric of 100 followed by higher metric of secondary nic. So we will look for 2nd default route line on iproute and grep its src ip which will be 2nd nic
	//nic names keep changing so relying on metric logic
	cmd := "ip route | awk '/metric/ { for(i=1;i<=NF;i++) if($i==\"metric\" && $(i+1)>100) print $0 }' | grep -oE '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b' | sed -n '2p'"
	sec_int, err := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", masterPodName, cmd)
	o.Expect(err).NotTo(o.HaveOccurred())
	re := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	sec_int = re.FindAllString(sec_int, -1)[0]
	e2e.Logf("Secondary Interface IP is : %s", sec_int)
	return sec_int
}

// get generic multus NAD yaml file, replace varibles as per requirements in ushift and create NAD with DHCP
func createMultusNADforUshift(oc *exutil.CLI, pod_pmtrs map[string]string, MultusNADGenericYaml string) (err error) {
	for rep, value := range pod_pmtrs {
		MultusNADGenericYaml = strings.ReplaceAll(MultusNADGenericYaml, rep, value)
	}
	MultusNADFileName := "MultusNAD-" + getRandomString() + ".yaml"
	defer os.Remove(MultusNADFileName)
	os.WriteFile(MultusNADFileName, []byte(MultusNADGenericYaml), 0644)
	// create multus NAD for Microshift
	_, err = oc.WithoutNamespace().Run("create").Args("-f", MultusNADFileName).Output()
	return err
}

// get generic MultusPod yaml file, replace varibles as per requirements in ushift and create Multus Pod
func createMultusPodforUshift(oc *exutil.CLI, pod_pmtrs map[string]string) (err error) {
	MultusPodGenericYaml := getFileContentforUshift("microshift", "multus-pod-generic.yaml")
	//replace all variables as per createMultusPodforUshift() arguements
	for rep, value := range pod_pmtrs {
		MultusPodGenericYaml = strings.ReplaceAll(MultusPodGenericYaml, rep, value)
	}
	MultusPodFileName := "MultusPod-" + getRandomString() + ".yaml"
	defer os.Remove(MultusPodFileName)
	os.WriteFile(MultusPodFileName, []byte(MultusPodGenericYaml), 0644)
	// create MultusPod for Microshift
	_, err = oc.WithoutNamespace().Run("create").Args("-f", MultusPodFileName).Output()
	return err
}

// configure DHCP pool from dnsmasq for CNI IPAM DHCP testing
func enableDHCPforCNI(oc *exutil.CLI, nodeName string) {
	cmdAddlink := "ip link add testbr1 type bridge"
	_, cmdAddlinkErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdAddlink)
	o.Expect(cmdAddlinkErr).NotTo(o.HaveOccurred())

	cmdAddIPv4 := "ip address add 88.8.8.2/24 dev testbr1"
	_, cmdAddIPv4Err := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdAddIPv4)
	o.Expect(cmdAddIPv4Err).NotTo(o.HaveOccurred())

	cmdAddIPv6 := "ip address add fd00:dead:beef:10::2/64 dev testbr1"
	_, cmdAddIPv6Err := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdAddIPv6)
	o.Expect(cmdAddIPv6Err).NotTo(o.HaveOccurred())

	cmdUplink := "ip link set up testbr1"
	_, cmdUplinkErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdUplink)
	o.Expect(cmdUplinkErr).NotTo(o.HaveOccurred())

	cmdShowIP := "ip add show testbr1"
	cmdShowIPOutput, cmdShowIPErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdShowIP)
	o.Expect(cmdShowIPErr).NotTo(o.HaveOccurred())
	o.Expect(cmdShowIPOutput).To(o.ContainSubstring("88.8.8.2"))

	dnsmasqFile := "/etc/dnsmasq.conf"
	cmdConfigdnsmasq := fmt.Sprintf(`cat > %v << EOF
	   no-resolv
	   expand-hosts
	   bogus-priv
	   domain=mydomain.net
	   local=/mydomain.net/
	   interface=testbr1
	   dhcp-range=88.8.8.10,88.8.8.250,24h
	   enable-ra
	   dhcp-range=tag:testbr1,::1,constructor:testbr1,ra-names,12h
	   bind-interfaces`, dnsmasqFile)
	_, cmdConfigdnsmasqErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdConfigdnsmasq)
	o.Expect(cmdConfigdnsmasqErr).NotTo(o.HaveOccurred())

	cmdRestartdnsmasq := "systemctl restart dnsmasq --now"
	_, cmdRestartdnsmasqErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdRestartdnsmasq)
	o.Expect(cmdRestartdnsmasqErr).NotTo(o.HaveOccurred())

	cmdCheckdnsmasq := "systemctl status dnsmasq"
	cmdCheckdnsmasqOutput, cmdCheckdnsmasqErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdCheckdnsmasq)
	o.Expect(cmdCheckdnsmasqErr).NotTo(o.HaveOccurred())
	o.Expect(cmdCheckdnsmasqOutput).To(o.ContainSubstring("active (running)"))

	addDHCPFirewall := "firewall-cmd --add-service=dhcp"
	_, addDHCPFirewallErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", addDHCPFirewall)
	o.Expect(addDHCPFirewallErr).NotTo(o.HaveOccurred())
}

// disable dnsmasq for CNI IPAM DHCP testing
func disableDHCPforCNI(oc *exutil.CLI, nodeName string) {
	cmdDelIP := "ip address del 88.8.8.2/24 dev testbr1"
	_, cmdDelIPErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdDelIP)
	o.Expect(cmdDelIPErr).NotTo(o.HaveOccurred())

	cmdDelIPv6 := "ip address del fd00:dead:beef:10::2/64 dev testbr1"
	_, cmdDelIPv6Err := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdDelIPv6)
	o.Expect(cmdDelIPv6Err).NotTo(o.HaveOccurred())

	cmdDownlink := "ip link set down testbr1"
	_, cmdDownlinkErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdDownlink)
	o.Expect(cmdDownlinkErr).NotTo(o.HaveOccurred())

	cmdDellink := "ip link delete testbr1"
	_, cmdDellinkErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdDellink)
	o.Expect(cmdDellinkErr).NotTo(o.HaveOccurred())

	cmdStopdnsmasq := "systemctl stop dnsmasq --now"
	_, cmdStopdnsmasqErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdStopdnsmasq)
	o.Expect(cmdStopdnsmasqErr).NotTo(o.HaveOccurred())

	cmdDeldnsmasqFile := "rm /etc/dnsmasq.conf"
	_, cmdDeldnsmasqFileErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmdDeldnsmasqFile)
	o.Expect(cmdDeldnsmasqFileErr).NotTo(o.HaveOccurred())

	remDHCPFirewall := "firewall-cmd --remove-service=dhcp"
	_, remDHCPFirewallErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", remDHCPFirewall)
	o.Expect(remDHCPFirewallErr).NotTo(o.HaveOccurred())
}

// Using getMicroshiftPodMultiNetworks for microshift pod when NAD using macvlan and ipvlan
func getMicroshiftPodMultiNetworks(oc *exutil.CLI, namespace string, podName string, netName string) (string, string) {
	cmd1 := "ip a sho " + netName + " | awk 'NR==3{print $2}' |grep -Eo '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'"
	cmd2 := "ip a sho " + netName + " | awk 'NR==7{print $2}' |grep -Eo '([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}'"
	podv4Output, err := e2eoutput.RunHostCmd(namespace, podName, cmd1)
	o.Expect(err).NotTo(o.HaveOccurred())
	podIPv4 := strings.TrimSpace(podv4Output)
	podv6Output, err1 := e2eoutput.RunHostCmd(namespace, podName, cmd2)
	o.Expect(err1).NotTo(o.HaveOccurred())
	podIPv6 := strings.TrimSpace(podv6Output)
	return podIPv4, podIPv6
}

func checkMicroshiftIPStackType(oc *exutil.CLI) string {
	podNetwork, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("pod", "-n", "openshift-dns", "-l", "dns.operator.openshift.io/daemonset-node-resolver",
		"-o=jsonpath='{ .items[*].status.podIPs[*].ip }'").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("pod network is %v", podNetwork)

	if strings.Count(podNetwork, ":") >= 2 && strings.Count(podNetwork, ".") >= 2 {
		return "dualstack"
	} else if strings.Count(podNetwork, ":") >= 2 {
		return "ipv6single"
	} else if strings.Count(podNetwork, ".") >= 2 {
		return "ipv4single"
	}
	return ""
}

// Return IPv6
func getMicroshiftNodeIPV6(oc *exutil.CLI) string {
	ipStack := checkMicroshiftIPStackType(oc)
	o.Expect(ipStack).ShouldNot(o.BeEmpty())
	o.Expect(ipStack).NotTo(o.Equal("ipv4single"))
	nodeName := getMicroshiftNodeName(oc)
	if ipStack == "ipv6single" {
		e2e.Logf("Its a Single Stack Cluster, either IPv4 or IPv6")
		InternalIP, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[?(@.type==\"InternalIP\")].address}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The node's Internal IP is %q", InternalIP)
		return InternalIP
	}
	if ipStack == "dualstack" {
		e2e.Logf("Its a Dual Stack Cluster")
		InternalIP1, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[0].address}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The node's 1st Internal IP is %q", InternalIP1)
		InternalIP2, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[1].address}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The node's 2nd Internal IP is %q", InternalIP2)
		if netutils.IsIPv6String(InternalIP1) {
			return InternalIP1
		}
		return InternalIP2
	}
	return ""
}

// Return IPv6 and IPv4 in vars respectively for Dual Stack and IPv4/IPv6 in 2nd var for single stack Clusters, and var1 will be nil in those cases
func getMicroshiftNodeIP(oc *exutil.CLI, nodeName string) (string, string) {
	ipStack := checkMicroshiftIPStackType(oc)
	if (ipStack == "ipv6single") || (ipStack == "ipv4single") {
		e2e.Logf("Its a Single Stack Cluster, either IPv4 or IPv6")
		InternalIP, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[?(@.type==\"InternalIP\")].address}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The node's Internal IP is %q", InternalIP)
		return "", InternalIP
	}
	e2e.Logf("Its a Dual Stack Cluster")
	InternalIP1, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[0].address}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The node's 1st Internal IP is %q", InternalIP1)
	InternalIP2, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[1].address}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The node's 2nd Internal IP is %q", InternalIP2)
	if netutils.IsIPv6String(InternalIP1) {
		return InternalIP1, InternalIP2
	}
	return InternalIP2, InternalIP1
}

func getMicroshiftNodeName(oc *exutil.CLI) string {
	nodeName, err := oc.AsAdmin().Run("get").Args("nodes", "-o=jsonpath={.items[0].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return nodeName
}

func getPodMultiNetworksMicroshift(oc *exutil.CLI, namespace, podName, netName string) (string, string) {
	// IPv4: only global addresses on the target device
	cmd4 := fmt.Sprintf(`ip -4 -o addr show dev %s scope global | awk '{print $4}' | cut -d/ -f1 | head -n1`, netName)

	// IPv6: only global (non-link-local) addresses on the target device
	// Using "scope global" within ip ensures fe80:: (scope link) is excluded
	cmd6 := fmt.Sprintf(`ip -6 -o addr show dev %s scope global | awk '{print $4}' | cut -d/ -f1 | head -n1`, netName)

	podv4Output, err := e2eoutput.RunHostCmd(namespace, podName, cmd4)
	o.Expect(err).NotTo(o.HaveOccurred())
	podIPv4 := strings.TrimSpace(podv4Output)

	podv6Output, err := e2eoutput.RunHostCmd(namespace, podName, cmd6)
	o.Expect(err).NotTo(o.HaveOccurred())
	podIPv6 := strings.TrimSpace(podv6Output)

	return podIPv4, podIPv6
}
