package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ssh"

	"net"

	"github.com/aws/aws-sdk-go/aws"
	awsSession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/openshift/origin/test/extended/util/compat_otp"
	"github.com/vmware/govmomi"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

type tcpdumpDaemonSet struct {
	name         string
	namespace    string
	nodeLabel    string
	labelKey     string
	phyInterface string
	dstPort      int
	dstHost      string
	template     string
}

type ibmPowerVsInstance struct {
	instance
	ibmRegion     string
	ibmVpcName    string
	clientPowerVs *compat_otp.IBMPowerVsSession
}

func (ds *tcpdumpDaemonSet) createTcpdumpDS(oc *exutil.CLI) error {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ds.template, "-p", "NAME="+ds.name, "NAMESPACE="+ds.namespace, "NODELABEL="+ds.nodeLabel, "LABELKEY="+ds.labelKey, "INF="+ds.phyInterface, "DSTPORT="+strconv.Itoa(ds.dstPort), "HOST="+ds.dstHost)
		if err1 != nil {
			e2e.Logf("Tcpdump daemonset created failed :%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("fail to create Tcpdump daemonset %v", ds.name)
	}
	return nil
}

func deleteTcpdumpDS(oc *exutil.CLI, dsName, dsNS string) {
	_, err := runOcWithRetry(oc.AsAdmin(), "delete", "ds", dsName, "-n", dsNS, "--ignore-not-found=true")
	o.Expect(err).NotTo(o.HaveOccurred())
}

// Get AWS credential from cluster
func getAwsCredentialFromCluster(oc *exutil.CLI) error {
	if compat_otp.CheckPlatform(oc) != "aws" {
		g.Skip("it is not aws platform and can not get credential, and then skip it.")
	}
	credential, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret/aws-creds", "-n", "kube-system", "-o", "json").Output()
	// Skip for sts and c2s clusters.
	if err != nil {
		e2e.Logf("Cannot get AWS basic auth credential,%v", err)
		return err
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	accessKeyIDBase64, secureKeyBase64 := gjson.Get(credential, `data.aws_access_key_id`).String(), gjson.Get(credential, `data.aws_secret_access_key`).String()
	accessKeyID, err1 := base64.StdEncoding.DecodeString(accessKeyIDBase64)
	o.Expect(err1).NotTo(o.HaveOccurred())
	secureKey, err2 := base64.StdEncoding.DecodeString(secureKeyBase64)
	o.Expect(err2).NotTo(o.HaveOccurred())
	clusterRegion, err3 := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.aws.region}").Output()
	o.Expect(err3).NotTo(o.HaveOccurred())
	os.Setenv("AWS_ACCESS_KEY_ID", string(accessKeyID))
	os.Setenv("AWS_SECRET_ACCESS_KEY", string(secureKey))
	os.Setenv("AWS_REGION", clusterRegion)
	return nil
}

// Get AWS int svc instance ID
func getAwsIntSvcInstanceID(a *compat_otp.AwsClient, oc *exutil.CLI) (string, error) {
	clusterPrefixName := compat_otp.GetClusterPrefixName(oc)
	instanceName := clusterPrefixName + "-int-svc"
	instanceID, err := a.GetAwsInstanceID(instanceName)
	if err != nil {
		e2e.Logf("Get bastion instance id failed with error %v .", err)
		return "", err
	}
	return instanceID, nil
}

// Get int svc instance private ip and public ip
func getAwsIntSvcIPs(a *compat_otp.AwsClient, oc *exutil.CLI) map[string]string {
	instanceID, err := getAwsIntSvcInstanceID(a, oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	ips, err := a.GetAwsIntIPs(instanceID)
	o.Expect(err).NotTo(o.HaveOccurred())
	return ips
}

// Update int svc instance ingress rule to allow destination port
func updateAwsIntSvcSecurityRule(a *compat_otp.AwsClient, oc *exutil.CLI, dstPort int64) {
	instanceID, err := getAwsIntSvcInstanceID(a, oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	err = a.UpdateAwsIntSecurityRule(instanceID, dstPort)
	o.Expect(err).NotTo(o.HaveOccurred())

}

func installIPEchoServiceOnAWS(a *compat_otp.AwsClient, oc *exutil.CLI) (string, error) {
	user := os.Getenv("SSH_CLOUD_PRIV_AWS_USER")
	if user == "" {
		user = "core"
	}

	sshkey, err := compat_otp.GetPrivateKey()
	o.Expect(err).NotTo(o.HaveOccurred())
	command := "sudo netstat -ntlp | grep 9095 || sudo podman run --name ipecho -d -p 9095:80 quay.io/openshifttest/ip-echo:1.2.0"
	e2e.Logf("Run command", command)

	ips := getAwsIntSvcIPs(a, oc)
	publicIP, ok := ips["publicIP"]
	if !ok {
		return "", fmt.Errorf("no public IP found for Int Svc instance")
	}
	privateIP, ok := ips["privateIP"]
	if !ok {
		return "", fmt.Errorf("no private IP found for Int Svc instance")
	}

	sshClient := compat_otp.SshClient{User: user, Host: publicIP, Port: 22, PrivateKey: sshkey}
	err = sshClient.Run(command)
	if err != nil {
		e2e.Logf("Failed to run %v: %v", command, err)
		return "", err
	}

	updateAwsIntSvcSecurityRule(a, oc, 9095)

	ipEchoURL := net.JoinHostPort(privateIP, "9095")
	return ipEchoURL, nil
}

func getIfaddrFromNode(nodeName string, oc *exutil.CLI) string {
	egressIpconfig, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.cloud\\.network\\.openshift\\.io/egress-ipconfig}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The egressipconfig is %v", egressIpconfig)
	if len(egressIpconfig) == 0 {
		e2e.Logf("The node %s doesn't have egressIP annotation", nodeName)
		return ""
	}
	ifaddr := strings.Split(egressIpconfig, "\"")[9]
	e2e.Logf("The subnet of node %s is %v .", nodeName, ifaddr)
	return ifaddr
}

func getPrimaryIfaddrFromBMNode(oc *exutil.CLI, nodeName string) (string, string) {
	primaryIfaddr, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.k8s\\.ovn\\.org/node-primary-ifaddr}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The primaryIfaddr is %v for node %s", primaryIfaddr, nodeName)
	var ipv4Ifaddr, ipv6Ifaddr string
	tempSlice := strings.Split(primaryIfaddr, "\"")
	ipStackType := checkIPStackType(oc)
	switch ipStackType {
	case "ipv4single":
		o.Expect(len(tempSlice) > 3).Should(o.BeTrue())
		ipv4Ifaddr = tempSlice[3]
		e2e.Logf("The ipv4 subnet of node %s is %v .", nodeName, ipv4Ifaddr)
	case "dualstack":
		o.Expect(len(tempSlice) > 7).Should(o.BeTrue())
		ipv4Ifaddr = tempSlice[3]
		ipv6Ifaddr = tempSlice[7]
		e2e.Logf("The ipv4 subnet of node %s is %v, ipv6 subnet is :%v", nodeName, ipv4Ifaddr, ipv6Ifaddr)
	case "ipv6single":
		o.Expect(len(tempSlice) > 3).Should(o.BeTrue())
		ipv6Ifaddr = tempSlice[3]
		e2e.Logf("The ipv6 subnet of node %s is %v .", nodeName, ipv6Ifaddr)
	default:
		e2e.Logf("Get ipStackType as %s", ipStackType)
		g.Skip("Skip for not supported IP stack type!! ")
	}
	return ipv4Ifaddr, ipv6Ifaddr
}

func findUnUsedIPsOnNode(oc *exutil.CLI, nodeName, cidr string, number int) []string {
	ipRange, _ := Hosts(cidr)
	var ipUnused = []string{}
	//shuffle the ips slice
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(ipRange), func(i, j int) { ipRange[i], ipRange[j] = ipRange[j], ipRange[i] })
	var err error
	var podName string
	var ns string
	podName, err = compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
	o.Expect(err).NotTo(o.HaveOccurred())
	ns = "openshift-ovn-kubernetes"

	for _, ip := range ipRange {
		if len(ipUnused) < number {
			pingCmd := "ping -c4 -t1 " + ip
			msg, err := compat_otp.RemoteShPodWithBash(oc, ns, podName, pingCmd)
			if err != nil && (strings.Contains(msg, "Destination Host Unreachable") || strings.Contains(msg, "100% packet loss")) {
				e2e.Logf("%s is not used!\n", ip)
				ipUnused = append(ipUnused, ip)
			} else if err != nil {
				break
			}
		} else {
			break
		}

	}
	return ipUnused
}

func findFreeIPs(oc *exutil.CLI, nodeName string, number int) []string {
	var freeIPs []string
	platform := compat_otp.CheckPlatform(oc)
	if strings.Contains(platform, "vsphere") {
		sub1, err := getDefaultSubnet(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		freeIPs = findUnUsedIPs(oc, sub1, number)

	} else if strings.Contains(platform, "baremetal") || strings.Contains(platform, "none") || strings.Contains(platform, "nutanix") || strings.Contains(platform, "kubevirt") || strings.Contains(platform, "powervs") {
		ipv4Sub, _ := getPrimaryIfaddrFromBMNode(oc, nodeName)
		tempSlice := strings.Split(ipv4Sub, "/")
		o.Expect(len(tempSlice) > 1).Should(o.BeTrue())
		preFix, err := strconv.Atoi(tempSlice[1])
		o.Expect(err).NotTo(o.HaveOccurred())
		if preFix > 29 {
			g.Skip("There might be no enough free IPs in current subnet, skip the test!!")
		}
		freeIPs = findUnUsedIPsOnNode(oc, nodeName, ipv4Sub, number)

	} else {
		sub1 := getIfaddrFromNode(nodeName, oc)
		if len(sub1) == 0 && strings.Contains(platform, "gcp") {
			g.Skip("Skip the tests as no egressIP annoatation on this platform nodes!!")
		}
		o.Expect(len(sub1) == 0).NotTo(o.BeTrue())
		freeIPs = findUnUsedIPsOnNode(oc, nodeName, sub1, number)
	}
	return freeIPs
}

func findFreeIPsForCIDRs(oc *exutil.CLI, nodeName, cidr string, number int) []string {
	var freeIPs []string
	freeIPs = findUnUsedIPsOnNode(oc, nodeName, cidr, number)
	o.Expect(len(freeIPs)).Should(o.Equal(number))
	return freeIPs
}

func findFreeIPv6s(oc *exutil.CLI, nodeName string, number int) []string {
	var freeIPs []string
	_, ipv6Sub := getPrimaryIfaddrFromBMNode(oc, nodeName)
	tempSlice := strings.Split(ipv6Sub, "/")
	o.Expect(len(tempSlice) > 1).Should(o.BeTrue())
	preFix, err := strconv.Atoi(tempSlice[1])
	o.Expect(err).NotTo(o.HaveOccurred())
	if preFix > 126 {
		g.Skip("There might be no enough free IPs in current subnet, skip the test!!")
	}
	freeIPs, err = findUnUsedIPv6(oc, ipv6Sub, number)
	o.Expect(err).NotTo(o.HaveOccurred())
	return freeIPs
}

func execCommandInOVNPodOnNode(oc *exutil.CLI, nodeName, command string) (string, error) {
	ovnPodName, err := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
	o.Expect(err).NotTo(o.HaveOccurred())
	msg, err := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPodName, command)
	if err != nil {
		e2e.Logf("Execute ovn command failed with  err:%v .", err)
		return msg, err
	}
	return msg, nil
}

func execCommandInSDNPodOnNode(oc *exutil.CLI, nodeName, command string) (string, error) {
	sdnPodName, err := compat_otp.GetPodName(oc, "openshift-sdn", "app=sdn", nodeName)
	o.Expect(err).NotTo(o.HaveOccurred())
	msg, err := compat_otp.RemoteShPodWithBash(oc, "openshift-sdn", sdnPodName, command)
	if err != nil {
		e2e.Logf("Execute sdn command failed with  err:%v .", err)
		return msg, err
	}
	return msg, nil
}

func getgcloudClient(oc *exutil.CLI) *compat_otp.Gcloud {
	if compat_otp.CheckPlatform(oc) != "gcp" {
		g.Skip("it is not gcp platform!")
	}
	projectID, err := compat_otp.GetGcpProjectID(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	if projectID != "openshift-qe" {
		g.Skip("openshift-qe project is needed to execute this test case!")
	}
	gcloud := compat_otp.Gcloud{ProjectID: projectID}
	return gcloud.Login()
}

func getIntSvcExternalIPFromGcp(oc *exutil.CLI, infraID string) (string, error) {
	externalIP, err := getgcloudClient(oc).GetIntSvcExternalIP(infraID)
	e2e.Logf("Additional VM external ip: %s", externalIP)
	return externalIP, err
}

func installIPEchoServiceOnGCP(oc *exutil.CLI, infraID string, host string) (string, error) {
	e2e.Logf("Infra id: %s, install ipecho service on host %s", infraID, host)

	// Run ip-echo service on the additional VM
	serviceName := "ip-echo"
	internalIP, err := getgcloudClient(oc).GetIntSvcInternalIP(infraID)
	o.Expect(err).NotTo(o.HaveOccurred())
	port := "9095"
	runIPEcho := fmt.Sprintf("sudo netstat -ntlp | grep %s || sudo podman run --name %s -d -p %s:80 quay.io/openshifttest/ip-echo:1.2.0", port, serviceName, port)
	user := os.Getenv("SSH_CLOUD_PRIV_GCP_USER")
	if user == "" {
		user = "core"
	}

	err = sshRunCmd(host, user, runIPEcho)
	if err != nil {
		e2e.Logf("Failed to run %v: %v", runIPEcho, err)
		return "", err
	}

	// Update firewall rules to expose ip-echo service
	ruleName := fmt.Sprintf("%s-int-svc-ingress-allow", infraID)
	ports, err := getgcloudClient(oc).GetFirewallAllowPorts(ruleName)
	if err != nil {
		e2e.Logf("Failed to update firewall rules for port %v: %v", ports, err)
		return "", err
	}

	if !strings.Contains(ports, "tcp:"+port) {
		addIPEchoPort := fmt.Sprintf("%s,tcp:%s", ports, port)
		updateFirewallPortErr := getgcloudClient(oc).UpdateFirewallAllowPorts(ruleName, addIPEchoPort)
		if updateFirewallPortErr != nil {
			return "", updateFirewallPortErr
		}
		e2e.Logf("Allow Ports: %s", addIPEchoPort)
	}
	ipEchoURL := net.JoinHostPort(internalIP, port)
	return ipEchoURL, nil
}

func uninstallIPEchoServiceOnGCP(oc *exutil.CLI) {
	infraID, err := compat_otp.GetInfraID(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	host, err := getIntSvcExternalIPFromGcp(oc, infraID)
	o.Expect(err).NotTo(o.HaveOccurred())
	//Remove ip-echo service
	user := os.Getenv("SSH_CLOUD_PRIV_GCP_USER")
	if user == "" {
		user = "cloud-user"
	}
	o.Expect(sshRunCmd(host, user, "sudo podman rm ip-echo -f")).NotTo(o.HaveOccurred())
	//Update firewall rules
	ruleName := fmt.Sprintf("%s-int-svc-ingress-allow", infraID)
	ports, err := getgcloudClient(oc).GetFirewallAllowPorts(ruleName)
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(ports, "tcp:9095") {
		updatedPorts := strings.Replace(ports, ",tcp:9095", "", -1)
		o.Expect(getgcloudClient(oc).UpdateFirewallAllowPorts(ruleName, updatedPorts)).NotTo(o.HaveOccurred())
	}
}

func getZoneOfInstanceFromGcp(oc *exutil.CLI, infraID string, workerName string) (string, error) {
	zone, err := getgcloudClient(oc).GetZone(infraID, workerName)
	e2e.Logf("zone for instance %v is: %s", workerName, zone)
	return zone, err
}

func startInstanceOnGcp(oc *exutil.CLI, nodeName string, zone string) error {
	err := getgcloudClient(oc).StartInstance(nodeName, zone)
	return err
}

func stopInstanceOnGcp(oc *exutil.CLI, nodeName string, zone string) error {
	err := getgcloudClient(oc).StopInstance(nodeName, zone)
	return err
}

// Run timeout ssh connection test from GCP int-svc instance
func accessEgressNodeFromIntSvcInstanceOnGCP(host string, IPaddr string) (string, error) {
	user := os.Getenv("SSH_CLOUD_PRIV_GCP_USER")
	if user == "" {
		user = "core"
	}
	cmd := fmt.Sprintf(`timeout 5 bash -c "</dev/tcp/%v/22"`, IPaddr)
	err := sshRunCmd(host, user, cmd)

	if err != nil {
		e2e.Logf("Failed to run %v: %v", cmd, err)

		// Extract the return code from the err1 variable
		if returnedErr, ok := err.(*ssh.ExitError); ok {
			return fmt.Sprintf("%d", returnedErr.ExitStatus()), err
		}
		// IO problems, the return code was not sent back
		return "", err
	}

	return "0", nil
}

// start one AWS instance
func startInstanceOnAWS(a *compat_otp.AwsClient, hostname string) {
	instanceID, err := a.GetAwsInstanceIDFromHostname(hostname)
	o.Expect(err).NotTo(o.HaveOccurred())
	stateErr := wait.Poll(5*time.Second, 120*time.Second, func() (bool, error) {
		state, err := a.GetAwsInstanceState(instanceID)
		if err != nil {
			e2e.Logf("%v", err)
			return false, nil
		}
		if state == "running" {
			e2e.Logf("The instance  is running")
			return true, nil
		}
		if state == "stopped" {
			err = a.StartInstance(instanceID)
			o.Expect(err).NotTo(o.HaveOccurred())
			return true, nil
		}
		e2e.Logf("The instance  is in %v,not in a state from which it can be started.", state)
		return false, nil

	})
	compat_otp.AssertWaitPollNoErr(stateErr, fmt.Sprintf("The instance  is not in a state from which it can be started."))
}

func stopInstanceOnAWS(a *compat_otp.AwsClient, hostname string) {
	instanceID, err := a.GetAwsInstanceIDFromHostname(hostname)
	o.Expect(err).NotTo(o.HaveOccurred())
	stateErr := wait.Poll(5*time.Second, 120*time.Second, func() (bool, error) {
		state, err := a.GetAwsInstanceState(instanceID)
		if err != nil {
			e2e.Logf("%v", err)
			return false, nil
		}
		if state == "stopped" {
			e2e.Logf("The instance  is already stopped.")
			return true, nil
		}
		if state == "running" {
			err = a.StopInstance(instanceID)
			o.Expect(err).NotTo(o.HaveOccurred())
			return true, nil
		}
		e2e.Logf("The instance is in %v,not in a state from which it can be stopped.", state)
		return false, nil

	})
	compat_otp.AssertWaitPollNoErr(stateErr, fmt.Sprintf("The instance  is not in a state from which it can be stopped."))
}

// Run timeout ssh connection test from AWS int-svc instance
func accessEgressNodeFromIntSvcInstanceOnAWS(a *compat_otp.AwsClient, oc *exutil.CLI, IPaddr string) (string, error) {
	user := os.Getenv("SSH_CLOUD_PRIV_AWS_USER")
	if user == "" {
		user = "core"
	}

	sshkey := os.Getenv("SSH_CLOUD_PRIV_KEY")
	if sshkey == "" {
		sshkey = "../internal/config/keys/openshift-qe.pem"
	}

	ips := getAwsIntSvcIPs(a, oc)
	publicIP, ok := ips["publicIP"]
	if !ok {
		return "", fmt.Errorf("no public IP found for Int Svc instance")
	}

	cmd := fmt.Sprintf(`timeout 5 bash -c "</dev/tcp/%v/22"`, IPaddr)
	sshClient := compat_otp.SshClient{User: user, Host: publicIP, Port: 22, PrivateKey: sshkey}
	err := sshClient.Run(cmd)
	if err != nil {
		e2e.Logf("Failed to run %v: %v", cmd, err)

		// Extract the return code from the err1 variable
		if returnedErr, ok := err.(*ssh.ExitError); ok {
			return fmt.Sprintf("%d", returnedErr.ExitStatus()), err
		}
		// IO problems, the return code was not sent back
		return "", err
	}

	return "0", nil
}

func findIP(input string) []string {
	numBlock := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	regexPattern := numBlock + "\\." + numBlock + "\\." + numBlock + "\\." + numBlock

	regEx := regexp.MustCompile(regexPattern)
	return regEx.FindAllString(input, -1)
}

func unique(s []string) []string {
	inResult := make(map[string]bool)
	var result []string
	for _, str := range s {
		if _, ok := inResult[str]; !ok {
			inResult[str] = true
			result = append(result, str)
		}
	}
	return result
}

type azureCredentials struct {
	AzureClientID       string `json:"azure_client_id,omitempty"`
	AzureClientSecret   string `json:"azure_client_secret,omitempty"`
	AzureSubscriptionID string `json:"azure_subscription_id,omitempty"`
	AzureTenantID       string `json:"azure_tenant_id,omitempty"`
}

// Get Azure credentials from cluster
func getAzureCredentialFromCluster(oc *exutil.CLI) error {
	if compat_otp.CheckPlatform(oc) != "azure" {
		g.Skip("it is not azure platform and can not get credential, and then skip it.")
	}
	credential, getSecErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret/azure-credentials", "-n", "kube-system", "-o=jsonpath={.data}").Output()
	if getSecErr != nil {
		e2e.Logf("Cannot get credential from secret/azure-credentials with error : %v,", getSecErr)
		return getSecErr
	}
	azureCreds := azureCredentials{}
	unmarshalErr := json.Unmarshal([]byte(credential), &azureCreds)
	if unmarshalErr != nil {
		e2e.Logf("Unmarshal error : %v,", unmarshalErr)
		return unmarshalErr
	}
	azureClientID, decodeACIDErr := base64.StdEncoding.DecodeString(azureCreds.AzureClientID)
	if decodeACIDErr != nil {
		e2e.Logf("Decode azureClientID error : %v ", decodeACIDErr)
		return decodeACIDErr
	}
	azureClientSecret, decodeACSErr := base64.StdEncoding.DecodeString(azureCreds.AzureClientSecret)
	if decodeACSErr != nil {
		e2e.Logf("Decode azureClientSecret error: %v", decodeACSErr)
		return decodeACSErr
	}
	azureSubscriptionID, decodeASIDErr := base64.StdEncoding.DecodeString(azureCreds.AzureSubscriptionID)
	if decodeASIDErr != nil {
		e2e.Logf("Decode azureSubscriptionID error: %v ", decodeASIDErr)
		return decodeASIDErr
	}
	azureTenantID, decodeATIDErr := base64.StdEncoding.DecodeString(azureCreds.AzureTenantID)
	if decodeATIDErr != nil {
		e2e.Logf("Decode azureTenantID error : %v ", decodeATIDErr)
		return decodeATIDErr
	}
	os.Setenv("AZURE_CLIENT_ID", string(azureClientID))
	os.Setenv("AZURE_CLIENT_SECRET", string(azureClientSecret))
	os.Setenv("AZURE_SUBSCRIPTION_ID", string(azureSubscriptionID))
	os.Setenv("AZURE_TENANT_ID", string(azureTenantID))
	e2e.Logf("Azure credentials successfully loaded.")

	return nil
}

func getAzureResourceGroup(oc *exutil.CLI) (string, error) {
	if compat_otp.CheckPlatform(oc) != "azure" {
		return "", fmt.Errorf("it is not azure platform and can not get resource group")
	}
	credential, getCredErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret/azure-credentials", "-n", "kube-system", "-o=jsonpath={.data.azure_resourcegroup}").Output()
	if getCredErr != nil {
		e2e.Logf("Cannot get credential from secret/azure-credentials with error : %v,", getCredErr)
		return "", getCredErr
	}

	azureResourceGroup, rgErr := base64.StdEncoding.DecodeString(credential)
	if rgErr != nil {
		e2e.Logf("Cannot get resource group, error: %v", rgErr)
		return "", rgErr
	}

	return string(azureResourceGroup), nil
}

func isAzurePrivate(oc *exutil.CLI) bool {
	installConfig, err := runOcWithRetry(oc.AsAdmin(), "get", "cm", "cluster-config-v1", "-n", "kube-system", "-o=jsonpath={.data.install-config}")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "i/o timeout") {
			e2e.Logf("System issues with err=%v\n)", err)
			return true
		}
		e2e.Logf("\nTry to get cm  cluster-config-v1, but failed with error: %v \n", err)
		return false
	}

	if strings.Contains(installConfig, "publish: Internal") && strings.Contains(installConfig, "outboundType: Loadbalancer") {
		e2e.Logf("This is Azure Private cluster.")
		return true
	}

	return false
}

func isAzureStack(oc *exutil.CLI) bool {
	cloudName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.azure.cloudName}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.ToLower(cloudName) == "azurestackcloud" {
		e2e.Logf("This is Azure Stack cluster.")
		return true
	}
	return false
}

func getAzureIntSvcResrouceGroup(oc *exutil.CLI) (string, error) {
	azureResourceGroup, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.azure.networkResourceGroupName}").Output()
	if err != nil {
		e2e.Logf("Cannot get resource group, error: %v", err)
		return "", err
	}
	return azureResourceGroup, nil
}

func getAzureIntSvcVMPrivateIP(oc *exutil.CLI, sess *compat_otp.AzureSession, rg string) (string, error) {
	privateIP := ""
	clusterPrefixName := compat_otp.GetClusterPrefixName(oc)
	vmName := clusterPrefixName + "-int-svc"
	privateIP, getPrivateIPErr := compat_otp.GetAzureVMPrivateIP(sess, rg, vmName)
	if getPrivateIPErr != nil {
		e2e.Logf("Cannot get private IP from int svc vm, error: %v", getPrivateIPErr)
		return "", getPrivateIPErr
	}
	return privateIP, nil
}

func getAzureIntSvcVMPublicIP(oc *exutil.CLI, sess *compat_otp.AzureSession, rg string) (string, error) {
	publicIP := ""
	clusterPrefixName := compat_otp.GetClusterPrefixName(oc)
	vmName := clusterPrefixName + "-int-svc"
	publicIP, getPublicIPErr := compat_otp.GetAzureVMPublicIP(sess, rg, vmName)
	if getPublicIPErr != nil {
		e2e.Logf("Cannot get public IP from int svc vm, error: %v", getPublicIPErr)
		return "", getPublicIPErr
	}
	return publicIP, nil
}

func installIPEchoServiceOnAzure(oc *exutil.CLI, sess *compat_otp.AzureSession, rg string) (string, error) {
	user := "core"
	sshkey, err := compat_otp.GetPrivateKey()
	o.Expect(err).NotTo(o.HaveOccurred())
	command := "sudo netstat -ntlp | grep 9095 || sudo podman run --name ipecho -d -p 9095:80 quay.io/openshifttest/ip-echo:1.2.0"
	e2e.Logf("Run command, %s \n", command)

	privateIP, privateIPErr := getAzureIntSvcVMPrivateIP(oc, sess, rg)
	if privateIPErr != nil || privateIP == "" {
		return "", privateIPErr
	}
	publicIP, publicIPErr := getAzureIntSvcVMPublicIP(oc, sess, rg)
	if publicIPErr != nil || publicIP == "" {
		return "", publicIPErr
	}

	sshClient := compat_otp.SshClient{User: user, Host: publicIP, Port: 22, PrivateKey: sshkey}
	err = sshClient.Run(command)
	if err != nil {
		e2e.Logf("Failed to run %v: %v", command, err)
		return "", err
	}

	ipEchoURL := net.JoinHostPort(privateIP, "9095")
	return ipEchoURL, nil
}

// Run timeout ssh connection test from Azure int-svc instance
func accessEgressNodeFromIntSvcInstanceOnAzure(sess *compat_otp.AzureSession, oc *exutil.CLI, rg string, IPaddr string) (string, error) {
	user := os.Getenv("SSH_CLOUD_PRIV_AZURE_USER")
	if user == "" {
		user = "core"
	}

	sshkey, err := compat_otp.GetPrivateKey()
	o.Expect(err).NotTo(o.HaveOccurred())

	publicIP, publicIPErr := getAzureIntSvcVMPublicIP(oc, sess, rg)
	if publicIPErr != nil || publicIP == "" {
		return "", publicIPErr
	}

	cmd := fmt.Sprintf(`timeout 5 bash -c "</dev/tcp/%v/22"`, IPaddr)
	sshClient := compat_otp.SshClient{User: user, Host: publicIP, Port: 22, PrivateKey: sshkey}
	err = sshClient.Run(cmd)
	if err != nil {
		e2e.Logf("Failed to run %v: %v", cmd, err)

		// Extract the return code from the err1 variable
		if returnedErr, ok := err.(*ssh.ExitError); ok {
			return fmt.Sprintf("%d", returnedErr.ExitStatus()), err
		}
		// IO problems, the return code was not sent back
		return "", err
	}

	return "0", nil
}

// runOcWithRetry runs the oc command with up to 5 retries if a timeout error occurred while running the command.
func runOcWithRetry(oc *exutil.CLI, cmd string, args ...string) (string, error) {
	var err error
	var output string
	maxRetries := 5

	for numRetries := 0; numRetries < maxRetries; numRetries++ {
		if numRetries > 0 {
			e2e.Logf("Retrying oc command (retry count=%v/%v)", numRetries+1, maxRetries)
		}

		output, err = oc.Run(cmd).Args(args...).Output()
		// If an error was found, either return the error, or retry if a timeout error was found.
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "i/o timeout") {
				// Retry on "i/o timeout" errors
				e2e.Logf("Warning: oc command encountered i/o timeout.\nerr=%v\n)", err)
				continue
			}
			return output, err
		}
		// Break out of loop if no error.
		break
	}
	return output, err
}

func createSnifferDaemonset(oc *exutil.CLI, ns, dsName, nodeLabel, labelKey, dstHost, phyInf string, dstPort int) (tcpDS *tcpdumpDaemonSet, err error) {
	buildPruningBaseDir := testdata.FixturePath("networking")
	tcpdumpDSTemplate := filepath.Join(buildPruningBaseDir, "tcpdump-daemonset-template.yaml")

	_, err = runOcWithRetry(oc.AsAdmin().WithoutNamespace(), "adm", "policy", "add-scc-to-user", "privileged", fmt.Sprintf("system:serviceaccount:%s:default", ns))
	o.Expect(err).NotTo(o.HaveOccurred())

	tcpdumpDS := tcpdumpDaemonSet{
		name:         dsName,
		template:     tcpdumpDSTemplate,
		namespace:    ns,
		nodeLabel:    nodeLabel,
		labelKey:     labelKey,
		phyInterface: phyInf,
		dstPort:      dstPort,
		dstHost:      dstHost,
	}

	dsErr := tcpdumpDS.createTcpdumpDS(oc)
	if dsErr != nil {
		return &tcpdumpDS, dsErr
	}

	platform := compat_otp.CheckPlatform(oc)

	// Due to slowness associated with OpenStack cluster through PSI, add a little wait time before checking tcpdumpDS for OSP
	if platform == "openstack" {
		time.Sleep(30 * time.Second)
	}
	dsReadyErr := waitDaemonSetReady(oc, ns, tcpdumpDS.name)
	if dsReadyErr != nil {
		return &tcpdumpDS, dsReadyErr
	}
	return &tcpdumpDS, nil
}

// waitDaemonSetReady by checking  if NumberReady == DesiredNumberScheduled.
func waitDaemonSetReady(oc *exutil.CLI, ns, dsName string) error {
	desiredNumStr, scheduledErr := runOcWithRetry(oc.AsAdmin(), "get", "ds", dsName, "-n", ns, "-ojsonpath={.status.desiredNumberScheduled}")
	if scheduledErr != nil {
		return fmt.Errorf("Cannot get DesiredNumberScheduled for daemonset :%s", dsName)
	}
	desiredNum, convertErr := strconv.Atoi(desiredNumStr)
	o.Expect(convertErr).NotTo(o.HaveOccurred())

	dsErr := wait.Poll(10*time.Second, 5*time.Minute, func() (bool, error) {
		readyNumStr, readyErr := runOcWithRetry(oc.AsAdmin(), "get", "ds", dsName, "-n", ns, "-ojsonpath={.status.numberReady}")
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
		return fmt.Errorf("The  daemonset :%s is not ready", dsName)
	}

	return nil
}

// checkMatchedIPs, match is true, expectIP is expected in logs,match is false, expectIP is NOT expected in logs
func checkMatchedIPs(oc *exutil.CLI, ns, dsName string, searchString, expectedIP string, match bool) error {
	e2e.Logf("Expected egressIP hit egress node logs : %v", match)
	matchErr := wait.Poll(10*time.Second, 30*time.Second, func() (bool, error) {
		foundIPs, searchErr := getSnifferLogs(oc, ns, dsName, searchString)
		o.Expect(searchErr).NotTo(o.HaveOccurred())

		_, ok := foundIPs[expectedIP]
		// Expect there are matched IPs
		if match && !ok {
			e2e.Logf("Waiting for the logs to be synced, try next round.")
			return false, nil
		}
		//Expect there is no matched IP
		if !match && ok {
			e2e.Logf("Waiting for the logs to be synced, try next round.")
			return false, nil
		}

		return true, nil
	})
	e2e.Logf("Checking expected result in tcpdump log got error message as: %v.", matchErr)
	return matchErr
}

// getSnifferLogs scan sniffer logs and return the source IPs for the request.
func getSnifferLogs(oc *exutil.CLI, ns, dsName, searchString string) (map[string]int, error) {
	snifferPods := getPodName(oc, ns, "name="+dsName)
	var snifLogs string
	for _, pod := range snifferPods {
		log, err := runOcWithRetry(oc.AsAdmin(), "logs", pod, "-n", ns)
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
			ipPortSlice := strings.Split(matchLineSlice[9], ".")
			e2e.Logf(matchLineSlice[9])
			ip = strings.Join(ipPortSlice[:len(ipPortSlice)-1], ".")
			e2e.Logf("Found source ip %s in this log line.", ip)
			matchedIPs[ip]++
		}

	} else {
		e2e.Logf("No new log generated!")
	}

	return matchedIPs, nil
}

func getRequestURL(domainName string) (string, string) {
	randomStr := getRandomString()
	url := fmt.Sprintf("curl -s http://%s/?request=%s --connect-timeout 5", domainName, randomStr)
	return randomStr, url
}

func waitCloudPrivateIPconfigUpdate(oc *exutil.CLI, egressIP string, exist bool) {
	platform := compat_otp.CheckPlatform(oc)
	if strings.Contains(platform, "baremetal") || strings.Contains(platform, "vsphere") || strings.Contains(platform, "nutanix") {
		e2e.Logf("Baremetal and Vsphere platform don't have cloudprivateipconfig, no need check cloudprivateipconfig!")
	} else {
		egressipErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			e2e.Logf("Wait for cloudprivateipconfig updated,expect %s exist: %v.", egressIP, exist)
			output, err := runOcWithRetry(oc.AsAdmin(), "get", "cloudprivateipconfig", egressIP, "-ocustom-columns=NAME:.metadata.name,NODE:.spec.node,STATE:.status.conditions[].reason")
			e2e.Logf(output)
			if exist && err == nil && strings.Contains(output, egressIP) && strings.Contains(output, "CloudResponseSuccess") {
				return true, nil
			}
			if !exist && err != nil && strings.Contains(output, "NotFound") {
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(egressipErr, "CloudprivateConfigIP was not updated as expected!")
	}

}

// getSnifPhyInf Get physical interface
func getSnifPhyInf(oc *exutil.CLI, nodeName string) (string, error) {
	var phyInf string
	ifaceErr2 := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 15*time.Second, false, func(cxt context.Context) (bool, error) {
		ifaceList2, ifaceErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		if ifaceErr != nil {
			e2e.Logf("Debug node Error: %v", ifaceErr)
			return false, nil
		}
		e2e.Logf(ifaceList2)
		infList := strings.Split(ifaceList2, "\n")
		for _, inf := range infList {
			if strings.Contains(inf, "ovs-if-phys0") {
				phyInf = strings.Fields(inf)[3]
			}
		}

		return true, nil
	})
	return phyInf, ifaceErr2

}

// nslookDomainName get the first IP
func nslookDomainName(domainName string) string {
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

// verifyEgressIPinTCPDump Verify the EgressIP takes effect.
func verifyEgressIPinTCPDump(oc *exutil.CLI, pod, podNS, expectedEgressIP, dstHost, tcpdumpNS, tcpdumpName string, expectedOrNot bool) error {
	egressipErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
		randomStr, url := getRequestURL(dstHost)
		_, err := e2eoutput.RunHostCmd(podNS, pod, url)
		if checkMatchedIPs(oc, tcpdumpNS, tcpdumpName, randomStr, expectedEgressIP, expectedOrNot) != nil || err != nil {
			e2e.Logf("Expected to find egressIP in tcpdump is: %v, did not get expected result in tcpdump log, try next round.", expectedOrNot)
			return false, nil
		}
		return true, nil
	})

	return egressipErr
}

type instance struct {
	nodeName string
	oc       *exutil.CLI
}

func (i *instance) GetName() string {
	return i.nodeName
}

type ospInstance struct {
	instance
	ospObj compat_otp.Osp
}

// OspCredentials get creds of osp platform
func OspCredentials(oc *exutil.CLI) {
	credentials, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret/openstack-credentials", "-n", "kube-system", "-o", `jsonpath={.data.clouds\.yaml}`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	credential, err := base64.StdEncoding.DecodeString(credentials)
	o.Expect(err).NotTo(o.HaveOccurred())
	var (
		username       string
		password       string
		projectID      string
		authURL        string
		userDomainName string
		regionName     string
		projectName    string
	)
	credVars := []string{"auth_url", "username", "password", "project_id", "user_domain_name", "region_name", "project_name"}
	for _, s := range credVars {
		r, _ := regexp.Compile(`` + s + `:.*`)
		match := r.FindAllString(string(credential), -1)
		if strings.Contains(s, "username") {
			username = strings.Split(match[0], " ")[1]
			os.Setenv("OSP_DR_USERNAME", username)
		}
		if strings.Contains(s, "password") {
			password = strings.Split(match[0], " ")[1]
			os.Setenv("OSP_DR_PASSWORD", password)
		}
		if strings.Contains(s, "auth_url") {
			authURL = strings.Split(match[0], " ")[1]
			os.Setenv("OSP_DR_AUTH_URL", authURL)
		}
		if strings.Contains(s, "project_id") {
			projectID = strings.Split(match[0], " ")[1]
			os.Setenv("OSP_DR_PROJECT_ID", projectID)
		}
		if strings.Contains(s, "user_domain_name") {
			userDomainName = strings.Split(match[0], " ")[1]
			os.Setenv("OSP_DR_USER_DOMAIN_NAME", userDomainName)
		}
		if strings.Contains(s, "region_name") {
			regionName = strings.Split(match[0], " ")[1]
			os.Setenv("OSP_DR_REGION_NAME", regionName)
		}
		if strings.Contains(s, "project_name") {
			projectName = strings.Split(match[0], " ")[1]
			os.Setenv("OSP_DR_PROJECT_NAME", projectName)
		}
	}
}

// VsphereCloudClient pass env details to login function, and used to login
func VsphereCloudClient(oc *exutil.CLI) (*compat_otp.Vmware, *govmomi.Client) {
	credential, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret/vsphere-creds", "-n", "kube-system", "-o", `jsonpath={.data}`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	output := gjson.Parse(credential).Value().(map[string]interface{})
	var accessKeyIDBase64 string
	var secureKeyBase64 string
	for key, value := range output {
		if strings.Contains(key, "username") {
			accessKeyIDBase64 = fmt.Sprint(value)
		} else if strings.Contains(key, "password") {
			secureKeyBase64 = fmt.Sprint(value)
		}
	}
	accessKeyID, err1 := base64.StdEncoding.DecodeString(accessKeyIDBase64)
	o.Expect(err1).NotTo(o.HaveOccurred())
	secureKey, err2 := base64.StdEncoding.DecodeString(secureKeyBase64)
	o.Expect(err2).NotTo(o.HaveOccurred())
	cloudConfig, err3 := oc.AsAdmin().WithoutNamespace().Run("get").Args("cm/cloud-provider-config", "-n", "openshift-config", "-o", `jsonpath={.data.config}`).OutputToFile("vsphere.ini")
	o.Expect(err3).NotTo(o.HaveOccurred())
	cmd := fmt.Sprintf(`grep -i server "%v" | awk -F '"' '{print $2}'`, cloudConfig)
	serverURL, err4 := exec.Command("bash", "-c", cmd).Output()
	e2e.Logf("\n serverURL: %s \n", string(serverURL))
	o.Expect(err4).NotTo(o.HaveOccurred())
	envUsername := string(accessKeyID)
	envPassword := string(secureKey)
	envURL := string(serverURL)
	envURL = strings.TrimSuffix(envURL, "\n")
	encodedPassword := url.QueryEscape(envPassword)
	govmomiURL := fmt.Sprintf("https://%s:%s@%s/sdk", envUsername, encodedPassword, envURL)
	vmware := compat_otp.Vmware{GovmomiURL: govmomiURL}
	return vmware.Login()
}

// startVMOnAzure start one Azure VM
func startVMOnAzure(az *compat_otp.AzureSession, nodeName, rg string) {
	stateErr := wait.Poll(5*time.Second, 120*time.Second, func() (bool, error) {
		vmState, stateErr := compat_otp.GetAzureVMInstanceState(az, nodeName, rg)
		if stateErr != nil {
			e2e.Logf("%v", stateErr)
			return false, nil
		}
		if strings.EqualFold(vmState, "poweredOn") || strings.EqualFold(vmState, "running") || strings.EqualFold(vmState, "active") || strings.EqualFold(vmState, "ready") {
			e2e.Logf("The instance  has been started with state:%s !", vmState)
			return true, nil
		}
		if strings.EqualFold(vmState, "poweredOff") || strings.EqualFold(vmState, "stopped") || strings.EqualFold(vmState, "paused") || strings.EqualFold(vmState, "notready") {
			e2e.Logf("Start instance %s\n", nodeName)
			_, err := compat_otp.StartAzureVM(az, nodeName, rg)
			o.Expect(err).NotTo(o.HaveOccurred())
			return true, nil
		}
		e2e.Logf("The instance  is in %v,not in a state from which it can be started.", vmState)
		return false, nil

	})
	compat_otp.AssertWaitPollNoErr(stateErr, fmt.Sprintf("The instance %s is not in a state from which it can be started.", nodeName))
}

// stopVMOnAzure stop one Azure VM
func stopVMOnAzure(az *compat_otp.AzureSession, nodeName, rg string) {
	stateErr := wait.Poll(5*time.Second, 120*time.Second, func() (bool, error) {
		vmState, stateErr := compat_otp.GetAzureVMInstanceState(az, nodeName, rg)
		if stateErr != nil {
			e2e.Logf("%v", stateErr)
			return false, nil
		}
		if strings.EqualFold(vmState, "poweredoff") || strings.EqualFold(vmState, "stopped") || strings.EqualFold(vmState, "stopping") || strings.EqualFold(vmState, "paused") || strings.EqualFold(vmState, "pausing") || strings.EqualFold(vmState, "deallocated") || strings.EqualFold(vmState, "notready") {
			e2e.Logf("The instance %s has been stopped already, and now is with state:%s !", nodeName, vmState)
			return true, nil
		}
		if strings.EqualFold(vmState, "poweredOn") || strings.EqualFold(vmState, "running") || strings.EqualFold(vmState, "active") || strings.EqualFold(vmState, "ready") {
			e2e.Logf("Stop instance %s\n", nodeName)
			_, err := compat_otp.StopAzureVM(az, nodeName, rg)
			o.Expect(err).NotTo(o.HaveOccurred())
			return true, nil
		}
		e2e.Logf("The instance  is in %v,not in a state from which it can be stopped.", vmState)
		return false, nil

	})
	compat_otp.AssertWaitPollNoErr(stateErr, fmt.Sprintf("The instance %s is not in a state from which it can be stopped.", nodeName))
}

func verifyEgressIPWithIPEcho(oc *exutil.CLI, podNS, podName, ipEchoURL string, hit bool, expectedIPs ...string) {
	timeout := estimateTimeoutForEgressIP(oc)
	if hit {
		egressErr := wait.Poll(5*time.Second, timeout, func() (bool, error) {
			sourceIP, err := e2eoutput.RunHostCmd(podNS, podName, "curl -s "+ipEchoURL+" --connect-timeout 5")
			if err != nil {
				e2e.Logf("error,%v", err)
				return false, nil
			}
			if !contains(expectedIPs, sourceIP) {
				e2e.Logf("Not expected IP,soure IP is %s", sourceIP)
				return false, nil
			}
			return true, nil

		})
		compat_otp.AssertWaitPollNoErr(egressErr, fmt.Sprintf("sourceIP was not included in %v", expectedIPs))
	} else {
		egressErr := wait.Poll(5*time.Second, timeout, func() (bool, error) {
			sourceIP, err := e2eoutput.RunHostCmd(podNS, podName, "curl -s "+ipEchoURL+" --connect-timeout 5")
			if err != nil {
				e2e.Logf("error,%v", err)
				return false, nil
			}
			if contains(expectedIPs, sourceIP) {
				e2e.Logf("Not expected IP,soure IP is %s", sourceIP)
				return false, nil
			}
			return true, nil

		})
		compat_otp.AssertWaitPollNoErr(egressErr, fmt.Sprintf("sourceIP was still included in %v", expectedIPs))
	}
}

func verifyExpectedEIPNumInEIPObject(oc *exutil.CLI, egressIPObject string, expectedNumber int) {
	timeout := estimateTimeoutForEgressIP(oc)
	egressErr := wait.Poll(5*time.Second, timeout, func() (bool, error) {
		egressIPMaps1 := getAssignedEIPInEIPObject(oc, egressIPObject)
		if len(egressIPMaps1) != expectedNumber {
			e2e.Logf("Current EgressIP object length is %v,but expected is %v \n", len(egressIPMaps1), expectedNumber)
			return false, nil
		}
		return true, nil

	})
	compat_otp.AssertWaitPollNoErr(egressErr, fmt.Sprintf("Failed to get expected number egressIPs %v", expectedNumber))
}

func estimateTimeoutForEgressIP(oc *exutil.CLI) time.Duration {
	// https://bugzilla.redhat.com/show_bug.cgi?id=2105801#c8
	// https://issues.redhat.com/browse/OCPBUGS-684
	// Due to above two bugs, Azure and openstack is much slower for egressIP taking effect after configuration.
	timeout := 100 * time.Second
	platform := compat_otp.CheckPlatform(oc)
	if strings.Contains(platform, "azure") || strings.Contains(platform, "openstack") {
		timeout = 210 * time.Second
	}
	return timeout
}

// GetBmhNodeMachineConfig gets Machine Config for BM host node
func GetBmhNodeMachineConfig(oc *exutil.CLI, nodeName string) (string, error) {
	provideIDOutput, bmhErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o", `jsonpath='{.spec.providerID}'`).Output()
	o.Expect(bmhErr).NotTo(o.HaveOccurred())
	bmh := strings.Split(provideIDOutput, "/")[4]
	e2e.Logf("\n The baremetal host for the node is:%v\n", bmh)
	return bmh, bmhErr
}

// stopVMOnIpiBM stop one IPI BM VM
func stopVMOnIPIBM(oc *exutil.CLI, nodeName string) error {
	stopErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
		vmInstance, err := GetBmhNodeMachineConfig(oc, nodeName)
		if err != nil {
			return false, nil
		}
		e2e.Logf("\n\n\n vmInstance for the node is: %v \n\n\n", vmInstance)

		patch := `[{"op": "replace", "path": "/spec/online", "value": false}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("bmh", "-n", "openshift-machine-api", vmInstance, "--type=json", "-p", patch).Execute()
		if patchErr != nil {
			return false, nil
		}
		return true, nil
	})
	e2e.Logf("Not able to stop %s, got error: %v.", nodeName, stopErr)
	return stopErr
}

// startVMOnIpiBM starts one IPI BM VM
func startVMOnIPIBM(oc *exutil.CLI, nodeName string) error {
	startErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
		vmInstance, err := GetBmhNodeMachineConfig(oc, nodeName)
		if err != nil {
			return false, nil
		}
		e2e.Logf("\n\n\n vmInstance for the node is: %v \n\n\n", vmInstance)

		patch := `[{"op": "replace", "path": "/spec/online", "value": true}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("bmh", "-n", "openshift-machine-api", vmInstance, "--type=json", "-p", patch).Execute()
		if patchErr != nil {
			return false, nil
		}
		return true, nil
	})
	e2e.Logf("Not able to start %s, got error: %v.", nodeName, startErr)
	return startErr
}

func specialPlatformCheck(oc *exutil.CLI) bool {
	platform := compat_otp.CheckPlatform(oc)
	specialPlatform := false
	e2e.Logf("Check credential in kube-system to see if this cluster is a special STS cluster.")
	switch platform {
	case "aws":
		credErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("secrets", "-n", "kube-system", "aws-creds").Execute()
		if credErr != nil {
			specialPlatform = true
		}
	case "gcp":
		credErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("secrets", "-n", "kube-system", "gcp-credentials").Execute()
		if credErr != nil {
			specialPlatform = true
		}
	case "azure":
		credErr := getAzureCredentialFromCluster(oc)
		if credErr != nil {
			specialPlatform = true
		}
	default:
		e2e.Logf("Skip this check for other platforms that do not have special STS scenario.")
	}
	return specialPlatform
}

// Get cluster proxy IP
func getProxyIP(oc *exutil.CLI) string {
	httpProxy, err := runOcWithRetry(oc.AsAdmin(), "get", "proxy", "cluster", "-o=jsonpath={.status.httpProxy}")
	o.Expect(err).NotTo(o.HaveOccurred())

	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	proxyIPs := re.FindAllString(httpProxy, -1)
	if len(proxyIPs) == 0 {
		return ""
	}
	return proxyIPs[0]

}

// getIPechoURLFromUPIPrivateVlanBM,  this function is used for template upi-on-baremetal/versioned-installer-packet-http_proxy-private-vlan as IP echo was deployed as part of the template
func getIPechoURLFromUPIPrivateVlanBM(oc *exutil.CLI) string {
	if checkProxy(oc) {
		proxyIP := getProxyIP(oc)
		if proxyIP == "" {
			return ""
		}
		ipEchoURL := net.JoinHostPort(proxyIP, "9095")
		workNode, err := compat_otp.GetFirstWorkerNode(oc)
		o.Expect(err).ShouldNot(o.HaveOccurred())
		_, curlErr := compat_otp.DebugNode(oc, workNode, "curl", "-s", ipEchoURL, "--connect-timeout", "5")
		if curlErr == nil {
			return ipEchoURL
		}
	}
	return ""
}

func getClusterNetworkInfo(oc *exutil.CLI) (string, string) {
	clusterNetworkInfoString, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("network", "cluster", "-o=jsonpath={.spec.clusterNetwork}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	// match out network CIDR and hostPrefix
	pattern := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+\/\d+|\d+`)
	clusterNetworkInfo := pattern.FindAllString(clusterNetworkInfoString, 2)
	networkCIDR := clusterNetworkInfo[0]
	hostPrefix := clusterNetworkInfo[1]
	e2e.Logf("network CIDR: %v;  hostPrefix: %v", networkCIDR, hostPrefix)
	return networkCIDR, hostPrefix
}

// start one instance on Nutanix
func startInstanceOnNutanix(nutanix *compat_otp.NutanixClient, hostname string) {
	instanceID, err := nutanix.GetNutanixVMUUID(hostname)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The instance %s  UUID is :%s", hostname, instanceID)
	stateErr := wait.Poll(5*time.Second, 120*time.Second, func() (bool, error) {
		state, err := nutanix.GetNutanixVMState(instanceID)
		if err != nil {
			e2e.Logf("Failed to get instance state %s, Error: %v", hostname, err)
			return false, nil
		}
		if state == "ON" {
			e2e.Logf("The instance %s is already running", hostname)
			return true, nil
		}
		if state == "OFF" {
			err = nutanix.ChangeNutanixVMState(instanceID, "ON")
			o.Expect(err).NotTo(o.HaveOccurred())
			return true, nil
		}
		e2e.Logf("The instance  is in %v,not in a state from which it can be started.", state)
		return false, nil

	})
	compat_otp.AssertWaitPollNoErr(stateErr, fmt.Sprintf("The instance is not in a state from which it can be started."))
}

// stop one instance on Nutanix
func stopInstanceOnNutanix(nutanix *compat_otp.NutanixClient, hostname string) {
	instanceID, err := nutanix.GetNutanixVMUUID(hostname)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The instance %s  UUID is :%s", hostname, instanceID)
	stateErr := wait.Poll(5*time.Second, 120*time.Second, func() (bool, error) {
		state, err := nutanix.GetNutanixVMState(instanceID)
		if err != nil {
			e2e.Logf("Failed to get instance state %s, Error: %v", hostname, err)
			return false, nil
		}
		if state == "OFF" {
			e2e.Logf("The instance  is already stopped.")
			return true, nil
		}
		if state == "ON" {
			err = nutanix.ChangeNutanixVMState(instanceID, "OFF")
			o.Expect(err).NotTo(o.HaveOccurred())
			return true, nil
		}
		e2e.Logf("The instance is in %v,not in a state from which it can be stopped.", state)
		return false, nil

	})
	compat_otp.AssertWaitPollNoErr(stateErr, fmt.Sprintf("The instance is not in a state from which it can be stopped."))
}

func checkDisconnect(oc *exutil.CLI) bool {
	workNode, err := compat_otp.GetFirstWorkerNode(oc)
	o.Expect(err).ShouldNot(o.HaveOccurred())
	curlCMD := "curl -I ifconfig.me --connect-timeout 5"
	output, err := compat_otp.DebugNode(oc, workNode, "bash", "-c", curlCMD)
	if !strings.Contains(output, "HTTP") || err != nil {
		e2e.Logf("Unable to access the public Internet from the cluster.")
		return true
	}

	e2e.Logf("Successfully connected to the public Internet from the cluster.")
	return false
}

// get ibm powervs instance for an OCP node
func newIBMPowerInstance(oc *exutil.CLI, clientPowerVs *compat_otp.IBMPowerVsSession, ibmRegion, ibmVpcName, nodeName string) *ibmPowerVsInstance {
	return &ibmPowerVsInstance{
		instance: instance{
			nodeName: nodeName,
			oc:       oc,
		},
		clientPowerVs: clientPowerVs,
		ibmRegion:     ibmRegion,
		ibmVpcName:    ibmVpcName,
	}
}

// start the ibm powervs instancce
func (ibmPws *ibmPowerVsInstance) Start() error {
	instanceID, status, idErr := compat_otp.GetIBMPowerVsInstanceInfo(ibmPws.clientPowerVs, ibmPws.nodeName)
	o.Expect(idErr).NotTo(o.HaveOccurred())
	e2e.Logf("\n The ibmPowervs instance %s is currently in state: %s \n", ibmPws.nodeName, status)
	if status == "active" {
		e2e.Logf("The node is already in active state, no need to start it again\n")
		return nil
	}
	return compat_otp.PerformInstanceActionOnPowerVs(ibmPws.clientPowerVs, instanceID, "start")
}

// stop the ibm powervs instance
func (ibmPws *ibmPowerVsInstance) Stop() error {
	instanceID, status, idErr := compat_otp.GetIBMPowerVsInstanceInfo(ibmPws.clientPowerVs, ibmPws.nodeName)
	o.Expect(idErr).NotTo(o.HaveOccurred())
	e2e.Logf("\n The ibmPowervs instance %s is currently in state: %s \n", ibmPws.nodeName, status)
	if status == "shutoff" {
		e2e.Logf("The node is already in shutoff state, no need to stop it again\n")
		return nil
	}
	return compat_otp.PerformInstanceActionOnPowerVs(ibmPws.clientPowerVs, instanceID, "stop")
}

func cfgRouteOnExternalHost(oc *exutil.CLI, host string, user string, pod string, ns string, externalIntf string) bool {
	nodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, pod, "-o=jsonpath={.spec.nodeName}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	nodeIp := getNodeIPv4(oc, ns, nodeName)
	podIP := getPodIPv4(oc, ns, pod)
	routeCmd := "ip route add " + podIP + " via " + nodeIp + " dev " + externalIntf

	err = sshRunCmd(host, user, routeCmd)
	if err != nil {
		e2e.Logf("send command %v fail with error info %v", routeCmd, err)
		return false
	} else {
		return true
	}
}

func rmRouteOnExternalHost(oc *exutil.CLI, host string, user string, pod string, ns string) {
	var chkRes bool
	podIP := getPodIPv4(oc, ns, pod)
	routeCmd := "ip route delete " + podIP + " && " + "ip route"
	ipRoute := podIP + "/32"

	outPut, err := sshRunCmdOutPut(host, user, routeCmd)
	if err != nil || strings.Contains(outPut, ipRoute) {
		e2e.Logf("send command %v fail with error info %v", routeCmd, err)
		chkRes = false
	} else {
		e2e.Logf("successfully removed the ip route %v, %v", podIP, outPut)
		chkRes = true
	}
	o.Expect(chkRes).To(o.BeTrue())
}

func sshRunCmdOutPut(host string, user string, cmd string) (string, error) {
	privateKey := os.Getenv("SSH_CLOUD_PRIV_KEY")
	if privateKey == "" {
		privateKey = "../internal/config/keys/openshift-qe.pem"
	}
	sshClient := compat_otp.SshClient{User: user, Host: host, Port: 22, PrivateKey: privateKey}
	return sshClient.RunOutput(cmd)
}

func getNodeFromEIP(oc *exutil.CLI, egressIP, eipObject string) string {
	eipMap := getAssignedEIPInEIPObject(oc, eipObject)
	for _, eipPair := range eipMap {
		if eipPair["egressIP"] == egressIP {
			return eipPair["node"]
		}
	}
	return ""
}

// enableIPForwarding enable or disable IP forwarding on all nodes
func enableIPForwarding(oc *exutil.CLI, enable bool) {
	currentStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("network.operator", "cluster", "-o=jsonpath={.spec.defaultNetwork.ovnKubernetesConfig.gatewayConfig.ipForwarding}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	currentStatus = strings.TrimSpace(currentStatus)

	// Track if we actually made a change
	changeMade := false

	if enable && currentStatus != "Global" {
		e2e.Logf("Enable IP forwarding on all nodes (current status: %q)", currentStatus)
		patch := `[{"op": "replace", "path": "/spec/defaultNetwork/ovnKubernetesConfig/gatewayConfig/ipForwarding", "value": "Global"}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("network.operator", "cluster", "--type=json", "-p", patch).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		changeMade = true
	} else if !enable && currentStatus == "Global" {
		e2e.Logf("Disable IP forwarding on all nodes (current status: %q)", currentStatus)
		patch := `[{"op": "replace", "path": "/spec/defaultNetwork/ovnKubernetesConfig/gatewayConfig/ipForwarding", "value": "Restricted"}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("network.operator", "cluster", "--type=json", "-p", patch).Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())
		changeMade = true
	} else {
		e2e.Logf("IP forwarding status already set to desired state (current: %q, desired enable: %v), skipping patch", currentStatus, enable)
	}

	// Only wait for rollout if we actually made a change
	if changeMade {
		// check ovnkube-node ds rollout status and confirm if rollout has triggered
		err = wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 6*time.Minute, false, func(cxt context.Context) (bool, error) {
			status, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", "openshift-ovn-kubernetes", "ds", "ovnkube-node", "--timeout", "5m").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			if strings.Contains(status, "rollout to finish") && strings.Contains(status, "successfully rolled out") {
				e2e.Logf("ovnkube rollout was triggerred and rolled out successfully")
				return true, nil
			}
			e2e.Logf("ovnkube rollout trigger hasn't happened yet. Trying again")
			return false, nil
		})
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// checkInterfaceExistsOnHypervisorHost checks if the interface exists on hypervisor host
func checkInterfaceExistsOnHypervisorHost(host, inferfaceStr string) bool {
	showInfCmd := "ip link show " + inferfaceStr
	err := sshRunCmd(host, "root", showInfCmd)
	if err != nil {
		e2e.Logf("The interface %v does not exist on host %v", inferfaceStr, host)
		return false
	}
	return true
}

// getEC2Service creates and returns an EC2 service client
func getEC2Service() (*ec2.EC2, error) {
	mySession := awsSession.Must(awsSession.NewSession())
	svc := ec2.New(mySession, aws.NewConfig())
	return svc, nil
}

// getNetworkInterfaceID gets the primary network interface ID for an EC2 instance
func getNetworkInterfaceID(a *compat_otp.AwsClient, instanceID string) (string, error) {
	svc, err := getEC2Service()
	if err != nil {
		return "", fmt.Errorf("failed to create EC2 service: %v", err)
	}

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{&instanceID},
	}

	result, err := svc.DescribeInstances(input)
	if err != nil {
		return "", fmt.Errorf("failed to describe instance %s: %v", instanceID, err)
	}

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("no instance found with ID %s", instanceID)
	}

	instance := result.Reservations[0].Instances[0]
	if len(instance.NetworkInterfaces) == 0 {
		return "", fmt.Errorf("instance %s has no network interfaces", instanceID)
	}

	// Get the primary network interface (DeviceIndex 0)
	for _, eni := range instance.NetworkInterfaces {
		if eni.Attachment != nil && *eni.Attachment.DeviceIndex == 0 {
			return *eni.NetworkInterfaceId, nil
		}
	}

	return "", fmt.Errorf("no primary network interface found for instance %s", instanceID)
}

// assignPrivateIPsToENI assigns the specified number of secondary private IP addresses to a network interface
// Returns the list of assigned IP addresses
func assignPrivateIPsToENI(a *compat_otp.AwsClient, networkInterfaceID string, count int) ([]string, error) {
	if count <= 0 {
		return []string{}, nil
	}

	svc, err := getEC2Service()
	if err != nil {
		return nil, fmt.Errorf("failed to create EC2 service: %v", err)
	}

	input := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             &networkInterfaceID,
		SecondaryPrivateIpAddressCount: aws.Int64(int64(count)),
	}

	result, err := svc.AssignPrivateIpAddresses(input)
	if err != nil {
		return nil, fmt.Errorf("failed to assign private IP addresses to %s: %v", networkInterfaceID, err)
	}

	assignedIPs := make([]string, 0)
	if result.AssignedPrivateIpAddresses != nil {
		for _, ip := range result.AssignedPrivateIpAddresses {
			if ip.PrivateIpAddress != nil {
				assignedIPs = append(assignedIPs, *ip.PrivateIpAddress)
			}
		}
	}

	e2e.Logf("Assigned %d private IPs to network interface %s: %v", count, networkInterfaceID, assignedIPs)
	return assignedIPs, nil
}

// unassignPrivateIPsFromENI removes secondary private IP addresses from a network interface
func unassignPrivateIPsFromENI(a *compat_otp.AwsClient, networkInterfaceID string, ipAddresses []string) error {
	if len(ipAddresses) == 0 {
		return nil
	}

	svc, err := getEC2Service()
	if err != nil {
		return fmt.Errorf("failed to create EC2 service: %v", err)
	}

	// Convert string slice to []*string for AWS SDK
	awsIPs := make([]*string, len(ipAddresses))
	for i := range ipAddresses {
		awsIPs[i] = &ipAddresses[i]
	}

	input := &ec2.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: &networkInterfaceID,
		PrivateIpAddresses: awsIPs,
	}

	_, err = svc.UnassignPrivateIpAddresses(input)
	if err != nil {
		return fmt.Errorf("failed to unassign private IP addresses from %s: %v", networkInterfaceID, err)
	}

	e2e.Logf("Unassigned %d private IPs from network interface %s", len(ipAddresses), networkInterfaceID)
	return nil
}

func restartCNCC(oc *exutil.CLI) {
	restartErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "--all", "-n", "openshift-cloud-network-config-controller").Execute()
	o.Expect(restartErr).NotTo(o.HaveOccurred())
	// Wait for pods to be ready again
	readyErr := wait.Poll(10*time.Second, 300*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", "openshift-cloud-network-config-controller", "-o=jsonpath={.items[*].status.conditions[?(@.type=='Ready')].status}").Output()
		if err != nil {
			e2e.Logf("Error getting pod status: %v", err)
			return false, nil
		}
		if !strings.Contains(output, "True") {
			e2e.Logf("Waiting for cloud network config controller pods to be ready...")
			return false, nil
		}
		e2e.Logf("Cloud network config controller pods are ready")
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(readyErr, "Cloud network config controller pods did not become ready")
}
