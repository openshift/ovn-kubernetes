package oteutils

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	netutils "k8s.io/utils/net"
)

type PingPodResourceNode struct {
	Name      string
	Namespace string
	Nodename  string
	Template  string
}

type AclSettings struct {
	DenySetting  string `json:"deny"`
	AllowSetting string `json:"allow"`
}

func (pod *PingPodResourceNode) CreatePingPodNode(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace, "NODENAME="+pod.Nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
}

func RemoveResource(oc *exutil.CLI, asAdmin bool, withoutNamespace bool, parameters ...string) {
	output, err := DoAction(oc, "delete", asAdmin, withoutNamespace, parameters...)
	if err != nil && (strings.Contains(output, "NotFound") || strings.Contains(output, "No resources found")) {
		e2e.Logf("the resource is deleted already")
		return
	}
	o.Expect(err).NotTo(o.HaveOccurred())

	err = wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, 120*time.Second, true, func(_ context.Context) (bool, error) {
		output, err := DoAction(oc, "get", asAdmin, withoutNamespace, parameters...)
		if err != nil && (strings.Contains(output, "NotFound") || strings.Contains(output, "No resources found")) {
			e2e.Logf("the resource is delete successfully")
			return true, nil
		}
		return false, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to delete resource %v", parameters))
}

func DoAction(oc *exutil.CLI, action string, asAdmin bool, withoutNamespace bool, parameters ...string) (string, error) {
	if asAdmin && withoutNamespace {
		return oc.AsAdmin().WithoutNamespace().Run(action).Args(parameters...).Output()
	}
	if asAdmin && !withoutNamespace {
		return oc.AsAdmin().Run(action).Args(parameters...).Output()
	}
	if !asAdmin && withoutNamespace {
		return oc.WithoutNamespace().Run(action).Args(parameters...).Output()
	}
	if !asAdmin && !withoutNamespace {
		return oc.Run(action).Args(parameters...).Output()
	}
	return "", nil
}

func ApplyResourceFromTemplateByAdmin(oc *exutil.CLI, parameters ...string) error {
	var configFile string
	err := wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, 60*time.Second, true, func(_ context.Context) (bool, error) {
		output, err := oc.AsAdmin().Run("process").Args(parameters...).Output()
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		tmpFile, err := os.CreateTemp("", GetRandomString()+"resource-*.json")
		if err != nil {
			e2e.Logf("failed to create temp file: %v, and try next round", err)
			return false, nil
		}
		defer func() { _ = tmpFile.Close() }()
		if _, err := tmpFile.Write([]byte(output)); err != nil {
			e2e.Logf("failed to write temp file: %v, and try next round", err)
			return false, nil
		}
		configFile = tmpFile.Name()
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("as admin fail to process %v", parameters))

	e2e.Logf("the file of resource is %s", configFile)
	return oc.WithoutNamespace().AsAdmin().Run("apply").Args("-f", configFile).Execute()
}

func GetRandomString() string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	seed := rand.New(rand.NewSource(time.Now().UnixNano()))
	buffer := make([]byte, 8)
	for index := range buffer {
		buffer[index] = chars[seed.Intn(len(chars))]
	}
	return string(buffer)
}

func GetPodStatus(oc *exutil.CLI, namespace string, podName string) (string, error) {
	podStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.phase}").Output()
	if err != nil {
		return "", err
	}
	e2e.Logf("The pod  %s status in namespace %s is %q", podName, namespace, podStatus)
	return podStatus, nil
}

func CheckPodReady(oc *exutil.CLI, namespace string, podName string) (bool, error) {
	podOutPut, err := GetPodStatus(oc, namespace, podName)
	status := []string{"Running", "Ready", "Complete", "Succeeded"}
	return Contains(status, podOutPut), err
}

func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func WaitPodReady(oc *exutil.CLI, namespace string, podName string) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 60*time.Second, true, func(_ context.Context) (bool, error) {
		status, err1 := CheckPodReady(oc, namespace, podName)
		if err1 != nil {
			// Transient errors (apiserver blip, throttling) should not abort the
			// poll; keep retrying until the pod is ready or the timeout fires.
			e2e.Logf("the err:%v, wait for pod %v to become ready.", err1, podName)
			return false, nil
		}
		return status, nil
	})

	if err != nil {
		podDescribe := DescribePod(oc, namespace, podName)
		e2e.Logf("oc describe pod %v.", podName)
		e2e.Logf("%s", podDescribe)
	}
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("pod %v is not ready", podName))
}

func DescribePod(oc *exutil.CLI, namespace string, podName string) string {
	podDescribe, err := oc.WithoutNamespace().Run("describe").Args("pod", "-n", namespace, podName).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The pod  %s status is %q", podName, podDescribe)
	return podDescribe
}

func CheckNetworkType(oc *exutil.CLI) string {
	var networkType string
	// The get can fail transiently (apiserver blip, throttling, connection reset). If we
	// swallowed the error and returned "", callers gate on strings.Contains(type, "ovn")
	// and would falsely skip as "non-ovn cluster". Retry until we get a non-empty type.
	err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		output, err1 := oc.WithoutNamespace().AsAdmin().Run("get").Args("network.operator", "cluster", "-o=jsonpath={.spec.defaultNetwork.type}").Output()
		if err1 != nil || strings.TrimSpace(output) == "" {
			e2e.Logf("failed to get network type (output=%q, err=%v), try next round", output, err1)
			return false, nil
		}
		networkType = strings.ToLower(output)
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to determine cluster network type")
	return networkType
}

func CheckIPStackType(oc *exutil.CLI) string {
	svcNetwork, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("network.operator", "cluster", "-o=jsonpath={.spec.serviceNetwork}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Count(svcNetwork, ":") >= 2 && strings.Count(svcNetwork, ".") >= 2 {
		return "dualstack"
	} else if strings.Count(svcNetwork, ":") >= 2 {
		return "ipv6single"
	} else if strings.Count(svcNetwork, ".") >= 2 {
		return "ipv4single"
	}
	return ""
}

// For normal user to create resources in the specified namespace from the file (not template)
func CreateResourceFromFile(oc *exutil.CLI, ns, file string) {
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", file, "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

// GetPodIP returns IPv6 and IPv4 in vars in order on dual stack respectively and main IP in case of single stack (v4 or v6) in 1st var, and nil in 2nd var
func GetPodIP(oc *exutil.CLI, namespace string, podName string) (string, string) {
	ipStack := CheckIPStackType(oc)
	switch ipStack {
	case "ipv6single", "ipv4single":
		podIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The pod  %s IP in namespace %s is %q", podName, namespace, podIP)
		return podIP, ""
	case "dualstack":
		podIP1, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[1].ip}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The pod's %s 1st IP in namespace %s is %q", podName, namespace, podIP1)
		podIP2, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The pod's %s 2nd IP in namespace %s is %q", podName, namespace, podIP2)
		if netutils.IsIPv6String(podIP1) {
			e2e.Logf("This is IPv4 primary dual stack cluster")
			return podIP1, podIP2
		}
		e2e.Logf("This is IPv6 primary dual stack cluster")
		return podIP2, podIP1
	}
	return "", ""
}

// CurlPod2PodPass checks connectivity across pods regardless of network addressing type on cluster
func CurlPod2PodPass(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := GetPodIP(oc, namespaceDst, podNameDst)
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP2, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlPod2PodFail ensures no connectivity from a pod to pod regardless of network addressing type on cluster
func CurlPod2PodFail(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := GetPodIP(oc, namespaceDst, podNameDst)
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	}
}

func (AclSettings *AclSettings) GetJSONString() string {
	jsonACLSetting, _ := json.Marshal(AclSettings)
	annotationString := "k8s.ovn.org/acl-logging=" + string(jsonACLSetting)
	return annotationString
}

func WaitForNetworkOperatorState(oc *exutil.CLI, interval int, timeout int, expectedStatus string) {
	WaitForClusterOperatorState(oc, "network", interval, timeout, expectedStatus)
}

func WaitForClusterOperatorState(oc *exutil.CLI, co string, interval int, timeout int, expectedStatus string) {
	errCheck := wait.PollUntilContextTimeout(context.TODO(), time.Duration(interval)*time.Second, time.Duration(timeout)*time.Minute, true, func(_ context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", co).Output()
		if err != nil {
			e2e.Logf("Fail to get clusteroperator network, error:%s. Trying again", err)
			return false, nil
		}
		if matched, _ := regexp.MatchString(expectedStatus, output); !matched {
			e2e.Logf("Network operator state is:%s", output)
			return false, nil
		}
		return true, nil
	})
	o.Expect(errCheck).NotTo(o.HaveOccurred(), "Timed out waiting for the expected condition")
}

func SetNamespacePrivileged(oc *exutil.CLI, namespace string) {
	err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", namespace, "security.openshift.io/scc.podSecurityLabelSync=false", "--overwrite").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
	err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", namespace, "pod-security.kubernetes.io/enforce=privileged", "--overwrite").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

// DebugNode runs cmd on the given node via "oc debug node/<name>" without chroot.
// The debug pod uses host networking, so commands such as "ip route" operate on
// the node's host network namespace.
func DebugNode(oc *exutil.CLI, nodeName string, cmd ...string) (string, error) {
	args := []string{"-n", "default", "node/" + nodeName, "--"}
	args = append(args, cmd...)
	return oc.AsAdmin().WithoutNamespace().Run("debug").Args(args...).Output()
}

func DebugNodeWithOptionsAndChroot(oc *exutil.CLI, nodeName string, options []string, cmd ...string) (string, error) {
	args := []string{"-n", "default", "node/" + nodeName}
	args = append(args, options...)
	args = append(args, "--")
	chrootCmd := append([]string{"chroot", "/host"}, cmd...)
	args = append(args, chrootCmd...)
	output, err := oc.AsAdmin().WithoutNamespace().Run("debug").Args(args...).Output()
	return output, err
}

type PingPodResource struct {
	Name      string
	Namespace string
	Template  string
}

func (pod *PingPodResource) CreatePingPod(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
}

type GenericServiceResource struct {
	ServiceName           string
	Namespace             string
	Protocol              string
	Selector              string
	ServiceType           string
	IPFamilyPolicy        string
	ExternalTrafficPolicy string
	InternalTrafficPolicy string
	Template              string
}

func (svc *GenericServiceResource) CreateServiceFromParams(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", svc.Template,
			"-p", "SERVICENAME="+svc.ServiceName, "NAMESPACE="+svc.Namespace, "PROTOCOL="+svc.Protocol,
			"SELECTOR="+svc.Selector, "serviceType="+svc.ServiceType, "ipFamilyPolicy="+svc.IPFamilyPolicy,
			"internalTrafficPolicy="+svc.InternalTrafficPolicy, "externalTrafficPolicy="+svc.ExternalTrafficPolicy)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create svc %v", svc.ServiceName))
}

// GetSvcIP returns the service IPs. For single-stack it returns (clusterIP, "").
// For dual-stack it returns (IPv6, IPv4).
func GetSvcIP(oc *exutil.CLI, namespace, svcName string) (string, string) {
	ipStack := CheckIPStackType(oc)
	if ipStack == "ipv4single" || ipStack == "ipv6single" {
		svcIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		return svcIP, ""
	}
	svcIP0, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	svcIP1, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[1]}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if netutils.IsIPv6String(svcIP0) {
		return svcIP0, svcIP1
	}
	return svcIP1, svcIP0
}

// CurlPod2SvcPass verifies connectivity from a pod to a ClusterIP service on port 27017.
func CurlPod2SvcPass(oc *exutil.CLI, namespaceSrc, namespaceSvc, podNameSrc, svcName string) {
	svcIP1, svcIP2 := GetSvcIP(oc, namespaceSvc, svcName)
	_, err := e2eoutput.RunHostCmdWithRetries(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(svcIP1, "27017"), 3*time.Second, 15*time.Second)
	o.Expect(err).NotTo(o.HaveOccurred())
	if svcIP2 != "" {
		_, err = e2eoutput.RunHostCmdWithRetries(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(svcIP2, "27017"), 3*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// GetOVNKMasterOVNkubeNode returns the ovnkube-node pod running on the node that
// currently holds the ovn-kubernetes-master lease.
func GetOVNKMasterOVNkubeNode(oc *exutil.CLI) string {
	leaderPod, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("lease", "ovn-kubernetes-master", "-n", "openshift-ovn-kubernetes", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	leaderNodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", leaderPod, "-n", "openshift-ovn-kubernetes", "-o=jsonpath={.spec.nodeName}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	ovnKubePod, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-ovn-kubernetes", "-l", "app=ovnkube-node", "--field-selector", "spec.nodeName="+leaderNodeName, "-o=jsonpath={.items[0].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return ovnKubePod
}

// RemoteShPodWithBash runs cmd inside the given pod using bash.
func RemoteShPodWithBash(oc *exutil.CLI, namespace, podName, cmd string) (string, error) {
	return oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", namespace, podName, "--", "bash", "-c", cmd).Output()
}

// CheckPlatform returns the lower-cased cluster platform type.
func CheckPlatform(oc *exutil.CLI) string {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.type}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return strings.ToLower(output)
}

// PatchResourceAsAdmin applies a merge patch to the given resource as admin.
func PatchResourceAsAdmin(oc *exutil.CLI, resource, patch string) {
	err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(resource, "-p", patch, "--type=merge").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

// GetOVNGatewayMode returns "local" or "shared" based on a node's l3-gateway-config.
func GetOVNGatewayMode(oc *exutil.CLI) string {
	nodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "kubernetes.io/os=linux", "-o", "jsonpath={.items[0].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	output, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("node", nodeName).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(output, `"local"`) {
		return "local"
	}
	return "shared"
}

// SwitchOVNGatewayMode migrates the cluster between "local" and "shared" gateway
// modes and waits for the ovnkube-node rollout and network operator to settle.
func SwitchOVNGatewayMode(oc *exutil.CLI, mode string) {
	currentMode := GetOVNGatewayMode(oc)
	switch {
	case currentMode == "local" && mode == "shared":
		PatchResourceAsAdmin(oc, "network.operator/cluster", `{"spec":{"defaultNetwork":{"ovnKubernetesConfig":{"gatewayConfig":{"routingViaHost": false}}}}}`)
	case currentMode == "shared" && mode == "local":
		PatchResourceAsAdmin(oc, "network.operator/cluster", `{"spec":{"defaultNetwork":{"ovnKubernetesConfig":{"gatewayConfig":{"routingViaHost": true}}}}}`)
	default:
		e2e.Logf("Cluster is already on requested gateway mode %s", mode)
	}
	_, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", "openshift-ovn-kubernetes", "ds", "ovnkube-node").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	// On OVN IC the ovnkube-node DaemonSet rollout can take up to ~660s.
	WaitForNetworkOperatorState(oc, 100, 18, "True.*False.*False")
}

// GetNodeIP returns the node's internal IPs. For single-stack it returns
// ("", IP); for dual-stack it returns (IPv6, IPv4).
func GetNodeIP(oc *exutil.CLI, nodeName string) (string, string) {
	ipStack := CheckIPStackType(oc)
	if ipStack == "ipv6single" || ipStack == "ipv4single" {
		internalIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, `-o=jsonpath={.status.addresses[?(@.type=="InternalIP")].address}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		return "", internalIP
	}
	ip1, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[0].address}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	ip2, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[1].address}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if netutils.IsIPv6String(ip1) {
		return ip1, ip2
	}
	return ip2, ip1
}

// GetSvcIPv4 returns the first (IPv4) cluster IP of a service.
func GetSvcIPv4(oc *exutil.CLI, namespace, svcName string) string {
	svcIPv4, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return svcIPv4
}

// CurlPod2SvcFail verifies there is NO connectivity from a pod to a ClusterIP service on port 27017.
func CurlPod2SvcFail(oc *exutil.CLI, namespaceSrc, namespaceSvc, podNameSrc, svcName string) {
	svcIP1, svcIP2 := GetSvcIP(oc, namespaceSvc, svcName)
	_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 3 -s "+net.JoinHostPort(svcIP1, "27017"))
	o.Expect(err).To(o.HaveOccurred())
	if svcIP2 != "" {
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 3 -s "+net.JoinHostPort(svcIP2, "27017"))
		o.Expect(err).To(o.HaveOccurred())
	}
}

// DebugNodeWithChroot runs cmd on a node via "oc debug" chrooted into /host.
func DebugNodeWithChroot(oc *exutil.CLI, nodeName string, cmd ...string) (string, error) {
	return DebugNodeWithOptionsAndChroot(oc, nodeName, []string{"-q"}, cmd...)
}

// LabelPod adds (or with a trailing "-", removes) a label on a pod.
func LabelPod(oc *exutil.CLI, namespace, podName, label string) error {
	return oc.AsAdmin().WithoutNamespace().Run("label").Args("pod", podName, "-n", namespace, label, "--overwrite").Execute()
}

// CreateNamespaceUDN creates a fresh namespace labeled as a primary
// user-defined-network namespace and returns its name.
func CreateNamespaceUDN(oc *exutil.CLI) string {
	ns := "e2e-test-udn-" + GetRandomString()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ns,
			Labels: map[string]string{"k8s.ovn.org/primary-user-defined-network": "null"},
		},
	}
	_, err := oc.AdminKubeClient().CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	oc.KubeFramework().AddNamespacesToDelete(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	return ns
}

type UdnNetDefResource struct {
	Nadname          string
	Namespace        string
	NadNetworkName   string
	Topology         string
	Subnet           string
	NetAttachDefName string
	Role             string
	Template         string
}

func (nad *UdnNetDefResource) CreateUdnNad(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", nad.Template,
			"-p", "NADNAME="+nad.Nadname, "NAMESPACE="+nad.Namespace, "NAD_NETWORK_NAME="+nad.NadNetworkName,
			"TOPOLOGY="+nad.Topology, "SUBNET="+nad.Subnet, "NET_ATTACH_DEF_NAME="+nad.NetAttachDefName, "ROLE="+nad.Role)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create nad %v", nad.Nadname))
}

type UdnPodResource struct {
	Name      string
	Namespace string
	Label     string
	Template  string
}

func (pod *UdnPodResource) CreateUdnPod(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace, "LABEL="+pod.Label)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
}

// WaitForPodWithLabelReady waits until all pods selected by label in ns are Ready.
func WaitForPodWithLabelReady(oc *exutil.CLI, ns, label string) error {
	return wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 3*time.Minute, true, func(_ context.Context) (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label, `-ojsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}`).Output()
		if err != nil || status == "" {
			e2e.Logf("failed to get pod status: %v, retrying...", err)
			return false, nil
		}
		if strings.Contains(status, "False") {
			e2e.Logf("the pod Ready status not met; wanted True but got %v, retrying...", status)
			return false, nil
		}
		return true, nil
	})
}

// GetClusterNodesBy returns the names of nodes with the given role.
func GetClusterNodesBy(oc *exutil.CLI, role string) ([]string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "node-role.kubernetes.io/"+role, "-o", "jsonpath={.items[*].metadata.name}").Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(output), nil
}

type LoadBalancerServiceResource struct {
	Name                          string
	Namespace                     string
	Protocol                      string
	LabelKey                      string
	LabelValue                    string
	ExternalTrafficPolicy         string
	AllocateLoadBalancerNodePorts bool
	Template                      string
}

func (svc *LoadBalancerServiceResource) CreateLoadBalancerService(oc *exutil.CLI) {
	err := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", svc.Template,
		"-p", "NAME="+svc.Name, "NAMESPACE="+svc.Namespace, "PROTOCOL="+svc.Protocol,
		"LABELKEY1="+svc.LabelKey, "LABELVALUE1="+svc.LabelValue,
		"EXTERNALTRAFFICPOLICY="+svc.ExternalTrafficPolicy,
		"NODEPORTALLOCATION="+fmt.Sprintf("%t", svc.AllocateLoadBalancerNodePorts))
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create LoadBalancer service %v", svc.Name))
}

// CheckLoadBalancerSvcStatus waits until the LoadBalancer service is assigned an ingress IP.
func CheckLoadBalancerSvcStatus(oc *exutil.CLI, namespace, svcName string) error {
	return wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 300*time.Second, true, func(_ context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.status.loadBalancer.ingress[0].ip}").Output()
		if err != nil {
			e2e.Logf("Failed to get service status, error:%v. Trying again", err)
			return false, nil
		}
		if strings.Contains(output, "<pending>") || output == "" {
			e2e.Logf("LoadBalancer ingress IP not assigned yet. Trying again")
			return false, nil
		}
		return true, nil
	})
}

// GetLoadBalancerSvcIP returns the LoadBalancer service's ingress IP.
func GetLoadBalancerSvcIP(oc *exutil.CLI, namespace, svcName string) string {
	svcIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.status.loadBalancer.ingress[0].ip}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return svcIP
}

// GetLoadBalancerSvcNodePort returns the nodePort assigned to the LoadBalancer service (empty if none).
func GetLoadBalancerSvcNodePort(oc *exutil.CLI, namespace, svcName string) string {
	nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.ports[0].nodePort}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return nodePort
}

// ValidateService curls the service IP from the given node and checks for the expected response.
func ValidateService(oc *exutil.CLI, curlHostNode, svcExternalIP string) bool {
	output, err := DebugNode(oc, curlHostNode, "curl", svcExternalIP, "--connect-timeout", "5")
	if err != nil {
		e2e.Logf("curl from node %s to %s failed: %v", curlHostNode, svcExternalIP, err)
	}
	return strings.Contains(output, "Hello OpenShift!")
}

const (
	machineAPINamespace = "openshift-machine-api"
	mapiMachineset      = "machinesets.machine.openshift.io"
	mapiMachine         = "machines.machine.openshift.io"
)

// GetInfrastructureName returns the cluster's infrastructure name.
func GetInfrastructureName(oc *exutil.CLI) string {
	name, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.infrastructureName}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return name
}

// GetAllNodes returns the names of all nodes in the cluster.
func GetAllNodes(oc *exutil.CLI) ([]string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-o", "jsonpath={.items[*].metadata.name}").Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(output), nil
}

// GetAllPodsWithLabel returns the names of pods selected by label in a namespace.
func GetAllPodsWithLabel(oc *exutil.CLI, namespace, label string) ([]string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", namespace, "-l", label, "-o", "jsonpath={.items[*].metadata.name}").Output()
	if err != nil || strings.TrimSpace(output) == "" {
		return []string{}, err
	}
	return strings.Fields(output), nil
}

// GetPodNameOnNode returns the name of the pod selected by label running on the given node.
func GetPodNameOnNode(oc *exutil.CLI, namespace, label, node string) (string, error) {
	return oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", namespace, "-l", label, "--field-selector", "spec.nodeName="+node, "-o", "jsonpath={.items[0].metadata.name}").Output()
}

// GetPodNodeName returns the node a pod is scheduled on.
func GetPodNodeName(oc *exutil.CLI, namespace, podName string) (string, error) {
	return oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", namespace, "-o=jsonpath={.spec.nodeName}").Output()
}

// GetPodIPv4 returns the first (IPv4) pod IP.
func GetPodIPv4(oc *exutil.CLI, namespace, podName string) string {
	podIPv4, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return podIPv4
}

// RemoteShPodWithBashSpecifyContainer runs cmd inside a specific container of a pod using bash.
func RemoteShPodWithBashSpecifyContainer(oc *exutil.CLI, namespace, podName, containerName, cmd string) (string, error) {
	return oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", namespace, podName, "-c", containerName, "--", "bash", "-c", cmd).Output()
}

func listWorkerMachineSetNames(oc *exutil.CLI) []string {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(mapiMachineset, "-o=jsonpath={.items[*].metadata.name}", "-n", machineAPINamespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.TrimSpace(output) == "" {
		return nil
	}
	return strings.Fields(output)
}

func getRandomMachineSetName(oc *exutil.CLI) string {
	names := listWorkerMachineSetNames(oc)
	o.Expect(names).NotTo(o.BeEmpty(), "no machinesets found in cluster")
	for _, n := range names {
		if !strings.Contains(n, "rhel") {
			return n
		}
	}
	return names[0]
}

// MachineSetDescription describes a MachineSet to create by cloning an existing one.
type MachineSetDescription struct {
	Name     string
	Replicas int
}

// CreateMachineSet clones an existing worker machineset under a new name/replica count.
// The new nodes are tainted (mapi:NoSchedule) so only pods pinned via nodeName land there.
func (ms *MachineSetDescription) CreateMachineSet(oc *exutil.CLI) {
	srcName := getRandomMachineSetName(oc)
	jsonStr, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(mapiMachineset, srcName, "-n", machineAPINamespace, "-o=json").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	var obj map[string]interface{}
	o.Expect(json.Unmarshal([]byte(jsonStr), &obj)).NotTo(o.HaveOccurred())
	delete(obj, "status")

	if meta, ok := obj["metadata"].(map[string]interface{}); ok {
		meta["name"] = ms.Name
		for _, k := range []string{"resourceVersion", "uid", "creationTimestamp", "generation", "selfLink", "managedFields", "annotations"} {
			delete(meta, k)
		}
	}
	spec, _ := obj["spec"].(map[string]interface{})
	o.Expect(spec).NotTo(o.BeNil())
	spec["replicas"] = ms.Replicas
	if sel, ok := spec["selector"].(map[string]interface{}); ok {
		if ml, ok := sel["matchLabels"].(map[string]interface{}); ok {
			ml["machine.openshift.io/cluster-api-machineset"] = ms.Name
		}
	}
	if tmpl, ok := spec["template"].(map[string]interface{}); ok {
		if tmeta, ok := tmpl["metadata"].(map[string]interface{}); ok {
			if tlabels, ok := tmeta["labels"].(map[string]interface{}); ok {
				tlabels["machine.openshift.io/cluster-api-machineset"] = ms.Name
			}
		}
		if tspec, ok := tmpl["spec"].(map[string]interface{}); ok {
			tspec["taints"] = []interface{}{map[string]interface{}{"effect": "NoSchedule", "key": "mapi", "value": "mapi_test"}}
		}
	}

	out, err := json.Marshal(obj)
	o.Expect(err).NotTo(o.HaveOccurred())
	tmpFile, err := os.CreateTemp("", "machineset-*.json")
	o.Expect(err).NotTo(o.HaveOccurred())
	defer func() { _ = tmpFile.Close() }()
	_, err = tmpFile.Write(out)
	o.Expect(err).NotTo(o.HaveOccurred())

	if err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", tmpFile.Name()).Execute(); err != nil {
		_ = ms.DeleteMachineSet(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
	}
	WaitForMachinesRunning(oc, ms.Replicas, ms.Name)
}

// DeleteMachineSet deletes the machineset.
func (ms *MachineSetDescription) DeleteMachineSet(oc *exutil.CLI) error {
	return oc.AsAdmin().WithoutNamespace().Run("delete").Args(mapiMachineset, ms.Name, "-n", machineAPINamespace).Execute()
}

// WaitForMachinesRunning waits until the machineset reports machineNumber ready replicas.
func WaitForMachinesRunning(oc *exutil.CLI, machineNumber int, machineSetName string) {
	e2e.Logf("Waiting for %d machine(s) in %s to be Running", machineNumber, machineSetName)
	if machineNumber >= 1 {
		time.Sleep(180 * time.Second)
	}
	err := wait.PollUntilContextTimeout(context.TODO(), 60*time.Second, 1200*time.Second, true, func(_ context.Context) (bool, error) {
		msg, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args(mapiMachineset, machineSetName, "-o=jsonpath={.status.readyReplicas}", "-n", machineAPINamespace).Output()
		running, _ := strconv.Atoi(strings.TrimSpace(msg))
		if running != machineNumber {
			e2e.Logf("machineset %s has %d/%d ready replicas, retrying", machineSetName, running, machineNumber)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("machines in %s did not reach Running", machineSetName))
}

// GetMachineNamesFromMachineSet returns the machine names belonging to a machineset.
func GetMachineNamesFromMachineSet(oc *exutil.CLI, machineSetName string) []string {
	machineNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(mapiMachine, "-o=jsonpath={.items[*].metadata.name}", "-l", "machine.openshift.io/cluster-api-machineset="+machineSetName, "-n", machineAPINamespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return strings.Fields(machineNames)
}

// GetNodeNameFromMachine returns the node backing a machine.
func GetNodeNameFromMachine(oc *exutil.CLI, machineName string) string {
	nodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(mapiMachine, machineName, "-o=jsonpath={.status.nodeRef.name}", "-n", machineAPINamespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return nodeName
}

// SvcEndpointDetails identifies a service backend and the ovnkube-node pod on its node.
type SvcEndpointDetails struct {
	OvnKubeNodePod string
	NodeName       string
	PodIP          string
}

// GetOVNConstruct returns the logical switch / router name for the endpoint's node.
func (ep *SvcEndpointDetails) GetOVNConstruct(oc *exutil.CLI, constructType string) string {
	var ovnConstruct string
	getCmd := "ovn-nbctl " + constructType
	_ = wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 2*time.Minute, true, func(_ context.Context) (bool, error) {
		cmdOutput, cmdErr := RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ep.OvnKubeNodePod, getCmd)
		if cmdErr != nil {
			e2e.Logf("%v, waiting for expected result to be synced, retrying", cmdErr)
			return false, nil
		}
		if cmdOutput == "" {
			return true, nil
		}
		var matchStr string
		if constructType == "ls-list" {
			matchStr = fmt.Sprintf(`\((%s)\)`, ep.NodeName)
		} else {
			matchStr = fmt.Sprintf(`\((GR_%s)\)`, ep.NodeName)
		}
		re := regexp.MustCompile(matchStr)
		for _, line := range strings.Split(cmdOutput, "\n") {
			if re.FindString(line) != "" {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					ovnConstruct = fields[0]
				}
			}
		}
		return true, nil
	})
	return ovnConstruct
}

// GetOVNLBConstruct verifies the load_balancer entries for the endpoint's pod IP exist on the construct.
func (ep *SvcEndpointDetails) GetOVNLBConstruct(oc *exutil.CLI, constructType, construct string) bool {
	result := false
	_ = wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 2*time.Minute, true, func(_ context.Context) (bool, error) {
		getCmd := "ovn-nbctl " + constructType + " " + construct + " | grep " + ep.PodIP
		cmdOutput, cmdErr := RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ep.OvnKubeNodePod, "northd", getCmd)
		if cmdErr != nil {
			e2e.Logf("%v, waiting for expected result to be synced, retrying", cmdErr)
			result = false
			return false, nil
		}
		if len(strings.Split(cmdOutput, "\n")) >= 2 {
			result = true
		} else {
			result = false
		}
		return true, nil
	})
	return result
}
