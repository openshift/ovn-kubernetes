package oteutils

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

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

func DebugNodeWithOptionsAndChroot(oc *exutil.CLI, nodeName string, options []string, cmd ...string) (string, error) {
	args := []string{"-n", "default", "node/" + nodeName}
	args = append(args, options...)
	args = append(args, "--")
	chrootCmd := append([]string{"chroot", "/host"}, cmd...)
	args = append(args, chrootCmd...)
	output, err := oc.AsAdmin().WithoutNamespace().Run("debug").Args(args...).Output()
	return output, err
}
