package oteutils

import (
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

type IpBlockCIDRsSingle struct {
	Name      string
	Namespace string
	Cidr      string
	Cidr2     string
	Cidr3     string
	Template  string
}

func (ipBlock_policy *IpBlockCIDRsSingle) CreateipBlockCIDRObjectSingle(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_policy.Template, "-p", "NAME="+ipBlock_policy.Name, "NAMESPACE="+ipBlock_policy.Namespace, "CIDR="+ipBlock_policy.Cidr, "CIDR2="+ipBlock_policy.Cidr2)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create network policy %v", ipBlock_policy.Name))
}

func ApplyResourceFromTemplateByAdmin(oc *exutil.CLI, parameters ...string) error {
	var configFile string
	err := wait.Poll(3*time.Second, 60*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().Run("process").Args(parameters...).OutputToFile(GetRandomString() + "resource.json")
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		configFile = output
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

func CheckNetworkType(oc *exutil.CLI) string {
	output, _ := oc.WithoutNamespace().AsAdmin().Run("get").Args("network.operator", "cluster", "-o=jsonpath={.spec.defaultNetwork.type}").Output()
	return strings.ToLower(output)
}

func CreateResourceFromFile(oc *exutil.CLI, ns, file string) {
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", file, "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func PatchResourceAsAdmin(oc *exutil.CLI, resource, patch string, nameSpace ...string) {
	var cargs []string
	if len(nameSpace) > 0 {
		cargs = []string{resource, "-p", patch, "-n", nameSpace[0], "--type=merge"}
	} else {
		cargs = []string{resource, "-p", patch, "--type=merge"}
	}
	err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(cargs...).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func GetPodName(oc *exutil.CLI, namespace string, label string) []string {
	var podName []string
	podNameAll, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", namespace, "pod", "-l", label, "-ojsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	podName = strings.Split(podNameAll, " ")
	o.Expect(len(podName)).NotTo(o.BeEquivalentTo(0))
	e2e.Logf("The pod(s) are  %v ", podName)
	return podName
}

func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

func IsIPInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

func HostCIDR(ipStr string) string {
	if IsIPv4(ipStr) {
		return ipStr + "/32"
	}
	return ipStr + "/128"
}

func FirstIPByFamily(ips []string, wantIPv4 bool) string {
	for _, ip := range ips {
		if IsIPv4(ip) == wantIPv4 {
			return ip
		}
	}
	return ""
}

func WaitForNetworkOperatorState(oc *exutil.CLI, interval int, timeout int, expectedStatus string) {
	WaitForClusterOperatorState(oc, "network", interval, timeout, expectedStatus)
}

func WaitForClusterOperatorState(oc *exutil.CLI, co string, interval int, timeout int, expectedStatus string) {
	errCheck := wait.Poll(time.Duration(interval)*time.Second, time.Duration(timeout)*time.Minute, func() (bool, error) {
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
	o.Expect(errCheck).NotTo(o.HaveOccurred(), fmt.Sprintf("Timed out waiting for the expected condition"))
}
