package oteutils

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
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

type PingPodResource struct {
	Name      string
	Namespace string
	Template  string
}

type PingPodResourceNode struct {
	Name      string
	Namespace string
	Nodename  string
	Template  string
}

type IpBlockCIDRsDual struct {
	Name      string
	Namespace string
	CidrIpv4  string
	CidrIpv6  string
	Cidr2Ipv4 string
	Cidr2Ipv6 string
	Cidr3Ipv4 string
	Cidr3Ipv6 string
	Template  string
}

type IpBlockCIDRsSingle struct {
	Name      string
	Namespace string
	Cidr      string
	Cidr2     string
	Cidr3     string
	Template  string
}
type IpBlockCIDRsExceptDual struct {
	Name            string
	Namespace       string
	CidrIpv4        string
	CidrIpv4Except  string
	CidrIpv6        string
	CidrIpv6Except  string
	Cidr2Ipv4       string
	Cidr2Ipv4Except string
	Cidr2Ipv6       string
	Cidr2Ipv6Except string
	Cidr3Ipv4       string
	Cidr3Ipv4Except string
	Cidr3Ipv6       string
	Cidr3Ipv6Except string
	Template        string
}
type IpBlockCIDRsExceptSingle struct {
	Name      string
	Namespace string
	Cidr      string
	Except    string
	Cidr2     string
	Except2   string
	Cidr3     string
	Except3   string
	Template  string
}

type GenericServiceResource struct {
	Servicename           string
	Namespace             string
	Protocol              string
	Selector              string
	ServiceType           string
	IpFamilyPolicy        string
	ExternalTrafficPolicy string
	InternalTrafficPolicy string
	Template              string
}

type AclSettings struct {
	DenySetting  string `json:"deny"`
	AllowSetting string `json:"allow"`
}

func (pod *PingPodResource) CreatePingPod(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.Template, "-p", "NAME="+pod.Name, "NAMESPACE="+pod.Namespace)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create pod %v", pod.Name))
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

// Single CIDR on Dual stack
func (ipBlock_policy *IpBlockCIDRsDual) CreateipBlockCIDRObjectDual(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_policy.Template, "-p", "NAME="+ipBlock_policy.Name, "NAMESPACE="+ipBlock_policy.Namespace, "cidrIpv6="+ipBlock_policy.CidrIpv6, "cidrIpv4="+ipBlock_policy.CidrIpv4)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create network policy %v", ipBlock_policy.Name))
}

// Single CIDR on single stack
func (ipBlock_policy *IpBlockCIDRsSingle) CreateipBlockCIDRObjectSingle(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_policy.Template, "-p", "NAME="+ipBlock_policy.Name, "NAMESPACE="+ipBlock_policy.Namespace, "CIDR="+ipBlock_policy.Cidr)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create network policy %v", ipBlock_policy.Name))
}

// Single IP Block with except clause on Dual stack
func (ipBlock_except_policy *IpBlockCIDRsExceptDual) CreateipBlockExceptObjectDual(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {

		policyApplyError := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_except_policy.Template, "-p", "NAME="+ipBlock_except_policy.Name, "NAMESPACE="+ipBlock_except_policy.Namespace, "CIDR_IPv6="+ipBlock_except_policy.CidrIpv6, "EXCEPT_IPv6="+ipBlock_except_policy.CidrIpv6Except, "CIDR_IPv4="+ipBlock_except_policy.CidrIpv4, "EXCEPT_IPv4="+ipBlock_except_policy.CidrIpv4Except)
		if policyApplyError != nil {
			e2e.Logf("the err:%v, and try next round", policyApplyError)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create network policy %v", ipBlock_except_policy.Name))
}

// Single IP Block with except clause on Single stack
func (ipBlock_except_policy *IpBlockCIDRsExceptSingle) CreateipBlockExceptObjectSingle(oc *exutil.CLI, _ bool) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {

		policyApplyError := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_except_policy.Template, "-p", "NAME="+ipBlock_except_policy.Name, "NAMESPACE="+ipBlock_except_policy.Namespace, "CIDR="+ipBlock_except_policy.Cidr, "EXCEPT="+ipBlock_except_policy.Except)
		if policyApplyError != nil {
			e2e.Logf("the err:%v, and try next round", policyApplyError)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create network policy %v", ipBlock_except_policy.Name))
}

// Function to create ingress or egress policy with multiple CIDRs on Dual Stack Cluster
func (ipBlock_cidrs_policy *IpBlockCIDRsDual) CreateIPBlockMultipleCIDRsObjectDual(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_cidrs_policy.Template, "-p", "NAME="+ipBlock_cidrs_policy.Name, "NAMESPACE="+ipBlock_cidrs_policy.Namespace, "cidrIpv6="+ipBlock_cidrs_policy.CidrIpv6, "cidrIpv4="+ipBlock_cidrs_policy.CidrIpv4, "cidr2Ipv4="+ipBlock_cidrs_policy.Cidr2Ipv4, "cidr2Ipv6="+ipBlock_cidrs_policy.Cidr2Ipv6, "cidr3Ipv4="+ipBlock_cidrs_policy.Cidr3Ipv4, "cidr3Ipv6="+ipBlock_cidrs_policy.Cidr3Ipv6)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create network policy %v", ipBlock_cidrs_policy.Name))
}

// Function to create ingress or egress policy with multiple CIDRs on Single Stack Cluster
func (ipBlock_cidrs_policy *IpBlockCIDRsSingle) CreateIPBlockMultipleCIDRsObjectSingle(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_cidrs_policy.Template, "-p", "NAME="+ipBlock_cidrs_policy.Name, "NAMESPACE="+ipBlock_cidrs_policy.Namespace, "CIDR="+ipBlock_cidrs_policy.Cidr, "CIDR2="+ipBlock_cidrs_policy.Cidr2, "CIDR3="+ipBlock_cidrs_policy.Cidr3)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create network policy %v", ipBlock_cidrs_policy.Name))
}

func (service *GenericServiceResource) CreateServiceFromParams(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", service.Template, "-p", "SERVICENAME="+service.Servicename, "NAMESPACE="+service.Namespace, "PROTOCOL="+service.Protocol, "SELECTOR="+service.Selector, "serviceType="+service.ServiceType, "ipFamilyPolicy="+service.IpFamilyPolicy, "internalTrafficPolicy="+service.InternalTrafficPolicy, "externalTrafficPolicy="+service.ExternalTrafficPolicy)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create svc %v", service.Servicename))
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
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The pod  %s status in namespace %s is %q", podName, namespace, podStatus)
	return podStatus, err
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
			e2e.Logf("the err:%v, wait for pod %v to become ready.", err1, podName)
			return status, err1
		}
		if !status {
			return status, nil
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

func CheckPlatform(oc *exutil.CLI) string {
	output, _ := oc.WithoutNamespace().AsAdmin().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.type}").Output()
	return strings.ToLower(output)
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

func GetPodIPv4(oc *exutil.CLI, namespace string, podName string) string {
	podIPv4, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The pod  %s IP in namespace %s is %q", podName, namespace, podIPv4)
	return podIPv4
}

// For normal user to create resources in the specified namespace from the file (not template)
func CreateResourceFromFile(oc *exutil.CLI, ns, file string) {
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", file, "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func WaitForPodWithLabelReady(oc *exutil.CLI, ns, label string) error {
	return wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 5*time.Minute, true, func(_ context.Context) (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label, "-ojsonpath={.items[*].status.conditions[?(@.type==\"Ready\")].status}").Output()
		e2e.Logf("the Ready status of pod is %v", status)
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

func GetPodName(oc *exutil.CLI, namespace string, label string) []string {
	var podName []string
	podNameAll, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", namespace, "pod", "-l", label, "-ojsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	podName = strings.Split(podNameAll, " ")
	o.Expect(len(podName)).NotTo(o.BeEquivalentTo(0))
	e2e.Logf("The pod(s) are  %v ", podName)
	return podName
}

/*
GetSvcIP returns IPv6 and IPv4 in vars in order on dual stack respectively and main Svc IP in case of single stack (v4 or v6) in 1st var, and nil in 2nd var.
LoadBalancer svc will return Ingress VIP in var1, v4 or v6 and NodePort svc will return Ingress SvcIP in var1 and NodePort in var2
*/
func GetSvcIP(oc *exutil.CLI, namespace string, svcName string) (string, string) {
	ipStack := CheckIPStackType(oc)
	svctype, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.type}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	ipFamilyType, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.IpFamilyPolicy}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if (svctype == "ClusterIP") || (svctype == "NodePort") {
		if (ipStack == "ipv6single") || (ipStack == "ipv4single") {
			svcIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			if svctype == "ClusterIP" {
				e2e.Logf("The service %s IP in namespace %s is %q", svcName, namespace, svcIP)
				return svcIP, ""
			}
			nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("The NodePort service %s IP and NodePort in namespace %s is %s %s", svcName, namespace, svcIP, nodePort)
			return svcIP, nodePort

		} else if (ipStack == "dualstack" && ipFamilyType == "PreferDualStack") || (ipStack == "dualstack" && ipFamilyType == "RequireDualStack") {
			ipFamilyPrecedence, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.ipFamilies[0]}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			//if IPv4 is listed first in ipFamilies then clustrIPs allocation will take order as Ipv4 first and then Ipv6 else reverse
			svcIPv4, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("The service %s IP in namespace %s is %q", svcName, namespace, svcIPv4)
			svcIPv6, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[1]}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("The service %s IP in namespace %s is %q", svcName, namespace, svcIPv6)
			/*As stated Nodeport type svc will return node port value in 2nd var. We don't care about what svc address is coming in 1st var as we evetually going to get
			node IPs later and use that in curl operation to node_ip:nodeport*/
			if ipFamilyPrecedence == "IPv4" {
				e2e.Logf("The ipFamilyPrecedence is Ipv4, Ipv6")
				switch svctype {
				case "NodePort":
					nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
					o.Expect(err).NotTo(o.HaveOccurred())
					e2e.Logf("The Dual Stack NodePort service %s IP and NodePort in namespace %s is %s %s", svcName, namespace, svcIPv4, nodePort)
					return svcIPv4, nodePort
				default:
					return svcIPv6, svcIPv4
				}
			} else {
				e2e.Logf("The ipFamilyPrecedence is Ipv6, Ipv4")
				switch svctype {
				case "NodePort":
					nodePort, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.ports[*].nodePort}").Output()
					o.Expect(err).NotTo(o.HaveOccurred())
					e2e.Logf("The Dual Stack NodePort service %s IP and NodePort in namespace %s is %s %s", svcName, namespace, svcIPv6, nodePort)
					return svcIPv6, nodePort
				default:
					svcIPv4, svcIPv6 = svcIPv6, svcIPv4
					return svcIPv6, svcIPv4
				}
			}
		} else {
			//Its a Dual Stack Cluster with SingleStack ipFamilyPolicy
			svcIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("The service %s IP in namespace %s is %q", svcName, namespace, svcIP)
			return svcIP, ""
		}
	} else {
		//Loadbalancer will be supported for single stack Ipv4 here for mostly GCP,Azure. We can take further enhancements wrt Metal platforms in Metallb utils later
		e2e.Logf("The serviceType is LoadBalancer")
		platform := CheckPlatform(oc)
		var jsonString string
		if platform == "aws" {
			jsonString = "-o=jsonpath={.status.loadBalancer.ingress[0].hostname}"
		} else {
			jsonString = "-o=jsonpath={.status.loadBalancer.ingress[0].ip}"
		}

		err := wait.PollUntilContextTimeout(context.TODO(), 30*time.Second, 300*time.Second, true, func(_ context.Context) (bool, error) {
			svcIP, er := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, jsonString).Output()
			o.Expect(er).NotTo(o.HaveOccurred())
			if svcIP == "" {
				e2e.Logf("Waiting for lb service IP assignment. Trying again...")
				return false, nil
			}
			return true, nil
		})
		o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to assign lb svc IP to %v", svcName))
		lbSvcIP, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, jsonString).Output()
		e2e.Logf("The %s lb service Ingress VIP in namespace %s is %q", svcName, namespace, lbSvcIP)
		return lbSvcIP, ""
	}
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

// CurlNode2PodPass checks node to pod connectivity regardless of network addressing type on cluster
func CurlNode2PodPass(oc *exutil.CLI, nodeName string, namespace string, podName string) {
	//GetPodIP returns IPv6 and IPv4 in order on dual stack in PodIP1 and PodIP2 respectively and main IP in case of single stack (v4 or v6) in PodIP1, and nil in PodIP2
	podIP1, podIP2 := GetPodIP(oc, namespace, podName)
	if podIP2 != "" {
		podv6URL := net.JoinHostPort(podIP1, "8080")
		podv4URL := net.JoinHostPort(podIP2, "8080")
		_, err := DebugNode(oc, nodeName, "curl", podv4URL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = DebugNode(oc, nodeName, "curl", podv6URL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		podURL := net.JoinHostPort(podIP1, "8080")
		_, err := DebugNode(oc, nodeName, "curl", podURL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlNode2PodFail checks node to pod disconnectivity regardless of network addressing type on cluster
func CurlNode2PodFail(oc *exutil.CLI, nodeName string, namespace string, podName string) {
	//GetPodIP returns IPv6 and IPv4 in order on dual stack in PodIP1 and PodIP2 respectively and main IP in case of single stack (v4 or v6) in PodIP1, and nil in PodIP2
	podIP1, podIP2 := GetPodIP(oc, namespace, podName)
	if podIP2 != "" {
		podv6URL := net.JoinHostPort(podIP1, "8080")
		podv4URL := net.JoinHostPort(podIP2, "8080")
		_, err := DebugNode(oc, nodeName, "curl", podv4URL, "-s", "--connect-timeout", "5")
		o.Expect(err).To(o.HaveOccurred())
		_, err = DebugNode(oc, nodeName, "curl", podv6URL, "-s", "--connect-timeout", "5")
		o.Expect(err).To(o.HaveOccurred())
	} else {
		podURL := net.JoinHostPort(podIP1, "8080")
		_, err := DebugNode(oc, nodeName, "curl", podURL, "-s", "--connect-timeout", "5")
		o.Expect(err).To(o.HaveOccurred())
	}
}

// CurlNode2SvcPass checks node to svc connectivity regardless of network addressing type on cluster
func CurlNode2SvcPass(oc *exutil.CLI, nodeName string, namespace string, svcName string) {
	svcIP1, svcIP2 := GetSvcIP(oc, namespace, svcName)
	if svcIP2 != "" {
		svc6URL := net.JoinHostPort(svcIP1, "27017")
		svc4URL := net.JoinHostPort(svcIP2, "27017")
		_, err := DebugNode(oc, nodeName, "curl", svc4URL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = DebugNode(oc, nodeName, "curl", svc6URL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		svcURL := net.JoinHostPort(svcIP1, "27017")
		_, err := DebugNode(oc, nodeName, "curl", svcURL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlNode2SvcFail checks node to svc connectivity regardless of network addressing type on cluster
func CurlNode2SvcFail(oc *exutil.CLI, nodeName string, namespace string, svcName string) {
	svcIP1, svcIP2 := GetSvcIP(oc, namespace, svcName)
	if svcIP2 != "" {
		svc6URL := net.JoinHostPort(svcIP1, "27017")
		svc4URL := net.JoinHostPort(svcIP2, "27017")
		output, _ := DebugNode(oc, nodeName, "curl", svc4URL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("Failed")))
		output, _ = DebugNode(oc, nodeName, "curl", svc6URL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("Failed")))
	} else {
		svcURL := net.JoinHostPort(svcIP1, "27017")
		output, _ := DebugNode(oc, nodeName, "curl", svcURL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("Failed")))
	}
}

// CurlPod2SvcPass checks pod to svc connectivity regardless of network addressing type on cluster
func CurlPod2SvcPass(oc *exutil.CLI, namespaceSrc string, namespaceSvc string, podNameSrc string, svcName string) {
	svcIP1, svcIP2 := GetSvcIP(oc, namespaceSvc, svcName)
	if svcIP2 != "" {
		_, err := e2eoutput.RunHostCmdWithRetries(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(svcIP1, "27017"), 3*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmdWithRetries(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(svcIP2, "27017"), 3*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmdWithRetries(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(svcIP1, "27017"), 3*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlPod2SvcFail ensures no connectivity from a pod to svc regardless of network addressing type on cluster
func CurlPod2SvcFail(oc *exutil.CLI, namespaceSrc string, namespaceSvc string, podNameSrc string, svcName string) {
	svcIP1, svcIP2 := GetSvcIP(oc, namespaceSvc, svcName)
	if svcIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 3 -s "+net.JoinHostPort(svcIP1, "27017"))
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 3 -s "+net.JoinHostPort(svcIP2, "27017"))
		o.Expect(err).To(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 3 -s "+net.JoinHostPort(svcIP1, "27017"))
		o.Expect(err).To(o.HaveOccurred())
	}
}

// For SingleStack function returns IPv6 or IPv4 hostsubnet in case OVN
// For SDN plugin returns only IPv4 hostsubnet
// Dual stack not supported on openshiftSDN
// IPv6 single stack not supported on openshiftSDN
// network can be "default" for the default network or  UDN network name
func GetNodeSubnet(oc *exutil.CLI, nodeName string, network string) string {

	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.k8s\\.ovn\\.org/node-subnets}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	var data map[string]interface{}
	_ = json.Unmarshal([]byte(output), &data)
	hostSubnets := data[network].([]interface{})
	hostSubnet := hostSubnets[0].(string)
	return hostSubnet

}

func GetNodeSubnetDualStack(oc *exutil.CLI, nodeName string, network string) (string, string) {

	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.k8s\\.ovn\\.org/node-subnets}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("output is %v", output)
	var data map[string]interface{}
	_ = json.Unmarshal([]byte(output), &data)
	hostSubnets := data[network].([]interface{})
	hostSubnetIPv4 := hostSubnets[0].(string)
	hostSubnetIPv6 := hostSubnets[1].(string)

	e2e.Logf("Host subnet is %v and %v", hostSubnetIPv4, hostSubnetIPv6)

	return hostSubnetIPv4, hostSubnetIPv6
}

func (AclSettings *AclSettings) GetJSONString() string {
	jsonACLSetting, _ := json.Marshal(AclSettings)
	annotationString := "k8s.ovn.org/acl-logging=" + string(jsonACLSetting)
	return annotationString
}

// find the ovn-K cluster manager master pod
func GetOVNKMasterPod(oc *exutil.CLI) string {
	leaderCtrlPlanePod, leaderNodeLogerr := oc.AsAdmin().WithoutNamespace().Run("get").Args("lease", "ovn-kubernetes-master", "-n", "openshift-ovn-kubernetes", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(leaderNodeLogerr).NotTo(o.HaveOccurred())
	return leaderCtrlPlanePod
}

// find the cluster-manager's ovnkube-node for accessing master components
func GetOVNKMasterOVNkubeNode(oc *exutil.CLI) string {
	leaderPod, leaderNodeLogerr := oc.AsAdmin().WithoutNamespace().Run("get").Args("lease", "ovn-kubernetes-master", "-n", "openshift-ovn-kubernetes", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(leaderNodeLogerr).NotTo(o.HaveOccurred())
	leaderNodeName, getNodeErr := GetPodNodeName(oc, "openshift-ovn-kubernetes", leaderPod)
	o.Expect(getNodeErr).NotTo(o.HaveOccurred())
	ovnKubePod, podErr := GetOVNKPodOnNode(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", leaderNodeName)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	return ovnKubePod
}

func OvnkubeNodePod(oc *exutil.CLI, nodeName string) string {
	ovnNodePod, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", "openshift-ovn-kubernetes", "pod", "-l", "app=ovnkube-node",
		"-o=jsonpath={.items[?(@.spec.nodeName==\""+nodeName+"\")].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The ovnkube-node pod on node %s is %s", nodeName, ovnNodePod)
	o.Expect(ovnNodePod).NotTo(o.BeEmpty())
	return ovnNodePod
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

func NbContructToMap(nbConstruct string) map[string]string {
	listKeyValues := strings.Split(nbConstruct, "\n")
	tempMap := make(map[string]string)
	for _, keyValPair := range listKeyValues {
		keyValItem := strings.SplitN(keyValPair, ":", 2)
		key := strings.Trim(keyValItem[0], " ")
		val := strings.TrimLeft(keyValItem[1], " ")
		tempMap[key] = val

	}
	return tempMap
}

// Create resources in the specified namespace from the file (not template) that is expected to fail
func CreateResourceFromFileWithError(oc *exutil.CLI, ns, file string) error {
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", file, "-n", ns).Execute()
	return err
}

// --- Helper functions migrated from openshift-tests-private ---

// SshClient is a simple SSH client struct
type SshClient struct {
	User       string
	Host       string
	Port       int
	PrivateKey string
}

func (c *SshClient) Run(cmd string) error {
	sshCmd := fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i %s -p %d %s@%s '%s'",
		c.PrivateKey, c.Port, c.User, c.Host, cmd)
	_, err := exec.Command("bash", "-c", sshCmd).CombinedOutput()
	return err
}

func SetNamespacePrivileged(oc *exutil.CLI, namespace string) {
	err := oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", namespace, "security.openshift.io/scc.podSecurityLabelSync=false", "--overwrite").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
	err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", namespace, "pod-security.kubernetes.io/enforce=privileged", "--overwrite").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func GetOVNKPodOnNode(oc *exutil.CLI, namespace string, label string, nodeName string) (string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", namespace, "-l", label, "--field-selector", "spec.nodeName="+nodeName, "-o=jsonpath={.items[0].metadata.name}").Output()
	return output, err
}

func GetPodNodeName(oc *exutil.CLI, namespace string, podName string) (string, error) {
	nodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.spec.nodeName}").Output()
	return nodeName, err
}

func RemoteShPodWithBashSpecifyContainer(oc *exutil.CLI, namespace string, podName string, containerName string, command string) (string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", namespace, "-c", containerName, podName, "--", "bash", "-c", command).Output()
	return output, err
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

func GetSpecificPodLogs(oc *exutil.CLI, namespace string, containerName string, podName string, filter string) (string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", namespace, "-c", containerName, podName).Output()
	if err != nil {
		return "", err
	}
	var filteredLines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, filter) {
			filteredLines = append(filteredLines, line)
		}
	}
	return strings.Join(filteredLines, "\n"), nil
}

func LabelPod(oc *exutil.CLI, namespace string, podName string, label string) error {
	return oc.AsAdmin().WithoutNamespace().Run("label").Args("pod", podName, "-n", namespace, label).Execute()
}

func DebugNode(oc *exutil.CLI, nodeName string, cmd ...string) (string, error) {
	args := []string{"-n", "default", "node/" + nodeName, "--"}
	args = append(args, cmd...)
	output, err := oc.AsAdmin().WithoutNamespace().Run("debug").Args(args...).Output()
	return output, err
}

func IsHypershiftHostedCluster(oc *exutil.CLI) bool {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.controlPlaneTopology}").Output()
	if err != nil {
		return false
	}
	return strings.Contains(output, "External")
}

// NetworkPolicyResource is a struct for creating network policies from templates
type NetworkPolicyResource struct {
	Name             string
	Namespace        string
	Policy           string
	PolicyType       string
	Direction1       string
	NamespaceSel1    string
	NamespaceSelKey1 string
	NamespaceSelVal1 string
	Template         string
}

func (np *NetworkPolicyResource) CreateNetworkPolicy(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(_ context.Context) (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", np.Template, "-p",
			"NAME="+np.Name, "NAMESPACE="+np.Namespace, "POLICY="+np.Policy, "POLICYTYPE="+np.PolicyType,
			"DIRECTION1="+np.Direction1, "NAMESPACESEL1="+np.NamespaceSel1,
			"NAMESPACESELKEY1="+np.NamespaceSelKey1, "NAMESPACESELVAL1="+np.NamespaceSelVal1)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create network policy %v", np.Name))
}
