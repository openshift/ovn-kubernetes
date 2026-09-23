package oteutils

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

type EgressIPResource1 struct {
	Name          string
	Template      string
	EgressIP1     string
	EgressIP2     string
	NsLabelKey    string
	NsLabelValue  string
	PodLabelKey   string
	PodLabelValue string
}

func (egressIP *EgressIPResource1) CreateEgressIPObject1(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", egressIP.Template, "-p", "NAME="+egressIP.Name, "EGRESSIP1="+egressIP.EgressIP1, "EGRESSIP2="+egressIP.EgressIP2)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to create EgressIP %v", egressIP.Name))
}

func (egressIP *EgressIPResource1) DeleteEgressIPObject1(oc *exutil.CLI) {
	RemoveResource(oc, true, true, "egressip", egressIP.Name)
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

func RemoveResource(oc *exutil.CLI, asAdmin bool, withoutNamespace bool, parameters ...string) {
	output, err := DoAction(oc, "delete", asAdmin, withoutNamespace, parameters...)
	if err != nil && (strings.Contains(output, "NotFound") || strings.Contains(output, "No resources found")) {
		e2e.Logf("the resource is deleted already")
		return
	}
	o.Expect(err).NotTo(o.HaveOccurred())

	err = wait.Poll(3*time.Second, 120*time.Second, func() (bool, error) {
		output, err := DoAction(oc, "get", asAdmin, withoutNamespace, parameters...)
		if err != nil && (strings.Contains(output, "NotFound") || strings.Contains(output, "No resources found")) {
			e2e.Logf("the resource is delete successfully")
			return true, nil
		}
		return false, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("fail to delete resource %v", parameters))
}

func ApplyResourceFromTemplateByAdmin(oc *exutil.CLI, parameters ...string) error {
	var processedContent string
	err := wait.Poll(3*time.Second, 15*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().Run("process").Args(parameters...).Output()
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		processedContent = output
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("as admin fail to process %v", parameters))

	return oc.WithoutNamespace().AsAdmin().Run("apply").InputString(processedContent).Args("-f", "-").Execute()
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

func CheckPlatform(oc *exutil.CLI) string {
	output, _ := oc.WithoutNamespace().AsAdmin().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.type}").Output()
	return strings.ToLower(output)
}

func CheckNetworkType(oc *exutil.CLI) string {
	output, _ := oc.WithoutNamespace().AsAdmin().Run("get").Args("network.operator", "cluster", "-o=jsonpath={.spec.defaultNetwork.type}").Output()
	return strings.ToLower(output)
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

func IsHypershiftHostedCluster(oc *exutil.CLI) bool {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.controlPlaneTopology}").Output()
	if err != nil {
		return false
	}
	return strings.Contains(output, "External")
}

func GetPodIPv4(oc *exutil.CLI, namespace string, podName string) string {
	podIPv4, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The pod  %s IP in namespace %s is %q", podName, namespace, podIPv4)
	return podIPv4
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

// For normal user to create resources in the specified namespace from the file (not template)
func CreateResourceFromFile(oc *exutil.CLI, ns, file string) {
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", file, "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func WaitForPodWithLabelReady(oc *exutil.CLI, ns, label string) error {
	return wait.Poll(5*time.Second, 5*time.Minute, func() (bool, error) {
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

func WaitForPodWithLabelGone(oc *exutil.CLI, ns, label string) error {
	errWait := wait.Poll(5*time.Second, 10*time.Minute, func() (bool, error) {
		podsOutput, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label).Output()
		if strings.Contains(podsOutput, "NotFound") || strings.Contains(podsOutput, "No resources found") {
			e2e.Logf("the resource is deleted already")
			return true, nil
		}
		e2e.Logf("Wait for pods to be deleted, retrying...")
		return false, nil
	})
	if errWait != nil {
		return fmt.Errorf("case: %v\nerror: %s", g.CurrentSpecReport().FullText(), fmt.Sprintf("pod with lable %v in ns %v is not gone", label, ns))
	}
	return nil

}

func GetSAToken(oc *exutil.CLI) (string, error) {
	token, err := oc.AsAdmin().WithoutNamespace().Run("sa").Args("get-token", "prometheus-k8s", "-n", "openshift-monitoring").Output()
	if err != nil {
		// Fallback: create a token
		token, err = oc.AsAdmin().WithoutNamespace().Run("create").Args("token", "prometheus-k8s", "-n", "openshift-monitoring").Output()
	}
	return token, err
}

func GetOVNMetrics(oc *exutil.CLI, url string) string {
	var metricsLog string
	olmToken, err := GetSAToken(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(olmToken).NotTo(o.BeEmpty())
	metricsErr := wait.Poll(5*time.Second, 10*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "-c", "prometheus", "prometheus-k8s-0", "--", "env", "-u", "HTTPS_PROXY", "-u", "https_proxy", "curl", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", olmToken), fmt.Sprintf("%s", url)).Output()
		if err != nil {
			e2e.Logf("Can't get metrics and try again, the error is:%s", err)
			return false, nil
		}
		metricsLog = output
		return true, nil
	})
	o.Expect(metricsErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
	return metricsLog
}

// ExtractMetricValue parses metrics content and returns the value (second field) from the Nth line
// matching metricName. This replaces shell pipelines like: cat file | grep metric | awk 'NR==N{print $2}'
func ExtractMetricValue(content, metricName string, matchIndex int) string {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, metricName) {
			count++
			if count == matchIndex {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					return fields[1]
				}
			}
		}
	}
	return ""
}

func GetOVNMetricsInSpecificContainer(oc *exutil.CLI, containerName string, podName string, url string, metricName string) string {
	var metricValue string
	metricsErr := wait.Poll(5*time.Second, 10*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-ovn-kubernetes", "-c", containerName, podName, "--", "curl", url).Output()
		if err != nil {
			e2e.Logf("Can't get metrics and try again, the error is:%s", err)
			return false, nil
		}
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, metricName+" ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					metricValue = fields[1]
				}
			}
		}
		if metricValue == "" {
			e2e.Logf("Metric %s not found in output, retrying", metricName)
			return false, nil
		}
		e2e.Logf("The output of the %s is : %v", metricName, metricValue)
		return true, nil

	})
	o.Expect(metricsErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
	return metricValue
}

func CheckovnkubeMasterNetworkProgrammingetrics(oc *exutil.CLI, url string, metrics string) {
	olmToken, err := GetSAToken(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(olmToken).NotTo(o.BeEmpty())
	metricsErr := wait.Poll(5*time.Second, 10*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "-c", "prometheus", "prometheus-k8s-0", "--", "curl", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", olmToken), fmt.Sprintf("%s", url)).Output()
		if err != nil {
			e2e.Logf("Can't get metrics and try again, the error is:%s", err)
			return false, nil
		}
		metricsValue := ExtractMetricValue(output, metrics, 2)
		if metricsValue != "" {
			e2e.Logf("The output of the metrics for %s is : %v", metrics, metricsValue)
		} else {
			e2e.Logf("Can't get metrics for %s:", metrics)
			return false, nil
		}
		return true, nil
	})
	o.Expect(metricsErr).NotTo(o.HaveOccurred(), fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
}

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

		err := wait.Poll(30*time.Second, 300*time.Second, func() (bool, error) {
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

func GetControllerManagerLeaderIP(oc *exutil.CLI) string {
	leaderPodName, leaderErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("lease", "openshift-master-controllers", "-n", "openshift-controller-manager", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(leaderErr).NotTo(o.HaveOccurred())
	o.Expect(leaderPodName).ShouldNot(o.BeEmpty(), "leader pod name is empty")
	// holderIdentity format is "<pod-name>_<leader-election-id>", extract just the pod name
	if parts := strings.SplitN(leaderPodName, "_", 2); len(parts) > 1 {
		leaderPodName = parts[0]
	}
	e2e.Logf("The leader pod name is %s", leaderPodName)
	leaderPodIP := GetPodIPv4(oc, "openshift-controller-manager", leaderPodName)
	return leaderPodIP
}

func GetOVNKMasterPod(oc *exutil.CLI) string {
	leaderCtrlPlanePod, leaderNodeLogerr := oc.AsAdmin().WithoutNamespace().Run("get").Args("lease", "ovn-kubernetes-master", "-n", "openshift-ovn-kubernetes", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(leaderNodeLogerr).NotTo(o.HaveOccurred())
	return leaderCtrlPlanePod
}

func GetOVNKPodOnNode(oc *exutil.CLI, namespace string, label string, nodeName string) (string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", namespace, "-l", label, "--field-selector", "spec.nodeName="+nodeName, "-o=jsonpath={.items[0].metadata.name}").Output()
	return output, err
}

func GetClusterNodesBy(oc *exutil.CLI, role string) ([]string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", fmt.Sprintf("node-role.kubernetes.io/%s=", role), "-o=jsonpath={.items[*].metadata.name}").Output()
	if err != nil {
		return nil, err
	}
	if output == "" {
		return []string{}, nil
	}
	return strings.Split(output, " "), nil
}

func GetFirstWorkerNode(oc *exutil.CLI) (string, error) {
	nodes, err := GetClusterNodesBy(oc, "worker")
	if err != nil || len(nodes) == 0 {
		return "", fmt.Errorf("no worker nodes found: %v", err)
	}
	return nodes[0], nil
}
