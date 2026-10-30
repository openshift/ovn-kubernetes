package oteutils

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

type PingPodResource struct {
	Name      string
	Namespace string
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
	// Clean up the processed temp file so repeated runs don't leave it on the runner.
	defer func() { _ = os.Remove(configFile) }()
	if err := oc.WithoutNamespace().AsAdmin().Run("apply").Args("-f", configFile).Execute(); err != nil {
		return fmt.Errorf("failed to apply resource from %s: %w", configFile, err)
	}
	return nil
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

// CheckPodReady reports whether the pod's Ready condition is True. A pod can be
// in the Running phase while still unready, and a Succeeded pod cannot serve
// traffic, so gate on the Ready condition rather than the phase to avoid driving
// connectivity checks at a destination that is not yet serving.
func CheckPodReady(oc *exutil.CLI, namespace string, podName string) (bool, error) {
	readyStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, `-o=jsonpath={.status.conditions[?(@.type=="Ready")].status}`).Output()
	if err != nil {
		return false, fmt.Errorf("failed to get ready condition of pod %s/%s: %w", namespace, podName, err)
	}
	return strings.TrimSpace(readyStatus) == "True", nil
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
		// A matched pod whose Ready condition is still absent is omitted from the
		// jsonpath result, so compare the number of Ready states against the number
		// of matched pods and require every state to be "True" (reject False/Unknown).
		names, nerr := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label, "-ojsonpath={.items[*].metadata.name}").Output()
		if nerr != nil {
			e2e.Logf("failed to get pod names: %v, retrying...", nerr)
			return false, nil
		}
		readyStates := strings.Fields(status)
		if len(readyStates) != len(strings.Fields(names)) {
			e2e.Logf("not all matched pods have a Ready condition yet (states=%v), retrying...", status)
			return false, nil
		}
		for _, s := range readyStates {
			if s != "True" {
				e2e.Logf("the pod Ready status not met; wanted all True but got %v, retrying...", status)
				return false, nil
			}
		}
		return true, nil
	})
}

func GetPodName(oc *exutil.CLI, namespace string, label string) []string {
	podNameAll, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", namespace, "pod", "-l", label, "-ojsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	// strings.Fields drops the empty string so a no-match result is caught by the
	// emptiness check (strings.Split("", " ") would return [""], length 1).
	podName := strings.Fields(podNameAll)
	o.Expect(podName).NotTo(o.BeEmpty(), fmt.Sprintf("no pods found with label %s in namespace %s", label, namespace))
	e2e.Logf("The pod(s) are  %v ", podName)
	return podName
}
