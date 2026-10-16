package oteutils

import (
	"context"
	"fmt"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

func DoAction(oc *exutil.CLI, action string, asAdmin bool, withoutNamespace bool, parameters ...string) (string, error) {
	var run *exutil.CLI
	switch {
	case asAdmin && withoutNamespace:
		run = oc.AsAdmin().WithoutNamespace()
	case asAdmin && !withoutNamespace:
		run = oc.AsAdmin()
	case !asAdmin && withoutNamespace:
		run = oc.WithoutNamespace()
	default:
		run = oc
	}
	output, err := run.Run(action).Args(parameters...).Output()
	if err != nil {
		return output, fmt.Errorf("oc %s %v failed: %w", action, parameters, err)
	}
	return output, nil
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

// For normal user to create resources in the specified namespace from the file (not template)
func CreateResourceFromFile(oc *exutil.CLI, ns, file string) {
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", file, "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
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

// GetPodIPs returns all of a pod's IP addresses (one per IP family, so two
// entries on a dual-stack cluster), letting callers exercise every family.
func GetPodIPs(oc *exutil.CLI, namespace string, podName string) []string {
	podIPs, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[*].ip}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	ips := strings.Fields(podIPs)
	o.Expect(ips).NotTo(o.BeEmpty(), fmt.Sprintf("no IPs found for pod %s/%s", namespace, podName))
	e2e.Logf("The pod %s IPs in namespace %s are %v", podName, namespace, ips)
	return ips
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

func LabelPod(oc *exutil.CLI, namespace string, podName string, label string) error {
	return oc.AsAdmin().WithoutNamespace().Run("label").Args("pod", podName, "-n", namespace, label).Execute()
}
