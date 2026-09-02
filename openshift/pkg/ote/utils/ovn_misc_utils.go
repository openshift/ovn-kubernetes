package oteutils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

const (
	MachineAPINamespace = "openshift-machine-api"
	MapiMachineset      = "machinesets.machine.openshift.io"
	MapiMachine         = "machines.machine.openshift.io"
)

func SkipIfMachineAPIUnavailable(oc *exutil.CLI) {
	msg, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachine, "--no-headers", "-n", MachineAPINamespace).Output()
	machinesRunning := strings.Count(msg, "Running")
	if machinesRunning == 0 {
		g.Skip("Expect at least one Running machine. Found none!!!")
	}
}

func GetInfrastructureName(oc *exutil.CLI) string {
	infrastructureName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.infrastructureName}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return infrastructureName
}

func GetRandomMachineSetName(oc *exutil.CLI) string {
	machineSetNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachineset, "-o=jsonpath={.items[*].metadata.name}", "-n", MachineAPINamespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if machineSetNames == "" {
		g.Skip("No machinesets available in cluster, skip test")
	}
	allNames := strings.Split(machineSetNames, " ")
	var filtered []string
	for _, name := range allNames {
		if !strings.Contains(name, "rhel") {
			labels, lerr := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachineset, name, "-o=jsonpath={.spec.template.metadata.labels}", "-n", MachineAPINamespace).Output()
			if lerr == nil && !strings.Contains(labels, `"machine.openshift.io/os-id":"Windows"`) {
				filtered = append(filtered, name)
			}
		}
	}
	if len(filtered) == 0 {
		g.Skip("No suitable Linux worker machinesets available, skip test")
	}
	return filtered[0]
}

func CreateMachineSetFromExisting(oc *exutil.CLI, name string, replicas int) {
	e2e.Logf("Creating a new MachineSet %s with %d replicas...", name, replicas)
	sourceName := GetRandomMachineSetName(oc)
	machineSetJSON, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachineset, sourceName, "-n", MachineAPINamespace, "-o=json").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	var ms map[string]interface{}
	err = json.Unmarshal([]byte(machineSetJSON), &ms)
	o.Expect(err).NotTo(o.HaveOccurred())

	metadata := ms["metadata"].(map[string]interface{})
	metadata["name"] = name
	delete(metadata, "resourceVersion")
	delete(metadata, "uid")
	delete(metadata, "creationTimestamp")
	delete(metadata, "generation")

	spec := ms["spec"].(map[string]interface{})
	spec["replicas"] = float64(replicas)

	selector := spec["selector"].(map[string]interface{})
	matchLabels := selector["matchLabels"].(map[string]interface{})
	matchLabels["machine.openshift.io/cluster-api-machineset"] = name

	tmpl := spec["template"].(map[string]interface{})
	tmplMeta := tmpl["metadata"].(map[string]interface{})
	tmplLabels := tmplMeta["labels"].(map[string]interface{})
	tmplLabels["machine.openshift.io/cluster-api-machineset"] = name

	tmplSpec := tmpl["spec"].(map[string]interface{})
	tmplSpec["taints"] = []interface{}{
		map[string]interface{}{
			"effect": "NoSchedule",
			"key":    "mapi",
			"value":  "mapi_test",
		},
	}

	delete(ms, "status")

	modifiedJSON, err := json.Marshal(ms)
	o.Expect(err).NotTo(o.HaveOccurred())

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("machineset-%s.json", name))
	err = os.WriteFile(tmpFile, modifiedJSON, 0644)
	o.Expect(err).NotTo(o.HaveOccurred())

	if createErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", tmpFile).Execute(); createErr != nil {
		DeleteMachineSet(oc, name)
		o.Expect(createErr).NotTo(o.HaveOccurred())
	}

	if replicas > 0 {
		WaitForMachineSetRunning(oc, replicas, name)
	}
}

func DeleteMachineSet(oc *exutil.CLI, name string) {
	e2e.Logf("Deleting MachineSet %s...", name)
	oc.AsAdmin().WithoutNamespace().Run("delete").Args(MapiMachineset, name, "-n", MachineAPINamespace, "--ignore-not-found=true").Execute()
}

func WaitForMachineSetRunning(oc *exutil.CLI, replicas int, name string) {
	e2e.Logf("Waiting for MachineSet %s to have %d running replicas...", name, replicas)
	pollErr := wait.PollUntilContextTimeout(context.Background(), 60*time.Second, 1200*time.Second, true, func(ctx context.Context) (bool, error) {
		msg, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachineset, name, "-o=jsonpath={.status.readyReplicas}", "-n", MachineAPINamespace).Output()
		readyStr := strings.TrimSpace(msg)
		if readyStr == "" {
			readyStr = "0"
		}
		var ready int
		fmt.Sscanf(readyStr, "%d", &ready)
		if ready != replicas {
			phase, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachine, "-n", MachineAPINamespace, "-l", "machine.openshift.io/cluster-api-machineset="+name, "-o=jsonpath={.items[*].status.phase}").Output()
			if strings.Contains(phase, "Failed") {
				return false, fmt.Errorf("some machines went into Failed phase")
			}
			e2e.Logf("Expected %d machines running, currently %d, waiting...", replicas, ready)
			return false, nil
		}
		e2e.Logf("All %d machines are Running", replicas)
		return true, nil
	})
	if pollErr != nil {
		if strings.Contains(pollErr.Error(), "Failed") {
			g.Skip("Machine provisioning failed, skip test")
		}
		e2e.Failf("Expected %d machines running after 20 minutes, got error: %v", replicas, pollErr)
	}
	if replicas >= 1 {
		WaitForMachineSetNodesReady(oc, name)
	}
}

func WaitForMachineSetNodesReady(oc *exutil.CLI, name string) {
	err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 180*time.Second, false, func(ctx context.Context) (bool, error) {
		nodeNames := GetNodeNamesFromMachineSet(oc, name)
		for _, nodeName := range nodeNames {
			if nodeName == "" {
				continue
			}
			readyStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.status.conditions[?(@.type==\"Ready\")].status}").Output()
			if err != nil || readyStatus != "True" {
				return false, nil
			}
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "some nodes are not ready in 3 minutes")
}

func WaitForMachineSetDeleted(oc *exutil.CLI, name string) {
	e2e.Logf("Waiting for MachineSet %s machines to disappear...", name)
	wait.PollUntilContextTimeout(context.Background(), 60*time.Second, 1200*time.Second, true, func(ctx context.Context) (bool, error) {
		machineNames, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachine, "-o=jsonpath={.items[*].metadata.name}", "-l", "machine.openshift.io/cluster-api-machineset="+name, "-n", MachineAPINamespace).Output()
		if machineNames != "" {
			e2e.Logf("Machines still exist, waiting...")
			return false, nil
		}
		return true, nil
	})
}

func GetMachineNamesFromMachineSet(oc *exutil.CLI, machineSetName string) []string {
	machineNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachine, "-o=jsonpath={.items[*].metadata.name}", "-l", "machine.openshift.io/cluster-api-machineset="+machineSetName, "-n", MachineAPINamespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if machineNames == "" {
		return []string{}
	}
	return strings.Split(machineNames, " ")
}

func GetNodeNamesFromMachineSet(oc *exutil.CLI, machineSetName string) []string {
	nodeNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachine, "-o=jsonpath={.items[*].status.nodeRef.name}", "-l", "machine.openshift.io/cluster-api-machineset="+machineSetName, "-n", MachineAPINamespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if nodeNames == "" {
		return []string{}
	}
	return strings.Split(nodeNames, " ")
}

func GetNodeNameFromMachine(oc *exutil.CLI, machineName string) string {
	nodeName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(MapiMachine, machineName, "-o=jsonpath={.status.nodeRef.name}", "-n", MachineAPINamespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return nodeName
}

func CurlPod2ExternalPass(oc *exutil.CLI, namespaceSrc string, podNameSrc string) {
	output, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -Ik --connect-timeout 5 www.google.com")
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).To(o.ContainSubstring("200"))
}

func AddLabelToNode(oc *exutil.CLI, nodeName string, key string, value string) {
	err := oc.AsAdmin().WithoutNamespace().Run("label").Args("node", nodeName, fmt.Sprintf("%s=%s", key, value), "--overwrite").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func DeleteLabelFromNode(oc *exutil.CLI, nodeName string, key string) {
	err := oc.AsAdmin().WithoutNamespace().Run("label").Args("node", nodeName, key+"-").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func GetAllPods(oc *exutil.CLI, namespace string) ([]string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", namespace, "-o=jsonpath={.items[*].metadata.name}").Output()
	if err != nil {
		return nil, err
	}
	if output == "" {
		return []string{}, nil
	}
	return strings.Split(output, " "), nil
}

func AddAnnotationsToSpecificResource(oc *exutil.CLI, resource string, namespace string, annotation string) {
	args := []string{resource, annotation}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	err := oc.AsAdmin().WithoutNamespace().Run("annotate").Args(args...).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func RemoveAnnotationFromSpecificResource(oc *exutil.CLI, resource string, namespace string, annotation string) {
	args := []string{resource, annotation + "-"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	err := oc.AsAdmin().WithoutNamespace().Run("annotate").Args(args...).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func GetFirstLinuxWorkerNode(oc *exutil.CLI) (string, error) {
	nodes, err := GetSchedulableLinuxWorkerNodes(oc)
	if err != nil {
		return "", err
	}
	if len(nodes) == 0 {
		return "", fmt.Errorf("no schedulable Linux worker nodes found")
	}
	return nodes[0], nil
}

func GetFirstCoreOsWorkerNode(oc *exutil.CLI) (string, error) {
	return GetFirstLinuxWorkerNode(oc)
}

func AssertPodToBeReady(oc *exutil.CLI, podName string, namespace string) {
	err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 120*time.Second, true, func(ctx context.Context) (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", namespace, "-o=jsonpath={.status.phase}").Output()
		if err != nil {
			return false, nil
		}
		return status == "Running", nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), fmt.Sprintf("pod %s is not ready", podName))
}

func AssertWaitPollNoErr(err error, msg string) {
	o.Expect(err).NotTo(o.HaveOccurred(), msg)
}

func CheckNetworkOperatorStatus(oc *exutil.CLI) error {
	return wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 300*time.Second, true, func(ctx context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusteroperators", "network", "-o=jsonpath={.status.conditions}").Output()
		if err != nil {
			return false, nil
		}
		if strings.Contains(output, `"type":"Available"`) && strings.Contains(output, `"status":"True"`) {
			return true, nil
		}
		return false, nil
	})
}

func CheckDisconnect(oc *exutil.CLI) bool {
	workNode, err := GetFirstWorkerNode(oc)
	if err != nil {
		return true
	}
	output, err := DebugNode(oc, workNode, "bash", "-c", "curl -I ifconfig.me --connect-timeout 5")
	if !strings.Contains(output, "HTTP") || err != nil {
		e2e.Logf("Unable to access the public Internet from the cluster.")
		return true
	}
	e2e.Logf("Successfully connected to the public Internet from the cluster.")
	return false
}
