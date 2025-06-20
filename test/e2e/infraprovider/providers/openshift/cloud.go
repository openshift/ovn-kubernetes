package openshift

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/api/machine/v1beta1"
	machineclient "github.com/openshift/client-go/machine/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/ptr"
)

func (o openshift) delCloudMachine() error {
	return o.machineClient.MachineV1beta1().MachineSets(machineAPINamespace).Delete(context.TODO(), testMachineSetName, metav1.DeleteOptions{})
}

func (c contextOpenshift) addCloudMachine() (*machine, error) {
	newMachine := &machine{}
	if err := c.ensureTestMachineSet(); err != nil {
		fmt.Errorf("failed to ensure test machine set exists: %w", err)
	}
	// get initial count of nodes before scaling
	initWorkerNodeNames, err := getWorkerNodeNameSet(c.kubeClient)
	if err != nil {
		return newMachine, fmt.Errorf("failed to get worker node name: %v", err)
	}
	if err = scaleMachineSetReplicas(c.machineClient, testMachineSetName); err != nil {
		return newMachine, fmt.Errorf("failed to scale machineset %s: %v", testMachineSetName, err)
	}
	if err = waitUntilNodeCountIncByOne(c.kubeClient, initWorkerNodeNames.Len()); err != nil {
		return newMachine, fmt.Errorf("failed to observe new machine being added as a kuberetes node: %v", err)
	}
	if newMachine.name, err = getNewNodeName(c.kubeClient, initWorkerNodeNames); err != nil {
		return newMachine, fmt.Errorf("failed to get newly added node name: %v", err)
	}
	if err = waitUntilNodeReady(c.kubeClient, newMachine.name); err != nil {
		return newMachine, err
	}
	if err = setMachineIPs(c.kubeClient, newMachine); err != nil {
		return newMachine, fmt.Errorf("failed to get node %s IPs: %v", newMachine.name, err)
	}
	if err = c.kubeClient.CoreV1().Nodes().Delete(context.TODO(), newMachine.name, metav1.DeleteOptions{}); err != nil {
		return newMachine, fmt.Errorf("failed to delete kubernetes node %s: %v", newMachine.name, err)
	}
	return newMachine, nil
}

func waitUntilNodeCountIncByOne(kubeClient *kubernetes.Clientset, initNodeCount int) error {
	expectedNodeCount := initNodeCount + 1
	timeout := 5 * time.Minute
	// wait for node count to increment
	err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, timeout, true, func(ctx context.Context) (done bool, err error) {
		currentWorkerNodeNames, err := getWorkerNodeNameSet(kubeClient)
		if err != nil {
			return false, fmt.Errorf("failed to get worker node names: %v", err)
		}
		if currentWorkerNodeNames.Len() == expectedNodeCount {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("nodes failed to scale to %d (timeout %s): %v", expectedNodeCount, timeout.String(), err)
	}
	return nil
}

// listWorkerMachineSets list all worker machineSets
func (c contextOpenshift) ensureTestMachineSet() error {
	machineSets, err := c.machineClient.MachineV1beta1().MachineSets(machineAPINamespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list machine sets: %v", machineSets)
	}
	if len(machineSets.Items) == 0 {
		return fmt.Errorf("at least one machine set must be present")
	}
	for _, machineSet := range machineSets.Items {
		if machineSet.Name == testMachineSetName {
			return nil
		}
	}

	for _, machineSet := range machineSets.Items {
		// skip machine sets that maybe owned by other tests
		if strings.Contains(machineSet.Name, testMachineSetName) {
			continue
		}
		if val, ok := machineSet.Labels[machineLabelRole]; ok {
			if val == "worker" {
				newMachineSet := patchMachineSet(machineSet.DeepCopy())
				_, err = c.machineClient.MachineV1beta1().MachineSets(machineAPINamespace).Create(context.TODO(), newMachineSet, metav1.CreateOptions{})
				return err
			}
		}
	}
	return fmt.Errorf("failed to ensure a test machine set exists")
}

func (m *machine) cloudExecCommand(cmd string) (result, error) {
	var r result
	signer, err := getSigner()
	if err != nil {
		return r, fmt.Errorf("error getting signer: %v", err)
	}
	r, err = runSSHCommand(cmd, m.getValidIP()+":22", signer)
	if err != nil {
		return r, fmt.Errorf("failed to run SSH command for %s@%s: %w: %+v", machineUserName, m.getValidIP(), err, r)
	}
	return r, nil
}

func waitUntilNodeReady(kubeClient *kubernetes.Clientset, nodeName string) error {
	timeout := 5 * time.Minute
	err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, timeout, true, func(ctx context.Context) (done bool, err error) {
		return isNodeReady(kubeClient, nodeName)
	})
	if err != nil {
		return fmt.Errorf("node %s failed to become Ready (timeout %s): %v", nodeName, timeout.String(), err)
	}
	return nil
}

func getNewNodeName(kubeClient *kubernetes.Clientset, initNodeNames sets.Set[string]) (string, error) {
	currentNodeNames, err := getWorkerNodeNameSet(kubeClient)
	if err != nil {
		return "", fmt.Errorf("failed to get worker node names: %v", err)
	}
	deltaNodeNames := initNodeNames.Difference(currentNodeNames).UnsortedList()
	if len(deltaNodeNames) != 1 {
		return "", fmt.Errorf("expected one machine to be added but found %d", len(deltaNodeNames))
	}
	return deltaNodeNames[0], nil
}

func isNodeReady(kubeClient *kubernetes.Clientset, name string) (bool, error) {
	node, err := kubeClient.CoreV1().Nodes().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get kubernetes node %s: %v", name, err)
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			return true, nil
		}
	}
	return false, nil
}

func getWorkerNodeNameSet(kubeClient *kubernetes.Clientset) (sets.Set[string], error) {
	workerNodeNames := sets.New[string]()
	workerNodeList, err := kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{
		LabelSelector: nodeLabelSelectorWorker,
	})
	if err != nil {
		return workerNodeNames, fmt.Errorf("failed to list worker nodes: %v", err)
	}
	for _, workerNode := range workerNodeList.Items {
		workerNodeNames.Insert(workerNode.Name)
	}
	return workerNodeNames, nil
}

func scaleMachineSetReplicas(machineClient *machineclient.Clientset, machineSetName string) error {
	testMachineSet, err := machineClient.MachineV1beta1().MachineSets(machineAPINamespace).Get(context.TODO(), machineSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get test machine set %s: %v", machineSetName, err)
	}
	replicas := *testMachineSet.Spec.Replicas
	replicas++
	testMachineSet.Spec.Replicas = &replicas
	_, err = machineClient.MachineV1beta1().MachineSets(machineAPINamespace).Update(context.TODO(), testMachineSet, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to get increment replicate count for test machine set: %v", err)
	}
	return nil
}

func patchMachineSet(machineSet *v1beta1.MachineSet) *v1beta1.MachineSet {
	machineSet.Name = testMachineSetName
	machineSet.Spec.Replicas = ptr.To(int32(0))
	machineSet.Spec.Selector.MatchLabels[machineLabelCAPI] = testMachineSetName
	machineSet.Spec.Template.ObjectMeta.Labels[machineLabelCAPI] = testMachineSetName
	return machineSet
}

func getNodeIPAddressForEachFamily(node *corev1.Node) (string, string) {
	var ipv4, ipv6 string
	for _, nodeAddress := range node.Status.Addresses {
		if nodeAddress.Type != corev1.NodeInternalIP && nodeAddress.Type != corev1.NodeExternalIP {
			continue
		}
		if nodeAddress.Address == "" {
			continue
		}
		if ipv4 == "" && !utilnet.IsIPv6String(nodeAddress.Address) {
			ipv4 = nodeAddress.Address
		}
		if ipv6 == "" && utilnet.IsIPv6String(nodeAddress.Address) {
			ipv6 = nodeAddress.Address
		}
	}
	return ipv4, ipv6
}
func setMachineIPs(kubeClient *kubernetes.Clientset, machine *machine) error {
	node, err := kubeClient.CoreV1().Nodes().Get(context.TODO(), machine.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get kubernetes node %s: %v", machine.name, err)
	}
	machine.ipv4, machine.ipv6 = getNodeIPAddressForEachFamily(node)
	return nil
}
