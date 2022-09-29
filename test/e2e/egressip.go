package e2e

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/onsi/ginkgo"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	utilnet "k8s.io/utils/net"
)

var _ = ginkgo.Describe("e2e egress IP validation", func() {
	const (
		servicePort          int32  = 9999
		podHTTPPort          string = "8080"
		svcname              string = "egressip"
		targetNodeName       string = "egressTargetNode-allowed"
		deniedTargetNodeName string = "egressTargetNode-denied"
		egressIPYaml         string = "egressip.yaml"
		egressFirewallYaml   string = "egressfirewall.yaml"
		waitInterval                = 3 * time.Second
		ciNetworkName               = "kind"
	)

	type node struct {
		name   string
		nodeIP string
	}

	podEgressLabel := map[string]string{
		"wants": "egress",
	}

	var (
		egress1Node, egress2Node, pod1Node, pod2Node, targetNode, deniedTargetNode node
		pod1Name                                                                   = "e2e-egressip-pod-1"
		pod2Name                                                                   = "e2e-egressip-pod-2"
	)

	targetPodAndTest := func(namespace, fromName, toName, toIP string) wait.ConditionFunc {
		return func() (bool, error) {
			stdout, err := framework.RunKubectl(namespace, "exec", fromName, "--", "curl", "--connect-timeout", "2", fmt.Sprintf("%s/hostname", net.JoinHostPort(toIP, podHTTPPort)))
			if err != nil || stdout != toName {
				framework.Logf("Error: attempted connection to pod %s found err:  %v", toName, err)
				return false, nil
			}
			return true, nil
		}
	}

	targetDestinationAndTest := func(namespace, destination string, podNames []string) wait.ConditionFunc {
		return func() (bool, error) {
			for _, podName := range podNames {
				_, err := framework.RunKubectl(namespace, "exec", podName, "--", "curl", "--connect-timeout", "2", "-k", destination)
				if err != nil {
					framework.Logf("Error: attempted connection to API server found err:  %v", err)
					return false, nil
				}
			}
			return true, nil
		}
	}

	removeSliceElement := func(s []string, i int) []string {
		s[i] = s[len(s)-1]
		return s[:len(s)-1]
	}

	// targetExternalContainerAndTest targets the external test container from
	// our test pods, collects its logs and verifies that the logs have traces
	// of the `verifyIPs` provided. We need to target the external test
	// container multiple times until we verify that all IPs provided by
	// `verifyIPs` have been verified. This is done by passing it a slice of
	// verifyIPs and removing each item when it has been found. This function is
	// wrapped in a `wait.PollImmediate` which results in the fact that it only
	// passes once verifyIPs is of length 0. targetExternalContainerAndTest
	// initiates only a single connection at a time, sequentially, hence: we
	// perform one connection attempt, check that the IP seen is expected,
	// remove it from the list of verifyIPs, see that it's length is not 0 and
	// retry again. We do this until all IPs have been seen. If that never
	// happens (because of a bug) the test fails.
	targetExternalContainerAndTest := func(targetNode node, podName, podNamespace string, expectSuccess bool, verifyIPs []string) wait.ConditionFunc {
		return func() (bool, error) {
			_, err := framework.RunKubectl(podNamespace, "exec", podName, "--", "curl", "--connect-timeout", "2", net.JoinHostPort(targetNode.nodeIP, "80"))
			if err != nil {
				if !expectSuccess {
					// curl should timeout with a string containing this error, and this should be the case if we expect a failure
					if !strings.Contains(err.Error(), "Connection timed out") {
						framework.Logf("the test expected netserver container to not be able to connect, but it did with another error, err : %v", err)
						return false, nil
					}
					return true, nil
				}
				return false, nil
			}
			var targetNodeLogs string
			if strings.Contains(targetNode.name, "-host-net-pod") {
				// host-networked-pod
				targetNodeLogs, err = framework.RunKubectl(podNamespace, "logs", targetNode.name)
			} else {
				// external container
				targetNodeLogs, err = runCommand("docker", "logs", targetNode.name)
			}
			if err != nil {
				framework.Logf("failed to inspect logs in test container: %v", err)
				return false, nil
			}
			targetNodeLogs = strings.TrimSuffix(targetNodeLogs, "\n")
			logLines := strings.Split(targetNodeLogs, "\n")
			lastLine := logLines[len(logLines)-1]
			for i := 0; i < len(verifyIPs); i++ {
				if strings.Contains(lastLine, verifyIPs[i]) {
					verifyIPs = removeSliceElement(verifyIPs, i)
					break
				}
			}
			if len(verifyIPs) != 0 && expectSuccess {
				framework.Logf("the test external container did not have any trace of the IPs: %v being logged, last logs: %s", verifyIPs, logLines[len(logLines)-1])
				return false, nil
			}
			if !expectSuccess && len(verifyIPs) == 0 {
				framework.Logf("the test external container did have a trace of the IPs: %v being logged, it should not have, last logs: %s", verifyIPs, logLines[len(logLines)-1])
				return false, nil
			}
			return true, nil
		}
	}

	type egressIPStatus struct {
		Node     string `json:"node"`
		EgressIP string `json:"egressIP"`
	}

	type egressIP struct {
		Status struct {
			Items []egressIPStatus `json:"items"`
		} `json:"status"`
	}
	type egressIPs struct {
		Items []egressIP `json:"items"`
	}

	getEgressIPStatusItems := func() []egressIPStatus {
		egressIPs := egressIPs{}
		egressIPStdout, err := framework.RunKubectl("default", "get", "eip", "-o", "json")
		if err != nil {
			framework.Logf("Error: failed to get the EgressIP object, err: %v", err)
			return nil
		}
		json.Unmarshal([]byte(egressIPStdout), &egressIPs)
		if len(egressIPs.Items) > 1 {
			framework.Failf("Didn't expect to retrieve more than one egress IP during the execution of this test, saw: %v", len(egressIPs.Items))
		}
		return egressIPs.Items[0].Status.Items
	}

	verifyEgressIPStatusLengthEquals := func(statusLength int) []egressIPStatus {
		var statuses []egressIPStatus
		err := wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			statuses = getEgressIPStatusItems()
			return len(statuses) == statusLength, nil
		})
		if err != nil {
			framework.Failf("Error: expected to have %v egress IP assignment, got: %v", statusLength, len(statuses))
		}
		return statuses
	}

	f := framework.NewDefaultFramework(svcname)

	// Determine what mode the CI is running in and get relevant endpoint information for the tests
	ginkgo.BeforeEach(func() {
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(f.ClientSet, 2)
		framework.ExpectNoError(err)
		if len(nodes.Items) < 2 {
			framework.Failf("Test requires >= 2 Ready nodes, but there are only %v nodes", len(nodes.Items))
		}
		ips := e2enode.CollectAddresses(nodes, v1.NodeInternalIP)
		egress1Node = node{
			name:   nodes.Items[0].Name,
			nodeIP: ips[0],
		}
		egress2Node = node{
			name:   nodes.Items[1].Name,
			nodeIP: ips[1],
		}
		pod1Node = node{
			name:   nodes.Items[0].Name,
			nodeIP: ips[0],
		}
		pod2Node = node{
			name:   nodes.Items[1].Name,
			nodeIP: ips[1],
		}
		targetNode = node{
			name: targetNodeName,
		}
		deniedTargetNode = node{
			name: deniedTargetNodeName,
		}
		if utilnet.IsIPv6String(egress1Node.nodeIP) {
			_, targetNode.nodeIP = createClusterExternalContainer(targetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"}, []string{})
			_, deniedTargetNode.nodeIP = createClusterExternalContainer(deniedTargetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"}, []string{})
		} else {
			targetNode.nodeIP, _ = createClusterExternalContainer(targetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"}, []string{})
			deniedTargetNode.nodeIP, _ = createClusterExternalContainer(deniedTargetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"}, []string{})
		}
	})

	ginkgo.AfterEach(func() {
		framework.RunKubectlOrDie("default", "delete", "eip", svcname)
		framework.RunKubectlOrDie("default", "label", "node", egress1Node.name, "k8s.ovn.org/egress-assignable-")
		framework.RunKubectlOrDie("default", "label", "node", egress2Node.name, "k8s.ovn.org/egress-assignable-")
		deleteClusterExternalContainer(targetNode.name)
		deleteClusterExternalContainer(deniedTargetNode.name)
	})

	// Validate the egress IP by creating a httpd container on the kind networking
	// (effectively seen as "outside" the cluster) and curl it from a pod in the cluster
	// which matches the egress IP stanza.

	/* This test does the following:
	   0. Add the "k8s.ovn.org/egress-assignable" label to two nodes
	   1. Create an EgressIP object with two egress IPs defined
	   2. Check that the status is of length two and both are assigned to different nodes
	   3. Create two pods matching the EgressIP: one running on each of the egress nodes
	   4. Check connectivity from both to an external "node" and verify that the IPs are both of the above
	   5. Check connectivity from one pod to the other and verify that the connection is achieved
	   6. Check connectivity from both pods to the api-server (running hostNetwork:true) and verifying that the connection is achieved
	   7. Update one of the pods, unmatching the EgressIP
	   8. Check connectivity from that one to an external "node" and verify that the IP is the node IP.
	   9. Check connectivity from the other one to an external "node"  and verify that the IPs are both of the above
	   10. Remove the node label off one of the egress node
	   11. Check that the status is of length one
	   12. Check connectivity from the remaining pod to an external "node" and verify that the IP is the remaining egress IP
	   13. Remove the node label off the last egress node
	   14. Check that the status is of length zero
	   15. Check connectivity from the remaining pod to an external "node" and verify that the IP is the node IP.
	   16. Re-add the label to one of the egress nodes
	   17. Check that the status is of length one
	   18. Check connectivity from the remaining pod to an external "node" and verify that the IP is the remaining egress IP
	*/
	ginkgo.It("Should validate the egress IP functionality against remote hosts", func() {

		command := []string{"/agnhost", "netexec", fmt.Sprintf("--http-port=%s", podHTTPPort)}

		ginkgo.By("0. Add the \"k8s.ovn.org/egress-assignable\" label to two nodes")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable", "dummy")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		podNamespace := f.Namespace
		podNamespace.Labels = map[string]string{
			"name": f.Namespace.Name,
		}
		updateNamespace(f, podNamespace)

		ginkgo.By("1. Create an EgressIP object with two egress IPs defined")
		dupIP := func(ip net.IP) net.IP {
			dup := make(net.IP, len(ip))
			copy(dup, ip)
			return dup
		}
		// Assign the egress IP without conflicting with any node IP,
		// the kind subnet is /16 or /64 so the following should be fine.
		egressNodeIP := net.ParseIP(egress1Node.nodeIP)
		egressIP1 := dupIP(egressNodeIP)
		egressIP1[len(egressIP1)-2]++
		egressIP2 := dupIP(egressNodeIP)
		egressIP2[len(egressIP2)-2]++
		egressIP2[len(egressIP2)-1]++

		var egressIPConfig = fmt.Sprintf(`apiVersion: k8s.ovn.org/v1
kind: EgressIP
metadata:
    name: ` + svcname + `
spec:
    egressIPs:
    - ` + egressIP1.String() + `
    - ` + egressIP2.String() + `
    podSelector:
        matchLabels:
            wants: egress
    namespaceSelector:
        matchLabels:
            name: ` + f.Namespace.Name + `
`)
		if err := ioutil.WriteFile(egressIPYaml, []byte(egressIPConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}
		defer func() {
			if err := os.Remove(egressIPYaml); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()

		framework.Logf("Create the EgressIP configuration")
		framework.RunKubectlOrDie("default", "create", "-f", egressIPYaml)

		ginkgo.By("2. Check that the status is of length two and both are assigned to different nodes")
		statuses := verifyEgressIPStatusLengthEquals(2)
		if statuses[0].Node == statuses[1].Node {
			framework.Failf("Step 2. Check that the status is of length two and both are assigned to different nodess, failed, err: both egress IPs have been assigned to the same node")
		}

		ginkgo.By("3. Create two pods matching the EgressIP: one running on each of the egress nodes")
		createGenericPodWithLabel(f, pod1Name, pod1Node.name, f.Namespace.Name, command, podEgressLabel)
		createGenericPodWithLabel(f, pod2Name, pod2Node.name, f.Namespace.Name, command, podEgressLabel)

		err := wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			for _, podName := range []string{pod1Name, pod2Name} {
				kubectlOut := getPodAddress(podName, f.Namespace.Name)
				srcIP := net.ParseIP(kubectlOut)
				if srcIP == nil {
					return false, nil
				}
			}
			return true, nil
		})
		framework.ExpectNoError(err, "Step 3. Create two pods matching the EgressIP: one running on each of the egress nodes, failed, err: %v", err)

		pod2IP := getPodAddress(pod2Name, f.Namespace.Name)
		ginkgo.By("4. Check connectivity from both to an external \"node\" and verify that the IPs are both of the above")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP1.String(), egressIP2.String()}))
		framework.ExpectNoError(err, "Step 4. Check connectivity from first to an external \"node\" and verify that the IPs are both of the above, failed: %v", err)
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod2Name, podNamespace.Name, true, []string{egressIP1.String(), egressIP2.String()}))
		framework.ExpectNoError(err, "Step 4. Check connectivity from second to an external \"node\" and verify that the IPs are both of the above, failed: %v", err)

		ginkgo.By("5. Check connectivity from one pod to the other and verify that the connection is achieved")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetPodAndTest(f.Namespace.Name, pod1Name, pod2Name, pod2IP))
		framework.ExpectNoError(err, "Step 5. Check connectivity from one pod to the other and verify that the connection is achieved, failed, err: %v", err)

		ginkgo.By("6. Check connectivity from both pods to the api-server (running hostNetwork:true) and verifying that the connection is achieved")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetDestinationAndTest(podNamespace.Name, fmt.Sprintf("https://%s/version", net.JoinHostPort(getApiAddress(), "443")), []string{pod1Name, pod2Name}))
		framework.ExpectNoError(err, "Step 6. Check connectivity from both pods to the api-server (running hostNetwork:true) and verifying that the connection is achieved, failed, err: %v", err)

		ginkgo.By("7. Update one of the pods, unmatching the EgressIP")
		pod2 := getPod(f, pod2Name)
		pod2.Labels = map[string]string{}
		updatePod(f, pod2)

		ginkgo.By("8. Check connectivity from that one to an external \"node\" and verify that the IP is the node IP.")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod2Name, podNamespace.Name, true, []string{pod2Node.nodeIP}))
		framework.ExpectNoError(err, "Step 8. Check connectivity from that one to an external \"node\" and verify that the IP is the node IP, failed, err: %v", err)

		ginkgo.By("9. Check connectivity from the other one to an external \"node\" and verify that the IPs are both of the above")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP1.String(), egressIP2.String()}))
		framework.ExpectNoError(err, "Step 9. Check connectivity from the other one to an external \"node\" and verify that the IP is one of the egress IPs, failed, err: %v", err)

		ginkgo.By("10. Remove the node label off one of the egress node")
		framework.RemoveLabelOffNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable")

		ginkgo.By("11. Check that the status is of length one")
		statuses = verifyEgressIPStatusLengthEquals(1)

		ginkgo.By("12. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is the remaining egress IP")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{statuses[0].EgressIP}))
		framework.ExpectNoError(err, "Step 12. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is the remaining egress IP, failed, err: %v", err)

		ginkgo.By("13. Remove the node label off the last egress node")
		framework.RemoveLabelOffNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable")

		ginkgo.By("14. Check that the status is of length zero")
		statuses = verifyEgressIPStatusLengthEquals(0)

		ginkgo.By("15. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is the node IP.")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{pod1Node.nodeIP}))
		framework.ExpectNoError(err, "Step  15. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is the node IP, failed, err: %v", err)

		ginkgo.By("16. Re-add the label to one of the egress nodes")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		ginkgo.By("17. Check that the status is of length one")
		statuses = verifyEgressIPStatusLengthEquals(1)

		ginkgo.By("18. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is the remaining egress IP")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{statuses[0].EgressIP}))
		framework.ExpectNoError(err, "Step 18. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is the remaining egress IP, failed, err: %v", err)
	})

	// Validate the egress IP by creating a httpd container on the kind networking
	// (effectively seen as "outside" the cluster) and curl it from a pod in the cluster
	// which matches the egress IP stanza. Aim is to check if the SNATs towards nodeIP versus
	// SNATs towards egressIPs are being correctly deleted and recreated.
	// NOTE: See https://bugzilla.redhat.com/show_bug.cgi?id=2078222 for details on inconsistency

	/* This test does the following:
	   0. Add the "k8s.ovn.org/egress-assignable" label to egress1Node
	   1. Creating host-networked pod, on non-egress node (egress2Node) to act as "another node"
	   2. Create an EgressIP object with one egress IP defined
	   3. Check that the status is of length one and that it is assigned to egress1Node
	   4. Create one pod matching the EgressIP: running on egress1Node
	   5. Check connectivity from pod to an external "node" and verify that the srcIP is the expected egressIP
	   6. Check connectivity from pod to another node (egress2Node) and verify that the srcIP is the expected [egressIP if SGW] & [nodeIP if LGW]
	   7. Add the "k8s.ovn.org/egress-assignable" label to egress2Node
	   8. Remove the "k8s.ovn.org/egress-assignable" label from egress1Node
	   9. Check that the status is of length one and that it is assigned to egress2Node
	   10. Check connectivity from pod to an external "node" and verify that the srcIP is the expected egressIP
	   11. Check connectivity from pod to another node (egress2Node) and verify that the srcIP is the expected nodeIP (known inconsistency compared to step 6 for SGW)
	   12. Create second pod not matching the EgressIP: running on egress1Node
	   13. Check connectivity from second pod to external node and verify that the srcIP is the expected nodeIP
	   14. Add pod selector label to make second pod egressIP managed
	   15. Check connectivity from second pod to external node and verify that the srcIP is the expected egressIP
	   16. Check connectivity from second pod to another node (egress2Node) and verify that the srcIP is the expected nodeIP (this verifies SNAT's towards nodeIP are not deleted for pods unless pod is on its own egressNode)
	*/
	ginkgo.It("Should validate the egress IP SNAT functionality against host-networked pods", func() {

		command := []string{"/agnhost", "netexec", fmt.Sprintf("--http-port=%s", podHTTPPort)}

		ginkgo.By("0. Add the \"k8s.ovn.org/egress-assignable\" label to egress1Node node")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable", "dummy")
		framework.Logf("Added egress-assignable label to node %s", egress1Node.name)
		framework.ExpectNodeHasLabel(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		ginkgo.By("1. Creating host-networked pod, on non-egress node to act as \"another node\"")
		_, err := createPod(f, egress2Node.name+"-host-net-pod", egress2Node.name, f.Namespace.Name, []string{}, map[string]string{}, func(p *v1.Pod) {
			p.Spec.HostNetwork = true
			p.Spec.Containers[0].Image = "docker.io/httpd"
		})
		framework.ExpectNoError(err)
		hostNetPod := node{
			name:   egress2Node.name + "-host-net-pod",
			nodeIP: egress2Node.nodeIP,
		}
		framework.Logf("Created pod %s on node %s", hostNetPod.name, egress2Node.name)

		podNamespace := f.Namespace
		podNamespace.Labels = map[string]string{
			"name": f.Namespace.Name,
		}
		updateNamespace(f, podNamespace)

		ginkgo.By("2. Create an EgressIP object with one egress IP defined")
		dupIP := func(ip net.IP) net.IP {
			dup := make(net.IP, len(ip))
			copy(dup, ip)
			return dup
		}
		// Assign the egress IP without conflicting with any node IP,
		// the kind subnet is /16 or /64 so the following should be fine.
		egressNodeIP := net.ParseIP(egress1Node.nodeIP)
		egressIP1 := dupIP(egressNodeIP)
		egressIP1[len(egressIP1)-2]++

		var egressIPConfig = fmt.Sprintf(`apiVersion: k8s.ovn.org/v1
kind: EgressIP
metadata:
    name: ` + svcname + `
spec:
    egressIPs:
    - ` + egressIP1.String() + `
    podSelector:
        matchLabels:
            wants: egress
    namespaceSelector:
        matchLabels:
            name: ` + f.Namespace.Name + `
`)
		if err := ioutil.WriteFile(egressIPYaml, []byte(egressIPConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}
		defer func() {
			if err := os.Remove(egressIPYaml); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()

		framework.Logf("Create the EgressIP configuration")
		framework.RunKubectlOrDie("default", "create", "-f", egressIPYaml)

		ginkgo.By("3. Check that the status is of length one and that it is assigned to egress1Node")
		statuses := verifyEgressIPStatusLengthEquals(1)
		if statuses[0].Node != egress1Node.name {
			framework.Failf("Step 2. Check that the status is of length one and that it is assigned to egress1Node, failed")
		}

		ginkgo.By("4. Create one pod matching the EgressIP: running on egress1Node")
		createGenericPodWithLabel(f, pod1Name, pod1Node.name, f.Namespace.Name, command, podEgressLabel)

		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			kubectlOut := getPodAddress(pod1Name, f.Namespace.Name)
			srcIP := net.ParseIP(kubectlOut)
			if srcIP == nil {
				return false, nil
			}
			return true, nil
		})
		framework.ExpectNoError(err, "Step 4. Create one pod matching the EgressIP: running on egress1Node, failed, err: %v", err)
		framework.Logf("Created pod %s on node %s", pod1Name, pod1Node.name)

		ginkgo.By("5. Check connectivity from pod to an external node and verify that the srcIP is the expected egressIP")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP1.String()}))
		framework.ExpectNoError(err, "Step 5. Check connectivity from pod to an external node and verify that the srcIP is the expected egressIP, failed: %v", err)

		ginkgo.By("6. Check connectivity from pod to another node and verify that the srcIP is the expected [egressIP if SGW] & [nodeIP if LGW]")
		var verifyIP string
		if IsGatewayModeLocal() {
			verifyIP = egressNodeIP.String()
		} else {
			verifyIP = egressIP1.String()
		}
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(hostNetPod, pod1Name, podNamespace.Name, true, []string{verifyIP}))
		framework.ExpectNoError(err, "Step 6. Check connectivity from pod to another node and verify that the srcIP is the expected [egressIP if SGW] & [nodeIP if LGW], failed: %v", err)

		ginkgo.By("7. Add the \"k8s.ovn.org/egress-assignable\" label to egress2Node")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable", "dummy")
		framework.Logf("Added egress-assignable label to node %s", egress2Node.name)
		framework.ExpectNodeHasLabel(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		ginkgo.By("8. Remove the \"k8s.ovn.org/egress-assignable\" label from egress1Node")
		framework.RemoveLabelOffNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable")

		ginkgo.By("9. Check that the status is of length one and that it is assigned to egress2Node")
		// There is sometimes a slight delay for the EIP fail over to happen,
		// so let's use the pollimmediate struct to check if eventually egress2Node becomes the egress node
		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			statuses := getEgressIPStatusItems()
			return (len(statuses) == 1) && (statuses[0].Node == egress2Node.name), nil
		})
		framework.ExpectNoError(err, "Step 9. Check that the status is of length one and that it is assigned to egress2Node, failed: %v", err)

		ginkgo.By("10. Check connectivity from pod to an external \"node\" and verify that the srcIP is the expected egressIP")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP1.String()}))
		framework.ExpectNoError(err, "Step 10. Check connectivity from pod to an external \"node\" and verify that the srcIP is the expected egressIP, failed, err: %v", err)

		ginkgo.By("11. Check connectivity from pod to another node and verify that the srcIP is the expected nodeIP (known inconsistency compared to step 6 for SGW)")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(hostNetPod, pod1Name, podNamespace.Name, true, []string{egressNodeIP.String()}))
		framework.ExpectNoError(err, "Step 11. Check connectivity from pod to another node and verify that the srcIP is the expected nodeIP (known inconsistency compared to step 6), failed: %v", err)

		ginkgo.By("12. Create second pod not matching the EgressIP: running on egress1Node")
		createGenericPodWithLabel(f, pod2Name, pod1Node.name, f.Namespace.Name, command, map[string]string{})
		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			kubectlOut := getPodAddress(pod2Name, f.Namespace.Name)
			srcIP := net.ParseIP(kubectlOut)
			if srcIP == nil {
				return false, nil
			}
			return true, nil
		})
		framework.ExpectNoError(err, "Step 12. Create second pod not matching the EgressIP: running on egress1Node, failed, err: %v", err)
		framework.Logf("Created pod %s on node %s", pod2Name, pod1Node.name)

		ginkgo.By("13. Check connectivity from second pod to external node and verify that the srcIP is the expected nodeIP")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod2Name, podNamespace.Name, true, []string{egressNodeIP.String()}))
		framework.ExpectNoError(err, "Step 13. Check connectivity from second pod to external node and verify that the srcIP is the expected nodeIP, failed: %v", err)

		ginkgo.By("14. Add pod selector label to make second pod egressIP managed")
		pod2 := getPod(f, pod2Name)
		pod2.Labels = podEgressLabel
		updatePod(f, pod2)

		ginkgo.By("15. Check connectivity from second pod to external node and verify that the srcIP is the expected egressIP")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod2Name, podNamespace.Name, true, []string{egressIP1.String()}))
		framework.ExpectNoError(err, "Step 15. Check connectivity from second pod to external node and verify that the srcIP is the expected egressIP, failed: %v", err)

		ginkgo.By("16. Check connectivity from second pod to another node and verify that the srcIP is the expected nodeIP (this verifies SNAT's towards nodeIP are not deleted unless node is egressNode)")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(hostNetPod, pod2Name, podNamespace.Name, true, []string{egressNodeIP.String()}))
		framework.ExpectNoError(err, "Step 16. Check connectivity from second pod to another node and verify that the srcIP is the expected nodeIP (this verifies SNAT's towards nodeIP are not deleted unless node is egressNode), failed: %v", err)
	})

	// Validate the egress IP works with egress firewall by creating two httpd
	// containers on the kind networking (effectively seen as "outside" the cluster)
	// and curl them from a pod in the cluster which matches the egress IP stanza.
	// The IP allowed by the egress firewall rule should work, the other not.

	/* This test does the following:
	   0. Add the "k8s.ovn.org/egress-assignable" label to one nodes
	   1. Create an EgressIP object with one egress IP defined
	   2. Create an EgressFirewall object with one allow rule and one "block-all" rule defined
	   3. Create two pods matching both egress firewall and egress IP
	   4. Check connectivity to the blocked IP and verify that it fails
	   5. Check connectivity to the allowed IP and verify it has the egress IP
	   6. Check connectivity to the kubernetes API IP and verify that it works [currently skipped]
	   7. Check connectivity to the other pod IP and verify that it works
	   8. Check connectivity to the service IP and verify that it works
	*/
	ginkgo.It("Should validate the egress IP functionality against remote hosts with egress firewall applied", func() {

		command := []string{"/agnhost", "netexec", fmt.Sprintf("--http-port=%s", podHTTPPort)}

		ginkgo.By("0. Add the \"k8s.ovn.org/egress-assignable\" label to one nodes")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		podNamespace := f.Namespace
		podNamespace.Labels = map[string]string{
			"name": f.Namespace.Name,
		}
		updateNamespace(f, podNamespace)

		ginkgo.By("1. Create an EgressIP object with one egress IP defined")
		dupIP := func(ip net.IP) net.IP {
			dup := make(net.IP, len(ip))
			copy(dup, ip)
			return dup
		}
		// Assign the egress IP without conflicting with any node IP,
		// the kind subnet is /16 or /64 so the following should be fine.
		egressNodeIP := net.ParseIP(egress1Node.nodeIP)
		egressIP := dupIP(egressNodeIP)
		egressIP[len(egressIP)-2]++

		var egressIPConfig = `apiVersion: k8s.ovn.org/v1
kind: EgressIP
metadata:
    name: ` + svcname + `
spec:
    egressIPs:
    - ` + egressIP.String() + `
    podSelector:
        matchLabels:
            wants: egress
    namespaceSelector:
        matchLabels:
            name: ` + f.Namespace.Name + `
`

		if err := ioutil.WriteFile(egressIPYaml, []byte(egressIPConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}

		defer func() {
			if err := os.Remove(egressIPYaml); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()

		framework.Logf("Create the EgressIP configuration")
		framework.RunKubectlOrDie("default", "create", "-f", egressIPYaml)

		ginkgo.By("2. Create an EgressFirewall object with one allow rule and one \"block-all\" rule defined")

		var firewallAllowNode, firewallDenyAll string
		if utilnet.IsIPv6String(targetNode.nodeIP) {
			firewallAllowNode = targetNode.nodeIP + "/128"
			firewallDenyAll = "::/0"
		} else {
			firewallAllowNode = targetNode.nodeIP + "/32"
			firewallDenyAll = "0.0.0.0/0"
		}

		var egressFirewallConfig = fmt.Sprintf(`apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default
  namespace: ` + f.Namespace.Name + `
spec:
  egress:
  - type: Allow
    to:
      cidrSelector: ` + firewallAllowNode + `
  - type: Deny
    to:
      cidrSelector: ` + firewallDenyAll + `
`)

		if err := ioutil.WriteFile(egressFirewallYaml, []byte(egressFirewallConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}

		defer func() {
			if err := os.Remove(egressFirewallYaml); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()

		framework.RunKubectlOrDie(f.Namespace.Name, "create", "-f", egressFirewallYaml)

		ginkgo.By("3. Create two pods, and matching service, matching both egress firewall and egress IP")
		createGenericPodWithLabel(f, pod1Name, pod1Node.name, f.Namespace.Name, command, podEgressLabel)
		createGenericPodWithLabel(f, pod2Name, pod2Node.name, f.Namespace.Name, command, podEgressLabel)
		serviceIP, err := createServiceForPodsWithLabel(f, f.Namespace.Name, servicePort, podHTTPPort, "ClusterIP", podEgressLabel)
		framework.ExpectNoError(err, "Step 3. Create two pods, and matching service, matching both egress firewall and egress IP, failed creating service, err: %v", err)

		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			for _, podName := range []string{pod1Name, pod2Name} {
				kubectlOut := getPodAddress(podName, f.Namespace.Name)
				srcIP := net.ParseIP(kubectlOut)
				if srcIP == nil {
					return false, nil
				}
			}
			return true, nil
		})
		framework.ExpectNoError(err, "Step 3. Create two pods matching both egress firewall and egress IP, failed, err: %v", err)

		pod2IP := getPodAddress(pod2Name, f.Namespace.Name)

		ginkgo.By("Checking that the status is of length one")
		verifyEgressIPStatusLengthEquals(1)

		ginkgo.By("4. Check connectivity to the blocked IP and verify that it fails")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(deniedTargetNode, pod1Name, podNamespace.Name, false, []string{egressIP.String()}))
		framework.ExpectNoError(err, "Step:  4. Check connectivity to the blocked IP and verify that it fails, failed, err: %v", err)

		ginkgo.By("5. Check connectivity to the allowed IP and verify it has the egress IP")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP.String()}))
		framework.ExpectNoError(err, "Step: 5. Check connectivity to the allowed IP and verify it has the egress IP, failed, err: %v", err)

		// TODO: in the future once we only have shared gateway mode: implement egress firewall so that
		// pods that have a "deny all 0.0.0.0/0" rule, still can connect to the Kubernetes API service
		// and re-enable this check

		// ginkgo.By("6. Check connectivity to the kubernetes API IP and verify that it works")
		// err = wait.PollImmediate(retryInterval, retryTimeout, targetAPIServiceAndTest(podNamespace.Name, []string{pod1Name, pod2Name}))
		// framework.ExpectNoError(err, "Step 6. Check connectivity to the kubernetes API IP and verify that it works, failed, err %v", err)

		ginkgo.By("7. Check connectivity to the other pod IP and verify that it works")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetPodAndTest(f.Namespace.Name, pod1Name, pod2Name, pod2IP))
		framework.ExpectNoError(err, "Step 7. Check connectivity to the other pod IP and verify that it works, err: %v", err)

		ginkgo.By("8. Check connectivity to the service IP and verify that it works")
		servicePortAsString := strconv.Itoa(int(servicePort))
		err = wait.PollImmediate(retryInterval, retryTimeout, targetDestinationAndTest(podNamespace.Name, fmt.Sprintf("http://%s/hostname", net.JoinHostPort(serviceIP, servicePortAsString)), []string{pod1Name, pod2Name}))
		framework.ExpectNoError(err, "8. Check connectivity to the service IP and verify that it works, failed, err %v", err)
	})
})
