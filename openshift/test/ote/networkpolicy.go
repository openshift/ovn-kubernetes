package ote

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"

	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"
)

var _ = g.Describe("[sig-network] SDN networkpolicy", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("networking-networkpolicy")

	g.BeforeEach(func() {
		networkType := oteutils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("Skip testing on non-ovn cluster!!!")
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote] 41082-Check ACL audit logs can be extracted", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			allowFromSameNS     = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-same-namespace.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Obtain the namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()

		g.By("Enable ACL logging on the namespace ns1")
		aclSettings := oteutils.AclSettings{DenySetting: "alert", AllowSetting: "alert"}
		err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", ns1, aclSettings.GetJSONString()).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())

		g.By("create default deny ingress networkpolicy in ns1")
		oteutils.CreateResourceFromFile(oc, ns1, ingressTypeFile)

		g.By("create allow same namespace networkpolicy in ns1")
		oteutils.CreateResourceFromFile(oc, ns1, allowFromSameNS)

		g.By("create 1st hello pod in ns1")
		pod1ns1 := oteutils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := oteutils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}

		pod2ns1.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)

		// Capture the existing log so the assertion only considers records appended
		// by the traffic this test generates, not a stale verdict=allow from before.
		beforeOutput, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Checking connectivity from pod2 to pod1 to generate messages")
		oteutils.CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		output, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(strings.TrimPrefix(output, beforeOutput), "verdict=allow")).To(o.BeTrue())

	})
	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs] 41407-Check networkpolicy ACL audit message is logged with correct policy name", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			allowFromSameNS     = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-same-namespace.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		var namespaces [2]string
		policyList := [2]string{"default-deny-ingress", "allow-from-same-namespace"}
		for i := 0; i < 2; i++ {
			oc.SetupProject()
			namespaces[i] = oc.Namespace()
			g.By(fmt.Sprintf("Enable ACL logging on the namespace %s", namespaces[i]))
			aclSettings := oteutils.AclSettings{DenySetting: "alert", AllowSetting: "warning"}
			err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", namespaces[i], aclSettings.GetJSONString()).Execute()
			o.Expect(err1).NotTo(o.HaveOccurred())

			g.By(fmt.Sprintf("Create default deny ingress networkpolicy in %s", namespaces[i]))
			oteutils.CreateResourceFromFile(oc, namespaces[i], ingressTypeFile)
			output, err := oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(policyList[0]))

			g.By(fmt.Sprintf("Create allow same namespace networkpolicy in %s", namespaces[i]))
			oteutils.CreateResourceFromFile(oc, namespaces[i], allowFromSameNS)
			output, err = oc.Run("get").Args("networkpolicy").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring(policyList[1]))

			pod := oteutils.PingPodResourceNode{
				Name:      "",
				Namespace: namespaces[i],
				Nodename:  "",
				Template:  pingPodNodeTemplate,
			}
			for j := 0; j < 2; j++ {
				g.By(fmt.Sprintf("Create hello pod in %s", namespaces[i]))
				pod.Name = "hello-pod" + strconv.Itoa(j)
				pod.Nodename = nodeList.Items[j].Name
				pod.CreatePingPodNode(oc)
				oteutils.WaitPodReady(oc, pod.Namespace, pod.Name)
			}
			g.By(fmt.Sprintf("Checking connectivity from second pod to  first pod to generate messages in %s", namespaces[i]))
			oteutils.CurlPod2PodPass(oc, namespaces[i], "hello-pod1", namespaces[i], "hello-pod0")
			oc.SetupProject()
		}

		output, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ACL logs for allow-from-same-namespace policy \n %s", output)
		// policy name truncated to allow-from-same-name in ACL log message
		for i := 0; i < len(namespaces); i++ {
			searchString := fmt.Sprintf("name=\"NP:%s:allow-from-same-name\", verdict=allow, severity=warning", namespaces[i])
			o.Expect(strings.Contains(output, searchString)).To(o.BeTrue())
			oteutils.RemoveResource(oc, true, true, "networkpolicy", policyList[1], "-n", namespaces[i])
			oteutils.CurlPod2PodFail(oc, namespaces[i], "hello-pod0", namespaces[i], "hello-pod1")
		}
		output, err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[1].Name, "--path=ovn/acl-audit-log.log").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ACL logs for default-deny-ingress policy \n %s", output)
		for i := 0; i < len(namespaces); i++ {
			searchString := fmt.Sprintf("name=\"NP:%s:Ingress\", verdict=drop, severity=alert", namespaces[i])
			o.Expect(strings.Contains(output, searchString)).To(o.BeTrue())
		}

	})
	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][WRS][V-BR.33] 41080-Check network policy ACL audit messages are logged to journald", g.Serial, func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			allowFromSameNS     = filepath.Join(buildPruningBaseDir, "networkpolicy/allow-from-same-namespace.yaml")
			ingressTypeFile     = filepath.Join(buildPruningBaseDir, "networkpolicy/default-deny-ingress.yaml")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("This case requires 2 nodes, but the cluster has less than two nodes")
		}

		g.By("Configure audit message logging destination to journald")
		patchSResource := "networks.operator.openshift.io/cluster"
		// Capture the current destination so cleanup restores it instead of blindly
		// clearing it to "" (which would clobber a pre-existing cluster setting).
		originalAuditDestination, getErr := oc.AsAdmin().WithoutNamespace().Run("get").Args(patchSResource, "-o", "jsonpath={.spec.defaultNetwork.ovnKubernetesConfig.policyAuditConfig.destination}").Output()
		o.Expect(getErr).NotTo(o.HaveOccurred())
		patchInfo := `{"spec":{"defaultNetwork":{"ovnKubernetesConfig":{"policyAuditConfig": {"destination": "libc"}}}}}`
		undoPatchInfo := fmt.Sprintf(`{"spec":{"defaultNetwork":{"ovnKubernetesConfig":{"policyAuditConfig": {"destination": %q}}}}}`, strings.TrimSpace(originalAuditDestination))
		defer func() {
			_, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args(patchSResource, "-p", undoPatchInfo, "--type=merge").Output()
			o.Expect(patchErr).NotTo(o.HaveOccurred())
			oteutils.WaitForNetworkOperatorState(oc, 100, 15, "True.*False.*False")
		}()
		_, patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args(patchSResource, "-p", patchInfo, "--type=merge").Output()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		// The policyAuditConfig change triggers an ovnkube-node DaemonSet rollout that
		// reconfigures ovn-controller's audit destination on every node. The network
		// operator can momentarily report Progressing=False in the gap before the rollout
		// begins, so a single "True.*False.*False" wait can return prematurely and leave
		// the node under test running the old (audit-disabled) ovn-controller config.
		// First wait for the rollout to actually start (Progressing=True), then for it to
		// fully complete, before generating traffic and checking journald.
		oteutils.WaitForNetworkOperatorState(oc, 5, 5, "True.*True.*False")
		oteutils.WaitForNetworkOperatorState(oc, 15, 15, "True.*False.*False")

		g.By("Obtain the namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns1)

		g.By("Enable ACL logging on the namespace ns1")
		aclSettings := oteutils.AclSettings{DenySetting: "alert", AllowSetting: "alert"}
		err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", ns1, aclSettings.GetJSONString()).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())

		g.By("create default deny ingress networkpolicy in ns1")
		oteutils.CreateResourceFromFile(oc, ns1, ingressTypeFile)

		g.By("create allow same namespace networkpolicy in ns1")
		oteutils.CreateResourceFromFile(oc, ns1, allowFromSameNS)

		g.By("create 1st hello pod in ns1")
		pod1ns1 := oteutils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1ns1.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, pod1ns1.Namespace, pod1ns1.Name)

		g.By("create 2nd hello pod in ns1")
		pod2ns1 := oteutils.PingPodResourceNode{
			Name:      "hello-pod2",
			Namespace: ns1,
			Nodename:  nodeList.Items[1].Name,
			Template:  pingPodNodeTemplate,
		}

		pod2ns1.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, pod2ns1.Namespace, pod2ns1.Name)

		g.By("Checking connectivity from pod2 to pod1 to generate messages")
		oteutils.CurlPod2PodPass(oc, ns1, "hello-pod2", ns1, "hello-pod1")

		g.By("Checking messages are logged to journald")
		// Trailing '|| true' keeps grep's "no match" (exit 1) from surfacing as a
		// debug-container failure, so we can assert on the content instead of the exit code.
		// Poll because audit messages may take a moment to be flushed to journald.
		cmd := fmt.Sprintf("journalctl -t ovn-controller --since '1min ago' | grep 'name=\"NP:%s:allow-from-same-name\", verdict=allow' || true", ns1)
		o.Eventually(func() bool {
			output, journalctlErr := oteutils.DebugNodeWithOptionsAndChroot(oc, nodeList.Items[0].Name, []string{"-q"}, "bin/sh", "-c", cmd)
			if journalctlErr != nil {
				e2e.Logf("Error reading journald: %v", journalctlErr)
				return false
			}
			e2e.Logf("Output %s", output)
			return strings.Contains(output, "verdict=allow")
		}, 30*time.Second, 3*time.Second).Should(o.BeTrue(), "expected ovn-controller journald to contain a 'verdict=allow' ACL audit message")

	})
})
