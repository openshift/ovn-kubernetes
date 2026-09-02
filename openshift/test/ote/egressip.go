package ote

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/testdata"
	oteutils "github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/ote/utils"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[sig-network][Suite:openshift/ovn-kubernetes] SDN EgressIP", func() {
	defer g.GinkgoRecover()

	var oc = exutil.NewCLI("ote-egress")

	var (
		egressNodeLabel = "k8s.ovn.org/egress-assignable"
		aclLogPath      = "--path=ovn/acl-audit-log.log"
	)

	g.BeforeEach(func() {
		networkType := oteutils.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovnkubernetes") {
			g.Skip("Skip testing on non-OVN clusters")
		}
	})

	// -------- EgressFirewall tests --------

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 53223-Verify ACL audit logs can be generated for traffic hit EgressFirewall rules", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressFWTemplate    = filepath.Join(buildPruningBaseDir, "egressfirewall1-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("1. Obtain the namespace")
		ns1 := oc.Namespace()

		g.By("2. Enable ACL logging on the namespace ns1")
		oteutils.EnableACLOnNamespace(oc, ns1, "info", "info")

		g.By("3. Create hello pod in ns1")
		pod1 := oteutils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, ns1, pod1.Name)

		g.By("4. Create an EgressFirewall")
		egressFW1 := oteutils.EgressFirewall1{
			Name:      "default",
			Namespace: ns1,
			Template:  egressFWTemplate,
		}
		egressFW1.CreateEgressFWObject1(oc)
		efErr := oteutils.WaitEgressFirewallApplied(oc, egressFW1.Name, ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		g.By("5. Check www.test.com is blocked")
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "curl -s www.test.com --connect-timeout 5")
			return err
		}, "60s", "10s").Should(o.HaveOccurred())

		g.By("6. Check www.redhat.com is allowed")
		_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).ToNot(o.HaveOccurred())

		g.By("7. Verify acl logs for egressfirewall generated")
		egressFwRegex := fmt.Sprintf("EF:%s:.*", ns1)
		aclLogs, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		r := regexp.MustCompile(egressFwRegex)
		matches := r.FindAllString(aclLogs, -1)
		matched1, matchErr1 := regexp.MatchString(egressFwRegex+"verdict=drop, severity=info", aclLogs)
		o.Expect(matchErr1).NotTo(o.HaveOccurred())
		o.Expect(matched1).To(o.BeTrue(), fmt.Sprintf("The egressfirewall acllogs were not generated as expected, acl logs for this namespace %s,are: \n %s", ns1, matches))
		matched2, matchErr2 := regexp.MatchString(egressFwRegex+"verdict=allow, severity=info", aclLogs)
		o.Expect(matchErr2).NotTo(o.HaveOccurred())
		o.Expect(matched2).To(o.BeTrue(), fmt.Sprintf("The egressfirewall acllogs were not generated as expected, acl logs for this namespace %s,are: \n %s", ns1, matches))
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 53224-Disable and enable acl logging for EgressFirewall", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressFWTemplate    = filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("1. Obtain the namespace")
		ns1 := oc.Namespace()

		g.By("2. Enable ACL logging on the namespace ns1")
		oteutils.EnableACLOnNamespace(oc, ns1, "info", "info")

		g.By("3. Create hello pod in ns1")
		pod1 := oteutils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, ns1, pod1.Name)

		g.By("4. Create an EgressFirewall")
		egressFW2 := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns1,
			Ruletype:  "Deny",
			Cidr:      "0.0.0.0/0",
			Template:  egressFWTemplate,
		}
		egressFW2.CreateEgressFW2Object(oc)
		ipStackType := oteutils.CheckIPStackType(oc)
		if ipStackType == "dualstack" {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns1, "-p", `{"spec":{"egress":[{"type":"Deny","to":{"cidrSelector":"0.0.0.0/0"}},{"type":"Deny","to":{"cidrSelector":"::/0"}}]}}`, "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		}
		err = oteutils.WaitEgressFirewallApplied(oc, egressFW2.Name, ns1)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Generate egress traffic which will hit the egressfirewall")
		_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		g.By("6. Verify acl logs for egressfirewall generated")
		egressFwRegex := fmt.Sprintf("EF:%s:.*", ns1)
		aclLogs, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		r := regexp.MustCompile(egressFwRegex)
		matches := r.FindAllString(aclLogs, -1)
		aclLogNum := len(matches)
		o.Expect(aclLogNum > 0).To(o.BeTrue(), fmt.Sprintf("No matched acl logs numbers for namespace %s, and actual matched logs are: \n %v ", ns1, matches))

		g.By("7. Disable acl logs")
		oteutils.DisableACLOnNamespace(oc, ns1)

		g.By("8. Generate egress traffic which will hit the egressfirewall")
		_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		g.By("9. Verify no incremental acl logs")
		aclLogs2, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		matches2 := r.FindAllString(aclLogs2, -1)
		aclLogNum2 := len(matches2)
		o.Expect(aclLogNum2 == aclLogNum).To(o.BeTrue(), fmt.Sprintf("Before disable,actual matched logs are: \n %v ,after disable,actual matched logs are: \n %v", matches, matches2))

		g.By("10. Enable acl logs")
		oteutils.EnableACLOnNamespace(oc, ns1, "alert", "alert")

		g.By("11. Generate egress traffic which will hit the egressfirewall")
		_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		g.By("12. Verify new acl logs for egressfirewall generated")
		aclLogs3, err3 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err3).NotTo(o.HaveOccurred())
		matches3 := r.FindAllString(aclLogs3, -1)
		aclLogNum3 := len(matches3)
		o.Expect(aclLogNum3 > aclLogNum).To(o.BeTrue(), fmt.Sprintf("Previous actual matched logs are: \n %v ,after enable again,actual matched logs are: \n %v", matches, aclLogNum3))
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 53226-The namespace enabled acl logging will not affect the namespace not enabling acl logging", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressFWTemplate    = filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("1. Obtain the namespace")
		ns1 := oc.Namespace()

		g.By("2. Enable ACL logging on the namespace ns1")
		oteutils.EnableACLOnNamespace(oc, ns1, "info", "info")

		g.By("3. Create hello pod in ns1")
		pod1 := oteutils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns1,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod1.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, ns1, pod1.Name)

		g.By("4. Create an EgressFirewall")
		ipStackType := oteutils.CheckIPStackType(oc)
		egressFW1 := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns1,
			Ruletype:  "Deny",
			Cidr:      "0.0.0.0/0",
			Template:  egressFWTemplate,
		}
		egressFW1.CreateEgressFW2Object(oc)
		defer egressFW1.DeleteEgressFW2Object(oc)
		if ipStackType == "dualstack" {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns1, "-p", `{"spec":{"egress":[{"type":"Deny","to":{"cidrSelector":"0.0.0.0/0"}},{"type":"Deny","to":{"cidrSelector":"::/0"}}]}}`, "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		}
		err = oteutils.WaitEgressFirewallApplied(oc, egressFW1.Name, ns1)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Generate egress traffic which will hit the egressfirewall")
		_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		g.By("6. Verify acl logs for egressfirewall generated")
		egressFwRegex := fmt.Sprintf("EF:%s:.*", ns1)
		aclLogs, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		r := regexp.MustCompile(egressFwRegex)
		matches := r.FindAllString(aclLogs, -1)
		aclLogNum := len(matches)
		o.Expect(aclLogNum > 0).To(o.BeTrue())

		g.By("7. Create a new namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()

		g.By("8. Create hello pod in ns2")
		pod2 := oteutils.PingPodResourceNode{
			Name:      "hello-pod1",
			Namespace: ns2,
			Nodename:  nodeList.Items[0].Name,
			Template:  pingPodNodeTemplate,
		}
		pod2.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, ns2, pod2.Name)

		g.By("9. Generate egress traffic in ns2")
		_, err = e2eoutput.RunHostCmd(pod2.Namespace, pod2.Name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("10. Verify no acl logs for egressfirewall generated in ns2")
		egressFwRegexNs2 := fmt.Sprintf("EF:%s:.*", ns2)
		o.Consistently(func() int {
			aclLogs2, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			r2 := regexp.MustCompile(egressFwRegexNs2)
			matches2 := r2.FindAllString(aclLogs2, -1)
			return len(matches2)
		}, 10*time.Second, 5*time.Second).Should(o.Equal(0))

		g.By("11. Create an EgressFirewall in ns2")
		egressFW2 := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns2,
			Ruletype:  "Deny",
			Cidr:      "0.0.0.0/0",
			Template:  egressFWTemplate,
		}
		egressFW2.CreateEgressFW2Object(oc)
		defer egressFW2.DeleteEgressFW2Object(oc)
		if ipStackType == "dualstack" {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns2, "-p", `{"spec":{"egress":[{"type":"Deny","to":{"cidrSelector":"0.0.0.0/0"}},{"type":"Deny","to":{"cidrSelector":"::/0"}}]}}`, "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		}
		err = oteutils.WaitEgressFirewallApplied(oc, egressFW2.Name, ns2)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("12. Generate egress traffic which will hit the egressfirewall in ns2")
		_, err = e2eoutput.RunHostCmd(pod2.Namespace, pod2.Name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		g.By("13. Verify no acl logs for egressfirewall generated in ns2")
		o.Consistently(func() int {
			aclLogs2, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			r2 := regexp.MustCompile(egressFwRegexNs2)
			matches2 := r2.FindAllString(aclLogs2, -1)
			return len(matches2)
		}, 10*time.Second, 5*time.Second).Should(o.Equal(0))
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs][Feature:EgressFirewall] 59709-No duplicate egressfirewall rules in the OVN Northbound database after restart OVN master pod", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressFWTemplate1   = filepath.Join(buildPruningBaseDir, "egressfirewall1-template.yaml")
		)

		g.By("Obtain the namespace")
		ns1 := oc.Namespace()

		g.By("Create egressfirewall rules under same namespace")
		egressFW := oteutils.EgressFirewall1{
			Name:      "default",
			Namespace: ns1,
			Template:  egressFWTemplate1,
		}
		egressFW.CreateEgressFWObject1(oc)
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				egressFW.DeleteEgressFWObject1(oc)
			}
		}()
		efErr := oteutils.WaitEgressFirewallApplied(oc, egressFW.Name, ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		g.By("Get the base number of egressfirewall rules")
		ovnACLCmd := fmt.Sprintf("ovn-nbctl --format=table --no-heading  --columns=action,priority,match find acl external_ids:k8s.ovn.org/name=%s", ns1)
		ovnMasterPodName := oteutils.GetOVNKMasterOVNkubeNode(oc)
		listOutput, listErr := oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, ovnACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		e2e.Logf("The egressfirewall rules before restart ovn master pod: \n %s", listOutput)
		baseCount := len(strings.Split(listOutput, "\n"))

		g.By("Restart cluster-manager's ovnkube-node pod")
		err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnMasterPodName, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		g.By("Check the result, the number of egressfirewall rules should be same as before")
		ovnMasterPodName = oteutils.GetOVNKMasterOVNkubeNode(oc)
		listOutput, listErr = oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, ovnACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		e2e.Logf("The egressfirewall rules after restart ovn master pod: \n %s", listOutput)
		resultCount := len(strings.Split(listOutput, "\n"))
		o.Expect(resultCount).Should(o.Equal(baseCount))
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 60488-EgressFirewall works for a nodeSelector for matchLabels", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		g.By("Label one node to match egressfirewall rule")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough worker nodes for this test, skip the case!!")
		}

		ipStackType := oteutils.CheckIPStackType(oc)

		node1 := nodeList.Items[0].Name
		node2 := nodeList.Items[1].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, node1, "ef-dep")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, node1, "ef-dep", "qe")

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall3-template.yaml")

		g.By("Get new namespace")
		ns := oc.Namespace()

		var cidrValue string
		if ipStackType == "ipv6single" {
			cidrValue = "::/0"
		} else {
			cidrValue = "0.0.0.0/0"
		}

		g.By("Create a pod")
		pod1 := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod1.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("Check the nodes can be accessed or not")
		node1IP1, node1IP2 := oteutils.GetNodeIP(oc, node1)
		node2IP1, node2IP2 := oteutils.GetNodeIP(oc, node2)
		_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node1IP2)
		if err != nil {
			g.Skip("Ping node IP failed, skip the test in this environment.")
		}
		if node1IP1 != "" {
			_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node1IP1)
			if err != nil {
				g.Skip("Ping node IP failed, skip the test in this environment.")
			}
		}

		g.By("Create an EgressFirewall object with rule nodeSelector")
		egressFW2 := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns,
			Ruletype:  "Deny",
			Cidr:      cidrValue,
			Template:  egressFWTemplate,
		}
		defer egressFW2.DeleteEgressFW2Object(oc)
		egressFW2.CreateEgressFW2Object(oc)

		g.By("Verify the node matched egressfirewall will be allowed")
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node1IP2)
			return err
		}, "60s", "10s").ShouldNot(o.HaveOccurred())
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node2IP2)
			return err
		}, "10s", "5s").Should(o.HaveOccurred())

		if ipStackType == "dualstack" {
			egressFW2.DeleteEgressFW2Object(oc)
			egressFW2.Cidr = "::/0"
			defer egressFW2.DeleteEgressFW2Object(oc)
			egressFW2.CreateEgressFW2Object(oc)
			o.Eventually(func() error {
				_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node1IP1)
				return err
			}, "60s", "10s").ShouldNot(o.HaveOccurred())
			o.Eventually(func() error {
				_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node2IP1)
				return err
			}, "10s", "5s").Should(o.HaveOccurred())
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 60812-EgressFirewall works for a nodeSelector for matchExpressions", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		g.By("Label one node to match egressfirewall rule")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough worker nodes for this test, skip the case!!")
		}

		ipStackType := oteutils.CheckIPStackType(oc)

		node1 := nodeList.Items[0].Name
		node2 := nodeList.Items[1].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, node1, "ef-org")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, node1, "ef-org", "dev")

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall4-template.yaml")

		g.By("Get new namespace")
		ns := oc.Namespace()

		var cidrValue string
		if ipStackType == "ipv6single" {
			cidrValue = "::/0"
		} else {
			cidrValue = "0.0.0.0/0"
		}

		g.By("Create a pod")
		pod1 := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod1.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("Check the nodes can be accessed or not")
		node1IP1, node1IP2 := oteutils.GetNodeIP(oc, node1)
		node2IP1, node2IP2 := oteutils.GetNodeIP(oc, node2)
		_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node1IP2)
		if err != nil {
			g.Skip("Ping node IP failed, skip the test in this environment.")
		}
		if node1IP1 != "" {
			_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node1IP1)
			if err != nil {
				g.Skip("Ping node IP failed, skip the test in this environment.")
			}
		}

		g.By("Create an EgressFirewall object with rule nodeSelector")
		egressFW2 := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns,
			Ruletype:  "Deny",
			Cidr:      cidrValue,
			Template:  egressFWTemplate,
		}
		defer egressFW2.DeleteEgressFW2Object(oc)
		egressFW2.CreateEgressFW2Object(oc)

		g.By("Verify the node matched egressfirewall will be allowed, unmatched will be blocked")
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node1IP2)
			return err
		}, "60s", "10s").ShouldNot(o.HaveOccurred())
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node2IP2)
			return err
		}, "10s", "5s").Should(o.HaveOccurred())

		if ipStackType == "dualstack" {
			egressFW2.DeleteEgressFW2Object(oc)
			egressFW2.Cidr = "::/0"
			defer egressFW2.DeleteEgressFW2Object(oc)
			egressFW2.CreateEgressFW2Object(oc)
			o.Eventually(func() error {
				_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node1IP1)
				return err
			}, "60s", "10s").ShouldNot(o.HaveOccurred())
			o.Eventually(func() error {
				_, err = e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "ping -c 2 "+node2IP1)
				return err
			}, "10s", "5s").Should(o.HaveOccurred())
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs][Feature:EgressFirewall] 61176-61177-EgressFirewall with dnsName in uppercase and long namespace restart", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		ns := "test-egressfirewall-with-a-very-long-namespace-61176-61177"

		g.By("1. Create a long namespace over 43 characters, create an EgressFirewall object with mixed of Allow and Deny rules")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", ns, "--ignore-not-found=true").Execute()
		nsErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", ns).Execute()
		o.Expect(nsErr).NotTo(o.HaveOccurred())
		oteutils.SetNamespacePrivileged(oc, ns)

		egressFW5 := oteutils.EgressFirewall5{
			Name:        "default",
			Namespace:   ns,
			Ruletype1:   "Allow",
			Rulename1:   "dnsName",
			Rulevalue1:  "WWW.GOOGLE.COM",
			Protocol1:   "TCP",
			Portnumber1: 443,
			Ruletype2:   "Deny",
			Rulename2:   "dnsName",
			Rulevalue2:  "www.facebook.com",
			Protocol2:   "TCP",
			Portnumber2: 443,
			Template:    egressFWTemplate,
		}

		defer oteutils.RemoveResource(oc, true, true, "egressfirewall", egressFW5.Name, "-n", egressFW5.Namespace)
		egressFW5.CreateEgressFW5Object(oc)
		efErr := oteutils.WaitEgressFirewallApplied(oc, egressFW5.Name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		g.By("2. Create a test pod in the namespace")
		pod1 := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod1.CreatePingPod(oc.AsAdmin())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1.Name, "-n", pod1.Namespace).Execute()
		oteutils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("3. Check www.facebook.com is blocked")
		o.Eventually(func() bool {
			_, stderr, _ := e2eoutput.RunHostCmdWithFullOutput(pod1.Namespace, pod1.Name, "curl -I -k https://www.facebook.com --connect-timeout 5")
			return stderr != ""
		}, "120s", "10s").Should(o.BeTrue(), "Deny rule did not work as expected!!")

		g.By("4. Check www.google.com is allowed")
		o.Eventually(func() bool {
			_, err := e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "curl -I -k https://www.google.com --connect-timeout 5")
			return err == nil
		}, "120s", "10s").Should(o.BeTrue(), "Allow rule did not work as expected!!")

		testPodNodeName, _ := oteutils.GetPodNodeName(oc, pod1.Namespace, pod1.Name)
		o.Expect(testPodNodeName != "").Should(o.BeTrue())
		e2e.Logf("node name for the test pod is: %v", testPodNodeName)

		g.By("5. Check ACLs in northdb")
		masterOVNKubeNodePod := oteutils.GetOVNKMasterOVNkubeNode(oc)
		o.Expect(masterOVNKubeNodePod != "").Should(o.BeTrue())
		aclCmd := "ovn-nbctl --no-leader-only find acl|grep external_ids|grep test-egressfirewall-with-a-very-long-namespace ||true"
		checkAclErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			aclOutput, aclErr := oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", masterOVNKubeNodePod, aclCmd)
			if aclErr != nil {
				e2e.Logf("%v,Waiting for ACLs to be synced, try next ...,", aclErr)
				return false, nil
			}
			if strings.Contains(aclOutput, "test-egressfirewall-with-a-very-long-namespace") && strings.Count(aclOutput, "test-egressfirewall-with-a-very-long-namespace") == 4 {
				e2e.Logf("The ACLs for egressfirewall in northbd are as expected!")
				return true, nil
			}
			return false, nil
		})
		oteutils.AssertWaitPollNoErr(checkAclErr, "ACLs were not synced correctly!")

		g.By("6. Restart OVNK nodes")
		defer oteutils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		delPodErr := oc.AsAdmin().Run("delete").Args("pod", "-l", "app=ovnkube-node", "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())
		oteutils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		g.By("7. Check ACL again in northdb after restart")
		masterOVNKubeNodePod = oteutils.GetOVNKMasterOVNkubeNode(oc)
		o.Expect(masterOVNKubeNodePod != "").Should(o.BeTrue())
		checkAclErr = wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			aclOutput, aclErr := oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", masterOVNKubeNodePod, aclCmd)
			if aclErr != nil {
				e2e.Logf("%v,Waiting for ACLs to be synced, try next ...,", aclErr)
				return false, nil
			}
			if strings.Contains(aclOutput, "test-egressfirewall-with-a-very-long-namespace") && strings.Count(aclOutput, "test-egressfirewall-with-a-very-long-namespace") == 4 {
				e2e.Logf("The ACLs for egressfirewall in northbd are as expected!")
				return true, nil
			}
			return false, nil
		})
		oteutils.AssertWaitPollNoErr(checkAclErr, "ACLs were not synced correctly!")

		g.By("8. Check egressfirewall rules still work correctly after restart")
		o.Eventually(func() bool {
			_, stderr, _ := e2eoutput.RunHostCmdWithFullOutput(pod1.Namespace, pod1.Name, "curl -I -k https://www.facebook.com --connect-timeout 5")
			return stderr != ""
		}, "120s", "10s").Should(o.BeTrue(), "Deny rule did not work correctly after restart!!")

		o.Eventually(func() bool {
			_, err := e2eoutput.RunHostCmd(pod1.Namespace, pod1.Name, "curl -I -k https://www.google.com --connect-timeout 5")
			return err == nil
		}, "120s", "10s").Should(o.BeTrue(), "Allow rule did not work correctly after restart!!")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 65173-Misconfigured Egress Firewall can be corrected", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressFWTemplate2   = filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")
		)

		g.By("Obtain the namespace")
		ns := oc.Namespace()

		g.By("Create an EgressFirewall with missing cidr prefix")
		egressFW2 := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns,
			Ruletype:  "Deny",
			Cidr:      "1.1.1.1",
			Template:  egressFWTemplate2,
		}
		egressFW2.CreateEgressFW2Object(oc)

		g.By("Verify EgressFirewall was not applied correctly")
		checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
			output, efErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", "-n", ns, egressFW2.Name).Output()
			if efErr != nil {
				e2e.Logf("Failed to get egressfirewall %v, error: %s. Trying again", egressFW2, efErr)
				return false, nil
			}
			if !strings.Contains(output, "EgressFirewall Rules not correctly applied") {
				e2e.Logf("The egressfirewall output message not expected, trying again. \n %s", output)
				return false, nil
			}
			return true, nil
		})
		oteutils.AssertWaitPollNoErr(checkErr, "EgressFirewall with missing cidr prefix should not be applied correctly!")

		g.By("Apply EgressFirewall again with correct cidr")
		egressFW2.Cidr = "1.1.1.0/24"
		egressFW2.CreateEgressFW2Object(oc)

		g.By("Verify EgressFirewall was applied correctly")
		efErr := oteutils.WaitEgressFirewallApplied(oc, egressFW2.Name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs][Feature:EgressFirewall] 67491-EgressFirewall works with ANP BANP and NP for egress traffic", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		ipStackType := oteutils.CheckIPStackType(oc)
		platform := oteutils.CheckPlatform(oc)
		acceptedPlatform := strings.Contains(platform, "none")
		if !(ipStackType == "ipv4single" || (acceptedPlatform && ipStackType == "dualstack")) {
			g.Skip("This case should be run on UPI packet dualstack cluster or IPv4 cluster, skip other platform or network stack type.")
		}

		var (
			testID                      = "67491"
			testDataDir                 = testdata.FixturePath("networking")
			banpCRTemplate              = filepath.Join(testDataDir, "adminnetworkpolicy", "banp-single-rule-cidr-template.yaml")
			anpCRTemplate               = filepath.Join(testDataDir, "adminnetworkpolicy", "anp-single-rule-cidr-template.yaml")
			pingPodTemplate             = filepath.Join(testDataDir, "ping-for-pod-template.yaml")
			egressFWTemplate            = filepath.Join(testDataDir, "egressfirewall2-template.yaml")
			ipBlockEgressTemplateSingle = filepath.Join(testDataDir, "networkpolicy", "ipblock", "ipBlock-egress-single-CIDR-template.yaml")
			matchLabelKey               = "kubernetes.io/metadata.name"
		)

		g.By("Get test namespace")
		ns := oc.Namespace()

		g.By("Create a pod")
		pod1 := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod1.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("4. Create a Baseline Admin Network Policy with deny action to cidr")
		banpCR := oteutils.SingleRuleCIDRBANPPolicyResource{
			Name:       "default",
			SubjectKey: matchLabelKey,
			SubjectVal: ns,
			RuleName:   "default-deny-to-" + ns,
			RuleAction: "Deny",
			Cidr:       "0.0.0.0/0",
			Template:   banpCRTemplate,
		}
		defer oteutils.RemoveResource(oc, true, true, "banp", banpCR.Name)
		banpCR.CreateSingleRuleCIDRBANP(oc)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("banp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, banpCR.Name)).To(o.BeTrue())

		g.By("Get one IP address for domain name www.google.com")
		ipv4, ipv6 := oteutils.GetIPFromDnsName("www.google.com")
		o.Expect(len(ipv4) == 0).NotTo(o.BeTrue())

		g.By("Create an EgressFirewall")
		egressFW := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns,
			Ruletype:  "Allow",
			Cidr:      ipv4 + "/32",
			Template:  egressFWTemplate,
		}
		egressFW.CreateEgressFW2Object(oc)
		err = oteutils.WaitEgressFirewallApplied(oc, egressFW.Name, ns)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Verify destination got blocked")
		oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv4, false)

		g.By("Remove BANP")
		oteutils.RemoveResource(oc, true, true, "banp", banpCR.Name)
		oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv4, true)

		g.By("Create ANP with deny action to cidr")
		anpCR := oteutils.SingleRuleCIDRANPPolicyResource{
			Name:       "anp-" + testID,
			SubjectKey: matchLabelKey,
			SubjectVal: ns,
			Priority:   10,
			RuleName:   "allow-to-" + ns,
			RuleAction: "Deny",
			Cidr:       "0.0.0.0/0",
			Template:   anpCRTemplate,
		}
		defer oteutils.RemoveResource(oc, true, true, "anp", anpCR.Name)
		anpCR.CreateSingleRuleCIDRANP(oc)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, anpCR.Name)).To(o.BeTrue())

		g.By("Verify destination got blocked")
		oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv4, false)
		g.By("Remove ANP")
		oteutils.RemoveResource(oc, true, true, "anp", anpCR.Name)
		oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv4, true)

		g.By("Create Network Policy with limited access to cidr which is not same as egressfirewall")
		npIPBlock := oteutils.IpBlockCIDRsSingle{
			Name:      "ipblock-single-cidr-egress",
			Template:  ipBlockEgressTemplateSingle,
			Cidr:      "1.1.1.1/32",
			Namespace: ns,
		}
		npIPBlock.CreateipBlockCIDRObjectSingle(oc)
		output, err = oc.AsAdmin().Run("get").Args("networkpolicy", "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress"))

		g.By("Verify destination got blocked")
		oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv4, false)

		g.By("Remove network policy")
		oteutils.RemoveResource(oc, true, true, "-n", ns, "networkpolicy", npIPBlock.Name)

		if ipStackType == "dualstack" {
			if !oteutils.CheckIPv6PublicAccess(oc) {
				g.Skip("Not be able to access the public website with IPv6,skip below test steps!!")
			}
			o.Expect(len(ipv6) == 0).NotTo(o.BeTrue())
			g.By("Create BANP with deny action to ipv6 cidr")
			banpCR.Cidr = "::/0"
			banpCR.CreateSingleRuleCIDRBANP(oc)
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("banp").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, banpCR.Name)).To(o.BeTrue())

			g.By("Update egressfirewall with ipv6 address")
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns, "-p", `{"spec":{"egress":[{"type":"Allow","to":{"cidrSelector":"`+ipv6+`/128"}}]}}`, "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())

			g.By("Verify destination got blocked")
			oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv6, false)

			g.By("Remove BANP")
			oteutils.RemoveResource(oc, true, true, "banp", banpCR.Name)
			oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv6, true)

			g.By("Create ANP")
			anpCR.Cidr = "::/0"
			anpCR.CreateSingleRuleCIDRANP(oc)
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, anpCR.Name)).To(o.BeTrue())

			g.By("Verify destination got blocked")
			oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv6, false)

			g.By("Remove ANP")
			oteutils.RemoveResource(oc, true, true, "anp", anpCR.Name)
			oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv6, true)

			g.By("Create Network Policy")
			npIPBlock.Cidr = "2001::02/128"
			npIPBlock.CreateipBlockCIDRObjectSingle(oc)
			output, err = oc.AsAdmin().Run("get").Args("networkpolicy", "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress"))

			g.By("Verify destination got blocked")
			oteutils.VerifyDstIPAccess(pod1.Name, ns, ipv6, false)
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 72054-EgressFirewall rules should include all IPs of matched node when nodeSelector is used", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall3-template.yaml")

		g.By("1. Label one node to match egressfirewall rule")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough worker nodes for this test, skip the case!!")
		}

		node1 := nodeList.Items[0].Name
		node2 := nodeList.Items[1].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, node1, "ef-dep")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, node1, "ef-dep", "qe")

		allNode1IPsv4, allNode1IPsv6 := oteutils.GetAllHostCIDR(oc, node1)
		allNode2IPsv4, allNode2IPRv6 := oteutils.GetAllHostCIDR(oc, node2)

		g.By("2. Get new namespace")
		ns := oc.Namespace()

		g.By("3. Create a pod in the namespace")
		testPod := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		testPod.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, testPod.Namespace, testPod.Name)

		g.By("4. Check the nodes can be accessed before egressFirewall with nodeSelector is applied")
		if !oteutils.CheckNodeAccessibilityFromAPod(oc, node1, testPod.Namespace, testPod.Name) || !oteutils.CheckNodeAccessibilityFromAPod(oc, node2, testPod.Namespace, testPod.Name) {
			g.Skip("Pre-test check failed, test is skipped!")
		}

		g.By("5. Create an egressFirewall with rule nodeSelector")
		ipStackType := oteutils.CheckIPStackType(oc)
		var cidrValue string
		if ipStackType == "ipv6single" {
			cidrValue = "::/0"
		} else {
			cidrValue = "0.0.0.0/0"
		}

		egressFW2 := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns,
			Ruletype:  "Deny",
			Cidr:      cidrValue,
			Template:  egressFWTemplate,
		}
		defer egressFW2.DeleteEgressFW2Object(oc)
		egressFW2.CreateEgressFW2Object(oc)
		efErr := oteutils.WaitEgressFirewallApplied(oc, egressFW2.Name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		g.By("6. Verify Egress firewall rules in NBDB of all nodes")
		ovnACLCmd := fmt.Sprintf("ovn-nbctl --format=table --no-heading  --columns=action,priority,match find acl external_ids:k8s.ovn.org/name=%s | grep allow", ns)
		nodelist, nodeErr := oteutils.GetAllNodesbyOSType(oc, "linux")
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(len(nodelist)).NotTo(o.BeEquivalentTo(0))

		for _, eachNode := range nodelist {
			ovnKubePod := oteutils.OvnkubeNodePod(oc, eachNode)
			listOutput, listErr := oteutils.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubePod, ovnACLCmd)
			o.Expect(listErr).NotTo(o.HaveOccurred())

			if ipStackType == "dualstack" || ipStackType == "ipv4single" {
				for _, nodeIPv4Addr := range allNode1IPsv4 {
					o.Expect(listOutput).Should(o.ContainSubstring(nodeIPv4Addr), fmt.Sprintf("%s for node %s is not in egressfirewall rules as expected", nodeIPv4Addr, node1))
				}
				for _, nodeIPv4Addr := range allNode2IPsv4 {
					o.Expect(listOutput).ShouldNot(o.ContainSubstring(nodeIPv4Addr), fmt.Sprintf("%s for node %s should not be in egressfirewall rules", nodeIPv4Addr, node2))
				}
			}

			if ipStackType == "dualstack" || ipStackType == "ipv6single" {
				for _, nodeIPv6Addr := range allNode1IPsv6 {
					o.Expect(listOutput).Should(o.ContainSubstring(nodeIPv6Addr), fmt.Sprintf("%s for node %s is not in egressfirewall rules as expected", nodeIPv6Addr, node1))
				}
				for _, nodeIPv6Addr := range allNode2IPRv6 {
					o.Expect(listOutput).ShouldNot(o.ContainSubstring(nodeIPv6Addr), fmt.Sprintf("%s for node %s should not be in egressfirewall rules", nodeIPv6Addr, node2))
				}
			}
		}

		g.By("7. Verified matched node can be accessed from all its interfaces, unmatched node can not be accessed from any of its interfaces")
		result1 := oteutils.CheckNodeAccessibilityFromAPod(oc, node1, testPod.Namespace, testPod.Name)
		o.Expect(result1).Should(o.BeTrue())
		result2 := oteutils.CheckNodeAccessibilityFromAPod(oc, node2, testPod.Namespace, testPod.Name)
		o.Expect(result2).Should(o.BeFalse())

		if ipStackType == "dualstack" || ipStackType == "ipv6single" {
			egressFW2.DeleteEgressFW2Object(oc)
			egressFW2.Cidr = "::/0"
			defer egressFW2.DeleteEgressFW2Object(oc)
			egressFW2.CreateEgressFW2Object(oc)
			efErr = oteutils.WaitEgressFirewallApplied(oc, egressFW2.Name, ns)
			o.Expect(efErr).NotTo(o.HaveOccurred())

			result1 := oteutils.CheckNodeAccessibilityFromAPod(oc, node1, testPod.Namespace, testPod.Name)
			o.Expect(result1).Should(o.BeTrue())
			result2 := oteutils.CheckNodeAccessibilityFromAPod(oc, node2, testPod.Namespace, testPod.Name)
			o.Expect(result2).Should(o.BeFalse())
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 73721-73722-Update domain name EgressFirewall works after restart ovnkube-node pods", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		_, crdErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd", "dnsnameresolvers.network.openshift.io").Output()
		if crdErr != nil {
			g.Skip("DNSNameResolver CRD not available on this cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		efwSingle := filepath.Join(buildPruningBaseDir, "egressfirewall", "egressfirewall-specific-dnsname.yaml")
		efwDualstack := filepath.Join(buildPruningBaseDir, "egressfirewall", "egressfirewall-specific-dnsname-dualstack.yaml")

		g.By("Create egressfirewall file")
		ns := oc.Namespace()
		ipStackType := oteutils.CheckIPStackType(oc)
		if ipStackType == "dualstack" {
			oteutils.CreateResourceFromFile(oc, ns, efwDualstack)
		} else {
			oteutils.CreateResourceFromFile(oc, ns, efwSingle)
		}
		efErr := oteutils.WaitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		g.By("Create a pod")
		pod1 := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod1.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("Update the domain name to a different one")
		updateValue := `[{"op":"replace","path":"/spec/egress/0/to/dnsName", "value":"www.redhat.com"}]`
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", updateValue).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		efErr = oteutils.WaitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		g.By("Verify the allowed rules take effect")
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "www.redhat.com", true)
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "www.facebook.com", true)
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "registry-1.docker.io", false)

		g.By("The dns names in dnsnameresolver get updated as well")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("dnsnameresolver", "-n", "openshift-ovn-kubernetes", "-o", "yaml").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "dnsName: www.facebook.com")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "dnsName: www.redhat.com")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "dnsName: registry-1.docker.io")).NotTo(o.BeTrue())

		g.By("Restart the ovnkube-node pod")
		defer oteutils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		podNode, err := oteutils.GetPodNodeName(oc, pod1.Namespace, pod1.Name)
		o.Expect(err).NotTo(o.HaveOccurred())
		delPodErr := oc.AsAdmin().Run("delete").Args("pod", "-l", "app=ovnkube-node", "-n", "openshift-ovn-kubernetes", "--field-selector", "spec.nodeName="+podNode).Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())

		g.By("Wait for ovnkube-node pods back up")
		oteutils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		g.By("Verify the function still works")
		efErr = oteutils.WaitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "www.redhat.com", true)
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "www.facebook.com", true)
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "registry-1.docker.io", false)
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 73723-dnsName has wildcard in EgressFirewall rules", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		_, crdErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("crd", "dnsnameresolvers.network.openshift.io").Output()
		if crdErr != nil {
			g.Skip("DNSNameResolver CRD not available on this cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		efwSingle := filepath.Join(buildPruningBaseDir, "egressfirewall", "egressfirewall-wildcard.yaml")
		efwDualstack := filepath.Join(buildPruningBaseDir, "egressfirewall", "egressfirewall-wildcard-dualstack.yaml")

		g.By("Create egressfirewall file")
		ns := oc.Namespace()
		ipStackType := oteutils.CheckIPStackType(oc)
		if ipStackType == "dualstack" {
			oteutils.CreateResourceFromFile(oc, ns, efwDualstack)
		} else {
			oteutils.CreateResourceFromFile(oc, ns, efwSingle)
		}
		efErr := oteutils.WaitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		g.By("Create a pod")
		pod1 := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod1.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, pod1.Namespace, pod1.Name)

		g.By("Verify the allowed rules which match the wildcard take effect")
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "www.google.com", true)
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "www.redhat.com", false)

		g.By("Update the domain name to a long domain name")
		updateValue := `[{"op":"replace","path":"/spec/egress/0/to/dnsName", "value":"*.whatever.you.like.here.followed.by.svc-1.google.com"}]`
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", updateValue).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		efErr = oteutils.WaitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		g.By("Verify the allowed rules which match the wildcard take effect")
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "type.whatever.you.like.here.followed.by.svc-1.google.com", true)
		oteutils.VerifyDesitnationAccess(oc, pod1.Name, pod1.Namespace, "www.google.com", false)
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][LEVEL0][Feature:EgressFirewall] 78162-Egress traffic works with ANP and egress firewall", func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		ipStackType := oteutils.CheckIPStackType(oc)
		platform := oteutils.CheckPlatform(oc)
		acceptedPlatform := strings.Contains(platform, "none")
		if !(ipStackType == "ipv4single" || (acceptedPlatform && ipStackType == "dualstack")) {
			g.Skip("This case should be run on UPI packet dualstack cluster or IPv4 cluster, skip other platform or network stack type.")
		}

		var (
			testID           = "78162"
			testDataDir      = testdata.FixturePath("networking")
			anpCRTemplate    = filepath.Join(testDataDir, "adminnetworkpolicy", "anp-single-rule-cidr-template.yaml")
			pingPodTemplate  = filepath.Join(testDataDir, "ping-for-pod-template.yaml")
			egressFWTemplate = filepath.Join(testDataDir, "egressfirewall2-template.yaml")
			matchLabelKey    = "kubernetes.io/metadata.name"
			allowedIPList    = []string{}
			deniedIPList     = []string{}
			patchEfw         string
			patchANP         string
		)

		g.By("1. Obtain the namespace")
		ns := oc.Namespace()

		g.By("2. Create a pod")
		pod := oteutils.PingPodResource{
			Name:      "hello-pod",
			Namespace: ns,
			Template:  pingPodTemplate,
		}
		pod.CreatePingPod(oc)
		oteutils.WaitPodReady(oc, pod.Namespace, pod.Name)

		g.By("3. Get an IP address for domain names")
		allowedIPv4, allowedIPv6 := oteutils.GetIPFromDnsName("www.google.com")
		o.Expect(len(allowedIPv4) == 0).NotTo(o.BeTrue())
		ipv4CIDR := allowedIPv4 + "/32"
		allowedIPList = append(allowedIPList, allowedIPv4)
		deniedIPv4, deniedIPv6 := oteutils.GetIPFromDnsName("www.facebook.com")
		o.Expect(len(deniedIPv4) == 0).NotTo(o.BeTrue())
		deniedIPList = append(deniedIPList, deniedIPv4)

		patchEfw = `[{"op": "add", "path":"/spec/egress/1", "value": {"type":"Deny","to":{"cidrSelector":"0.0.0.0/0"}}}]`
		patchANP = `[{"op": "add", "path": "/spec/egress/1", "value": {"name":"deny egresss", "action": "Deny", "to": [{"networks": ["0.0.0.0/0"]}]}}]`

		if ipStackType == "dualstack" {
			if oteutils.CheckIPv6PublicAccess(oc) {
				o.Expect(len(allowedIPv6) == 0).NotTo(o.BeTrue())
				ipv6CIDR := allowedIPv6 + "/128"
				allowedIPList = append(allowedIPList, allowedIPv6)
				o.Expect(len(deniedIPv6) == 0).NotTo(o.BeTrue())
				deniedIPList = append(deniedIPList, deniedIPv6)
				patchEfw = `[{"op": "add", "path":"/spec/egress/1", "value": {"type":"Allow","to":{"cidrSelector":"` + ipv6CIDR + `"}}}, {"op": "add", "path":"/spec/egress/2", "value": {"type":"Deny","to":{"cidrSelector":"0.0.0.0/0"}}}, {"op": "add", "path":"/spec/egress/3", "value": {"type":"Deny","to":{"cidrSelector":"::/0"}}}]`
				patchANP = `[{"op": "add", "path": "/spec/egress/0/to/0/networks/1", "value": "` + ipv6CIDR + `"}, {"op": "add", "path": "/spec/egress/1", "value": {"name":"deny egresss", "action": "Deny", "to": [{"networks": ["0.0.0.0/0", "::/0"]}]}}]`
			} else {
				e2e.Logf("Dual stack cluster does not have access to public websites")
			}
		}

		egressFW := oteutils.EgressFirewall2{
			Name:      "default",
			Namespace: ns,
			Ruletype:  "Allow",
			Cidr:      allowedIPv4 + "/32",
			Template:  egressFWTemplate,
		}

		anpCR := oteutils.SingleRuleCIDRANPPolicyResource{
			Name:       "anp-network-egress" + testID,
			SubjectKey: matchLabelKey,
			SubjectVal: ns,
			Priority:   10,
			RuleName:   "allow-to-" + ns,
			RuleAction: "Allow",
			Cidr:       ipv4CIDR,
			Template:   anpCRTemplate,
		}

		g.By("5. Verify the intended denied IP is reachable before egress firewall is applied")
		for i := 0; i < len(deniedIPList); i++ {
			e2e.Logf("Verify %s is accessible before egress firewall is applied", deniedIPList[i])
			oteutils.VerifyDstIPAccess(pod.Name, ns, deniedIPList[i], true)
		}

		g.By("6. Create egress firewall")
		egressFW.CreateEgressFW2Object(oc)
		err := oteutils.WaitEgressFirewallApplied(oc, egressFW.Name, ns)
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.PatchReplaceResourceAsAdmin(oc, "egressfirewall/default", patchEfw, ns)
		efwRules, efwRulesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", ns, "egressfirewall", "default", "-o=jsonpath={.spec.egress}").Output()
		o.Expect(efwRulesErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Egress Firewall Rules after update : %s", efwRules)

		g.By("7. Validate traffic after egress firewall is applied")
		for i := 0; i < len(allowedIPList); i++ {
			g.By(fmt.Sprintf("Verify %s is accessible with just egress firewall", allowedIPList[i]))
			oteutils.VerifyDstIPAccess(pod.Name, ns, allowedIPList[i], true)
			g.By(fmt.Sprintf("Verify %s is not accessible with just egress firewall", deniedIPList[i]))
			oteutils.VerifyDstIPAccess(pod.Name, ns, deniedIPList[i], false)
		}

		g.By("8. Create ANP with Allow action to an IP and Deny action to all CIDRs")
		defer oteutils.RemoveResource(oc, true, true, "anp", anpCR.Name)
		anpCR.CreateSingleRuleCIDRANP(oc)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, anpCR.Name)).To(o.BeTrue())
		oteutils.PatchReplaceResourceAsAdmin(oc, "anp/"+anpCR.Name, patchANP)

		anpRules, rulesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy", anpCR.Name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(rulesErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP Rules after update : %s", anpRules)

		g.By("9. Validate traffic with ANP and Egress firewall configured")
		for i := 0; i < len(allowedIPList); i++ {
			g.By(fmt.Sprintf("Verify %s is accessible after ANP is created", allowedIPList[i]))
			oteutils.VerifyDstIPAccess(pod.Name, ns, allowedIPList[i], true)
			g.By(fmt.Sprintf("Verify %s is not accessible after ANP is created", deniedIPList[i]))
			oteutils.VerifyDstIPAccess(pod.Name, ns, deniedIPList[i], false)
		}

		g.By("10. Remove Egress Firewall")
		oteutils.RemoveResource(oc, true, true, "egressfirewall", egressFW.Name, "-n", egressFW.Namespace)

		g.By("11. Validate traffic with just ANP configured")
		for i := 0; i < len(allowedIPList); i++ {
			g.By(fmt.Sprintf("Verify %s is accessible after egress firewall is removed", allowedIPList[i]))
			oteutils.VerifyDstIPAccess(pod.Name, ns, allowedIPList[i], true)
			g.By(fmt.Sprintf("Verify %s is not accessible after egress firewall is removed", deniedIPList[i]))
			oteutils.VerifyDstIPAccess(pod.Name, ns, deniedIPList[i], false)
		}
	})

	// -------- EgressIP tests (cloud_egressip_ovn) --------

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 47031-After reboot egress node EgressIP still work", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		oteutils.SkipIfMachineAPIUnavailable(oc)

		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		g.By("1.1 Label EgressIP node")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		g.By("2.1 Create first egressip object")
		freeIPs := oteutils.FindFreeIPs(oc, nodeList.Items[0].Name, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip1 := oteutils.EgressIPResource1{
			Name:          "egressip-47031",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip1.CreateEgressIPObject2(oc)
		defer egressip1.DeleteEgressIPObject1(oc)

		g.By("3.1 Create first namespace")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns1)

		g.By("3.2 Apply a label to test namespace")
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3.3 Create pods in test namespace")
		oteutils.CreateResourceFromFile(oc, ns1, testPodFile)
		err = oteutils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		oteutils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")

		g.By("3.4 Apply label to one pod in test namespace")
		testPodName := oteutils.GetPodName(oc, ns1, "name=test-pods")
		err = oteutils.LabelPod(oc, ns1, testPodName[0], "color=pink")
		defer oteutils.LabelPod(oc, ns1, testPodName[0], "color-")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Check only one EgressIP assigned in the object")
		egressIPMaps := oteutils.GetAssignedEIPInEIPObject(oc, egressip1.Name)
		o.Expect(len(egressIPMaps)).Should(o.Equal(1))

		g.By("5. Reboot egress node")
		defer oteutils.CheckNodeStatus(oc, egressNode, "Ready")
		oteutils.RebootNode(oc, egressNode)
		oteutils.CheckNodeStatus(oc, egressNode, "NotReady")
		oteutils.CheckNodeStatus(oc, egressNode, "Ready")
		err = oteutils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		oteutils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName = oteutils.GetPodName(oc, ns1, "name=test-pods")
		err = oteutils.LabelPod(oc, ns1, testPodName[0], "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Check EgressIP assigned after reboot")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip1.Name, 1)
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 54647-No stale duplicated SNAT on gateway router after egressIP failover", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		g.By("1. Get two nodes from same subnet")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		found, nodeNames := oteutils.GetTwoNodesSameSubnet(oc, nodeList)
		if !found {
			g.Skip("Cannot find two nodes in same subnet, skip!!")
		}
		egressNode1 := nodeNames[0]
		egressNode2 := nodeNames[1]

		g.By("2. Label nodes as egress assignable")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)

		g.By("3. Create egressIP object with 2 IPs")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode1, 2)
		o.Expect(len(freeIPs)).Should(o.Equal(2))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-54647",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("4. Create namespace and pods")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns1)
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.CreateResourceFromFile(oc, ns1, testPodFile)
		err = oteutils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		oteutils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName := oteutils.GetPodName(oc, ns1, "name=test-pods")
		err = oteutils.LabelPod(oc, ns1, testPodName[0], "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Verify EgressIP assigned")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)

		g.By("6. Remove egress label from one node to force failover")
		egressIPMaps := oteutils.GetAssignedEIPInEIPObject(oc, egressip.Name)
		var assignedNode string
		for _, eipMap := range egressIPMaps {
			assignedNode = eipMap["node"]
		}
		if assignedNode == egressNode1 {
			e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		} else {
			e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
		}

		g.By("7. Verify EgressIP still assigned after failover")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)

		g.By("8. Check no stale/duplicated SNAT on gateway router")
		newEIPMaps := oteutils.GetAssignedEIPInEIPObject(oc, egressip.Name)
		var failoverNode string
		for _, eipMap := range newEIPMaps {
			failoverNode = eipMap["node"]
		}
		o.Expect(failoverNode).NotTo(o.Equal(assignedNode), "EgressIP should have moved to a different node after failover")
		snatOutput, snatErr := oteutils.GetSNATofEgressIP(oc, failoverNode, freeIPs[0])
		o.Expect(snatErr).NotTo(o.HaveOccurred())
		snatCount := 0
		for _, s := range snatOutput {
			if strings.Contains(s, freeIPs[0]) {
				snatCount++
			}
		}
		o.Expect(snatCount).Should(o.BeNumerically("<=", 1), "Found duplicated SNAT entries for egressIP %s", freeIPs[0])
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 54741-EgressIP health check via GRPC on hypershift cluster", g.Serial, func() {
		g.Skip("HyperShift OTE infrastructure not yet available")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 61582-66112-New ROSA node with label EgressIP assigned during machinepool creation", g.Serial, func() {
		g.Skip("ROSA machinepool OTE infrastructure not yet available")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 64293-EgressIP should not break access to host networked pods", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		g.By("1. Label EgressIP node")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		g.By("2. Create egressIP object")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-64293",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("3. Create namespace and pods")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns1)
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.CreateResourceFromFile(oc, ns1, testPodFile)
		err = oteutils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		oteutils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName := oteutils.GetPodName(oc, ns1, "name=test-pods")
		err = oteutils.LabelPod(oc, ns1, testPodName[0], "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Verify EgressIP assigned")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)

		g.By("5. Verify pod can access the Kubernetes API service (host networked)")
		svcIP, _ := oteutils.GetSvcIP(oc, "default", "kubernetes")
		curlCmd := fmt.Sprintf("curl -s %s --connect-timeout 5", net.JoinHostPort(svcIP, "443"))
		o.Eventually(func() error {
			_, err := e2eoutput.RunHostCmd(ns1, testPodName[0], curlCmd)
			return err
		}, "60s", "10s").ShouldNot(o.HaveOccurred())
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 67091-EgressIP status synced with cloudprivateipconfig after OVNK restart", g.Serial, func() {
		platform := oteutils.CheckPlatform(oc)
		if !strings.Contains(platform, "aws") && !strings.Contains(platform, "gcp") && !strings.Contains(platform, "azure") {
			g.Skip("This test only runs on AWS/GCP/Azure platforms")
		}
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		g.By("1. Label EgressIP node")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		g.By("2. Create egressIP object")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-67091",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("3. Create namespace, label and pods")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns1)
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.CreateResourceFromFile(oc, ns1, testPodFile)
		err = oteutils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		oteutils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName := oteutils.GetPodName(oc, ns1, "name=test-pods")
		err = oteutils.LabelPod(oc, ns1, testPodName[0], "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Verify EgressIP assigned")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)

		g.By("5. Restart OVNK pods")
		defer oteutils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "-l", "app=ovnkube-node", "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		g.By("6. Verify EgressIP status synced with cloudprivateipconfig")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)
		cpicOutput, cpicErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("cloudprivateipconfig", freeIPs[0], "-o", "yaml").Output()
		o.Expect(cpicErr).NotTo(o.HaveOccurred())
		o.Expect(cpicOutput).To(o.ContainSubstring(egressNode))
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][FdpOvnOvs][Feature:EgressIP] 70667-SNAT and lr-policy-list deleted after pods deleted with egressIP", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		g.By("1. Label EgressIP node")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		egressNode := nodeList.Items[0].Name
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		g.By("2. Create egressIP object")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-70667",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("3. Create namespace and pods")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns1)
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.CreateResourceFromFile(oc, ns1, testPodFile)
		err = oteutils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		oteutils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName := oteutils.GetPodName(oc, ns1, "name=test-pods")
		// Select a pod running on the egress node so the SNAT check queries the correct zone's OVN NBDB
		targetPod := testPodName[0]
		for _, pod := range testPodName {
			nodeName, nodeErr := oteutils.GetPodNodeName(oc, ns1, pod)
			o.Expect(nodeErr).NotTo(o.HaveOccurred())
			if nodeName == egressNode {
				targetPod = pod
				break
			}
		}
		e2e.Logf("Selected pod %s for SNAT verification (egressNode: %s)", targetPod, egressNode)
		err = oteutils.LabelPod(oc, ns1, targetPod, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4. Verify EgressIP assigned and SNAT exists for the pod")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)
		testPodIP := oteutils.GetPodIPv4(oc, ns1, targetPod)
		snatOutput, snatErr := oteutils.GetSNATofEgressIP(oc, egressNode, freeIPs[0])
		o.Expect(snatErr).NotTo(o.HaveOccurred())
		o.Expect(len(snatOutput)).Should(o.Equal(1))
		o.Expect(snatOutput[0]).To(o.ContainSubstring(testPodIP))

		g.By("5. Delete the labelled pod")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", targetPod, "-n", ns1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("6. Verify SNAT rule cleaned up after pod deleted")
		o.Eventually(func() bool {
			snatOut, err := oteutils.GetSNATofEgressIP(oc, egressNode, freeIPs[0])
			if err != nil {
				return true
			}
			return !strings.Contains(strings.Join(snatOut, " "), testPodIP)
		}, "300s", "10s").Should(o.BeTrue(), "SNAT rule not cleaned up after pod deletion")

		g.By("7. Verify lr-policy-list cleaned up")
		lrPolicyOutput, lrErr := oteutils.GetlrPolicyList(oc, egressNode, "", false)
		o.Expect(lrErr).NotTo(o.HaveOccurred())
		o.Expect(strings.Join(lrPolicyOutput, " ")).NotTo(o.ContainSubstring(testPodIP))
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 73694-No stale snat rules left after egressIP failover", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		g.By("1. Get two nodes from same subnet")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		found, nodeNames := oteutils.GetTwoNodesSameSubnet(oc, nodeList)
		if !found {
			g.Skip("Cannot find two nodes in same subnet, skip!!")
		}
		egressNode1 := nodeNames[0]
		egressNode2 := nodeNames[1]

		g.By("2. Label nodes as egress assignable")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)

		g.By("3. Create egressIP object")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode1, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-73694",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("4. Create namespace and pods")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns1)
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.CreateResourceFromFile(oc, ns1, testPodFile)
		err = oteutils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		oteutils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName := oteutils.GetPodName(oc, ns1, "name=test-pods")
		err = oteutils.LabelPod(oc, ns1, testPodName[0], "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Verify EgressIP assigned")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)

		g.By("6. Force failover by removing egress label")
		egressIPMaps := oteutils.GetAssignedEIPInEIPObject(oc, egressip.Name)
		var assignedNode string
		for _, eipMap := range egressIPMaps {
			assignedNode = eipMap["node"]
		}
		if assignedNode == egressNode1 {
			e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		} else {
			e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
		}

		g.By("7. Verify no stale SNAT rules after failover")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)
		newEgressIPMaps := oteutils.GetAssignedEIPInEIPObject(oc, egressip.Name)
		var newNode string
		for _, eipMap := range newEgressIPMaps {
			newNode = eipMap["node"]
		}
		o.Expect(newNode).NotTo(o.Equal(assignedNode))

		snatOutput, snatErr := oteutils.GetSNATofEgressIP(oc, newNode, freeIPs[0])
		o.Expect(snatErr).NotTo(o.HaveOccurred())
		snatCount := 0
		for _, s := range snatOutput {
			if strings.Contains(s, freeIPs[0]) {
				snatCount++
			}
		}
		o.Expect(snatCount).Should(o.BeNumerically("<=", 1), "Found stale SNAT rules after failover")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 78663-Pods on default network and UDNs can access k8s service when node is egressIP", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		buildPruningBaseDir := testdata.FixturePath("networking")
		testPodFile := filepath.Join(buildPruningBaseDir, "testpod.yaml")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")

		g.By("1. Check IP stack and node count")
		ipStackType := oteutils.CheckIPStackType(oc)
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if ipStackType == "ipv6single" && len(nodeList.Items) < 2 {
			g.Skip("Need at least 2 nodes for ipv6single stack")
		}

		g.By("2. Label EgressIP node")
		egressNode := nodeList.Items[0].Name
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)

		g.By("3. Create egressIP object")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-78663",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("4. Create namespace and pods on default network")
		oc.SetupProject()
		ns1 := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns1)
		err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org=qe").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", ns1, "org-").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		oteutils.CreateResourceFromFile(oc, ns1, testPodFile)
		err = oteutils.WaitForPodWithLabelReady(oc, ns1, "name=test-pods")
		oteutils.AssertWaitPollNoErr(err, "this pod with label name=test-pods not ready")
		testPodName := oteutils.GetPodName(oc, ns1, "name=test-pods")
		err = oteutils.LabelPod(oc, ns1, testPodName[0], "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Verify EgressIP assigned")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)

		g.By("6. Verify pod can access kubernetes service")
		o.Eventually(func() error {
			_, err := e2eoutput.RunHostCmd(ns1, testPodName[0], "curl -sk https://kubernetes.default.svc --connect-timeout 5")
			return err
		}, "60s", "10s").ShouldNot(o.HaveOccurred())
	})

	// -------- EgressIP UDN tests --------

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 77654-Validate egressIP with mixed of multiple non-overlapping UDNs and default network layer3 layer2 IPv4", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, skip!!")
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")

		egressNode := nodeList.Items[0].Name
		theOtherNode := nodeList.Items[1].Name

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		g.By("1. Create namespaces: first for default network, rest for UDNs")
		ns := oc.Namespace()
		var allNS []string
		allNS = append(allNS, ns)
		for i := 0; i < 4; i++ {
			nsUdn := oteutils.CreateNamespaceUDN(oc, "egressip-77654")
			defer oteutils.DeleteNamespace(oc, nsUdn)
			allNS = append(allNS, nsUdn)
		}

		g.By("2. Apply label to all namespaces")
		for _, nsItem := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nsItem, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nsItem, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			oteutils.SetNamespacePrivileged(oc, nsItem)
		}

		g.By("3. Create UDN CRDs")
		oteutils.CreateGeneralUDNCRD(oc, allNS[1], "udn-77654-l3-1", "192.168.10.0/24", "", "192.168.10.0/24", "layer3")
		oteutils.CreateGeneralUDNCRD(oc, allNS[2], "udn-77654-l3-2", "192.168.20.0/24", "", "192.168.20.0/24", "layer3")
		oteutils.CreateGeneralUDNCRD(oc, allNS[3], "udn-77654-l2-1", "192.168.30.0/24", "", "192.168.30.0/24", "layer2")
		oteutils.CreateGeneralUDNCRD(oc, allNS[4], "udn-77654-l2-2", "192.168.40.0/24", "", "192.168.40.0/24", "layer2")

		g.By("4. Create egressIP object")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-77654",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("5. Create pods on the non-egress node")
		for _, nsItem := range allNS {
			pod := oteutils.PingPodResourceNode{
				Name:      "test-pod",
				Namespace: nsItem,
				Nodename:  theOtherNode,
				Template:  pingPodNodeTemplate,
			}
			pod.CreatePingPodNode(oc)
			oteutils.WaitPodReady(oc, nsItem, pod.Name)
			err = oteutils.LabelPod(oc, nsItem, pod.Name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("6. Verify EgressIP assigned")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 77655-Validate egressIP with mixed of multiple overlapping UDNs and default network layer3 layer2 IPv4", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, skip!!")
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")

		egressNode := nodeList.Items[0].Name
		theOtherNode := nodeList.Items[1].Name

		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode, egressNodeLabel, "true")

		g.By("1. Create namespaces")
		ns := oc.Namespace()
		var allNS []string
		allNS = append(allNS, ns)
		for i := 0; i < 4; i++ {
			nsUdn := oteutils.CreateNamespaceUDN(oc, "egressip-77655")
			defer oteutils.DeleteNamespace(oc, nsUdn)
			allNS = append(allNS, nsUdn)
		}

		g.By("2. Apply labels to all namespaces")
		for _, nsItem := range allNS {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nsItem, "org-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nsItem, "org=qe").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			oteutils.SetNamespacePrivileged(oc, nsItem)
		}

		g.By("3. Create UDN CRDs with overlapping subnets")
		oteutils.CreateGeneralUDNCRD(oc, allNS[1], "udn-77655-l3-1", "192.168.10.0/24", "", "192.168.10.0/24", "layer3")
		oteutils.CreateGeneralUDNCRD(oc, allNS[2], "udn-77655-l3-2", "192.168.10.0/24", "", "192.168.10.0/24", "layer3")
		oteutils.CreateGeneralUDNCRD(oc, allNS[3], "udn-77655-l2-1", "192.168.20.0/24", "", "192.168.20.0/24", "layer2")
		oteutils.CreateGeneralUDNCRD(oc, allNS[4], "udn-77655-l2-2", "192.168.20.0/24", "", "192.168.20.0/24", "layer2")

		g.By("4. Create egressIP object")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-77655",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("5. Create pods on the non-egress node")
		for _, nsItem := range allNS {
			pod := oteutils.PingPodResourceNode{
				Name:      "test-pod",
				Namespace: nsItem,
				Nodename:  theOtherNode,
				Template:  pingPodNodeTemplate,
			}
			pod.CreatePingPodNode(oc)
			oteutils.WaitPodReady(oc, nsItem, pod.Name)
			err = oteutils.LabelPod(oc, nsItem, pod.Name, "color=pink")
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("6. Verify EgressIP assigned")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 77744-egressIP Failover with UDNs layer3 layer2 IPv4", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		found, nodeNames := oteutils.GetTwoNodesSameSubnet(oc, nodeList)
		if !found {
			g.Skip("Cannot find two nodes in same subnet, skip!!")
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressIP2Template := filepath.Join(buildPruningBaseDir, "egressip-config2-template.yaml")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")

		egressNode1 := nodeNames[0]
		egressNode2 := nodeNames[1]
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel, "true")
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)

		g.By("1. Create UDN namespaces")
		ns := oc.Namespace()
		oteutils.SetNamespacePrivileged(oc, ns)
		nsUdn := oteutils.CreateNamespaceUDN(oc, "egressip-77744")
		defer oteutils.DeleteNamespace(oc, nsUdn)
		oteutils.SetNamespacePrivileged(oc, nsUdn)

		for _, nsItem := range []string{ns, nsUdn} {
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nsItem, "org=qe").Execute()
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("ns", nsItem, "org-").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("2. Create UDN CRD")
		oteutils.CreateGeneralUDNCRD(oc, nsUdn, "udn-77744", "192.168.10.0/24", "", "192.168.10.0/24", "layer3")

		g.By("3. Create egressIP object")
		freeIPs := oteutils.FindFreeIPs(oc, egressNode1, 1)
		o.Expect(len(freeIPs)).Should(o.Equal(1))
		egressip := oteutils.EgressIPResource1{
			Name:          "egressip-77744",
			Template:      egressIP2Template,
			EgressIP1:     freeIPs[0],
			NsLabelKey:    "org",
			NsLabelValue:  "qe",
			PodLabelKey:   "color",
			PodLabelValue: "pink",
		}
		egressip.CreateEgressIPObject2(oc)
		defer egressip.DeleteEgressIPObject1(oc)

		g.By("4. Create pods")
		pod := oteutils.PingPodResourceNode{
			Name:      "test-pod",
			Namespace: nsUdn,
			Nodename:  egressNode2,
			Template:  pingPodNodeTemplate,
		}
		pod.CreatePingPodNode(oc)
		oteutils.WaitPodReady(oc, nsUdn, pod.Name)
		err = oteutils.LabelPod(oc, nsUdn, pod.Name, "color=pink")
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("5. Verify EgressIP assigned")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)

		g.By("6. Force failover")
		egressIPMaps := oteutils.GetAssignedEIPInEIPObject(oc, egressip.Name)
		var assignedNode string
		for _, eipMap := range egressIPMaps {
			assignedNode = eipMap["node"]
		}
		if assignedNode == egressNode1 {
			e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode1, egressNodeLabel)
		} else {
			e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, egressNode2, egressNodeLabel)
		}

		g.By("7. Verify EgressIP failover")
		oteutils.VerifyExpectedEIPNumInEIPObject(oc, egressip.Name, 1)
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 77840-egressIP with non-overlapping UDNs layer3 IPv6 dualstack", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		ipStackType := oteutils.CheckIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.Skip("Skip on IPv4 single stack cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, skip!!")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 77841-egressIP with overlapping UDNs layer3 IPv6 dualstack", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		ipStackType := oteutils.CheckIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.Skip("Skip on IPv4 single stack cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Need 2 nodes for the test, skip!!")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 77842-egressIP Failover with UDNs layer3 IPv6", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		ipStackType := oteutils.CheckIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.Skip("Skip on IPv4 single stack cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		found, _ := oteutils.GetTwoNodesSameSubnet(oc, nodeList)
		if !found {
			g.Skip("Cannot find two nodes in same subnet, skip!!")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 78199-egressIP after UDN deleted then recreated layer3 layer2 IPv4", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		found, _ := oteutils.GetTwoNodesSameSubnet(oc, nodeList)
		if !found {
			g.Skip("Cannot find two nodes in same subnet, skip!!")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 78200-egressIP after OVNK restarted layer3 layer2 IPv4", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		found, _ := oteutils.GetTwoNodesSameSubnet(oc, nodeList)
		if !found {
			g.Skip("Cannot find two nodes in same subnet, skip!!")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 78247-egressIP after UDN deleted then recreated layer3 IPv6 dualstack", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		ipStackType := oteutils.CheckIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.Skip("Skip on IPv4 single stack cluster")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 78274-egressIP after OVNK restarted layer3 IPv6 dualstack", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		ipStackType := oteutils.CheckIPStackType(oc)
		if ipStackType == "ipv4single" {
			g.Skip("Skip on IPv4 single stack cluster")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 78276-UDN egressIP Pods not affected by egressIP on other netnamespace", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 1 {
			g.Skip("Need at least 1 node for the test")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 78293-After reboot egress node EgressIP on UDN still work layer3 layer2 IPv4", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		oteutils.SkipIfMachineAPIUnavailable(oc)
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 78453-Traffic load balanced egressIP UDN layer3 IPv4", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("Need at least 3 nodes for the test")
		}
		found, _ := oteutils.GetTwoNodesSameSubnet(oc, nodeList)
		if !found {
			g.Skip("Cannot find two nodes in same subnet, skip!!")
		}
		g.Skip("Not implemented")
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressIP] 79097-Traffic load balanced egressIP UDN layer2 IPv4", g.Serial, func() {
		if oteutils.CheckDisconnect(oc) {
			g.Skip("Skip for disconnected cluster")
		}
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 3 {
			g.Skip("Need at least 3 nodes for the test")
		}
		found, _ := oteutils.GetTwoNodesSameSubnet(oc, nodeList)
		if !found {
			g.Skip("Cannot find two nodes in same subnet, skip!!")
		}
		g.Skip("Not implemented")
	})

	// -------- EgressRouter test --------

	// -------- EgressQoS test --------

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressQos] 74054-Egress traffic works with ANP BANP and NP with EgressQoS", g.Serial, func() {
		g.Skip("EgressQoS DSCP service infrastructure not yet available in OTE")
	})

	// -------- OVN Misc EgressFirewall status tests --------

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 69762-Check egressfirewall status when all zones reported success", func() {
		ipStackType := oteutils.CheckIPStackType(oc)
		var egressFWCIDR1, egressFWCIDR2 string
		if ipStackType == "dualstack" {
			egressFWCIDR1 = "2.1.1.0/24"
			egressFWCIDR2 = "2021::/96"
		} else if ipStackType == "ipv6single" {
			egressFWCIDR1 = "2021::/96"
			egressFWCIDR2 = "2022::/96"
		} else {
			egressFWCIDR1 = "2.1.1.0/24"
			egressFWCIDR2 = "2.1.2.0/24"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")

		g.By("1. Create egressfirewall object")
		ns := oc.Namespace()
		egressFW := oteutils.EgressFirewall5{
			Name:        "default",
			Namespace:   ns,
			Ruletype1:   "Allow",
			Rulename1:   "cidrSelector",
			Rulevalue1:  egressFWCIDR1,
			Protocol1:   "TCP",
			Portnumber1: 80,
			Ruletype2:   "Allow",
			Rulename2:   "cidrSelector",
			Rulevalue2:  egressFWCIDR2,
			Protocol2:   "TCP",
			Portnumber2: 80,
			Template:    egressFWTemplate,
		}
		defer oteutils.RemoveResource(oc, true, true, "egressfirewall", egressFW.Name, "-n", egressFW.Namespace)
		egressFW.CreateEgressFW5Object(oc)

		g.By("2. Check status of egressfirewall object")
		checkErr := oteutils.CheckEgressFWStatus(oc, egressFW.Name, ns, "EgressFirewall Rules applied")
		oteutils.AssertWaitPollNoErr(checkErr, fmt.Sprintf("EgressFirewall Rule %s doesn't apply in time", egressFW.Name))
		messages, messagesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.Name, "-n", egressFW.Namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(messagesErr).NotTo(o.HaveOccurred())
		nodes, getNodeErr := oteutils.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			o.Expect(messages).Should(o.ContainSubstring(node + ": EgressFirewall Rules applied"))
		}
	})

	g.It("[JIRA:Networking][OTP][ovn-kubernetes-ote][Feature:EgressFirewall] 69876-Check egressfirewall status when there is zone reported failure", func() {
		ipStackType := oteutils.CheckIPStackType(oc)
		var egressFWCIDR1, egressFWCIDR2 string
		if ipStackType == "dualstack" {
			egressFWCIDR1 = "1.1.1.1"
			egressFWCIDR2 = "2011::11"
		} else if ipStackType == "ipv6single" {
			egressFWCIDR1 = "2011::11"
			egressFWCIDR2 = "2012::11"
		} else {
			egressFWCIDR1 = "1.1.1.1"
			egressFWCIDR2 = "2.1.1.1"
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")

		g.By("1. Create egressfirewall object which missing CIDR prefix")
		ns := oc.Namespace()
		egressFW := oteutils.EgressFirewall5{
			Name:        "default",
			Namespace:   ns,
			Ruletype1:   "Allow",
			Rulename1:   "cidrSelector",
			Rulevalue1:  egressFWCIDR1,
			Protocol1:   "TCP",
			Portnumber1: 80,
			Ruletype2:   "Allow",
			Rulename2:   "cidrSelector",
			Rulevalue2:  egressFWCIDR2,
			Protocol2:   "TCP",
			Portnumber2: 80,
			Template:    egressFWTemplate,
		}
		defer oteutils.RemoveResource(oc, true, true, "egressfirewall", egressFW.Name, "-n", egressFW.Namespace)
		egressFW.CreateEgressFW5Object(oc)

		g.By("2. Check status of egressfirewall object")
		checkErr := oteutils.CheckEgressFWStatus(oc, egressFW.Name, ns, "EgressFirewall Rules not correctly applied")
		oteutils.AssertWaitPollNoErr(checkErr, fmt.Sprintf("EgressFirewall Rule %s doesn't show failure in time", egressFW.Name))
		messages, messagesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", egressFW.Name, "-n", egressFW.Namespace, `-ojsonpath={.status.messages}`).Output()
		o.Expect(messagesErr).NotTo(o.HaveOccurred())
		nodes, getNodeErr := oteutils.GetAllNodesbyOSType(oc, "linux")
		o.Expect(getNodeErr).NotTo(o.HaveOccurred())
		for _, node := range nodes {
			o.Expect(strings.Contains(messages, node+": EgressFirewall Rules not correctly applied")).Should(o.BeTrue())
		}
	})
})
