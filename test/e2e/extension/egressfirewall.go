package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	clusterinfra "github.com/openshift/origin/test/extended/util/compat_otp/clusterinfra"

	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

var _ = g.Describe("[OTP][sig-networking] SDN egressfirewall", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-egressfirewall", compat_otp.KubeConfigPath())
	var aclLogPath = "--path=ovn/acl-audit-log.log"
	g.BeforeEach(func() {
		networkType := compat_otp.CheckNetworkType(oc)
		if !strings.Contains(networkType, "ovn") {
			g.Skip("This case requires OVNKubernetes as network plugin, skip the test as the cluster does not have OVN network plugin")
		}

		if checkProxy(oc) {
			g.Skip("This is proxy cluster, egressfirewall cannot be tested on proxy cluster, skip the test.")
		}
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-High-53223-Verify ACL audit logs can be generated for traffic hit EgressFirewall rules.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressFWTemplate    = filepath.Join(buildPruningBaseDir, "egressfirewall1-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("1. Obtain the namespace \n")
		ns1 := oc.Namespace()

		compat_otp.By("2. Enable ACL looging on the namespace ns1 \n")
		enableACLOnNamespace(oc, ns1, "info", "info")

		compat_otp.By("3. create hello pod in ns1 \n")

		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("4. Create an EgressFirewall \n")
		egressFW1 := egressFirewall1{
			name:      "default",
			namespace: ns1,
			template:  egressFWTemplate,
		}
		egressFW1.createEgressFWObject1(oc)
		efErr := waitEgressFirewallApplied(oc, egressFW1.name, ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("5. Check www.test.com is blocked \n")
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -s www.test.com --connect-timeout 5")
			return err
		}, "60s", "10s").Should(o.HaveOccurred())

		compat_otp.By("6. Check www.redhat.com is allowed \n")
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).ToNot(o.HaveOccurred())

		compat_otp.By("7. Verify acl logs for egressfirewall generated. \n")
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

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Medium-53224-Disable and enable acl logging for EgressFirewall.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressFWTemplate    = filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("1. Obtain the namespace \n")
		ns1 := oc.Namespace()

		compat_otp.By("2. Enable ACL looging on the namespace ns1 \n")
		enableACLOnNamespace(oc, ns1, "info", "info")

		compat_otp.By("3. create hello pod in ns1 \n")

		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("4. Create an EgressFirewall \n")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns1,
			ruletype:  "Deny",
			cidr:      "0.0.0.0/0",
			template:  egressFWTemplate,
		}
		egressFW2.createEgressFW2Object(oc)
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns1, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"::/0\"}}]}}", "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		}
		err = waitEgressFirewallApplied(oc, egressFW2.name, ns1)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("5. Generate egress traffic which will hit the egressfirewall. \n")
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		compat_otp.By("6. Verify acl logs for egressfirewall generated. \n")
		egressFwRegex := fmt.Sprintf("EF:%s:.*", ns1)
		aclLogs, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		r := regexp.MustCompile(egressFwRegex)
		matches := r.FindAllString(aclLogs, -1)
		aclLogNum := len(matches)
		o.Expect(aclLogNum > 0).To(o.BeTrue(), fmt.Sprintf("No matched acl logs numbers for namespace %s, and actual matched logs are: \n %v ", ns1, matches))

		compat_otp.By("7. Disable  acl logs. \n")
		disableACLOnNamespace(oc, ns1)

		compat_otp.By("8. Generate egress traffic which will hit the egressfirewall. \n")
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		g.By("9. Verify no incremental acl logs. \n")
		aclLogs2, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		matches2 := r.FindAllString(aclLogs2, -1)
		aclLogNum2 := len(matches2)
		o.Expect(aclLogNum2 == aclLogNum).To(o.BeTrue(), fmt.Sprintf("Before disable,actual matched logs are: \n %v ,after disable,actual matched logs are: \n %v", matches, matches2))

		compat_otp.By("10. Enable acl logs. \n")
		enableACLOnNamespace(oc, ns1, "alert", "alert")

		compat_otp.By("11. Generate egress traffic which will hit the egressfirewall. \n")
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		g.By("12. Verify new acl logs for egressfirewall generated. \n")
		aclLogs3, err3 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err3).NotTo(o.HaveOccurred())
		matches3 := r.FindAllString(aclLogs3, -1)
		aclLogNum3 := len(matches3)
		o.Expect(aclLogNum3 > aclLogNum).To(o.BeTrue(), fmt.Sprintf("Previous actual matched logs are: \n %v ,after enable again,actual matched logs are: \n %v", matches, aclLogNum3))
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-Medium-53226-The namespace enabled acl logging will not affect the namespace not enabling acl logging.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
			egressFWTemplate    = filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")
		)

		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("1. Obtain the namespace \n")
		ns1 := oc.Namespace()

		compat_otp.By("2. Enable ACL looging on the namespace ns1 \n")
		enableACLOnNamespace(oc, ns1, "info", "info")

		compat_otp.By("3. create hello pod in ns1 \n")

		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("4. Create an EgressFirewall \n")
		egressFW1 := egressFirewall2{
			name:      "default",
			namespace: ns1,
			ruletype:  "Deny",
			cidr:      "0.0.0.0/0",
			template:  egressFWTemplate,
		}
		egressFW1.createEgressFW2Object(oc)
		defer egressFW1.deleteEgressFW2Object(oc)
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns1, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"::/0\"}}]}}", "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		}
		err = waitEgressFirewallApplied(oc, egressFW1.name, ns1)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("5. Generate egress traffic which will hit the egressfirewall. \n")
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		compat_otp.By("6. Verify acl logs for egressfirewall generated. \n")
		egressFwRegex := fmt.Sprintf("EF:%s:.*", ns1)
		aclLogs, err2 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
		o.Expect(err2).NotTo(o.HaveOccurred())
		r := regexp.MustCompile(egressFwRegex)
		matches := r.FindAllString(aclLogs, -1)
		aclLogNum := len(matches)
		o.Expect(aclLogNum > 0).To(o.BeTrue())

		compat_otp.By("7. Create a new namespace. \n")
		oc.SetupProject()
		ns2 := oc.Namespace()

		compat_otp.By("8. create hello pod in ns2 \n")

		pod2 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns2,
			nodename:  nodeList.Items[0].Name,
			template:  pingPodNodeTemplate,
		}
		pod2.createPingPodNode(oc)
		waitPodReady(oc, ns2, pod2.name)

		compat_otp.By("9. Generate egress traffic in ns2. \n")
		_, err = e2eoutput.RunHostCmd(pod2.namespace, pod2.name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("10. Verify no acl logs for egressfirewall generated in ns2. \n")
		egressFwRegexNs2 := fmt.Sprintf("egressFirewall_%s_.*", ns2)
		o.Consistently(func() int {
			aclLogs2, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			r2 := regexp.MustCompile(egressFwRegexNs2)
			matches2 := r2.FindAllString(aclLogs2, -1)
			return len(matches2)
		}, 10*time.Second, 5*time.Second).Should(o.Equal(0))

		compat_otp.By("11. Create an EgressFirewall in ns2 \n")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns2,
			ruletype:  "Deny",
			cidr:      "0.0.0.0/0",
			template:  egressFWTemplate,
		}
		egressFW2.createEgressFW2Object(oc)
		defer egressFW2.deleteEgressFW2Object(oc)
		if ipStackType == "dualstack" {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns2, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"::/0\"}}]}}", "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		}
		err = waitEgressFirewallApplied(oc, egressFW2.name, ns2)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("12. Generate egress traffic which will hit the egressfirewall in ns2. \n")
		_, err = e2eoutput.RunHostCmd(pod2.namespace, pod2.name, "curl -s www.redhat.com --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())

		compat_otp.By("13. Verify no acl logs for egressfirewall generated in ns2. \n")
		o.Consistently(func() int {
			aclLogs2, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", nodeList.Items[0].Name, aclLogPath).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			r2 := regexp.MustCompile(egressFwRegexNs2)
			matches2 := r2.FindAllString(aclLogs2, -1)
			return len(matches2)
		}, 10*time.Second, 5*time.Second).Should(o.Equal(0))
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-ConnectedOnly-High-55345-[FdpOvnOvs] Drop ACL for EgressFirewall should have priority lower than allow ACL despite being last in the chain.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			pingPodNodeTemplate = filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
			egressFWTemplate2   = filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")
			egressFWTemplate1   = filepath.Join(buildPruningBaseDir, "egressfirewall1-template.yaml")
		)

		compat_otp.By("Obtain the namespace \n")
		ns1 := oc.Namespace()

		compat_otp.By("create hello pod in ns1 \n")
		pod1 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns1,
			template:  pingPodNodeTemplate,
		}
		pod1.createPingPodNode(oc)
		waitPodReady(oc, ns1, pod1.name)

		compat_otp.By("Create an EgressFirewall \n")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns1,
			ruletype:  "Deny",
			cidr:      "0.0.0.0/0",
			template:  egressFWTemplate2,
		}
		egressFW2.createEgressFW2Object(oc)
		efErr := waitEgressFirewallApplied(oc, egressFW2.name, ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Apply another EgressFirewall with allow rules under same namespace \n")
		egressFW := egressFirewall1{
			name:      "default",
			namespace: ns1,
			template:  egressFWTemplate1,
		}
		egressFW.createEgressFWObject1(oc)
		errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns1, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Allow\",\"to\":{\"dnsName\":\"www.test.com\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}]}}", "--type=merge").Execute()
		o.Expect(errPatch).NotTo(o.HaveOccurred())
		efErr = waitEgressFirewallApplied(oc, egressFW.name, ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Check the result, default deny rules should have lower priority than allow rules\n")
		ovnACLCmd := fmt.Sprintf("ovn-nbctl --format=table --no-heading  --columns=action,priority,match find acl external_ids:k8s.ovn.org/name=%s", ns1)
		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, ovnACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())

		strLines := strings.Split(listOutput, "\n")
		o.Expect(len(strLines) >= 2).Should(o.BeTrue(), fmt.Sprintf("The output of acl list is not as expected,\n%s", listOutput))
		var allowRules []int
		var denyRule int
		for _, line := range strLines {
			slice := strings.Fields(line)
			if strings.Contains(line, "allow") {
				priority := slice[1]
				intVar, _ := strconv.Atoi(priority)
				allowRules = append(allowRules, intVar)
			}
			if strings.Contains(line, "drop") {
				priority := slice[1]
				denyRule, _ = strconv.Atoi(priority)
			}
		}
		for _, allow := range allowRules {
			o.Expect(allow > denyRule).Should(o.BeTrue(), fmt.Sprintf("The allow rule priority is %v, the deny rule priority is %v.", allow, denyRule))
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-ConnectedOnly-High-59709-[FdpOvnOvs] [NETWORKCUSIM] No duplicate egressfirewall rules in the OVN Northbound database after restart OVN master pod. [Disruptive]", func() {
		//This is from bug https://issues.redhat.com/browse/OCPBUGS-811
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressFWTemplate1   = filepath.Join(buildPruningBaseDir, "egressfirewall1-template.yaml")
		)

		compat_otp.By("Obtain the namespace \n")
		ns1 := oc.Namespace()

		compat_otp.By("Create egressfirewall rules under same namespace \n")
		egressFW := egressFirewall1{
			name:      "default",
			namespace: ns1,
			template:  egressFWTemplate1,
		}
		egressFW.createEgressFWObject1(oc)
		defer func() {
			if os.Getenv("DELETE_NAMESPACE") != "false" {
				egressFW.deleteEgressFWObject1(oc)
			}
		}()
		efErr := waitEgressFirewallApplied(oc, egressFW.name, ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Get the base number of egressfirewall rules\n")
		ovnACLCmd := fmt.Sprintf("ovn-nbctl --format=table --no-heading  --columns=action,priority,match find acl external_ids:k8s.ovn.org/name=%s", ns1)
		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, ovnACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		e2e.Logf("The egressfirewall rules before restart ovn master pod: \n %s", listOutput)
		baseCount := len(strings.Split(listOutput, "\n"))

		compat_otp.By("Restart cluster-manager's ovnkube-node pod\n")
		err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", ovnMasterPodName, "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		compat_otp.By("Check the result, the number of egressfirewal rules should be same as before.")
		ovnMasterPodName = getOVNKMasterOVNkubeNode(oc)
		listOutput, listErr = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, ovnACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		e2e.Logf("The egressfirewall rules after restart ovn master pod: \n %s", listOutput)
		resultCount := len(strings.Split(listOutput, "\n"))
		o.Expect(resultCount).Should(o.Equal(baseCount))
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:huirwang-High-43464-EgressFirewall works with IPv6 address.", func() {
		// Note: this case focuses on Egressfirewall working with IPv6 address, as ipv6 single cluster with proxy where egressfirewall cannot work, so only test it on dual stack.
		// Currently only on the UPI packet dualstack cluster, the pod can access public website with IPv6 address.
		ipStackType := checkIPStackType(oc)
		if ipStackType != "dualstack" || !checkIPv6PublicAccess(oc) {
			g.Skip("This case should be run on UPI packet dualstack cluster, skip other platform or network stack type.")
		}

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")

		compat_otp.By("create new namespace")
		oc.SetupProject()
		ns := oc.Namespace()

		compat_otp.By("Create an EgressFirewall object with rule deny.")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Deny",
			cidr:      "::/0",
			template:  egressFWTemplate,
		}
		egressFW2.createEgressFW2Object(oc)
		defer egressFW2.deleteEgressFW2Object(oc)
		errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"::/0\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}]}}", "--type=merge").Execute()
		o.Expect(errPatch).NotTo(o.HaveOccurred())
		efErr := waitEgressFirewallApplied(oc, egressFW2.name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)
		defer pod1.deletePingPod(oc)

		compat_otp.By("Check both ipv6 and ipv4 are blocked")
		_, err := e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -6 www.google.com --connect-timeout 5 -I")
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -4 www.google.com --connect-timeout 5 -I")
		o.Expect(err).To(o.HaveOccurred())

		compat_otp.By("Remove egressfirewall object")
		egressFW2.deleteEgressFW2Object(oc)

		compat_otp.By("Create an EgressFirewall object with rule allow.")
		egressFW2 = egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Allow",
			cidr:      "::/0",
			template:  egressFWTemplate,
		}
		egressFW2.createEgressFW2Object(oc)
		errPatch = oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Allow\",\"to\":{\"cidrSelector\":\"::/0\"}},{\"type\":\"Allow\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}]}}", "--type=merge").Execute()
		o.Expect(errPatch).NotTo(o.HaveOccurred())
		efErr = waitEgressFirewallApplied(oc, egressFW2.name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Check both ipv4 and ipv6 destination can be accessed")
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -6 www.google.com --connect-timeout 5 -I")
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -4 www.google.com --connect-timeout 5 -I")
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	// author: jechen@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:jechen-High-44940-No segmentation error in ovnkube-control-plane or syntax error in ovn-controller after egressfirewall resource that referencing a DNS name is deleted.", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall1-template.yaml")

		compat_otp.By("1. Create a new namespace, create an EgressFirewall object with references a DNS name in the namespace.")
		ns := oc.Namespace()

		egressFW1 := egressFirewall1{
			name:      "default",
			namespace: ns,
			template:  egressFWTemplate,
		}

		defer egressFW1.deleteEgressFWObject1(oc)
		egressFW1.createEgressFWObject1(oc)
		efErr := waitEgressFirewallApplied(oc, egressFW1.name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("2. Delete the EgressFirewall, check logs of ovnkube-control-plane pod for error, there should be no segementation error, no DNS value not found in dnsMap error message.")
		removeResource(oc, true, true, "egressfirewall", egressFW1.name, "-n", egressFW1.namespace)

		leaderCtrlPlanePod := getOVNKMasterPod(oc)
		o.Expect(leaderCtrlPlanePod).ShouldNot(o.BeEmpty())
		e2e.Logf("\n leaderCtrlPlanePod: %v\n", leaderCtrlPlanePod)

		o.Consistently(func() bool {
			podlogs, _ := oc.AsAdmin().Run("logs").Args(leaderCtrlPlanePod, "-n", "openshift-ovn-kubernetes", "-c", "ovnkube-cluster-manager").Output()
			return strings.Count(podlogs, `SIGSEGV: segmentation violation`) == 0 && strings.Count(podlogs, `DNS value not found in dnsMap for domain`) == 0
		}, 60*time.Second, 10*time.Second).Should(o.BeTrue(), "Segementation error or no DNS value in dnsMap error message found in ovnkube-control-plane pod log!!")
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:huirwang-High-37778-EgressFirewall can be deleted after the project deleted.", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressFWTemplate1   = filepath.Join(buildPruningBaseDir, "egressfirewall1-template.yaml")
		)

		compat_otp.By("Obtain the namespace \n")
		oc.SetupProject()
		ns1 := oc.Namespace()

		compat_otp.By("Create egressfirewall rules under same namespace \n")
		egressFW := egressFirewall1{
			name:      "default",
			namespace: ns1,
			template:  egressFWTemplate1,
		}
		egressFW.createEgressFWObject1(oc)
		defer egressFW.deleteEgressFWObject1(oc)
		compat_otp.AssertWaitPollNoErr(waitEgressFirewallApplied(oc, egressFW.name, ns1), fmt.Sprintf("Wait for the  egressFW/%s applied successfully timeout", egressFW.name))

		compat_otp.By("Delete namespace .\n")
		errNs := oc.WithoutNamespace().AsAdmin().Run("delete").Args("ns", ns1).Execute()
		o.Expect(errNs).NotTo(o.HaveOccurred())

		compat_otp.By("Verify no egressfirewall object  ")
		outPut, errFW := oc.AsAdmin().Run("get").Args("egressfirewall", egressFW.name, "-n", ns1).Output()
		o.Expect(errFW).To(o.HaveOccurred())
		o.Expect(outPut).NotTo(o.ContainSubstring(egressFW.name))

		compat_otp.By("Check ovn db, corresponding egressfirewall acls were deleted.")
		ovnACLCmd := fmt.Sprintf("ovn-nbctl --format=table --no-heading  --columns=action,priority,match find acl external_ids:k8s.ovn.org/name=%s", ns1)
		ovnMasterPodName := getOVNKMasterOVNkubeNode(oc)
		listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterPodName, ovnACLCmd)
		o.Expect(listErr).NotTo(o.HaveOccurred())
		e2e.Logf("The egressfirewall rules after project deleted: \n %s", listOutput)
		o.Expect(listOutput).NotTo(o.ContainSubstring("allow"))
		o.Expect(listOutput).NotTo(o.ContainSubstring("drop "))
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-High-60488-EgressFirewall works for a nodeSelector for matchLabels.", func() {
		compat_otp.By("Label one node to match egressfirewall rule")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough worker nodes for this test, skip the case!!")
		}

		ipStackType := checkIPStackType(oc)

		node1 := nodeList.Items[0].Name
		node2 := nodeList.Items[1].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, node1, "ef-dep")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, node1, "ef-dep", "qe")

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall3-template.yaml")

		compat_otp.By("Get new namespace")
		ns := oc.Namespace()

		var cidrValue string
		if ipStackType == "ipv6single" {
			cidrValue = "::/0"
		} else {
			cidrValue = "0.0.0.0/0"
		}

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Check the nodes can be acccessed or not")
		// Will skip the test if the nodes IP cannot be pinged even without egressfirewall
		node1IP1, node1IP2 := getNodeIP(oc, node1)
		node2IP1, node2IP2 := getNodeIP(oc, node2)
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node1IP2)
		if err != nil {
			g.Skip("Ping node IP failed, skip the test in this environment.")
		}
		if node1IP1 != "" {
			_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node1IP1)
			if err != nil {
				g.Skip("Ping node IP failed, skip the test in this environment.")
			}

		}

		compat_otp.By("Create an EgressFirewall object with rule nodeSelector.")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Deny",
			cidr:      cidrValue,
			template:  egressFWTemplate,
		}
		defer egressFW2.deleteEgressFW2Object(oc)
		egressFW2.createEgressFW2Object(oc)

		compat_otp.By("Verify the node matched egressfirewall will be allowed.")
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node1IP2)
			return err
		}, "60s", "10s").ShouldNot(o.HaveOccurred())
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node2IP2)
			return err
		}, "10s", "5s").Should(o.HaveOccurred())

		if ipStackType == "dualstack" {
			// Test node ipv6 address as well
			egressFW2.deleteEgressFW2Object(oc)
			egressFW2.cidr = "::/0"
			defer egressFW2.deleteEgressFW2Object(oc)
			egressFW2.createEgressFW2Object(oc)
			o.Eventually(func() error {
				_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node1IP1)
				return err
			}, "60s", "10s").ShouldNot(o.HaveOccurred())
			o.Eventually(func() error {
				_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node2IP1)
				return err
			}, "10s", "5s").Should(o.HaveOccurred())
		}
	})

	// author: huirwang@redhat.com
	g.It("ConnectedOnly-Author:huirwang-High-60812-EgressFirewall works for a nodeSelector for matchExpressions.", func() {
		compat_otp.By("Label one node to match egressfirewall rule")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough worker nodes for this test, skip the case!!")
		}

		ipStackType := checkIPStackType(oc)

		node1 := nodeList.Items[0].Name
		node2 := nodeList.Items[1].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, node1, "ef-org")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, node1, "ef-org", "dev")

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall4-template.yaml")

		compat_otp.By("Get new namespace")
		ns := oc.Namespace()

		var cidrValue string
		if ipStackType == "ipv6single" {
			cidrValue = "::/0"
		} else {
			cidrValue = "0.0.0.0/0"
		}

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Check the nodes can be acccessed or not")
		// Will skip the test if the nodes IP cannot be pinged even without egressfirewall
		node1IP1, node1IP2 := getNodeIP(oc, node1)
		node2IP1, node2IP2 := getNodeIP(oc, node2)
		_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node1IP2)
		if err != nil {
			g.Skip("Ping node IP failed, skip the test in this environment.")
		}
		if node1IP1 != "" {
			_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node1IP1)
			if err != nil {
				g.Skip("Ping node IP failed, skip the test in this environment.")
			}
		}

		compat_otp.By("Create an EgressFirewall object with rule nodeSelector.")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Deny",
			cidr:      cidrValue,
			template:  egressFWTemplate,
		}
		defer egressFW2.deleteEgressFW2Object(oc)
		egressFW2.createEgressFW2Object(oc)

		compat_otp.By("Verify the node matched egressfirewall will be allowed, unmatched will be blocked!!")
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node1IP2)
			return err
		}, "60s", "10s").ShouldNot(o.HaveOccurred())
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node2IP2)
			return err
		}, "10s", "5s").Should(o.HaveOccurred())

		if ipStackType == "dualstack" {
			// Test node ipv6 address as well
			egressFW2.deleteEgressFW2Object(oc)
			egressFW2.cidr = "::/0"
			defer egressFW2.deleteEgressFW2Object(oc)
			egressFW2.createEgressFW2Object(oc)
			o.Eventually(func() error {
				_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node1IP1)
				return err
			}, "60s", "10s").ShouldNot(o.HaveOccurred())
			o.Eventually(func() error {
				_, err = e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "ping -c 2 "+node2IP1)
				return err
			}, "10s", "5s").Should(o.HaveOccurred())

		}
	})

	g.It("NonHyperShiftHOST-NonPreRelease-Longduration-Author:huirwang-High-61213-Delete IGMP Groups when deleting stale chassis.[Disruptive]", func() {
		// This is from bug https://issues.redhat.com/browse/OCPBUGS-7230
		platform := compat_otp.CheckPlatform(oc)
		if strings.Contains(platform, "baremetal") || strings.Contains(platform, "none") {
			g.Skip("Skip for non-supported auto scaling machineset platforms!!")
		}
		clusterinfra.SkipConditionally(oc)
		compat_otp.By("Create a new machineset with 2 nodes")
		infrastructureName := clusterinfra.GetInfrastructureName(oc)
		machinesetName := infrastructureName + "-61213"
		ms := clusterinfra.MachineSetDescription{Name: machinesetName, Replicas: 2}
		defer clusterinfra.WaitForMachinesDisapper(oc, machinesetName)
		defer ms.DeleteMachineSet(oc)
		ms.CreateMachineSet(oc)
		clusterinfra.WaitForMachinesRunning(oc, 2, machinesetName)
		machineName := clusterinfra.GetMachineNamesFromMachineSet(oc, machinesetName)
		nodeName0 := clusterinfra.GetNodeNameFromMachine(oc, machineName[0])
		nodeName1 := clusterinfra.GetNodeNameFromMachine(oc, machineName[1])

		compat_otp.By("Obtain the namespace \n")
		ns := oc.Namespace()

		compat_otp.By("Enable multicast on namespace  \n")
		enableMulticast(oc, ns)

		compat_otp.By("Delete ovnkuber-master pods and two nodes \n")
		err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("pods", "-l", "app=ovnkube-control-plane", "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-control-plane")
		err = ms.DeleteMachineSet(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		clusterinfra.WaitForMachinesDisapper(oc, machinesetName)

		compat_otp.By("Wait ovnkuber-control-plane pods ready\n")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-control-plane")
		compat_otp.AssertWaitPollNoErr(err, "ovnkube-control-plane pods are not ready")

		compat_otp.By("Check ovn db, the stale chassis for deleted node should be deleted")
		for _, machine := range []string{nodeName0, nodeName1} {
			ovnACLCmd := fmt.Sprintf("ovn-sbctl --columns _uuid,hostname list chassis")
			ovnMasterSourthDBLeaderPod := getOVNKMasterOVNkubeNode(oc)
			o.Eventually(func() string {
				outPut, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnMasterSourthDBLeaderPod, ovnACLCmd)
				o.Expect(listErr).NotTo(o.HaveOccurred())
				return outPut
			}, "120s", "10s").ShouldNot(o.ContainSubstring(machine), "The stale chassis still existed!")
		}

		compat_otp.By("Check ovnkuber control plane logs, no IGMP_Group logs")
		ovnMasterPodName := getOVNKMasterPod(oc)
		searchString := "Transaction causes multiple rows in \"IGMP_Group\" table to have identical values"
		logContents, logErr := compat_otp.GetSpecificPodLogs(oc, "openshift-ovn-kubernetes", "ovnkube-cluster-manager", ovnMasterPodName, "")
		o.Expect(logErr).ShouldNot(o.HaveOccurred())
		o.Expect(strings.Contains(logContents, searchString)).Should(o.BeFalse())
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-NonPreRelease-PreChkUpgrade-Author:huirwang-High-62056-Check egressfirewall is functional post upgrade", func() {
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			statefulSetHelloPod = filepath.Join(buildPruningBaseDir, "statefulset-hello.yaml")
			egressFWTemplate    = filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")
			ns                  = "62056-upgrade-ns"
			allowedIPList       = []string{}
			ipv6CIDR            string
			ipv4CIDR            string
		)

		compat_otp.By("1. create new namespace")
		err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2. Get an IP address for domain name www.redhat.com for allow rule ")
		allowedIPv4, allowedIPv6 := getIPFromDnsName("www.redhat.com")
		o.Expect(len(allowedIPv4) == 0).NotTo(o.BeTrue())
		ipv4CIDR = allowedIPv4 + "/32"
		allowedIPList = append(allowedIPList, allowedIPv4)
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			if checkIPv6PublicAccess(oc) {
				o.Expect(len(allowedIPv6) == 0).NotTo(o.BeTrue())
				ipv6CIDR = allowedIPv6 + "/128"
				allowedIPList = append(allowedIPList, allowedIPv6)
			} else {
				e2e.Logf("Dual stack cluster does not have access to public websites for IPv6 address.")
			}

		}

		compat_otp.By("3. Create an EgressFirewall object with rule deny.")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Deny",
			cidr:      "0.0.0.0/0",
			template:  egressFWTemplate,
		}
		egressFW2.createEgressFW2Object(oc)

		compat_otp.By("4. Update EgressFirewall object with rule specific allow rule.")
		if ipStackType == "dualstack" && checkIPv6PublicAccess(oc) {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Allow\",\"to\":{\"cidrSelector\":\""+ipv4CIDR+"\"}},{\"type\":\"Allow\",\"to\":{\"cidrSelector\":\""+ipv6CIDR+"\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"::/0\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}]}}", "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		} else {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Allow\",\"to\":{\"cidrSelector\":\""+ipv4CIDR+"\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}]}}", "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		}
		efErr := waitEgressFirewallApplied(oc, egressFW2.name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("5. Create a pod in the namespace")
		createResourceFromFile(oc, ns, statefulSetHelloPod)
		podErr := waitForPodWithLabelReady(oc, ns, "app=hello")
		compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
		helloPodname := getPodName(oc, ns, "app=hello")[0]

		compat_otp.By("6. Check the allowed destination can be accessed!")
		for i := 0; i < len(allowedIPList); i++ {
			compat_otp.By(fmt.Sprintf("Verify %s is accessible with just egress firewall", allowedIPList[i]))
			verifyDstIPAccess(helloPodname, ns, allowedIPList[i], true)
		}
		compat_otp.By("7.Check the other website can be blocked!")
		_, err = e2eoutput.RunHostCmd(ns, helloPodname, "curl yahoo.com --connect-timeout 5 -I")
		o.Expect(err).To(o.HaveOccurred())
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-NonPreRelease-PstChkUpgrade-Author:huirwang-High-62056-Check egressfirewall is functional post upgrade", func() {
		ns := "62056-upgrade-ns"
		nsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", ns).Execute()
		if nsErr != nil {
			g.Skip("Skip the PstChkUpgrade test as 62056-upgrade-ns namespace does not exist, PreChkUpgrade test did not run")
		}

		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", ns, "--ignore-not-found=true").Execute()

		compat_otp.By("Verify if EgressFirewall was applied correctly")
		efErr := waitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Get allow IP list ")
		cidrList, cidrErr := oc.AsAdmin().Run("get").Args("-n", ns, "egressfirewall.k8s.ovn.org/default", "-o=jsonpath={.spec.egress[?(@.type==\"Allow\")].to.cidrSelector}").Output()
		o.Expect(cidrErr).NotTo(o.HaveOccurred())
		o.Expect(cidrList == "").NotTo(o.BeTrue())
		e2e.Logf("The allowed destination IPs are: %s", cidrList)
		// Regular expression to match IPv4 and IPv6 addresses with CIDR notation
		ipRegex := `(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}|[0-9a-fA-F:]+(?::[0-9a-fA-F]{1,4}){1,7}\/\d{1,3}`
		re := regexp.MustCompile(ipRegex)
		matches := re.FindAllString(cidrList, -1)
		var allowedIPList []string
		for _, match := range matches {
			// Split the match on the '/' character and take only the IP part
			ip := strings.Split(match, "/")[0]
			allowedIPList = append(allowedIPList, ip)
		}

		compat_otp.By("Get the pod in the namespace")
		podErr := waitForPodWithLabelReady(oc, ns, "app=hello")
		compat_otp.AssertWaitPollNoErr(podErr, "The statefulSet pod is not ready")
		helloPodname := getPodName(oc, ns, "app=hello")[0]

		compat_otp.By("Check the allowed destination can be accessed!")
		for i := 0; i < len(allowedIPList); i++ {
			compat_otp.By(fmt.Sprintf("Verify %s is accessible with just egress firewall", allowedIPList[i]))
			verifyDstIPAccess(helloPodname, ns, allowedIPList[i], true)
		}
		compat_otp.By("Check the other website can be blocked!")
		_, err := e2eoutput.RunHostCmd(ns, helloPodname, "curl yahoo.com --connect-timeout 5 -I")
		o.Expect(err).To(o.HaveOccurred())
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-61176-High-61177-79704-Medium-[FdpOvnOvs] EgressFirewall with dnsName in uppercase can be created, and EgressFirewall should work with namespace that is longer than forth-three characters even after restart. [Disruptive]", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		ns := "test-egressfirewall-with-a-very-long-namespace-61176-61177"

		compat_otp.By("1. Create a long namespace over 43 characters, create an EgressFirewall object with mixed of Allow and Deny rules.")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", ns, "--ignore-not-found=true").Execute()
		nsErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", ns).Execute()
		o.Expect(nsErr).NotTo(o.HaveOccurred())
		compat_otp.SetNamespacePrivileged(oc, ns)

		egressFW5 := egressFirewall5{
			name:        "default",
			namespace:   ns,
			ruletype1:   "Allow",
			rulename1:   "dnsName",
			rulevalue1:  "WWW.GOOGLE.COM",
			protocol1:   "TCP",
			portnumber1: 443,
			ruletype2:   "Deny",
			rulename2:   "dnsName",
			rulevalue2:  "www.facebook.com",
			protocol2:   "TCP",
			portnumber2: 443,
			template:    egressFWTemplate,
		}

		defer removeResource(oc, true, true, "egressfirewall", egressFW5.name, "-n", egressFW5.namespace)
		egressFW5.createEgressFW5Object(oc)
		efErr := waitEgressFirewallApplied(oc, egressFW5.name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n egressfirewall is applied\n")

		compat_otp.By("2. Create a test pod in the namespace")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc.AsAdmin())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1.name, "-n", pod1.namespace).Execute()
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("3. Check www.facebook.com is blocked \n")
		o.Eventually(func() bool {
			_, stderr, _ := e2eoutput.RunHostCmdWithFullOutput(pod1.namespace, pod1.name, "curl -I -k https://www.facebook.com --connect-timeout 5")
			return stderr != ""
		}, "120s", "10s").Should(o.BeTrue(), "Deny rule did not work as expected!!")

		compat_otp.By("4. Check www.google.com is allowed \n")
		o.Eventually(func() bool {
			_, err := e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -I -k https://www.google.com --connect-timeout 5")
			return err == nil
		}, "120s", "10s").Should(o.BeTrue(), "Allow rule did not work as expected!!")

		testPodNodeName, _ := compat_otp.GetPodNodeName(oc, pod1.namespace, pod1.name)
		o.Expect(testPodNodeName != "").Should(o.BeTrue())
		e2e.Logf("node name for the test pod is: %v", testPodNodeName)

		compat_otp.By("5. Check ACLs in northdb. \n")
		masterOVNKubeNodePod := getOVNKMasterOVNkubeNode(oc)
		o.Expect(masterOVNKubeNodePod != "").Should(o.BeTrue())
		aclCmd := "ovn-nbctl --no-leader-only find acl|grep external_ids|grep test-egressfirewall-with-a-very-long-namespace ||true"
		checkAclErr := wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			aclOutput, aclErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", masterOVNKubeNodePod, aclCmd)
			if aclErr != nil {
				e2e.Logf("%v,Waiting for ACLs to be synced, try next ...,", aclErr)
				return false, nil
			}
			// check ACLs rules for the long namespace
			if strings.Contains(aclOutput, "test-egressfirewall-with-a-very-long-namespace") && strings.Count(aclOutput, "test-egressfirewall-with-a-very-long-namespace") == 4 {
				e2e.Logf("The ACLs for egressfirewall in northbd are as expected!")
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(checkAclErr, "ACLs were not synced correctly!")

		compat_otp.By("6. Restart OVNK nodes\n")
		defer waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		delPodErr := oc.AsAdmin().Run("delete").Args("pod", "-l", "app=ovnkube-node", "-n", "openshift-ovn-kubernetes").Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())

		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		compat_otp.By("7. Check ACL again in northdb after restart. \n")
		// since ovnkube-node pods are re-created during restart, obtain ovnMasterOVNkubeNodePod again
		masterOVNKubeNodePod = getOVNKMasterOVNkubeNode(oc)
		o.Expect(masterOVNKubeNodePod != "").Should(o.BeTrue())
		checkAclErr = wait.Poll(10*time.Second, 100*time.Second, func() (bool, error) {
			aclOutput, aclErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", masterOVNKubeNodePod, aclCmd)
			if aclErr != nil {
				e2e.Logf("%v,Waiting for ACLs to be synced, try next ...,", aclErr)
				return false, nil
			}
			// check ACLs rules for the long namespace after restart
			if strings.Contains(aclOutput, "test-egressfirewall-with-a-very-long-namespace") && strings.Count(aclOutput, "test-egressfirewall-with-a-very-long-namespace") == 4 {
				e2e.Logf("The ACLs for egressfirewall in northbd are as expected!")
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(checkAclErr, "ACLs were not synced correctly!")

		compat_otp.By("8. Check egressfirewall rules still work correctly after restart \n")
		o.Eventually(func() bool {
			_, stderr, _ := e2eoutput.RunHostCmdWithFullOutput(pod1.namespace, pod1.name, "curl -I -k https://www.facebook.com --connect-timeout 5")
			return stderr != ""
		}, "120s", "10s").Should(o.BeTrue(), "Deny rule did not work correctly after restart!!")

		o.Eventually(func() bool {
			_, err := e2eoutput.RunHostCmd(pod1.namespace, pod1.name, "curl -I -k https://www.google.com --connect-timeout 5")
			return err == nil
		}, "120s", "10s").Should(o.BeTrue(), "Allow rule did not work correctly after restart!!")
	})

	// author: jechen@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:jechen-High-37774-Set EgressFirewall to limit the pod connection to specific CIDR ranges in different namespaces.", func() {

		buildPruningBaseDir := testdata.FixturePath("networking")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall5-template.yaml")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		url1 := "www.yahoo.com"    // used as Deny rule for first namespace
		url2 := "www.ericsson.com" // used as Deny rule for second namespace
		url3 := "www.google.com"   // is not used as Deny rule in either namespace

		compat_otp.By("1. nslookup obtain dns server ip for url1 and url2\n")
		ips1, err := net.LookupIP(url1)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ip address from nslookup for %v: %v", url1, ips1)

		ips2, err := net.LookupIP(url2)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ip address from lookup for %v: %v", url2, ips2)

		ips3, err := net.LookupIP(url3)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("ip address from lookup for %v: %v", url3, ips3)

		ipStackType := checkIPStackType(oc)
		e2e.Logf("\n ipStackType: %v\n", ipStackType)

		// get all IPv4 and IPv6 addresses of 3 hosts above
		var ipv4Addr1, ipv6Addr1, ipv4Addr2, ipv6Addr2, ipv4Addr3, ipv6Addr3 []string
		for j := 0; j <= len(ips1)-1; j++ {
			if IsIPv4(ips1[j].String()) {
				ipv4Addr1 = append(ipv4Addr1, ips1[j].String())
			}
			if IsIPv6(ips1[j].String()) {
				ipv6Addr1 = append(ipv6Addr1, ips1[j].String())
			}
		}

		for j := 0; j <= len(ips2)-1; j++ {
			if IsIPv4(ips2[j].String()) {
				ipv4Addr2 = append(ipv4Addr2, ips2[j].String())
			}
			if IsIPv6(ips2[j].String()) {
				ipv6Addr2 = append(ipv6Addr2, ips2[j].String())
			}
		}

		for j := 0; j <= len(ips3)-1; j++ {
			if IsIPv4(ips3[j].String()) {
				ipv4Addr3 = append(ipv4Addr3, ips3[j].String())
			}
			if IsIPv6(ips3[j].String()) {
				ipv6Addr3 = append(ipv6Addr3, ips3[j].String())
			}
		}

		e2e.Logf("ipv4Address1: %v, ipv6Address1: %v\n\n", ipv4Addr1, ipv6Addr1)
		e2e.Logf("ipv4Address2: %v, ipv6Address2: %v\n\n", ipv4Addr2, ipv6Addr2)
		e2e.Logf("ipv4Address3: %v, ipv6Address3: %v\n\n", ipv4Addr3, ipv6Addr3)

		//Store IPv4 addresses of the 3 hosts above in ip1, ip2, ip3
		//Store IPv6 addresses of the 3 hosts above in ip4, ip5, ip6
		var cidrValue1, cidrValue2, cidrValue3, cidrValue4, ip1, ip2, ip3, ip4, ip5, ip6 string
		if ipStackType == "ipv6single" {
			if len(ipv6Addr1) < 2 || len(ipv6Addr2) < 2 || len(ipv6Addr3) < 2 {
				g.Skip("Not enough IPv6 address for the hosts that are used in this test with v6 single cluster, need two IPv6 addresses from each host, skip the test.")
			}
			ip1 = ipv6Addr1[0]
			ip2 = ipv6Addr2[0]
			ip3 = ipv6Addr3[0]
			cidrValue1 = ip1 + "/128"
			cidrValue2 = ip2 + "/128"

			ip4 = ipv6Addr1[1]
			ip5 = ipv6Addr2[1]
			ip6 = ipv6Addr3[1]
			cidrValue3 = ip4 + "/128"
			cidrValue4 = ip5 + "/128"
		} else if ipStackType == "ipv4single" {
			if len(ipv4Addr1) < 2 || len(ipv4Addr2) < 2 || len(ipv4Addr3) < 2 {
				g.Skip("Not enough IPv4 address for the hosts that are used in this test with V4 single cluster, need two IPv4 addresses from each host, skip the test.")
			}
			ip1 = ipv4Addr1[0]
			ip2 = ipv4Addr2[0]
			ip3 = ipv4Addr3[0]
			cidrValue1 = ip1 + "/32"
			cidrValue2 = ip2 + "/32"

			ip4 = ipv4Addr1[1]
			ip5 = ipv4Addr2[1]
			ip6 = ipv4Addr3[1]
			cidrValue3 = ip4 + "/32"
			cidrValue4 = ip5 + "/32"
		} else if ipStackType == "dualstack" {
			if len(ipv4Addr1) < 1 || len(ipv4Addr2) < 1 || len(ipv4Addr3) < 1 || len(ipv6Addr1) < 1 || len(ipv6Addr2) < 1 || len(ipv6Addr3) < 1 {
				g.Skip("Not enough IPv4 or IPv6 address for the hosts that are used in this test with dualstack cluster, need at least one IPv4 and one IPv6 address from each host, skip the test.")
			}
			ip1 = ipv4Addr1[0]
			ip2 = ipv4Addr2[0]
			ip3 = ipv4Addr3[0]
			cidrValue1 = ip1 + "/32"
			cidrValue2 = ip2 + "/32"

			ip4 = ipv6Addr1[0]
			ip5 = ipv6Addr2[0]
			ip6 = ipv6Addr3[0]
			cidrValue3 = ip4 + "/128"
			cidrValue4 = ip5 + "/128"
		}
		e2e.Logf("\n cidrValue1: %v,  cidrValue2: %v\n", cidrValue1, cidrValue2)
		e2e.Logf("\n IP1: %v,  IP2: %v, IP3: %v\n", ip1, ip2, ip3)
		e2e.Logf("\n cidrValue3: %v,  cidrValue4: %v\n", cidrValue3, cidrValue4)
		e2e.Logf("\n IP4: %v,  IP5: %v, IP6: %v\n", ip4, ip5, ip6)

		compat_otp.By("2. Obtain first namespace, create egressfirewall1 in it\n")
		ns1 := oc.Namespace()

		egressFW1 := egressFirewall5{
			name:        "default",
			namespace:   ns1,
			ruletype1:   "Deny",
			rulename1:   "cidrSelector",
			rulevalue1:  cidrValue1,
			protocol1:   "TCP",
			portnumber1: 443,
			ruletype2:   "Allow",
			rulename2:   "dnsName",
			rulevalue2:  "www.redhat.com",
			protocol2:   "TCP",
			portnumber2: 443,
			template:    egressFWTemplate,
		}

		defer removeResource(oc, true, true, "egressfirewall", egressFW1.name, "-n", egressFW1.namespace)
		egressFW1.createEgressFW5Object(oc)
		efErr := waitEgressFirewallApplied(oc, egressFW1.name, ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n egressfirewall is applied\n")

		compat_otp.By("3. Create a test pod in first namespace")
		pod1ns1 := pingPodResource{
			name:      "hello-pod1",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1ns1.createPingPod(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod1ns1.name, "-n", pod1ns1.namespace).Execute()
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		compat_otp.By("4. Create a second namespace, and create egressfirewall2 in it\n")
		oc.SetupProject()
		ns2 := oc.Namespace()

		egressFW2 := egressFirewall5{
			name:        "default",
			namespace:   ns2,
			ruletype1:   "Deny",
			rulename1:   "cidrSelector",
			rulevalue1:  cidrValue2,
			protocol1:   "TCP",
			portnumber1: 443,
			ruletype2:   "Deny",
			rulename2:   "dnsName",
			rulevalue2:  "www.redhat.com",
			protocol2:   "TCP",
			portnumber2: 443,
			template:    egressFWTemplate,
		}

		defer removeResource(oc, true, true, "egressfirewall", egressFW2.name, "-n", egressFW2.namespace)
		egressFW2.createEgressFW5Object(oc)
		efErr = waitEgressFirewallApplied(oc, egressFW2.name, ns2)
		o.Expect(efErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n egressfirewall is applied\n")

		compat_otp.By("5. Create a test pod in second namespace")
		pod2ns2 := pingPodResource{
			name:      "hello-pod2",
			namespace: ns2,
			template:  pingPodTemplate,
		}
		pod2ns2.createPingPod(oc)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", pod2ns2.name, "-n", pod2ns2.namespace).Execute()
		waitPodReady(oc, pod2ns2.namespace, pod2ns2.name)

		// for v4 single, test v4 CIDR first, then test it be replaced by another v4 CIDR
		// for V6 single, test v4 CIDR first, then test it be replaced by another v4 CIDR
		// for dualStack, test v4 CIDR first, then test it be replaced by another v6 CIDR
		var curlCmd1, curlCmd2, curlCmd3, newCurlCmd1, newCurlCmd2, newCurlCmd3 string
		if ipStackType == "ipv4single" {
			curlCmd1 = "curl -I -4 -k https://" + url1 + " --resolve " + url1 + ":443:" + ip1 + " --connect-timeout 5"
			curlCmd2 = "curl -I -4 -k https://" + url2 + " --resolve " + url2 + ":443:" + ip2 + " --connect-timeout 5"
			curlCmd3 = "curl -I -4 -k https://" + url3 + " --resolve " + url3 + ":443:" + ip3 + " --connect-timeout 5"

			newCurlCmd1 = "curl -I -4 -k https://" + url1 + " --resolve " + url1 + ":443:" + ip4 + " --connect-timeout 5"
			newCurlCmd2 = "curl -I -4 -k https://" + url2 + " --resolve " + url2 + ":443:" + ip5 + " --connect-timeout 5"
			newCurlCmd3 = "curl -I -4 -k https://" + url3 + " --resolve " + url3 + ":443:" + ip6 + " --connect-timeout 5"
		} else if ipStackType == "ipv6single" {
			curlCmd1 = "curl -I -6 -k https://" + url1 + " --resolve " + url1 + ":443:[" + ip1 + "] --connect-timeout 5"
			curlCmd2 = "curl -I -6 -k https://" + url2 + " --resolve " + url2 + ":443:[" + ip2 + "] --connect-timeout 5"
			curlCmd3 = "curl -I -6 -k https://" + url3 + " --resolve " + url3 + ":443:[" + ip3 + "] --connect-timeout 5"

			newCurlCmd1 = "curl -I -6 -k https://" + url1 + " --resolve " + url1 + ":443:[" + ip4 + "] --connect-timeout 5"
			newCurlCmd2 = "curl -I -6 -k https://" + url2 + " --resolve " + url2 + ":443:[" + ip5 + "] --connect-timeout 5"
			newCurlCmd3 = "curl -I -6 -k https://" + url3 + " --resolve " + url3 + ":443:[" + ip6 + "] --connect-timeout 5"
		} else if ipStackType == "dualstack" { // for dualstack, use v6 CIDR to replace v4 CIDR
			curlCmd1 = "curl -I -4 -k https://" + url1 + " --resolve " + url1 + ":443:" + ip1 + " --connect-timeout 5"
			curlCmd2 = "curl -I -4 -k https://" + url2 + " --resolve " + url2 + ":443:" + ip2 + " --connect-timeout 5"
			curlCmd3 = "curl -I -4 -k https://" + url3 + " --resolve " + url3 + ":443:" + ip3 + " --connect-timeout 5"

			newCurlCmd1 = "curl -I -6 -k https://" + url1 + " --resolve " + url1 + ":443:[" + ip4 + "] --connect-timeout 5"
			newCurlCmd2 = "curl -I -6 -k https://" + url2 + " --resolve " + url2 + ":443:[" + ip5 + "] --connect-timeout 5"
			newCurlCmd3 = "curl -I -6 -k https://" + url3 + " --resolve " + url3 + ":443:[" + ip6 + "] --connect-timeout 5"
		}

		compat_otp.By("\n6.1. Check deny rule of first namespace is blocked from test pod of first namespace because of the deny rule in first namespace\n")
		_, err1 := e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, curlCmd1)
		o.Expect(err1).To(o.HaveOccurred(), "curl the deny rule of first namespace from first namespace failed")

		compat_otp.By("\n6.2. Check deny rule of second namespce is allowed from test pod of first namespace, it is not affected by deny rile in second namespace\n")
		_, err2 := e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, curlCmd2)
		o.Expect(err2).NotTo(o.HaveOccurred(), "curl the deny rule of second namespace from first namespace failed")

		compat_otp.By("\n6.3. Check url3 is allowed from test pod of first namespace, it is not affected by either deny rule of two namespaces\n")
		_, err3 := e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, curlCmd3)
		o.Expect(err3).NotTo(o.HaveOccurred(), "curl url3 from first namesapce failed")

		compat_otp.By("\n7.1. Check deny rule of first namespace is allowed from test pod of second namespace, it is not affected by deny rule in first namespace\n")
		_, err1 = e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, curlCmd1)
		o.Expect(err1).NotTo(o.HaveOccurred(), "curl the deny rule of second namespace from first namespace failed")

		compat_otp.By("\n7.2. Check deny rule in second namespace is blocked from test pod of second namespace because of the deny rule in second namespace\n")
		_, err2 = e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, curlCmd2)
		o.Expect(err2).To(o.HaveOccurred(), "curl the deny rule of second namespace from second namespace failed")

		compat_otp.By("\n7.3. Check url3 is allowed from test pod of second namespace, it is not affected by either deny rule of two namespaces\n")
		_, err3 = e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, curlCmd3)
		o.Expect(err3).NotTo(o.HaveOccurred(), "curl url3 from first namesapce failed")

		compat_otp.By("\n\n8. Replace CIDR of first rule of each egressfirewall with another CIDR \n\n")
		change1 := "[{\"op\":\"replace\",\"path\":\"/spec/egress/0/to/cidrSelector\", \"value\":\"" + cidrValue3 + "\"}]"
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns1, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", change1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		change2 := "[{\"op\":\"replace\",\"path\":\"/spec/egress/0/to/cidrSelector\", \"value\":\"" + cidrValue4 + "\"}]"
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns2, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", change2).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		newCidr, cidrErr := oc.AsAdmin().Run("get").Args("-n", ns1, "egressfirewall.k8s.ovn.org/default", "-o=jsonpath={.spec.egress[0].to.cidrSelector}").Output()
		o.Expect(cidrErr).NotTo(o.HaveOccurred())
		o.Expect(newCidr == cidrValue3).Should(o.BeTrue())
		e2e.Logf("\n\nnew CIDR for first rule in first namespace %v is %v\n\n", ns1, newCidr)

		newCidr, cidrErr = oc.AsAdmin().Run("get").Args("-n", ns2, "egressfirewall.k8s.ovn.org/default", "-o=jsonpath={.spec.egress[0].to.cidrSelector}").Output()
		o.Expect(cidrErr).NotTo(o.HaveOccurred())
		o.Expect(newCidr == cidrValue4).Should(o.BeTrue())
		e2e.Logf("\n\nnew CIDR for first rule in second namespace %v is %v\n\n", ns2, newCidr)

		compat_otp.By("\n\n Repeat curl tests with after CIDR update \n\n")
		compat_otp.By("\n8.1 Curl deny rule of first namespace from first namespace\n")
		_, err1 = e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, newCurlCmd1)
		o.Expect(err1).To(o.HaveOccurred(), "curl the deny rule of first namespace from first namespace failed after CIDR update")

		compat_otp.By("\n8.2 Curl deny rule of second namespace from first namespace\n")
		_, err2 = e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, newCurlCmd2)
		o.Expect(err2).NotTo(o.HaveOccurred(), "curl the deny rule of second namespace from first namespace failed after CIDR update")

		compat_otp.By("\n8.3 Curl url with no rule from first namespace\n")
		_, err3 = e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, newCurlCmd3)
		o.Expect(err3).NotTo(o.HaveOccurred(), "curl url3 from first namesapce failed after CIDR update")

		compat_otp.By("\n8.4 Curl deny rule of first namespace from second namespace\n")
		_, err1 = e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, newCurlCmd1)
		o.Expect(err1).NotTo(o.HaveOccurred(), "curl the deny rule of first namespace from second namespace failed after CIDR update")

		compat_otp.By("\n8.5 Curl deny rule of second namespace from second namespace\n")
		_, err2 = e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, newCurlCmd2)
		o.Expect(err2).To(o.HaveOccurred(), "curl the deny rule of second namespace from second namespace failed after CIDR update")

		compat_otp.By("\n8.6 Curl url with no rule from second namespace\n")
		_, err3 = e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, newCurlCmd3)
		o.Expect(err3).NotTo(o.HaveOccurred(), "curl url3 from second namesapce failed after CIDR update")

		compat_otp.By("\n9. Change the Allow rule of egressfirewall of first namespace to be denied\n")
		change := "[{\"op\":\"replace\",\"path\":\"/spec/egress/1/type\", \"value\":\"Deny\"}]"
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns1, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", change).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		// After second rule in first namespace is changed from Allow to Deny, access to www.redhat.com should be blocked from first namespace
		o.Eventually(func() bool {
			_, err := e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, "curl -I -4 https://www.redhat.com --connect-timeout 5")
			return err != nil
		}, "120s", "10s").Should(o.BeTrue(), "Deny rule did not work as expected in first namespace after rule change for IPv4!!")

		o.Eventually(func() bool {
			_, err := e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, "curl -I -4 https://www.redhat.com --connect-timeout 5")
			return err != nil
		}, "120s", "10s").Should(o.BeTrue(), "Deny rule did not work as expected in second namespace for IPv4!!")

		if ipStackType == "dualstack" {
			o.Eventually(func() bool {
				_, err := e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, "curl -I -6  https://www.redhat.com --connect-timeout 5")
				return err != nil
			}, "120s", "10s").Should(o.BeTrue(), "Deny rule did not work as expected in first namespace after rule change for IPv6 !!")

			o.Eventually(func() bool {
				_, err := e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, "curl -I -6 https://www.redhat.com --connect-timeout 5")
				return err != nil
			}, "120s", "10s").Should(o.BeTrue(), "Deny rule did not work as expected in second namespace for IPv6!!")
		}

		compat_otp.By("\n10. Change the second Deny rule of egressfirewall of second namespace to be allowed\n")
		change = "[{\"op\":\"replace\",\"path\":\"/spec/egress/1/type\", \"value\":\"Allow\"}]"
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns2, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", change).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		// After second rule in second namespace is changed from Deny to Allow, access to www.redhat.com should be still be blocked from first namespace but allowed from second namespace
		o.Eventually(func() bool {
			_, err := e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, "curl -I -4 https://www.redhat.com/en --connect-timeout 5")
			return err != nil
		}, "120s", "10s").Should(o.BeTrue(), "After rule change, Allow rule in second namespace does not affect first namespace for IPv4!!")

		o.Eventually(func() bool {
			_, err := e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, "curl -I -4 https://www.redhat.com/en --connect-timeout 5")
			return err == nil
		}, "120s", "10s").Should(o.BeTrue(), "Allow rule did not work as expected in second namespace after rule change for IPv4!!")

		if ipStackType == "dualstack" {
			o.Eventually(func() bool {
				_, err := e2eoutput.RunHostCmd(pod1ns1.namespace, pod1ns1.name, "curl -I -6 https://www.redhat.com/en --connect-timeout 5")
				return err != nil
			}, "120s", "10s").Should(o.BeTrue(), "After rule change, Allow rule in second namespace does not affect first namespace for IPv6!!")

			o.Eventually(func() bool {
				_, err := e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, "curl -I -6 https://www.redhat.com/en --connect-timeout 5")
				return err == nil
			}, "120s", "10s").Should(o.BeTrue(), "Allow rule did not work as expected in second namespace after rule change for IPv6 !!")
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-ConnectedOnly-High-65173-[NETWORKCUSIM] Misconfigured Egress Firewall can be corrected.", func() {
		//This is from customer bug https://issues.redhat.com/browse/OCPBUGS-15182
		var (
			buildPruningBaseDir = testdata.FixturePath("networking")
			egressFWTemplate2   = filepath.Join(buildPruningBaseDir, "egressfirewall2-template.yaml")
		)

		compat_otp.By("Obtain the namespace \n")
		ns := oc.Namespace()

		compat_otp.By("Create an EgressFirewall with missing cidr prefix\n")
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Deny",
			cidr:      "1.1.1.1",
			template:  egressFWTemplate2,
		}
		egressFW2.createEgressFW2Object(oc)

		compat_otp.By("Verify EgressFirewall was not applied correctly\n")
		checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
			output, efErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", "-n", ns, egressFW2.name).Output()
			if efErr != nil {
				e2e.Logf("Failed to get egressfirewall %v, error: %s. Trying again", egressFW2, efErr)
				return false, nil
			}
			if !strings.Contains(output, "EgressFirewall Rules not correctly applied") {
				e2e.Logf("The egressfirewall output message not expexted, trying again. \n %s", output)
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("EgressFirewall with missing cidr prefix should not be applied correctly!"))

		compat_otp.By("Apply EgressFirewall again with correct cidr\n")
		egressFW2.cidr = "1.1.1.0/24"
		egressFW2.createEgressFW2Object(oc)

		compat_otp.By("Verify EgressFirewall was applied correctly\n")
		efErr := waitEgressFirewallApplied(oc, egressFW2.name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())
	})

	// author: jechen@redhat.com
	g.It("Author:jechen-NonHyperShiftHOST-ConnectedOnly-High-72054-EgressFirewall rules should include all IPs of matched node when nodeSelector is used.", func() {

		// https://issues.redhat.com/browse/OCPBUGS-13665

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall3-template.yaml")

		compat_otp.By("1. Label one node to match egressfirewall rule")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough worker nodes for this test, skip the case!!")
		}

		// node1 is going to be labelled to be a matched node, node2 is not labelled so it is not a matched node
		node1 := nodeList.Items[0].Name
		node2 := nodeList.Items[1].Name
		defer e2enode.RemoveLabelOffNode(oc.KubeFramework().ClientSet, node1, "ef-dep")
		e2enode.AddOrUpdateLabelOnNode(oc.KubeFramework().ClientSet, node1, "ef-dep", "qe")

		// Get all host IPs of both nodes
		allNode1IPsv4, allNode1IPsv6 := getAllHostCIDR(oc, node1)
		allNode2IPsv4, allNode2IPRv6 := getAllHostCIDR(oc, node2)

		compat_otp.By("2. Get new namespace")
		ns := oc.Namespace()

		compat_otp.By("3. Create a pod in the namespace")
		testPod := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		testPod.createPingPod(oc)
		waitPodReady(oc, testPod.namespace, testPod.name)

		compat_otp.By("4.Check the nodes can be acccessed before egressFirewall with nodeSelector is applied")
		if !checkNodeAccessibilityFromAPod(oc, node1, testPod.namespace, testPod.name) || !checkNodeAccessibilityFromAPod(oc, node2, testPod.namespace, testPod.name) {
			g.Skip("Pre-test check failed, test is skipped!")
		}

		compat_otp.By(" 5. Create an egressFirewall with rule nodeSelector.")
		ipStackType := checkIPStackType(oc)
		var cidrValue string
		if ipStackType == "ipv6single" {
			cidrValue = "::/0"
		} else {
			cidrValue = "0.0.0.0/0" // for Dualstack, test with v4 CIDR first, then test V6 CIDR later
		}

		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Deny",
			cidr:      cidrValue,
			template:  egressFWTemplate,
		}
		defer egressFW2.deleteEgressFW2Object(oc)
		egressFW2.createEgressFW2Object(oc)
		efErr := waitEgressFirewallApplied(oc, egressFW2.name, ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By(" 6. Verify Egress firewall rules in NBDB of all nodes.")
		ovnACLCmd := fmt.Sprintf("ovn-nbctl --format=table --no-heading  --columns=action,priority,match find acl external_ids:k8s.ovn.org/name=%s | grep allow", ns)
		nodelist, nodeErr := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		o.Expect(len(nodelist)).NotTo(o.BeEquivalentTo(0))

		for _, eachNode := range nodelist {
			ovnKubePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", eachNode)
			o.Expect(podErr).NotTo(o.HaveOccurred())
			listOutput, listErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubePod, ovnACLCmd)
			o.Expect(listErr).NotTo(o.HaveOccurred())

			// egressFirewall rules should include all the IPs of the matched node1 in NBDB, but do not include IPs for unmatched node2
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

		compat_otp.By(" 7. Verified matched node can be accessed from all its interfaces, unmatched node can not be accessed from any of its interfaces.")
		result1 := checkNodeAccessibilityFromAPod(oc, node1, testPod.namespace, testPod.name)
		o.Expect(result1).Should(o.BeTrue())
		result2 := checkNodeAccessibilityFromAPod(oc, node2, testPod.namespace, testPod.name)
		o.Expect(result2).Should(o.BeFalse())

		if ipStackType == "dualstack" || ipStackType == "ipv6single" {
			// Delete original egressFirewall, recreate the egressFirewall with IPv6 CIDR, then check access to nodes through IPv6 interfaces
			egressFW2.deleteEgressFW2Object(oc)
			egressFW2.cidr = "::/0"
			defer egressFW2.deleteEgressFW2Object(oc)
			egressFW2.createEgressFW2Object(oc)

			result1 := checkNodeAccessibilityFromAPod(oc, node1, testPod.namespace, testPod.name)
			o.Expect(result1).Should(o.BeTrue())
			result2 := checkNodeAccessibilityFromAPod(oc, node2, testPod.namespace, testPod.name)
			o.Expect(result2).Should(o.BeFalse())
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-ConnectedOnly-Medium-67491-[FdpOvnOvs] EgressFirewall works with ANP, BANP and NP for egress traffic.", func() {
		ipStackType := checkIPStackType(oc)
		platform := compat_otp.CheckPlatform(oc)
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
			ipBlockEgressTemplateSingle = filepath.Join(testDataDir, "networkpolicy/ipblock/ipBlock-egress-single-CIDR-template.yaml")
			matchLabelKey               = "kubernetes.io/metadata.name"
		)

		compat_otp.By("Get test namespace")
		ns := oc.Namespace()

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("4. Create a Baseline Admin Network Policy with deny action to cidr")
		banpCR := singleRuleCIDRBANPPolicyResource{
			name:       "default",
			subjectKey: matchLabelKey,
			subjectVal: ns,
			ruleName:   "default-deny-to-" + ns,
			ruleAction: "Deny",
			cidr:       "0.0.0.0/0",
			template:   banpCRTemplate,
		}
		defer removeResource(oc, true, true, "banp", banpCR.name)
		banpCR.createSingleRuleCIDRBANP(oc)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("banp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, banpCR.name)).To(o.BeTrue())

		compat_otp.By("Get one IP address for domain name www.google.com")
		ipv4, ipv6 := getIPFromDnsName("www.google.com")
		o.Expect(len(ipv4) == 0).NotTo(o.BeTrue())

		compat_otp.By("Create an EgressFirewall \n")
		egressFW := egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Allow",
			cidr:      ipv4 + "/32",
			template:  egressFWTemplate,
		}
		egressFW.createEgressFW2Object(oc)
		err = waitEgressFirewallApplied(oc, egressFW.name, ns)
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("Verify destination got blocked")
		verifyDstIPAccess(pod1.name, ns, ipv4, false)

		compat_otp.By("Remove BANP")
		removeResource(oc, true, true, "banp", banpCR.name)
		verifyDstIPAccess(pod1.name, ns, ipv4, true)

		compat_otp.By("Create ANP with deny action to cidr")
		anpCR := singleRuleCIDRANPPolicyResource{
			name:       "anp-" + testID,
			subjectKey: matchLabelKey,
			subjectVal: ns,
			priority:   10,
			ruleName:   "allow-to-" + ns,
			ruleAction: "Deny",
			cidr:       "0.0.0.0/0",
			template:   anpCRTemplate,
		}
		defer removeResource(oc, true, true, "anp", anpCR.name)
		anpCR.createSingleRuleCIDRANP(oc)
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, anpCR.name)).To(o.BeTrue())

		compat_otp.By("Verify destination got blocked")
		verifyDstIPAccess(pod1.name, ns, ipv4, false)
		compat_otp.By("Remove ANP")
		removeResource(oc, true, true, "anp", anpCR.name)
		verifyDstIPAccess(pod1.name, ns, ipv4, true)

		compat_otp.By("Create Network Policy with limited access to cidr which is not same as egressfirewall")
		npIPBlock := ipBlockCIDRsSingle{
			name:      "ipblock-single-cidr-egress",
			template:  ipBlockEgressTemplateSingle,
			cidr:      "1.1.1.1/32",
			namespace: ns,
		}
		npIPBlock.createipBlockCIDRObjectSingle(oc)
		output, err = oc.AsAdmin().Run("get").Args("networkpolicy", "-n", ns).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress"))

		compat_otp.By("Verify destination got blocked")
		verifyDstIPAccess(pod1.name, ns, ipv4, false)

		compat_otp.By("Remove network policy")
		removeResource(oc, true, true, "-n", ns, "networkpolicy", npIPBlock.name)

		if ipStackType == "dualstack" {
			// Retest with ipv6 address
			if !checkIPv6PublicAccess(oc) {
				g.Skip("Not be able to access the public website with IPv6,skip below test steps!!")
			}
			o.Expect(len(ipv6) == 0).NotTo(o.BeTrue())
			compat_otp.By("Create ANP with deny action to ipv6 cidr")
			banpCR.cidr = "::/0"
			banpCR.createSingleRuleCIDRBANP(oc)
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("banp").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, banpCR.name)).To(o.BeTrue())

			compat_otp.By("Update egressfirewall with ipv6 address")
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Allow\",\"to\":{\"cidrSelector\":\""+ipv6+"/128\"}}]}}", "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())

			compat_otp.By("Verify destination got blocked")
			verifyDstIPAccess(pod1.name, ns, ipv6, false)

			compat_otp.By("Remove BANP")
			removeResource(oc, true, true, "banp", banpCR.name)
			verifyDstIPAccess(pod1.name, ns, ipv6, true)

			compat_otp.By("Create ANP")
			anpCR.cidr = "::/0"
			anpCR.createSingleRuleCIDRANP(oc)
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(strings.Contains(output, anpCR.name)).To(o.BeTrue())

			compat_otp.By("Verify destination got blocked")
			verifyDstIPAccess(pod1.name, ns, ipv6, false)

			compat_otp.By("Remove ANP")
			removeResource(oc, true, true, "anp", anpCR.name)
			verifyDstIPAccess(pod1.name, ns, ipv6, true)

			compat_otp.By("Create Network Policy")
			npIPBlock.cidr = "2001::02/128"
			npIPBlock.createipBlockCIDRObjectSingle(oc)
			output, err = oc.AsAdmin().Run("get").Args("networkpolicy", "-n", ns).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).To(o.ContainSubstring("ipblock-single-cidr-egress"))

			compat_otp.By("Verify destination got blocked")
			verifyDstIPAccess(pod1.name, ns, ipv6, false)
		}
	})

	// author: huirwang@redhat.com
	g.It("Author:huirwang-NonHyperShiftHOST-NonPreRelease-Longduration-Medium-74657-EgressFirewall nodeSelector works after some specific operations. [Disruptive]", func() {
		//https://issues.redhat.com/browse/OCPBUGS-34331
		compat_otp.By("Get worker nodes")
		nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
		o.Expect(err).NotTo(o.HaveOccurred())
		if len(nodeList.Items) < 2 {
			g.Skip("Not enough worker nodes for this test, skip the case!!")
		}
		node1 := nodeList.Items[0].Name
		node2 := nodeList.Items[1].Name

		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodNodeTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-specific-node-template.yaml")
		egressFWTemplate := filepath.Join(buildPruningBaseDir, "egressfirewall3-template.yaml")

		compat_otp.By("Get namespace")
		ns := oc.Namespace()

		compat_otp.By("Create egressfirewall from file")
		type egressFirewallConfig struct {
			Domains []string
		}
		outputEFFilePath := "/tmp/egress_firewall_8000.yaml"
		domainsPerFile := 7999
		yamlTemplate := `apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default
spec:
  egress:
{{- range .Domains }}
  - type: Allow
    to:
      dnsName: {{ . }}
{{- end }}
  - type: Deny
    to:
      cidrSelector: 0.0.0.0/0
`

		// Parse the YAML template
		tmpl, err := template.New("egressFirewall").Parse(yamlTemplate)
		o.Expect(err).NotTo(o.HaveOccurred())
		// Generate the egressfirewall file
		domains := make([]string, domainsPerFile)
		for i := 0; i < domainsPerFile; i++ {
			domains[i] = fmt.Sprintf("fake-domain-%d.com", i+1)
		}
		// Create the EgressFirewallConfig struct
		config := egressFirewallConfig{Domains: domains}
		// Open the output file
		defer os.Remove(outputEFFilePath)
		outputFile, err := os.Create(outputEFFilePath)
		o.Expect(err).NotTo(o.HaveOccurred())
		// Execute the template and write to the file
		err = tmpl.Execute(outputFile, config)
		o.Expect(err).NotTo(o.HaveOccurred())
		outputFile.Close()
		e2e.Logf("Successfully generated %s\n", outputEFFilePath)
		err = oc.WithoutNamespace().AsAdmin().Run("create").Args("-f", outputEFFilePath, "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		o.Eventually(func() bool {
			output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall/default", "-n", ns).Output()
			e2e.Logf("\n EgressFiewall status: %v\n", output)
			return strings.Contains(output, "EgressFirewall Rules applied")
		}, "1800s", "30s").Should(o.BeTrue(), "Egressfiewall Rules were not correctly applied!!")

		compat_otp.By("Delete the egressfirewall and stop nbdb for one node")
		removeResource(oc, true, true, "egressfirewall/default", "-n", ns)
		killNBDBCmd := "crictl stop $(crictl ps | grep nbdb | awk '{print $1}')"
		_, debugNodeErr := compat_otp.DebugNodeWithChroot(oc, node1, "bash", "-c", killNBDBCmd)
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())

		compat_otp.By("Create second namespace and two pods")
		oc.SetupProject()
		ns2 := oc.Namespace()
		pod1ns2 := pingPodResourceNode{
			name:      "hello-pod1",
			namespace: ns2,
			nodename:  node1,
			template:  pingPodNodeTemplate,
		}
		pod1ns2.createPingPodNode(oc)
		waitPodReady(oc, pod1ns2.namespace, pod1ns2.name)
		pod2ns2 := pingPodResourceNode{
			name:      "hello-pod2",
			namespace: ns2,
			nodename:  node2,
			template:  pingPodNodeTemplate,
		}
		pod2ns2.createPingPodNode(oc)
		waitPodReady(oc, pod2ns2.namespace, pod2ns2.name)
		compat_otp.By("Get one master node IP.")
		master1, err := compat_otp.GetFirstMasterNode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		master1IP1, master1IP2 := getNodeIP(oc, master1)
		_, err = e2eoutput.RunHostCmd(pod1ns2.namespace, pod1ns2.name, "ping -c 2 "+master1IP2)
		if err != nil {
			g.Skip("Ping node IP failed without egressfirewall, skip the test in this environment.")
		}

		compat_otp.By("Create EgressFirewall object with nodeSelector.")
		ipStackType := checkIPStackType(oc)
		var cidrValue string
		if ipStackType == "ipv6single" {
			cidrValue = "::/0"
		} else {
			cidrValue = "0.0.0.0/0"
		}
		egressFW2 := egressFirewall2{
			name:      "default",
			namespace: ns2,
			ruletype:  "Deny",
			cidr:      cidrValue,
			template:  egressFWTemplate,
		}
		defer egressFW2.deleteEgressFW2Object(oc)
		egressFW2.createEgressFW2Object(oc)
		efErr := waitEgressFirewallApplied(oc, "default", ns2)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify the master node can NOT be accessed from both pods")
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod1ns2.namespace, pod1ns2.name, "ping -c 2 "+master1IP2)
			return err
		}, "60s", "10s").Should(o.HaveOccurred())
		o.Eventually(func() error {
			_, err = e2eoutput.RunHostCmd(pod2ns2.namespace, pod2ns2.name, "ping -c 2 "+master1IP2)
			return err
		}, "10s", "5s").Should(o.HaveOccurred())

		compat_otp.By("Label the master node which would match the egressfirewall.")
		defer compat_otp.DeleteLabelFromNode(oc, master1, "ef-dep")
		compat_otp.AddLabelToNode(oc, master1, "ef-dep", "qe")

		compat_otp.By("Verify the master node can be accessed from both pods")
		_, err = e2eoutput.RunHostCmdWithRetries(pod1ns2.namespace, pod1ns2.name, "ping -c 2 "+master1IP2, 5*time.Second, 20*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmdWithRetries(pod2ns2.namespace, pod2ns2.name, "ping -c 2 "+master1IP2, 5*time.Second, 20*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())

		if ipStackType == "dualstack" {
			// Test node ipv6 address as well
			egressFW2.deleteEgressFW2Object(oc)
			egressFW2.cidr = "::/0"
			defer egressFW2.deleteEgressFW2Object(oc)
			egressFW2.createEgressFW2Object(oc)
			efErr = waitEgressFirewallApplied(oc, "default", ns2)
			o.Expect(efErr).NotTo(o.HaveOccurred())

			compat_otp.By("Verify the master node can be accessed from both pods with IPv6")
			_, err = e2eoutput.RunHostCmdWithRetries(pod1ns2.namespace, pod1ns2.name, "ping -c 2 "+master1IP1, 5*time.Second, 20*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = e2eoutput.RunHostCmdWithRetries(pod2ns2.namespace, pod2ns2.name, "ping -c 2 "+master1IP1, 5*time.Second, 20*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())
		}
	})

	g.It("[Level0] Author:asood-ConnectedOnly-High-78162-Egress traffic works with ANP and egress firewall.", func() {
		ipStackType := checkIPStackType(oc)
		platform := compat_otp.CheckPlatform(oc)
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

		compat_otp.By("1. Obtain the namespace")
		ns := oc.Namespace()

		compat_otp.By("2. Create a pod ")
		pod := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod.createPingPod(oc)
		waitPodReady(oc, pod.namespace, pod.name)

		compat_otp.By("3. Get an IP address for domain name www.google.com for allow rule and www.facebook.com for deny rule validation")
		allowedIPv4, allowedIPv6 := getIPFromDnsName("www.google.com")
		o.Expect(len(allowedIPv4) == 0).NotTo(o.BeTrue())
		ipv4CIDR := allowedIPv4 + "/32"
		allowedIPList = append(allowedIPList, allowedIPv4)
		deniedIPv4, deniedIPv6 := getIPFromDnsName("www.facebook.com")
		o.Expect(len(deniedIPv4) == 0).NotTo(o.BeTrue())
		deniedIPList = append(deniedIPList, deniedIPv4)

		// patch payload for egress firewall and ANP
		patchEfw = "[{\"op\": \"add\", \"path\":\"/spec/egress/1\", \"value\": {\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}}]"
		patchANP = "[{\"op\": \"add\", \"path\": \"/spec/egress/1\", \"value\": {\"name\":\"deny egresss\", \"action\": \"Deny\", \"to\": [{\"networks\": [\"0.0.0.0/0\"]}]}}]"

		if ipStackType == "dualstack" {
			if checkIPv6PublicAccess(oc) {
				o.Expect(len(allowedIPv6) == 0).NotTo(o.BeTrue())
				ipv6CIDR := allowedIPv6 + "/128"
				allowedIPList = append(allowedIPList, allowedIPv6)
				o.Expect(len(deniedIPv6) == 0).NotTo(o.BeTrue())
				deniedIPList = append(deniedIPList, deniedIPv6)
				patchEfw = "[{\"op\": \"add\", \"path\":\"/spec/egress/1\", \"value\": {\"type\":\"Allow\",\"to\":{\"cidrSelector\":\"" + ipv6CIDR + "\"}}}, {\"op\": \"add\", \"path\":\"/spec/egress/2\", \"value\": {\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}}, {\"op\": \"add\", \"path\":\"/spec/egress/3\", \"value\": {\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"::/0\"}}}]"
				patchANP = "[{\"op\": \"add\", \"path\": \"/spec/egress/0/to/0/networks/1\", \"value\": \"" + ipv6CIDR + "\"}, {\"op\": \"add\", \"path\": \"/spec/egress/1\", \"value\": {\"name\":\"deny egresss\", \"action\": \"Deny\", \"to\": [{\"networks\": [\"0.0.0.0/0\", \"::/0\"]}]}}]"

			} else {
				e2e.Logf("Dual stack cluster does not have access to public websites")
			}

		}

		egressFW := egressFirewall2{
			name:      "default",
			namespace: ns,
			ruletype:  "Allow",
			cidr:      allowedIPv4 + "/32",
			template:  egressFWTemplate,
		}

		anpCR := singleRuleCIDRANPPolicyResource{
			name:       "anp-network-egress" + testID,
			subjectKey: matchLabelKey,
			subjectVal: ns,
			priority:   10,
			ruleName:   "allow-to-" + ns,
			ruleAction: "Allow",
			cidr:       ipv4CIDR,
			template:   anpCRTemplate,
		}
		compat_otp.By("5. Verify the intended denied IP is reachable before egress firewall is applied")
		for i := 0; i < len(deniedIPList); i++ {
			e2e.Logf("Verify %s is accessible before egress firewall is applied", deniedIPList[i])
			verifyDstIPAccess(pod.name, ns, deniedIPList[i], true)
		}

		compat_otp.By("6. Create egress firewall")
		egressFW.createEgressFW2Object(oc)
		err := waitEgressFirewallApplied(oc, egressFW.name, ns)
		o.Expect(err).NotTo(o.HaveOccurred())
		patchReplaceResourceAsAdmin(oc, "egressfirewall/default", patchEfw, ns)
		efwRules, efwRulesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", ns, "egressfirewall", "default", "-o=jsonpath={.spec.egress}").Output()
		o.Expect(efwRulesErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n Egress Firewall Rules after update : %s", efwRules)
		compat_otp.By("7. Validate traffic after egress firewall is applied")
		for i := 0; i < len(allowedIPList); i++ {
			compat_otp.By(fmt.Sprintf("Verify %s is accessible with just egress firewall", allowedIPList[i]))
			verifyDstIPAccess(pod.name, ns, allowedIPList[i], true)
			compat_otp.By(fmt.Sprintf("Verify %s is not accessible with just egress firewall", deniedIPList[i]))
			verifyDstIPAccess(pod.name, ns, deniedIPList[i], false)
		}

		compat_otp.By("8. Create ANP with Allow action to an IP and Deny action to all CIDRs")
		defer removeResource(oc, true, true, "anp", anpCR.name)
		anpCR.createSingleRuleCIDRANP(oc)
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("anp").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, anpCR.name)).To(o.BeTrue())
		patchReplaceResourceAsAdmin(oc, "anp/"+anpCR.name, patchANP)

		anpRules, rulesErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("adminnetworkpolicy", anpCR.name, "-o=jsonpath={.spec.egress}").Output()
		o.Expect(rulesErr).NotTo(o.HaveOccurred())
		e2e.Logf("\n ANP Rules  after update : %s", anpRules)
		compat_otp.By("9. Validate traffic with ANP and Egress firewall configured")
		for i := 0; i < len(allowedIPList); i++ {
			compat_otp.By(fmt.Sprintf("Verify %s is accessible after ANP is created", allowedIPList[i]))
			verifyDstIPAccess(pod.name, ns, allowedIPList[i], true)
			compat_otp.By(fmt.Sprintf("Verify %s is not accessible after ANP is created", deniedIPList[i]))
			verifyDstIPAccess(pod.name, ns, deniedIPList[i], false)
		}
		compat_otp.By("10. Remove Egress Firewall")
		removeResource(oc, true, true, "egressfirewall", egressFW.name, "-n", egressFW.namespace)
		compat_otp.By("11. Validate traffic with just ANP configured")
		for i := 0; i < len(allowedIPList); i++ {
			compat_otp.By(fmt.Sprintf("Verify %s is accessible after egress firewall is removed", allowedIPList[i]))
			verifyDstIPAccess(pod.name, ns, allowedIPList[i], true)
			compat_otp.By(fmt.Sprintf("Verify %s is not accessible after egress firewall is removed", deniedIPList[i]))
			verifyDstIPAccess(pod.name, ns, deniedIPList[i], false)
		}

	})
})

var _ = g.Describe("[OTP][sig-networking] SDN egressfirewall-techpreview", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLI("networking-egressfirewall", compat_otp.KubeConfigPath())
	g.BeforeEach(func() {
		if !compat_otp.IsTechPreviewNoUpgrade(oc) {
			g.Skip("featureSet: TechPreviewNoUpgrade is required for this test")
		}

		if checkProxy(oc) || checkDisconnect(oc) {
			g.Skip("This is proxy/disconnect cluster, skip the test.")
		}

		ipStackType := checkIPStackType(oc)
		platform := compat_otp.CheckPlatform(oc)
		acceptedPlatform := strings.Contains(platform, "none")
		if !(ipStackType == "ipv4single" || (acceptedPlatform && ipStackType == "dualstack")) {
			g.Skip("This case should be run on UPI packet dualstack cluster or IPv4 cluster, skip other platform or network stack type.")
		}
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:huirwang-Critical-73723-dnsName has wildcard in EgressFirewall rules.", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		efwSingle := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-wildcard.yaml")
		efwDualstack := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-wildcard-dualstack.yaml")

		compat_otp.By("Create egressfirewall file")
		ns := oc.Namespace()

		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			createResourceFromFile(oc, ns, efwDualstack)
		} else {
			createResourceFromFile(oc, ns, efwSingle)
		}
		efErr := waitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Verify the allowed rules which match the wildcard take effect.")
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.google.com", true)
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.redhat.com", false)

		compat_otp.By("Update the domain name to a litlle bit long domain name.")
		updateValue := "[{\"op\":\"replace\",\"path\":\"/spec/egress/0/to/dnsName\", \"value\":\"*.whatever.you.like.here.followed.by.svc-1.google.com\"}]"
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", updateValue).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		efErr = waitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify the allowed rules which match the wildcard take effect.")
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "type.whatever.you.like.here.followed.by.svc-1.google.com", true)
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.google.com", false)
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:huirwang-Medium-73724-dnsName has same wildcard domain name in EgressFirewall rules in different namespaces.", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		efwSingle := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-wildcard.yaml")
		efwDualstack := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-wildcard-dualstack.yaml")

		compat_otp.By("Create a test pod in first namespace ")
		ns1 := oc.Namespace()
		pod1ns1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1ns1.createPingPod(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		compat_otp.By("Create a test pod in the second namespace ")
		oc.SetupProject()
		ns2 := oc.Namespace()
		pod1ns2 := pingPodResource{
			name:      "hello-pod",
			namespace: ns2,
			template:  pingPodTemplate,
		}
		pod1ns2.createPingPod(oc)
		waitPodReady(oc, pod1ns2.namespace, pod1ns2.name)

		compat_otp.By("Create EgressFirewall in both namespaces ")
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			createResourceFromFile(oc, ns1, efwDualstack)
			createResourceFromFile(oc, ns2, efwDualstack)
		} else {
			createResourceFromFile(oc, ns1, efwSingle)
			createResourceFromFile(oc, ns2, efwSingle)
		}
		efErr := waitEgressFirewallApplied(oc, "default", ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())
		efErr = waitEgressFirewallApplied(oc, "default", ns2)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify the allowed rules which match the wildcard take effect for both namespace.")
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.google.com", true)
		verifyDesitnationAccess(oc, pod1ns2.name, pod1ns2.namespace, "www.google.com", true)

		compat_otp.By("Verify other website which doesn't match the wildcard would be blocked")
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.redhat.com", false)
		verifyDesitnationAccess(oc, pod1ns2.name, pod1ns2.namespace, "www.redhat.com", false)

		compat_otp.By("Update the wildcard domain name to a different one in second namespace.")
		updateValue := "[{\"op\":\"replace\",\"path\":\"/spec/egress/0/to/dnsName\", \"value\":\"*.redhat.com\"}]"
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns2, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", updateValue).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		efErr = waitEgressFirewallApplied(oc, "default", ns2)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify the udpated rule taking effect in second namespace.")
		verifyDesitnationAccess(oc, pod1ns2.name, pod1ns2.namespace, "www.google.com", false)
		verifyDesitnationAccess(oc, pod1ns2.name, pod1ns2.namespace, "www.redhat.com", true)

		compat_otp.By("Verify the egressfirewall rules in first namespace still works")
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.google.com", true)
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.redhat.com", false)

		compat_otp.By("Remove egressfirewall in first namespace.")
		removeResource(oc, true, true, "egressfirewall/default", "-n", ns1)

		compat_otp.By("Verify no blocking for the destination domain names in first namespace")
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.google.com", true)
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.redhat.com", true)
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:huirwang-Critical-73719-Allowing access to DNS names even if the IP addresses associated with them changes. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		efwSingle := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-specific-dnsname.yaml")
		efwDualstack := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-specific-dnsname-dualstack.yaml")

		compat_otp.By("Create an egressfirewall file")
		ns := oc.Namespace()
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			createResourceFromFile(oc, ns, efwDualstack)
		} else {
			createResourceFromFile(oc, ns, efwSingle)
		}
		efErr := waitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Verify the allowed rules take effect.")
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "registry-1.docker.io", true)
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.facebook.com", true)
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.redhat.com", false)

		compat_otp.By("Verify dnsnameresolver contains the allowed dns names.")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("dnsnameresolver", "-n", "openshift-ovn-kubernetes", "-o", "yaml").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The dnsnameresolver output is : \n %s ", output)
		o.Expect(strings.Contains(output, "dnsName: www.facebook.com")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "dnsName: registry-1.docker.io")).To(o.BeTrue())
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:huirwang-Medium-73721-Medium-73722-Update domain name in EgressFirewall,EgressFirewall works after restart ovnkube-node pods. [Disruptive]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		efwSingle := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-specific-dnsname.yaml")
		efwDualstack := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-specific-dnsname-dualstack.yaml")

		compat_otp.By("Create egressfirewall file")
		ns := oc.Namespace()
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			createResourceFromFile(oc, ns, efwDualstack)
		} else {
			createResourceFromFile(oc, ns, efwSingle)
		}
		efErr := waitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Create a pod ")
		pod1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns,
			template:  pingPodTemplate,
		}
		pod1.createPingPod(oc)
		waitPodReady(oc, pod1.namespace, pod1.name)

		compat_otp.By("Update the domain name to a different one.")
		updateValue := "[{\"op\":\"replace\",\"path\":\"/spec/egress/0/to/dnsName\", \"value\":\"www.redhat.com\"}]"
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("-n", ns, "egressfirewall.k8s.ovn.org/default", "--type=json", "-p", updateValue).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		efErr = waitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify the allowed rules take effect.")
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.redhat.com", true)
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.facebook.com", true)
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "registry-1.docker.io", false)

		compat_otp.By("The dns names in dnsnameresolver get udpated as well.")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("dnsnameresolver", "-n", "openshift-ovn-kubernetes", "-o", "yaml").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The dnsnameresolver output is : \n %s ", output)
		o.Expect(strings.Contains(output, "dnsName: www.facebook.com")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "dnsName: www.redhat.com")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "dnsName: registry-1.docker.io")).NotTo(o.BeTrue())

		compat_otp.By("Restart the ovnkube-node pod ")
		defer waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
		podNode, err := compat_otp.GetPodNodeName(oc, pod1.namespace, pod1.name)
		o.Expect(err).NotTo(o.HaveOccurred())
		delPodErr := oc.AsAdmin().Run("delete").Args("pod", "-l", "app=ovnkube-node", "-n", "openshift-ovn-kubernetes", "--field-selector", "spec.nodeName="+podNode).Execute()
		o.Expect(delPodErr).NotTo(o.HaveOccurred())

		compat_otp.By("Wait for ovnkube-node pods back up.")
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")

		compat_otp.By("Verify the function still works")
		efErr = waitEgressFirewallApplied(oc, "default", ns)
		o.Expect(efErr).NotTo(o.HaveOccurred())
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.redhat.com", true)
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "www.facebook.com", true)
		verifyDesitnationAccess(oc, pod1.name, pod1.namespace, "registry-1.docker.io", false)
	})

	// author: huirwang@redhat.com
	g.It("NonHyperShiftHOST-ConnectedOnly-Author:huirwang-Medium-73720-Same domain name in different namespaces should work correctly. [Serial]", func() {
		buildPruningBaseDir := testdata.FixturePath("networking")
		pingPodTemplate := filepath.Join(buildPruningBaseDir, "ping-for-pod-template.yaml")
		efwSingle := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-specific-dnsname.yaml")
		efwDualstack := filepath.Join(buildPruningBaseDir, "egressfirewall/egressfirewall-specific-dnsname-dualstack.yaml")

		compat_otp.By("Create test pod in first namespace")
		ns1 := oc.Namespace()
		pod1ns1 := pingPodResource{
			name:      "hello-pod",
			namespace: ns1,
			template:  pingPodTemplate,
		}
		pod1ns1.createPingPod(oc)
		waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

		compat_otp.By("Create test pod in second namespace")
		oc.SetupProject()
		ns2 := oc.Namespace()
		pod1ns2 := pingPodResource{
			name:      "hello-pod",
			namespace: ns2,
			template:  pingPodTemplate,
		}
		pod1ns2.createPingPod(oc)
		waitPodReady(oc, pod1ns2.namespace, pod1ns2.name)

		compat_otp.By("Create egressfirewall in both namespaces")
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			createResourceFromFile(oc, ns1, efwDualstack)
			createResourceFromFile(oc, ns2, efwDualstack)
		} else {
			createResourceFromFile(oc, ns1, efwSingle)
			createResourceFromFile(oc, ns2, efwSingle)
		}
		efErr := waitEgressFirewallApplied(oc, "default", ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())
		efErr = waitEgressFirewallApplied(oc, "default", ns2)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify the allowed rules take effect on both namespaces")
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "registry-1.docker.io", true)
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.facebook.com", true)
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.redhat.com", false)
		verifyDesitnationAccess(oc, pod1ns2.name, pod1ns2.namespace, "registry-1.docker.io", true)
		verifyDesitnationAccess(oc, pod1ns2.name, pod1ns2.namespace, "www.facebook.com", true)
		verifyDesitnationAccess(oc, pod1ns2.name, pod1ns2.namespace, "www.redhat.com", false)

		compat_otp.By("Delete egressfirewall in second namespace")
		removeResource(oc, true, true, "egressfirewall/default", "-n", ns2)

		compat_otp.By("Verify the previous blocked dns name can be accessed.")
		verifyDesitnationAccess(oc, pod1ns2.name, pod1ns2.namespace, "www.redhat.com", true)

		compat_otp.By("Verify dnsnameresolver still contains the allowed dns names.")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("dnsnameresolver", "-n", "openshift-ovn-kubernetes", "-o", "yaml").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The dnsnameresolver output is : \n %s ", output)
		o.Expect(strings.Contains(output, "dnsName: www.facebook.com")).To(o.BeTrue())
		o.Expect(strings.Contains(output, "dnsName: registry-1.docker.io")).To(o.BeTrue())

		compat_otp.By("Verify egressfirewall in first namespace still works")
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "registry-1.docker.io", true)
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.facebook.com", true)
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.redhat.com", false)

		compat_otp.By("Remove one domain name in first namespace")
		if ipStackType == "dualstack" {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns1, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Allow\",\"to\":{\"dnsName\":\"registry-1.docker.io\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"::/0\"}}]}}", "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		} else {
			errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("egressfirewall.k8s.ovn.org/default", "-n", ns1, "-p", "{\"spec\":{\"egress\":[{\"type\":\"Allow\",\"to\":{\"dnsName\":\"registry-1.docker.io\"}},{\"type\":\"Deny\",\"to\":{\"cidrSelector\":\"0.0.0.0/0\"}}]}}", "--type=merge").Execute()
			o.Expect(errPatch).NotTo(o.HaveOccurred())
		}
		efErr = waitEgressFirewallApplied(oc, "default", ns1)
		o.Expect(efErr).NotTo(o.HaveOccurred())

		compat_otp.By("Verify removed dns name will be blocked")
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "registry-1.docker.io", true)
		verifyDesitnationAccess(oc, pod1ns1.name, pod1ns1.namespace, "www.facebook.com", false)

		compat_otp.By("Verify removed dns name was removed from dnsnameresolver as well.")
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("dnsnameresolver", "-n", "openshift-ovn-kubernetes", "-o", "yaml").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The dnsnameresolver output is : \n %s ", output)
		o.Expect(strings.Contains(output, "dnsName: www.facebook.com")).NotTo(o.BeTrue())
		o.Expect(strings.Contains(output, "dnsName: registry-1.docker.io")).To(o.BeTrue())
	})

})
