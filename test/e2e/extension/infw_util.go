package networking

import (
	"fmt"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

type infwCResource struct {
	name          string
	primary_inf   string
	nodelabel     string
	src_cidr1     string
	protocol_1    string
	protocoltype1 string
	range_1       string
	action_1      string
	protocol_2    string
	protocoltype2 string
	range_2       string
	action_2      string
	template      string
}

type infwCResource_multiple_cidr struct {
	name          string
	primary_inf   string
	nodelabel     string
	src_cidr1     string
	src_cidr2     string
	protocol_1    string
	protocoltype1 string
	range_1       string
	action_1      string
	protocol_2    string
	protocoltype2 string
	range_2       string
	action_2      string
	template      string
}

type infwCResource_icmp struct {
	name        string
	primary_inf string
	nodelabel   string
	src_cidr    string
	action_1    string
	action_2    string
	template    string
}

type infwConfigResource struct {
	namespace string
	nodelabel string
	template  string
}

func (infw *infwCResource) createinfwCR(oc *exutil.CLI) {
	g.By("Creating infw CR from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", infw.template, "-p", "NAME="+infw.name, "PRIMARY_INF="+infw.primary_inf, "NODELABEL="+infw.nodelabel, "SRC_CIDR1="+infw.src_cidr1, "PROTOCOL_1="+infw.protocol_1, "PROTOCOLTYPE1="+infw.protocoltype1, "RANGE_1="+infw.range_1, "ACTION_1="+infw.action_1, "PROTOCOL_2="+infw.protocol_2, "PROTOCOLTYPE2="+infw.protocoltype2, "RANGE_2="+infw.range_2, "ACTION_2="+infw.action_2)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create infw CR %v", infw.name))
}

func (infw_multiple_cidr *infwCResource_multiple_cidr) createinfwCR_multiple_cidr(oc *exutil.CLI) {
	g.By("Creating infw CR from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", infw_multiple_cidr.template, "-p", "NAME="+infw_multiple_cidr.name, "PRIMARY_INF="+infw_multiple_cidr.primary_inf, "NODELABEL="+infw_multiple_cidr.nodelabel, "SRC_CIDR1="+infw_multiple_cidr.src_cidr1, "SRC_CIDR2="+infw_multiple_cidr.src_cidr2, "PROTOCOL_1="+infw_multiple_cidr.protocol_1, "PROTOCOLTYPE1="+infw_multiple_cidr.protocoltype1, "RANGE_1="+infw_multiple_cidr.range_1, "ACTION_1="+infw_multiple_cidr.action_1, "PROTOCOLTYPE2="+infw_multiple_cidr.protocoltype2, "PROTOCOL_2="+infw_multiple_cidr.protocol_2, "RANGE_2="+infw_multiple_cidr.range_2, "ACTION_2="+infw_multiple_cidr.action_2)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create infw CR %v", infw_multiple_cidr.name))
}

func (infwcfg *infwConfigResource) createinfwConfig(oc *exutil.CLI) {
	g.By("Creating infw config from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", infwcfg.template, "-p", "NAMESPACE="+infwcfg.namespace, "NODELABEL="+infwcfg.nodelabel)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create infw Config Resource"))
}

func (infwICMP *infwCResource_icmp) createinfwICMP(oc *exutil.CLI) {
	g.By("Creating infw ICMP from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", infwICMP.template, "-p", "NAME="+infwICMP.name, "PRIMARY_INF="+infwICMP.primary_inf, "NODELABEL="+infwICMP.nodelabel, "SRC_CIDR="+infwICMP.src_cidr, "ACTION_2="+infwICMP.action_2, "ACTION_1="+infwICMP.action_1)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create infw ICMP"))
}

func deleteinfwCR(oc *exutil.CLI, cr string) {
	e2e.Logf("delete %s in namespace %s", "openshift-ingress-node-firewall", cr)
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("IngressNodeFirewall", cr).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func deleteinfwCfg(oc *exutil.CLI) {
	e2e.Logf("deleting ingressnodefirewallconfig in namespace openshift-ingress-node-firewall")
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("IngressNodeFirewallConfig", "ingressnodefirewallconfig", "-n", "openshift-ingress-node-firewall").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func restartInfwDaemons(oc *exutil.CLI) {
	e2e.Logf("Restarting ingress node firewall daemons in namespace openshift-ingress-node-firewall")
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "-l=app=ingress-node-firewall-daemon", "-n", "openshift-ingress-node-firewall").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
	err = waitForPodWithLabelReady(oc, "openshift-ingress-node-firewall", "app=ingress-node-firewall-daemon")
	compat_otp.AssertWaitPollNoErr(err, "Ingress node firewall daemons not ready")
}

func getinfwDaemonForNode(oc *exutil.CLI, nodeName string) string {
	infwDaemon, err := compat_otp.GetPodName(oc, "openshift-ingress-node-firewall", "app=ingress-node-firewall-daemon", nodeName)
	o.Expect(err).NotTo(o.HaveOccurred())
	return infwDaemon
}

func waitforInfwDaemonsready(oc *exutil.CLI) {
	err := waitForPodWithLabelReady(oc, "openshift-ingress-node-firewall", "app=ingress-node-firewall-daemon")
	compat_otp.AssertWaitPollNoErr(err, "Ingress node firewall daemons not ready")
}
