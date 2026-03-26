package networking

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/extension/testdata"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/openshift/origin/test/extended/util/compat_otp"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	netutils "k8s.io/utils/net"
)

type pingPodResource struct {
	name      string
	namespace string
	template  string
}

type pingPodResourceNode struct {
	name      string
	namespace string
	nodename  string
	template  string
}

type pingPodResourceWinNode struct {
	name      string
	namespace string
	image     string
	nodename  string
	template  string
}

type egressIPResource1 struct {
	name          string
	template      string
	egressIP1     string
	egressIP2     string
	nsLabelKey    string
	nsLabelValue  string
	podLabelKey   string
	podLabelValue string
}

type egressFirewall1 struct {
	name      string
	namespace string
	template  string
}

type egressFirewall2 struct {
	name      string
	namespace string
	ruletype  string
	cidr      string
	template  string
}

type ipBlockCIDRsDual struct {
	name      string
	namespace string
	cidrIpv4  string
	cidrIpv6  string
	cidr2Ipv4 string
	cidr2Ipv6 string
	cidr3Ipv4 string
	cidr3Ipv6 string
	template  string
}

type ipBlockCIDRsSingle struct {
	name      string
	namespace string
	cidr      string
	cidr2     string
	cidr3     string
	template  string
}
type ipBlockCIDRsExceptDual struct {
	name            string
	namespace       string
	cidrIpv4        string
	cidrIpv4Except  string
	cidrIpv6        string
	cidrIpv6Except  string
	cidr2Ipv4       string
	cidr2Ipv4Except string
	cidr2Ipv6       string
	cidr2Ipv6Except string
	cidr3Ipv4       string
	cidr3Ipv4Except string
	cidr3Ipv6       string
	cidr3Ipv6Except string
	template        string
}
type ipBlockCIDRsExceptSingle struct {
	name      string
	namespace string
	cidr      string
	except    string
	cidr2     string
	except2   string
	cidr3     string
	except3   string
	template  string
}

type genericServiceResource struct {
	servicename           string
	namespace             string
	protocol              string
	selector              string
	serviceType           string
	ipFamilyPolicy        string
	externalTrafficPolicy string
	internalTrafficPolicy string
	template              string
}

type windowGenericServiceResource struct {
	servicename           string
	namespace             string
	protocol              string
	selector              string
	serviceType           string
	ipFamilyPolicy        string
	externalTrafficPolicy string
	internalTrafficPolicy string
	template              string
}

type testPodMultinetwork struct {
	name      string
	namespace string
	nodename  string
	nadname   string
	labelname string
	template  string
}

type externalIPService struct {
	name       string
	namespace  string
	externalIP string
	template   string
}

type externalIPPod struct {
	name      string
	namespace string
	template  string
}

type nodePortService struct {
	name      string
	namespace string
	nodeName  string
	template  string
}

type egressPolicy struct {
	name         string
	namespace    string
	cidrSelector string
	template     string
}
type aclSettings struct {
	DenySetting  string `json:"deny"`
	AllowSetting string `json:"allow"`
}

type egressrouterMultipleDst struct {
	name           string
	namespace      string
	reservedip     string
	gateway        string
	destinationip1 string
	destinationip2 string
	destinationip3 string
	template       string
}

type egressrouterRedSDN struct {
	name          string
	namespace     string
	reservedip    string
	gateway       string
	destinationip string
	labelkey      string
	labelvalue    string
	template      string
}

type egressFirewall5 struct {
	name        string
	namespace   string
	ruletype1   string
	rulename1   string
	rulevalue1  string
	protocol1   string
	portnumber1 int
	ruletype2   string
	rulename2   string
	rulevalue2  string
	protocol2   string
	portnumber2 int
	template    string
}

type egressNetworkpolicy struct {
	name      string
	namespace string
	ruletype  string
	rulename  string
	rulevalue string
	template  string
}

type svcEndpontDetails struct {
	ovnKubeNodePod string
	nodeName       string
	podIP          string
}

type migrationDetails struct {
	name                   string
	template               string
	namespace              string
	virtualmachinesintance string
}

type kubeletKillerPod struct {
	name      string
	namespace string
	nodename  string
	template  string
}

type httpserverPodResourceNode struct {
	name          string
	namespace     string
	containerport int32
	hostport      int32
	nodename      string
	template      string
}

// struct for using nncp to create VF on sriov node
type VRFResource struct {
	name     string
	intfname string
	nodename string
	tableid  int
	template string
}

// struct to create a pod with named port
type namedPortPodResource struct {
	name          string
	namespace     string
	podLabelKey   string
	podLabelVal   string
	portname      string
	containerport int32
	template      string
}

func (pod *pingPodResource) createPingPod(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (pod *pingPodResourceNode) createPingPodNode(oc *exutil.CLI) {
	err := wait.Poll(3*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "NODENAME="+pod.nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (pod *pingPodResourceWinNode) createPingPodWinNode(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplate(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "IMAGE="+pod.image, "NODENAME="+pod.nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func (pod *testPodMultinetwork) createTestPodMultinetwork(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "NODENAME="+pod.nodename, "LABELNAME="+pod.labelname, "NADNAME="+pod.nadname)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

func applyResourceFromTemplate(oc *exutil.CLI, parameters ...string) error {
	var configFile string
	err := wait.Poll(3*time.Second, 15*time.Second, func() (bool, error) {
		output, err := oc.Run("process").Args(parameters...).OutputToFile(getRandomString() + "ping-pod.json")
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		configFile = output
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to process %v", parameters))

	e2e.Logf("the file of resource is %s", configFile)
	return oc.WithoutNamespace().Run("apply").Args("-f", configFile).Execute()
}

func (egressIP *egressIPResource1) createEgressIPObject1(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", egressIP.template, "-p", "NAME="+egressIP.name, "EGRESSIP1="+egressIP.egressIP1, "EGRESSIP2="+egressIP.egressIP2)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create EgressIP %v", egressIP.name))
}

func (egressIP *egressIPResource1) deleteEgressIPObject1(oc *exutil.CLI) {
	removeResource(oc, true, true, "egressip", egressIP.name)
}

func (egressIP *egressIPResource1) createEgressIPObject2(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", egressIP.template, "-p", "NAME="+egressIP.name, "EGRESSIP1="+egressIP.egressIP1, "NSLABELKEY="+egressIP.nsLabelKey, "NSLABELVALUE="+egressIP.nsLabelValue, "PODLABELKEY="+egressIP.podLabelKey, "PODLABELVALUE="+egressIP.podLabelValue)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create EgressIP %v", egressIP.name))
}

func (egressFirewall *egressFirewall1) createEgressFWObject1(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", egressFirewall.template, "-p", "NAME="+egressFirewall.name, "NAMESPACE="+egressFirewall.namespace)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create EgressFW %v", egressFirewall.name))
}

func (egressFirewall *egressFirewall1) deleteEgressFWObject1(oc *exutil.CLI) {
	removeResource(oc, true, true, "egressfirewall", egressFirewall.name, "-n", egressFirewall.namespace)
}

func (egressFirewall *egressFirewall2) createEgressFW2Object(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", egressFirewall.template, "-p", "NAME="+egressFirewall.name, "NAMESPACE="+egressFirewall.namespace, "RULETYPE="+egressFirewall.ruletype, "CIDR="+egressFirewall.cidr)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create EgressFW2 %v", egressFirewall.name))
}

func (EFW *egressFirewall5) createEgressFW5Object(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		parameters := []string{"--ignore-unknown-parameters=true", "-f", EFW.template, "-p", "NAME=" + EFW.name, "NAMESPACE=" + EFW.namespace, "RULETYPE1=" + EFW.ruletype1, "RULENAME1=" + EFW.rulename1, "RULEVALUE1=" + EFW.rulevalue1, "PROTOCOL1=" + EFW.protocol1, "PORTNUMBER1=" + strconv.Itoa(EFW.portnumber1), "RULETYPE2=" + EFW.ruletype2, "RULENAME2=" + EFW.rulename2, "RULEVALUE2=" + EFW.rulevalue2, "PROTOCOL2=" + EFW.protocol2, "PORTNUMBER2=" + strconv.Itoa(EFW.portnumber2)}
		err1 := applyResourceFromTemplateByAdmin(oc, parameters...)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create EgressFW2 %v", EFW.name))
}

func (eNPL *egressNetworkpolicy) createEgressNetworkPolicyObj(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		parameters := []string{"--ignore-unknown-parameters=true", "-f", eNPL.template, "-p", "NAME=" + eNPL.name, "NAMESPACE=" + eNPL.namespace, "RULETYPE=" + eNPL.ruletype, "RULENAME=" + eNPL.rulename, "RULEVALUE=" + eNPL.rulevalue}
		err1 := applyResourceFromTemplateByAdmin(oc, parameters...)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create EgressNetworkPolicy %v in Namespace %v", eNPL.name, eNPL.namespace))
}

// Single CIDR on Dual stack
func (ipBlock_policy *ipBlockCIDRsDual) createipBlockCIDRObjectDual(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_policy.template, "-p", "NAME="+ipBlock_policy.name, "NAMESPACE="+ipBlock_policy.namespace, "cidrIpv6="+ipBlock_policy.cidrIpv6, "cidrIpv4="+ipBlock_policy.cidrIpv4)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network policy %v", ipBlock_policy.name))
}

// Single CIDR on single stack
func (ipBlock_policy *ipBlockCIDRsSingle) createipBlockCIDRObjectSingle(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_policy.template, "-p", "NAME="+ipBlock_policy.name, "NAMESPACE="+ipBlock_policy.namespace, "CIDR="+ipBlock_policy.cidr)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network policy %v", ipBlock_policy.name))
}

// Single IP Block with except clause on Dual stack
func (ipBlock_except_policy *ipBlockCIDRsExceptDual) createipBlockExceptObjectDual(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {

		policyApplyError := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_except_policy.template, "-p", "NAME="+ipBlock_except_policy.name, "NAMESPACE="+ipBlock_except_policy.namespace, "CIDR_IPv6="+ipBlock_except_policy.cidrIpv6, "EXCEPT_IPv6="+ipBlock_except_policy.cidrIpv6Except, "CIDR_IPv4="+ipBlock_except_policy.cidrIpv4, "EXCEPT_IPv4="+ipBlock_except_policy.cidrIpv4Except)
		if policyApplyError != nil {
			e2e.Logf("the err:%v, and try next round", policyApplyError)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network policy %v", ipBlock_except_policy.name))
}

// Single IP Block with except clause on Single stack
func (ipBlock_except_policy *ipBlockCIDRsExceptSingle) createipBlockExceptObjectSingle(oc *exutil.CLI, except bool) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {

		policyApplyError := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_except_policy.template, "-p", "NAME="+ipBlock_except_policy.name, "NAMESPACE="+ipBlock_except_policy.namespace, "CIDR="+ipBlock_except_policy.cidr, "EXCEPT="+ipBlock_except_policy.except)
		if policyApplyError != nil {
			e2e.Logf("the err:%v, and try next round", policyApplyError)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network policy %v", ipBlock_except_policy.name))
}

// Function to create ingress or egress policy with multiple CIDRs on Dual Stack Cluster
func (ipBlock_cidrs_policy *ipBlockCIDRsDual) createIPBlockMultipleCIDRsObjectDual(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_cidrs_policy.template, "-p", "NAME="+ipBlock_cidrs_policy.name, "NAMESPACE="+ipBlock_cidrs_policy.namespace, "cidrIpv6="+ipBlock_cidrs_policy.cidrIpv6, "cidrIpv4="+ipBlock_cidrs_policy.cidrIpv4, "cidr2Ipv4="+ipBlock_cidrs_policy.cidr2Ipv4, "cidr2Ipv6="+ipBlock_cidrs_policy.cidr2Ipv6, "cidr3Ipv4="+ipBlock_cidrs_policy.cidr3Ipv4, "cidr3Ipv6="+ipBlock_cidrs_policy.cidr3Ipv6)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network policy %v", ipBlock_cidrs_policy.name))
}

// Function to create ingress or egress policy with multiple CIDRs on Single Stack Cluster
func (ipBlock_cidrs_policy *ipBlockCIDRsSingle) createIPBlockMultipleCIDRsObjectSingle(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", ipBlock_cidrs_policy.template, "-p", "NAME="+ipBlock_cidrs_policy.name, "NAMESPACE="+ipBlock_cidrs_policy.namespace, "CIDR="+ipBlock_cidrs_policy.cidr, "CIDR2="+ipBlock_cidrs_policy.cidr2, "CIDR3="+ipBlock_cidrs_policy.cidr3)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create network policy %v", ipBlock_cidrs_policy.name))
}

func (service *genericServiceResource) createServiceFromParams(oc *exutil.CLI) {
	err := wait.Poll(3*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", service.template, "-p", "SERVICENAME="+service.servicename, "NAMESPACE="+service.namespace, "PROTOCOL="+service.protocol, "SELECTOR="+service.selector, "serviceType="+service.serviceType, "ipFamilyPolicy="+service.ipFamilyPolicy, "internalTrafficPolicy="+service.internalTrafficPolicy, "externalTrafficPolicy="+service.externalTrafficPolicy)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create svc %v", service.servicename))
}

func (service *windowGenericServiceResource) createWinServiceFromParams(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", service.template, "-p", "SERVICENAME="+service.servicename, "NAMESPACE="+service.namespace, "PROTOCOL="+service.protocol, "SELECTOR="+service.selector, "serviceType="+service.serviceType, "ipFamilyPolicy="+service.ipFamilyPolicy, "internalTrafficPolicy="+service.internalTrafficPolicy, "externalTrafficPolicy="+service.externalTrafficPolicy)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create svc %v", service.servicename))
}

func (egressrouter *egressrouterMultipleDst) createEgressRouterMultipeDst(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", egressrouter.template, "-p", "NAME="+egressrouter.name, "NAMESPACE="+egressrouter.namespace, "RESERVEDIP="+egressrouter.reservedip, "GATEWAY="+egressrouter.gateway, "DSTIP1="+egressrouter.destinationip1, "DSTIP2="+egressrouter.destinationip2, "DSTIP3="+egressrouter.destinationip3)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create egressrouter %v", egressrouter.name))
}

func (egressrouter *egressrouterRedSDN) createEgressRouterRedSDN(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", egressrouter.template, "-p", "NAME="+egressrouter.name, "NAMESPACE="+egressrouter.namespace, "RESERVEDIP="+egressrouter.reservedip, "GATEWAY="+egressrouter.gateway, "DSTIP="+egressrouter.destinationip, "LABELKEY="+egressrouter.labelkey, "LABELVALUE="+egressrouter.labelvalue)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create egressrouter %v", egressrouter.name))
}

func (egressFirewall *egressFirewall2) deleteEgressFW2Object(oc *exutil.CLI) {
	removeResource(oc, true, true, "egressfirewall", egressFirewall.name, "-n", egressFirewall.namespace)
}

func (pod *pingPodResource) deletePingPod(oc *exutil.CLI) {
	removeResource(oc, false, true, "pod", pod.name, "-n", pod.namespace)
}

func (pod *pingPodResourceNode) deletePingPodNode(oc *exutil.CLI) {
	removeResource(oc, false, true, "pod", pod.name, "-n", pod.namespace)
}

func removeResource(oc *exutil.CLI, asAdmin bool, withoutNamespace bool, parameters ...string) {
	output, err := doAction(oc, "delete", asAdmin, withoutNamespace, parameters...)
	if err != nil && (strings.Contains(output, "NotFound") || strings.Contains(output, "No resources found")) {
		e2e.Logf("the resource is deleted already")
		return
	}
	o.Expect(err).NotTo(o.HaveOccurred())

	err = wait.Poll(3*time.Second, 120*time.Second, func() (bool, error) {
		output, err := doAction(oc, "get", asAdmin, withoutNamespace, parameters...)
		if err != nil && (strings.Contains(output, "NotFound") || strings.Contains(output, "No resources found")) {
			e2e.Logf("the resource is delete successfully")
			return true, nil
		}
		return false, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to delete resource %v", parameters))
}

func doAction(oc *exutil.CLI, action string, asAdmin bool, withoutNamespace bool, parameters ...string) (string, error) {
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

func applyResourceFromTemplateByAdmin(oc *exutil.CLI, parameters ...string) error {
	var configFile string
	err := wait.Poll(3*time.Second, 15*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().Run("process").Args(parameters...).OutputToFile(getRandomString() + "resource.json")
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		configFile = output
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("as admin fail to process %v", parameters))

	e2e.Logf("the file of resource is %s", configFile)
	return oc.WithoutNamespace().AsAdmin().Run("apply").Args("-f", configFile).Execute()
}

func getRandomString() string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	seed := rand.New(rand.NewSource(time.Now().UnixNano()))
	buffer := make([]byte, 8)
	for index := range buffer {
		buffer[index] = chars[seed.Intn(len(chars))]
	}
	return string(buffer)
}

func getPodStatus(oc *exutil.CLI, namespace string, podName string) (string, error) {
	podStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.phase}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The pod  %s status in namespace %s is %q", podName, namespace, podStatus)
	return podStatus, err
}

func checkPodReady(oc *exutil.CLI, namespace string, podName string) (bool, error) {
	podOutPut, err := getPodStatus(oc, namespace, podName)
	status := []string{"Running", "Ready", "Complete", "Succeeded"}
	return contains(status, podOutPut), err
}

func checkPodNotReady(oc *exutil.CLI, namespace string, podName string) (bool, error) {
	podOutPut, err := getPodStatus(oc, namespace, podName)
	status := []string{"Pending", "ContainerCreating"}
	return contains(status, podOutPut), err
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func waitPodReady(oc *exutil.CLI, namespace string, podName string) {
	err := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
		status, err1 := checkPodReady(oc, namespace, podName)
		if err1 != nil {
			e2e.Logf("the err:%v, wait for pod %v to become ready.", err1, podName)
			return status, err1
		}
		if !status {
			return status, nil
		}
		return status, nil
	})

	if err != nil {
		podDescribe := describePod(oc, namespace, podName)
		e2e.Logf("oc describe pod %v.", podName)
		e2e.Logf(podDescribe)
	}
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("pod %v is not ready", podName))
}

func describePod(oc *exutil.CLI, namespace string, podName string) string {
	podDescribe, err := oc.WithoutNamespace().Run("describe").Args("pod", "-n", namespace, podName).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The pod  %s status is %q", podName, podDescribe)
	return podDescribe
}

func execCommandInSpecificPod(oc *exutil.CLI, namespace string, podName string, command string) (string, error) {
	e2e.Logf("The command is: %v", command)
	command1 := []string{"-n", namespace, podName, "--", "bash", "-c", command}
	msg, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args(command1...).Output()
	if err != nil {
		e2e.Logf("Execute command failed with  err:%v  and output is %v.", err, msg)
		return msg, err
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	return msg, nil
}

func execCommandInNetworkingPod(oc *exutil.CLI, command string) (string, error) {
	var cmd []string
	podName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", "openshift-ovn-kubernetes", "-l", "app=ovnkube-node", "-o=jsonpath={.items[0].metadata.name}").Output()
	if err != nil {
		e2e.Logf("Cannot get ovn-kubernetes pods, errors: %v", err)
		return "", err
	}
	cmd = []string{"-n", "openshift-ovn-kubernetes", "-c", "ovnkube-controller", podName, "--", "/bin/sh", "-c", command}

	msg, err := oc.WithoutNamespace().AsAdmin().Run("exec").Args(cmd...).Output()
	if err != nil {
		e2e.Logf("Execute command failed with  err:%v .", err)
		return "", err
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	return msg, nil
}

func getDefaultInterface(oc *exutil.CLI) (string, error) {
	getDefaultInterfaceCmd := "/usr/sbin/ip -4 route show default"
	int1, err := execCommandInNetworkingPod(oc, getDefaultInterfaceCmd)
	if err != nil {
		e2e.Logf("Cannot get default interface, errors: %v", err)
		return "", err
	}
	defInterface := strings.Split(int1, " ")[4]
	e2e.Logf("Get the default inteface: %s", defInterface)
	return defInterface, nil
}

func getDefaultSubnet(oc *exutil.CLI) (string, error) {
	int1, _ := getDefaultInterface(oc)
	getDefaultSubnetCmd := "/usr/sbin/ip -4 -brief a show " + int1
	subnet1, err := execCommandInNetworkingPod(oc, getDefaultSubnetCmd)
	defSubnet := strings.Fields(subnet1)[2]
	if err != nil {
		e2e.Logf("Cannot get default subnet, errors: %v", err)
		return "", err
	}
	e2e.Logf("Get the default subnet: %s", defSubnet)
	return defSubnet, nil
}

// Hosts function return the host network CIDR
func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	e2e.Logf("in Hosts function, ip: %v, ipnet: %v", ip, ipnet)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func findUnUsedIPs(oc *exutil.CLI, cidr string, number int) []string {
	ipRange, _ := Hosts(cidr)
	var ipUnused = []string{}
	//shuffle the ips slice
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(ipRange), func(i, j int) { ipRange[i], ipRange[j] = ipRange[j], ipRange[i] })
	for _, ip := range ipRange {
		if len(ipUnused) < number {
			pingCmd := "ping -c4 -t1 " + ip
			_, err := execCommandInNetworkingPod(oc, pingCmd)
			if err != nil {
				e2e.Logf("%s is not used!\n", ip)
				ipUnused = append(ipUnused, ip)
			}
		} else {
			break
		}

	}
	return ipUnused
}

func ipEchoServer() string {
	return "172.31.249.80:9095"
}

func checkPlatform(oc *exutil.CLI) string {
	output, _ := oc.WithoutNamespace().AsAdmin().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.type}").Output()
	return strings.ToLower(output)
}

func checkNetworkType(oc *exutil.CLI) string {
	output, _ := oc.WithoutNamespace().AsAdmin().Run("get").Args("network.operator", "cluster", "-o=jsonpath={.spec.defaultNetwork.type}").Output()
	return strings.ToLower(output)
}

func getDefaultIPv6Subnet(oc *exutil.CLI) (string, error) {
	int1, _ := getDefaultInterface(oc)
	getDefaultSubnetCmd := "/usr/sbin/ip -6 -brief a show " + int1
	subnet1, err := execCommandInNetworkingPod(oc, getDefaultSubnetCmd)
	if err != nil {
		e2e.Logf("Cannot get default ipv6 subnet, errors: %v", err)
		return "", err
	}
	defSubnet := strings.Fields(subnet1)[2]
	e2e.Logf("Get the default ipv6 subnet: %s", defSubnet)
	return defSubnet, nil
}

func findUnUsedIPv6(oc *exutil.CLI, cidr string, number int) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	number += 2
	var ips []string
	var i = 0
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		//Not use the first two IPv6 addresses , such as 2620:52:0:4e::  , 2620:52:0:4e::1
		if i == 0 || i == 1 {
			i++
			continue
		}
		//Start to detect the IPv6 adress is used or not
		if i < number {
			pingCmd := "ping -c4 -t1 -6 " + ip.String()
			_, err := execCommandInNetworkingPod(oc, pingCmd)
			if err != nil {
				e2e.Logf("%s is not used!\n", ip)
				ips = append(ips, ip.String())
				i++
			}
		} else {
			break
		}

	}

	return ips, nil
}

func ipv6EchoServer(isIPv6 bool) string {
	if isIPv6 {
		return "[2620:52:0:4974:def4:1ff:fee7:8144]:8085"
	}
	return "10.73.116.56:8085"
}

func checkIPStackType(oc *exutil.CLI) string {
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

func installSctpModule(oc *exutil.CLI, configFile string) {
	status, _ := oc.AsAdmin().Run("get").Args("machineconfigs").Output()
	if !strings.Contains(status, "load-sctp-module") {
		err := oc.WithoutNamespace().AsAdmin().Run("create").Args("-f", configFile).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

func checkSctpModule(oc *exutil.CLI, nodeName, namespace string) {
	defer compat_otp.RecoverNamespaceRestricted(oc, namespace)
	compat_otp.SetNamespacePrivileged(oc, namespace)
	err := wait.Poll(30*time.Second, 15*time.Minute, func() (bool, error) {
		// Check nodes status to make sure all nodes are up after rebooting caused by load-sctp-module
		nodesStatus, err := oc.AsAdmin().Run("get").Args("node").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("oc_get_nodes: %v", nodesStatus)
		status, _ := oc.AsAdmin().Run("debug").Args("node/"+nodeName, "--", "cat", "/sys/module/sctp/initstate").Output()
		if strings.Contains(status, "live") {
			e2e.Logf("stcp module is installed in the %s", nodeName)
			return true, nil
		}
		return false, nil
	})
	compat_otp.AssertWaitPollNoErr(err, "stcp module is installed in the nodes")
}

func getPodIPv4(oc *exutil.CLI, namespace string, podName string) string {
	podIPv4, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The pod  %s IP in namespace %s is %q", podName, namespace, podIPv4)
	return podIPv4
}

func getPodIPv6(oc *exutil.CLI, namespace string, podName string, ipStack string) string {
	if ipStack == "ipv6single" {
		podIPv6, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The pod  %s IP in namespace %s is %q", podName, namespace, podIPv6)
		return podIPv6
	} else if ipStack == "dualstack" {
		podIPv6, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[1].ip}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The pod  %s IP in namespace %s is %q", podName, namespace, podIPv6)
		return podIPv6
	}
	return ""
}

// For normal user to create resources in the specified namespace from the file (not template)
func createResourceFromFile(oc *exutil.CLI, ns, file string) {
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", file, "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func waitForPodWithLabelReady(oc *exutil.CLI, ns, label string) error {
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

func waitForPodWithLabelGone(oc *exutil.CLI, ns, label string) error {
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

func getSvcIPv4(oc *exutil.CLI, namespace string, svcName string) string {
	svcIPv4, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The service %s IPv4 in namespace %s is %q", svcName, namespace, svcIPv4)
	return svcIPv4
}

func getSvcIPv6(oc *exutil.CLI, namespace string, svcName string) string {
	svcIPv6, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[1]}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The service %s IPv6 in namespace %s is %q", svcName, namespace, svcIPv6)
	return svcIPv6
}

func getSvcIPv6SingleStack(oc *exutil.CLI, namespace string, svcName string) string {
	svcIPv6, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The service %s IPv6 in namespace %s is %q", svcName, namespace, svcIPv6)
	return svcIPv6
}

func getSvcIPdualstack(oc *exutil.CLI, namespace string, svcName string) (string, string) {
	svcIPv4, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[0]}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The service %s IPv4 in namespace %s is %q", svcName, namespace, svcIPv4)
	svcIPv6, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.clusterIPs[1]}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The service %s IPv6 in namespace %s is %q", svcName, namespace, svcIPv6)
	return svcIPv4, svcIPv6
}

// check if a configmap is created in specific namespace [usage: checkConfigMap(oc, namesapce, configmapName)]
func checkConfigMap(oc *exutil.CLI, ns, configmapName string) error {
	return wait.Poll(5*time.Second, 3*time.Minute, func() (bool, error) {
		searchOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("cm", "-n", ns).Output()
		if err != nil {
			e2e.Logf("failed to get configmap: %v", err)
			return false, nil
		}
		if strings.Contains(searchOutput, configmapName) {
			e2e.Logf("configmap %v found", configmapName)
			return true, nil
		}
		return false, nil
	})
}

func sshRunCmd(host string, user string, cmd string) error {
	privateKey := os.Getenv("SSH_CLOUD_PRIV_KEY")
	if privateKey == "" {
		privateKey = "../internal/config/keys/openshift-qe.pem"
	}
	sshClient := compat_otp.SshClient{User: user, Host: host, Port: 22, PrivateKey: privateKey}
	return sshClient.Run(cmd)
}

// For Admin to patch a resource in the specified namespace
func patchResourceAsAdmin(oc *exutil.CLI, resource, patch string, nameSpace ...string) {
	var cargs []string
	if len(nameSpace) > 0 {
		cargs = []string{resource, "-p", patch, "-n", nameSpace[0], "--type=merge"}
	} else {
		cargs = []string{resource, "-p", patch, "--type=merge"}
	}
	err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(cargs...).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

// Check network operator status in intervals until timeout
func checkNetworkOperatorState(oc *exutil.CLI, interval int, timeout int) {
	errCheck := wait.Poll(time.Duration(interval)*time.Second, time.Duration(timeout)*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "network").Output()
		if err != nil {
			e2e.Logf("Fail to get clusteroperator network, error:%s. Trying again", err)
			return false, nil
		}
		matched, _ := regexp.MatchString("True.*False.*False", output)
		e2e.Logf("Network operator state is:%s", output)
		o.Expect(matched).To(o.BeTrue())
		return false, nil
	})
	o.Expect(errCheck.Error()).To(o.ContainSubstring("timed out waiting for the condition"))
}

func getNodeIPv4(oc *exutil.CLI, namespace, nodeName string) string {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", oc.Namespace(), "node", nodeName, "-o=jsonpath={.status.addresses[?(@.type==\"InternalIP\")].address}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if err != nil {
		e2e.Logf("Cannot get node default interface ipv4 address, errors: %v", err)
	}

	// when egressIP is applied to a node, it would be listed as internal IP for the node, thus, there could be more than one IPs shown as internal IP
	// use RE to match out to first internal IP
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	nodeipv4 := re.FindAllString(output, -1)[0]
	e2e.Logf("The IPv4 of node's default interface is %q", nodeipv4)
	return nodeipv4
}

// Return IPv6 and IPv4 in vars respectively for Dual Stack and IPv4/IPv6 in 2nd var for single stack Clusters, and var1 will be nil in those cases
func getNodeIP(oc *exutil.CLI, nodeName string) (string, string) {
	ipStack := checkIPStackType(oc)
	if (ipStack == "ipv6single") || (ipStack == "ipv4single") {
		e2e.Logf("Its a Single Stack Cluster, either IPv4 or IPv6")
		InternalIP, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[?(@.type==\"InternalIP\")].address}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The node's Internal IP is %q", InternalIP)
		return "", InternalIP
	}
	e2e.Logf("Its a Dual Stack Cluster")
	InternalIP1, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[0].address}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The node's 1st Internal IP is %q", InternalIP1)
	InternalIP2, err := oc.AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.status.addresses[1].address}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The node's 2nd Internal IP is %q", InternalIP2)
	if netutils.IsIPv6String(InternalIP1) {
		return InternalIP1, InternalIP2
	}
	return InternalIP2, InternalIP1
}

// get CLuster Manager's leader info
func getLeaderInfo(oc *exutil.CLI, namespace string, cmName string, networkType string) string {
	if networkType == "ovnkubernetes" {
		linuxNodeList, err := compat_otp.GetAllNodesbyOSType(oc, "linux")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(linuxNodeList).NotTo(o.BeEmpty())
		podName, getPodNameErr := compat_otp.GetPodName(oc, namespace, cmName, linuxNodeList[0])
		o.Expect(getPodNameErr).NotTo(o.HaveOccurred())
		o.Expect(podName).NotTo(o.BeEmpty())
		return podName
	}
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("cm", "openshift-network-controller", "-n", namespace, "-o=jsonpath={.metadata.annotations.control-plane\\.alpha\\.kubernetes\\.io\\/leader}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	var sdnAnnotations map[string]interface{}
	json.Unmarshal([]byte(output), &sdnAnnotations)
	leaderNodeName := sdnAnnotations["holderIdentity"].(string)
	o.Expect(leaderNodeName).NotTo(o.BeEmpty())
	ocGetPods, podErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", "openshift-sdn", "pod", "-l app=sdn", "-o=wide").OutputToFile("ocgetpods.txt")
	defer os.RemoveAll(ocGetPods)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	rawGrepOutput, rawGrepErr := exec.Command("bash", "-c", "cat "+ocGetPods+" | grep "+leaderNodeName+" | awk '{print $1}'").Output()
	o.Expect(rawGrepErr).NotTo(o.HaveOccurred())
	leaderPodName := strings.TrimSpace(string(rawGrepOutput))
	e2e.Logf("The leader Pod's name: %v", leaderPodName)
	return leaderPodName
}

func checkSDNMetrics(oc *exutil.CLI, url string, metrics string) {
	var metricsOutput []byte
	var metricsLog []byte
	olmToken, err := compat_otp.GetSAToken(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(olmToken).NotTo(o.BeEmpty())
	metricsErr := wait.Poll(5*time.Second, 10*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "-c", "prometheus", "prometheus-k8s-0", "--", "curl", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", olmToken), fmt.Sprintf("%s", url)).OutputToFile("metrics.txt")
		if err != nil {
			e2e.Logf("Can't get metrics and try again, the error is:%s", err)
			return false, nil
		}
		metricsLog, _ = exec.Command("bash", "-c", "cat "+output+" ").Output()
		metricsString := string(metricsLog)
		if strings.Contains(metricsString, "ovnkube_controller_pod") {
			metricsOutput, _ = exec.Command("bash", "-c", "cat "+output+" | grep "+metrics+" | awk 'NR==1{print $2}'").Output()
		} else {
			metricsOutput, _ = exec.Command("bash", "-c", "cat "+output+" | grep "+metrics+" | awk 'NR==3{print $2}'").Output()
		}
		metricsValue := strings.TrimSpace(string(metricsOutput))
		if metricsValue != "" {
			e2e.Logf("The output of the metrics for %s is : %v", metrics, metricsValue)
		} else {
			e2e.Logf("Can't get metrics for %s:", metrics)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(metricsErr, fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
}

func getEgressCIDRs(oc *exutil.CLI, node string) string {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostsubnet", node, "-o=jsonpath={.egressCIDRs}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("egressCIDR for hostsubnet node %v is: %v", node, output)
	return output
}

// get egressIP from a node
// When they are multiple egressIPs on the node, egressIp list is in format of ["10.0.247.116","10.0.156.51"]
// as an example from the output of command "oc get hostsubnet <node> -o=jsonpath={.egressIPs}"
// convert the iplist into an array of ip addresses
func getEgressIPByKind(oc *exutil.CLI, kind string, kindName string, expectedNum int) ([]string, error) {
	var ip = []string{}
	iplist, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(kind, kindName, "-o=jsonpath={.egressIPs}").Output()
	isIPListEmpty := (iplist == "" || iplist == "[]")
	if expectedNum == 0 {
		// Add waiting time for egressIP removed
		egressIPEmptyErr := wait.Poll(30*time.Second, 5*time.Minute, func() (bool, error) {
			iplist, err = oc.AsAdmin().WithoutNamespace().Run("get").Args(kind, kindName, "-o=jsonpath={.egressIPs}").Output()
			if iplist == "" || iplist == "[]" {
				e2e.Logf("EgressIP list is empty")
				return true, nil
			}
			e2e.Logf("EgressIP list is %s, not removed, or have err:%v, and try next round", iplist, err)
			return false, nil
		})
		return ip, egressIPEmptyErr
	}
	if !isIPListEmpty && iplist != "[]" {
		ip = strings.Split(iplist[2:len(iplist)-2], "\",\"")
	}
	if isIPListEmpty || len(ip) < expectedNum || err != nil {
		err = wait.Poll(30*time.Second, 5*time.Minute, func() (bool, error) {
			iplist, err = oc.AsAdmin().WithoutNamespace().Run("get").Args(kind, kindName, "-o=jsonpath={.egressIPs}").Output()
			if len(iplist) > 0 && iplist != "[]" {
				ip = strings.Split(iplist[2:len(iplist)-2], "\",\"")
			}
			if len(ip) < expectedNum || err != nil {
				e2e.Logf("only got %d egressIP, or have err:%v, and try next round", len(ip), err)
				return false, nil
			}
			if len(iplist) > 0 && len(ip) == expectedNum {
				e2e.Logf("Found egressIP list for %v %v is: %v", kind, kindName, iplist)
				return true, nil
			}
			return false, nil
		})
		e2e.Logf("Only got %d egressIP, or have err:%v", len(ip), err)
		return ip, err
	}
	return ip, nil
}

func getPodName(oc *exutil.CLI, namespace string, label string) []string {
	var podName []string
	podNameAll, err := oc.AsAdmin().Run("get").Args("-n", namespace, "pod", "-l", label, "-ojsonpath={.items..metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	podName = strings.Split(podNameAll, " ")
	o.Expect(len(podName)).NotTo(o.BeEquivalentTo(0))
	e2e.Logf("The pod(s) are  %v ", podName)
	return podName
}

// starting from first node, compare its subnet with subnet of subsequent nodes in the list
// until two nodes with same subnet found, otherwise, return false to indicate that no two nodes with same subnet found
func findTwoNodesWithSameSubnet(oc *exutil.CLI, nodeList *v1.NodeList) (bool, [2]string) {
	var nodes [2]string
	for i := 0; i < (len(nodeList.Items) - 1); i++ {
		for j := i + 1; j < len(nodeList.Items); j++ {
			firstSub := getIfaddrFromNode(nodeList.Items[i].Name, oc)
			secondSub := getIfaddrFromNode(nodeList.Items[j].Name, oc)
			if firstSub == secondSub {
				e2e.Logf("Found nodes with same subnet.")
				nodes[0] = nodeList.Items[i].Name
				nodes[1] = nodeList.Items[j].Name
				return true, nodes
			}
		}
	}
	return false, nodes
}

func getSDNMetrics(oc *exutil.CLI, podName string) string {
	var metricsLog string
	metricsErr := wait.Poll(5*time.Second, 10*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-sdn", fmt.Sprintf("%s", podName), "--", "curl", "localhost:29100/metrics").OutputToFile("metrics.txt")
		if err != nil {
			e2e.Logf("Can't get metrics and try again, the error is:%s", err)
			return false, nil
		}
		metricsLog = output
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(metricsErr, fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
	return metricsLog
}

func getOVNMetrics(oc *exutil.CLI, url string) string {
	var metricsLog string
	olmToken, err := compat_otp.GetSAToken(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(olmToken).NotTo(o.BeEmpty())
	metricsErr := wait.Poll(5*time.Second, 10*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "-c", "prometheus", "prometheus-k8s-0", "--", "env", "-u", "HTTPS_PROXY", "-u", "https_proxy", "curl", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", olmToken), fmt.Sprintf("%s", url)).OutputToFile("metrics.txt")
		if err != nil {
			e2e.Logf("Can't get metrics and try again, the error is:%s", err)
			return false, nil
		}
		metricsLog = output
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(metricsErr, fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
	return metricsLog
}

func checkIPsec(oc *exutil.CLI) string {
	output, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("network.operator", "cluster", "-o=jsonpath={.spec.defaultNetwork.ovnKubernetesConfig.ipsecConfig.mode}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if output == "" {
		// if have {} in 4.15+, that means it upgraded from previous version and with ipsec enabled.
		output, err = oc.WithoutNamespace().AsAdmin().Run("get").Args("network.operator", "cluster", "-o=jsonpath={.spec.defaultNetwork.ovnKubernetesConfig.ipsecConfig}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
	}
	e2e.Logf("The ipsec state is === %v ===", output)
	return output
}

func getAssignedEIPInEIPObject(oc *exutil.CLI, egressIPObject string) []map[string]string {
	timeout := estimateTimeoutForEgressIP(oc)
	var egressIPs string
	egressipErr := wait.Poll(10*time.Second, timeout, func() (bool, error) {
		egressIPStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressip", egressIPObject, "-ojsonpath={.status.items}").Output()
		if err != nil {
			e2e.Logf("Wait to get EgressIP object applied,try next round. %v", err)
			return false, nil
		}
		if egressIPStatus == "" {
			e2e.Logf("Wait to get EgressIP object applied,try next round. %v", err)
			return false, nil
		}
		egressIPs = egressIPStatus
		e2e.Logf("egressIPStatus: %v", egressIPs)
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to apply egressIPs:%s", egressipErr))

	var egressIPJsonMap []map[string]string
	json.Unmarshal([]byte(egressIPs), &egressIPJsonMap)
	e2e.Logf("egressIPJsonMap:%v", egressIPJsonMap)
	return egressIPJsonMap
}

func rebootNode(oc *exutil.CLI, nodeName string) {
	e2e.Logf("\nRebooting node %s....", nodeName)
	_, err1 := compat_otp.DebugNodeWithChroot(oc, nodeName, "shutdown", "-r", "+1")
	o.Expect(err1).NotTo(o.HaveOccurred())
}

func checkNodeStatus(oc *exutil.CLI, nodeName string, expectedStatus string) {
	var expectedStatus1 string
	if expectedStatus == "Ready" {
		expectedStatus1 = "True"
	} else if expectedStatus == "NotReady" {
		expectedStatus1 = "Unknown"
	} else {
		err1 := fmt.Errorf("TBD supported node status")
		o.Expect(err1).NotTo(o.HaveOccurred())
	}
	err := wait.Poll(5*time.Second, 15*time.Minute, func() (bool, error) {
		statusOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", nodeName, "-ojsonpath={.status.conditions[-1].status}").Output()
		if err != nil {
			e2e.Logf("\nGet node status with error : %v", err)
			return false, nil
		}
		e2e.Logf("Expect Node %s in state %v, kubelet status is %s", nodeName, expectedStatus, statusOutput)
		if statusOutput != expectedStatus1 {
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Node %s is not in expected status %s", nodeName, expectedStatus))
}

func updateEgressIPObject(oc *exutil.CLI, egressIPObjectName string, egressIP string) {
	patchResourceAsAdmin(oc, "egressip/"+egressIPObjectName, "{\"spec\":{\"egressIPs\":[\""+egressIP+"\"]}}")
	egressipErr := wait.Poll(10*time.Second, 180*time.Second, func() (bool, error) {
		output, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("egressip", egressIPObjectName, "-o=jsonpath={.status.items[*]}").Output()
		if err != nil {
			e2e.Logf("Wait to get EgressIP object applied,try next round. %v", err)
			return false, nil
		}
		if !strings.Contains(output, egressIP) {
			e2e.Logf("Wait for new IP %s applied,try next round.", egressIP)
			e2e.Logf(output)
			return false, nil
		}
		e2e.Logf(output)
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(egressipErr, fmt.Sprintf("Failed to apply new egressIP %s:%v", egressIP, egressipErr))
}

func getTwoNodesSameSubnet(oc *exutil.CLI, nodeList *v1.NodeList) (bool, []string) {
	var egressNodes []string
	if len(nodeList.Items) < 2 {
		e2e.Logf("Not enough nodes available for the test, skip the case!!")
		return false, nil
	}
	platform := compat_otp.CheckPlatform(oc)
	if strings.Contains(platform, "aws") {
		e2e.Logf("find the two nodes that have same subnet")
		check, nodes := findTwoNodesWithSameSubnet(oc, nodeList)
		if check {
			egressNodes = nodes[:2]
		} else {
			e2e.Logf("No more than 2 worker nodes in same subnet, skip the test!!!")
			return false, nil
		}
	} else {
		e2e.Logf("since worker nodes all have same subnet, just pick first two nodes as egress nodes")
		egressNodes = append(egressNodes, nodeList.Items[0].Name)
		egressNodes = append(egressNodes, nodeList.Items[1].Name)
	}
	return true, egressNodes
}

/*
getSvcIP returns IPv6 and IPv4 in vars in order on dual stack respectively and main Svc IP in case of single stack (v4 or v6) in 1st var, and nil in 2nd var.
LoadBalancer svc will return Ingress VIP in var1, v4 or v6 and NodePort svc will return Ingress SvcIP in var1 and NodePort in var2
*/
func getSvcIP(oc *exutil.CLI, namespace string, svcName string) (string, string) {
	ipStack := checkIPStackType(oc)
	svctype, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.type}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	ipFamilyType, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.spec.ipFamilyPolicy}").Output()
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
		platform := compat_otp.CheckPlatform(oc)
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
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to assign lb svc IP to %v", svcName))
		lbSvcIP, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, jsonString).Output()
		e2e.Logf("The %s lb service Ingress VIP in namespace %s is %q", svcName, namespace, lbSvcIP)
		return lbSvcIP, ""
	}
}

// getPodIP returns IPv6 and IPv4 in vars in order on dual stack respectively and main IP in case of single stack (v4 or v6) in 1st var, and nil in 2nd var
func getPodIP(oc *exutil.CLI, namespace string, podName string) (string, string) {
	ipStack := checkIPStackType(oc)
	if (ipStack == "ipv6single") || (ipStack == "ipv4single") {
		podIP, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The pod  %s IP in namespace %s is %q", podName, namespace, podIP)
		return podIP, ""
	} else if ipStack == "dualstack" {
		podIP1, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[1].ip}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The pod's %s 1st IP in namespace %s is %q", podName, namespace, podIP1)
		podIP2, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, podName, "-o=jsonpath={.status.podIPs[0].ip}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The pod's %s 2nd IP in namespace %s is %q", podName, namespace, podIP2)
		if netutils.IsIPv6String(podIP1) {
			e2e.Logf("This is IPv4 primary dual stack cluster")
			return podIP1, podIP2
		}
		e2e.Logf("This is IPv6 primary dual stack cluster")
		return podIP2, podIP1
	}
	return "", ""
}

// CurlPod2PodPass checks connectivity across pods regardless of network addressing type on cluster
func CurlPod2PodPass(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := getPodIP(oc, namespaceDst, podNameDst)
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP2, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlPod2PodFail ensures no connectivity from a pod to pod regardless of network addressing type on cluster
func CurlPod2PodFail(oc *exutil.CLI, namespaceSrc string, podNameSrc string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := getPodIP(oc, namespaceDst, podNameDst)
	if podIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP2, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(podIP1, "8080"))
		o.Expect(err).To(o.HaveOccurred())
	}
}

// CurlNode2PodPass checks node to pod connectivity regardless of network addressing type on cluster
func CurlNode2PodPass(oc *exutil.CLI, nodeName string, namespace string, podName string) {
	//getPodIP returns IPv6 and IPv4 in order on dual stack in PodIP1 and PodIP2 respectively and main IP in case of single stack (v4 or v6) in PodIP1, and nil in PodIP2
	podIP1, podIP2 := getPodIP(oc, namespace, podName)
	if podIP2 != "" {
		podv6URL := net.JoinHostPort(podIP1, "8080")
		podv4URL := net.JoinHostPort(podIP2, "8080")
		_, err := compat_otp.DebugNode(oc, nodeName, "curl", podv4URL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = compat_otp.DebugNode(oc, nodeName, "curl", podv6URL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		podURL := net.JoinHostPort(podIP1, "8080")
		_, err := compat_otp.DebugNode(oc, nodeName, "curl", podURL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlNode2PodFail checks node to pod disconnectivity regardless of network addressing type on cluster
func CurlNode2PodFail(oc *exutil.CLI, nodeName string, namespace string, podName string) {
	//getPodIP returns IPv6 and IPv4 in order on dual stack in PodIP1 and PodIP2 respectively and main IP in case of single stack (v4 or v6) in PodIP1, and nil in PodIP2
	podIP1, podIP2 := getPodIP(oc, namespace, podName)
	if podIP2 != "" {
		podv6URL := net.JoinHostPort(podIP1, "8080")
		podv4URL := net.JoinHostPort(podIP2, "8080")
		_, err := compat_otp.DebugNode(oc, nodeName, "curl", podv4URL, "-s", "--connect-timeout", "5")
		o.Expect(err).To(o.HaveOccurred())
		_, err = compat_otp.DebugNode(oc, nodeName, "curl", podv6URL, "-s", "--connect-timeout", "5")
		o.Expect(err).To(o.HaveOccurred())
	} else {
		podURL := net.JoinHostPort(podIP1, "8080")
		_, err := compat_otp.DebugNode(oc, nodeName, "curl", podURL, "-s", "--connect-timeout", "5")
		o.Expect(err).To(o.HaveOccurred())
	}
}

// CurlNode2SvcPass checks node to svc connectivity regardless of network addressing type on cluster
func CurlNode2SvcPass(oc *exutil.CLI, nodeName string, namespace string, svcName string) {
	svcIP1, svcIP2 := getSvcIP(oc, namespace, svcName)
	if svcIP2 != "" {
		svc6URL := net.JoinHostPort(svcIP1, "27017")
		svc4URL := net.JoinHostPort(svcIP2, "27017")
		_, err := compat_otp.DebugNode(oc, nodeName, "curl", svc4URL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = compat_otp.DebugNode(oc, nodeName, "curl", svc6URL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		svcURL := net.JoinHostPort(svcIP1, "27017")
		_, err := compat_otp.DebugNode(oc, nodeName, "curl", svcURL, "-s", "--connect-timeout", "5")
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlNode2SvcFail checks node to svc connectivity regardless of network addressing type on cluster
func CurlNode2SvcFail(oc *exutil.CLI, nodeName string, namespace string, svcName string) {
	svcIP1, svcIP2 := getSvcIP(oc, namespace, svcName)
	if svcIP2 != "" {
		svc6URL := net.JoinHostPort(svcIP1, "27017")
		svc4URL := net.JoinHostPort(svcIP2, "27017")
		output, _ := compat_otp.DebugNode(oc, nodeName, "curl", svc4URL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("Failed")))
		output, _ = compat_otp.DebugNode(oc, nodeName, "curl", svc6URL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("Failed")))
	} else {
		svcURL := net.JoinHostPort(svcIP1, "27017")
		output, _ := compat_otp.DebugNode(oc, nodeName, "curl", svcURL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("Failed")))
	}
}

// CurlPod2SvcPass checks pod to svc connectivity regardless of network addressing type on cluster
func CurlPod2SvcPass(oc *exutil.CLI, namespaceSrc string, namespaceSvc string, podNameSrc string, svcName string) {
	svcIP1, svcIP2 := getSvcIP(oc, namespaceSvc, svcName)
	if svcIP2 != "" {
		_, err := e2eoutput.RunHostCmdWithRetries(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(svcIP1, "27017"), 3*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmdWithRetries(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(svcIP2, "27017"), 3*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmdWithRetries(namespaceSrc, podNameSrc, "curl --connect-timeout 5 -s "+net.JoinHostPort(svcIP1, "27017"), 3*time.Second, 15*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlPod2SvcFail ensures no connectivity from a pod to svc regardless of network addressing type on cluster
func CurlPod2SvcFail(oc *exutil.CLI, namespaceSrc string, namespaceSvc string, podNameSrc string, svcName string) {
	svcIP1, svcIP2 := getSvcIP(oc, namespaceSvc, svcName)
	if svcIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 3 -s "+net.JoinHostPort(svcIP1, "27017"))
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 3 -s "+net.JoinHostPort(svcIP2, "27017"))
		o.Expect(err).To(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl --connect-timeout 3 -s "+net.JoinHostPort(svcIP1, "27017"))
		o.Expect(err).To(o.HaveOccurred())
	}
}

func checkProxy(oc *exutil.CLI) bool {
	httpProxy, err := doAction(oc, "get", true, true, "proxy", "cluster", "-o=jsonpath={.status.httpProxy}")
	o.Expect(err).NotTo(o.HaveOccurred())
	httpsProxy, err := doAction(oc, "get", true, true, "proxy", "cluster", "-o=jsonpath={.status.httpsProxy}")
	o.Expect(err).NotTo(o.HaveOccurred())
	if httpProxy != "" || httpsProxy != "" {
		return true
	}
	return false
}

// SDNHostwEgressIP find out which egress node has the egressIP
func SDNHostwEgressIP(oc *exutil.CLI, node []string, egressip string) string {
	var ip []string
	var foundHost string
	for i := 0; i < len(node); i++ {
		iplist, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostsubnet", node[i], "-o=jsonpath={.egressIPs}").Output()
		e2e.Logf("iplist for node %v: %v", node, iplist)
		if iplist != "" && iplist != "[]" {
			ip = strings.Split(iplist[2:len(iplist)-2], "\",\"")
		}
		if iplist == "" || iplist == "[]" || err != nil {
			err = wait.Poll(30*time.Second, 3*time.Minute, func() (bool, error) {
				iplist, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("hostsubnet", node[i], "-o=jsonpath={.egressIPs}").Output()
				if iplist != "" && iplist != "[]" {
					e2e.Logf("Found egressIP list for node %v is: %v", node, iplist)
					ip = strings.Split(iplist[2:len(iplist)-2], "\",\"")
					return true, nil
				}
				if err != nil {
					e2e.Logf("only got %d egressIP, or have err:%v, and try next round", len(ip), err)
					return false, nil
				}
				return false, nil
			})
		}
		if isValueInList(egressip, ip) {
			foundHost = node[i]
			break
		}
	}
	return foundHost
}

func isValueInList(value string, list []string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// getPodMultiNetwork is designed to get both v4 and v6 addresses from pod's secondary interface(net1) which is not in the cluster's SDN or OVN network
func getPodMultiNetwork(namespace string, podName string) (string, string) {
	cmd1 := "ip -o -4 addr show dev net1 | awk '$3 == \"inet\" {print $4}' | cut -d'/' -f1"
	cmd2 := "ip -o -6 addr show dev net1 | awk '$3 == \"inet6\" {print $4}' | head -1 | cut -d'/' -f1"
	podIPv4, err := e2eoutput.RunHostCmdWithRetries(namespace, podName, cmd1, 2*time.Second, 10*time.Second)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("pod net1 ipv4 is: %s", podIPv4)
	o.Expect(podIPv4).NotTo(o.BeNil())
	podipv4 := strings.TrimSpace(podIPv4)
	podIPv6, err1 := e2eoutput.RunHostCmdWithRetries(namespace, podName, cmd2, 2*time.Second, 10*time.Second)
	o.Expect(err1).NotTo(o.HaveOccurred())
	e2e.Logf("pod net1 ipv6 is: %s", podIPv6)
	o.Expect(podIPv6).NotTo(o.BeNil())
	podipv6 := strings.TrimSpace(podIPv6)
	e2e.Logf("The v4 address of %s is: %v", podName, podipv4)
	e2e.Logf("The v4 address of %s is: %v", podName, podipv6)
	return podipv4, podipv6
}

// Pinging pod's secondary interfaces should pass
func curlPod2PodMultiNetworkPass(namespaceSrc string, podNameSrc string, podIPv4 string, podIPv6 string) {
	// Poll to check IPv4 connectivity
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		msg, _ := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl  "+podIPv4+":8080  --connect-timeout 5")
		if !strings.Contains(msg, "Hello OpenShift!") {
			e2e.Logf("The curl should pass but fail, and try next round")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Test fail with err:%s", err))

	// Poll to check IPv6 connectivity
	err1 := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		msg1, _ := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -g -6 ["+podIPv6+"]:8080  --connect-timeout 5")
		if !strings.Contains(msg1, "Hello OpenShift!") {
			e2e.Logf("The curl should pass but fail, and try next round")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err1, fmt.Sprintf("Test fail with err:%s", err1))
}

// Pinging pod's secondary interfaces should fail
func curlPod2PodMultiNetworkFail(namespaceSrc string, podNameSrc string, podIPv4 string, podIPv6 string) {
	// Poll to check IPv4 connectivity
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		msg, _ := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl  "+podIPv4+":8080  --connect-timeout 5")
		if strings.Contains(msg, "Hello OpenShift!") {
			e2e.Logf("The curl should fail but pass, and try next round")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Test fail with err:%s", err))

	// Poll to check IPv6 connectivity
	err1 := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		msg1, _ := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -g -6 ["+podIPv6+"]:8080  --connect-timeout 5")
		if strings.Contains(msg1, "Hello OpenShift!") {
			e2e.Logf("The curl should fail but pass, and try next round")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err1, fmt.Sprintf("Test fail with err:%s", err1))
}

// This function is for testing MultiNetwork with IPBlock policy only
func curlPod2PodMultiNetworkIPBlockPass(namespaceSrc string, podNameSrc string, podIPv4 string, podIPv6 string) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		msg, _ := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl  "+podIPv4+":8080  --connect-timeout 5")
		if !strings.Contains(msg, "Hello OpenShift!") {
			e2e.Logf("The curl should pass but fail, and try next round")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Test fail with err:%s", err))
}

// This function is for testing MultiNetwork with IPBlock policy only
func curlPod2PodMultiNetworkIPBlockFail(namespaceSrc string, podNameSrc string, podIPv4 string, podIPv6 string) {
	err := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		msg, _ := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl  "+podIPv4+":8080  --connect-timeout 5")
		if strings.Contains(msg, "Hello OpenShift!") {
			e2e.Logf("The curl should fail but pass, and try next round")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Test fail with err:%s", err))
}

// This function will bring 2 namespaces, 5 pods and 2 NADs for all multus multinetworkpolicy cases
func prepareMultinetworkTest(oc *exutil.CLI, ns1 string, ns2 string, patchInfo string) {
	buildPruningBaseDir := testdata.FixturePath("networking/multinetworkpolicy")
	netAttachDefFile1 := filepath.Join(buildPruningBaseDir, "MultiNetworkPolicy-NAD1.yaml")
	netAttachDefFile2 := filepath.Join(buildPruningBaseDir, "MultiNetworkPolicy-NAD2.yaml")
	pingPodTemplate := filepath.Join(buildPruningBaseDir, "MultiNetworkPolicy-pod-template.yaml")
	patchSResource := "networks.operator.openshift.io/cluster"

	compat_otp.By("Getting the ready-schedulable worker nodes")
	nodeList, nodeErr := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
	o.Expect(nodeErr).NotTo(o.HaveOccurred())
	if len(nodeList.Items) < 1 {
		g.Skip("The cluster has no ready node for the testing")
	}

	compat_otp.By("Enable MacvlanNetworkpolicy in the cluster")
	patchResourceAsAdmin(oc, patchSResource, patchInfo)
	waitForNetworkOperatorState(oc, 10, 5, "True.*True.*False")
	waitForNetworkOperatorState(oc, 60, 15, "True.*False.*False")

	compat_otp.By("Create MultiNetworkPolicy-NAD1 in ns1")
	err1 := oc.AsAdmin().Run("create").Args("-f", netAttachDefFile1, "-n", ns1).Execute()
	o.Expect(err1).NotTo(o.HaveOccurred())
	output, err2 := oc.AsAdmin().Run("get").Args("net-attach-def", "-n", ns1).Output()
	o.Expect(err2).NotTo(o.HaveOccurred())
	o.Expect(output).To(o.ContainSubstring("macvlan-nad1"))

	compat_otp.By("Create 1st pod in ns1")
	pod1ns1 := testPodMultinetwork{
		name:      "blue-pod-1",
		namespace: ns1,
		nodename:  nodeList.Items[0].Name,
		nadname:   "macvlan-nad1",
		labelname: "blue-openshift",
		template:  pingPodTemplate,
	}
	pod1ns1.createTestPodMultinetwork(oc)
	waitPodReady(oc, pod1ns1.namespace, pod1ns1.name)

	compat_otp.By("Create second pod in ns1")
	pod2ns1 := testPodMultinetwork{
		name:      "blue-pod-2",
		namespace: ns1,
		nodename:  nodeList.Items[1].Name,
		nadname:   "macvlan-nad1",
		labelname: "blue-openshift",
		template:  pingPodTemplate,
	}
	pod2ns1.createTestPodMultinetwork(oc)
	waitPodReady(oc, pod2ns1.namespace, pod2ns1.name)

	compat_otp.By("Create third pod in ns1")
	pod3ns1 := testPodMultinetwork{
		name:      "red-pod-1",
		namespace: ns1,
		nodename:  nodeList.Items[0].Name,
		nadname:   "macvlan-nad1",
		labelname: "red-openshift",
		template:  pingPodTemplate,
	}
	pod3ns1.createTestPodMultinetwork(oc)
	waitPodReady(oc, pod3ns1.namespace, pod3ns1.name)

	compat_otp.By("Create MultiNetworkPolicy-NAD2 in ns2")
	err4 := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", netAttachDefFile2, "-n", ns2).Execute()
	o.Expect(err4).NotTo(o.HaveOccurred())
	output, err5 := oc.AsAdmin().Run("get").Args("net-attach-def", "-n", ns2).Output()
	o.Expect(err5).NotTo(o.HaveOccurred())
	o.Expect(output).To(o.ContainSubstring("macvlan-nad2"))

	compat_otp.By("Create 1st pod in ns2")
	pod1ns2 := testPodMultinetwork{
		name:      "blue-pod-3",
		namespace: ns2,
		nodename:  nodeList.Items[0].Name,
		nadname:   "macvlan-nad2",
		labelname: "blue-openshift",
		template:  pingPodTemplate,
	}
	pod1ns2.createTestPodMultinetwork(oc)
	waitPodReady(oc, pod1ns2.namespace, pod1ns2.name)

	compat_otp.By("Create second pod in ns2")
	pod2ns2 := testPodMultinetwork{
		name:      "red-pod-2",
		namespace: ns2,
		nodename:  nodeList.Items[0].Name,
		nadname:   "macvlan-nad2",
		labelname: "red-openshift",
		template:  pingPodTemplate,
	}
	pod2ns2.createTestPodMultinetwork(oc)
	waitPodReady(oc, pod2ns2.namespace, pod2ns2.name)
}

// check if an ip address is added to node's NIC, or removed from node's NIC
func checkPrimaryNIC(oc *exutil.CLI, nodeName string, ip string, flag bool) {
	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		output, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", "/usr/sbin/ip -4 -brief address show")
		if err != nil {
			e2e.Logf("Cannot get primary NIC interface, errors: %v, try again", err)
			return false, nil
		}
		if flag && !strings.Contains(output, ip) {
			e2e.Logf("egressIP has not been added to node's NIC correctly, try again")
			return false, nil
		}
		if !flag && strings.Contains(output, ip) {
			e2e.Logf("egressIP has not been removed from node's NIC correctly, try again")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Failed to get NIC on the host:%s", checkErr))
}

func checkEgressIPonSDNHost(oc *exutil.CLI, node string, expectedEgressIP []string) {
	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		ip, err := getEgressIPByKind(oc, "hostsubnet", node, len(expectedEgressIP))
		if err != nil {
			e2e.Logf("\n got the error: %v\n, try again", err)
			return false, nil
		}
		if !unorderedEqual(ip, expectedEgressIP) {
			e2e.Logf("\n got egressIP as %v while expected egressIP is %v, try again", ip, expectedEgressIP)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Failed to get egressIP on the host:%s", checkErr))
}

func unorderedEqual(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for _, value := range first {
		if !contains(second, value) {
			return false
		}
	}
	return true
}

func checkovnkubeMasterNetworkProgrammingetrics(oc *exutil.CLI, url string, metrics string) {
	var metricsOutput []byte
	olmToken, err := compat_otp.GetSAToken(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(olmToken).NotTo(o.BeEmpty())
	metricsErr := wait.Poll(5*time.Second, 10*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "-c", "prometheus", "prometheus-k8s-0", "--", "curl", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", olmToken), fmt.Sprintf("%s", url)).OutputToFile("metrics.txt")
		if err != nil {
			e2e.Logf("Can't get metrics and try again, the error is:%s", err)
			return false, nil
		}
		metricsOutput, _ = exec.Command("bash", "-c", "cat "+output+" | grep "+metrics+" | awk 'NR==2{print $2}'").Output()
		metricsValue := strings.TrimSpace(string(metricsOutput))
		if metricsValue != "" {
			e2e.Logf("The output of the metrics for %s is : %v", metrics, metricsValue)
		} else {
			e2e.Logf("Can't get metrics for %s:", metrics)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(metricsErr, fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
}

func getControllerManagerLeaderIP(oc *exutil.CLI) string {
	leaderPodName, leaderErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("lease", "openshift-master-controllers", "-n", "openshift-controller-manager", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(leaderErr).NotTo(o.HaveOccurred())
	o.Expect(leaderPodName).ShouldNot(o.BeEmpty(), "leader pod name is empty")
	e2e.Logf("The leader pod name is %s", leaderPodName)
	leaderPodIP := getPodIPv4(oc, "openshift-controller-manager", leaderPodName)
	return leaderPodIP
}

func describeCheckEgressIPByKind(oc *exutil.CLI, kind string, kindName string) string {
	output, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args(kind, kindName).Output()

	o.Expect(err).NotTo(o.HaveOccurred())
	egressIPReg, _ := regexp.Compile(".*Egress IPs.*")
	egressIPStr := egressIPReg.FindString(output)
	egressIPArr := strings.Split(egressIPStr, ":")

	//remove whitespace in front of the ip address
	ip := strings.TrimSpace(egressIPArr[1])
	e2e.Logf("get egressIP from oc describe %v %v: --->%s<---", kind, kindName, ip)
	return ip
}

func findUnUsedIPsOnNodeOrFail(oc *exutil.CLI, nodeName, cidr string, expectedNum int) []string {
	freeIPs := findUnUsedIPsOnNode(oc, nodeName, cidr, expectedNum)
	if len(freeIPs) != expectedNum {
		g.Skip("Did not get enough free IPs for the test, skip the test.")
	}
	return freeIPs
}

func (pod *externalIPPod) createExternalIPPod(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplate(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create the externalIP pod %v", pod.name))
}

func checkParameter(oc *exutil.CLI, namespace string, kind string, kindName string, parameter string) string {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", namespace, kind, kindName, parameter).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return output
}

func patchReplaceResourceAsAdmin(oc *exutil.CLI, resource, patch string, nameSpace ...string) {
	var cargs []string
	if len(nameSpace) > 0 {
		cargs = []string{resource, "-p", patch, "-n", nameSpace[0], "--type=json"}
	} else {
		cargs = []string{resource, "-p", patch, "--type=json"}
	}
	err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(cargs...).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

// For SingleStack function returns IPv6 or IPv4 hostsubnet in case OVN
// For SDN plugin returns only IPv4 hostsubnet
// Dual stack not supported on openshiftSDN
// IPv6 single stack not supported on openshiftSDN
// network can be "default" for the default network or  UDN network name
func getNodeSubnet(oc *exutil.CLI, nodeName string, network string) string {

	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.k8s\\.ovn\\.org/node-subnets}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	var data map[string]interface{}
	json.Unmarshal([]byte(output), &data)
	hostSubnets := data[network].([]interface{})
	hostSubnet := hostSubnets[0].(string)
	return hostSubnet

}

func getNodeSubnetDualStack(oc *exutil.CLI, nodeName string, network string) (string, string) {

	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.k8s\\.ovn\\.org/node-subnets}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("output is %v", output)
	var data map[string]interface{}
	json.Unmarshal([]byte(output), &data)
	hostSubnets := data[network].([]interface{})
	hostSubnetIPv4 := hostSubnets[0].(string)
	hostSubnetIPv6 := hostSubnets[1].(string)

	e2e.Logf("Host subnet is %v and %v", hostSubnetIPv4, hostSubnetIPv6)

	return hostSubnetIPv4, hostSubnetIPv6
}

func getIPv4Capacity(oc *exutil.CLI, nodeName string) string {
	ipv4Capacity := ""
	egressIPConfig, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.cloud\\.network\\.openshift\\.io/egress-ipconfig}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The egressipconfig is %v \n", egressIPConfig)
	switch compat_otp.CheckPlatform(oc) {
	case "aws":
		ipv4Capacity = strings.Split(strings.Split(egressIPConfig, ":")[5], ",")[0]
	case "gcp":
		ipv4Capacity = strings.Split(egressIPConfig, ":")[5]
		ipv4Capacity = ipv4Capacity[:len(ipv4Capacity)-3]
	default:
		e2e.Logf("Not support cloud provider for auto egressip cases for now.")
		g.Skip("Not support cloud provider for auto egressip cases for now.")
	}

	return ipv4Capacity
}

func (aclSettings *aclSettings) getJSONString() string {
	jsonACLSetting, _ := json.Marshal(aclSettings)
	annotationString := "k8s.ovn.org/acl-logging=" + string(jsonACLSetting)
	return annotationString
}

func enableACLOnNamespace(oc *exutil.CLI, namespace, denyLevel, allowLevel string) {
	e2e.Logf("Enable ACL looging on the namespace %s", namespace)
	aclSettings := aclSettings{DenySetting: denyLevel, AllowSetting: allowLevel}
	err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("--overwrite", "ns", namespace, aclSettings.getJSONString()).Execute()
	o.Expect(err1).NotTo(o.HaveOccurred())
}

func disableACLOnNamespace(oc *exutil.CLI, namespace string) {
	e2e.Logf("Disable ACL looging on the namespace %s", namespace)
	err1 := oc.AsAdmin().WithoutNamespace().Run("annotate").Args("ns", namespace, "k8s.ovn.org/acl-logging-").Execute()
	o.Expect(err1).NotTo(o.HaveOccurred())
}

func getNodeMacAddress(oc *exutil.CLI, nodeName string) string {
	var macAddress string
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.k8s\\.ovn\\.org/l3-gateway-config}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	var data map[string]interface{}
	json.Unmarshal([]byte(output), &data)
	l3GatewayConfigAnnotations := data["default"].(interface{})
	l3GatewayConfigAnnotationsJSON := l3GatewayConfigAnnotations.(map[string]interface{})
	macAddress = l3GatewayConfigAnnotationsJSON["mac-address"].(string)
	return macAddress

}

// check if an env is in a configmap in specific namespace [usage: checkConfigMap(oc, namesapce, configmapName, envString)]
func checkEnvInConfigMap(oc *exutil.CLI, ns, configmapName string, envString string) error {
	err := checkConfigMap(oc, ns, configmapName)
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("cm %v is not found in namespace %v", configmapName, ns))

	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("configmap", "-n", ns, configmapName, "-oyaml").Output()
		if err != nil {
			e2e.Logf("Failed to get configmap %v, error: %s. Trying again", configmapName, err)
			return false, nil
		}
		if !strings.Contains(output, envString) {
			e2e.Logf("Did not find %v in ovnkube-config configmap,try next round.", envString)
			return false, nil
		}
		return true, nil
	})
	return checkErr
}

// check if certain log message is in a pod in specific namespace
func checkLogMessageInPod(oc *exutil.CLI, namespace string, containerName string, podName string, filter string) (string, error) {
	var podLogs string
	var err, checkErr error
	checkErr = wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		podLogs, err = compat_otp.GetSpecificPodLogsCombinedOrNot(oc, namespace, containerName, podName, filter, true)
		if len(podLogs) == 0 || err != nil {
			e2e.Logf("did not get expected podLogs: %v, or have err:%v, try again", podLogs, err)
			return false, nil
		}
		return true, nil
	})
	if checkErr != nil {
		return podLogs, fmt.Errorf(fmt.Sprintf("fail to get expected log in pod %v, err: %v", podName, err))
	}
	return podLogs, nil
}

// get OVN-Kubernetes management interface (ovn-k8s-mp0) IP for the node
func getOVNK8sNodeMgmtIPv4(oc *exutil.CLI, nodeName string) string {
	var output string
	var err error
	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		output, err = compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", "/usr/sbin/ip -4 -brief address show | grep ovn-k8s-mp0")
		if output == "" || err != nil {
			e2e.Logf("Did not get node's management interface, errors: %v, try again", err)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("fail to get management interface for node %v, err: %v", nodeName, checkErr))

	e2e.Logf("Match out the OVN-Kubernetes management IP address for the node")
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	nodeOVNK8sMgmtIP := re.FindAllString(output, -1)[0]
	e2e.Logf("Got ovn-k8s management interface IP for node %v as: %v", nodeName, nodeOVNK8sMgmtIP)
	return nodeOVNK8sMgmtIP
}

// findLogFromPod will search logs for a specific string in the specific container of the pod or just the pod
func findLogFromPod(oc *exutil.CLI, searchString string, namespace string, podLabel string, podContainer ...string) bool {
	findLog := false
	podNames := getPodName(oc, namespace, podLabel)
	var cargs []string
	for _, podName := range podNames {
		if len(podContainer) > 0 {
			cargs = []string{podName, "-c", podContainer[0], "-n", namespace}
		} else {
			cargs = []string{podName, "-n", namespace}
		}
		output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args(cargs...).OutputToFile("podlog")
		o.Expect(err).NotTo(o.HaveOccurred())
		grepOutput, err := exec.Command("bash", "-c", "cat "+output+" | grep -i '"+searchString+"' | wc -l").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		grepOutputString := strings.TrimSpace(string(grepOutput))
		if grepOutputString != "0" {
			e2e.Logf("Found the '%s' string in %s number of lines.", searchString, grepOutputString)
			findLog = true
			break
		}
	}
	return findLog
}

// searchOVNDBForSpecCmd This is used for lr-policy-list and snat rules check in ovn db.
func searchOVNDBForSpecCmd(oc *exutil.CLI, cmd, searchKeyword string, times int) error {
	ovnPod := getOVNKMasterOVNkubeNode(oc)
	o.Expect(ovnPod).ShouldNot(o.Equal(""))
	var cmdOutput string
	checkOVNDbErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
		output, cmdErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, cmd)
		if cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try next ...,", cmdErr)
			return false, nil
		}
		cmdOutput = output
		if strings.Count(output, searchKeyword) == times {
			return true, nil
		}
		return false, nil
	})
	if checkOVNDbErr != nil {
		e2e.Logf("The command check result in ovndb is not expected ! See below output \n %s ", cmdOutput)
	}
	return checkOVNDbErr
}

// waitEgressFirewallApplied Wait egressfirewall applied
func waitEgressFirewallApplied(oc *exutil.CLI, efName, ns string) error {
	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		output, efErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", "-n", ns, efName).Output()
		if efErr != nil {
			e2e.Logf("Failed to get egressfirewall %v, error: %s. Trying again", efName, efErr)
			return false, nil
		}
		if !strings.Contains(output, "EgressFirewall Rules applied") {
			e2e.Logf("The egressfirewall was not applied, trying again. \n %s", output)
			return false, nil
		}
		return true, nil
	})
	return checkErr
}

// switchOVNGatewayMode will switch to requested mode, shared or local
func switchOVNGatewayMode(oc *exutil.CLI, mode string) {
	currentMode := getOVNGatewayMode(oc)
	if currentMode == "local" && mode == "shared" {
		e2e.Logf("Migrating cluster to shared gateway mode")
		patchResourceAsAdmin(oc, "network.operator/cluster", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"gatewayConfig\":{\"routingViaHost\": false}}}}}")
	} else if currentMode == "shared" && mode == "local" {
		e2e.Logf("Migrating cluster to Local gw mode")
		patchResourceAsAdmin(oc, "network.operator/cluster", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"gatewayConfig\":{\"routingViaHost\": true}}}}}")
	} else {
		e2e.Logf("Cluster is already on requested gateway mode")
	}
	_, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", "openshift-ovn-kubernetes", "ds", "ovnkube-node").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	//on OVN IC it takes upto 660 seconds for nodes ds to rollout so lets poll with timeout of 700 seconds
	waitForNetworkOperatorState(oc, 100, 18, "True.*False.*False")
}

// getOVNGatewayMode will return configured OVN gateway mode, shared or local
func getOVNGatewayMode(oc *exutil.CLI) string {
	nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
	o.Expect(err).NotTo(o.HaveOccurred())
	if len(nodeList.Items) < 1 {
		g.Skip("This case requires at least one schedulable node")
	}
	output, err := oc.AsAdmin().WithoutNamespace().NotShowInfo().Run("describe").Args("node", nodeList.Items[0].Name).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	str := "local"
	modeString := strconv.Quote(str)
	if strings.Contains(output, modeString) {
		e2e.Logf("Cluster is running on OVN Local Gateway Mode")
		return str
	}
	return "shared"
}

func getEgressCIDRsForNode(oc *exutil.CLI, nodeName string) string {
	var sub1 string
	platform := compat_otp.CheckPlatform(oc)
	if strings.Contains(platform, "vsphere") || strings.Contains(platform, "baremetal") || strings.Contains(platform, "none") || strings.Contains(platform, "nutanix") || strings.Contains(platform, "powervs") {
		defaultSubnetV4, err := getDefaultSubnet(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		_, ipNet, err1 := net.ParseCIDR(defaultSubnetV4)
		o.Expect(err1).NotTo(o.HaveOccurred())
		e2e.Logf("ipnet: %v", ipNet)
		sub1 = ipNet.String()
		e2e.Logf("\n\n\n sub1 as -->%v<--\n\n\n", sub1)
	} else {
		sub1 = getIfaddrFromNode(nodeName, oc)
	}
	return sub1
}

// get routerID by node name
func getRouterID(oc *exutil.CLI, nodeName string) (string, error) {
	// get the ovnkube-node pod on the node
	ovnKubePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	o.Expect(ovnKubePod).ShouldNot(o.Equal(""))
	var cmdOutput, routerName, routerID string
	var cmdErr error
	routerName = "GR_" + nodeName
	cmd := "ovn-nbctl show | grep " + routerName + " | grep 'router '|awk '{print $2}'"
	checkOVNDbErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
		cmdOutput, cmdErr = compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnKubePod, cmd)
		if cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try again ...,", cmdErr)
			return false, nil
		}

		// Command output always has first line as: Defaulted container "northd" out of: northd, nbdb, kube-rbac-proxy, sbdb, ovnkube-master, ovn-dbchecker
		// Take result from the second line
		cmdOutputLines := strings.Split(cmdOutput, "\n")
		if len(cmdOutputLines) >= 2 {
			routerID = cmdOutputLines[1]
			return true, nil
		}
		e2e.Logf("%v,Waiting for expected result to be synced, try again ...,")
		return false, nil
	})
	if checkOVNDbErr != nil {
		e2e.Logf("The command check result in ovndb is not expected ! See below output \n %s ", cmdOutput)
	}
	return routerID, checkOVNDbErr
}

func getSNATofEgressIP(oc *exutil.CLI, nodeName, egressIP string) ([]string, error) {
	// get the ovnkube-node pod on the node
	ovnKubePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	o.Expect(ovnKubePod).ShouldNot(o.Equal(""))
	var cmdOutput string
	var cmdErr error
	var snatIP []string

	cmd := "ovn-nbctl --no-headings --column logical_ip --format=table find nat external_ip=" + egressIP
	checkOVNDbErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
		cmdOutput, cmdErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubePod, "northd", cmd)
		if cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try again ...,", cmdErr)
			return false, nil
		}

		if cmdOutput != "" {
			cmdOutputLines := strings.Split(cmdOutput, "\n")
			for i := 0; i < len(cmdOutputLines); i++ {
				ip := strings.Trim(cmdOutputLines[i], "\"")
				snatIP = append(snatIP, ip)
			}
			return true, nil
		}

		e2e.Logf("Waiting for expected result to be synced, try again ...")
		return false, nil
	})
	if checkOVNDbErr != nil {
		e2e.Logf("The command check result in ovndb is not expected ! See below output \n %s ", cmdOutput)
	}
	return snatIP, checkOVNDbErr
}

// enableSCTPModuleOnNode Manual way to enable sctp in a cluster
func enableSCTPModuleOnNode(oc *exutil.CLI, nodeName, role string) {
	e2e.Logf("This is %s worker node: %s", role, nodeName)
	checkSCTPCmd := "cat /sys/module/sctp/initstate"
	output, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", checkSCTPCmd)
	var installCmd string
	if err != nil || !strings.Contains(output, "live") {
		e2e.Logf("No sctp module installed, will enable sctp module!!!")
		installCmd = "modprobe sctp"
		e2e.Logf("Install command is %s", installCmd)

		// Try 3 times to enable sctp
		o.Eventually(func() error {
			_, installErr := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", installCmd)
			if installErr != nil && strings.EqualFold(role, "rhel") {
				e2e.Logf("%v", installErr)
				g.Skip("Yum insall to enable sctp cannot work in a disconnected cluster, skip the test!!!")
			}
			return installErr
		}, "15s", "5s").ShouldNot(o.HaveOccurred(), fmt.Sprintf("Failed to install sctp module on node %s", nodeName))

		// Wait for sctp applied
		o.Eventually(func() string {
			output, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", checkSCTPCmd)
			if err != nil {
				e2e.Logf("Wait for sctp applied, %v", err)
			}
			return output
		}, "60s", "10s").Should(o.ContainSubstring("live"), fmt.Sprintf("Failed to load sctp module on node %s", nodeName))
	} else {
		e2e.Logf("sctp module is loaded on node %s\n%s", nodeName, output)
	}

}

func prepareSCTPModule(oc *exutil.CLI, sctpModule string) {
	nodesOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(nodesOutput, "SchedulingDisabled") || strings.Contains(nodesOutput, "NotReady") {
		g.Skip("There are already some nodes in NotReady or SchedulingDisabled status in cluster, skip the test!!! ")
	}

	nodes, err := compat_otp.GetSchedulableLinuxWorkerNodes(oc)
	if err != nil || len(nodes) < 1 {
		g.Skip("Can not find any woker nodes in the cluster")
	}

	for _, worker := range nodes {
		enableSCTPModuleOnNode(oc, worker.Name, "rhcos")
	}

}

// getIPv4Gateway get ipv4 gateway address
func getIPv4Gateway(oc *exutil.CLI, nodeName string) string {
	cmd := "ip -4 route | grep default | awk '{print $3}'"
	output, err := compat_otp.DebugNode(oc, nodeName, "bash", "-c", cmd)
	o.Expect(err).NotTo(o.HaveOccurred())
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	ips := re.FindAllString(output, -1)
	if len(ips) == 0 {
		return ""
	}
	e2e.Logf("The default gateway of node %s is %s", nodeName, ips[0])
	return ips[0]
}

// getInterfacePrefix return the prefix of the primary interface IP
func getInterfacePrefix(oc *exutil.CLI, nodeName string) string {
	defInf, err := getDefaultInterface(oc)
	o.Expect(err).NotTo(o.HaveOccurred())
	cmd := fmt.Sprintf("ip -4 -brief a show %s | awk '{print $3}' ", defInf)
	output, err := compat_otp.DebugNode(oc, nodeName, "bash", "-c", cmd)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("IP address for default interface %s is %s", defInf, output)
	sli := strings.Split(output, "/")
	if len(sli) > 0 {
		return strings.Split(sli[1], "\n")[0]
	}
	return "24"
}

func excludeSriovNodes(oc *exutil.CLI) []string {
	// In rdu1 and rdu2 clusters, there are two sriov nodes with mlx nic, by default, egressrouter case cannot run on it
	// So here exclude sriov nodes in rdu1 and rdu2 clusters, just use the other common worker nodes
	var workers []string
	nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, node := range nodeList.Items {
		_, ok := node.Labels["node-role.kubernetes.io/sriov"]
		if !ok {
			e2e.Logf("node %s is not sriov node,add it to worker list.", node.Name)
			workers = append(workers, node.Name)
		}
	}
	return workers
}

func getSriovNodes(oc *exutil.CLI) []string {
	// In rdu1 and rdu2 clusters, there are two sriov nodes with mlx nic
	var workers string
	workers, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/sriov", "--no-headers", "-o=custom-columns=NAME:.metadata.name").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return strings.Split(workers, "\n")
}

func checkClusterStatus(oc *exutil.CLI, expectedStatus string) {
	// get all master nodes
	masterNodes, getAllMasterNodesErr := compat_otp.GetClusterNodesBy(oc, "master")
	o.Expect(getAllMasterNodesErr).NotTo(o.HaveOccurred())
	o.Expect(masterNodes).NotTo(o.BeEmpty())

	// check master nodes status, expect Ready status for them
	for _, masterNode := range masterNodes {
		checkNodeStatus(oc, masterNode, "Ready")
	}

	// get all worker nodes
	workerNodes, getAllWorkerNodesErr := compat_otp.GetClusterNodesBy(oc, "worker")
	o.Expect(getAllWorkerNodesErr).NotTo(o.HaveOccurred())
	o.Expect(workerNodes).NotTo(o.BeEmpty())

	// check worker nodes status, expect Ready status for them
	for _, workerNode := range masterNodes {
		checkNodeStatus(oc, workerNode, "Ready")
	}
}

func getOVNKCtrlPlanePodOnHostedCluster(oc *exutil.CLI, namespace, cmName, hyperShiftMgmtNS string) string {
	// get leader ovnkube-control-plane pod on hypershift hosted cluster
	ovnkCtrlPlanePodLead, leaderErr := oc.AsGuestKubeconf().Run("get").Args("lease", "ovn-kubernetes-master", "-n", "openshift-ovn-kubernetes", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(leaderErr).NotTo(o.HaveOccurred())
	e2e.Logf("ovnkube-control-plane pod of the hosted cluster is %s", ovnkCtrlPlanePodLead)
	return ovnkCtrlPlanePodLead
}

func waitForPodWithLabelReadyOnHostedCluster(oc *exutil.CLI, ns, label string) error {
	return wait.Poll(15*time.Second, 10*time.Minute, func() (bool, error) {
		status, err := oc.AsAdmin().AsGuestKubeconf().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label, "-ojsonpath={.items[*].status.conditions[?(@.type==\"Ready\")].status}").Output()
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

func getPodNameOnHostedCluster(oc *exutil.CLI, namespace, label string) []string {
	var podName []string
	podNameAll, err := oc.AsAdmin().AsGuestKubeconf().Run("get").Args("-n", namespace, "pod", "-l", label, "-ojsonpath={.items..metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	podName = strings.Split(podNameAll, " ")
	e2e.Logf("The pod(s) are  %v ", podName)
	return podName
}

func getReadySchedulableNodesOnHostedCluster(oc *exutil.CLI) ([]string, error) {
	output, err := oc.AsAdmin().AsGuestKubeconf().Run("get").Args("node", "-ojsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	var nodesOnHostedCluster, schedulableNodes []string
	nodesOnHostedCluster = strings.Split(output, " ")
	for _, nodeName := range nodesOnHostedCluster {
		err := wait.Poll(10*time.Second, 15*time.Minute, func() (bool, error) {
			statusOutput, err := oc.AsAdmin().AsGuestKubeconf().Run("get").Args("nodes", nodeName, "-ojsonpath={.status.conditions[-1].status}").Output()
			if err != nil {
				e2e.Logf("\nGet node status with error : %v", err)
				return false, nil
			}
			if statusOutput != "True" {
				return false, nil
			}
			schedulableNodes = append(schedulableNodes, nodeName)
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Node %s is not in expected status %s", nodeName, "Ready"))
	}
	e2e.Logf("Scheduleable nodes on hosted cluster are:  %v ", schedulableNodes)
	return schedulableNodes, nil
}

func checkLogMessageInPodOnHostedCluster(oc *exutil.CLI, namespace string, containerName string, podName string, filter string) (string, error) {
	var podLogs string
	var err, checkErr error
	checkErr = wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		podLogs, err = compat_otp.GetSpecificPodLogs(oc.AsAdmin().AsGuestKubeconf(), namespace, containerName, podName, filter)
		if len(podLogs) == 0 || err != nil {
			e2e.Logf("did not get expected podLog: %v, or have err:%v, try again", podLogs, err)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("fail to get expected log in pod %v, err: %v", podName, checkErr))
	return podLogs, nil

}

// get OVN-Kubernetes management interface (ovn-k8s-mp0) IP for the node on hosted cluster
func getOVNK8sNodeMgmtIPv4OnHostedCluster(oc *exutil.CLI, nodeName string) string {
	var output string
	var outputErr error
	defer compat_otp.RecoverNamespaceRestricted(oc.AsGuestKubeconf(), "default")
	compat_otp.SetNamespacePrivileged(oc.AsGuestKubeconf(), "default")
	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		output, outputErr = oc.AsGuestKubeconf().WithoutNamespace().Run("debug").Args("-n", "default", "node/"+nodeName, "--", "chroot", "/host", "bash", "-c", "/usr/sbin/ip -4 -brief address show | grep ovn-k8s-mp0").Output()
		if output == "" || outputErr != nil {
			e2e.Logf("Did not get node's management interface on hosted cluster, errors: %v, try again", outputErr)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("fail to get management interface for node %v, err: %v", nodeName, checkErr))

	e2e.Logf("Match out the OVN-Kubernetes management IP address for the node on hosted cluster")
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	nodeOVNK8sMgmtIPOnHostedCluster := re.FindAllString(output, -1)[0]
	e2e.Logf("Got ovn-k8s management interface IP for node on hosted cluster %v as: %v", nodeName, nodeOVNK8sMgmtIPOnHostedCluster)
	return nodeOVNK8sMgmtIPOnHostedCluster
}

// execute command on debug node with chroot on node of hosted cluster
func execCmdOnDebugNodeOfHostedCluster(oc *exutil.CLI, nodeName string, cmdOptions []string) error {
	cargs := []string{"node/" + nodeName, "--", "chroot", "/host"}
	if len(cmdOptions) > 0 {
		cargs = append(cargs, cmdOptions...)
	}

	debugErr := oc.AsGuestKubeconf().WithoutNamespace().Run("debug").Args(cargs...).Execute()

	return debugErr
}

// check the cronjobs in the openshift-multus namespace
func getMultusCronJob(oc *exutil.CLI) string {
	cronjobLog, cronjobErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("cronjobs", "-n", "openshift-multus").Output()
	o.Expect(cronjobErr).NotTo(o.HaveOccurred())
	return cronjobLog
}

// get name of OVN egressIP object(s)
func getOVNEgressIPObject(oc *exutil.CLI) []string {
	var egressIPObjects = []string{}
	egressIPObjectsAll, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressip", "-ojsonpath={.items..metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if len(egressIPObjectsAll) > 0 {
		egressIPObjects = strings.Split(egressIPObjectsAll, " ")
	}
	e2e.Logf("egressIPObjects are  %v ", egressIPObjects)
	return egressIPObjects
}

// Pod's seconary interface can be assigned with ipv4 only, ipv6 only or dualstack address. getPodMultiNetwork can get ipv4 only and dualstack address but not ipv6 only address
// getPodMultiNetworkIPv6 will defined to get ipv6 only address.
func getPodMultiNetworkIPv6(oc *exutil.CLI, namespace string, podName string) string {
	cmd1 := "ip a sho net1 | awk 'NR==3{print $2}' |grep -Eo '([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}'"
	podIPv6, err1 := e2eoutput.RunHostCmd(namespace, podName, cmd1)
	o.Expect(err1).NotTo(o.HaveOccurred())
	MultiNetworkIPv6 := strings.TrimSpace(podIPv6)
	return MultiNetworkIPv6
}

// get node that hosts the egressIP
func getHostsubnetByEIP(oc *exutil.CLI, expectedEIP string) string {
	var nodeHostsEIP string
	nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
	o.Expect(err).NotTo(o.HaveOccurred())

	for i, v := range nodeList.Items {
		ip, err := getEgressIPByKind(oc, "hostsubnet", nodeList.Items[i].Name, 1)
		o.Expect(err).NotTo(o.HaveOccurred())
		if ip[0] == expectedEIP {
			e2e.Logf("Found node %v host egressip %v ", v.Name)
			nodeHostsEIP = nodeList.Items[i].Name
			break
		}
	}
	return nodeHostsEIP
}

// find the ovn-K cluster manager master pod
func getOVNKMasterPod(oc *exutil.CLI) string {
	leaderCtrlPlanePod, leaderNodeLogerr := oc.AsAdmin().WithoutNamespace().Run("get").Args("lease", "ovn-kubernetes-master", "-n", "openshift-ovn-kubernetes", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(leaderNodeLogerr).NotTo(o.HaveOccurred())
	return leaderCtrlPlanePod
}

// find the cluster-manager's ovnkube-node for accessing master components
func getOVNKMasterOVNkubeNode(oc *exutil.CLI) string {
	leaderPod, leaderNodeLogerr := oc.AsAdmin().WithoutNamespace().Run("get").Args("lease", "ovn-kubernetes-master", "-n", "openshift-ovn-kubernetes", "-o=jsonpath={.spec.holderIdentity}").Output()
	o.Expect(leaderNodeLogerr).NotTo(o.HaveOccurred())
	leaderNodeName, getNodeErr := compat_otp.GetPodNodeName(oc, "openshift-ovn-kubernetes", leaderPod)
	o.Expect(getNodeErr).NotTo(o.HaveOccurred())
	ovnKubePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", leaderNodeName)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	return ovnKubePod
}

// enable multicast on specific namespace
func enableMulticast(oc *exutil.CLI, ns string) {
	_, err := runOcWithRetry(oc.AsAdmin().WithoutNamespace(), "annotate", "namespace", ns, "k8s.ovn.org/multicast-enabled=true")
	o.Expect(err).NotTo(o.HaveOccurred())
}

func getCNOStatusCondition(oc *exutil.CLI) string {
	CNOStatusCondition, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("clusteroperators", "network", "-o=jsonpath={.status.conditions}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	return CNOStatusCondition
}

// return severity, expr and runbook of specific ovn alert in networking-rules
func getOVNAlertNetworkingRules(oc *exutil.CLI, alertName string) (string, string, string) {
	// get all ovn alert names in networking-rules
	ns := "openshift-ovn-kubernetes"
	allAlerts, nameErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", ns, "networking-rules", "-o=jsonpath={.spec.groups[*].rules[*].alert}").Output()
	o.Expect(nameErr).NotTo(o.HaveOccurred())
	e2e.Logf("The alert are %v", allAlerts)

	if !strings.Contains(allAlerts, alertName) {
		e2e.Failf("Target alert %v is not found", alertName)
		return "", "", ""
	} else {
		var severity, expr string
		severity, severityErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", ns, "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\""+alertName+"\")].labels.severity}").Output()
		o.Expect(severityErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alert severity is %v", severity)
		expr, exprErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", ns, "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\""+alertName+"\")].expr}").Output()
		o.Expect(exprErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alert expr is %v", expr)
		runbook, runbookErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", ns, "networking-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\""+alertName+"\")].annotations.runbook_url}").Output()
		o.Expect(runbookErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alert runbook is %v", runbook)

		return severity, expr, runbook
	}
}

// return severity, expr and runbook of specific ovn alert in master-rules
func getOVNAlertMasterRules(oc *exutil.CLI, alertName string) (string, string, string) {
	// get all ovn alert names in networking-rules
	ns := "openshift-ovn-kubernetes"
	allAlerts, nameErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", ns, "master-rules", "-o=jsonpath={.spec.groups[*].rules[*].alert}").Output()
	o.Expect(nameErr).NotTo(o.HaveOccurred())
	e2e.Logf("The alert are %v", allAlerts)

	if !strings.Contains(allAlerts, alertName) {
		e2e.Failf("Target alert %v is not found", alertName)
		return "", "", ""
	} else {
		var severity, expr string
		severity, severityErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", ns, "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\""+alertName+"\")].labels.severity}").Output()
		o.Expect(severityErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alert severity is %v", severity)
		expr, exprErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", ns, "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\""+alertName+"\")].expr}").Output()
		o.Expect(exprErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alert expr is %v", expr)
		runbook, runbookErr := oc.AsAdmin().Run("get").Args("prometheusrule", "-n", ns, "master-rules", "-o=jsonpath={.spec.groups[*].rules[?(@.alert==\""+alertName+"\")].annotations.runbook_url}").Output()
		o.Expect(runbookErr).NotTo(o.HaveOccurred())
		e2e.Logf("The alert runbook is %v", runbook)

		return severity, expr, runbook
	}
}

// returns all the logical routers and switches on all the nodes
func getOVNConstructs(oc *exutil.CLI, constructType string, nodeNames []string) []string {
	var ovnConstructs []string
	var matchStr string
	//var cmdOutput string

	getCmd := "ovn-nbctl --no-leader-only " + constructType
	ovnPod := getOVNKMasterOVNkubeNode(oc)
	o.Expect(ovnPod).ShouldNot(o.Equal(""))
	checkOVNDbErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
		cmdOutput, cmdErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", ovnPod, getCmd)
		if cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try again ...,", cmdErr)
			return false, nil
		}
		o.Expect(cmdOutput).ShouldNot(o.Equal(""))
		for _, index := range strings.Split(cmdOutput, "\n") {
			for _, node := range nodeNames {
				if constructType == "ls-list" {
					matchStr = fmt.Sprintf("\\((%s\\))", node)
				} else {
					matchStr = fmt.Sprintf("\\((GR_%s\\))", node)
				}
				re := regexp.MustCompile(matchStr)
				if re.FindString(index) != "" {
					ovnConstruct := strings.Fields(index)
					ovnConstructs = append(ovnConstructs, ovnConstruct[0])
				}
			}
		}
		return true, nil
	})
	if checkOVNDbErr != nil {
		e2e.Logf("The result in ovndb is not expected ! See below output \n %s ", checkOVNDbErr)
	}
	return ovnConstructs
}

// Returns the logical router or logical switch on a node
func (svcEndpontDetails *svcEndpontDetails) getOVNConstruct(oc *exutil.CLI, constructType string) string {
	var ovnConstruct string
	var matchStr string
	getCmd := "ovn-nbctl " + constructType
	checkOVNDbErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
		cmdOutput, cmdErr := compat_otp.RemoteShPodWithBash(oc, "openshift-ovn-kubernetes", svcEndpontDetails.ovnKubeNodePod, getCmd)
		if cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try again ...,", cmdErr)
			return false, nil
		}
		if cmdOutput == "" {
			return true, nil
		}
		for _, index := range strings.Split(cmdOutput, "\n") {

			if constructType == "ls-list" {
				matchStr = fmt.Sprintf("\\((%s\\))", svcEndpontDetails.nodeName)
			} else {
				matchStr = fmt.Sprintf("\\((GR_%s\\))", svcEndpontDetails.nodeName)
			}
			re := regexp.MustCompile(matchStr)
			if re.FindString(index) != "" {
				matchedStr := strings.Fields(index)
				ovnConstruct = matchedStr[0]
			}
		}
		return true, nil
	})
	if checkOVNDbErr != nil {
		e2e.Logf("The result in ovndb is not expected ! See below output \n %s ", checkOVNDbErr)
	}
	return ovnConstruct
}

// returns load balancer entries created for LB service type on routers or switches on all nodes
func getOVNLBContructs(oc *exutil.CLI, constructType string, endPoint string, ovnConstruct []string) bool {
	var result bool
	ovnPod := getOVNKMasterOVNkubeNode(oc)
	o.Expect(ovnPod).ShouldNot(o.Equal(""))
	//only if the count for any of output is less than three the success will be false
	result = true
	for _, construct := range ovnConstruct {
		checkOVNDbErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
			getCmd := "ovn-nbctl --no-leader-only " + constructType + " " + construct + " | grep " + endPoint
			cmdOutput, cmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnPod, "northd", getCmd)
			if cmdErr != nil {
				e2e.Logf("%v,Waiting for expected result to be synced, try next ...,", cmdErr)
				result = false
				return false, nil
			}
			if len(strings.Split(cmdOutput, "\n")) >= 2 {
				e2e.Logf("Required entries %s were created for service on %s", constructType, construct)
				result = true
			} else {
				e2e.Logf("Required entries %s were not created for service on %s", constructType, construct)
				result = false
			}
			return true, nil
		})
		if checkOVNDbErr != nil {
			e2e.Logf("The command check result in ovndb is not expected ! See below output \n %s ", checkOVNDbErr)
			result = false
		}

	}
	return result
}

// returns load balancer entries created for LB service type on routers or switches on a single node
func (svcEndpontDetails *svcEndpontDetails) getOVNLBContruct(oc *exutil.CLI, constructType string, construct string) bool {
	var result bool
	//only if the count for any of output is less than three the success will be false
	result = true
	checkOVNDbErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
		getCmd := "ovn-nbctl " + constructType + " " + construct + " | grep " + svcEndpontDetails.podIP
		cmdOutput, cmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", svcEndpontDetails.ovnKubeNodePod, "northd", getCmd)
		if cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try next ...,", cmdErr)
			result = false
			return false, nil
		}
		if len(strings.Split(cmdOutput, "\n")) >= 2 {
			e2e.Logf("Required entries %s were created for service on %s", constructType, construct)
			result = true
		} else {
			e2e.Logf("Required entries %s were not created for service on %s", constructType, construct)
			result = false
		}
		return true, nil
	})
	if checkOVNDbErr != nil {
		e2e.Logf("The command check result in ovndb is not expected ! See below output \n %s ", checkOVNDbErr)
		result = false
	}

	return result
}

func getServiceEndpoints(oc *exutil.CLI, serviceName string, serviceNamespace string) string {
	serviceEndpoint, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("ep", serviceName, "-n", serviceNamespace, "--no-headers").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(serviceEndpoint).ShouldNot(o.BeEmpty())
	e2e.Logf("Service endpoint %v", serviceEndpoint)
	result := strings.Fields(serviceEndpoint)
	return result[1]
}

func getOVNMetricsInSpecificContainer(oc *exutil.CLI, containerName string, podName string, url string, metricName string) string {
	var metricValue string
	metricsErr := wait.Poll(5*time.Second, 10*time.Second, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-ovn-kubernetes", "-c", containerName, podName, "--", "curl", url).OutputToFile("metrics.txt")
		if err != nil {
			e2e.Logf("Can't get metrics and try again, the error is:%s", err)
			return false, nil
		}
		metricOutput, getMetricErr := exec.Command("bash", "-c", "cat "+output+" | grep -e '^"+metricName+" ' | awk 'END {print $2}'").Output()
		o.Expect(getMetricErr).NotTo(o.HaveOccurred())
		metricValue = strings.TrimSpace(string(metricOutput))
		o.Expect(metricValue).ShouldNot(o.BeEmpty())
		e2e.Logf("The output of the %s is : %v", metricName, metricValue)
		return true, nil

	})
	compat_otp.AssertWaitPollNoErr(metricsErr, fmt.Sprintf("Fail to get metric and the error is:%s", metricsErr))
	return metricValue
}

// CurlNodePortPass checks nodeport svc reacability from a node regardless of network addressing type on cluster
func CurlNodePortPass(oc *exutil.CLI, nodeNameFrom string, nodeNameTo string, nodePort string) {
	nodeIP1, nodeIP2 := getNodeIP(oc, nodeNameTo)
	if nodeIP1 != "" {
		nodev6URL := net.JoinHostPort(nodeIP1, nodePort)
		nodev4URL := net.JoinHostPort(nodeIP2, nodePort)
		curlCmd := fmt.Sprintf("curl %s --connect-timeout 5 && curl %s --connect-timeout 5", nodev4URL, nodev6URL)
		o.Eventually(func() bool {
			output, err := compat_otp.DebugNode(oc, nodeNameFrom, "bash", "-c", curlCmd)
			return err == nil && strings.Contains(output, "Hello OpenShift")
		}, "30s", "10s").Should(o.BeTrue(), "NodePort Service was not be able to access!")
	} else {
		nodeURL := net.JoinHostPort(nodeIP2, nodePort)
		o.Eventually(func() bool {
			output, err := compat_otp.DebugNode(oc, nodeNameFrom, "curl", nodeURL, "-s", "--connect-timeout", "5")
			return err == nil && strings.Contains(output, "Hello OpenShift")
		}, "30s", "10s").Should(o.BeTrue(), "NodePort Service was not be able to access!")
	}
}

// CurlNodePortFail checks nodeport svc unreacability from a node regardless of network addressing type on cluster
func CurlNodePortFail(oc *exutil.CLI, nodeNameFrom string, nodeNameTo string, nodePort string) {
	nodeIP1, nodeIP2 := getNodeIP(oc, nodeNameTo)
	if nodeIP1 != "" {
		nodev6URL := net.JoinHostPort(nodeIP1, nodePort)
		nodev4URL := net.JoinHostPort(nodeIP2, nodePort)
		output, _ := compat_otp.DebugNode(oc, nodeNameFrom, "curl", nodev4URL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("timed out"), o.ContainSubstring("Connection refused")))
		output, _ = compat_otp.DebugNode(oc, nodeNameFrom, "curl", nodev6URL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("timed out"), o.ContainSubstring("Connection refused")))
	} else {
		nodeURL := net.JoinHostPort(nodeIP2, nodePort)
		output, _ := compat_otp.DebugNode(oc, nodeNameFrom, "curl", nodeURL, "--connect-timeout", "5")
		o.Expect(output).To(o.Or(o.ContainSubstring("28"), o.ContainSubstring("timed out"), o.ContainSubstring("Connection refused")))
	}
}

func CurlPod2NodePortPass(oc *exutil.CLI, namespaceSrc string, podNameSrc string, nodeNameTo string, nodePort string) {
	nodeIP1, nodeIP2 := getNodeIP(oc, nodeNameTo)
	if nodeIP1 != "" {
		nodev6URL := net.JoinHostPort(nodeIP1, nodePort)
		nodev4URL := net.JoinHostPort(nodeIP2, nodePort)
		output, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl "+nodev4URL+" --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("Hello OpenShift"))
		output, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl "+nodev6URL+" --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("Hello OpenShift"))
	} else {
		nodeURL := net.JoinHostPort(nodeIP2, nodePort)
		output, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl "+nodeURL+" --connect-timeout 5")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("Hello OpenShift"))
	}
}

func CurlPod2NodePortFail(oc *exutil.CLI, namespaceSrc string, podNameSrc string, nodeNameTo string, nodePort string) {
	nodeIP1, nodeIP2 := getNodeIP(oc, nodeNameTo)
	if nodeIP1 != "" {
		nodev6URL := net.JoinHostPort(nodeIP1, nodePort)
		nodev4URL := net.JoinHostPort(nodeIP2, nodePort)
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl "+nodev4URL+" --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl "+nodev6URL+" --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())
	} else {
		nodeURL := net.JoinHostPort(nodeIP2, nodePort)
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl "+nodeURL+" --connect-timeout 5")
		o.Expect(err).To(o.HaveOccurred())
	}
}

// get primary NIC interface name
func getPrimaryNICname(oc *exutil.CLI) string {
	masterNode, getMasterNodeErr := compat_otp.GetFirstMasterNode(oc)
	o.Expect(getMasterNodeErr).NotTo(o.HaveOccurred())
	primary_int, err := compat_otp.DebugNodeWithChroot(oc, masterNode, "bash", "-c", "nmcli -g connection.interface-name c show ovs-if-phys0")
	o.Expect(err).NotTo(o.HaveOccurred())
	primary_inf_name := strings.Split(primary_int, "\n")
	e2e.Logf("Primary Inteface name is : %s", primary_inf_name[0])
	return primary_inf_name[0]
}

// get file contents to be modified for SCTP
func getFileContentforSCTP(baseDir string, name string) (fileContent string) {
	filePath := filepath.Join(testdata.FixturePath("networking", baseDir), name)
	fileOpen, err := os.Open(filePath)
	defer fileOpen.Close()
	if err != nil {
		e2e.Failf("Failed to open file: %s", filePath)
	}
	fileRead, _ := io.ReadAll(fileOpen)
	if err != nil {
		e2e.Failf("Failed to read file: %s", filePath)
	}
	return string(fileRead)
}

// get generic sctpclient pod yaml file, replace variables as per requirements
func createSCTPclientOnNode(oc *exutil.CLI, pod_pmtrs map[string]string) (err error) {
	PodGenericYaml := getFileContentforSCTP("sctp", "sctpclientspecificnode.yaml")
	for rep, value := range pod_pmtrs {
		PodGenericYaml = strings.ReplaceAll(PodGenericYaml, rep, value)
	}
	podFileName := "temp-sctp-client-pod-" + getRandomString() + ".yaml"
	defer os.Remove(podFileName)
	os.WriteFile(podFileName, []byte(PodGenericYaml), 0644)
	// create ping pod for Microshift
	_, err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", podFileName).Output()
	return err
}

// get generic sctpserver pod yaml file, replace variables as per requirements
func createSCTPserverOnNode(oc *exutil.CLI, pod_pmtrs map[string]string) (err error) {
	PodGenericYaml := getFileContentforSCTP("sctp", "sctpserverspecificnode.yaml")
	for rep, value := range pod_pmtrs {
		PodGenericYaml = strings.ReplaceAll(PodGenericYaml, rep, value)
	}
	podFileName := "temp-sctp-server-pod-" + getRandomString() + ".yaml"
	defer os.Remove(podFileName)
	os.WriteFile(podFileName, []byte(PodGenericYaml), 0644)
	// create ping pod for Microshift
	_, err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", podFileName).Output()
	return err
}

// configure IPSec at runtime, targetStatus can be full/disabled/external
func configIPSecAtRuntime(oc *exutil.CLI, targetStatus string) (err error) {
	var targetConfig, currentStatus string
	ipsecState := checkIPsec(oc)
	if ipsecState == "{}" || ipsecState == "Full" {
		currentStatus = "full"
	} else if ipsecState == "Disabled" {
		currentStatus = "disabled"
	} else if ipsecState == "External" {
		currentStatus = "external"
	}
	if currentStatus == targetStatus {
		e2e.Logf("The IPSec is already in %v state", targetStatus)
		return
	} else if targetStatus == "full" {
		//In 4.15+, enabling/disabling ipsec would require nodes restart
		targetConfig = "true"
		e2e.Logf("Start to enable ipsec.")
		_, err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Full\"}}}}}", "--type=merge").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Wait the MC applying getting started")
		o.Eventually(func() error {
			err := compat_otp.AssertOrCheckMCP(oc, "master", 30*time.Second, 30*time.Second, false)
			return err
		}, "300s", "30s").ShouldNot(o.BeNil(), "MC applying didn't start yet.")
		//Add test points for case OCP-79034
		e2e.Logf("Both IPsec container and host pods will be launched.")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", "-n", "openshift-ovn-kubernetes").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("The ds in openshift-ovn-kubernetes are : \n", output)
		o.Expect(strings.Contains(output, "ovn-ipsec-containerized")).Should(o.BeTrue())
		o.Expect(strings.Contains(output, "ovn-ipsec-host")).Should(o.BeTrue())
		e2e.Logf("Verify CNO status shows progress state")
		checkCNORenderState(oc)
		e2e.Logf("Wait the MC were applied to nodes ")
		err = compat_otp.AssertOrCheckMCP(oc, "master", 60*time.Second, 30*time.Minute, false)
		o.Expect(err).NotTo(o.HaveOccurred())
		err = compat_otp.AssertOrCheckMCP(oc, "worker", 60*time.Second, 5*time.Minute, false)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("MC applying done ")
		e2e.Logf("Wait ipsec container ds disappeared in openshift-ovn-kubernetes")
		o.Eventually(func() bool {
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("ds", "-n", "openshift-ovn-kubernetes").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("The ds in openshift-ovn-kubernetes are : \n", output)
			return !strings.Contains(output, "ovn-ipsec-containerized")
		}, "300s", "30s").ShouldNot(o.BeNil(), "Timeout for waiting ovn-ipsec-containerized being removed!")
		e2e.Logf("Wait ipsec host pods running in openshift-ovn-kubernetes")
		err = waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())
	} else if targetStatus == "disabled" {
		targetConfig = "false"
		_, err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Disabled\"}}}}}", "--type=merge").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Wait ovn-ipsec pods disappeared")
		err = waitForPodWithLabelGone(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec")
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Wait the MC applying getting started ")
		o.Eventually(func() error {
			err := compat_otp.AssertOrCheckMCP(oc, "master", 30*time.Second, 30*time.Second, false)
			return err
		}, "300s", "30s").ShouldNot(o.BeNil(), "MC applying didn't start yet.")
		e2e.Logf("Verify CNO status shows progress state")
		checkCNORenderState(oc)
		e2e.Logf("Wait the MC were applied to nodes ")
		err = compat_otp.AssertOrCheckMCP(oc, "master", 60*time.Second, 30*time.Minute, false)
		o.Expect(err).NotTo(o.HaveOccurred())
		err = compat_otp.AssertOrCheckMCP(oc, "worker", 60*time.Second, 5*time.Minute, false)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("MC applying done ")
		e2e.Logf("Verify IPsec MC were removed")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("mc").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "ipsec")).ShouldNot(o.BeTrue())
	}

	checkErr := checkIPSecInDB(oc, targetConfig)
	compat_otp.AssertWaitPollNoErr(checkErr, "check IPSec configuration failed")

	return nil
}

// check IPSec configuration in northd, targetConfig should be "true" or "false"
func checkIPSecInDB(oc *exutil.CLI, targetConfig string) error {
	ovnLeaderpod := getOVNKMasterOVNkubeNode(oc)
	return wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		getIPSec, getErr := execCommandInSpecificPod(oc, "openshift-ovn-kubernetes", ovnLeaderpod, "ovn-nbctl --no-leader-only get nb_global . ipsec")
		o.Expect(getErr).NotTo(o.HaveOccurred())
		if strings.Contains(getIPSec, targetConfig) {
			return true, nil
		}
		e2e.Logf("Can't get expected ipsec configuration and try again")
		return false, nil
	})
}

// IsIPv4 check if the string is an IPv4 address.
func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

// IsIPv6 check if the string is an IPv6 address.
func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

// checkSCTPResultPASS
func checkSCTPResultPASS(oc *exutil.CLI, namespace, sctpServerPodName, sctpClientPodname, dstIP, dstPort string) {
	compat_otp.By("sctpserver pod start to wait for sctp traffic")
	_, _, _, err1 := oc.Run("exec").Args("-n", oc.Namespace(), sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
	o.Expect(err1).NotTo(o.HaveOccurred())
	time.Sleep(5 * time.Second)

	compat_otp.By("check sctp process enabled in the sctp server pod")
	msg, err2 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
	o.Expect(err2).NotTo(o.HaveOccurred())
	o.Expect(strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp")).To(o.BeTrue())

	compat_otp.By("sctpclient pod start to send sctp traffic")
	_, err3 := e2eoutput.RunHostCmd(oc.Namespace(), sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+dstIP+" "+dstPort+" --sctp; }")
	o.Expect(err3).NotTo(o.HaveOccurred())

	compat_otp.By("server sctp process will end after get sctp traffic from sctp client")
	time.Sleep(5 * time.Second)
	msg1, err4 := e2eoutput.RunHostCmd(oc.Namespace(), sctpServerPodName, "ps aux | grep sctp")
	o.Expect(err4).NotTo(o.HaveOccurred())
	o.Expect(msg1).NotTo(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"))
}

func ovnkubeNodePod(oc *exutil.CLI, nodeName string) string {
	// get OVNkubeNode pod on specific node.
	ovnNodePod, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", "openshift-ovn-kubernetes", "pod", "-l app=ovnkube-node", "--field-selector", "spec.nodeName="+nodeName, "-o=jsonpath={.items[0].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The ovnkube-node pod on node %s is %s", nodeName, ovnNodePod)
	o.Expect(ovnNodePod).NotTo(o.BeEmpty())
	return ovnNodePod
}

func waitForNetworkOperatorState(oc *exutil.CLI, interval int, timeout int, expectedStatus string) {
	waitForClusterOperatorState(oc, "network", interval, timeout, expectedStatus)
}

func waitForClusterOperatorState(oc *exutil.CLI, co string, interval int, timeout int, expectedStatus string) {
	errCheck := wait.Poll(time.Duration(interval)*time.Second, time.Duration(timeout)*time.Minute, func() (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", co).Output()
		if err != nil {
			e2e.Logf("Fail to get clusteroperator network, error:%s. Trying again", err)
			return false, nil
		}
		if matched, _ := regexp.MatchString(expectedStatus, output); !matched {
			e2e.Logf("Network operator state is:%s", output)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(errCheck, fmt.Sprintf("Timed out waiting for the expected condition"))
}

func enableIPForwardingOnSpecNodeNIC(oc *exutil.CLI, worker, secNIC string) {
	cmd := fmt.Sprintf("sysctl net.ipv4.conf.%s.forwarding", secNIC)
	output, debugNodeErr := compat_otp.DebugNode(oc, worker, "bash", "-c", cmd)
	o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
	if !strings.Contains(output, ".forwarding = 1") {
		e2e.Logf("Enable IP forwarding for NIC %s on node %s ...", secNIC, worker)
		enableCMD := fmt.Sprintf("sysctl -w net.ipv4.conf.%s.forwarding=1", secNIC)
		_, debugNodeErr = compat_otp.DebugNode(oc, worker, "bash", "-c", enableCMD)
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
	}
	e2e.Logf("IP forwarding was enabled for NIC %s on node %s!", secNIC, worker)
}

func disableIPForwardingOnSpecNodeNIC(oc *exutil.CLI, worker, secNIC string) {
	cmd := fmt.Sprintf("sysctl net.ipv4.conf.%s.forwarding", secNIC)
	output, debugNodeErr := compat_otp.DebugNode(oc, worker, "bash", "-c", cmd)
	o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
	if strings.Contains(output, ".forwarding = 1") {
		e2e.Logf("Disable IP forwarding for NIC %s on node %s ...", secNIC, worker)
		disableCMD := fmt.Sprintf("sysctl -w net.ipv4.conf.%s.forwarding=0", secNIC)
		_, debugNodeErr = compat_otp.DebugNode(oc, worker, "bash", "-c", disableCMD)
		o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
	}
	e2e.Logf("IP forwarding was disabled for NIC %s on node %s!", secNIC, worker)
}

func nbContructToMap(nbConstruct string) map[string]string {
	listKeyValues := strings.Split(nbConstruct, "\n")
	var tempMap map[string]string
	tempMap = make(map[string]string)
	for _, keyValPair := range listKeyValues {
		keyValItem := strings.SplitN(keyValPair, ":", 2)
		key := strings.Trim(keyValItem[0], " ")
		val := strings.TrimLeft(keyValItem[1], " ")
		tempMap[key] = val

	}
	return tempMap
}

// Create live migration job on Kubevirt cluster
func (migrationjob *migrationDetails) createMigrationJob(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", migrationjob.template, "-p", "NAME="+migrationjob.name, "NAMESPACE="+migrationjob.namespace, "VMI="+migrationjob.virtualmachinesintance)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create migration job %v", migrationjob.name))
}

// Delete migration job on Kubevirt cluster
func (migrationjob *migrationDetails) deleteMigrationJob(oc *exutil.CLI) {
	removeResource(oc, true, true, "virtualmachineinstancemigration.kubevirt.io", migrationjob.name, "-n", migrationjob.namespace)
}

// Check all cluster operators status on the cluster
func checkAllClusterOperatorsState(oc *exutil.CLI, interval int, timeout int) {
	operatorsString, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "-o=jsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	var clusterOperators []string
	if operatorsString != "" {
		clusterOperators = strings.Split(operatorsString, " ")
	}

	for _, clusterOperator := range clusterOperators {
		errCheck := wait.Poll(time.Duration(interval)*time.Second, time.Duration(timeout)*time.Minute, func() (bool, error) {
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", clusterOperator).Output()
			if err != nil {
				e2e.Logf("Fail to get state for operator %s, error:%s. Trying again", clusterOperator, err)
				return false, err
			}
			if matched, _ := regexp.MatchString("True.*False.*False", output); !matched {
				e2e.Logf("Operator %s on hosted cluster is in state:%s", output)
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(errCheck, "Timed out waiting for the expected condition")
	}
}

// Check OVNK health: OVNK pods health and ovnkube-node DS health
func checkOVNKState(oc *exutil.CLI) error {
	// check all OVNK pods
	waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")
	if !compat_otp.IsHypershiftHostedCluster(oc) {
		waitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovnkube-control-plane")
	}
	// check ovnkube-node ds rollout status and confirm if rollout has triggered
	return wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", "openshift-ovn-kubernetes", "ds", "ovnkube-node", "--timeout", "5m").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if strings.Contains(status, "rollout to finish") && strings.Contains(status, "successfully rolled out") {
			e2e.Logf("ovnkube rollout was triggerred and rolled out successfully")
			return true, nil
		}
		e2e.Logf("ovnkube rollout trigger hasn't happened yet. Trying again")
		return false, nil
	})
}

func addDummyInferface(oc *exutil.CLI, nodeName, IP, nicName string) {
	e2e.Logf("Add a dummy interface %s on node %s \n", nicName, nodeName)
	cmd := fmt.Sprintf("ip link a %s type dummy && ip link set dev %s up && ip a add %s dev %s && ip a show %s", nicName, nicName, IP, nicName, nicName)
	output, debugNodeErr := compat_otp.DebugNode(oc, nodeName, "bash", "-c", cmd)
	o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
	e2e.Logf("The dummy interface was added. \n %s", output)

}

func addIPtoInferface(oc *exutil.CLI, nodeName, IP, nicName string) {
	e2e.Logf("Add IP address %s to interface %s on node %s \n", IP, nicName, nodeName)
	cmd := fmt.Sprintf("ip a show %s && ip a add %s dev %s", nicName, IP, nicName)
	_, debugNodeErr := compat_otp.DebugNode(oc, nodeName, "bash", "-c", cmd)
	o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
}

func delIPFromInferface(oc *exutil.CLI, nodeName, IP, nicName string) {
	e2e.Logf("Remove IP address %s from interface %s on node %s \n", IP, nicName, nodeName)
	cmd := fmt.Sprintf("ip a show %s && ip a del %s dev %s", nicName, IP, nicName)
	_, debugNodeErr := compat_otp.DebugNode(oc, nodeName, "bash", "-c", cmd)
	o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
}

func removeDummyInterface(oc *exutil.CLI, nodeName, nicName string) {
	e2e.Logf("Remove a dummy interface %s on node %s \n", nicName, nodeName)
	cmd := fmt.Sprintf("ip a show %s && ip link del %s type dummy", nicName, nicName)
	output, debugNodeErr := compat_otp.DebugNode(oc, nodeName, "bash", "-c", cmd)
	nicNotExistStr := fmt.Sprintf("Device \"%s\" does not exist", nicName)
	if debugNodeErr != nil && strings.Contains(output, nicNotExistStr) {
		e2e.Logf("The dummy interface %s does not exist on node %s ! \n", nicName, nodeName)
		return
	}
	o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
	e2e.Logf("The dummy interface %s was removed from node %s ! \n", nicName, nodeName)
}

func (kkPod *kubeletKillerPod) createKubeletKillerPodOnNode(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", kkPod.template, "-p", "NAME="+kkPod.name, "NAMESPACE="+kkPod.namespace, "NODENAME="+kkPod.nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create Kubelet-Killer pod %v", kkPod.name))
}

func getNodeNameByIPv4(oc *exutil.CLI, nodeIPv4 string) (nodeName string) {
	nodeList, err := e2enode.GetReadySchedulableNodes(context.TODO(), oc.KubeFramework().ClientSet)
	o.Expect(err).NotTo(o.HaveOccurred())
	for _, node := range nodeList.Items {
		_, IPv4 := getNodeIP(oc, node.Name)
		if IPv4 == nodeIPv4 {
			nodeName = node.Name
			break
		}
	}
	return nodeName
}

// patch resource in specific namespace, this is useful when patching resource to hosted cluster that is in "-n clusters" namespace
func patchResourceAsAdminNS(oc *exutil.CLI, ns, resource, patch string) {
	err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(resource, "-p", patch, "--type=merge", "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

// get proxy IP and port of hosted cluster
func getProxyIPandPortOnHostedCluster(oc *exutil.CLI, hostedClusterName, namespace string) (string, string) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("hostedclusters", hostedClusterName, "-n", namespace, "-o=jsonpath={.spec.configuration.proxy.httpProxy}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if len(output) != 0 {
		//match out the proxy IP
		re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
		proxyIP := re.FindAllString(output, -1)[0]
		proxyPort := strings.Split(output, ":")[2]
		e2e.Logf("proxy IP is %s, proxy port is %s", proxyIP, proxyPort)
		return proxyIP, proxyPort
	} else {
		return "", ""
	}
}

// GetMachineNamesFromMachineSetOnROSA gets all Machines in a Machinepool on a classic ROSA cluster by label
// This function only appliable to classic ROSA, as there is no "machine" resource on ROSA hosted cluster
func getMachineNamesFromMachinePoolOnROSA(oc *exutil.CLI, machineSetName string, machineAPINamespace string) []string {
	e2e.Logf("Getting all Machines in a Machineset by specific label ...")
	machineNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("machine", "-o=jsonpath={.items[*].metadata.name}", "-l", "machine.openshift.io/cluster-api-machine-type="+machineSetName, "-n", machineAPINamespace).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if machineNames != "" {
		return strings.Split(machineNames, " ")
	} else {
		return nil
	}
}

// Wait for machine on a classic ROSA to be ready - this function only appliable to classic ROSA, as there is no "machine" resource on ROSA hosted cluster
func waitMachineOnROSAReady(oc *exutil.CLI, machineName string, namespace string) error {
	return wait.Poll(15*time.Second, 10*time.Minute, func() (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("machine", machineName, "-n", namespace, "-o=jsonpath={.status.phase}").Output()
		e2e.Logf("Machine %v status is %v", machineName, status)
		if err != nil || status == "" {
			e2e.Logf("Failed to get machine status: %v, retrying...", err)
			return false, nil
		}
		if !strings.Contains(status, "Running") {
			e2e.Logf("Machine %v is in %v, not in Running state, retrying...", status)
			return false, nil
		}
		return true, nil
	})
}

type apbStaticExternalRoute struct {
	name       string
	labelkey   string
	labelvalue string
	ip1        string
	ip2        string
	bfd        bool
	template   string
}

type apbDynamicExternalRoute struct {
	name                string
	labelKey            string
	labelValue          string
	podLabelKey         string
	podLabelValue       string
	namespaceLabelKey   string
	namespaceLabelValue string
	bfd                 bool
	template            string
}

func (sgwpr *apbStaticExternalRoute) deleteAPBExternalRoute(oc *exutil.CLI) {
	removeResource(oc, true, true, "apbexternalroute", sgwpr.name)
}

func (sgwpr *apbStaticExternalRoute) createAPBExternalRoute(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", sgwpr.template, "-p", "NAME="+sgwpr.name, "LABELKEY="+sgwpr.labelkey, "LABELVALUE="+sgwpr.labelvalue, "IP1="+sgwpr.ip1, "IP2="+sgwpr.ip2, "BFD="+strconv.FormatBool(sgwpr.bfd))
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create apbexternalroute %v", sgwpr.name))
}

func (sgwpr *apbDynamicExternalRoute) createAPBDynamicExternalRoute(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", sgwpr.template, "-p", "NAME="+sgwpr.name, "LABELKEY="+sgwpr.labelKey, "LABELVALUE="+sgwpr.labelValue,
			"PODLABELKEY="+sgwpr.podLabelKey, "PODLABELVALUE="+sgwpr.podLabelValue,
			"NSLABELKEY="+sgwpr.namespaceLabelKey, "NSLABELVALUE="+sgwpr.namespaceLabelValue,
			"BFD="+strconv.FormatBool(sgwpr.bfd))
		if err1 != nil {
			e2e.Logf("Could not create due to err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create APB External Route %s due to %v", sgwpr.name, err))
}

func checkAPBExternalRouteStatus(oc *exutil.CLI, gwName string, expectedStatus string) error {
	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		output, gwErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("apbexternalroute", gwName).Output()
		if gwErr != nil {
			e2e.Logf("Failed to get apbexternalroute %v, error: %s. Trying again", gwName, gwErr)
			return false, nil
		}
		if !strings.Contains(output, expectedStatus) {
			e2e.Logf("Expected status is %v, the apbexternalroute status is %v, trying again.", expectedStatus, output)
			return false, nil
		}
		return true, nil
	})
	return checkErr
}

func checkEgressFWStatus(oc *exutil.CLI, fwName string, ns string, expectedStatus string) error {
	checkErr := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		output, fwErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("egressfirewall", "-n", ns, fwName).Output()
		if fwErr != nil {
			e2e.Logf("Failed to get egressfirewall %v, error: %s. Trying again", fwName, fwErr)
			return false, nil
		}
		if !strings.Contains(output, expectedStatus) {
			e2e.Logf("Expected status is %v, the egressfirewall status is %v, trying again.", expectedStatus, output)
			return false, nil
		}
		return true, nil
	})
	return checkErr
}

func checkNodeIdentityWebhook(oc *exutil.CLI) (string, error) {
	webhooks, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("ValidatingWebhookConfiguration", "network-node-identity.openshift.io", "-o=jsonpath={.webhooks[*].name}").Output()
	return webhooks, err
}

func disableNodeIdentityWebhook(oc *exutil.CLI, namespace string, cmName string) (string, error) {
	_, err := oc.AsAdmin().WithoutNamespace().Run("create").Args("configmap", cmName, "-n", namespace, "--from-literal=enabled=false").Output()
	o.Eventually(func() bool {
		result := true
		_, cmErr := oc.AsAdmin().Run("get").Args("configmap/"+cmName, "-n", namespace).Output()
		if cmErr != nil {
			e2e.Logf(fmt.Sprintf("Wait for configmap/%s to be created", cmName))
			result = false
		}
		return result
	}, "60s", "5s").Should(o.BeTrue(), fmt.Sprintf("configmap/%sis not created", cmName))
	return "", err
}

// get lr-policy-list from logical_router_policy table
func getlrPolicyList(oc *exutil.CLI, nodeName, tableID string, expected bool) ([]string, error) {
	// get the ovnkube-node pod on the node
	ovnKubeNodePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	o.Expect(ovnKubeNodePod).ShouldNot(o.Equal(""))
	var lspOutput string
	var lspErr error
	var lrPolicyList []string

	lspCmd := "ovn-nbctl lr-policy-list ovn_cluster_router | grep '" + tableID + " '"
	checkLspErr := wait.Poll(10*time.Second, 2*time.Minute, func() (bool, error) {
		lspOutput, lspErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, "northd", lspCmd)
		if lspErr == nil && lspOutput != "" && expected {
			cmdOutputLines := strings.Split(lspOutput, "\n")
			for i := 0; i < len(cmdOutputLines); i++ {
				lrPolicyList = append(lrPolicyList, cmdOutputLines[i])
			}
			return true, nil
		}

		// check lr-policy-list grep with tableID returned empty, usually there is "command terminated with exit code 1" to lspErr returned, so lspErr is not checked here
		if lspOutput != "ip4.src ==" && !expected {
			e2e.Logf("lr-policy-list of table %s is cleared up as expected", tableID)
			return true, nil
		}

		e2e.Logf("Waiting for expected result to be synced, try again ...")
		return false, nil
	})
	if checkLspErr != nil {
		e2e.Logf("The command check result in ovndb is not expected ! See below output \n %s ", lspOutput)
	}
	return lrPolicyList, checkLspErr
}

// Create a kubeconfig that impersonates ovnkube-node
func generateKubeConfigFileForContext(oc *exutil.CLI, nodeName string, ovnKubeNodePod string, kubeConfigFilePath string, userContext string) bool {
	var (
		pemFile     = "/etc/ovn/ovnkube-node-certs/ovnkube-client-current.pem"
		certFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
		clusterName = "default-cluster"
		userName    = "default-user"
	)

	baseDomain, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("dns/cluster", "-o=jsonpath={.spec.baseDomain}").Output()
	if err != nil || baseDomain == "" {
		e2e.Logf("Base Domain could not retrieved")
		return false
	}
	e2e.Logf("Base Domain %v", baseDomain)
	apiServerFQDN := fmt.Sprintf("api.%s", baseDomain)

	setUpClusterCmd := fmt.Sprintf("export KUBECONFIG=%s; kubectl config set-cluster %s --server=https://%s:6443 --certificate-authority %s --embed-certs", kubeConfigFilePath, clusterName, apiServerFQDN, certFile)
	setUserCredentialsCmd := fmt.Sprintf("export KUBECONFIG=%s; kubectl config set-credentials %s --client-key %s --client-certificate %s --embed-certs", kubeConfigFilePath, userName, pemFile, pemFile)
	setContextCmd := fmt.Sprintf("export KUBECONFIG=%s; kubectl config set-context %s --cluster %s --user %s", kubeConfigFilePath, userContext, clusterName, userName)
	testContextCmd := fmt.Sprintf("export KUBECONFIG=%s; kubectl config use-context %s; oc get nodes", kubeConfigFilePath, userContext)

	cmdOutput, cmdErr := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, "ovnkube-controller", setUpClusterCmd)
	if cmdErr != nil || !strings.Contains(cmdOutput, "Cluster "+"\""+clusterName+"\""+" set.") {
		e2e.Logf("Setting cluster for impersonation failed %v.", cmdErr)
		return false
	}
	e2e.Logf("Cluster set - %v", cmdOutput)

	cmdOutput, cmdErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, "ovnkube-controller", setUserCredentialsCmd)
	if cmdErr != nil || !strings.Contains(cmdOutput, "User "+"\""+userName+"\""+" set.") {
		e2e.Logf("Setting user credentials for impersonation failed %v.", cmdErr)
		return false
	}
	e2e.Logf("User credentials set - %v", cmdOutput)

	cmdOutput, cmdErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, "ovnkube-controller", setContextCmd)
	if cmdErr != nil || !strings.Contains(cmdOutput, "Context "+"\""+userContext+"\""+" created.") {
		e2e.Logf("Context creation for impersonation failed %v.", cmdErr)
		return false
	}
	e2e.Logf("Context created - %v", cmdOutput)

	cmdOutput, cmdErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubeNodePod, "ovnkube-controller", testContextCmd)
	if cmdErr != nil || !strings.Contains(cmdOutput, "Switched to context "+"\""+userContext+"\"") || !strings.Contains(cmdOutput, nodeName) {
		e2e.Logf("Test command for impersonation failed %v.", cmdErr)
		return false
	}
	e2e.Logf("Successfully created and tested kubeconfig for impersonation")
	return true
}

func findNodesWithSameSubnet(oc *exutil.CLI, nodeList []string) (bool, []string) {
	sameSubNode := make(map[string][]string)
	for _, node := range nodeList {
		subNet := getNodeSubnet(oc, node, "default")
		if _, ok := sameSubNode[subNet]; ok {
			sameSubNode[subNet] = append(sameSubNode[subNet], node)
			if len(sameSubNode[subNet]) >= 2 {
				return true, sameSubNode[subNet]
			}
		} else {
			sameSubNode[subNet] = []string{node}
		}
	}
	return false, nil
}

// Get endpoints for service:port in northdb of the node
func getLBListEndpointsbySVCIPPortinNBDB(oc *exutil.CLI, nodeName, svcPort string) ([]string, error) {
	// get the ovnkube-node pod of the node
	ovnKubePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	o.Expect(ovnKubePod).ShouldNot(o.Equal(""))
	var cmdOutput string
	var cmdErr error
	var endpoints []string

	lbCmd := "ovn-nbctl lb-list | grep  \"" + svcPort + "\"  | awk '{print $NF}'"
	checkOVNDbErr := wait.Poll(2*time.Second, 2*time.Minute, func() (bool, error) {
		cmdOutput, cmdErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubePod, "northd", lbCmd)
		if cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try again ...,", cmdErr)
			return false, nil
		}

		if cmdOutput != "" {
			cmdOutputLines := strings.Split(cmdOutput, ",")
			for i := 0; i < len(cmdOutputLines); i++ {
				endpoints = append(endpoints, cmdOutputLines[i])
			}
			return true, nil
		}

		e2e.Logf("Waiting for expected result to be synced, try again ...")
		return false, nil
	})
	if checkOVNDbErr != nil {
		e2e.Logf("The command check result in ovndb is not expected ! See below output \n %s ", cmdOutput)
	}
	return endpoints, checkOVNDbErr
}

// Get all pods with same label and also are in same state
func getAllPodsWithLabelAndCertainState(oc *exutil.CLI, namespace string, label string, podState string) []string {
	var allPodsWithCertainState []string
	allPodsWithLabel, getPodErr := compat_otp.GetAllPodsWithLabel(oc, namespace, label)
	o.Expect(getPodErr).NotTo(o.HaveOccurred())
	o.Expect(len(allPodsWithLabel)).ShouldNot(o.Equal(0))

	for _, eachPod := range allPodsWithLabel {
		podStatus, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, eachPod).Output()
		if strings.Contains(podStatus, podState) {
			allPodsWithCertainState = append(allPodsWithCertainState, eachPod)
		}
	}
	return allPodsWithCertainState
}

// Get OVN-Kubernetes management interface (ovn-k8s-mp0) IPv6 address for the node
func getOVNK8sNodeMgmtIPv6(oc *exutil.CLI, nodeName string) string {
	var cmdOutput string
	var err error
	checkErr := wait.Poll(2*time.Second, 10*time.Second, func() (bool, error) {
		cmdOutput, err = compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", "/usr/sbin/ip -o -6 addr show dev ovn-k8s-mp0 | awk '$3 == \"inet6\" && $6 == \"global\" {print $4}' | cut -d'/' -f1")
		if cmdOutput == "" || err != nil {
			e2e.Logf("Did not get node's IPv6 management interface, errors: %v, try again", err)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Failed to get IPv6 management interface for node %v, err: %v", nodeName, checkErr))

	nodeOVNK8sMgmtIPv6 := strings.Split(cmdOutput, "\n")[0]
	return nodeOVNK8sMgmtIPv6
}

// Get joint switch IP(s) by node name
func getJoinSwitchIPofNode(oc *exutil.CLI, nodeName string) ([]string, []string) {
	// get the ovnkube-node pod on the node
	ovnKubePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	o.Expect(ovnKubePod).ShouldNot(o.Equal(""))
	var cmdOutput string
	var joinSwitchIPv4s, joinSwitchIPv6s []string
	var cmdErr error
	cmd := "ovn-nbctl get logical_router_port rtoj-GR_" + nodeName + " networks"
	checkOVNDbErr := wait.Poll(3*time.Second, 2*time.Minute, func() (bool, error) {
		cmdOutput, cmdErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubePod, "northd", cmd)
		if cmdOutput == "" || cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try again ...,", cmdErr)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkOVNDbErr, fmt.Sprintf("Failed to get join switch networks for node %v, err: %v", nodeName, checkOVNDbErr))

	// output string would be something like: ["100.64.0.8/16", "fd98::8/64"]
	rightTrimed := strings.TrimRight(strings.TrimLeft(cmdOutput, "["), "]") //trim left [ and right ] from the output string
	outputs := strings.Split(rightTrimed, ", ")
	if len(outputs) > 0 {
		for _, str := range outputs {
			ipv4orv6 := strings.TrimRight(strings.TrimLeft(str, "\""), "\"") // trim left " and right " around IP address string
			if IsIPv4(ipv4orv6) {
				joinSwitchIPv4s = append(joinSwitchIPv4s, ipv4orv6)
			}
			if IsIPv6(ipv4orv6) {
				joinSwitchIPv6s = append(joinSwitchIPv6s, ipv4orv6)
			}
		}
	}
	return joinSwitchIPv4s, joinSwitchIPv6s
}

// Get host network IPs in NBDB of node
func getHostNetworkIPsinNBDB(oc *exutil.CLI, nodeName string, externalID string) []string {
	// get the ovnkube-node pod on the node
	ovnKubePod, podErr := compat_otp.GetPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node", nodeName)
	o.Expect(podErr).NotTo(o.HaveOccurred())
	o.Expect(ovnKubePod).ShouldNot(o.Equal(""))
	var cmdOutput string
	var hostNetworkIPs []string
	var cmdErr error
	cmd := "ovn-nbctl --column address find address_set " + externalID
	checkOVNDbErr := wait.Poll(3*time.Second, 2*time.Minute, func() (bool, error) {
		cmdOutput, cmdErr = compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnKubePod, "northd", cmd)
		if cmdOutput == "" || cmdErr != nil {
			e2e.Logf("%v,Waiting for expected result to be synced, try again ...,", cmdErr)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkOVNDbErr, fmt.Sprintf("Failed to get host network IPs for node %v, err: %v", nodeName, checkOVNDbErr))

	// two example outputs from "ovn-nbctl --column address find address_set <externalID>" command
	// addresses           : ["10.128.0.2", "10.128.2.2", "10.129.0.2", "10.130.0.2", "10.130.2.2", "10.131.2.2", "100.64.0.2"]
	// addresses           : ["fd01:0:0:1::2", "fd01:0:0:2::2", "fd01:0:0:3::2", "fd01:0:0:5::2", "fd01:0:0:7::2", "fd01:0:0:8::2"]
	// match out all IP (v4 or v6) addresses under " "
	re := regexp.MustCompile(`"[^",]+"`)
	ipStrs := re.FindAllString(cmdOutput, -1)
	for _, eachIpString := range ipStrs {
		ip := strings.TrimRight(strings.TrimLeft(eachIpString, "\""), "\"") //trim left " and right " from the string to get IP address
		hostNetworkIPs = append(hostNetworkIPs, ip)
	}
	return hostNetworkIPs
}

// Check if second array is a subset of first array
func unorderedContains(first, second []string) bool {
	set := make(map[string]bool)

	for _, element := range first {
		set[element] = true
	}

	for _, element := range second {
		if !set[element] {
			return false
		}
	}

	return true
}

// Get all host CIDRs for a cluster node, including those for multiple interefaces
func getAllHostCIDR(oc *exutil.CLI, nodeName string) ([]string, []string) {
	var allNodeIPsv4, allNodeIPsv6 []string
	outputString, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-o=jsonpath={.metadata.annotations.k8s\\.ovn\\.org\\/host-cidrs}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	// sample output from the command:  ["172.22.0.237/24","192.168.111.25/24","fd2e:6f44:5dd8:c956::19/128"]
	hostCIDRsString := strings.TrimRight(strings.TrimLeft(outputString, "["), "]") // trim the left [ and right ] around the CIDRs string
	hostCIDRs := strings.Split(hostCIDRsString, ",")

	if len(hostCIDRs) != 0 {
		for _, eachCIDR := range hostCIDRs {
			ipString := strings.TrimRight(strings.TrimLeft(eachCIDR, "\""), "\"") // trim the left " and right "" around the IP string
			ip := strings.Split(ipString, "/")[0]                                 //remove IP prefix, only get IP address
			if IsIPv4(ip) {
				allNodeIPsv4 = append(allNodeIPsv4, ip)
			}
			if IsIPv6(ip) {
				allNodeIPsv6 = append(allNodeIPsv6, ip)
			}
		}
	}
	e2e.Logf("\n cluster ipStackType: %s, for node %s, got all its v4 CIDRs: %v, v6 CIDRs: %v\n", checkIPStackType(oc), nodeName, allNodeIPsv4, allNodeIPsv6)
	return allNodeIPsv4, allNodeIPsv6
}

// Check a node can be accessed from any of its host interface from a pod
func checkNodeAccessibilityFromAPod(oc *exutil.CLI, nodeName, ns, podName string) bool {
	// Get all host IPs of the node
	ipStackType := checkIPStackType(oc)
	allNodeIPsv4, allNodeIPsv6 := getAllHostCIDR(oc, nodeName)

	if ipStackType == "dualstack" || ipStackType == "ipv4single" {
		for _, nodeIPv4Addr := range allNodeIPsv4 {
			_, err := e2eoutput.RunHostCmd(ns, podName, "ping -c 2 "+nodeIPv4Addr)
			if err != nil {
				e2e.Logf(fmt.Sprintf("Access to node %s failed at interface %s", nodeName, nodeIPv4Addr))
				return false
			}
		}
	}
	if ipStackType == "dualstack" || ipStackType == "ipv6single" {
		for _, nodeIPv6Addr := range allNodeIPsv6 {
			_, err := e2eoutput.RunHostCmd(ns, podName, "ping -c 2 "+nodeIPv6Addr)
			if err != nil {
				e2e.Logf(fmt.Sprintf("Access to node %s failed at interface %s", nodeName, nodeIPv6Addr))
				return false
			}
		}
	}
	return true
}

func verifySctpConnPod2IP(oc *exutil.CLI, namespace, sctpServerPodIP, sctpServerPodName, sctpClientPodname string, pass bool) {
	e2e.Logf("sctpserver pod start to wait for sctp traffic")
	msg, err := e2eoutput.RunHostCmdWithRetries(namespace, sctpServerPodName, "ps aux | grep sctp", 3*time.Second, 30*time.Second)
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(msg, "/usr/bin/ncat -l 30102 --sctp") {
		e2e.Logf("sctpserver pod is already listening on port 30102.")
	} else {
		cmdNcat, _, _, _ := oc.AsAdmin().Run("exec").Args("-n", namespace, sctpServerPodName, "--", "/usr/bin/ncat", "-l", "30102", "--sctp").Background()
		defer cmdNcat.Process.Kill()
		e2e.Logf("check sctp process enabled in the sctp server pod")
		o.Eventually(func() string {
			msg, err := e2eoutput.RunHostCmdWithRetries(namespace, sctpServerPodName, "ps aux | grep sctp", 3*time.Second, 30*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())
			return msg
		}, "10s", "5s").Should(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "No sctp process running on sctp server pod")
	}

	e2e.Logf("sctpclient pod start to send sctp traffic")
	e2eoutput.RunHostCmd(namespace, sctpClientPodname, "echo 'Test traffic using sctp port from sctpclient to sctpserver' | { ncat -v "+sctpServerPodIP+" 30102 --sctp; }")

	e2e.Logf("server sctp process will end after get sctp traffic from sctp client")
	if pass {
		o.Eventually(func() string {
			msg, err := e2eoutput.RunHostCmdWithRetries(namespace, sctpServerPodName, "ps aux | grep sctp", 3*time.Second, 30*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())
			return msg
		}, "10s", "5s").ShouldNot(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "Sctp process didn't end after get sctp traffic from sctp client")
	} else {
		msg, err := e2eoutput.RunHostCmd(namespace, sctpServerPodName, "ps aux | grep sctp")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(msg).Should(o.ContainSubstring("/usr/bin/ncat -l 30102 --sctp"), "Sctp process ended after get sctp traffic from sctp client")
	}

}

// Get apiVIP or ingessVIP on the cluster (vSphere or BM)
func GetVIPOnCluster(oc *exutil.CLI, platform string, vipType string) []string {
	if !strings.Contains(platform, "baremetal") && !strings.Contains(platform, "vsphere") {
		g.Skip("Skip for non-vSphere/non-Baremetal cluster")
	}
	var cmdOutput, jsonpathstr string
	var err error
	var vips []string
	switch vipType {
	case "apiVIP":
		jsonpathstr = "-o=jsonpath={.status.platformStatus." + platform + ".apiServerInternalIPs}"
	case "ingressVIP":
		jsonpathstr = "-o=jsonpath={.status.platformStatus." + platform + ".ingressIPs}"
	default:
		e2e.Failf("VIP Type only can be apiVIP or ingressVIP")
	}

	checkErr := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		cmdOutput, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", jsonpathstr).Output()
		if cmdOutput == "" || err != nil {
			e2e.Logf("Did not get %s, errors: %v, try again", vipType, err)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Failed to get %s on this platform %v, err: %v", vipType, platform, checkErr))

	// match out all IP (v4 or v6) addresses under " "
	re := regexp.MustCompile(`"[^",]+"`)
	ipStrs := re.FindAllString(cmdOutput, -1)
	for _, eachIpString := range ipStrs {
		ip := strings.TrimRight(strings.TrimLeft(eachIpString, "\""), "\"") //trim left " and right " from the string to get IP address
		vips = append(vips, ip)
	}

	return vips
}

// Find apiVIP or ingressVIP node on vSphere or BM
func FindVIPNode(oc *exutil.CLI, vip string) string {
	nodeList, err := compat_otp.GetAllNodesbyOSType(oc, "linux")
	o.Expect(err).NotTo(o.HaveOccurred())
	defaultInt, _ := getDefaultInterface(oc)

	for _, node := range nodeList {
		output, err := compat_otp.DebugNode(oc, node, "bash", "-c", "ip add show "+defaultInt)
		o.Expect(err).NotTo(o.HaveOccurred())
		if strings.Contains(output, vip) {
			e2e.Logf("Node %s is VIP node", node)
			return node
		}
	}
	return ""
}

// Return IPv4 address and IPv4 address with prefix
func getIPv4AndIPWithPrefixForNICOnNode(oc *exutil.CLI, node, nic string) (string, string) {
	cmd := fmt.Sprintf("ip -4 -brief a show %s | awk '{print $3}' ", nic)
	output, debugNodeErr := compat_otp.DebugNode(oc, node, "bash", "-c", cmd)
	o.Expect(debugNodeErr).NotTo(o.HaveOccurred())
	pattern := `(\d+\.\d+\.\d+\.\d+/\d+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(output)
	o.Expect(len(matches) > 1).Should(o.BeTrue())
	ipAddressWithPrefix := matches[1]
	e2e.Logf("IP address with prefix:", ipAddressWithPrefix)

	ipParts := strings.Split(ipAddressWithPrefix, "/")
	ipAddress := ipParts[0]

	e2e.Logf("The IPv4 of interface %s on node %s is %s and ipAddressWithPrefix is %s", nic, node, ipAddress, ipAddressWithPrefix)
	return ipAddress, ipAddressWithPrefix
}

// check respective config availability for IPsec NS on external host specific to Beijing BM host.
// this func might be scaled up in future if we comes down to support net2net as well
func applyConfigTypeExtHost(leftPublicIP, configType string) error {
	switch configType {
	case "host2hostTransportRDU2":
		err := sshRunCmd(leftPublicIP, "core", "sudo cp /home/core/nstest_host2host_transport.conf.bak.rdu2 /etc/ipsec.d/nstest.conf && sudo systemctl restart ipsec")
		if err != nil {
			return fmt.Errorf("Could not apply host2host config. Check External Host %v", err)
		}
	case "host2hostTunnelRDU2":
		err := sshRunCmd(leftPublicIP, "core", "sudo cp /home/core/nstest_host2host_tunnel.conf.bak.rdu2 /etc/ipsec.d/nstest.conf && sudo systemctl restart ipsec")
		if err != nil {
			return fmt.Errorf("Could not apply host2host config. Check External Host %v", err)
		}
	case "host2netTransportRDU2":
		err := sshRunCmd(leftPublicIP, "core", "sudo cp /home/core/nstest_host2net_transport.conf.rdu2 /etc/ipsec.d/nstest.conf && sudo systemctl restart ipsec")
		if err != nil {
			return fmt.Errorf("Could not apply host2net config. Check External Host %v", err)
		}
	case "host2netTunnelRDU2":
		err := sshRunCmd(leftPublicIP, "core", "sudo cp /home/core/nstest_host2net_tunnel.conf.rdu2 /etc/ipsec.d/nstest.conf && sudo systemctl restart ipsec")
		if err != nil {
			return fmt.Errorf("Could not apply host2net config. Check External Host %v", err)
		}
	}
	return nil
}

// get hostname for LB service, this fuction is likely to be useful only for AWS, other public cloud platforms may not give LB service hostname
func getLBSVCHostname(oc *exutil.CLI, namespace, svc string) string {
	var LBSVCHostname string
	var cmdErr error

	platform := compat_otp.CheckPlatform(oc)
	if !strings.Contains(platform, "aws") {
		g.Skip("Skip for non-AWS cluster")
	}

	e2e.Logf("Getting the Load Balancer service hostname ...")
	getLBSVCHostnameErr := wait.Poll(5*time.Second, 2*time.Minute, func() (bool, error) {
		LBSVCHostname, cmdErr = oc.AsAdmin().WithoutNamespace().Run("get").Args("svc", svc, "-n", namespace, "-o=jsonpath={.status.loadBalancer.ingress[0].hostname}").Output()
		if cmdErr != nil || LBSVCHostname == "pending" || LBSVCHostname == "" {
			e2e.Logf("%v,Waiting for expected result to be synced, try again ...,", cmdErr)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(getLBSVCHostnameErr, fmt.Sprintf("Could not get LB service's hostname, err: %v", getLBSVCHostnameErr))

	return LBSVCHostname
}

// get IP address of LB service
func getLBSVCIP(oc *exutil.CLI, namespace string, svcName string) string {
	var svcExternalIP string
	var cmdErr error
	checkErr := wait.Poll(5*time.Second, 300*time.Second, func() (bool, error) {
		svcExternalIP, cmdErr = oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-n", namespace, svcName, "-o=jsonpath={.status.loadBalancer.ingress[0].ip}").Output()
		if svcExternalIP == "" || cmdErr != nil {
			e2e.Logf("Waiting for lb service IP assignment. Trying again...")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Failed to get externalIP to the externalIP service %s", svcName))

	return svcExternalIP
}

func getNetworkDiagnosticsAvailable(oc *exutil.CLI) string {
	statusOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("Network.config.openshift.io/cluster", "-o=jsonpath={.status.conditions[?(@.type == \"NetworkDiagnosticsAvailable\")].status}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	statusOutput = strings.ToLower(statusOutput)
	e2e.Logf("NetworkDiagnosticsAvailable status is %s", statusOutput)
	return statusOutput
}

func verifyDesitnationAccess(oc *exutil.CLI, podName, podNS, domainName string, passOrFail bool) {
	curlCmd := fmt.Sprintf("curl -s -I %s --connect-timeout 5 ", domainName)
	if passOrFail {
		_, err := e2eoutput.RunHostCmdWithRetries(podNS, podName, curlCmd, 10*time.Second, 20*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
		ipStackType := checkIPStackType(oc)
		if ipStackType == "dualstack" {
			curlCmd = fmt.Sprintf("curl -s -6 -I %s --connect-timeout 5", domainName)
			_, err := e2eoutput.RunHostCmdWithRetries(podNS, podName, curlCmd, 10*time.Second, 20*time.Second)
			o.Expect(err).NotTo(o.HaveOccurred())
		}

	} else {
		o.Eventually(func() error {
			_, err := e2eoutput.RunHostCmd(podNS, podName, curlCmd)
			return err
		}, "20s", "10s").Should(o.HaveOccurred())
	}
}

// First ip is ipv4, secondary is ipv6.
func getIPFromDnsName(dnsName string) (string, string) {
	ips, err := net.LookupIP(dnsName)
	o.Expect(err).NotTo(o.HaveOccurred())

	var ipv4, ipv6 string
	for _, ip := range ips {
		if ip.To4() != nil && ipv4 == "" {
			ipv4 = ip.String()
		} else if strings.Contains(ip.String(), ":") && ipv6 == "" {
			ipv6 = ip.String()
		}
		if ipv4 != "" && ipv6 != "" {
			break
		}
	}
	e2e.Logf("The resovled IPv4, IPv6 address for dns name %s is %s,%s", dnsName, ipv4, ipv6)
	return ipv4, ipv6
}

func verifyDstIPAccess(podName, podNS, ip string, passOrFail bool) {
	var curlCmd string
	if strings.Contains(ip, ":") {
		e2e.Logf("The IP %s is IPv6 address.", ip)
		curlCmd = fmt.Sprintf("curl -s -6 -I [%s] --connect-timeout 5 ", ip)
	} else {
		e2e.Logf("The IP %s is IPv4 address.", ip)
		curlCmd = fmt.Sprintf("curl -s -I %s --connect-timeout 5 ", ip)
	}

	if passOrFail {
		_, err := e2eoutput.RunHostCmdWithRetries(podNS, podName, curlCmd, 10*time.Second, 120*time.Second)
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		o.Eventually(func() error {
			_, err := e2eoutput.RunHostCmd(podNS, podName, curlCmd)
			return err
		}, "20s", "10s").Should(o.HaveOccurred())
	}
}

// Function to obtain API VIP on BM cluster
func GetAPIVIPOnCluster(oc *exutil.CLI) string {
	apiVIP := ""
	var err error
	o.Eventually(func() error {
		apiVIP, err = oc.WithoutNamespace().AsAdmin().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.baremetal.apiServerInternalIP}").Output()
		return err
	}, "60s", "5s").ShouldNot(o.HaveOccurred())

	return apiVIP
}

func (pod *httpserverPodResourceNode) createHttpservePodNodeByAdmin(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace, "CONTAINERPORT="+strconv.Itoa(int(pod.containerport)), "HOSTPORT="+strconv.Itoa(int(pod.hostport)), "NODENAME="+pod.nodename)
		if err1 != nil {
			e2e.Logf("the err:%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("fail to create pod %v", pod.name))
}

// CurlPod2NodePass checks connectivity from a pod to node that has httpserverPod on it
func CurlPod2NodePass(oc *exutil.CLI, namespaceSrc, podNameSrc, nodeNameDst, DstHostPort string) {
	nodeIP2, nodeIP1 := getNodeIP(oc, nodeNameDst)
	if nodeIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -I --connect-timeout 5 -s "+net.JoinHostPort(nodeIP1, DstHostPort))
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -I --connect-timeout 5 -s "+net.JoinHostPort(nodeIP2, DstHostPort))
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -I --connect-timeout 5 -s "+net.JoinHostPort(nodeIP1, DstHostPort))
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// CurlPod2PodFail ensures no connectivity from pod to node that has httpserverPod on it
func CurlPod2NodeFail(oc *exutil.CLI, namespaceSrc, podNameSrc, nodeNameDst, DstHostPort string) {
	nodeIP2, nodeIP1 := getNodeIP(oc, nodeNameDst)
	if nodeIP2 != "" {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -I --connect-timeout 5 -s "+net.JoinHostPort(nodeIP1, DstHostPort))
		o.Expect(err).To(o.HaveOccurred())
		_, err = e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -I --connect-timeout 5 -s "+net.JoinHostPort(nodeIP2, DstHostPort))
		o.Expect(err).To(o.HaveOccurred())
	} else {
		_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -I --connect-timeout 5 -s "+net.JoinHostPort(nodeIP1, DstHostPort))
		o.Expect(err).To(o.HaveOccurred())
	}
}

// CurlPod2HostPass checks connectivity from a pod to host that has httpserverPod on it
func CurlPod2HostPass(oc *exutil.CLI, namespaceSrc, podNameSrc, hostip, DstHostPort string) {
	_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -I --connect-timeout 5 -s "+net.JoinHostPort(hostip, DstHostPort))
	o.Expect(err).NotTo(o.HaveOccurred())
}

// CurlPod2HostFail ensures no connectivity from pod to host that has httpserverPod on it
func CurlPod2HostFail(oc *exutil.CLI, namespaceSrc, podNameSrc, hostip, DstHostPort string) {
	_, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -I --connect-timeout 5 -s "+net.JoinHostPort(hostip, DstHostPort))
	o.Expect(err).To(o.HaveOccurred())
}

// Check the cluster is fips enabled
func checkFips(oc *exutil.CLI) bool {
	node, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "--selector=node-role.kubernetes.io/worker,kubernetes.io/os=linux", "-o=jsonpath={.items[0].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	fipsInfo, err := compat_otp.DebugNodeWithChroot(oc, node, "bash", "-c", "fips-mode-setup --check")
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(fipsInfo, "FIPS mode is disabled.") {
		e2e.Logf("FIPS is not enabled.")
		return false
	}
	e2e.Logf("FIPS is enabled.")
	return true
}

// Check whether it is able to access public web with IPv6 address
func checkIPv6PublicAccess(oc *exutil.CLI) bool {
	workNode, err := compat_otp.GetFirstWorkerNode(oc)
	o.Expect(err).ShouldNot(o.HaveOccurred())
	curlCMD := "curl -6 www.google.com --connect-timeout 5 -I"
	output, err := compat_otp.DebugNode(oc, workNode, "bash", "-c", curlCMD)
	if !strings.Contains(output, "HTTP") || err != nil {
		e2e.Logf(output)
		e2e.Logf("Unable to access the public Internet with IPv6 from the cluster.")
		return false
	}
	e2e.Logf("Successfully connected to the public Internet with IPv6 from the cluster.")
	return true
}

func forceRebootNode(oc *exutil.CLI, nodeName string) {
	e2e.Logf("\nRebooting node %s....", nodeName)
	runCmd, _, _, runCmdErr := oc.AsAdmin().Run("debug").Args("node/"+nodeName, "--", "chroot", "/host", "reboot", "--force").Background()
	defer runCmd.Process.Kill()
	o.Expect(runCmdErr).NotTo(o.HaveOccurred())
	waitForNetworkOperatorState(oc, 100, 15, "True.*False.*False")
}

// Create resources in the specified namespace from the file (not template) that is expected to fail
func createResourceFromFileWithError(oc *exutil.CLI, ns, file string) error {
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", file, "-n", ns).Execute()
	return err
}

// Struct to create pod with customized response
type customResponsePodResource struct {
	name        string
	namespace   string
	labelKey    string
	labelVal    string
	responseStr string
	template    string
}

func (pod *customResponsePodResource) createCustomResponsePod(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplate(oc, "--ignore-unknown-parameters=true", "-f", pod.template, "-p", "NAME="+pod.name, "NAMESPACE="+pod.namespace,
			"LABELKEY="+pod.labelKey, "LABELVAL="+pod.labelVal,
			"RESPONSESTR="+pod.responseStr)
		if err1 != nil {
			e2e.Logf("the err:%v, and try again...", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create pod %s due to %v", pod.name, err))
}

// Struct to create service with session ability
type sessionAffinityServiceResource struct {
	name           string
	namespace      string
	ipFamilyPolicy string
	selLabelKey    string
	SelLabelVal    string
	template       string
}

func (svc *sessionAffinityServiceResource) createSessionAffiniltyService(oc *exutil.CLI) {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplate(oc, "--ignore-unknown-parameters=true", "-f", svc.template, "-p", "NAME="+svc.name, "NAMESPACE="+svc.namespace,
			"IPFAMILYPOLICY="+svc.ipFamilyPolicy, "SELLABELKEY="+svc.selLabelKey, "SELLABELVAL="+svc.SelLabelVal)
		if err1 != nil {
			e2e.Logf("the err:%v, and try again...", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create pservice %s due to %v", svc.name, err))
}

func getEnabledFeatureGates(oc *exutil.CLI) ([]string, error) {
	enabledFeatureGates, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("featuregate", "cluster", "-o=jsonpath={.status.featureGates[0].enabled[*].name}").Output()
	if err != nil {
		return nil, err
	}

	return strings.Split(enabledFeatureGates, " "), nil
}

// IsFeaturegateEnabled check whether a featuregate is in enabled or not
func IsFeaturegateEnabled(oc *exutil.CLI, featuregate string) (bool, error) {
	enabledFeatureGates, err := getEnabledFeatureGates(oc)
	if err != nil {
		return false, err
	}
	for _, f := range enabledFeatureGates {
		if f == featuregate {
			return true, nil
		}
	}
	return false, nil
}

func SkipIfNoFeatureGate(oc *exutil.CLI, featuregate string) {
	enabled, err := IsFeaturegateEnabled(oc, featuregate)
	o.Expect(err).NotTo(o.HaveOccurred(), "Error getting enabled featuregates")

	if !enabled {
		g.Skip(fmt.Sprintf("Featuregate %s is not enabled in this cluster", featuregate))
	}
}

// Create VF policy through NMstate
func (vrf *VRFResource) createVRF(oc *exutil.CLI) error {
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", vrf.template, "-p", "NAME="+vrf.name, "INTFNAME="+vrf.intfname, "NODENAME="+vrf.nodename, "TABLEID="+strconv.Itoa(int(vrf.tableid)))
		if err1 != nil {
			e2e.Logf("Creating VRF on the node failed :%v, and try next round", err1)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("fail to create VRF on the node %v", vrf.name)
	}
	return nil
}

func (namedPortPod *namedPortPodResource) createNamedPortPod(oc *exutil.CLI) {
	compat_otp.By("Creating named port pod from template")
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		err1 := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", namedPortPod.template, "-p", "NAME="+namedPortPod.name,
			"NAMESPACE="+namedPortPod.namespace, "PODLABELKEY="+namedPortPod.podLabelKey, "PODLABELVAL="+namedPortPod.podLabelVal,
			"PORTNAME="+namedPortPod.portname, "CONTAINERPORT="+strconv.Itoa(int(namedPortPod.containerport)))
		if err1 != nil {
			e2e.Logf("Error creating resource:%v, and trying again", err1)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Failed to create named port pod %v", namedPortPod.name))
}

func getTcpdumpOnNodeCmdFromPod(oc *exutil.CLI, nodeName, tcpdumpCmd, namespace, podname, cmdOnPod string) string {
	compat_otp.By("Enable tcpdump on node")
	cmdTcpdump, cmdOutput, _, err := oc.AsAdmin().Run("debug").Args("-n", "default", "node/"+nodeName, "--", "bash", "-c", tcpdumpCmd).Background()
	defer cmdTcpdump.Process.Kill()
	o.Expect(err).NotTo(o.HaveOccurred())

	//Wait 5 seconds to let the tcpdump ready for capturing traffic
	time.Sleep(5 * time.Second)

	compat_otp.By("Curl external host:port from test pods")

	var tcpdumpErr error = nil
	checkErr := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
		_, curlErr := e2eoutput.RunHostCmd(namespace, podname, cmdOnPod)
		if curlErr == nil {
			tcpdumpErr = cmdTcpdump.Wait()
			e2e.Logf("The captured tcpdump outout is: \n%s\n", cmdOutput.String())
		}
		if curlErr != nil || tcpdumpErr != nil {
			e2e.Logf("Getting error at executing curl command: %v or at waiting for tcpdump: %v, try again ...", curlErr, tcpdumpErr)
			return false, nil
		}
		if cmdOutput.String() == "" {
			e2e.Logf("Did not capture tcpdump packets,try again ...")
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, fmt.Sprintf("Unable to get tcpdump when curling from pod:%s from namespace: %s", podname, namespace))

	cmdTcpdump.Process.Kill()
	return cmdOutput.String()
}

func collectMustGather(oc *exutil.CLI, dstDir string, imageStream string, parameters []string) (string, error) {
	args := []string{"must-gather"}
	if dstDir != "" {
		args = append(args, "--dest-dir="+dstDir)
	}
	if imageStream != "" {
		args = append(args, "--image-stream="+imageStream)
	}
	if len(parameters) > 0 {
		args = append(args, "--")
		for _, param := range parameters {
			args = append(args, param)
		}
	}
	output, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args(args...).Output()
	if err != nil && strings.Contains(output, "ImagePullBackOff") {
		e2e.Logf("unable to pull image, try again...")
		output, err = oc.AsAdmin().WithoutNamespace().Run("adm").Args(args...).Output()
		if err != nil {
			e2e.Logf("collect must-gather failed, err: %v", err)
			return "", err
		}
	}
	return output, nil
}

func verifyPodConnCrossNodes(oc *exutil.CLI) bool {
	buildPruningBaseDir := testdata.FixturePath("networking")
	helloDaemonset := filepath.Join(buildPruningBaseDir, "hello-pod-daemonset.yaml")

	compat_otp.By("Create a temporay project for pods to pods connection checking.")
	oc.SetupProject()
	ns := oc.Namespace()

	compat_otp.By("Create hello-pod-daemonset in namespace.")
	createResourceFromFile(oc, ns, helloDaemonset)
	err := waitForPodWithLabelReady(oc, ns, "name=hello-pod")
	compat_otp.AssertWaitPollNoErr(err, "ipsec pods are not ready after killing pluto")

	compat_otp.By("Checking pods connection")
	return verifyPodConnCrossNodesSpecNS(oc, ns, "name=hello-pod")
}

func waitForPodsCount(oc *exutil.CLI, namespace, labelSelector string, expectedCount int, interval, timeout time.Duration) error {
	return wait.Poll(interval, timeout, func() (bool, error) {
		allPods, getPodErr := compat_otp.GetAllPodsWithLabel(oc, namespace, labelSelector)
		if getPodErr != nil {
			e2e.Logf("Error fetching pods: %v, retrying...", getPodErr)
			return false, nil
		}
		if len(allPods) == expectedCount {
			return true, nil // Condition met, exit polling
		}
		e2e.Logf("Expected %d pods, but found %d. Retrying...", expectedCount, len(allPods))
		return false, nil
	})
}

func verifyPodConnCrossNodesSpecNS(oc *exutil.CLI, namespace, podLabel string) bool {
	pass := true
	pods := getPodName(oc, namespace, podLabel)

	for _, srcPod := range pods {
		for _, targetPod := range pods {
			if targetPod != srcPod {
				podIP1, podIP2 := getPodIP(oc, namespace, targetPod)
				e2e.Logf("Curling from pod: %s with IP: %s\n", srcPod, podIP1)
				_, err := e2eoutput.RunHostCmd(namespace, srcPod, "curl --connect-timeout 10 -s "+net.JoinHostPort(podIP1, "8080"))
				if err != nil {
					e2e.Logf("pods connection failed from %s to %s:8080", srcPod, podIP1)
					srcNode, err := compat_otp.GetPodNodeName(oc, namespace, srcPod)
					o.Expect(err).NotTo(o.HaveOccurred())
					dstNode, err := compat_otp.GetPodNodeName(oc, namespace, targetPod)
					o.Expect(err).NotTo(o.HaveOccurred())
					e2e.Logf("Checking the if the pods's located nodes in SchedulingDisabled or NotReady status.")
					output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", srcNode, dstNode).Output()
					e2e.Logf(output)
					o.Expect(err).NotTo(o.HaveOccurred())
					if strings.Contains(output, "SchedulingDisabled") || strings.Contains(output, "NotReady") {
						continue
					}
					e2e.Logf("pods connection failed between nodes %s and %s", srcNode, dstNode)
					pass = false
				}
				if podIP2 != "" {
					e2e.Logf("Curling from pod: %s with IP: %s\n", srcPod, podIP2)
					_, err := e2eoutput.RunHostCmd(namespace, srcPod, "curl --connect-timeout 10 -s "+net.JoinHostPort(podIP2, "8080"))
					if err != nil {
						e2e.Logf("pods connection failed from %s to %s:8080", srcPod, podIP2)
						srcNode, err := compat_otp.GetPodNodeName(oc, namespace, srcPod)
						o.Expect(err).NotTo(o.HaveOccurred())
						dstNode, err := compat_otp.GetPodNodeName(oc, namespace, targetPod)
						o.Expect(err).NotTo(o.HaveOccurred())
						e2e.Logf("Checking the if the pods's located nodes in SchedulingDisabled or NotReady status.")
						output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", srcNode, dstNode).Output()
						e2e.Logf(output)
						o.Expect(err).NotTo(o.HaveOccurred())
						if strings.Contains(output, "SchedulingDisabled") || strings.Contains(output, "NotReady") {
							continue
						}
						e2e.Logf("pods connection failed between nodes %s and %s", srcNode, dstNode)
						pass = false
					}
				}

			}
		}
	}
	e2e.Logf("The pods connection pass check is %v ", pass)
	return pass
}

func checkIPSecNATTEanbled(oc *exutil.CLI) bool {
	ovnPod := getPodName(oc, "openshift-ovn-kubernetes", "app=ovnkube-node")[0]
	cmd := "ovn-nbctl --no-leader-only get NB_Global . options"
	e2e.Logf("The command is: %v", cmd)
	out, err := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, "openshift-ovn-kubernetes", ovnPod, "nbdb", cmd)
	if err != nil {
		e2e.Logf("Execute command failed with  err:%v  and output is %v.", err, out)
	}
	o.Expect(err).NotTo(o.HaveOccurred())

	if strings.Contains(out, `ipsec_encapsulation="true"`) {
		e2e.Logf("The cluster is IPSec enabled NAT-T.")
		return true
	} else {
		e2e.Logf("The cluster is IPSec enabled with ESP.")
		return false
	}
}

func verifyIPSecLoaded(oc *exutil.CLI, nodeName string, num int) {
	var expectedNum int
	if num == 0 {
		expectedNum = 0
	} else {
		expectedNum = (num - 1) * 2
	}
	cmd := `ipsec status | grep "Total IPsec connections"`
	// After node reboot, need to wait the IPSec connections loaded
	checkErr := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
		out, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", cmd)
		e2e.Logf("Total  IPsec connection is : \n%s", out)
		return strings.Contains(out, fmt.Sprintf("active %v", expectedNum)), err
	})
	compat_otp.AssertWaitPollNoErr(checkErr, "IPsec connections were not loaded completely!")
}

func PingNode2PodPass(oc *exutil.CLI, nodeName string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := getPodIP(oc, namespaceDst, podNameDst)
	if podIP2 != "" {
		_, err := compat_otp.DebugNode(oc, nodeName, "ping6", "-c", "4", podIP1)
		o.Expect(err).NotTo(o.HaveOccurred())
		_, err = compat_otp.DebugNode(oc, nodeName, "ping", "-c", "4", podIP2)
		o.Expect(err).NotTo(o.HaveOccurred())
	} else {
		if netutils.IsIPv6String(podIP1) {
			_, err := compat_otp.DebugNode(oc, nodeName, "ping6", "-c", "4", podIP1)
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			_, err := compat_otp.DebugNode(oc, nodeName, "ping", "-c", "4", podIP1)
			o.Expect(err).NotTo(o.HaveOccurred())
		}
	}
}

func PingNode2PodFail(oc *exutil.CLI, nodeName string, namespaceDst string, podNameDst string) {
	podIP1, podIP2 := getPodIP(oc, namespaceDst, podNameDst)
	if podIP2 != "" {
		_, err := compat_otp.DebugNode(oc, nodeName, "ping6", "-c", "4", podIP1)
		o.Expect(err).To(o.HaveOccurred())
		_, err = compat_otp.DebugNode(oc, nodeName, "ping", "-c", "4", podIP2)
		o.Expect(err).To(o.HaveOccurred())
	} else {
		if netutils.IsIPv6String(podIP1) {
			_, err := compat_otp.DebugNode(oc, nodeName, "ping6", "-c", "4", podIP1)
			o.Expect(err).To(o.HaveOccurred())
		} else {
			_, err := compat_otp.DebugNode(oc, nodeName, "ping", "-c", "4", podIP1)
			o.Expect(err).To(o.HaveOccurred())
		}
	}
}

// Check if BaselineCapabilities have been set
func isBaselineCapsSet(oc *exutil.CLI) bool {
	baselineCapabilitySet, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterversion", "version", "-o=jsonpath={.spec.capabilities.baselineCapabilitySet}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("baselineCapabilitySet parameters: %v\n", baselineCapabilitySet)
	return len(baselineCapabilitySet) != 0
}

// Check if component is listed in clusterversion.status.capabilities.enabledCapabilities
func isEnabledCapability(oc *exutil.CLI, component string) bool {
	enabledCapabilities, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterversion", "-o=jsonpath={.items[*].status.capabilities.enabledCapabilities}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("Cluster enabled capability parameters: %v\n", enabledCapabilities)
	return strings.Contains(enabledCapabilities, component)
}

// curl pod to external connectivity check
func curlPod2ExternalPass(oc *exutil.CLI, namespaceSrc string, podNameSrc string) {
	ipStack := checkIPStackType(oc)
	if (ipStack == "ipv4single") || (ipStack == "dualstack") {
		output, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -Ik --connect-timeout 5 www.google.com")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "200 OK")).To(o.BeTrue())
	} else {
		output, err := e2eoutput.RunHostCmd(namespaceSrc, podNameSrc, "curl -Ik --connect-timeout 5 www.google.com")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(output, "200 OK")).To(o.BeTrue())
	}
}

// Get MTU value of br-ex on the node
func getNodeMTU(oc *exutil.CLI, nodeName string) int {
	cmdMTU := `ip a show br-ex |grep mtu`
	out, err := compat_otp.DebugNodeWithChroot(oc, nodeName, "bash", "-c", cmdMTU)
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf(out)
	// Define regex to  capute mtu value
	re := regexp.MustCompile(`mtu (\d+)`)
	match := re.FindStringSubmatch(out)
	o.Expect(len(match) > 1).Should(o.BeTrue())
	e2e.Logf("MTU on node %s is : %s", nodeName, match[1])
	mtu, err := strconv.Atoi(match[1])
	if err == nil {
		return mtu
	} else {
		return 0
	}

}

// get mcp status as per nodeType
func getmcpStatus(oc *exutil.CLI, nodeRole string) error {
	return wait.Poll(60*time.Second, 15*time.Minute, func() (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("mcp", nodeRole, "-ojsonpath={.status.conditions[?(@.type=='Updating')].status}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("\nCurrent mcp UPDATING Status is %s\n", status)
		if strings.Contains(status, "False") {
			e2e.Logf("\nmcp updated successfully ")
		} else {
			e2e.Logf("\nmcp is still in UPDATING state")
			return false, nil
		}
		return true, nil
	})
}

// Enable/Disable IPsec, network co will reflect the state from mcp.
func checkCNORenderState(oc *exutil.CLI) {
	errCheck := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 180*time.Second, false, func(cxt context.Context) (bool, error) {
		expectedStatus := "True.*True.*False.*machine config pool in progressing state"
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "network").Output()
		if err != nil {
			e2e.Logf("Fail to get clusteroperator network, error:%s. Trying again", err)
			return false, nil
		}
		if matched, _ := regexp.MatchString(expectedStatus, output); !matched {
			e2e.Logf("Network operator state is:%s", output)
			return false, nil
		}
		return true, nil
	})
	compat_otp.AssertWaitPollNoErr(errCheck, "Timed out waiting for the expected condition")
}

// IPSec full mode option, support "Always/Auto"
func configIPSecEncyptOption(oc *exutil.CLI, encyptionOption string) {
	e2e.Logf("Configure IPSec full mode option as %s", encyptionOption)
	_, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("networks.operator.openshift.io", "cluster", "-p", "{\"spec\":{\"defaultNetwork\":{\"ovnKubernetesConfig\":{\"ipsecConfig\":{\"mode\":\"Full\",\"full\":{\"encapsulation\": \""+encyptionOption+"\"}}}}}}", "--type=merge").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	// check ovnkube-node ds rollout status and confirm if rollout has triggered
	checkErr := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("rollout").Args("status", "-n", "openshift-ovn-kubernetes", "ds", "ovnkube-node", "--timeout", "5m").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if strings.Contains(status, "rollout to finish") && strings.Contains(status, "successfully rolled out") {
			e2e.Logf("ovnkube rollout was triggerred and rolled out successfully")
			return true, nil
		}
		e2e.Logf("ovnkube rollout trigger hasn't happened yet. Trying again")
		return false, nil
	})
	compat_otp.AssertWaitPollNoErr(checkErr, "Timed out waiting for ovnkube-node ds rollout.")

}

// Wait mcp to be expected status.
// Updating:True/False Updated: True/False  Degraded:True/False
func waitMCPExpectedStatus(oc *exutil.CLI, mcp, mcptype, expectedStatus string) {
	// check ovnkube-node ds rollout status and confirm if rollout has triggered
	checkErr := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
		status, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("mcp", mcp, "-o=jsonpath={.status.conditions[?(@.type==\""+mcptype+"\")].status}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("MCP %s %s expected status is %s, current status is %s", mcp, mcptype, expectedStatus, status)
		if strings.Contains(expectedStatus, status) {
			return true, nil
		}
		return false, nil
	})

	compat_otp.AssertWaitPollNoErr(checkErr, "Timed out waiting for mcp to be expected status.")
}

func verifyIPSecLoadedInContainers(oc *exutil.CLI, num int) {
	e2e.Logf("The cluster is using IPSec containers")
	var expectedNum int
	if num == 0 {
		expectedNum = 0
	} else {
		expectedNum = (num - 1) * 2
	}
	cmd := `ipsec status | grep "Total IPsec connections"`
	ipsecNS := "openshift-ovn-kubernetes"
	// After node reboot, need to wait the IPSec connections loaded
	ipsecPods := getPodName(oc, ipsecNS, "app=ovn-ipsec")
	o.Expect(len(ipsecPods) > 0).Should(o.BeTrue())

	checkErr := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
		out, err := compat_otp.RemoteShPodWithBashSpecifyContainer(oc, ipsecNS, ipsecPods[0], "ovn-ipsec", cmd)
		e2e.Logf("Total  IPsec connection is : \n%s", out)
		return strings.Contains(out, fmt.Sprintf("active %v", expectedNum)), err
	})
	compat_otp.AssertWaitPollNoErr(checkErr, "IPsec connections were not loaded completely!")
}

func isRDUPlatformSuitable(oc *exutil.CLI) bool {
	msg, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("routes", "console", "-n", "openshift-console").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	validClusters := []string{
		"sriov.openshift-qe.sdn.com",
		"offload.openshift-qe.sdn.com",
		"sdn146.openshift-qe.sdn.com",
		"sdn147.openshift-qe.sdn.com",
		"sdn148.openshift-qe.sdn.com",
		"sdn149.openshift-qe.sdn.com",
		"sdn150.openshift-qe.sdn.com",
	}
	matched := false
	for _, cluster := range validClusters {
		if strings.Contains(msg, cluster) {
			matched = true
			break
		}
	}
	if !matched {
		g.Skip("This case will only run on QE RDU clusters. Skipping for other environments!")
		return false
	}
	return true
}

func getOpenshiftVersion(oc *exutil.CLI) string {
	version, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterversion/version", "-ojsonpath={.status.desired.version}").Output()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`^(\d+\.\d+)`)
	matches := re.FindStringSubmatch(version)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func createImageDigestMirrorSet(oc *exutil.CLI, imagedigestmirrorsetname string, imageDigestMirrorSetFile string) error {
	pollInterval := 10 * time.Second
	waitTimeout := 120 * time.Second
	err := oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", imageDigestMirrorSetFile).Execute()
	if err != nil {
		return fmt.Errorf("Error applying image digest mirror set: %w", err)
	}
	return wait.Poll(pollInterval, waitTimeout, func() (bool, error) {
		err := oc.AsAdmin().WithoutNamespace().
			Run("get").Args("imagedigestmirrorset", imagedigestmirrorsetname).Execute()
		return err == nil, nil
	})
}

func createCatalogSource(oc *exutil.CLI, operatorName string, catalogSourceName string, catalogNamespace string, catalogSourceTemplateFile string) error {
	pollInterval := 10 * time.Second
	waitTimeout := 120 * time.Second
	openshiftVersion := getOpenshiftVersion(oc)
	if openshiftVersion == "" {
		return fmt.Errorf("Failed to get OpenShift version")
	}
	image := "quay.io/redhat-user-workloads/ocp-art-tenant/art-fbc:ocp__" + openshiftVersion + "__" + operatorName + "-rhel9-operator"
	e2e.Logf("Creating catalog source with name  '%s' in namespace '%s'", catalogSourceName, catalogNamespace)
	err := applyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", catalogSourceTemplateFile, "-p", "CATALOGSOURCENAME="+catalogSourceName, "CATALOGNAMESPACE="+catalogNamespace, "IMAGE="+image)
	if err != nil {
		return fmt.Errorf("Error applying catalog source: %w", err)
	}

	// Wait for CatalogSource to exist and be ready
	return wait.Poll(pollInterval, waitTimeout, func() (bool, error) {
		// Check if CatalogSource exists
		err := oc.AsAdmin().WithoutNamespace().Run("get").Args("catalogsource", catalogSourceName, "-n", catalogNamespace).Execute()
		if err != nil {
			e2e.Logf("CatalogSource not found yet: %v", err)
			return false, nil
		}

		// Check if CatalogSource connection state is READY
		connectionState, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("catalogsource", catalogSourceName,
			"-n", catalogNamespace, "-o=jsonpath={.status.connectionState.lastObservedState}").Output()
		if err != nil {
			e2e.Logf("Failed to get connection state: %v", err)
			return false, nil
		}

		if string(connectionState) != "READY" {
			e2e.Logf("CatalogSource connection state is '%s', waiting for 'READY'", string(connectionState))
			return false, nil
		}

		// Check if registry pod is running and ready
		podName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", catalogNamespace,
			"-l", "olm.catalogSource="+catalogSourceName,
			"-o=jsonpath={.items[0].metadata.name}").Output()
		if err != nil || len(podName) == 0 {
			e2e.Logf("Registry pod not found yet: %v", err)
			return false, nil
		}

		// Check pod ready condition
		podReady, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", string(podName), "-n", catalogNamespace,
			"-o=jsonpath={.status.conditions[?(@.type=='Ready')].status}").Output()
		if err != nil {
			e2e.Logf("Failed to get pod ready status: %v", err)
			return false, nil
		}

		if string(podReady) != "True" {
			e2e.Logf("Registry pod '%s' is not ready yet: %s", string(podName), string(podReady))
			return false, nil
		}
		e2e.Logf("CatalogSource '%s' is ready with pod '%s'", catalogSourceName, string(podName))
		return true, nil
	})
}

func getOperatorCatalogSource(oc *exutil.CLI, catalog string, namespace string) string {
	if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "OperatorLifecycleManager")) {
		g.Skip("Skipping the test as baselinecaps have been set and OperatorLifecycleManager capability is not enabled!")
	}
	catalogSourceNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("catalogsource", "-n", namespace, "-o=jsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(catalogSourceNames, catalog) {
		return catalog
	} else {
		return ""
	}
}

func getImageDigestMirrorSet(oc *exutil.CLI, imagedigestmirrorsetname string) string {
	imageDigestMirrorSetNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("imagedigestmirrorset", "-o=jsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	if strings.Contains(imageDigestMirrorSetNames, imagedigestmirrorsetname) {
		return imagedigestmirrorsetname
	} else {
		return ""
	}
}

// setupOperatorCatalogSource checks if stage-registry-idms exists and sets up the catalog source accordingly.
// If stage-registry-idms exists, it returns "qe-app-registry" as the catalog source name without creating resources.
// Otherwise, it creates the image digest mirror set and catalog source as needed, then returns the catalog source name.
// operatorName: the name of the operator (e.g., "ingress-node-firewall", "kubernetes-nmstate", "metallb")
func setupOperatorCatalogSource(oc *exutil.CLI, operatorName, defaultCatalogSourceName, imageDigestMirrorSetName, catalogNamespace, imageDigestMirrorSetFile, catalogSourceTemplate string) string {
	compat_otp.By("Check the image digest mirror set and catalog source")
	// Check if stage-registry-idms exists
	idmsList, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("idms", "-o=jsonpath={.items[*].metadata.name}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	if strings.Contains(idmsList, "stage-registry-idms") {
		compat_otp.By("stage-registry-idms found, using qe-app-registry directly")
		return "qe-app-registry"
	}

	// Create image digest mirror set if needed
	imageDigestMirrorSet := getImageDigestMirrorSet(oc, imageDigestMirrorSetName)
	if imageDigestMirrorSet == "" {
		compat_otp.By("Creating image digest mirror set")
		o.Expect(createImageDigestMirrorSet(oc, imageDigestMirrorSetName, imageDigestMirrorSetFile)).NotTo(o.HaveOccurred())
	}

	// Create catalog source if needed
	catalogSource := getOperatorCatalogSource(oc, defaultCatalogSourceName, catalogNamespace)
	if catalogSource == "" {
		compat_otp.By("Creating catalog source")
		o.Expect(createCatalogSource(oc, operatorName, defaultCatalogSourceName, catalogNamespace, catalogSourceTemplate)).NotTo(o.HaveOccurred())
	}

	return defaultCatalogSourceName
}
