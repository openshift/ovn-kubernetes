// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	udnv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	infraapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/debug"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	testutils "k8s.io/kubernetes/test/utils"
	admissionapi "k8s.io/pod-security-admission/api"
	utilnet "k8s.io/utils/net"
)

// restartOVNKubeNodePod restarts the ovnkube-node pod from namespace, running on nodeName
func restartOVNKubeNodePod(clientset kubernetes.Interface, namespace string, nodeName string) error {
	ovnKubeNodePods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "app=ovnkube-node",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return fmt.Errorf("could not get ovnkube-node pods: %w", err)
	}

	if len(ovnKubeNodePods.Items) <= 0 {
		return fmt.Errorf("could not find ovnkube-node pod running on node %s", nodeName)
	}
	for _, pod := range ovnKubeNodePods.Items {
		if err := deletePodWithWait(context.TODO(), clientset, &pod); err != nil {
			return fmt.Errorf("could not delete ovnkube-node pod on node %s: %w", nodeName, err)
		}
	}

	framework.Logf("waiting for node %s to have running ovnkube-node pod", nodeName)
	err = wait.Poll(2*time.Second, 3*time.Minute, func() (bool, error) {
		ovnKubeNodePods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=ovnkube-node",
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err != nil {
			return false, fmt.Errorf("could not get ovnkube-node pods: %w", err)
		}

		if len(ovnKubeNodePods.Items) <= 0 {
			framework.Logf("Node %s has no ovnkube-node pod yet", nodeName)
			return false, nil
		}
		for _, pod := range ovnKubeNodePods.Items {
			if ready, err := testutils.PodRunningReady(&pod); !ready {
				framework.Logf("%v", err)
				return false, nil
			}
		}
		return true, nil
	})

	return err
}

// restartOVNKubeNodePodsInParallel restarts multiple ovnkube-node pods in parallel. See `restartOVNKubeNodePod`
func restartOVNKubeNodePodsInParallel(clientset kubernetes.Interface, namespace string, nodeNames ...string) error {
	framework.Logf("restarting ovnkube-node for %v", nodeNames)

	restartFuncs := make([]func() error, 0, len(nodeNames))
	for _, n := range nodeNames {
		nodeName := n
		restartFuncs = append(restartFuncs, func() error {
			return restartOVNKubeNodePod(clientset, namespace, nodeName)
		})
	}

	return utilerrors.AggregateGoroutines(restartFuncs...)
}

// This is a replacement for e2epod.DeletePodWithWait(), which does not handle pods that
// may be automatically restarted (https://issues.k8s.io/126785)
func deletePodWithWait(ctx context.Context, c kubernetes.Interface, pod *v1.Pod) error {
	if pod == nil {
		return nil
	}

	framework.Logf("Deleting pod %q in namespace %q", pod.Name, pod.Namespace)
	err := c.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil // assume pod was already deleted
		}
		return fmt.Errorf("pod Delete API error: %w", err)
	}
	framework.Logf("Wait up to %v for pod %q to be fully deleted", e2epod.PodDeleteTimeout, pod.Name)
	err = waitForPodNotFoundInNamespace(ctx, c, pod.Name, pod.Namespace, pod.UID, e2epod.PodDeleteTimeout)
	if err != nil {
		return fmt.Errorf("pod %q was not deleted: %w", pod.Name, err)
	}
	return nil
}

// This is a replacement for e2epod.DeletePodWithWaitByName(), which does not handle pods
// that may be automatically restarted (https://issues.k8s.io/126785)
func deletePodWithWaitByName(ctx context.Context, c kubernetes.Interface, podName, podNamespace string) error {
	pod, err := c.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil // assume pod was already deleted
		}
		return fmt.Errorf("pod Get API error: %w", err)
	}
	if pod.UID == "" {
		return fmt.Errorf("unexpected Pod with no UID returned from API!")
	}
	return deletePodWithWait(ctx, c, pod)
}

// This is an alternative version of e2epod.WaitForPodNotFoundInNamespace(), which takes
// a UID as well.
func waitForPodNotFoundInNamespace(ctx context.Context, c kubernetes.Interface, podName, ns string, uid types.UID, timeout time.Duration) error {
	err := framework.Gomega().Eventually(ctx, framework.HandleRetry(func(ctx context.Context) (*v1.Pod, error) {
		pod, err := c.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		if pod != nil && pod.UID != uid {
			return nil, nil
		}
		return pod, err
	})).WithTimeout(timeout).Should(gomega.BeNil())
	if err != nil {
		return fmt.Errorf("expected pod to not be found: %w", err)
	}
	return nil
}

func getFirstIPStringOfFamily(family utilnet.IPFamily, ips []string) string {
	for _, ip := range ips {
		if utilnet.IPFamilyOfString(ip) == family {
			return ip
		}
	}
	return ""
}

func getSupportedIPFamilies(cs kubernetes.Interface) (bool, bool) {
	n, err := e2enode.GetRandomReadySchedulableNode(context.TODO(), cs)
	framework.ExpectNoError(err, "must fetch a Ready Node")
	v4NodeAddrs := e2enode.GetAddressesByTypeAndFamily(n, v1.NodeInternalIP, v1.IPv4Protocol)
	v6NodeAddrs := e2enode.GetAddressesByTypeAndFamily(n, v1.NodeInternalIP, v1.IPv6Protocol)
	return len(v4NodeAddrs) > 0, len(v6NodeAddrs) > 0
}

func getSupportedIPFamiliesSlice(cs kubernetes.Interface) []utilnet.IPFamily {
	v4, v6 := getSupportedIPFamilies(cs)
	switch {
	case v4 && v6:
		return []utilnet.IPFamily{utilnet.IPv4, utilnet.IPv6}
	case v4:
		return []utilnet.IPFamily{utilnet.IPv4}
	case v6:
		return []utilnet.IPFamily{utilnet.IPv6}
	}
	return nil
}

// isControlPlaneNode checks if a node is a control plane (master) node
func isControlPlaneNode(node v1.Node) bool {
	if _, exists := node.Labels["node-role.kubernetes.io/master"]; exists {
		return true
	}
	if _, exists := node.Labels["node-role.kubernetes.io/control-plane"]; exists {
		return true
	}

	for _, taint := range node.Spec.Taints {
		if taint.Key == "node-role.kubernetes.io/master" ||
			taint.Key == "node-role.kubernetes.io/control-plane" {
			return true
		}
	}

	return false
}

func isLocalGWModeEnabled() bool {
	val, present := os.LookupEnv("OVN_GATEWAY_MODE")
	return present && val == "local"
}

// waitForNodeReadyState waits for the specified node to reach the desired Ready state within the given timeout
func waitForNodeReadyState(f *framework.Framework, nodeName string, timeout time.Duration, desiredReady bool) {
	var stateDescription, expectationMessage string
	if desiredReady {
		stateDescription = "Ready"
		expectationMessage = "Node should become Ready after startup"
	} else {
		stateDescription = "NotReady"
		expectationMessage = "Node should become NotReady after shutdown"
	}

	gomega.Eventually(func() bool {
		node, err := f.ClientSet.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
		if err != nil {
			framework.Logf("Error getting node %s: %v", nodeName, err)
			return false
		}

		for _, condition := range node.Status.Conditions {
			if condition.Type == v1.NodeReady {
				isReady := condition.Status == v1.ConditionTrue
				if isReady == desiredReady {
					framework.Logf("Node %s is now %s", nodeName, stateDescription)
					return true
				}
			}
		}
		return false
	}, timeout, 10*time.Second).Should(gomega.BeTrue(), expectationMessage)
}

func newTestFramework(basename string) *framework.Framework {
	f := newPrivilegedTestFramework(basename)
	ginkgo.JustAfterEach(func() {
		logLocation := "/var/log"
		coredumpDir := "/tmp/kind/logs/coredumps"
		dbLocation := "/var/lib/openvswitch"
		// https://github.com/ovn-kubernetes/ovn-kubernetes/issues/5782
		skippedCoredumps := []string{"zebra", "bgpd", "mgmtd", "bfdd"}

		var coredumpFiles []string
		files, err := os.ReadDir(coredumpDir)
		if err == nil {
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				fileName := file.Name()
				if slices.ContainsFunc(skippedCoredumps, func(s string) bool {
					return strings.Contains(fileName, s)
				}) {
					framework.Logf("Ignoring coredump for skipped process: %s", fileName)
					continue
				}
				coredumpFiles = append(coredumpFiles, fileName)
			}
		}

		if len(coredumpFiles) == 0 && !ginkgo.CurrentSpecReport().Failed() {
			return
		}

		ovsdbLocations := []string{"/etc/origin/openvswitch", "/etc/openvswitch"}
		dbs := []string{"ovnnb_db.db", "ovnsb_db.db"}
		ovsdb := "conf.db"

		testName := strings.Trim(
			regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(ginkgo.CurrentSpecReport().LeafNodeText, "_"),
			"_",
		)
		logDir := fmt.Sprintf("%s/e2e-dbs/%s-%s", logLocation, testName, f.UniqueName)
		nodes, err := f.ClientSet.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
		framework.ExpectNoError(err)
		for _, node := range nodes.Items {
			_, err = infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"mkdir", "-p", logDir})
			framework.ExpectNoError(err)

			for _, ovsdbLocation := range ovsdbLocations {
				_, err = infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"stat", fmt.Sprintf("%s/%s", ovsdbLocation, ovsdb)})
				if err == nil {
					_, err = infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"cp", "-f", fmt.Sprintf("%s/%s", ovsdbLocation, ovsdb),
						fmt.Sprintf("%s/%s", logDir, fmt.Sprintf("%s-%s", node.Name, ovsdb))})
					framework.ExpectNoError(err)
					break
				}
			}

			_, err = infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"stat", fmt.Sprintf("%s/%s", dbLocation, dbs[0])})
			if err == nil {
				for _, db := range dbs {
					_, err = infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"cp", "-f", fmt.Sprintf("%s/%s", dbLocation, db),
						fmt.Sprintf("%s/%s", logDir, db)})
					framework.ExpectNoError(err, "copy DBs to file location must succeed")
				}
			}
		}

		if len(coredumpFiles) != 0 {
			ginkgo.AbortSuite(fmt.Sprintf("Coredumps found during test execution: %s", strings.Join(coredumpFiles, ", ")))
		}
	})

	return f
}

func newPrivilegedTestFramework(basename string) *framework.Framework {
	f := framework.NewDefaultFramework(basename)
	f.NamespacePodSecurityLevel = admissionapi.LevelPrivileged
	f.DumpAllNamespaceInfo = func(ctx context.Context, f *framework.Framework, namespace string) {
		debug.DumpAllNamespaceInfo(context.TODO(), f.ClientSet, namespace)
	}
	return f
}

func matchL3SubnetsByIPFamilies(families sets.Set[utilnet.IPFamily], in ...udnv1.Layer3Subnet) (out []udnv1.Layer3Subnet) {
	for _, subnet := range in {
		if families.Has(utilnet.IPFamilyOfCIDRString(string(subnet.CIDR))) {
			out = append(out, subnet)
		}
	}
	return
}

func matchL2SubnetsByIPFamilies(families sets.Set[utilnet.IPFamily], in ...udnv1.CIDR) (out []udnv1.CIDR) {
	for _, subnet := range in {
		if families.Has(utilnet.IPFamilyOfCIDRString(string(subnet))) {
			out = append(out, subnet)
		}
	}
	return
}

// podNetworkAnnotation is the pod annotation key for OVN network info.
const podNetworkAnnotation = "k8s.ovn.org/pod-networks"

// podAnnotationRaw is the JSON-serialized form of a pod's network attachment.
type podAnnotationRaw struct {
	IPs      []string        `json:"ip_addresses"`
	MAC      string          `json:"mac_address"`
	Gateways []string        `json:"gateway_ips,omitempty"`
	Routes   []podRouteRaw   `json:"routes,omitempty"`
	IP       string          `json:"ip_address,omitempty"`
	Gateway  string          `json:"gateway_ip,omitempty"`
	Primary  bool            `json:"primary"`
}

type podRouteRaw struct {
	Dest    string `json:"dest"`
	NextHop string `json:"nextHop"`
}

// podAnnotationParsed holds the parsed form of a pod's network attachment.
type podAnnotationParsed struct {
	IPs      []*net.IPNet
	MAC      net.HardwareAddr
	Gateways []net.IP
	Routes   []podRouteParsed
	Primary  bool
}

type podRouteParsed struct {
	Dest    *net.IPNet
	NextHop net.IP
}

type annotationNotSetError struct {
	msg string
}

func (e annotationNotSetError) Error() string {
	return e.msg
}

func newAnnotationNotSetError(format string, args ...interface{}) error {
	return annotationNotSetError{msg: fmt.Sprintf(format, args...)}
}

func unmarshalPodAnnotation(annotations map[string]string, networkName string) (*podAnnotationParsed, error) {
	ovnAnnotation, ok := annotations[podNetworkAnnotation]
	if !ok {
		return nil, newAnnotationNotSetError("could not find OVN pod annotation in %v", annotations)
	}

	podNetworks := make(map[string]podAnnotationRaw)
	if err := json.Unmarshal([]byte(ovnAnnotation), &podNetworks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ovn pod annotation %q: %v", ovnAnnotation, err)
	}
	tempA := podNetworks[networkName]
	a := &tempA

	parsed := &podAnnotationParsed{Primary: a.Primary}
	var err error
	parsed.MAC, err = net.ParseMAC(a.MAC)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pod MAC %q: %v", a.MAC, err)
	}

	if len(a.IPs) == 0 {
		if a.IP == "" {
			return nil, fmt.Errorf("bad annotation data (neither ip_address nor ip_addresses is set)")
		}
		a.IPs = append(a.IPs, a.IP)
	} else if a.IP != "" && a.IP != a.IPs[0] {
		return nil, fmt.Errorf("bad annotation data (ip_address and ip_addresses conflict)")
	}
	for _, ipstr := range a.IPs {
		ip, ipnet, err := net.ParseCIDR(ipstr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pod IP %q: %v", ipstr, err)
		}
		ipnet.IP = ip
		parsed.IPs = append(parsed.IPs, ipnet)
	}

	if len(a.Gateways) == 0 {
		if a.Gateway != "" {
			a.Gateways = append(a.Gateways, a.Gateway)
		}
	} else if a.Gateway != "" && a.Gateway != a.Gateways[0] {
		return nil, fmt.Errorf("bad annotation data (gateway_ip and gateway_ips conflict)")
	}
	for _, gwstr := range a.Gateways {
		gw := net.ParseIP(gwstr)
		if gw == nil {
			return nil, fmt.Errorf("failed to parse pod gateway %q", gwstr)
		}
		parsed.Gateways = append(parsed.Gateways, gw)
	}

	for _, r := range a.Routes {
		route := podRouteParsed{}
		_, route.Dest, err = net.ParseCIDR(r.Dest)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pod route dest %q: %v", r.Dest, err)
		}
		if route.Dest.IP.IsUnspecified() {
			return nil, fmt.Errorf("bad podNetwork data: default route %v should be specified as gateway", route)
		}
		if r.NextHop != "" {
			route.NextHop = net.ParseIP(r.NextHop)
			if route.NextHop == nil {
				return nil, fmt.Errorf("failed to parse pod route next hop %q", r.NextHop)
			} else if utilnet.IsIPv6(route.NextHop) != utilnet.IsIPv6CIDR(route.Dest) {
				return nil, fmt.Errorf("pod route %s has next hop %s of different family", r.Dest, r.NextHop)
			}
		}
		parsed.Routes = append(parsed.Routes, route)
	}

	return parsed, nil
}

func getPodAnnotationForAttachment(pod *v1.Pod, attachmentName string) (*podAnnotationParsed, error) {
	result, err := unmarshalPodAnnotation(pod.Annotations, attachmentName)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall annotations for pod %q: %v", pod.Name, err)
	}
	return result, nil
}

func getPodAnnotationIPsForAttachment(k8sClient kubernetes.Interface, podNamespace, podName, attachmentName string) ([]*net.IPNet, error) {
	pod, err := k8sClient.CoreV1().Pods(podNamespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	podAnnotation, err := getPodAnnotationForAttachment(pod, attachmentName)
	if err != nil {
		return nil, err
	}
	return podAnnotation.IPs, nil
}

func namespacedName(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func getFirstCIDROfFamily(family utilnet.IPFamily, ipnets []*net.IPNet) *net.IPNet {
	for _, ipnet := range ipnets {
		if utilnet.IPFamilyOfCIDR(ipnet) == family {
			return ipnet
		}
	}
	return nil
}

// podIPsForUserDefinedPrimaryNetwork returns the v4 or v6 IPs for a pod on the UDN
func getPodAnnotationIPsForPrimaryNetworkByIPFamily(k8sClient kubernetes.Interface, podNamespace, podName, networkName string, family utilnet.IPFamily) (string, error) {
	if networkName != "default" {
		networkName = namespacedName(podNamespace, networkName)
	}
	ipnets, err := getPodAnnotationIPsForAttachment(k8sClient, podNamespace, podName, networkName)
	if err != nil {
		return "", err
	}
	ipnet := getFirstCIDROfFamily(family, ipnets)
	if ipnet == nil {
		return "", nil
	}
	return ipnet.IP.String(), nil
}

// =============================================================================
// EVPN Utilities
// =============================================================================

const (
	// externalFRRContainerName is the name of the external FRR container
	// created during KIND cluster setup with BGP enabled (./contrib/kind.sh -rae)
	externalFRRContainerName = "frr"
)

// randomVNI generates a random VXLAN Network Identifier in the valid 24-bit range (1-16777215).
func randomVNI() int32 {
	return int32(randomN(16777215)) + 1
}

// newL3IPVRFNetworkSpec returns a new Layer3 CUDN EVPN IP-VRF network specification
// with the given CUDN subnets and a random VNI, filtered to only include CIDRs for the
// IP families supported by the cluster.
func newL3IPVRFNetworkSpec(ipFamilySet sets.Set[utilnet.IPFamily], cudnIPv4, cudnIPv6 string) *udnv1.NetworkSpec {
	var subnets []udnv1.Layer3Subnet
	if ipFamilySet.Has(utilnet.IPv4) {
		subnets = append(subnets, udnv1.Layer3Subnet{CIDR: udnv1.CIDR(cudnIPv4)})
	}
	if ipFamilySet.Has(utilnet.IPv6) {
		subnets = append(subnets, udnv1.Layer3Subnet{CIDR: udnv1.CIDR(cudnIPv6)})
	}
	return &udnv1.NetworkSpec{
		Topology: udnv1.NetworkTopologyLayer3,
		Layer3: &udnv1.Layer3Config{
			Role:    udnv1.NetworkRolePrimary,
			Subnets: subnets,
		},
		Transport: udnv1.TransportOptionEVPN,
		EVPN: &udnv1.EVPNConfig{
			IPVRF: &udnv1.VRFConfig{
				VNI: randomVNI(),
			},
		},
	}
}

// newL2MACVRFNetworkSpec returns a new Layer2 CUDN EVPN MAC-VRF network specification
// with the given CUDN subnets and a random VNI, filtered to only include CIDRs for the
// IP families supported by the cluster.
func newL2MACVRFNetworkSpec(ipFamilySet sets.Set[utilnet.IPFamily], cudnIPv4, cudnIPv6 string) *udnv1.NetworkSpec {
	var subnets udnv1.DualStackCIDRs
	if ipFamilySet.Has(utilnet.IPv4) {
		subnets = append(subnets, udnv1.CIDR(cudnIPv4))
	}
	if ipFamilySet.Has(utilnet.IPv6) {
		subnets = append(subnets, udnv1.CIDR(cudnIPv6))
	}
	return &udnv1.NetworkSpec{
		Topology: udnv1.NetworkTopologyLayer2,
		Layer2: &udnv1.Layer2Config{
			Role:    udnv1.NetworkRolePrimary,
			Subnets: subnets,
		},
		Transport: udnv1.TransportOptionEVPN,
		EVPN: &udnv1.EVPNConfig{
			MACVRF: &udnv1.VRFConfig{
				VNI: randomVNI(),
			},
		},
	}
}

// newL2MACVRFIPVRFNetworkSpec returns a new Layer2 CUDN EVPN network specification
// with both MAC-VRF and IP-VRF configured, using the given CUDN subnets and random VNIs,
// filtered to only include CIDRs for the IP families supported by the cluster.
func newL2MACVRFIPVRFNetworkSpec(ipFamilySet sets.Set[utilnet.IPFamily], cudnIPv4, cudnIPv6 string) *udnv1.NetworkSpec {
	var subnets udnv1.DualStackCIDRs
	if ipFamilySet.Has(utilnet.IPv4) {
		subnets = append(subnets, udnv1.CIDR(cudnIPv4))
	}
	if ipFamilySet.Has(utilnet.IPv6) {
		subnets = append(subnets, udnv1.CIDR(cudnIPv6))
	}
	return &udnv1.NetworkSpec{
		Topology: udnv1.NetworkTopologyLayer2,
		Layer2: &udnv1.Layer2Config{
			Role:    udnv1.NetworkRolePrimary,
			Subnets: subnets,
		},
		Transport: udnv1.TransportOptionEVPN,
		EVPN: &udnv1.EVPNConfig{
			MACVRF: &udnv1.VRFConfig{
				VNI: randomVNI(),
			},
			IPVRF: &udnv1.VRFConfig{
				VNI: randomVNI(),
			},
		},
	}
}

// vtyshCommand builds a shell command that invokes vtysh with single-quoted -c arguments.
func vtyshCommand(args ...string) []string {
	var parts []string
	for _, arg := range args {
		parts = append(parts, fmt.Sprintf("-c '%s'", arg))
	}
	return []string{"sh", "-c", "vtysh " + strings.Join(parts, " ")}
}

// setupVNIVIDMappingsOnExternalFRR sets up VLAN/VNI mappings for the given
// bridge and vxlan interfaces.
func setupVNIVIDMappingsOnExternalFRR(vni, vid int, bridgeName, vxlanName string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	vidStr := fmt.Sprintf("%d", vid)
	vniStr := fmt.Sprintf("%d", vni)
	commands := [][]string{
		{"bridge", "vlan", "add", "dev", bridgeName, "vid", vidStr, "self"},
		{"bridge", "vlan", "add", "dev", vxlanName, "vid", vidStr},
		{"bridge", "vni", "add", "dev", vxlanName, "vni", vniStr},
		{"bridge", "vlan", "add", "dev", vxlanName, "vid", vidStr, "tunnel_info", "id", vniStr},
	}
	for _, cmd := range commands {
		if _, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd); err != nil {
			return fmt.Errorf("failed to setup VLAN/VNI mappings (VNI %d, VID %d): %w", vni, vid, err)
		}
	}
	framework.Logf("VLAN/VNI mappings setup complete on %s (VNI %d, VID %d)", externalFRRContainerName, vni, vid)
	return nil
}

// setupSVIOnExternalFRR sets up a SVI on the provided VLAN and VLAN aware
// bridge and optionally attaches it to a VRF.
func setupSVIOnExternalFRR(ictx infraapi.Context, vid int, bridgeName, vrfName string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	vidStr := fmt.Sprintf("%d", vid)
	sviName := fmt.Sprintf("%s.%d", bridgeName, vid)

	_, err := infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "add", sviName, "link", bridgeName, "type", "vlan", "id", vidStr})
	if err != nil {
		return fmt.Errorf("failed to create SVI %s: %w", sviName, err)
	}
	ictx.AddCleanUpFn(func() error {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr,
			[]string{"ip", "link", "del", sviName})
		if err != nil {
			return fmt.Errorf("failed to delete SVI %s: %v", sviName, err)
		}
		framework.Logf("SVI %s cleanup complete on %s (VID %d, VRF: %q)", sviName, externalFRRContainerName, vid, vrfName)
		return nil
	})

	_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "set", sviName, "addrgenmode", "none"})
	if err != nil {
		return fmt.Errorf("failed to disable addrgen on SVI %s: %w", sviName, err)
	}

	if vrfName != "" {
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
			[]string{"ip", "link", "set", sviName, "master", vrfName})
		if err != nil {
			return fmt.Errorf("failed to bind SVI %s to VRF %s: %w", sviName, vrfName, err)
		}
	}

	_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "set", sviName, "up"})
	if err != nil {
		return fmt.Errorf("failed to bring up SVI %s: %w", sviName, err)
	}

	framework.Logf("SVI %s setup complete on %s (VID %d, VRF: %q)", sviName, externalFRRContainerName, vid, vrfName)
	return nil
}

// SetupEVPNBridgeOnExternalFRR creates a Linux bridge and VXLAN device on the external FRR
// container. This is the foundation for both MAC-VRF and IP-VRF tests.
//
// Creates:
//   - bridgeName (e.g. "brevpn7a3f"): Linux bridge with vlan_filtering enabled, vlan_default_pvid 0
//   - vxlanName  (e.g. "vxevpn7a3f"): VXLAN device in SVD (Single VXLAN Device) mode with vnifilter
//
// Cleanup is automatically registered via ictx.AddCleanUpFn().
func SetupEVPNBridgeOnExternalFRR(ictx infraapi.Context, frrVTEPIPAddress, bridgeName, vxlanName string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

	commands := [][]string{
		{"ip", "link", "add", bridgeName, "type", "bridge", "vlan_filtering", "1", "vlan_default_pvid", "0"},
		{"ip", "link", "set", bridgeName, "addrgenmode", "none"},
	}
	for _, cmd := range commands {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd)
		if err != nil {
			return fmt.Errorf("failed to execute %v: %w", cmd, err)
		}
	}

	vxlanCmd := []string{
		"ip", "link", "add", vxlanName, "type", "vxlan",
		"dstport", "4789",
		"local", frrVTEPIPAddress,
		"nolearning",
		"external",
		"vnifilter",
	}
	_, err := infraprovider.Get().ExecExternalContainerCommand(frr, vxlanCmd)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", vxlanName, err)
	}

	commands = [][]string{
		{"ip", "link", "set", vxlanName, "addrgenmode", "none"},
		{"ip", "link", "set", vxlanName, "master", bridgeName},
	}
	for _, cmd := range commands {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd)
		if err != nil {
			return fmt.Errorf("failed to execute %v: %w", cmd, err)
		}
	}

	commands = [][]string{
		{"ip", "link", "set", bridgeName, "up"},
		{"ip", "link", "set", vxlanName, "up"},
	}
	for _, cmd := range commands {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, cmd)
		if err != nil {
			return fmt.Errorf("failed to execute %v: %w", cmd, err)
		}
	}

	bridgeCmd := []string{
		"bridge", "link", "set", "dev", vxlanName,
		"vlan_tunnel", "on",
		"neigh_suppress", "on",
		"learning", "off",
	}
	_, err = infraprovider.Get().ExecExternalContainerCommand(frr, bridgeCmd)
	if err != nil {
		return fmt.Errorf("failed to configure %s bridge options: %w", vxlanName, err)
	}

	ictx.AddCleanUpFn(func() error {
		frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", vxlanName})
		if err != nil {
			return fmt.Errorf("failed to delete %s: %w", vxlanName, err)
		}
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr, []string{"ip", "link", "del", bridgeName})
		if err != nil {
			return fmt.Errorf("failed to delete %s: %w", bridgeName, err)
		}
		framework.Logf("EVPN bridge cleanup complete on %s", externalFRRContainerName)
		return nil
	})

	framework.Logf("EVPN bridge setup complete on %s (%s + %s with local IP %s)", externalFRRContainerName, bridgeName, vxlanName, frrVTEPIPAddress)
	return nil
}

// SetupMACVRFOnExternalFRR configures MAC-VRF (Layer 2 EVPN) on the external FRR container.
// Requires: SetupEVPNBridgeOnExternalFRR must be called first.
// Cleanup is automatically registered via ictx.AddCleanUpFn().
func SetupMACVRFOnExternalFRR(ictx infraapi.Context, vni, vid int, bridgeName, vxlanName string) error {
	if err := setupVNIVIDMappingsOnExternalFRR(vni, vid, bridgeName, vxlanName); err != nil {
		return fmt.Errorf("failed to configure VLAN/VNI mapping on bridge %s: %w", bridgeName, err)
	}
	if err := setupSVIOnExternalFRR(ictx, vid, bridgeName, ""); err != nil {
		return fmt.Errorf("failed to configure SVI for VID %d: %w", vid, err)
	}
	framework.Logf("MAC-VRF setup complete on %s (VNI %d)", externalFRRContainerName, vni)
	return nil
}

// SetupIPVRFOnExternalFRR configures IP-VRF (Layer 3 EVPN) on the external FRR container.
// Requires: SetupEVPNBridgeOnExternalFRR must be called first.
// Cleanup is automatically registered via ictx.AddCleanUpFn().
func SetupIPVRFOnExternalFRR(ictx infraapi.Context, vrfName string, vni, vid int, bridgeName, vxlanName string) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	vniStr := fmt.Sprintf("%d", vni)

	_, err := infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "add", vrfName, "type", "vrf", "table", vniStr})
	if err != nil {
		return fmt.Errorf("failed to create VRF %s: %w", vrfName, err)
	}

	_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
		[]string{"ip", "link", "set", vrfName, "up"})
	if err != nil {
		return fmt.Errorf("failed to bring up VRF %s: %w", vrfName, err)
	}

	ictx.AddCleanUpFn(func() error {
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr,
			[]string{"ip", "link", "del", vrfName})
		if err != nil {
			return fmt.Errorf("failed to delete Linux VRF %s: %v", vrfName, err)
		}
		_, err = infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand(
			"configure terminal", fmt.Sprintf("no vrf %s", vrfName), "end",
		))
		if err != nil {
			return fmt.Errorf("failed to delete FRR VRF definition %s: %v", vrfName, err)
		}
		framework.Logf("IP-VRF cleanup complete on %s (VNI %d)", externalFRRContainerName, vni)
		return nil
	})

	if err := setupVNIVIDMappingsOnExternalFRR(vni, vid, bridgeName, vxlanName); err != nil {
		return fmt.Errorf("failed to configure VLAN/VNI mapping on bridge %s: %w", bridgeName, err)
	}
	if err := setupSVIOnExternalFRR(ictx, vid, bridgeName, vrfName); err != nil {
		return fmt.Errorf("failed to configure SVI for VID %d: %w", vid, err)
	}

	framework.Logf("IP-VRF setup complete on %s (VNI %d)", externalFRRContainerName, vni)
	return nil
}

// RestoreFRRIPv6AfterVRFAssignment re-adds any IPv6 addresses in frrIPs that belong to
// one of the given subnets onto iface. Linux silently removes global IPv6 addresses when
// an interface is enslaved to a VRF device.
func RestoreFRRIPv6AfterVRFAssignment(frr infraapi.ExternalContainer, iface string, frrIPs, subnets []string) error {
	for _, frrIP := range frrIPs {
		if !utilnet.IsIPv6String(frrIP) {
			continue
		}
		for _, subnet := range subnets {
			if !utilnet.IsIPv6CIDRString(subnet) {
				continue
			}
			_, ipNet, err := net.ParseCIDR(subnet)
			if err != nil || !ipNet.Contains(net.ParseIP(frrIP)) {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			cidr := fmt.Sprintf("%s/%d", frrIP, ones)
			if _, addErr := infraprovider.Get().ExecExternalContainerCommand(frr,
				[]string{"ip", "-6", "addr", "replace", cidr, "dev", iface}); addErr != nil {
				return fmt.Errorf("failed to restore IPv6 address %s on %s after VRF assignment: %w", cidr, iface, addErr)
			}
			framework.Logf("Restored IPv6 address %s on %s after VRF assignment (kernel drops global IPv6 on VRF enslavement)", cidr, iface)
			break
		}
	}
	return nil
}

func randomN(n int) int {
	r, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand.Int failed: %v", err))
	}
	return int(r.Int64())
}

// randomVTEPSubnets generates a random VTEP subnet for parallel test isolation.
// Uses /24 (254 usable IPs) within RFC 6598 shared address space (100.64.0.0/10),
// giving 15,872 possible /24 subnets while avoiding:
//   - 100.64.0.0/16 (default join subnet)
//   - 100.65.0.0/16 (UDN primary join subnet)
//
// 100.88.0.0/16 (transit subnet) is NOT excluded because transit IPs are purely
// internal to OVN's logical network and never appear on physical interfaces.
// Safe second octets: 66-127 (62 values).
//
// Only IPv4 is returned: IPv6 VTEPs are not supported for EVPN transport.
func randomVTEPSubnets() string {
	second := randomN(62) + 66 // 66-127
	third := randomN(256)      // 0-255
	return fmt.Sprintf("100.%d.%d.0/24", second, third)
}

func getExternalFRRIP(ipFamilySet sets.Set[utilnet.IPFamily]) (string, error) {
	kindNetwork, err := infraprovider.Get().PrimaryNetwork()
	if err != nil {
		return "", err
	}
	frrNetIf, err := infraprovider.Get().GetExternalContainerNetworkInterface(infraapi.ExternalContainer{Name: externalFRRContainerName}, kindNetwork)
	if err != nil {
		return "", err
	}

	var externalFRRIP string
	switch {
	case ipFamilySet.Has(utilnet.IPv4) && frrNetIf.IPv4 != "":
		externalFRRIP = frrNetIf.IPv4
	case ipFamilySet.Has(utilnet.IPv6) && frrNetIf.IPv6 != "":
		externalFRRIP = frrNetIf.IPv6
	default:
		return "", fmt.Errorf("can't find external FRR IP on kind network")
	}
	return externalFRRIP, nil
}

// vtepLoopbackHostCIDR returns ip/prefix for loopback add/del and host-cidrs checks (/32 or /128).
func vtepLoopbackHostCIDR(ip net.IP) string {
	pl := 32
	if utilnet.IsIPv6(ip) {
		pl = 128
	}
	return fmt.Sprintf("%s/%d", ip.String(), pl)
}

// incrementIP returns a copy of ip with offset added. Works for both IPv4 and IPv6.
func incrementIP(baseIP net.IP, offset int) net.IP {
	ip := make(net.IP, len(baseIP))
	copy(ip, baseIP)
	for i := len(ip) - 1; i >= 0 && offset > 0; i-- {
		sum := int(ip[i]) + offset
		ip[i] = byte(sum % 256)
		offset = sum / 256
	}
	return ip
}

// nodeIPsOverlapCIDRs returns true if at least one node's InternalIP falls
// within one of the provided CIDRs.
func nodeIPsOverlapCIDRs(nodeList *v1.NodeList, cidrStrings []string) bool {
	var cidrs []*net.IPNet
	for _, s := range cidrStrings {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		cidrs = append(cidrs, ipNet)
	}
	for _, node := range nodeList.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type != v1.NodeInternalIP {
				continue
			}
			ip := net.ParseIP(addr.Address)
			if ip == nil {
				continue
			}
			for _, cidr := range cidrs {
				if cidr.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// EnsureVTEPLoopbackIPs seeds each node with a VTEP-reachable IP when the
// VTEP CIDRs are custom subnets that don't overlap with the node's existing
// InternalIPs. It allocates one IP per CIDR per node, adds it to the loopback
// interface, and waits for it to appear in host-cidrs.
//
// When node IPs already fall within the VTEP CIDRs (e.g. VTEP CIDRs match the
// node IP subnets) this is a no-op.
func ensureVTEPLoopbackIPs(
	f *framework.Framework,
	ictx infraapi.Context,
	vtepCIDRs []string,
) error {
	nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	if nodeIPsOverlapCIDRs(nodeList, vtepCIDRs) {
		return nil
	}

	var parsedCIDRs []*net.IPNet
	for _, cidr := range vtepCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse VTEP CIDR %q: %w", cidr, err)
		}
		parsedCIDRs = append(parsedCIDRs, ipNet)
	}

	for i, node := range nodeList.Items {
		for _, ipNet := range parsedCIDRs {
			ip := incrementIP(ipNet.IP, i+1)
			if !ipNet.Contains(ip) {
				return fmt.Errorf("ran out of IPs in CIDR %s for node %s", ipNet, node.Name)
			}
			hostCIDR := vtepLoopbackHostCIDR(ip)
			_, err := infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"ip", "addr", "replace", hostCIDR, "dev", "lo"})
			if err != nil {
				return fmt.Errorf("failed to add VTEP IP %s to loopback on node %s: %w", ip, node.Name, err)
			}
			framework.Logf("Added VTEP IP %s to loopback on node %s", hostCIDR, node.Name)
		}
		nodeName := node.Name
		allocatedIPs := make([]string, 0, len(parsedCIDRs))
		for _, ipNet := range parsedCIDRs {
			allocatedIPs = append(allocatedIPs, incrementIP(ipNet.IP, i+1).String())
		}
		err := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			n, err := f.ClientSet.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			hostCIDRs, err := util.ParseNodeHostCIDRs(n)
			if err != nil {
				return false, nil
			}
			for _, ipStr := range allocatedIPs {
				parsed := net.ParseIP(ipStr)
				if parsed == nil {
					return false, fmt.Errorf("invalid allocated VTEP IP %q", ipStr)
				}
				if !hostCIDRs.Has(vtepLoopbackHostCIDR(parsed)) {
					return false, nil
				}
			}
			return true, nil
		})
		if err != nil {
			return fmt.Errorf("timed out waiting for VTEP IPs %v to appear in host-cidrs on node %s: %w", allocatedIPs, nodeName, err)
		}
		framework.Logf("VTEP IPs %v confirmed in host-cidrs on node %s", allocatedIPs, nodeName)
	}

	ictx.AddCleanUpFn(func() error {
		nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return err
		}
		for i, node := range nodeList.Items {
			for _, ipNet := range parsedCIDRs {
				ip := incrementIP(ipNet.IP, i+1)
				_, _ = infraprovider.Get().ExecK8NodeCommand(node.Name, []string{"ip", "addr", "del", vtepLoopbackHostCIDR(ip), "dev", "lo"})
			}
		}
		return nil
	})

	return nil
}

// RestartExternalFRRDaemons force-kills the main FRR child processes inside the
// out-of-cluster FRR container (bgpd, zebra, staticd, bfdd, mgmtd) and leaves watchfrr
// and the container running. watchfrr then restarts the daemons, which reloads config
// from /etc/frr/frr.conf (kept in sync with "write memory" during test setup).
func restartExternalFRRDaemons() error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}

	framework.Logf("Restarting FRR daemons inside %q (keeping container alive)", externalFRRContainerName)

	for _, proc := range []string{"bgpd", "zebra", "staticd", "bfdd", "mgmtd"} {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr,
			[]string{"killall", "-9", proc})
		if err != nil {
			framework.Logf("killall %s: %v (may already be stopped)", proc, err)
		}
	}

	framework.Logf("Waiting for watchfrr to restart FRR daemons inside %q", externalFRRContainerName)
	return nil
}

// WaitForExternalFRRProcessReady polls until the FRR process inside the external container
// responds to "vtysh -c 'show version'". Used right after RestartExternalFRRDaemons to
// ensure FRR has fully started before attempting to re-apply kernel state or check BGP.
func waitForExternalFRRProcessReady(timeout time.Duration) error {
	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	return wait.PollImmediate(3*time.Second, timeout, func() (bool, error) {
		_, err := infraprovider.Get().ExecExternalContainerCommand(frr, vtyshCommand("show version"))
		if err != nil {
			framework.Logf("FRR process not ready yet: %v", err)
			return false, nil
		}
		return true, nil
	})
}

// RestartFRRK8sPods deletes all pods in the given namespace and waits for new
// pods to be Running and Ready.
func restartFRRK8sPods(clientset kubernetes.Interface, namespace string) error {
	ctx := context.TODO()
	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list FRR-K8s pods in %q: %w", namespace, err)
	}
	if len(podList.Items) == 0 {
		return fmt.Errorf("no FRR-K8s pods found in namespace %q", namespace)
	}
	expectedCount := len(podList.Items)

	framework.Logf("Deleting %d FRR-K8s pods in namespace %q", expectedCount, namespace)
	for i := range podList.Items {
		if err := deletePodWithWait(ctx, clientset, &podList.Items[i]); err != nil {
			return fmt.Errorf("failed to delete FRR-K8s pod %q: %w", podList.Items[i].Name, err)
		}
	}

	framework.Logf("Waiting for %d FRR-K8s pods to be Running/Ready in namespace %q", expectedCount, namespace)
	return wait.PollImmediate(5*time.Second, 3*time.Minute, func() (bool, error) {
		newList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, nil
		}
		if len(newList.Items) < expectedCount {
			framework.Logf("FRR-K8s pods: %d/%d present", len(newList.Items), expectedCount)
			return false, nil
		}
		for i := range newList.Items {
			pod := &newList.Items[i]
			if pod.Status.Phase != v1.PodRunning {
				framework.Logf("FRR-K8s pod %q not Running yet (phase: %s)", pod.Name, pod.Status.Phase)
				return false, nil
			}
			for _, c := range pod.Status.ContainerStatuses {
				if !c.Ready {
					framework.Logf("FRR-K8s pod %q container %q not Ready yet", pod.Name, c.Name)
					return false, nil
				}
			}
		}
		framework.Logf("All %d FRR-K8s pods are Running/Ready", expectedCount)
		return true, nil
	})
}

// WaitForEVPNRouteConvergence polls the external FRR container until all Established
// BGP neighbors show bidirectional route exchange in "show bgp l2vpn evpn summary json".
func waitForEVPNRouteConvergence(expectedNeighborCount int, timeout time.Duration) error {
	type bgpNeighbor struct {
		State  string `json:"state"`
		PfxRcd int    `json:"pfxRcd"`
		PfxSnt int    `json:"pfxSnt"`
	}
	type bgpSummary struct {
		Peers map[string]bgpNeighbor `json:"peers"`
	}

	frr := infraapi.ExternalContainer{Name: externalFRRContainerName}
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		out, err := infraprovider.Get().ExecExternalContainerCommand(frr,
			vtyshCommand("show bgp l2vpn evpn summary json"))
		if err != nil {
			framework.Logf("WaitForEVPNRouteConvergence: vtysh error: %v", err)
			return false, nil
		}

		var summary bgpSummary
		if err := json.Unmarshal([]byte(out), &summary); err != nil {
			framework.Logf("WaitForEVPNRouteConvergence: JSON parse error: %v", err)
			return false, nil
		}

		established := 0
		bidir := 0
		for ip, peer := range summary.Peers {
			if peer.State == "Established" {
				established++
				if peer.PfxRcd > 0 && peer.PfxSnt > 0 {
					bidir++
					framework.Logf("WaitForEVPNRouteConvergence: neighbor %s Established pfxRcd=%d pfxSnt=%d (bidirectional)", ip, peer.PfxRcd, peer.PfxSnt)
				} else {
					framework.Logf("WaitForEVPNRouteConvergence: neighbor %s Established pfxRcd=%d pfxSnt=%d (waiting for bidirectional exchange)", ip, peer.PfxRcd, peer.PfxSnt)
				}
			} else {
				framework.Logf("WaitForEVPNRouteConvergence: neighbor %s state=%s (not Established)", ip, peer.State)
			}
		}

		framework.Logf("WaitForEVPNRouteConvergence: %d/%d Established, %d/%d have bidirectional EVPN routes with spine",
			established, expectedNeighborCount, bidir, expectedNeighborCount)
		return established >= expectedNeighborCount && bidir >= expectedNeighborCount, nil
	})
}

// WaitForDaemonSetReady polls until a DaemonSet has all pods updated, ready, and available.
func waitForDaemonSetReady(clientset kubernetes.Interface, namespace, name string, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		ds, err := clientset.AppsV1().DaemonSets(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			framework.Logf("WaitForDaemonSetReady: error getting DaemonSet %s/%s: %v", namespace, name, err)
			return false, nil
		}
		ready := ds.Status.DesiredNumberScheduled > 0 &&
			ds.Status.DesiredNumberScheduled == ds.Status.NumberReady &&
			ds.Status.DesiredNumberScheduled == ds.Status.UpdatedNumberScheduled &&
			ds.Status.NumberUnavailable == 0
		if !ready {
			framework.Logf("DaemonSet %s/%s: desired=%d ready=%d updated=%d unavailable=%d",
				namespace, name,
				ds.Status.DesiredNumberScheduled, ds.Status.NumberReady,
				ds.Status.UpdatedNumberScheduled, ds.Status.NumberUnavailable)
		}
		return ready, nil
	})
}
