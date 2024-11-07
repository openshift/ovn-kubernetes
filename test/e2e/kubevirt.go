package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/diagnostics"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/images"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/kubevirt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/pointer"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	butaneconfig "github.com/coreos/butane/config"
	butanecommon "github.com/coreos/butane/config/common"

	ipamclaimsv1alpha1 "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1"
	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	kubevirtv1 "kubevirt.io/api/core/v1"
	kvmigrationsv1alpha1 "kubevirt.io/api/migrations/v1alpha1"
)

func newControllerRuntimeClient() (crclient.Client, error) {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	err = kubevirtv1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = kvmigrationsv1alpha1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = ipamclaimsv1alpha1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = nadv1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	return crclient.New(config, crclient.Options{
		Scheme: scheme,
	})
}

var _ = Describe("Kubevirt Virtual Machines", func() {
	var (
		fr                  = wrappedTestFramework("kv-live-migration")
		d                   = diagnostics.New(fr)
		crClient            crclient.Client
		namespace           string
		tcpServerPort       = int32(9900)
		wg                  sync.WaitGroup
		selectedNodes       = []corev1.Node{}
		httpServerTestPods  = []*corev1.Pod{}
		iperfServerTestPods = []*corev1.Pod{}
		clientSet           kubernetes.Interface
		// Systemd resolvd prevent resolving kube api service by fqdn, so
		// we replace it here with NetworkManager
		labelNode = func(nodeName, label string) error {
			patch := fmt.Sprintf(`{"metadata": {"labels": {"%s": ""}}}`, label)
			_, err := fr.ClientSet.CoreV1().Nodes().Patch(context.Background(), nodeName, types.MergePatchType, []byte(patch), metav1.PatchOptions{})
			if err != nil {
				return err
			}
			return nil
		}

		unlabelNode = func(nodeName, label string) error {
			patch := fmt.Sprintf(`[{"op": "remove", "path": "/metadata/labels/%s"}]`, label)
			_, err := clientSet.CoreV1().Nodes().Patch(context.Background(), nodeName, types.JSONPatchType, []byte(patch), metav1.PatchOptions{})
			if err != nil {
				return err
			}
			return nil
		}
		isDualStack = func() bool {
			GinkgoHelper()
			nodeList, err := fr.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeList.Items).NotTo(BeEmpty())
			hasIPv4Address, hasIPv6Address := false, false
			for _, addr := range nodeList.Items[0].Status.Addresses {
				if addr.Type == corev1.NodeInternalIP {
					if utilnet.IsIPv4String(addr.Address) {
						hasIPv4Address = true
					}
					if utilnet.IsIPv6String(addr.Address) {
						hasIPv6Address = true
					}
				}
			}
			return hasIPv4Address && hasIPv6Address
		}
	)

	type liveMigrationTestData struct {
		mode                kubevirtv1.MigrationMode
		numberOfVMs         int
		shouldExpectFailure bool
	}

	var (
		sendEcho = func(conn *net.TCPConn) error {
			strEcho := "Halo"

			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return fmt.Errorf("failed configuring connection deadline: %w", err)
			}
			_, err := conn.Write([]byte(strEcho))
			if err != nil {
				return fmt.Errorf("failed Write to server: %w", err)
			}

			reply := make([]byte, 1024)

			_, err = conn.Read(reply)
			if err != nil {
				return fmt.Errorf("failed Read to server: %w", err)
			}

			if strings.Compare(string(reply), strEcho) == 0 {
				return fmt.Errorf("unexpected reply '%s'", string(reply))
			}
			return nil
		}

		sendEchos = func(conns []*net.TCPConn) error {
			for _, conn := range conns {
				if err := sendEcho(conn); err != nil {
					return err
				}
			}
			return nil
		}

		dial = func(addr string) (*net.TCPConn, error) {
			tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
			if err != nil {
				return nil, fmt.Errorf("failed ResolveTCPAddr: %w", err)
			}
			backoff := wait.Backoff{
				Steps:    4,
				Duration: 10 * time.Millisecond,
				Factor:   5.0,
				Jitter:   0.1,
			}
			allErrors := func(error) bool { return true }
			var conn *net.TCPConn
			if err := retry.OnError(backoff, allErrors, func() error {
				conn, err = net.DialTCP("tcp", nil, tcpAddr)
				if err != nil {
					return fmt.Errorf("failed DialTCP: %w", err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			if err := conn.SetKeepAlive(true); err != nil {
				return nil, err
			}
			return conn, nil
		}

		dialServiceNodePort = func(svc *corev1.Service) ([]*net.TCPConn, error) {
			worker, err := fr.ClientSet.CoreV1().Nodes().Get(context.TODO(), "ovn-worker", metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			endpoints := []*net.TCPConn{}
			nodePort := fmt.Sprintf("%d", svc.Spec.Ports[0].NodePort)
			port := fmt.Sprintf("%d", svc.Spec.Ports[0].Port)

			d.TCPDumpDaemonSet([]string{"any", "eth0", "breth0"}, fmt.Sprintf("port %s or port %s", port, nodePort))
			for _, address := range worker.Status.Addresses {
				if address.Type != corev1.NodeHostName {
					addr := net.JoinHostPort(address.Address, nodePort)
					conn, err := dial(addr)
					if err != nil {
						return endpoints, err
					}
					endpoints = append(endpoints, conn)
				}
			}
			return endpoints, nil
		}

		/*

			reconnect = func(conns []*net.TCPConn) error {
				for i, conn := range conns {
					conn.Close()
					conn, err := dial(conn.RemoteAddr().String())
					if err != nil {
						return err
					}
					conns[i] = conn
				}
				return nil
			}
		*/
		composeService = func(name, vmName string, port int32) *corev1.Service {
			ipFamilyPolicy := corev1.IPFamilyPolicyPreferDualStack
			return &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: name + vmName,
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{
						Port: port,
					}},
					Selector: map[string]string{
						kubevirtv1.VirtualMachineNameLabel: vmName,
					},
					Type:           corev1.ServiceTypeNodePort,
					IPFamilyPolicy: &ipFamilyPolicy,
				},
			}
		}

		by = func(vmName string, step string) string {
			fullStep := fmt.Sprintf("%s: %s", vmName, step)
			By(fullStep)
			return fullStep
		}

		/*
			createDenyAllPolicy = func(vmName string) (*knet.NetworkPolicy, error) {
				policy := &knet.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "deny-all-" + vmName,
					},
					Spec: knet.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{
							kubevirtv1.VirtualMachineNameLabel: vmName,
						}},
						PolicyTypes: []knet.PolicyType{knet.PolicyTypeEgress, knet.PolicyTypeIngress},
						Ingress:     []knet.NetworkPolicyIngressRule{},
						Egress:      []knet.NetworkPolicyEgressRule{},
					},
				}
				return fr.ClientSet.NetworkingV1().NetworkPolicies(namespace).Create(context.TODO(), policy, metav1.CreateOptions{})
			}
		*/

		checkEastWestTraffic = func(vmi *kubevirtv1.VirtualMachineInstance, podIPsByName map[string][]string, stage string) {
			GinkgoHelper()
			Expect(podIPsByName).NotTo(BeEmpty())
			polling := 15 * time.Second
			timeout := time.Minute
			for podName, podIPs := range podIPsByName {
				for _, podIP := range podIPs {
					output := ""
					Eventually(func() error {
						var err error
						output, err = kubevirt.RunCommand(vmi, fmt.Sprintf("curl http://%s", net.JoinHostPort(podIP, "8000")), polling)
						return err
					}).
						WithPolling(polling).
						WithTimeout(timeout).
						Should(Succeed(), func() string { return stage + ": " + podName + ": " + output })
				}
			}
		}

		checkEastWestIperfTraffic = func(vmi *kubevirtv1.VirtualMachineInstance, podIPsByName map[string][]string, stage string) {
			GinkgoHelper()
			Expect(podIPsByName).NotTo(BeEmpty())
			polling := 15 * time.Second
			timeout := time.Minute
			for podName, podIPs := range podIPsByName {
				for _, podIP := range podIPs {
					output := ""
					Eventually(func() error {
						var err error
						output, err = kubevirt.RunCommand(vmi, fmt.Sprintf("iperf3 -t 1 -c %s", podIP), polling)
						return err
					}).
						WithPolling(polling).
						WithTimeout(timeout).
						Should(Succeed(), func() string { return stage + ": " + podName + ": " + output })
				}
			}
		}

		httpServerTestPodsDefaultNetworkIPs = func() map[string][]string {
			ips := map[string][]string{}
			for _, pod := range httpServerTestPods {
				for _, podIP := range pod.Status.PodIPs {
					ips[pod.Name] = append(ips[pod.Name], podIP.IP)
				}
			}
			return ips
		}

		podsMultusNetworkIPs = func(pods []*corev1.Pod, networkStatusPredicate func(nadapi.NetworkStatus) bool) map[string][]string {
			GinkgoHelper()
			ips := map[string][]string{}
			for _, pod := range pods {
				var networkStatuses []nadapi.NetworkStatus
				Eventually(func() ([]nadapi.NetworkStatus, error) {
					var err error
					networkStatuses, err = podNetworkStatus(pod, networkStatusPredicate)
					return networkStatuses, err
				}).
					WithTimeout(5 * time.Second).
					WithPolling(200 * time.Millisecond).
					Should(HaveLen(1))
				for _, ip := range networkStatuses[0].IPs {
					ips[pod.Name] = append(ips[pod.Name], ip)
				}
			}
			return ips
		}

		checkConnectivity = func(vmName string, endpoints []*net.TCPConn, stage string) {
			GinkgoHelper()
			by(vmName, "Check connectivity "+stage)
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vmName,
				},
			}
			err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).NotTo(HaveOccurred())
			polling := 15 * time.Second
			timeout := time.Minute
			step := by(vmName, stage+": Check tcp connection is not broken")
			Eventually(func() error { return sendEchos(endpoints) }).
				WithPolling(polling).
				WithTimeout(timeout).
				Should(Succeed(), step)

			stage = by(vmName, stage+": Check e/w tcp traffic")
			checkEastWestTraffic(vmi, httpServerTestPodsDefaultNetworkIPs(), stage)

			step = by(vmName, stage+": Check n/s tcp traffic")
			output := ""
			Eventually(func() error {
				output, err = kubevirt.RunCommand(vmi, "curl -kL https://kubernetes.default.svc.cluster.local", polling)
				return err
			}).
				WithPolling(polling).
				WithTimeout(timeout).
				Should(Succeed(), func() string { return step + ": " + output })
		}

		checkConnectivityAndNetworkPolicies = func(vmName string, endpoints []*net.TCPConn, stage string) {
			GinkgoHelper()
			checkConnectivity(vmName, endpoints, stage)
			By("Skip network policy, test should be fixed after OVN bump broke them")
			/*
				step := by(vmName, stage+": Create deny all network policy")
				policy, err := createDenyAllPolicy(vmName)
				Expect(err).NotTo(HaveOccurred(), step)

				step = by(vmName, stage+": Check connectivity block after create deny all network policy")
				Eventually(func() error { return sendEchos(endpoints) }).
					WithPolling(time.Second).
					WithTimeout(5*time.Second).
					ShouldNot(Succeed(), step)

				Expect(fr.ClientSet.NetworkingV1().NetworkPolicies(namespace).Delete(context.TODO(), policy.Name, metav1.DeleteOptions{})).To(Succeed())

				// After apply a deny all policy, the keep-alive packets will be block and
				// the tcp connection may break, to overcome that the test reconnects
				// after deleting the deny all policy to ensure a healthy tcp connection
				Expect(reconnect(endpoints)).To(Succeed(), step)

				step = by(vmName, stage+": Check connectivity is restored after delete deny all network policy")
				Expect(sendEchos(endpoints)).To(Succeed(), step)
			*/
		}

		composeAgnhostPod = func(name, namespace, nodeName string, args ...string) *corev1.Pod {
			agnHostPod := e2epod.NewAgnhostPod(namespace, name, nil, nil, nil, args...)
			agnHostPod.Spec.NodeName = nodeName
			return agnHostPod
		}

		liveMigrateVirtualMachine = func(vmName string) {
			GinkgoHelper()
			vmimCreationRetries := 0
			Eventually(func() error {
				if vmimCreationRetries > 0 {
					// retry due to unknown issue where kubevirt webhook gets stuck reading the request body
					// https://github.com/ovn-org/ovn-kubernetes/issues/3902#issuecomment-1750257559
					By(fmt.Sprintf("Retrying vmim %s creation", vmName))
				}
				vmim := &kubevirtv1.VirtualMachineInstanceMigration{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:    namespace,
						GenerateName: vmName,
					},
					Spec: kubevirtv1.VirtualMachineInstanceMigrationSpec{
						VMIName: vmName,
					},
				}
				err := crClient.Create(context.Background(), vmim)
				vmimCreationRetries++
				return err
			}).WithPolling(time.Second).WithTimeout(time.Minute).Should(Succeed())
		}

		checkLiveMigrationSucceeded = func(vmName string, migrationMode kubevirtv1.MigrationMode) {
			GinkgoHelper()
			By("checking the VM live-migrated correctly")
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vmName,
				},
			}
			err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).NotTo(HaveOccurred(), "should success retrieving vmi")
			currentNode := vmi.Status.NodeName

			Eventually(func() *kubevirtv1.VirtualMachineInstanceMigrationState {
				err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
				Expect(err).NotTo(HaveOccurred())
				return vmi.Status.MigrationState
			}).WithPolling(time.Second).WithTimeout(10*time.Minute).ShouldNot(BeNil(), "should have a MigrationState")
			Eventually(func() string {
				err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
				Expect(err).NotTo(HaveOccurred())
				return vmi.Status.MigrationState.TargetNode
			}).WithPolling(time.Second).WithTimeout(10*time.Minute).ShouldNot(Equal(currentNode), "should refresh MigrationState")
			Eventually(func() bool {
				err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
				Expect(err).NotTo(HaveOccurred())
				return vmi.Status.MigrationState.Completed
			}).WithPolling(time.Second).WithTimeout(20*time.Minute).Should(BeTrue(), "should complete migration")
			err = crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).NotTo(HaveOccurred(), "should success retrieving vmi after migration")
			Expect(vmi.Status.MigrationState.Failed).To(BeFalse(), func() string {
				vmiJSON, err := json.Marshal(vmi)
				if err != nil {
					return fmt.Sprintf("failed marshaling migrated VM: %v", vmiJSON)
				}
				return fmt.Sprintf("should live migrate successfully: %s", string(vmiJSON))
			})
			Expect(vmi.Status.MigrationState.Mode).To(Equal(migrationMode), "should be the expected migration mode %s", migrationMode)
		}

		vmiMigrations = func(client crclient.Client) ([]kubevirtv1.VirtualMachineInstanceMigration, error) {
			unstructuredVMIMigrations := &unstructured.UnstructuredList{}
			unstructuredVMIMigrations.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   kubevirtv1.GroupVersion.Group,
				Kind:    "VirtualMachineInstanceMigrationList",
				Version: kubevirtv1.GroupVersion.Version,
			})

			if err := client.List(context.Background(), unstructuredVMIMigrations); err != nil {
				return nil, err
			}
			if len(unstructuredVMIMigrations.Items) == 0 {
				return nil, fmt.Errorf("empty migration list")
			}

			var migrations []kubevirtv1.VirtualMachineInstanceMigration
			for i := range unstructuredVMIMigrations.Items {
				var vmiMigration kubevirtv1.VirtualMachineInstanceMigration
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
					unstructuredVMIMigrations.Items[i].Object,
					&vmiMigration,
				); err != nil {
					return nil, err
				}
				migrations = append(migrations, vmiMigration)
			}

			return migrations, nil
		}

		checkLiveMigrationFailed = func(vmName string) {
			GinkgoHelper()
			By("checking the VM live-migrated failed to migrate")
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vmName,
				},
			}
			err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).NotTo(HaveOccurred(), "should success retrieving vmi")

			Eventually(func() (kubevirtv1.VirtualMachineInstanceMigrationPhase, error) {
				migrations, err := vmiMigrations(crClient)
				if err != nil {
					return kubevirtv1.MigrationPhaseUnset, err
				}
				if len(migrations) > 1 {
					return kubevirtv1.MigrationPhaseUnset, fmt.Errorf("expected one migration, got %d", len(migrations))
				}
				return migrations[0].Status.Phase, nil
			}).WithPolling(time.Second).WithTimeout(5 * time.Minute).Should(
				Equal(kubevirtv1.MigrationFailed),
			)
		}

		ipv4 = func(iface kubevirt.Interface) []kubevirt.Address {
			return iface.IPv4.Address
		}

		ipv6 = func(iface kubevirt.Interface) []kubevirt.Address {
			return iface.IPv6.Address
		}

		findNonLoopbackInterface = func(interfaces []kubevirt.Interface) *kubevirt.Interface {
			for _, iface := range interfaces {
				if iface.Name != "lo" {
					return &iface
				}
			}
			return nil
		}

		addressByFamily = func(familyFn func(iface kubevirt.Interface) []kubevirt.Address, vmi *kubevirtv1.VirtualMachineInstance) func() ([]kubevirt.Address, error) {
			return func() ([]kubevirt.Address, error) {
				networkState, err := kubevirt.RetrieveNetworkState(vmi)
				if err != nil {
					return nil, err
				}
				iface := findNonLoopbackInterface(networkState.Interfaces)
				if iface == nil {
					return nil, fmt.Errorf("missing non loopback interface")
				}
				return familyFn(*iface), nil
			}

		}

		addressesFromStatus = func(vmi *kubevirtv1.VirtualMachineInstance) func() ([]string, error) {
			return func() ([]string, error) {
				err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
				if err != nil {
					return nil, err
				}
				var addresses []string
				for _, iface := range vmi.Status.Interfaces {
					for _, ip := range iface.IPs {
						addresses = append(addresses, ip)
					}
				}
				return addresses, nil
			}
		}

		createVirtualMachine = func(vm *kubevirtv1.VirtualMachine) {
			GinkgoHelper()
			By(fmt.Sprintf("Create virtual machine %s", vm.Name))
			vmCreationRetries := 0
			Eventually(func() error {
				if vmCreationRetries > 0 {
					// retry due to unknown issue where kubevirt webhook gets stuck reading the request body
					// https://github.com/ovn-org/ovn-kubernetes/issues/3902#issuecomment-1750257559
					By(fmt.Sprintf("Retrying vm %s creation", vm.Name))
				}
				err := crClient.Create(context.Background(), vm)
				vmCreationRetries++
				return err
			}).WithPolling(time.Second).WithTimeout(time.Minute).Should(Succeed())
		}

		createVirtualMachineInstance = func(vmi *kubevirtv1.VirtualMachineInstance) {
			GinkgoHelper()
			By(fmt.Sprintf("Create virtual machine instance %s", vmi.Name))
			vmiCreationRetries := 0
			Eventually(func() error {
				if vmiCreationRetries > 0 {
					// retry due to unknown issue where kubevirt webhook gets stuck reading the request body
					// https://github.com/ovn-org/ovn-kubernetes/issues/3902#issuecomment-1750257559
					By(fmt.Sprintf("Retrying vmi %s creation", vmi.Name))
				}
				err := crClient.Create(context.Background(), vmi)
				vmiCreationRetries++
				return err
			}).WithPolling(time.Second).WithTimeout(time.Minute).Should(Succeed())
		}

		waitVirtualMachineInstanceReadiness = func(vmi *kubevirtv1.VirtualMachineInstance) {
			GinkgoHelper()
			By(fmt.Sprintf("Waiting for readiness at virtual machine %s", vmi.Name))
			Eventually(func() []kubevirtv1.VirtualMachineInstanceCondition {
				err := crClient.Get(context.Background(), crclient.ObjectKeyFromObject(vmi), vmi)
				Expect(err).To(SatisfyAny(
					WithTransform(apierrors.IsNotFound, BeTrue()),
					Succeed(),
				))
				return vmi.Status.Conditions
			}).WithPolling(time.Second).WithTimeout(5 * time.Minute).Should(
				ContainElement(SatisfyAll(
					HaveField("Type", kubevirtv1.VirtualMachineInstanceReady),
					HaveField("Status", corev1.ConditionTrue),
				)))
		}

		waitVirtualMachineAddresses = func(vmi *kubevirtv1.VirtualMachineInstance) []kubevirt.Address {
			GinkgoHelper()
			step := by(vmi.Name, "Wait for virtual machine to receive IPv4 address from DHCP")
			Eventually(addressByFamily(ipv4, vmi)).
				WithPolling(time.Second).
				WithTimeout(5*time.Minute).
				Should(HaveLen(1), step)
			addresses, err := addressByFamily(ipv4, vmi)()
			Expect(err).NotTo(HaveOccurred())
			if isDualStack() {
				output, err := kubevirt.RunCommand(vmi, `echo '{"interfaces":[{"name":"enp1s0","type":"ethernet","state":"up","ipv4":{"enabled":true,"dhcp":true},"ipv6":{"enabled":true,"dhcp":true,"autoconf":false}}],"routes":{"config":[{"destination":"::/0","next-hop-interface":"enp1s0","next-hop-address":"fe80::1"}]}}' |nmstatectl apply`, 5*time.Second)
				Expect(err).NotTo(HaveOccurred(), output)
				step = by(vmi.Name, "Wait for virtual machine to receive IPv6 address from DHCP")
				Eventually(addressByFamily(ipv6, vmi)).
					WithPolling(time.Second).
					WithTimeout(5*time.Minute).
					Should(HaveLen(2), func() string {
						output, _ := kubevirt.RunCommand(vmi, "journalctl -u nmstate", 2*time.Second)
						return step + " -> journal nmstate: " + output
					})
				ipv6Addresses, err := addressByFamily(ipv6, vmi)()
				Expect(err).NotTo(HaveOccurred())
				addresses = append(addresses, ipv6Addresses...)
			}
			return addresses
		}

		virtualMachineAddressesFromStatus = func(vmi *kubevirtv1.VirtualMachineInstance, expectedNumberOfAddresses int) []string {
			GinkgoHelper()
			step := by(vmi.Name, "Wait for virtual machine to report addresses")
			Eventually(addressesFromStatus(vmi)).
				WithPolling(time.Second).
				WithTimeout(10*time.Second).
				Should(HaveLen(expectedNumberOfAddresses), step)

			addresses, err := addressesFromStatus(vmi)()
			Expect(err).NotTo(HaveOccurred())
			return addresses
		}

		generateVMI = func(labels map[string]string, annotations map[string]string, nodeSelector map[string]string, networkSource kubevirtv1.NetworkSource, cloudInitVolumeSource kubevirtv1.VolumeSource, image string) *kubevirtv1.VirtualMachineInstance {
			return &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    namespace,
					GenerateName: "worker-",
					Annotations:  annotations,
					Labels:       labels,
				},
				Spec: kubevirtv1.VirtualMachineInstanceSpec{
					NodeSelector: nodeSelector,
					Domain: kubevirtv1.DomainSpec{
						Resources: kubevirtv1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
						},
						Devices: kubevirtv1.Devices{
							Disks: []kubevirtv1.Disk{
								{
									DiskDevice: kubevirtv1.DiskDevice{
										Disk: &kubevirtv1.DiskTarget{
											Bus: kubevirtv1.DiskBusVirtio,
										},
									},
									Name: "containerdisk",
								},
								{
									DiskDevice: kubevirtv1.DiskDevice{
										Disk: &kubevirtv1.DiskTarget{
											Bus: kubevirtv1.DiskBusVirtio,
										},
									},
									Name: "cloudinitdisk",
								},
							},
							Interfaces: []kubevirtv1.Interface{
								{
									Name: "net1",
									InterfaceBindingMethod: kubevirtv1.InterfaceBindingMethod{
										Bridge: &kubevirtv1.InterfaceBridge{},
									},
								},
							},
							Rng: &kubevirtv1.Rng{},
						},
					},
					Networks: []kubevirtv1.Network{
						{
							Name:          "net1",
							NetworkSource: networkSource,
						},
					},
					TerminationGracePeriodSeconds: pointer.Int64(5),
					Volumes: []kubevirtv1.Volume{
						{
							Name: "containerdisk",
							VolumeSource: kubevirtv1.VolumeSource{
								ContainerDisk: &kubevirtv1.ContainerDiskSource{
									Image: image,
								},
							},
						},
						{
							Name:         "cloudinitdisk",
							VolumeSource: cloudInitVolumeSource,
						},
					},
				},
			}
		}

		generateVM = func(vmi *kubevirtv1.VirtualMachineInstance) *kubevirtv1.VirtualMachine {
			return &kubevirtv1.VirtualMachine{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    namespace,
					GenerateName: vmi.GenerateName,
				},
				Spec: kubevirtv1.VirtualMachineSpec{
					Running: pointer.Bool(true),
					Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: vmi.Annotations,
							Labels:      vmi.Labels,
						},
						Spec: vmi.Spec,
					},
				},
			}
		}

		fcosVMI = func(labels map[string]string, annotations map[string]string, nodeSelector map[string]string, networkSource kubevirtv1.NetworkSource, butane string) (*kubevirtv1.VirtualMachineInstance, error) {
			workingDirectory, err := os.Getwd()
			if err != nil {
				return nil, err
			}
			ignition, _, err := butaneconfig.TranslateBytes([]byte(butane), butanecommon.TranslateBytesOptions{
				TranslateOptions: butanecommon.TranslateOptions{
					FilesDir: workingDirectory,
				},
			})
			cloudInitVolumeSource := kubevirtv1.VolumeSource{
				CloudInitConfigDrive: &kubevirtv1.CloudInitConfigDriveSource{
					UserData: string(ignition),
				},
			}
			return generateVMI(labels, annotations, nodeSelector, networkSource, cloudInitVolumeSource, kubevirt.FedoraCoreOSContainerDiskImage), nil
		}

		fcosVM = func(labels map[string]string, annotations map[string]string, nodeSelector map[string]string, networkSource kubevirtv1.NetworkSource, butane string) (*kubevirtv1.VirtualMachine, error) {
			vmi, err := fcosVMI(labels, annotations, nodeSelector, networkSource, butane)
			if err != nil {
				return nil, err
			}
			return generateVM(vmi), nil
		}

		fedoraWithTestToolingVMI = func(labels map[string]string, annotations map[string]string, nodeSelector map[string]string, networkSource kubevirtv1.NetworkSource, userData, networkData string) *kubevirtv1.VirtualMachineInstance {
			cloudInitVolumeSource := kubevirtv1.VolumeSource{
				CloudInitNoCloud: &kubevirtv1.CloudInitNoCloudSource{
					UserData:    userData,
					NetworkData: networkData,
				},
			}
			return generateVMI(labels, annotations, nodeSelector, networkSource, cloudInitVolumeSource, kubevirt.FedoraContainerDiskImage)
		}

		fedoraWithTestToolingVM = func(labels map[string]string, annotations map[string]string, nodeSelector map[string]string, networkSource kubevirtv1.NetworkSource, userData, networkData string) *kubevirtv1.VirtualMachine {
			return generateVM(fedoraWithTestToolingVMI(labels, annotations, nodeSelector, networkSource, userData, networkData))
		}

		composeDefaultNetworkLiveMigratableVM = func(labels map[string]string, butane string) (*kubevirtv1.VirtualMachine, error) {
			annotations := map[string]string{
				"kubevirt.io/allow-pod-bridge-network-live-migration": "",
			}
			nodeSelector := map[string]string{
				namespace: "",
			}
			networkSource := kubevirtv1.NetworkSource{
				Pod: &kubevirtv1.PodNetwork{},
			}
			return fcosVM(labels, annotations, nodeSelector, networkSource, butane)
		}

		composeDefaultNetworkLiveMigratableVMs = func(numberOfVMs int, labels map[string]string) ([]*kubevirtv1.VirtualMachine, error) {
			butane := fmt.Sprintf(`
variant: fcos
version: 1.4.0
storage:
  files:
    - path: /root/test/server.go
      contents:
        local: kubevirt/echoserver/main.go
systemd:
  units:
    - name: systemd-resolved.service
      mask: true
    - name: replace-resolved.service
      enabled: true
      contents: |
        [Unit]
        Description=Replace systemd resolvd with NetworkManager
        Wants=network-online.target
        After=network-online.target
        [Service]
        ExecStart=rm -f /etc/resolv.conf
        ExecStart=systemctl restart NetworkManager
        Type=oneshot
        [Install]
        WantedBy=multi-user.target
    - name: echoserver.service
      enabled: true
      contents: |
        [Unit]
        Description=Golang echo server
        Wants=replace-resolved.service
        After=replace-resolved.service
        [Service]
        ExecStart=podman run --name tcpserver --tls-verify=false --privileged --net=host -v /root/test:/test:z registry.access.redhat.com/ubi9/go-toolset:1.20 go run /test/server.go %d
        [Install]
        WantedBy=multi-user.target
passwd:
  users:
  - name: core
    password_hash: $y$j9T$b7RFf2LW7MUOiF4RyLHKA0$T.Ap/uzmg8zrTcUNXyXvBvT26UgkC6zZUVg3UKXeEp5
`, tcpServerPort)

			vms := []*kubevirtv1.VirtualMachine{}
			for i := 1; i <= numberOfVMs; i++ {
				vm, err := composeDefaultNetworkLiveMigratableVM(labels, butane)
				if err != nil {
					return nil, err
				}
				vms = append(vms, vm)
			}
			return vms, nil
		}
		liveMigrateAndCheck = func(vmName string, migrationMode kubevirtv1.MigrationMode, endpoints []*net.TCPConn, step string) {
			liveMigrateVirtualMachine(vmName)
			checkLiveMigrationSucceeded(vmName, migrationMode)
			checkConnectivityAndNetworkPolicies(vmName, endpoints, step)
		}

		runLiveMigrationTest = func(td liveMigrationTestData, vm *kubevirtv1.VirtualMachine) {
			GinkgoHelper()
			defer GinkgoRecover()
			defer wg.Done()
			step := by(vm.Name, "Login to virtual machine")
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vm.Name,
				},
			}
			err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).NotTo(HaveOccurred())
			Expect(kubevirt.LoginToFedora(vmi, "core", "fedora")).To(Succeed(), step)

			waitVirtualMachineAddresses(vmi)

			step = by(vm.Name, "Expose tcpServer as a service")
			svc, err := fr.ClientSet.CoreV1().Services(namespace).Create(context.TODO(), composeService("tcpserver", vm.Name, tcpServerPort), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), step)
			defer func() {
				output, err := kubevirt.RunCommand(vmi, "podman logs tcpserver", 10*time.Second)
				Expect(err).NotTo(HaveOccurred())
				fmt.Printf("%s tcpserver logs: %s", vmi.Name, output)
			}()

			By("Wait some time for service to settle")
			time.Sleep(2 * time.Second)

			endpoints, err := dialServiceNodePort(svc)
			Expect(err).ToNot(HaveOccurred(), step)

			checkConnectivityAndNetworkPolicies(vm.Name, endpoints, "before live migration")
			// Do just one migration that will fail
			if td.shouldExpectFailure {
				by(vm.Name, "Live migrate virtual machine to check failed migration")
				liveMigrateVirtualMachine(vm.Name)
				checkLiveMigrationFailed(vm.Name)
				checkConnectivityAndNetworkPolicies(vm.Name, endpoints, "after live migrate to check failed migration")
			} else {
				originalNode := vmi.Status.NodeName
				by(vm.Name, "Live migrate for the first time")
				liveMigrateAndCheck(vm.Name, td.mode, endpoints, "after live migrate for the first time")

				by(vm.Name, "Live migrate for the second time to a node not owning the subnet")
				// Remove the node selector label from original node to force
				// live migration to a different one.
				Expect(unlabelNode(originalNode, namespace)).To(Succeed())
				liveMigrateAndCheck(vm.Name, td.mode, endpoints, "after live migration for the second time to node not owning subnet")

				by(vm.Name, "Live migrate for the third time to the node owning the subnet")
				// Patch back the original node with the label and remove it
				// from the rest of nodes to force live migration target to it.
				Expect(labelNode(originalNode, namespace)).To(Succeed())
				for _, selectedNode := range selectedNodes {
					if selectedNode.Name != originalNode {
						Expect(unlabelNode(selectedNode.Name, namespace)).To(Succeed())
					}
				}
				liveMigrateAndCheck(vm.Name, td.mode, endpoints, "after live migration to node owning the subnet")
			}

		}

		checkPodHasIPAtStatus = func(g Gomega, pod *corev1.Pod) {
			g.Expect(pod.Status.PodIP).NotTo(BeEmpty(), "pod %s has no valid IP address yet", pod.Name)
		}

		createHTTPServerPods = func(annotations map[string]string) []*corev1.Pod {
			var pods []*corev1.Pod
			for _, selectedNode := range selectedNodes {
				pod := composeAgnhostPod(
					"testpod-"+selectedNode.Name,
					namespace,
					selectedNode.Name,
					"netexec", "--http-port", "8000")
				pod.Annotations = annotations
				pods = append(pods, e2epod.NewPodClient(fr).CreateSync(context.TODO(), pod))
			}
			return pods
		}

		createIperfServerPods = func(nodes []corev1.Node, netConfig networkAttachmentConfig) ([]*corev1.Pod, error) {
			annotations := map[string]string{}
			annotations["k8s.v1.cni.cncf.io/networks"] = fmt.Sprintf(`[{"name": %q}]`, netConfig.name)
			var pods []*corev1.Pod
			for _, node := range nodes {
				pod, err := createPod(fr, "testpod-"+node.Name, node.Name, namespace, []string{"iperf3", "-s"}, map[string]string{}, func(pod *corev1.Pod) {
					pod.Annotations = annotations
					pod.Spec.Containers[0].Image = iperf3Image
				})
				if err != nil {
					return nil, err
				}
				pods = append(pods, pod)
			}
			return pods, nil
		}

		waitForPodsCondition = func(pods []*corev1.Pod, conditionFn func(g Gomega, pod *corev1.Pod)) {
			for _, pod := range pods {
				Eventually(func(g Gomega) {
					var err error
					pod, err = fr.ClientSet.CoreV1().Pods(fr.Namespace.Name).Get(context.TODO(), pod.Name, metav1.GetOptions{})
					g.Expect(err).NotTo(HaveOccurred())
					conditionFn(g, pod)
				}).
					WithTimeout(time.Minute).
					WithPolling(time.Second).
					Should(Succeed())
			}
		}

		updatePods = func(pods []*corev1.Pod) []*corev1.Pod {
			for i, pod := range pods {
				var err error
				pod, err = fr.ClientSet.CoreV1().Pods(fr.Namespace.Name).Get(context.TODO(), pod.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				pods[i] = pod
			}
			return pods
		}

		prepareHTTPServerPods = func(annotations map[string]string, conditionFn func(g Gomega, pod *corev1.Pod)) {
			By("Preparing HTTP server pods")
			httpServerTestPods = createHTTPServerPods(annotations)
			waitForPodsCondition(httpServerTestPods, conditionFn)
			httpServerTestPods = updatePods(httpServerTestPods)
		}

		removeImagesInNode = func(node, imageURL string) error {
			By("Removing unused images in node " + node)
			output, err := runCommand(containerRuntime, "exec", node,
				"crictl", "images", "-o", "json")
			if err != nil {
				return err
			}

			// Remove tag if exists.
			taglessImageURL := strings.Split(imageURL, ":")[0]
			imageID, err := images.ImageIDByImageURL(taglessImageURL, output)
			if err != nil {
				return err
			}
			if imageID != "" {
				_, err = runCommand(containerRuntime, "exec", node,
					"crictl", "rmi", imageID)
				if err != nil {
					return err
				}
				_, err = runCommand(containerRuntime, "exec", node,
					"crictl", "rmi", "--prune")
				if err != nil {
					return err
				}
			}
			return nil
		}

		removeImagesInNodes = func(imageURL string) error {
			nodesList, err := fr.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			for nodeIdx, _ := range nodesList.Items {
				err = removeImagesInNode(nodesList.Items[nodeIdx].Name, imageURL)
				if err != nil {
					return err
				}
			}
			return nil
		}
	)
	BeforeEach(func() {
		namespace = fr.Namespace.Name
		// So we can use it at AfterEach, since fr.ClientSet is nil there
		clientSet = fr.ClientSet

		var err error
		crClient, err = newControllerRuntimeClient()
		Expect(err).NotTo(HaveOccurred())
	})

	Context("with default pod network", Ordered, func() {

		BeforeEach(func() {
			workerNodeList, err := fr.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: labels.FormatLabels(map[string]string{"node-role.kubernetes.io/worker": ""})})
			Expect(err).NotTo(HaveOccurred())
			nodesByOVNZone := map[string][]corev1.Node{}
			for _, workerNode := range workerNodeList.Items {
				ovnZone, ok := workerNode.Labels["k8s.ovn.org/zone-name"]
				if !ok {
					ovnZone = "global"
				}
				_, ok = nodesByOVNZone[ovnZone]
				if !ok {
					nodesByOVNZone[ovnZone] = []corev1.Node{}
				}
				nodesByOVNZone[ovnZone] = append(nodesByOVNZone[ovnZone], workerNode)
			}

			selectedNodes = []corev1.Node{}
			// If there is one global zone select the first three for the
			// migration
			if len(nodesByOVNZone) == 1 {
				selectedNodes = []corev1.Node{
					workerNodeList.Items[0],
					workerNodeList.Items[1],
					workerNodeList.Items[2],
				}
				// Otherwise select a pair of nodes from different OVN zones
			} else {
				for _, nodes := range nodesByOVNZone {
					selectedNodes = append(selectedNodes, nodes[0])
					if len(selectedNodes) == 3 {
						break // we want just three of them
					}
				}
			}

			Expect(selectedNodes).To(HaveLen(3), "at least three nodes in different zones are needed for interconnect scenarios")

			// Label the selected nodes with the generated namespaces, so we can
			// configure VM nodeSelector with it and live migration will take only
			// them into consideration
			for _, node := range selectedNodes {
				Expect(labelNode(node.Name, namespace)).To(Succeed())
			}

			prepareHTTPServerPods(map[string]string{}, checkPodHasIPAtStatus)

		})

		AfterEach(func() {
			for _, node := range selectedNodes {
				unlabelNode(node.Name, namespace)
			}
		})

		AfterAll(func() {
			Expect(removeImagesInNodes(kubevirt.FedoraCoreOSContainerDiskImage)).To(Succeed())
		})

		DescribeTable("when live migration", func(td liveMigrationTestData) {
			if td.mode == kubevirtv1.MigrationPostCopy && os.Getenv("GITHUB_ACTIONS") == "true" {
				Skip("Post copy live migration not working at github actions")
			}
			var (
				err error
			)

			Expect(err).NotTo(HaveOccurred())

			d.ConntrackDumpingDaemonSet()
			d.OVSFlowsDumpingDaemonSet("breth0")
			d.IPTablesDumpingDaemonSet()

			bandwidthPerMigration := resource.MustParse("40Mi")
			forcePostCopyMigrationPolicy := &kvmigrationsv1alpha1.MigrationPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "force-post-copy",
				},
				Spec: kvmigrationsv1alpha1.MigrationPolicySpec{
					AllowPostCopy:           pointer.Bool(true),
					CompletionTimeoutPerGiB: pointer.Int64(1),
					BandwidthPerMigration:   &bandwidthPerMigration,
					Selectors: &kvmigrationsv1alpha1.Selectors{
						VirtualMachineInstanceSelector: kvmigrationsv1alpha1.LabelSelector{
							"test-live-migration": "post-copy",
						},
					},
				},
			}
			if td.mode == kubevirtv1.MigrationPostCopy {
				err = crClient.Create(context.TODO(), forcePostCopyMigrationPolicy)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(crClient.Delete(context.TODO(), forcePostCopyMigrationPolicy)).To(Succeed())
				}()
			}

			vmLabels := map[string]string{}
			if td.mode == kubevirtv1.MigrationPostCopy {
				vmLabels = forcePostCopyMigrationPolicy.Spec.Selectors.VirtualMachineInstanceSelector
			}
			vms, err := composeDefaultNetworkLiveMigratableVMs(td.numberOfVMs, vmLabels)
			Expect(err).NotTo(HaveOccurred())

			for _, vm := range vms {
				By(fmt.Sprintf("Create virtual machine %s", vm.Name))
				vmCreationRetries := 0
				Eventually(func() error {
					if vmCreationRetries > 0 {
						// retry due to unknown issue where kubevirt webhook gets stuck reading the request body
						// https://github.com/ovn-org/ovn-kubernetes/issues/3902#issuecomment-1750257559
						By(fmt.Sprintf("Retrying vm %s creation", vm.Name))
					}
					err = crClient.Create(context.Background(), vm)
					vmCreationRetries++
					return err
				}).WithPolling(time.Second).WithTimeout(time.Minute).Should(Succeed())
			}

			for _, vm := range vms {
				By(fmt.Sprintf("Create virtual machine %s", vm.Name))
				if td.shouldExpectFailure {
					By("annotating the VMI with `fail fast`")
					vmKey := types.NamespacedName{Namespace: namespace, Name: vm.Name}
					var vmi kubevirtv1.VirtualMachineInstance
					Eventually(func() error {
						return crClient.Get(context.TODO(), vmKey, &vmi)
					}).WithPolling(time.Second).WithTimeout(time.Minute).Should(Succeed())

					vmi.ObjectMeta.Annotations[kubevirtv1.FuncTestLauncherFailFastAnnotation] = "true"

					Expect(crClient.Update(context.TODO(), &vmi)).To(Succeed())
				}
			}

			for _, vm := range vms {
				By(fmt.Sprintf("Waiting for readiness at virtual machine %s", vm.Name))
				Eventually(func() bool {
					err = crClient.Get(context.Background(), crclient.ObjectKeyFromObject(vm), vm)
					Expect(err).NotTo(HaveOccurred())
					return vm.Status.Ready
				}).WithPolling(time.Second).WithTimeout(5 * time.Minute).Should(BeTrue())
			}
			wg.Add(int(td.numberOfVMs))
			for _, vm := range vms {
				go runLiveMigrationTest(td, vm)
			}
			wg.Wait()
		},
			Entry("with pre-copy succeeds, should keep connectivity", liveMigrationTestData{
				mode:        kubevirtv1.MigrationPreCopy,
				numberOfVMs: 1,
			}),
			Entry("with post-copy succeeds, should keep connectivity", liveMigrationTestData{
				mode:        kubevirtv1.MigrationPostCopy,
				numberOfVMs: 1,
			}),
			Entry("with pre-copy fails, should keep connectivity", liveMigrationTestData{
				mode:                kubevirtv1.MigrationPreCopy,
				numberOfVMs:         1,
				shouldExpectFailure: true,
			}),
		)
	})
	Context("with secondary network and persistent ips configured", Ordered, func() {
		AfterAll(func() {
			Expect(removeImagesInNodes(kubevirt.FedoraContainerDiskImage)).To(Succeed())
		})
		type testCommand struct {
			description string
			cmd         func()
		}
		type resourceCommand struct {
			description string
			cmd         func() string
		}
		var (
			nad      *nadv1.NetworkAttachmentDefinition
			vm       *kubevirtv1.VirtualMachine
			vmi      *kubevirtv1.VirtualMachineInstance
			cidrIPv4 = "10.128.0.0/24"
			cidrIPv6 = "2010:100:200::0/60"
			restart  = testCommand{
				description: "restart",
				cmd: func() {
					By("Restarting vm")
					output, err := exec.Command("virtctl", "restart", "-n", namespace, vmi.Name).CombinedOutput()
					Expect(err).NotTo(HaveOccurred(), output)

					By("Wait some time to vmi conditions to catch up after restart")
					time.Sleep(3 * time.Second)

					waitVirtualMachineInstanceReadiness(vmi)
				},
			}
			liveMigrate = testCommand{
				description: "live migration",
				cmd: func() {
					liveMigrateVirtualMachine(vmi.Name)
					checkLiveMigrationSucceeded(vmi.Name, kubevirtv1.MigrationPreCopy)
				},
			}
			networkData = `version: 2
ethernets:
  eth0:
    dhcp4: true
    dhcp6: true
    ipv6-address-generation: eui64`
			userData = `#cloud-config
password: fedora
chpasswd: { expire: False }`
			virtualMachine = resourceCommand{
				description: "VirtualMachine",
				cmd: func() string {
					vm = fedoraWithTestToolingVM(nil /*labels*/, nil /*annotations*/, nil /*nodeSelector*/, kubevirtv1.NetworkSource{
						Multus: &kubevirtv1.MultusNetwork{
							NetworkName: nad.Name,
						},
					}, userData, networkData)
					createVirtualMachine(vm)
					return vm.Name
				},
			}

			virtualMachineInstance = resourceCommand{
				description: "VirtualMachineInstance",
				cmd: func() string {
					vmi = fedoraWithTestToolingVMI(nil /*labels*/, nil /*annotations*/, nil /*nodeSelector*/, kubevirtv1.NetworkSource{
						Multus: &kubevirtv1.MultusNetwork{
							NetworkName: nad.Name,
						},
					}, userData, networkData)
					createVirtualMachineInstance(vmi)
					return vmi.Name
				},
			}
		)
		type testData struct {
			description string
			resource    resourceCommand
			test        testCommand
			topology    string
		}
		DescribeTable("should keep ip", func(td testData) {
			netConfig := newNetworkAttachmentConfig(
				networkAttachmentConfigParams{
					namespace:          namespace,
					name:               "net1",
					topology:           td.topology,
					cidr:               strings.Join([]string{cidrIPv4, cidrIPv6}, ","),
					allowPersistentIPs: true,
				})

			if td.topology == "localnet" {
				By("setting up the localnet underlay")
				nodes := ovsPods(clientSet)
				Expect(nodes).NotTo(BeEmpty())
				defer func() {
					By("tearing down the localnet underlay")
					Expect(teardownUnderlay(nodes)).To(Succeed())
				}()

				const secondaryInterfaceName = "eth1"
				Expect(setupUnderlay(nodes, secondaryInterfaceName, netConfig)).To(Succeed())
			}

			By("Creating NetworkAttachmentDefinition")
			nad = generateNAD(netConfig)
			Expect(crClient.Create(context.Background(), nad)).To(Succeed())
			workerNodeList, err := fr.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: labels.FormatLabels(map[string]string{"node-role.kubernetes.io/worker": ""})})
			Expect(err).NotTo(HaveOccurred())
			selectedNodes = workerNodeList.Items
			Expect(selectedNodes).NotTo(BeEmpty())

			iperfServerTestPods, err = createIperfServerPods(selectedNodes, netConfig)
			Expect(err).NotTo(HaveOccurred())

			vmiName := td.resource.cmd()
			vmi = &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vmiName,
				},
			}

			waitVirtualMachineInstanceReadiness(vmi)
			Expect(crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)).To(Succeed())

			step := by(vmi.Name, "Login to virtual machine for the first time")
			Eventually(func() error {
				return kubevirt.LoginToFedora(vmi, "fedora", "fedora")
			}).
				WithTimeout(5*time.Second).
				WithPolling(time.Second).
				Should(Succeed(), step)

			step = by(vmi.Name, "Wait for addresses at the virtual machine")

			// expect 2 addresses on dual-stack deployments; 1 on single-stack
			expectedNumberOfAddresses := len(strings.Split(netConfig.cidr, ","))
			expectedAddreses := virtualMachineAddressesFromStatus(vmi, expectedNumberOfAddresses)
			expectedAddresesAtGuest := expectedAddreses
			testPodsIPs := podsMultusNetworkIPs(iperfServerTestPods, podNetworkStatusByNetConfigPredicate(netConfig))

			Eventually(kubevirt.RetrieveAllGlobalAddressesFromGuest).
				WithArguments(vmi).
				WithTimeout(5*time.Second).
				WithPolling(time.Second).
				Should(ConsistOf(expectedAddresesAtGuest), step)

			step = by(vmi.Name, fmt.Sprintf("Check east/west traffic before %s %s", td.resource.description, td.test.description))

			checkEastWestIperfTraffic(vmi, testPodsIPs, step)

			by(vmi.Name, fmt.Sprintf("Running %s for %s", td.test.description, td.resource.description))
			td.test.cmd()

			step = by(vmi.Name, fmt.Sprintf("Login to virtual machine after %s %s", td.resource.description, td.test.description))
			Expect(kubevirt.LoginToFedora(vmi, "fedora", "fedora")).To(Succeed(), step)
			var obtainedAddresses []string

			obtainedAddresses = virtualMachineAddressesFromStatus(vmi, expectedNumberOfAddresses)

			Expect(obtainedAddresses).To(Equal(expectedAddreses))
			Eventually(kubevirt.RetrieveAllGlobalAddressesFromGuest).
				WithArguments(vmi).
				WithTimeout(5*time.Second).
				WithPolling(time.Second).
				Should(ConsistOf(expectedAddresesAtGuest), step)

			step = by(vmi.Name, fmt.Sprintf("Check east/west traffic after %s %s", td.resource.description, td.test.description))
			checkEastWestIperfTraffic(vmi, testPodsIPs, step)
		},
			func(td testData) string {
				return fmt.Sprintf("after %s of %s with %s", td.test.description, td.resource.description, td.topology)
			},
			Entry(nil, testData{
				resource: virtualMachine,
				test:     restart,
				topology: "localnet",
			}),
			Entry(nil, testData{
				resource: virtualMachine,
				test:     restart,
				topology: "layer2",
			}),
			Entry(nil, testData{
				resource: virtualMachine,
				test:     liveMigrate,
				topology: "localnet",
			}),
			Entry(nil, testData{
				resource: virtualMachine,
				test:     liveMigrate,
				topology: "layer2",
			}),
			Entry(nil, testData{
				resource: virtualMachineInstance,
				test:     liveMigrate,
				topology: "localnet",
			}),
			Entry(nil, testData{
				resource: virtualMachineInstance,
				test:     liveMigrate,
				topology: "layer2",
			}),
		)
	})
})
