package ovn

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/urfave/cli/v2"

	ipamclaimsapi "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1"
	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type lspEnableValue *bool

var (
	lspEnableNotSpecified    lspEnableValue = nil
	lspEnableExplicitlyTrue  lspEnableValue = ptr.To(true)
	lspEnableExplicitlyFalse lspEnableValue = ptr.To(false)
)

type liveMigrationPodInfo struct {
	podPhase           v1.PodPhase
	annotation         map[string]string
	creationTimestamp  metav1.Time
	expectedLspEnabled lspEnableValue
}

type liveMigrationInfo struct {
	vmName        string
	sourcePodInfo liveMigrationPodInfo
	targetPodInfo liveMigrationPodInfo
}

var _ = Describe("OVN Multi-Homed pod operations for layer2 network", func() {
	var (
		app       *cli.App
		fakeOvn   *FakeOVN
		initialDB libovsdbtest.TestSetup
	)

	BeforeEach(func() {
		Expect(config.PrepareTestConfig()).To(Succeed()) // reset defaults

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fakeOvn = NewFakeOVN(true)
		initialDB = libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{},
		}

		config.OVNKubernetesFeature = *minimalFeatureConfig()
		config.Gateway.V4MasqueradeSubnet = dummyMasqueradeSubnet().String()
	})

	AfterEach(func() {
		fakeOvn.shutdown()
	})

	table.DescribeTable(
		"reconciles a new",
		func(netInfo secondaryNetInfo, testConfig testConfiguration) {
			const podIdx = 0
			podInfo := dummyL2TestPod(ns, netInfo, podIdx, podIdx)
			if testConfig.configToOverride != nil {
				config.OVNKubernetesFeature = *testConfig.configToOverride
			}
			app.Action = func(ctx *cli.Context) error {
				pod := newMultiHomedPod(podInfo, netInfo)

				const nodeIPv4CIDR = "192.168.126.202/24"
				By(fmt.Sprintf("Creating a node named %q, with IP: %s", nodeName, nodeIPv4CIDR))
				testNode, err := newNodeWithSecondaryNets(nodeName, nodeIPv4CIDR, netInfo)
				Expect(err).NotTo(HaveOccurred())
				Expect(setupFakeOvnForLayer2Topology(fakeOvn, initialDB, netInfo, testNode, podInfo, pod)).To(Succeed())

				// for layer2 on interconnect, it is the cluster manager that
				// allocates the OVN annotation; on unit tests, this just
				// doesn't happen, and we create the pod with these annotations
				// set. Hence, no point checking they're the expected ones.
				// TODO: align the mocked annotations with the production code
				//   - currently missing setting the routes.
				if !config.OVNKubernetesFeature.EnableInterconnect {
					By("asserting the pod OVN pod networks annotation are the expected ones")
					// check that after start networks annotations and nbdb will be updated
					Eventually(func() string {
						return getPodAnnotations(fakeOvn.fakeClient.KubeClient, podInfo.namespace, podInfo.podName)
					}).WithTimeout(2 * time.Second).Should(MatchJSON(podInfo.getAnnotationsJson()))
				}

				expectationOptions := testConfig.expectationOptions
				By("asserting the OVN entities provisioned in the NBDB are the expected ones")
				Eventually(fakeOvn.nbClient).Should(
					libovsdbtest.HaveData(
						newSecondaryNetworkExpectationMachine(
							fakeOvn,
							[]testPod{podInfo},
							expectationOptions...,
						).expectedLogicalSwitchesAndPorts()...))

				return nil
			}

			Expect(app.Run([]string{app.Name})).To(Succeed())
		},
		table.Entry("pod on a user defined secondary network",
			dummySecondaryLayer2UserDefinedNetwork("100.200.0.0/16"),
			nonICClusterTestConfiguration(),
		),

		table.Entry("pod on a user defined secondary network on an interconnect cluster",
			dummySecondaryLayer2UserDefinedNetwork("100.200.0.0/16"),
			icClusterTestConfiguration(),
		),
	)

	table.DescribeTable(
		"reconciles a new kubevirt-related pod during its live-migration phases",
		func(netInfo secondaryNetInfo, testConfig testConfiguration, migrationInfo *liveMigrationInfo) {
			ipamClaim := ipamclaimsapi.IPAMClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: ns,
					Name:      netInfo.netName + "-" + migrationInfo.vmName,
				},
				Spec: ipamclaimsapi.IPAMClaimSpec{
					Network:   netInfo.netName,
					Interface: "net1",
				},
			}
			netInfo.allowPersistentIPs = true
			netInfo.ipamClaimReference = ipamClaim.Name

			const (
				sourcePodInfoIdx    = 0
				targetPodInfoIdx    = 1
				secondaryNetworkIdx = 0
			)
			sourcePodInfo := dummyL2TestPod(ns, netInfo, sourcePodInfoIdx, secondaryNetworkIdx)
			if testConfig.configToOverride != nil {
				config.OVNKubernetesFeature = *testConfig.configToOverride
			}
			app.Action = func(ctx *cli.Context) error {
				sourcePod := newMultiHomedKubevirtPod(
					migrationInfo.vmName,
					migrationInfo.sourcePodInfo,
					sourcePodInfo,
					netInfo)

				const nodeIPv4CIDR = "192.168.126.202/24"
				By(fmt.Sprintf("Creating a node named %q, with IP: %s", nodeName, nodeIPv4CIDR))
				testNode, err := newNodeWithSecondaryNets(nodeName, nodeIPv4CIDR, netInfo)
				Expect(err).NotTo(HaveOccurred())

				Expect(setupFakeOvnForLayer2Topology(fakeOvn, initialDB, netInfo, testNode, sourcePodInfo, sourcePod,
					&ipamclaimsapi.IPAMClaimList{Items: []ipamclaimsapi.IPAMClaim{ipamClaim}}),
				).To(Succeed())

				// for layer2 on interconnect, it is the cluster manager that
				// allocates the OVN annotation; on unit tests, this just
				// doesn't happen, and we create the pod with these annotations
				// set. Hence, no point checking they're the expected ones.
				// TODO: align the mocked annotations with the production code
				//   - currently missing setting the routes.
				if !config.OVNKubernetesFeature.EnableInterconnect {
					By("asserting the pod OVN pod networks annotation are the expected ones")
					// check that after start networks annotations and nbdb will be updated
					Eventually(func() string {
						return getPodAnnotations(fakeOvn.fakeClient.KubeClient, sourcePodInfo.namespace, sourcePodInfo.podName)
					}).WithTimeout(2 * time.Second).Should(MatchJSON(sourcePodInfo.getAnnotationsJson()))
				}

				expectationOptions := testConfig.expectationOptions
				By("asserting the OVN entities provisioned in the NBDB are the expected ones before migration started")
				Eventually(fakeOvn.nbClient).Should(
					libovsdbtest.HaveData(
						newSecondaryNetworkExpectationMachine(
							fakeOvn,
							[]testPod{sourcePodInfo},
							expectationOptions...,
						).expectedLogicalSwitchesAndPorts()...))

				targetPodInfo := dummyL2TestPod(ns, netInfo, targetPodInfoIdx, secondaryNetworkIdx)
				targetKvPod := newMultiHomedKubevirtPod(
					migrationInfo.vmName,
					migrationInfo.targetPodInfo,
					targetPodInfo,
					netInfo)

				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(targetKvPod.Namespace).Create(context.Background(), targetKvPod, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				By("asserting the OVN entities provisioned in the NBDB are the expected ones after migration")
				expectedPodLspEnabled := map[string]*bool{}
				expectedPodLspEnabled[sourcePodInfo.podName] = migrationInfo.sourcePodInfo.expectedLspEnabled

				testPods := []testPod{sourcePodInfo}
				if !util.PodCompleted(targetKvPod) {
					testPods = append(testPods, targetPodInfo)
					expectedPodLspEnabled[targetPodInfo.podName] = migrationInfo.targetPodInfo.expectedLspEnabled
				}
				Eventually(fakeOvn.nbClient).Should(
					libovsdbtest.HaveData(
						newSecondaryNetworkExpectationMachine(
							fakeOvn,
							testPods,
							expectationOptions...,
						).expectedLogicalSwitchesAndPortsWithLspEnabled(expectedPodLspEnabled)...))
				return nil
			}

			Expect(app.Run([]string{app.Name})).To(Succeed())
		},

		table.Entry("on a layer2 topology with user defined secondary network, when target pod is not yet ready",
			dummySecondaryLayer2UserDefinedNetwork("100.200.0.0/16"),
			nonICClusterTestConfiguration(),
			notReadyMigrationInfo(),
		),

		table.Entry("on a layer2 topology with user defined secondary network, when target pod is ready",
			dummySecondaryLayer2UserDefinedNetwork("100.200.0.0/16"),
			nonICClusterTestConfiguration(),
			readyMigrationInfo(),
		),

		table.Entry("on a layer2 topology with user defined secondary network and an IC cluster, when target pod is not yet ready",
			dummySecondaryLayer2UserDefinedNetwork("100.200.0.0/16"),
			icClusterTestConfiguration(),
			notReadyMigrationInfo(),
		),

		table.Entry("on a layer2 topology with user defined secondary network and an IC cluster, when target pod is ready",
			dummySecondaryLayer2UserDefinedNetwork("100.200.0.0/16"),
			icClusterTestConfiguration(),
			readyMigrationInfo(),
		),

		table.Entry("on a layer2 topology with user defined secondary network and an IC cluster, when target pod failed",
			dummySecondaryLayer2UserDefinedNetwork("100.200.0.0/16"),
			icClusterTestConfiguration(),
			failedMigrationInfo(),
		),

		table.Entry("on a localnet topology with user defined secondary network, when target pod is not yet ready",
			dummyLocalnetWithSecondaryUserDefinedNetwork("100.200.0.0/16"),
			nonICClusterTestConfiguration(),
			notReadyMigrationInfo(),
		),

		table.Entry("on a localnet topology with user defined secondary network, when target pod is ready",
			dummyLocalnetWithSecondaryUserDefinedNetwork("100.200.0.0/16"),
			nonICClusterTestConfiguration(),
			readyMigrationInfo(),
		),

		table.Entry("on a localnet topology with user defined secondary network and an IC cluster, when target pod is not yet ready",
			dummyLocalnetWithSecondaryUserDefinedNetwork("100.200.0.0/16"),
			icClusterTestConfiguration(),
			notReadyMigrationInfo(),
		),

		table.Entry("on a localnet topology with user defined secondary network and an IC cluster, when target pod is ready",
			dummyLocalnetWithSecondaryUserDefinedNetwork("100.200.0.0/16"),
			icClusterTestConfiguration(),
			readyMigrationInfo(),
		),

		table.Entry("on a localnet topology with user defined secondary network and an IC cluster, when target pod failed",
			dummyLocalnetWithSecondaryUserDefinedNetwork("100.200.0.0/16"),
			icClusterTestConfiguration(),
			failedMigrationInfo(),
		),
	)
})

func dummyLocalnetWithSecondaryUserDefinedNetwork(subnets string) secondaryNetInfo {
	return secondaryNetInfo{
		netName:  secondaryNetworkName,
		nadName:  namespacedName(ns, nadName),
		topology: ovntypes.LocalnetTopology,
		subnets:  subnets,
	}
}

func dummySecondaryLayer2UserDefinedNetwork(subnets string) secondaryNetInfo {
	return secondaryNetInfo{
		netName:  secondaryNetworkName,
		nadName:  namespacedName(ns, nadName),
		topology: ovntypes.Layer2Topology,
		subnets:  subnets,
	}
}

func dummyL2TestPod(nsName string, info secondaryNetInfo, podIdx, secondaryNetIdx int) testPod {
	const nodeSubnet = "10.128.1.0/24"
	pod := newTPod(nodeName, nodeSubnet, "10.128.1.2", "10.128.1.1", fmt.Sprintf("%s-%d", podName, podIdx), fmt.Sprintf("10.128.1.%d", podIdx+3), fmt.Sprintf("0a:58:0a:80:01:%0.2d", podIdx+3), nsName)
	pod.addNetwork(
		info.netName,
		info.nadName,
		info.subnets,
		"",
		"",
		fmt.Sprintf("100.200.0.%d/16", secondaryNetIdx+1),
		fmt.Sprintf("0a:58:64:c8:00:%0.2d", secondaryNetIdx+1),
		"secondary",
		0,
		[]util.PodRoute{},
	)
	return pod
}

func setupFakeOvnForLayer2Topology(fakeOvn *FakeOVN, initialDB libovsdbtest.TestSetup, netInfo secondaryNetInfo, testNode *v1.Node, podInfo testPod, pod *corev1.Pod, extraObjects ...runtime.Object) error {
	By(fmt.Sprintf("creating a network attachment definition for network: %s", netInfo.netName))
	nad, err := newNetworkAttachmentDefinition(
		ns,
		nadName,
		*netInfo.netconf(),
	)
	if err != nil {
		return err
	}
	By("setting up the OVN DB without any entities in it")
	if err = netInfo.setupOVNDependencies(&initialDB); err != nil {
		return err
	}
	objects := []runtime.Object{
		&v1.NamespaceList{
			Items: []v1.Namespace{
				*newNamespace(ns),
			},
		},
		&v1.NodeList{Items: []v1.Node{*testNode}},
		&v1.PodList{
			Items: []v1.Pod{
				*pod,
			},
		},
		&nadapi.NetworkAttachmentDefinitionList{
			Items: []nadapi.NetworkAttachmentDefinition{*nad},
		},
	}

	objects = append(objects, extraObjects...)

	fakeOvn.startWithDBSetup(initialDB, objects...)
	podInfo.populateLogicalSwitchCache(fakeOvn)

	// on IC, the test itself spits out the pod with the
	// annotations set, since on production it would be the
	// clustermanager to annotate the pod.
	if !config.OVNKubernetesFeature.EnableInterconnect {
		By("asserting the pod originally does *not* feature the OVN pod networks annotation")
		// pod exists, networks annotations don't
		pod, err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(podInfo.namespace).Get(context.Background(), podInfo.podName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		_, ok := pod.Annotations[util.OvnPodAnnotationName]
		if ok {
			return fmt.Errorf("pod annotation %s is not expected", util.OvnPodAnnotationName)
		}
	}

	if err = fakeOvn.controller.WatchNamespaces(); err != nil {
		return err
	}
	if err = fakeOvn.controller.WatchPods(); err != nil {
		return err
	}
	By("asserting the pod (once reconciled) *features* the OVN pod networks annotation")
	secondaryNetController, ok := fakeOvn.secondaryControllers[secondaryNetworkName]
	if ok != true {
		return fmt.Errorf("secondary network controller %s is expected", secondaryNetworkName)
	}

	podInfo.populateSecondaryNetworkLogicalSwitchCache(fakeOvn, secondaryNetController)
	if err = secondaryNetController.bnc.WatchNodes(); err != nil {
		return err
	}
	if err = secondaryNetController.bnc.WatchPods(); err != nil {
		return err
	}
	return err
}

func notReadyMigrationInfo() *liveMigrationInfo {
	const vmName = "my-vm"
	return &liveMigrationInfo{
		vmName: vmName,
		sourcePodInfo: liveMigrationPodInfo{
			podPhase:           v1.PodRunning,
			creationTimestamp:  metav1.NewTime(time.Now().Add(-time.Hour)),
			expectedLspEnabled: lspEnableNotSpecified,
		},
		targetPodInfo: liveMigrationPodInfo{
			podPhase:           v1.PodRunning,
			creationTimestamp:  metav1.NewTime(time.Now()),
			expectedLspEnabled: lspEnableExplicitlyFalse,
		},
	}
}

func readyMigrationInfo() *liveMigrationInfo {
	const vmName = "my-vm"
	return &liveMigrationInfo{
		vmName: vmName,
		sourcePodInfo: liveMigrationPodInfo{
			podPhase:           v1.PodRunning,
			creationTimestamp:  metav1.NewTime(time.Now().Add(-time.Hour)),
			expectedLspEnabled: lspEnableExplicitlyFalse,
		},
		targetPodInfo: liveMigrationPodInfo{
			podPhase:           v1.PodRunning,
			creationTimestamp:  metav1.NewTime(time.Now()),
			annotation:         map[string]string{kubevirtv1.MigrationTargetReadyTimestamp: "some-timestamp"},
			expectedLspEnabled: lspEnableExplicitlyTrue,
		},
	}
}

func failedMigrationInfo() *liveMigrationInfo {
	const vmName = "my-vm"
	return &liveMigrationInfo{
		vmName: vmName,
		sourcePodInfo: liveMigrationPodInfo{
			podPhase:           v1.PodRunning,
			creationTimestamp:  metav1.NewTime(time.Now().Add(-time.Hour)),
			expectedLspEnabled: lspEnableExplicitlyTrue,
		},
		targetPodInfo: liveMigrationPodInfo{
			podPhase:          v1.PodFailed,
			creationTimestamp: metav1.NewTime(time.Now()),
		},
	}
}
