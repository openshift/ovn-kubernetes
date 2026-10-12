// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package networkmanager

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	ovncnitypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	ratypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

func TestSetAdvertisements(t *testing.T) {
	testNodeName := "testNode"
	testNADName := "test/NAD"
	testRAName := "testRA"
	testVRFName := "testVRF"

	defaultNetwork := &ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: types.DefaultNetworkName,
			Type: "ovn-k8s-cni-overlay",
		},
		MTU: 1400,
	}
	primaryNetwork := &ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: "primary",
			Type: "ovn-k8s-cni-overlay",
		},
		Topology: "layer3",
		Role:     "primary",
		MTU:      1400,
	}

	podNetworkRA := ratypes.RouteAdvertisements{
		ObjectMeta: metav1.ObjectMeta{
			Name: testRAName,
		},
		Spec: ratypes.RouteAdvertisementsSpec{
			TargetVRF:    testVRFName,
			NodeSelector: metav1.LabelSelector{},
			Advertisements: []ratypes.AdvertisementType{
				ratypes.PodNetwork,
			},
		},
		Status: ratypes.RouteAdvertisementsStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Accepted",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}
	nonPodNetworkRA := ratypes.RouteAdvertisements{
		ObjectMeta: metav1.ObjectMeta{
			Name: testRAName,
		},
		Spec: ratypes.RouteAdvertisementsSpec{
			TargetVRF:    testVRFName,
			NodeSelector: metav1.LabelSelector{},
		},
		Status: ratypes.RouteAdvertisementsStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Accepted",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}
	podNetworkRANotAccepted := podNetworkRA
	podNetworkRANotAccepted.Status = ratypes.RouteAdvertisementsStatus{}
	podNetworkRARejected := *podNetworkRA.DeepCopy()
	podNetworkRARejected.Status.Conditions[0].Status = metav1.ConditionFalse
	podNetworkRAOutdated := podNetworkRA
	podNetworkRAOutdated.Generation = 1

	testNode := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNodeName,
		},
	}
	otherNode := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "otherNode",
		},
	}

	tests := []struct {
		name                      string
		network                   *ovncnitypes.NetConf
		ra                        *ratypes.RouteAdvertisements
		node                      corev1.Node
		missingRA                 bool
		expectNoNetwork           bool
		existingPodAdvertisements map[string][]string
		existingEIPAdvertisements map[string][]string
		expected                  map[string][]string
		expectedEIP               map[string][]string
	}{
		{
			name:    "reconciles VRF advertisements for selected node of default node network controller",
			network: defaultNetwork,
			ra:      &podNetworkRA,
			node:    testNode,
			expected: map[string][]string{
				testNodeName: {testVRFName},
			},
		},
		{
			name:    "reconciles VRF advertisements for selected node of primary network controller",
			network: primaryNetwork,
			ra:      &podNetworkRA,
			node:    testNode,
			expected: map[string][]string{
				testNodeName: {testVRFName},
			},
		},
		{
			name:    "ignores advertisements that are not for the pod network",
			network: defaultNetwork,
			ra:      &nonPodNetworkRA,
			node:    testNode,
		},
		{
			name:    "ignores advertisements that are not for applicable node",
			network: defaultNetwork,
			ra:      &podNetworkRA,
			node:    otherNode,
		},
		{
			name:    "ignores advertisements with no Accepted condition",
			network: defaultNetwork,
			ra:      &podNetworkRANotAccepted,
			node:    testNode,
		},
		{
			name:    "starts new network without advertisements when advertisements are rejected",
			network: primaryNetwork,
			ra:      &podNetworkRARejected,
			node:    testNode,
		},
		{
			name:    "starts new network without advertisements when advertisements are old",
			network: primaryNetwork,
			ra:      &podNetworkRAOutdated,
			node:    testNode,
		},
		{
			name:    "preserves existing advertisements when advertisements are rejected",
			network: primaryNetwork,
			ra:      &podNetworkRARejected,
			node:    testNode,
			existingPodAdvertisements: map[string][]string{
				testNodeName: {"previous-pod-vrf"},
			},
			existingEIPAdvertisements: map[string][]string{
				testNodeName: {"previous-eip-vrf"},
			},
			expected: map[string][]string{
				testNodeName: {"previous-pod-vrf"},
			},
			expectedEIP: map[string][]string{
				testNodeName: {"previous-eip-vrf"},
			},
		},
		{
			name:      "preserves existing advertisements when route advertisement is missing",
			network:   primaryNetwork,
			ra:        &podNetworkRA,
			node:      testNode,
			missingRA: true,
			existingPodAdvertisements: map[string][]string{
				testNodeName: {"previous-pod-vrf"},
			},
			existingEIPAdvertisements: map[string][]string{
				testNodeName: {"previous-eip-vrf"},
			},
			expected: map[string][]string{
				testNodeName: {"previous-pod-vrf"},
			},
			expectedEIP: map[string][]string{
				testNodeName: {"previous-eip-vrf"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			config.OVNKubernetesFeature.EnableMultiNetwork = true
			config.OVNKubernetesFeature.EnableRouteAdvertisements = true
			fakeClient := util.GetOVNClientset().GetOVNKubeControllerClientset()
			wf, err := factory.NewOVNKubeControllerWatchFactory(fakeClient, "test-node")
			g.Expect(err).ToNot(gomega.HaveOccurred())

			tcm := &testControllerManager{
				controllers: map[string]NetworkController{},
				defaultNetwork: &testNetworkController{
					ReconcilableNetInfo: &util.DefaultNetInfo{},
				},
			}
			nm := newNetworkController("", testNodeName, tcm, wf)

			namespace, name, err := cache.SplitMetaNamespaceKey(testNADName)
			g.Expect(err).ToNot(gomega.HaveOccurred())
			nadAnnotations := map[string]string{
				types.OvnRouteAdvertisementsKey: "[\"" + tt.ra.Name + "\"]",
			}
			nad, err := buildNADWithAnnotations(name, namespace, tt.network, nadAnnotations)
			g.Expect(err).ToNot(gomega.HaveOccurred())

			_, err = fakeClient.KubeClient.CoreV1().Nodes().Create(context.Background(), &tt.node, metav1.CreateOptions{})
			g.Expect(err).ToNot(gomega.HaveOccurred())
			if !tt.missingRA {
				_, err = fakeClient.RouteAdvertisementsClient.K8sV1().RouteAdvertisements().Create(context.Background(), tt.ra, metav1.CreateOptions{})
				g.Expect(err).ToNot(gomega.HaveOccurred())
			}
			_, err = fakeClient.NetworkAttchDefClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Create(context.Background(), nad, metav1.CreateOptions{})
			g.Expect(err).ToNot(gomega.HaveOccurred())

			err = wf.Start()
			g.Expect(err).ToNot(gomega.HaveOccurred())
			defer wf.Shutdown()

			netInfo, err := util.NewNetInfo(tt.network)
			g.Expect(err).ToNot(gomega.HaveOccurred())
			mutableNetInfo := util.NewMutableNetInfo(netInfo)
			mutableNetInfo.AddNADs(testNADName)

			if tt.existingPodAdvertisements != nil || tt.existingEIPAdvertisements != nil {
				existingNetInfo := util.NewMutableNetInfo(netInfo)
				existingNetInfo.AddNADs(testNADName)
				existingNetInfo.SetPodNetworkAdvertisedVRFs(tt.existingPodAdvertisements)
				existingNetInfo.SetEgressIPAdvertisedVRFs(tt.existingEIPAdvertisements)
				existingController := &testNetworkController{
					ReconcilableNetInfo: util.NewReconcilableNetInfo(existingNetInfo),
					tcm:                 tcm,
				}
				tcm.controllers[testNetworkKey(netInfo)] = existingController
				nm.setNetworkState(existingNetInfo.GetNetworkName(), &networkControllerState{controller: existingController})
			}

			nm.getNADKeysForNetwork = func(networkName string) []string {
				if networkName == mutableNetInfo.GetNetworkName() {
					return []string{testNADName}
				}
				return nil
			}

			nm.EnsureNetwork(mutableNetInfo)
			g.Expect(nm.Start()).To(gomega.Succeed())
			defer nm.Stop()

			meetsExpectations := func(g gomega.Gomega) {
				tcm.Lock()
				defer tcm.Unlock()
				var reconcilable ReconcilableNetworkController
				switch tt.network.Name {
				case types.DefaultNetworkName:
					reconcilable = tcm.GetDefaultNetworkController()
				default:
					reconcilable = tcm.controllers[testNetworkKey(netInfo)]
				}

				if tt.expectNoNetwork {
					g.Expect(reconcilable).To(gomega.BeNil())
					return
				}
				g.Expect(reconcilable).ToNot(gomega.BeNil())

				if tt.expected == nil {
					tt.expected = map[string][]string{}
				}
				g.Expect(reconcilable.GetPodNetworkAdvertisedVRFs()).To(gomega.Equal(tt.expected))
				if tt.expectedEIP == nil {
					tt.expectedEIP = map[string][]string{}
				}
				g.Expect(reconcilable.GetEgressIPAdvertisedVRFs()).To(gomega.Equal(tt.expectedEIP))
			}

			g.Eventually(meetsExpectations).Should(gomega.Succeed())
			g.Consistently(meetsExpectations).Should(gomega.Succeed())
		})
	}
}

func TestNetworkControllerIsNodeManaged(t *testing.T) {
	const localNode = "local-node"

	tests := []struct {
		name       string
		controller *networkController
		node       *corev1.Node
		want       bool
	}{
		{
			name:       "cluster manager manages unannotated node",
			controller: &networkController{},
			node:       &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}},
			want:       true,
		},
		{
			name:       "node manager manages its own unannotated node",
			controller: &networkController{node: localNode},
			node:       &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: localNode}},
			want:       true,
		},
		{
			name:       "node manager ignores foreign unannotated node",
			controller: &networkController{node: localNode},
			node:       &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			g.Expect(tt.controller.isNodeManaged(tt.node)).To(gomega.Equal(tt.want))
		})
	}
}

// A RouteAdvertisements that becomes Accepted while a network's controller
// is starting must still leave the network advertised once Start returns.
// The network's sync read the RouteAdvertisements before it was accepted,
// and syncRunningNetworks, which the Accepted transition triggers, skips a
// network whose Start has not returned.
//
// The RouteAdvertisements and node workers are not started, so the test's
// own call to syncRunningNetworks is the only one: either worker running
// it after Start returns would reconcile the network without the fix. Their
// listers, which setAdvertisements reads, still work. The path from those
// informers to syncRunningNetworks is not covered here.
func TestSetAdvertisementsWhenAcceptedDuringStart(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	t.Cleanup(func() {
		g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	})
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableRouteAdvertisements = true

	const (
		nodeName = "testNode"
		nadName  = "test/NAD"
		raName   = "testRA"
	)
	network := &ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: "primary",
			Type: "ovn-k8s-cni-overlay",
		},
		Topology: "layer3",
		Role:     "primary",
		MTU:      1400,
	}
	ra := &ratypes.RouteAdvertisements{
		ObjectMeta: metav1.ObjectMeta{
			Name:       raName,
			Generation: 1,
		},
		Spec: ratypes.RouteAdvertisementsSpec{
			NodeSelector:   metav1.LabelSelector{},
			Advertisements: []ratypes.AdvertisementType{ratypes.PodNetwork},
		},
		Status: ratypes.RouteAdvertisementsStatus{
			Conditions: []metav1.Condition{{
				Type:               "Accepted",
				Status:             metav1.ConditionFalse,
				ObservedGeneration: 1,
			}},
		},
	}

	fakeClient := util.GetOVNClientset().GetOVNKubeControllerClientset()
	wf, err := factory.NewOVNKubeControllerWatchFactory(fakeClient, nodeName)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	netInfo, err := util.NewNetInfo(network)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	startEntered := make(chan struct{})
	enter := sync.OnceFunc(func() { close(startEntered) })
	releaseStart := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseStart) })
	tcm := &testControllerManager{
		controllers: map[string]NetworkController{},
		defaultNetwork: &testNetworkController{
			ReconcilableNetInfo: &util.DefaultNetInfo{},
		},
		startHook: func(networkName string) {
			if networkName != netInfo.GetNetworkName() {
				return
			}
			enter()
			<-releaseStart
		},
	}
	nm := newNetworkController("", nodeName, tcm, wf)
	// Their queues start at construction, so stop them before dropping them.
	controller.Stop(nm.raController, nm.nodeController)
	nm.raController = nil
	nm.nodeController = nil

	namespace, name, err := cache.SplitMetaNamespaceKey(nadName)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	nad, err := buildNADWithAnnotations(name, namespace, network, map[string]string{
		types.OvnRouteAdvertisementsKey: "[\"" + raName + "\"]",
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	ctx := context.Background()
	_, err = fakeClient.KubeClient.CoreV1().Nodes().Create(ctx,
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}, metav1.CreateOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	_, err = fakeClient.RouteAdvertisementsClient.K8sV1().RouteAdvertisements().Create(ctx, ra, metav1.CreateOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	_, err = fakeClient.NetworkAttchDefClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Create(ctx, nad, metav1.CreateOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	g.Expect(wf.Start()).To(gomega.Succeed())
	defer wf.Shutdown()

	mutableNetInfo := util.NewMutableNetInfo(netInfo)
	mutableNetInfo.AddNADs(nadName)
	nm.getNADKeysForNetwork = func(networkName string) []string {
		if networkName == netInfo.GetNetworkName() {
			return []string{nadName}
		}
		return nil
	}

	// Started before the network is known, so the network is synced by the
	// reconciler as one created at runtime is, not by the initial sync.
	g.Expect(nm.Start()).To(gomega.Succeed())
	// Release a held Start before stopping, or Stop waits on it forever.
	defer func() {
		release()
		nm.Stop()
	}()
	nm.EnsureNetwork(mutableNetInfo)

	// The network's controller is inside Start, created by a sync that
	// read the RouteAdvertisements as not accepted.
	g.Eventually(startEntered).WithTimeout(5 * time.Second).Should(gomega.BeClosed())

	// Accept the RouteAdvertisements and wait for the lister to show it.
	accepted, err := fakeClient.RouteAdvertisementsClient.K8sV1().RouteAdvertisements().Get(ctx, raName, metav1.GetOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	accepted.Status.Conditions[0].Status = metav1.ConditionTrue
	_, err = fakeClient.RouteAdvertisementsClient.K8sV1().RouteAdvertisements().UpdateStatus(ctx, accepted, metav1.UpdateOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Eventually(func() metav1.ConditionStatus {
		got, err := nm.raLister.Get(raName)
		if err != nil || len(got.Status.Conditions) == 0 {
			return ""
		}
		return got.Status.Conditions[0].Status
	}).WithTimeout(5 * time.Second).Should(gomega.Equal(metav1.ConditionTrue))

	// Do what the RouteAdvertisements controller does for the transition,
	// and finish it, while Start is still held.
	g.Expect(nm.syncRunningNetworks()).To(gomega.Succeed())
	release()

	advertised := func(g gomega.Gomega) {
		tcm.Lock()
		defer tcm.Unlock()
		reconcilable := tcm.controllers[testNetworkKey(netInfo)]
		g.Expect(reconcilable).ToNot(gomega.BeNil())
		g.Expect(reconcilable.GetPodNetworkAdvertisedVRFs()).To(gomega.Equal(map[string][]string{
			nodeName: {types.DefaultNetworkName},
		}))
	}
	g.Eventually(advertised).WithTimeout(5 * time.Second).Should(gomega.Succeed())
}

// recordingReconciler reports each key before passing it to the wrapped
// reconciler.
type recordingReconciler struct {
	controller.Reconciler
	onReconcile func(key string)
}

func (r *recordingReconciler) Reconcile(key string) {
	r.onReconcile(key)
	r.Reconciler.Reconcile(key)
}

// A RouteAdvertisements that becomes Accepted after a network is running
// reaches the network through the RouteAdvertisements informer and worker
// and syncRunningNetworks, and leaves the network advertised.
//
// The node worker is not started, so after the update only the
// RouteAdvertisements worker runs syncRunningNetworks, which queues the
// default network and then each running network. The test requires that
// sequence as well as the advertisement, so pending start-up work that reads
// the accepted RouteAdvertisements cannot satisfy it alone.
func TestSetAdvertisementsWhenAcceptedAfterStart(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	t.Cleanup(func() {
		g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	})
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableRouteAdvertisements = true

	const (
		nodeName = "testNode"
		nadName  = "test/NAD"
		raName   = "testRA"
	)
	network := &ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: "primary",
			Type: "ovn-k8s-cni-overlay",
		},
		Topology: "layer3",
		Role:     "primary",
		MTU:      1400,
	}
	// The fake clientset does not set resourceVersion, and raNeedsUpdate
	// ignores an update that does not change it.
	ra := &ratypes.RouteAdvertisements{
		ObjectMeta: metav1.ObjectMeta{
			Name:            raName,
			Generation:      1,
			ResourceVersion: "1",
		},
		Spec: ratypes.RouteAdvertisementsSpec{
			NodeSelector:   metav1.LabelSelector{},
			Advertisements: []ratypes.AdvertisementType{ratypes.PodNetwork},
		},
		Status: ratypes.RouteAdvertisementsStatus{
			Conditions: []metav1.Condition{{
				Type:               "Accepted",
				Status:             metav1.ConditionFalse,
				ObservedGeneration: 1,
			}},
		},
	}

	fakeClient := util.GetOVNClientset().GetOVNKubeControllerClientset()
	wf, err := factory.NewOVNKubeControllerWatchFactory(fakeClient, nodeName)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	netInfo, err := util.NewNetInfo(network)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	tcm := &testControllerManager{
		controllers: map[string]NetworkController{},
		defaultNetwork: &testNetworkController{
			ReconcilableNetInfo: &util.DefaultNetInfo{},
		},
	}
	nm := newNetworkController("", nodeName, tcm, wf)
	// Its queue starts at construction, so stop it before dropping it.
	controller.Stop(nm.nodeController)
	nm.nodeController = nil

	var updateSent, defaultQueued atomic.Bool
	queuedAfterUpdate := make(chan struct{})
	markQueued := sync.OnceFunc(func() { close(queuedAfterUpdate) })
	nm.networkReconciler = &recordingReconciler{
		Reconciler: nm.networkReconciler,
		onReconcile: func(key string) {
			if !updateSent.Load() {
				return
			}
			switch key {
			case types.DefaultNetworkName:
				defaultQueued.Store(true)
			case netInfo.GetNetworkName():
				if defaultQueued.Load() {
					markQueued()
				}
			}
		},
	}

	namespace, name, err := cache.SplitMetaNamespaceKey(nadName)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	nad, err := buildNADWithAnnotations(name, namespace, network, map[string]string{
		types.OvnRouteAdvertisementsKey: "[\"" + raName + "\"]",
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	ctx := context.Background()
	_, err = fakeClient.KubeClient.CoreV1().Nodes().Create(ctx,
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}, metav1.CreateOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	_, err = fakeClient.RouteAdvertisementsClient.K8sV1().RouteAdvertisements().Create(ctx, ra, metav1.CreateOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	_, err = fakeClient.NetworkAttchDefClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Create(ctx, nad, metav1.CreateOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	g.Expect(wf.Start()).To(gomega.Succeed())
	defer wf.Shutdown()

	mutableNetInfo := util.NewMutableNetInfo(netInfo)
	mutableNetInfo.AddNADs(nadName)
	nm.getNADKeysForNetwork = func(networkName string) []string {
		if networkName == netInfo.GetNetworkName() {
			return []string{nadName}
		}
		return nil
	}

	g.Expect(nm.Start()).To(gomega.Succeed())
	defer nm.Stop()
	nm.EnsureNetwork(mutableNetInfo)

	// The network is running, without advertisements: the
	// RouteAdvertisements is not accepted yet.
	advertisements := func() map[string][]string {
		tcm.Lock()
		defer tcm.Unlock()
		reconcilable := tcm.controllers[testNetworkKey(netInfo)]
		if reconcilable == nil {
			return nil
		}
		return reconcilable.GetPodNetworkAdvertisedVRFs()
	}
	g.Eventually(func() bool {
		return nm.getNetworkState(netInfo.GetNetworkName()).controller != nil
	}).WithTimeout(5 * time.Second).Should(gomega.BeTrue())
	g.Expect(advertisements()).To(gomega.BeEmpty())

	accepted, err := fakeClient.RouteAdvertisementsClient.K8sV1().RouteAdvertisements().Get(ctx, raName, metav1.GetOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	accepted.Status.Conditions[0].Status = metav1.ConditionTrue
	accepted.ResourceVersion = "2"
	updateSent.Store(true)
	_, err = fakeClient.RouteAdvertisementsClient.K8sV1().RouteAdvertisements().UpdateStatus(ctx, accepted, metav1.UpdateOptions{})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	g.Eventually(queuedAfterUpdate).WithTimeout(5 * time.Second).Should(gomega.BeClosed())

	g.Eventually(advertisements).WithTimeout(5 * time.Second).Should(gomega.Equal(map[string][]string{
		nodeName: {types.DefaultNetworkName},
	}))
}

// noDefaultControllerManager reports no default network controller, as
// FakeControllerManager does.
type noDefaultControllerManager struct {
	*testControllerManager
}

func (m noDefaultControllerManager) GetDefaultNetworkController() ReconcilableNetworkController {
	return nil
}

// The network manager does not own the default network's lifecycle, so
// starting its controller must not queue it again: with a manager that
// reports no default controller, each such sync would start another one.
func TestDefaultNetworkIsNotSyncedAgainAfterStart(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	t.Cleanup(func() {
		g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	})
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableRouteAdvertisements = true

	const nodeName = "testNode"
	fakeClient := util.GetOVNClientset().GetOVNKubeControllerClientset()
	wf, err := factory.NewOVNKubeControllerWatchFactory(fakeClient, nodeName)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(wf.Start()).To(gomega.Succeed())
	defer wf.Shutdown()

	tcm := &testControllerManager{controllers: map[string]NetworkController{}}
	nm := newNetworkController("", nodeName, noDefaultControllerManager{tcm}, wf)
	// Their queues start at construction, so stop them before dropping them.
	controller.Stop(nm.raController, nm.nodeController)
	nm.raController = nil
	nm.nodeController = nil
	nm.getNADKeysForNetwork = func(string) []string { return nil }

	netInfo, err := util.NewNetInfo(&ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: types.DefaultNetworkName,
			Type: "ovn-k8s-cni-overlay",
		},
		MTU: 1400,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	g.Expect(nm.Start()).To(gomega.Succeed())
	defer nm.Stop()
	nm.EnsureNetwork(util.NewMutableNetInfo(netInfo))

	starts := func() int {
		tcm.Lock()
		defer tcm.Unlock()
		n := 0
		for _, key := range tcm.started {
			if key == testNetworkKey(netInfo) {
				n++
			}
		}
		return n
	}
	g.Eventually(starts).WithTimeout(5 * time.Second).Should(gomega.BeNumerically(">=", 1))
	g.Consistently(starts, time.Second).Should(gomega.BeNumerically("<=", 3))
}

// Without route advertisements nothing runs syncRunningNetworks, so a
// network that has started is not queued again.
func TestNetworkIsNotSyncedAgainWithoutRouteAdvertisements(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	t.Cleanup(func() {
		g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	})
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableRouteAdvertisements = false

	netInfo, err := util.NewNetInfo(&ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: "primary",
			Type: "ovn-k8s-cni-overlay",
		},
		Topology: "layer3",
		Role:     "primary",
		MTU:      1400,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	tcm := &testControllerManager{
		controllers: map[string]NetworkController{},
		defaultNetwork: &testNetworkController{
			ReconcilableNetInfo: &util.DefaultNetInfo{},
		},
	}
	nm := newNetworkController("", "testNode", tcm, nil)
	var queued atomic.Int32
	nm.networkReconciler = &recordingReconciler{
		Reconciler: nm.networkReconciler,
		onReconcile: func(key string) {
			if key == netInfo.GetNetworkName() {
				queued.Add(1)
			}
		},
	}

	g.Expect(nm.Start()).To(gomega.Succeed())
	defer nm.Stop()
	nm.EnsureNetwork(util.NewMutableNetInfo(netInfo))

	g.Eventually(func() bool {
		return nm.getNetworkState(netInfo.GetNetworkName()).controller != nil
	}).WithTimeout(5 * time.Second).Should(gomega.BeTrue())
	g.Consistently(queued.Load, 500*time.Millisecond).Should(gomega.BeEquivalentTo(1))
}

func TestNetworkControllerReconcilePendingNetworkRefChange(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	t.Cleanup(func() {
		g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	})
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableRouteAdvertisements = false

	netConf := &ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: "udn-net",
			Type: "ovn-k8s-cni-overlay",
		},
		Topology: types.Layer3Topology,
		Role:     types.NetworkRolePrimary,
		NADName:  "ns1/primary",
		Subnets:  "10.128.0.0/14",
	}
	netInfo, err := util.NewNetInfo(netConf)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	tests := []struct {
		name           string
		nodeHasNetwork bool
	}{
		{
			name:           "active",
			nodeHasNetwork: true,
		},
		{
			name:           "inactive",
			nodeHasNetwork: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			tcm := &testControllerManager{
				controllers: map[string]NetworkController{},
				defaultNetwork: &testNetworkController{
					ReconcilableNetInfo: &util.DefaultNetInfo{},
				},
			}
			nm := newNetworkController("", "", tcm, nil)
			nm.nodeHasNetwork = func(_, _ string) bool { return tt.nodeHasNetwork }

			networkName := netInfo.GetNetworkName()
			mutableNetInfo := util.NewMutableNetInfo(netInfo)
			mutableNetInfo.SetNADs(netConf.NADName)
			nm.setNetwork(networkName, mutableNetInfo)

			var gotNode string
			var gotActive bool
			var callCount int
			testController := &testNetworkController{
				ReconcilableNetInfo: util.NewReconcilableNetInfo(netInfo),
				tcm:                 tcm,
				handleRefChange: func(node string, active bool) {
					gotNode = node
					gotActive = active
					callCount++
				},
			}
			nm.networkControllers[networkName] = &networkControllerState{
				controller: testController,
			}

			nm.NotifyNetworkRefChange(networkName, "node1")
			err := nm.syncNetwork(networkName)
			g.Expect(err).ToNot(gomega.HaveOccurred())

			g.Expect(callCount).To(gomega.Equal(1))
			g.Expect(gotNode).To(gomega.Equal("node1"))
			g.Expect(gotActive).To(gomega.Equal(tt.nodeHasNetwork))

			nm.NotifyNetworkRefChange(networkName, "node1")
			err = nm.syncNetwork(networkName)
			g.Expect(err).ToNot(gomega.HaveOccurred())
			g.Expect(callCount).To(gomega.Equal(1))
		})
	}
}

func TestNetworkControllerClearsPendingNetworkRefOnDelete(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	t.Cleanup(func() {
		g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	})
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableRouteAdvertisements = false

	netConf := &ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: "udn-net",
			Type: "ovn-k8s-cni-overlay",
		},
		Topology: types.Layer3Topology,
		Role:     types.NetworkRolePrimary,
		NADName:  "ns1/primary",
		Subnets:  "10.128.0.0/14",
	}
	netInfo, err := util.NewNetInfo(netConf)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	tcm := &testControllerManager{
		controllers: map[string]NetworkController{},
		defaultNetwork: &testNetworkController{
			ReconcilableNetInfo: &util.DefaultNetInfo{},
		},
	}
	nm := newNetworkController("", "", tcm, nil)
	nm.nodeHasNetwork = func(_, _ string) bool { return true }

	networkName := netInfo.GetNetworkName()
	mutableNetInfo := util.NewMutableNetInfo(netInfo)
	mutableNetInfo.SetNADs(netConf.NADName)
	nm.setNetwork(networkName, mutableNetInfo)

	var callCount int
	testController := &testNetworkController{
		ReconcilableNetInfo: util.NewReconcilableNetInfo(netInfo),
		tcm:                 tcm,
		handleRefChange: func(string, bool) {
			callCount++
		},
	}
	nm.networkControllers[networkName] = &networkControllerState{
		controller: testController,
	}

	nm.NotifyNetworkRefChange(networkName, "node1")
	err = nm.deleteNetwork(networkName)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(callCount).To(gomega.Equal(0))

	var followupCalls int
	followupController := &testNetworkController{
		ReconcilableNetInfo: util.NewReconcilableNetInfo(netInfo),
		tcm:                 tcm,
		handleRefChange: func(string, bool) {
			followupCalls++
		},
	}
	nm.networkControllers[networkName] = &networkControllerState{
		controller: followupController,
	}
	nm.setNetwork(networkName, mutableNetInfo)
	err = nm.syncNetwork(networkName)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(followupCalls).To(gomega.Equal(0))
}

func TestNetworkControllerStopsNetworkOnStartFailure(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	t.Cleanup(func() {
		g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	})
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableRouteAdvertisements = false

	netConf := &ovncnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			Name: "udn-net",
			Type: "ovn-k8s-cni-overlay",
		},
		Topology: types.Layer3Topology,
		Role:     types.NetworkRolePrimary,
		NADName:  "ns1/primary",
		Subnets:  "10.128.0.0/14",
	}
	netInfo, err := util.NewNetInfo(netConf)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	tcm := &testControllerManager{
		controllers: map[string]NetworkController{},
		defaultNetwork: &testNetworkController{
			ReconcilableNetInfo: &util.DefaultNetInfo{},
		},
		raiseErrorWhenStartingController: fmt.Errorf("start failed"),
	}
	nm := newNetworkController("", "", tcm, nil)

	mutableNetInfo := util.NewMutableNetInfo(netInfo)
	mutableNetInfo.SetNADs(netConf.NADName)
	networkName := mutableNetInfo.GetNetworkName()
	nm.setNetwork(networkName, mutableNetInfo)

	err = nm.syncNetwork(networkName)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("failed to start network"))

	tcm.Lock()
	defer tcm.Unlock()
	expectedNetworkKey := testNetworkKey(netInfo)
	g.Expect(tcm.started).To(gomega.Equal([]string{expectedNetworkKey}))
	g.Expect(tcm.stopped).To(gomega.Equal([]string{expectedNetworkKey}))
}

// TestNetworkController_ConcurrentReconciliation validates that the networkReconciler
// can safely handle concurrent network additions and deletions without data races.
func TestNetworkController_ConcurrentReconciliation(t *testing.T) {
	g := gomega.NewWithT(t)

	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	fakeClient := util.GetOVNClientset().GetOVNKubeControllerClientset()
	wf, err := factory.NewOVNKubeControllerWatchFactory(fakeClient, "test-node")
	g.Expect(err).ToNot(gomega.HaveOccurred())

	tcm := &testControllerManager{
		controllers: map[string]NetworkController{},
		defaultNetwork: &testNetworkController{
			ReconcilableNetInfo: &util.DefaultNetInfo{},
		},
	}
	nm := newNetworkController("test", "", tcm, wf)

	err = wf.Start()
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer wf.Shutdown()

	g.Expect(nm.Start()).To(gomega.Succeed())
	defer nm.Stop()

	const numNetworks = 20
	const numIterations = 3

	for iteration := 0; iteration < numIterations; iteration++ {
		t.Logf("Iteration %d/%d: Testing concurrent add/delete of %d networks", iteration+1, numIterations, numNetworks)

		// Phase 1: Concurrent network additions
		var addWg sync.WaitGroup
		for i := 0; i < numNetworks; i++ {
			addWg.Add(1)
			go func(idx int) {
				defer addWg.Done()

				// Create a test network
				networkName := fmt.Sprintf("test-net-%d-%d", iteration, idx)
				netConf := &ovncnitypes.NetConf{
					NetConf: cnitypes.NetConf{
						Name: networkName,
						Type: "ovn-k8s-cni-overlay",
					},
					Topology: "layer2",
					Role:     "secondary",
					MTU:      1400,
				}

				netInfo, err := util.NewNetInfo(netConf)
				if err != nil {
					t.Errorf("Failed to create NetInfo for %s: %v", networkName, err)
					return
				}

				mutableNetInfo := util.NewMutableNetInfo(netInfo)
				nm.EnsureNetwork(mutableNetInfo)
			}(i)
		}
		addWg.Wait()

		// getAllNetworks() returns only secondary networks, not the default network
		g.Eventually(nm.getAllNetworks, 5*time.Second, 100*time.Millisecond).
			Should(gomega.HaveLen(numNetworks))

		// Phase 2: Concurrent network deletions
		var delWg sync.WaitGroup
		for i := 0; i < numNetworks; i++ {
			delWg.Add(1)
			go func(idx int) {
				defer delWg.Done()
				networkName := fmt.Sprintf("test-net-%d-%d", iteration, idx)
				nm.DeleteNetwork(networkName)
			}(i)
		}
		delWg.Wait()

		g.Eventually(nm.getAllNetworks).WithTimeout(5*time.Second).
			WithPolling(100*time.Millisecond).Should(gomega.BeEmpty(),
			"all test networks should be deleted")
	}
}

// TestNetworkController_ConcurrentReconciliationMixed validates concurrent operations
// with mixed add, update, and delete operations happening simultaneously.
func TestNetworkController_ConcurrentReconciliationMixed(t *testing.T) {
	g := gomega.NewWithT(t)

	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	fakeClient := util.GetOVNClientset().GetOVNKubeControllerClientset()
	wf, err := factory.NewOVNKubeControllerWatchFactory(fakeClient, "test-node")
	g.Expect(err).ToNot(gomega.HaveOccurred())

	tcm := &testControllerManager{
		controllers: map[string]NetworkController{},
		defaultNetwork: &testNetworkController{
			ReconcilableNetInfo: &util.DefaultNetInfo{},
		},
	}
	nm := newNetworkController("test", "", tcm, wf)

	err = wf.Start()
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer wf.Shutdown()

	g.Expect(nm.Start()).To(gomega.Succeed())
	defer nm.Stop()

	const numOperations = 30
	const numUniqueNetworks = 10
	var wg sync.WaitGroup

	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			networkName := fmt.Sprintf("mixed-net-%d", idx%numUniqueNetworks)
			netConf := &ovncnitypes.NetConf{
				NetConf: cnitypes.NetConf{
					Name: networkName,
					Type: "ovn-k8s-cni-overlay",
				},
				Topology: "layer2",
				Role:     "secondary",
				MTU:      1400,
			}

			netInfo, err := util.NewNetInfo(netConf)
			if err != nil {
				t.Errorf("Failed to create NetInfo: %v", err)
				return
			}

			mutableNetInfo := util.NewMutableNetInfo(netInfo)

			// Randomly add or delete
			if idx%3 == 0 {
				nm.DeleteNetwork(networkName)
			} else {
				nm.EnsureNetwork(mutableNetInfo)
			}
		}(i)
	}
	wg.Wait()

	// Ensure all networks exist to reach a deterministic final state
	for i := 0; i < numUniqueNetworks; i++ {
		networkName := fmt.Sprintf("mixed-net-%d", i)
		netConf := &ovncnitypes.NetConf{
			NetConf: cnitypes.NetConf{
				Name: networkName,
				Type: "ovn-k8s-cni-overlay",
			},
			Topology: "layer2",
			Role:     "secondary",
			MTU:      1400,
		}

		netInfo, err := util.NewNetInfo(netConf)
		g.Expect(err).ToNot(gomega.HaveOccurred())

		mutableNetInfo := util.NewMutableNetInfo(netInfo)
		nm.EnsureNetwork(mutableNetInfo)
	}

	// Verify all networks exist (deterministic final state)
	g.Eventually(func(g gomega.Gomega) {
		networks := nm.getAllNetworks()
		// getAllNetworks() returns secondary networks only
		g.Expect(networks).To(gomega.HaveLen(numUniqueNetworks),
			"Expected %d networks after mixed operations, got %d", numUniqueNetworks, len(networks))

		// Verify each network can be retrieved
		for _, network := range networks {
			retrieved := nm.getNetwork(network.GetNetworkName())
			g.Expect(retrieved).ToNot(gomega.BeNil())
		}
	}).Should(gomega.Succeed())
}
