// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package controllermanager

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/mock"
	"github.com/vishvananda/netlink"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/cni"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	uplinkfake "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/uplink/v1alpha1/apis/clientset/versioned/fake"
	uplinkinformerfactory "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/uplink/v1alpha1/apis/informers/externalversions"
	factoryMocks "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/factory/mocks"
	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/node/routemanager"
	ovntest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	nadinformermocks "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions/k8s.cni.cncf.io/v1"
	nadlistermocks "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/listers/k8s.cni.cncf.io/v1"
	coreinformermocks "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/client-go/informers/core/v1"
	corelistermocks "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/client-go/listers/core/v1"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/vswitchd"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func genListStalePortsCmd() string {
	return "ovs-vsctl --timeout=15 --data=bare --no-headings --columns=name find interface ofport=-1"
}

func genDeleteStalePortCmd(ifaces ...string) string {
	staleIfacesCmd := ""
	for _, iface := range ifaces {
		if len(staleIfacesCmd) > 0 {
			staleIfacesCmd += fmt.Sprintf(" -- --if-exists --with-iface del-port %s", iface)
		} else {
			staleIfacesCmd += fmt.Sprintf("ovs-vsctl --timeout=15 --if-exists --with-iface del-port %s", iface)
		}
	}
	return staleIfacesCmd
}

func newTestOVSClient(ovsData []libovsdbtest.TestData) (libovsdbclient.Client, *libovsdbtest.Context) {
	ovsClient, testCtx, err := libovsdbtest.NewOVSTestHarness(libovsdbtest.TestSetup{
		OVSData: ovsData,
	})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return ovsClient, testCtx
}

func ovsPortAndInterface(portUUID, ifaceUUID, name string, extIDs map[string]string) (*vswitchd.Port, *vswitchd.Interface) {
	return &vswitchd.Port{UUID: portUUID, Name: name, Interfaces: []string{ifaceUUID}},
		&vswitchd.Interface{UUID: ifaceUUID, Name: name, ExternalIDs: extIDs}
}

// fakeNetLinkOps answers link lookups from a set of names. Only the two methods
// the OVS pod interface health checks use are implemented; anything else panics
// on the embedded nil interface, which keeps the fake honest.
type fakeNetLinkOps struct {
	util.NetLinkOps
	links sets.Set[string]
}

func (f *fakeNetLinkOps) LinkByName(name string) (netlink.Link, error) {
	if f.links.Has(name) {
		return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
	}
	return nil, netlink.LinkNotFoundError{}
}

func (f *fakeNetLinkOps) IsLinkNotFoundError(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
}

// useFakeNetLinkOps makes the given host netdev names, and only those, exist
// for the duration of the spec.
func useFakeNetLinkOps(names ...string) *fakeNetLinkOps {
	fake := &fakeNetLinkOps{links: sets.New(names...)}
	original := util.GetNetLinkOps()
	util.SetNetLinkOpMockInst(fake)
	DeferCleanup(func() { util.SetNetLinkOpMockInst(original) })
	return fake
}

// newTestNCM builds a NodeControllerManager backed by an in-memory OVS
// database. The returned context must be cleaned up by the caller.
func newTestNCM(fakeClient *util.OVNClientset, factoryMock *factoryMocks.NodeWatchFactory, nodeName string,
	ovsData []libovsdbtest.TestData) (*NodeControllerManager, *libovsdbtest.Context) {
	nadListerMock := &nadlistermocks.NetworkAttachmentDefinitionLister{}
	nadInformerMock := &nadinformermocks.NetworkAttachmentDefinitionInformer{}
	nadInformerMock.On("Lister").Return(nadListerMock)
	nadInformerMock.On("Informer").Return(nil)
	factoryMock.On("NADInformer").Return(nadInformerMock)
	nodeInformerMock := &coreinformermocks.NodeInformer{}
	nodeListerMock := &corelistermocks.NodeLister{}
	nodeListerMock.On("List", mock.Anything).Return(nil, nil)
	nodeInformerMock.On("Lister").Return(nodeListerMock)
	factoryMock.On("NodeCoreInformer").Return(nodeInformerMock)

	ovsClient, ovsCleanup := newTestOVSClient(ovsData)
	ncm, err := NewNodeControllerManager(fakeClient, factoryMock, nodeName, &sync.WaitGroup{}, nil,
		routemanager.NewController(), ovsClient)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return ncm, ovsCleanup
}

func expectUplinkInformers(factoryMock *factoryMocks.NodeWatchFactory) {
	uplinkClient := uplinkfake.NewSimpleClientset()
	uplinkFactory := uplinkinformerfactory.NewSharedInformerFactory(uplinkClient, time.Second)

	factoryMock.On("UplinkInformer").Return(uplinkFactory.K8s().V1alpha1().Uplinks())
	factoryMock.On("UplinkStateInformer").Return(uplinkFactory.K8s().V1alpha1().UplinkStates())
}

func expectNodeInformer(nodeInformerMock *coreinformermocks.NodeInformer) {
	nodeInformerMock.On("Informer").Return(cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&corev1.Node{},
		time.Second,
		cache.Indexers{},
	))
}

var _ = Describe("Healthcheck tests", func() {
	var execMock *ovntest.FakeExec
	var factoryMock factoryMocks.NodeWatchFactory
	var fakeClient *util.OVNClientset
	var err error

	BeforeEach(func() {
		Expect(config.PrepareTestConfig()).To(Succeed())
		execMock = ovntest.NewFakeExec()
		Expect(util.SetExec(execMock)).To(Succeed())
		factoryMock = factoryMocks.NodeWatchFactory{}
		v1Objects := []runtime.Object{}
		fakeClient = &util.OVNClientset{
			KubeClient: fake.NewSimpleClientset(v1Objects...),
		}
	})

	AfterEach(func() {
		util.ResetRunner()
	})

	Describe("checkForStaleOVSInternalPorts", func() {

		Context("bridge has stale ports", func() {
			It("removes stale ports from bridge", func() {
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genListStalePortsCmd(),
					Output: "foo\n\nbar\n\n" + types.K8sMgmtIntfName + "\n\n",
					Err:    nil,
				})
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genDeleteStalePortCmd("foo", "bar"),
					Output: "",
					Err:    nil,
				})
				checkForStaleOVSInternalPorts()
				Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc)
			})
		})

		Context("bridge does not have stale ports", func() {
			It("Does not remove any ports from bridge", func() {
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genListStalePortsCmd(),
					Output: types.K8sMgmtIntfName + "\n\n",
					Err:    nil,
				})
				checkForStaleOVSInternalPorts()
				Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc)
			})
		})
	})

	Describe("checkForStaleOVSPodInterfaces", func() {
		var ncm *NodeControllerManager
		var ovsCleanup *libovsdbtest.Context
		nodeName := "localNode"
		podList := []*corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "a-pod",
					Namespace:   "a-ns",
					Annotations: map[string]string{},
					UID:         "pod-a-uuid-1",
				},
				Spec: corev1.PodSpec{
					NodeName: nodeName,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "b-pod",
					Namespace:   "b-ns",
					Annotations: map[string]string{},
					UID:         "pod-b-uuid-2",
				},
				Spec: corev1.PodSpec{
					NodeName: nodeName,
				},
			},
		}

		setupNCM := func(ovsData []libovsdbtest.TestData) {
			factoryMock.On("GetPods", "").Return(podList, nil)
			ncm, ovsCleanup = newTestNCM(fakeClient, &factoryMock, nodeName, ovsData)
		}

		BeforeEach(func() {
			// By default every pod OVS interface in these specs is backed by a
			// live host netdev, so only the pod-UID check decides what is stale.
			useFakeNetLinkOps("pod-a-ifc", "pod-b-ifc", "stale-pod-ifc", "vfio-pod-ifc", "veth-ifc")
		})

		AfterEach(func() {
			if ovsCleanup != nil {
				ovsCleanup.Cleanup()
			}
		})

		Context("bridge has stale representor ports", func() {
			It("removes stale VF rep ports from bridge", func() {
				portA, ifaceA := ovsPortAndInterface("port-1", "iface-1", "pod-a-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "a-ns_a-pod", "iface-id-ver": "pod-a-uuid-1", "vf-netdev-name": "blah"})
				portB, ifaceB := ovsPortAndInterface("port-2", "iface-2", "pod-b-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "b-ns_b-pod", "iface-id-ver": "pod-b-uuid-2", "vf-netdev-name": "blah"})
				portStale, ifaceStale := ovsPortAndInterface("port-3", "iface-3", "stale-pod-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "stale-ns_stale-pod", "iface-id-ver": "pod-stale-uuid-3", "vf-netdev-name": "blah"})
				setupNCM([]libovsdbtest.TestData{
					&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
					&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-1", "port-2", "port-3"}},
					portA, ifaceA, portB, ifaceB, portStale, ifaceStale,
				})
				ncm.checkForStaleOVSPodInterfaces()
				_, err := libovsdbops.GetOVSPort(ncm.ovsClient, "pod-a-ifc")
				Expect(err).NotTo(HaveOccurred())
				_, err = libovsdbops.GetOVSPort(ncm.ovsClient, "pod-b-ifc")
				Expect(err).NotTo(HaveOccurred())
				_, err = libovsdbops.GetOVSPort(ncm.ovsClient, "stale-pod-ifc")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("bridge does not have stale representor ports", func() {
			It("does not remove any port from bridge", func() {
				portA, ifaceA := ovsPortAndInterface("port-1", "iface-1", "pod-a-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "a-ns_a-pod", "iface-id-ver": "pod-a-uuid-1", "vf-netdev-name": "blah"})
				portB, ifaceB := ovsPortAndInterface("port-2", "iface-2", "pod-b-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "b-ns_b-pod", "iface-id-ver": "pod-b-uuid-2", "vf-netdev-name": "blah"})
				setupNCM([]libovsdbtest.TestData{
					&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
					&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-1", "port-2"}},
					portA, ifaceA, portB, ifaceB,
				})
				ncm.checkForStaleOVSPodInterfaces()
				_, err := libovsdbops.GetOVSPort(ncm.ovsClient, "pod-a-ifc")
				Expect(err).NotTo(HaveOccurred())
				_, err = libovsdbops.GetOVSPort(ncm.ovsClient, "pod-b-ifc")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("bridge has stale VFIO representor ports", func() {
			It("removes stale VFIO rep ports identified by vf-is-vfio=true", func() {
				portA, ifaceA := ovsPortAndInterface("port-1", "iface-1", "pod-a-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "a-ns_a-pod", "iface-id-ver": "pod-a-uuid-1", "vf-netdev-name": "blah"})
				portVfio, ifaceVfio := ovsPortAndInterface("port-4", "iface-4", "vfio-pod-ifc", map[string]string{
					"sandbox": "456defbbb", "iface-id": "vfio-ns_vfio-pod", "iface-id-ver": "pod-vfio-uuid-4", "vf-is-vfio": "true"})
				setupNCM([]libovsdbtest.TestData{
					&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
					&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-1", "port-4"}},
					portA, ifaceA, portVfio, ifaceVfio,
				})
				ncm.checkForStaleOVSPodInterfaces()
				_, err := libovsdbops.GetOVSPort(ncm.ovsClient, "pod-a-ifc")
				Expect(err).NotTo(HaveOccurred())
				_, err = libovsdbops.GetOVSPort(ncm.ovsClient, "vfio-pod-ifc")
				Expect(err).To(HaveOccurred())
			})

			It("does not remove VFIO rep ports for existing pods", func() {
				portA, ifaceA := ovsPortAndInterface("port-1", "iface-1", "pod-a-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "a-ns_a-pod", "iface-id-ver": "pod-a-uuid-1", "vf-is-vfio": "true"})
				portB, ifaceB := ovsPortAndInterface("port-2", "iface-2", "pod-b-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "b-ns_b-pod", "iface-id-ver": "pod-b-uuid-2", "vf-is-vfio": "true"})
				setupNCM([]libovsdbtest.TestData{
					&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
					&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-1", "port-2"}},
					portA, ifaceA, portB, ifaceB,
				})
				ncm.checkForStaleOVSPodInterfaces()
				_, err := libovsdbops.GetOVSPort(ncm.ovsClient, "pod-a-ifc")
				Expect(err).NotTo(HaveOccurred())
				_, err = libovsdbops.GetOVSPort(ncm.ovsClient, "pod-b-ifc")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("bridge has stale veth host-side interfaces", func() {
			It("removes stale veth interfaces (no representor markers) for gone pods", func() {
				portVeth, ifaceVeth := ovsPortAndInterface("port-5", "iface-5", "veth-ifc", map[string]string{
					"sandbox": "789abc", "iface-id": "stale-ns_stale-pod", "iface-id-ver": "pod-stale-uuid-5"})
				portA, ifaceA := ovsPortAndInterface("port-1", "iface-1", "pod-a-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "a-ns_a-pod", "iface-id-ver": "pod-a-uuid-1"})
				setupNCM([]libovsdbtest.TestData{
					&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
					&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-5", "port-1"}},
					portVeth, ifaceVeth, portA, ifaceA,
				})
				ncm.checkForStaleOVSPodInterfaces()
				_, err := libovsdbops.GetOVSPort(ncm.ovsClient, "pod-a-ifc")
				Expect(err).NotTo(HaveOccurred())
				_, err = libovsdbops.GetOVSPort(ncm.ovsClient, "veth-ifc")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("bridge has pod ports whose host netdev is gone", func() {
			// This is what a node reboot leaves behind: conf.db survives, no
			// veth does, and the pod keeps its UID so the staleness check above
			// cannot see it.
			It("removes the port left behind by a reboot and keeps the live one", func() {
				useFakeNetLinkOps("pod-a-ifc")
				portA, ifaceA := ovsPortAndInterface("port-1", "iface-1", "pod-a-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "a-ns_a-pod", "iface-id-ver": "pod-a-uuid-1"})
				portB, ifaceB := ovsPortAndInterface("port-2", "iface-2", "pod-b-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "b-ns_b-pod", "iface-id-ver": "pod-b-uuid-2"})
				setupNCM([]libovsdbtest.TestData{
					&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
					&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-1", "port-2"}},
					portA, ifaceA, portB, ifaceB,
				})
				ncm.checkForStaleOVSPodInterfaces()
				_, err := libovsdbops.GetOVSPort(ncm.ovsClient, "pod-a-ifc")
				Expect(err).NotTo(HaveOccurred())
				_, err = libovsdbops.GetOVSPort(ncm.ovsClient, "pod-b-ifc")
				Expect(err).To(HaveOccurred())
			})

			It("keeps dpdk ports, which have no kernel netdev by design", func() {
				useFakeNetLinkOps()
				portA, ifaceA := ovsPortAndInterface("port-1", "iface-1", "pod-a-ifc", map[string]string{
					"sandbox": "123abcfaa", "iface-id": "a-ns_a-pod", "iface-id-ver": "pod-a-uuid-1"})
				ifaceA.Type = "dpdk"
				setupNCM([]libovsdbtest.TestData{
					&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
					&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-1"}},
					portA, ifaceA,
				})
				ncm.checkForStaleOVSPodInterfaces()
				_, err := libovsdbops.GetOVSPort(ncm.ovsClient, "pod-a-ifc")
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("repairMissingOVSPodInterfaces", func() {
		var ncm *NodeControllerManager
		var ovsCleanup *libovsdbtest.Context
		const (
			nodeName      = "localNode"
			podNamespace  = "a-ns"
			podName       = "a-pod"
			podUID        = "pod-a-uuid-1"
			sandboxID     = "123abcfaa"
			hostIfaceName = "pod-a-ifc"
			ifaceID       = "a-ns_a-pod"
		)
		var pod *corev1.Pod
		var journalEntry *cni.PortJournalEntry

		// brIntOnly is a br-int that has lost the pod's port, the state an
		// ovsdb-server restart or a conf.db rollback leaves behind.
		brIntOnly := []libovsdbtest.TestData{
			&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
			&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int"},
		}

		journaledPorts := func() []string {
			entries, err := cni.ListPortJournal()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.HostIfaceName)
			}
			return names
		}

		repairCount := func(result string) float64 {
			m := &dto.Metric{}
			ExpectWithOffset(1, metrics.MetricPodInterfaceRepairs.WithLabelValues(result).Write(m)).To(Succeed())
			return m.GetCounter().GetValue()
		}

		BeforeEach(func() {
			cni.SetPortJournalDir(filepath.Join(GinkgoT().TempDir(), "ports"))
			useFakeNetLinkOps(hostIfaceName)

			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
					UID:       podUID,
				},
				Spec: corev1.PodSpec{NodeName: nodeName},
			}
			journalEntry = &cni.PortJournalEntry{
				PodNamespace:  podNamespace,
				PodName:       podName,
				PodUID:        podUID,
				SandboxID:     sandboxID,
				PodIfName:     "eth0",
				HostIfaceName: hostIfaceName,
				IfaceID:       ifaceID,
				ExternalIDs: map[string]string{
					"iface-id":     ifaceID,
					"iface-id-ver": podUID,
					"sandbox":      sandboxID,
					"attached_mac": "0a:58:0a:80:03:9e",
				},
			}
		})

		AfterEach(func() {
			if ovsCleanup != nil {
				ovsCleanup.Cleanup()
				ovsCleanup = nil
			}
		})

		setup := func(ovsData []libovsdbtest.TestData) {
			factoryMock.On("GetPod", podNamespace, podName).Return(pod, nil)
			ncm, ovsCleanup = newTestNCM(fakeClient, &factoryMock, nodeName, ovsData)
		}

		It("re-plugs a port that OVS lost while the sandbox is still running", func() {
			Expect(cni.WritePortJournal(journalEntry)).To(Succeed())
			setup(brIntOnly)

			before := repairCount("success")
			ncm.repairMissingOVSPodInterfaces()

			iface, err := libovsdbops.GetOVSInterface(ncm.ovsClient, hostIfaceName)
			Expect(err).NotTo(HaveOccurred())
			Expect(iface.ExternalIDs).To(Equal(journalEntry.ExternalIDs))
			// The port must not come back marked transient: that flag is what
			// made an OVS restart delete it in the first place.
			port, err := libovsdbops.GetOVSPort(ncm.ovsClient, hostIfaceName)
			Expect(err).NotTo(HaveOccurred())
			Expect(port.OtherConfig).NotTo(HaveKey("transient"))
			bridge, err := libovsdbops.GetBridge(ncm.ovsClient, "br-int")
			Expect(err).NotTo(HaveOccurred())
			Expect(bridge.Ports).To(ContainElement(port.UUID))

			Expect(repairCount("success")).To(Equal(before + 1))
			// The entry stays, the pod may need repairing again.
			Expect(journaledPorts()).To(ConsistOf(hostIfaceName))
		})

		It("does nothing when the port is already on br-int", func() {
			Expect(cni.WritePortJournal(journalEntry)).To(Succeed())
			port, iface := ovsPortAndInterface("port-1", "iface-1", hostIfaceName, map[string]string{
				"sandbox": sandboxID, "iface-id": ifaceID, "iface-id-ver": podUID})
			setup([]libovsdbtest.TestData{
				&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
				&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-1"}},
				port, iface,
			})

			before := repairCount("success")
			ncm.repairMissingOVSPodInterfaces()

			Expect(repairCount("success")).To(Equal(before))
			// The row must be left exactly as OVS had it: the journal carries an
			// attached_mac that a repair would have written.
			existing, err := libovsdbops.GetOVSInterface(ncm.ovsClient, hostIfaceName)
			Expect(err).NotTo(HaveOccurred())
			Expect(existing.ExternalIDs).NotTo(HaveKey("attached_mac"))
			bridge, err := libovsdbops.GetBridge(ncm.ovsClient, "br-int")
			Expect(err).NotTo(HaveOccurred())
			Expect(bridge.Ports).To(HaveLen(1))
		})

		It("does not add a second interface for a logical port something else already owns", func() {
			Expect(cni.WritePortJournal(journalEntry)).To(Succeed())
			// A new sandbox for the same pod got a different host veth name.
			port, iface := ovsPortAndInterface("port-1", "iface-1", "pod-a-ifc-new", map[string]string{
				"sandbox": "999newsandbox", "iface-id": ifaceID, "iface-id-ver": podUID})
			setup([]libovsdbtest.TestData{
				&vswitchd.OpenvSwitch{UUID: "root-ovs", Bridges: []string{"bridge-uuid"}},
				&vswitchd.Bridge{UUID: "bridge-uuid", Name: "br-int", Ports: []string{"port-1"}},
				port, iface,
			})

			before := repairCount("success")
			ncm.repairMissingOVSPodInterfaces()

			Expect(repairCount("success")).To(Equal(before))
			_, err := libovsdbops.GetOVSInterface(ncm.ovsClient, hostIfaceName)
			Expect(err).To(HaveOccurred())
		})

		It("forgets a port whose host netdev is gone", func() {
			useFakeNetLinkOps()
			Expect(cni.WritePortJournal(journalEntry)).To(Succeed())
			setup(brIntOnly)

			ncm.repairMissingOVSPodInterfaces()

			Expect(journaledPorts()).To(BeEmpty())
			_, err := libovsdbops.GetOVSInterface(ncm.ovsClient, hostIfaceName)
			Expect(err).To(HaveOccurred())
		})

		It("does not repair a port recorded by a previous instance of the pod", func() {
			journalEntry.PodUID = "pod-a-uuid-0"
			Expect(cni.WritePortJournal(journalEntry)).To(Succeed())
			setup(brIntOnly)

			ncm.repairMissingOVSPodInterfaces()

			_, err := libovsdbops.GetOVSInterface(ncm.ovsClient, hostIfaceName)
			Expect(err).To(HaveOccurred())
			// The netdev is still there, so the entry must survive for the
			// instant when CNI DEL finally removes it.
			Expect(journaledPorts()).To(ConsistOf(hostIfaceName))
		})

		It("does not repair a port of a pod that is being deleted", func() {
			now := metav1.Now()
			pod.DeletionTimestamp = &now
			Expect(cni.WritePortJournal(journalEntry)).To(Succeed())
			setup(brIntOnly)

			ncm.repairMissingOVSPodInterfaces()

			_, err := libovsdbops.GetOVSInterface(ncm.ovsClient, hostIfaceName)
			Expect(err).To(HaveOccurred())
		})

		It("does not repair a port of a pod that has moved to another node", func() {
			pod.Spec.NodeName = "otherNode"
			Expect(cni.WritePortJournal(journalEntry)).To(Succeed())
			setup(brIntOnly)

			ncm.repairMissingOVSPodInterfaces()

			_, err := libovsdbops.GetOVSInterface(ncm.ovsClient, hostIfaceName)
			Expect(err).To(HaveOccurred())
		})

		It("does not repair while the pod cannot be read from the apiserver", func() {
			Expect(cni.WritePortJournal(journalEntry)).To(Succeed())
			factoryMock.On("GetPod", podNamespace, podName).Return(nil, errors.New("not found"))
			ncm, ovsCleanup = newTestNCM(fakeClient, &factoryMock, nodeName, brIntOnly)

			ncm.repairMissingOVSPodInterfaces()

			_, err := libovsdbops.GetOVSInterface(ncm.ovsClient, hostIfaceName)
			Expect(err).To(HaveOccurred())
			// An apiserver blip must never cost the pod its chance of a repair.
			Expect(journaledPorts()).To(ConsistOf(hostIfaceName))
		})

		It("does nothing when no port has been journaled", func() {
			setup(brIntOnly)

			before := repairCount("success")
			ncm.repairMissingOVSPodInterfaces()
			Expect(repairCount("success")).To(Equal(before))
		})
	})

	Describe("NewNodeControllerManager", func() {
		It("creates a VRF manager in DPU mode", func() {
			Expect(config.PrepareTestConfig()).To(Succeed())
			config.OVNKubernetesFeature.EnableNetworkSegmentation = true
			config.OVNKubernetesFeature.EnableMultiNetwork = true
			config.OvnKubeNode.Mode = types.NodeModeDPU

			factoryMock := factoryMocks.NodeWatchFactory{}
			factoryMock.On("UserDefinedNetworkInformer").Return(nil)
			factoryMock.On("ClusterUserDefinedNetworkInformer").Return(nil)
			factoryMock.On("NamespaceInformer").Return(nil)
			nadListerMock := &nadlistermocks.NetworkAttachmentDefinitionLister{}
			nadInformerMock := &nadinformermocks.NetworkAttachmentDefinitionInformer{}
			nadInformerMock.On("Lister").Return(nadListerMock)
			nadInformerMock.On("Informer").Return(nil)
			factoryMock.On("NADInformer").Return(nadInformerMock)
			nodeInformerMock := &coreinformermocks.NodeInformer{}
			nodeListerMock := &corelistermocks.NodeLister{}
			nodeInformerMock.On("Lister").Return(nodeListerMock)
			expectNodeInformer(nodeInformerMock)
			factoryMock.On("NodeCoreInformer").Return(nodeInformerMock)
			fakeClient := &util.OVNClientset{
				KubeClient:   fake.NewSimpleClientset(),
				UplinkClient: uplinkfake.NewSimpleClientset(),
			}
			expectUplinkInformers(&factoryMock)

			ncm, err := NewNodeControllerManager(fakeClient, &factoryMock, "worker1",
				&sync.WaitGroup{}, nil, routemanager.NewController(), nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(ncm.vrfManager).NotTo(BeNil())
			Expect(ncm.ruleManager).To(BeNil())
		})
	})

	Context("verify cleanup of deleted networks", func() {
		var (
			staleNetID uint = 1000
			nodeName        = "worker1"
			nad             = ovntest.GenerateNAD("bluenet", "rednad", "greenamespace",
				types.Layer3Topology, "100.128.0.0/16", types.NetworkRolePrimary)
			netName      = "bluenet"
			netID        = 1003
			v4NodeSubnet = "10.128.0.0/24"
			v6NodeSubnet = "ae70::66/112"
			testNS       ns.NetNS
			fakeClient   *util.OVNClientset
			routeManager = routemanager.NewController()
		)

		BeforeEach(func() {
			// Restore global default values before each testcase
			Expect(config.PrepareTestConfig()).To(Succeed())

			testNS, err = testutils.NewNS()
			Expect(err).NotTo(HaveOccurred())
			v1Objects := []runtime.Object{}
			fakeClient = &util.OVNClientset{
				KubeClient:   fake.NewSimpleClientset(v1Objects...),
				UplinkClient: uplinkfake.NewSimpleClientset(),
			}
		})

		AfterEach(func() {
			Expect(testNS.Close()).To(Succeed())
			Expect(testutils.UnmountNS(testNS)).To(Succeed())
		})

		ovntest.OnSupportedPlatformsIt("check vrf devices are cleaned for deleted networks", func() {
			config.OVNKubernetesFeature.EnableNetworkSegmentation = true
			config.OVNKubernetesFeature.EnableMultiNetwork = true

			factoryMock := factoryMocks.NodeWatchFactory{}
			netInfo, err := util.ParseNADInfo(nad)
			mutableNetInfo := util.NewMutableNetInfo(netInfo)
			Expect(err).NotTo(HaveOccurred())
			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Annotations: map[string]string{
						"k8s.ovn.org/network-ids":  fmt.Sprintf("{\"%s\": \"%d\"}", netName, netID),
						"k8s.ovn.org/node-subnets": fmt.Sprintf("{\"%s\":[\"%s\", \"%s\"]}", netName, v4NodeSubnet, v6NodeSubnet)},
				},
			}
			nodeList := []*corev1.Node{node}
			factoryMock.On("GetNodeForWindows", nodeName).Return(nodeList[0], nil)
			factoryMock.On("GetNodes").Return(nodeList, nil)
			factoryMock.On("UserDefinedNetworkInformer").Return(nil)
			factoryMock.On("ClusterUserDefinedNetworkInformer").Return(nil)
			factoryMock.On("NamespaceInformer").Return(nil)
			nadListerMock := &nadlistermocks.NetworkAttachmentDefinitionLister{}
			nadInformerMock := &nadinformermocks.NetworkAttachmentDefinitionInformer{}
			nadInformerMock.On("Lister").Return(nadListerMock)
			nadInformerMock.On("Informer").Return(nil)
			factoryMock.On("NADInformer").Return(nadInformerMock)
			nodeListerMock := &corelistermocks.NodeLister{}
			nodeListerMock.On("List", mock.Anything).Return(nodeList, nil)
			nodeInformerMock := &coreinformermocks.NodeInformer{}
			nodeInformerMock.On("Lister").Return(nodeListerMock)
			expectNodeInformer(nodeInformerMock)
			factoryMock.On("NodeCoreInformer").Return(nodeInformerMock)
			expectUplinkInformers(&factoryMock)

			ncm, err := NewNodeControllerManager(fakeClient, &factoryMock, nodeName, &sync.WaitGroup{}, nil, routeManager, nil)
			Expect(err).NotTo(HaveOccurred())

			err = testNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				mutableNetInfo.SetNetworkID(int(staleNetID))
				staleVrfDevice := util.GetNetworkVRFName(mutableNetInfo)
				ovntest.AddVRFLink(staleVrfDevice, uint32(staleNetID))
				_, err = util.GetNetLinkOps().LinkByName(staleVrfDevice)
				Expect(err).NotTo(HaveOccurred())

				mutableNetInfo.SetNetworkID(int(int(netID)))
				validVrfDevice := util.GetNetworkVRFName(mutableNetInfo)
				ovntest.AddVRFLink(validVrfDevice, uint32(netID))
				_, err = util.GetNetLinkOps().LinkByName(validVrfDevice)
				Expect(err).NotTo(HaveOccurred())

				err = ncm.CleanupStaleNetworks(mutableNetInfo)
				Expect(err).NotTo(HaveOccurred())

				// Verify CleanupDeletedNetworks cleans up VRF configuration for
				// already deleted network.
				_, err = util.GetNetLinkOps().LinkByName(staleVrfDevice)
				Expect(err).To(HaveOccurred())

				// Verify CleanupDeletedNetworks didn't cleanup VRF configuration for
				// existing network.
				_, err = util.GetNetLinkOps().LinkByName(validVrfDevice)
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		ovntest.OnSupportedPlatformsIt("check stale mpx devices are cleaned for deleted networks", func() {
			config.OVNKubernetesFeature.EnableNetworkSegmentation = true
			config.OVNKubernetesFeature.EnableMultiNetwork = true

			staleMgtPort := fmt.Sprintf("%s%d", types.K8sMgmtIntfNamePrefix, staleNetID)
			fexec := ovntest.NewFakeExec()
			Expect(util.SetExec(fexec)).To(Succeed())
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-vsctl --timeout=15" +
					" --if-exists del-port br-int " + staleMgtPort,
			})
			factoryMock := factoryMocks.NodeWatchFactory{}
			netInfo, err := util.ParseNADInfo(nad)
			mutableNetInfo := util.NewMutableNetInfo(netInfo)
			Expect(err).NotTo(HaveOccurred())
			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Annotations: map[string]string{
						"k8s.ovn.org/network-ids":  fmt.Sprintf("{\"%s\": \"%d\"}", netName, netID),
						"k8s.ovn.org/node-subnets": fmt.Sprintf("{\"%s\":[\"%s\", \"%s\"]}", netName, v4NodeSubnet, v6NodeSubnet)},
				},
			}
			nodeList := []*corev1.Node{node}
			factoryMock.On("GetNodeForWindows", nodeName).Return(nodeList[0], nil)
			factoryMock.On("GetNodes").Return(nodeList, nil)
			factoryMock.On("UserDefinedNetworkInformer").Return(nil)
			factoryMock.On("ClusterUserDefinedNetworkInformer").Return(nil)
			factoryMock.On("NamespaceInformer").Return(nil)
			nadListerMock := &nadlistermocks.NetworkAttachmentDefinitionLister{}
			nadInformerMock := &nadinformermocks.NetworkAttachmentDefinitionInformer{}
			nadInformerMock.On("Lister").Return(nadListerMock)
			nadInformerMock.On("Informer").Return(nil)
			factoryMock.On("NADInformer").Return(nadInformerMock)
			nodeListerMock := &corelistermocks.NodeLister{}
			nodeListerMock.On("List", mock.Anything).Return(nodeList, nil)
			nodeInformerMock := &coreinformermocks.NodeInformer{}
			nodeInformerMock.On("Lister").Return(nodeListerMock)
			expectNodeInformer(nodeInformerMock)
			factoryMock.On("NodeCoreInformer").Return(nodeInformerMock)
			expectUplinkInformers(&factoryMock)
			Expect(err).NotTo(HaveOccurred())
			ncm, err := NewNodeControllerManager(fakeClient, &factoryMock, nodeName, &sync.WaitGroup{}, nil, routeManager, nil)
			Expect(err).NotTo(HaveOccurred())

			err = testNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()
				By("Add stale kernel mpx interface")
				ovntest.AddLink(staleMgtPort)

				By("Add active UDN kernel mpx interface")
				validMgtPort := fmt.Sprintf("%s%d", types.K8sMgmtIntfNamePrefix, netID)
				ovntest.AddLink(validMgtPort)

				mutableNetInfo.SetNetworkID(int(netID))

				By("Cleaning up stale networks")
				err = ncm.CleanupStaleNetworks(mutableNetInfo)
				Expect(err).NotTo(HaveOccurred())

				By("Stale mpx interface should have been removed")
				_, err = util.GetNetLinkOps().LinkByName(staleMgtPort)
				var notFoundErr netlink.LinkNotFoundError
				Expect(errors.As(err, &notFoundErr)).To(BeTrue())

				By("Valid mpx interface should NOT have been removed")
				_, err = util.GetNetLinkOps().LinkByName(validMgtPort)
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
