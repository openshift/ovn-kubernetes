package pod

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/id"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/ip/subnet"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/pod"
	ovncnitypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	kubemocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/mocks"
	v1mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/client-go/listers/core/v1"
)

type testPod struct {
	scheduled   bool
	hostNetwork bool
	completed   bool
	network     *nadapi.NetworkSelectionElement
}

func (p testPod) getPod(t *testing.T) *corev1.Pod {

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "pod",
			UID:         apitypes.UID("pod"),
			Namespace:   "namespace",
			Annotations: map[string]string{},
		},
		Spec: corev1.PodSpec{
			HostNetwork: p.hostNetwork,
		},
		Status: corev1.PodStatus{},
	}
	if p.scheduled {
		pod.Spec.NodeName = "node"
	}
	if p.completed {
		pod.Status.Phase = corev1.PodSucceeded
	}

	if p.network != nil {
		bytes, err := json.Marshal([]*nadapi.NetworkSelectionElement{p.network})
		if err != nil {
			t.Fatalf("Invalid network selection")
		}
		pod.ObjectMeta.Annotations[nadapi.NetworkAttachmentAnnot] = string(bytes)
	}

	return pod
}

type ipAllocatorStub struct {
	released bool
}

func (a *ipAllocatorStub) AddOrUpdateSubnet(name string, subnets []*net.IPNet, excludeSubnets ...*net.IPNet) error {
	panic("not implemented") // TODO: Implement
}

func (a ipAllocatorStub) DeleteSubnet(name string) {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) GetSubnets(name string) ([]*net.IPNet, error) {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) AllocateUntilFull(name string) error {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) AllocateIPs(name string, ips []*net.IPNet) error {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) AllocateNextIPs(name string) ([]*net.IPNet, error) {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) ReleaseIPs(name string, ips []*net.IPNet) error {
	a.released = true
	return nil
}

func (a *ipAllocatorStub) ConditionalIPRelease(name string, ips []*net.IPNet, predicate func() (bool, error)) (bool, error) {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) ForSubnet(name string) subnet.NamedAllocator {
	return nil
}

func (a *ipAllocatorStub) GetSubnetName([]*net.IPNet) (string, bool) {
	panic("not implemented") // TODO: Implement
}

type idAllocatorStub struct {
	released bool
}

func (a *idAllocatorStub) AllocateID(name string) (int, error) {
	panic("not implemented") // TODO: Implement
}

func (a *idAllocatorStub) ReserveID(name string, id int) error {
	panic("not implemented") // TODO: Implement
}

func (a *idAllocatorStub) ReleaseID(name string) {
	a.released = true
}

func (a *idAllocatorStub) ForName(name string) id.NamedAllocator {
	panic("not implemented") // TODO: Implement
}

func (a *idAllocatorStub) GetSubnetName([]*net.IPNet) (string, bool) {
	panic("not implemented") // TODO: Implement
}

func TestPodAllocator_reconcileForNAD(t *testing.T) {
	type args struct {
		old     *testPod
		new     *testPod
		release bool
	}
	tests := []struct {
		name            string
		args            args
		ipam            bool
		idAllocation    bool
		tracked         bool
		expectAllocate  bool
		expectIPRelease bool
		expectIDRelease bool
		expectTracked   bool
	}{
		{
			name: "Pod not scheduled",
			args: args{
				new: &testPod{},
			},
		},
		{
			name: "Pod on host network",
			args: args{
				new: &testPod{
					hostNetwork: true,
				},
			},
		},
		{
			name: "Pod not on network",
			args: args{
				new: &testPod{
					scheduled: true,
				},
			},
		},
		{
			name: "Pod on network",
			args: args{
				new: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
			},
			expectAllocate: true,
		},
		{
			name: "Pod completed, release inactive, IP allocation",
			ipam: true,
			args: args{
				new: &testPod{
					scheduled: true,
					completed: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
			},
			expectTracked: true,
		},
		{
			name:         "Pod completed, release inactive, ID allocation",
			idAllocation: true,
			args: args{
				new: &testPod{
					scheduled: true,
					completed: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
			},
			expectTracked: true,
		},
		{
			name: "Pod completed, release inactive, no allocation",
			args: args{
				new: &testPod{
					scheduled: true,
					completed: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
			},
		},
		{
			name: "Pod completed, release active, not previously released, IP allocation",
			ipam: true,
			args: args{
				new: &testPod{
					scheduled: true,
					completed: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
			expectIPRelease: true,
			expectTracked:   true,
		},
		{
			name:         "Pod completed, release active, not previously released, ID allocation",
			idAllocation: true,
			args: args{
				new: &testPod{
					scheduled: true,
					completed: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
			expectTracked:   true,
			expectIDRelease: true,
		},
		{
			name: "Pod completed, release active, not previously released, no allocation",
			args: args{
				new: &testPod{
					scheduled: true,
					completed: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
		},
		{
			name: "Pod completed, release active, previously released, IP allocation",
			ipam: true,
			args: args{
				new: &testPod{
					scheduled: true,
					completed: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
			tracked:       true,
			expectTracked: true,
		},
		{
			name:         "Pod completed, release active, previously released, ID allocation",
			idAllocation: true,
			args: args{
				new: &testPod{
					scheduled: true,
					completed: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
			tracked:       true,
			expectTracked: true,
		},
		{
			name: "Pod deleted, not scheduled",
			args: args{
				old: &testPod{},
			},
		},
		{
			name: "Pod deleted, on host network",
			args: args{
				old: &testPod{
					hostNetwork: true,
				},
			},
		},
		{
			name: "Pod deleted, not on network",
			args: args{
				old: &testPod{
					scheduled: true,
				},
			},
		},
		{
			name: "Pod deleted, not previously released, IP allocation",
			ipam: true,
			args: args{
				old: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
			expectIPRelease: true,
		},
		{
			name:         "Pod deleted, not previously released, ID allocation",
			idAllocation: true,
			args: args{
				old: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
			expectIDRelease: true,
		},
		{
			name: "Pod deleted, not previously released, no allocation",
			args: args{
				old: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
		},
		{
			name: "Pod deleted, previously released, IP allocation",
			ipam: true,
			args: args{
				old: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
			tracked: true,
		},
		{
			name:         "Pod deleted, previously released, ID allocation",
			idAllocation: true,
			args: args{
				old: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name: "nad",
					},
				},
				release: true,
			},
			tracked: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ipallocator := &ipAllocatorStub{}
			idallocator := &idAllocatorStub{}

			podListerMock := &v1mocks.PodLister{}
			kubeMock := &kubemocks.Interface{}
			podNamespaceLister := &v1mocks.PodNamespaceLister{}

			podListerMock.On("Pods", mock.AnythingOfType("string")).Return(podNamespaceLister)

			var allocated bool
			kubeMock.On("UpdatePod", mock.AnythingOfType(fmt.Sprintf("%T", &corev1.Pod{}))).Run(
				func(args mock.Arguments) {
					allocated = true
				},
			).Return(nil)

			netConf := &ovncnitypes.NetConf{
				Topology: types.Layer2Topology,
			}
			if tt.ipam {
				netConf.Subnets = "10.1.130.0/24"
			}

			config.OVNKubernetesFeature.EnableInterconnect = tt.idAllocation

			netInfo, err := util.NewNetInfo(netConf)
			if err != nil {
				t.Fatalf("Invalid netConf")
			}
			netInfo.AddNAD("namespace/nad")

			podAnnotationAllocator := pod.NewPodAnnotationAllocator(
				netInfo,
				podListerMock,
				kubeMock,
			)

			a := &PodAllocator{
				netInfo:                netInfo,
				ipAllocator:            ipallocator,
				idAllocator:            idallocator,
				podAnnotationAllocator: podAnnotationAllocator,
				releasedPods:           map[string]sets.Set[string]{},
				releasedPodsMutex:      sync.Mutex{},
			}

			var old, new *corev1.Pod
			if tt.args.old != nil {
				old = tt.args.old.getPod(t)
			}
			if tt.args.new != nil {
				new = tt.args.new.getPod(t)
				podNamespaceLister.On("Get", mock.AnythingOfType("string")).Return(new, nil)
			}

			if tt.tracked {
				a.releasedPods["namespace/nad"] = sets.New("pod")
			}

			err = a.reconcile(old, new, tt.args.release)
			if err != nil {
				t.Errorf("reconcile failed: %v", err)
			}

			if tt.expectAllocate != allocated {
				t.Errorf("expected pod ips allocated to be %v but it was %v", tt.expectAllocate, allocated)
			}

			if tt.expectIPRelease != ipallocator.released {
				t.Errorf("expected pod ips released to be %v but it was %v", tt.expectIPRelease, ipallocator.released)
			}

			if tt.expectIDRelease != idallocator.released {
				t.Errorf("expected pod ID released to be %v but it was %v", tt.expectIPRelease, ipallocator.released)
			}

			if tt.expectTracked != a.releasedPods["namespace/nad"].Has("pod") {
				t.Errorf("expected pod tracked to be %v but it was %v", tt.expectTracked, a.releasedPods["namespace/nad"].Has("pod"))
			}
		})
	}
}
