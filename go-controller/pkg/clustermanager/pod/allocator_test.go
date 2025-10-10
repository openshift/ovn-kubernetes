package pod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	ipamclaimsapi "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1"
	fakeipamclaimclient "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1/apis/clientset/versioned/fake"
	ipamclaimsfactory "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1/apis/informers/externalversions"
	ipamclaimslister "github.com/k8snetworkplumbingwg/ipamclaims/pkg/crd/ipamclaims/v1alpha1/apis/listers/ipamclaims/v1alpha1"
	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/id"
	ipallocator "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/ip"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/ip/subnet"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/mac"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/pod"
	ovncnitypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	kubemocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/mocks"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/persistentips"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	v1mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/client-go/listers/core/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/networkmanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type testPod struct {
	scheduled   bool
	hostNetwork bool
	completed   bool
	network     *nadapi.NetworkSelectionElement
	labels      map[string]string
}

func (p testPod) getPod(t *testing.T) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "pod",
			UID:         apitypes.UID("pod"),
			Namespace:   "namespace",
			Annotations: map[string]string{},
			Labels:      p.labels,
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
	released   bool
	fullIPPool bool
}

func (a *ipAllocatorStub) AddOrUpdateSubnet(_ subnet.SubnetConfig) error {
	panic("not implemented") // TODO: Implement
}

func (a ipAllocatorStub) DeleteSubnet(string) {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) GetSubnets(string) ([]*net.IPNet, error) {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) AllocateUntilFull(string) error {
	a.fullIPPool = true
	return nil
}

func (a *ipAllocatorStub) AllocateIPPerSubnet(string, []*net.IPNet) error {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) AllocateNextIPs(string) ([]*net.IPNet, error) {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) ReleaseIPs(string, []*net.IPNet) error {
	a.released = true
	return nil
}

func (a *ipAllocatorStub) ConditionalIPRelease(string, []*net.IPNet, func() (bool, error)) (bool, error) {
	panic("not implemented") // TODO: Implement
}

func (a *ipAllocatorStub) ForSubnet(string) subnet.NamedAllocator {
	return &namedAllocatorStub{
		fullIPPool: a.fullIPPool,
	}
}

func (a *ipAllocatorStub) GetSubnetName([]*net.IPNet) (string, bool) {
	panic("not implemented") // TODO: Implement
}

type idAllocatorStub struct {
	released bool
}

func (a *idAllocatorStub) AllocateID(string) (int, error) {
	panic("not implemented") // TODO: Implement
}

func (a *idAllocatorStub) ReserveID(string, int) error {
	panic("not implemented") // TODO: Implement
}

func (a *idAllocatorStub) ReleaseID(string) {
	a.released = true
}

func (a *idAllocatorStub) ForName(string) id.NamedAllocator {
	panic("not implemented") // TODO: Implement
}

func (a *idAllocatorStub) GetSubnetName([]*net.IPNet) (string, bool) {
	panic("not implemented") // TODO: Implement
}

type namedAllocatorStub struct {
	fullIPPool bool
}

func (nas *namedAllocatorStub) AllocateIPs([]*net.IPNet) error {
	if nas.fullIPPool {
		return ipallocator.ErrFull
	}
	return nil
}

func (nas *namedAllocatorStub) AllocateNextIPs() ([]*net.IPNet, error) {
	return nil, nil
}

func (nas *namedAllocatorStub) ReleaseIPs([]*net.IPNet) error {
	return nil
}

type macRegistryStub struct {
	reservedMAC, releasedMAC net.HardwareAddr
	ownerID                  string
	reserveErr, releaseErr   error
}

func (m *macRegistryStub) Reserve(owner string, mac net.HardwareAddr) error {
	m.ownerID = owner
	m.reservedMAC = mac
	return m.reserveErr
}
func (m *macRegistryStub) Release(owner string, mac net.HardwareAddr) error {
	m.ownerID = owner
	m.releasedMAC = mac
	return m.releaseErr
}

func TestPodAllocator_reconcileForNAD(t *testing.T) {
	type args struct {
		old       *testPod
		new       *testPod
		ipamClaim *ipamclaimsapi.IPAMClaim
		nads      []*nadapi.NetworkAttachmentDefinition
		release   bool
	}
	tests := []struct {
		name              string
		args              args
		ipam              bool
		idAllocation      bool
		macRegistry       *macRegistryStub
		tracked           bool
		role              string
		expectAllocate    bool
		expectIPRelease   bool
		expectIDRelease   bool
		expectMACReserve  *net.HardwareAddr
		expectMACRelease  *net.HardwareAddr
		expectMACOwnerID  string
		expectTracked     bool
		fullIPPool        bool
		expectEvents      []string
		expectError       string
		podAnnotation     *util.PodAnnotation
		newPodCopyRunning bool
		podListerErr      error
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
		{
			name: "Pod on network, persistent IP requested, IPAMClaim features IPs",
			args: args{
				new: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name:               "nad",
						IPAMClaimReference: "claim",
					},
				},
				ipamClaim: &ipamclaimsapi.IPAMClaim{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "claim",
						Namespace: "namespace",
					},
					Status: ipamclaimsapi.IPAMClaimStatus{
						IPs: []string{"192.168.200.80/24"},
					},
				},
			},
			expectAllocate: true,
			ipam:           true,
		},
		{
			name: "Pod deleted, persistent IPs, IP not released",
			args: args{
				old: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name:               "nad",
						IPAMClaimReference: "claim",
					},
				},
				ipamClaim: &ipamclaimsapi.IPAMClaim{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "claim",
						Namespace: "namespace",
					},
					Status: ipamclaimsapi.IPAMClaimStatus{
						IPs: []string{"192.168.200.80/24"},
					},
				},
				release: true,
			},
			ipam: true,
		},
		{
			name: "Pod deleted, persistent IPs requested *but* not found, IP released",
			args: args{
				old: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Name:               "nad",
						IPAMClaimReference: "claim",
					},
				},
				ipamClaim: &ipamclaimsapi.IPAMClaim{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "claim",
						Namespace: "namespace",
					},
					Status: ipamclaimsapi.IPAMClaimStatus{},
				},
				release: true,
			},
			ipam:            true,
			expectIPRelease: true,
		},
		{
			name: "Pod with primary network NSE, expect event and error",
			args: args{
				new: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Namespace: "namespace",
						Name:      "nad",
					},
				},
				nads: []*nadapi.NetworkAttachmentDefinition{
					ovntest.GenerateNAD("surya", "nad", "namespace",
						types.Layer3Topology, "100.128.0.0/16", types.NetworkRolePrimary),
				},
			},
			role:         types.NetworkRolePrimary,
			expectError:  "failed to get NAD to network mapping: unexpected primary network \"\" specified with a NetworkSelectionElement &{Name:nad Namespace:namespace IPRequest:[] MacRequest: InfinibandGUIDRequest: InterfaceRequest: PortMappingsRequest:[] BandwidthRequest:<nil> CNIArgs:<nil> GatewayRequest:[] IPAMClaimReference:}",
			expectEvents: []string{"Warning ErrorAllocatingPod unexpected primary network \"\" specified with a NetworkSelectionElement &{Name:nad Namespace:namespace IPRequest:[] MacRequest: InfinibandGUIDRequest: InterfaceRequest: PortMappingsRequest:[] BandwidthRequest:<nil> CNIArgs:<nil> GatewayRequest:[] IPAMClaimReference:}"},
		},
		{
			name: "Pod on network with exhausted ip pool, expect event and error",
			args: args{
				new: &testPod{
					scheduled: true,
					network: &nadapi.NetworkSelectionElement{
						Namespace: "namespace",
						Name:      "nad",
					},
				},
			},
			podAnnotation: &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets("10.1.130.0/24"),
				MAC: util.IPAddrToHWAddr(ovntest.MustParseIPNets("10.1.130.0/24")[0].IP),
			},
			ipam:         true,
			fullIPPool:   true,
			expectEvents: []string{"Warning ErrorAllocatingPod failed to update pod namespace/pod: failed to ensure requested or annotated IPs [10.1.130.0/24] for namespace/nad/namespace/pod: subnet address pool exhausted"},
			expectError:  "failed to update pod namespace/pod: failed to ensure requested or annotated IPs [10.1.130.0/24] for namespace/nad/namespace/pod: subnet address pool exhausted",
		},

		// podAllocator's macRegistry record mac on pod creation
		{
			name:        "macRegistry should record pod's MAC",
			macRegistry: &macRegistryStub{},
			args: args{
				new: &testPod{
					scheduled: true,
					// use predictable MAC address for testing.
					network: &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad", MacRequest: "0a:0a:0a:0a:0a:0a"},
				},
			},
			expectMACReserve: &net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a},
			expectAllocate:   true,
		},
		{
			name:        "should fail when macRegistry fail to reserve pod's MAC",
			macRegistry: &macRegistryStub{reserveErr: errors.New("test reserve failure")},
			args: args{
				new: &testPod{
					scheduled: true,
					// use predictable MAC address for testing.
					network: &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad", MacRequest: "0a:0a:0a:0a:0a:0a"},
				},
			},
			expectError: `failed to update pod namespace/pod: failed to reserve MAC address "0a:0a:0a:0a:0a:0a" for owner "namespace/pod" on network attachment "namespace/nad": test reserve failure`,
		},
		{
			name:        "should emit pod event when macRegistry fail to reserve pod's MAC due to MAC conflict",
			macRegistry: &macRegistryStub{reserveErr: mac.ErrReserveMACConflict},
			args: args{
				new: &testPod{
					scheduled: true,
					// use predictable MAC address for testing.
					network: &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad", MacRequest: "0a:0a:0a:0a:0a:0a"},
				},
			},
			expectError:  `failed to update pod namespace/pod: failed to reserve MAC address "0a:0a:0a:0a:0a:0a" for owner "namespace/pod" on network attachment "namespace/nad": MAC address already in use`,
			expectEvents: []string{`Warning ErrorAllocatingPod failed to update pod namespace/pod: failed to reserve MAC address "0a:0a:0a:0a:0a:0a" for owner "namespace/pod" on network attachment "namespace/nad": MAC address already in use`},
		},
		{
			name:        "should NOT fail when macRegistry gets repeated reserve requests (same mac and owner)",
			macRegistry: &macRegistryStub{reserveErr: mac.ErrMACReserved},
			args: args{
				new: &testPod{
					scheduled: true,
					network:   &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
				},
			},
			expectAllocate: true,
		},
		// podAllocator's macRegistry remove mac record on pod complete/deleted
		{
			name:          "Pod completed, macRegistry should release pod's MAC",
			ipam:          true,
			macRegistry:   &macRegistryStub{},
			podAnnotation: &util.PodAnnotation{MAC: net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a}},
			args: args{
				release: true,
				new: &testPod{
					scheduled: true,
					completed: true,
					network:   &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
				},
			},
			expectMACRelease: &net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a},
			expectIPRelease:  true,
			expectTracked:    true,
		},
		{
			name:          "Pod completed, has VM label, macRegistry should release pod's MAC",
			ipam:          true,
			macRegistry:   &macRegistryStub{},
			podAnnotation: &util.PodAnnotation{MAC: net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a}},
			args: args{
				release: true,
				new: &testPod{
					scheduled: true,
					completed: true,
					network:   &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
					labels:    map[string]string{"vm.kubevirt.io/name": "myvm"},
				},
			},
			expectMACRelease: &net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a},
			expectIPRelease:  true,
			expectTracked:    true,
		},
		{
			name:          "Pod completed, should fail when macRegistry fail to release pod MAC",
			ipam:          true,
			macRegistry:   &macRegistryStub{releaseErr: errors.New("test release failure")},
			podAnnotation: &util.PodAnnotation{MAC: net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a}},
			args: args{
				release: true,
				new: &testPod{
					scheduled: true,
					completed: true,
					// use predictable MAC address for testing.
					network: &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad", MacRequest: "0a:0a:0a:0a:0a:0a"},
				},
			},
			expectError:     `failed to release pod "namespace/pod" mac "0a:0a:0a:0a:0a:0a": failed to release MAC address "0a:0a:0a:0a:0a:0a" for owner "namespace/pod" on network "": test release failure`,
			expectIPRelease: true,
		},
		{
			// In a scenario of VM migration, migration destination and source pods use the same network configuration,
			// including MAC address. The MAC address should not be released as long there is at least one VM pod running.
			name:          "Pod completed, has VM label, macRegistry should NOT release MAC when not all associated VM pods are in completed state",
			ipam:          true,
			macRegistry:   &macRegistryStub{},
			podAnnotation: &util.PodAnnotation{MAC: net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a}},
			args: args{
				release: true,
				new: &testPod{
					scheduled: true,
					completed: true,
					network:   &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
					labels:    map[string]string{"vm.kubevirt.io/name": ""},
				},
			},
			newPodCopyRunning: true,
			expectTracked:     true,
			expectIPRelease:   true,
		},
		{
			name:          "Pod completed, has VM label, macRegistry should fail when checking associated VM pods are in complete state",
			ipam:          true,
			macRegistry:   &macRegistryStub{},
			podListerErr:  errors.New("test error"),
			podAnnotation: &util.PodAnnotation{MAC: net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a}},
			args: args{
				release: true,
				new: &testPod{
					scheduled: true,
					completed: true,
					network:   &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
					labels:    map[string]string{"vm.kubevirt.io/name": "myvm"},
				},
			},
			expectError:     `failed to release pod "namespace/pod" mac "0a:0a:0a:0a:0a:0a": failed checking all VM "namespace/myvm" pods are completed: failed finding related pods for pod namespace/pod when checking if they are completed: test error`,
			expectIPRelease: true,
		},
		{
			name:          "Pod completed, should NOT fail when macRegistry fail to release pod's MAC due to miss-match owner error",
			ipam:          true,
			macRegistry:   &macRegistryStub{releaseErr: mac.ErrReleaseMismatchOwner},
			podAnnotation: &util.PodAnnotation{MAC: net.HardwareAddr{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a}},
			args: args{
				release: true,
				new: &testPod{
					scheduled: true,
					completed: true,
					network:   &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
				},
			},
			expectIPRelease: true,
			expectTracked:   true,
		},
		// podAllocator compose MAC owner IDs as expected
		{
			name:        "should compose MAC owner ID from pod.namespace and pod.name",
			macRegistry: &macRegistryStub{},
			args: args{
				new: &testPod{
					network:   &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
					scheduled: true,
				},
			},
			expectMACOwnerID: "namespace/pod",
			expectAllocate:   true,
		},
		{
			name:        "Pod completed, should compose MAC owner ID from pod.namespace and pod.name",
			ipam:        true,
			macRegistry: &macRegistryStub{},
			args: args{
				release: true,
				new: &testPod{
					scheduled: true, completed: true,
					network: &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
				},
			},
			expectMACOwnerID: "namespace/pod",
			expectTracked:    true,
			expectIPRelease:  true,
		},
		{
			// In a scenario of VM migration, migration destination and source pods use the same network configuration,
			// including MAC address. Given VM pods, composing the owner ID from the VM name relaxes MAC conflict errors,
			// when VM is migrated (where migration source and destination pods share the same MAC).
			name:             "Given pod with VM label, should compose MAC owner ID from pod.namespace and VM label",
			expectMACOwnerID: "namespace/myvm",
			macRegistry:      &macRegistryStub{},
			args: args{
				new: &testPod{
					network:   &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
					scheduled: true,
					labels:    map[string]string{"vm.kubevirt.io/name": "myvm"},
				},
			},
			expectAllocate: true,
		},
		{
			// In a scenario of VM migration, migration destination and source pods use the same network configuration,
			// including MAC address. Given VM pods, composing the owner ID from the VM name relaxes MAC conflict errors,
			// when VM is migrated (where migration source and destination pods share the same MAC).
			name:        "Pod completed, has VM label, should compose MAC owner ID from pod.namespace and VM label",
			ipam:        true,
			macRegistry: &macRegistryStub{},
			args: args{
				release: true,
				new: &testPod{
					scheduled: true, completed: true,
					network: &nadapi.NetworkSelectionElement{Namespace: "namespace", Name: "nad"},
					labels:  map[string]string{"vm.kubevirt.io/name": "myvm"},
				},
			},
			expectMACOwnerID: "namespace/myvm",
			expectTracked:    true,
			expectIPRelease:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			ipallocator := &ipAllocatorStub{}
			idallocator := &idAllocatorStub{}

			podListerMock := &v1mocks.PodLister{}
			nodeListerMock := &v1mocks.NodeLister{}
			kubeMock := &kubemocks.InterfaceOVN{}
			podNamespaceLister := &v1mocks.PodNamespaceLister{}

			if tt.podListerErr != nil {
				podNamespaceLister.On("List", mock.AnythingOfType("labels.internalSelector")).
					Return(nil, tt.podListerErr).Once()
			}

			podListerMock.On("Pods", mock.AnythingOfType("string")).Return(podNamespaceLister)

			var allocated bool
			kubeMock.On("UpdatePodStatus", mock.AnythingOfType(fmt.Sprintf("%T", &corev1.Pod{}))).Run(
				func(mock.Arguments) {
					allocated = true
				},
			).Return(nil)

			kubeMock.On(
				"UpdateIPAMClaimIPs",
				mock.AnythingOfType(fmt.Sprintf("%T", &ipamclaimsapi.IPAMClaim{})),
			).Return(nil)

			nodeListerMock.On("Get", mock.AnythingOfType("string")).Return(&corev1.Node{}, nil)

			netConf := &ovncnitypes.NetConf{
				Topology:           types.Layer2Topology,
				AllowPersistentIPs: tt.ipam && tt.args.ipamClaim != nil,
			}

			if tt.role != "" {
				netConf.Role = tt.role
			}

			if tt.ipam {
				netConf.Subnets = "10.1.130.0/24"
			}

			config.OVNKubernetesFeature.EnableInterconnect = tt.idAllocation

			// config.IPv4Mode needs to be set so that the ipv4 of the userdefined primary networks can match the running cluster
			config.IPv4Mode = true
			netInfo, err := util.NewNetInfo(netConf)
			if err != nil {
				t.Fatalf("Invalid netConf")
			}
			mutableNetInfo := util.NewMutableNetInfo(netInfo)
			mutableNetInfo.AddNADs("namespace/nad")
			netInfo = mutableNetInfo

			var ipamClaimsReconciler persistentips.PersistentAllocations
			if tt.ipam && tt.args.ipamClaim != nil {
				ctx, cancel := context.WithCancel(context.Background())
				ipamClaimsLister, teardownFn := generateIPAMClaimsListerAndTeardownFunc(ctx.Done(), tt.args.ipamClaim)
				ipamClaimsReconciler = persistentips.NewIPAMClaimReconciler(kubeMock, netInfo, ipamClaimsLister)

				t.Cleanup(func() {
					cancel()
					teardownFn()
				})
			}

			var opts []pod.AllocatorOption
			if tt.macRegistry != nil {
				opts = append(opts, pod.WithMACRegistry(tt.macRegistry))
			}
			podAnnotationAllocator := pod.NewPodAnnotationAllocator(
				netInfo,
				podListerMock,
				kubeMock,
				ipamClaimsReconciler,
				opts...,
			)

			testNs := "namespace"
			nadNetworks := map[string]util.NetInfo{}
			for _, nad := range tt.args.nads {
				if nad.Namespace == testNs {
					nadNetwork, _ := util.ParseNADInfo(nad)
					if nadNetwork.IsPrimaryNetwork() {
						if _, ok := nadNetworks[testNs]; !ok {
							nadNetworks[testNs] = nadNetwork
						}
					}
				}
			}

			fakeNetworkManager := &networkmanager.FakeNetworkManager{PrimaryNetworks: nadNetworks}

			fakeRecorder := record.NewFakeRecorder(10)

			config.OVNKubernetesFeature.EnableMultiNetwork = true
			config.OVNKubernetesFeature.EnableNetworkSegmentation = true

			a := &PodAllocator{
				netInfo:                netInfo,
				ipAllocator:            ipallocator,
				idAllocator:            idallocator,
				podAnnotationAllocator: podAnnotationAllocator,
				releasedPods:           map[string]sets.Set[string]{},
				releasedPodsMutex:      sync.Mutex{},
				ipamClaimsReconciler:   ipamClaimsReconciler,
				networkManager:         fakeNetworkManager,
				recorder:               fakeRecorder,
				nodeLister:             nodeListerMock,
			}

			var old, new *corev1.Pod
			if tt.args.old != nil {
				old = tt.args.old.getPod(t)
			}
			if tt.args.new != nil {
				new = tt.args.new.getPod(t)
				podNamespaceLister.On("Get", mock.AnythingOfType("string")).Return(new, nil)

				pods := []*corev1.Pod{new}
				if tt.newPodCopyRunning {
					cp := new.DeepCopy()
					cp.Status.Phase = corev1.PodRunning
					cp.UID = "copy"
					pods = append(pods, cp)
				}
				if tt.podListerErr == nil {
					podNamespaceLister.On("List", mock.AnythingOfType("labels.internalSelector")).
						Return(pods, nil).Once()
				}
			}

			if tt.tracked {
				a.releasedPods["namespace/nad"] = sets.New("pod")
			}

			if tt.fullIPPool {
				if err := a.ipAllocator.AllocateUntilFull(netConf.Subnets); err != nil {
					t.Fatalf("failed to allocate subnets until full: %v", err)
				}
			}

			if tt.podAnnotation != nil {
				if new != nil {
					new.Annotations, err = util.MarshalPodAnnotation(new.Annotations, tt.podAnnotation, "namespace/nad")
					if err != nil {
						t.Fatalf("failed to set pod annotations: %v", err)
					}
				}
				if old != nil {
					old.Annotations, err = util.MarshalPodAnnotation(old.Annotations, tt.podAnnotation, "namespace/nad")
					if err != nil {
						t.Fatalf("failed to set pod annotations: %v", err)
					}
				}
			}

			err = a.reconcile(old, new, tt.args.release)
			if len(tt.expectError) > 0 {
				g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(tt.expectError)))
			} else if err != nil {
				t.Errorf("reconcile unexpected failure: %v", err)
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
			if tt.expectMACReserve != nil && tt.macRegistry.reservedMAC.String() != tt.expectMACReserve.String() {
				t.Errorf("expected pod MAC reserved to be %v but it was %v", tt.expectMACReserve, tt.macRegistry.reservedMAC)
			}
			if tt.expectMACRelease != nil && tt.expectMACRelease.String() != tt.macRegistry.releasedMAC.String() {
				t.Errorf("expected pod MAC released to be %v but it was %v", tt.expectMACRelease, tt.macRegistry.releasedMAC)
			}
			if tt.expectMACOwnerID != "" && tt.expectMACOwnerID != tt.macRegistry.ownerID {
				t.Errorf("expected pod MAC owner ID to be %v but it was %v", tt.expectMACOwnerID, tt.macRegistry.ownerID)
			}

			var obtainedEvents []string
			for {
				if len(fakeRecorder.Events) == 0 {
					break
				}
				obtainedEvents = append(obtainedEvents, <-fakeRecorder.Events)
			}
			g.Expect(tt.expectEvents).To(gomega.Equal(obtainedEvents))
		})
	}
}

func generateIPAMClaimsListerAndTeardownFunc(stopChannel <-chan struct{}, ipamClaims ...runtime.Object) (ipamclaimslister.IPAMClaimLister, func()) {
	ipamClaimClient := fakeipamclaimclient.NewSimpleClientset(ipamClaims...)
	informerFactory := ipamclaimsfactory.NewSharedInformerFactory(ipamClaimClient, 0)
	lister := informerFactory.K8s().V1alpha1().IPAMClaims().Lister()
	informerFactory.Start(stopChannel)
	informerFactory.WaitForCacheSync(stopChannel)
	return lister, func() {
		informerFactory.Shutdown()
	}
}
