package pod

import (
	"errors"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	ipam "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/ip"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/allocator/ip/subnet"
	ovncnitypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/onsi/gomega"
)

type allocatorStub struct {
	netxtIPs         []*net.IPNet
	allocateIPsError error
	releasedIPs      []*net.IPNet
}

func (a *allocatorStub) AllocateIPs(ips []*net.IPNet) error {
	return a.allocateIPsError
}

func (a *allocatorStub) AllocateNextIPs() ([]*net.IPNet, error) {
	return a.netxtIPs, nil
}

func (a *allocatorStub) ReleaseIPs(ips []*net.IPNet) error {
	a.releasedIPs = ips
	return nil
}

func (a *allocatorStub) IsErrAllocated(err error) bool {
	return errors.Is(err, ipam.ErrAllocated)
}

func Test_allocatePodAnnotationWithRollback(t *testing.T) {
	randomMac, err := util.GenerateRandMAC()
	if err != nil {
		t.Fatalf("failed to generate random mac")
	}

	requestedMAC := "01:02:03:04:05:06"
	requestedMACParsed, err := net.ParseMAC(requestedMAC)
	if err != nil {
		t.Fatalf("failed to generate random mac")
	}

	type args struct {
		ipAllocator subnet.NamedAllocator
		network     *nadapi.NetworkSelectionElement
		reallocate  bool
	}
	tests := []struct {
		name                      string
		args                      args
		ipam                      bool
		podAnnotation             *util.PodAnnotation
		invalidNetworkAnnotation  bool
		wantUpdatedPod            bool
		wantGeneratedMac          bool
		wantPodAnnotation         *util.PodAnnotation
		wantReleasedIPs           []*net.IPNet
		wantReleasedIPsOnRollback []*net.IPNet
		wantErr                   bool
	}{
		{
			// on secondary L2 networks with no IPAM, we expect to generate a
			// random mac
			name:             "expect generated mac, no IPAM",
			wantUpdatedPod:   true,
			wantGeneratedMac: true,
		},
		{
			// on secondary L2 networks with no IPAM, if the pod is already
			// annotated with a random MAC, we expect no further changes
			name: "expect no updates, has mac, no IPAM",
			podAnnotation: &util.PodAnnotation{
				MAC: randomMac,
			},
			wantPodAnnotation: &util.PodAnnotation{
				MAC: randomMac,
			},
		},
		{
			// on secondary L2 network with no IPAM, honor static IP requests
			// present in the network selection annotation
			name: "expect requested static IP, no gateway, no IPAM",
			args: args{
				network: &nadapi.NetworkSelectionElement{
					IPRequest: []string{"192.168.0.4/24"},
				},
				ipAllocator: &allocatorStub{
					netxtIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				},
			},
			wantUpdatedPod: true,
			wantPodAnnotation: &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets("192.168.0.4/24"),
				MAC: util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.4/24")[0].IP),
			},
		},
		{
			// on secondary L2 network with no IPAM, honor static IP and gateway
			// requests present in the network selection annotation
			name: "expect requested static IP, with gateway, no IPAM",
			args: args{
				network: &nadapi.NetworkSelectionElement{
					IPRequest:      []string{"192.168.0.4/24"},
					GatewayRequest: ovntest.MustParseIPs("192.168.0.1"),
				},
				ipAllocator: &allocatorStub{
					netxtIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				},
			},
			wantUpdatedPod: true,
			wantPodAnnotation: &util.PodAnnotation{
				IPs:      ovntest.MustParseIPNets("192.168.0.4/24"),
				MAC:      util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.4/24")[0].IP),
				Gateways: ovntest.MustParseIPs("192.168.0.1"),
			},
		},
		{
			// on networks with IPAM, expect error if static IP request present
			// in the network selection annotation
			name: "expect error, static ip request, IPAM",
			ipam: true,
			args: args{
				network: &nadapi.NetworkSelectionElement{
					IPRequest: []string{"192.168.0.3/24"},
				},
			},
			wantUpdatedPod: true,
			wantErr:        true,
		},
		{
			// on networks with IPAM, expect a normal IP, MAC and gateway
			// allocation
			name: "expect new IP",
			ipam: true,
			args: args{
				ipAllocator: &allocatorStub{
					netxtIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				},
			},
			wantUpdatedPod: true,
			wantPodAnnotation: &util.PodAnnotation{
				IPs:      ovntest.MustParseIPNets("192.168.0.3/24"),
				MAC:      util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.3/24")[0].IP),
				Gateways: []net.IP{ovntest.MustParseIP("192.168.0.1").To4()},
				Routes: []util.PodRoute{
					{
						Dest:    ovntest.MustParseIPNet("100.64.0.0/16"),
						NextHop: ovntest.MustParseIP("192.168.0.1").To4(),
					},
				},
			},
			wantReleasedIPsOnRollback: ovntest.MustParseIPNets("192.168.0.3/24"),
		},
		{
			// on networks with IPAM, if pod is already annotated, expect no
			// further updates but do allocate the IP
			name: "expect no updates, annotated, IPAM",
			ipam: true,
			podAnnotation: &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				MAC: util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.3/24")[0].IP),
			},
			args: args{
				ipAllocator: &allocatorStub{},
			},
			wantPodAnnotation: &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				MAC: util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.3/24")[0].IP),
			},
			wantReleasedIPsOnRollback: ovntest.MustParseIPNets("192.168.0.3/24"),
		},
		{
			// on networks with IPAM, if pod is already annotated, expect no
			// further updates and no error if the IP is already allocated
			name: "expect no updates, annotated, already allocated, IPAM",
			ipam: true,
			podAnnotation: &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				MAC: util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.3/24")[0].IP),
			},
			args: args{
				ipAllocator: &allocatorStub{
					allocateIPsError: ipam.ErrAllocated,
				},
			},
			wantPodAnnotation: &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				MAC: util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.3/24")[0].IP),
			},
		},
		{
			// on networks with IPAM, if pod is already annotated, expect error
			// if allocation fails
			name: "expect error, annotated, allocation fails, IPAM",
			ipam: true,
			podAnnotation: &util.PodAnnotation{
				IPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				MAC: util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.3/24")[0].IP),
			},
			args: args{
				ipAllocator: &allocatorStub{
					allocateIPsError: errors.New("Allocate IPs failed"),
				},
			},
			wantErr: true,
		},
		{
			// on networks with IPAM, try to honor IP request allowing to
			// re-allocater on error
			name: "expect requested non-static IP, IPAM",
			ipam: true,
			args: args{
				reallocate: true,
				network: &nadapi.NetworkSelectionElement{
					IPRequest: []string{"192.168.0.4/24"},
				},
				ipAllocator: &allocatorStub{
					netxtIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				},
			},
			wantUpdatedPod: true,
			wantPodAnnotation: &util.PodAnnotation{
				IPs:      ovntest.MustParseIPNets("192.168.0.4/24"),
				MAC:      util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.4/24")[0].IP),
				Gateways: []net.IP{ovntest.MustParseIP("192.168.0.1").To4()},
				Routes: []util.PodRoute{
					{
						Dest:    ovntest.MustParseIPNet("100.64.0.0/16"),
						NextHop: ovntest.MustParseIP("192.168.0.1").To4(),
					},
				},
			},
			wantReleasedIPsOnRollback: ovntest.MustParseIPNets("192.168.0.4/24"),
		},
		{
			// on networks with IPAM, try to honor IP request that is already
			// allocated
			name: "expect requested non-static IP, already allocated, IPAM",
			ipam: true,
			args: args{
				reallocate: true,
				network: &nadapi.NetworkSelectionElement{
					IPRequest: []string{"192.168.0.4/24"},
				},
				ipAllocator: &allocatorStub{
					netxtIPs:         ovntest.MustParseIPNets("192.168.0.3/24"),
					allocateIPsError: ipam.ErrAllocated,
				},
			},
			wantUpdatedPod: true,
			wantPodAnnotation: &util.PodAnnotation{
				IPs:      ovntest.MustParseIPNets("192.168.0.4/24"),
				MAC:      util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.4/24")[0].IP),
				Gateways: []net.IP{ovntest.MustParseIP("192.168.0.1").To4()},
				Routes: []util.PodRoute{
					{
						Dest:    ovntest.MustParseIPNet("100.64.0.0/16"),
						NextHop: ovntest.MustParseIP("192.168.0.1").To4(),
					},
				},
			},
		},
		{
			// on networks with IPAM, trying to honor IP request but
			// re-allocating on error
			name: "expect reallocate to new IP, error on requested non-static IP, IPAM",
			ipam: true,
			args: args{
				reallocate: true,
				network: &nadapi.NetworkSelectionElement{
					IPRequest: []string{"192.168.0.4/24"},
				},
				ipAllocator: &allocatorStub{
					netxtIPs:         ovntest.MustParseIPNets("192.168.0.3/24"),
					allocateIPsError: errors.New("Allocate IPs failed"),
				},
			},
			wantUpdatedPod: true,
			wantPodAnnotation: &util.PodAnnotation{
				IPs:      ovntest.MustParseIPNets("192.168.0.3/24"),
				MAC:      util.IPAddrToHWAddr(ovntest.MustParseIPNets("192.168.0.3/24")[0].IP),
				Gateways: []net.IP{ovntest.MustParseIP("192.168.0.1").To4()},
				Routes: []util.PodRoute{
					{
						Dest:    ovntest.MustParseIPNet("100.64.0.0/16"),
						NextHop: ovntest.MustParseIP("192.168.0.1").To4(),
					},
				},
			},
			wantReleasedIPsOnRollback: ovntest.MustParseIPNets("192.168.0.3/24"),
		},
		{
			// on networks with IPAM, expect error on an invalid IP request
			name: "expect error, invalid requested IP, no IPAM",
			ipam: false,
			args: args{
				network: &nadapi.NetworkSelectionElement{
					IPRequest: []string{"ivalid"},
				},
				ipAllocator: &allocatorStub{
					netxtIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				},
			},
			wantErr: true,
		},
		{
			// on networks with IPAM, expect error on an invalid MAC request
			name: "expect error, invalid requested MAC, IPAM",
			ipam: true,
			args: args{
				network: &nadapi.NetworkSelectionElement{
					MacRequest: "ivalid",
				},
				ipAllocator: &allocatorStub{
					netxtIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				},
			},
			wantErr:         true,
			wantReleasedIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
		},
		{
			// on networks with IPAM, honor a MAC request through the network
			// selection element
			name: "expect requested MAC",
			ipam: true,
			args: args{
				network: &nadapi.NetworkSelectionElement{
					MacRequest: requestedMAC,
				},
				ipAllocator: &allocatorStub{
					netxtIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				},
			},
			wantUpdatedPod: true,
			wantPodAnnotation: &util.PodAnnotation{
				IPs:      ovntest.MustParseIPNets("192.168.0.3/24"),
				MAC:      requestedMACParsed,
				Gateways: []net.IP{ovntest.MustParseIP("192.168.0.1").To4()},
				Routes: []util.PodRoute{
					{
						Dest:    ovntest.MustParseIPNet("100.64.0.0/16"),
						NextHop: ovntest.MustParseIP("192.168.0.1").To4(),
					},
				},
			},
			wantReleasedIPsOnRollback: ovntest.MustParseIPNets("192.168.0.3/24"),
		},
		{
			// on networks with IPAM, expect error on an invalid network
			// selection element
			name: "expect error, invalid network annotation, IPAM",
			ipam: true,
			args: args{
				network: &nadapi.NetworkSelectionElement{
					MacRequest: "ivalid",
				},
				ipAllocator: &allocatorStub{
					netxtIPs: ovntest.MustParseIPNets("192.168.0.3/24"),
				},
			},
			invalidNetworkAnnotation: true,
			wantErr:                  true,
			wantReleasedIPs:          ovntest.MustParseIPNets("192.168.0.3/24"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			g := gomega.NewWithT(t)

			network := tt.args.network
			if network == nil {
				network = &nadapi.NetworkSelectionElement{}
			}
			network.Name = "network"
			network.Namespace = "namespace"

			var netInfo util.NetInfo
			netInfo = &util.DefaultNetInfo{}
			nadName := types.DefaultNetworkName
			if !tt.ipam {
				nadName = util.GetNADName(network.Namespace, network.Name)
				netInfo, err = util.NewNetInfo(&ovncnitypes.NetConf{
					Topology: types.LocalnetTopology,
					NetConf: cnitypes.NetConf{
						Name: network.Name,
					},
					NADName: nadName,
				})
				if err != nil {
					t.Fatalf("failed to create NetInfo: %v", err)
				}
			}

			pod := &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod",
					Namespace: "namespace",
				},
			}
			if tt.podAnnotation != nil {
				pod.Annotations, err = util.MarshalPodAnnotation(nil, tt.podAnnotation, nadName)
				if err != nil {
					t.Fatalf("failed to set pod annotations: %v", err)
				}
			}

			if tt.invalidNetworkAnnotation {
				pod.ObjectMeta.Annotations = map[string]string{
					nadapi.NetworkAttachmentAnnot: "",
				}
			}

			pod, podAnnotation, rollback, err := allocatePodAnnotationWithRollback(
				tt.args.ipAllocator,
				netInfo,
				pod,
				network,
				tt.args.reallocate,
			)

			if tt.args.ipAllocator != nil {
				releasedIPs := tt.args.ipAllocator.(*allocatorStub).releasedIPs
				g.Expect(releasedIPs).To(gomega.Equal(tt.wantReleasedIPs), "Release on error behaved unexpectedly")
				tt.args.ipAllocator.(*allocatorStub).releasedIPs = nil

				rollback()
				releasedIPs = tt.args.ipAllocator.(*allocatorStub).releasedIPs
				g.Expect(releasedIPs).To(gomega.Equal(tt.wantReleasedIPsOnRollback), "Release on rollback behaved unexpectedly")
			}

			if tt.wantErr {
				// check the expected error after we have checked above that the
				// rollback has behaved as expected
				g.Expect(err).To(gomega.HaveOccurred(), "Expected error")
				return
			}
			g.Expect(err).NotTo(gomega.HaveOccurred(), "Did not expect error")

			if tt.wantGeneratedMac {
				g.Expect(podAnnotation).NotTo(gomega.BeNil(), "Expected updated pod annotation")
				g.Expect(podAnnotation.IPs).To(gomega.BeNil(), "Did not expect IPs")
				g.Expect(podAnnotation.MAC[0]&2).To(gomega.BeEquivalentTo(2), "Expected local MAC")
				return
			}

			g.Expect(podAnnotation).To(gomega.Equal(tt.wantPodAnnotation))

			if tt.wantUpdatedPod {
				g.Expect(pod).NotTo(gomega.BeNil(), "Expected an updated pod")
			}
		})
	}
}
