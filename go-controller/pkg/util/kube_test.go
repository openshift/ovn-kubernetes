package util

import (
	"context"
	"fmt"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientsetfake "k8s.io/client-go/kubernetes/fake"
)

func TestNewClientset(t *testing.T) {
	tests := []struct {
		desc        string
		inpConfig   config.KubernetesConfig
		errExpected bool
	}{
		{
			desc: "error: cover code path --> config.KubernetesConfig.Kubeconfig != ``",
			inpConfig: config.KubernetesConfig{
				Kubeconfig: "blah",
			},
			errExpected: true,
		},
		{
			desc: "error: missing token for https",
			inpConfig: config.KubernetesConfig{
				APIServer: "https",
			},
			errExpected: true,
		},
		{
			desc: "error: CACert invalid for https config",
			inpConfig: config.KubernetesConfig{
				CACert:    "testCert",
				APIServer: "https",
				Token:     "testToken",
			},
			errExpected: true,
		},
		{
			desc: "success: config input valid https",
			inpConfig: config.KubernetesConfig{
				APIServer: "https",
				Token:     "testToken",
			},
		},
		{
			desc: "success: cover code path --> config.APIServer == http",
			inpConfig: config.KubernetesConfig{
				APIServer: "http",
			},
		},
		{
			desc:        "error: cover code path that assumes client running inside container environment",
			inpConfig:   config.KubernetesConfig{},
			errExpected: true,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, e := NewOVNClientset(&tc.inpConfig)
			t.Log(res, e)
			if tc.errExpected {
				assert.Error(t, e)
			} else {
				assert.NotNil(t, res)
			}
		})
	}
}

func TestIsClusterIPSet(t *testing.T) {
	tests := []struct {
		desc   string
		inp    v1.Service
		expOut bool
	}{
		{
			desc: "false: test when ClusterIP set to ClusterIPNone",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					ClusterIP: v1.ClusterIPNone,
				},
			},
			expOut: false,
		},
		{
			desc: "false: test when ClusterIP set to empty string",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					ClusterIP: "",
				},
			},
			expOut: false,
		},
		{
			desc: "true: test when ClusterIP set to NON-empty string",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					ClusterIP: "blah",
				},
			},
			expOut: true,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := IsClusterIPSet(&tc.inp)
			assert.Equal(t, res, tc.expOut)
		})
	}
}

func TestValidateProtocol(t *testing.T) {
	tests := []struct {
		desc   string
		inp    v1.Protocol
		expOut v1.Protocol
		expErr bool
	}{
		{
			desc: "valid protocol SCTP",
			inp:  v1.ProtocolSCTP,
		},
		{
			desc:   "invalid protocol -> blah",
			inp:    "blah",
			expErr: true,
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			e := ValidateProtocol(tc.inp)
			if tc.expErr {
				assert.Error(t, e)
			} else {
				assert.NoError(t, e)
			}
		})
	}
}

func TestServiceTypeHasClusterIP(t *testing.T) {
	tests := []struct {
		desc   string
		inp    v1.Service
		expOut bool
	}{
		{
			desc: "true: test when Type set to `ClusterIP`",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					Type: "ClusterIP",
				},
			},
			expOut: true,
		},
		{
			desc: "true: test when Type set to `NodePort`",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					Type: "NodePort",
				},
			},
			expOut: true,
		},
		{
			desc: "true: test when Type set to `LoadBalancer`",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					Type: "LoadBalancer",
				},
			},
			expOut: true,
		},
		{
			desc: "false: test when Type set to `loadbalancer`",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					Type: "loadbalancer",
				},
			},
			expOut: false,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := ServiceTypeHasClusterIP(&tc.inp)
			assert.Equal(t, res, tc.expOut)
		})
	}
}

func TestServiceTypeHasNodePort(t *testing.T) {
	tests := []struct {
		desc   string
		inp    v1.Service
		expOut bool
	}{
		{
			desc: "true: test when Type set to `ClusterIP`",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					Type: "ClusterIP",
				},
			},
			expOut: false,
		},
		{
			desc: "true: test when Type set to `NodePort`",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					Type: "NodePort",
				},
			},
			expOut: true,
		},
		{
			desc: "true: test when Type set to `LoadBalancer`",
			inp: v1.Service{
				Spec: v1.ServiceSpec{
					Type: "LoadBalancer",
				},
			},
			expOut: true,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := ServiceTypeHasNodePort(&tc.inp)
			assert.Equal(t, res, tc.expOut)
		})
	}
}

func TestGetNodePrimaryIP(t *testing.T) {
	tests := []struct {
		desc   string
		inp    v1.Node
		expErr bool
		expOut string
	}{
		{
			desc: "error: node has neither external nor internal IP",
			inp: v1.Node{
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{Type: v1.NodeHostName, Address: "HN"},
					},
				},
			},
			expErr: true,
			expOut: "HN",
		},
		{
			desc: "success: node's internal IP returned",
			inp: v1.Node{
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{Type: v1.NodeHostName, Address: "HN"},
						{Type: v1.NodeInternalIP, Address: "IntIP"},
						{Type: v1.NodeExternalIP, Address: "ExtIP"},
					},
				},
			},
			expOut: "IntIP",
		},
		{
			desc: "success: node's external IP returned",
			inp: v1.Node{
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{Type: v1.NodeHostName, Address: "HN"},
						{Type: v1.NodeExternalIP, Address: "ExtIP"},
					},
				},
			},
			expOut: "ExtIP",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, e := GetNodePrimaryIP(&tc.inp)
			t.Log(res, e)
			if tc.expErr {
				assert.Error(t, e)
			} else {
				assert.Equal(t, res, tc.expOut)
			}
		})
	}
}

func TestGetPodNetSelAnnotation(t *testing.T) {
	tests := []struct {
		desc             string
		inpPod           v1.Pod
		inpNetAnnotation string
		expErr           bool
		expOutput        []*types.NetworkSelectionElement
	}{
		{
			desc:             "empty annotation string input",
			inpPod:           v1.Pod{},
			inpNetAnnotation: "",
		},
		{
			desc: "json unmarshal error",
			inpPod: v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:fd:98:00:01","ip_address":"192.168.0.5/24"}}`},
				},
			},
			inpNetAnnotation: "k8s.ovn.org/pod-networks",
			expErr:           true,
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, e := GetPodNetSelAnnotation(&tc.inpPod, tc.inpNetAnnotation)
			t.Log(res, e)
			if tc.expErr {
				assert.Error(t, e)
			}
			if tc.expOutput != nil {
				assert.Greater(t, len(res), 0)
			}
		})
	}
}

func Test_GetNodePrimaryIP(t *testing.T) {
	cases := []struct {
		name     string
		nodeInfo *v1.Node
		hostname string
		address  string
		wantErr  bool
	}{
		{
			name:     "non existent Node",
			nodeInfo: makeNodeWithAddresses("", "", ""),
			hostname: "nonexist",
			address:  "",
			wantErr:  true,
		},

		{
			name:     "Node with internal and external address",
			nodeInfo: makeNodeWithAddresses("fakeHost", "192.168.1.1", "90.90.90.90"),
			hostname: "fakeHost",
			address:  "192.168.1.1",
		},
		{
			name:     "Node with internal and external address IPV6",
			nodeInfo: makeNodeWithAddresses("fakeHost", "fd00:1234::1", "2001:db8::2"),
			hostname: "fakeHost",
			address:  "fd00:1234::1",
		},
		{
			name:     "Node with only IPv4 ExternalIP set",
			nodeInfo: makeNodeWithAddresses("fakeHost", "", "90.90.90.90"),
			hostname: "fakeHost",
			address:  "90.90.90.90",
		},

		{
			name:     "Node with only IPv6 ExternalIP set",
			nodeInfo: makeNodeWithAddresses("fakeHost", "", "2001:db8::2"),
			hostname: "fakeHost",
			address:  "2001:db8::2",
		},
	}
	for _, c := range cases {
		client := clientsetfake.NewSimpleClientset(c.nodeInfo)
		node, _ := client.CoreV1().Nodes().Get(context.TODO(), c.hostname, metav1.GetOptions{})
		ip, err := GetNodePrimaryIP(node)
		if err != nil != c.wantErr {
			t.Errorf("Case[%s] Expected error %v got %v", c.name, c.wantErr, err)
		}
		if ip != c.address {
			t.Errorf("Case[%s] Expected IP %q got %q", c.name, c.address, ip)
		}
	}
}

// makeNodeWithAddresses return a node object with the specified parameters
func makeNodeWithAddresses(name, internal, external string) *v1.Node {
	if name == "" {
		return &v1.Node{}
	}

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{},
		},
	}

	if internal != "" {
		node.Status.Addresses = append(node.Status.Addresses,
			v1.NodeAddress{Type: v1.NodeInternalIP, Address: internal},
		)
	}

	if external != "" {
		node.Status.Addresses = append(node.Status.Addresses,
			v1.NodeAddress{Type: v1.NodeExternalIP, Address: external},
		)
	}

	return node
}
