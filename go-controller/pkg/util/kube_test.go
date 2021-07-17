package util

import (
	"fmt"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Go Daddy Class 2 CA
const validCACert string = `-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIBADANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEh
MB8GA1UEChMYVGhlIEdvIERhZGR5IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBE
YWRkeSBDbGFzcyAyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA0MDYyOTE3
MDYyMFoXDTM0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRo
ZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3Mg
MiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN
ADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XCA
PVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux6w
wdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLOtXi
EqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWoriMY
avx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZEewo+
YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjgcAwgb0wHQYDVR0OBBYEFNLE
sNKR1EwRcbNhyz2h/t2oatTjMIGNBgNVHSMEgYUwgYKAFNLEsNKR1EwRcbNhyz2h
/t2oatTjoWekZTBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYVGhlIEdvIERhZGR5
IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
ggEBADJL87LKPpH8EsahB4yOd6AzBhRckB4Y9wimPQoZ+YeAEW5p5JYXMP80kWNy
OO7MHAGjHZQopDH2esRU1/blMVgDoszOYtuURXO1v0XJJLXVggKtI3lpjbi2Tc7P
TMozI+gciKqdi0FuFskg5YmezTvacPd+mSYgFFQlq25zheabIZ0KbIIOqPjCDPoQ
HmyW74cNxA9hi63ugyuV+I6ShHI56yDqg+2DzZduCLzrTia2cyvk0/ZM/iZx4mER
dEr/VxqHD3VILs9RaRegAhJhldXRQLIQTO7ErBBDpqWeCtWVYpoNz4iCxTIM5Cuf
ReYNnyicsbkqWletNw+vHX/bvZ8=
-----END CERTIFICATE-----`

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
			desc: "error: CAData invalid for https config",
			inpConfig: config.KubernetesConfig{
				CAData:    []byte("testCert"),
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
				CAData:    []byte(validCACert),
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
