package deploymentconfig

import (
	"fmt"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestPreconfiguredUDNAddresses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    map[string]string
		want    bool
		wantErr bool
	}{
		{
			name: "enabled in rendered config with unrelated sections",
			data: map[string]string{"ovnkube.conf": "[default]\nmtu=1400\n[ovnkubernetesfeature]\nenable-network-segmentation=true\nenable-preconfigured-udn-addresses=true\n[gateway]\nmode=shared\n"},
			want: true,
		},
		{
			name: "disabled",
			data: map[string]string{"ovnkube.conf": "[ovnkubernetesfeature]\nenable-preconfigured-udn-addresses=false\n"},
		},
		{
			name: "absent flag",
			data: map[string]string{"ovnkube.conf": "[ovnkubernetesfeature]\nenable-network-segmentation=true\n"},
		},
		{
			name: "comment is not an enabled flag",
			data: map[string]string{"ovnkube.conf": "[ovnkubernetesfeature]\n# enable-preconfigured-udn-addresses=true\n"},
		},
		{
			name:    "invalid boolean",
			data:    map[string]string{"ovnkube.conf": "[ovnkubernetesfeature]\nenable-preconfigured-udn-addresses=not-a-bool\n"},
			wantErr: true,
		},
		{name: "missing config key", data: map[string]string{}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &openshift{configClient: fake.NewSimpleClientset(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "ovnkube-config", Namespace: "openshift-ovn-kubernetes"},
				Data:       tc.data,
			})}
			got, err := provider.preconfiguredUDNAddressesEnabled()
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got %v, %v; want enabled=%v, error=%v", got, err, tc.want, tc.wantErr)
			}
			if !tc.wantErr && provider.IsConfigurationEnabled(api.PreconfiguredUDNAddressesConfig) != tc.want {
				t.Fatal("configuration query did not use the rendered feature setting")
			}
		})
	}
}

func TestPreconfiguredUDNAddressesReadFailure(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("API unavailable")
	})
	provider := &openshift{configClient: client}
	if _, err := provider.preconfiguredUDNAddressesEnabled(); err == nil {
		t.Fatal("API failures must not be treated as a disabled feature")
	}
}
