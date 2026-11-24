// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package deploymentconfig

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	"k8s.io/client-go/rest"
)

// TestIsConfigurationEnabledUDNARPNDPFloodDisabled covers the API outcomes
// against a fake apiserver that only serves the overrides ConfigMap.
func TestIsConfigurationEnabledUDNARPNDPFloodDisabled(t *testing.T) {
	configMap := func(data string) string {
		return `{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"` + ovnConfigOverridesConfigMap + `"},"data":{` + data + `}}`
	}
	tests := []struct {
		name      string
		status    int
		body      string
		want      bool
		panicWant []string
	}{
		{name: "configmap not found", status: http.StatusNotFound,
			body: `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`},
		{name: "key absent", status: http.StatusOK, body: configMap(`"openflow-probe":"10"`)},
		// The value is read as CNO does: trimmed, then strconv.ParseBool; only a
		// boolean true turns the feature on.
		{name: "override true", status: http.StatusOK, body: configMap(`"disable-udn-arp-ndp-flood":"true"`), want: true},
		{name: "override padded True", status: http.StatusOK, body: configMap(`"disable-udn-arp-ndp-flood":" True "`), want: true},
		{name: "override 1", status: http.StatusOK, body: configMap(`"disable-udn-arp-ndp-flood":"1"`), want: true},
		{name: "override false", status: http.StatusOK, body: configMap(`"disable-udn-arp-ndp-flood":"false"`)},
		{name: "override 0", status: http.StatusOK, body: configMap(`"disable-udn-arp-ndp-flood":"0"`)},
		{name: "override blank", status: http.StatusOK, body: configMap(`"disable-udn-arp-ndp-flood":"  "`)},
		{name: "override invalid: ignored, as CNO does", status: http.StatusOK, body: configMap(`"disable-udn-arp-ndp-flood":"yes"`)},
		{name: "apiserver error", status: http.StatusInternalServerError,
			body:      `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"boom","code":500}`,
			panicWant: []string{ovnConfigOverridesNamespace, ovnConfigOverridesConfigMap, "boom"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/namespaces/openshift-network-operator/configmaps/ovn-kubernetes-config-overrides" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			var got bool
			var panicked any
			dc, err := New(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer func() { panicked = recover() }()
				got = dc.IsConfigurationEnabled(api.UDNARPNDPFloodDisabled)
			}()
			if len(tt.panicWant) > 0 {
				for _, want := range tt.panicWant {
					if !strings.Contains(fmt.Sprint(panicked), want) {
						t.Fatalf("panic %v does not mention %q", panicked, want)
					}
				}
				return
			}
			if panicked != nil || got != tt.want {
				t.Fatalf("got (%v, panic %v), want %v", got, panicked, tt.want)
			}
		})
	}
}

func TestIsConfigurationEnabledWithoutCluster(t *testing.T) {
	// `list tests` builds the tree without a cluster.
	dc, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if dc.IsConfigurationEnabled(api.UDNARPNDPFloodDisabled) {
		t.Fatal("UDNARPNDPFloodDisabled reported enabled without a cluster")
	}
}
