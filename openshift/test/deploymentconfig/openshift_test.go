// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package deploymentconfig

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	primaryIfAddrAnnotation = "k8s.ovn.org/node-primary-ifaddr"
	hybridOverlaySubnetAnno = "k8s.ovn.org/hybrid-overlay-node-subnet"
	cloudEgressIPConfigV4   = `[{"ifaddr":{"ipv4":"10.0.0.0/18"}}]`
)

func node(name string, labels, annotations map[string]string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      labels,
			Annotations: annotations,
		},
	}
}

func osLabels(os string) map[string]string {
	return map[string]string{corev1.LabelOSStable: os}
}

// TestNodeMachineNetworks covers machine network discovery, which runs during
// Ginkgo tree construction. Windows nodes have no node-primary-ifaddr, so their
// subnet comes from the cloud egress IP config annotation instead.
func TestNodeMachineNetworks(t *testing.T) {
	tests := []struct {
		name    string
		nodes   []corev1.Node
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "windows node uses the cloud egress-ipconfig subnet",
			nodes: []corev1.Node{
				node("windows-1", osLabels("windows"), map[string]string{
					cloudEgressIPConfigAnnotation: cloudEgressIPConfigV4,
					hybridOverlaySubnetAnno:       "10.132.2.0/24",
				}),
			},
			want: map[string][]string{"windows-1": {"10.0.0.0/18"}},
		},
		{
			name: "linux node prefers the cloud egress-ipconfig subnet",
			nodes: []corev1.Node{
				node("linux-cloud", osLabels("linux"), map[string]string{
					cloudEgressIPConfigAnnotation: cloudEgressIPConfigV4,
					primaryIfAddrAnnotation:       `{"ipv4":"10.0.25.79/18"}`,
				}),
			},
			want: map[string][]string{"linux-cloud": {"10.0.0.0/18"}},
		},
		{
			name: "linux node without the cloud annotation falls back to node-primary-ifaddr",
			nodes: []corev1.Node{
				node("linux-baremetal", osLabels("linux"), map[string]string{
					primaryIfAddrAnnotation: `{"ipv4":"192.168.1.10/24"}`,
				}),
			},
			want: map[string][]string{"linux-baremetal": {"192.168.1.0/24"}},
		},
		{
			name: "dual stack cloud node returns both families",
			nodes: []corev1.Node{
				node("dual", osLabels("linux"), map[string]string{
					cloudEgressIPConfigAnnotation: `[{"ifaddr":{"ipv4":"10.0.0.0/18","ipv6":"fd00::/64"}}]`,
				}),
			},
			want: map[string][]string{"dual": {"10.0.0.0/18", "fd00::/64"}},
		},
		{
			name: "node missing both annotations is an error",
			nodes: []corev1.Node{
				node("bare", osLabels("linux"), nil),
			},
			wantErr: true,
		},
		{
			name: "malformed cloud annotation with no fallback is an error",
			nodes: []corev1.Node{
				node("bad-cloud", osLabels("linux"), map[string]string{
					cloudEgressIPConfigAnnotation: `[{"ifaddr":{"ipv4":"not-a-cidr"}}]`,
				}),
			},
			wantErr: true,
		},
		{
			name: "malformed node-primary-ifaddr is an error",
			nodes: []corev1.Node{
				node("bad-ifaddr", osLabels("linux"), map[string]string{
					primaryIfAddrAnnotation: `{"ipv4":"not-a-cidr"}`,
				}),
			},
			wantErr: true,
		},
		{
			name: "mixed cluster includes both windows and linux nodes",
			nodes: []corev1.Node{
				node("linux-1", osLabels("linux"), map[string]string{
					cloudEgressIPConfigAnnotation: cloudEgressIPConfigV4,
					primaryIfAddrAnnotation:       `{"ipv4":"10.0.25.79/18"}`,
				}),
				node("windows-1", osLabels("windows"), map[string]string{
					cloudEgressIPConfigAnnotation: cloudEgressIPConfigV4,
					hybridOverlaySubnetAnno:       "10.132.2.0/24",
				}),
			},
			want: map[string][]string{
				"linux-1":   {"10.0.0.0/18"},
				"windows-1": {"10.0.0.0/18"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeMachineNetworks(tt.nodes)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got result %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCloudEgressIPConfigSubnets checks the annotation parser directly. Unlike
// util.ParseCloudEgressIPConfig it must not require node-primary-ifaddr.
func TestCloudEgressIPConfigSubnets(t *testing.T) {
	tests := []struct {
		name    string
		node    corev1.Node
		want    []string
		wantErr bool
	}{
		{
			name: "parses without node-primary-ifaddr",
			node: node("windows-1", nil, map[string]string{cloudEgressIPConfigAnnotation: cloudEgressIPConfigV4}),
			want: []string{"10.0.0.0/18"},
		},
		{
			name: "reads only the first entry",
			node: node("multi", nil, map[string]string{
				cloudEgressIPConfigAnnotation: `[{"ifaddr":{"ipv4":"10.0.0.0/18"}},{"ifaddr":{"ipv4":"10.1.0.0/18"}}]`,
			}),
			want: []string{"10.0.0.0/18"},
		},
		{
			name:    "annotation absent",
			node:    node("none", nil, nil),
			wantErr: true,
		},
		{
			name:    "annotation is not valid json",
			node:    node("bad-json", nil, map[string]string{cloudEgressIPConfigAnnotation: `not json`}),
			wantErr: true,
		},
		{
			name:    "annotation is an empty list",
			node:    node("empty-list", nil, map[string]string{cloudEgressIPConfigAnnotation: `[]`}),
			wantErr: true,
		},
		{
			name:    "entry carries no addresses",
			node:    node("no-addr", nil, map[string]string{cloudEgressIPConfigAnnotation: `[{"ifaddr":{}}]`}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cloudEgressIPConfigSubnets(&tt.node)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got result %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
