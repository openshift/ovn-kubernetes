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
	cloudEgressIPAnnotation = "cloud.network.openshift.io/egress-ipconfig"
	hybridOverlaySubnetAnno = "k8s.ovn.org/hybrid-overlay-node-subnet"
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

func linuxLabels() map[string]string {
	return map[string]string{corev1.LabelOSStable: "linux"}
}

func windowsLabels() map[string]string {
	return map[string]string{corev1.LabelOSStable: "windows"}
}

// TestNodeMachineNetworks covers the node predicate used when computing machine
// network exclusions during Ginkgo tree construction (OCPBUGS-133493): unmanaged
// nodes are skipped, managed nodes still fail loudly on bad annotations.
func TestNodeMachineNetworks(t *testing.T) {
	tests := []struct {
		name    string
		nodes   []corev1.Node
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "linux node with valid node-primary-ifaddr is included",
			nodes: []corev1.Node{
				node("linux-1", linuxLabels(), map[string]string{
					primaryIfAddrAnnotation: `{"ipv4":"192.168.1.10/24"}`,
				}),
			},
			want: map[string][]string{"linux-1": {"192.168.1.0/24"}},
		},
		{
			name: "linux node with cloud egress-ipconfig uses the cloud subnet",
			nodes: []corev1.Node{
				// ParseCloudEgressIPConfig also reads node-primary-ifaddr to
				// populate V4.IP, so a cloud node carries both annotations.
				node("linux-cloud", linuxLabels(), map[string]string{
					cloudEgressIPAnnotation: `[{"interface":"eni-abc","ifaddr":{"ipv4":"10.0.128.0/18"},"capacity":{"ipv4":14}}]`,
					primaryIfAddrAnnotation: `{"ipv4":"10.0.130.5/18"}`,
				}),
			},
			want: map[string][]string{"linux-cloud": {"10.0.128.0/18"}},
		},
		{
			name: "linux node missing both annotations is an error",
			nodes: []corev1.Node{
				node("linux-bare", linuxLabels(), nil),
			},
			wantErr: true,
		},
		{
			name: "linux node with malformed annotation is an error",
			nodes: []corev1.Node{
				node("linux-bad", linuxLabels(), map[string]string{
					primaryIfAddrAnnotation: `{"ipv4":"not-a-cidr"}`,
				}),
			},
			wantErr: true,
		},
		{
			name: "windows node without annotations is skipped",
			nodes: []corev1.Node{
				node("windows-1", windowsLabels(), nil),
			},
			want: map[string][]string{},
		},
		{
			name: "windows hybrid-overlay node without primary ifaddr is skipped",
			nodes: []corev1.Node{
				node("windows-hybrid", windowsLabels(), map[string]string{
					hybridOverlaySubnetAnno: "10.132.2.0/24",
				}),
			},
			want: map[string][]string{},
		},
		{
			name: "mixed cluster keeps linux nodes and drops windows nodes",
			nodes: []corev1.Node{
				node("linux-1", linuxLabels(), map[string]string{
					primaryIfAddrAnnotation: `{"ipv4":"192.168.1.10/24"}`,
				}),
				node("windows-1", windowsLabels(), map[string]string{
					hybridOverlaySubnetAnno: "10.132.2.0/24",
				}),
			},
			want: map[string][]string{"linux-1": {"192.168.1.0/24"}},
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

func TestIsOVNManagedNode(t *testing.T) {
	tests := []struct {
		name string
		node corev1.Node
		want bool
	}{
		{
			name: "linux node is managed",
			node: node("linux-1", linuxLabels(), nil),
			want: true,
		},
		{
			name: "windows node is not managed",
			node: node("windows-1", windowsLabels(), nil),
			want: false,
		},
		{
			name: "node without an os label is treated as managed",
			node: node("unlabelled", nil, nil),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOVNManagedNode(&tt.node); got != tt.want {
				t.Errorf("isOVNManagedNode() = %v, want %v", got, tt.want)
			}
		})
	}
}
