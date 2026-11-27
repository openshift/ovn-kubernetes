// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package cnooverrides

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func overridesConfigMap(value string) *corev1.ConfigMap {
	data := map[string]string{}
	if value != "\x00absent" {
		data[disableUDNARPNDPFloodOverride] = value
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: OvnConfigOverridesNamespace,
			Name:      OvnConfigOverridesConfigMap,
		},
		Data: data,
	}
}

// The value must parse the way CNO does (validateConfigOverrideBool): the
// trimmed value must parse as a boolean true; a missing, blank or invalid
// value leaves the feature off.
func TestIsUDNARPNDPFloodDisabled(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "override true", value: "true", want: true},
		{name: "override padded True", value: " True ", want: true},
		{name: "override 1", value: "1", want: true},
		{name: "override false", value: "false"},
		{name: "override empty", value: ""},
		{name: "override invalid", value: "yes"},
		{name: "key missing", value: "\x00absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset([]runtime.Object{overridesConfigMap(tc.value)}...)
			got, err := IsUDNARPNDPFloodDisabled(client)
			if err != nil {
				t.Fatalf("IsUDNARPNDPFloodDisabled() error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("IsUDNARPNDPFloodDisabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A cluster without the override ConfigMap (every deployment that does not
// disable UDN ARP/NDP flood) must report false, not an error.
func TestIsUDNARPNDPFloodDisabledWithoutConfigMap(t *testing.T) {
	client := fake.NewSimpleClientset()
	got, err := IsUDNARPNDPFloodDisabled(client)
	if err != nil {
		t.Fatalf("IsUDNARPNDPFloodDisabled() error: %v", err)
	}
	if got {
		t.Fatal("IsUDNARPNDPFloodDisabled() = true, want false when the ConfigMap is absent")
	}
}
