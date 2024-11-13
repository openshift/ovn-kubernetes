/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:path=udnnodes,scope=Cluster
// +kubebuilder::singular=udnnode
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=".status.status"
// +kubebuilder:subresource:status
// UDNNode holds node specific information per network
type UDNNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UDNNodeSpec   `json:"spec,omitempty"`
	Status UDNNodeStatus `json:"status,omitempty"`
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// UDNNodeSpec defines the desired state of UDNNode
type UDNNodeSpec struct {
	// NodeSubnets are used for the pod network across the cluster.
	//
	// Dual-stack clusters may set 2 subnets (one for each IP family), otherwise only 1 subnet is allowed.
	// Given subnet is split into smaller subnets for every node.
	//
	// +optional
	NodeSubnets DualStackCIDRs `json:"nodeSubnets,omitempty"`

	// JoinSubnets are used inside the OVN network topology.
	//
	// Dual-stack clusters may set 2 subnets (one for each IP family), otherwise only 1 subnet is allowed.
	// This field is only allowed for "Primary" network.
	// It is not recommended to set this field without explicit need and understanding of the OVN network topology.
	// When omitted, the platform will choose a reasonable default which is subject to change over time.
	//
	// +optional
	JoinSubnets DualStackCIDRs `json:"joinSubnets,omitempty"`
}

// UDNNodeStatus defines the observed state of UDNNode
type UDNNodeStatus struct {
	// A concise indication of whether the EgressQoS resource is applied with success.
	// +optional
	Status string `json:"status,omitempty"`

	// An array of condition objects indicating details about status of EgressQoS object.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// + ---
// + TODO: Add the following validations when available (kube v1.31).
// + kubebuilder:validation:XValidation:rule="isCIDR(self)", message="CIDR is invalid"
type CIDR string

// +kubebuilder:validation:MinItems=1
// +kubebuilder:validation:MaxItems=2
// + ---
// + TODO: Add the following validations when available (kube v1.31).
// + kubebuilder:validation:XValidation:rule="size(self) != 2 || isCIDR(self[0]) && isCIDR(self[1]) && cidr(self[0]).ip().family() != cidr(self[1]).ip().family()", message="When 2 CIDRs are set, they must be from different IP families"
type DualStackCIDRs []CIDR
