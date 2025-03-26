/*


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
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DynamicHopApplyConfiguration represents an declarative configuration of the DynamicHop type for use
// with apply.
type DynamicHopApplyConfiguration struct {
	PodSelector           *v1.LabelSelector `json:"podSelector,omitempty"`
	NamespaceSelector     *v1.LabelSelector `json:"namespaceSelector,omitempty"`
	NetworkAttachmentName *string           `json:"networkAttachmentName,omitempty"`
	BFDEnabled            *bool             `json:"bfdEnabled,omitempty"`
}

// DynamicHopApplyConfiguration constructs an declarative configuration of the DynamicHop type for use with
// apply.
func DynamicHop() *DynamicHopApplyConfiguration {
	return &DynamicHopApplyConfiguration{}
}

// WithPodSelector sets the PodSelector field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PodSelector field is set to the value of the last call.
func (b *DynamicHopApplyConfiguration) WithPodSelector(value v1.LabelSelector) *DynamicHopApplyConfiguration {
	b.PodSelector = &value
	return b
}

// WithNamespaceSelector sets the NamespaceSelector field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NamespaceSelector field is set to the value of the last call.
func (b *DynamicHopApplyConfiguration) WithNamespaceSelector(value v1.LabelSelector) *DynamicHopApplyConfiguration {
	b.NamespaceSelector = &value
	return b
}

// WithNetworkAttachmentName sets the NetworkAttachmentName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NetworkAttachmentName field is set to the value of the last call.
func (b *DynamicHopApplyConfiguration) WithNetworkAttachmentName(value string) *DynamicHopApplyConfiguration {
	b.NetworkAttachmentName = &value
	return b
}

// WithBFDEnabled sets the BFDEnabled field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the BFDEnabled field is set to the value of the last call.
func (b *DynamicHopApplyConfiguration) WithBFDEnabled(value bool) *DynamicHopApplyConfiguration {
	b.BFDEnabled = &value
	return b
}
