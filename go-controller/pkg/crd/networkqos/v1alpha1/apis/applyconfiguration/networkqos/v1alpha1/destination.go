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

package v1alpha1

import (
	networkingv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// DestinationApplyConfiguration represents a declarative configuration of the Destination type for use
// with apply.
type DestinationApplyConfiguration struct {
	PodSelector       *v1.LabelSelectorApplyConfiguration `json:"podSelector,omitempty"`
	NamespaceSelector *v1.LabelSelectorApplyConfiguration `json:"namespaceSelector,omitempty"`
	IPBlock           *networkingv1.IPBlock               `json:"ipBlock,omitempty"`
}

// DestinationApplyConfiguration constructs a declarative configuration of the Destination type for use with
// apply.
func Destination() *DestinationApplyConfiguration {
	return &DestinationApplyConfiguration{}
}

// WithPodSelector sets the PodSelector field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PodSelector field is set to the value of the last call.
func (b *DestinationApplyConfiguration) WithPodSelector(value *v1.LabelSelectorApplyConfiguration) *DestinationApplyConfiguration {
	b.PodSelector = value
	return b
}

// WithNamespaceSelector sets the NamespaceSelector field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NamespaceSelector field is set to the value of the last call.
func (b *DestinationApplyConfiguration) WithNamespaceSelector(value *v1.LabelSelectorApplyConfiguration) *DestinationApplyConfiguration {
	b.NamespaceSelector = value
	return b
}

// WithIPBlock sets the IPBlock field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the IPBlock field is set to the value of the last call.
func (b *DestinationApplyConfiguration) WithIPBlock(value networkingv1.IPBlock) *DestinationApplyConfiguration {
	b.IPBlock = &value
	return b
}
