// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	apinetworkv1 "github.com/openshift/api/network/v1"
	internal "github.com/openshift/client-go/network/applyconfigurations/internal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	managedfields "k8s.io/apimachinery/pkg/util/managedfields"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// EgressNetworkPolicyApplyConfiguration represents an declarative configuration of the EgressNetworkPolicy type for use
// with apply.
type EgressNetworkPolicyApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Spec                             *EgressNetworkPolicySpecApplyConfiguration `json:"spec,omitempty"`
}

// EgressNetworkPolicy constructs an declarative configuration of the EgressNetworkPolicy type for use with
// apply.
func EgressNetworkPolicy(name, namespace string) *EgressNetworkPolicyApplyConfiguration {
	b := &EgressNetworkPolicyApplyConfiguration{}
	b.WithName(name)
	b.WithNamespace(namespace)
	b.WithKind("EgressNetworkPolicy")
	b.WithAPIVersion("network.openshift.io/v1")
	return b
}

// ExtractEgressNetworkPolicy extracts the applied configuration owned by fieldManager from
// egressNetworkPolicy. If no managedFields are found in egressNetworkPolicy for fieldManager, a
// EgressNetworkPolicyApplyConfiguration is returned with only the Name, Namespace (if applicable),
// APIVersion and Kind populated. It is possible that no managed fields were found for because other
// field managers have taken ownership of all the fields previously owned by fieldManager, or because
// the fieldManager never owned fields any fields.
// egressNetworkPolicy must be a unmodified EgressNetworkPolicy API object that was retrieved from the Kubernetes API.
// ExtractEgressNetworkPolicy provides a way to perform a extract/modify-in-place/apply workflow.
// Note that an extracted apply configuration will contain fewer fields than what the fieldManager previously
// applied if another fieldManager has updated or force applied any of the previously applied fields.
// Experimental!
func ExtractEgressNetworkPolicy(egressNetworkPolicy *apinetworkv1.EgressNetworkPolicy, fieldManager string) (*EgressNetworkPolicyApplyConfiguration, error) {
	return extractEgressNetworkPolicy(egressNetworkPolicy, fieldManager, "")
}

// ExtractEgressNetworkPolicyStatus is the same as ExtractEgressNetworkPolicy except
// that it extracts the status subresource applied configuration.
// Experimental!
func ExtractEgressNetworkPolicyStatus(egressNetworkPolicy *apinetworkv1.EgressNetworkPolicy, fieldManager string) (*EgressNetworkPolicyApplyConfiguration, error) {
	return extractEgressNetworkPolicy(egressNetworkPolicy, fieldManager, "status")
}

func extractEgressNetworkPolicy(egressNetworkPolicy *apinetworkv1.EgressNetworkPolicy, fieldManager string, subresource string) (*EgressNetworkPolicyApplyConfiguration, error) {
	b := &EgressNetworkPolicyApplyConfiguration{}
	err := managedfields.ExtractInto(egressNetworkPolicy, internal.Parser().Type("com.github.openshift.api.network.v1.EgressNetworkPolicy"), fieldManager, b, subresource)
	if err != nil {
		return nil, err
	}
	b.WithName(egressNetworkPolicy.Name)
	b.WithNamespace(egressNetworkPolicy.Namespace)

	b.WithKind("EgressNetworkPolicy")
	b.WithAPIVersion("network.openshift.io/v1")
	return b, nil
}

// WithKind sets the Kind field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Kind field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithKind(value string) *EgressNetworkPolicyApplyConfiguration {
	b.Kind = &value
	return b
}

// WithAPIVersion sets the APIVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the APIVersion field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithAPIVersion(value string) *EgressNetworkPolicyApplyConfiguration {
	b.APIVersion = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithName(value string) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Name = &value
	return b
}

// WithGenerateName sets the GenerateName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the GenerateName field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithGenerateName(value string) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.GenerateName = &value
	return b
}

// WithNamespace sets the Namespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Namespace field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithNamespace(value string) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Namespace = &value
	return b
}

// WithUID sets the UID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the UID field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithUID(value types.UID) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.UID = &value
	return b
}

// WithResourceVersion sets the ResourceVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ResourceVersion field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithResourceVersion(value string) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.ResourceVersion = &value
	return b
}

// WithGeneration sets the Generation field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Generation field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithGeneration(value int64) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Generation = &value
	return b
}

// WithCreationTimestamp sets the CreationTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CreationTimestamp field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithCreationTimestamp(value metav1.Time) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.CreationTimestamp = &value
	return b
}

// WithDeletionTimestamp sets the DeletionTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionTimestamp field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithDeletionTimestamp(value metav1.Time) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionTimestamp = &value
	return b
}

// WithDeletionGracePeriodSeconds sets the DeletionGracePeriodSeconds field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionGracePeriodSeconds field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithDeletionGracePeriodSeconds(value int64) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionGracePeriodSeconds = &value
	return b
}

// WithLabels puts the entries into the Labels field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Labels field,
// overwriting an existing map entries in Labels field with the same key.
func (b *EgressNetworkPolicyApplyConfiguration) WithLabels(entries map[string]string) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Labels == nil && len(entries) > 0 {
		b.Labels = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Labels[k] = v
	}
	return b
}

// WithAnnotations puts the entries into the Annotations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Annotations field,
// overwriting an existing map entries in Annotations field with the same key.
func (b *EgressNetworkPolicyApplyConfiguration) WithAnnotations(entries map[string]string) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Annotations == nil && len(entries) > 0 {
		b.Annotations = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Annotations[k] = v
	}
	return b
}

// WithOwnerReferences adds the given value to the OwnerReferences field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the OwnerReferences field.
func (b *EgressNetworkPolicyApplyConfiguration) WithOwnerReferences(values ...*v1.OwnerReferenceApplyConfiguration) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithOwnerReferences")
		}
		b.OwnerReferences = append(b.OwnerReferences, *values[i])
	}
	return b
}

// WithFinalizers adds the given value to the Finalizers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Finalizers field.
func (b *EgressNetworkPolicyApplyConfiguration) WithFinalizers(values ...string) *EgressNetworkPolicyApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		b.Finalizers = append(b.Finalizers, values[i])
	}
	return b
}

func (b *EgressNetworkPolicyApplyConfiguration) ensureObjectMetaApplyConfigurationExists() {
	if b.ObjectMetaApplyConfiguration == nil {
		b.ObjectMetaApplyConfiguration = &v1.ObjectMetaApplyConfiguration{}
	}
}

// WithSpec sets the Spec field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Spec field is set to the value of the last call.
func (b *EgressNetworkPolicyApplyConfiguration) WithSpec(value *EgressNetworkPolicySpecApplyConfiguration) *EgressNetworkPolicyApplyConfiguration {
	b.Spec = value
	return b
}
