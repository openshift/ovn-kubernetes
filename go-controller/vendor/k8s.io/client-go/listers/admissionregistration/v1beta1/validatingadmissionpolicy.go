/*
Copyright The Kubernetes Authors.

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

// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// ValidatingAdmissionPolicyLister helps list ValidatingAdmissionPolicies.
// All objects returned here must be treated as read-only.
type ValidatingAdmissionPolicyLister interface {
	// List lists all ValidatingAdmissionPolicies in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*admissionregistrationv1beta1.ValidatingAdmissionPolicy, err error)
	// Get retrieves the ValidatingAdmissionPolicy from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*admissionregistrationv1beta1.ValidatingAdmissionPolicy, error)
	ValidatingAdmissionPolicyListerExpansion
}

// validatingAdmissionPolicyLister implements the ValidatingAdmissionPolicyLister interface.
type validatingAdmissionPolicyLister struct {
	listers.ResourceIndexer[*admissionregistrationv1beta1.ValidatingAdmissionPolicy]
}

// NewValidatingAdmissionPolicyLister returns a new ValidatingAdmissionPolicyLister.
func NewValidatingAdmissionPolicyLister(indexer cache.Indexer) ValidatingAdmissionPolicyLister {
	return &validatingAdmissionPolicyLister{listers.New[*admissionregistrationv1beta1.ValidatingAdmissionPolicy](indexer, admissionregistrationv1beta1.Resource("validatingadmissionpolicy"))}
}
