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
// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressservice/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// EgressServiceLister helps list EgressServices.
// All objects returned here must be treated as read-only.
type EgressServiceLister interface {
	// List lists all EgressServices in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.EgressService, err error)
	// EgressServices returns an object that can list and get EgressServices.
	EgressServices(namespace string) EgressServiceNamespaceLister
	EgressServiceListerExpansion
}

// egressServiceLister implements the EgressServiceLister interface.
type egressServiceLister struct {
	listers.ResourceIndexer[*v1.EgressService]
}

// NewEgressServiceLister returns a new EgressServiceLister.
func NewEgressServiceLister(indexer cache.Indexer) EgressServiceLister {
	return &egressServiceLister{listers.New[*v1.EgressService](indexer, v1.Resource("egressservice"))}
}

// EgressServices returns an object that can list and get EgressServices.
func (s *egressServiceLister) EgressServices(namespace string) EgressServiceNamespaceLister {
	return egressServiceNamespaceLister{listers.NewNamespaced[*v1.EgressService](s.ResourceIndexer, namespace)}
}

// EgressServiceNamespaceLister helps list and get EgressServices.
// All objects returned here must be treated as read-only.
type EgressServiceNamespaceLister interface {
	// List lists all EgressServices in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.EgressService, err error)
	// Get retrieves the EgressService from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.EgressService, error)
	EgressServiceNamespaceListerExpansion
}

// egressServiceNamespaceLister implements the EgressServiceNamespaceLister
// interface.
type egressServiceNamespaceLister struct {
	listers.ResourceIndexer[*v1.EgressService]
}
