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
	v1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// UserDefinedNetworkLister helps list UserDefinedNetworks.
// All objects returned here must be treated as read-only.
type UserDefinedNetworkLister interface {
	// List lists all UserDefinedNetworks in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.UserDefinedNetwork, err error)
	// UserDefinedNetworks returns an object that can list and get UserDefinedNetworks.
	UserDefinedNetworks(namespace string) UserDefinedNetworkNamespaceLister
	UserDefinedNetworkListerExpansion
}

// userDefinedNetworkLister implements the UserDefinedNetworkLister interface.
type userDefinedNetworkLister struct {
	listers.ResourceIndexer[*v1.UserDefinedNetwork]
}

// NewUserDefinedNetworkLister returns a new UserDefinedNetworkLister.
func NewUserDefinedNetworkLister(indexer cache.Indexer) UserDefinedNetworkLister {
	return &userDefinedNetworkLister{listers.New[*v1.UserDefinedNetwork](indexer, v1.Resource("userdefinednetwork"))}
}

// UserDefinedNetworks returns an object that can list and get UserDefinedNetworks.
func (s *userDefinedNetworkLister) UserDefinedNetworks(namespace string) UserDefinedNetworkNamespaceLister {
	return userDefinedNetworkNamespaceLister{listers.NewNamespaced[*v1.UserDefinedNetwork](s.ResourceIndexer, namespace)}
}

// UserDefinedNetworkNamespaceLister helps list and get UserDefinedNetworks.
// All objects returned here must be treated as read-only.
type UserDefinedNetworkNamespaceLister interface {
	// List lists all UserDefinedNetworks in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.UserDefinedNetwork, err error)
	// Get retrieves the UserDefinedNetwork from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.UserDefinedNetwork, error)
	UserDefinedNetworkNamespaceListerExpansion
}

// userDefinedNetworkNamespaceLister implements the UserDefinedNetworkNamespaceLister
// interface.
type userDefinedNetworkNamespaceLister struct {
	listers.ResourceIndexer[*v1.UserDefinedNetwork]
}
