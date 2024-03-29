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
	v1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// AdminPolicyBasedExternalRouteLister helps list AdminPolicyBasedExternalRoutes.
// All objects returned here must be treated as read-only.
type AdminPolicyBasedExternalRouteLister interface {
	// List lists all AdminPolicyBasedExternalRoutes in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.AdminPolicyBasedExternalRoute, err error)
	// Get retrieves the AdminPolicyBasedExternalRoute from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.AdminPolicyBasedExternalRoute, error)
	AdminPolicyBasedExternalRouteListerExpansion
}

// adminPolicyBasedExternalRouteLister implements the AdminPolicyBasedExternalRouteLister interface.
type adminPolicyBasedExternalRouteLister struct {
	indexer cache.Indexer
}

// NewAdminPolicyBasedExternalRouteLister returns a new AdminPolicyBasedExternalRouteLister.
func NewAdminPolicyBasedExternalRouteLister(indexer cache.Indexer) AdminPolicyBasedExternalRouteLister {
	return &adminPolicyBasedExternalRouteLister{indexer: indexer}
}

// List lists all AdminPolicyBasedExternalRoutes in the indexer.
func (s *adminPolicyBasedExternalRouteLister) List(selector labels.Selector) (ret []*v1.AdminPolicyBasedExternalRoute, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.AdminPolicyBasedExternalRoute))
	})
	return ret, err
}

// Get retrieves the AdminPolicyBasedExternalRoute from the index for a given name.
func (s *adminPolicyBasedExternalRouteLister) Get(name string) (*v1.AdminPolicyBasedExternalRoute, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("adminpolicybasedexternalroute"), name)
	}
	return obj.(*v1.AdminPolicyBasedExternalRoute), nil
}
