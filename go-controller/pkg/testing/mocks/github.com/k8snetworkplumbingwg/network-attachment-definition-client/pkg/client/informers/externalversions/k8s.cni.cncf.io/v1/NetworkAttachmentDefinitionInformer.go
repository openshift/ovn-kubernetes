// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	k8s_cni_cncf_iov1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/listers/k8s.cni.cncf.io/v1"
	mock "github.com/stretchr/testify/mock"
	cache "k8s.io/client-go/tools/cache"
)

// NetworkAttachmentDefinitionInformer is an autogenerated mock type for the NetworkAttachmentDefinitionInformer type
type NetworkAttachmentDefinitionInformer struct {
	mock.Mock
}

// Informer provides a mock function with given fields:
func (_m *NetworkAttachmentDefinitionInformer) Informer() cache.SharedIndexInformer {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Informer")
	}

	var r0 cache.SharedIndexInformer
	if rf, ok := ret.Get(0).(func() cache.SharedIndexInformer); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(cache.SharedIndexInformer)
		}
	}

	return r0
}

// Lister provides a mock function with given fields:
func (_m *NetworkAttachmentDefinitionInformer) Lister() k8s_cni_cncf_iov1.NetworkAttachmentDefinitionLister {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Lister")
	}

	var r0 k8s_cni_cncf_iov1.NetworkAttachmentDefinitionLister
	if rf, ok := ret.Get(0).(func() k8s_cni_cncf_iov1.NetworkAttachmentDefinitionLister); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(k8s_cni_cncf_iov1.NetworkAttachmentDefinitionLister)
		}
	}

	return r0
}

// NewNetworkAttachmentDefinitionInformer creates a new instance of NetworkAttachmentDefinitionInformer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewNetworkAttachmentDefinitionInformer(t interface {
	mock.TestingT
	Cleanup(func())
}) *NetworkAttachmentDefinitionInformer {
	mock := &NetworkAttachmentDefinitionInformer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
