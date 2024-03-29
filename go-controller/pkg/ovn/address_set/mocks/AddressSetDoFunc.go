// Code generated by mockery v2.16.0. DO NOT EDIT.

package mocks

import (
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	mock "github.com/stretchr/testify/mock"
)

// AddressSetDoFunc is an autogenerated mock type for the AddressSetDoFunc type
type AddressSetDoFunc struct {
	mock.Mock
}

// Execute provides a mock function with given fields: as
func (_m *AddressSetDoFunc) Execute(as addressset.AddressSet) error {
	ret := _m.Called(as)

	var r0 error
	if rf, ok := ret.Get(0).(func(addressset.AddressSet) error); ok {
		r0 = rf(as)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewAddressSetDoFunc interface {
	mock.TestingT
	Cleanup(func())
}

// NewAddressSetDoFunc creates a new instance of AddressSetDoFunc. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAddressSetDoFunc(t mockConstructorTestingTNewAddressSetDoFunc) *AddressSetDoFunc {
	mock := &AddressSetDoFunc{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
