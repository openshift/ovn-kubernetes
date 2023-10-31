// Code generated by mockery v2.14.1. DO NOT EDIT.

package mocks

import (
	net "net"

	mock "github.com/stretchr/testify/mock"
)

// HTTPServer is an autogenerated mock type for the HTTPServer type
type HTTPServer struct {
	mock.Mock
}

// Serve provides a mock function with given fields: listener
func (_m *HTTPServer) Serve(listener net.Listener) error {
	ret := _m.Called(listener)

	var r0 error
	if rf, ok := ret.Get(0).(func(net.Listener) error); ok {
		r0 = rf(listener)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewHTTPServer interface {
	mock.TestingT
	Cleanup(func())
}

// NewHTTPServer creates a new instance of HTTPServer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewHTTPServer(t mockConstructorTestingTNewHTTPServer) *HTTPServer {
	mock := &HTTPServer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
