// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// SriovnetOps is an autogenerated mock type for the SriovnetOps type
type SriovnetOps struct {
	mock.Mock
}

// GetNetDevicesFromPci provides a mock function with given fields: pciAddress
func (_m *SriovnetOps) GetNetDevicesFromPci(pciAddress string) ([]string, error) {
	ret := _m.Called(pciAddress)

	var r0 []string
	if rf, ok := ret.Get(0).(func(string) []string); ok {
		r0 = rf(pciAddress)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(pciAddress)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPfPciFromVfPci provides a mock function with given fields: vfPciAddress
func (_m *SriovnetOps) GetPfPciFromVfPci(vfPciAddress string) (string, error) {
	ret := _m.Called(vfPciAddress)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(vfPciAddress)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(vfPciAddress)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUplinkRepresentor provides a mock function with given fields: vfPciAddress
func (_m *SriovnetOps) GetUplinkRepresentor(vfPciAddress string) (string, error) {
	ret := _m.Called(vfPciAddress)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(vfPciAddress)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(vfPciAddress)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetVfIndexByPciAddress provides a mock function with given fields: vfPciAddress
func (_m *SriovnetOps) GetVfIndexByPciAddress(vfPciAddress string) (int, error) {
	ret := _m.Called(vfPciAddress)

	var r0 int
	if rf, ok := ret.Get(0).(func(string) int); ok {
		r0 = rf(vfPciAddress)
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(vfPciAddress)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetVfRepresentor provides a mock function with given fields: uplink, vfIndex
func (_m *SriovnetOps) GetVfRepresentor(uplink string, vfIndex int) (string, error) {
	ret := _m.Called(uplink, vfIndex)

	var r0 string
	if rf, ok := ret.Get(0).(func(string, int) string); ok {
		r0 = rf(uplink, vfIndex)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, int) error); ok {
		r1 = rf(uplink, vfIndex)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetVfRepresentorSmartNIC provides a mock function with given fields: pfID, vfIndex
func (_m *SriovnetOps) GetVfRepresentorSmartNIC(pfID string, vfIndex string) (string, error) {
	ret := _m.Called(pfID, vfIndex)

	var r0 string
	if rf, ok := ret.Get(0).(func(string, string) string); ok {
		r0 = rf(pfID, vfIndex)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(pfID, vfIndex)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
