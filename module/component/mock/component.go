// Code generated by mockery v2.21.4. DO NOT EDIT.

package component

import (
	irrecoverable "gosolo/module/irrecoverable"
	mock "github.com/stretchr/testify/mock"
)

// Component is an autogenerated mock type for the Component type
type Component struct {
	mock.Mock
}

// Done provides a mock function with given fields:
func (_m *Component) Done() <-chan struct{} {
	ret := _m.Called()

	var r0 <-chan struct{}
	if rf, ok := ret.Get(0).(func() <-chan struct{}); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(<-chan struct{})
		}
	}

	return r0
}

// Ready provides a mock function with given fields:
func (_m *Component) Ready() <-chan struct{} {
	ret := _m.Called()

	var r0 <-chan struct{}
	if rf, ok := ret.Get(0).(func() <-chan struct{}); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(<-chan struct{})
		}
	}

	return r0
}

// Start provides a mock function with given fields: _a0
func (_m *Component) Start(_a0 irrecoverable.SignalerContext) {
	_m.Called(_a0)
}

type mockConstructorTestingTNewComponent interface {
	mock.TestingT
	Cleanup(func())
}

// NewComponent creates a new instance of Component. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewComponent(t mockConstructorTestingTNewComponent) *Component {
	mock := &Component{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
