// Code generated by mockery v2.21.4. DO NOT EDIT.

package component

import (
	component "gosolo/module/component"
	irrecoverable "gosolo/module/irrecoverable"

	mock "github.com/stretchr/testify/mock"
)

// ComponentWorker is an autogenerated mock type for the ComponentWorker type
type ComponentWorker struct {
	mock.Mock
}

// Execute provides a mock function with given fields: ctx, ready
func (_m *ComponentWorker) Execute(ctx irrecoverable.SignalerContext, ready component.ReadyFunc) {
	_m.Called(ctx, ready)
}

type mockConstructorTestingTNewComponentWorker interface {
	mock.TestingT
	Cleanup(func())
}

// NewComponentWorker creates a new instance of ComponentWorker. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewComponentWorker(t mockConstructorTestingTNewComponentWorker) *ComponentWorker {
	mock := &ComponentWorker{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
