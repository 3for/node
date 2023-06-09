// Code generated by mockery v2.16.0. DO NOT EDIT.

package gasprice

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// poolMock is an autogenerated mock type for the pool type
type poolMock struct {
	mock.Mock
}

// GetGasPrice provides a mock function with given fields: ctx
func (_m *poolMock) GetGasPrice(ctx context.Context) (uint64, error) {
	ret := _m.Called(ctx)

	var r0 uint64
	if rf, ok := ret.Get(0).(func(context.Context) uint64); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetGasPrice provides a mock function with given fields: ctx, gasPrice
func (_m *poolMock) SetGasPrice(ctx context.Context, gasPrice uint64) error {
	ret := _m.Called(ctx, gasPrice)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint64) error); ok {
		r0 = rf(ctx, gasPrice)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTnewPoolMock interface {
	mock.TestingT
	Cleanup(func())
}

// newPoolMock creates a new instance of poolMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func newPoolMock(t mockConstructorTestingTnewPoolMock) *poolMock {
	mock := &poolMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
