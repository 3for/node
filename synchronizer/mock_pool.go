// Code generated by mockery v2.16.0. DO NOT EDIT.

package synchronizer

import (
	context "context"

	mock "github.com/stretchr/testify/mock"

	types "github.com/ethereum/go-ethereum/core/types"
)

// poolMock is an autogenerated mock type for the poolInterface type
type poolMock struct {
	mock.Mock
}

// AddTx provides a mock function with given fields: ctx, tx
func (_m *poolMock) AddTx(ctx context.Context, tx types.Transaction) error {
	ret := _m.Called(ctx, tx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, types.Transaction) error); ok {
		r0 = rf(ctx, tx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteReorgedTransactions provides a mock function with given fields: ctx, txs
func (_m *poolMock) DeleteReorgedTransactions(ctx context.Context, txs []*types.Transaction) error {
	ret := _m.Called(ctx, txs)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []*types.Transaction) error); ok {
		r0 = rf(ctx, txs)
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
