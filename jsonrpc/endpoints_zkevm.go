package jsonrpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/0xPolygonHermez/zkevm-node/hex"
	"github.com/0xPolygonHermez/zkevm-node/log"
	"github.com/0xPolygonHermez/zkevm-node/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/jackc/pgx/v4"
)

// ZKEVMEndpoints contains implementations for the "zkevm" RPC endpoints
type ZKEVMEndpoints struct {
	config Config
	state  stateInterface
	txMan  dbTxManager
}

// ConsolidatedBlockNumber returns current block number for consolidated blocks
func (z *ZKEVMEndpoints) ConsolidatedBlockNumber() (interface{}, rpcError) {
	return z.txMan.NewDbTxScope(z.state, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpcError) {
		lastBlockNumber, err := z.state.GetLastConsolidatedL2BlockNumber(ctx, dbTx)
		if err != nil {
			const errorMessage = "failed to get last consolidated block number from state"
			log.Errorf("%v:%v", errorMessage, err)
			return nil, newRPCError(defaultErrorCode, errorMessage)
		}

		return hex.EncodeUint64(lastBlockNumber), nil
	})
}

// IsBlockConsolidated returns the consolidation status of a provided block number
func (z *ZKEVMEndpoints) IsBlockConsolidated(blockNumber argUint64) (interface{}, rpcError) {
	return z.txMan.NewDbTxScope(z.state, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpcError) {
		IsL2BlockConsolidated, err := z.state.IsL2BlockConsolidated(ctx, uint64(blockNumber), dbTx)
		if err != nil {
			const errorMessage = "failed to check if the block is consolidated"
			log.Errorf("%v: %v", errorMessage, err)
			return nil, newRPCError(defaultErrorCode, errorMessage)
		}

		return IsL2BlockConsolidated, nil
	})
}

// IsBlockVirtualized returns the virtualization status of a provided block number
func (z *ZKEVMEndpoints) IsBlockVirtualized(blockNumber argUint64) (interface{}, rpcError) {
	return z.txMan.NewDbTxScope(z.state, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpcError) {
		IsL2BlockVirtualized, err := z.state.IsL2BlockVirtualized(ctx, uint64(blockNumber), dbTx)
		if err != nil {
			const errorMessage = "failed to check if the block is virtualized"
			log.Errorf("%v: %v", errorMessage, err)
			return nil, newRPCError(defaultErrorCode, errorMessage)
		}

		return IsL2BlockVirtualized, nil
	})
}

// BatchNumberByBlockNumber returns the batch number from which the passed block number is created
func (z *ZKEVMEndpoints) BatchNumberByBlockNumber(blockNumber argUint64) (interface{}, rpcError) {
	return z.txMan.NewDbTxScope(z.state, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpcError) {
		batchNum, err := z.state.BatchNumberByL2BlockNumber(ctx, uint64(blockNumber), dbTx)
		if err != nil {
			const errorMessage = "failed to get batch number from block number"
			log.Errorf("%v: %v", errorMessage, err.Error())
			return nil, newRPCError(defaultErrorCode, errorMessage)
		}

		return hex.EncodeUint64(batchNum), nil
	})
}

// BatchNumber returns the latest virtualized batch number
func (z *ZKEVMEndpoints) BatchNumber() (interface{}, rpcError) {
	return z.txMan.NewDbTxScope(z.state, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpcError) {
		lastBatchNumber, err := z.state.GetLastBatchNumber(ctx, dbTx)
		if err != nil {
			return "0x0", newRPCError(defaultErrorCode, "failed to get the last batch number from state")
		}

		return hex.EncodeUint64(lastBatchNumber), nil
	})
}

// VirtualBatchNumber returns the latest virtualized batch number
func (z *ZKEVMEndpoints) VirtualBatchNumber() (interface{}, rpcError) {
	return z.txMan.NewDbTxScope(z.state, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpcError) {
		lastBatchNumber, err := z.state.GetLastVirtualBatchNum(ctx, dbTx)
		if err != nil {
			return "0x0", newRPCError(defaultErrorCode, "failed to get the last virtual batch number from state")
		}

		return hex.EncodeUint64(lastBatchNumber), nil
	})
}

// VerifiedBatchNumber returns the latest verified batch number
func (z *ZKEVMEndpoints) VerifiedBatchNumber() (interface{}, rpcError) {
	return z.txMan.NewDbTxScope(z.state, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpcError) {
		lastBatch, err := z.state.GetLastVerifiedBatch(ctx, dbTx)
		if err != nil {
			return "0x0", newRPCError(defaultErrorCode, "failed to get the last verified batch number from state")
		}

		return hex.EncodeUint64(lastBatch.BatchNumber), nil
	})
}

// GetBatchByNumber returns information about a batch by batch number
func (z *ZKEVMEndpoints) GetBatchByNumber(batchNumber BatchNumber, fullTx bool) (interface{}, rpcError) {
	return z.txMan.NewDbTxScope(z.state, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpcError) {
		var err error
		batchNumber, rpcErr := batchNumber.getNumericBatchNumber(ctx, z.state, dbTx)
		if rpcErr != nil {
			return nil, rpcErr
		}

		batch, err := z.state.GetBatchByNumber(ctx, batchNumber, dbTx)
		if errors.Is(err, state.ErrNotFound) {
			return nil, nil
		} else if err != nil {
			return rpcErrorResponse(defaultErrorCode, fmt.Sprintf("couldn't load batch from state by number %v", batchNumber), err)
		}

		txs, err := z.state.GetTransactionsByBatchNumber(ctx, batchNumber, dbTx)
		if !errors.Is(err, state.ErrNotFound) && err != nil {
			return rpcErrorResponse(defaultErrorCode, fmt.Sprintf("couldn't load batch txs from state by number %v", batchNumber), err)
		}

		receipts := make([]types.Receipt, 0, len(txs))
		for _, tx := range txs {
			receipt, err := z.state.GetTransactionReceipt(ctx, tx.Hash(), dbTx)
			if err != nil {
				return rpcErrorResponse(defaultErrorCode, fmt.Sprintf("couldn't load receipt for tx %v", tx.Hash().String()), err)
			}
			receipts = append(receipts, *receipt)
		}

		virtualBatch, err := z.state.GetVirtualBatch(ctx, batchNumber, dbTx)
		if err != nil && !errors.Is(err, state.ErrNotFound) {
			return rpcErrorResponse(defaultErrorCode, fmt.Sprintf("couldn't load virtual batch from state by number %v", batchNumber), err)
		}

		verifiedBatch, err := z.state.GetVerifiedBatch(ctx, batchNumber, dbTx)
		if err != nil && !errors.Is(err, state.ErrNotFound) {
			return rpcErrorResponse(defaultErrorCode, fmt.Sprintf("couldn't load virtual batch from state by number %v", batchNumber), err)
		}

		batch.Transactions = txs
		rpcBatch := l2BatchToRPCBatch(batch, virtualBatch, verifiedBatch, receipts, fullTx)

		return rpcBatch, nil
	})
}

// GetBroadcastURI returns the IP:PORT of the broadcast service provided
// by the Trusted Sequencer JSON RPC server
func (z *ZKEVMEndpoints) GetBroadcastURI() (interface{}, rpcError) {
	return z.config.BroadcastURI, nil
}
