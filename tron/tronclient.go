package tron

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xPolygonHermez/zkevm-node/tron/pb"
	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc"
)

// Client defines typed wrappers for the Tron RPC API.
type Client struct {
	client pb.WalletClient
}

// NewClient creates a client that uses the given RPC client.
func NewClient(url string) (*Client, error) {
	conn, err := grpc.Dial(url, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return &Client{
		client: pb.NewWalletClient(conn),
	}, nil
}

func (tc *Client) GetBalance(address string) (int64, error) {
	response, err := tc.client.GetAccount(context.Background(),
		&pb.Account{
			Address: common.FromHex("41" + strings.TrimPrefix(address, "0x")),
		})
	if err != nil {
		return 0, err
	}
	fmt.Printf("balance:%v\n", response.Balance)
	return response.Balance, nil
}

func (tc *Client) TriggerConstantContract(contractAddress string, data []byte) ([]byte, error) {
	response, err := tc.client.TriggerConstantContract(context.Background(),
		&pb.TriggerSmartContract{
			OwnerAddress:    nil,
			ContractAddress: common.FromHex("41" + strings.TrimPrefix(contractAddress, "0x")),
			CallValue:       0,
			Data:            data,
			CallTokenValue:  0,
			TokenId:         0,
		})
	if err != nil {
		return nil, err
	}
	if response.Result.Code != pb.Return_SUCCESS || response.Transaction.GetRet()[0].Ret == pb.Transaction_Result_FAILED {
		return nil, fmt.Errorf("code:%v message:%v", response.Result.Code, string(response.Result.Message))
	}

	fmt.Printf("result:%v\n", response.ConstantResult[0])
	return response.ConstantResult[0], nil
}

func (tc *Client) TriggerContract(ownerAddress, contractAddress string, data []byte) (*pb.Transaction, error) {
	response, err := tc.client.TriggerContract(context.Background(),
		&pb.TriggerSmartContract{
			OwnerAddress:    common.FromHex("41" + strings.TrimPrefix(ownerAddress, "0x")),
			ContractAddress: common.FromHex("41" + strings.TrimPrefix(contractAddress, "0x")),
			CallValue:       0,
			Data:            data,
			CallTokenValue:  0,
			TokenId:         0,
		})
	if err != nil {
		return nil, err
	}
	if response.Result.Code != pb.Return_SUCCESS {
		return nil, fmt.Errorf("code:%v message:%v", response.Result.Code, string(response.Result.Message))
	}
	return response.Transaction, nil
}

func (tc *Client) BroadcastTransaction(ctx context.Context, trx *pb.Transaction) error {
	result, err := tc.client.BroadcastTransaction(ctx, trx)
	if err != nil {
		return err
	}
	if result.Code != pb.Return_SUCCESS {
		return fmt.Errorf("code:%v message:%v", result.Code, string(result.Message))
	}
	return nil
}
