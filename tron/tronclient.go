package tron

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/0xPolygonHermez/zkevm-node/tron/pb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Client defines typed wrappers for the Tron RPC API.
type Client struct {
	client pb.WalletClient
}

// NewClient creates a client that uses the given RPC client.
func NewClient(url string) *Client {
	conn, err := grpc.Dial(url, grpc.WithInsecure())
	if err != nil {
		os.Exit(0)
	}
	return &Client{
		client: pb.NewWalletClient(conn),
	}
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

// Package goLang sha256 hash algorithm.
func Hash(s []byte) ([]byte, error) {
	h := sha256.New()
	_, err := h.Write(s)
	if err != nil {
		return nil, err
	}
	bs := h.Sum(nil)
	return bs, nil
}

func (tc *Client) sendTriggerContract(ownerPriKey, ownerAddress, contractAddress string, data []byte, feeLimmit int64) error {
	trx, err := tc.TriggerContract(ownerAddress, contractAddress, data)

	if err != nil {
		return err
	}
	trx.RawData.FeeLimit = feeLimmit
	rawData, _ := proto.Marshal(trx.GetRawData())
	hash, err := Hash(rawData)
	if err != nil {
		return err
	}

	signature, err := secp256k1.Sign(hash, []byte(ownerPriKey))
	if err != nil {
		return err
	}

	trx.Signature = append(trx.GetSignature(), signature)

	err = tc.BroadcastTransaction(context.Background(), trx)
	if err != nil {
		return err
	}

	return nil
}
