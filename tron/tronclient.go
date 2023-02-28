package tron

import (
	"os"

	"github.com/0xPolygonHermez/zkevm-node/tron/pb"
	"google.golang.org/grpc"
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
