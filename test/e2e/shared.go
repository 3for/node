//nolint:deadcode,unused,varcheck
package e2e

import (
	"github.com/0xPolygonHermez/zkevm-node/log"
	"github.com/0xPolygonHermez/zkevm-node/state"
	"github.com/0xPolygonHermez/zkevm-node/test/operations"
	"github.com/ethereum/go-ethereum/core/types"
)

var networks = []struct {
	Name         string
	URL          string
	WebSocketURL string
	ChainID      uint64
	ChainType    string
	EventURL     string
	PrivateKey   string
}{
	{
		Name:         "Local L1",
		URL:          operations.DefaultL1NetworkURL,
		WebSocketURL: operations.DefaultL1NetworkWebSocketURL,
		ChainID:      operations.DefaultL1ChainID,
		ChainType:    operations.DefaultL1ChainType,
		EventURL:       operations.DefaultL1EventURL,
		PrivateKey:   operations.DefaultSequencerPrivateKey,
	},
	{
		Name:         "Local L2",
		URL:          operations.DefaultL2NetworkURL,
		WebSocketURL: operations.DefaultL2NetworkWebSocketURL,
		ChainID:      operations.DefaultL2ChainID,
		ChainType:    operations.DefaultL2ChainType,
		EventURL:	  operations.DefaultL2EventURL,
		PrivateKey:   operations.DefaultSequencerPrivateKey,
	},
}

func logTx(tx *types.Transaction) {
	sender, _ := state.GetSender(*tx)
	log.Debugf("********************")
	log.Debugf("Hash: %v", tx.Hash())
	log.Debugf("From: %v", sender)
	log.Debugf("Nonce: %v", tx.Nonce())
	log.Debugf("ChainId: %v", tx.ChainId())
	log.Debugf("To: %v", tx.To())
	log.Debugf("Gas: %v", tx.Gas())
	log.Debugf("GasPrice: %v", tx.GasPrice())
	log.Debugf("Cost: %v", tx.Cost())

	// b, _ := tx.MarshalBinary()
	//log.Debugf("RLP: ", hex.EncodeToHex(b))
	log.Debugf("********************")
}
