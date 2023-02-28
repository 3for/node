package tron

import (
	"math/rand"
	"strconv"
)

const (
	JsonRpcVersion       = "2.0"
	GetLogsMethod        = "eth_getLogs"
	GetTransactionByHash = "eth_getTransactionReceipt"
	GetBlockByNumber     = "eth_blockNumber"
	MAXQueryAddress      = 3
)

type NewFilter struct {
	Address   []string `json:"address"`
	FromBlock string   `json:"fromBlock"`
	ToBlock   string   `json:"toBlock"`
}
type FilterEventParams struct {
	BaseQueryParam
	Method string      `json:"method"`
	Params []NewFilter `json:"params"`
}
type FilterOtherParams struct {
	BaseQueryParam
	Method string   `json:"method"`
	Params []string `json:"params"`
}

type BaseQueryParam struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      string `json:"id"`
}
type FilterEventResponse struct {
	BaseQueryParam
}

type FilterTxResponse struct {
	BaseQueryParam
}

type FilterTxNumberResponse struct {
	BaseQueryParam
	Result string `json:result`
}

func GetDefaultBaseParm() BaseQueryParam {
	param := BaseQueryParam{
		Jsonrpc: JsonRpcVersion,
		Id:      strconv.FormatInt(int64(rand.Int()%100), 10),
	}
	return param
}
