package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/0xPolygonHermez/zkevm-node/encoding"
	"github.com/0xPolygonHermez/zkevm-node/hex"
	"github.com/0xPolygonHermez/zkevm-node/log"
	"github.com/0xPolygonHermez/zkevm-node/test/contracts/bin/Counter"
	"github.com/0xPolygonHermez/zkevm-node/test/contracts/bin/ERC20"
	"github.com/0xPolygonHermez/zkevm-node/test/contracts/bin/EmitLog"
	"github.com/0xPolygonHermez/zkevm-node/test/contracts/bin/Storage"
	"github.com/0xPolygonHermez/zkevm-node/test/operations"
	"github.com/0xPolygonHermez/zkevm-node/tron"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"google.golang.org/protobuf/proto"
)

const (
	txTimeout = 60 * time.Second
)

func main() {
	var networks = []struct {
		Name           string
		URL            string
		ChainID        uint64
		ChainType      string
		EventURL       string
		EventURLApiKey string
		PrivateKey     string
	}{
		{Name: "Local L1", URL: operations.DefaultL1NetworkURL, ChainID: operations.DefaultL1ChainID, ChainType: operations.DefaultL1ChainType, EventURL: operations.DefaultL1EventURL, EventURLApiKey: operations.DefaultL1EventURLApiKey, PrivateKey: operations.DefaultSequencerPrivateKey},
		//		{Name: "Local L2", URL: operations.DefaultL2NetworkURL, ChainID: operations.DefaultL2ChainID, ChainType: operations.DefaultL2ChainType, EventURL: operations.DefaultL2EventURL, EventURLApiKey: operations.DefaultL2EventURLApiKey, PrivateKey: operations.DefaultSequencerPrivateKey},
	}

	for _, network := range networks {
		ctx := context.Background()

		log.Infof("connecting to %v: %v, chaintype: %v", network.Name, network.URL, network.ChainType)

		switch network.ChainType {
		case "Eth":
			client, err := ethclient.Dial(network.URL)
			chkErr(err)
			log.Infof("connected")

			auth := operations.MustGetAuth(network.PrivateKey, network.ChainID)
			chkErr(err)

			const receiverAddr = "0x617b3a3528F9cDd6630fd3301B9c8911F7Bf063D"

			balance, err := client.BalanceAt(ctx, auth.From, nil)
			chkErr(err)
			log.Debugf("ETH Balance for %v: %v", auth.From, balance)

			// Counter
			log.Debugf("Sending TX to deploy Counter SC")
			_, tx, counterSC, err := Counter.DeployCounter(auth, client)
			chkErr(err)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			log.Debugf("Calling Increment method from Counter SC")
			tx, err = counterSC.Increment(auth)
			chkErr(err)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			fmt.Println()

			// EmitLog
			log.Debugf("Sending TX to deploy EmitLog SC")
			_, tx, emitLogSC, err := EmitLog.DeployEmitLog(auth, client)
			chkErr(err)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			log.Debugf("Calling EmitLogs method from EmitLog SC")
			tx, err = emitLogSC.EmitLogs(auth)
			chkErr(err)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			fmt.Println()

			// ERC20
			mintAmount, _ := big.NewInt(0).SetString("1000000000000000000000", encoding.Base10)
			log.Debugf("Sending TX to deploy ERC20 SC")
			_, tx, erc20SC, err := ERC20.DeployERC20(auth, client, "Test Coin", "TCO")
			chkErr(err)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			log.Debugf("Sending TX to do a ERC20 mint")
			tx, err = erc20SC.Mint(auth, mintAmount)
			chkErr(err)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			transferAmount, _ := big.NewInt(0).SetString("900000000000000000000", encoding.Base10)
			log.Debugf("Sending TX to do a ERC20 transfer")
			tx, err = erc20SC.Transfer(auth, common.HexToAddress(receiverAddr), transferAmount)
			chkErr(err)
			auth.Nonce = big.NewInt(0).SetUint64(tx.Nonce() + 1)
			log.Debugf("Sending invalid TX to do a ERC20 transfer")
			invalidTx, err := erc20SC.Transfer(auth, common.HexToAddress(receiverAddr), transferAmount)
			chkErr(err)
			log.Debugf("Invalid ERC20 tx hash: %v", invalidTx.Hash())
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			operations.WaitTxToBeMined(ctx, client, invalidTx, txTimeout) //nolint:errcheck
			chkErr(err)
			auth.Nonce = nil
			fmt.Println()

			// Storage
			const numberToStore = 22
			log.Debugf("Sending TX to deploy Storage SC")
			_, tx, storageSC, err := Storage.DeployStorage(auth, client)
			chkErr(err)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			log.Debugf("Calling Store method from Storage SC")
			tx, err = storageSC.Store(auth, big.NewInt(numberToStore))
			chkErr(err)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			fmt.Println()

			// Valid ETH Transfer
			balance, err = client.BalanceAt(ctx, auth.From, nil)
			log.Debugf("ETH Balance for %v: %v", auth.From, balance)
			chkErr(err)
			const halfDivision = 2
			transferAmount = balance.Quo(balance, big.NewInt(halfDivision))
			log.Debugf("Transfer Amount: %v", transferAmount)

			log.Debugf("Sending TX to transfer ETH")
			to := common.HexToAddress(receiverAddr)
			tx = ethTransfer(ctx, client, auth, to, transferAmount, nil)
			fmt.Println()

			// Invalid ETH Transfer
			log.Debugf("Sending Invalid TX to transfer ETH")
			nonce := tx.Nonce() + 1
			ethTransfer(ctx, client, auth, to, transferAmount, &nonce)
			err = operations.WaitTxToBeMined(ctx, client, tx, txTimeout)
			chkErr(err)
			fmt.Println()
		case "Tron":
			tronRPCClient, err := tron.NewClient(network.URL)
			chkErr(err)
			client := tronRPCClient

			// set private object
			privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(network.PrivateKey, "0x"))
			chkErr(err)
			fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey).String() // Has prefix "0x"
			log.Infof("privObject:%v", fromAddr)
			//client.GetBalance("E552F6487585C2B58BC2C9BB4492BC1F17132CD0")
			balance, err := client.GetBalance(fromAddr)
			chkErr(err)
			log.Debugf("TRX Balance for %v: %v", fromAddr, balance)

			counterAddr := "0x3B4648518419DA1D92ED12505193FFF13E3FD492" //TFNd4gzLoxqKuKCdqUFKc883i1VwH19yj4
			counterABI := "[{\"inputs\":[],\"name\":\"count\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"increment\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
			parsed, err := abi.JSON(strings.NewReader(counterABI))
			chkErr(err)
			data, err := parsed.Pack("getCount")
			chkErr(err)
			client.TriggerConstantContract(counterAddr, data)

			feeLimit := uint64(200000000)

			data, err = parsed.Pack("increment")
			chkErr(err)
			err = sendTriggerContract(client, privateKey, fromAddr, counterAddr, data, feeLimit)
			chkErr(err)

			data, err = parsed.Pack("getCount")
			chkErr(err)
			client.TriggerConstantContract(counterAddr, data)

			// create query filter
			txID := "0xe6993883bd4019fe5ce2b9a906911d7b640d78d8d558dbe678a8a964cf6a624f"
			var txIDs = []string{txID}
			queryFilter := tron.FilterOtherParams{
				BaseQueryParam: tron.GetDefaultBaseParm(),
				Method:         tron.GetTransactionReceipt,
				Params:         txIDs,
			}
			result, err := QueryTronInfo(network.EventURL, network.EventURLApiKey, queryFilter)
			chkErr(err)
			var transactionReceipt tron.FilterTxResponse
			if err := json.Unmarshal(result, &transactionReceipt); err != nil {
				chkErr(err)
			}

			//EmitLog contract
			emitLogAddr := "0xA70FF0AF98D0B03F72D65E02BB2A57A01A4DBC9D" //TRCYwdwgPGMYg13tZ3aQK7UvQdb9U9KgyP
			emitLogABI := "[{\"anonymous\":false,\"inputs\":[],\"name\":\"Log\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"}],\"name\":\"LogA\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"b\",\"type\":\"uint256\"}],\"name\":\"LogAB\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"b\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"c\",\"type\":\"uint256\"}],\"name\":\"LogABC\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"b\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"c\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"d\",\"type\":\"uint256\"}],\"name\":\"LogABCD\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"emitLogs\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
			parsed, err = abi.JSON(strings.NewReader(emitLogABI))
			chkErr(err)
			data, err = parsed.Pack("emitLogs")
			chkErr(err)
			err = sendTriggerContract(client, privateKey, fromAddr, emitLogAddr, data, feeLimit)
			chkErr(err)

			//get event log
			var tronContractAddresses []string
			tronContractAddresses = append(tronContractAddresses, emitLogAddr)
			fromBlock := int64(31816623)
			toBlock := int64(31816772)
			GetTronEventsByContractAddress(network.EventURL, network.EventURLApiKey, tronContractAddresses, fromBlock, toBlock)

		default:
			fmt.Println("ChainType value should be in [Eth,Tron]")
			return
		}

	}
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

func sendTriggerContract(client *tron.Client, ownerPriKey *ecdsa.PrivateKey, ownerAddress, contractAddress string, data []byte, feeLimmit uint64) error {
	trx, err := client.TriggerContract(ownerAddress, contractAddress, data)

	if err != nil {
		return err
	}
	trx.RawData.FeeLimit = int64(feeLimmit)
	rawData, _ := proto.Marshal(trx.GetRawData())
	hash, err := Hash(rawData)
	if err != nil {
		return err
	}
	println("rawData hash:", hex.EncodeToHex(hash))

	signature, err := crypto.Sign(hash, ownerPriKey)
	if err != nil {
		return err
	}

	trx.Signature = append(trx.GetSignature(), signature)

	err = client.BroadcastTransaction(context.Background(), trx)
	if err != nil {
		return err
	}

	return nil
}

func MakeRequest(req *http.Request, tronGridAPIKey string) ([]byte, error) {
	client := http.Client{}
	req.Header.Add("TRON-PRO-API-KEY", tronGridAPIKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// response
	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return body, err
	}
	log.Debug("Error do http request from URL", "status", resp.StatusCode, "URL", req.URL.String())
	return nil, fmt.Errorf("error while make tron requset  from url: %v, status: %v", req.URL.String(), resp.StatusCode)
}

// GetTronGridEndpoint returns tron server endpoint
func GetTronGridEndpoint(endpoint, tronGridURL string) string {
	u, _ := url.Parse(tronGridURL)
	u.Path = path.Join(u.Path, endpoint)
	return u.String()
}

func GetTronEventsByContractAddress(tronGridURL, tronGridAPIKey string, address []string, from, to int64) ([]types.Log, error) {
	var decodedAddress []string
	for _, adr := range address {
		decodedAddress = append(decodedAddress, adr[2:])
	}
	var logAHash = crypto.Keccak256Hash([]byte("LogA(uint256)"))
	var topics []string
	topics = append(topics, logAHash.Hex())
	//create filter
	filter := tron.NewFilter{
		Address:   decodedAddress,
		FromBlock: "0x" + strconv.FormatInt(from, 16),
		ToBlock:   "0x" + strconv.FormatInt(to, 16),
		Topics:    topics,
	}
	filtersArray := []tron.NewFilter{filter}
	queryFilter := tron.FilterEventParams{
		BaseQueryParam: tron.GetDefaultBaseParm(),
		Method:         tron.GetLogsMethod,
		Params:         filtersArray,
	}

	queryByte, err := json.Marshal(queryFilter)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", GetTronGridEndpoint("/jsonrpc", tronGridURL), bytes.NewBuffer(queryByte))
	if err != nil {
		return nil, err
	}
	result, err := MakeRequest(req, tronGridAPIKey)
	if err != nil {
		return nil, err
	}
	var filterChangeResult tron.FilterEventResponse
	if err := json.Unmarshal(result, &filterChangeResult); err != nil {
		return nil, err
	}
	return filterChangeResult.Result, nil
}

func QueryTronInfo(tronGridURL, tronGridAPIKey string, queryFilter tron.FilterOtherParams) ([]byte, error) {
	queryByte, err := json.Marshal(queryFilter)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", GetTronGridEndpoint("/jsonrpc", tronGridURL), bytes.NewBuffer(queryByte))
	if err != nil {
		return nil, err
	}
	result, err := MakeRequest(req, tronGridAPIKey)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func ethTransfer(ctx context.Context, client *ethclient.Client, auth *bind.TransactOpts, to common.Address, amount *big.Int, nonce *uint64) *types.Transaction {
	if nonce == nil {
		log.Infof("reading nonce for account: %v", auth.From.Hex())
		var err error
		n, err := client.NonceAt(ctx, auth.From, nil)
		log.Infof("nonce: %v", n)
		chkErr(err)
		nonce = &n
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	chkErr(err)

	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{To: &to})
	chkErr(err)

	tx := types.NewTransaction(*nonce, to, amount, gasLimit, gasPrice, nil)

	signedTx, err := auth.Signer(auth.From, tx)
	chkErr(err)

	log.Infof("sending transfer tx")
	err = client.SendTransaction(ctx, signedTx)
	chkErr(err)
	log.Infof("tx sent: %v", signedTx.Hash().Hex())

	rlp, err := signedTx.MarshalBinary()
	chkErr(err)

	log.Infof("tx rlp: %v", hex.EncodeToHex(rlp))

	return signedTx
}

func chkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
