package etherman

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xPolygonHermez/zkevm-node/encoding"
	"github.com/0xPolygonHermez/zkevm-node/etherman/etherscan"
	"github.com/0xPolygonHermez/zkevm-node/etherman/ethgasstation"
	"github.com/0xPolygonHermez/zkevm-node/etherman/smartcontracts/matic"
	"github.com/0xPolygonHermez/zkevm-node/etherman/smartcontracts/polygonzkevm"
	"github.com/0xPolygonHermez/zkevm-node/etherman/smartcontracts/polygonzkevmglobalexitroot"
	ethmanTypes "github.com/0xPolygonHermez/zkevm-node/etherman/types"
	"github.com/0xPolygonHermez/zkevm-node/log"
	"github.com/0xPolygonHermez/zkevm-node/state"
	"github.com/0xPolygonHermez/zkevm-node/test/operations"
	"github.com/0xPolygonHermez/zkevm-node/tron"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
)

var (
	updateGlobalExitRootSignatureHash           = crypto.Keccak256Hash([]byte("UpdateGlobalExitRoot(bytes32,bytes32)"))
	forcedBatchSignatureHash                    = crypto.Keccak256Hash([]byte("ForceBatch(uint64,bytes32,address,bytes)"))
	sequencedBatchesEventSignatureHash          = crypto.Keccak256Hash([]byte("SequenceBatches(uint64)"))
	forceSequencedBatchesSignatureHash          = crypto.Keccak256Hash([]byte("SequenceForceBatches(uint64)"))
	verifyBatchesSignatureHash                  = crypto.Keccak256Hash([]byte("VerifyBatches(uint64,bytes32,address)"))
	verifyBatchesTrustedAggregatorSignatureHash = crypto.Keccak256Hash([]byte("VerifyBatchesTrustedAggregator(uint64,bytes32,address)"))
	setTrustedSequencerURLSignatureHash         = crypto.Keccak256Hash([]byte("SetTrustedSequencerURL(string)"))
	setForceBatchAllowedSignatureHash           = crypto.Keccak256Hash([]byte("SetForceBatchAllowed(bool)"))
	setTrustedSequencerSignatureHash            = crypto.Keccak256Hash([]byte("SetTrustedSequencer(address)"))
	transferOwnershipSignatureHash              = crypto.Keccak256Hash([]byte("OwnershipTransferred(address,address)"))
	setSecurityCouncilSignatureHash             = crypto.Keccak256Hash([]byte("SetSecurityCouncil(address)"))
	proofDifferentStateSignatureHash            = crypto.Keccak256Hash([]byte("ProofDifferentState(bytes32,bytes32)"))
	emergencyStateActivatedSignatureHash        = crypto.Keccak256Hash([]byte("EmergencyStateActivated()"))
	emergencyStateDeactivatedSignatureHash      = crypto.Keccak256Hash([]byte("EmergencyStateDeactivated()"))
	updateZkEVMVersionSignatureHash             = crypto.Keccak256Hash([]byte("UpdateZkEVMVersion(uint64,uint64,string)"))

	// Proxy events
	initializedSignatureHash    = crypto.Keccak256Hash([]byte("Initialized(uint8)"))
	adminChangedSignatureHash   = crypto.Keccak256Hash([]byte("AdminChanged(address,address)"))
	beaconUpgradedSignatureHash = crypto.Keccak256Hash([]byte("BeaconUpgraded(address)"))
	upgradedSignatureHash       = crypto.Keccak256Hash([]byte("Upgraded(address)"))

	// ErrNotFound is used when the object is not found
	ErrNotFound = errors.New("not found")
	// ErrIsReadOnlyMode is used when the EtherMan client is in read-only mode.
	ErrIsReadOnlyMode = errors.New("etherman client in read-only mode: no account configured to send transactions to L1. " +
		"please check the [Etherman] PrivateKeyPath and PrivateKeyPassword configuration")
	// ErrPrivateKeyNotFound used when the provided sender does not have a private key registered to be used
	ErrPrivateKeyNotFound = errors.New("can't find sender private key to sign tx")
)

// SequencedBatchesSigHash returns the hash for the `SequenceBatches` event.
func SequencedBatchesSigHash() common.Hash { return sequencedBatchesEventSignatureHash }

// TrustedVerifyBatchesSigHash returns the hash for the `TrustedVerifyBatches` event.
func TrustedVerifyBatchesSigHash() common.Hash { return verifyBatchesTrustedAggregatorSignatureHash }

// EventOrder is the the type used to identify the events order
type EventOrder string

const (
	// GlobalExitRootsOrder identifies a GlobalExitRoot event
	GlobalExitRootsOrder EventOrder = "GlobalExitRoots"
	// SequenceBatchesOrder identifies a VerifyBatch event
	SequenceBatchesOrder EventOrder = "SequenceBatches"
	// ForcedBatchesOrder identifies a ForcedBatches event
	ForcedBatchesOrder EventOrder = "ForcedBatches"
	// TrustedVerifyBatchOrder identifies a TrustedVerifyBatch event
	TrustedVerifyBatchOrder EventOrder = "TrustedVerifyBatch"
	// SequenceForceBatchesOrder identifies a SequenceForceBatches event
	SequenceForceBatchesOrder EventOrder = "SequenceForceBatches"
)

type ethereumClient interface {
	ethereum.ChainReader
	ethereum.ChainStateReader
	ethereum.ContractCaller
	ethereum.GasEstimator
	ethereum.GasPricer
	ethereum.LogFilterer
	ethereum.TransactionReader
	ethereum.TransactionSender

	bind.DeployBackend
}

type externalGasProviders struct {
	MultiGasProvider bool
	Providers        []ethereum.GasPricer
}

// Client is a simple implementation of EtherMan.
type Client struct {
	EthClient             ethereumClient
	TronRPCClient         *tron.Client
	PoE                   *polygonzkevm.Polygonzkevm
	GlobalExitRootManager *polygonzkevmglobalexitroot.Polygonzkevmglobalexitroot
	Matic                 *matic.Matic
	SCAddresses           []common.Address

	GasProviders externalGasProviders

	cfg  Config
	auth map[common.Address]bind.TransactOpts // empty in case of read-only client
}

// NewClient creates a new etherman.
func NewClient(cfg Config) (*Client, error) {
	switch cfg.L1ChainType {
	case "Eth":
		// Connect to ethereum node
		ethClient, err := ethclient.Dial(cfg.URL)
		if err != nil {
			log.Errorf("error connecting to %s: %+v", cfg.URL, err)
			return nil, err
		}
		// Create smc clients
		poe, err := polygonzkevm.NewPolygonzkevm(cfg.PoEAddr, ethClient)
		if err != nil {
			return nil, err
		}
		globalExitRoot, err := polygonzkevmglobalexitroot.NewPolygonzkevmglobalexitroot(cfg.GlobalExitRootManagerAddr, ethClient)
		if err != nil {
			return nil, err
		}
		matic, err := matic.NewMatic(cfg.MaticAddr, ethClient)
		if err != nil {
			return nil, err
		}
		var scAddresses []common.Address
		scAddresses = append(scAddresses, cfg.PoEAddr, cfg.GlobalExitRootManagerAddr)

		gProviders := []ethereum.GasPricer{ethClient}
		if cfg.MultiGasProvider {
			if cfg.Etherscan.ApiKey == "" {
				log.Info("No ApiKey provided for etherscan. Ignoring provider...")
			} else {
				log.Info("ApiKey detected for etherscan")
				gProviders = append(gProviders, etherscan.NewEtherscanService(cfg.Etherscan.ApiKey))
			}
			gProviders = append(gProviders, ethgasstation.NewEthGasStationService())
		}

		return &Client{
			EthClient:             ethClient,
			PoE:                   poe,
			Matic:                 matic,
			GlobalExitRootManager: globalExitRoot,
			SCAddresses:           scAddresses,
			GasProviders: externalGasProviders{
				MultiGasProvider: cfg.MultiGasProvider,
				Providers:        gProviders,
			},
			cfg:  cfg,
			auth: map[common.Address]bind.TransactOpts{},
		}, nil
	case "Tron":
		// Connect to Tron node
		tronRPCClient, err := tron.NewClient(cfg.URL)
		if err != nil {
			log.Errorf("error connecting to %s: %+v", cfg.URL, err)
			return nil, err
		}
		var scAddresses []common.Address
		scAddresses = append(scAddresses, cfg.PoEAddr, cfg.GlobalExitRootManagerAddr)

		return &Client{
			TronRPCClient: tronRPCClient,
			SCAddresses:   scAddresses,
			cfg:           cfg,
			auth:          map[common.Address]bind.TransactOpts{},
		}, nil
	}

	return nil, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// VerifyGenBlockNumber verifies if the genesis Block Number is valid
func (etherMan *Client) VerifyGenBlockNumber(ctx context.Context, genBlockNumber uint64) (bool, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		genBlock := big.NewInt(0).SetUint64(genBlockNumber)
		response, err := etherMan.EthClient.CodeAt(ctx, etherMan.cfg.PoEAddr, genBlock)
		if err != nil {
			log.Error("error getting smc code for gen block number. Error: ", err)
			return false, err
		}
		responseString := hex.EncodeToString(response)
		if responseString == "" {
			return false, nil
		}
		responsePrev, err := etherMan.EthClient.CodeAt(ctx, etherMan.cfg.PoEAddr, genBlock.Sub(genBlock, big.NewInt(1)))
		if err != nil {
			if parsedErr, ok := tryParseError(err); ok {
				if errors.Is(parsedErr, ErrMissingTrieNode) {
					return true, nil
				}
			}
			log.Error("error getting smc code for gen block number. Error: ", err)
			return false, err
		}
		responsePrevString := hex.EncodeToString(responsePrev)
		if responsePrevString != "" {
			return false, nil
		}
		return true, nil

	case "Tron":
		var params = []string{etherMan.cfg.PoEAddr.String()}
		params = append(params, "0x"+strconv.FormatUint(genBlockNumber, 16))
		queryFilter := tron.FilterOtherParams{
			BaseQueryParam: tron.GetDefaultBaseParm(),
			Method:         tron.CodeAt,
			Params:         params,
		}
		response, err := QueryTronInfo(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, queryFilter)
		if err != nil {
			log.Error("error getting Tron smc code for gen block number. Error: ", err)
			return false, err
		}
		responseString := hex.EncodeToString(response)
		if responseString == "" {
			return false, nil
		}
		//query previous info
		genBlock := big.NewInt(0).SetUint64(genBlockNumber)
		prevBlock := genBlock.Sub(genBlock, big.NewInt(1)) // one block before
		params = []string{etherMan.cfg.PoEAddr.String()}
		params = append(params, hexutil.EncodeBig(prevBlock))
		queryFilter = tron.FilterOtherParams{
			BaseQueryParam: tron.GetDefaultBaseParm(),
			Method:         tron.CodeAt,
			Params:         params,
		}
		responsePrev, err := QueryTronInfo(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, queryFilter)
		if err != nil {
			log.Error("error getting Tron prev smc code for gen prev block number. Error: ", err)
			return false, err
		}
		responsePrevString := hex.EncodeToString(responsePrev)
		if responsePrevString != "" {
			//return false, nil //TODO. ZYD. Tron eth_getCode DO NOT support blocknumber filter now.
			return true, nil
		}
		return true, nil
	}
	return false, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// TronParseUpdateZkEVMVersion is a log parse operation binding the contract event 0xed7be53c9f1a96a481223b15568a5b1a475e01a74b347d6ca187c8bf0c078cd6.
//
// Solidity: event UpdateZkEVMVersion(uint64 numBatch, uint64 forkID, string version)
func (etherMan *Client) TronParseUpdateZkEVMVersion(log types.Log) (*polygonzkevm.PolygonzkevmUpdateZkEVMVersion, error) {
	event := new(polygonzkevm.PolygonzkevmUpdateZkEVMVersion)
	polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
	if err != nil {
		return nil, err
	}
	if err := etherMan.UnpackLog(polygonzkevmABI, event, "UpdateZkEVMVersion", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GetForks returns fork information
func (etherMan *Client) GetForks(ctx context.Context) ([]state.ForkIDInterval, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		// Filter query
		query := ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(1),
			Addresses: etherMan.SCAddresses,
			Topics:    [][]common.Hash{{updateZkEVMVersionSignatureHash}},
		}
		logs, err := etherMan.EthClient.FilterLogs(ctx, query)
		if err != nil {
			return []state.ForkIDInterval{}, err
		}
		var forks []state.ForkIDInterval
		for i, l := range logs {
			zkevmVersion, err := etherMan.PoE.ParseUpdateZkEVMVersion(l)
			if err != nil {
				return []state.ForkIDInterval{}, err
			}
			var fork state.ForkIDInterval
			if i == 0 {
				fork = state.ForkIDInterval{
					FromBatchNumber: zkevmVersion.NumBatch,
					ToBatchNumber:   math.MaxUint64,
					ForkId:          zkevmVersion.ForkID,
					Version:         zkevmVersion.Version,
				}
			} else {
				forks[len(forks)-1].ToBatchNumber = zkevmVersion.NumBatch - 1
				fork = state.ForkIDInterval{
					FromBatchNumber: zkevmVersion.NumBatch,
					ToBatchNumber:   math.MaxUint64,
					ForkId:          zkevmVersion.ForkID,
					Version:         zkevmVersion.Version,
				}
			}
			forks = append(forks, fork)
		}
		log.Debugf("Forks decoded: %+v", forks)
		return forks, nil
	case "Tron":
		var decodedAddress []string
		for _, adr := range etherMan.SCAddresses {
			decodedAddress = append(decodedAddress, adr.String()[2:])
		}
		var topics []string
		topics = append(topics, updateZkEVMVersionSignatureHash.Hex())
		// Filter query
		query := tron.NewFilter{
			FromBlock: "0x1", //TODO, too early?
			Address:   decodedAddress,
			Topics:    topics,
		}
		logs, err := FilterTronLogs(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, query)
		if err != nil {
			return []state.ForkIDInterval{}, err
		}

		var forks []state.ForkIDInterval
		for i, l := range logs {
			zkevmVersion, err := etherMan.TronParseUpdateZkEVMVersion(l)
			if err != nil {
				return []state.ForkIDInterval{}, err
			}
			var fork state.ForkIDInterval
			if i == 0 {
				fork = state.ForkIDInterval{
					FromBatchNumber: zkevmVersion.NumBatch,
					ToBatchNumber:   math.MaxUint64,
					ForkId:          zkevmVersion.ForkID,
					Version:         zkevmVersion.Version,
				}
			} else {
				forks[len(forks)-1].ToBatchNumber = zkevmVersion.NumBatch - 1
				fork = state.ForkIDInterval{
					FromBatchNumber: zkevmVersion.NumBatch,
					ToBatchNumber:   math.MaxUint64,
					ForkId:          zkevmVersion.ForkID,
					Version:         zkevmVersion.Version,
				}
			}
			forks = append(forks, fork)
		}
		log.Debugf("Tron Forks decoded: %+v", forks)
		return forks, nil
	}
	return nil, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// query Tron blockchain events, as eth_getLogs
func FilterTronLogs(tronGridURL, tronGridAPIKey string, filter tron.NewFilter) ([]types.Log, error) {
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

// query Tron blockchain info, such as eth_getCode
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

// GetRollupInfoByBlockRange function retrieves the Rollup information that are included in all this ethereum blocks
// from block x to block y.
func (etherMan *Client) GetRollupInfoByBlockRange(ctx context.Context, fromBlock uint64, toBlock *uint64) ([]Block, map[common.Hash][]Order, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		// Filter query
		query := ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(fromBlock),
			Addresses: etherMan.SCAddresses,
		}
		if toBlock != nil {
			query.ToBlock = new(big.Int).SetUint64(*toBlock)
		}
		blocks, blocksOrder, err := etherMan.readEvents(ctx, query)
		if err != nil {
			return nil, nil, err
		}
		return blocks, blocksOrder, nil
	case "Tron":
		var decodedAddress []string
		for _, adr := range etherMan.SCAddresses {
			decodedAddress = append(decodedAddress, adr.String()[2:])
		}
		//create filter
		filterLogs := tron.NewFilter{
			Address:   decodedAddress,
			FromBlock: "0x" + strconv.FormatUint(fromBlock, 16),
		}
		blocks, blocksOrder, err := etherMan.readTronEvents(ctx, filterLogs)
		if err != nil {
			return nil, nil, err
		}
		return blocks, blocksOrder, nil
	}
	return nil, nil, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// Order contains the event order to let the synchronizer store the information following this order.
type Order struct {
	Name EventOrder
	Pos  int
}

func (etherMan *Client) readEvents(ctx context.Context, query ethereum.FilterQuery) ([]Block, map[common.Hash][]Order, error) {
	logs, err := etherMan.EthClient.FilterLogs(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	var blocks []Block
	blocksOrder := make(map[common.Hash][]Order)
	for _, vLog := range logs {
		err := etherMan.processEvent(ctx, vLog, &blocks, &blocksOrder)
		if err != nil {
			log.Warnf("error processing event. Retrying... Error: %s. vLog: %+v", err.Error(), vLog)
			return nil, nil, err
		}
	}
	return blocks, blocksOrder, nil
}

// read Tron events
func (etherMan *Client) readTronEvents(ctx context.Context, filterLogs tron.NewFilter) ([]Block, map[common.Hash][]Order, error) {
	logs, err := FilterTronLogs(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, filterLogs)
	if err != nil {
		return nil, nil, err
	}
	var blocks []Block
	blocksOrder := make(map[common.Hash][]Order)
	for _, vLog := range logs {
		err := etherMan.processEvent(ctx, vLog, &blocks, &blocksOrder)
		if err != nil {
			log.Warnf("error processing event. Retrying... Error: %s. vLog: %+v", err.Error(), vLog)
			return nil, nil, err
		}
	}
	return blocks, blocksOrder, nil
}

func (etherMan *Client) processEvent(ctx context.Context, vLog types.Log, blocks *[]Block, blocksOrder *map[common.Hash][]Order) error {
	switch vLog.Topics[0] {
	case sequencedBatchesEventSignatureHash:
		return etherMan.sequencedBatchesEvent(ctx, vLog, blocks, blocksOrder)
	case updateGlobalExitRootSignatureHash:
		return etherMan.updateGlobalExitRootEvent(ctx, vLog, blocks, blocksOrder)
	case forcedBatchSignatureHash:
		return etherMan.forcedBatchEvent(ctx, vLog, blocks, blocksOrder)
	case verifyBatchesTrustedAggregatorSignatureHash:
		return etherMan.verifyBatchesTrustedAggregatorEvent(ctx, vLog, blocks, blocksOrder)
	case verifyBatchesSignatureHash:
		log.Warn("VerifyBatches event not implemented yet")
		return nil
	case forceSequencedBatchesSignatureHash:
		return etherMan.forceSequencedBatchesEvent(ctx, vLog, blocks, blocksOrder)
	case setTrustedSequencerURLSignatureHash:
		log.Debug("SetTrustedSequencerURL event detected")
		return nil
	case setForceBatchAllowedSignatureHash:
		log.Debug("SetForceBatchAllowed event detected")
		return nil
	case setTrustedSequencerSignatureHash:
		log.Debug("SetTrustedSequencer event detected")
		return nil
	case initializedSignatureHash:
		log.Debug("Initialized event detected")
		return nil
	case adminChangedSignatureHash:
		log.Debug("AdminChanged event detected")
		return nil
	case beaconUpgradedSignatureHash:
		log.Debug("BeaconUpgraded event detected")
		return nil
	case upgradedSignatureHash:
		log.Debug("Upgraded event detected")
		return nil
	case transferOwnershipSignatureHash:
		log.Debug("TransferOwnership event detected")
		return nil
	case setSecurityCouncilSignatureHash:
		log.Debug("SetSecurityCouncil event detected")
		return nil
	case proofDifferentStateSignatureHash:
		log.Debug("ProofDifferentState event detected")
		return nil
	case emergencyStateActivatedSignatureHash:
		log.Debug("EmergencyStateActivated event detected")
		return nil
	case emergencyStateDeactivatedSignatureHash:
		log.Debug("EmergencyStateDeactivated event detected")
		return nil
	case updateZkEVMVersionSignatureHash:
		log.Debug("UpdateZkEVMVersion event detected")
		return nil
	}
	log.Warn("Event not registered: ", vLog)
	return nil
}

// TronParseUpdateGlobalExitRoot is a log parse operation binding the contract event 0x61014378f82a0d809aefaf87a8ac9505b89c321808287a6e7810f29304c1fce3.
//
// Solidity: event UpdateGlobalExitRoot(bytes32 indexed mainnetExitRoot, bytes32 indexed rollupExitRoot)
func (etherMan *Client) TronParseUpdateGlobalExitRoot(log types.Log) (*polygonzkevmglobalexitroot.PolygonzkevmglobalexitrootUpdateGlobalExitRoot, error) {
	event := new(polygonzkevmglobalexitroot.PolygonzkevmglobalexitrootUpdateGlobalExitRoot)
	polygonzkevmglobalexitrootABI, err := abi.JSON(strings.NewReader(polygonzkevmglobalexitroot.PolygonzkevmglobalexitrootABI))
	if err != nil {
		return nil, err
	}

	if err := etherMan.TronUnpackLog(polygonzkevmglobalexitrootABI, event, "UpdateGlobalExitRoot", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TronUnpackLog unpacks a retrieved log into the provided output structure.
func (etherMan *Client) TronUnpackLog(tronABI abi.ABI, out interface{}, event string, log types.Log) error {
	if log.Topics[0] != tronABI.Events[event].ID {
		return fmt.Errorf("event signature mismatch")
	}
	if len(log.Data) > 0 {
		if err := tronABI.UnpackIntoInterface(out, event, log.Data); err != nil {
			return err
		}
	}
	var indexed abi.Arguments
	for _, arg := range tronABI.Events[event].Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}
	return abi.ParseTopics(out, indexed, log.Topics[1:])
}

func (etherMan *Client) updateGlobalExitRootEvent(ctx context.Context, vLog types.Log, blocks *[]Block, blocksOrder *map[common.Hash][]Order) error {
	log.Debug("UpdateGlobalExitRoot event detected")
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		globalExitRoot, err := etherMan.GlobalExitRootManager.ParseUpdateGlobalExitRoot(vLog)
		if err != nil {
			return err
		}
		fullBlock, err := etherMan.EthClient.BlockByHash(ctx, vLog.BlockHash)
		if err != nil {
			return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
		}
		var gExitRoot GlobalExitRoot
		gExitRoot.MainnetExitRoot = common.BytesToHash(globalExitRoot.MainnetExitRoot[:])
		gExitRoot.RollupExitRoot = common.BytesToHash(globalExitRoot.RollupExitRoot[:])
		gExitRoot.BlockNumber = vLog.BlockNumber
		gExitRoot.GlobalExitRoot = hash(globalExitRoot.MainnetExitRoot, globalExitRoot.RollupExitRoot)

		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			t := time.Unix(int64(fullBlock.Time()), 0)
			block := prepareBlock(vLog, t, fullBlock)
			block.GlobalExitRoots = append(block.GlobalExitRoots, gExitRoot)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].GlobalExitRoots = append((*blocks)[len(*blocks)-1].GlobalExitRoots, gExitRoot)
		} else {
			log.Error("Error processing UpdateGlobalExitRoot event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing UpdateGlobalExitRoot event")
		}
		or := Order{
			Name: GlobalExitRootsOrder,
			Pos:  len((*blocks)[len(*blocks)-1].GlobalExitRoots) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)
		return nil
	case "Tron":
		globalExitRoot, err := etherMan.TronParseUpdateGlobalExitRoot(vLog)
		if err != nil {
			return err
		}
		fullBlock, err := etherMan.TronBlockByHash(vLog.BlockHash)
		if err != nil {
			return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
		}
		var gExitRoot GlobalExitRoot
		gExitRoot.MainnetExitRoot = common.BytesToHash(globalExitRoot.MainnetExitRoot[:])
		gExitRoot.RollupExitRoot = common.BytesToHash(globalExitRoot.RollupExitRoot[:])
		gExitRoot.BlockNumber = vLog.BlockNumber
		gExitRoot.GlobalExitRoot = hash(globalExitRoot.MainnetExitRoot, globalExitRoot.RollupExitRoot)

		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			t := time.Unix(int64(fullBlock.Time()), 0)
			block := prepareBlock(vLog, t, fullBlock)
			block.GlobalExitRoots = append(block.GlobalExitRoots, gExitRoot)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].GlobalExitRoots = append((*blocks)[len(*blocks)-1].GlobalExitRoots, gExitRoot)
		} else {
			log.Error("Error processing UpdateGlobalExitRoot event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing UpdateGlobalExitRoot event")
		}
		or := Order{
			Name: GlobalExitRootsOrder,
			Pos:  len((*blocks)[len(*blocks)-1].GlobalExitRoots) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)
		return nil
	}
	return errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// WaitTxToBeMined waits for an L1 tx to be mined. It will return error if the tx is reverted or timeout is exceeded
func (etherMan *Client) WaitTxToBeMined(ctx context.Context, tx *types.Transaction, timeout time.Duration) (bool, error) {
	err := operations.WaitTxToBeMined(ctx, etherMan.EthClient, tx, timeout)
	if errors.Is(err, context.DeadlineExceeded) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// EstimateGasSequenceBatches estimates gas for sending batches
func (etherMan *Client) EstimateGasSequenceBatches(sender common.Address, sequences []ethmanTypes.Sequence) (*types.Transaction, error) {
	opts, err := etherMan.getAuthByAddress(sender)
	if err == ErrNotFound {
		return nil, ErrPrivateKeyNotFound
	}
	opts.NoSend = true

	tx, err := etherMan.sequenceBatches(opts, sequences)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

// BuildSequenceBatchesTxData builds a []bytes to be sent to the PoE SC method SequenceBatches.
func (etherMan *Client) BuildSequenceBatchesTxData(sender common.Address, sequences []ethmanTypes.Sequence) (to *common.Address, data []byte, err error) {
	opts, err := etherMan.getAuthByAddress(sender)
	if err == ErrNotFound {
		return nil, nil, fmt.Errorf("failed to build sequence batches, err: %w", ErrPrivateKeyNotFound)
	}
	opts.NoSend = true
	// force nonce, gas limit and gas price to avoid querying it from the chain
	opts.Nonce = big.NewInt(1)
	opts.GasLimit = uint64(1)
	opts.GasPrice = big.NewInt(1)

	tx, err := etherMan.sequenceBatches(opts, sequences)
	if err != nil {
		return nil, nil, err
	}

	return tx.To(), tx.Data(), nil
}

func (etherMan *Client) sequenceBatches(opts bind.TransactOpts, sequences []ethmanTypes.Sequence) (*types.Transaction, error) {
	var batches []polygonzkevm.PolygonZkEVMBatchData
	for _, seq := range sequences {
		batch := polygonzkevm.PolygonZkEVMBatchData{
			Transactions:       seq.BatchL2Data,
			GlobalExitRoot:     seq.GlobalExitRoot,
			Timestamp:          uint64(seq.Timestamp),
			MinForcedTimestamp: uint64(seq.ForcedBatchTimestamp),
		}

		batches = append(batches, batch)
	}

	tx, err := etherMan.PoE.SequenceBatches(&opts, batches, opts.From)
	if err != nil {
		if parsedErr, ok := tryParseError(err); ok {
			err = parsedErr
		}
	}

	return tx, err
}

// BuildTrustedVerifyBatchesTxData builds a []bytes to be sent to the PoE SC method TrustedVerifyBatches.
func (etherMan *Client) BuildTrustedVerifyBatchesTxData(lastVerifiedBatch, newVerifiedBatch uint64, inputs *ethmanTypes.FinalProofInputs) (to *common.Address, data []byte, err error) {
	opts, err := etherMan.generateRandomAuth()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build trusted verify batches, err: %w", err)
	}
	opts.NoSend = true
	// force nonce, gas limit and gas price to avoid querying it from the chain
	opts.Nonce = big.NewInt(1)
	opts.GasLimit = uint64(1)
	opts.GasPrice = big.NewInt(1)

	var newLocalExitRoot [32]byte
	copy(newLocalExitRoot[:], inputs.NewLocalExitRoot)

	var newStateRoot [32]byte
	copy(newStateRoot[:], inputs.NewStateRoot)

	log.Info("Proof before trim: %v", inputs.FinalProof.Proof)
	proof, err := encoding.DecodeBytes(&inputs.FinalProof.Proof)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode proof, err: %w", err)
	}
	log.Info("Proof after trim: %v", common.Bytes2Hex(proof))

	const pendStateNum = 0 // TODO hardcoded for now until we implement the pending state feature

	tx, err := etherMan.PoE.VerifyBatchesTrustedAggregator(
		&opts,
		pendStateNum,
		lastVerifiedBatch,
		newVerifiedBatch,
		newLocalExitRoot,
		newStateRoot,
		proof,
	)
	if err != nil {
		if parsedErr, ok := tryParseError(err); ok {
			err = parsedErr
		}
		return nil, nil, err
	}

	return tx.To(), tx.Data(), nil
}

// GetSendSequenceFee get super/trusted sequencer fee
func (etherMan *Client) GetSendSequenceFee(numBatches uint64) (*big.Int, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		f, err := etherMan.PoE.GetCurrentBatchFee(&bind.CallOpts{Pending: false})
		if err != nil {
			return nil, err
		}
		fee := new(big.Int).Mul(f, new(big.Int).SetUint64(numBatches))
		return fee, nil
	case "Tron":
		polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
		if err != nil {
			return nil, err
		}
		callData, err := polygonzkevmABI.Pack("getCurrentBatchFee")
		if err != nil {
			return nil, err
		}
		data, err := etherMan.TronRPCClient.TriggerConstantContract(etherMan.cfg.PoEAddr.String(), callData)
		if err != nil {
			return nil, err
		}

		ret := new(big.Int)
		if err = polygonzkevmABI.UnpackIntoInterface(ret, "getCurrentBatchFee", data); err != nil {
			return nil, err
		}
		return ret, nil
	}
	return nil, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// TrustedSequencer gets trusted sequencer address
func (etherMan *Client) TrustedSequencer() (common.Address, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		return etherMan.PoE.TrustedSequencer(&bind.CallOpts{Pending: false})
	case "Tron":
		polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
		if err != nil {
			return common.Address{}, err
		}
		callData, err := polygonzkevmABI.Pack("trustedSequencer")
		if err != nil {
			return common.Address{}, err
		}

		data, err := etherMan.TronRPCClient.TriggerConstantContract(etherMan.cfg.PoEAddr.String(), callData)
		if err != nil {
			return common.Address{}, err
		}

		ret := new(common.Address)
		if err = polygonzkevmABI.UnpackIntoInterface(ret, "trustedSequencer", data); err != nil {
			return common.Address{}, err
		}

		return *ret, nil
	}
	return common.Address{}, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// TronParseForceBatch is a log parse operation binding the contract event 0xf94bb37db835f1ab585ee00041849a09b12cd081d77fa15ca070757619cbc931.
//
// Solidity: event ForceBatch(uint64 indexed forceBatchNum, bytes32 lastGlobalExitRoot, address sequencer, bytes transactions)
func (etherMan *Client) TronParseForceBatch(log types.Log) (*polygonzkevm.PolygonzkevmForceBatch, error) {
	event := new(polygonzkevm.PolygonzkevmForceBatch)
	polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
	if err != nil {
		return nil, err
	}
	if err := etherMan.UnpackLog(polygonzkevmABI, event, "ForceBatch", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

func (etherMan *Client) forcedBatchEvent(ctx context.Context, vLog types.Log, blocks *[]Block, blocksOrder *map[common.Hash][]Order) error {
	log.Debug("ForceBatch event detected")
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		fb, err := etherMan.PoE.ParseForceBatch(vLog)
		if err != nil {
			return err
		}
		var forcedBatch ForcedBatch
		forcedBatch.BlockNumber = vLog.BlockNumber
		forcedBatch.ForcedBatchNumber = fb.ForceBatchNum
		forcedBatch.GlobalExitRoot = fb.LastGlobalExitRoot
		// Read the tx for this batch.
		tx, isPending, err := etherMan.EthClient.TransactionByHash(ctx, vLog.TxHash)
		if err != nil {
			return err
		} else if isPending {
			return fmt.Errorf("error: tx is still pending. TxHash: %s", tx.Hash().String())
		}
		msg, err := tx.AsMessage(types.NewLondonSigner(tx.ChainId()), big.NewInt(0))
		if err != nil {
			return err
		}
		if fb.Sequencer == msg.From() {
			txData := tx.Data()
			// Extract coded txs.
			// Load contract ABI
			abi, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
			if err != nil {
				return err
			}

			// Recover Method from signature and ABI
			method, err := abi.MethodById(txData[:4])
			if err != nil {
				return err
			}

			// Unpack method inputs
			data, err := method.Inputs.Unpack(txData[4:])
			if err != nil {
				return err
			}
			bytedata := data[0].([]byte)
			forcedBatch.RawTxsData = bytedata
		} else {
			forcedBatch.RawTxsData = fb.Transactions
		}
		forcedBatch.Sequencer = fb.Sequencer
		fullBlock, err := etherMan.EthClient.BlockByHash(ctx, vLog.BlockHash)
		if err != nil {
			return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
		}
		t := time.Unix(int64(fullBlock.Time()), 0)
		forcedBatch.ForcedAt = t
		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			block := prepareBlock(vLog, t, fullBlock)
			block.ForcedBatches = append(block.ForcedBatches, forcedBatch)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].ForcedBatches = append((*blocks)[len(*blocks)-1].ForcedBatches, forcedBatch)
		} else {
			log.Error("Error processing ForceBatch event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing ForceBatch event")
		}
		or := Order{
			Name: ForcedBatchesOrder,
			Pos:  len((*blocks)[len(*blocks)-1].ForcedBatches) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)
		return nil
	case "Tron":
		fb, err := etherMan.TronParseForceBatch(vLog)
		if err != nil {
			return err
		}
		var forcedBatch ForcedBatch
		forcedBatch.BlockNumber = vLog.BlockNumber
		forcedBatch.ForcedBatchNumber = fb.ForceBatchNum
		forcedBatch.GlobalExitRoot = fb.LastGlobalExitRoot
		// Read the tx for this batch.
		tx, isPending, err := etherMan.TronTransactionByHash(vLog.TxHash)
		if err != nil {
			return err
		} else if isPending {
			return fmt.Errorf("error: tx is still pending. TxHash: %s", tx.Hash().String())
		}
		msg, err := tx.AsMessage(types.NewLondonSigner(tx.ChainId()), big.NewInt(0))
		if err != nil {
			return err
		}
		if fb.Sequencer == msg.From() {
			txData := tx.Data()
			// Extract coded txs.
			// Load contract ABI
			abi, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
			if err != nil {
				return err
			}

			// Recover Method from signature and ABI
			method, err := abi.MethodById(txData[:4])
			if err != nil {
				return err
			}

			// Unpack method inputs
			data, err := method.Inputs.Unpack(txData[4:])
			if err != nil {
				return err
			}
			bytedata := data[0].([]byte)
			forcedBatch.RawTxsData = bytedata
		} else {
			forcedBatch.RawTxsData = fb.Transactions
		}
		forcedBatch.Sequencer = fb.Sequencer
		fullBlock, err := etherMan.TronBlockByHash(vLog.BlockHash)
		if err != nil {
			return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
		}
		t := time.Unix(int64(fullBlock.Time()), 0)
		forcedBatch.ForcedAt = t
		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			block := prepareBlock(vLog, t, fullBlock)
			block.ForcedBatches = append(block.ForcedBatches, forcedBatch)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].ForcedBatches = append((*blocks)[len(*blocks)-1].ForcedBatches, forcedBatch)
		} else {
			log.Error("Error processing ForceBatch event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing ForceBatch event")
		}
		or := Order{
			Name: ForcedBatchesOrder,
			Pos:  len((*blocks)[len(*blocks)-1].ForcedBatches) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)

		return nil
	}
	return errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// TronParseSequenceBatches is a log parse operation binding the contract event 0x303446e6a8cb73c83dff421c0b1d5e5ce0719dab1bff13660fc254e58cc17fce.
//
// Solidity: event SequenceBatches(uint64 indexed numBatch)
func (etherMan *Client) TronParseSequenceBatches(log types.Log) (*polygonzkevm.PolygonzkevmSequenceBatches, error) {
	event := new(polygonzkevm.PolygonzkevmSequenceBatches)
	polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
	if err != nil {
		return nil, err
	}
	if err := etherMan.UnpackLog(polygonzkevmABI, event, "SequenceBatches", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// UnpackLog unpacks a retrieved log into the provided output structure.
func (etherMan *Client) UnpackLog(contractABI abi.ABI, out interface{}, event string, log types.Log) error {
	if log.Topics[0] != contractABI.Events[event].ID {
		return fmt.Errorf("event signature mismatch")
	}
	if len(log.Data) > 0 {
		if err := contractABI.UnpackIntoInterface(out, event, log.Data); err != nil {
			return err
		}
	}
	var indexed abi.Arguments
	for _, arg := range contractABI.Events[event].Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}
	return abi.ParseTopics(out, indexed, log.Topics[1:])
}

type rpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

func UnmarshalRPCTxJSON(tx *rpcTransaction, msg []byte) (*types.Transaction, error) {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return nil, err
	}
	return tx.tx, json.Unmarshal(msg, &tx.txExtraInfo)
}

type FilterRPCTxResponse struct {
	tron.BaseQueryParam
	Result rpcTransaction `json:result`
}
type rpcBlock struct {
	Hash         common.Hash         `json:"hash"`
	Transactions []rpcTransaction    `json:"transactions"`
	UncleHashes  []common.Hash       `json:"uncles"`
	Withdrawals  []*types.Withdrawal `json:"withdrawals,omitempty"`
}
type rpcBlockAndHeader struct {
	head TronHeader
	rpcBlock
}
type FilterBlockResponse struct {
	tron.BaseQueryParam
	Result rpcBlockAndHeader `json:result`
}
type FilterTronHeaderResponse struct {
	tron.BaseQueryParam
	Result TronHeader `json:result`
}

// Tron Header represents a block header in the Ethereum blockchain.
type TronHeader struct {
	ParentHash  common.Hash      `json:"parentHash"       gencodec:"required"`
	UncleHash   common.Hash      `json:"sha3Uncles"       gencodec:"required"`
	Coinbase    common.Address   `json:"miner"`
	Root        string           `json:"stateRoot"        gencodec:"required"` //TODO. ZYD. the result format should be 64bit hash
	TxHash      common.Hash      `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash common.Hash      `json:"receiptsRoot"     gencodec:"required"`
	Bloom       types.Bloom      `json:"logsBloom"        gencodec:"required"`
	Difficulty  string           `json:"difficulty"       gencodec:"required"` //TODO. ZYD. the result format not right
	Number      string           `json:"number"           gencodec:"required"` //TODO. ZYD. the result format not right
	GasLimit    string           `json:"gasLimit"         gencodec:"required"` //TODO. ZYD. the result format not right
	GasUsed     string           `json:"gasUsed"          gencodec:"required"` //TODO. ZYD. the result format not right
	Time        string           `json:"timestamp"        gencodec:"required"` //TODO. ZYD. the result format not right
	Extra       string           `json:"extraData"        gencodec:"required"` //TODO. ZYD. the result format not right
	MixDigest   common.Hash      `json:"mixHash"`
	Nonce       types.BlockNonce `json:"nonce"`

	// BaseFee was added by EIP-1559 and is ignored in legacy headers.
	BaseFee string `json:"baseFeePerGas" rlp:"optional"` //TODO. ZYD. the result format not right

	// WithdrawalsHash was added by EIP-4895 and is ignored in legacy headers.
	WithdrawalsHash *common.Hash `json:"withdrawalsRoot" rlp:"optional"`

	/*
		TODO (MariusVanDerWijden) Add this field once needed
		// Random was added during the merge and contains the BeaconState randomness
		Random common.Hash `json:"random" rlp:"optional"`
	*/
}

// TronTransactionByHash returns the transaction with the given hash.
func (etherMan *Client) TronTransactionByHash(hash common.Hash) (tx *types.Transaction, isPending bool, err error) {
	var params = []string{hash.Hex()}
	queryFilter := tron.FilterOtherParams{
		BaseQueryParam: tron.GetDefaultBaseParm(),
		Method:         tron.GetTransactionByHash,
		Params:         params,
	}
	result, err := QueryTronInfo(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, queryFilter)
	if errors.Is(err, ethereum.NotFound) {
		return nil, false, ethereum.NotFound
	} else if err != nil {
		return nil, false, err
	}
	var transaction FilterRPCTxResponse
	if err := json.Unmarshal(result, &transaction); err != nil {
		return nil, false, err
	}
	var rpcTransactionJson *rpcTransaction
	tx, err = UnmarshalRPCTxJSON(rpcTransactionJson, result)
	if err != nil {
		return nil, false, err
	}
	return tx, transaction.Result.BlockNumber == nil, nil
}

// TronBlockByHash returns the given full block.
//
// Note that loading full blocks requires two requests. Use HeaderByHash
// if you don't need all transactions or uncle headers.
func (etherMan *Client) TronBlockByHash(hash common.Hash) (*types.Block, error) {
	var params = []string{hash.Hex()}
	params = append(params, "true") //set true to get full block
	queryFilter := tron.FilterOtherParams{
		BaseQueryParam: tron.GetDefaultBaseParm(),
		Method:         tron.BlockByHash,
		Params:         params,
	}
	raw, err := QueryTronInfo(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, queryFilter)
	if err != nil {
		return nil, err
	}
	return parseTronBlock(raw)
}
func (etherMan *Client) sequencedBatchesEvent(ctx context.Context, vLog types.Log, blocks *[]Block, blocksOrder *map[common.Hash][]Order) error {
	log.Debug("SequenceBatches event detected")
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		sb, err := etherMan.PoE.ParseSequenceBatches(vLog)
		if err != nil {
			return err
		}
		// Read the tx for this event.
		tx, isPending, err := etherMan.EthClient.TransactionByHash(ctx, vLog.TxHash)
		if err != nil {
			return err
		} else if isPending {
			return fmt.Errorf("error tx is still pending. TxHash: %s", tx.Hash().String())
		}
		msg, err := tx.AsMessage(types.NewLondonSigner(tx.ChainId()), big.NewInt(0))
		if err != nil {
			return err
		}
		sequences, err := decodeSequences(tx.Data(), sb.NumBatch, msg.From(), vLog.TxHash, msg.Nonce())
		if err != nil {
			return fmt.Errorf("error decoding the sequences: %v", err)
		}

		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			fullBlock, err := etherMan.EthClient.BlockByHash(ctx, vLog.BlockHash)
			if err != nil {
				return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
			}
			block := prepareBlock(vLog, time.Unix(int64(fullBlock.Time()), 0), fullBlock)
			block.SequencedBatches = append(block.SequencedBatches, sequences)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].SequencedBatches = append((*blocks)[len(*blocks)-1].SequencedBatches, sequences)
		} else {
			log.Error("Error processing SequencedBatches event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing SequencedBatches event")
		}
		or := Order{
			Name: SequenceBatchesOrder,
			Pos:  len((*blocks)[len(*blocks)-1].SequencedBatches) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)
		return nil
	case "Tron":
		sb, err := etherMan.TronParseSequenceBatches(vLog)
		if err != nil {
			return err
		}
		// Read the tx for this event.
		tx, isPending, err := etherMan.TronTransactionByHash(vLog.TxHash)
		if err != nil {
			return err
		} else if isPending {
			return fmt.Errorf("error tx is still pending. TxHash: %s", tx.Hash().String())
		}
		msg, err := tx.AsMessage(types.NewLondonSigner(tx.ChainId()), big.NewInt(0))
		if err != nil {
			return err
		}
		sequences, err := decodeSequences(tx.Data(), sb.NumBatch, msg.From(), vLog.TxHash, msg.Nonce())
		if err != nil {
			return fmt.Errorf("error decoding the sequences: %v", err)
		}
		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			fullBlock, err := etherMan.TronBlockByHash(vLog.BlockHash)
			if err != nil {
				return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
			}
			block := prepareBlock(vLog, time.Unix(int64(fullBlock.Time()), 0), fullBlock)
			block.SequencedBatches = append(block.SequencedBatches, sequences)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].SequencedBatches = append((*blocks)[len(*blocks)-1].SequencedBatches, sequences)
		} else {
			log.Error("Error processing SequencedBatches event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing SequencedBatches event")
		}
		or := Order{
			Name: SequenceBatchesOrder,
			Pos:  len((*blocks)[len(*blocks)-1].SequencedBatches) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)
		return nil
	}
	return errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

func decodeSequences(txData []byte, lastBatchNumber uint64, sequencer common.Address, txHash common.Hash, nonce uint64) ([]SequencedBatch, error) {
	// Extract coded txs.
	// Load contract ABI
	abi, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
	if err != nil {
		return nil, err
	}

	// Recover Method from signature and ABI
	method, err := abi.MethodById(txData[:4])
	if err != nil {
		return nil, err
	}

	// Unpack method inputs
	data, err := method.Inputs.Unpack(txData[4:])
	if err != nil {
		return nil, err
	}
	var sequences []polygonzkevm.PolygonZkEVMBatchData
	bytedata, err := json.Marshal(data[0])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytedata, &sequences)
	if err != nil {
		return nil, err
	}
	coinbase := (data[1]).(common.Address)
	sequencedBatches := make([]SequencedBatch, len(sequences))
	for i, seq := range sequences {
		bn := lastBatchNumber - uint64(len(sequences)-(i+1))
		sequencedBatches[i] = SequencedBatch{
			BatchNumber:           bn,
			SequencerAddr:         sequencer,
			TxHash:                txHash,
			Nonce:                 nonce,
			Coinbase:              coinbase,
			PolygonZkEVMBatchData: seq,
		}
	}

	return sequencedBatches, nil
}

// TronParseVerifyBatchesTrustedAggregator is a log parse operation binding the contract event 0xcb339b570a7f0b25afa7333371ff11192092a0aeace12b671f4c212f2815c6fe.
//
// Solidity: event VerifyBatchesTrustedAggregator(uint64 indexed numBatch, bytes32 stateRoot, address indexed aggregator)
func (etherMan *Client) TronParseVerifyBatchesTrustedAggregator(log types.Log) (*polygonzkevm.PolygonzkevmVerifyBatchesTrustedAggregator, error) {
	event := new(polygonzkevm.PolygonzkevmVerifyBatchesTrustedAggregator)
	polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
	if err != nil {
		return nil, err
	}
	if err := etherMan.UnpackLog(polygonzkevmABI, event, "VerifyBatchesTrustedAggregator", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
func (etherMan *Client) verifyBatchesTrustedAggregatorEvent(ctx context.Context, vLog types.Log, blocks *[]Block, blocksOrder *map[common.Hash][]Order) error {
	log.Debug("TrustedVerifyBatches event detected")
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		vb, err := etherMan.PoE.ParseVerifyBatchesTrustedAggregator(vLog)
		if err != nil {
			return err
		}
		var trustedVerifyBatch VerifiedBatch
		trustedVerifyBatch.BlockNumber = vLog.BlockNumber
		trustedVerifyBatch.BatchNumber = vb.NumBatch
		trustedVerifyBatch.TxHash = vLog.TxHash
		trustedVerifyBatch.StateRoot = vb.StateRoot
		trustedVerifyBatch.Aggregator = vb.Aggregator

		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			fullBlock, err := etherMan.EthClient.BlockByHash(ctx, vLog.BlockHash)
			if err != nil {
				return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
			}
			block := prepareBlock(vLog, time.Unix(int64(fullBlock.Time()), 0), fullBlock)
			block.VerifiedBatches = append(block.VerifiedBatches, trustedVerifyBatch)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].VerifiedBatches = append((*blocks)[len(*blocks)-1].VerifiedBatches, trustedVerifyBatch)
		} else {
			log.Error("Error processing trustedVerifyBatch event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing trustedVerifyBatch event")
		}
		or := Order{
			Name: TrustedVerifyBatchOrder,
			Pos:  len((*blocks)[len(*blocks)-1].VerifiedBatches) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)
		return nil
	case "Tron":
		vb, err := etherMan.TronParseVerifyBatchesTrustedAggregator(vLog)
		if err != nil {
			return err
		}
		var trustedVerifyBatch VerifiedBatch
		trustedVerifyBatch.BlockNumber = vLog.BlockNumber
		trustedVerifyBatch.BatchNumber = vb.NumBatch
		trustedVerifyBatch.TxHash = vLog.TxHash
		trustedVerifyBatch.StateRoot = vb.StateRoot
		trustedVerifyBatch.Aggregator = vb.Aggregator

		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			fullBlock, err := etherMan.TronBlockByHash(vLog.BlockHash)
			if err != nil {
				return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
			}
			block := prepareBlock(vLog, time.Unix(int64(fullBlock.Time()), 0), fullBlock)
			block.VerifiedBatches = append(block.VerifiedBatches, trustedVerifyBatch)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].VerifiedBatches = append((*blocks)[len(*blocks)-1].VerifiedBatches, trustedVerifyBatch)
		} else {
			log.Error("Error processing trustedVerifyBatch event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing trustedVerifyBatch event")
		}
		or := Order{
			Name: TrustedVerifyBatchOrder,
			Pos:  len((*blocks)[len(*blocks)-1].VerifiedBatches) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)

		return nil
	}
	return errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// TronParseSequenceForceBatches is a log parse operation binding the contract event 0x648a61dd2438f072f5a1960939abd30f37aea80d2e94c9792ad142d3e0a490a4.
//
// Solidity: event SequenceForceBatches(uint64 indexed numBatch)
func (etherMan *Client) TronParseSequenceForceBatches(log types.Log) (*polygonzkevm.PolygonzkevmSequenceForceBatches, error) {
	event := new(polygonzkevm.PolygonzkevmSequenceForceBatches)
	polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
	if err != nil {
		return nil, err
	}
	if err := etherMan.UnpackLog(polygonzkevmABI, event, "SequenceForceBatches", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

func (etherMan *Client) forceSequencedBatchesEvent(ctx context.Context, vLog types.Log, blocks *[]Block, blocksOrder *map[common.Hash][]Order) error {
	log.Debug("SequenceForceBatches event detect")
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		fsb, err := etherMan.PoE.ParseSequenceForceBatches(vLog)
		if err != nil {
			return err
		}

		// Read the tx for this batch.
		tx, isPending, err := etherMan.EthClient.TransactionByHash(ctx, vLog.TxHash)
		if err != nil {
			return err
		} else if isPending {
			return fmt.Errorf("error: tx is still pending. TxHash: %s", tx.Hash().String())
		}
		msg, err := tx.AsMessage(types.NewLondonSigner(tx.ChainId()), big.NewInt(0))
		if err != nil {
			return err
		}
		fullBlock, err := etherMan.EthClient.BlockByHash(ctx, vLog.BlockHash)
		if err != nil {
			return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
		}
		sequencedForceBatch, err := decodeSequencedForceBatches(tx.Data(), fsb.NumBatch, msg.From(), vLog.TxHash, fullBlock, msg.Nonce())
		if err != nil {
			return err
		}

		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			block := prepareBlock(vLog, time.Unix(int64(fullBlock.Time()), 0), fullBlock)
			block.SequencedForceBatches = append(block.SequencedForceBatches, sequencedForceBatch)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].SequencedForceBatches = append((*blocks)[len(*blocks)-1].SequencedForceBatches, sequencedForceBatch)
		} else {
			log.Error("Error processing ForceSequencedBatches event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing ForceSequencedBatches event")
		}
		or := Order{
			Name: SequenceForceBatchesOrder,
			Pos:  len((*blocks)[len(*blocks)-1].SequencedForceBatches) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)

		return nil
	case "Tron":
		fsb, err := etherMan.TronParseSequenceForceBatches(vLog)
		if err != nil {
			return err
		}

		// Read the tx for this batch.
		tx, isPending, err := etherMan.TronTransactionByHash(vLog.TxHash)
		if err != nil {
			return err
		} else if isPending {
			return fmt.Errorf("error: tx is still pending. TxHash: %s", tx.Hash().String())
		}
		msg, err := tx.AsMessage(types.NewLondonSigner(tx.ChainId()), big.NewInt(0))
		if err != nil {
			return err
		}
		fullBlock, err := etherMan.TronBlockByHash(vLog.BlockHash)
		if err != nil {
			return fmt.Errorf("error getting hashParent. BlockNumber: %d. Error: %w", vLog.BlockNumber, err)
		}
		sequencedForceBatch, err := decodeSequencedForceBatches(tx.Data(), fsb.NumBatch, msg.From(), vLog.TxHash, fullBlock, msg.Nonce())
		if err != nil {
			return err
		}

		if len(*blocks) == 0 || ((*blocks)[len(*blocks)-1].BlockHash != vLog.BlockHash || (*blocks)[len(*blocks)-1].BlockNumber != vLog.BlockNumber) {
			block := prepareBlock(vLog, time.Unix(int64(fullBlock.Time()), 0), fullBlock)
			block.SequencedForceBatches = append(block.SequencedForceBatches, sequencedForceBatch)
			*blocks = append(*blocks, block)
		} else if (*blocks)[len(*blocks)-1].BlockHash == vLog.BlockHash && (*blocks)[len(*blocks)-1].BlockNumber == vLog.BlockNumber {
			(*blocks)[len(*blocks)-1].SequencedForceBatches = append((*blocks)[len(*blocks)-1].SequencedForceBatches, sequencedForceBatch)
		} else {
			log.Error("Error processing ForceSequencedBatches event. BlockHash:", vLog.BlockHash, ". BlockNumber: ", vLog.BlockNumber)
			return fmt.Errorf("error processing ForceSequencedBatches event")
		}
		or := Order{
			Name: SequenceForceBatchesOrder,
			Pos:  len((*blocks)[len(*blocks)-1].SequencedForceBatches) - 1,
		}
		(*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash] = append((*blocksOrder)[(*blocks)[len(*blocks)-1].BlockHash], or)

		return nil
	}
	return errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

func decodeSequencedForceBatches(txData []byte, lastBatchNumber uint64, sequencer common.Address, txHash common.Hash, block *types.Block, nonce uint64) ([]SequencedForceBatch, error) {
	// Extract coded txs.
	// Load contract ABI
	abi, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
	if err != nil {
		return nil, err
	}

	// Recover Method from signature and ABI
	method, err := abi.MethodById(txData[:4])
	if err != nil {
		return nil, err
	}

	// Unpack method inputs
	data, err := method.Inputs.Unpack(txData[4:])
	if err != nil {
		return nil, err
	}

	var forceBatches []polygonzkevm.PolygonZkEVMForcedBatchData
	bytedata, err := json.Marshal(data[0])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytedata, &forceBatches)
	if err != nil {
		return nil, err
	}

	sequencedForcedBatches := make([]SequencedForceBatch, len(forceBatches))
	for i, force := range forceBatches {
		bn := lastBatchNumber - uint64(len(forceBatches)-(i+1))
		sequencedForcedBatches[i] = SequencedForceBatch{
			BatchNumber:                 bn,
			Coinbase:                    sequencer,
			TxHash:                      txHash,
			Timestamp:                   time.Unix(int64(block.Time()), 0),
			Nonce:                       nonce,
			PolygonZkEVMForcedBatchData: force,
		}
	}
	return sequencedForcedBatches, nil
}

func prepareBlock(vLog types.Log, t time.Time, fullBlock *types.Block) Block {
	var block Block
	block.BlockNumber = vLog.BlockNumber
	block.BlockHash = vLog.BlockHash
	block.ParentHash = fullBlock.ParentHash()
	block.ReceivedAt = t
	return block
}

func hash(data ...[32]byte) [32]byte {
	var res [32]byte
	hash := sha3.NewLegacyKeccak256()
	for _, d := range data {
		hash.Write(d[:]) //nolint:errcheck,gosec
	}
	copy(res[:], hash.Sum(nil))
	return res
}

func TronHeader2EthHeader(tronHeader *TronHeader) (*types.Header, error) {
	var ethHeader types.Header

	ethHeader.ParentHash = tronHeader.ParentHash
	ethHeader.UncleHash = tronHeader.UncleHash
	ethHeader.Coinbase = tronHeader.Coinbase
	ethHeader.Root = common.HexToHash(tronHeader.Root)
	ethHeader.TxHash = tronHeader.TxHash
	ethHeader.ReceiptHash = tronHeader.ReceiptHash
	ethHeader.Bloom = tronHeader.Bloom

	str := tronHeader.Difficulty
	base := 10
	if strings.HasPrefix(str, "0x") {
		str = str[2:]
		base = 16
	}
	difficulty, ok := new(big.Int).SetString(str, base)
	if !ok {
		return nil, fmt.Errorf("could not parse tronHeader.Difficulty")
	}
	ethHeader.Difficulty = difficulty

	str = tronHeader.Number
	base = 10
	if strings.HasPrefix(str, "0x") {
		str = str[2:]
		base = 16
	}
	number, ok := new(big.Int).SetString(str, base)
	if !ok {
		return nil, fmt.Errorf("could not parse tronHeader.number")
	}
	ethHeader.Number = number

	str = tronHeader.GasLimit
	base = 10
	if strings.HasPrefix(str, "0x") {
		str = str[2:]
		base = 16
	}

	gasLimit, err := strconv.ParseUint(str, base, 0)
	if err != nil {
		return nil, fmt.Errorf("could not parse tronHeader.GasLimit, err:", err)
	}
	ethHeader.GasLimit = gasLimit

	str = tronHeader.GasUsed
	base = 10
	if strings.HasPrefix(str, "0x") {
		str = str[2:]
		base = 16
	}
	gasUsed, err := strconv.ParseUint(str, base, 0)
	if err != nil {
		return nil, fmt.Errorf("could not parse tronHeader.GasUsed, err:", err)
	}
	ethHeader.GasUsed = gasUsed

	str = tronHeader.Time
	base = 10
	if strings.HasPrefix(str, "0x") {
		str = str[2:]
		base = 16
	}
	time, err := strconv.ParseUint(str, 16, 0)
	if err != nil {
		return nil, fmt.Errorf("could not parse tronHeader.Time, err:", err)
	}
	ethHeader.Time = time

	str = strings.TrimPrefix(tronHeader.Extra, "0x")
	extra, err := hex.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf("could not parse tronHeader.Extra, err:", err)
	}
	ethHeader.Extra = extra
	ethHeader.MixDigest = tronHeader.MixDigest
	ethHeader.Nonce = tronHeader.Nonce

	str = tronHeader.BaseFee
	base = 10
	if strings.HasPrefix(str, "0x") {
		str = str[2:]
		base = 16
	}
	baseFee, ok := new(big.Int).SetString(str, base)
	if !ok {
		return nil, fmt.Errorf("could not parse tronHeader.BaseFee")
	}
	ethHeader.BaseFee = baseFee

	ethHeader.WithdrawalsHash = tronHeader.WithdrawalsHash

	return &ethHeader, nil
}

// TronHeaderByNumber returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (etherMan *Client) TronHeaderByNumber(number *big.Int) (*types.Header, error) {
	var params = []string{hexutil.EncodeBig(number)}
	params = append(params, "false") //If true it returns the full transaction objects, if false only the hashes of the transactions.
	queryFilter := tron.FilterOtherParams{
		BaseQueryParam: tron.GetDefaultBaseParm(),
		Method:         tron.HeaderByNumber,
		Params:         params,
	}
	raw, err := QueryTronInfo(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, queryFilter)
	fmt.Println(string(raw))
	if err != nil {
		return nil, err
	}

	var tronHeaderResp FilterTronHeaderResponse
	if err := json.Unmarshal(raw, &tronHeaderResp); err != nil {
		return nil, err
	}
	tronHeader := tronHeaderResp.Result
	return TronHeader2EthHeader(&tronHeader)
}

// HeaderByNumber returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (etherMan *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		return etherMan.EthClient.HeaderByNumber(ctx, number)
	case "Tron":
		return etherMan.TronHeaderByNumber(number)
	}
	return nil, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

func parseTronBlock(raw []byte) (*types.Block, error) {
	// Decode header and transactions.
	var head *types.Header
	var body rpcBlock
	var tronHeaderResp FilterTronHeaderResponse
	if err := json.Unmarshal(raw, &tronHeaderResp); err != nil {
		return nil, err
	}
	tronHeader := tronHeaderResp.Result
	head, err := TronHeader2EthHeader(&tronHeader)
	if err != nil {
		return nil, err
	}

	var tronBlockResp FilterBlockResponse
	if err := json.Unmarshal(raw, &tronBlockResp); err != nil {
		return nil, err
	}
	body = tronBlockResp.Result.rpcBlock
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, fmt.Errorf("server returned non-empty uncle list but block header indicates no uncles")
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, fmt.Errorf("server returned empty uncle list but block header indicates uncles")
	}
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, fmt.Errorf("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, fmt.Errorf("server returned empty transaction list but block header indicates transactions")
	}
	// Load uncles because they are not included in the block response.
	var uncles []*types.Header //

	// Fill the sender cache of transactions in the block.
	txs := make([]*types.Transaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		txs[i] = tx.tx
	}
	return types.NewBlockWithHeader(head).WithBody(txs, uncles).WithWithdrawals(body.Withdrawals), nil
}

// TronBlockByNumber returns a block from the current canonical chain. If number is nil, the
// latest known block is returned.
//
// Note that loading full blocks requires two requests. Use HeaderByNumber
// if you don't need all transactions or uncle headers.
func (etherMan *Client) TronBlockByNumber(number *big.Int) (*types.Block, error) {
	var params = []string{hexutil.EncodeBig(number)}
	params = append(params, "true") //If true it returns the full transaction objects, if false only the hashes of the transactions.
	queryFilter := tron.FilterOtherParams{
		BaseQueryParam: tron.GetDefaultBaseParm(),
		Method:         tron.HeaderByNumber,
		Params:         params,
	}
	raw, err := QueryTronInfo(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, queryFilter)
	fmt.Println(string(raw))
	if err != nil {
		return nil, err
	}

	return parseTronBlock(raw)
}

// EthBlockByNumber function retrieves the ethereum block information by ethereum block number.
func (etherMan *Client) EthBlockByNumber(ctx context.Context, blockNumber uint64) (*types.Block, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		block, err := etherMan.EthClient.BlockByNumber(ctx, new(big.Int).SetUint64(blockNumber))
		if err != nil {
			if errors.Is(err, ethereum.NotFound) || err.Error() == "block does not exist in blockchain" {
				return nil, ErrNotFound
			}
			return nil, err
		}
		return block, nil
	case "Tron":
		block, err := etherMan.TronBlockByNumber(new(big.Int).SetUint64(blockNumber))
		if err != nil {
			if errors.Is(err, ethereum.NotFound) || err.Error() == "block does not exist in blockchain" {
				return nil, ErrNotFound
			}
			return nil, err
		}
		return block, nil
	}
	return nil, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// GetLastBatchTimestamp function allows to retrieve the lastTimestamp value in the smc
func (etherMan *Client) GetLastBatchTimestamp() (uint64, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		return etherMan.PoE.LastTimestamp(&bind.CallOpts{Pending: false})
	case "Tron":
		polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
		if err != nil {
			return 0, err
		}
		callData, err := polygonzkevmABI.Pack("")
		data, err := etherMan.TronRPCClient.TriggerConstantContract(etherMan.cfg.PoEAddr.String(), callData)
		if err != nil {
			return 0, err
		}

		var ret = new(uint64)
		if err = polygonzkevmABI.UnpackIntoInterface(ret, "lastTimestamp", data); err != nil {
			return 0, err
		}
		return *ret, nil

	}
	return 0, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// GetLatestBatchNumber function allows to retrieve the latest proposed batch in the smc
func (etherMan *Client) GetLatestBatchNumber() (uint64, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		return etherMan.PoE.LastBatchSequenced(&bind.CallOpts{Pending: false})
	case "Tron":
		polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
		if err != nil {
			return 0, err
		}
		callData, err := polygonzkevmABI.Pack("lastBatchSequenced")
		data, err := etherMan.TronRPCClient.TriggerConstantContract(etherMan.cfg.PoEAddr.String(), callData)
		if err != nil {
			return 0, err
		}

		var ret = new(uint64)
		if err = polygonzkevmABI.UnpackIntoInterface(ret, "lastBatchSequenced", data); err != nil {
			return 0, nil
		}
		return *ret, nil
	}
	return 0, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// GetLatestBlockNumber gets the latest block number from the ethereum
func (etherMan *Client) GetLatestBlockNumber(ctx context.Context) (uint64, error) {
	header, err := etherMan.EthClient.HeaderByNumber(ctx, nil)
	if err != nil || header == nil {
		return 0, err
	}
	return header.Number.Uint64(), nil
}

// GetLatestBlockTimestamp gets the latest block timestamp from the ethereum
func (etherMan *Client) GetLatestBlockTimestamp(ctx context.Context) (uint64, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		header, err := etherMan.EthClient.HeaderByNumber(ctx, nil)
		if err != nil || header == nil {
			return 0, err
		}
		return header.Time, nil
	case "Tron":
		return etherMan.TronRPCClient.GetLatestBlockTimestamp()
	}
	return 0, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// GetLatestVerifiedBatchNum gets latest verified batch from ethereum
func (etherMan *Client) GetLatestVerifiedBatchNum() (uint64, error) {
	return etherMan.PoE.LastVerifiedBatch(&bind.CallOpts{Pending: false})
}

// GetTx function get ethereum tx
func (etherMan *Client) GetTx(ctx context.Context, txHash common.Hash) (*types.Transaction, bool, error) {
	return etherMan.EthClient.TransactionByHash(ctx, txHash)
}

// GetTxReceipt function gets ethereum tx receipt
func (etherMan *Client) GetTxReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	return etherMan.EthClient.TransactionReceipt(ctx, txHash)
}

// ApproveMatic function allow to approve tokens in matic smc
func (etherMan *Client) ApproveMatic(ctx context.Context, account common.Address, maticAmount *big.Int, to common.Address) (*types.Transaction, error) {
	opts, err := etherMan.getAuthByAddress(account)
	if err == ErrNotFound {
		return nil, errors.New("can't find account private key to sign tx")
	}
	if etherMan.GasProviders.MultiGasProvider {
		opts.GasPrice = etherMan.GetL1GasPrice(ctx)
	}
	tx, err := etherMan.Matic.Approve(&opts, etherMan.cfg.PoEAddr, maticAmount)
	if err != nil {
		if parsedErr, ok := tryParseError(err); ok {
			err = parsedErr
		}
		return nil, fmt.Errorf("error approving balance to send the batch. Error: %w", err)
	}

	return tx, nil
}

// GetTrustedSequencerURL Gets the trusted sequencer url from rollup smc
func (etherMan *Client) GetTrustedSequencerURL() (string, error) {
	return etherMan.PoE.TrustedSequencerURL(&bind.CallOpts{Pending: false})
}

// GetL2ChainID returns L2 Chain ID
func (etherMan *Client) GetL2ChainID() (uint64, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		return etherMan.PoE.ChainID(&bind.CallOpts{Pending: false})
	case "Tron":
		polygonzkevmABI, err := abi.JSON(strings.NewReader(polygonzkevm.PolygonzkevmABI))
		if err != nil {
			return 0, err
		}
		callData, err := polygonzkevmABI.Pack("chainID")
		if err != nil {
			return 0, err
		}
		data, err := etherMan.TronRPCClient.TriggerConstantContract(etherMan.cfg.PoEAddr.String(), callData)
		if err != nil {
			return 0, err
		}

		// Unpack the results
		var (
			ret0 = new(uint64)
		)
		if err = polygonzkevmABI.UnpackIntoInterface(ret0, "chainID", data); err != nil {
			return 0, nil
		}
		return (*ret0), nil
	}
	return 0, nil
}

// GetL2ForkID returns current L2 Fork ID
func (etherMan *Client) GetL2ForkID() (uint64, error) {
	// TODO: implement this
	return 1, nil
}

// GetL2ForkIDIntervals return L2 Fork ID intervals
func (etherMan *Client) GetL2ForkIDIntervals() ([]state.ForkIDInterval, error) {
	// TODO: implement this
	return []state.ForkIDInterval{{FromBatchNumber: 0, ToBatchNumber: math.MaxUint64, ForkId: 1}}, nil
}

// GetL1GasPrice gets the l1 gas price
func (etherMan *Client) GetL1GasPrice(ctx context.Context) *big.Int {
	// Get gasPrice from providers
	gasPrice := big.NewInt(0)
	for i, prov := range etherMan.GasProviders.Providers {
		gp, err := prov.SuggestGasPrice(ctx)
		if err != nil {
			log.Warnf("error getting gas price from provider %d. Error: %s", i+1, err.Error())
		} else if gasPrice.Cmp(gp) == -1 { // gasPrice < gp
			gasPrice = gp
		}
	}
	log.Debug("gasPrice chose: ", gasPrice)
	return gasPrice
}

// SendTx sends a tx to L1
func (etherMan *Client) SendTx(ctx context.Context, tx *types.Transaction) error {
	return etherMan.EthClient.SendTransaction(ctx, tx)
}

// CurrentNonce returns the current nonce for the provided account
func (etherMan *Client) CurrentNonce(ctx context.Context, account common.Address) (uint64, error) {
	return etherMan.EthClient.NonceAt(ctx, account, nil)
}

// SuggestedGasPrice returns the suggest nonce for the network at the moment
func (etherMan *Client) SuggestedGasPrice(ctx context.Context) (*big.Int, error) {
	suggestedGasPrice := etherMan.GetL1GasPrice(ctx)
	if suggestedGasPrice.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("failed to get the suggested gas price")
	}
	return suggestedGasPrice, nil
}

// EstimateGas returns the estimated gas for the tx
func (etherMan *Client) EstimateGas(ctx context.Context, from common.Address, to *common.Address, value *big.Int, data []byte) (uint64, error) {
	return etherMan.EthClient.EstimateGas(ctx, ethereum.CallMsg{
		From:  from,
		To:    to,
		Value: value,
		Data:  data,
	})
}

// CheckTxWasMined check if a tx was already mined
func (etherMan *Client) CheckTxWasMined(ctx context.Context, txHash common.Hash) (bool, *types.Receipt, error) {
	switch etherMan.cfg.L1ChainType {
	case "Eth":
		receipt, err := etherMan.EthClient.TransactionReceipt(ctx, txHash)
		if errors.Is(err, ethereum.NotFound) {
			return false, nil, nil
		} else if err != nil {
			return false, nil, err
		}

		return true, receipt, nil
	case "Tron":
		var txIDs = []string{txHash.Hex()}
		queryFilter := tron.FilterOtherParams{
			BaseQueryParam: tron.GetDefaultBaseParm(),
			Method:         tron.GetTransactionByHash,
			Params:         txIDs,
		}
		result, err := QueryTronInfo(etherMan.cfg.TronGrid.Url, etherMan.cfg.TronGrid.ApiKey, queryFilter)
		if errors.Is(err, ethereum.NotFound) {
			return false, nil, nil
		} else if err != nil {
			return false, nil, err
		}

		var transactionReceipt tron.FilterTxResponse
		if err := json.Unmarshal(result, &transactionReceipt); err != nil {
			return false, nil, err
		}

		return true, &transactionReceipt.Result, nil
	}
	return false, nil, errors.New("L1ChainType should be 'Tron' or 'Eth'")
}

// SignTx tries to sign a transaction accordingly to the provided sender
func (etherMan *Client) SignTx(ctx context.Context, sender common.Address, tx *types.Transaction) (*types.Transaction, error) {
	auth, err := etherMan.getAuthByAddress(sender)
	if err == ErrNotFound {
		return nil, ErrPrivateKeyNotFound
	}
	signedTx, err := auth.Signer(auth.From, tx)
	if err != nil {
		return nil, err
	}
	return signedTx, nil
}

// GetRevertMessage tries to get a revert message of a transaction
func (etherMan *Client) GetRevertMessage(ctx context.Context, tx *types.Transaction) (string, error) {
	if tx == nil {
		return "", nil
	}

	receipt, err := etherMan.GetTxReceipt(ctx, tx.Hash())
	if err != nil {
		return "", err
	}
	//TODO, ZYD, does Tron support RevertReason?
	if receipt.Status == types.ReceiptStatusFailed {
		revertMessage, err := operations.RevertReason(ctx, etherMan.EthClient, tx, receipt.BlockNumber)
		if err != nil {
			return "", err
		}
		return revertMessage, nil
	}
	return "", nil
}

// AddOrReplaceAuth adds an authorization or replace an existent one to the same account
func (etherMan *Client) AddOrReplaceAuth(auth bind.TransactOpts) error {
	log.Infof("added or replaced authorization for address: %v", auth.From.String())
	etherMan.auth[auth.From] = auth
	return nil
}

// LoadAuthFromKeyStore loads an authorization from a key store file
func (etherMan *Client) LoadAuthFromKeyStore(path, password string) (*bind.TransactOpts, error) {
	auth, err := newAuthFromKeystore(path, password, etherMan.cfg.L1ChainID)
	if err != nil {
		return nil, err
	}

	log.Infof("loaded authorization for address: %v", auth.From.String())
	etherMan.auth[auth.From] = auth
	return &auth, nil
}

// newKeyFromKeystore creates an instance of a keystore key from a keystore file
func newKeyFromKeystore(path, password string) (*keystore.Key, error) {
	if path == "" && password == "" {
		return nil, nil
	}
	keystoreEncrypted, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	log.Infof("decrypting key from: %v", path)
	key, err := keystore.DecryptKey(keystoreEncrypted, password)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// newAuthFromKeystore an authorization instance from a keystore file
func newAuthFromKeystore(path, password string, chainID uint64) (bind.TransactOpts, error) {
	log.Infof("reading key from: %v", path)
	key, err := newKeyFromKeystore(path, password)
	if err != nil {
		return bind.TransactOpts{}, err
	}
	if key == nil {
		return bind.TransactOpts{}, nil
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, new(big.Int).SetUint64(chainID))
	if err != nil {
		return bind.TransactOpts{}, err
	}
	return *auth, nil
}

// getAuthByAddress tries to get an authorization from the authorizations map
func (etherMan *Client) getAuthByAddress(addr common.Address) (bind.TransactOpts, error) {
	auth, found := etherMan.auth[addr]
	if !found {
		return bind.TransactOpts{}, ErrNotFound
	}
	return auth, nil
}

// generateRandomAuth generates an authorization instance from a
// randomly generated private key to be used to estimate gas for PoE
// operations NOT restricted to the Trusted Sequencer
func (etherMan *Client) generateRandomAuth() (bind.TransactOpts, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return bind.TransactOpts{}, errors.New("failed to generate a private key to estimate L1 txs")
	}
	chainID := big.NewInt(0).SetUint64(etherMan.cfg.L1ChainID)
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return bind.TransactOpts{}, errors.New("failed to generate a fake authorization to estimate L1 txs")
	}

	return *auth, nil
}
