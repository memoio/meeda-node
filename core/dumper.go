package core

import (
	"context"
	"math/big"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	proxyfileproof "github.com/memoio/did-solidity/go-contracts/proxy-proof"
	proof "github.com/memoio/go-did/file-proof"
	"github.com/memoio/meeda-node/database"
	"github.com/memoio/meeda-node/logs"
)

var (
	// blockNumber = big.NewInt(0)
	logger = logs.Logger("dumper")
)

type Dumper struct {
	endpoint        string
	contractABI     []abi.ABI
	contractAddress []common.Address
	// store           MapStore

	blockNumber *big.Int

	eventNameMap map[common.Hash]string
	indexedMap   map[common.Hash]abi.Arguments
}

func NewDataAvailabilityDumper(chain string) (dumper *Dumper, err error) {
	dumper = &Dumper{
		// store:        store,
		eventNameMap: make(map[common.Hash]string),
		indexedMap:   make(map[common.Hash]abi.Arguments),
	}

	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)
	dumper.endpoint = endpoint

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return dumper, err
	}
	defer client.Close()

	// new instanceIns
	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return dumper, err
	}

	fileProofAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProof)
	if err != nil {
		return dumper, err
	}

	fileProofPledgeAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProofPledge)
	if err != nil {
		return dumper, err
	}

	dumper.contractAddress = []common.Address{fileProofAddr, fileProofPledgeAddr}

	fpContractABI, err := abi.JSON(strings.NewReader(proxyfileproof.IFileProofABI))
	if err != nil {
		return dumper, err
	}

	fpPledgeContractABI, err := abi.JSON(strings.NewReader(proxyfileproof.IPledgeABI))
	if err != nil {
		return dumper, err
	}

	dumper.contractABI = []abi.ABI{fpContractABI, fpPledgeContractABI}

	for name, event := range dumper.contractABI[0].Events {
		dumper.eventNameMap[event.ID] = name

		var indexed abi.Arguments
		for _, arg := range dumper.contractABI[0].Events[name].Inputs {
			if arg.Indexed {
				indexed = append(indexed, arg)
			}
		}
		dumper.indexedMap[event.ID] = indexed
	}

	for name, event := range dumper.contractABI[1].Events {
		dumper.eventNameMap[event.ID] = name

		var indexed abi.Arguments
		for _, arg := range dumper.contractABI[1].Events[name].Inputs {
			if arg.Indexed {
				indexed = append(indexed, arg)
			}
		}
		dumper.indexedMap[event.ID] = indexed
	}

	blockNumber, err := database.GetBlockNumber()
	if err != nil {
		blockNumber = 0
	}
	dumper.blockNumber = big.NewInt(blockNumber)

	return dumper, nil
}

func (d *Dumper) SubscribeFileProof(ctx context.Context) error {
	// var last *big.Int
	for {
		d.DumpFileProof()

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(10 * time.Second):
		}
	}
}

func (d *Dumper) DumpFileProof() error {
	client, err := ethclient.DialContext(context.TODO(), d.endpoint)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	defer client.Close()

	eventsFileProof, err := client.FilterLogs(context.TODO(), ethereum.FilterQuery{
		FromBlock: d.blockNumber,
		Addresses: []common.Address{d.contractAddress[0]},
	})
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	eventsFileProofPledge, err := client.FilterLogs(context.TODO(), ethereum.FilterQuery{
		FromBlock: d.blockNumber,
		Addresses: []common.Address{d.contractAddress[1]},
	})
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	lastBlockNumber := d.blockNumber

	for _, event := range eventsFileProof {
		eventName, ok1 := d.eventNameMap[event.Topics[0]]
		if !ok1 {
			continue
		}
		switch eventName {
		case "AddFile":
			logger.Info("Handle Add File Event")
			err = d.HandleAddFile(event)
		case "SubmitProof":
			logger.Info("Handle Submit Proof Event")
			err = d.HandleSubmitProof(event)
		case "ChallengeRes":
			logger.Info("Handle Challenge Res Event")
			err = d.HandleChallengeRes(event)
		default:
			continue
		}
		if err != nil {
			logger.Error(err.Error())
			break
		}

		d.blockNumber = big.NewInt(int64(event.BlockNumber) + 1)
	}

	for _, event := range eventsFileProofPledge {
		eventName, ok1 := d.eventNameMap[event.Topics[0]]
		if !ok1 {
			continue
		}
		switch eventName {
		case "Penalize":
			logger.Info("Handle Penalize Event")
			err = d.HandlePenalize(event)
		default:
			continue
		}
		if err != nil {
			logger.Error(err.Error())
			break
		}
	}

	if d.blockNumber.Cmp(lastBlockNumber) == 1 {
		database.SetBlockNumber(d.blockNumber.Int64())
	}

	return nil
}

func (d *Dumper) unpack(log types.Log, contractType uint8, out interface{}) error {
	eventName := d.eventNameMap[log.Topics[0]]
	indexed := d.indexedMap[log.Topics[0]]
	switch contractType {
	case 0:
		err := d.contractABI[0].UnpackIntoInterface(out, eventName, log.Data)
		if err != nil {
			return err
		}
	default:
		err := d.contractABI[1].UnpackIntoInterface(out, eventName, log.Data)
		if err != nil {
			return err
		}
	}

	return abi.ParseTopics(out, indexed, log.Topics[1:])
}

type AddFile struct {
	Account common.Address
	Etag    [4][32]byte
	Start   *big.Int
	End     *big.Int
	Size    uint64
	Price   uint64
}

func (d *Dumper) HandleAddFile(log types.Log) error {
	var out AddFile
	err := d.unpack(log, 0, &out)
	if err != nil {
		return err
	}

	// store file
	var file = database.DAFileInfo{
		Commit:     proof.FromSolidityG1(out.Etag),
		Size:       int64(out.Size),
		Expiration: out.End.Int64(),
	}

	return file.CreateDAFileInfo()
}

type SubmitProof struct {
	Submitter common.Address
	Rnd       [32]byte
	Cn        [4][32]byte
	Pn        proxyfileproof.IFileProofProofInfo
	Last      *big.Int
	Profit    *big.Int
}

func (d *Dumper) HandleSubmitProof(log types.Log) error {
	var out SubmitProof
	err := d.unpack(log, 0, &out)
	if err != nil {
		return err
	}

	// store proof
	var rnd fr.Element
	rnd.SetBytes(out.Rnd[:])
	var proof = database.DAProofInfo{
		Submitter: out.Submitter,
		Rnd:       rnd,
		Commits:   proof.FromSolidityG1(out.Cn),
		Proof:     proof.FromSolidityProof(out.Pn),
		Last:      out.Last,
		Profit:    out.Profit,
	}

	return proof.CreateDAProofInfo()
}

func (d *Dumper) HandleChallengeRes(log types.Log) error {
	var out database.DAChallengeResInfo
	err := d.unpack(log, 0, &out)
	if err != nil {
		return err
	}

	// store penalty
	return out.CreateDAChallengeResInfo()
}

func (d *Dumper) HandlePenalize(log types.Log) error {
	var out database.DAPenaltyInfo
	err := d.unpack(log, 1, &out)
	if err != nil {
		return err
	}

	// store penalty
	return out.CreateDAPenaltyInfo()
}
