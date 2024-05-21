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
	contractABI     abi.ABI
	contractAddress common.Address
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

	dumper.contractAddress, err = instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProof)
	if err != nil {
		return dumper, err
	}

	dumper.contractABI, err = abi.JSON(strings.NewReader(proxyfileproof.IFileProofABI))
	if err != nil {
		return dumper, err
	}

	for name, event := range dumper.contractABI.Events {
		dumper.eventNameMap[event.ID] = name

		var indexed abi.Arguments
		for _, arg := range dumper.contractABI.Events[name].Inputs {
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
		err := d.DumpFileProof()
		if err != nil {
			return err
		}

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
		return err
	}
	defer client.Close()

	events, err := client.FilterLogs(context.TODO(), ethereum.FilterQuery{
		FromBlock: d.blockNumber,
		Addresses: []common.Address{d.contractAddress},
	})
	if err != nil {
		return err
	}
	lastBlockNumber := d.blockNumber

	for _, event := range events {
		eventName, ok1 := d.eventNameMap[event.Topics[0]]
		if !ok1 {
			continue
		}
		switch eventName {
		case "AddFile":
			logger.Info("Handle Add File Evnent")
			err = d.HandleAddFile(event)
		case "SubmitProof":
			logger.Info("Handle Submit Proof Evnent")
			err = d.HandleSubmitProof(event)
		default:
			continue
		}
		if err != nil {
			logger.Error(err.Error())
			break
		}

		d.blockNumber = big.NewInt(int64(event.BlockNumber) + 1)
	}
	if d.blockNumber.Cmp(lastBlockNumber) == 1 {
		database.SetBlockNumber(d.blockNumber.Int64())
	}

	return nil
}

func (d *Dumper) unpack(log types.Log, out interface{}) error {
	eventName := d.eventNameMap[log.Topics[0]]
	indexed := d.indexedMap[log.Topics[0]]
	err := d.contractABI.UnpackIntoInterface(out, eventName, log.Data)
	if err != nil {
		return err
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
	err := d.unpack(log, &out)
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
	Rnd [32]byte
	Cn  [4][32]byte
	Pn  proxyfileproof.IFileProofProofInfo
	Res bool
}

func (d *Dumper) HandleSubmitProof(log types.Log) error {
	var out SubmitProof
	err := d.unpack(log, &out)
	if err != nil {
		return err
	}

	// store proof
	var rnd fr.Element
	rnd.SetBytes(out.Rnd[:])
	var proof = database.DAProofInfo{
		Rnd:     rnd,
		Commits: proof.FromSolidityG1(out.Cn),
		Proof:   proof.FromSolidityProof(out.Pn),
		Result:  out.Res,
	}

	return proof.CreateDAProofInfo()

}
