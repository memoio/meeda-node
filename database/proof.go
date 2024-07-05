package database

import (
	"errors"
	"math/big"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
)

type DAProofInfo struct {
	// gorm.Model
	Submitter common.Address
	Rnd       fr.Element
	Commits   bls12381.G1Affine
	Proof     kzg.OpeningProof
	Last      *big.Int
	Profit    *big.Int
}

type DAProofInfoStore struct {
	Submitter    string
	Rnd          string
	Commits      string
	H            string
	ClaimedValue string
	Last         string
	Profit       string
}

func InitDAProofInfoTable() error {
	return GlobalDataBase.AutoMigrate(&DAProofInfoStore{})
}

func (p *DAProofInfo) CreateDAProofInfo() error {
	var info = &DAProofInfoStore{
		Submitter:    p.Submitter.Hex(),
		Rnd:          p.Rnd.String(),
		Commits:      p.Commits.X.String() + " | " + p.Commits.Y.String(),
		H:            p.Proof.H.X.String() + " | " + p.Commits.Y.String(),
		ClaimedValue: p.Proof.ClaimedValue.String(),
		Last:         p.Last.String(),
		Profit:       p.Profit.String(),
	}
	return GlobalDataBase.Create(info).Error
}

func GetDAProofLength() (int64, error) {
	var length int64
	err := GlobalDataBase.Model(&DAProofInfoStore{}).Count(&length).Error

	return length, err
}

func GetLastDAProof() (DAProofInfo, error) {
	var proof DAProofInfoStore
	err := GlobalDataBase.Model(&DAProofInfoStore{}).Last(&proof).Error
	if err != nil {
		return DAProofInfo{}, err
	}

	return proofStoreToProof(proof)
}

func GetDAProofBySubmitterAndRnd(submitter common.Address, rnd fr.Element) (DAProofInfo, error) {
	var proof DAProofInfoStore
	err := GlobalDataBase.Model(&DAProofInfoStore{}).Where("submitter = ? AND rnd = ?", submitter.Hex(), rnd.String()).First(&proof).Error
	if err != nil {
		return DAProofInfo{}, err
	}

	return proofStoreToProof(proof)
}

func GetDAProofsByRnd(rnd fr.Element) ([]DAProofInfo, error) {
	proofs := []DAProofInfoStore{}
	err := GlobalDataBase.Model(&DAProofInfoStore{}).Where("rnd = ?", rnd.String()).Find(&proofs).Error
	if err != nil {
		return nil, err
	}

	proofsInfo := []DAProofInfo{}
	for _, proof := range proofs {
		proofInfo, err := proofStoreToProof(proof)
		if err != nil {
			return nil, err
		}
		proofsInfo = append(proofsInfo, proofInfo)
	}

	return proofsInfo, nil
}

func GetDAProofsBySubmitter(submitter common.Address) ([]DAProofInfo, error) {
	proofs := []DAProofInfoStore{}
	err := GlobalDataBase.Model(&DAProofInfoStore{}).Where("submitter = ?", submitter.Hex()).Find(&proofs).Error
	if err != nil {
		return nil, err
	}

	proofsInfo := []DAProofInfo{}
	for _, proof := range proofs {
		proofInfo, err := proofStoreToProof(proof)
		if err != nil {
			return nil, err
		}
		proofsInfo = append(proofsInfo, proofInfo)
	}

	return proofsInfo, nil
}

func proofStoreToProof(proof DAProofInfoStore) (DAProofInfo, error) {
	var rnd fr.Element
	var commits bls12381.G1Affine
	var kzgProof kzg.OpeningProof
	splitCommits := strings.Split(proof.Commits, " | ")
	splitH := strings.Split(proof.H, " | ")

	_, err := rnd.SetString(proof.Rnd)
	if err != nil {
		return DAProofInfo{}, err
	}

	_, err = commits.X.SetString(splitCommits[0])
	if err != nil {
		return DAProofInfo{}, err
	}
	_, err = commits.Y.SetString(splitCommits[1])
	if err != nil {
		return DAProofInfo{}, err
	}

	_, err = kzgProof.H.X.SetString(splitH[0])
	if err != nil {
		return DAProofInfo{}, err
	}
	_, err = kzgProof.H.Y.SetString(splitH[1])
	if err != nil {
		return DAProofInfo{}, err
	}

	_, err = kzgProof.ClaimedValue.SetString(proof.ClaimedValue)
	if err != nil {
		return DAProofInfo{}, err
	}

	last, ok := big.NewInt(0).SetString(proof.Last, 10)
	if !ok {
		return DAProofInfo{}, errors.New("big.NewInt(0).SetString(proof.Last, 10) failed")
	}

	profit, ok := big.NewInt(0).SetString(proof.Profit, 10)
	if !ok {
		return DAProofInfo{}, errors.New("big.NewInt(0).SetString(proof.Profit, 10) failed")
	}

	return DAProofInfo{
		Submitter: common.HexToAddress(proof.Submitter),
		Rnd:     rnd,
		Commits: commits,
		Proof:   kzgProof,
		Last: last,
		Profit: profit,
	}, nil
}

var blockNumberKey = "block_number_key"

type DABlockNumber struct {
	BlockNumberKey string `gorm:"primarykey;column:key"`
	BlockNumber    int64
}

func SetBlockNumber(blockNumber int64) error {
	var daBlockNumber = DABlockNumber{
		BlockNumberKey: blockNumberKey,
		BlockNumber:    blockNumber,
	}
	return GlobalDataBase.Save(&daBlockNumber).Error
}

func GetBlockNumber() (int64, error) {
	var blockNumber DABlockNumber
	err := GlobalDataBase.Model(&DABlockNumber{}).First(&blockNumber).Error

	return blockNumber.BlockNumber, err
}
