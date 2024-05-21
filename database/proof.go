package database

import (
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
)

type DAProofInfo struct {
	// gorm.Model
	Rnd     fr.Element
	Commits bls12381.G1Affine
	Proof   kzg.OpeningProof
	Result  bool
}

type DAProofInfoStore struct {
	Rnd          string
	Commits      string
	H            string
	ClaimedValue string
	Result       bool
}

func InitDAProofInfoTable() error {
	return GlobalDataBase.AutoMigrate(&DAProofInfoStore{})
}

func (p *DAProofInfo) CreateDAProofInfo() error {
	var info = &DAProofInfoStore{
		Rnd:          p.Rnd.String(),
		Commits:      p.Commits.X.String() + " | " + p.Commits.Y.String(),
		H:            p.Proof.H.X.String() + " | " + p.Commits.Y.String(),
		ClaimedValue: p.Proof.ClaimedValue.String(),
		Result:       p.Result,
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

func GetDAProofByRnd(rnd fr.Element) (DAProofInfo, error) {
	var proof DAProofInfoStore
	err := GlobalDataBase.Model(&DAProofInfoStore{}).Where("rnd = ?", rnd.String()).First(&proof).Error
	if err != nil {
		return DAProofInfo{}, err
	}

	return proofStoreToProof(proof)
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

	return DAProofInfo{
		Rnd:     rnd,
		Commits: commits,
		Proof:   kzgProof,
		Result:  proof.Result,
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
