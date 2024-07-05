package database

import (
	"encoding/hex"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type DAFileIDInfo struct {
	// gorm.Model
	Commit bls12381.G1Affine
	Mid    string
}

type DAFileIDInfoStore struct {
	Commitment string `gorm:"uniqueIndex;column:commitment"`
	Mid    string `gorm:"uniqueIndex;column:mid"`
}

func (f *DAFileIDInfo) CreateDAFileIDInfo() error {
	commitByte48 := f.Commit.Bytes()
	var info = &DAFileIDInfoStore{
		Commitment: hex.EncodeToString(commitByte48[:]),
		Mid:    f.Mid,
	}
	return GlobalDataBase.Create(info).Error
}

func GetFileIDInfoByCommit(commit bls12381.G1Affine) (DAFileIDInfo, error) {
	var file DAFileIDInfoStore
	commitByte48 := commit.Bytes()
	err := GlobalDataBase.Model(&DAFileIDInfoStore{}).Where("commitment = ?", hex.EncodeToString(commitByte48[:])).First(&file).Error

	return DAFileIDInfo{
		Commit: commit,
		Mid:    file.Mid,
	}, err
}
