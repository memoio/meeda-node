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
	Commit string `gorm:"index;column:commit"`
	Mid    string `gorm:"index;column:mid"`
}

func (f *DAFileIDInfo) CreateDAFileIDInfo() error {
	commitByte48 := f.Commit.Bytes()
	var info = &DAFileIDInfoStore{
		Commit: hex.EncodeToString(commitByte48[:]),
		Mid:    f.Mid,
	}
	return GlobalDataBase.Create(info).Error
}

func GetFileIDInfoByCommit(commit bls12381.G1Affine) (DAFileIDInfo, error) {
	var file DAFileIDInfoStore
	commitByte48 := commit.Bytes()
	err := GlobalDataBase.Model(&DAFileIDInfoStore{}).Where("\"commit\" = ?", hex.EncodeToString(commitByte48[:])).First(&file).Error

	return DAFileIDInfo{
		Commit: commit,
		Mid:    file.Mid,
	}, err
}
