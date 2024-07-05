package database

import (
	"encoding/hex"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"gorm.io/gorm"
)

type DAFileInfo struct {
	// gorm.Model
	Commit              bls12381.G1Affine
	Size                int64
	Expiration          int64
	ChooseNumber        int64
	ProvedSuccessNumber int64
}

type DAFileInfoStore struct {
	gorm.Model
	Commit              string `gorm:"uniqueIndex;column:commit"`
	Size                int64
	Expiration          int64
	ChooseNumber        int64
	ProvedSuccessNumber int64
}

func InitDAFileInfoTable() error {
	return GlobalDataBase.AutoMigrate(&DAFileInfoStore{})
}

func (f *DAFileInfo) CreateDAFileInfo() error {
	commitByte48 := f.Commit.Bytes()
	var info = &DAFileInfoStore{
		Commit:     hex.EncodeToString(commitByte48[:]),
		Size:       f.Size,
		Expiration: f.Expiration,
	}
	return GlobalDataBase.Create(info).Error
}

func (f *DAFileInfo) UpdateDAFileInfo() error {
	commitByte48 := f.Commit.Bytes()
	commit := hex.EncodeToString(commitByte48[:])

	return GlobalDataBase.Model(&DAFileInfoStore{}).Where("commit = ?", commit).Updates(map[string]interface{}{"choose_number": f.ChooseNumber, "proved_success_number": f.ChooseNumber}).Error
}

func GetDAFileLength() (int64, error) {
	var length int64
	err := GlobalDataBase.Model(&DAFileInfoStore{}).Count(&length).Error
	return length, err
}

func GetFileInfoByID(id uint) (DAFileInfo, error) {
	var file DAFileInfoStore
	err := GlobalDataBase.Model(&DAFileInfoStore{}).Where("id = ?", id).First(&file).Error
	if err != nil {
		return DAFileInfo{}, err
	}

	commitByte48, err := hex.DecodeString(file.Commit)
	if err != nil {
		return DAFileInfo{}, err
	}
	var commit bls12381.G1Affine
	_, err = commit.SetBytes(commitByte48)
	if err != nil {
		return DAFileInfo{}, err
	}

	return DAFileInfo{
		Commit:              commit,
		Size:                file.Size,
		Expiration:          file.Expiration,
		ChooseNumber:        file.ChooseNumber,
		ProvedSuccessNumber: file.ProvedSuccessNumber,
	}, nil
}


func GetFileInfoByCommit(commit bls12381.G1Affine) (DAFileInfo, error) {
	var file DAFileInfoStore
	commitByte48 := commit.Bytes()
	err := GlobalDataBase.Model(&DAFileInfoStore{}).Where("commit = ?", hex.EncodeToString(commitByte48[:])).First(&file).Error

	return DAFileInfo{
		Commit:              commit,
		Size:                file.Size,
		Expiration:          file.Expiration,
		ChooseNumber:        file.ChooseNumber,
		ProvedSuccessNumber: file.ProvedSuccessNumber,
	}, err
}

// func GetFileByCommit(commit bls12381.G1Affine) ([]byte, error) {
// 	var file DAFileInfo
// 	var buf bytes.Buffer
// 	commitByte48 := commit.Bytes()
// 	err := GlobalDataBase.Model(&DAFileInfoStore{}).Where("\"commit\" = ?", hex.EncodeToString(commitByte48[:])).First(&file).Error
// 	if err != nil {
// 		return nil, err
// 	}

// 	err = daStore.GetObject(context.TODO(), file.Mid, &buf, gateway.ObjectOptions{})
// 	if err != nil {
// 		return nil, err
// 	}

// 	return buf.Bytes(), nil
// }
