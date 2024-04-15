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
	Commit              string `gorm:"index;column:commit"`
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

func GetRangeDAFileInfo(start uint, end uint) ([]DAFileInfo, error) {
	var files []DAFileInfoStore
	var result []DAFileInfo
	err := GlobalDataBase.Model(&DAFileInfoStore{}).Where("id >= ? and id <= ?", start, end).Find(&files).Error
	if err != nil {
		return nil, err
	}

	result = make([]DAFileInfo, len(files))
	for index, file := range files {
		var commit bls12381.G1Affine
		commitByte, err := hex.DecodeString(file.Commit)
		if err != nil {
			return nil, err
		}
		_, err = commit.SetBytes(commitByte)
		if err != nil {
			return nil, err
		}

		result[index] = DAFileInfo{
			Commit:              commit,
			Size:                file.Size,
			Expiration:          file.Expiration,
			ChooseNumber:        file.ChooseNumber,
			ProvedSuccessNumber: file.ProvedSuccessNumber,
		}
	}
	return result, nil
}

func GetFileInfoByCommit(commit bls12381.G1Affine) (DAFileInfo, error) {
	var file DAFileInfoStore
	commitByte48 := commit.Bytes()
	err := GlobalDataBase.Model(&DAFileInfoStore{}).Where("\"commit\" = ?", hex.EncodeToString(commitByte48[:])).First(&file).Error

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
