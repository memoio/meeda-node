package database

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"gorm.io/gorm"
)

type DAChallengeResInfo struct {
	// gorm.Model
	Submitter  common.Address
	Challenger common.Address
	Last       *big.Int
	Res        bool
}

type DAChallengeResInfoStore struct {
	gorm.Model
	Submitter  string `gorm:"index"`
	Challenger string `gorm:"index"`
	Last       string `gorm:"index"`
	Res        bool
}

type DAPenaltyInfo struct {
	// gorm.Model
	PenalizedAccount   common.Address
	RewardedAccount    common.Address
	RewardAmount       *big.Int
	ToFoundationAmount *big.Int
}

type DAPenaltyInfoStore struct {
	gorm.Model
	From            string `gorm:"index"`
	To              string `gorm:"index"`
	ToValue         string
	FoundationValue string
}

func InitDAChallengeResInfoTable() error {
	return GlobalDataBase.AutoMigrate(&DAChallengeResInfoStore{})
}

func (c *DAChallengeResInfo) CreateDAChallengeResInfo() error {
	var info = &DAChallengeResInfoStore{
		Submitter:  c.Submitter.Hex(),
		Challenger: c.Challenger.Hex(),
		Last:       c.Last.String(),
		Res:        c.Res,
	}
	return GlobalDataBase.Create(info).Error
}

func GetDAChallengeResLength() (int64, error) {
	var length int64
	err := GlobalDataBase.Model(&DAChallengeResInfoStore{}).Count(&length).Error

	return length, err
}

func GetChallengeResByAccount(account common.Address, accountType uint8) ([]DAChallengeResInfo, error) {
	var results []DAChallengeResInfoStore
	var err error
	switch accountType {
	case 0:
		err = GlobalDataBase.Model(&DAChallengeResInfoStore{}).Where("submitter <> ?", account.Hex()).Find(&results).Error
	default:
		err = GlobalDataBase.Model(&DAChallengeResInfoStore{}).Where("challenger <> ?", account.Hex()).Find(&results).Error
	}
	if err != nil {
		return nil, err
	}

	var resInfo []DAChallengeResInfo
	var ok bool
	bigNum, last := new(big.Int), new(big.Int)

	for _, challengeResInfoStore := range results {
		last, ok = bigNum.SetString(challengeResInfoStore.Last, 10)
		if !ok {
			return nil, errors.New("bigNum.SetString(challengeResInfoStore.Last, 10) fail")
		}
		challengeResInfo := DAChallengeResInfo{
			Submitter:  common.HexToAddress(challengeResInfoStore.Submitter),
			Challenger: common.HexToAddress(challengeResInfoStore.Challenger),
			Last:       last,
			Res:        challengeResInfoStore.Res,
		}
		resInfo = append(resInfo, challengeResInfo)
	}

	return resInfo, nil
}

func GetChallengeResByLast(last *big.Int) ([]DAChallengeResInfo, error) {
	var results []DAChallengeResInfoStore
	err := GlobalDataBase.Model(&DAChallengeResInfoStore{}).Where("last <> ?", last.String()).Find(&results).Error
	if err != nil {
		return nil, err
	}

	var resInfo []DAChallengeResInfo
	var ok bool
	bigNum, last := new(big.Int), new(big.Int)

	for _, challengeResInfoStore := range results {
		last, ok = bigNum.SetString(challengeResInfoStore.Last, 10)
		if !ok {
			return nil, errors.New("bigNum.SetString(challengeResInfoStore.Last, 10) fail")
		}
		challengeResInfo := DAChallengeResInfo{
			Submitter:  common.HexToAddress(challengeResInfoStore.Submitter),
			Challenger: common.HexToAddress(challengeResInfoStore.Challenger),
			Last:       last,
			Res:        challengeResInfoStore.Res,
		}
		resInfo = append(resInfo, challengeResInfo)
	}

	return resInfo, nil
}

func GetChallengeResBySubmitterAndLast(submitter common.Address, last *big.Int) (DAChallengeResInfo, error) {
	var result DAChallengeResInfoStore
	err := GlobalDataBase.Model(&DAChallengeResInfoStore{}).Where("submitter = ? AND last = ?", submitter.Hex(), last.String()).First(&result).Error
	if err != nil {
		return DAChallengeResInfo{}, err
	}
	challengeResInfo := DAChallengeResInfo{
		Submitter:  submitter,
		Challenger: common.HexToAddress(result.Challenger),
		Last:       last,
		Res:        result.Res,
	}
	return challengeResInfo, nil
}

func InitDAPenaltyInfoTable() error {
	return GlobalDataBase.AutoMigrate(&DAPenaltyInfoStore{})
}

func (p *DAPenaltyInfo) CreateDAPenaltyInfo() error {
	var info = &DAPenaltyInfoStore{
		From:            p.PenalizedAccount.Hex(),
		To:              p.RewardedAccount.Hex(),
		ToValue:         p.RewardAmount.String(),
		FoundationValue: p.ToFoundationAmount.String(),
	}
	return GlobalDataBase.Create(info).Error
}

func GetDAPenaltyLength() (int64, error) {
	var length int64
	err := GlobalDataBase.Model(&DAPenaltyInfoStore{}).Count(&length).Error

	return length, err
}

func GetPenaltyByAccount(account common.Address, accountType uint8) ([]DAPenaltyInfo, error) {
	var penalties []DAPenaltyInfoStore
	var err error
	switch accountType {
	case 0:
		err = GlobalDataBase.Model(&DAPenaltyInfoStore{}).Where("from <> ?", account.Hex()).Find(&penalties).Error
	default:
		err = GlobalDataBase.Model(&DAPenaltyInfoStore{}).Where("to <> ?", account.Hex()).Find(&penalties).Error
	}
	if err != nil {
		return nil, err
	}

	var penaltiesInfo []DAPenaltyInfo
	var ok bool
	bigNum, toValue, fValue := new(big.Int), new(big.Int), new(big.Int)

	for _, penaltyInfoStore := range penalties {
		toValue, ok = bigNum.SetString(penaltyInfoStore.ToValue, 10)
		if !ok {
			return nil, errors.New("bigNum.SetString(penaltyInfoStore.ToValue, 10) fail")
		}
		fValue, ok = bigNum.SetString(penaltyInfoStore.FoundationValue, 10)
		if !ok {
			return nil, errors.New("bigNum.SetString(penaltyInfoStore.FoundationValue, 10) fail")
		}
		penaltyInfo := DAPenaltyInfo{
			PenalizedAccount:   common.HexToAddress(penaltyInfoStore.From),
			RewardedAccount:    common.HexToAddress(penaltyInfoStore.To),
			RewardAmount:       toValue,
			ToFoundationAmount: fValue,
		}
		penaltiesInfo = append(penaltiesInfo, penaltyInfo)
	}

	return penaltiesInfo, nil
}
