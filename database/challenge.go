package database

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type DAChallengeResInfo struct {
	Submitter  common.Address
	Challenger common.Address
	Last       *big.Int
	Res        bool
}

type DAChallengeResInfoStore struct {
	Submitter  string `gorm:"index"`
	Challenger string `gorm:"index"`
	Last       string `gorm:"index"`
	Res        bool
}

type DAPenaltyInfo struct {
	From            common.Address
	To              common.Address
	ToValue         *big.Int
	FoundationValue *big.Int
}

type DAPenaltyInfoStore struct {
	PenalizedAccount string `gorm:"index;column:penalizedaccount"`
	RewardedAccount  string `gorm:"index;column:rewardedaccount"`
	RewardValue      string `gorm:"column:rewardvalue"`
	FoundationValue  string `gorm:"column:foundationvalue"`
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
	results := []DAChallengeResInfoStore{}
	var err error
	switch accountType {
	case 0:
		err = GlobalDataBase.Model(&DAChallengeResInfoStore{}).Where("submitter = ?", account.Hex()).Find(&results).Error
	default:
		err = GlobalDataBase.Model(&DAChallengeResInfoStore{}).Where("challenger = ?", account.Hex()).Find(&results).Error
	}
	if err != nil {
		return nil, err
	}

	resInfo := []DAChallengeResInfo{}
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
	results := []DAChallengeResInfoStore{}
	err := GlobalDataBase.Model(&DAChallengeResInfoStore{}).Where("last = ?", last.String()).Find(&results).Error
	if err != nil {
		return nil, err
	}

	resInfo := []DAChallengeResInfo{}
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
		PenalizedAccount: p.From.Hex(),
		RewardedAccount:  p.To.Hex(),
		RewardValue:      p.ToValue.String(),
		FoundationValue:  p.FoundationValue.String(),
	}
	return GlobalDataBase.Create(info).Error
}

func GetDAPenaltyLength() (int64, error) {
	var length int64
	err := GlobalDataBase.Model(&DAPenaltyInfoStore{}).Count(&length).Error

	return length, err
}

func GetPenaltyByAccount(account common.Address, accountType uint8) ([]DAPenaltyInfo, error) {
	penalties := []DAPenaltyInfoStore{}
	var err error
	switch accountType {
	case 0:
		err = GlobalDataBase.Model(&DAPenaltyInfoStore{}).Where("penalizedaccount = ?", account.Hex()).Find(&penalties).Error
	default:
		err = GlobalDataBase.Model(&DAPenaltyInfoStore{}).Where("rewardedaccount = ?", account.Hex()).Find(&penalties).Error
	}
	if err != nil {
		return nil, err
	}

	penaltiesInfo := []DAPenaltyInfo{}
	var ok bool
	bigNum, toValue, fValue := new(big.Int), new(big.Int), new(big.Int)

	for _, penaltyInfoStore := range penalties {
		toValue, ok = bigNum.SetString(penaltyInfoStore.RewardValue, 10)
		if !ok {
			return nil, errors.New("bigNum.SetString(penaltyInfoStore.RewardValue, 10) fail")
		}
		fValue, ok = bigNum.SetString(penaltyInfoStore.FoundationValue, 10)
		if !ok {
			return nil, errors.New("bigNum.SetString(penaltyInfoStore.FoundationValue, 10) fail")
		}
		penaltyInfo := DAPenaltyInfo{
			From:            common.HexToAddress(penaltyInfoStore.PenalizedAccount),
			To:              common.HexToAddress(penaltyInfoStore.RewardedAccount),
			ToValue:         toValue,
			FoundationValue: fValue,
		}
		penaltiesInfo = append(penaltiesInfo, penaltyInfo)
	}

	return penaltiesInfo, nil
}
