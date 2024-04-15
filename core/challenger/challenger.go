package challenger

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	proof "github.com/memoio/go-did/file-proof"
	"github.com/memoio/meeda-node/database"
	"golang.org/x/xerrors"
)

type DataAvailabilityChallenger struct {
	endpoint           string
	proofProxyAddr     common.Address
	proofInstance      proof.ProofInstance
	selectedFileNumber int64
	interval           time.Duration
	period             time.Duration
	respondTime        int64
	last               int64

	lastRnd       fr.Element
	startIndex    uint
	endIndex      uint
	provedSuccess bool
}

func NewDataAvailabilityChallenger(chain string, sk *ecdsa.PrivateKey) (*DataAvailabilityChallenger, error) {
	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)
	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// new instance
	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return nil, err
	}

	// get proof proxy address
	proofProxyAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProofProxy)
	if err != nil {
		return nil, err
	}

	instance, err := proof.NewProofInstance(sk, chain)
	if err != nil {
		return nil, err
	}

	info, err := instance.GetSettingInfo()
	if err != nil {
		return nil, err
	}

	return &DataAvailabilityChallenger{
		endpoint:           endpoint,
		proofProxyAddr:     proofProxyAddr,
		proofInstance:      *instance,
		selectedFileNumber: int64(info.ChalSum),
		interval:           time.Duration(info.Interval) * time.Second,
		period:             time.Duration(info.Period) * time.Second,
		respondTime:        int64(info.RespondTime),
		last:               0,
	}, nil
}

func (c *DataAvailabilityChallenger) ChallengeAggregatedCommits(ctx context.Context) {
	for c.last == 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		rnd, _, lastTime, err := c.proofInstance.GetVerifyInfo()
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		c.last = lastTime.Int64()
		c.lastRnd = rnd
	}

	for {
		wait := c.calculateWatingTime()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		rndBytes, err := c.proofInstance.GetRndRawBytes()
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		proof, err := c.getAggregatedProof(rndBytes)
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		if c.lastRnd.Equal(&proof.Rnd) {
			logger.Error("Rnd shouldn't be equal to last one, maybe sunmitter do not submit proof")
			continue
		}
		c.lastRnd = proof.Rnd

		commits, err := c.selectCommits(rndBytes)
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		if !checkAggregateCommits(commits, proof.Commits) {
			logger.Info("submitted proof is wrong, so we start chanllenge")
			c.provedSuccess = false
			err := c.challenge(commits)
			if err != nil {
				logger.Error(err.Error())
			}
		} else {
			c.provedSuccess = true
			logger.Info("submitted proof is correct")
		}

		err = c.handleProveResult()
		if err != nil {
			logger.Error(err.Error())
		}
	}
}

func (c *DataAvailabilityChallenger) calculateWatingTime() time.Duration {
	challengeCycleSeconds := int64((c.interval + c.period).Seconds())
	now := time.Now().Unix()
	duration := now - c.last
	over := duration % challengeCycleSeconds
	waitingSeconds := challengeCycleSeconds - over

	c.last = now - over + challengeCycleSeconds
	// next := c.last + challengeCycleSeconds

	return time.Duration(waitingSeconds) * time.Second
}

func (c *DataAvailabilityChallenger) getAggregatedProof(rndBytes [32]byte) (database.DAProofInfo, error) {
	var rnd fr.Element
	rnd.SetBytes(rndBytes[:])
	proof, err := database.GetDAProofByRnd(rnd)
	if err != nil {
		return database.DAProofInfo{}, err
	}

	return proof, nil
}

func (c *DataAvailabilityChallenger) selectCommits(rndBytes [32]byte) ([]bls12381.G1Affine, error) {
	var commits []bls12381.G1Affine = make([]bls12381.G1Affine, c.selectedFileNumber)
	info, err := c.proofInstance.GetChallengeInfo()
	if err != nil {
		return nil, err
	}
	length := info.ChalLength.Int64()

	var random *big.Int = big.NewInt(0).SetBytes(rndBytes[:])
	random = new(big.Int).Mod(random, big.NewInt(length))
	startIndex := new(big.Int).Div(random, big.NewInt(2)).Int64()

	var endIndex int64
	if c.selectedFileNumber > length {
		endIndex = startIndex + (length-1)/2
	} else {
		endIndex = startIndex + (c.selectedFileNumber-1)/2
	}
	c.startIndex = uint(startIndex + 1)
	c.endIndex = uint(endIndex + 1)

	files, err := database.GetRangeDAFileInfo(uint(startIndex+1), uint(endIndex+1))
	if err != nil {
		return nil, err
	}

	var tmpCommits = make([]bls12381.G1Affine, len(files))
	for index, file := range files {
		if file.Expiration > c.last {
			tmpCommits[index] = file.Commit
		} else {
			tmpCommits[index] = zeroCommit
		}
	}

	for index := 0; index < int(c.selectedFileNumber); index++ {
		commits[index] = tmpCommits[index%int(length)/2]
	}

	return commits, nil
}

func (c *DataAvailabilityChallenger) challenge(commits []bls12381.G1Affine) error {
	err := c.proofInstance.Challenge(0)
	if err != nil {
		return err
	}

	for {
		info, err := c.proofInstance.GetChallengeInfo()
		if err != nil {
			return err
		}

		if info.ChalStatus%2 == 1 {
			if time.Now().Unix() > c.last+c.respondTime*int64(info.ChalStatus+1) {
				err = c.proofInstance.EndChallenge()
				if err != nil {
					return err
				}
				logger.Info("we success because they failed generate aggregate commit")
				return nil
			}
		} else if info.ChalStatus == 0 {
			fail, err := c.proofInstance.IsSubmitterWinner()
			if err != nil {
				return err
			}
			if fail {
				c.provedSuccess = true
				logger.Info("we failed because the submitter success on the last prove")
			} else {
				logger.Info("we success because the submitter failed on the last prove")
			}

			return nil
		} else {
			logger.Infof("challenge-%d", info.ChalStatus)
			cns, err := c.getResponseCommits()
			if err != nil {
				return err
			}

			var splitLength = len(commits) / 10
			for index, cn := range cns {
				if !checkAggregateCommits(commits[splitLength*index:splitLength*(index+1)], cn) {
					err = c.proofInstance.Challenge(uint8(index))
					if err != nil {
						return err
					}

					commits = commits[splitLength*index : splitLength*(index+1)]
				}
			}
		}

		time.Sleep(5 * time.Second)
	}
}

func (c *DataAvailabilityChallenger) getResponseCommits() ([10]bls12381.G1Affine, error) {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return [10]bls12381.G1Affine{}, err
	}
	defer client.Close()

	blockNumber, err := client.BlockNumber(context.TODO())
	if err != nil {
		return [10]bls12381.G1Affine{}, err
	}

	for number := blockNumber; number > 0; number-- {
		block, err := client.BlockByNumber(context.TODO(), big.NewInt(int64(number)))
		if err != nil {
			return [10]bls12381.G1Affine{}, err
		}
		for _, tx := range block.Transactions() {
			if tx != nil {
				if tx.To() != nil {
					if tx.To().Hex() == c.proofProxyAddr.Hex() {
						out, err := unpackChallenge(tx.Data()[4:])
						if err != nil {
							continue
						}

						var commits [10]bls12381.G1Affine
						for index, cn := range out {
							commits[index] = proof.FromSolidityG1(cn)
						}

						return commits, nil
					}
				}
			}
		}
	}
	return [10]bls12381.G1Affine{}, nil
}

func (c *DataAvailabilityChallenger) handleProveResult() error {
	files, err := database.GetRangeDAFileInfo(c.startIndex, c.endIndex)
	if err != nil {
		return err
	}

	length := int64(len(files))
	total := c.selectedFileNumber / 2
	cycle := total / length
	over := total % length

	for i := int64(0); i < over; i++ {
		if files[i].Expiration <= c.last {
			files[i].ChooseNumber = files[i].ChooseNumber + 2
			if c.provedSuccess {
				files[i].ProvedSuccessNumber = files[i].ProvedSuccessNumber + 2
			}
		}
	}

	for _, file := range files {
		if file.Expiration <= c.last {
			file.ChooseNumber = file.ChooseNumber + 2*cycle
			if c.provedSuccess {
				file.ProvedSuccessNumber = file.ProvedSuccessNumber + 2*cycle
			}

			err = file.UpdateDAFileInfo()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func checkAggregateCommits(commits []bls12381.G1Affine, aggregateCommit bls12381.G1Affine) bool {
	var foldedCommit = commits[0]
	for index := 1; index < len(commits); index++ {
		// fold commit
		foldedCommit.Add(&foldedCommit, &commits[index])
	}
	return foldedCommit.Equal(&aggregateCommit)
}

func unpackChallenge(data []byte) ([10][4][32]byte, error) {
	if len(data) != 10*4*32 {
		return [10][4][32]byte{}, xerrors.New("can't match")
	}

	var res [10][4][32]byte
	for x := 0; x < 10; x++ {
		for y := 0; y < 4; y++ {
			index := x*4 + y
			copy(res[x][y][:], data[index*32:(index+1)*32])
		}
	}

	return res, nil
}
