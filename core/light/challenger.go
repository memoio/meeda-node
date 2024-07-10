package light

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	proof "github.com/memoio/go-did/file-proof"
	"github.com/memoio/meeda-node/database"
)

type DataAvailabilityChallenger struct {
	endpoint           string
	proofProxyAddr     common.Address
	proofInstance      proof.ProofInstance
	verifyKey          kzg.VerifyingKey
	selectedFileNumber int64
	interval           time.Duration
	period             time.Duration
	respondTime        int64
	last               int64

	lastRnd    fr.Element
}

func NewDataAvailabilityChallenger(chain string, sk *ecdsa.PrivateKey, addrs *proof.ContractAddress) (*DataAvailabilityChallenger, error) {
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

	instance, err := proof.NewProofInstance(sk, chain, addrs)
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
		verifyKey:          DefaultSRS.Vk,
		selectedFileNumber: int64(info.ChalSum),
		interval:           time.Duration(info.Interval) * time.Second,
		period:             time.Duration(info.Period) * time.Second,
		respondTime:        int64(info.RespondTime),
		last:               0,
		lastRnd:            fr.Element{},
	}, nil
}

func (c *DataAvailabilityChallenger) ChallengeAggregatedCommits(ctx context.Context) {
	for c.last == 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		err := c.proofInstance.GenerateRnd()
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		lastTime, err := c.proofInstance.GetLast()
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		_rnd, err := c.proofInstance.GetRndRawBytes()
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		c.last = lastTime.Int64()
		c.lastRnd = *c.lastRnd.SetBytes(_rnd[:])
	}

	var proofs []database.DAProofInfo
	for {
		wait := c.calculateWatingTime()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		for _, proof := range proofs {
			err := c.handleProveResult(proof)
			if err != nil {
				logger.Error(err.Error())
			}
		}

		err := c.proofInstance.GenerateRnd()
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		rndBytes, err := c.proofInstance.GetRndRawBytes()
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		proofs, err = c.getAggregatedProofs(rndBytes)
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		if len(proofs) == 0 {
			logger.Info("get no proof at this cycle, last:", c.last)
			continue
		}

		if c.lastRnd.Equal(&proofs[0].Rnd) {
			logger.Error("Rnd shouldn't be equal to last one, maybe sunmitter do not submit proof")
			continue
		}
		c.lastRnd = proofs[0].Rnd

		for _, proof := range proofs {
			if proof.Submitter==userAddr {
				continue
			}
			err = kzg.Verify(&proof.Commits, &proof.Proof, proof.Rnd, c.verifyKey)
			if err != nil {
				logger.Info("Submitted proof is wrong, so we start chanllenge. Submitter:", proof.Submitter.Hex(), " Cycle:", time.Unix(proof.Last.Int64(), 0).Format("2006-01-02 15:04:05"))
				go func(submitter common.Address) {
					err := c.proofInstance.ChallengePn(submitter)
					if err != nil {
						logger.Error(err.Error())
					}
				}(proof.Submitter)
				continue
			}
			commits, err := c.selectCommits(proof.Submitter, rndBytes)
			if err != nil {
				logger.Error(err.Error())
				continue
			}
			if !checkAggregateCommits(commits, proof.Commits) {
				logger.Info("Submitted commit is wrong, so we start chanllenge. Submitter:", proof.Submitter.Hex(), " Cycle:", time.Unix(proof.Last.Int64(), 0).Format("2006-01-02 15:04:05"))
				go func(submitter common.Address, commits []bls12381.G1Affine) {
					err := c.challengeCn(submitter, commits)
					if err != nil {
						logger.Error(err.Error())
					}
				}(proof.Submitter, commits)
				continue
			} else {
				logger.Info("Submitted proof is correct! Submitter:", proof.Submitter.Hex(), " Cycle:", time.Unix(proof.Last.Int64(), 0).Format("2006-01-02 15:04:05"))
			}
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

func (c *DataAvailabilityChallenger) getAggregatedProofs(rndBytes [32]byte) ([]database.DAProofInfo, error) {
	var rnd fr.Element
	rnd.SetBytes(rndBytes[:])
	proofs, err := database.GetDAProofsByRnd(rnd)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

func (c *DataAvailabilityChallenger) selectFiles(submitter common.Address, rndBytes [32]byte) ([]database.DAFileInfo, error) {
	var files []database.DAFileInfo = make([]database.DAFileInfo, c.selectedFileNumber)
	length, err := c.proofInstance.GetFilesAmount()
	if err != nil {
		return nil, err
	}

	big2 := big.NewInt(2)
	random := big.NewInt(0).SetBytes(rndBytes[:])
	random = new(big.Int).Mod(random, length)
	startIndex := new(big.Int).Div(random, big2).Int64()

	var tmpIndex int64
	tmpInt := new(big.Int)
	submitterInt := submitter.Big()
	for i := int64(0); i < c.selectedFileNumber; i++ {
		tmpInt.Mul(big.NewInt(i), submitterInt)
		tmpInt.Mod(tmpInt, length)
		tmpIndex = tmpInt.Div(tmpInt, big2).Int64()
		tmpIndex += startIndex
		file, err := database.GetFileInfoByID(uint(tmpIndex + 1))
		if err != nil {
			return nil, err
		}
		files[i] = file
	}

	return files, nil
}

func (c *DataAvailabilityChallenger) selectCommits(submitter common.Address, rndBytes [32]byte) ([]bls12381.G1Affine, error) {
	var commits []bls12381.G1Affine = make([]bls12381.G1Affine, c.selectedFileNumber)
	files, err := c.selectFiles(submitter, rndBytes)
	if err != nil {
		return nil, err
	}
	for i := int64(0); i < c.selectedFileNumber; i++ {
		if files[i].Expiration > c.last {
			commits[i] = files[i].Commit
		} else {
			commits[i] = zeroCommit
		}
	}

	return commits, nil
}

func (c *DataAvailabilityChallenger) challengeCn(submitter common.Address, commits []bls12381.G1Affine) error {
	err := c.proofInstance.ChallengeCn(submitter, 0)
	if err != nil {
		return err
	}

	for {
		info, err := c.proofInstance.GetChallengeInfo(submitter)
		if err != nil {
			return err
		}

		if info.Status%2 == 1 {
			if time.Now().Unix() > c.last+c.respondTime*int64(info.Status+1) {
				err = c.proofInstance.EndChallenge(submitter)
				if err != nil {
					return err
				}
				logger.Info("we success because they failed generate aggregate commit")
				return nil
			}
		} else if info.Status == 11 {
			fail, err := c.proofInstance.IsSubmitterWinner()
			if err != nil {
				return err
			}
			if fail {
				logger.Info("we failed because the submitter success on the last prove")
			} else {
				logger.Info("we success because the submitter failed on the last prove")
			}
			return nil
		} else {
			logger.Infof("challenge-%d", info.Status)
			cns := info.DividedCn
			var splitLength = len(commits) / 10
			for index, cn := range cns {
				if !checkAggregateCommits(commits[splitLength*index:splitLength*(index+1)], proof.FromSolidityG1(cn)) {
					err = c.proofInstance.ChallengeCn(submitter, uint8(index))
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

func (c *DataAvailabilityChallenger) handleProveResult(proof database.DAProofInfo) error {
	files, err := c.selectFiles(proof.Submitter, proof.Rnd.Bytes())
	if err != nil {
		return err
	}

	challengeRes, err := database.GetChallengeResBySubmitterAndLast(proof.Submitter, proof.Last)
	if err != nil || challengeRes.Res {
		for _, file := range files {
			if file.Expiration >= c.last {
				file.ChooseNumber++
				err = file.UpdateDAFileInfo()
				if err != nil {
					return err
				}
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
