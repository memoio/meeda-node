package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	proof "github.com/memoio/go-did/file-proof"
	"github.com/memoio/meeda-node/database"
	"github.com/memoio/meeda-node/gateway"
	"github.com/memoio/meeda-node/utils"
)

type DataAvailabilityProver struct {
	proofInstance      proof.ProofInstance
	submitter          common.Address
	selectedFileNumber int64
	provingKey         kzg.ProvingKey
	interval           time.Duration
	period             time.Duration
	respondTime        int64
	last               int64
}

func NewDataAvailabilityProver(chain string, sk *ecdsa.PrivateKey, addrs *proof.ContractAddress) (*DataAvailabilityProver, error) {
	instance, err := proof.NewProofInstance(sk, chain, addrs)
	if err != nil {
		return nil, err
	}

	info, err := instance.GetSettingInfo()
	if err != nil {
		return nil, err
	}

	submittersInfo, err := instance.GetSubmittersInfo()
	if err != nil {
		return nil, err
	}

	return &DataAvailabilityProver{
		proofInstance:      *instance,
		submitter:          submittersInfo.MainSubmitter,
		selectedFileNumber: int64(info.ChalSum),
		provingKey:         DefaultSRS.Pk,
		interval:           time.Duration(info.Interval) * time.Second,
		period:             time.Duration(info.Period) * time.Second,
		respondTime:        int64(info.RespondTime),
		last:               0,
	}, nil
}

func (p *DataAvailabilityProver) ProveDataAccess(ctx context.Context) {
	var lastRnd fr.Element
	var nowRnd fr.Element
	var finalExpire *big.Int
	var proveSuccess bool
	for p.last == 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		err := p.proofInstance.GenerateRnd()
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		lastTime, err := p.proofInstance.GetLast()
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		p.last = lastTime.Int64()
	}

	for {
		wait, nextTime := p.calculateWatingTime()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		p.resetChallengeStatus()

		var err error
		start := time.Now()
		logger.Info("start prove")
		lastRnd = nowRnd
		nowRnd, finalExpire, err = p.generateRND()
		if err != nil {
			logger.Error(err.Error())
			proveSuccess = false
			continue
		}

		if start.Unix() > finalExpire.Int64() {
			logger.Error("all file is expired, there is no need to prove")
			p.last = nextTime
			continue
		}
		if lastRnd.Cmp(&nowRnd) == 0 && proveSuccess {
			logger.Error("rnd shouldn't be the same as before")
			continue
		}

		commits, proofs, err := p.selectFiles(nowRnd)
		if err != nil {
			logger.Error(err.Error())
			proveSuccess = false
			continue
		}

		err = p.proveToContract(commits, proofs, nowRnd)
		if err != nil {
			logger.Error(err.Error())
			proveSuccess = false
			continue
		}
		logger.Infof("end prove, using: %fs", time.Since(start).Seconds())

		proveSuccess = true

		start = time.Now()
		logger.Info("start response chanllenge")
		p.last = nextTime

		err = p.responseChallenge(commits)
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		logger.Infof("end response challenge, using: %fs", time.Since(start).Seconds())
	}
}

func (p *DataAvailabilityProver) calculateWatingTime() (time.Duration, int64) {
	challengeCycleSeconds := int64((p.interval + p.period).Seconds())
	now := time.Now().Unix()
	duration := now - p.last
	over := duration % challengeCycleSeconds
	var waitingSeconds int64 = 0
	if over < int64(p.interval.Seconds()) {
		waitingSeconds = int64(p.interval.Seconds()) - over
	}

	p.last = now - over
	next := p.last + challengeCycleSeconds

	return time.Duration(waitingSeconds) * time.Second, next
}

func (p *DataAvailabilityProver) resetChallengeStatus() error {
	info, err := p.proofInstance.GetChallengeInfo(p.submitter)
	if err != nil {
		return err
	}

	if info.Status != 0 && info.Status != 11 {
		return p.proofInstance.EndChallenge(p.submitter)
	}

	return nil
}

func (p *DataAvailabilityProver) generateRND() (fr.Element, *big.Int, error) {
	rnd := fr.Element{}
	err := p.proofInstance.GenerateRnd()
	if err != nil {
		return rnd, nil, err
	}

	_rnd, err := p.proofInstance.GetRndRawBytes()
	if err != nil {
		return rnd, nil, err
	}
	rnd.SetBytes(_rnd[:])

	finalExpire, err := p.proofInstance.GetFinalExpire()
	if err != nil {
		return rnd, nil, err
	}

	return rnd, finalExpire, nil
}

func (p *DataAvailabilityProver) selectFiles(rnd fr.Element) ([]bls12381.G1Affine, []kzg.OpeningProof, error) {
	var commits []bls12381.G1Affine = make([]bls12381.G1Affine, p.selectedFileNumber)
	var proofs []kzg.OpeningProof = make([]kzg.OpeningProof, p.selectedFileNumber)
	length, err := p.proofInstance.GetFilesAmount()
	if err != nil {
		return nil, nil, err
	}

	rndBytes, err := p.proofInstance.GetRndRawBytes()
	if err != nil {
		return nil, nil, err
	}

	big2 := big.NewInt(2)
	var random *big.Int = big.NewInt(0).SetBytes(rndBytes[:])
	random = new(big.Int).Mod(random, length)
	startIndex := new(big.Int).Div(random, big2).Int64()

	var tmpIndex int64
	tmpInt := new(big.Int)
	submitterInt := p.submitter.Big()
	for i := int64(0); i < p.selectedFileNumber; i++ {
		tmpInt.Mul(big.NewInt(i), submitterInt)
		tmpInt.Mod(tmpInt, length)
		tmpIndex = tmpInt.Div(tmpInt, big2).Int64()
		tmpIndex += startIndex
		file, err := database.GetFileInfoByID(uint(tmpIndex + 1))
		if err != nil {
			return nil, nil, err
		}

		if file.Expiration > p.last {
			var w bytes.Buffer
			id, err := database.GetFileIDInfoByCommit(file.Commit)
			if err != nil {
				return nil, nil, err
			}
			err = daStore.GetObject(context.TODO(), id.Mid, &w, gateway.ObjectOptions{})
			if err != nil {
				return nil, nil, err
			}

			poly := utils.SplitData(w.Bytes())
			proof, err := kzg.Open(poly, rnd, p.provingKey)
			if err != nil {
				return nil, nil, err
			}

			commits[i] = file.Commit
			proofs[i] = proof
		} else {
			commits[i] = zeroCommit
			proofs[i] = zeroProof
		}
	}

	return commits, proofs, nil
}

func (p *DataAvailabilityProver) proveToContract(commits []bls12381.G1Affine, proofs []kzg.OpeningProof, rnd fr.Element) error {
	// fold proof
	var foldedCommit bls12381.G1Affine
	var foldedProof kzg.OpeningProof
	var foldedPi bls12381.G1Affine
	var foldedValue fr.Element

	foldedCommit = commits[0]
	foldedPi = proofs[0].H
	foldedValue = proofs[0].ClaimedValue
	for index := 1; index < len(commits); index++ {
		// compute
		foldedCommit.Add(&foldedCommit, &commits[index])
		// compute
		foldedPi.Add(&foldedPi, &proofs[index].H)
		// compute
		foldedValue.Add(&foldedValue, &proofs[index].ClaimedValue)
	}

	// var tmpCommit []bls12381.G1Affine
	// var aggregatedCommits [10]bls12381.G1Affine
	// var splitLength = len(commits) / 10
	// for i := 0; i < 10; i++ {
	// 	tmpCommit = commits[i*splitLength : (i+1)*splitLength]
	// 	var aggregatedCommit bls12381.G1Affine = tmpCommit[0]
	// 	for _, commit := range tmpCommit[1:] {
	// 		aggregatedCommit.Add(&aggregatedCommit, &commit)
	// 	}
	// 	aggregatedCommits[i] = aggregatedCommit
	// }

	foldedProof.H = foldedPi
	foldedProof.ClaimedValue = foldedValue

	logger.Info(rnd)
	logger.Info(foldedProof)

	return p.proofInstance.SubmitAggregationProof(rnd, foldedCommit, foldedProof)
}

func (p *DataAvailabilityProver) responseChallenge(commits []bls12381.G1Affine) error {
	var splitedCommits [10][]bls12381.G1Affine
	for {
		info, err := p.proofInstance.GetChallengeInfo(p.submitter)
		if err != nil {
			return err
		}

		if info.Status%2 == 0 {
			if time.Now().Unix() > p.last+p.respondTime*int64(info.Status+1) {
				if info.Status != 0 {
					return p.proofInstance.EndChallenge(p.submitter)
				} else {
					return nil
				}
			}
		} else if info.Status == 11 {
			return nil
		} else {
			if info.Status != 1 {
				commits = splitedCommits[info.ChalIndex]
			}
			var aggregatedCommits [10]bls12381.G1Affine
			var splitLength = len(commits) / 10
			if splitLength == 1 {
				return p.proofInstance.ResponseChallenge([10]bls12381.G1Affine(commits), true)
			} else {
				for i := 0; i < 10; i++ {
					splitedCommits[i] = commits[i*splitLength : (i+1)*splitLength]
					var aggregatedCommit bls12381.G1Affine = splitedCommits[i][0]
					for _, commit := range splitedCommits[i][1:] {
						aggregatedCommit.Add(&aggregatedCommit, &commit)
					}
					aggregatedCommits[i] = aggregatedCommit
					fmt.Println(aggregatedCommit)
				}
				err := p.proofInstance.ResponseChallenge(aggregatedCommits, false)
				if err != nil {
					return err
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func (p *DataAvailabilityProver) Pledge() error {
	bal, err := p.proofInstance.GetPledgeBalance(p.submitter)
	if err != nil {
		return err
	}
	info, err := p.proofInstance.GetSettingInfo()
	if err != nil {
		return err
	}

	if bal.Cmp(info.SubPledge) == -1 {
		bal.Sub(info.SubPledge, bal)
		err = p.proofInstance.Pledge(bal)
		if err != nil {
			return err
		}
	}
	return nil
}
