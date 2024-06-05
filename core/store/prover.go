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
	proof "github.com/memoio/go-did/file-proof"
	"github.com/memoio/meeda-node/database"
	"github.com/memoio/meeda-node/gateway"
	"github.com/memoio/meeda-node/utils"
)

type DataAvailabilityProver struct {
	proofInstance      proof.ProofInstance
	selectedFileNumber int64
	provingKey         kzg.ProvingKey
	interval           time.Duration
	period             time.Duration
	respondTime        int64
	last               int64
}

func NewDataAvailabilityProver(chain string, sk *ecdsa.PrivateKey) (*DataAvailabilityProver, error) {
	instance, err := proof.NewProofInstance(sk, chain)
	if err != nil {
		return nil, err
	}

	info, err := instance.GetSettingInfo()
	if err != nil {
		return nil, err
	}

	return &DataAvailabilityProver{
		proofInstance:      *instance,
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
	var proveSuccess bool
	for p.last == 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		_, _, lastTime, err := p.proofInstance.GetVerifyInfo()
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
		var lock bool
		start := time.Now()
		logger.Info("start prove")
		lastRnd = nowRnd
		nowRnd, lock, err = p.generateRND()
		if err != nil {
			logger.Error(err.Error())
			proveSuccess = false
			continue
		}

		if !lock {
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

	p.last = p.last + duration - over
	next := p.last + challengeCycleSeconds

	return time.Duration(waitingSeconds) * time.Second, next
}

func (p *DataAvailabilityProver) resetChallengeStatus() error {
	info, err := p.proofInstance.GetChallengeInfo()
	if err != nil {
		return err
	}

	if info.ChalStatus != 0 {
		return p.proofInstance.EndChallenge()
	}

	return nil
}

func (p *DataAvailabilityProver) generateRND() (fr.Element, bool, error) {
	rnd := fr.Element{}
	err := p.proofInstance.GenerateRnd()
	if err != nil {
		return rnd, false, err
	}

	rnd, lock, _, err := p.proofInstance.GetVerifyInfo()
	if err != nil {
		return rnd, false, err
	}
	return rnd, lock, nil
}

func (p *DataAvailabilityProver) selectFiles(rnd fr.Element) ([]bls12381.G1Affine, []kzg.OpeningProof, error) {
	var commits []bls12381.G1Affine = make([]bls12381.G1Affine, p.selectedFileNumber)
	var proofs []kzg.OpeningProof = make([]kzg.OpeningProof, p.selectedFileNumber)
	info, err := p.proofInstance.GetChallengeInfo()
	if err != nil {
		return nil, nil, err
	}
	length := info.ChalLength.Int64()

	rndBytes, err := p.proofInstance.GetRndRawBytes()
	if err != nil {
		return nil, nil, err
	}

	var random *big.Int = big.NewInt(0).SetBytes(rndBytes[:])
	random = new(big.Int).Mod(random, big.NewInt(length))
	startIndex := new(big.Int).Div(random, big.NewInt(2)).Int64()

	var endIndex int64
	if p.selectedFileNumber > length {
		endIndex = startIndex + (length-1)/2
	} else {
		endIndex = startIndex + (p.selectedFileNumber-1)/2
	}

	files, err := database.GetRangeDAFileInfo(uint(startIndex+1), uint(endIndex+1))
	if err != nil {
		return nil, nil, err
	}

	var tmpCommits = make([]bls12381.G1Affine, len(files))
	var tmpProofs = make([]kzg.OpeningProof, len(files))
	for index, file := range files {
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

			tmpCommits[index] = file.Commit
			tmpProofs[index] = proof
		} else {
			tmpCommits[index] = zeroCommit
			tmpProofs[index] = zeroProof
		}
	}

	for index := 0; index < int(p.selectedFileNumber); index++ {
		commits[index] = tmpCommits[index%int(length)/2]
		proofs[index] = tmpProofs[index%int(length)/2]
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
		info, err := p.proofInstance.GetChallengeInfo()
		if err != nil {
			return err
		}

		if info.ChalStatus%2 == 0 {
			if time.Now().Unix() > p.last+p.respondTime*int64(info.ChalStatus+1) {
				if info.ChalStatus != 0 {
					return p.proofInstance.EndChallenge()
				} else {
					return nil
				}
			}
		} else if info.ChalStatus == 11 {
			var splitLength = len(commits) / 10
			selectedCommits := commits[int(info.ChalIndex)*splitLength : int(info.ChalIndex+1)*splitLength]
			return p.proofInstance.OneStepProve(selectedCommits)
		} else {
			if info.ChalStatus != 1 {
				commits = splitedCommits[info.ChalIndex]
			}
			var aggregatedCommits [10]bls12381.G1Affine
			var splitLength = len(commits) / 10
			for i := 0; i < 10; i++ {
				splitedCommits[i] = commits[i*splitLength : (i+1)*splitLength]
				var aggregatedCommit bls12381.G1Affine = splitedCommits[i][0]
				for _, commit := range splitedCommits[i][1:] {
					aggregatedCommit.Add(&aggregatedCommit, &commit)
				}
				aggregatedCommits[i] = aggregatedCommit
				fmt.Println(aggregatedCommit)
			}
			err := p.proofInstance.ResponseChallenge(aggregatedCommits)
			if err != nil {
				return err
			}
		}
		time.Sleep(5 * time.Second)
	}
}
