package challenger

import (
	"crypto/ecdsa"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	proof "github.com/memoio/go-did/file-proof"
	"github.com/memoio/meeda-node/logs"
)

var baseUrl = "localhost:8081"
var logger = logs.Logger("challenger node")
var zeroCommit bls12381.G1Affine
var zeroProof kzg.OpeningProof
var userSk *ecdsa.PrivateKey
var proofInstance *proof.ProofInstance

func InitChallengerNode(sk *ecdsa.PrivateKey) error {
	userSk = sk

	zeroCommit.X.SetZero()
	zeroCommit.Y.SetZero()

	zeroProof.ClaimedValue.SetZero()
	zeroProof.H.X.SetZero()
	zeroProof.H.Y.SetZero()

	var err error
	proofInstance, err = proof.NewProofInstance(userSk, "dev")
	if err != nil {
		return err
	}

	return nil
}
