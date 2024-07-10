package store

import (
	"crypto/ecdsa"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	dkzg "github.com/memoio/did-solidity/kzg"
	proof "github.com/memoio/go-did/file-proof"
	"github.com/memoio/meeda-node/gateway"
	"github.com/memoio/meeda-node/logs"
)

var DefaultSRS *kzg.SRS
var zeroCommit bls12381.G1Affine
var zeroProof kzg.OpeningProof

var defaultProofInstance *proof.ProofInstance
var submitterSk *ecdsa.PrivateKey
var daStore gateway.IGateway
var logger = logs.Logger("store node")
var defaultDABucket string = "da-bucket"
var defaultDAObject string = "da-txdata"
var defaultExpiration time.Duration = 7 * 24 * time.Hour

func InitStoreNode(chain string, sk *ecdsa.PrivateKey, api, token string, addrs *proof.ContractAddress) error {
	if api == "" {
		store, err := gateway.NewGateway()
		if err != nil {
			return err
		}
		daStore = store
	} else {
		store, err := gateway.CreateGateWay(api, token)
		if err != nil {
			return err
		}
		daStore = store
	}

	key, err := dkzg.InitKey()
	if err != nil {
		return err
	}

	DefaultSRS = &kzg.SRS{
		Pk: key.Pk,
		Vk: key.Vk,
	}

	zeroCommit.X.SetZero()
	zeroCommit.Y.SetZero()

	zeroProof.ClaimedValue.SetZero()
	zeroProof.H.X.SetZero()
	zeroProof.H.Y.SetZero()

	submitterSk = sk
	defaultProofInstance, err = proof.NewProofInstance(sk, chain, addrs)
	return err
}
