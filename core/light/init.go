package light

import (
	"crypto/ecdsa"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	dkzg "github.com/memoio/did-solidity/kzg"
	proof "github.com/memoio/go-did/file-proof"
	"github.com/memoio/meeda-node/logs"
)

var baseUrl string
var oldStoreNodeUrl string
var logger = logs.Logger("light node")
var zeroCommit bls12381.G1Affine
var zeroProof kzg.OpeningProof
var userSk *ecdsa.PrivateKey
var userAddr common.Address
var proofInstance *proof.ProofInstance
var DefaultSRS *kzg.SRS

func InitLightNode(chain string, sk *ecdsa.PrivateKey, ip, oldip string, addrs *proof.ContractAddress) error {
	userSk = sk
	userAddr = crypto.PubkeyToAddress(userSk.PublicKey)

	zeroCommit.X.SetZero()
	zeroCommit.Y.SetZero()

	zeroProof.ClaimedValue.SetZero()
	zeroProof.H.X.SetZero()
	zeroProof.H.Y.SetZero()

	var err error
	proofInstance, err = proof.NewProofInstance(userSk, chain, addrs)
	if err != nil {
		return err
	}

	key, err := dkzg.InitKey()
	if err != nil {
		return err
	}

	DefaultSRS = &kzg.SRS{
		Pk: key.Pk,
		Vk: key.Vk,
	}

	baseUrl = ip
	oldStoreNodeUrl = oldip

	return nil
}
