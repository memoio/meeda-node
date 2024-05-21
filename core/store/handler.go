package store

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/memoio/meeda-node/database"
	"github.com/memoio/meeda-node/gateway"
	"github.com/memoio/meeda-node/logs"
	"github.com/memoio/meeda-node/utils"
)

func LoadStoreModule(g *gin.RouterGroup) {
	g.GET("/getObject", getObjectHandler)
	g.POST("/putObject", putObjectHandler)
	g.GET("/warmup", warmupHandler)
	fmt.Println("load store node moudle success!")
}

func getObjectHandler(c *gin.Context) {
	id := c.Query("id")
	if len(id) == 0 {
		lerr := logs.ServerError{Message: "object's id is not set"}
		errRes := logs.ToAPIErrorCode(lerr)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	if len(id) == 96 {
		commit, err := decodeCommit(id)
		if err != nil {
			errRes := logs.ToAPIErrorCode(err)
			c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
			return
		}

		// check if it is submite to contract
		file, err := database.GetFileInfoByCommit(commit)
		if err != nil {
			errRes := logs.ToAPIErrorCode(err)
			c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
			return
		}

		fileID, err := database.GetFileIDInfoByCommit(file.Commit)
		if err != nil {
			errRes := logs.ToAPIErrorCode(err)
			c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
			return
		}

		id = fileID.Mid
	}

	var w bytes.Buffer
	err := daStore.GetObject(c.Request.Context(), id, &w, gateway.ObjectOptions{})
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	c.Data(http.StatusOK, utils.TypeByExtension(""), w.Bytes())
}

func putObjectHandler(c *gin.Context) {
	body := make(map[string]interface{})
	c.BindJSON(&body)
	data, ok := body["data"].(string)
	if !ok {
		errRes := logs.ToAPIErrorCode(logs.ServerError{Message: "field 'data' is not set"})
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}
	from, ok := body["from"].(string)
	if !ok {
		errRes := logs.ToAPIErrorCode(logs.ServerError{Message: "field 'from' is not set"})
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	databyte, err := hex.DecodeString(data)
	if err != nil {
		errRes := logs.ToAPIErrorCode(logs.ServerError{Message: "field 'data' is not legally hexadecimal presented"})
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	object := defaultDAObject + hex.EncodeToString(crypto.Keccak256(databyte))

	var buf *bytes.Buffer = bytes.NewBuffer(databyte)
	oi, err := daStore.PutObject(c.Request.Context(), defaultDABucket, object, buf, gateway.ObjectOptions{})
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	elements := split(databyte)
	commit, err := kzg.Commit(elements, DefaultSRS.Pk)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	start := time.Now()
	end := start.Add(defaultExpiration)
	hash := defaultProofInstance.GetCredentialHash(common.HexToAddress(from), commit, uint64(oi.Size), big.NewInt(start.Unix()), big.NewInt(end.Unix()))
	signature, err := crypto.Sign(hash, submitterSk)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	// 记录commit => mid的映射
	var fileInfo = database.DAFileIDInfo{
		Commit: commit,
		Mid:    oi.Cid,
	}
	err = fileInfo.CreateDAFileIDInfo()
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	commitBytes := commit.Bytes()
	c.JSON(http.StatusOK, gin.H{
		"commit":    hex.EncodeToString(commitBytes[:]),
		"size":      oi.Size,
		"start":     start.Unix(),
		"end":       end.Unix(),
		"signature": hex.EncodeToString(signature),
	})
}

func warmupHandler(c *gin.Context) {
	tempStore := daStore.(*gateway.Mefs)
	err := tempStore.MakeBucketWithLocation(c.Request.Context(), defaultDABucket)
	if err != nil {
		if !strings.Contains(err.Error(), "already exist") {
			errRes := logs.ToAPIErrorCode(err)
			c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
			return
		}
	} else {
		logger.Info("Create bucket ", defaultDABucket)
		for !tempStore.CheckBucket(c.Request.Context(), defaultDABucket) {
			time.Sleep(5 * time.Second)
		}
	}
	c.JSON(http.StatusOK, nil)
}

func decodeCommit(id string) (bls12381.G1Affine, error) {
	var commit bls12381.G1Affine
	commitBytes, err := hex.DecodeString(id)
	if err != nil {
		return commit, err
	}
	_, err = commit.SetBytes(commitBytes)
	if err != nil {
		return commit, err
	}

	return commit, nil
}
