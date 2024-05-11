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
	"github.com/ethereum/go-ethereum/common/hexutil"
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
		c.Error(lerr)
		return
	}

	var commit bls12381.G1Affine
	idBytes, err := hexutil.Decode(id)
	if err != nil {
		c.Error(err)
		return
	}
	err = commit.Unmarshal(idBytes)
	if err != nil {
		c.Error(err)
		return
	}

	// check if it is submite to contract
	file, err := database.GetFileInfoByCommit(commit)
	if err != nil {
		c.Error(err)
		return
	}

	fileID, err := database.GetFileIDInfoByCommit(file.Commit)
	if err != nil {
		c.Error(err)
		return
	}

	var w bytes.Buffer
	err = daStore.GetObject(c.Request.Context(), fileID.Mid, &w, gateway.ObjectOptions{})
	if err != nil {
		c.Error(err)
		return
	}

	c.Data(http.StatusOK, utils.TypeByExtension(""), w.Bytes())
}

func putObjectHandler(c *gin.Context) {
	body := make(map[string]interface{})
	c.BindJSON(&body)
	data, ok := body["data"].(string)
	if !ok {
		lerr := logs.ServerError{Message: "field 'data' is not set"}
		c.Error(lerr)
		return
	}
	from, ok := body["from"].(string)
	if !ok {
		lerr := logs.ServerError{Message: "field 'address' is not set"}
		c.Error(lerr)
		return
	}

	databyte, err := hex.DecodeString(data)
	if err != nil {
		lerr := logs.ServerError{Message: "field 'data' is not legally hexadecimal presented"}
		c.Error(lerr)
		return
	}

	object := defaultDAObject + hex.EncodeToString(crypto.Keccak256(databyte))

	var buf *bytes.Buffer = bytes.NewBuffer(databyte)
	oi, err := daStore.PutObject(c.Request.Context(), defaultDABucket, object, buf, gateway.ObjectOptions{})
	if err != nil {
		c.Error(err)
		return
	}

	elements := split(databyte)
	// log.Println(string(buf.Bytes()), elements)
	commit, err := kzg.Commit(elements, DefaultSRS.Pk)
	if err != nil {
		c.Error(err)
		return
	}

	start := time.Now()
	end := start.Add(defaultExpiration)
	hash := defaultProofInstance.GetCredentialHash(common.HexToAddress(from), commit, uint64(oi.Size), big.NewInt(start.Unix()), big.NewInt(end.Unix()))
	signature, err := crypto.Sign(hash, submitterSk)
	if err != nil {
		c.Error(err)
		return
	}

	// 记录commit => mid的映射
	var fileInfo = database.DAFileIDInfo{
		Commit: commit,
		Mid:    oi.Cid,
	}
	err = fileInfo.CreateDAFileIDInfo()
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"commit":   hex.EncodeToString(commit.Marshal()),
		"size":     oi.Size,
		"start":    start.Unix(),
		"end":      end.Unix(),
		"sigature": hex.EncodeToString(signature),
	})
}

func warmupHandler(c *gin.Context) {
	tempStore := daStore.(*gateway.Mefs)
	err := tempStore.MakeBucketWithLocation(c.Request.Context(), defaultDABucket)
	if err != nil {
		if !strings.Contains(err.Error(), "already exist") {
			c.Error(err)
		}
	} else {
		logger.Info("Create bucket ", defaultDABucket)
		for !tempStore.CheckBucket(c.Request.Context(), defaultDABucket) {
			time.Sleep(5 * time.Second)
		}
	}
	c.JSON(http.StatusOK, nil)
}
