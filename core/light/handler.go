package light

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/gin-gonic/gin"
	"github.com/memoio/meeda-node/database"
	"github.com/memoio/meeda-node/logs"
	"github.com/memoio/meeda-node/utils"
	"golang.org/x/xerrors"
)

func LoadLightModule(g *gin.RouterGroup) {
	g.GET("/getObject", getObjectHandler)
	g.POST("/putObject", putObjectHandler)
	g.GET("/getObjectInfo", getObjectInfoHandler)
	g.GET("/getProofInfo", getProofInfoHandler)
	fmt.Println("load light node moudle success!")
}

func getObjectHandler(c *gin.Context) {
	id := c.Query("id")
	if len(id) == 0 {
		lerr := logs.ServerError{Message: "object's id is not set"}
		errRes := logs.ToAPIErrorCode(lerr)
		logger.Error(lerr)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	data, status, err := getObjectFromStoreNode(baseUrl, id)
	if err != nil {
		logger.Error(err)
		c.AbortWithStatusJSON(status, err.Error())
		return
	}

	c.Data(http.StatusOK, utils.TypeByExtension(""), data)
}

func putObjectHandler(c *gin.Context) {
	body := make(map[string]interface{})
	c.BindJSON(&body)
	data, ok := body["data"].(string)
	if !ok {
		lerr := logs.ServerError{Message: "field 'data' is not set"}
		errRes := logs.ToAPIErrorCode(lerr)
		logger.Error(lerr)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	databyte, err := hex.DecodeString(data)
	if err != nil {
		lerr := logs.ServerError{Message: "field 'data' is not legally hexadecimal presented"}
		errRes := logs.ToAPIErrorCode(lerr)
		logger.Error(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	result, status, err := putObjectIntoStoreNode(baseUrl, databyte, userAddr.String())
	if err != nil {
		logger.Error(err)
		c.AbortWithStatusJSON(status, err.Error())
		return
	}

	commit, err := decodeCommit(result.Commit)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		logger.Error(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	signature, err := hex.DecodeString(result.Signature)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		logger.Error(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	err = proofInstance.AddFile(commit, uint64(result.Size), big.NewInt(result.Start), big.NewInt(result.End), signature)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		logger.Error(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	commitBytes := commit.Bytes()
	c.JSON(http.StatusOK, gin.H{
		"id": hex.EncodeToString(commitBytes[:]),
	})
}

func getObjectInfoHandler(c *gin.Context) {
	id := c.Query("id")
	if len(id) == 0 {
		lerr := logs.ServerError{Message: "object's id is not set"}
		errRes := logs.ToAPIErrorCode(lerr)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	commit, err := decodeCommit(id)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	info, err := database.GetFileInfoByCommit(commit)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         id,
		"size":       info.Size,
		"expiration": info.Expiration,
	})
}

func getProofInfoHandler(c *gin.Context) {
	id := c.Query("id")
	if len(id) == 0 {
		lerr := logs.ServerError{Message: "object's id is not set"}
		errRes := logs.ToAPIErrorCode(lerr)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	commit, err := decodeCommit(id)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	info, err := database.GetFileInfoByCommit(commit)
	if err != nil {
		errRes := logs.ToAPIErrorCode(err)
		c.AbortWithStatusJSON(errRes.HTTPStatusCode, errRes)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":                  id,
		"chooseNuber":         info.ChooseNumber,
		"provedSuccessNumber": info.ProvedSuccessNumber,
	})
}

func getObjectFromStoreNode(url string, id string) ([]byte, int, error) {
	client := &http.Client{Timeout: time.Minute}
	url = url + "/getObject"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 500, err
	}

	params := req.URL.Query()
	params.Add("id", id)
	req.URL.RawQuery = params.Encode()

	res, err := client.Do(req)
	if err != nil {
		return nil, 500, err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 500, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, res.StatusCode, xerrors.Errorf(string(data))
	}

	return data, 200, nil
}

type PutObjectResult struct {
	Commit    string
	Size      int64
	Start     int64
	End       int64
	Signature string
}

func putObjectIntoStoreNode(url string, data []byte, from string) (PutObjectResult, int, error) {
	client := &http.Client{Timeout: time.Minute}
	url = url + "/putObject"

	var payload = make(map[string]string)
	payload["from"] = from
	payload["data"] = hex.EncodeToString(data)

	b, err := json.Marshal(payload)
	if err != nil {
		return PutObjectResult{}, 500, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return PutObjectResult{}, 500, err
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return PutObjectResult{}, 500, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return PutObjectResult{}, 500, err
	}

	if res.StatusCode != http.StatusOK {
		return PutObjectResult{}, res.StatusCode, xerrors.Errorf(string(body))
	}

	var result PutObjectResult
	err = json.Unmarshal(body, &result)
	if err != nil {
		return PutObjectResult{}, 500, err
	}

	return result, 200, nil
}

func decodeCommit(id string) (bls12381.G1Affine, error) {
	var commit bls12381.G1Affine
	commitBytes, err := hex.DecodeString(id)
	if err != nil {
		return commit, err
	}
	err = commit.Unmarshal(commitBytes)

	return commit, err
}
