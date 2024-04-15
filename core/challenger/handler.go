package challenger

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
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/gin-gonic/gin"
	"github.com/memoio/meeda-node/database"
	"github.com/memoio/meeda-node/logs"
	"github.com/memoio/meeda-node/utils"
	"golang.org/x/xerrors"
)

func LoadChallengerModule(g *gin.RouterGroup) {
	g.GET("/getObject", getObjectHandler)
	g.POST("/putObject", putObjectHandler)
	g.GET("/getObjectInfo", getObjectInfoHandler)
	g.GET("/getProofInfo", getProofInfoHandler)
	fmt.Println("load challenger moudle success!")
}

func getObjectHandler(c *gin.Context) {
	id := c.Query("id")
	if len(id) == 0 {
		lerr := logs.ServerError{Message: "object's id is not set"}
		c.Error(lerr)
		return
	}

	data, err := getObjectFromStoreNode(baseUrl, id)
	if err != nil {
		lerr := logs.ServerError{Message: "get object from store node failed"}
		c.Error(lerr)
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
		c.Error(lerr)
		return
	}
	from, ok := body["from"].(string)
	if !ok {
		lerr := logs.ServerError{Message: "field 'from' is not set"}
		c.Error(lerr)
		return
	}

	databyte, err := hex.DecodeString(data)
	if err != nil {
		lerr := logs.ServerError{Message: "field 'data' is not legally hexadecimal presented"}
		c.Error(lerr)
		return
	}

	result, err := putObjectIntoStoreNode(baseUrl, databyte, from)
	if err != nil {
		lerr := logs.ServerError{Message: "Error when calling store node api"}
		c.Error(lerr)
		return
	}

	var commit bls12381.G1Affine
	commitBytes, err := hex.DecodeString(result.Commit)
	if err != nil {
		lerr := logs.ServerError{Message: "commit is not legally hexadecimal presented"}
		c.Error(lerr)
		return
	}
	err = commit.Unmarshal(commitBytes)
	if err != nil {
		c.Error(err)
		return
	}

	signature, err := hex.DecodeString(result.Signature)
	if err != nil {
		c.Error(err)
		return
	}

	err = proofInstance.AddFile(commit, uint64(result.Size), big.NewInt(result.Start), big.NewInt(result.End), signature)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id": hex.EncodeToString(commit.Marshal()),
	})
}

func getObjectInfoHandler(c *gin.Context) {
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

	info, err := database.GetFileInfoByCommit(commit)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"commit":     id,
		"size":       info.Size,
		"expiration": info.Expiration,
	})
}

func getProofInfoHandler(c *gin.Context) {

}

func getObjectFromStoreNode(url string, id string) ([]byte, error) {
	client := &http.Client{Timeout: time.Minute}
	url = url + "/getObject"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	params := req.URL.Query()
	params.Add("id", id)
	req.URL.RawQuery = params.Encode()

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("Respond code[%d]", res.StatusCode)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

type PutObjectResult struct {
	Commit    string
	Size      int64
	Start     int64
	End       int64
	Signature string
}

func putObjectIntoStoreNode(url string, data []byte, from string) (PutObjectResult, error) {
	client := &http.Client{Timeout: time.Minute}
	url = url + "/putObject"

	var payload = make(map[string]string)
	payload["from"] = from
	payload["data"] = hex.EncodeToString(data)

	b, err := json.Marshal(payload)
	if err != nil {
		return PutObjectResult{}, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return PutObjectResult{}, err
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return PutObjectResult{}, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return PutObjectResult{}, err
	}

	if res.StatusCode != http.StatusOK {
		return PutObjectResult{}, xerrors.Errorf("Respond code[%d]: %s", res.StatusCode, string(body))
	}

	var result PutObjectResult
	err = json.Unmarshal(body, &result)
	if err != nil {
		return PutObjectResult{}, err
	}

	return result, nil
}
