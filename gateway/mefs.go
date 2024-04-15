package gateway

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	mclient "github.com/memoio/go-mefs-v2/api/client"
	"github.com/memoio/go-mefs-v2/build"
	mcode "github.com/memoio/go-mefs-v2/lib/code"
	metag "github.com/memoio/go-mefs-v2/lib/etag"
	mtypes "github.com/memoio/go-mefs-v2/lib/types"
	"github.com/memoio/meeda-node/logs"
	"github.com/memoio/meeda-node/utils"
)

var logger = logs.Logger("mefs")

var _ IGateway = (*Mefs)(nil)

type Mefs struct {
	st      StorageType
	addr    string
	headers http.Header
}

func NewGateway() (IGateway, error) {
	repoDir := os.Getenv("MEFS_PATH")
	addr, headers, err := mclient.GetMemoClientInfo(repoDir)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return nil, lerr
	}
	napi, closer, err := mclient.NewUserNode(context.Background(), addr, headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return nil, lerr
	}
	defer closer()
	_, err = napi.ShowStorage(context.Background())
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return nil, lerr
	}

	return &Mefs{
		st:      MEFS,
		addr:    addr,
		headers: headers,
	}, nil
}

func (m *Mefs) GetStoreType(ctx context.Context) StorageType {
	return m.st
}

func (m *Mefs) MakeBucketWithLocation(ctx context.Context, bucket string) error {
	napi, closer, err := mclient.NewUserNode(ctx, m.addr, m.headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return lerr
	}
	defer closer()
	opts := mcode.DefaultBucketOptions()

	_, err = napi.CreateBucket(ctx, bucket, opts)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return lerr
	}
	return nil
}

func (m *Mefs) GetBucketInfo(ctx context.Context, bucket string) (bi mtypes.BucketInfo, err error) {
	napi, closer, err := mclient.NewUserNode(ctx, m.addr, m.headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return bi, lerr
	}
	defer closer()

	bi, err = napi.HeadBucket(ctx, bucket)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return bi, lerr
	}
	return bi, nil
}

func (m *Mefs) PutObject(ctx context.Context, bucket, object string, r io.Reader, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	err = m.MakeBucketWithLocation(ctx, bucket)
	if err != nil {
		if !strings.Contains(err.Error(), "already exist") {
			lerr := logs.StorageError{Message: err.Error()}
			logger.Error(lerr)
			return objInfo, lerr
		}
	} else {
		log.Println("create bucket ", bucket)
		for !m.CheckBucket(ctx, bucket) {
			time.Sleep(10 * time.Second)
		}
	}

	napi, closer, err := mclient.NewUserNode(ctx, m.addr, m.headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return objInfo, lerr
	}
	defer closer()

	poo := mtypes.CidUploadOption()
	for k, v := range opts.UserDefined {
		poo.UserDefined[k] = v
	}
	moi, err := napi.PutObject(ctx, bucket, object, r, poo)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return objInfo, lerr
	}

	etag, _ := metag.ToString(moi.ETag)

	return ObjectInfo{
		Bucket:      bucket,
		Name:        moi.Name,
		Size:        int64(moi.Size),
		Cid:         etag,
		ModTime:     time.Unix(moi.GetTime(), 0),
		UserDefined: moi.UserDefined,
		SType:       m.st,
	}, nil
}

func (m *Mefs) GetObject(ctx context.Context, objectName string, writer io.Writer, opts ObjectOptions) error {
	napi, closer, err := mclient.NewUserNode(ctx, m.addr, m.headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return lerr
	}
	defer closer()

	objInfo, err := napi.HeadObject(ctx, "", objectName)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return lerr
	}

	length := int64(objInfo.Size)

	stepLen := int64(build.DefaultSegSize * 16)
	stepAccMax := 16

	start := int64(0)
	end := length
	stepacc := 1
	for start < end {
		if stepacc > stepAccMax {
			stepacc = stepAccMax
		}

		readLen := stepLen*int64(stepacc) - (start % stepLen)
		if end-start < readLen {
			readLen = end - start
		}

		doo := mtypes.DownloadObjectOptions{
			Start:  start,
			Length: readLen,
		}

		data, err := napi.GetObject(ctx, "", objectName, doo)
		if err != nil {
			//log.Println("received length err is:", start, readLen, stepLen, err)
			break
		}
		writer.Write(data)
		start += int64(readLen)
		stepacc *= 2
	}

	return nil
}

func (m *Mefs) GetObjectEtag(ctx context.Context, bucket, object string) (string, error) {
	napi, closer, err := mclient.NewUserNode(ctx, m.addr, m.headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return "", lerr
	}
	defer closer()

	objInfo, err := napi.HeadObject(ctx, bucket, object)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return "", lerr
	}
	return metag.ToString(objInfo.ETag)
}

func (m *Mefs) GetObjectInfo(ctx context.Context, cid string) (ObjectInfo, error) {
	result := ObjectInfo{}
	napi, closer, err := mclient.NewUserNode(ctx, m.addr, m.headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return result, lerr
	}
	defer closer()

	objInfo, err := napi.HeadObject(ctx, "", cid)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return result, lerr
	}
	ctype := utils.TypeByExtension(objInfo.Name)
	if objInfo.UserDefined["content-type"] != "" {
		ctype = objInfo.UserDefined["content-type"]
	}
	return ObjectInfo{
		Name:  objInfo.Name,
		Size:  int64(objInfo.Size),
		CType: ctype,
	}, nil
}

func (m *Mefs) ListObjects(ctx context.Context, bucket string) ([]ObjectInfo, error) {
	var loi []ObjectInfo
	napi, closer, err := mclient.NewUserNode(ctx, m.addr, m.headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return loi, lerr
	}
	defer closer()
	mloi, err := napi.ListObjects(ctx, bucket, mtypes.ListObjectsOptions{MaxKeys: 1000})
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return loi, lerr
	}

	for _, oi := range mloi.Objects {
		etag, _ := metag.ToString(oi.ETag)
		loi = append(loi, ObjectInfo{
			Bucket:      bucket,
			Name:        oi.GetName(),
			ModTime:     time.Unix(oi.GetTime(), 0).UTC(),
			Size:        int64(oi.Size),
			Cid:         etag,
			UserDefined: oi.UserDefined,
		})
	}

	return loi, nil
}

func (m *Mefs) DeleteObject(ctx context.Context, bucket, object string) error {
	napi, closer, err := mclient.NewUserNode(ctx, m.addr, m.headers)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return lerr
	}
	defer closer()

	err = napi.DeleteObject(ctx, bucket, object)
	if err != nil {
		lerr := logs.StorageError{Message: err.Error()}
		logger.Error(lerr)
		return lerr
	}
	return nil
}

func (m *Mefs) CheckBucket(ctx context.Context, bucket string) bool {
	bi, err := m.GetBucketInfo(ctx, bucket)
	if err != nil {
		return false
	}

	return bi.Confirmed
}
