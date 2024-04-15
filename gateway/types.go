package gateway

import (
	"math/big"
	"time"
)

type ObjectInfo struct {
	SType       StorageType
	Bucket      string
	Name        string
	Size        int64
	Cid         string
	ModTime     time.Time
	CType       string
	UserDefined map[string]string
}

type ObjectOptions struct {
	Size         int64
	Sign         string
	Area         string
	MTime        time.Time
	DeleteMarker bool
	UserDefined  map[string]string
}

type StorageType uint8

const (
	MEFS StorageType = iota
	IPFS
	QINIU
)

func (s StorageType) String() string {
	switch s {
	case MEFS:
		return "mefs"
	case IPFS:
		return "ipfs"
	case QINIU:
		return "qiniu"
	default:
		return "unknow storage"
	}
}

func StringToStorageType(s string) StorageType {
	storage := new(big.Int)
	storage.SetString(s, 10)
	return StorageType(storage.Uint64())
}

func Uint8ToStorageType(s uint8) StorageType {
	return StorageType(s)
}
