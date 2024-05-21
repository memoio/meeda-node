package database

import (
	"os"
	"path/filepath"
	"time"

	"github.com/memoio/meeda-node/logs"
	"github.com/mitchellh/go-homedir"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var GlobalDataBase *gorm.DB
var logger = logs.Logger("database")

func InitDatabase(path string) error {
	dir, err := homedir.Expand(path)
	if err != nil {
		return err
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0666)
		if err != nil {
			return err
		}
	}

	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "meeda.db")), &gorm.Config{})
	if err != nil {
		return err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	// 设置连接池中空闲连接的最大数量。
	sqlDB.SetMaxIdleConns(10)
	// 设置打开数据库连接的最大数量。
	sqlDB.SetMaxOpenConns(100)
	// 设置超时时间
	sqlDB.SetConnMaxLifetime(time.Second * 30)

	err = sqlDB.Ping()
	if err != nil {
		return err
	}
	db.AutoMigrate(&DAFileInfoStore{}, &DAFileIDInfoStore{}, &DAProofInfoStore{}, &DABlockNumber{})
	GlobalDataBase = db
	return nil
}
