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

func init() {
	dir, err := homedir.Expand("~/.meeda-store")
	if err != nil {
		panic(err)
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0666)
		if err != nil {
			panic(err)
		}
	}

	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "meeda.db")), &gorm.Config{})
	if err != nil {
		logger.Panicf("Failed to connect to database: %s", err.Error())
	}

	sqlDB, err := db.DB()
	if err != nil {
		logger.Panicf("Failed to get sql database: %s", err.Error())
	}

	// 设置连接池中空闲连接的最大数量。
	sqlDB.SetMaxIdleConns(10)
	// 设置打开数据库连接的最大数量。
	sqlDB.SetMaxOpenConns(100)
	// 设置超时时间
	sqlDB.SetConnMaxLifetime(time.Second * 30)

	err = sqlDB.Ping()
	if err != nil {
		logger.Panicf("Failed to ping database: %s", err.Error())
	}
	db.AutoMigrate(&DAFileInfoStore{}, &DAFileIDInfoStore{}, &DAProofInfoStore{})
	GlobalDataBase = db
}
