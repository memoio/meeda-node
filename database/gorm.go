package database

import (
	"time"

	"github.com/memoio/meeda-node/logs"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var GlobalDataBase *gorm.DB
var logger = logs.Logger("database")

func init() {
	db, err := gorm.Open(sqlite.Open("backend.db"), &gorm.Config{})
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
