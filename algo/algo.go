package algo

import (
	"github.com/hellobchain/newcryptosm"
	"github.com/hellobchain/wswlog/wlogging"
)

var sm2AlgoFlag bool

var logger = wlogging.MustGetLoggerWithoutName()

func SetGMFlag() {
	logger.Debug("SetGMFlag")
	sm2AlgoFlag = true
}

func GetGMFlag() bool {
	logger.Debug("GetGMFlag:", sm2AlgoFlag)
	return sm2AlgoFlag
}

func GetDefaultHash() newcryptosm.Hash {
	if sm2AlgoFlag {
		return newcryptosm.SM3
	} else {
		return newcryptosm.SHA256
	}
}

func GetAlgo() string {
	if sm2AlgoFlag {
		return "sm2"
	} else {
		return "ecdsa"
	}
}
