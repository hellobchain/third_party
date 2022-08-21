package algo

import (
	"github.com/spf13/viper"
	"github.com/wsw365904/newcryptosm"
	"github.com/wsw365904/wswlog/wlogging"
)

var logger = wlogging.MustGetLoggerWithoutName()

func SetGMFlag() {
	logger.Info("SetGMFlag")
	viper.Set("GMFlag", true)
}

func GetGMFlag() bool {
	algoFlag := viper.GetBool("GMFlag")
	logger.Info("GetGMFlag:", algoFlag)
	return algoFlag
}

func GetDefaultHash() newcryptosm.Hash {
	if GetGMFlag() {
		return newcryptosm.SM3
	} else {
		return newcryptosm.SHA256
	}
}

func GetAlgo() string {
	if GetGMFlag() {
		return "sm2"
	} else {
		return "ecdsa"
	}
}
