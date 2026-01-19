package logger

import (
	"log"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var globalLogger *zap.Logger

const DefaultLogLevel = "info"

func Init(level string) {
	if level == "" {
		level = DefaultLogLevel
	}

	var l zapcore.Level
	if err := l.Set(level); err != nil {
		panic(err)
	}
	globalLogger = NewLogger(l)
}

func GetLogger() *zap.Logger {
	return globalLogger
}

func NewLogger(level zapcore.Level) *zap.Logger {
	logConf := zap.NewProductionConfig()
	logConf.Level = zap.NewAtomicLevelAt(level)
	logger, err := logConf.Build()
	if err != nil {
		log.Fatalf("create log failed:%s", err.Error())
	}
	return logger
}
