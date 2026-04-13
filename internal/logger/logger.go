package logger

import (
	"log"

	"go.uber.org/zap"
)

func Init() *zap.Logger {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Could not initialize logger: %v", err)
	}

	zap.ReplaceGlobals(logger)

	logger.Info("Logger initialized")
	return logger
}
