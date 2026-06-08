package logging

import "go.uber.org/zap"

func New(level string) *zap.Logger {
    config := zap.NewProductionConfig()
    if level == "debug" {
        config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
    }
    logger, _ := config.Build()
    return logger
}