package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"sql-proxy/internal/config"
	"sql-proxy/internal/logging"
	"sql-proxy/internal/proxy"

	"go.uber.org/zap"
)

func main() {
	configPath := flag.String("config", "config.yaml", "config file path")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		panic(err)
	}

	logger := logging.New(cfg.LogLevel)
	defer logger.Sync()

	srv := proxy.NewServer(cfg, logger)

	logger.Info("starting SQL proxy",
		zap.String("listen_addr", cfg.ListenAddr),
		zap.String("upstream_addr", cfg.UpstreamAddr),
	)

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		logger.Info("received shutdown signal")
		// srv.Shutdown() // بعداً فعال می‌کنیم
	}()

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server stopped with error", zap.Error(err))
	}

	logger.Info("server stopped")
}
