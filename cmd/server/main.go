package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miloyuans/openauthing/internal/config"
	"github.com/miloyuans/openauthing/internal/logging"
	"github.com/miloyuans/openauthing/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stdout, nil)).Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger, err := logging.New(cfg.Log.Level)
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stdout, nil)).Error("failed to initialize logger", "error", err)
		os.Exit(1)
	}

	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	logger.Info("server started", "addr", cfg.HTTP.Addr, "app", cfg.App.Name, "env", cfg.App.Env)

	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("server exited", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown failed", "error", err)
			os.Exit(1)
		}
	}
}
