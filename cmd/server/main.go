package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/miloyuans/openauthing/internal/config"
	"github.com/miloyuans/openauthing/internal/server"
)

func main() {
	cfg := config.Load()
	srv := server.New(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	log.Printf("openauthing listening on %s", cfg.HTTP.Addr)

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("server exited with error: %v", err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Fatalf("server shutdown failed: %v", err)
		}
	}
}
