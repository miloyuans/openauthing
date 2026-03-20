package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/miloyuans/openauthing/internal/config"
	platformhandler "github.com/miloyuans/openauthing/internal/platform/handler"
	platformrepo "github.com/miloyuans/openauthing/internal/platform/repo"
	platformservice "github.com/miloyuans/openauthing/internal/platform/service"
	servermiddleware "github.com/miloyuans/openauthing/internal/server/middleware"
)

const defaultServiceName = "openauthing"

type Server struct {
	cfg        config.Config
	httpServer *http.Server
	logger     *slog.Logger
}

func New(cfg config.Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:    cfg,
		logger: logger,
	}

	router := chi.NewRouter()
	router.Use(servermiddleware.RequestID)
	router.Use(servermiddleware.CORS(cfg.HTTP.AllowedOrigins))
	router.Use(servermiddleware.Recovery(logger))
	router.Use(servermiddleware.Logging(logger))

	readinessRepo := platformrepo.NewConfigReadinessRepository(cfg)
	serviceName := cfg.App.Name
	if serviceName == "" {
		serviceName = defaultServiceName
	}

	statusService := platformservice.NewStatusService(serviceName, readinessRepo)
	statusHandler := platformhandler.NewStatusHandler(statusService)
	statusHandler.Register(router)

	apiRouter := chi.NewRouter()
	apiRouter.Use(servermiddleware.AuthPlaceholder)
	statusHandler.RegisterAPI(apiRouter)
	router.Mount("/api/v1", apiRouter)

	s.httpServer = &http.Server{
		Addr:    cfg.HTTP.Addr,
		Handler: router,
	}

	return s
}

func (s *Server) Start() error {
	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
