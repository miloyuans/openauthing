package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/miloyuans/openauthing/internal/config"
	"github.com/miloyuans/openauthing/internal/shared/httpjson"
)

const (
	serviceName  = "openauthing"
	currentPhase = "phase-1"
)

type Server struct {
	cfg        config.Config
	httpServer *http.Server
}

func New(cfg config.Config) *Server {
	s := &Server{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /api/v1/meta", s.handleMeta)

	s.httpServer = &http.Server{
		Addr:         cfg.HTTP.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
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

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	_ = httpjson.Write(w, http.StatusOK, map[string]any{
		"service":     serviceName,
		"status":      "ok",
		"environment": s.cfg.Environment,
		"phase":       currentPhase,
	})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	checks := map[string]bool{
		"postgres_dsn_configured": s.cfg.Postgres.DSN != "",
		"redis_addr_configured":   s.cfg.Redis.Addr != "",
		"cookie_secret_configured": s.cfg.Security.CookieSecret != "" &&
			s.cfg.Security.CookieSecret != "change-me",
	}

	ready := true
	for _, passed := range checks {
		if !passed {
			ready = false
			break
		}
	}

	statusCode := http.StatusOK
	status := "ready"
	if !ready {
		statusCode = http.StatusServiceUnavailable
		status = "bootstrap_required"
	}

	_ = httpjson.Write(w, statusCode, map[string]any{
		"service": serviceName,
		"status":  status,
		"phase":   currentPhase,
		"checks":  checks,
	})
}

func (s *Server) handleMeta(w http.ResponseWriter, _ *http.Request) {
	_ = httpjson.Write(w, http.StatusOK, map[string]any{
		"service": serviceName,
		"phase":   currentPhase,
		"modules": []string{
			"usercenter",
			"authcore",
			"oidc",
			"saml",
			"cas",
			"ldap",
			"scim",
			"apps",
			"audit",
			"session",
			"policy",
			"shared",
		},
		"roadmap": []map[string]string{
			{"id": "phase-1", "name": "基础框架"},
			{"id": "phase-2", "name": "Auth Core"},
			{"id": "phase-3", "name": "OIDC"},
			{"id": "phase-4", "name": "SAML"},
			{"id": "phase-5", "name": "CAS"},
			{"id": "phase-6", "name": "LDAP"},
			{"id": "phase-7", "name": "SCIM"},
			{"id": "phase-8", "name": "增强"},
		},
	})
}
