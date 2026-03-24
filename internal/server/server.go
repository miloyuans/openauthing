package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	authhandler "github.com/miloyuans/openauthing/internal/auth/handler"
	authmiddleware "github.com/miloyuans/openauthing/internal/auth/middleware"
	authpassword "github.com/miloyuans/openauthing/internal/auth/password"
	authrepo "github.com/miloyuans/openauthing/internal/auth/repo"
	authratelimit "github.com/miloyuans/openauthing/internal/auth/ratelimit"
	authservice "github.com/miloyuans/openauthing/internal/auth/service"
	appshandler "github.com/miloyuans/openauthing/internal/apps/handler"
	appsrepo "github.com/miloyuans/openauthing/internal/apps/repo"
	appsservice "github.com/miloyuans/openauthing/internal/apps/service"
	"github.com/miloyuans/openauthing/internal/config"
	oidchandler "github.com/miloyuans/openauthing/internal/oidc/handler"
	"github.com/miloyuans/openauthing/internal/oidc/keys"
	oidcrepo "github.com/miloyuans/openauthing/internal/oidc/repo"
	oidcservice "github.com/miloyuans/openauthing/internal/oidc/service"
	platformhandler "github.com/miloyuans/openauthing/internal/platform/handler"
	platformrepo "github.com/miloyuans/openauthing/internal/platform/repo"
	platformservice "github.com/miloyuans/openauthing/internal/platform/service"
	samlhandler "github.com/miloyuans/openauthing/internal/saml/handler"
	samlkeys "github.com/miloyuans/openauthing/internal/saml/keys"
	samlrepo "github.com/miloyuans/openauthing/internal/saml/repo"
	samlservice "github.com/miloyuans/openauthing/internal/saml/service"
	servermiddleware "github.com/miloyuans/openauthing/internal/server/middleware"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
	usercenterhandler "github.com/miloyuans/openauthing/internal/usercenter/handler"
	usercenterrepo "github.com/miloyuans/openauthing/internal/usercenter/repo"
	usercenterservice "github.com/miloyuans/openauthing/internal/usercenter/service"
)

const defaultServiceName = "openauthing"

type Server struct {
	cfg        config.Config
	httpServer *http.Server
	logger     *slog.Logger
	store      *postgresstore.Store
}

func New(cfg config.Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}

	store, err := postgresstore.Open(cfg.Postgres.DSN)
	if err != nil {
		return nil, fmt.Errorf("open postgres store: %w", err)
	}

	s := &Server{
		cfg:    cfg,
		logger: logger,
		store:  store,
	}

	router := chi.NewRouter()
	router.Use(servermiddleware.RequestID)
	router.Use(servermiddleware.CORS(cfg.HTTP.AllowedOrigins))
	router.Use(servermiddleware.Recovery(logger))
	router.Use(servermiddleware.Logging(logger))

	oidcKeyManager, err := keys.NewManager(cfg.OIDC.SigningKeyFile, logger)
	if err != nil {
		return nil, fmt.Errorf("create oidc key manager: %w", err)
	}

	samlIssuer := strings.TrimSpace(cfg.OIDC.Issuer)
	if samlIssuer == "" {
		samlIssuer = "http://localhost:8080"
	}

	samlEntityID := strings.TrimSpace(cfg.SAML.IDPEntityID)
	if samlEntityID == "" {
		samlEntityID = strings.TrimRight(samlIssuer, "/") + "/saml/idp/metadata"
	}

	samlKeyManager, err := samlkeys.NewManager(samlEntityID, cfg.SAML.CertificateFile, cfg.SAML.PrivateKeyFile, logger)
	if err != nil {
		return nil, fmt.Errorf("create saml key manager: %w", err)
	}

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

	userRepo := usercenterrepo.NewPostgresUserRepository(store)
	sessionRepo := authrepo.NewPostgresSessionRepository(store)
	groupRepo := usercenterrepo.NewPostgresGroupRepository(store)
	roleRepo := usercenterrepo.NewPostgresRoleRepository(store)
	appRepo := appsrepo.NewPostgresApplicationRepository(store)
	samlRepo := samlrepo.NewPostgresServiceProviderRepository(store)
	oidcRepo := oidcrepo.NewPostgresRepository(store)
	loginLimiter := authratelimit.NewMemoryLimiter(5, time.Minute)
	authSvc := authservice.NewService(userRepo, sessionRepo, authpassword.NewArgon2ID(), loginLimiter, store, cfg.Session.Secret, logger)
	oidcSvc := oidcservice.NewService(cfg.OIDC, oidcKeyManager, oidcRepo, oidcRepo, oidcRepo, oidcRepo, userRepo, authSvc, store, cfg.Session.Secret, logger)
	oidcHandler := oidchandler.NewHandler(oidcSvc, authhandler.DefaultCookieName)
	samlSvc := samlservice.NewService(cfg.SAML, samlIssuer, appRepo, samlRepo, samlKeyManager)
	samlHandler := samlhandler.NewHandler(samlSvc)
	oidcHandler.Register(router)
	samlHandler.RegisterPublic(router)
	authHandler := authhandler.NewHandler(
		authSvc,
		authhandler.DefaultCookieName,
		strings.EqualFold(cfg.App.Env, "production"),
		authmiddleware.RequireSession(authhandler.DefaultCookieName, authSvc),
	)

	userHandler := usercenterhandler.NewUserHandler(usercenterservice.NewUserService(userRepo))
	groupHandler := usercenterhandler.NewGroupHandler(usercenterservice.NewGroupService(groupRepo))
	roleHandler := usercenterhandler.NewRoleHandler(usercenterservice.NewRoleService(roleRepo))
	appHandler := appshandler.NewApplicationHandler(appsservice.NewApplicationService(appRepo))

	authHandler.Register(apiRouter)
	userHandler.Register(apiRouter)
	groupHandler.Register(apiRouter)
	roleHandler.Register(apiRouter)
	appHandler.Register(apiRouter)
	samlHandler.RegisterAPI(apiRouter)
	router.Mount("/api/v1", apiRouter)

	s.httpServer = &http.Server{
		Addr:    cfg.HTTP.Addr,
		Handler: router,
	}

	return s, nil
}

func (s *Server) Start() error {
	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	return s.store.Close()
}
