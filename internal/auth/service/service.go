package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	authpassword "github.com/miloyuans/openauthing/internal/auth/password"
	authrepo "github.com/miloyuans/openauthing/internal/auth/repo"
	"github.com/miloyuans/openauthing/internal/auth/sessionid"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/requestid"
	"github.com/miloyuans/openauthing/internal/shared/validate"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

const (
	invalidCredentialsMessage = "invalid username/email or password"
	defaultSessionTTL         = 24 * time.Hour
)

type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error)
	GetByUsername(ctx context.Context, username string) (userdomain.User, error)
	GetByEmail(ctx context.Context, email string) (userdomain.User, error)
	UpdateLastLoginAt(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error
}

type PasswordVerifier interface {
	Verify(plain, encoded string) (bool, error)
}

type RateLimiter interface {
	Allow(key string) bool
	Reset(key string)
}

type TxManager interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}

type SIDManager interface {
	Generate() (string, error)
	Hash(secret, sid string) (string, error)
}

type Service struct {
	users         UserRepository
	sessions      authrepo.SessionRepository
	passwords     PasswordVerifier
	limiter       RateLimiter
	txManager     TxManager
	sidManager    SIDManager
	sessionSecret string
	sessionTTL    time.Duration
	logger        *slog.Logger
	now           func() time.Time
}

type defaultSIDManager struct{}

func (defaultSIDManager) Generate() (string, error) {
	return sessionid.Generate()
}

func (defaultSIDManager) Hash(secret, sid string) (string, error) {
	return sessionid.Hash(secret, sid)
}

func NewService(
	users UserRepository,
	sessions authrepo.SessionRepository,
	passwords PasswordVerifier,
	limiter RateLimiter,
	txManager TxManager,
	sessionSecret string,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if passwords == nil {
		passwords = authpassword.NewArgon2ID()
	}

	return &Service{
		users:         users,
		sessions:      sessions,
		passwords:     passwords,
		limiter:       limiter,
		txManager:     txManager,
		sidManager:    defaultSIDManager{},
		sessionSecret: strings.TrimSpace(sessionSecret),
		sessionTTL:    defaultSessionTTL,
		logger:        logger,
		now:           time.Now,
	}
}

func (s *Service) Login(ctx context.Context, input authdomain.LoginInput, meta authdomain.RequestMeta) (authdomain.LoginResult, error) {
	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.TrimSpace(input.Email)
	meta.IP = strings.TrimSpace(meta.IP)
	meta.UserAgent = strings.TrimSpace(meta.UserAgent)

	if err := validateLoginInput(input); err != nil {
		return authdomain.LoginResult{}, err
	}

	loginMethod := "username"
	loginValue := input.Username
	lookup := s.users.GetByUsername
	if input.Email != "" {
		loginMethod = "email"
		loginValue = strings.ToLower(input.Email)
		lookup = s.users.GetByEmail
	}

	limitKey := loginMethod + ":" + loginValue
	if s.limiter != nil && !s.limiter.Allow(limitKey) {
		s.logLoginFailure(ctx, loginMethod, loginValue, "rate_limited", nil)
		return authdomain.LoginResult{}, apierror.TooManyRequests("too many login attempts", nil)
	}

	user, err := lookup(ctx, loginValue)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrAmbiguous) {
			s.logLoginFailure(ctx, loginMethod, loginValue, "user_lookup_failed", err)
			return authdomain.LoginResult{}, apierror.Unauthorized(invalidCredentialsMessage)
		}

		s.logLoginFailure(ctx, loginMethod, loginValue, "user_lookup_error", err)
		return authdomain.LoginResult{}, err
	}

	if user.Status != "active" {
		s.logLoginFailure(ctx, loginMethod, loginValue, "user_not_active", nil, "user_id", user.ID.String(), "status", user.Status)
		return authdomain.LoginResult{}, apierror.Unauthorized(invalidCredentialsMessage)
	}

	if strings.TrimSpace(user.PasswordHash) == "" || strings.TrimSpace(user.PasswordAlgo) != authpassword.Algorithm {
		s.logLoginFailure(ctx, loginMethod, loginValue, "password_not_available", nil, "user_id", user.ID.String(), "password_algo", user.PasswordAlgo)
		return authdomain.LoginResult{}, apierror.Unauthorized(invalidCredentialsMessage)
	}

	ok, err := s.passwords.Verify(input.Password, user.PasswordHash)
	if err != nil {
		s.logLoginFailure(ctx, loginMethod, loginValue, "password_verify_error", err, "user_id", user.ID.String())
		return authdomain.LoginResult{}, apierror.Unauthorized(invalidCredentialsMessage)
	}
	if !ok {
		s.logLoginFailure(ctx, loginMethod, loginValue, "password_mismatch", nil, "user_id", user.ID.String())
		return authdomain.LoginResult{}, apierror.Unauthorized(invalidCredentialsMessage)
	}

	if strings.TrimSpace(s.sessionSecret) == "" {
		return authdomain.LoginResult{}, apierror.InvalidConfig("session.secret is required for session issuance", nil)
	}

	rawSID, err := s.sidManager.Generate()
	if err != nil {
		return authdomain.LoginResult{}, apierror.Internal()
	}

	hashedSID, err := s.sidManager.Hash(s.sessionSecret, rawSID)
	if err != nil {
		return authdomain.LoginResult{}, apierror.Internal()
	}

	now := s.now().UTC()
	expiresAt := now.Add(s.sessionTTL)
	session := authdomain.Session{
		TenantID:    user.TenantID,
		UserID:      user.ID,
		SID:         hashedSID,
		LoginMethod: loginMethod,
		MFAVerified: false,
		IP:          meta.IP,
		UserAgent:   meta.UserAgent,
		Status:      authdomain.SessionStatusActive,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		LastSeenAt:  now,
	}

	if err := s.withinTx(ctx, func(txCtx context.Context) error {
		if err := s.users.UpdateLastLoginAt(txCtx, user.ID, now); err != nil {
			return err
		}

		createdSession, createErr := s.sessions.Create(txCtx, session)
		if createErr != nil {
			return createErr
		}
		session = createdSession
		return nil
	}); err != nil {
		s.logLoginFailure(ctx, loginMethod, loginValue, "create_session_failed", err, "user_id", user.ID.String())
		return authdomain.LoginResult{}, err
	}

	user.LastLoginAt = &now
	if s.limiter != nil {
		s.limiter.Reset(limitKey)
	}

	s.logger.Info("session created",
		"request_id", requestid.FromContext(ctx),
		"user_id", user.ID.String(),
		"tenant_id", user.TenantID.String(),
		"session_id", session.ID.String(),
		"login_method", loginMethod,
	)
	s.logger.Info("auth login succeeded",
		"request_id", requestid.FromContext(ctx),
		"login_method", loginMethod,
		"login_value", loginValue,
		"user_id", user.ID.String(),
		"tenant_id", user.TenantID.String(),
		"session_id", session.ID.String(),
	)

	return authdomain.LoginResult{
		Authenticated: true,
		User:          authdomain.NewUserSummary(user),
		SessionID:     rawSID,
		ExpiresAt:     expiresAt,
	}, nil
}

func (s *Service) Authenticate(ctx context.Context, rawSID string) (authdomain.Session, error) {
	hashedSID, err := s.sidManager.Hash(s.sessionSecret, rawSID)
	if err != nil {
		return authdomain.Session{}, apierror.Unauthorized("authentication is required")
	}

	session, err := s.sessions.GetBySID(ctx, hashedSID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return authdomain.Session{}, apierror.Unauthorized("authentication is required")
		}
		return authdomain.Session{}, err
	}

	if session.Status != authdomain.SessionStatusActive || s.now().UTC().After(session.ExpiresAt) {
		return authdomain.Session{}, apierror.Unauthorized("authentication is required")
	}

	lastSeenAt := s.now().UTC()
	if err := s.sessions.Touch(ctx, session.ID, lastSeenAt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return authdomain.Session{}, apierror.Unauthorized("authentication is required")
		}
		return authdomain.Session{}, err
	}
	session.LastSeenAt = lastSeenAt

	return session, nil
}

func (s *Service) Me(ctx context.Context, session authdomain.Session) (authdomain.UserSummary, error) {
	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return authdomain.UserSummary{}, apierror.Unauthorized("authentication is required")
		}
		return authdomain.UserSummary{}, err
	}

	return authdomain.NewUserSummary(user), nil
}

func (s *Service) LogoutCurrent(ctx context.Context, session authdomain.Session) error {
	logoutAt := s.now().UTC()
	if err := s.sessions.Logout(ctx, session.ID, logoutAt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return apierror.NotFound("session not found")
		}
		return err
	}

	s.logger.Info("session logout",
		"request_id", requestid.FromContext(ctx),
		"user_id", session.UserID.String(),
		"session_id", session.ID.String(),
	)
	return nil
}

func (s *Service) ListSessions(ctx context.Context, currentSession authdomain.Session) ([]authdomain.SessionListItem, error) {
	sessions, err := s.sessions.ListByUserID(ctx, currentSession.UserID)
	if err != nil {
		return nil, err
	}

	items := make([]authdomain.SessionListItem, 0, len(sessions))
	for _, session := range sessions {
		items = append(items, authdomain.NewSessionListItem(session, currentSession.ID))
	}

	return items, nil
}

func (s *Service) RevokeSession(ctx context.Context, currentSession authdomain.Session, id string) error {
	sessionID, err := uuid.Parse(strings.TrimSpace(id))
	if err != nil {
		return apierror.Validation(map[string]any{
			"fields": map[string]string{"id": "must be a valid UUID"},
		})
	}

	revokedAt := s.now().UTC()
	if err := s.sessions.RevokeByID(ctx, sessionID, currentSession.UserID, revokedAt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return apierror.NotFound("session not found")
		}
		return err
	}

	s.logger.Info("session revoke",
		"request_id", requestid.FromContext(ctx),
		"user_id", currentSession.UserID.String(),
		"session_id", sessionID.String(),
	)
	return nil
}

func (s *Service) withinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.txManager == nil {
		return fn(ctx)
	}

	return s.txManager.WithinTx(ctx, fn)
}

func validateLoginInput(input authdomain.LoginInput) error {
	fieldErrors := map[string]string{}
	hasUsername := input.Username != ""
	hasEmail := input.Email != ""

	switch {
	case hasUsername && hasEmail:
		fieldErrors["username"] = "username and email cannot be used together"
		fieldErrors["email"] = "username and email cannot be used together"
	case !hasUsername && !hasEmail:
		fieldErrors["username"] = "username or email is required"
	}

	if hasUsername {
		validate.Username("username", input.Username, fieldErrors)
	}
	if hasEmail {
		validate.Email("email", input.Email, fieldErrors)
		if strings.TrimSpace(input.Email) == "" {
			fieldErrors["email"] = "is required"
		}
	}
	validate.Password("password", input.Password, fieldErrors)

	if len(fieldErrors) > 0 {
		return apierror.Validation(map[string]any{"fields": fieldErrors})
	}

	return nil
}

func (s *Service) logLoginFailure(ctx context.Context, method, value, reason string, err error, extra ...any) {
	attrs := []any{
		"request_id", requestid.FromContext(ctx),
		"login_method", method,
		"login_value", value,
		"reason", reason,
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	attrs = append(attrs, extra...)

	s.logger.Warn("auth login failed", attrs...)
}
