package service

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	authrepo "github.com/miloyuans/openauthing/internal/auth/repo"
	"github.com/miloyuans/openauthing/internal/logging"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type userRepoStub struct {
	getByIDFn         func(ctx context.Context, id uuid.UUID) (userdomain.User, error)
	getByUsernameFn   func(ctx context.Context, username string) (userdomain.User, error)
	getByEmailFn      func(ctx context.Context, email string) (userdomain.User, error)
	updateLastLoginFn func(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error
}

func (s userRepoStub) GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error) {
	return s.getByIDFn(ctx, id)
}

func (s userRepoStub) GetByUsername(ctx context.Context, username string) (userdomain.User, error) {
	return s.getByUsernameFn(ctx, username)
}

func (s userRepoStub) GetByEmail(ctx context.Context, email string) (userdomain.User, error) {
	return s.getByEmailFn(ctx, email)
}

func (s userRepoStub) UpdateLastLoginAt(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error {
	return s.updateLastLoginFn(ctx, id, lastLoginAt)
}

type sessionRepoStub struct {
	createFn       func(ctx context.Context, session authdomain.Session) (authdomain.Session, error)
	getBySIDFn     func(ctx context.Context, sid string) (authdomain.Session, error)
	listByUserIDFn func(ctx context.Context, userID uuid.UUID) ([]authdomain.Session, error)
	touchFn        func(ctx context.Context, id uuid.UUID, lastSeenAt time.Time) error
	logoutFn       func(ctx context.Context, id uuid.UUID, logoutAt time.Time) error
	revokeFn       func(ctx context.Context, id, userID uuid.UUID, logoutAt time.Time) error
}

func (s sessionRepoStub) Create(ctx context.Context, session authdomain.Session) (authdomain.Session, error) {
	return s.createFn(ctx, session)
}

func (s sessionRepoStub) GetBySID(ctx context.Context, sid string) (authdomain.Session, error) {
	return s.getBySIDFn(ctx, sid)
}

func (s sessionRepoStub) ListByUserID(ctx context.Context, userID uuid.UUID) ([]authdomain.Session, error) {
	return s.listByUserIDFn(ctx, userID)
}

func (s sessionRepoStub) Touch(ctx context.Context, id uuid.UUID, lastSeenAt time.Time) error {
	return s.touchFn(ctx, id, lastSeenAt)
}

func (s sessionRepoStub) Logout(ctx context.Context, id uuid.UUID, logoutAt time.Time) error {
	return s.logoutFn(ctx, id, logoutAt)
}

func (s sessionRepoStub) RevokeByID(ctx context.Context, id, userID uuid.UUID, logoutAt time.Time) error {
	return s.revokeFn(ctx, id, userID, logoutAt)
}

type verifierStub struct {
	verifyFn func(plain, encoded string) (bool, error)
}

func (s verifierStub) Verify(plain, encoded string) (bool, error) {
	return s.verifyFn(plain, encoded)
}

type limiterStub struct {
	allow      bool
	resetCalls int
}

func (s *limiterStub) Allow(string) bool {
	return s.allow
}

func (s *limiterStub) Reset(string) {
	s.resetCalls++
}

type sidManagerStub struct {
	generateFn func() (string, error)
	hashFn     func(secret, sid string) (string, error)
}

func (s sidManagerStub) Generate() (string, error) {
	return s.generateFn()
}

func (s sidManagerStub) Hash(secret, sid string) (string, error) {
	return s.hashFn(secret, sid)
}

type txManagerStub struct {
	calls int
}

func (s *txManagerStub) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	s.calls++
	return fn(ctx)
}

func TestServiceLoginCreatesSession(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	updated := false
	createdSession := false
	limiter := &limiterStub{allow: true}
	txManager := &txManagerStub{}

	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	service := NewService(
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) {
				return userdomain.User{}, store.ErrNotFound
			},
			getByUsernameFn: func(_ context.Context, username string) (userdomain.User, error) {
				if username != "alice" {
					t.Fatalf("unexpected username: %q", username)
				}
				return userdomain.User{
					ID:           userID,
					TenantID:     tenantID,
					Username:     "alice",
					Email:        "alice@example.com",
					DisplayName:  "Alice",
					PasswordHash: "hashed-secret",
					PasswordAlgo: "argon2id",
					Status:       "active",
					Source:       "local",
				}, nil
			},
			getByEmailFn: func(context.Context, string) (userdomain.User, error) {
				t.Fatal("email lookup should not be used")
				return userdomain.User{}, nil
			},
			updateLastLoginFn: func(_ context.Context, id uuid.UUID, _ time.Time) error {
				if id != userID {
					t.Fatalf("unexpected user id: %s", id)
				}
				updated = true
				return nil
			},
		},
		sessionRepoStub{
			createFn: func(_ context.Context, session authdomain.Session) (authdomain.Session, error) {
				createdSession = true
				if session.UserID != userID || session.TenantID != tenantID {
					t.Fatalf("unexpected session payload: %#v", session)
				}
				session.ID = uuid.New()
				return session, nil
			},
			getBySIDFn: func(context.Context, string) (authdomain.Session, error) {
				return authdomain.Session{}, store.ErrNotFound
			},
			listByUserIDFn: func(context.Context, uuid.UUID) ([]authdomain.Session, error) {
				return nil, nil
			},
			touchFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			logoutFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			revokeFn: func(context.Context, uuid.UUID, uuid.UUID, time.Time) error { return nil },
		},
		verifierStub{verifyFn: func(plain, encoded string) (bool, error) {
			if plain != "secret123" || encoded != "hashed-secret" {
				t.Fatalf("unexpected verify args: %q %q", plain, encoded)
			}
			return true, nil
		}},
		limiter,
		txManager,
		"session-secret",
		logger,
	)
	service.sidManager = sidManagerStub{
		generateFn: func() (string, error) { return "raw-sid", nil },
		hashFn: func(secret, sid string) (string, error) {
			if secret != "session-secret" || sid != "raw-sid" {
				t.Fatalf("unexpected sid hash args: %q %q", secret, sid)
			}
			return "hashed-sid", nil
		},
	}
	service.now = func() time.Time {
		return time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	}

	result, err := service.Login(context.Background(), authdomain.LoginInput{
		Username: "alice",
		Password: "secret123",
	}, authdomain.RequestMeta{
		IP:        "127.0.0.1",
		UserAgent: "unit-test",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if !result.Authenticated || result.User.ID != userID || result.SessionID != "raw-sid" {
		t.Fatalf("unexpected login result: %#v", result)
	}
	if !updated || !createdSession {
		t.Fatalf("expected last_login_at update and session create, updated=%v createdSession=%v", updated, createdSession)
	}
	if limiter.resetCalls != 1 {
		t.Fatalf("expected limiter reset once, got %d", limiter.resetCalls)
	}
	if txManager.calls != 1 {
		t.Fatalf("expected transaction manager to be used once, got %d", txManager.calls)
	}
}

func TestServiceLoginRejectsWrongPassword(t *testing.T) {
	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	service := NewService(
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) {
				return userdomain.User{}, store.ErrNotFound
			},
			getByUsernameFn: func(_ context.Context, _ string) (userdomain.User, error) {
				return userdomain.User{
					ID:           uuid.New(),
					TenantID:     uuid.New(),
					Username:     "alice",
					PasswordHash: "hashed-secret",
					PasswordAlgo: "argon2id",
					Status:       "active",
					Source:       "local",
				}, nil
			},
			getByEmailFn: func(context.Context, string) (userdomain.User, error) {
				return userdomain.User{}, store.ErrNotFound
			},
			updateLastLoginFn: func(context.Context, uuid.UUID, time.Time) error {
				t.Fatal("update last login should not be called")
				return nil
			},
		},
		sessionRepoStub{
			createFn: func(context.Context, authdomain.Session) (authdomain.Session, error) {
				t.Fatal("session create should not be called")
				return authdomain.Session{}, nil
			},
			getBySIDFn: func(context.Context, string) (authdomain.Session, error) { return authdomain.Session{}, store.ErrNotFound },
			listByUserIDFn: func(context.Context, uuid.UUID) ([]authdomain.Session, error) { return nil, nil },
			touchFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			logoutFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			revokeFn: func(context.Context, uuid.UUID, uuid.UUID, time.Time) error { return nil },
		},
		verifierStub{verifyFn: func(string, string) (bool, error) { return false, nil }},
		&limiterStub{allow: true},
		nil,
		"session-secret",
		logger,
	)

	_, err = service.Login(context.Background(), authdomain.LoginInput{
		Username: "alice",
		Password: "wrong-password",
	}, authdomain.RequestMeta{})
	if err == nil {
		t.Fatal("expected login failure")
	}

	assertAPIErrorCode(t, err, apierror.CodeUnauthorized)
}

func TestServiceLoginRejectsDisabledUser(t *testing.T) {
	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	service := NewService(
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) {
				return userdomain.User{}, store.ErrNotFound
			},
			getByUsernameFn: func(_ context.Context, _ string) (userdomain.User, error) {
				return userdomain.User{
					ID:           uuid.New(),
					TenantID:     uuid.New(),
					Username:     "alice",
					PasswordHash: "hashed-secret",
					PasswordAlgo: "argon2id",
					Status:       "disabled",
					Source:       "local",
				}, nil
			},
			getByEmailFn: func(context.Context, string) (userdomain.User, error) {
				return userdomain.User{}, store.ErrNotFound
			},
			updateLastLoginFn: func(context.Context, uuid.UUID, time.Time) error {
				t.Fatal("update last login should not be called")
				return nil
			},
		},
		sessionRepoStub{
			createFn: func(context.Context, authdomain.Session) (authdomain.Session, error) {
				t.Fatal("session create should not be called")
				return authdomain.Session{}, nil
			},
			getBySIDFn: func(context.Context, string) (authdomain.Session, error) { return authdomain.Session{}, store.ErrNotFound },
			listByUserIDFn: func(context.Context, uuid.UUID) ([]authdomain.Session, error) { return nil, nil },
			touchFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			logoutFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			revokeFn: func(context.Context, uuid.UUID, uuid.UUID, time.Time) error { return nil },
		},
		verifierStub{verifyFn: func(string, string) (bool, error) {
			t.Fatal("password verifier should not be called for disabled user")
			return false, nil
		}},
		&limiterStub{allow: true},
		nil,
		"session-secret",
		logger,
	)

	_, err = service.Login(context.Background(), authdomain.LoginInput{
		Username: "alice",
		Password: "secret123",
	}, authdomain.RequestMeta{})
	if err == nil {
		t.Fatal("expected login failure")
	}

	assertAPIErrorCode(t, err, apierror.CodeUnauthorized)
}

func TestServiceLoginRejectsRateLimitedRequest(t *testing.T) {
	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	service := NewService(
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) {
				return userdomain.User{}, store.ErrNotFound
			},
			getByUsernameFn: func(context.Context, string) (userdomain.User, error) {
				t.Fatal("user lookup should not run when rate limited")
				return userdomain.User{}, nil
			},
			getByEmailFn: func(context.Context, string) (userdomain.User, error) {
				t.Fatal("user lookup should not run when rate limited")
				return userdomain.User{}, nil
			},
			updateLastLoginFn: func(context.Context, uuid.UUID, time.Time) error {
				t.Fatal("last login update should not run when rate limited")
				return nil
			},
		},
		sessionRepoStub{
			createFn: func(context.Context, authdomain.Session) (authdomain.Session, error) {
				t.Fatal("session create should not run when rate limited")
				return authdomain.Session{}, nil
			},
			getBySIDFn: func(context.Context, string) (authdomain.Session, error) { return authdomain.Session{}, store.ErrNotFound },
			listByUserIDFn: func(context.Context, uuid.UUID) ([]authdomain.Session, error) { return nil, nil },
			touchFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			logoutFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			revokeFn: func(context.Context, uuid.UUID, uuid.UUID, time.Time) error { return nil },
		},
		verifierStub{verifyFn: func(string, string) (bool, error) {
			t.Fatal("verifier should not run when rate limited")
			return false, nil
		}},
		&limiterStub{allow: false},
		nil,
		"session-secret",
		logger,
	)

	_, err = service.Login(context.Background(), authdomain.LoginInput{
		Username: "alice",
		Password: "secret123",
	}, authdomain.RequestMeta{})
	if err == nil {
		t.Fatal("expected rate limited error")
	}

	assertAPIErrorCode(t, err, apierror.CodeRateLimited)
}

func TestServiceAuthenticateRejectsExpiredSession(t *testing.T) {
	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	service := NewService(
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) { return userdomain.User{}, nil },
			getByUsernameFn: func(context.Context, string) (userdomain.User, error) { return userdomain.User{}, nil },
			getByEmailFn: func(context.Context, string) (userdomain.User, error) { return userdomain.User{}, nil },
			updateLastLoginFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
		},
		sessionRepoStub{
			createFn: func(context.Context, authdomain.Session) (authdomain.Session, error) { return authdomain.Session{}, nil },
			getBySIDFn: func(context.Context, string) (authdomain.Session, error) {
				return authdomain.Session{
					ID:        uuid.New(),
					UserID:    uuid.New(),
					TenantID:  uuid.New(),
					Status:    authdomain.SessionStatusActive,
					ExpiresAt: time.Date(2026, 3, 19, 10, 0, 0, 0, time.UTC),
				}, nil
			},
			listByUserIDFn: func(context.Context, uuid.UUID) ([]authdomain.Session, error) { return nil, nil },
			touchFn: func(context.Context, uuid.UUID, time.Time) error {
				t.Fatal("touch should not run for expired session")
				return nil
			},
			logoutFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			revokeFn: func(context.Context, uuid.UUID, uuid.UUID, time.Time) error { return nil },
		},
		verifierStub{verifyFn: func(string, string) (bool, error) { return false, nil }},
		&limiterStub{allow: true},
		nil,
		"session-secret",
		logger,
	)
	service.sidManager = sidManagerStub{
		generateFn: func() (string, error) { return "raw", nil },
		hashFn:     func(string, string) (string, error) { return "hashed", nil },
	}
	service.now = func() time.Time {
		return time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	}

	_, err = service.Authenticate(context.Background(), "raw")
	if err == nil {
		t.Fatal("expected expired session to be rejected")
	}

	assertAPIErrorCode(t, err, apierror.CodeUnauthorized)
}

func TestServiceLogoutCurrent(t *testing.T) {
	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	loggedOut := false
	service := NewService(
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) { return userdomain.User{}, nil },
			getByUsernameFn: func(context.Context, string) (userdomain.User, error) { return userdomain.User{}, nil },
			getByEmailFn: func(context.Context, string) (userdomain.User, error) { return userdomain.User{}, nil },
			updateLastLoginFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
		},
		sessionRepoStub{
			createFn: func(context.Context, authdomain.Session) (authdomain.Session, error) { return authdomain.Session{}, nil },
			getBySIDFn: func(context.Context, string) (authdomain.Session, error) { return authdomain.Session{}, store.ErrNotFound },
			listByUserIDFn: func(context.Context, uuid.UUID) ([]authdomain.Session, error) { return nil, nil },
			touchFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			logoutFn: func(_ context.Context, id uuid.UUID, _ time.Time) error {
				loggedOut = true
				if id == uuid.Nil {
					t.Fatal("expected non-nil session id")
				}
				return nil
			},
			revokeFn: func(context.Context, uuid.UUID, uuid.UUID, time.Time) error { return nil },
		},
		verifierStub{verifyFn: func(string, string) (bool, error) { return false, nil }},
		&limiterStub{allow: true},
		nil,
		"session-secret",
		logger,
	)

	err = service.LogoutCurrent(context.Background(), authdomain.Session{
		ID:     uuid.New(),
		UserID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("logout current session: %v", err)
	}
	if !loggedOut {
		t.Fatal("expected session logout to be called")
	}
}

func TestServiceRevokeSession(t *testing.T) {
	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	targetSessionID := uuid.New()
	currentUserID := uuid.New()
	revoked := false

	service := NewService(
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) { return userdomain.User{}, nil },
			getByUsernameFn: func(context.Context, string) (userdomain.User, error) { return userdomain.User{}, nil },
			getByEmailFn: func(context.Context, string) (userdomain.User, error) { return userdomain.User{}, nil },
			updateLastLoginFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
		},
		sessionRepoStub{
			createFn: func(context.Context, authdomain.Session) (authdomain.Session, error) { return authdomain.Session{}, nil },
			getBySIDFn: func(context.Context, string) (authdomain.Session, error) { return authdomain.Session{}, store.ErrNotFound },
			listByUserIDFn: func(context.Context, uuid.UUID) ([]authdomain.Session, error) { return nil, nil },
			touchFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			logoutFn: func(context.Context, uuid.UUID, time.Time) error { return nil },
			revokeFn: func(_ context.Context, id, userID uuid.UUID, _ time.Time) error {
				revoked = true
				if id != targetSessionID || userID != currentUserID {
					t.Fatalf("unexpected revoke args: %s %s", id, userID)
				}
				return nil
			},
		},
		verifierStub{verifyFn: func(string, string) (bool, error) { return false, nil }},
		&limiterStub{allow: true},
		nil,
		"session-secret",
		logger,
	)

	err = service.RevokeSession(context.Background(), authdomain.Session{
		ID:     uuid.New(),
		UserID: currentUserID,
	}, targetSessionID.String())
	if err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if !revoked {
		t.Fatal("expected revoke repo to be called")
	}
}

func assertAPIErrorCode(t *testing.T, err error, code string) {
	t.Helper()

	var apiErr apierror.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected api error, got %T", err)
	}
	if apiErr.Code != code {
		t.Fatalf("expected code %q, got %q", code, apiErr.Code)
	}
}

var _ authrepo.SessionRepository = sessionRepoStub{}
