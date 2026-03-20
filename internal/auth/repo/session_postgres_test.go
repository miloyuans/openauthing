package repo

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

func TestPostgresSessionRepositoryCreateUsesTransactionContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresSessionRepository(pgStore)

	now := time.Now()
	sessionID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	input := authdomain.Session{
		TenantID:    tenantID,
		UserID:      userID,
		SID:         "hashed-sid",
		LoginMethod: "username",
		MFAVerified: false,
		IP:          "127.0.0.1",
		UserAgent:   "unit-test",
		Status:      authdomain.SessionStatusActive,
		ExpiresAt:   now.Add(time.Hour),
		LastSeenAt:  now,
	}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO auth_sessions").
		WithArgs(
			tenantID,
			userID,
			"hashed-sid",
			"username",
			false,
			"127.0.0.1",
			"unit-test",
			authdomain.SessionStatusActive,
			input.ExpiresAt,
			now,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "user_id", "sid", "login_method", "mfa_verified", "ip", "user_agent", "status", "expires_at", "created_at", "last_seen_at", "logout_at",
		}).AddRow(
			sessionID, tenantID, userID, "hashed-sid", "username", false, "127.0.0.1", "unit-test", authdomain.SessionStatusActive, input.ExpiresAt, now, now, nil,
		))
	mock.ExpectCommit()

	err = pgStore.WithinTx(context.Background(), func(ctx context.Context) error {
		_, createErr := repository.Create(ctx, input)
		return createErr
	})
	if err != nil {
		t.Fatalf("create session in tx: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresSessionRepositoryGetBySID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresSessionRepository(pgStore)

	now := time.Now()
	sessionID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()

	mock.ExpectQuery("SELECT id, tenant_id, user_id, sid, login_method, mfa_verified, ip, user_agent, status, expires_at, created_at, last_seen_at, logout_at\\s+FROM auth_sessions\\s+WHERE sid = \\$1").
		WithArgs("hashed-sid").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "user_id", "sid", "login_method", "mfa_verified", "ip", "user_agent", "status", "expires_at", "created_at", "last_seen_at", "logout_at",
		}).AddRow(
			sessionID, tenantID, userID, "hashed-sid", "username", false, "127.0.0.1", "unit-test", authdomain.SessionStatusActive, now.Add(time.Hour), now, now, nil,
		))

	session, err := repository.GetBySID(context.Background(), "hashed-sid")
	if err != nil {
		t.Fatalf("get session by sid: %v", err)
	}

	if session.ID != sessionID || session.UserID != userID {
		t.Fatalf("unexpected session: %#v", session)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
