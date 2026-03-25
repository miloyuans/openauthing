package repo

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/saml/domain"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

func TestPostgresLoginSessionRepositoryUpsertUsesTransactionContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresLoginSessionRepository(pgStore)

	now := time.Now().UTC()
	appID := uuid.New()
	userID := uuid.New()
	sessionID := uuid.New()
	loginSessionID := uuid.New()
	input := domain.LoginSession{
		AppID:        appID,
		UserID:       userID,
		SessionID:    sessionID,
		NameID:       "alice@example.com",
		SessionIndex: sessionID.String(),
		Status:       domain.LoginSessionStatusActive,
		IssuedAt:     now,
		ExpiresAt:    now.Add(24 * time.Hour),
	}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO saml_login_sessions").
		WithArgs(
			appID,
			userID,
			sessionID,
			"alice@example.com",
			sessionID.String(),
			domain.LoginSessionStatusActive,
			now,
			input.ExpiresAt,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "app_id", "user_id", "session_id", "name_id", "session_index", "status", "issued_at", "expires_at", "created_at", "updated_at", "logout_at",
		}).AddRow(
			loginSessionID, appID, userID, sessionID, "alice@example.com", sessionID.String(), domain.LoginSessionStatusActive, now, input.ExpiresAt, now, now, nil,
		))
	mock.ExpectCommit()

	err = pgStore.WithinTx(context.Background(), func(ctx context.Context) error {
		_, upsertErr := repository.Upsert(ctx, input)
		return upsertErr
	})
	if err != nil {
		t.Fatalf("upsert login session in tx: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresLoginSessionRepositoryGetActiveByAppAndSessionIndex(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresLoginSessionRepository(pgStore)

	now := time.Now().UTC()
	appID := uuid.New()
	userID := uuid.New()
	sessionID := uuid.New()
	loginSessionID := uuid.New()

	mock.ExpectQuery("SELECT id, app_id, user_id, session_id, name_id, session_index, status, issued_at, expires_at, created_at, updated_at, logout_at\\s+FROM saml_login_sessions\\s+WHERE app_id = \\$1 AND session_index = \\$2 AND status = \\$3\\s+ORDER BY issued_at DESC\\s+LIMIT 1").
		WithArgs(appID, sessionID.String(), domain.LoginSessionStatusActive).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "app_id", "user_id", "session_id", "name_id", "session_index", "status", "issued_at", "expires_at", "created_at", "updated_at", "logout_at",
		}).AddRow(
			loginSessionID, appID, userID, sessionID, "alice@example.com", sessionID.String(), domain.LoginSessionStatusActive, now, now.Add(24*time.Hour), now, now, nil,
		))

	session, err := repository.GetActiveByAppAndSessionIndex(context.Background(), appID, sessionID.String())
	if err != nil {
		t.Fatalf("get login session by session index: %v", err)
	}

	if session.ID != loginSessionID || session.SessionID != sessionID {
		t.Fatalf("unexpected login session: %#v", session)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresLoginSessionRepositoryInvalidateBySessionID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresLoginSessionRepository(pgStore)

	sessionID := uuid.New()
	logoutAt := time.Now().UTC()

	mock.ExpectExec("UPDATE saml_login_sessions\\s+SET status = \\$2,\\s+logout_at = \\$3,\\s+updated_at = NOW\\(\\)\\s+WHERE session_id = \\$1 AND status = \\$4").
		WithArgs(sessionID, domain.LoginSessionStatusLoggedOut, logoutAt, domain.LoginSessionStatusActive).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repository.InvalidateBySessionID(context.Background(), sessionID, logoutAt); err != nil {
		t.Fatalf("invalidate login sessions by center session id: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
