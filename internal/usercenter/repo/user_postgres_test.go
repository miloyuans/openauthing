package repo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	storepkg "github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

func TestPostgresUserRepositoryCreateUsesTransactionContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresUserRepository(pgStore)

	now := time.Now()
	tenantID := uuid.New()
	userID := uuid.New()
	input := domain.User{
		TenantID:     tenantID,
		Username:     "alice",
		Email:        "alice@example.com",
		Phone:        "+10000000001",
		DisplayName:  "Alice",
		PasswordHash: "",
		PasswordAlgo: "argon2id",
		Status:       "active",
		Source:       "local",
	}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs(
			tenantID,
			"alice",
			"alice@example.com",
			"+10000000001",
			"Alice",
			"",
			"argon2id",
			"active",
			"local",
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "username", "email", "phone", "display_name", "password_hash", "password_algo", "status", "source", "last_login_at", "created_at", "updated_at",
		}).AddRow(
			userID, tenantID, "alice", "alice@example.com", "+10000000001", "Alice", "", "argon2id", "active", "local", nil, now, now,
		))
	mock.ExpectCommit()

	err = pgStore.WithinTx(context.Background(), func(ctx context.Context) error {
		_, createErr := repository.Create(ctx, input)
		return createErr
	})
	if err != nil {
		t.Fatalf("create user in tx: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresUserRepositoryListAppliesFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresUserRepository(pgStore)

	now := time.Now()
	tenantID := uuid.New()
	userID := uuid.New()

	mock.ExpectQuery("SELECT id, tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source, last_login_at, created_at, updated_at\\s+FROM users\\s+WHERE 1 = 1 AND tenant_id = \\$1 AND username ILIKE \\$2 AND status = \\$3 ORDER BY created_at DESC LIMIT \\$4 OFFSET \\$5").
		WithArgs(tenantID, "%ali%", "active", 10, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "username", "email", "phone", "display_name", "password_hash", "password_algo", "status", "source", "last_login_at", "created_at", "updated_at",
		}).AddRow(
			userID, tenantID, "alice", "alice@example.com", "+10000000001", "Alice", "", "argon2id", "active", "local", nil, now, now,
		))

	items, err := repository.List(context.Background(), domain.UserListFilter{
		TenantID: &tenantID,
		Username: "ali",
		Status:   "active",
		Limit:    10,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("list users: %v", err)
	}

	if len(items) != 1 || items[0].Username != "alice" {
		t.Fatalf("unexpected users: %#v", items)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresUserRepositoryGetByUsernameReturnsAmbiguousWhenMultipleUsersMatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresUserRepository(pgStore)

	now := time.Now()
	firstTenantID := uuid.New()
	secondTenantID := uuid.New()

	mock.ExpectQuery("SELECT id, tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source, last_login_at, created_at, updated_at\\s+FROM users\\s+WHERE username = \\$1\\s+ORDER BY created_at DESC\\s+LIMIT 2").
		WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "username", "email", "phone", "display_name", "password_hash", "password_algo", "status", "source", "last_login_at", "created_at", "updated_at",
		}).
			AddRow(uuid.New(), firstTenantID, "alice", "alice-1@example.com", nil, "Alice One", "hash-1", "argon2id", "active", "local", nil, now, now).
			AddRow(uuid.New(), secondTenantID, "alice", "alice-2@example.com", nil, "Alice Two", "hash-2", "argon2id", "active", "local", nil, now, now))

	_, err = repository.GetByUsername(context.Background(), "alice")
	if !errors.Is(err, storepkg.ErrAmbiguous) {
		t.Fatalf("expected ambiguous error, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresUserRepositoryUpdateLastLoginAt(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresUserRepository(pgStore)

	userID := uuid.New()
	lastLoginAt := time.Now()

	mock.ExpectExec("UPDATE users SET last_login_at = \\$2, updated_at = NOW\\(\\) WHERE id = \\$1").
		WithArgs(userID, lastLoginAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repository.UpdateLastLoginAt(context.Background(), userID, lastLoginAt); err != nil {
		t.Fatalf("update last login: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
