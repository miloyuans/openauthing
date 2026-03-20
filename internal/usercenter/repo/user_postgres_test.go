package repo

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

func TestPostgresUserRepositoryCreateUsesTransactionContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	store := postgresstore.NewWithDB(db)
	repository := NewPostgresUserRepository(store)

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

	err = store.WithinTx(context.Background(), func(ctx context.Context) error {
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

	store := postgresstore.NewWithDB(db)
	repository := NewPostgresUserRepository(store)

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
}
