package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/store"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type userRepoStub struct {
	listFn           func(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error)
	createFn         func(ctx context.Context, user domain.User) (domain.User, error)
	getFn            func(ctx context.Context, id uuid.UUID) (domain.User, error)
	getByUsernameFn  func(ctx context.Context, username string) (domain.User, error)
	getByEmailFn     func(ctx context.Context, email string) (domain.User, error)
	updateLastLoginFn func(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error
	updateFn         func(ctx context.Context, user domain.User) (domain.User, error)
}

func (s userRepoStub) List(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error) {
	return s.listFn(ctx, filter)
}

func (s userRepoStub) Create(ctx context.Context, user domain.User) (domain.User, error) {
	return s.createFn(ctx, user)
}

func (s userRepoStub) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return s.getFn(ctx, id)
}

func (s userRepoStub) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	if s.getByUsernameFn == nil {
		return domain.User{}, store.ErrNotFound
	}
	return s.getByUsernameFn(ctx, username)
}

func (s userRepoStub) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	if s.getByEmailFn == nil {
		return domain.User{}, store.ErrNotFound
	}
	return s.getByEmailFn(ctx, email)
}

func (s userRepoStub) UpdateLastLoginAt(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error {
	if s.updateLastLoginFn == nil {
		return nil
	}
	return s.updateLastLoginFn(ctx, id, lastLoginAt)
}

func (s userRepoStub) Update(ctx context.Context, user domain.User) (domain.User, error) {
	return s.updateFn(ctx, user)
}

type passwordHasherStub struct {
	hashFn func(plain string) (string, error)
}

func (s passwordHasherStub) Hash(plain string) (string, error) {
	return s.hashFn(plain)
}

func (passwordHasherStub) Algorithm() string {
	return "argon2id"
}

func TestUserServiceCreateAllowsEmptyPasswordHash(t *testing.T) {
	tenantID := uuid.New()
	service := NewUserService(userRepoStub{
		createFn: func(_ context.Context, user domain.User) (domain.User, error) {
			if user.PasswordHash != "" {
				t.Fatalf("expected empty password hash, got %q", user.PasswordHash)
			}
			if user.PasswordAlgo != defaultPasswordAlgo {
				t.Fatalf("expected default password algo, got %q", user.PasswordAlgo)
			}
			return user, nil
		},
	})

	created, err := service.Create(context.Background(), domain.CreateUserInput{
		TenantID:    tenantID,
		Username:    "alice",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if created.Status != "active" || created.Source != "local" {
		t.Fatalf("unexpected defaults: %#v", created)
	}
}

func TestUserServiceCreateHashesPlainPassword(t *testing.T) {
	service := NewUserServiceWithPasswordHasher(userRepoStub{
		createFn: func(_ context.Context, user domain.User) (domain.User, error) {
			if user.PasswordHash != "argon2-hash" {
				t.Fatalf("expected hashed password, got %q", user.PasswordHash)
			}
			if user.PasswordAlgo != "argon2id" {
				t.Fatalf("expected argon2id algo, got %q", user.PasswordAlgo)
			}
			return user, nil
		},
	}, passwordHasherStub{
		hashFn: func(plain string) (string, error) {
			if plain != "secret123" {
				t.Fatalf("unexpected password: %q", plain)
			}
			return "argon2-hash", nil
		},
	})

	_, err := service.Create(context.Background(), domain.CreateUserInput{
		TenantID:    uuid.New(),
		Username:    "alice",
		DisplayName: "Alice",
		Password:    "secret123",
	})
	if err != nil {
		t.Fatalf("create user with password: %v", err)
	}
}

func TestUserServiceRejectsPlaintextPasswordHash(t *testing.T) {
	service := NewUserService(userRepoStub{
		createFn: func(context.Context, domain.User) (domain.User, error) {
			t.Fatal("repo create should not be called")
			return domain.User{}, nil
		},
	})

	_, err := service.Create(context.Background(), domain.CreateUserInput{
		TenantID:     uuid.New(),
		Username:     "alice",
		DisplayName:  "Alice",
		PasswordHash: "secret123",
	})
	if err == nil {
		t.Fatal("expected validation error")
	}

	var apiErr apierror.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected apierror, got %T", err)
	}
	if apiErr.Code != apierror.CodeValidationError {
		t.Fatalf("expected validation_error, got %q", apiErr.Code)
	}
}

func TestUserServiceUpdateMapsNotFound(t *testing.T) {
	service := NewUserService(userRepoStub{
		getFn: func(_ context.Context, _ uuid.UUID) (domain.User, error) {
			return domain.User{}, store.ErrNotFound
		},
	})

	_, err := service.Update(context.Background(), uuid.NewString(), domain.UpdateUserInput{})
	if err == nil {
		t.Fatal("expected not found error")
	}

	var apiErr apierror.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected apierror, got %T", err)
	}

	if apiErr.Code != apierror.CodeNotFound {
		t.Fatalf("expected not_found, got %q", apiErr.Code)
	}
}
