package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/store"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type userRepoStub struct {
	listFn   func(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error)
	createFn func(ctx context.Context, user domain.User) (domain.User, error)
	getFn    func(ctx context.Context, id uuid.UUID) (domain.User, error)
	updateFn func(ctx context.Context, user domain.User) (domain.User, error)
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

func (s userRepoStub) Update(ctx context.Context, user domain.User) (domain.User, error) {
	return s.updateFn(ctx, user)
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
