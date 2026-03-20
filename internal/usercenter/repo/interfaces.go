package repo

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type UserRepository interface {
	List(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error)
	Create(ctx context.Context, user domain.User) (domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (domain.User, error)
	GetByUsername(ctx context.Context, username string) (domain.User, error)
	GetByEmail(ctx context.Context, email string) (domain.User, error)
	UpdateLastLoginAt(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error
	Update(ctx context.Context, user domain.User) (domain.User, error)
}

type GroupRepository interface {
	List(ctx context.Context, filter domain.GroupListFilter) ([]domain.Group, error)
	Create(ctx context.Context, group domain.Group) (domain.Group, error)
}

type RoleRepository interface {
	List(ctx context.Context, filter domain.RoleListFilter) ([]domain.Role, error)
	Create(ctx context.Context, role domain.Role) (domain.Role, error)
}
