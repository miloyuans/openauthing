package repo

import (
	"context"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/apps/domain"
)

type ApplicationRepository interface {
	List(ctx context.Context, filter domain.ApplicationListFilter) ([]domain.Application, error)
	Create(ctx context.Context, app domain.Application) (domain.Application, error)
	GetByID(ctx context.Context, id uuid.UUID) (domain.Application, error)
}
