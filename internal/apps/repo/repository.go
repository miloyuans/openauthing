package repo

import (
	"context"

	"github.com/miloyuans/openauthing/internal/apps/domain"
)

type ApplicationRepository interface {
	List(ctx context.Context, filter domain.ApplicationListFilter) ([]domain.Application, error)
	Create(ctx context.Context, app domain.Application) (domain.Application, error)
}
