package repo

import (
	"context"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/saml/domain"
)

type ServiceProviderRepository interface {
	GetByAppID(ctx context.Context, appID uuid.UUID) (domain.ServiceProvider, error)
	Upsert(ctx context.Context, sp domain.ServiceProvider) (domain.ServiceProvider, error)
}
