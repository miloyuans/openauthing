package repo

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/saml/domain"
)

type ServiceProviderRepository interface {
	GetByAppID(ctx context.Context, appID uuid.UUID) (domain.ServiceProvider, error)
	GetByEntityID(ctx context.Context, entityID string) (domain.ServiceProvider, error)
	Upsert(ctx context.Context, sp domain.ServiceProvider) (domain.ServiceProvider, error)
}

type LoginSessionRepository interface {
	Upsert(ctx context.Context, session domain.LoginSession) (domain.LoginSession, error)
	GetActiveByAppAndSessionIndex(ctx context.Context, appID uuid.UUID, sessionIndex string) (domain.LoginSession, error)
	GetActiveByAppAndNameID(ctx context.Context, appID uuid.UUID, nameID string) (domain.LoginSession, error)
	InvalidateBySessionID(ctx context.Context, sessionID uuid.UUID, logoutAt time.Time) error
}
