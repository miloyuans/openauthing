package repo

import (
	"context"
	"time"

	"github.com/google/uuid"
	oidcdomain "github.com/miloyuans/openauthing/internal/oidc/domain"
)

type ClientRepository interface {
	GetByClientID(ctx context.Context, clientID string) (oidcdomain.Client, error)
}

type AuthorizationCodeRepository interface {
	CreateAuthorizationCode(ctx context.Context, code oidcdomain.AuthorizationCode) (oidcdomain.AuthorizationCode, error)
	GetByCodeHashForUpdate(ctx context.Context, codeHash string) (oidcdomain.AuthorizationCode, error)
	Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error
}

type RefreshTokenRepository interface {
	CreateRefreshToken(ctx context.Context, token oidcdomain.RefreshToken) (oidcdomain.RefreshToken, error)
}
