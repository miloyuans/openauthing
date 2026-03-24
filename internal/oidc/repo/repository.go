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
	GetRefreshTokenByHashForUpdate(ctx context.Context, tokenHash string) (oidcdomain.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, id uuid.UUID, replacedByID uuid.UUID, changedAt time.Time) error
	MarkRefreshTokenReplay(ctx context.Context, id uuid.UUID, detectedAt time.Time) error
	RevokeRefreshTokenByHash(ctx context.Context, tokenHash string, revokedAt time.Time) error
	RevokeRefreshTokensBySessionID(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error
}

type AccessTokenRepository interface {
	CreateAccessToken(ctx context.Context, token oidcdomain.AccessToken) (oidcdomain.AccessToken, error)
	GetAccessTokenByHash(ctx context.Context, tokenHash string) (oidcdomain.AccessToken, error)
	RevokeAccessTokenByHash(ctx context.Context, tokenHash string, revokedAt time.Time) error
	RevokeAccessTokensBySessionID(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error
}
