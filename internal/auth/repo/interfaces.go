package repo

import (
	"context"
	"time"

	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
)

type SessionRepository interface {
	Create(ctx context.Context, session authdomain.Session) (authdomain.Session, error)
	GetBySID(ctx context.Context, sid string) (authdomain.Session, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]authdomain.Session, error)
	Touch(ctx context.Context, id uuid.UUID, lastSeenAt time.Time) error
	Logout(ctx context.Context, id uuid.UUID, logoutAt time.Time) error
	RevokeByID(ctx context.Context, id, userID uuid.UUID, logoutAt time.Time) error
}
