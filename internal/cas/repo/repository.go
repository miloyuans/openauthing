package repo

import (
	"context"
	"time"

	"github.com/google/uuid"
	casdomain "github.com/miloyuans/openauthing/internal/cas/domain"
)

type TicketRepository interface {
	Create(ctx context.Context, ticket casdomain.Ticket) (casdomain.Ticket, error)
	GetActiveTGTBySessionID(ctx context.Context, sessionID uuid.UUID, now time.Time) (casdomain.Ticket, error)
	GetByTicketForUpdate(ctx context.Context, ticket string) (casdomain.Ticket, error)
	Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error
	InvalidateBySessionID(ctx context.Context, sessionID uuid.UUID, consumedAt time.Time) error
}
