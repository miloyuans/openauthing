package repo

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	casdomain "github.com/miloyuans/openauthing/internal/cas/domain"
	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

type PostgresTicketRepository struct {
	store *postgresstore.Store
}

func NewPostgresTicketRepository(store *postgresstore.Store) *PostgresTicketRepository {
	return &PostgresTicketRepository{store: store}
}

func (r *PostgresTicketRepository) Create(ctx context.Context, ticket casdomain.Ticket) (casdomain.Ticket, error) {
	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		`INSERT INTO cas_tickets (
    ticket, type, service, user_id, session_id, parent_ticket_id, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
RETURNING id, ticket, type, service, user_id, session_id, parent_ticket_id, consumed_at, expires_at, created_at`,
		ticket.Ticket,
		ticket.Type,
		nullableString(ticket.Service),
		ticket.UserID,
		ticket.SessionID,
		ticket.ParentTicketID,
		ticket.ExpiresAt,
	)

	var created casdomain.Ticket
	if err := scanTicket(row, &created); err != nil {
		return casdomain.Ticket{}, store.NormalizeError(err)
	}

	return created, nil
}

func (r *PostgresTicketRepository) GetActiveTGTBySessionID(ctx context.Context, sessionID uuid.UUID, now time.Time) (casdomain.Ticket, error) {
	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		`SELECT id, ticket, type, service, user_id, session_id, parent_ticket_id, consumed_at, expires_at, created_at
FROM cas_tickets
WHERE session_id = $1 AND type = $2 AND consumed_at IS NULL AND expires_at > $3
ORDER BY created_at DESC
LIMIT 1`,
		sessionID,
		casdomain.TicketTypeTGT,
		now,
	)

	var ticket casdomain.Ticket
	if err := scanTicket(row, &ticket); err != nil {
		return casdomain.Ticket{}, store.NormalizeError(err)
	}

	return ticket, nil
}

func (r *PostgresTicketRepository) GetByTicketForUpdate(ctx context.Context, ticket string) (casdomain.Ticket, error) {
	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		`SELECT id, ticket, type, service, user_id, session_id, parent_ticket_id, consumed_at, expires_at, created_at
FROM cas_tickets
WHERE ticket = $1
FOR UPDATE`,
		ticket,
	)

	var item casdomain.Ticket
	if err := scanTicket(row, &item); err != nil {
		return casdomain.Ticket{}, store.NormalizeError(err)
	}

	return item, nil
}

func (r *PostgresTicketRepository) Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error {
	result, err := r.store.Executor(ctx).ExecContext(
		ctx,
		`UPDATE cas_tickets
SET consumed_at = $2
WHERE id = $1 AND consumed_at IS NULL`,
		id,
		consumedAt,
	)
	if err != nil {
		return store.NormalizeError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

func (r *PostgresTicketRepository) InvalidateBySessionID(ctx context.Context, sessionID uuid.UUID, consumedAt time.Time) error {
	_, err := r.store.Executor(ctx).ExecContext(
		ctx,
		`UPDATE cas_tickets
SET consumed_at = COALESCE(consumed_at, $2)
WHERE session_id = $1 AND consumed_at IS NULL`,
		sessionID,
		consumedAt,
	)
	if err != nil {
		return store.NormalizeError(err)
	}

	return nil
}

type ticketScanner interface {
	Scan(dest ...any) error
}

func scanTicket(scanner ticketScanner, ticket *casdomain.Ticket) error {
	var (
		service        sql.NullString
		parentTicketID uuid.NullUUID
		consumedAt     sql.NullTime
	)

	if err := scanner.Scan(
		&ticket.ID,
		&ticket.Ticket,
		&ticket.Type,
		&service,
		&ticket.UserID,
		&ticket.SessionID,
		&parentTicketID,
		&consumedAt,
		&ticket.ExpiresAt,
		&ticket.CreatedAt,
	); err != nil {
		return err
	}

	ticket.Service = ""
	if service.Valid {
		ticket.Service = service.String
	}

	ticket.ParentTicketID = nil
	if parentTicketID.Valid {
		value := parentTicketID.UUID
		ticket.ParentTicketID = &value
	}

	ticket.ConsumedAt = nil
	if consumedAt.Valid {
		value := consumedAt.Time
		ticket.ConsumedAt = &value
	}

	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}

	return value
}
