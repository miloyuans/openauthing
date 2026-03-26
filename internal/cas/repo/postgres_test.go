package repo

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	casdomain "github.com/miloyuans/openauthing/internal/cas/domain"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

func TestPostgresTicketRepositoryCreateUsesTransactionContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresTicketRepository(pgStore)

	now := time.Now().UTC()
	ticketID := uuid.New()
	userID := uuid.New()
	sessionID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO cas_tickets").
		WithArgs(
			"hash-st-ticket",
			casdomain.TicketTypeST,
			"https://service.example.test/app",
			userID,
			sessionID,
			nil,
			now.Add(time.Minute),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "ticket", "type", "service", "user_id", "session_id", "parent_ticket_id", "consumed_at", "expires_at", "created_at",
		}).AddRow(
			ticketID,
			"hash-st-ticket",
			casdomain.TicketTypeST,
			"https://service.example.test/app",
			userID,
			sessionID,
			nil,
			nil,
			now.Add(time.Minute),
			now,
		))
	mock.ExpectCommit()

	err = pgStore.WithinTx(context.Background(), func(ctx context.Context) error {
		_, createErr := repository.Create(ctx, casdomain.Ticket{
			Ticket:    "hash-st-ticket",
			Type:      casdomain.TicketTypeST,
			Service:   "https://service.example.test/app",
			UserID:    userID,
			SessionID: sessionID,
			ExpiresAt: now.Add(time.Minute),
		})
		return createErr
	})
	if err != nil {
		t.Fatalf("create ticket in tx: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresTicketRepositoryConsume(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	defer db.Close()

	pgStore := postgresstore.NewWithDB(db)
	repository := NewPostgresTicketRepository(pgStore)

	ticketID := uuid.New()
	consumedAt := time.Now().UTC()

	mock.ExpectExec("UPDATE cas_tickets\\s+SET consumed_at = \\$2\\s+WHERE id = \\$1 AND consumed_at IS NULL").
		WithArgs(ticketID, consumedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repository.Consume(context.Background(), ticketID, consumedAt); err != nil {
		t.Fatalf("consume ticket: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
