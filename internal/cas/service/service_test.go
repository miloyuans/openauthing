package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	casdomain "github.com/miloyuans/openauthing/internal/cas/domain"
	"github.com/miloyuans/openauthing/internal/config"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type userRepoStub struct {
	getByIDFn       func(ctx context.Context, id uuid.UUID) (userdomain.User, error)
	listGroupCodesFn func(ctx context.Context, userID uuid.UUID) ([]string, error)
}

func (s userRepoStub) GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error) {
	return s.getByIDFn(ctx, id)
}

func (s userRepoStub) ListGroupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if s.listGroupCodesFn == nil {
		return nil, nil
	}
	return s.listGroupCodesFn(ctx, userID)
}

type ticketRepoStub struct {
	createFn               func(ctx context.Context, ticket casdomain.Ticket) (casdomain.Ticket, error)
	getActiveTGTBySessionFn func(ctx context.Context, sessionID uuid.UUID, now time.Time) (casdomain.Ticket, error)
	getByTicketForUpdateFn func(ctx context.Context, ticket string) (casdomain.Ticket, error)
	consumeFn              func(ctx context.Context, id uuid.UUID, consumedAt time.Time) error
	invalidateFn           func(ctx context.Context, sessionID uuid.UUID, consumedAt time.Time) error
}

func (s ticketRepoStub) Create(ctx context.Context, ticket casdomain.Ticket) (casdomain.Ticket, error) {
	return s.createFn(ctx, ticket)
}

func (s ticketRepoStub) GetActiveTGTBySessionID(ctx context.Context, sessionID uuid.UUID, now time.Time) (casdomain.Ticket, error) {
	return s.getActiveTGTBySessionFn(ctx, sessionID, now)
}

func (s ticketRepoStub) GetByTicketForUpdate(ctx context.Context, ticket string) (casdomain.Ticket, error) {
	return s.getByTicketForUpdateFn(ctx, ticket)
}

func (s ticketRepoStub) Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error {
	return s.consumeFn(ctx, id, consumedAt)
}

func (s ticketRepoStub) InvalidateBySessionID(ctx context.Context, sessionID uuid.UUID, consumedAt time.Time) error {
	if s.invalidateFn == nil {
		return nil
	}
	return s.invalidateFn(ctx, sessionID, consumedAt)
}

type txManagerStub struct{}

func (txManagerStub) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type ticketValueManagerStub struct {
	generated []string
}

func (s *ticketValueManagerStub) Generate(prefix string) (string, error) {
	if len(s.generated) == 0 {
		return "", errors.New("no generated tickets configured")
	}
	value := s.generated[0]
	s.generated = s.generated[1:]
	return value, nil
}

func (*ticketValueManagerStub) Hash(secret, rawValue string) (string, error) {
	return "hash:" + rawValue, nil
}

func TestServiceLoginCreatesTGTAndST(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	now := time.Now().UTC()
	created := make([]casdomain.Ticket, 0, 2)

	svc := NewService(
		config.CASConfig{
			AllowedServiceHosts:     []string{"service.example.test"},
			ServiceTicketTTLSeconds: 120,
		},
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) {
				return userdomain.User{ID: userID, Status: "active"}, nil
			},
		},
		ticketRepoStub{
			getActiveTGTBySessionFn: func(context.Context, uuid.UUID, time.Time) (casdomain.Ticket, error) {
				return casdomain.Ticket{}, store.ErrNotFound
			},
			createFn: func(_ context.Context, ticket casdomain.Ticket) (casdomain.Ticket, error) {
				ticket.ID = uuid.New()
				ticket.CreatedAt = now
				created = append(created, ticket)
				return ticket, nil
			},
		},
		txManagerStub{},
		"test-secret",
		nil,
	)
	svc.now = func() time.Time { return now }
	svc.ticketValues = &ticketValueManagerStub{generated: []string{"TGT-raw-ticket", "ST-raw-ticket"}}

	rawTicket, err := svc.Login(context.Background(), authdomain.Session{
		UserID:    userID,
		ID:        sessionID,
		ExpiresAt: now.Add(24 * time.Hour),
	}, "https://service.example.test/app")
	if err != nil {
		t.Fatalf("issue cas login ticket: %v", err)
	}

	if rawTicket != "ST-raw-ticket" {
		t.Fatalf("expected raw ST ticket, got %q", rawTicket)
	}
	if len(created) != 2 {
		t.Fatalf("expected 2 stored tickets, got %d", len(created))
	}
	if created[0].Type != casdomain.TicketTypeTGT || created[0].Service != "" {
		t.Fatalf("unexpected TGT record: %#v", created[0])
	}
	if created[1].Type != casdomain.TicketTypeST || created[1].Service != "https://service.example.test/app" {
		t.Fatalf("unexpected ST record: %#v", created[1])
	}
	if created[1].Ticket != "hash:ST-raw-ticket" {
		t.Fatalf("expected hashed ST ticket, got %q", created[1].Ticket)
	}
}

func TestValidateServiceTicketConsumesAndReturnsAttributes(t *testing.T) {
	userID := uuid.New()
	ticketID := uuid.New()
	now := time.Now().UTC()
	consumed := false

	svc := NewService(
		config.CASConfig{
			AllowedServiceHosts:     []string{"service.example.test"},
			ServiceTicketTTLSeconds: 120,
		},
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) {
				return userdomain.User{
					ID:          userID,
					Username:    "alice",
					Email:       "alice@example.com",
					DisplayName: "Alice",
					Status:      "active",
				}, nil
			},
			listGroupCodesFn: func(context.Context, uuid.UUID) ([]string, error) {
				return []string{"platform", "ops"}, nil
			},
		},
		ticketRepoStub{
			getByTicketForUpdateFn: func(context.Context, string) (casdomain.Ticket, error) {
				return casdomain.Ticket{
					ID:        ticketID,
					Type:      casdomain.TicketTypeST,
					Service:   "https://service.example.test/app",
					UserID:    userID,
					ExpiresAt: now.Add(time.Minute),
				}, nil
			},
			consumeFn: func(_ context.Context, id uuid.UUID, consumedAt time.Time) error {
				consumed = id == ticketID && !consumedAt.IsZero()
				return nil
			},
		},
		txManagerStub{},
		"test-secret",
		nil,
	)
	svc.now = func() time.Time { return now }
	svc.ticketValues = &ticketValueManagerStub{}

	result, err := svc.ValidateServiceTicket(context.Background(), "https://service.example.test/app", "ST-raw-ticket", true)
	if err != nil {
		t.Fatalf("validate service ticket: %v", err)
	}

	if !consumed {
		t.Fatal("expected service ticket to be consumed")
	}
	if result.Username != "alice" || result.Attributes.Email != "alice@example.com" || len(result.Attributes.Groups) != 2 {
		t.Fatalf("unexpected validation result: %#v", result)
	}
}

func TestValidateServiceTicketRejectsConsumedTicket(t *testing.T) {
	now := time.Now().UTC()
	consumedAt := now.Add(-time.Minute)

	svc := NewService(
		config.CASConfig{AllowedServiceHosts: []string{"service.example.test"}},
		userRepoStub{
			getByIDFn: func(context.Context, uuid.UUID) (userdomain.User, error) {
				t.Fatal("get user should not be called for consumed ticket")
				return userdomain.User{}, nil
			},
		},
		ticketRepoStub{
			getByTicketForUpdateFn: func(context.Context, string) (casdomain.Ticket, error) {
				return casdomain.Ticket{
					ID:         uuid.New(),
					Type:       casdomain.TicketTypeST,
					Service:    "https://service.example.test/app",
					ConsumedAt: &consumedAt,
					ExpiresAt:  now.Add(time.Minute),
				}, nil
			},
			consumeFn: func(context.Context, uuid.UUID, time.Time) error {
				t.Fatal("consume should not be called for already consumed ticket")
				return nil
			},
		},
		txManagerStub{},
		"test-secret",
		nil,
	)
	svc.now = func() time.Time { return now }
	svc.ticketValues = &ticketValueManagerStub{}

	_, err := svc.ValidateServiceTicket(context.Background(), "https://service.example.test/app", "ST-raw-ticket", false)
	if err == nil {
		t.Fatal("expected invalid ticket error")
	}

	var protocolErr casdomain.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("expected protocol error, got %T", err)
	}
	if protocolErr.Code != casdomain.FailureCodeInvalidTicket || !strings.Contains(protocolErr.Message, "already been consumed") {
		t.Fatalf("unexpected protocol error: %#v", protocolErr)
	}
}
