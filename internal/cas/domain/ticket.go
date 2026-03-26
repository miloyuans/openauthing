package domain

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

const (
	TicketTypeTGT = "TGT"
	TicketTypeST  = "ST"
	TicketTypePT  = "PT"
	TicketTypePGT = "PGT"

	FailureCodeInvalidRequest = "INVALID_REQUEST"
	FailureCodeInvalidService = "INVALID_SERVICE"
	FailureCodeInvalidTicket  = "INVALID_TICKET"
	FailureCodeInternalError  = "INTERNAL_ERROR"
)

type Ticket struct {
	ID             uuid.UUID  `json:"id"`
	Ticket         string     `json:"-"`
	Type           string     `json:"type"`
	Service        string     `json:"service,omitempty"`
	UserID         uuid.UUID  `json:"user_id"`
	SessionID      uuid.UUID  `json:"session_id"`
	ParentTicketID *uuid.UUID `json:"parent_ticket_id,omitempty"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

type ValidationAttributes struct {
	Username    string
	Email       string
	DisplayName string
	Groups      []string
}

type ValidationResult struct {
	Username   string
	Attributes ValidationAttributes
}

type ProtocolError struct {
	Status  int
	Code    string
	Message string
}

func (e ProtocolError) Error() string {
	if e.Message != "" {
		return e.Message
	}

	return http.StatusText(e.Status)
}
