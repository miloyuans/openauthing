package domain

import (
	"time"

	"github.com/google/uuid"
)

const (
	LoginSessionStatusActive    = "active"
	LoginSessionStatusLoggedOut = "logged_out"
)

type LoginSession struct {
	ID           uuid.UUID  `json:"id"`
	AppID        uuid.UUID  `json:"app_id"`
	UserID       uuid.UUID  `json:"user_id"`
	SessionID    uuid.UUID  `json:"session_id"`
	NameID       string     `json:"name_id"`
	SessionIndex string     `json:"session_index"`
	Status       string     `json:"status"`
	IssuedAt     time.Time  `json:"issued_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LogoutAt     *time.Time `json:"logout_at,omitempty"`
}
