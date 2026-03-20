package domain

import (
	"time"

	"github.com/google/uuid"
)

const (
	SessionStatusActive    = "active"
	SessionStatusLoggedOut = "logged_out"
	SessionStatusRevoked   = "revoked"
)

type Session struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	UserID      uuid.UUID  `json:"user_id"`
	SID         string     `json:"-"`
	LoginMethod string     `json:"login_method"`
	MFAVerified bool       `json:"mfa_verified"`
	IP          string     `json:"ip"`
	UserAgent   string     `json:"user_agent"`
	Status      string     `json:"status"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	LogoutAt    *time.Time `json:"logout_at,omitempty"`
}

type SessionListItem struct {
	ID          uuid.UUID  `json:"id"`
	LoginMethod string     `json:"login_method"`
	MFAVerified bool       `json:"mfa_verified"`
	IP          string     `json:"ip"`
	UserAgent   string     `json:"user_agent"`
	Status      string     `json:"status"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	LogoutAt    *time.Time `json:"logout_at,omitempty"`
	Current     bool       `json:"current"`
}

func NewSessionListItem(session Session, currentSessionID uuid.UUID) SessionListItem {
	return SessionListItem{
		ID:          session.ID,
		LoginMethod: session.LoginMethod,
		MFAVerified: session.MFAVerified,
		IP:          session.IP,
		UserAgent:   session.UserAgent,
		Status:      session.Status,
		ExpiresAt:   session.ExpiresAt,
		CreatedAt:   session.CreatedAt,
		LastSeenAt:  session.LastSeenAt,
		LogoutAt:    session.LogoutAt,
		Current:     session.ID == currentSessionID,
	}
}
