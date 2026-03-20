package domain

import (
	"time"

	"github.com/google/uuid"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type LoginInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RequestMeta struct {
	IP        string
	UserAgent string
}

type UserSummary struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email,omitempty"`
	DisplayName string    `json:"display_name"`
	Status      string    `json:"status"`
	Source      string    `json:"source"`
}

type LoginResult struct {
	Authenticated bool        `json:"authenticated"`
	User          UserSummary `json:"user"`
	SessionID     string      `json:"-"`
	ExpiresAt     time.Time   `json:"-"`
}

func NewUserSummary(user userdomain.User) UserSummary {
	return UserSummary{
		ID:          user.ID,
		TenantID:    user.TenantID,
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Status:      user.Status,
		Source:      user.Source,
	}
}
