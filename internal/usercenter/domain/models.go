package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Username     string     `json:"username"`
	Email        string     `json:"email,omitempty"`
	Phone        string     `json:"phone,omitempty"`
	DisplayName  string     `json:"display_name"`
	PasswordHash string     `json:"-"`
	PasswordAlgo string     `json:"password_algo"`
	Status       string     `json:"status"`
	Source       string     `json:"source"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type UserListFilter struct {
	TenantID *uuid.UUID
	Username string
	Email    string
	Status   string
	Limit    int
	Offset   int
}

type CreateUserInput struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	Phone        string    `json:"phone"`
	DisplayName  string    `json:"display_name"`
	PasswordHash string    `json:"password_hash"`
	PasswordAlgo string    `json:"password_algo"`
	Status       string    `json:"status"`
	Source       string    `json:"source"`
}

type UpdateUserInput struct {
	Username     *string `json:"username"`
	Email        *string `json:"email"`
	Phone        *string `json:"phone"`
	DisplayName  *string `json:"display_name"`
	PasswordHash *string `json:"password_hash"`
	PasswordAlgo *string `json:"password_algo"`
	Status       *string `json:"status"`
	Source       *string `json:"source"`
}

type Group struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type GroupListFilter struct {
	TenantID *uuid.UUID
	Name     string
	Code     string
	Limit    int
	Offset   int
}

type CreateGroupInput struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
}

type Role struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RoleListFilter struct {
	TenantID *uuid.UUID
	Name     string
	Code     string
	Limit    int
	Offset   int
}

type CreateRoleInput struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
}
