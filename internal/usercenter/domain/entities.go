package domain

import "time"

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Organization struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ParentID  string    `json:"parent_id,omitempty"`
	Name      string    `json:"name"`
	Code      string    `json:"code"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type User struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	OrganizationID string     `json:"organization_id,omitempty"`
	Username       string     `json:"username"`
	Email          string     `json:"email,omitempty"`
	Phone          string     `json:"phone,omitempty"`
	DisplayName    string     `json:"display_name"`
	PasswordHash   string     `json:"-"`
	PasswordAlgo   string     `json:"password_algo"`
	Status         string     `json:"status"`
	Source         string     `json:"source"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type UserProfile struct {
	UserID     string         `json:"user_id"`
	Avatar     string         `json:"avatar,omitempty"`
	Title      string         `json:"title,omitempty"`
	Department string         `json:"department,omitempty"`
	Locale     string         `json:"locale,omitempty"`
	Timezone   string         `json:"timezone,omitempty"`
	Extra      map[string]any `json:"extra,omitempty"`
}

type Group struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Role struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Permission struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	Effect    string    `json:"effect"`
	CreatedAt time.Time `json:"created_at"`
}
