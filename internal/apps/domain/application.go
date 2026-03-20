package domain

import (
	"time"

	"github.com/google/uuid"
)

const (
	TypeOIDCClient = "oidc-client"
	TypeSAMLSP     = "saml-sp"
	TypeCASService = "cas-service"
	TypeLDAPClient = "ldap-client"
	TypeSCIMTarget = "scim-target"

	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusDraft    = "draft"
)

type Application struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	HomepageURL string    `json:"homepage_url"`
	IconURL     string    `json:"icon_url"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ApplicationListFilter struct {
	TenantID *uuid.UUID
	Name     string
	Code     string
	Type     string
	Status   string
	Limit    int
	Offset   int
}

type CreateApplicationInput struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	HomepageURL string    `json:"homepage_url"`
	IconURL     string    `json:"icon_url"`
	Description string    `json:"description"`
}
