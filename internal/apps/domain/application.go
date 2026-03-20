package domain

import "time"

type ApplicationType string

const (
	ApplicationTypeOIDCClient ApplicationType = "oidc-client"
	ApplicationTypeSAMLSP     ApplicationType = "saml-sp"
	ApplicationTypeCASService ApplicationType = "cas-service"
	ApplicationTypeLDAPClient ApplicationType = "ldap-client"
	ApplicationTypeSCIMTarget ApplicationType = "scim-target"
)

type ApplicationStatus string

const (
	ApplicationStatusActive   ApplicationStatus = "active"
	ApplicationStatusDisabled ApplicationStatus = "disabled"
	ApplicationStatusDraft    ApplicationStatus = "draft"
)

type Application struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Name        string            `json:"name"`
	Code        string            `json:"code"`
	Type        ApplicationType   `json:"type"`
	Status      ApplicationStatus `json:"status"`
	HomepageURL string            `json:"homepage_url"`
	IconURL     string            `json:"icon_url"`
	Description string            `json:"description"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}
