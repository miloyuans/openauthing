package domain

import (
	"net/url"
	"time"

	"github.com/google/uuid"
)

const (
	ResponseTypeCode         = "code"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"

	TokenEndpointAuthMethodNone              = "none"
	TokenEndpointAuthMethodClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthMethodClientSecretPost  = "client_secret_post"

	CodeChallengeMethodS256 = "S256"
)

type Client struct {
	ID                        uuid.UUID `json:"id"`
	TenantID                  uuid.UUID `json:"tenant_id"`
	AppID                     uuid.UUID `json:"app_id"`
	ClientID                  string    `json:"client_id"`
	ClientSecretHash          string    `json:"-"`
	RedirectURIs              []string  `json:"redirect_uris"`
	PostLogoutRedirectURIs    []string  `json:"post_logout_redirect_uris"`
	GrantTypes                []string  `json:"grant_types"`
	ResponseTypes             []string  `json:"response_types"`
	Scopes                    []string  `json:"scopes"`
	TokenEndpointAuthMethod   string    `json:"token_endpoint_auth_method"`
	RequirePKCE               bool      `json:"require_pkce"`
	AccessTokenTTLSeconds     int       `json:"access_token_ttl"`
	RefreshTokenTTLSeconds    int       `json:"refresh_token_ttl"`
	IDTokenSignedResponseAlg  string    `json:"id_token_signed_response_alg"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type AuthorizationRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

type AuthorizationResult struct {
	RedirectURI string
	Code        string
	State       string
}

func (r AuthorizationResult) RedirectLocation() string {
	redirectURL, _ := url.Parse(r.RedirectURI)
	query := redirectURL.Query()
	query.Set("code", r.Code)
	if r.State != "" {
		query.Set("state", r.State)
	}
	redirectURL.RawQuery = query.Encode()
	return redirectURL.String()
}

type AuthorizationCode struct {
	ID                  uuid.UUID  `json:"id"`
	OIDCClientID        uuid.UUID  `json:"oidc_client_id"`
	TenantID            uuid.UUID  `json:"tenant_id"`
	UserID              uuid.UUID  `json:"user_id"`
	SessionID           uuid.UUID  `json:"session_id"`
	CodeHash            string     `json:"-"`
	RedirectURI         string     `json:"redirect_uri"`
	Scopes              []string   `json:"scopes"`
	Nonce               string     `json:"nonce"`
	CodeChallenge       string     `json:"-"`
	CodeChallengeMethod string     `json:"code_challenge_method"`
	ExpiresAt           time.Time  `json:"expires_at"`
	CreatedAt           time.Time  `json:"created_at"`
	ConsumedAt          *time.Time `json:"consumed_at,omitempty"`
}

type RefreshToken struct {
	ID           uuid.UUID  `json:"id"`
	OIDCClientID uuid.UUID  `json:"oidc_client_id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	UserID       uuid.UUID  `json:"user_id"`
	SessionID    uuid.UUID  `json:"session_id"`
	TokenHash    string     `json:"-"`
	Scopes       []string   `json:"scopes"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

type TokenRequest struct {
	GrantType        string
	Code             string
	RedirectURI      string
	ClientID         string
	ClientSecret     string
	ClientAuthMethod string
	CodeVerifier     string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope,omitempty"`
}

type ProtocolError struct {
	Status      int
	Code        string
	Description string
	RedirectURI string
	State       string
}

func (e ProtocolError) Error() string {
	if e.Description != "" {
		return e.Description
	}

	return e.Code
}

func (e ProtocolError) ShouldRedirect() bool {
	return e.RedirectURI != ""
}

func (e ProtocolError) RedirectLocation() string {
	redirectURL, _ := url.Parse(e.RedirectURI)
	query := redirectURL.Query()
	query.Set("error", e.Code)
	if e.Description != "" {
		query.Set("error_description", e.Description)
	}
	if e.State != "" {
		query.Set("state", e.State)
	}
	redirectURL.RawQuery = query.Encode()
	return redirectURL.String()
}
