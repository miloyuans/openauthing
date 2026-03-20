package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	authpassword "github.com/miloyuans/openauthing/internal/auth/password"
	"github.com/miloyuans/openauthing/internal/config"
	oidcdomain "github.com/miloyuans/openauthing/internal/oidc/domain"
	oidcjwt "github.com/miloyuans/openauthing/internal/oidc/jwt"
	"github.com/miloyuans/openauthing/internal/oidc/keys"
	oidcrepo "github.com/miloyuans/openauthing/internal/oidc/repo"
	"github.com/miloyuans/openauthing/internal/oidc/tokenvalue"
	"github.com/miloyuans/openauthing/internal/shared/requestid"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

const (
	defaultIssuer                  = "http://localhost:8080"
	defaultAuthorizationCodeTTL    = 5 * time.Minute
	defaultTokenType               = "Bearer"
	supportedIDTokenSigningAlg     = "RS256"
	oauthErrorInvalidRequest       = "invalid_request"
	oauthErrorInvalidClient        = "invalid_client"
	oauthErrorInvalidGrant         = "invalid_grant"
	oauthErrorInvalidScope         = "invalid_scope"
	oauthErrorUnauthorizedClient   = "unauthorized_client"
	oauthErrorUnsupportedGrantType = "unsupported_grant_type"
	oauthErrorUnsupportedResponse  = "unsupported_response_type"
	oidcErrorLoginRequired         = "login_required"
)

type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error)
}

type SessionAuthenticator interface {
	Authenticate(ctx context.Context, sid string) (authdomain.Session, error)
}

type PasswordVerifier interface {
	Verify(plain, encoded string) (bool, error)
}

type TokenValueManager interface {
	Generate() (string, error)
	Hash(secret, rawValue string) (string, error)
}

type TokenSigner interface {
	Sign(claims map[string]any) (string, error)
}

type TxManager interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}

type Service struct {
	issuer             string
	codeTTL            time.Duration
	clients            oidcrepo.ClientRepository
	authorizationCodes oidcrepo.AuthorizationCodeRepository
	refreshTokens      oidcrepo.RefreshTokenRepository
	users              UserRepository
	sessions           SessionAuthenticator
	passwords          PasswordVerifier
	tokenValues        TokenValueManager
	tokenSigner        TokenSigner
	txManager          TxManager
	credentialSecret   string
	logger             *slog.Logger
	now                func() time.Time
	keyManager         *keys.Manager
}

type defaultTokenValueManager struct{}

func (defaultTokenValueManager) Generate() (string, error) {
	return tokenvalue.Generate()
}

func (defaultTokenValueManager) Hash(secret, rawValue string) (string, error) {
	return tokenvalue.Hash(secret, rawValue)
}

func NewService(
	cfg config.OIDCConfig,
	keyManager *keys.Manager,
	clients oidcrepo.ClientRepository,
	authorizationCodes oidcrepo.AuthorizationCodeRepository,
	refreshTokens oidcrepo.RefreshTokenRepository,
	users UserRepository,
	sessions SessionAuthenticator,
	txManager TxManager,
	credentialSecret string,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}

	codeTTL := time.Duration(cfg.AuthorizationCodeTTLSeconds) * time.Second
	if codeTTL <= 0 {
		codeTTL = defaultAuthorizationCodeTTL
	}

	return &Service{
		issuer:             normalizeIssuer(cfg.Issuer),
		codeTTL:            codeTTL,
		clients:            clients,
		authorizationCodes: authorizationCodes,
		refreshTokens:      refreshTokens,
		users:              users,
		sessions:           sessions,
		passwords:          authpassword.NewArgon2ID(),
		tokenValues:        defaultTokenValueManager{},
		tokenSigner:        oidcjwt.NewSigner(keyManager),
		txManager:          txManager,
		credentialSecret:   strings.TrimSpace(credentialSecret),
		logger:             logger,
		now:                time.Now,
		keyManager:         keyManager,
	}
}

func (s *Service) DiscoveryDocument() oidcdomain.DiscoveryDocument {
	return oidcdomain.DiscoveryDocument{
		Issuer:                           s.issuer,
		AuthorizationEndpoint:            s.endpoint("/oauth2/authorize"),
		TokenEndpoint:                    s.endpoint("/oauth2/token"),
		UserinfoEndpoint:                 s.endpoint("/oauth2/userinfo"),
		JWKSURI:                          s.endpoint("/.well-known/jwks.json"),
		ResponseTypesSupported:           []string{oidcdomain.ResponseTypeCode},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{supportedIDTokenSigningAlg},
		ScopesSupported:                  []string{"openid", "profile", "email", "offline_access"},
		ClaimsSupported: []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"auth_time",
			"sid",
			"name",
			"preferred_username",
			"email",
			"email_verified",
		},
		GrantTypesSupported:               []string{oidcdomain.GrantTypeAuthorizationCode, oidcdomain.GrantTypeRefreshToken},
		TokenEndpointAuthMethodsSupported: []string{
			oidcdomain.TokenEndpointAuthMethodClientSecretBasic,
			oidcdomain.TokenEndpointAuthMethodClientSecretPost,
			oidcdomain.TokenEndpointAuthMethodNone,
		},
		CodeChallengeMethodsSupported: []string{oidcdomain.CodeChallengeMethodS256},
	}
}

func (s *Service) JWKS() oidcdomain.JWKSet {
	if s.keyManager == nil {
		return oidcdomain.JWKSet{}
	}

	return s.keyManager.PublicJWKSet()
}

func (s *Service) Authorize(ctx context.Context, input oidcdomain.AuthorizationRequest, rawSID string) (oidcdomain.AuthorizationResult, error) {
	input.ResponseType = strings.TrimSpace(input.ResponseType)
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.RedirectURI = strings.TrimSpace(input.RedirectURI)
	input.Scope = strings.TrimSpace(input.Scope)
	input.State = strings.TrimSpace(input.State)
	input.CodeChallenge = strings.TrimSpace(input.CodeChallenge)
	input.CodeChallengeMethod = strings.TrimSpace(input.CodeChallengeMethod)
	input.Nonce = strings.TrimSpace(input.Nonce)

	if strings.TrimSpace(s.credentialSecret) == "" {
		return oidcdomain.AuthorizationResult{}, fmt.Errorf("oidc credential secret is required")
	}

	client, err := s.clients.GetByClientID(ctx, input.ClientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidClient, "client_id is invalid", "", input.State)
		}
		return oidcdomain.AuthorizationResult{}, err
	}

	if !containsString(client.RedirectURIs, input.RedirectURI) {
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidRequest, "redirect_uri is invalid", "", input.State)
	}

	if input.ResponseType != oidcdomain.ResponseTypeCode {
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusBadRequest, oauthErrorUnsupportedResponse, "only response_type=code is supported", input.RedirectURI, input.State)
	}

	if !containsString(client.ResponseTypes, oidcdomain.ResponseTypeCode) {
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusBadRequest, oauthErrorUnauthorizedClient, "client does not allow response_type=code", input.RedirectURI, input.State)
	}

	if !containsString(client.GrantTypes, oidcdomain.GrantTypeAuthorizationCode) {
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusBadRequest, oauthErrorUnauthorizedClient, "client does not allow authorization_code grant", input.RedirectURI, input.State)
	}

	requestedScopes, err := validateRequestedScopes(input.Scope, client.Scopes)
	if err != nil {
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidScope, err.Error(), input.RedirectURI, input.State)
	}

	if err := validateAuthorizeRequestShape(input, client.RequirePKCE); err != nil {
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidRequest, err.Error(), input.RedirectURI, input.State)
	}

	if rawSID == "" {
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusFound, oidcErrorLoginRequired, "user authentication is required", input.RedirectURI, input.State)
	}

	session, err := s.sessions.Authenticate(ctx, rawSID)
	if err != nil {
		s.logger.Warn("oidc authorize login required",
			"request_id", requestid.FromContext(ctx),
			"client_id", client.ClientID,
			"redirect_uri", input.RedirectURI,
			"error", err,
		)
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusFound, oidcErrorLoginRequired, "user authentication is required", input.RedirectURI, input.State)
	}

	if session.TenantID != client.TenantID {
		return oidcdomain.AuthorizationResult{}, newProtocolError(http.StatusBadRequest, oauthErrorUnauthorizedClient, "session tenant does not match client tenant", input.RedirectURI, input.State)
	}

	rawCode, err := s.tokenValues.Generate()
	if err != nil {
		return oidcdomain.AuthorizationResult{}, fmt.Errorf("generate authorization code: %w", err)
	}

	codeHash, err := s.tokenValues.Hash(s.credentialSecret, rawCode)
	if err != nil {
		return oidcdomain.AuthorizationResult{}, fmt.Errorf("hash authorization code: %w", err)
	}

	now := s.now().UTC()
	if _, err := s.authorizationCodes.CreateAuthorizationCode(ctx, oidcdomain.AuthorizationCode{
		OIDCClientID:        client.ID,
		TenantID:            client.TenantID,
		UserID:              session.UserID,
		SessionID:           session.ID,
		CodeHash:            codeHash,
		RedirectURI:         input.RedirectURI,
		Scopes:              requestedScopes,
		Nonce:               input.Nonce,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		ExpiresAt:           now.Add(s.codeTTL),
	}); err != nil {
		return oidcdomain.AuthorizationResult{}, err
	}

	s.logger.Info("oidc authorization code issued",
		"request_id", requestid.FromContext(ctx),
		"client_id", client.ClientID,
		"user_id", session.UserID.String(),
		"session_id", session.ID.String(),
		"scopes", strings.Join(requestedScopes, " "),
	)

	return oidcdomain.AuthorizationResult{
		RedirectURI: input.RedirectURI,
		Code:        rawCode,
		State:       input.State,
	}, nil
}

func (s *Service) ExchangeCode(ctx context.Context, input oidcdomain.TokenRequest) (oidcdomain.TokenResponse, error) {
	input.GrantType = strings.TrimSpace(input.GrantType)
	input.Code = strings.TrimSpace(input.Code)
	input.RedirectURI = strings.TrimSpace(input.RedirectURI)
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.ClientSecret = strings.TrimSpace(input.ClientSecret)
	input.ClientAuthMethod = strings.TrimSpace(input.ClientAuthMethod)
	input.CodeVerifier = strings.TrimSpace(input.CodeVerifier)

	if input.GrantType != oidcdomain.GrantTypeAuthorizationCode {
		return oidcdomain.TokenResponse{}, newProtocolError(http.StatusBadRequest, oauthErrorUnsupportedGrantType, "only grant_type=authorization_code is supported", "", "")
	}

	if strings.TrimSpace(s.credentialSecret) == "" {
		return oidcdomain.TokenResponse{}, fmt.Errorf("oidc credential secret is required")
	}

	client, err := s.clients.GetByClientID(ctx, input.ClientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return oidcdomain.TokenResponse{}, newProtocolError(http.StatusUnauthorized, oauthErrorInvalidClient, "client authentication failed", "", "")
		}
		return oidcdomain.TokenResponse{}, err
	}

	if !containsString(client.GrantTypes, oidcdomain.GrantTypeAuthorizationCode) {
		return oidcdomain.TokenResponse{}, newProtocolError(http.StatusBadRequest, oauthErrorUnauthorizedClient, "client does not allow authorization_code grant", "", "")
	}

	if err := s.authenticateClient(client, input.ClientAuthMethod, input.ClientSecret); err != nil {
		return oidcdomain.TokenResponse{}, err
	}

	codeHash, err := s.tokenValues.Hash(s.credentialSecret, input.Code)
	if err != nil {
		return oidcdomain.TokenResponse{}, fmt.Errorf("hash authorization code: %w", err)
	}

	now := s.now().UTC()
	var response oidcdomain.TokenResponse
	if err := s.withinTx(ctx, func(txCtx context.Context) error {
		code, lookupErr := s.authorizationCodes.GetByCodeHashForUpdate(txCtx, codeHash)
		if lookupErr != nil {
			if errors.Is(lookupErr, store.ErrNotFound) {
				return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization code is invalid or already used", "", "")
			}
			return lookupErr
		}

		if code.OIDCClientID != client.ID {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization code does not belong to the client", "", "")
		}
		if code.ConsumedAt != nil {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization code is invalid or already used", "", "")
		}
		if !now.Before(code.ExpiresAt) {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization code has expired", "", "")
		}
		if input.RedirectURI != code.RedirectURI {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "redirect_uri does not match", "", "")
		}
		if err := validateCodeVerifier(input.CodeVerifier, code, client.RequirePKCE); err != nil {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, err.Error(), "", "")
		}

		user, userErr := s.users.GetByID(txCtx, code.UserID)
		if userErr != nil {
			if errors.Is(userErr, store.ErrNotFound) {
				return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization subject is no longer available", "", "")
			}
			return userErr
		}
		if user.Status != "active" {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization subject is not active", "", "")
		}
		if user.TenantID != client.TenantID {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization subject tenant does not match the client", "", "")
		}

		accessToken, signErr := s.signToken(map[string]any{
			"iss":                s.issuer,
			"sub":                user.ID.String(),
			"aud":                client.ClientID,
			"exp":                now.Add(time.Duration(client.AccessTokenTTLSeconds) * time.Second).Unix(),
			"iat":                now.Unix(),
			"jti":                now.Format(time.RFC3339Nano) + ":" + user.ID.String(),
			"sid":                code.SessionID.String(),
			"scope":              strings.Join(code.Scopes, " "),
			"preferred_username": user.Username,
			"email":              user.Email,
			"name":               user.DisplayName,
			"token_use":          "access_token",
		})
		if signErr != nil {
			return signErr
		}

		idTokenClaims := map[string]any{
			"iss":                s.issuer,
			"sub":                user.ID.String(),
			"aud":                client.ClientID,
			"exp":                now.Add(time.Duration(client.AccessTokenTTLSeconds) * time.Second).Unix(),
			"iat":                now.Unix(),
			"sid":                code.SessionID.String(),
			"preferred_username": user.Username,
			"email":              user.Email,
			"name":               user.DisplayName,
		}
		if code.Nonce != "" {
			idTokenClaims["nonce"] = code.Nonce
		}

		idToken, signErr := s.signToken(idTokenClaims)
		if signErr != nil {
			return signErr
		}

		var refreshRaw string
		if containsString(client.GrantTypes, oidcdomain.GrantTypeRefreshToken) && client.RefreshTokenTTLSeconds > 0 {
			refreshRaw, signErr = s.tokenValues.Generate()
			if signErr != nil {
				return fmt.Errorf("generate refresh token: %w", signErr)
			}

			refreshHash, hashErr := s.tokenValues.Hash(s.credentialSecret, refreshRaw)
			if hashErr != nil {
				return fmt.Errorf("hash refresh token: %w", hashErr)
			}

			if _, createErr := s.refreshTokens.CreateRefreshToken(txCtx, oidcdomain.RefreshToken{
				OIDCClientID: client.ID,
				TenantID:     client.TenantID,
				UserID:       user.ID,
				SessionID:    code.SessionID,
				TokenHash:    refreshHash,
				Scopes:       code.Scopes,
				ExpiresAt:    now.Add(time.Duration(client.RefreshTokenTTLSeconds) * time.Second),
			}); createErr != nil {
				return createErr
			}
		}

		if consumeErr := s.authorizationCodes.Consume(txCtx, code.ID, now); consumeErr != nil {
			if errors.Is(consumeErr, store.ErrNotFound) {
				return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization code is invalid or already used", "", "")
			}
			return consumeErr
		}

		response = oidcdomain.TokenResponse{
			AccessToken:  accessToken,
			TokenType:    defaultTokenType,
			ExpiresIn:    client.AccessTokenTTLSeconds,
			RefreshToken: refreshRaw,
			IDToken:      idToken,
			Scope:        strings.Join(code.Scopes, " "),
		}

		return nil
	}); err != nil {
		return oidcdomain.TokenResponse{}, err
	}

	s.logger.Info("oidc token issued",
		"request_id", requestid.FromContext(ctx),
		"client_id", client.ClientID,
		"expires_in", response.ExpiresIn,
	)

	return response, nil
}

func (s *Service) endpoint(path string) string {
	return s.issuer + path
}

func normalizeIssuer(raw string) string {
	issuer := strings.TrimSpace(raw)
	if issuer == "" {
		issuer = defaultIssuer
	}

	return strings.TrimRight(issuer, "/")
}

func validateAuthorizeRequestShape(input oidcdomain.AuthorizationRequest, requirePKCE bool) error {
	if input.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if input.RedirectURI == "" {
		return fmt.Errorf("redirect_uri is required")
	}
	if err := validateAbsoluteURL(input.RedirectURI); err != nil {
		return fmt.Errorf("redirect_uri must be a valid absolute URL")
	}
	if input.Scope == "" {
		return fmt.Errorf("scope is required")
	}
	if len(input.Nonce) > 255 {
		return fmt.Errorf("nonce must be at most 255 characters")
	}
	if requirePKCE || input.CodeChallenge != "" || input.CodeChallengeMethod != "" {
		if input.CodeChallenge == "" {
			return fmt.Errorf("code_challenge is required")
		}
		if input.CodeChallengeMethod != oidcdomain.CodeChallengeMethodS256 {
			return fmt.Errorf("only code_challenge_method=S256 is supported")
		}
	}

	return nil
}

func validateRequestedScopes(raw string, allowed []string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("scope is required")
	}

	parts := strings.Fields(raw)
	seen := make(map[string]struct{}, len(parts))
	scopes := make([]string, 0, len(parts))
	hasOpenID := false
	for _, part := range parts {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}

		if !containsString(allowed, part) {
			return nil, fmt.Errorf("scope %q is not allowed for the client", part)
		}
		if part == "openid" {
			hasOpenID = true
		}
		scopes = append(scopes, part)
	}

	if !hasOpenID {
		return nil, fmt.Errorf("openid scope is required")
	}

	return scopes, nil
}

func validateCodeVerifier(verifier string, code oidcdomain.AuthorizationCode, requirePKCE bool) error {
	if code.CodeChallenge == "" && !requirePKCE {
		return nil
	}
	if verifier == "" {
		return fmt.Errorf("code_verifier is required")
	}
	if code.CodeChallengeMethod != oidcdomain.CodeChallengeMethodS256 {
		return fmt.Errorf("unsupported code challenge method")
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if computed != code.CodeChallenge {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}

	return nil
}

func (s *Service) authenticateClient(client oidcdomain.Client, authMethod, secret string) error {
	if authMethod == "" {
		authMethod = oidcdomain.TokenEndpointAuthMethodNone
	}
	if client.TokenEndpointAuthMethod != authMethod {
		return newProtocolError(http.StatusUnauthorized, oauthErrorInvalidClient, "client authentication failed", "", "")
	}

	switch authMethod {
	case oidcdomain.TokenEndpointAuthMethodNone:
		if secret != "" {
			return newProtocolError(http.StatusUnauthorized, oauthErrorInvalidClient, "client_secret is not allowed for this client", "", "")
		}
		return nil
	case oidcdomain.TokenEndpointAuthMethodClientSecretBasic, oidcdomain.TokenEndpointAuthMethodClientSecretPost:
		if strings.TrimSpace(secret) == "" || strings.TrimSpace(client.ClientSecretHash) == "" {
			return newProtocolError(http.StatusUnauthorized, oauthErrorInvalidClient, "client authentication failed", "", "")
		}

		ok, err := s.passwords.Verify(secret, client.ClientSecretHash)
		if err != nil || !ok {
			return newProtocolError(http.StatusUnauthorized, oauthErrorInvalidClient, "client authentication failed", "", "")
		}
		return nil
	default:
		return newProtocolError(http.StatusUnauthorized, oauthErrorInvalidClient, "unsupported token endpoint auth method", "", "")
	}
}

func (s *Service) signToken(claims map[string]any) (string, error) {
	signed, err := s.tokenSigner.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("sign oidc token: %w", err)
	}

	return signed, nil
}

func (s *Service) withinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.txManager == nil {
		return fn(ctx)
	}

	return s.txManager.WithinTx(ctx, fn)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func validateAbsoluteURL(raw string) error {
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("host is required")
	}

	return nil
}

func newProtocolError(status int, code, description, redirectURI, state string) oidcdomain.ProtocolError {
	return oidcdomain.ProtocolError{
		Status:      status,
		Code:        code,
		Description: description,
		RedirectURI: redirectURI,
		State:       state,
	}
}
