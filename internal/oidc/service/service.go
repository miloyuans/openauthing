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
	oauthErrorInvalidToken         = "invalid_token"
	oauthErrorUnauthorizedClient   = "unauthorized_client"
	oauthErrorUnsupportedGrantType = "unsupported_grant_type"
	oauthErrorUnsupportedResponse  = "unsupported_response_type"
	oidcErrorLoginRequired         = "login_required"
)

type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error)
	ListGroupCodes(ctx context.Context, userID uuid.UUID) ([]string, error)
	ListRoleCodes(ctx context.Context, userID uuid.UUID) ([]string, error)
}

type SessionManager interface {
	Authenticate(ctx context.Context, sid string) (authdomain.Session, error)
	LogoutCurrent(ctx context.Context, session authdomain.Session) error
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
	accessTokens       oidcrepo.AccessTokenRepository
	users              UserRepository
	sessions           SessionManager
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

type issuedTokens struct {
	Response       oidcdomain.TokenResponse
	RefreshTokenID uuid.UUID
}

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
	accessTokens oidcrepo.AccessTokenRepository,
	users UserRepository,
	sessions SessionManager,
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
		accessTokens:       accessTokens,
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
		RevocationEndpoint:               s.endpoint("/oauth2/revoke"),
		EndSessionEndpoint:               s.endpoint("/oauth2/logout"),
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
			"groups",
			"roles",
		},
		GrantTypesSupported: []string{
			oidcdomain.GrantTypeAuthorizationCode,
			oidcdomain.GrantTypeRefreshToken,
		},
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

	if err := s.ensureCredentialSecret(); err != nil {
		return oidcdomain.AuthorizationResult{}, err
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
	input.RefreshToken = strings.TrimSpace(input.RefreshToken)
	input.RedirectURI = strings.TrimSpace(input.RedirectURI)
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.ClientSecret = strings.TrimSpace(input.ClientSecret)
	input.ClientAuthMethod = strings.TrimSpace(input.ClientAuthMethod)
	input.CodeVerifier = strings.TrimSpace(input.CodeVerifier)

	if err := s.ensureCredentialSecret(); err != nil {
		return oidcdomain.TokenResponse{}, err
	}

	switch input.GrantType {
	case oidcdomain.GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, input)
	case oidcdomain.GrantTypeRefreshToken:
		return s.exchangeRefreshToken(ctx, input)
	default:
		return oidcdomain.TokenResponse{}, newProtocolError(http.StatusBadRequest, oauthErrorUnsupportedGrantType, "unsupported grant_type", "", "")
	}
}

func (s *Service) UserInfo(ctx context.Context, rawAccessToken string) (oidcdomain.UserInfo, error) {
	rawAccessToken = strings.TrimSpace(rawAccessToken)
	if rawAccessToken == "" {
		return oidcdomain.UserInfo{}, newProtocolError(http.StatusUnauthorized, oauthErrorInvalidToken, "access token is required", "", "")
	}

	tokenHash, err := s.tokenValues.Hash(s.credentialSecret, rawAccessToken)
	if err != nil {
		return oidcdomain.UserInfo{}, fmt.Errorf("hash access token: %w", err)
	}

	accessToken, err := s.accessTokens.GetAccessTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return oidcdomain.UserInfo{}, newProtocolError(http.StatusUnauthorized, oauthErrorInvalidToken, "access token is invalid", "", "")
		}
		return oidcdomain.UserInfo{}, err
	}

	now := s.now().UTC()
	if accessToken.RevokedAt != nil || !now.Before(accessToken.ExpiresAt) {
		return oidcdomain.UserInfo{}, newProtocolError(http.StatusUnauthorized, oauthErrorInvalidToken, "access token is invalid", "", "")
	}

	user, err := s.loadActiveUser(ctx, accessToken.UserID, accessToken.TenantID)
	if err != nil {
		if isProtocolErrorCode(err, oauthErrorInvalidGrant) {
			return oidcdomain.UserInfo{}, newProtocolError(http.StatusUnauthorized, oauthErrorInvalidToken, "access token subject is invalid", "", "")
		}
		return oidcdomain.UserInfo{}, err
	}

	groups, err := s.users.ListGroupCodes(ctx, user.ID)
	if err != nil {
		return oidcdomain.UserInfo{}, err
	}
	roles, err := s.users.ListRoleCodes(ctx, user.ID)
	if err != nil {
		return oidcdomain.UserInfo{}, err
	}

	return oidcdomain.UserInfo{
		Sub:               user.ID.String(),
		PreferredUsername: user.Username,
		Email:             user.Email,
		Name:              user.DisplayName,
		Groups:            sliceOrEmpty(groups),
		Roles:             sliceOrEmpty(roles),
		SID:               accessToken.SessionID.String(),
	}, nil
}

func (s *Service) Revoke(ctx context.Context, input oidcdomain.RevocationRequest) error {
	input.Token = strings.TrimSpace(input.Token)
	input.TokenTypeHint = strings.TrimSpace(input.TokenTypeHint)
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.ClientSecret = strings.TrimSpace(input.ClientSecret)
	input.ClientAuthMethod = strings.TrimSpace(input.ClientAuthMethod)

	if input.Token == "" {
		return newProtocolError(http.StatusBadRequest, oauthErrorInvalidRequest, "token is required", "", "")
	}

	client, err := s.lookupClient(ctx, input.ClientID)
	if err != nil {
		return err
	}
	if err := s.authenticateClient(client, input.ClientAuthMethod, input.ClientSecret); err != nil {
		return err
	}

	tokenHash, err := s.tokenValues.Hash(s.credentialSecret, input.Token)
	if err != nil {
		return fmt.Errorf("hash revoke token: %w", err)
	}

	now := s.now().UTC()
	switch input.TokenTypeHint {
	case oidcdomain.TokenTypeHintAccessToken:
		return s.revokeAccessToken(ctx, client, tokenHash, now)
	case oidcdomain.TokenTypeHintRefreshToken:
		return s.revokeRefreshToken(ctx, client, tokenHash, now)
	default:
		if err := s.revokeAccessToken(ctx, client, tokenHash, now); err != nil {
			return err
		}
		return s.revokeRefreshToken(ctx, client, tokenHash, now)
	}
}

func (s *Service) Logout(ctx context.Context, rawSID string, input oidcdomain.LogoutRequest) (oidcdomain.LogoutResult, error) {
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.PostLogoutRedirectURI = strings.TrimSpace(input.PostLogoutRedirectURI)

	result := oidcdomain.LogoutResult{LoggedOut: true}
	if input.PostLogoutRedirectURI != "" && input.ClientID == "" {
		return oidcdomain.LogoutResult{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidRequest, "client_id is required when post_logout_redirect_uri is used", "", "")
	}

	if input.ClientID != "" {
		client, err := s.lookupClient(ctx, input.ClientID)
		if err != nil {
			return oidcdomain.LogoutResult{}, err
		}
		if input.PostLogoutRedirectURI != "" {
			if !containsString(client.PostLogoutRedirectURIs, input.PostLogoutRedirectURI) {
				return oidcdomain.LogoutResult{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidRequest, "post_logout_redirect_uri is invalid", "", "")
			}
			result.RedirectURI = input.PostLogoutRedirectURI
		}
	}

	rawSID = strings.TrimSpace(rawSID)
	if rawSID == "" {
		return result, nil
	}

	session, err := s.sessions.Authenticate(ctx, rawSID)
	if err != nil {
		s.logger.Info("oidc logout without active session",
			"request_id", requestid.FromContext(ctx),
			"client_id", input.ClientID,
			"error", err,
		)
		return result, nil
	}

	now := s.now().UTC()
	if err := s.withinTx(ctx, func(txCtx context.Context) error {
		if err := s.sessions.LogoutCurrent(txCtx, session); err != nil {
			return err
		}
		return s.revokeSessionTokens(txCtx, session.ID, now)
	}); err != nil {
		return oidcdomain.LogoutResult{}, err
	}

	s.logger.Info("oidc logout",
		"request_id", requestid.FromContext(ctx),
		"user_id", session.UserID.String(),
		"session_id", session.ID.String(),
		"client_id", input.ClientID,
	)

	return result, nil
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, input oidcdomain.TokenRequest) (oidcdomain.TokenResponse, error) {
	client, err := s.lookupClient(ctx, input.ClientID)
	if err != nil {
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

		user, userErr := s.loadActiveUser(txCtx, code.UserID, client.TenantID)
		if userErr != nil {
			return userErr
		}

		issued, issueErr := s.issueTokens(txCtx, client, user, code.SessionID, code.Scopes, code.Nonce)
		if issueErr != nil {
			return issueErr
		}

		if consumeErr := s.authorizationCodes.Consume(txCtx, code.ID, now); consumeErr != nil {
			if errors.Is(consumeErr, store.ErrNotFound) {
				return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization code is invalid or already used", "", "")
			}
			return consumeErr
		}

		response = issued.Response
		return nil
	}); err != nil {
		return oidcdomain.TokenResponse{}, err
	}

	s.logger.Info("oidc token issued",
		"request_id", requestid.FromContext(ctx),
		"client_id", client.ClientID,
		"grant_type", oidcdomain.GrantTypeAuthorizationCode,
		"expires_in", response.ExpiresIn,
	)

	return response, nil
}

func (s *Service) exchangeRefreshToken(ctx context.Context, input oidcdomain.TokenRequest) (oidcdomain.TokenResponse, error) {
	client, err := s.lookupClient(ctx, input.ClientID)
	if err != nil {
		return oidcdomain.TokenResponse{}, err
	}

	if !containsString(client.GrantTypes, oidcdomain.GrantTypeRefreshToken) {
		return oidcdomain.TokenResponse{}, newProtocolError(http.StatusBadRequest, oauthErrorUnauthorizedClient, "client does not allow refresh_token grant", "", "")
	}

	if err := s.authenticateClient(client, input.ClientAuthMethod, input.ClientSecret); err != nil {
		return oidcdomain.TokenResponse{}, err
	}

	if input.RefreshToken == "" {
		return oidcdomain.TokenResponse{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidRequest, "refresh_token is required", "", "")
	}

	tokenHash, err := s.tokenValues.Hash(s.credentialSecret, input.RefreshToken)
	if err != nil {
		return oidcdomain.TokenResponse{}, fmt.Errorf("hash refresh token: %w", err)
	}

	now := s.now().UTC()
	var response oidcdomain.TokenResponse
	if err := s.withinTx(ctx, func(txCtx context.Context) error {
		refreshToken, lookupErr := s.refreshTokens.GetRefreshTokenByHashForUpdate(txCtx, tokenHash)
		if lookupErr != nil {
			if errors.Is(lookupErr, store.ErrNotFound) {
				return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "refresh token is invalid", "", "")
			}
			return lookupErr
		}

		if refreshToken.OIDCClientID != client.ID || refreshToken.ClientID != client.ClientID {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "refresh token is invalid", "", "")
		}
		if !now.Before(refreshToken.ExpiresAt) {
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "refresh token has expired", "", "")
		}
		if refreshToken.RevokedAt != nil {
			if refreshToken.ReplacedByID != nil {
				if markErr := s.refreshTokens.MarkRefreshTokenReplay(txCtx, refreshToken.ID, now); markErr != nil && !errors.Is(markErr, store.ErrNotFound) {
					return markErr
				}
				if revokeErr := s.revokeSessionTokens(txCtx, refreshToken.SessionID, now); revokeErr != nil {
					return revokeErr
				}
				s.logger.Warn("oidc refresh token replay detected",
					"request_id", requestid.FromContext(ctx),
					"client_id", client.ClientID,
					"user_id", refreshToken.UserID.String(),
					"session_id", refreshToken.SessionID.String(),
				)
			}
			return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "refresh token is invalid", "", "")
		}

		user, userErr := s.loadActiveUser(txCtx, refreshToken.UserID, client.TenantID)
		if userErr != nil {
			return userErr
		}

		issued, issueErr := s.issueTokens(txCtx, client, user, refreshToken.SessionID, refreshToken.Scopes, "")
		if issueErr != nil {
			return issueErr
		}
		if issued.RefreshTokenID == uuid.Nil {
			return fmt.Errorf("refresh token rotation requires refresh token issuance")
		}

		if rotateErr := s.refreshTokens.RotateRefreshToken(txCtx, refreshToken.ID, issued.RefreshTokenID, now); rotateErr != nil {
			if errors.Is(rotateErr, store.ErrNotFound) {
				return newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "refresh token is invalid", "", "")
			}
			return rotateErr
		}

		response = issued.Response
		return nil
	}); err != nil {
		return oidcdomain.TokenResponse{}, err
	}

	s.logger.Info("oidc token issued",
		"request_id", requestid.FromContext(ctx),
		"client_id", client.ClientID,
		"grant_type", oidcdomain.GrantTypeRefreshToken,
		"expires_in", response.ExpiresIn,
	)

	return response, nil
}

func (s *Service) issueTokens(
	ctx context.Context,
	client oidcdomain.Client,
	user userdomain.User,
	sessionID uuid.UUID,
	scopes []string,
	nonce string,
) (issuedTokens, error) {
	now := s.now().UTC()
	accessTokenExpiresAt := now.Add(time.Duration(client.AccessTokenTTLSeconds) * time.Second)

	accessToken, err := s.signToken(map[string]any{
		"iss":                s.issuer,
		"sub":                user.ID.String(),
		"aud":                client.ClientID,
		"exp":                accessTokenExpiresAt.Unix(),
		"iat":                now.Unix(),
		"jti":                uuid.NewString(),
		"sid":                sessionID.String(),
		"scope":              strings.Join(scopes, " "),
		"preferred_username": user.Username,
		"email":              user.Email,
		"name":               user.DisplayName,
		"token_use":          "access_token",
	})
	if err != nil {
		return issuedTokens{}, err
	}

	accessTokenHash, err := s.tokenValues.Hash(s.credentialSecret, accessToken)
	if err != nil {
		return issuedTokens{}, fmt.Errorf("hash access token: %w", err)
	}

	if _, err := s.accessTokens.CreateAccessToken(ctx, oidcdomain.AccessToken{
		OIDCClientID: client.ID,
		ClientID:     client.ClientID,
		TenantID:     client.TenantID,
		UserID:       user.ID,
		SessionID:    sessionID,
		TokenHash:    accessTokenHash,
		Scopes:       scopes,
		ExpiresAt:    accessTokenExpiresAt,
	}); err != nil {
		return issuedTokens{}, err
	}

	idTokenClaims := map[string]any{
		"iss":                s.issuer,
		"sub":                user.ID.String(),
		"aud":                client.ClientID,
		"exp":                accessTokenExpiresAt.Unix(),
		"iat":                now.Unix(),
		"sid":                sessionID.String(),
		"preferred_username": user.Username,
		"email":              user.Email,
		"name":               user.DisplayName,
	}
	if nonce != "" {
		idTokenClaims["nonce"] = nonce
	}

	idToken, err := s.signToken(idTokenClaims)
	if err != nil {
		return issuedTokens{}, err
	}

	result := issuedTokens{
		Response: oidcdomain.TokenResponse{
			AccessToken: accessToken,
			TokenType:   defaultTokenType,
			ExpiresIn:   client.AccessTokenTTLSeconds,
			IDToken:     idToken,
			Scope:       strings.Join(scopes, " "),
		},
	}

	if containsString(client.GrantTypes, oidcdomain.GrantTypeRefreshToken) && client.RefreshTokenTTLSeconds > 0 {
		rawRefreshToken, err := s.tokenValues.Generate()
		if err != nil {
			return issuedTokens{}, fmt.Errorf("generate refresh token: %w", err)
		}

		refreshTokenHash, err := s.tokenValues.Hash(s.credentialSecret, rawRefreshToken)
		if err != nil {
			return issuedTokens{}, fmt.Errorf("hash refresh token: %w", err)
		}

		createdRefreshToken, err := s.refreshTokens.CreateRefreshToken(ctx, oidcdomain.RefreshToken{
			OIDCClientID: client.ID,
			ClientID:     client.ClientID,
			TenantID:     client.TenantID,
			UserID:       user.ID,
			SessionID:    sessionID,
			TokenHash:    refreshTokenHash,
			Scopes:       scopes,
			ExpiresAt:    now.Add(time.Duration(client.RefreshTokenTTLSeconds) * time.Second),
		})
		if err != nil {
			return issuedTokens{}, err
		}

		result.Response.RefreshToken = rawRefreshToken
		result.RefreshTokenID = createdRefreshToken.ID
	}

	return result, nil
}

func (s *Service) loadActiveUser(ctx context.Context, userID, tenantID uuid.UUID) (userdomain.User, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return userdomain.User{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization subject is no longer available", "", "")
		}
		return userdomain.User{}, err
	}
	if user.Status != "active" {
		return userdomain.User{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization subject is not active", "", "")
	}
	if user.TenantID != tenantID {
		return userdomain.User{}, newProtocolError(http.StatusBadRequest, oauthErrorInvalidGrant, "authorization subject tenant does not match the client", "", "")
	}

	return user, nil
}

func (s *Service) revokeAccessToken(ctx context.Context, client oidcdomain.Client, tokenHash string, revokedAt time.Time) error {
	accessToken, err := s.accessTokens.GetAccessTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if accessToken.ClientID != client.ClientID {
		return nil
	}

	if err := s.accessTokens.RevokeAccessTokenByHash(ctx, tokenHash, revokedAt); err != nil {
		return err
	}

	s.logger.Info("oidc token revoked",
		"request_id", requestid.FromContext(ctx),
		"client_id", client.ClientID,
		"token_type", oidcdomain.TokenTypeHintAccessToken,
		"user_id", accessToken.UserID.String(),
		"session_id", accessToken.SessionID.String(),
	)

	return nil
}

func (s *Service) revokeRefreshToken(ctx context.Context, client oidcdomain.Client, tokenHash string, revokedAt time.Time) error {
	return s.withinTx(ctx, func(txCtx context.Context) error {
		refreshToken, err := s.refreshTokens.GetRefreshTokenByHashForUpdate(txCtx, tokenHash)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if refreshToken.ClientID != client.ClientID {
			return nil
		}

		if err := s.refreshTokens.RevokeRefreshTokenByHash(txCtx, tokenHash, revokedAt); err != nil {
			return err
		}

		s.logger.Info("oidc token revoked",
			"request_id", requestid.FromContext(ctx),
			"client_id", client.ClientID,
			"token_type", oidcdomain.TokenTypeHintRefreshToken,
			"user_id", refreshToken.UserID.String(),
			"session_id", refreshToken.SessionID.String(),
		)

		return nil
	})
}

func (s *Service) revokeSessionTokens(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error {
	if err := s.accessTokens.RevokeAccessTokensBySessionID(ctx, sessionID, revokedAt); err != nil {
		return err
	}
	if err := s.refreshTokens.RevokeRefreshTokensBySessionID(ctx, sessionID, revokedAt); err != nil {
		return err
	}

	return nil
}

func (s *Service) lookupClient(ctx context.Context, clientID string) (oidcdomain.Client, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return oidcdomain.Client{}, newProtocolError(http.StatusUnauthorized, oauthErrorInvalidClient, "client authentication failed", "", "")
	}

	client, err := s.clients.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return oidcdomain.Client{}, newProtocolError(http.StatusUnauthorized, oauthErrorInvalidClient, "client authentication failed", "", "")
		}
		return oidcdomain.Client{}, err
	}

	return client, nil
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

func (s *Service) ensureCredentialSecret() error {
	if strings.TrimSpace(s.credentialSecret) == "" {
		return fmt.Errorf("oidc credential secret is required")
	}

	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func sliceOrEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
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

func isProtocolErrorCode(err error, code string) bool {
	var protocolErr oidcdomain.ProtocolError
	return errors.As(err, &protocolErr) && protocolErr.Code == code
}
