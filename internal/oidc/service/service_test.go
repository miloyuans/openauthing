package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	"github.com/miloyuans/openauthing/internal/config"
	oidcdomain "github.com/miloyuans/openauthing/internal/oidc/domain"
	oidcrepo "github.com/miloyuans/openauthing/internal/oidc/repo"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

func TestAuthorizeCreatesAuthorizationCode(t *testing.T) {
	fixedNow := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	clientID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	userID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	sessionID := uuid.MustParse("44444444-4444-4444-4444-444444444444")

	codeRepo := &fakeAuthorizationCodeRepo{}
	service := newTestService(t, fixedNow, &fakeClientRepo{
		client: oidcdomain.Client{
			ID:                      clientID,
			TenantID:                tenantID,
			ClientID:                "demo-public-client",
			RedirectURIs:            []string{"https://client.example.test/callback"},
			GrantTypes:              []string{oidcdomain.GrantTypeAuthorizationCode, oidcdomain.GrantTypeRefreshToken},
			ResponseTypes:           []string{oidcdomain.ResponseTypeCode},
			Scopes:                  []string{"openid", "profile", "email"},
			TokenEndpointAuthMethod: oidcdomain.TokenEndpointAuthMethodNone,
			RequirePKCE:             true,
			AccessTokenTTLSeconds:   600,
			RefreshTokenTTLSeconds:  3600,
		},
	}, codeRepo, &fakeRefreshTokenRepo{}, &fakeUserRepo{}, &fakeSessionAuthenticator{
		session: authdomain.Session{
			ID:       sessionID,
			TenantID: tenantID,
			UserID:   userID,
			Status:   authdomain.SessionStatusActive,
		},
	}, &fakeTokenValueManager{
		generated: []string{"raw-auth-code"},
		hashed: map[string]string{
			"raw-auth-code": "hashed-auth-code",
		},
	}, &fakeTokenSigner{})

	result, err := service.Authorize(context.Background(), oidcdomain.AuthorizationRequest{
		ResponseType:        oidcdomain.ResponseTypeCode,
		ClientID:            "demo-public-client",
		RedirectURI:         "https://client.example.test/callback",
		Scope:               "openid profile email",
		State:               "state-1",
		CodeChallenge:       "PKCE-CHALLENGE",
		CodeChallengeMethod: oidcdomain.CodeChallengeMethodS256,
		Nonce:               "nonce-1",
	}, "raw-session")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	if result.Code != "raw-auth-code" || result.State != "state-1" {
		t.Fatalf("unexpected authorize result: %#v", result)
	}

	if codeRepo.created.CodeHash != "hashed-auth-code" {
		t.Fatalf("expected hashed auth code to be stored, got %#v", codeRepo.created)
	}

	if codeRepo.created.ExpiresAt != fixedNow.Add(5*time.Minute) {
		t.Fatalf("expected auth code expiry to follow config, got %s", codeRepo.created.ExpiresAt)
	}
}

func TestAuthorizeReturnsLoginRequiredWhenSessionMissing(t *testing.T) {
	service := newTestService(t, time.Now().UTC(), &fakeClientRepo{
		client: oidcdomain.Client{
			ID:                      uuid.New(),
			TenantID:                uuid.New(),
			ClientID:                "demo-public-client",
			RedirectURIs:            []string{"https://client.example.test/callback"},
			GrantTypes:              []string{oidcdomain.GrantTypeAuthorizationCode},
			ResponseTypes:           []string{oidcdomain.ResponseTypeCode},
			Scopes:                  []string{"openid"},
			TokenEndpointAuthMethod: oidcdomain.TokenEndpointAuthMethodNone,
			RequirePKCE:             true,
			AccessTokenTTLSeconds:   600,
			RefreshTokenTTLSeconds:  3600,
		},
	}, &fakeAuthorizationCodeRepo{}, &fakeRefreshTokenRepo{}, &fakeUserRepo{}, &fakeSessionAuthenticator{}, &fakeTokenValueManager{}, &fakeTokenSigner{})

	_, err := service.Authorize(context.Background(), oidcdomain.AuthorizationRequest{
		ResponseType:        oidcdomain.ResponseTypeCode,
		ClientID:            "demo-public-client",
		RedirectURI:         "https://client.example.test/callback",
		Scope:               "openid",
		State:               "state-2",
		CodeChallenge:       "PKCE-CHALLENGE",
		CodeChallengeMethod: oidcdomain.CodeChallengeMethodS256,
	}, "")
	if err == nil {
		t.Fatal("expected login_required error")
	}

	protocolErr := assertProtocolError(t, err, oidcErrorLoginRequired)
	if !protocolErr.ShouldRedirect() {
		t.Fatal("expected login_required to use redirect")
	}
}

func TestExchangeCodeIssuesTokensAndConsumesCode(t *testing.T) {
	fixedNow := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	clientID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	userID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	sessionID := uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")
	codeID := uuid.MustParse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
	verifier := "verifier-value-1234567890"

	codeRepo := &fakeAuthorizationCodeRepo{
		codeToReturn: oidcdomain.AuthorizationCode{
			ID:                  codeID,
			OIDCClientID:        clientID,
			TenantID:            tenantID,
			UserID:              userID,
			SessionID:           sessionID,
			CodeHash:            "hashed-auth-code",
			RedirectURI:         "https://client.example.test/callback",
			Scopes:              []string{"openid", "profile", "email"},
			CodeChallenge:       pkceS256(t, verifier),
			CodeChallengeMethod: oidcdomain.CodeChallengeMethodS256,
			ExpiresAt:           fixedNow.Add(5 * time.Minute),
			CreatedAt:           fixedNow,
		},
	}
	refreshRepo := &fakeRefreshTokenRepo{}
	tokenSigner := &fakeTokenSigner{
		tokens: []string{"access.jwt", "id.jwt"},
	}
	service := newTestService(t, fixedNow, &fakeClientRepo{
		client: oidcdomain.Client{
			ID:                      clientID,
			TenantID:                tenantID,
			ClientID:                "demo-public-client",
			GrantTypes:              []string{oidcdomain.GrantTypeAuthorizationCode, oidcdomain.GrantTypeRefreshToken},
			ResponseTypes:           []string{oidcdomain.ResponseTypeCode},
			Scopes:                  []string{"openid", "profile", "email"},
			TokenEndpointAuthMethod: oidcdomain.TokenEndpointAuthMethodNone,
			RequirePKCE:             true,
			AccessTokenTTLSeconds:   600,
			RefreshTokenTTLSeconds:  3600,
		},
	}, codeRepo, refreshRepo, &fakeUserRepo{
		user: userdomain.User{
			ID:          userID,
			TenantID:    tenantID,
			Username:    "alice",
			Email:       "alice@example.com",
			DisplayName: "Alice",
			Status:      "active",
		},
	}, &fakeSessionAuthenticator{}, &fakeTokenValueManager{
		hashed: map[string]string{
			"raw-auth-code": "hashed-auth-code",
			"raw-refresh":   "hashed-refresh",
		},
		generated: []string{"raw-refresh"},
	}, tokenSigner)

	response, err := service.ExchangeCode(context.Background(), oidcdomain.TokenRequest{
		GrantType:        oidcdomain.GrantTypeAuthorizationCode,
		Code:             "raw-auth-code",
		RedirectURI:      "https://client.example.test/callback",
		ClientID:         "demo-public-client",
		ClientAuthMethod: oidcdomain.TokenEndpointAuthMethodNone,
		CodeVerifier:     verifier,
	})
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}

	if response.AccessToken != "access.jwt" || response.IDToken != "id.jwt" || response.RefreshToken != "raw-refresh" {
		t.Fatalf("unexpected token response: %#v", response)
	}

	if !codeRepo.consumeCalled || codeRepo.consumedID != codeID {
		t.Fatalf("expected authorization code to be consumed, got %#v", codeRepo)
	}

	if refreshRepo.created.TokenHash != "hashed-refresh" {
		t.Fatalf("expected hashed refresh token to be persisted, got %#v", refreshRepo.created)
	}

	if len(tokenSigner.claimSets) != 2 {
		t.Fatalf("expected access and id token to be signed, got %d", len(tokenSigner.claimSets))
	}
}

func TestExchangeCodeRejectsWrongPKCEVerifier(t *testing.T) {
	fixedNow := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	clientID := uuid.New()
	codeRepo := &fakeAuthorizationCodeRepo{
		codeToReturn: oidcdomain.AuthorizationCode{
			ID:                  uuid.New(),
			OIDCClientID:        clientID,
			TenantID:            uuid.New(),
			UserID:              uuid.New(),
			SessionID:           uuid.New(),
			CodeHash:            "hashed-auth-code",
			RedirectURI:         "https://client.example.test/callback",
			Scopes:              []string{"openid"},
			CodeChallenge:       pkceS256(t, "correct-verifier"),
			CodeChallengeMethod: oidcdomain.CodeChallengeMethodS256,
			ExpiresAt:           fixedNow.Add(5 * time.Minute),
		},
	}
	service := newTestService(t, fixedNow, &fakeClientRepo{
		client: oidcdomain.Client{
			ID:                      clientID,
			TenantID:                codeRepo.codeToReturn.TenantID,
			ClientID:                "demo-public-client",
			GrantTypes:              []string{oidcdomain.GrantTypeAuthorizationCode},
			TokenEndpointAuthMethod: oidcdomain.TokenEndpointAuthMethodNone,
			RequirePKCE:             true,
			AccessTokenTTLSeconds:   600,
			RefreshTokenTTLSeconds:  3600,
		},
	}, codeRepo, &fakeRefreshTokenRepo{}, &fakeUserRepo{}, &fakeSessionAuthenticator{}, &fakeTokenValueManager{
		hashed: map[string]string{"raw-auth-code": "hashed-auth-code"},
	}, &fakeTokenSigner{})

	_, err := service.ExchangeCode(context.Background(), oidcdomain.TokenRequest{
		GrantType:        oidcdomain.GrantTypeAuthorizationCode,
		Code:             "raw-auth-code",
		RedirectURI:      "https://client.example.test/callback",
		ClientID:         "demo-public-client",
		ClientAuthMethod: oidcdomain.TokenEndpointAuthMethodNone,
		CodeVerifier:     "wrong-verifier",
	})
	if err == nil {
		t.Fatal("expected invalid_grant error")
	}

	assertProtocolError(t, err, oauthErrorInvalidGrant)
}

func TestExchangeCodeRejectsReplayedCode(t *testing.T) {
	fixedNow := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	consumedAt := fixedNow.Add(-time.Minute)
	clientID := uuid.New()
	service := newTestService(t, fixedNow, &fakeClientRepo{
		client: oidcdomain.Client{
			ID:                      clientID,
			TenantID:                uuid.New(),
			ClientID:                "demo-public-client",
			GrantTypes:              []string{oidcdomain.GrantTypeAuthorizationCode},
			TokenEndpointAuthMethod: oidcdomain.TokenEndpointAuthMethodNone,
			RequirePKCE:             true,
			AccessTokenTTLSeconds:   600,
			RefreshTokenTTLSeconds:  3600,
		},
	}, &fakeAuthorizationCodeRepo{
		codeToReturn: oidcdomain.AuthorizationCode{
			ID:           uuid.New(),
			OIDCClientID: clientID,
			TenantID:     uuid.New(),
			UserID:       uuid.New(),
			SessionID:    uuid.New(),
			CodeHash:     "hashed-auth-code",
			RedirectURI:  "https://client.example.test/callback",
			Scopes:       []string{"openid"},
			ExpiresAt:    fixedNow.Add(5 * time.Minute),
			ConsumedAt:   &consumedAt,
		},
	}, &fakeRefreshTokenRepo{}, &fakeUserRepo{}, &fakeSessionAuthenticator{}, &fakeTokenValueManager{
		hashed: map[string]string{"raw-auth-code": "hashed-auth-code"},
	}, &fakeTokenSigner{})

	_, err := service.ExchangeCode(context.Background(), oidcdomain.TokenRequest{
		GrantType:        oidcdomain.GrantTypeAuthorizationCode,
		Code:             "raw-auth-code",
		RedirectURI:      "https://client.example.test/callback",
		ClientID:         "demo-public-client",
		ClientAuthMethod: oidcdomain.TokenEndpointAuthMethodNone,
		CodeVerifier:     "unused",
	})
	if err == nil {
		t.Fatal("expected invalid_grant error")
	}

	assertProtocolError(t, err, oauthErrorInvalidGrant)
}

func newTestService(
	t *testing.T,
	now time.Time,
	clients oidcrepo.ClientRepository,
	authCodes oidcrepo.AuthorizationCodeRepository,
	refreshTokens oidcrepo.RefreshTokenRepository,
	users UserRepository,
	sessions SessionAuthenticator,
	tokenValues TokenValueManager,
	tokenSigner TokenSigner,
) *Service {
	t.Helper()

	service := NewService(
		config.OIDCConfig{Issuer: "https://iam.example.test", AuthorizationCodeTTLSeconds: 300},
		nil,
		clients,
		authCodes,
		refreshTokens,
		users,
		sessions,
		fakeTxManager{},
		"oidc-credential-secret",
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
	)
	service.now = func() time.Time { return now }
	service.tokenValues = tokenValues
	service.tokenSigner = tokenSigner
	return service
}

type fakeClientRepo struct {
	client oidcdomain.Client
	err    error
}

func (f *fakeClientRepo) GetByClientID(ctx context.Context, clientID string) (oidcdomain.Client, error) {
	if f.err != nil {
		return oidcdomain.Client{}, f.err
	}
	if f.client.ClientID != clientID {
		return oidcdomain.Client{}, store.ErrNotFound
	}
	return f.client, nil
}

type fakeAuthorizationCodeRepo struct {
	created      oidcdomain.AuthorizationCode
	codeToReturn oidcdomain.AuthorizationCode
	getErr       error
	consumeErr   error
	consumeCalled bool
	consumedID   uuid.UUID
}

func (f *fakeAuthorizationCodeRepo) CreateAuthorizationCode(ctx context.Context, code oidcdomain.AuthorizationCode) (oidcdomain.AuthorizationCode, error) {
	f.created = code
	if code.ID == uuid.Nil {
		code.ID = uuid.New()
	}
	return code, nil
}

func (f *fakeAuthorizationCodeRepo) GetByCodeHashForUpdate(ctx context.Context, codeHash string) (oidcdomain.AuthorizationCode, error) {
	if f.getErr != nil {
		return oidcdomain.AuthorizationCode{}, f.getErr
	}
	if f.codeToReturn.CodeHash != codeHash {
		return oidcdomain.AuthorizationCode{}, store.ErrNotFound
	}
	return f.codeToReturn, nil
}

func (f *fakeAuthorizationCodeRepo) Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error {
	f.consumeCalled = true
	f.consumedID = id
	return f.consumeErr
}

type fakeRefreshTokenRepo struct {
	created oidcdomain.RefreshToken
	err     error
}

func (f *fakeRefreshTokenRepo) CreateRefreshToken(ctx context.Context, token oidcdomain.RefreshToken) (oidcdomain.RefreshToken, error) {
	if f.err != nil {
		return oidcdomain.RefreshToken{}, f.err
	}
	f.created = token
	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	return token, nil
}

type fakeUserRepo struct {
	user userdomain.User
	err  error
}

func (f *fakeUserRepo) GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error) {
	if f.err != nil {
		return userdomain.User{}, f.err
	}
	if f.user.ID != id {
		return userdomain.User{}, store.ErrNotFound
	}
	return f.user, nil
}

type fakeSessionAuthenticator struct {
	session authdomain.Session
	err     error
}

func (f *fakeSessionAuthenticator) Authenticate(ctx context.Context, sid string) (authdomain.Session, error) {
	if f.err != nil {
		return authdomain.Session{}, f.err
	}
	if sid == "" {
		return authdomain.Session{}, store.ErrNotFound
	}
	return f.session, nil
}

type fakeTxManager struct{}

func (fakeTxManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type fakeTokenValueManager struct {
	generated []string
	hashIndex int
	genIndex  int
	hashed    map[string]string
}

func (f *fakeTokenValueManager) Generate() (string, error) {
	if f.genIndex >= len(f.generated) {
		return "", nil
	}
	value := f.generated[f.genIndex]
	f.genIndex++
	return value, nil
}

func (f *fakeTokenValueManager) Hash(secret, rawValue string) (string, error) {
	if hashed, ok := f.hashed[rawValue]; ok {
		return hashed, nil
	}
	return "", fmt.Errorf("unexpected token hash request for %q", rawValue)
}

type fakeTokenSigner struct {
	tokens    []string
	index     int
	claimSets []map[string]any
}

func (f *fakeTokenSigner) Sign(claims map[string]any) (string, error) {
	f.claimSets = append(f.claimSets, claims)
	if f.index >= len(f.tokens) {
		return "", fmt.Errorf("unexpected sign request")
	}
	token := f.tokens[f.index]
	f.index++
	return token, nil
}

func assertProtocolError(t *testing.T, err error, code string) oidcdomain.ProtocolError {
	t.Helper()

	var protocolErr oidcdomain.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("expected protocol error, got %v", err)
	}
	if protocolErr.Code != code {
		t.Fatalf("expected protocol error code %q, got %#v", code, protocolErr)
	}

	return protocolErr
}

func pkceS256(t *testing.T, verifier string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
