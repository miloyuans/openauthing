package repo

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	oidcdomain "github.com/miloyuans/openauthing/internal/oidc/domain"
	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

type PostgresRepository struct {
	store *postgresstore.Store
}

func NewPostgresRepository(store *postgresstore.Store) *PostgresRepository {
	return &PostgresRepository{store: store}
}

func (r *PostgresRepository) GetByClientID(ctx context.Context, clientID string) (oidcdomain.Client, error) {
	query := `
SELECT id, tenant_id, app_id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
       grant_types, response_types, scopes, token_endpoint_auth_method, require_pkce,
       access_token_ttl, refresh_token_ttl, id_token_signed_response_alg, created_at, updated_at
FROM oidc_clients
WHERE client_id = $1`

	row := r.store.Executor(ctx).QueryRowContext(ctx, query, clientID)

	var client oidcdomain.Client
	if err := scanClient(row, &client); err != nil {
		return oidcdomain.Client{}, store.NormalizeError(err)
	}

	return client, nil
}

func (r *PostgresRepository) CreateAuthorizationCode(ctx context.Context, code oidcdomain.AuthorizationCode) (oidcdomain.AuthorizationCode, error) {
	query := `
INSERT INTO oidc_authorization_codes (
    oidc_client_id, tenant_id, user_id, session_id, code_hash, redirect_uri, scopes,
    nonce, code_challenge, code_challenge_method, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
RETURNING id, oidc_client_id, tenant_id, user_id, session_id, code_hash, redirect_uri, scopes,
          nonce, code_challenge, code_challenge_method, expires_at, created_at, consumed_at`

	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		query,
		code.OIDCClientID,
		code.TenantID,
		code.UserID,
		code.SessionID,
		code.CodeHash,
		code.RedirectURI,
		code.Scopes,
		code.Nonce,
		code.CodeChallenge,
		code.CodeChallengeMethod,
		code.ExpiresAt,
	)

	var created oidcdomain.AuthorizationCode
	if err := scanAuthorizationCode(row, &created); err != nil {
		return oidcdomain.AuthorizationCode{}, store.NormalizeError(err)
	}

	return created, nil
}

func (r *PostgresRepository) GetByCodeHashForUpdate(ctx context.Context, codeHash string) (oidcdomain.AuthorizationCode, error) {
	query := `
SELECT id, oidc_client_id, tenant_id, user_id, session_id, code_hash, redirect_uri, scopes,
       nonce, code_challenge, code_challenge_method, expires_at, created_at, consumed_at
FROM oidc_authorization_codes
WHERE code_hash = $1
FOR UPDATE`

	row := r.store.Executor(ctx).QueryRowContext(ctx, query, codeHash)

	var code oidcdomain.AuthorizationCode
	if err := scanAuthorizationCode(row, &code); err != nil {
		return oidcdomain.AuthorizationCode{}, store.NormalizeError(err)
	}

	return code, nil
}

func (r *PostgresRepository) Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error {
	result, err := r.store.Executor(ctx).ExecContext(
		ctx,
		`UPDATE oidc_authorization_codes SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL`,
		id,
		consumedAt,
	)
	if err != nil {
		return store.NormalizeError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

func (r *PostgresRepository) CreateRefreshToken(ctx context.Context, token oidcdomain.RefreshToken) (oidcdomain.RefreshToken, error) {
	query := `
INSERT INTO oidc_refresh_tokens (
    oidc_client_id, tenant_id, user_id, session_id, token_hash, scopes, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
RETURNING id, oidc_client_id, tenant_id, user_id, session_id, token_hash, scopes, expires_at, created_at, revoked_at`

	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		query,
		token.OIDCClientID,
		token.TenantID,
		token.UserID,
		token.SessionID,
		token.TokenHash,
		token.Scopes,
		token.ExpiresAt,
	)

	var created oidcdomain.RefreshToken
	if err := scanRefreshToken(row, &created); err != nil {
		return oidcdomain.RefreshToken{}, store.NormalizeError(err)
	}

	return created, nil
}

type clientScanner interface {
	Scan(dest ...any) error
}

func scanClient(scanner clientScanner, client *oidcdomain.Client) error {
	var clientSecretHash sql.NullString
	if err := scanner.Scan(
		&client.ID,
		&client.TenantID,
		&client.AppID,
		&client.ClientID,
		&clientSecretHash,
		&client.RedirectURIs,
		&client.PostLogoutRedirectURIs,
		&client.GrantTypes,
		&client.ResponseTypes,
		&client.Scopes,
		&client.TokenEndpointAuthMethod,
		&client.RequirePKCE,
		&client.AccessTokenTTLSeconds,
		&client.RefreshTokenTTLSeconds,
		&client.IDTokenSignedResponseAlg,
		&client.CreatedAt,
		&client.UpdatedAt,
	); err != nil {
		return err
	}

	client.ClientSecretHash = ""
	if clientSecretHash.Valid {
		client.ClientSecretHash = clientSecretHash.String
	}

	return nil
}

type authorizationCodeScanner interface {
	Scan(dest ...any) error
}

func scanAuthorizationCode(scanner authorizationCodeScanner, code *oidcdomain.AuthorizationCode) error {
	var consumedAt sql.NullTime
	if err := scanner.Scan(
		&code.ID,
		&code.OIDCClientID,
		&code.TenantID,
		&code.UserID,
		&code.SessionID,
		&code.CodeHash,
		&code.RedirectURI,
		&code.Scopes,
		&code.Nonce,
		&code.CodeChallenge,
		&code.CodeChallengeMethod,
		&code.ExpiresAt,
		&code.CreatedAt,
		&consumedAt,
	); err != nil {
		return err
	}

	code.ConsumedAt = nil
	if consumedAt.Valid {
		parsed := consumedAt.Time
		code.ConsumedAt = &parsed
	}

	return nil
}

type refreshTokenScanner interface {
	Scan(dest ...any) error
}

func scanRefreshToken(scanner refreshTokenScanner, token *oidcdomain.RefreshToken) error {
	var revokedAt sql.NullTime
	if err := scanner.Scan(
		&token.ID,
		&token.OIDCClientID,
		&token.TenantID,
		&token.UserID,
		&token.SessionID,
		&token.TokenHash,
		&token.Scopes,
		&token.ExpiresAt,
		&token.CreatedAt,
		&revokedAt,
	); err != nil {
		return err
	}

	token.RevokedAt = nil
	if revokedAt.Valid {
		parsed := revokedAt.Time
		token.RevokedAt = &parsed
	}

	return nil
}
