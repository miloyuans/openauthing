package repo

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/saml/domain"
	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

type PostgresLoginSessionRepository struct {
	store *postgresstore.Store
}

func NewPostgresLoginSessionRepository(store *postgresstore.Store) *PostgresLoginSessionRepository {
	return &PostgresLoginSessionRepository{store: store}
}

func (r *PostgresLoginSessionRepository) Upsert(ctx context.Context, session domain.LoginSession) (domain.LoginSession, error) {
	row := r.store.Executor(ctx).QueryRowContext(ctx, `
INSERT INTO saml_login_sessions (
    app_id, user_id, session_id, name_id, session_index, status, issued_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (app_id, session_id) DO UPDATE
SET user_id = EXCLUDED.user_id,
    name_id = EXCLUDED.name_id,
    session_index = EXCLUDED.session_index,
    status = EXCLUDED.status,
    issued_at = EXCLUDED.issued_at,
    expires_at = EXCLUDED.expires_at,
    logout_at = NULL,
    updated_at = NOW()
RETURNING id, app_id, user_id, session_id, name_id, session_index, status, issued_at, expires_at, created_at, updated_at, logout_at`,
		session.AppID,
		session.UserID,
		session.SessionID,
		session.NameID,
		session.SessionIndex,
		session.Status,
		session.IssuedAt,
		session.ExpiresAt,
	)

	return scanLoginSession(row)
}

func (r *PostgresLoginSessionRepository) GetActiveByAppAndSessionIndex(ctx context.Context, appID uuid.UUID, sessionIndex string) (domain.LoginSession, error) {
	row := r.store.Executor(ctx).QueryRowContext(ctx, `
SELECT id, app_id, user_id, session_id, name_id, session_index, status, issued_at, expires_at, created_at, updated_at, logout_at
FROM saml_login_sessions
WHERE app_id = $1 AND session_index = $2 AND status = $3
ORDER BY issued_at DESC
LIMIT 1`,
		appID,
		sessionIndex,
		domain.LoginSessionStatusActive,
	)

	return scanLoginSession(row)
}

func (r *PostgresLoginSessionRepository) GetActiveByAppAndNameID(ctx context.Context, appID uuid.UUID, nameID string) (domain.LoginSession, error) {
	row := r.store.Executor(ctx).QueryRowContext(ctx, `
SELECT id, app_id, user_id, session_id, name_id, session_index, status, issued_at, expires_at, created_at, updated_at, logout_at
FROM saml_login_sessions
WHERE app_id = $1 AND name_id = $2 AND status = $3
ORDER BY issued_at DESC
LIMIT 1`,
		appID,
		nameID,
		domain.LoginSessionStatusActive,
	)

	return scanLoginSession(row)
}

func (r *PostgresLoginSessionRepository) InvalidateBySessionID(ctx context.Context, sessionID uuid.UUID, logoutAt time.Time) error {
	result, err := r.store.Executor(ctx).ExecContext(ctx, `
UPDATE saml_login_sessions
SET status = $2,
    logout_at = $3,
    updated_at = NOW()
WHERE session_id = $1 AND status = $4`,
		sessionID,
		domain.LoginSessionStatusLoggedOut,
		logoutAt,
		domain.LoginSessionStatusActive,
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

type loginSessionScanner interface {
	Scan(dest ...any) error
}

func scanLoginSession(row loginSessionScanner) (domain.LoginSession, error) {
	var (
		session  domain.LoginSession
		logoutAt sql.NullTime
	)
	if err := row.Scan(
		&session.ID,
		&session.AppID,
		&session.UserID,
		&session.SessionID,
		&session.NameID,
		&session.SessionIndex,
		&session.Status,
		&session.IssuedAt,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
		&logoutAt,
	); err != nil {
		return domain.LoginSession{}, store.NormalizeError(err)
	}

	session.LogoutAt = nil
	if logoutAt.Valid {
		parsed := logoutAt.Time
		session.LogoutAt = &parsed
	}

	return session, nil
}
