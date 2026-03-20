package repo

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

type PostgresSessionRepository struct {
	store *postgresstore.Store
}

func NewPostgresSessionRepository(store *postgresstore.Store) *PostgresSessionRepository {
	return &PostgresSessionRepository{store: store}
}

func (r *PostgresSessionRepository) Create(ctx context.Context, session authdomain.Session) (authdomain.Session, error) {
	query := `
INSERT INTO auth_sessions (
    tenant_id, user_id, sid, login_method, mfa_verified, ip, user_agent, status, expires_at, last_seen_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING id, tenant_id, user_id, sid, login_method, mfa_verified, ip, user_agent, status, expires_at, created_at, last_seen_at, logout_at`

	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		query,
		session.TenantID,
		session.UserID,
		session.SID,
		session.LoginMethod,
		session.MFAVerified,
		session.IP,
		session.UserAgent,
		session.Status,
		session.ExpiresAt,
		session.LastSeenAt,
	)

	var created authdomain.Session
	if err := scanSession(row, &created); err != nil {
		return authdomain.Session{}, store.NormalizeError(err)
	}

	return created, nil
}

func (r *PostgresSessionRepository) GetBySID(ctx context.Context, sid string) (authdomain.Session, error) {
	query := `
SELECT id, tenant_id, user_id, sid, login_method, mfa_verified, ip, user_agent, status, expires_at, created_at, last_seen_at, logout_at
FROM auth_sessions
WHERE sid = $1`

	row := r.store.Executor(ctx).QueryRowContext(ctx, query, sid)

	var session authdomain.Session
	if err := scanSession(row, &session); err != nil {
		return authdomain.Session{}, store.NormalizeError(err)
	}

	return session, nil
}

func (r *PostgresSessionRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]authdomain.Session, error) {
	query := `
SELECT id, tenant_id, user_id, sid, login_method, mfa_verified, ip, user_agent, status, expires_at, created_at, last_seen_at, logout_at
FROM auth_sessions
WHERE user_id = $1
ORDER BY created_at DESC`

	rows, err := r.store.Executor(ctx).QueryContext(ctx, query, userID)
	if err != nil {
		return nil, store.NormalizeError(err)
	}
	defer rows.Close()

	sessions := make([]authdomain.Session, 0)
	for rows.Next() {
		var session authdomain.Session
		if err := scanSession(rows, &session); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

func (r *PostgresSessionRepository) Touch(ctx context.Context, id uuid.UUID, lastSeenAt time.Time) error {
	return r.execStatuslessUpdate(ctx, `UPDATE auth_sessions SET last_seen_at = $2 WHERE id = $1`, id, lastSeenAt)
}

func (r *PostgresSessionRepository) Logout(ctx context.Context, id uuid.UUID, logoutAt time.Time) error {
	return r.execStatusUpdate(ctx, id, authdomain.SessionStatusLoggedOut, logoutAt)
}

func (r *PostgresSessionRepository) RevokeByID(ctx context.Context, id, userID uuid.UUID, logoutAt time.Time) error {
	result, err := r.store.Executor(ctx).ExecContext(
		ctx,
		`UPDATE auth_sessions
SET status = $3, logout_at = $4, last_seen_at = $4
WHERE id = $1 AND user_id = $2 AND status = $5`,
		id,
		userID,
		authdomain.SessionStatusRevoked,
		logoutAt,
		authdomain.SessionStatusActive,
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

func (r *PostgresSessionRepository) execStatusUpdate(ctx context.Context, id uuid.UUID, status string, changedAt time.Time) error {
	result, err := r.store.Executor(ctx).ExecContext(
		ctx,
		`UPDATE auth_sessions
SET status = $2, logout_at = $3, last_seen_at = $3
WHERE id = $1 AND status = $4`,
		id,
		status,
		changedAt,
		authdomain.SessionStatusActive,
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

func (r *PostgresSessionRepository) execStatuslessUpdate(ctx context.Context, query string, id uuid.UUID, changedAt time.Time) error {
	result, err := r.store.Executor(ctx).ExecContext(ctx, query, id, changedAt)
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

type sessionScanner interface {
	Scan(dest ...any) error
}

func scanSession(scanner sessionScanner, session *authdomain.Session) error {
	var logoutAt sql.NullTime
	if err := scanner.Scan(
		&session.ID,
		&session.TenantID,
		&session.UserID,
		&session.SID,
		&session.LoginMethod,
		&session.MFAVerified,
		&session.IP,
		&session.UserAgent,
		&session.Status,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.LastSeenAt,
		&logoutAt,
	); err != nil {
		return err
	}

	session.LogoutAt = nil
	if logoutAt.Valid {
		parsed := logoutAt.Time
		session.LogoutAt = &parsed
	}

	return nil
}
