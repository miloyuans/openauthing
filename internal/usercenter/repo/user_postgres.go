package repo

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type PostgresUserRepository struct {
	store *postgresstore.Store
}

func NewPostgresUserRepository(store *postgresstore.Store) *PostgresUserRepository {
	return &PostgresUserRepository{store: store}
}

func (r *PostgresUserRepository) List(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error) {
	query := `
SELECT id, tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source, last_login_at, created_at, updated_at
FROM users
WHERE 1 = 1`

	args := make([]any, 0, 6)
	argPos := 1

	if filter.TenantID != nil {
		query += fmt.Sprintf(" AND tenant_id = $%d", argPos)
		args = append(args, *filter.TenantID)
		argPos++
	}
	if filter.Username != "" {
		query += fmt.Sprintf(" AND username ILIKE $%d", argPos)
		args = append(args, "%"+filter.Username+"%")
		argPos++
	}
	if filter.Email != "" {
		query += fmt.Sprintf(" AND email ILIKE $%d", argPos)
		args = append(args, "%"+filter.Email+"%")
		argPos++
	}
	if filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, filter.Status)
		argPos++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argPos, argPos+1)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.store.Executor(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, store.NormalizeError(err)
	}
	defer rows.Close()

	users := make([]domain.User, 0)
	for rows.Next() {
		var user domain.User
		if err := scanUser(rows, &user); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (r *PostgresUserRepository) Create(ctx context.Context, user domain.User) (domain.User, error) {
	query := `
INSERT INTO users (
    tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING id, tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source, last_login_at, created_at, updated_at`

	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		query,
		user.TenantID,
		user.Username,
		nullableString(user.Email),
		nullableString(user.Phone),
		user.DisplayName,
		user.PasswordHash,
		user.PasswordAlgo,
		user.Status,
		user.Source,
	)

	var created domain.User
	if err := scanUser(row, &created); err != nil {
		return domain.User{}, store.NormalizeError(err)
	}

	return created, nil
}

func (r *PostgresUserRepository) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	query := `
SELECT id, tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source, last_login_at, created_at, updated_at
FROM users
WHERE id = $1`

	return r.querySingle(ctx, query, id)
}

func (r *PostgresUserRepository) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	query := `
SELECT id, tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source, last_login_at, created_at, updated_at
FROM users
WHERE username = $1
ORDER BY created_at DESC
LIMIT 2`

	return r.querySingleLimited(ctx, query, username)
}

func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	query := `
SELECT id, tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source, last_login_at, created_at, updated_at
FROM users
WHERE LOWER(email) = LOWER($1)
ORDER BY created_at DESC
LIMIT 2`

	return r.querySingleLimited(ctx, query, email)
}

func (r *PostgresUserRepository) UpdateLastLoginAt(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error {
	result, err := r.store.Executor(ctx).ExecContext(
		ctx,
		`UPDATE users SET last_login_at = $2, updated_at = NOW() WHERE id = $1`,
		id,
		lastLoginAt,
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

func (r *PostgresUserRepository) Update(ctx context.Context, user domain.User) (domain.User, error) {
	query := `
UPDATE users
SET username = $2,
    email = $3,
    phone = $4,
    display_name = $5,
    password_hash = $6,
    password_algo = $7,
    status = $8,
    source = $9,
    updated_at = NOW()
WHERE id = $1
RETURNING id, tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source, last_login_at, created_at, updated_at`

	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		query,
		user.ID,
		user.Username,
		nullableString(user.Email),
		nullableString(user.Phone),
		user.DisplayName,
		user.PasswordHash,
		user.PasswordAlgo,
		user.Status,
		user.Source,
	)

	var updated domain.User
	if err := scanUser(row, &updated); err != nil {
		return domain.User{}, store.NormalizeError(err)
	}

	return updated, nil
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	return value
}

func (r *PostgresUserRepository) querySingle(ctx context.Context, query string, args ...any) (domain.User, error) {
	row := r.store.Executor(ctx).QueryRowContext(ctx, query, args...)

	var user domain.User
	if err := scanUser(row, &user); err != nil {
		return domain.User{}, store.NormalizeError(err)
	}

	return user, nil
}

func (r *PostgresUserRepository) querySingleLimited(ctx context.Context, query string, args ...any) (domain.User, error) {
	rows, err := r.store.Executor(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return domain.User{}, store.NormalizeError(err)
	}
	defer rows.Close()

	users := make([]domain.User, 0, 2)
	for rows.Next() {
		var user domain.User
		if err := scanUser(rows, &user); err != nil {
			return domain.User{}, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return domain.User{}, err
	}

	switch len(users) {
	case 0:
		return domain.User{}, store.ErrNotFound
	case 1:
		return users[0], nil
	default:
		return domain.User{}, store.ErrAmbiguous
	}
}

type userScanner interface {
	Scan(dest ...any) error
}

func scanUser(scanner userScanner, user *domain.User) error {
	var email sql.NullString
	var phone sql.NullString
	var lastLoginAt sql.NullTime

	if err := scanner.Scan(
		&user.ID,
		&user.TenantID,
		&user.Username,
		&email,
		&phone,
		&user.DisplayName,
		&user.PasswordHash,
		&user.PasswordAlgo,
		&user.Status,
		&user.Source,
		&lastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return err
	}

	user.Email = ""
	if email.Valid {
		user.Email = email.String
	}

	user.Phone = ""
	if phone.Valid {
		user.Phone = phone.String
	}

	user.LastLoginAt = nil
	if lastLoginAt.Valid {
		parsed := lastLoginAt.Time
		user.LastLoginAt = &parsed
	}

	return nil
}
