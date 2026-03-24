package repo

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/apps/domain"
	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

type PostgresApplicationRepository struct {
	store *postgresstore.Store
}

func NewPostgresApplicationRepository(store *postgresstore.Store) *PostgresApplicationRepository {
	return &PostgresApplicationRepository{store: store}
}

func (r *PostgresApplicationRepository) List(ctx context.Context, filter domain.ApplicationListFilter) ([]domain.Application, error) {
	query := `
SELECT id, tenant_id, name, code, type, status, homepage_url, icon_url, description, created_at, updated_at
FROM applications
WHERE 1 = 1`
	args := make([]any, 0, 6)
	argPos := 1

	if filter.TenantID != nil {
		query += fmt.Sprintf(" AND tenant_id = $%d", argPos)
		args = append(args, *filter.TenantID)
		argPos++
	}
	if filter.Name != "" {
		query += fmt.Sprintf(" AND name ILIKE $%d", argPos)
		args = append(args, "%"+filter.Name+"%")
		argPos++
	}
	if filter.Code != "" {
		query += fmt.Sprintf(" AND code ILIKE $%d", argPos)
		args = append(args, "%"+filter.Code+"%")
		argPos++
	}
	if filter.Type != "" {
		query += fmt.Sprintf(" AND type = $%d", argPos)
		args = append(args, filter.Type)
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

	apps := make([]domain.Application, 0)
	for rows.Next() {
		var app domain.Application
		if err := rows.Scan(
			&app.ID,
			&app.TenantID,
			&app.Name,
			&app.Code,
			&app.Type,
			&app.Status,
			&app.HomepageURL,
			&app.IconURL,
			&app.Description,
			&app.CreatedAt,
			&app.UpdatedAt,
		); err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return apps, nil
}

func (r *PostgresApplicationRepository) Create(ctx context.Context, app domain.Application) (domain.Application, error) {
	query := `
INSERT INTO applications (tenant_id, name, code, type, status, homepage_url, icon_url, description)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, tenant_id, name, code, type, status, homepage_url, icon_url, description, created_at, updated_at`

	row := r.store.Executor(ctx).QueryRowContext(
		ctx,
		query,
		app.TenantID,
		app.Name,
		app.Code,
		app.Type,
		app.Status,
		app.HomepageURL,
		app.IconURL,
		app.Description,
	)

	var created domain.Application
	if err := row.Scan(
		&created.ID,
		&created.TenantID,
		&created.Name,
		&created.Code,
		&created.Type,
		&created.Status,
		&created.HomepageURL,
		&created.IconURL,
		&created.Description,
		&created.CreatedAt,
		&created.UpdatedAt,
	); err != nil {
		return domain.Application{}, store.NormalizeError(err)
	}

	return created, nil
}

func (r *PostgresApplicationRepository) GetByID(ctx context.Context, id uuid.UUID) (domain.Application, error) {
	row := r.store.Executor(ctx).QueryRowContext(ctx, `
SELECT id, tenant_id, name, code, type, status, homepage_url, icon_url, description, created_at, updated_at
FROM applications
WHERE id = $1`, id)

	var app domain.Application
	if err := row.Scan(
		&app.ID,
		&app.TenantID,
		&app.Name,
		&app.Code,
		&app.Type,
		&app.Status,
		&app.HomepageURL,
		&app.IconURL,
		&app.Description,
		&app.CreatedAt,
		&app.UpdatedAt,
	); err != nil {
		return domain.Application{}, store.NormalizeError(err)
	}

	return app, nil
}
