package repo

import (
	"context"
	"fmt"

	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type PostgresRoleRepository struct {
	store *postgresstore.Store
}

func NewPostgresRoleRepository(store *postgresstore.Store) *PostgresRoleRepository {
	return &PostgresRoleRepository{store: store}
}

func (r *PostgresRoleRepository) List(ctx context.Context, filter domain.RoleListFilter) ([]domain.Role, error) {
	query := `
SELECT id, tenant_id, name, code, description, created_at, updated_at
FROM roles
WHERE 1 = 1`
	args := make([]any, 0, 5)
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

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argPos, argPos+1)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.store.Executor(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, store.NormalizeError(err)
	}
	defer rows.Close()

	roles := make([]domain.Role, 0)
	for rows.Next() {
		var role domain.Role
		if err := rows.Scan(
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Code,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

func (r *PostgresRoleRepository) Create(ctx context.Context, role domain.Role) (domain.Role, error) {
	query := `
INSERT INTO roles (tenant_id, name, code, description)
VALUES ($1, $2, $3, $4)
RETURNING id, tenant_id, name, code, description, created_at, updated_at`

	row := r.store.Executor(ctx).QueryRowContext(ctx, query, role.TenantID, role.Name, role.Code, role.Description)

	var created domain.Role
	if err := row.Scan(
		&created.ID,
		&created.TenantID,
		&created.Name,
		&created.Code,
		&created.Description,
		&created.CreatedAt,
		&created.UpdatedAt,
	); err != nil {
		return domain.Role{}, store.NormalizeError(err)
	}

	return created, nil
}
