package repo

import (
	"context"
	"fmt"

	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type PostgresGroupRepository struct {
	store *postgresstore.Store
}

func NewPostgresGroupRepository(store *postgresstore.Store) *PostgresGroupRepository {
	return &PostgresGroupRepository{store: store}
}

func (r *PostgresGroupRepository) List(ctx context.Context, filter domain.GroupListFilter) ([]domain.Group, error) {
	query := `
SELECT id, tenant_id, name, code, description, created_at, updated_at
FROM groups
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

	groups := make([]domain.Group, 0)
	for rows.Next() {
		var group domain.Group
		if err := rows.Scan(
			&group.ID,
			&group.TenantID,
			&group.Name,
			&group.Code,
			&group.Description,
			&group.CreatedAt,
			&group.UpdatedAt,
		); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return groups, nil
}

func (r *PostgresGroupRepository) Create(ctx context.Context, group domain.Group) (domain.Group, error) {
	query := `
INSERT INTO groups (tenant_id, name, code, description)
VALUES ($1, $2, $3, $4)
RETURNING id, tenant_id, name, code, description, created_at, updated_at`

	row := r.store.Executor(ctx).QueryRowContext(ctx, query, group.TenantID, group.Name, group.Code, group.Description)

	var created domain.Group
	if err := row.Scan(
		&created.ID,
		&created.TenantID,
		&created.Name,
		&created.Code,
		&created.Description,
		&created.CreatedAt,
		&created.UpdatedAt,
	); err != nil {
		return domain.Group{}, store.NormalizeError(err)
	}

	return created, nil
}
