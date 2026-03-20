package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/validate"
	"github.com/miloyuans/openauthing/internal/store"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
	"github.com/miloyuans/openauthing/internal/usercenter/repo"
)

type RoleService struct {
	repo repo.RoleRepository
}

func NewRoleService(repo repo.RoleRepository) *RoleService {
	return &RoleService{repo: repo}
}

func (s *RoleService) List(ctx context.Context, filter domain.RoleListFilter) ([]domain.Role, error) {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	return s.repo.List(ctx, filter)
}

func (s *RoleService) Create(ctx context.Context, input domain.CreateRoleInput) (domain.Role, error) {
	role := domain.Role{
		TenantID:    input.TenantID,
		Name:        strings.TrimSpace(input.Name),
		Code:        strings.TrimSpace(input.Code),
		Description: strings.TrimSpace(input.Description),
	}

	fieldErrors := map[string]string{}
	if role.TenantID == uuid.Nil {
		fieldErrors["tenant_id"] = "is required"
	}
	validate.Required("name", role.Name, fieldErrors)
	validate.Code("code", role.Code, fieldErrors)

	if len(fieldErrors) > 0 {
		return domain.Role{}, apierror.Validation(map[string]any{"fields": fieldErrors})
	}

	created, err := s.repo.Create(ctx, role)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return domain.Role{}, apierror.Conflict("role already exists in tenant scope", nil)
		default:
			return domain.Role{}, err
		}
	}

	return created, nil
}
