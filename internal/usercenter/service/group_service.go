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

type GroupService struct {
	repo repo.GroupRepository
}

func NewGroupService(repo repo.GroupRepository) *GroupService {
	return &GroupService{repo: repo}
}

func (s *GroupService) List(ctx context.Context, filter domain.GroupListFilter) ([]domain.Group, error) {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	return s.repo.List(ctx, filter)
}

func (s *GroupService) Create(ctx context.Context, input domain.CreateGroupInput) (domain.Group, error) {
	group := domain.Group{
		TenantID:    input.TenantID,
		Name:        strings.TrimSpace(input.Name),
		Code:        strings.TrimSpace(input.Code),
		Description: strings.TrimSpace(input.Description),
	}

	fieldErrors := map[string]string{}
	if group.TenantID == uuid.Nil {
		fieldErrors["tenant_id"] = "is required"
	}
	validate.Required("name", group.Name, fieldErrors)
	validate.Code("code", group.Code, fieldErrors)

	if len(fieldErrors) > 0 {
		return domain.Group{}, apierror.Validation(map[string]any{"fields": fieldErrors})
	}

	created, err := s.repo.Create(ctx, group)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return domain.Group{}, apierror.Conflict("group already exists in tenant scope", nil)
		default:
			return domain.Group{}, err
		}
	}

	return created, nil
}
