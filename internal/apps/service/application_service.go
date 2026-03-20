package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/apps/domain"
	"github.com/miloyuans/openauthing/internal/apps/repo"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/validate"
	"github.com/miloyuans/openauthing/internal/store"
)

var (
	allowedApplicationTypes = []string{
		domain.TypeOIDCClient,
		domain.TypeSAMLSP,
		domain.TypeCASService,
		domain.TypeLDAPClient,
		domain.TypeSCIMTarget,
	}
	allowedApplicationStatuses = []string{
		domain.StatusActive,
		domain.StatusDisabled,
		domain.StatusDraft,
	}
)

type ApplicationService struct {
	repo repo.ApplicationRepository
}

func NewApplicationService(repo repo.ApplicationRepository) *ApplicationService {
	return &ApplicationService{repo: repo}
}

func (s *ApplicationService) List(ctx context.Context, filter domain.ApplicationListFilter) ([]domain.Application, error) {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	fieldErrors := map[string]string{}
	if filter.Type != "" {
		validate.OneOf("type", filter.Type, allowedApplicationTypes, fieldErrors)
	}
	if filter.Status != "" {
		validate.OneOf("status", filter.Status, allowedApplicationStatuses, fieldErrors)
	}
	if len(fieldErrors) > 0 {
		return nil, apierror.Validation(map[string]any{"fields": fieldErrors})
	}

	return s.repo.List(ctx, filter)
}

func (s *ApplicationService) Create(ctx context.Context, input domain.CreateApplicationInput) (domain.Application, error) {
	app := domain.Application{
		TenantID:    input.TenantID,
		Name:        strings.TrimSpace(input.Name),
		Code:        strings.TrimSpace(input.Code),
		Type:        strings.TrimSpace(input.Type),
		Status:      strings.TrimSpace(input.Status),
		HomepageURL: strings.TrimSpace(input.HomepageURL),
		IconURL:     strings.TrimSpace(input.IconURL),
		Description: strings.TrimSpace(input.Description),
	}

	if app.Status == "" {
		app.Status = domain.StatusActive
	}

	fieldErrors := map[string]string{}
	if app.TenantID == uuid.Nil {
		fieldErrors["tenant_id"] = "is required"
	}
	validate.Required("name", app.Name, fieldErrors)
	validate.Code("code", app.Code, fieldErrors)
	validate.OneOf("type", app.Type, allowedApplicationTypes, fieldErrors)
	validate.OneOf("status", app.Status, allowedApplicationStatuses, fieldErrors)
	validate.URL("homepage_url", app.HomepageURL, fieldErrors)
	validate.URL("icon_url", app.IconURL, fieldErrors)

	if len(fieldErrors) > 0 {
		return domain.Application{}, apierror.Validation(map[string]any{"fields": fieldErrors})
	}

	created, err := s.repo.Create(ctx, app)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return domain.Application{}, apierror.Conflict("application already exists in tenant scope", nil)
		default:
			return domain.Application{}, err
		}
	}

	return created, nil
}
