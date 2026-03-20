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

const defaultPasswordAlgo = "argon2id"

var (
	allowedUserStatuses = []string{"active", "disabled", "locked"}
	allowedUserSources  = []string{"local", "scim", "ldap-import"}
)

type UserService struct {
	repo repo.UserRepository
}

func NewUserService(repo repo.UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) List(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error) {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.Status != "" {
		fieldErrors := map[string]string{}
		validate.OneOf("status", filter.Status, allowedUserStatuses, fieldErrors)
		if len(fieldErrors) > 0 {
			return nil, apierror.Validation(map[string]any{"fields": fieldErrors})
		}
	}

	return s.repo.List(ctx, filter)
}

func (s *UserService) Create(ctx context.Context, input domain.CreateUserInput) (domain.User, error) {
	model := domain.User{
		TenantID:     input.TenantID,
		Username:     strings.TrimSpace(input.Username),
		Email:        strings.TrimSpace(input.Email),
		Phone:        strings.TrimSpace(input.Phone),
		DisplayName:  strings.TrimSpace(input.DisplayName),
		PasswordHash: input.PasswordHash,
		PasswordAlgo: strings.TrimSpace(input.PasswordAlgo),
		Status:       strings.TrimSpace(input.Status),
		Source:       strings.TrimSpace(input.Source),
	}

	applyUserDefaults(&model)
	if err := validateCreateUser(model); err != nil {
		return domain.User{}, err
	}

	created, err := s.repo.Create(ctx, model)
	if err != nil {
		return domain.User{}, mapUserRepoError(err)
	}

	return created, nil
}

func (s *UserService) GetByID(ctx context.Context, id string) (domain.User, error) {
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return domain.User{}, apierror.Validation(map[string]any{
			"fields": map[string]string{"id": "must be a valid UUID"},
		})
	}

	user, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return domain.User{}, mapUserRepoError(err)
	}

	return user, nil
}

func (s *UserService) Update(ctx context.Context, id string, input domain.UpdateUserInput) (domain.User, error) {
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return domain.User{}, apierror.Validation(map[string]any{
			"fields": map[string]string{"id": "must be a valid UUID"},
		})
	}

	current, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return domain.User{}, mapUserRepoError(err)
	}

	applyUserPatch(&current, input)
	applyUserDefaults(&current)

	if err := validateUpdateUser(current); err != nil {
		return domain.User{}, err
	}

	updated, err := s.repo.Update(ctx, current)
	if err != nil {
		return domain.User{}, mapUserRepoError(err)
	}

	return updated, nil
}

func applyUserDefaults(user *domain.User) {
	if user.PasswordAlgo == "" {
		user.PasswordAlgo = defaultPasswordAlgo
	}
	if user.Status == "" {
		user.Status = "active"
	}
	if user.Source == "" {
		user.Source = "local"
	}
}

func applyUserPatch(user *domain.User, input domain.UpdateUserInput) {
	if input.Username != nil {
		user.Username = strings.TrimSpace(*input.Username)
	}
	if input.Email != nil {
		user.Email = strings.TrimSpace(*input.Email)
	}
	if input.Phone != nil {
		user.Phone = strings.TrimSpace(*input.Phone)
	}
	if input.DisplayName != nil {
		user.DisplayName = strings.TrimSpace(*input.DisplayName)
	}
	if input.PasswordHash != nil {
		user.PasswordHash = *input.PasswordHash
	}
	if input.PasswordAlgo != nil {
		user.PasswordAlgo = strings.TrimSpace(*input.PasswordAlgo)
	}
	if input.Status != nil {
		user.Status = strings.TrimSpace(*input.Status)
	}
	if input.Source != nil {
		user.Source = strings.TrimSpace(*input.Source)
	}
}

func validateCreateUser(user domain.User) error {
	fieldErrors := map[string]string{}

	if user.TenantID == uuid.Nil {
		fieldErrors["tenant_id"] = "is required"
	}
	validate.Username("username", user.Username, fieldErrors)
	validate.Email("email", user.Email, fieldErrors)
	validate.Phone("phone", user.Phone, fieldErrors)
	validate.Required("display_name", user.DisplayName, fieldErrors)
	validate.OneOf("status", user.Status, allowedUserStatuses, fieldErrors)
	validate.OneOf("source", user.Source, allowedUserSources, fieldErrors)

	if len(fieldErrors) > 0 {
		return apierror.Validation(map[string]any{"fields": fieldErrors})
	}

	return nil
}

func validateUpdateUser(user domain.User) error {
	return validateCreateUser(user)
}

func mapUserRepoError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apierror.NotFound("user not found")
	case errors.Is(err, store.ErrConflict):
		return apierror.Conflict("user already exists in tenant scope", nil)
	default:
		return err
	}
}
